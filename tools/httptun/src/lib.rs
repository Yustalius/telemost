//! httptun — a TCP/UDP-over-HTTP streaming tunnel.
//!
//! Two roles share this crate:
//!   * [`run_server`] — an HTTPS server that bridges each HTTP session to a TCP
//!     or UDP target (or a built-in `echo`), used on the VPS.
//!   * [`run_mappings`] — fixed local TCP/UDP listeners that tunnel to configured
//!     targets through ordinary POST/GET requests, honoring the system HTTP proxy.
//!
//! The wire framing inside the HTTP bodies is `[u32be len][payload]`, with
//! `len == 0` a keepalive and `len == 0xFFFF_FFFF` a close marker. This keeps
//! keepalives out of the tunneled byte stream and lets the client tell a clean
//! target-close apart from a proxy-severed body.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::channel::mpsc as fmpsc;
use futures::{SinkExt, StreamExt};
use http_body::Frame as BodyFrame;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, io::Error>;

const CHAN_CAP: usize = 64;
const READ_BUF: usize = 32 * 1024;
const MAX_BATCH: usize = 256 * 1024;
const SESSION_IDLE: Duration = Duration::from_secs(300);
const LOCAL_BIND_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ---------------------------------------------------------------------------
// Shared config types
// ---------------------------------------------------------------------------

/// How the tunnel bodies are shaped on the wire.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// One long chunked POST (upstream) + one long chunked GET (downstream).
    /// Lowest latency; a proxy that cuts long bodies ends the session.
    Stream,
    /// Short long-polled requests. Survives proxy idle-cuts losslessly — the
    /// fallback for proxies that buffer or drop infinite bodies.
    Batch,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Stream => "stream",
            Mode::Batch => "batch",
        }
    }
}

/// How the client's reqwest client picks its outbound HTTP proxy.
#[derive(Clone, Debug)]
pub enum ProxyOpt {
    /// Read `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY` from the environment
    /// (reqwest's default). Under corp VPN this points at the `px` shim.
    Env,
    /// Ignore the environment and connect directly.
    Direct,
    /// Use this proxy URL explicitly.
    Explicit(String),
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub echo_all: bool,
    pub mode: Mode,
    pub keepalive: Duration,
    pub timeout: Duration,
    pub poll_wait: Duration,
    pub sans: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub server: String,
    pub mode: Mode,
    pub proxy: ProxyOpt,
    pub danger: bool,
    pub keepalive: Duration,
    pub timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortMap {
    pub transport: Transport,
    pub local_port: u16,
    pub target: String,
}

impl FromStr for PortMap {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (local, target) = value
            .split_once("->")
            .ok_or_else(|| "expected <tcp|udp>:<local_port>-><host:port>".to_owned())?;
        let (transport, local_port) = local
            .split_once(':')
            .ok_or_else(|| "missing protocol or local port".to_owned())?;
        let transport = match transport.to_ascii_lowercase().as_str() {
            "tcp" => Transport::Tcp,
            "udp" => Transport::Udp,
            other => return Err(format!("unsupported protocol {other}; expected tcp or udp")),
        };
        let local_port = local_port
            .parse::<u16>()
            .map_err(|_| format!("invalid local port {local_port}"))?;
        if local_port == 0 {
            return Err("local port must be greater than zero".to_owned());
        }
        validate_host_port(target)?;
        Ok(Self {
            transport,
            local_port,
            target: target.to_owned(),
        })
    }
}

fn validate_host_port(value: &str) -> std::result::Result<(), String> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        rest.split_once("]:")
            .ok_or_else(|| format!("invalid bracketed target {value}"))?
    } else {
        value
            .rsplit_once(':')
            .ok_or_else(|| format!("target {value} is missing a port"))?
    };
    if host.is_empty() {
        return Err("target host must not be empty".to_owned());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| format!("invalid target port in {value}"))?;
    if port == 0 {
        return Err("target port must be greater than zero".to_owned());
    }
    Ok(())
}

pub fn telemost_preset_maps(relay_host: &str) -> Vec<PortMap> {
    // hbbr rejects relay requests that arrive from a loopback source, so the
    // relay target must be the VPS's public address: the tunnel server dials it
    // and hbbr then sees a non-loopback peer. hbbs (rendezvous / NAT-test) does
    // accept loopback, so those stay on 127.0.0.1 to avoid an extra hairpin.
    let relay_target = if relay_host.contains(':') {
        format!("[{relay_host}]:21117")
    } else {
        format!("{relay_host}:21117")
    };
    vec![
        PortMap {
            transport: Transport::Udp,
            local_port: 23456,
            target: "127.0.0.1:21116".to_owned(),
        },
        PortMap {
            transport: Transport::Tcp,
            local_port: 23456,
            target: "127.0.0.1:21116".to_owned(),
        },
        PortMap {
            transport: Transport::Tcp,
            local_port: 23455,
            target: "127.0.0.1:21115".to_owned(),
        },
        PortMap {
            transport: Transport::Tcp,
            local_port: 23457,
            target: relay_target,
        },
    ]
}

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

const LEN_KEEPALIVE: u32 = 0;
const LEN_CLOSE: u32 = u32::MAX;

pub fn encode_data(payload: &[u8]) -> Bytes {
    debug_assert!(!payload.is_empty() && payload.len() < LEN_CLOSE as usize);
    let mut b = BytesMut::with_capacity(4 + payload.len());
    b.put_u32(payload.len() as u32);
    b.extend_from_slice(payload);
    b.freeze()
}

pub fn encode_keepalive() -> Bytes {
    Bytes::from_static(&[0, 0, 0, 0])
}

pub fn encode_close() -> Bytes {
    Bytes::from_static(&[0xff, 0xff, 0xff, 0xff])
}

#[derive(Debug, PartialEq, Eq)]
pub enum TunFrame {
    Data(Bytes),
    KeepAlive,
    Close,
}

/// Reassembles length-prefixed frames from an arbitrarily chunked byte stream.
#[derive(Default)]
pub struct FrameDecoder {
    buf: BytesMut,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    pub fn next_frame(&mut self) -> Option<TunFrame> {
        if self.buf.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]);
        if len == LEN_KEEPALIVE {
            self.buf.advance(4);
            return Some(TunFrame::KeepAlive);
        }
        if len == LEN_CLOSE {
            self.buf.advance(4);
            return Some(TunFrame::Close);
        }
        let len = len as usize;
        if self.buf.len() < 4 + len {
            return None;
        }
        self.buf.advance(4);
        Some(TunFrame::Data(self.buf.split_to(len).freeze()))
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn new_sid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn query_param(uri: &http::Uri, key: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|kv| {
        let mut it = kv.splitn(2, '=');
        if it.next()? == key {
            Some(it.next().unwrap_or("").to_string())
        } else {
            None
        }
    })
}

fn full(b: Bytes) -> BoxBody {
    Full::new(b).map_err(|never| match never {}).boxed()
}

fn text_resp(status: StatusCode, msg: &str) -> Response<BoxBody> {
    let mut response = Response::new(full(Bytes::from(msg.to_owned())));
    *response.status_mut() = status;
    response
}

fn octet_resp(body: Bytes) -> Response<BoxBody> {
    let mut response = Response::new(full(body));
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/octet-stream"),
    );
    response
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

struct Session {
    to_target: tokio::sync::mpsc::Sender<Bytes>,
    down: tokio::sync::Mutex<Option<fmpsc::Receiver<Bytes>>>,
    closed: Arc<AtomicBool>,
    last: std::sync::Mutex<Instant>,
    target: String,
}

impl Session {
    fn touch(&self) {
        if let Ok(mut g) = self.last.lock() {
            *g = Instant::now();
        }
    }
}

type Registry = Arc<tokio::sync::Mutex<HashMap<String, Arc<Session>>>>;

#[derive(Clone)]
struct ServerOpts {
    echo_all: bool,
    keepalive: Duration,
    timeout: Duration,
    poll_wait: Duration,
}

pub async fn run_server(cfg: ServerConfig) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    run_server_on(listener, cfg).await
}

/// Like [`run_server`] but on an already-bound listener (handy for embedding and
/// tests that need to know the actual port before the server starts).
pub async fn run_server_on(listener: TcpListener, cfg: ServerConfig) -> Result<()> {
    let tls = build_server_tls(&cfg.sans).context("building self-signed TLS config")?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let local = listener.local_addr().ok();

    let reg: Registry = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let opts = ServerOpts {
        echo_all: cfg.echo_all,
        keepalive: cfg.keepalive,
        timeout: cfg.timeout,
        poll_wait: cfg.poll_wait,
    };

    spawn_sweeper(reg.clone());

    log::info!(
        "httptun-server listening on {:?} (mode hint={}, echo_all={})",
        local,
        cfg.mode.as_str(),
        cfg.echo_all
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let reg = reg.clone();
        let opts = opts.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    log::debug!("tls handshake from {peer} failed: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls);
            let service = service_fn(move |req| handle(req, reg.clone(), opts.clone()));
            if let Err(e) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, service)
                .await
            {
                log::debug!("connection from {peer} ended: {e}");
            }
        });
    }
}

fn spawn_sweeper(reg: Registry) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut g = reg.lock().await;
            g.retain(|sid, s| {
                let idle = s.last.lock().map(|t| t.elapsed()).unwrap_or_default();
                let drop = s.closed.load(Relaxed) || idle > SESSION_IDLE;
                if drop {
                    s.closed.store(true, Relaxed);
                    log::debug!("sweeping session {sid} (target {})", s.target);
                }
                !drop
            });
        }
    });
}

async fn handle(
    req: Request<Incoming>,
    reg: Registry,
    opts: ServerOpts,
) -> Result<Response<BoxBody>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    log::debug!("--> {method} {path}?{query}");

    let resp = match (&method, path.as_str()) {
        (&Method::POST, "/o") => handle_open(req, &reg, &opts).await,
        (&Method::POST, "/u") => handle_up(req, &reg).await,
        (&Method::GET, "/d") => handle_down(req, &reg, &opts).await,
        (&Method::POST, "/c") => handle_close(req, &reg).await,
        (&Method::GET, "/") | (&Method::GET, "/health") => {
            text_resp(StatusCode::OK, "httptun-server ok\n")
        }
        _ => text_resp(StatusCode::NOT_FOUND, "not found\n"),
    };
    log::debug!("<-- {method} {path} {}", resp.status());
    Ok(resp)
}

async fn handle_open(
    req: Request<Incoming>,
    reg: &Registry,
    opts: &ServerOpts,
) -> Response<BoxBody> {
    let sid = match query_param(req.uri(), "s") {
        Some(s) if !s.is_empty() => s,
        _ => return text_resp(StatusCode::BAD_REQUEST, "missing session id\n"),
    };
    let target = req
        .headers()
        .get("x-target")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let target = match target {
        Some(t) if !t.is_empty() => t,
        _ => return text_resp(StatusCode::BAD_REQUEST, "missing X-Target\n"),
    };

    if reg.lock().await.contains_key(&sid) {
        return text_resp(StatusCode::OK, "");
    }

    match open_session(reg, sid, target, opts).await {
        Ok(()) => text_resp(StatusCode::OK, ""),
        Err((code, msg)) => text_resp(code, &msg),
    }
}

async fn open_session(
    reg: &Registry,
    sid: String,
    target: String,
    opts: &ServerOpts,
) -> std::result::Result<(), (StatusCode, String)> {
    let (to_tx, to_rx) = tokio::sync::mpsc::channel::<Bytes>(CHAN_CAP);
    let (down_tx, down_rx) = fmpsc::channel::<Bytes>(CHAN_CAP);
    let closed = Arc::new(AtomicBool::new(false));

    let spec = if opts.echo_all || target.eq_ignore_ascii_case("echo") {
        TargetSpec::Echo
    } else {
        parse_target(&target)?
    };
    match spec {
        TargetSpec::Echo => spawn_echo_bridge(to_rx, down_tx, closed.clone()),
        TargetSpec::Tcp(address) => {
            let stream =
                match tokio::time::timeout(opts.timeout, TcpStream::connect(&address)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        return Err((
                            StatusCode::BAD_GATEWAY,
                            format!("dial tcp {address}: {error}\n"),
                        ))
                    }
                    Err(_) => {
                        return Err((
                            StatusCode::GATEWAY_TIMEOUT,
                            format!("dial tcp {address}: timed out\n"),
                        ))
                    }
                };
            spawn_tcp_bridge(stream, to_rx, down_tx, closed.clone());
        }
        TargetSpec::Udp(address) => {
            let socket = connect_udp(&address, opts.timeout).await?;
            spawn_udp_bridge(socket, to_rx, down_tx, closed.clone());
        }
    }

    let session = Arc::new(Session {
        to_target: to_tx,
        down: tokio::sync::Mutex::new(Some(down_rx)),
        closed,
        last: std::sync::Mutex::new(Instant::now()),
        target: target.clone(),
    });
    reg.lock().await.insert(sid.clone(), session);
    log::debug!("opened session {sid} -> {target}");
    Ok(())
}

enum TargetSpec {
    Echo,
    Tcp(String),
    Udp(String),
}

fn parse_target(target: &str) -> std::result::Result<TargetSpec, (StatusCode, String)> {
    let (transport, address) = target.split_once("://").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "X-Target must be echo, tcp://host:port, or udp://host:port\n".to_owned(),
        )
    })?;
    validate_host_port(address).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid X-Target {target}: {error}\n"),
        )
    })?;
    match transport.to_ascii_lowercase().as_str() {
        "tcp" => Ok(TargetSpec::Tcp(address.to_owned())),
        "udp" => Ok(TargetSpec::Udp(address.to_owned())),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported X-Target protocol {transport}\n"),
        )),
    }
}

fn spawn_echo_bridge(
    mut to_rx: tokio::sync::mpsc::Receiver<Bytes>,
    mut down_tx: fmpsc::Sender<Bytes>,
    closed: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        while let Some(data) = to_rx.recv().await {
            if down_tx.send(data).await.is_err() {
                break;
            }
        }
        closed.store(true, Relaxed);
    });
}

fn spawn_tcp_bridge(
    stream: TcpStream,
    mut to_rx: tokio::sync::mpsc::Receiver<Bytes>,
    down_tx: fmpsc::Sender<Bytes>,
    closed: Arc<AtomicBool>,
) {
    let (mut rd, mut wr) = stream.into_split();
    let closed_w = closed.clone();
    tokio::spawn(async move {
        while let Some(data) = to_rx.recv().await {
            if wr.write_all(&data).await.is_err() {
                break;
            }
        }
        if let Err(error) = wr.shutdown().await {
            log::debug!("TCP target shutdown failed: {error}");
        }
        closed_w.store(true, Relaxed);
    });
    tokio::spawn(async move {
        let mut down_tx = down_tx;
        let mut buf = vec![0u8; READ_BUF];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if down_tx
                        .send(Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) => {
                    log::debug!("TCP target read failed: {error}");
                    break;
                }
            }
        }
        closed.store(true, Relaxed);
    });
}

async fn connect_udp(
    target: &str,
    timeout: Duration,
) -> std::result::Result<UdpSocket, (StatusCode, String)> {
    let mut addresses = match tokio::time::timeout(timeout, tokio::net::lookup_host(target)).await {
        Ok(Ok(addresses)) => addresses,
        Ok(Err(error)) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("resolve udp {target}: {error}\n"),
            ))
        }
        Err(_) => {
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                format!("resolve udp {target}: timed out\n"),
            ))
        }
    };
    let address = addresses.next().ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            format!("resolve udp {target}: no addresses\n"),
        )
    })?;
    let bind = if address.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).await.map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("bind UDP socket for {target}: {error}\n"),
        )
    })?;
    socket.connect(address).await.map_err(|error| {
        (
            StatusCode::BAD_GATEWAY,
            format!("connect udp {target}: {error}\n"),
        )
    })?;
    Ok(socket)
}

fn spawn_udp_bridge(
    socket: UdpSocket,
    mut to_rx: tokio::sync::mpsc::Receiver<Bytes>,
    down_tx: fmpsc::Sender<Bytes>,
    closed: Arc<AtomicBool>,
) {
    let socket = Arc::new(socket);
    let send_socket = socket.clone();
    let closed_w = closed.clone();
    tokio::spawn(async move {
        while let Some(datagram) = to_rx.recv().await {
            if let Err(error) = send_socket.send(&datagram).await {
                log::debug!("UDP target send failed: {error}");
                break;
            }
        }
        closed_w.store(true, Relaxed);
    });
    tokio::spawn(async move {
        let mut down_tx = down_tx;
        let mut buf = vec![0u8; u16::MAX as usize + 1];
        loop {
            tokio::select! {
                result = socket.recv(&mut buf) => match result {
                    Ok(n) => {
                        if down_tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        log::debug!("UDP target receive failed: {error}");
                        break;
                    }
                },
                _ = tokio::time::sleep(Duration::from_millis(250)) => {
                    if closed.load(Relaxed) {
                        break;
                    }
                }
            }
        }
        closed.store(true, Relaxed);
    });
}

async fn session_of(reg: &Registry, req: &Request<Incoming>) -> Option<Arc<Session>> {
    let sid = query_param(req.uri(), "s")?;
    let s = reg.lock().await.get(&sid).cloned();
    if let Some(s) = &s {
        s.touch();
    }
    s
}

async fn handle_up(req: Request<Incoming>, reg: &Registry) -> Response<BoxBody> {
    let session = match session_of(reg, &req).await {
        Some(s) => s,
        None => return text_resp(StatusCode::NOT_FOUND, "no such session\n"),
    };
    let mut body = req.into_body();
    let mut dec = FrameDecoder::new();
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(_) => break,
        };
        if let Ok(data) = frame.into_data() {
            dec.push(&data);
            while let Some(f) = dec.next_frame() {
                match f {
                    TunFrame::Data(d) => {
                        if session.to_target.send(d).await.is_err() {
                            return text_resp(StatusCode::GONE, "target closed\n");
                        }
                    }
                    TunFrame::KeepAlive => {}
                    TunFrame::Close => {
                        // Peer finished sending. The writer task drains what is
                        // already queued; the session is torn down by /c or by
                        // the sweeper.
                    }
                }
            }
        }
    }
    text_resp(StatusCode::OK, "")
}

async fn handle_down(
    req: Request<Incoming>,
    reg: &Registry,
    opts: &ServerOpts,
) -> Response<BoxBody> {
    let session = match session_of(reg, &req).await {
        Some(s) => s,
        None => return text_resp(StatusCode::NOT_FOUND, "no such session\n"),
    };
    if query_param(req.uri(), "seq").is_some() {
        handle_down_batch(session, opts).await
    } else {
        handle_down_stream(session, opts).await
    }
}

struct DownState {
    rx: fmpsc::Receiver<Bytes>,
    keepalive: Duration,
    done: bool,
}

async fn handle_down_stream(session: Arc<Session>, opts: &ServerOpts) -> Response<BoxBody> {
    let rx = match session.down.lock().await.take() {
        Some(r) => r,
        None => return text_resp(StatusCode::CONFLICT, "downstream already open\n"),
    };
    let state = DownState {
        rx,
        keepalive: opts.keepalive,
        done: false,
    };
    let stream = futures::stream::unfold(state, |mut st| async move {
        if st.done {
            return None;
        }
        tokio::select! {
            item = st.rx.next() => match item {
                Some(b) => Some((Ok::<BodyFrame<Bytes>, io::Error>(BodyFrame::data(encode_data(&b))), st)),
                None => {
                    st.done = true;
                    Some((Ok(BodyFrame::data(encode_close())), st))
                }
            },
            _ = tokio::time::sleep(st.keepalive) => {
                Some((Ok(BodyFrame::data(encode_keepalive())), st))
            }
        }
    });
    let mut response = Response::new(BodyExt::boxed(StreamBody::new(stream)));
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/octet-stream"),
    );
    response
}

async fn handle_down_batch(session: Arc<Session>, opts: &ServerOpts) -> Response<BoxBody> {
    let mut guard = session.down.lock().await;
    let rx = match guard.as_mut() {
        Some(r) => r,
        None => return octet_resp(encode_close()),
    };
    let mut out = BytesMut::new();
    // Long-poll: block up to poll_wait for the first byte so an idle client is
    // not hammering the proxy, then drain whatever else is immediately ready.
    match tokio::time::timeout(opts.poll_wait, rx.next()).await {
        Ok(Some(b)) => out.extend_from_slice(&encode_data(&b)),
        Ok(None) => {
            session.closed.store(true, Relaxed);
            return octet_resp(encode_close());
        }
        Err(_) => return octet_resp(Bytes::new()),
    }
    // Drain whatever else is immediately ready. A closed+empty channel yields
    // Err here and is reported as a close by the next poll's long-poll branch.
    while out.len() < MAX_BATCH {
        match rx.try_next() {
            Ok(Some(data)) => out.extend_from_slice(&encode_data(&data)),
            Ok(None) | Err(_) => break,
        }
    }
    octet_resp(out.freeze())
}

async fn handle_close(req: Request<Incoming>, reg: &Registry) -> Response<BoxBody> {
    if let Some(sid) = query_param(req.uri(), "s") {
        if let Some(s) = reg.lock().await.remove(&sid) {
            s.closed.store(true, Relaxed);
            log::debug!("closed session {sid}");
        }
    }
    text_resp(StatusCode::OK, "")
}

fn build_server_tls(sans: &[String]) -> Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let sans: Vec<String> = if sans.is_empty() {
        vec!["localhost".into()]
    } else {
        sans.to_vec()
    };
    let cert = rcgen::generate_simple_self_signed(sans).context("rcgen self-signed cert")?;
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
        .context("installing self-signed cert")?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Client: tunnel plumbing
// ---------------------------------------------------------------------------

struct TunnelCtx {
    client: reqwest::Client,
    server: String,
    mode: Mode,
    keepalive: Duration,
}

enum Up {
    Stream { tx: fmpsc::Sender<Bytes> },
    Batch { seq: u64 },
}

pub struct TunnelSender {
    up: Up,
    sid: String,
    ctx: Arc<TunnelCtx>,
    closed: Arc<AtomicBool>,
}

pub struct TunnelReceiver {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    reconnects: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
}

impl TunnelReceiver {
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }

    pub fn reconnects_arc(&self) -> Arc<AtomicU64> {
        self.reconnects.clone()
    }

    pub fn closed_arc(&self) -> Arc<AtomicBool> {
        self.closed.clone()
    }
}

impl TunnelSender {
    pub async fn send(&mut self, data: Bytes) -> Result<()> {
        match &mut self.up {
            Up::Stream { tx } => tx
                .send(encode_data(&data))
                .await
                .map_err(|_| anyhow!("upstream stream closed")),
            Up::Batch { seq } => {
                let n = *seq;
                *seq += 1;
                let url = format!("{}/u?s={}&seq={}", self.ctx.server, self.sid, n);
                let resp = self
                    .ctx
                    .client
                    .post(&url)
                    .body(encode_data(&data))
                    .send()
                    .await
                    .context("batch upstream POST")?;
                if !resp.status().is_success() {
                    bail!("batch upstream POST status {}", resp.status());
                }
                Ok(())
            }
        }
    }

    pub async fn finish(mut self) {
        match &mut self.up {
            Up::Stream { tx } => {
                let _ = tx.send(encode_close()).await;
                tx.close_channel();
            }
            Up::Batch { seq } => {
                let n = *seq;
                *seq += 1;
                let url = format!("{}/u?s={}&seq={}", self.ctx.server, self.sid, n);
                let _ = self.ctx.client.post(&url).body(encode_close()).send().await;
            }
        }
        let url = format!("{}/c?s={}", self.ctx.server, self.sid);
        let _ = self.ctx.client.post(&url).send().await;
        self.closed.store(true, Relaxed);
    }
}

async fn open_tunnel(
    ctx: Arc<TunnelCtx>,
    sid: String,
    target: &str,
) -> Result<(TunnelSender, TunnelReceiver)> {
    let open_url = format!("{}/o?s={}", ctx.server, sid);
    let resp = ctx
        .client
        .post(&open_url)
        .header("x-target", target)
        .send()
        .await
        .context("open session POST /o")?;
    if !resp.status().is_success() {
        bail!(
            "server refused session for {target}: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default().trim()
        );
    }

    let closed = Arc::new(AtomicBool::new(false));
    let reconnects = Arc::new(AtomicU64::new(0));

    let (down_tx, down_rx) = tokio::sync::mpsc::channel::<Bytes>(CHAN_CAP);
    tokio::spawn(down_driver(
        ctx.clone(),
        sid.clone(),
        down_tx,
        reconnects.clone(),
        closed.clone(),
    ));

    let up = match ctx.mode {
        Mode::Stream => {
            let (body_tx, body_rx) = fmpsc::channel::<Bytes>(CHAN_CAP);
            let up_url = format!("{}/u?s={}", ctx.server, sid);
            let ctx2 = ctx.clone();
            let closed2 = closed.clone();
            tokio::spawn(async move {
                let body = reqwest::Body::wrap_stream(body_rx.map(Ok::<Bytes, io::Error>));
                match ctx2.client.post(&up_url).body(body).send().await {
                    Ok(resp) => log::debug!("upstream POST /u finished: {}", resp.status()),
                    Err(e) => {
                        log::debug!("upstream POST /u error: {e}");
                        closed2.store(true, Relaxed);
                    }
                }
            });
            // Keepalive so an idle upstream body is not cut by a proxy timeout.
            let mut ka_tx = body_tx.clone();
            let ka = ctx.keepalive;
            let closed3 = closed.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(ka).await;
                    if closed3.load(Relaxed) || ka_tx.send(encode_keepalive()).await.is_err() {
                        break;
                    }
                }
            });
            Up::Stream { tx: body_tx }
        }
        Mode::Batch => Up::Batch { seq: 0 },
    };

    Ok((
        TunnelSender {
            up,
            sid,
            ctx,
            closed: closed.clone(),
        },
        TunnelReceiver {
            rx: down_rx,
            reconnects,
            closed,
        },
    ))
}

async fn down_driver(
    ctx: Arc<TunnelCtx>,
    sid: String,
    down_tx: tokio::sync::mpsc::Sender<Bytes>,
    reconnects: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
) {
    match ctx.mode {
        Mode::Stream => down_driver_stream(ctx, sid, down_tx, reconnects, closed).await,
        Mode::Batch => down_driver_batch(ctx, sid, down_tx, reconnects, closed).await,
    }
}

async fn down_driver_stream(
    ctx: Arc<TunnelCtx>,
    sid: String,
    down_tx: tokio::sync::mpsc::Sender<Bytes>,
    reconnects: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
) {
    let url = format!("{}/d?s={}", ctx.server, sid);
    let mut attempts = 0u32;
    while !closed.load(Relaxed) {
        let resp = match ctx.client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log::debug!("downstream GET /d status {}", r.status());
                break;
            }
            Err(e) => {
                log::debug!("downstream GET /d error: {e}");
                attempts += 1;
                reconnects.fetch_add(1, Relaxed);
                if attempts > 5 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let mut stream = resp.bytes_stream();
        let mut dec = FrameDecoder::new();
        let mut clean_close = false;
        'read: while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    log::debug!("downstream body error: {e}");
                    break;
                }
            };
            dec.push(&chunk);
            while let Some(f) = dec.next_frame() {
                match f {
                    TunFrame::Data(d) => {
                        if down_tx.send(d).await.is_err() {
                            closed.store(true, Relaxed);
                            break 'read;
                        }
                    }
                    TunFrame::KeepAlive => {}
                    TunFrame::Close => {
                        clean_close = true;
                        break 'read;
                    }
                }
            }
        }
        if clean_close || closed.load(Relaxed) {
            break;
        }
        // Body ended without a close marker: the proxy cut a long body. The
        // server dropped the receiver with it, so a retry will 409 — count the
        // reconnect attempt and give up (batch mode is the resilient path).
        attempts += 1;
        reconnects.fetch_add(1, Relaxed);
        log::debug!("downstream body cut unexpectedly (attempt {attempts})");
        if attempts > 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    closed.store(true, Relaxed);
}

async fn down_driver_batch(
    ctx: Arc<TunnelCtx>,
    sid: String,
    down_tx: tokio::sync::mpsc::Sender<Bytes>,
    reconnects: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
) {
    let mut seq = 0u64;
    while !closed.load(Relaxed) {
        let url = format!("{}/d?s={}&seq={}", ctx.server, sid, seq);
        seq += 1;
        let resp = match ctx.client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log::debug!("batch downstream status {}", r.status());
                break;
            }
            Err(e) => {
                log::debug!("batch downstream error: {e}");
                reconnects.fetch_add(1, Relaxed);
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let body = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                log::debug!("batch downstream body error: {e}");
                reconnects.fetch_add(1, Relaxed);
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let mut dec = FrameDecoder::new();
        dec.push(&body);
        let mut clean_close = false;
        while let Some(f) = dec.next_frame() {
            match f {
                TunFrame::Data(d) => {
                    if down_tx.send(d).await.is_err() {
                        closed.store(true, Relaxed);
                        break;
                    }
                }
                TunFrame::KeepAlive => {}
                TunFrame::Close => {
                    clean_close = true;
                    break;
                }
            }
        }
        if clean_close {
            break;
        }
    }
    closed.store(true, Relaxed);
}

fn build_client(cfg: &ClientConfig) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.danger)
        .connect_timeout(cfg.timeout)
        .pool_max_idle_per_host(16);
    b = match &cfg.proxy {
        ProxyOpt::Env => b,
        ProxyOpt::Direct => b.no_proxy(),
        ProxyOpt::Explicit(u) => {
            b.proxy(reqwest::Proxy::all(u.clone()).context("parsing --proxy url")?)
        }
    };
    b.build().context("building reqwest client")
}

fn ctx_from(cfg: &ClientConfig) -> Result<Arc<TunnelCtx>> {
    Ok(Arc::new(TunnelCtx {
        client: build_client(cfg)?,
        server: cfg.server.trim_end_matches('/').to_owned(),
        mode: cfg.mode,
        keepalive: cfg.keepalive,
        // cfg.timeout is applied as reqwest connect_timeout in build_client.
    }))
}

// ---------------------------------------------------------------------------
// Client: fixed TCP/UDP listeners
// ---------------------------------------------------------------------------

pub async fn run_mappings(cfg: ClientConfig, mappings: Vec<PortMap>) -> Result<()> {
    let task = start_mappings(cfg, mappings).await?;
    match task.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("mapping task failed: {error}")),
    }
}

pub async fn start_mappings(
    cfg: ClientConfig,
    mappings: Vec<PortMap>,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    if mappings.is_empty() {
        bail!("no mappings configured; pass --map or --telemost-preset");
    }
    for (index, mapping) in mappings.iter().enumerate() {
        if mappings[..index].iter().any(|other| {
            other.transport == mapping.transport && other.local_port == mapping.local_port
        }) {
            bail!(
                "duplicate {} listener on 127.0.0.1:{}",
                mapping.transport.as_str(),
                mapping.local_port
            );
        }
    }

    let ctx = ctx_from(&cfg)?;
    log::info!(
        "httptun-client -> {} (mode={}, proxy={:?})",
        ctx.server,
        cfg.mode.as_str(),
        cfg.proxy
    );

    let mut bound = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        let local = SocketAddr::new(LOCAL_BIND_IP, mapping.local_port);
        match mapping.transport {
            Transport::Tcp => {
                let listener = TcpListener::bind(local)
                    .await
                    .with_context(|| format!("binding TCP listener {local}"))?;
                log::info!("TCP {local} -> tcp://{}", mapping.target);
                bound.push(BoundMapping::Tcp(listener, mapping.target));
            }
            Transport::Udp => {
                let socket = UdpSocket::bind(local)
                    .await
                    .with_context(|| format!("binding UDP listener {local}"))?;
                log::info!("UDP {local} -> udp://{}", mapping.target);
                bound.push(BoundMapping::Udp(socket, mapping.target));
            }
        }
    }

    Ok(tokio::spawn(run_bound_mappings(ctx, bound)))
}

enum BoundMapping {
    Tcp(TcpListener, String),
    Udp(UdpSocket, String),
}

async fn run_bound_mappings(ctx: Arc<TunnelCtx>, bound: Vec<BoundMapping>) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    for mapping in bound {
        let ctx = ctx.clone();
        match mapping {
            BoundMapping::Tcp(listener, target) => {
                tasks.spawn(serve_tcp_mapping(listener, target, ctx));
            }
            BoundMapping::Udp(socket, target) => {
                tasks.spawn(serve_udp_mapping(socket, target, ctx));
            }
        }
    }
    match tasks.join_next().await {
        Some(Ok(Ok(()))) => bail!("mapping listener stopped unexpectedly"),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(error)) => Err(anyhow!("mapping task failed: {error}")),
        None => bail!("no mapping listeners started"),
    }
}

pub async fn run_tcp_mapping_on(
    listener: TcpListener,
    target: String,
    cfg: ClientConfig,
) -> Result<()> {
    validate_host_port(&target).map_err(|error| anyhow!(error))?;
    serve_tcp_mapping(listener, target, ctx_from(&cfg)?).await
}

async fn serve_tcp_mapping(
    listener: TcpListener,
    target: String,
    ctx: Arc<TunnelCtx>,
) -> Result<()> {
    loop {
        let (tcp, peer) = listener
            .accept()
            .await
            .context("accepting fixed TCP mapping")?;
        let target = target.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_tcp_connection(tcp, &target, ctx).await {
                log::debug!("TCP mapping connection from {peer} ended: {error}");
            }
        });
    }
}

async fn handle_tcp_connection(tcp: TcpStream, target: &str, ctx: Arc<TunnelCtx>) -> Result<()> {
    let sid = new_sid();
    let x_target = format!("tcp://{target}");
    log::debug!("TCP mapping -> {x_target} (session {sid})");
    let (sender, receiver) = open_tunnel(ctx, sid, &x_target).await?;
    bridge_tcp(tcp, sender, receiver).await;
    Ok(())
}

async fn bridge_tcp(tcp: TcpStream, mut sender: TunnelSender, mut receiver: TunnelReceiver) {
    let (mut rd, mut wr) = tcp.into_split();
    let up = async move {
        let mut buf = vec![0u8; READ_BUF];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(error) = sender.send(Bytes::copy_from_slice(&buf[..n])).await {
                        log::debug!("TCP mapping upstream ended: {error}");
                        break;
                    }
                }
                Err(error) => {
                    log::debug!("TCP mapping local read failed: {error}");
                    break;
                }
            }
        }
        sender.finish().await;
    };
    let down = async move {
        while let Some(data) = receiver.recv().await {
            if let Err(error) = wr.write_all(&data).await {
                log::debug!("TCP mapping local write failed: {error}");
                break;
            }
        }
        if let Err(error) = wr.shutdown().await {
            log::debug!("TCP mapping local shutdown failed: {error}");
        }
    };
    tokio::join!(up, down);
}

pub async fn run_udp_mapping_on(
    socket: UdpSocket,
    target: String,
    cfg: ClientConfig,
) -> Result<()> {
    validate_host_port(&target).map_err(|error| anyhow!(error))?;
    serve_udp_mapping(socket, target, ctx_from(&cfg)?).await
}

async fn serve_udp_mapping(socket: UdpSocket, target: String, ctx: Arc<TunnelCtx>) -> Result<()> {
    let socket = Arc::new(socket);
    let peers = Arc::new(tokio::sync::Mutex::new(HashMap::<
        SocketAddr,
        tokio::sync::mpsc::Sender<Bytes>,
    >::new()));
    let mut buf = vec![0u8; u16::MAX as usize + 1];
    loop {
        let (n, source) = socket
            .recv_from(&mut buf)
            .await
            .context("receiving local UDP datagram")?;
        if n == 0 {
            log::debug!("ignoring empty UDP datagram from {source}");
            continue;
        }
        let datagram = Bytes::copy_from_slice(&buf[..n]);
        let existing = peers.lock().await.get(&source).cloned();
        let is_new = existing.is_none();
        let sender = existing
            .unwrap_or_else(|| spawn_udp_peer(socket.clone(), source, target.clone(), ctx.clone()));
        if sender.send(datagram.clone()).await.is_err() {
            let replacement = spawn_udp_peer(socket.clone(), source, target.clone(), ctx.clone());
            peers.lock().await.insert(source, replacement.clone());
            replacement
                .send(datagram)
                .await
                .map_err(|_| anyhow!("new UDP peer task stopped before receiving data"))?;
        } else if is_new {
            peers.lock().await.insert(source, sender);
        }
    }
}

fn spawn_udp_peer(
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    target: String,
    ctx: Arc<TunnelCtx>,
) -> tokio::sync::mpsc::Sender<Bytes> {
    let (local_tx, local_rx) = tokio::sync::mpsc::channel::<Bytes>(CHAN_CAP);
    tokio::spawn(async move {
        if let Err(error) = run_udp_peer(socket, source, target, ctx, local_rx).await {
            log::debug!("UDP mapping peer {source} ended: {error}");
        }
    });
    local_tx
}

async fn run_udp_peer(
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    target: String,
    ctx: Arc<TunnelCtx>,
    mut local_rx: tokio::sync::mpsc::Receiver<Bytes>,
) -> Result<()> {
    let sid = new_sid();
    let x_target = format!("udp://{target}");
    log::debug!("UDP mapping {source} -> {x_target} (session {sid})");
    let (mut sender, mut receiver) = open_tunnel(ctx, sid, &x_target).await?;
    let idle = tokio::time::sleep(SESSION_IDLE);
    tokio::pin!(idle);
    loop {
        let active = tokio::select! {
            local = local_rx.recv() => match local {
                Some(datagram) => {
                    sender.send(datagram).await?;
                    true
                }
                None => false,
            },
            remote = receiver.recv() => match remote {
                Some(datagram) => {
                    socket
                        .send_to(&datagram, source)
                        .await
                        .with_context(|| format!("sending UDP response to {source}"))?;
                    true
                }
                None => false,
            },
            _ = &mut idle => false,
        };
        if !active {
            break;
        }
        idle.as_mut()
            .reset(tokio::time::Instant::now() + SESSION_IDLE);
    }
    sender.finish().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Client: measurement hooks
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct RttMs {
    min: f64,
    p50: f64,
    p95: f64,
    max: f64,
}

#[derive(serde::Serialize)]
struct PingReport {
    rtt_ms: RttMs,
    batched: bool,
    lost: usize,
    mode: String,
}

#[derive(serde::Serialize)]
struct ThroughputReport {
    mbps: f64,
    reconnects: u64,
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Send `count` fixed-size records to the server's echo target, matching each
/// echo back to its send to compute RTT and detect buffering. Prints one line
/// of JSON on stdout.
pub async fn selftest_ping(cfg: &ClientConfig, to: &str, count: usize, size: usize) -> Result<()> {
    let size = size.max(8);
    let count = count.max(1);
    let ctx = ctx_from(cfg)?;
    let sid = new_sid();
    let (mut sender, mut receiver) = open_tunnel(ctx, sid, to)
        .await
        .context("opening tunnel for selftest")?;

    let (arr_tx, mut arr_rx) = tokio::sync::mpsc::unbounded_channel::<(u64, Instant)>();
    let recv_task = tokio::spawn(async move {
        let mut acc = BytesMut::new();
        while let Some(b) = receiver.recv().await {
            acc.extend_from_slice(&b);
            while acc.len() >= size {
                let rec = acc.split_to(size);
                let mut seq = [0; 8];
                seq.copy_from_slice(&rec[..8]);
                let seq = u64::from_be_bytes(seq);
                if arr_tx.send((seq, Instant::now())).is_err() {
                    return;
                }
            }
        }
    });

    let gap = Duration::from_millis(50);
    let mut sent = vec![Instant::now(); count];
    for (i, s) in sent.iter_mut().enumerate() {
        let mut rec = vec![0u8; size];
        rec[0..8].copy_from_slice(&(i as u64).to_be_bytes());
        *s = Instant::now();
        sender
            .send(Bytes::from(rec))
            .await
            .context("sending ping")?;
        tokio::time::sleep(gap).await;
    }

    let mut rtts: Vec<Option<f64>> = vec![None; count];
    let mut arrivals: Vec<Instant> = Vec::new();
    let wait = gap * count as u32 + Duration::from_secs(5);
    let deadline = Instant::now() + wait;
    while arrivals.len() < count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, arr_rx.recv()).await {
            Ok(Some((seq, at))) => {
                if let Some(slot) = rtts.get_mut(seq as usize) {
                    if slot.is_none() {
                        *slot = Some((at - sent[seq as usize]).as_secs_f64() * 1000.0);
                        arrivals.push(at);
                    }
                }
            }
            _ => break,
        }
    }

    sender.finish().await;
    recv_task.abort();

    let mut ok: Vec<f64> = rtts.iter().filter_map(|o| *o).collect();
    ok.sort_by(f64::total_cmp);
    let lost = count - ok.len();
    let batched = detect_batched(&mut arrivals, gap);

    let report = PingReport {
        rtt_ms: RttMs {
            min: round3(ok.first().copied().unwrap_or(0.0)),
            p50: round3(percentile(&ok, 50.0)),
            p95: round3(percentile(&ok, 95.0)),
            max: round3(ok.last().copied().unwrap_or(0.0)),
        },
        batched,
        lost,
        mode: cfg.mode.as_str().to_owned(),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

/// Heuristic: if most echoes arrive clustered far closer together than they were
/// sent, something on the path buffered the stream and released it in a burst.
fn detect_batched(arrivals: &mut [Instant], gap: Duration) -> bool {
    if arrivals.len() < 4 {
        return false;
    }
    arrivals.sort();
    let threshold = gap / 2;
    let mut clustered = 0usize;
    for w in arrivals.windows(2) {
        if w[1] - w[0] < threshold {
            clustered += 1;
        }
    }
    clustered * 2 > arrivals.len() - 1
}

/// Blast fixed-size chunks to the echo target for `seconds` and measure the
/// echoed throughput. Prints one line of JSON on stdout.
pub async fn throughput(cfg: &ClientConfig, to: &str, seconds: u64) -> Result<()> {
    let seconds = seconds.max(1);
    let ctx = ctx_from(cfg)?;
    let sid = new_sid();
    let (mut sender, mut receiver) = open_tunnel(ctx, sid, to)
        .await
        .context("opening tunnel for throughput")?;

    let reconnects = receiver.reconnects_arc();
    let received = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let recv_received = received.clone();
    let recv_stop = stop.clone();
    let recv_task = tokio::spawn(async move {
        while let Some(b) = receiver.recv().await {
            recv_received.fetch_add(b.len() as u64, Relaxed);
            if recv_stop.load(Relaxed) {
                break;
            }
        }
    });

    let chunk = Bytes::from(vec![0x61u8; READ_BUF]);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        if sender.send(chunk.clone()).await.is_err() {
            break;
        }
    }
    // Let the last echoes drain before stopping the counter.
    tokio::time::sleep(Duration::from_millis(500)).await;
    stop.store(true, Relaxed);
    sender.finish().await;
    recv_task.abort();

    let bytes = received.load(Relaxed) as f64;
    let mbps = bytes * 8.0 / 1_000_000.0 / seconds as f64;
    let report = ThroughputReport {
        mbps: round3(mbps),
        reconnects: reconnects.load(Relaxed),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_across_split_chunks() {
        let mut enc = BytesMut::new();
        enc.extend_from_slice(&encode_data(b"abc"));
        enc.extend_from_slice(&encode_keepalive());
        enc.extend_from_slice(&encode_data(b"defgh"));
        enc.extend_from_slice(&encode_close());
        let bytes = enc.freeze();

        // Feed the byte stream one byte at a time; framing must not depend on
        // how the transport chunked the bytes.
        let mut dec = FrameDecoder::new();
        let mut out = Vec::new();
        for b in bytes.iter() {
            dec.push(&[*b]);
            while let Some(f) = dec.next_frame() {
                out.push(f);
            }
        }
        assert_eq!(
            out,
            vec![
                TunFrame::Data(Bytes::from_static(b"abc")),
                TunFrame::KeepAlive,
                TunFrame::Data(Bytes::from_static(b"defgh")),
                TunFrame::Close,
            ]
        );
    }

    #[test]
    fn decoder_holds_partial_frame() {
        let mut dec = FrameDecoder::new();
        dec.push(&[0, 0, 0, 4, b'x']); // len=4 but only 1 payload byte present
        assert_eq!(dec.next_frame(), None);
        dec.push(b"yz!");
        assert_eq!(
            dec.next_frame(),
            Some(TunFrame::Data(Bytes::from_static(b"xyz!")))
        );
        assert_eq!(dec.next_frame(), None);
    }
}
