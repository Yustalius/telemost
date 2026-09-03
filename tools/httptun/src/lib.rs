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
use std::path::PathBuf;
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

/// Which wire protocol the client speaks (and the server accepts).
#[derive(Clone, Debug)]
pub enum WireApi {
    /// v1: `/api/v1/*` paths, fixed opaque route ids, browser-like headers and
    /// an optional shared bearer token. This is the obfuscated public shape.
    V1 { token: Option<String> },
    /// Legacy: `/o /u /d /c` with an arbitrary `X-Target`. Kept only for the
    /// migration window; the server accepts it only under `allow_legacy`.
    Legacy,
}

impl WireApi {
    fn open_path(&self) -> &'static str {
        match self {
            WireApi::V1 { .. } => "/api/v1/session/open",
            WireApi::Legacy => "/o",
        }
    }
    fn send_path(&self) -> &'static str {
        match self {
            WireApi::V1 { .. } => "/api/v1/session/send",
            WireApi::Legacy => "/u",
        }
    }
    fn recv_path(&self) -> &'static str {
        match self {
            WireApi::V1 { .. } => "/api/v1/session/recv",
            WireApi::Legacy => "/d",
        }
    }
    fn close_path(&self) -> &'static str {
        match self {
            WireApi::V1 { .. } => "/api/v1/session/close",
            WireApi::Legacy => "/c",
        }
    }
}

/// A fixed server-side route: the v1 client asks for it by opaque `id`, and the
/// server dials the associated target. Replaces the arbitrary `X-Target` so the
/// server is not an open proxy.
#[derive(Clone, Debug)]
pub struct Route {
    pub id: String,
    pub transport: Transport,
    pub target: String,
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
    /// PEM certificate chain; when both this and `tls_key` are set the server
    /// serves that certificate instead of a startup self-signed one.
    pub tls_cert: Option<PathBuf>,
    /// PEM private key paired with `tls_cert`.
    pub tls_key: Option<PathBuf>,
    /// Shared bearer token required on every `/api/v1/*` request; `None` leaves
    /// the v1 API unauthenticated (dev/tests only).
    pub auth_token: Option<String>,
    /// Upper bound on concurrent sessions; opens past it are refused with 429.
    pub max_sessions: usize,
    /// Accept the legacy `/o /u /d /c` + `X-Target` API (migration only).
    pub allow_legacy: bool,
    /// Fixed v1 routes the server will dial by id.
    pub routes: Vec<Route>,
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub server: String,
    pub mode: Mode,
    pub proxy: ProxyOpt,
    pub danger: bool,
    pub keepalive: Duration,
    pub timeout: Duration,
    pub wire: WireApi,
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

/// The four fixed v1 route ids. They are opaque tokens on the wire (no
/// `tcp://host:port` leaks); the server maps each to a concrete target.
pub const ROUTE_RENDEZVOUS_UDP: &str = "ru";
pub const ROUTE_RENDEZVOUS_TCP: &str = "rt";
pub const ROUTE_NAT_TEST: &str = "nt";
pub const ROUTE_RELAY: &str = "rl";
/// Diagnostic loopback route for the measurement hooks (not one of the four).
pub const ROUTE_ECHO: &str = "echo";

/// v1 local listeners for telemost. The `target` field carries the opaque route
/// id (not a host:port); the server resolves it via [`telemost_preset_routes`].
pub fn telemost_preset_maps_v1() -> Vec<PortMap> {
    vec![
        PortMap {
            transport: Transport::Udp,
            local_port: 23456,
            target: ROUTE_RENDEZVOUS_UDP.to_owned(),
        },
        PortMap {
            transport: Transport::Tcp,
            local_port: 23456,
            target: ROUTE_RENDEZVOUS_TCP.to_owned(),
        },
        PortMap {
            transport: Transport::Tcp,
            local_port: 23455,
            target: ROUTE_NAT_TEST.to_owned(),
        },
        PortMap {
            transport: Transport::Tcp,
            local_port: 23457,
            target: ROUTE_RELAY.to_owned(),
        },
    ]
}

/// Server-side route table for telemost. hbbr rejects relay requests from a
/// loopback source, so the relay route dials the VPS's public address; hbbs
/// (rendezvous / NAT-test) accepts loopback and stays on 127.0.0.1.
pub fn telemost_preset_routes(relay_host: &str) -> Vec<Route> {
    let relay_target = if relay_host.contains(':') {
        format!("[{relay_host}]:21117")
    } else {
        format!("{relay_host}:21117")
    };
    vec![
        Route {
            id: ROUTE_RENDEZVOUS_UDP.to_owned(),
            transport: Transport::Udp,
            target: "127.0.0.1:21116".to_owned(),
        },
        Route {
            id: ROUTE_RENDEZVOUS_TCP.to_owned(),
            transport: Transport::Tcp,
            target: "127.0.0.1:21116".to_owned(),
        },
        Route {
            id: ROUTE_NAT_TEST.to_owned(),
            transport: Transport::Tcp,
            target: "127.0.0.1:21115".to_owned(),
        },
        Route {
            id: ROUTE_RELAY.to_owned(),
            transport: Transport::Tcp,
            target: relay_target,
        },
    ]
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
    auth_token: Option<Arc<str>>,
    max_sessions: usize,
    allow_legacy: bool,
    routes: Arc<HashMap<String, Route>>,
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
    let tls = build_server_tls(&cfg).context("building TLS config")?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let local = listener.local_addr().ok();

    let routes: HashMap<String, Route> = cfg
        .routes
        .iter()
        .map(|r| (r.id.clone(), r.clone()))
        .collect();

    let reg: Registry = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let opts = ServerOpts {
        echo_all: cfg.echo_all,
        keepalive: cfg.keepalive,
        timeout: cfg.timeout,
        poll_wait: cfg.poll_wait,
        auth_token: cfg.auth_token.as_deref().map(Arc::from),
        max_sessions: cfg.max_sessions.max(1),
        allow_legacy: cfg.allow_legacy,
        routes: Arc::new(routes),
    };

    spawn_sweeper(reg.clone());

    log::info!(
        "httptun-server listening on {:?} (mode hint={}, echo_all={}, auth={}, legacy={}, routes={}, max_sessions={})",
        local,
        cfg.mode.as_str(),
        cfg.echo_all,
        opts.auth_token.is_some(),
        opts.allow_legacy,
        opts.routes.len(),
        opts.max_sessions,
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

    // Every /api/v1/* request must carry the shared bearer token (when set).
    if path.starts_with("/api/v1/") && !authorized(&req, &opts) {
        let resp = text_resp(StatusCode::UNAUTHORIZED, "unauthorized\n");
        log::debug!("<-- {method} {path} {}", resp.status());
        return Ok(resp);
    }

    let resp = match (&method, path.as_str()) {
        // v1 API — opaque routes, bearer auth, web-app-shaped paths.
        (&Method::POST, "/api/v1/session/open") => handle_open_v1(req, &reg, &opts).await,
        (&Method::POST, "/api/v1/session/send") => handle_up(req, &reg).await,
        (&Method::GET, "/api/v1/session/recv") => handle_down(req, &reg, &opts).await,
        (&Method::POST, "/api/v1/session/close") => handle_close(req, &reg).await,
        // Legacy API — arbitrary X-Target, migration window only.
        (&Method::POST, "/o") if opts.allow_legacy => handle_open(req, &reg, &opts).await,
        (&Method::POST, "/u") if opts.allow_legacy => handle_up(req, &reg).await,
        (&Method::GET, "/d") if opts.allow_legacy => handle_down(req, &reg, &opts).await,
        (&Method::POST, "/c") if opts.allow_legacy => handle_close(req, &reg).await,
        (&Method::GET, "/") => decoy_resp(),
        (&Method::GET, "/health") => text_resp(StatusCode::OK, "ok\n"),
        _ => text_resp(StatusCode::NOT_FOUND, "not found\n"),
    };
    log::debug!("<-- {method} {path} {}", resp.status());
    Ok(resp)
}

fn authorized(req: &Request<Incoming>, opts: &ServerOpts) -> bool {
    let expected = match &opts.auth_token {
        Some(token) => token,
        None => return true,
    };
    req.headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|got| got == expected.as_ref())
        .unwrap_or(false)
}

fn decoy_resp() -> Response<BoxBody> {
    let body = "<!doctype html><title>ya-telemost</title><h1>It works</h1>\n";
    let mut response = Response::new(full(Bytes::from_static(body.as_bytes())));
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
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

    open_with_limit(reg, sid, target, opts).await
}

async fn handle_open_v1(
    req: Request<Incoming>,
    reg: &Registry,
    opts: &ServerOpts,
) -> Response<BoxBody> {
    let sid = match query_param(req.uri(), "s") {
        Some(s) if !s.is_empty() => s,
        _ => return text_resp(StatusCode::BAD_REQUEST, "missing session id\n"),
    };
    let route = match query_param(req.uri(), "r") {
        Some(r) if !r.is_empty() => r,
        _ => return text_resp(StatusCode::BAD_REQUEST, "missing route\n"),
    };
    let target = match resolve_route(&route, opts) {
        Some(t) => t,
        None => return text_resp(StatusCode::BAD_REQUEST, "unknown route\n"),
    };

    open_with_limit(reg, sid, target, opts).await
}

/// Maps an opaque v1 route id to a concrete `<transport>://host:port` target
/// (or the built-in echo). Returns `None` for anything not in the fixed table,
/// so an arbitrary target can never be reached through the v1 API.
fn resolve_route(route: &str, opts: &ServerOpts) -> Option<String> {
    if opts.echo_all || route == ROUTE_ECHO {
        return Some("echo".to_owned());
    }
    opts.routes
        .get(route)
        .map(|r| format!("{}://{}", r.transport.as_str(), r.target))
}

async fn open_with_limit(
    reg: &Registry,
    sid: String,
    target: String,
    opts: &ServerOpts,
) -> Response<BoxBody> {
    {
        let guard = reg.lock().await;
        if guard.contains_key(&sid) {
            return text_resp(StatusCode::OK, "");
        }
        if guard.len() >= opts.max_sessions {
            return text_resp(StatusCode::TOO_MANY_REQUESTS, "session limit reached\n");
        }
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
                        // An empty datagram would encode as len=0, colliding with
                        // the keepalive frame and getting dropped by the decoder
                        // (and tripping encode_data's debug_assert). Skip it, as
                        // the client-side listener already does.
                        if n == 0 {
                            continue;
                        }
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

fn build_server_tls(cfg: &ServerConfig) -> Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let (certs, key): (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) =
        match (&cfg.tls_cert, &cfg.tls_key) {
            (Some(cert_path), Some(key_path)) => load_pem_cert(cert_path, key_path)?,
            (Some(_), None) | (None, Some(_)) => {
                bail!("both --tls-cert and --tls-key must be given together")
            }
            (None, None) => self_signed_cert(&cfg.sans)?,
        };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("installing server certificate")?;
    Ok(config)
}

fn load_pem_cert(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("reading TLS cert {}", cert_path.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing TLS cert {}", cert_path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", cert_path.display());
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("reading TLS key {}", key_path.display()))?;
    Ok((certs, key))
}

fn self_signed_cert(
    sans: &[String],
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let sans: Vec<String> = if sans.is_empty() {
        vec!["localhost".into()]
    } else {
        sans.to_vec()
    };
    let cert = rcgen::generate_simple_self_signed(sans).context("rcgen self-signed cert")?;
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    Ok((vec![cert_der], PrivateKeyDer::Pkcs8(key_der)))
}

// ---------------------------------------------------------------------------
// Client: tunnel plumbing
// ---------------------------------------------------------------------------

struct TunnelCtx {
    client: reqwest::Client,
    server: String,
    mode: Mode,
    keepalive: Duration,
    // Per-request bound for the finite requests (open / batch send / close /
    // batch recv). Not applied to the long-lived stream bodies, which are
    // infinite by design; a buffering proxy could otherwise hang them forever.
    timeout: Duration,
    wire: WireApi,
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
                let url = format!(
                    "{}{}?s={}&seq={}",
                    self.ctx.server,
                    self.ctx.wire.send_path(),
                    self.sid,
                    n
                );
                let resp = self
                    .ctx
                    .client
                    .post(&url)
                    .body(encode_data(&data))
                    .timeout(self.ctx.timeout)
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
                let url = format!(
                    "{}{}?s={}&seq={}",
                    self.ctx.server,
                    self.ctx.wire.send_path(),
                    self.sid,
                    n
                );
                let _ = self
                    .ctx
                    .client
                    .post(&url)
                    .body(encode_close())
                    .timeout(self.ctx.timeout)
                    .send()
                    .await;
            }
        }
        let url = format!(
            "{}{}?s={}",
            self.ctx.server,
            self.ctx.wire.close_path(),
            self.sid
        );
        let _ = self
            .ctx
            .client
            .post(&url)
            .timeout(self.ctx.timeout)
            .send()
            .await;
        self.closed.store(true, Relaxed);
    }
}

async fn open_tunnel(
    ctx: Arc<TunnelCtx>,
    sid: String,
    target: &str,
) -> Result<(TunnelSender, TunnelReceiver)> {
    let open = match &ctx.wire {
        WireApi::V1 { .. } => {
            let open_url = format!(
                "{}{}?s={}&r={}",
                ctx.server,
                ctx.wire.open_path(),
                sid,
                target
            );
            ctx.client.post(&open_url)
        }
        WireApi::Legacy => {
            let open_url = format!("{}{}?s={}", ctx.server, ctx.wire.open_path(), sid);
            ctx.client.post(&open_url).header("x-target", target)
        }
    };
    let resp = open
        .timeout(ctx.timeout)
        .send()
        .await
        .context("open session")?;
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
            let up_url = format!("{}{}?s={}", ctx.server, ctx.wire.send_path(), sid);
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
    let url = format!("{}{}?s={}", ctx.server, ctx.wire.recv_path(), sid);
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

// Reconnect backoff for the batch downstream long-poll: start small, double on
// each consecutive failure, cap so a long proxy outage stops hammering it.
const DOWN_BACKOFF_MIN: Duration = Duration::from_millis(200);
const DOWN_BACKOFF_MAX: Duration = Duration::from_secs(5);

async fn down_driver_batch(
    ctx: Arc<TunnelCtx>,
    sid: String,
    down_tx: tokio::sync::mpsc::Sender<Bytes>,
    reconnects: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
) {
    let mut seq = 0u64;
    let mut backoff = DOWN_BACKOFF_MIN;
    while !closed.load(Relaxed) {
        let url = format!("{}{}?s={}&seq={}", ctx.server, ctx.wire.recv_path(), sid, seq);
        seq += 1;
        let resp = match ctx.client.get(&url).timeout(ctx.timeout).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                log::debug!("batch downstream status {}", r.status());
                break;
            }
            Err(e) => {
                log::debug!("batch downstream error: {e}");
                reconnects.fetch_add(1, Relaxed);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(DOWN_BACKOFF_MAX);
                continue;
            }
        };
        let body = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                log::debug!("batch downstream body error: {e}");
                reconnects.fetch_add(1, Relaxed);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(DOWN_BACKOFF_MAX);
                continue;
            }
        };
        backoff = DOWN_BACKOFF_MIN;
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

// A current Chrome UA; the v1 requests should look like an ordinary web app's
// XHR/fetch traffic rather than a bespoke tunnel client.
const V1_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

fn build_client(cfg: &ClientConfig) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.danger)
        .connect_timeout(cfg.timeout)
        .pool_max_idle_per_host(16);
    if let WireApi::V1 { token } = &cfg.wire {
        b = b.user_agent(V1_USER_AGENT);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::ACCEPT,
            http::HeaderValue::from_static("*/*"),
        );
        headers.insert(
            http::header::ACCEPT_LANGUAGE,
            http::HeaderValue::from_static("en-US,en;q=0.9"),
        );
        headers.insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("gzip, deflate, br"),
        );
        if let Some(token) = token {
            let mut value = http::HeaderValue::try_from(format!("Bearer {token}"))
                .context("building Authorization header")?;
            value.set_sensitive(true);
            headers.insert(http::header::AUTHORIZATION, value);
        }
        b = b.default_headers(headers);
    }
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
        // Applied both as reqwest connect_timeout (build_client) and as the
        // per-request timeout on the finite requests below.
        timeout: cfg.timeout,
        wire: cfg.wire.clone(),
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

// Tokio binds listeners with HANDLE_FLAG_INHERIT set, so a child spawned later
// via std::process::Command inherits the raw handle and keeps the port bound
// after this process exits; clear the flag right after bind to prevent that.
#[cfg(windows)]
fn clear_inherit_flag(socket: &impl std::os::windows::io::AsRawSocket) {
    extern "system" {
        fn SetHandleInformation(handle: *mut std::ffi::c_void, mask: u32, flags: u32) -> i32;
    }

    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;

    let handle = socket.as_raw_socket() as usize as *mut std::ffi::c_void;
    let ok = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    if ok == 0 {
        log::warn!(
            "failed to clear HANDLE_FLAG_INHERIT on tunnel listener socket; a child process spawned later could inherit it and keep the port held after exit"
        );
    }
}

// Windows enables SIO_UDP_CONNRESET by default, which surfaces a stale ICMP
// port-unreachable (from a previous sendto) as WSAECONNRESET on the next
// recv_from of an unconnected UDP socket; disable it so that harmless reset
// doesn't look like a real recv error.
#[cfg(windows)]
fn disable_udp_connreset(socket: &impl std::os::windows::io::AsRawSocket) {
    extern "system" {
        fn WSAIoctl(
            s: usize,
            dwIoControlCode: u32,
            lpvInBuffer: *mut std::ffi::c_void,
            cbInBuffer: u32,
            lpvOutBuffer: *mut std::ffi::c_void,
            cbOutBuffer: u32,
            lpcbBytesReturned: *mut u32,
            lpOverlapped: *mut std::ffi::c_void,
            lpCompletionRoutine: *mut std::ffi::c_void,
        ) -> i32;
    }

    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

    let handle = socket.as_raw_socket() as usize;
    let mut disabled: i32 = 0;
    let mut bytes_returned: u32 = 0;
    let ok = unsafe {
        WSAIoctl(
            handle,
            SIO_UDP_CONNRESET,
            &mut disabled as *mut i32 as *mut std::ffi::c_void,
            std::mem::size_of::<i32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok != 0 {
        log::warn!(
            "failed to disable SIO_UDP_CONNRESET on tunnel UDP socket; a stale ICMP port-unreachable could surface as WSAECONNRESET on recv_from"
        );
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
                #[cfg(windows)]
                clear_inherit_flag(&listener);
                log::info!("TCP {local} -> tcp://{}", mapping.target);
                bound.push(BoundMapping::Tcp(listener, mapping.target));
            }
            Transport::Udp => {
                let socket = UdpSocket::bind(local)
                    .await
                    .with_context(|| format!("binding UDP listener {local}"))?;
                #[cfg(windows)]
                clear_inherit_flag(&socket);
                #[cfg(windows)]
                disable_udp_connreset(&socket);
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
    // In v1 `target` is an opaque route id resolved server-side, not a host:port.
    if matches!(cfg.wire, WireApi::Legacy) {
        validate_host_port(&target).map_err(|error| anyhow!(error))?;
    }
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

/// In v1 the mapping `target` is an opaque route id sent verbatim; in legacy it
/// is a host:port that becomes a `<transport>://` X-Target.
fn open_arg(ctx: &TunnelCtx, transport: Transport, target: &str) -> String {
    match ctx.wire {
        WireApi::V1 { .. } => target.to_owned(),
        WireApi::Legacy => format!("{}://{}", transport.as_str(), target),
    }
}

async fn handle_tcp_connection(tcp: TcpStream, target: &str, ctx: Arc<TunnelCtx>) -> Result<()> {
    let sid = new_sid();
    let open = open_arg(&ctx, Transport::Tcp, target);
    log::debug!("TCP mapping -> {open} (session {sid})");
    let (sender, receiver) = open_tunnel(ctx, sid, &open).await?;
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
    if matches!(cfg.wire, WireApi::Legacy) {
        validate_host_port(&target).map_err(|error| anyhow!(error))?;
    }
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
        let (n, source) = match socket.recv_from(&mut buf).await {
            Ok(value) => value,
            // Windows can surface a stale ICMP port-unreachable as WSAECONNRESET on an
            // unconnected UDP socket; tearing the mapping down over it would take the
            // tunnel's other listeners with it.
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => continue,
            Err(error) => return Err(error).context("receiving local UDP datagram"),
        };
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
    let open = open_arg(&ctx, Transport::Udp, &target);
    log::debug!("UDP mapping {source} -> {open} (session {sid})");
    let (mut sender, mut receiver) = open_tunnel(ctx, sid, &open).await?;
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

/// One HTTPS GET with the tunnel's exact TLS stack (reqwest + the native root
/// store, honoring `danger` and the env proxy), so a run under corp VPN answers
/// "does `danger:false` validation survive the MWG proxy?" authoritatively.
/// Prints one JSON line; never errors on a TLS/connect failure (that is data).
pub async fn tls_probe(cfg: &ClientConfig, url: &str) -> Result<()> {
    let client = build_client(cfg)?;
    let started = Instant::now();
    let (ok, status, error) = match client.get(url).send().await {
        Ok(resp) => (true, Some(resp.status().as_u16()), None),
        Err(e) => {
            // Walk the source chain so the TLS cause (e.g. "invalid peer
            // certificate: UnknownIssuer" / "Expired") is visible, not just the
            // top "error sending request" wrapper.
            let mut msg = e.to_string();
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                msg.push_str(" -> ");
                msg.push_str(&s.to_string());
                src = s.source();
            }
            (false, e.status().map(|s| s.as_u16()), Some(msg))
        }
    };
    let report = serde_json::json!({
        "url": url,
        "danger": cfg.danger,
        "proxy": format!("{:?}", cfg.proxy),
        "ms": round3(started.elapsed().as_secs_f64() * 1000.0),
        "ok": ok,
        "status": status,
        "error": error,
    });
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

    #[test]
    fn empty_datagram_would_collide_with_keepalive() {
        // A zero-length payload framed as data ([0,0,0,0]) is byte-identical to
        // a keepalive, so the decoder reports KeepAlive and the datagram is lost.
        // This is why both UDP bridges must drop n==0 reads instead of forwarding
        // them (server: spawn_udp_bridge; client: serve_udp_mapping).
        assert_eq!(&encode_keepalive()[..], &[0u8, 0, 0, 0]);
        let mut dec = FrameDecoder::new();
        dec.push(&[0, 0, 0, 0]); // what encode_data(b"") would produce
        assert_eq!(dec.next_frame(), Some(TunFrame::KeepAlive));
        assert_eq!(dec.next_frame(), None);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_clear_inherit_flag_tcp() {
        use std::os::windows::io::AsRawSocket;

        extern "system" {
            fn GetHandleInformation(handle: *mut std::ffi::c_void, flags: *mut u32) -> i32;
        }
        const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let handle = listener.as_raw_socket() as usize as *mut std::ffi::c_void;

        let mut flags: u32 = 0;
        let ok = unsafe { GetHandleInformation(handle, &mut flags) };
        assert_ne!(ok, 0);
        assert_ne!(
            flags & HANDLE_FLAG_INHERIT,
            0,
            "TCP listener should be inheritable before clearing"
        );

        clear_inherit_flag(&listener);

        let mut flags2: u32 = 0;
        let ok2 = unsafe { GetHandleInformation(handle, &mut flags2) };
        assert_ne!(ok2, 0);
        assert_eq!(
            flags2 & HANDLE_FLAG_INHERIT,
            0,
            "TCP listener should not be inheritable after clearing"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_clear_inherit_flag_udp() {
        use std::os::windows::io::AsRawSocket;

        extern "system" {
            fn GetHandleInformation(handle: *mut std::ffi::c_void, flags: *mut u32) -> i32;
        }
        const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handle = socket.as_raw_socket() as usize as *mut std::ffi::c_void;

        let mut flags: u32 = 0;
        let ok = unsafe { GetHandleInformation(handle, &mut flags) };
        assert_ne!(ok, 0);
        assert_ne!(
            flags & HANDLE_FLAG_INHERIT,
            0,
            "UDP socket should be inheritable before clearing"
        );

        clear_inherit_flag(&socket);

        let mut flags2: u32 = 0;
        let ok2 = unsafe { GetHandleInformation(handle, &mut flags2) };
        assert_ne!(ok2, 0);
        assert_eq!(
            flags2 & HANDLE_FLAG_INHERIT,
            0,
            "UDP socket should not be inheritable after clearing"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_disable_udp_connreset_keeps_socket_usable() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        disable_udp_connreset(&socket);

        assert!(socket.local_addr().is_ok());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_rebind_after_child_spawn_tcp() {
        use std::process::{Command, Stdio};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        clear_inherit_flag(&listener);

        let mut child = Command::new("cmd")
            .args(["/c", "ping", "-n", "20", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        drop(listener);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let rebind = TcpListener::bind(addr).await;

        let _ = child.kill();
        let _ = child.wait();

        assert!(
            rebind.is_ok(),
            "expected to rebind TCP {addr} after clearing inherit flag, got {:?}",
            rebind.err()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_rebind_after_child_spawn_udp() {
        use std::process::{Command, Stdio};

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        clear_inherit_flag(&socket);

        let mut child = Command::new("cmd")
            .args(["/c", "ping", "-n", "20", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        drop(socket);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let rebind = UdpSocket::bind(addr).await;

        let _ = child.kill();
        let _ = child.wait();

        assert!(
            rebind.is_ok(),
            "expected to rebind UDP {addr} after clearing inherit flag, got {:?}",
            rebind.err()
        );
    }
}
