//! httptun — a TCP/UDP-over-HTTP streaming tunnel.
//!
//! Two roles share this crate:
//!   * [`run_server`] — an HTTPS server that bridges each HTTP session to a TCP
//!     or UDP target (or a built-in `echo`), used on the VPS.
//!   * [`run_mappings`] — fixed local TCP/UDP listeners that tunnel to configured
//!     targets through ordinary POST/GET requests, honoring the system HTTP proxy.
//!   * [`run_reverse`] — claims fixed server-side TCP listeners and bridges
//!     accepted connections to local client-side targets.
//!
//! The wire framing inside the HTTP bodies is `[u32be len][payload]`, with
//! `len == 0` a keepalive and `len == 0xFFFF_FFFF` a close marker. This keeps
//! keepalives out of the tunneled byte stream and lets the client tell a clean
//! target-close apart from a proxy-severed body.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::channel::mpsc as fmpsc;
use futures::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderName, Uri};
use http_body::{Body as _, Frame as BodyFrame};
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
const MAX_V2_QUEUE: usize = MAX_BATCH - (u16::MAX as usize + 1);
const EXPERIMENTAL_BATCH_BYTES: [usize; 3] = [64 * 1024, 128 * 1024, MAX_BATCH];
const SESSION_IDLE: Duration = Duration::from_secs(300);
const OPENING_IDLE: Duration = Duration::from_secs(60);
const LOCAL_BIND_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DASHBOARD_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DASHBOARD_PROGRESS_TIMEOUT: Duration = Duration::from_secs(30);
const REVERSE_ACCEPT_WAIT: Duration = Duration::from_secs(20);
const REVERSE_PENDING_IDLE: Duration = Duration::from_secs(30);
const REVERSE_OWNER_IDLE: Duration = Duration::from_secs(60);
const REVERSE_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

struct V2Counters {
    retries: AtomicU64,
    upstream_duplicates: AtomicU64,
    downstream_replays: AtomicU64,
    sequence_conflicts: AtomicU64,
    session_losses: AtomicU64,
}

static V2_COUNTERS: V2Counters = V2Counters {
    retries: AtomicU64::new(0),
    upstream_duplicates: AtomicU64::new(0),
    downstream_replays: AtomicU64::new(0),
    sequence_conflicts: AtomicU64::new(0),
    session_losses: AtomicU64::new(0),
};
static HTTP_CONNECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static HTTP_CONNECTIONS_ACTIVE: AtomicU64 = AtomicU64::new(0);
static HTTP_GETS: AtomicU64 = AtomicU64::new(0);
static HTTP_POSTS: AtomicU64 = AtomicU64::new(0);

struct HttpConnectionGuard;

impl Drop for HttpConnectionGuard {
    fn drop(&mut self) {
        HTTP_CONNECTIONS_ACTIVE.fetch_sub(1, Relaxed);
    }
}

struct DiagnosticSink {
    tx: tokio::sync::mpsc::UnboundedSender<serde_json::Value>,
    role: String,
    started: Instant,
    wall_started_ms: u128,
}

static DIAGNOSTICS: OnceLock<DiagnosticSink> = OnceLock::new();

/// Starts an opt-in JSONL event stream. Events contain only transport metadata;
/// request headers, authentication data, and application payloads are never
/// recorded.
pub async fn enable_diagnostics(path: &std::path::Path, role: &str) -> Result<()> {
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("opening diagnostic log {}", path.display()))?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    let sink = DiagnosticSink {
        tx,
        role: role.to_owned(),
        started: Instant::now(),
        wall_started_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    };
    DIAGNOSTICS
        .set(sink)
        .map_err(|_| anyhow!("diagnostics already enabled"))?;
    tokio::spawn(async move {
        let mut file = file;
        while let Some(event) = rx.recv().await {
            let mut line = match serde_json::to_vec(&event) {
                Ok(line) => line,
                Err(error) => {
                    log::warn!("serializing diagnostic event failed: {error}");
                    continue;
                }
            };
            line.push(b'\n');
            if let Err(error) = file.write_all(&line).await {
                log::warn!("writing diagnostic event failed: {error}");
                break;
            }
            if let Err(error) = file.flush().await {
                log::warn!("flushing diagnostic events failed: {error}");
                break;
            }
        }
    });
    diagnostic_event("process_start", serde_json::json!({}));
    Ok(())
}

fn diagnostic_event(event: &str, fields: serde_json::Value) {
    let Some(sink) = DIAGNOSTICS.get() else {
        return;
    };
    let elapsed = sink.started.elapsed();
    let mut record = serde_json::Map::new();
    record.insert("schema".to_owned(), serde_json::json!(1));
    record.insert("event".to_owned(), serde_json::json!(event));
    record.insert("role".to_owned(), serde_json::json!(sink.role));
    record.insert("pid".to_owned(), serde_json::json!(std::process::id()));
    record.insert(
        "monotonic_us".to_owned(),
        serde_json::json!(elapsed.as_micros()),
    );
    record.insert(
        "unix_ms".to_owned(),
        serde_json::json!(sink.wall_started_ms.saturating_add(elapsed.as_millis())),
    );
    if let serde_json::Value::Object(fields) = fields {
        record.extend(fields);
    }
    let _ = sink.tx.send(serde_json::Value::Object(record));
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct V2Diagnostics {
    pub retries: u64,
    pub upstream_duplicates: u64,
    pub downstream_replays: u64,
    pub sequence_conflicts: u64,
    pub session_losses: u64,
}

pub fn v2_diagnostics() -> V2Diagnostics {
    V2Diagnostics {
        retries: V2_COUNTERS.retries.load(Relaxed),
        upstream_duplicates: V2_COUNTERS.upstream_duplicates.load(Relaxed),
        downstream_replays: V2_COUNTERS.downstream_replays.load(Relaxed),
        sequence_conflicts: V2_COUNTERS.sequence_conflicts.load(Relaxed),
        session_losses: V2_COUNTERS.session_losses.load(Relaxed),
    }
}

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
    /// v2: sequenced batch requests with acknowledgements and replay safety.
    V2 { token: Option<String> },
}

impl WireApi {
    fn open_path(&self) -> &'static str {
        match self {
            WireApi::V1 { .. } => "/api/v1/session/open",
            WireApi::V2 { .. } => "/api/v2/session/open",
        }
    }
    fn send_path(&self) -> &'static str {
        match self {
            WireApi::V1 { .. } => "/api/v1/session/send",
            WireApi::V2 { .. } => "/api/v2/session/send",
        }
    }
    fn recv_path(&self) -> &'static str {
        match self {
            WireApi::V1 { .. } => "/api/v1/session/recv",
            WireApi::V2 { .. } => "/api/v2/session/recv",
        }
    }
    fn close_path(&self) -> &'static str {
        match self {
            WireApi::V1 { .. } => "/api/v1/session/close",
            WireApi::V2 { .. } => "/api/v2/session/close",
        }
    }
}

/// A fixed server-side route: the client asks for it by opaque `id`, and the
/// server dials the associated target so the server cannot act as an open proxy.
#[derive(Clone, Debug)]
pub struct Route {
    pub id: String,
    pub transport: Transport,
    pub target: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseEndpointConfig {
    pub id: String,
    pub bind: SocketAddr,
}

impl FromStr for ReverseEndpointConfig {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (id, bind) = value
            .split_once('=')
            .ok_or_else(|| "expected <endpoint_id>=<loopback:port>".to_owned())?;
        validate_reverse_id(id, "endpoint id")?;
        let bind = bind
            .parse::<SocketAddr>()
            .map_err(|_| format!("invalid reverse bind address {bind}"))?;
        if !bind.ip().is_loopback() {
            return Err("reverse bind address must be loopback".to_owned());
        }
        Ok(Self {
            id: id.to_owned(),
            bind,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub echo_all: bool,
    pub mode: Mode,
    pub keepalive: Duration,
    pub timeout: Duration,
    pub poll_wait: Duration,
    pub dashboard_backend: Option<String>,
    pub sans: Vec<String>,
    /// PEM certificate chain; when both this and `tls_key` are set the server
    /// serves that certificate instead of a startup self-signed one.
    pub tls_cert: Option<PathBuf>,
    /// PEM private key paired with `tls_cert`.
    pub tls_key: Option<PathBuf>,
    /// Shared bearer token required on every `/api/v1/*` and `/api/v2/*`
    /// request; `None` leaves both APIs unauthenticated (dev/tests only).
    pub auth_token: Option<String>,
    /// Upper bound on concurrent sessions; opens past it are refused with 429.
    pub max_sessions: usize,
    /// Fixed v1 routes the server will dial by id.
    pub routes: Vec<Route>,
    /// Fixed loopback listeners whose accepted TCP sockets are attached by a
    /// reverse client.
    pub reverse: Vec<ReverseEndpointConfig>,
    /// Enable the authenticated, bounded reverse diagnostic runner.
    pub reverse_diagnostics: bool,
    /// Accept opt-in profile B batch limits on reverse sessions.
    pub experimental_reverse_batches: bool,
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub server: String,
    pub mode: Mode,
    pub proxy: ProxyOpt,
    pub danger: bool,
    pub keepalive: Duration,
    pub timeout: Duration,
    /// Maximum total time spent retrying one v2 logical operation.
    pub retry_window: Duration,
    /// Opt-in profile B body limit. `None` preserves the baseline v2 behavior.
    pub experimental_batch_bytes: Option<usize>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseMap {
    pub endpoint_id: String,
    pub dial_target: String,
}

impl FromStr for ReverseMap {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (endpoint_id, dial_target) = value
            .split_once("->")
            .ok_or_else(|| "expected <endpoint_id>-><host:port>".to_owned())?;
        validate_reverse_id(endpoint_id, "endpoint id")?;
        validate_host_port(dial_target)?;
        Ok(Self {
            endpoint_id: endpoint_id.to_owned(),
            dial_target: dial_target.to_owned(),
        })
    }
}

fn validate_reverse_id(value: &str, label: &str) -> std::result::Result<(), String> {
    if value.is_empty() || value.len() > 128 {
        return Err(format!("{label} must contain 1 to 128 characters"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "{label} may contain only ASCII letters, digits, '.', '_' and '-'"
        ));
    }
    Ok(())
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

/// v2 frames deliberately have a kind byte so an empty datagram is distinct
/// from a keepalive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V2Frame {
    Data(Bytes),
    Close,
    Ack(u64),
    KeepAlive,
}

const V2_DATA: u8 = 0x01;
const V2_CLOSE: u8 = 0x02;
const V2_ACK: u8 = 0x03;
const V2_KEEPALIVE: u8 = 0x04;

pub fn encode_v2_frame(frame: &V2Frame) -> Bytes {
    let (kind, payload) = match frame {
        V2Frame::Data(data) => (V2_DATA, data.clone()),
        V2Frame::Close => (V2_CLOSE, Bytes::new()),
        V2Frame::Ack(seq) => (V2_ACK, Bytes::copy_from_slice(&seq.to_be_bytes())),
        V2Frame::KeepAlive => (V2_KEEPALIVE, Bytes::new()),
    };
    let mut out = BytesMut::with_capacity(5 + payload.len());
    out.put_u8(kind);
    out.put_u32(payload.len() as u32);
    out.extend_from_slice(&payload);
    out.freeze()
}

pub fn encode_v2_ack(seq: u64) -> Bytes {
    encode_v2_frame(&V2Frame::Ack(seq))
}

/// Fully parses a finite v2 HTTP body. A body which is incomplete, exceeds
/// the batch limit, or has an invalid control frame is never partly applied.
pub fn decode_v2_frames(body: &[u8]) -> Result<Vec<V2Frame>> {
    if body.len() > MAX_BATCH {
        bail!("v2 body exceeds batch limit");
    }
    let mut at = 0usize;
    let mut out = Vec::new();
    while at < body.len() {
        if body.len() - at < 5 {
            bail!("trailing partial v2 frame");
        }
        let kind = body[at];
        let len =
            u32::from_be_bytes([body[at + 1], body[at + 2], body[at + 3], body[at + 4]]) as usize;
        at += 5;
        if len > MAX_BATCH || body.len() - at < len {
            bail!("invalid v2 frame length");
        }
        let payload = Bytes::copy_from_slice(&body[at..at + len]);
        at += len;
        let frame = match kind {
            V2_DATA => V2Frame::Data(payload),
            V2_CLOSE if len == 0 => V2Frame::Close,
            V2_ACK if len == 8 => {
                let bytes: [u8; 8] = payload
                    .as_ref()
                    .try_into()
                    .map_err(|_| anyhow!("invalid v2 ack"))?;
                V2Frame::Ack(u64::from_be_bytes(bytes))
            }
            V2_KEEPALIVE if len == 0 => V2Frame::KeepAlive,
            V2_CLOSE | V2_ACK | V2_KEEPALIVE => bail!("invalid v2 control frame length"),
            _ => bail!("unknown v2 frame kind"),
        };
        out.push(frame);
    }
    Ok(out)
}

#[derive(Default)]
pub struct V2FrameDecoder {
    buf: BytesMut,
}

impl V2FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&mut self, chunk: &[u8]) -> Result<()> {
        if self.buf.len().saturating_add(chunk.len()) > MAX_BATCH {
            bail!("v2 body exceeds batch limit");
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }
    pub fn next_frame(&mut self) -> Result<Option<V2Frame>> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        if len > MAX_BATCH {
            bail!("invalid v2 frame length");
        }
        if self.buf.len() < 5 + len {
            return Ok(None);
        }
        let kind = self.buf[0];
        self.buf.advance(5);
        let payload = self.buf.split_to(len).freeze();
        match kind {
            V2_DATA => Ok(Some(V2Frame::Data(payload))),
            V2_CLOSE if len == 0 => Ok(Some(V2Frame::Close)),
            V2_ACK if len == 8 => {
                let bytes: [u8; 8] = payload
                    .as_ref()
                    .try_into()
                    .map_err(|_| anyhow!("invalid v2 ack"))?;
                Ok(Some(V2Frame::Ack(u64::from_be_bytes(bytes))))
            }
            V2_KEEPALIVE if len == 0 => Ok(Some(V2Frame::KeepAlive)),
            V2_CLOSE | V2_ACK | V2_KEEPALIVE => bail!("invalid v2 control frame length"),
            _ => bail!("unknown v2 frame kind"),
        }
    }
    pub fn finish(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            bail!("trailing partial v2 frame")
        }
    }
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

fn finite_resp(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<BoxBody> {
    let len = body.len() as u64;
    let mut response = Response::new(full(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    response
        .headers_mut()
        .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(len));
    response
}

fn reverse_text_resp(status: StatusCode, msg: &str) -> Response<BoxBody> {
    finite_resp(
        status,
        "text/plain; charset=utf-8",
        Bytes::copy_from_slice(msg.as_bytes()),
    )
}

fn reverse_json_resp<T: serde::Serialize>(value: &T) -> Response<BoxBody> {
    reverse_json_status(StatusCode::OK, value)
}

fn reverse_json_status<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<BoxBody> {
    match serde_json::to_vec(value) {
        Ok(body) => finite_resp(status, "application/json", Bytes::from(body)),
        Err(error) => {
            log::error!("serializing reverse response failed: {error}");
            reverse_text_resp(StatusCode::INTERNAL_SERVER_ERROR, "internal error\n")
        }
    }
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
    v1_generation: Option<u64>,
    _admission: tokio::sync::OwnedSemaphorePermit,
}

impl Session {
    fn touch(&self) {
        if let Ok(mut g) = self.last.lock() {
            *g = Instant::now();
        }
    }
}

type Registry = Arc<tokio::sync::Mutex<HashMap<String, Arc<Session>>>>;
type V2Registry = Arc<tokio::sync::Mutex<HashMap<String, V2Entry>>>;
type VersionClaims = Arc<tokio::sync::Mutex<HashMap<String, VersionClaim>>>;
type ReverseRegistry = Arc<tokio::sync::Mutex<ReverseState>>;
type ReverseDiagnosticJobs = Arc<tokio::sync::Mutex<HashMap<String, ReverseDiagnosticJob>>>;

#[derive(Clone, Debug, serde::Deserialize)]
struct ReverseDiagnosticRequest {
    endpoint_id: String,
    run_id: String,
    #[serde(default = "default_diagnostic_profile")]
    profile: String,
    #[serde(default = "default_diagnostic_passes")]
    passes: u8,
}

fn default_diagnostic_profile() -> String {
    "A-v2-baseline".to_owned()
}

fn default_diagnostic_passes() -> u8 {
    3
}

#[derive(Clone, Debug, serde::Serialize)]
struct ReverseDiagnosticJob {
    schema: u8,
    profile: String,
    endpoint_id: String,
    run_id: String,
    status: &'static str,
    started_unix_ms: u128,
    finished_unix_ms: Option<u128>,
    completed_checks: usize,
    failed_checks: usize,
    skipped_checks: Vec<&'static str>,
    error: Option<String>,
    measurements: Vec<ReverseDiagnosticMeasurement>,
    resources: Vec<ReverseDiagnosticResourceSample>,
}

#[derive(Clone, Debug, serde::Serialize)]
struct ReverseDiagnosticResourceSample {
    unix_ms: u128,
    v2_sessions: usize,
    reverse_pending: usize,
    rss_kib: Option<u64>,
    cpu_ticks: Option<u64>,
    http_connections_total: u64,
    http_connections_active: u64,
    http_gets: u64,
    http_posts: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
struct ReverseDiagnosticMeasurement {
    pass: u8,
    scenario: &'static str,
    test_id: String,
    concurrency: usize,
    ok: bool,
    expected_failure: bool,
    error: Option<&'static str>,
    connect_us: u128,
    first_byte_us: Option<u128>,
    total_us: u128,
    bytes_up: usize,
    bytes_down: usize,
}

#[derive(Debug, serde::Serialize)]
struct DiagnosticTargetRequest<'a> {
    command: &'a str,
    test_id: &'a str,
    bytes: usize,
    chunk_bytes: usize,
    delay_ms: u64,
    first_delay_ms: u64,
}

#[derive(Debug, serde::Deserialize)]
struct DiagnosticTargetResponse {
    ok: bool,
    bytes: usize,
}

struct ReverseState {
    endpoints: HashMap<String, ReverseEndpoint>,
    pending: usize,
    max_pending: usize,
}

struct ReverseEndpoint {
    bind: SocketAddr,
    owner: Option<ReverseOwner>,
    cursor: u64,
    conns: HashMap<String, AcceptedReverseConn>,
    notify: Arc<tokio::sync::Notify>,
}

struct ReverseOwner {
    id: String,
    last_seen: Instant,
}

struct AcceptedReverseConn {
    stream: TcpStream,
    peer: SocketAddr,
    accepted_at: Instant,
    owner: String,
    cursor: u64,
}

#[derive(Clone, Debug)]
struct ReverseAttach {
    endpoint_id: String,
    conn_id: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ReverseAcceptConn {
    id: String,
    peer: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ReverseAcceptResponse {
    conns: Vec<ReverseAcceptConn>,
    cursor: u64,
}

enum ReverseAccess<T> {
    Ready(T),
    Unknown,
    Conflict,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WireVersion {
    V1,
    V2,
}

struct VersionClaim {
    version: WireVersion,
    route: String,
    generation: u64,
    state: ClaimState,
}

enum ClaimState {
    Opening {
        started: Instant,
        done: tokio::sync::watch::Sender<u64>,
    },
    Ready,
}

enum OpenClaim {
    Owner {
        generation: u64,
        admission: tokio::sync::OwnedSemaphorePermit,
    },
    Wait(tokio::sync::watch::Receiver<u64>),
    Opening,
    Ready,
    Conflict,
    Limited,
}

enum V2Entry {
    Opening {
        route: String,
        generation: u64,
        started: Instant,
    },
    Ready {
        route: String,
        generation: u64,
        tx: tokio::sync::mpsc::Sender<V2Command>,
        batch_limit: usize,
        up_inflight: Arc<std::sync::Mutex<Option<(u64, Bytes)>>>,
        last: Arc<std::sync::Mutex<Instant>>,
    },
}

#[derive(Clone)]
struct ServerOpts {
    echo_all: bool,
    keepalive: Duration,
    timeout: Duration,
    poll_wait: Duration,
    dashboard: Option<DashboardBackend>,
    auth_token: Option<Arc<str>>,
    max_sessions: usize,
    routes: Arc<HashMap<String, Route>>,
    admission: Arc<tokio::sync::Semaphore>,
    claims: VersionClaims,
    next_generation: Arc<AtomicU64>,
    reverse_diagnostics: Option<ReverseDiagnosticJobs>,
    experimental_reverse_batches: bool,
}

#[derive(Clone)]
struct DashboardBackend {
    base: reqwest::Url,
    client: reqwest::Client,
    progress_timeout: Duration,
}

async fn start_reverse_endpoints(
    configs: &[ReverseEndpointConfig],
    max_pending: usize,
) -> Result<ReverseRegistry> {
    let mut listeners = Vec::with_capacity(configs.len());
    let mut endpoints = HashMap::with_capacity(configs.len());
    for config in configs {
        validate_reverse_id(&config.id, "endpoint id").map_err(anyhow::Error::msg)?;
        if !config.bind.ip().is_loopback() {
            bail!(
                "reverse endpoint {} must bind a loopback address",
                config.id
            );
        }
        if endpoints.contains_key(&config.id) {
            bail!("duplicate reverse endpoint {}", config.id);
        }
        let listener = TcpListener::bind(config.bind).await.with_context(|| {
            format!("binding reverse endpoint {} on {}", config.id, config.bind)
        })?;
        endpoints.insert(
            config.id.clone(),
            ReverseEndpoint {
                bind: config.bind,
                owner: None,
                cursor: 0,
                conns: HashMap::new(),
                notify: Arc::new(tokio::sync::Notify::new()),
            },
        );
        listeners.push((config.id.clone(), listener));
    }
    let registry = Arc::new(tokio::sync::Mutex::new(ReverseState {
        endpoints,
        pending: 0,
        max_pending,
    }));
    for (endpoint_id, listener) in listeners {
        let registry = registry.clone();
        tokio::spawn(reverse_accept_loop(endpoint_id, listener, registry));
    }
    spawn_reverse_sweeper(registry.clone());
    Ok(registry)
}

fn expire_reverse_endpoint(endpoint: &mut ReverseEndpoint, now: Instant) -> usize {
    let before = endpoint.conns.len();
    endpoint
        .conns
        .retain(|_, conn| now.duration_since(conn.accepted_at) <= REVERSE_PENDING_IDLE);
    if endpoint
        .owner
        .as_ref()
        .map(|owner| now.duration_since(owner.last_seen) > REVERSE_OWNER_IDLE)
        .unwrap_or(false)
    {
        endpoint.owner = None;
        endpoint.conns.clear();
    }
    before.saturating_sub(endpoint.conns.len())
}

async fn reverse_accept_loop(
    endpoint_id: String,
    listener: TcpListener,
    registry: ReverseRegistry,
) {
    let local = listener.local_addr().ok();
    log::info!("reverse endpoint {endpoint_id} listening on {local:?}");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(value) => value,
            Err(error) => {
                log::warn!("reverse endpoint {endpoint_id} accept failed: {error}");
                continue;
            }
        };
        let now = Instant::now();
        let mut state = registry.lock().await;
        let removed = match state.endpoints.get_mut(&endpoint_id) {
            Some(endpoint) => expire_reverse_endpoint(endpoint, now),
            None => return,
        };
        state.pending = state.pending.saturating_sub(removed);
        if state.pending >= state.max_pending {
            log::warn!("reverse pending connection limit reached; dropping {peer}");
            continue;
        }
        let inserted = if let Some(endpoint) = state.endpoints.get_mut(&endpoint_id) {
            if let Some(owner) = endpoint.owner.as_ref() {
                endpoint.cursor = endpoint.cursor.saturating_add(1);
                let cursor = endpoint.cursor;
                let conn_id = new_sid();
                endpoint.conns.insert(
                    conn_id.clone(),
                    AcceptedReverseConn {
                        stream,
                        peer,
                        accepted_at: now,
                        owner: owner.id.clone(),
                        cursor,
                    },
                );
                diagnostic_event(
                    "reverse_accept",
                    serde_json::json!({
                        "endpoint_id": endpoint_id,
                        "conn_id": conn_id,
                        "peer": peer.to_string(),
                    }),
                );
                log::debug!("reverse endpoint {endpoint_id} accepted {peer} as {conn_id}");
                Some(endpoint.notify.clone())
            } else {
                None
            }
        } else {
            return;
        };
        if let Some(notify) = inserted {
            state.pending += 1;
            drop(state);
            notify.notify_one();
        }
    }
}

fn spawn_reverse_sweeper(registry: ReverseRegistry) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REVERSE_SWEEP_INTERVAL).await;
            let now = Instant::now();
            let mut state = registry.lock().await;
            let removed = state
                .endpoints
                .values_mut()
                .map(|endpoint| expire_reverse_endpoint(endpoint, now))
                .sum::<usize>();
            state.pending = state.pending.saturating_sub(removed);
        }
    });
}

async fn claim_reverse_endpoint(
    registry: &ReverseRegistry,
    endpoint_id: &str,
    owner_id: &str,
) -> ReverseAccess<()> {
    let now = Instant::now();
    let mut state = registry.lock().await;
    let removed = match state.endpoints.get_mut(endpoint_id) {
        Some(endpoint) => expire_reverse_endpoint(endpoint, now),
        None => return ReverseAccess::Unknown,
    };
    state.pending = state.pending.saturating_sub(removed);
    let endpoint = match state.endpoints.get_mut(endpoint_id) {
        Some(endpoint) => endpoint,
        None => return ReverseAccess::Unknown,
    };
    match endpoint.owner.as_mut() {
        Some(owner) if owner.id == owner_id => {
            owner.last_seen = now;
            ReverseAccess::Ready(())
        }
        Some(_) => ReverseAccess::Conflict,
        None => {
            endpoint.owner = Some(ReverseOwner {
                id: owner_id.to_owned(),
                last_seen: now,
            });
            ReverseAccess::Ready(())
        }
    }
}

async fn reverse_snapshot(
    registry: &ReverseRegistry,
    endpoint_id: &str,
    owner_id: &str,
    after: u64,
) -> ReverseAccess<(ReverseAcceptResponse, bool)> {
    let now = Instant::now();
    let mut state = registry.lock().await;
    let removed = match state.endpoints.get_mut(endpoint_id) {
        Some(endpoint) => expire_reverse_endpoint(endpoint, now),
        None => return ReverseAccess::Unknown,
    };
    state.pending = state.pending.saturating_sub(removed);
    let endpoint = match state.endpoints.get_mut(endpoint_id) {
        Some(endpoint) => endpoint,
        None => return ReverseAccess::Unknown,
    };
    match endpoint.owner.as_mut() {
        Some(owner) if owner.id == owner_id => owner.last_seen = now,
        _ => return ReverseAccess::Conflict,
    }
    let mut conns = endpoint
        .conns
        .iter()
        .filter(|(_, conn)| conn.owner == owner_id && conn.cursor > after)
        .map(|(id, conn)| {
            diagnostic_event(
                "reverse_accept_delivered",
                serde_json::json!({
                    "endpoint_id": endpoint_id,
                    "conn_id": id,
                    "accept_wait_us": conn.accepted_at.elapsed().as_micros(),
                }),
            );
            (
                conn.cursor,
                ReverseAcceptConn {
                    id: id.clone(),
                    peer: conn.peer.to_string(),
                },
            )
        })
        .collect::<Vec<_>>();
    conns.sort_by_key(|(cursor, _)| *cursor);
    let ready = endpoint.cursor > after;
    ReverseAccess::Ready((
        ReverseAcceptResponse {
            conns: conns.into_iter().map(|(_, conn)| conn).collect(),
            cursor: endpoint.cursor,
        },
        ready,
    ))
}

async fn take_reverse_conn(
    registry: &ReverseRegistry,
    attach: &ReverseAttach,
    owner_id: &str,
) -> ReverseAccess<Option<TcpStream>> {
    let now = Instant::now();
    let mut state = registry.lock().await;
    let removed = match state.endpoints.get_mut(&attach.endpoint_id) {
        Some(endpoint) => expire_reverse_endpoint(endpoint, now),
        None => return ReverseAccess::Unknown,
    };
    state.pending = state.pending.saturating_sub(removed);
    let endpoint = match state.endpoints.get_mut(&attach.endpoint_id) {
        Some(endpoint) => endpoint,
        None => return ReverseAccess::Unknown,
    };
    match endpoint.owner.as_mut() {
        Some(owner) if owner.id == owner_id => owner.last_seen = now,
        _ => return ReverseAccess::Conflict,
    }
    let stream = endpoint.conns.remove(&attach.conn_id).and_then(|conn| {
        if conn.owner == owner_id {
            diagnostic_event(
                "reverse_attach",
                serde_json::json!({
                    "endpoint_id": attach.endpoint_id,
                    "conn_id": attach.conn_id,
                    "accept_to_attach_us": conn.accepted_at.elapsed().as_micros(),
                }),
            );
            Some(conn.stream)
        } else {
            None
        }
    });
    if stream.is_some() {
        state.pending = state.pending.saturating_sub(1);
    }
    ReverseAccess::Ready(stream)
}

async fn verify_reverse_owner(
    registry: &ReverseRegistry,
    endpoint_id: &str,
    owner_id: &str,
) -> ReverseAccess<()> {
    let now = Instant::now();
    let mut state = registry.lock().await;
    let removed = match state.endpoints.get_mut(endpoint_id) {
        Some(endpoint) => expire_reverse_endpoint(endpoint, now),
        None => return ReverseAccess::Unknown,
    };
    state.pending = state.pending.saturating_sub(removed);
    match state
        .endpoints
        .get(endpoint_id)
        .and_then(|endpoint| endpoint.owner.as_ref())
    {
        Some(owner) if owner.id == owner_id => ReverseAccess::Ready(()),
        _ => ReverseAccess::Conflict,
    }
}

fn parse_reverse_attach(route: &str) -> std::result::Result<Option<ReverseAttach>, ()> {
    let Some(rest) = route.strip_prefix("attach:") else {
        return Ok(None);
    };
    let mut parts = rest.split(':');
    let endpoint_id = parts.next().filter(|value| !value.is_empty()).ok_or(())?;
    let conn_id = parts.next().filter(|value| !value.is_empty()).ok_or(())?;
    if parts.next().is_some()
        || validate_reverse_id(endpoint_id, "endpoint id").is_err()
        || validate_reverse_id(conn_id, "connection id").is_err()
    {
        return Err(());
    }
    Ok(Some(ReverseAttach {
        endpoint_id: endpoint_id.to_owned(),
        conn_id: conn_id.to_owned(),
    }))
}

async fn handle_reverse_diagnostic_run(
    req: Request<Incoming>,
    reverse: &ReverseRegistry,
    v2reg: &V2Registry,
    opts: &ServerOpts,
) -> Response<BoxBody> {
    let Some(jobs) = opts.reverse_diagnostics.as_ref() else {
        return reverse_text_resp(StatusCode::NOT_FOUND, "not found\n");
    };
    let body = match read_v2_body(req.into_body()).await {
        Ok(body) => body,
        Err(_) => return reverse_text_resp(StatusCode::BAD_REQUEST, "invalid request\n"),
    };
    let request: ReverseDiagnosticRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return reverse_text_resp(StatusCode::BAD_REQUEST, "invalid request\n"),
    };
    if validate_reverse_id(&request.endpoint_id, "endpoint id").is_err()
        || validate_reverse_id(&request.run_id, "run id").is_err()
        || request.run_id.len() > 64
        || !matches!(
            request.profile.as_str(),
            "A-v2-baseline" | "B-batch-64" | "B-batch-128" | "B-batch-256"
        )
        || !(1..=3).contains(&request.passes)
    {
        return reverse_text_resp(StatusCode::BAD_REQUEST, "invalid request\n");
    }
    let bind = {
        let state = reverse.lock().await;
        match state.endpoints.get(&request.endpoint_id) {
            Some(endpoint) if endpoint.owner.is_some() => endpoint.bind,
            Some(_) => return reverse_text_resp(StatusCode::CONFLICT, "endpoint not claimed\n"),
            None => return reverse_text_resp(StatusCode::NOT_FOUND, "unknown endpoint\n"),
        }
    };
    {
        let mut jobs = jobs.lock().await;
        if jobs.contains_key(&request.run_id) {
            return reverse_text_resp(StatusCode::CONFLICT, "run already exists\n");
        }
        if jobs.values().filter(|job| job.status == "running").count() >= 1 {
            return reverse_text_resp(StatusCode::TOO_MANY_REQUESTS, "diagnostic run active\n");
        }
        if jobs.len() >= 16 {
            if let Some(oldest) = jobs
                .iter()
                .filter(|(_, job)| job.status != "running")
                .min_by_key(|(_, job)| job.started_unix_ms)
                .map(|(run_id, _)| run_id.clone())
            {
                jobs.remove(&oldest);
            } else {
                return reverse_text_resp(StatusCode::TOO_MANY_REQUESTS, "job limit reached\n");
            }
        }
        jobs.insert(
            request.run_id.clone(),
            ReverseDiagnosticJob {
                schema: 1,
                profile: request.profile.clone(),
                endpoint_id: request.endpoint_id.clone(),
                run_id: request.run_id.clone(),
                status: "running",
                started_unix_ms: unix_time_ms(),
                finished_unix_ms: None,
                completed_checks: 0,
                failed_checks: 0,
                skipped_checks: vec![
                    "transport_fault_injection_local_only",
                    "packet_capture_optional",
                ],
                error: None,
                measurements: Vec::new(),
                resources: Vec::new(),
            },
        );
    }
    let jobs_for_task = jobs.clone();
    let jobs_for_sampler = jobs.clone();
    let reverse_for_sampler = reverse.clone();
    let v2reg_for_sampler = v2reg.clone();
    let request_for_task = request.clone();
    let sampler_run_id = request.run_id.clone();
    let (stop_sampler, mut sampler_stopped) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let sample = reverse_diagnostic_resource_sample(
                        &v2reg_for_sampler,
                        &reverse_for_sampler,
                    ).await;
                    if let Some(job) = jobs_for_sampler.lock().await.get_mut(&sampler_run_id) {
                        job.resources.push(sample);
                    }
                }
                _ = &mut sampler_stopped => break,
            }
        }
    });
    tokio::spawn(async move {
        let result = run_reverse_diagnostic_suite(bind, &request_for_task).await;
        let _ = stop_sampler.send(());
        let mut jobs = jobs_for_task.lock().await;
        let Some(job) = jobs.get_mut(&request_for_task.run_id) else {
            return;
        };
        job.finished_unix_ms = Some(unix_time_ms());
        match result {
            Ok(measurements) => {
                job.completed_checks = measurements.len();
                job.failed_checks = measurements.iter().filter(|item| !item.ok).count();
                job.measurements = measurements;
                job.status = "complete";
            }
            Err(error) => {
                job.status = "error";
                job.error = Some(error.to_string());
            }
        }
    });
    reverse_json_status(
        StatusCode::ACCEPTED,
        &serde_json::json!({
            "run_id": request.run_id,
            "status": "running",
        }),
    )
}

async fn reverse_diagnostic_resource_sample(
    v2reg: &V2Registry,
    reverse: &ReverseRegistry,
) -> ReverseDiagnosticResourceSample {
    let v2_sessions = v2reg.lock().await.len();
    let reverse_pending = reverse.lock().await.pending;
    let (rss_kib, cpu_ticks) = read_linux_process_resources().await;
    ReverseDiagnosticResourceSample {
        unix_ms: unix_time_ms(),
        v2_sessions,
        reverse_pending,
        rss_kib,
        cpu_ticks,
        http_connections_total: HTTP_CONNECTIONS_TOTAL.load(Relaxed),
        http_connections_active: HTTP_CONNECTIONS_ACTIVE.load(Relaxed),
        http_gets: HTTP_GETS.load(Relaxed),
        http_posts: HTTP_POSTS.load(Relaxed),
    }
}

async fn read_linux_process_resources() -> (Option<u64>, Option<u64>) {
    let rss_kib = match tokio::fs::read_to_string("/proc/self/status").await {
        Ok(status) => status.lines().find_map(|line| {
            line.strip_prefix("VmRSS:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        }),
        Err(_) => None,
    };
    let cpu_ticks = match tokio::fs::read_to_string("/proc/self/stat").await {
        Ok(stat) => stat.rsplit_once(") ").and_then(|(_, fields)| {
            let fields = fields.split_whitespace().collect::<Vec<_>>();
            let user = fields.get(11)?.parse::<u64>().ok()?;
            let system = fields.get(12)?.parse::<u64>().ok()?;
            Some(user.saturating_add(system))
        }),
        Err(_) => None,
    };
    (rss_kib, cpu_ticks)
}

async fn handle_reverse_diagnostic_status(
    req: Request<Incoming>,
    opts: &ServerOpts,
) -> Response<BoxBody> {
    let Some(jobs) = opts.reverse_diagnostics.as_ref() else {
        return reverse_text_resp(StatusCode::NOT_FOUND, "not found\n");
    };
    let Some(run_id) = query_param(req.uri(), "run") else {
        return reverse_text_resp(StatusCode::BAD_REQUEST, "missing run id\n");
    };
    if validate_reverse_id(&run_id, "run id").is_err() {
        return reverse_text_resp(StatusCode::BAD_REQUEST, "invalid run id\n");
    }
    let job = jobs.lock().await.get(&run_id).cloned();
    match job {
        Some(job) => reverse_json_resp(&job),
        None => reverse_text_resp(StatusCode::NOT_FOUND, "unknown run\n"),
    }
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

async fn run_reverse_diagnostic_suite(
    bind: SocketAddr,
    request: &ReverseDiagnosticRequest,
) -> Result<Vec<ReverseDiagnosticMeasurement>> {
    let mut measurements = Vec::new();
    for pass in 1..=request.passes {
        for index in 0..10usize {
            let test_id = format!("{}-p{pass}-short-{index}", request.run_id);
            measurements.push(
                run_reverse_diagnostic_exchange(
                    bind,
                    pass,
                    "short_sequential",
                    test_id,
                    1,
                    "exchange",
                    256,
                    0,
                    0,
                    false,
                    false,
                )
                .await,
            );
        }
        for concurrency in [1usize, 8, 32] {
            let mut tasks = tokio::task::JoinSet::new();
            for index in 0..concurrency {
                let test_id = format!("{}-p{pass}-parallel-{concurrency}-{index}", request.run_id);
                tasks.spawn(run_reverse_diagnostic_exchange(
                    bind,
                    pass,
                    "parallel_short",
                    test_id,
                    concurrency,
                    "exchange",
                    256,
                    0,
                    0,
                    false,
                    false,
                ));
            }
            while let Some(result) = tasks.join_next().await {
                measurements.push(result.context("parallel diagnostic task failed")?);
            }
        }
        for bytes in [64 * 1024usize, 1024 * 1024] {
            let test_id = format!("{}-p{pass}-download-{bytes}", request.run_id);
            measurements.push(
                run_reverse_diagnostic_exchange(
                    bind, pass, "download", test_id, 1, "download", bytes, 0, 0, false, false,
                )
                .await,
            );
            let test_id = format!("{}-p{pass}-upload-{bytes}", request.run_id);
            measurements.push(
                run_reverse_diagnostic_exchange(
                    bind, pass, "upload", test_id, 1, "upload", bytes, 0, 0, false, false,
                )
                .await,
            );
        }

        let background_id = format!("{}-p{pass}-background", request.run_id);
        let background = tokio::spawn(run_reverse_diagnostic_exchange(
            bind,
            pass,
            "background_download",
            background_id,
            1,
            "download",
            2 * 1024 * 1024,
            16 * 1024,
            2,
            false,
            false,
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut foreground = tokio::task::JoinSet::new();
        for index in 0..8usize {
            foreground.spawn(run_reverse_diagnostic_exchange(
                bind,
                pass,
                "short_with_background",
                format!("{}-p{pass}-foreground-{index}", request.run_id),
                8,
                "exchange",
                256,
                0,
                0,
                false,
                false,
            ));
        }
        while let Some(result) = foreground.join_next().await {
            measurements.push(result.context("foreground diagnostic task failed")?);
        }
        measurements.push(
            background
                .await
                .context("background diagnostic task failed")?,
        );

        measurements.push(
            run_reverse_diagnostic_idle(bind, pass, format!("{}-p{pass}-idle", request.run_id))
                .await,
        );
        let slow_receiver = tokio::spawn(run_reverse_diagnostic_exchange(
            bind,
            pass,
            "slow_receiver",
            format!("{}-p{pass}-slow", request.run_id),
            1,
            "download",
            512 * 1024,
            8 * 1024,
            0,
            true,
            false,
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut slow_neighbors = tokio::task::JoinSet::new();
        for index in 0..8usize {
            slow_neighbors.spawn(run_reverse_diagnostic_exchange(
                bind,
                pass,
                "short_with_slow_receiver",
                format!("{}-p{pass}-slow-neighbor-{index}", request.run_id),
                8,
                "exchange",
                256,
                0,
                0,
                false,
                false,
            ));
        }
        while let Some(result) = slow_neighbors.join_next().await {
            measurements.push(result.context("slow-neighbor diagnostic task failed")?);
        }
        measurements.push(
            slow_receiver
                .await
                .context("slow-receiver diagnostic task failed")?,
        );
        measurements.push(
            run_reverse_diagnostic_exchange(
                bind,
                pass,
                "half_close",
                format!("{}-p{pass}-half-close", request.run_id),
                1,
                "download",
                64 * 1024,
                0,
                0,
                false,
                true,
            )
            .await,
        );
        measurements.push(
            run_reverse_diagnostic_exchange(
                bind,
                pass,
                "reset",
                format!("{}-p{pass}-reset", request.run_id),
                1,
                "reset",
                0,
                0,
                0,
                false,
                false,
            )
            .await,
        );
    }
    Ok(measurements)
}

#[allow(clippy::too_many_arguments)]
async fn run_reverse_diagnostic_exchange(
    bind: SocketAddr,
    pass: u8,
    scenario: &'static str,
    test_id: String,
    concurrency: usize,
    command: &'static str,
    bytes: usize,
    chunk_bytes: usize,
    delay_ms: u64,
    slow_receiver: bool,
    half_close: bool,
) -> ReverseDiagnosticMeasurement {
    let started = Instant::now();
    let expected_failure = command == "reset";
    let result = tokio::time::timeout(Duration::from_secs(120), async {
        let connect_started = Instant::now();
        let mut stream = TcpStream::connect(bind)
            .await
            .context("connecting reverse diagnostic endpoint")?;
        let connect_us = connect_started.elapsed().as_micros();
        let request = DiagnosticTargetRequest {
            command,
            test_id: &test_id,
            bytes,
            chunk_bytes: if chunk_bytes == 0 {
                16 * 1024
            } else {
                chunk_bytes
            },
            delay_ms,
            first_delay_ms: 0,
        };
        write_diagnostic_target_request(&mut stream, &request).await?;
        let mut bytes_up = 0usize;
        if command == "upload" || command == "exchange" {
            write_diagnostic_pattern(&mut stream, bytes).await?;
            bytes_up = bytes;
        }
        if half_close {
            stream
                .shutdown()
                .await
                .context("half-closing diagnostic stream")?;
        }
        let response_started = Instant::now();
        let response = read_diagnostic_target_response(&mut stream).await;
        if expected_failure {
            return match response {
                Err(_) => Ok((
                    connect_us,
                    Some(response_started.elapsed().as_micros()),
                    0,
                    0,
                )),
                Ok(_) => bail!("reset target returned a response"),
            };
        }
        let (response, first_byte_us) = response?;
        if !response.ok || response.bytes != bytes {
            bail!("diagnostic target rejected data");
        }
        let bytes_down = if command == "download" || command == "exchange" {
            read_diagnostic_pattern(&mut stream, response.bytes, slow_receiver).await?;
            response.bytes
        } else {
            0
        };
        Ok((connect_us, Some(first_byte_us), bytes_up, bytes_down))
    })
    .await;

    let (ok, error, connect_us, first_byte_us, bytes_up, bytes_down) = match result {
        Ok(Ok((connect_us, first_byte_us, bytes_up, bytes_down))) => {
            (true, None, connect_us, first_byte_us, bytes_up, bytes_down)
        }
        Ok(Err(error)) => {
            log::debug!("reverse diagnostic {scenario} failed: {error}");
            (
                false,
                Some(classify_diagnostic_error(&error)),
                0,
                None,
                0,
                0,
            )
        }
        Err(_) => (false, Some("timeout"), 0, None, 0, 0),
    };
    diagnostic_event(
        "reverse_diagnostic_measurement",
        serde_json::json!({
            "run_id": test_id.split("-p").next().unwrap_or_default(),
            "test_id": test_id,
            "scenario": scenario,
            "pass": pass,
            "concurrency": concurrency,
            "ok": ok,
            "expected_failure": expected_failure,
            "connect_us": connect_us,
            "first_byte_us": first_byte_us,
            "total_us": started.elapsed().as_micros(),
            "bytes_up": bytes_up,
            "bytes_down": bytes_down,
        }),
    );
    ReverseDiagnosticMeasurement {
        pass,
        scenario,
        test_id,
        concurrency,
        ok,
        expected_failure,
        error,
        connect_us,
        first_byte_us,
        total_us: started.elapsed().as_micros(),
        bytes_up,
        bytes_down,
    }
}

async fn run_reverse_diagnostic_idle(
    bind: SocketAddr,
    pass: u8,
    test_id: String,
) -> ReverseDiagnosticMeasurement {
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let connect_started = Instant::now();
        let mut stream = TcpStream::connect(bind).await?;
        let connect_us = connect_started.elapsed().as_micros();
        for suffix in ["before", "after"] {
            let command_id = format!("{test_id}-{suffix}");
            write_diagnostic_target_request(
                &mut stream,
                &DiagnosticTargetRequest {
                    command: "exchange",
                    test_id: &command_id,
                    bytes: 256,
                    chunk_bytes: 16 * 1024,
                    delay_ms: 0,
                    first_delay_ms: 0,
                },
            )
            .await?;
            write_diagnostic_pattern(&mut stream, 256).await?;
            let (response, _) = read_diagnostic_target_response(&mut stream).await?;
            if !response.ok || response.bytes != 256 {
                bail!("idle target response mismatch");
            }
            read_diagnostic_pattern(&mut stream, 256, false).await?;
            if suffix == "before" {
                tokio::time::sleep(Duration::from_secs(6)).await;
            }
        }
        Ok::<_, anyhow::Error>(connect_us)
    })
    .await;
    let (ok, error, connect_us) = match result {
        Ok(Ok(connect_us)) => (true, None, connect_us),
        Ok(Err(error)) => {
            log::debug!("reverse diagnostic idle failed: {error}");
            (false, Some(classify_diagnostic_error(&error)), 0)
        }
        Err(_) => (false, Some("timeout"), 0),
    };
    ReverseDiagnosticMeasurement {
        pass,
        scenario: "idle_resume",
        test_id,
        concurrency: 1,
        ok,
        expected_failure: false,
        error,
        connect_us,
        first_byte_us: None,
        total_us: started.elapsed().as_micros(),
        bytes_up: if ok { 512 } else { 0 },
        bytes_down: if ok { 512 } else { 0 },
    }
}

async fn write_diagnostic_target_request(
    stream: &mut TcpStream,
    request: &DiagnosticTargetRequest<'_>,
) -> Result<()> {
    let mut line = serde_json::to_vec(request).context("encoding diagnostic request")?;
    if line.len() > 4095 {
        bail!("diagnostic request is too large");
    }
    line.push(b'\n');
    stream
        .write_all(&line)
        .await
        .context("writing diagnostic request")
}

async fn read_diagnostic_target_response(
    stream: &mut TcpStream,
) -> Result<(DiagnosticTargetResponse, u128)> {
    let started = Instant::now();
    let mut line = Vec::with_capacity(256);
    let mut first_byte_us = None;
    loop {
        let mut byte = [0u8; 1];
        let count = stream
            .read(&mut byte)
            .await
            .context("reading diagnostic response")?;
        if count == 0 {
            bail!("diagnostic response EOF");
        }
        first_byte_us.get_or_insert_with(|| started.elapsed().as_micros());
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= 4095 {
            bail!("diagnostic response header is too large");
        }
        line.push(byte[0]);
    }
    let response = serde_json::from_slice(&line).context("decoding diagnostic response")?;
    Ok((response, first_byte_us.unwrap_or_default()))
}

async fn write_diagnostic_pattern(stream: &mut TcpStream, bytes: usize) -> Result<()> {
    let mut offset = 0usize;
    let mut buffer = vec![0u8; 16 * 1024];
    while offset < bytes {
        let count = (bytes - offset).min(buffer.len());
        for (index, byte) in buffer[..count].iter_mut().enumerate() {
            *byte = ((offset + index) % 251) as u8;
        }
        stream
            .write_all(&buffer[..count])
            .await
            .context("writing diagnostic payload")?;
        offset += count;
    }
    Ok(())
}

async fn read_diagnostic_pattern(
    stream: &mut TcpStream,
    bytes: usize,
    slow_receiver: bool,
) -> Result<()> {
    let mut offset = 0usize;
    let mut buffer = vec![0u8; if slow_receiver { 4 * 1024 } else { 32 * 1024 }];
    while offset < bytes {
        let capacity = buffer.len();
        let count = stream
            .read(&mut buffer[..(bytes - offset).min(capacity)])
            .await
            .context("reading diagnostic payload")?;
        if count == 0 {
            bail!("diagnostic payload EOF");
        }
        if buffer[..count]
            .iter()
            .enumerate()
            .any(|(index, byte)| *byte != ((offset + index) % 251) as u8)
        {
            bail!("diagnostic payload mismatch");
        }
        offset += count;
        if slow_receiver {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    Ok(())
}

fn classify_diagnostic_error(error: &anyhow::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("mismatch") || message.contains("rejected") {
        "integrity"
    } else if message.contains("EOF") {
        "eof"
    } else if message.contains("connect") {
        "connect"
    } else if message.contains("decode") {
        "protocol"
    } else {
        "io"
    }
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
    if cfg.reverse_diagnostics && cfg.auth_token.is_none() {
        bail!("reverse diagnostics require --auth-token");
    }
    let tls = build_server_tls(&cfg).context("building TLS config")?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let local = listener.local_addr().ok();
    let reverse = start_reverse_endpoints(&cfg.reverse, cfg.max_sessions.max(1)).await?;

    let routes: HashMap<String, Route> = cfg
        .routes
        .iter()
        .map(|r| (r.id.clone(), r.clone()))
        .collect();

    let reg: Registry = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let v2reg: V2Registry = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let claims: VersionClaims = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let dashboard = cfg
        .dashboard_backend
        .as_deref()
        .map(DashboardBackend::new)
        .transpose()?;
    let opts = ServerOpts {
        echo_all: cfg.echo_all,
        keepalive: cfg.keepalive,
        timeout: cfg.timeout,
        poll_wait: cfg.poll_wait,
        dashboard,
        auth_token: cfg.auth_token.as_deref().map(Arc::from),
        max_sessions: cfg.max_sessions.max(1),
        routes: Arc::new(routes),
        admission: Arc::new(tokio::sync::Semaphore::new(cfg.max_sessions.max(1))),
        claims,
        next_generation: Arc::new(AtomicU64::new(1)),
        reverse_diagnostics: cfg
            .reverse_diagnostics
            .then(|| Arc::new(tokio::sync::Mutex::new(HashMap::new()))),
        experimental_reverse_batches: cfg.experimental_reverse_batches,
    };

    spawn_sweeper(reg.clone(), opts.claims.clone());
    spawn_v2_sweeper(v2reg.clone(), opts.claims.clone());
    spawn_claim_sweeper(opts.claims.clone());
    if DIAGNOSTICS.get().is_some() {
        spawn_diagnostic_sampler(reg.clone(), v2reg.clone(), reverse.clone(), opts.clone());
    }

    log::info!(
        "httptun-server listening on {:?} (mode hint={}, echo_all={}, auth={}, dashboard={}, routes={}, reverse={}, reverse_diagnostics={}, experimental_reverse_batches={}, max_sessions={})",
        local,
        cfg.mode.as_str(),
        cfg.echo_all,
        opts.auth_token.is_some(),
        opts.dashboard.is_some(),
        opts.routes.len(),
        cfg.reverse.len(),
        opts.reverse_diagnostics.is_some(),
        opts.experimental_reverse_batches,
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
        HTTP_CONNECTIONS_TOTAL.fetch_add(1, Relaxed);
        HTTP_CONNECTIONS_ACTIVE.fetch_add(1, Relaxed);
        let acceptor = acceptor.clone();
        let reg = reg.clone();
        let v2reg = v2reg.clone();
        let reverse = reverse.clone();
        let opts = opts.clone();
        tokio::spawn(async move {
            let _connection_guard = HttpConnectionGuard;
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    log::debug!("tls handshake from {peer} failed: {e}");
                    return;
                }
            };
            let io = TokioIo::new(tls);
            let v2reg = v2reg.clone();
            let reverse = reverse.clone();
            let service = service_fn(move |req| {
                handle(
                    req,
                    reg.clone(),
                    v2reg.clone(),
                    reverse.clone(),
                    opts.clone(),
                )
            });
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

fn spawn_diagnostic_sampler(
    reg: Registry,
    v2reg: V2Registry,
    reverse: ReverseRegistry,
    opts: ServerOpts,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let v1_sessions = reg.lock().await.len();
            let (v2_opening, v2_ready) = {
                let guard = v2reg.lock().await;
                guard
                    .values()
                    .fold((0usize, 0usize), |(opening, ready), entry| match entry {
                        V2Entry::Opening { .. } => (opening + 1, ready),
                        V2Entry::Ready { .. } => (opening, ready + 1),
                    })
            };
            let (reverse_pending, reverse_owned) = {
                let state = reverse.lock().await;
                (
                    state.pending,
                    state
                        .endpoints
                        .values()
                        .filter(|endpoint| endpoint.owner.is_some())
                        .count(),
                )
            };
            diagnostic_event(
                "server_snapshot",
                serde_json::json!({
                    "v1_sessions": v1_sessions,
                    "v2_opening": v2_opening,
                    "v2_ready": v2_ready,
                    "reverse_pending": reverse_pending,
                    "reverse_owned": reverse_owned,
                    "admission_used": opts.max_sessions.saturating_sub(opts.admission.available_permits()),
                    "counters": {
                        "retries": V2_COUNTERS.retries.load(Relaxed),
                        "upstream_duplicates": V2_COUNTERS.upstream_duplicates.load(Relaxed),
                        "downstream_replays": V2_COUNTERS.downstream_replays.load(Relaxed),
                        "sequence_conflicts": V2_COUNTERS.sequence_conflicts.load(Relaxed),
                        "session_losses": V2_COUNTERS.session_losses.load(Relaxed),
                    },
                }),
            );
        }
    });
}

fn spawn_sweeper(reg: Registry, claims: VersionClaims) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut g = reg.lock().await;
            let mut expired = Vec::new();
            g.retain(|sid, s| {
                let idle = s.last.lock().map(|t| t.elapsed()).unwrap_or_default();
                let drop = s.closed.load(Relaxed) || idle > SESSION_IDLE;
                if drop {
                    if let Some(generation) = s.v1_generation {
                        expired.push((sid.clone(), generation));
                    }
                    s.closed.store(true, Relaxed);
                    log::debug!("sweeping session {sid} (target {})", s.target);
                }
                !drop
            });
            drop(g);
            if !expired.is_empty() {
                let mut claims = claims.lock().await;
                for (sid, generation) in expired {
                    if matches!(claims.get(&sid), Some(VersionClaim { version: WireVersion::V1, generation: current, state: ClaimState::Ready, .. }) if *current == generation)
                    {
                        claims.remove(&sid);
                    }
                }
            }
        }
    });
}

fn spawn_v2_sweeper(reg: V2Registry, claims: VersionClaims) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut guard = reg.lock().await;
            let mut expired = Vec::new();
            guard.retain(|sid, entry| match entry {
                V2Entry::Opening {
                    started,
                    generation,
                    ..
                } => {
                    let keep = started.elapsed() <= OPENING_IDLE;
                    if !keep {
                        expired.push((sid.clone(), *generation));
                    }
                    keep
                }
                V2Entry::Ready { last, .. } => {
                    let keep = last
                        .lock()
                        .map(|time| time.elapsed() <= SESSION_IDLE)
                        .unwrap_or(false);
                    if !keep {
                        expired.push((sid.clone(), v2_entry_generation(entry)));
                    }
                    keep
                }
            });
            drop(guard);
            if !expired.is_empty() {
                let mut claims = claims.lock().await;
                for (sid, generation) in expired {
                    if matches!(claims.get(&sid), Some(VersionClaim { version: WireVersion::V2, generation: current, .. }) if *current == generation)
                    {
                        if let Some(VersionClaim {
                            state: ClaimState::Opening { done, .. },
                            ..
                        }) = claims.remove(&sid)
                        {
                            done.send_replace(generation);
                        }
                    }
                }
            }
        }
    });
}

fn v2_entry_generation(entry: &V2Entry) -> u64 {
    match entry {
        V2Entry::Opening { generation, .. } | V2Entry::Ready { generation, .. } => *generation,
    }
}

fn spawn_claim_sweeper(claims: VersionClaims) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut claims = claims.lock().await;
            let stale: Vec<_> = claims
                .iter()
                .filter_map(|(sid, claim)| match &claim.state {
                    ClaimState::Opening { started, .. }
                        if claim.version == WireVersion::V1 && started.elapsed() > OPENING_IDLE =>
                    {
                        Some((sid.clone(), claim.generation))
                    }
                    _ => None,
                })
                .collect();
            for (sid, generation) in stale {
                if matches!(claims.get(&sid), Some(VersionClaim { generation: current, state: ClaimState::Opening { .. }, .. }) if *current == generation)
                {
                    if let Some(VersionClaim {
                        state: ClaimState::Opening { done, .. },
                        ..
                    }) = claims.remove(&sid)
                    {
                        done.send_replace(generation);
                    }
                }
            }
        }
    });
}

async fn handle(
    req: Request<Incoming>,
    reg: Registry,
    v2reg: V2Registry,
    reverse: ReverseRegistry,
    opts: ServerOpts,
) -> Result<Response<BoxBody>, Infallible> {
    let started = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let request_bytes = req
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    match &method {
        &Method::GET => {
            HTTP_GETS.fetch_add(1, Relaxed);
        }
        &Method::POST => {
            HTTP_POSTS.fetch_add(1, Relaxed);
        }
        _ => {}
    }
    log::debug!("--> {method} {path}");

    // Every /api/v1/* and /api/v2/* request must carry the shared bearer token (when set).
    if (path == "/api/v1"
        || path.starts_with("/api/v1/")
        || path == "/api/v2"
        || path.starts_with("/api/v2/"))
        && !authorized(&req, &opts)
    {
        let resp = if path == "/api/v2/reverse" || path.starts_with("/api/v2/reverse/") {
            reverse_text_resp(StatusCode::UNAUTHORIZED, "unauthorized\n")
        } else {
            text_resp(StatusCode::UNAUTHORIZED, "unauthorized\n")
        };
        log::debug!("<-- {method} {path} {}", resp.status());
        diagnostic_event(
            "http_request",
            serde_json::json!({
                "method": method.as_str(),
                "path": path,
                "status": resp.status().as_u16(),
                "request_bytes": request_bytes,
                "response_bytes": resp.body().size_hint().exact(),
                "duration_us": started.elapsed().as_micros(),
            }),
        );
        return Ok(resp);
    }

    let resp = if path == "/api/v2" || path.starts_with("/api/v2/") {
        match (&method, path.as_str()) {
            (&Method::POST, "/api/v2/session/open") => {
                handle_open_v2(req, &v2reg, &reg, &reverse, &opts).await
            }
            (&Method::POST, "/api/v2/session/send") => handle_up_v2(req, &v2reg).await,
            (&Method::GET, "/api/v2/session/recv") => handle_down_v2(req, &v2reg).await,
            (&Method::POST, "/api/v2/session/close") => handle_close_v2(req, &v2reg, &opts).await,
            (&Method::POST, "/api/v2/reverse/claim") => handle_reverse_claim(req, &reverse).await,
            (&Method::GET, "/api/v2/reverse/accept") => handle_reverse_accept(req, &reverse).await,
            (&Method::POST, "/api/v2/reverse/diagnostics/run") => {
                handle_reverse_diagnostic_run(req, &reverse, &v2reg, &opts).await
            }
            (&Method::GET, "/api/v2/reverse/diagnostics/status") => {
                handle_reverse_diagnostic_status(req, &opts).await
            }
            (_, "/api/v2/session/open") => method_not_allowed("POST", method == Method::HEAD),
            (_, "/api/v2/session/send") => method_not_allowed("POST", method == Method::HEAD),
            (_, "/api/v2/session/recv") => method_not_allowed("GET", method == Method::HEAD),
            (_, "/api/v2/session/close") => method_not_allowed("POST", method == Method::HEAD),
            (_, "/api/v2/reverse/claim") => {
                reverse_method_not_allowed("POST", method == Method::HEAD)
            }
            (_, "/api/v2/reverse/accept") => {
                reverse_method_not_allowed("GET", method == Method::HEAD)
            }
            (_, "/api/v2/reverse/diagnostics/run") => {
                reverse_method_not_allowed("POST", method == Method::HEAD)
            }
            (_, "/api/v2/reverse/diagnostics/status") => {
                reverse_method_not_allowed("GET", method == Method::HEAD)
            }
            (_, path) if path == "/api/v2/reverse" || path.starts_with("/api/v2/reverse/") => {
                reverse_text_resp(StatusCode::NOT_FOUND, "not found\n")
            }
            _ => neutral_resp(StatusCode::NOT_FOUND, method == Method::HEAD),
        }
    } else if path == "/api/v1" || path.starts_with("/api/v1/") {
        match (&method, path.as_str()) {
            (&Method::POST, "/api/v1/session/open") => {
                handle_open_v1(req, &reg, &v2reg, &opts).await
            }
            (&Method::POST, "/api/v1/session/send") => handle_up(req, &reg).await,
            (&Method::GET, "/api/v1/session/recv") => handle_down(req, &reg, &opts).await,
            (&Method::POST, "/api/v1/session/close") => handle_close(req, &reg, &opts).await,
            (_, "/api/v1/session/open") => method_not_allowed("POST", method == Method::HEAD),
            (_, "/api/v1/session/send") => method_not_allowed("POST", method == Method::HEAD),
            (_, "/api/v1/session/recv") => method_not_allowed("GET", method == Method::HEAD),
            (_, "/api/v1/session/close") => method_not_allowed("POST", method == Method::HEAD),
            _ => neutral_resp(StatusCode::NOT_FOUND, method == Method::HEAD),
        }
    } else if matches!(path.as_str(), "/o" | "/u" | "/d" | "/c") {
        neutral_resp(StatusCode::NOT_FOUND, method == Method::HEAD)
    } else if path == "/health" {
        match method {
            Method::GET => text_resp(StatusCode::OK, "ok\n"),
            Method::HEAD => neutral_resp(StatusCode::OK, true),
            _ => method_not_allowed("GET, HEAD", false),
        }
    } else if method == Method::CONNECT {
        method_not_allowed("GET, HEAD", false)
    } else if has_upgrade(req.headers()) {
        neutral_resp(StatusCode::BAD_REQUEST, method == Method::HEAD)
    } else if let Some(dashboard) = &opts.dashboard {
        match dashboard.forward(req).await {
            Ok(resp) => resp,
            Err(DashboardError::InvalidRequest) => {
                neutral_resp(StatusCode::BAD_REQUEST, method == Method::HEAD)
            }
            Err(DashboardError::Timeout) => {
                neutral_resp(StatusCode::GATEWAY_TIMEOUT, method == Method::HEAD)
            }
            Err(DashboardError::Unavailable) => {
                neutral_resp(StatusCode::BAD_GATEWAY, method == Method::HEAD)
            }
        }
    } else {
        neutral_resp(StatusCode::NOT_FOUND, method == Method::HEAD)
    };
    log::debug!("<-- {method} {path} {}", resp.status());
    diagnostic_event(
        "http_request",
        serde_json::json!({
            "method": method.as_str(),
            "path": path,
            "status": resp.status().as_u16(),
            "request_bytes": request_bytes,
            "response_bytes": resp.body().size_hint().exact(),
            "duration_us": started.elapsed().as_micros(),
        }),
    );
    Ok(resp)
}

fn neutral_resp(status: StatusCode, head: bool) -> Response<BoxBody> {
    if head {
        let mut response = Response::new(full(Bytes::new()));
        *response.status_mut() = status;
        response
    } else {
        text_resp(status, "\n")
    }
}

fn method_not_allowed(allow: &'static str, head: bool) -> Response<BoxBody> {
    let mut response = neutral_resp(StatusCode::METHOD_NOT_ALLOWED, head);
    response
        .headers_mut()
        .insert(http::header::ALLOW, http::HeaderValue::from_static(allow));
    response
}

fn reverse_method_not_allowed(allow: &'static str, head: bool) -> Response<BoxBody> {
    let mut response = if head {
        finite_resp(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            Bytes::new(),
        )
    } else {
        reverse_text_resp(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n")
    };
    response
        .headers_mut()
        .insert(http::header::ALLOW, http::HeaderValue::from_static(allow));
    response
}

fn reverse_params(req: &Request<Incoming>) -> Option<(String, String)> {
    let endpoint_id = query_param(req.uri(), "ep")
        .filter(|value| validate_reverse_id(value, "endpoint id").is_ok())?;
    let owner_id = query_param(req.uri(), "owner")
        .filter(|value| validate_reverse_id(value, "owner id").is_ok())?;
    Some((endpoint_id, owner_id))
}

async fn handle_reverse_claim(
    req: Request<Incoming>,
    registry: &ReverseRegistry,
) -> Response<BoxBody> {
    let (endpoint_id, owner_id) = match reverse_params(&req) {
        Some(value) => value,
        None => return reverse_text_resp(StatusCode::BAD_REQUEST, "invalid reverse parameters\n"),
    };
    match claim_reverse_endpoint(registry, &endpoint_id, &owner_id).await {
        ReverseAccess::Ready(()) => reverse_text_resp(StatusCode::OK, ""),
        ReverseAccess::Unknown => reverse_text_resp(StatusCode::NOT_FOUND, "unknown endpoint\n"),
        ReverseAccess::Conflict => {
            reverse_text_resp(StatusCode::CONFLICT, "endpoint owned by another client\n")
        }
    }
}

async fn handle_reverse_accept(
    req: Request<Incoming>,
    registry: &ReverseRegistry,
) -> Response<BoxBody> {
    let (endpoint_id, owner_id) = match reverse_params(&req) {
        Some(value) => value,
        None => return reverse_text_resp(StatusCode::BAD_REQUEST, "invalid reverse parameters\n"),
    };
    let after = match query_param(req.uri(), "after").and_then(|value| value.parse::<u64>().ok()) {
        Some(value) => value,
        None => return reverse_text_resp(StatusCode::BAD_REQUEST, "invalid cursor\n"),
    };
    let notify = {
        let state = registry.lock().await;
        match state.endpoints.get(&endpoint_id) {
            Some(endpoint) => endpoint.notify.clone(),
            None => return reverse_text_resp(StatusCode::NOT_FOUND, "unknown endpoint\n"),
        }
    };
    let deadline = tokio::time::Instant::now() + REVERSE_ACCEPT_WAIT;
    loop {
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let (response, ready) =
            match reverse_snapshot(registry, &endpoint_id, &owner_id, after).await {
                ReverseAccess::Ready(value) => value,
                ReverseAccess::Unknown => {
                    return reverse_text_resp(StatusCode::NOT_FOUND, "unknown endpoint\n")
                }
                ReverseAccess::Conflict => {
                    return reverse_text_resp(StatusCode::CONFLICT, "endpoint not owned\n")
                }
            };
        if ready || tokio::time::Instant::now() >= deadline {
            return reverse_json_resp(&response);
        }
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            return reverse_json_resp(&response);
        }
    }
}

enum DashboardError {
    InvalidRequest,
    Timeout,
    Unavailable,
}

impl DashboardBackend {
    fn new(value: &str) -> Result<Self> {
        let base = reqwest::Url::parse(value).context("invalid dashboard backend")?;
        let has_userinfo = value
            .split_once("://")
            .map(|(_, rest)| {
                let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                rest[..authority_end].contains('@')
            })
            .unwrap_or(false);
        let is_loopback = base
            .host_str()
            .map(|host| host.trim_matches(['[', ']']))
            .and_then(|host| host.parse::<IpAddr>().ok())
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
        if base.scheme() != "http"
            || !is_loopback
            || has_userinfo
            || !base.username().is_empty()
            || base.password().is_some()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
        {
            bail!("dashboard backend must be an http loopback URL with root path");
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .connect_timeout(DASHBOARD_CONNECT_TIMEOUT)
            .build()
            .context("building dashboard client")?;
        Ok(Self {
            base,
            client,
            progress_timeout: DASHBOARD_PROGRESS_TIMEOUT,
        })
    }

    async fn forward(
        &self,
        req: Request<Incoming>,
    ) -> std::result::Result<Response<BoxBody>, DashboardError> {
        let (parts, body) = req.into_parts();
        let url = self
            .url_for(&parts.uri)
            .ok_or(DashboardError::InvalidRequest)?;
        let head = parts.method == Method::HEAD;
        let headers = end_to_end_headers(&parts.headers, true);
        let (body, mut progress) = dashboard_body(body);
        let mut upstream = reqwest::Request::new(parts.method, url);
        *upstream.headers_mut() = headers;
        *upstream.body_mut() = Some(body);

        let send = self.client.execute(upstream);
        tokio::pin!(send);
        let deadline = tokio::time::sleep(self.progress_timeout);
        tokio::pin!(deadline);
        let mut upload_open = true;
        let response = loop {
            tokio::select! {
                result = &mut send => break result.map_err(|_| DashboardError::Unavailable)?,
                progress_update = progress.recv(), if upload_open => match progress_update {
                    Some(()) => deadline.as_mut().reset(tokio::time::Instant::now() + self.progress_timeout),
                    None => upload_open = false,
                },
                _ = &mut deadline => return Err(DashboardError::Timeout),
            }
        };
        Ok(proxy_response(response, head))
    }

    fn url_for(&self, uri: &Uri) -> Option<reqwest::Url> {
        if uri.scheme().is_some() || uri.authority().is_some() {
            return None;
        }
        let path_and_query = uri.path_and_query()?.as_str();
        if !path_and_query.starts_with('/') || path_and_query.starts_with("//") {
            return None;
        }
        reqwest::Url::parse(&format!(
            "{}{}",
            self.base.as_str().trim_end_matches('/'),
            path_and_query
        ))
        .ok()
    }
}

fn dashboard_body(body: Incoming) -> (reqwest::Body, tokio::sync::mpsc::UnboundedReceiver<()>) {
    let (progress_tx, progress_rx) = tokio::sync::mpsc::unbounded_channel();
    let stream = body.into_data_stream().map(move |chunk| {
        let _ = progress_tx.send(());
        chunk.map_err(|error| io::Error::new(io::ErrorKind::Other, error))
    });
    (reqwest::Body::wrap_stream(stream), progress_rx)
}

fn proxy_response(response: reqwest::Response, head: bool) -> Response<BoxBody> {
    let status = response.status();
    let headers = end_to_end_headers(response.headers(), false);
    if head {
        let mut proxied = Response::new(full(Bytes::new()));
        *proxied.status_mut() = status;
        *proxied.headers_mut() = headers;
        return proxied;
    }
    let stream = response.bytes_stream().map(|chunk| {
        chunk
            .map(BodyFrame::data)
            .map_err(|error| io::Error::new(io::ErrorKind::Other, error))
    });
    let mut proxied = Response::new(BodyExt::boxed(StreamBody::new(stream)));
    *proxied.status_mut() = status;
    *proxied.headers_mut() = headers;
    proxied
}

fn end_to_end_headers(headers: &HeaderMap, request: bool) -> HeaderMap {
    let nominated = connection_nominated_headers(headers);
    let mut filtered = HeaderMap::new();
    for (name, value) in headers {
        let name_text = name.as_str();
        if is_hop_by_hop(name, &nominated)
            || (request
                && (name_text.eq_ignore_ascii_case("forwarded")
                    || name_text.to_ascii_lowercase().starts_with("x-forwarded-")))
        {
            continue;
        }
        filtered.append(name.clone(), value.clone());
    }
    filtered
}

fn connection_nominated_headers(headers: &HeaderMap) -> Vec<HeaderName> {
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect()
}

fn is_hop_by_hop(name: &HeaderName, nominated: &[HeaderName]) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || nominated
        .iter()
        .any(|nominated_name| nominated_name == name)
}

fn has_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(http::header::UPGRADE)
        || connection_nominated_headers(headers)
            .iter()
            .any(|name| name == http::header::UPGRADE)
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

async fn reserve_open(
    opts: &ServerOpts,
    sid: &str,
    route: &str,
    version: WireVersion,
    wait_for_v1: bool,
) -> OpenClaim {
    let mut claims = opts.claims.lock().await;
    if let Some(claim) = claims.get(sid) {
        if claim.version != version || claim.route != route {
            return OpenClaim::Conflict;
        }
        return match &claim.state {
            ClaimState::Ready => OpenClaim::Ready,
            ClaimState::Opening { done, .. } if wait_for_v1 => OpenClaim::Wait(done.subscribe()),
            ClaimState::Opening { .. } => OpenClaim::Opening,
        };
    }
    let admission = match opts.admission.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return OpenClaim::Limited,
    };
    let generation = opts.next_generation.fetch_add(1, Relaxed);
    claims.insert(
        sid.to_owned(),
        VersionClaim {
            version,
            route: route.to_owned(),
            generation,
            state: ClaimState::Opening {
                started: Instant::now(),
                done: tokio::sync::watch::channel(0).0,
            },
        },
    );
    OpenClaim::Owner {
        generation,
        admission,
    }
}

async fn complete_claim(
    opts: &ServerOpts,
    sid: &str,
    version: WireVersion,
    generation: u64,
    success: bool,
) {
    let mut claims = opts.claims.lock().await;
    let Some(claim) = claims.get(sid) else {
        return;
    };
    if claim.version != version || claim.generation != generation {
        return;
    }
    if success {
        let done = match &claim.state {
            ClaimState::Opening { done, .. } => Some(done.clone()),
            ClaimState::Ready => None,
        };
        if let Some(claim) = claims.get_mut(sid) {
            claim.state = ClaimState::Ready;
        }
        if let Some(done) = done {
            done.send_replace(generation);
        }
    } else if let Some(VersionClaim {
        state: ClaimState::Opening { done, .. },
        ..
    }) = claims.remove(sid)
    {
        done.send_replace(generation);
    }
}

async fn release_claim_if_matches(
    opts: &ServerOpts,
    sid: &str,
    version: WireVersion,
    generation: u64,
) {
    let mut claims = opts.claims.lock().await;
    if matches!(claims.get(sid), Some(VersionClaim { version: current_version, generation: current_generation, .. }) if *current_version == version && *current_generation == generation)
    {
        if let Some(VersionClaim {
            state: ClaimState::Opening { done, .. },
            ..
        }) = claims.remove(sid)
        {
            done.send_replace(generation);
        }
    }
}

async fn handle_open_v1(
    req: Request<Incoming>,
    reg: &Registry,
    _v2reg: &V2Registry,
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

    loop {
        match reserve_open(opts, &sid, &route, WireVersion::V1, true).await {
            OpenClaim::Ready => return text_resp(StatusCode::OK, ""),
            OpenClaim::Conflict => {
                return text_resp(StatusCode::CONFLICT, "session version or route conflict\n")
            }
            OpenClaim::Limited => {
                return text_resp(StatusCode::TOO_MANY_REQUESTS, "session limit reached\n")
            }
            OpenClaim::Wait(mut done) => {
                let _ = done.changed().await;
            }
            OpenClaim::Opening => return text_resp(StatusCode::TOO_EARLY, "opening\n"),
            OpenClaim::Owner {
                generation,
                admission,
            } => {
                let result = open_session_with_admission(
                    reg,
                    sid.clone(),
                    target.clone(),
                    opts,
                    admission,
                    Some(generation),
                )
                .await;
                complete_claim(opts, &sid, WireVersion::V1, generation, result.is_ok()).await;
                return match result {
                    Ok(()) => text_resp(StatusCode::OK, ""),
                    Err((code, msg)) => text_resp(code, &msg),
                };
            }
        }
    }
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

async fn open_session_with_admission(
    reg: &Registry,
    sid: String,
    target: String,
    opts: &ServerOpts,
    admission: tokio::sync::OwnedSemaphorePermit,
    v1_generation: Option<u64>,
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
        v1_generation,
        _admission: admission,
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
            "route target must be echo, tcp://host:port, or udp://host:port\n".to_owned(),
        )
    })?;
    validate_host_port(address).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid route target {target}: {error}\n"),
        )
    })?;
    match transport.to_ascii_lowercase().as_str() {
        "tcp" => Ok(TargetSpec::Tcp(address.to_owned())),
        "udp" => Ok(TargetSpec::Udp(address.to_owned())),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported route target protocol {transport}\n"),
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
    // Long-poll: block up to a jittered poll_wait for the first byte so an idle client is
    // not hammering the proxy, then drain whatever else is immediately ready.
    match tokio::time::timeout(jittered_poll_wait(opts.poll_wait), rx.next()).await {
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

fn jittered_poll_wait_with_percent(poll_wait: Duration, percent: u16) -> Duration {
    poll_wait.mul_f64(f64::from(percent) / 1000.0)
}

fn jittered_poll_wait(poll_wait: Duration) -> Duration {
    use rand::Rng;

    jittered_poll_wait_with_percent(poll_wait, rand::thread_rng().gen_range(800..=1000))
}

async fn handle_close(
    req: Request<Incoming>,
    reg: &Registry,
    opts: &ServerOpts,
) -> Response<BoxBody> {
    if let Some(sid) = query_param(req.uri(), "s") {
        if let Some(s) = reg.lock().await.remove(&sid) {
            s.closed.store(true, Relaxed);
            log::debug!("closed session {sid}");
            if let Some(generation) = s.v1_generation {
                release_claim_if_matches(opts, &sid, WireVersion::V1, generation).await;
            }
        }
    }
    text_resp(StatusCode::OK, "")
}

// ---------------------------------------------------------------------------
// v2 server: each session is serialized by its own actor.  The registry lock
// only protects admission/opening state and is never held while doing I/O.
// ---------------------------------------------------------------------------

enum V2Command {
    Up {
        seq: u64,
        raw: Bytes,
        frames: Vec<V2Frame>,
        _inflight: V2InFlight,
        reply: tokio::sync::oneshot::Sender<(StatusCode, Bytes)>,
    },
    Down {
        seq: u64,
        reply: tokio::sync::oneshot::Sender<(StatusCode, Bytes)>,
    },
    Close {
        reply: tokio::sync::oneshot::Sender<()>,
    },
}

enum V2Event {
    Data(Bytes),
    Eof,
}

enum V2Writer {
    Tcp(tokio::net::tcp::OwnedWriteHalf),
    Udp(Arc<UdpSocket>),
    Echo,
    #[cfg(test)]
    Fail,
}

struct V2Pending {
    seq: u64,
    reply: tokio::sync::oneshot::Sender<(StatusCode, Bytes)>,
    deadline: tokio::time::Instant,
}

struct V2Actor {
    writer: V2Writer,
    events: tokio::sync::mpsc::Receiver<V2Event>,
    // Echo generates replies synchronously in the actor, but the receiver must
    // stay open until the client sends Close; otherwise it looks like target
    // EOF before the first downstream poll.
    _event_keepalive: Option<tokio::sync::mpsc::Sender<V2Event>>,
    queued: VecDeque<Bytes>,
    queued_bytes: usize,
    expected_up: u64,
    expected_down: u64,
    last_up: Option<(u64, Bytes, Bytes)>,
    cached_down: Option<(u64, Bytes)>,
    pending: Option<V2Pending>,
    batch_limit: usize,
    coalesce_ready: bool,
    upstream_closed: bool,
    eof: bool,
    terminal: bool,
    _admission: tokio::sync::OwnedSemaphorePermit,
}

async fn read_v2_body(mut body: Incoming) -> Result<Bytes> {
    let mut out = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let data = frame
            .context("reading v2 body")?
            .into_data()
            .map_err(|_| anyhow!("unexpected v2 body frame"))?;
        if out.len().saturating_add(data.len()) > MAX_BATCH {
            bail!("v2 body exceeds batch limit");
        }
        out.extend_from_slice(&data);
    }
    Ok(out.freeze())
}

fn parse_experimental_batch_limit(req: &Request<Incoming>) -> Result<Option<usize>> {
    let Some(value) = query_param(req.uri(), "batch_bytes") else {
        return Ok(None);
    };
    let bytes = value
        .parse::<usize>()
        .context("invalid experimental batch size")?;
    if !EXPERIMENTAL_BATCH_BYTES.contains(&bytes) {
        bail!("unsupported experimental batch size");
    }
    Ok(Some(bytes))
}

fn v2_seq(req: &Request<Incoming>) -> Result<u64> {
    query_param(req.uri(), "seq")
        .ok_or_else(|| anyhow!("missing sequence"))?
        .parse::<u64>()
        .context("invalid sequence")
}

async fn handle_open_v2(
    req: Request<Incoming>,
    reg: &V2Registry,
    _v1reg: &Registry,
    reverse: &ReverseRegistry,
    opts: &ServerOpts,
) -> Response<BoxBody> {
    let sid = match query_param(req.uri(), "s").filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => return text_resp(StatusCode::BAD_REQUEST, "missing session id\n"),
    };
    let route = match query_param(req.uri(), "r").filter(|r| !r.is_empty()) {
        Some(r) => r,
        None => return text_resp(StatusCode::BAD_REQUEST, "missing route\n"),
    };
    let experimental_batch_limit = match parse_experimental_batch_limit(&req) {
        Ok(value) => value,
        Err(_) => return text_resp(StatusCode::BAD_REQUEST, "invalid batch size\n"),
    };
    let batch_limit = experimental_batch_limit.unwrap_or(MAX_BATCH);
    let claim_route = experimental_batch_limit
        .map(|limit| format!("{route}\u{1f}batch_bytes={limit}"))
        .unwrap_or_else(|| route.clone());
    let attach = match parse_reverse_attach(&route) {
        Ok(value) => value,
        Err(()) => return reverse_text_resp(StatusCode::BAD_REQUEST, "invalid attach route\n"),
    };
    if experimental_batch_limit.is_some()
        && (!opts.experimental_reverse_batches || attach.is_none())
    {
        return reverse_text_resp(
            StatusCode::BAD_REQUEST,
            "experimental reverse batch size is disabled\n",
        );
    }
    let reverse_owner = if attach.is_some() {
        match query_param(req.uri(), "owner")
            .filter(|value| validate_reverse_id(value, "owner id").is_ok())
        {
            Some(value) => Some(value),
            None => return reverse_text_resp(StatusCode::BAD_REQUEST, "invalid owner id\n"),
        }
    } else {
        if resolve_route(&route, opts).is_none() {
            return text_resp(StatusCode::BAD_REQUEST, "unknown route\n");
        }
        None
    };
    if let (Some(attach), Some(owner_id)) = (&attach, &reverse_owner) {
        match verify_reverse_owner(reverse, &attach.endpoint_id, owner_id).await {
            ReverseAccess::Ready(()) => {}
            ReverseAccess::Unknown => {
                return reverse_text_resp(StatusCode::NOT_FOUND, "unknown endpoint\n")
            }
            ReverseAccess::Conflict => {
                return reverse_text_resp(StatusCode::CONFLICT, "endpoint not owned\n")
            }
        }
    }
    let (generation, permit) =
        match reserve_open(opts, &sid, &claim_route, WireVersion::V2, false).await {
            OpenClaim::Ready => return text_resp(StatusCode::OK, ""),
            OpenClaim::Opening => return text_resp(StatusCode::TOO_EARLY, "opening\n"),
            OpenClaim::Conflict => {
                return text_resp(StatusCode::CONFLICT, "session version or route conflict\n")
            }
            OpenClaim::Limited => {
                return text_resp(StatusCode::TOO_MANY_REQUESTS, "session limit reached\n")
            }
            OpenClaim::Wait(_) => return text_resp(StatusCode::TOO_EARLY, "opening\n"),
            OpenClaim::Owner {
                generation,
                admission,
            } => (generation, admission),
        };
    if let (Some(attach), Some(owner_id)) = (attach, reverse_owner) {
        let stream = match take_reverse_conn(reverse, &attach, &owner_id).await {
            ReverseAccess::Ready(Some(stream)) => stream,
            ReverseAccess::Ready(None) => {
                release_claim_if_matches(opts, &sid, WireVersion::V2, generation).await;
                return reverse_text_resp(StatusCode::GONE, "connection unavailable\n");
            }
            ReverseAccess::Unknown => {
                release_claim_if_matches(opts, &sid, WireVersion::V2, generation).await;
                return reverse_text_resp(StatusCode::NOT_FOUND, "unknown endpoint\n");
            }
            ReverseAccess::Conflict => {
                release_claim_if_matches(opts, &sid, WireVersion::V2, generation).await;
                return reverse_text_resp(StatusCode::CONFLICT, "endpoint not owned\n");
            }
        };
        let tx = create_v2_actor_from_tcp(
            stream,
            permit,
            opts.poll_wait,
            batch_limit,
            experimental_batch_limit.is_some(),
        );
        reg.lock().await.insert(
            sid.clone(),
            V2Entry::Ready {
                route: claim_route,
                generation,
                tx,
                batch_limit,
                up_inflight: Arc::new(std::sync::Mutex::new(None)),
                last: Arc::new(std::sync::Mutex::new(Instant::now())),
            },
        );
        complete_claim(opts, &sid, WireVersion::V2, generation, true).await;
        return reverse_text_resp(StatusCode::OK, "");
    }
    let existing = {
        let mut guard = reg.lock().await;
        if let Some(entry) = guard.get(&sid) {
            Some(match entry {
                V2Entry::Opening { route: old, .. } | V2Entry::Ready { route: old, .. } => {
                    old == &claim_route
                }
            })
        } else {
            guard.insert(
                sid.clone(),
                V2Entry::Opening {
                    route: claim_route.clone(),
                    generation,
                    started: Instant::now(),
                },
            );
            None
        }
    };
    if let Some(same) = existing {
        release_claim_if_matches(opts, &sid, WireVersion::V2, generation).await;
        return if same {
            text_resp(StatusCode::TOO_EARLY, "opening\n")
        } else {
            text_resp(StatusCode::CONFLICT, "session route conflict\n")
        };
    }
    let reg = reg.clone();
    let opts = opts.clone();
    tokio::spawn(async move {
        match create_v2_actor(
            &route,
            &opts,
            permit,
            batch_limit,
            experimental_batch_limit.is_some(),
        )
        .await
        {
            Ok(tx) => {
                let mut guard = reg.lock().await;
                if matches!(guard.get(&sid), Some(V2Entry::Opening { generation: g, .. }) if *g == generation)
                {
                    guard.insert(
                        sid.clone(),
                        V2Entry::Ready {
                            route: claim_route,
                            generation,
                            tx,
                            batch_limit,
                            up_inflight: Arc::new(std::sync::Mutex::new(None)),
                            last: Arc::new(std::sync::Mutex::new(Instant::now())),
                        },
                    );
                    drop(guard);
                    complete_claim(&opts, &sid, WireVersion::V2, generation, true).await;
                    return;
                }
            }
            Err(error) => {
                log::debug!("v2 session open failed: {error}");
                let mut guard = reg.lock().await;
                if matches!(guard.get(&sid), Some(V2Entry::Opening { generation: g, .. }) if *g == generation)
                {
                    guard.remove(&sid);
                }
            }
        }
        complete_claim(&opts, &sid, WireVersion::V2, generation, false).await;
    });
    text_resp(StatusCode::TOO_EARLY, "opening\n")
}

async fn v2_sender(
    reg: &V2Registry,
    sid: &str,
) -> std::result::Result<(tokio::sync::mpsc::Sender<V2Command>, usize), StatusCode> {
    match reg.lock().await.get(sid) {
        Some(V2Entry::Ready {
            tx,
            batch_limit,
            last,
            ..
        }) => {
            if let Ok(mut time) = last.lock() {
                *time = Instant::now();
            }
            Ok((tx.clone(), *batch_limit))
        }
        Some(V2Entry::Opening { .. }) => Err(StatusCode::TOO_EARLY),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Debug)]
struct V2InFlight(Arc<std::sync::Mutex<Option<(u64, Bytes)>>>);

impl Drop for V2InFlight {
    fn drop(&mut self) {
        if let Ok(mut in_flight) = self.0.lock() {
            *in_flight = None;
        }
    }
}

async fn v2_up_sender(
    reg: &V2Registry,
    sid: &str,
    seq: u64,
    raw: &Bytes,
) -> std::result::Result<(tokio::sync::mpsc::Sender<V2Command>, V2InFlight), StatusCode> {
    match reg.lock().await.get(sid) {
        Some(V2Entry::Ready {
            tx,
            up_inflight,
            last,
            ..
        }) => {
            if let Ok(mut time) = last.lock() {
                *time = Instant::now();
            }
            let mut in_flight = match up_inflight.lock() {
                Ok(value) => value,
                Err(_) => return Err(StatusCode::GONE),
            };
            match in_flight.as_ref() {
                None => {
                    *in_flight = Some((seq, raw.clone()));
                    Ok((tx.clone(), V2InFlight(up_inflight.clone())))
                }
                Some((active_seq, active_raw)) if *active_seq == seq && *active_raw == *raw => {
                    Err(StatusCode::TOO_EARLY)
                }
                Some(_) => {
                    V2_COUNTERS.sequence_conflicts.fetch_add(1, Relaxed);
                    Err(StatusCode::CONFLICT)
                }
            }
        }
        Some(V2Entry::Opening { .. }) => Err(StatusCode::TOO_EARLY),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn handle_up_v2(req: Request<Incoming>, reg: &V2Registry) -> Response<BoxBody> {
    let started = Instant::now();
    let sid = match query_param(req.uri(), "s") {
        Some(s) => s,
        None => return text_resp(StatusCode::BAD_REQUEST, "missing session id\n"),
    };
    let seq = match v2_seq(&req) {
        Ok(s) => s,
        Err(_) => return text_resp(StatusCode::BAD_REQUEST, "invalid sequence\n"),
    };
    let raw = match read_v2_body(req.into_body()).await {
        Ok(b) => b,
        Err(error) if error.to_string().contains("exceeds batch limit") => {
            return text_resp(StatusCode::PAYLOAD_TOO_LARGE, "body too large\n")
        }
        Err(_) => return text_resp(StatusCode::BAD_REQUEST, "invalid body\n"),
    };
    let frames = match decode_v2_frames(&raw).and_then(validate_v2_up) {
        Ok(f) => f,
        Err(_) => return text_resp(StatusCode::BAD_REQUEST, "invalid frames\n"),
    };
    let frame_count = frames.len();
    let data_bytes = frames
        .iter()
        .filter_map(|frame| match frame {
            V2Frame::Data(data) => Some(data.len()),
            _ => None,
        })
        .sum::<usize>();
    let request_bytes = raw.len();
    let (tx, inflight) = match v2_up_sender(reg, &sid, seq, &raw).await {
        Ok(value) => value,
        Err(s) => return text_resp(s, "session unavailable\n"),
    };
    let (reply, rx) = tokio::sync::oneshot::channel();
    if tx
        .send(V2Command::Up {
            seq,
            raw,
            frames,
            _inflight: inflight,
            reply,
        })
        .await
        .is_err()
    {
        V2_COUNTERS.session_losses.fetch_add(1, Relaxed);
        return text_resp(StatusCode::GONE, "session lost\n");
    }
    match rx.await {
        Ok((status, body)) if status.is_success() => {
            diagnostic_event(
                "v2_server_send",
                serde_json::json!({
                    "sid": sid,
                    "seq": seq,
                    "status": status.as_u16(),
                    "request_bytes": request_bytes,
                    "response_bytes": body.len(),
                    "frames": frame_count,
                    "data_bytes": data_bytes,
                    "queue_wait_us": started.elapsed().as_micros(),
                }),
            );
            octet_resp(body)
        }
        Ok((status, body)) => {
            diagnostic_event(
                "v2_server_send",
                serde_json::json!({
                    "sid": sid,
                    "seq": seq,
                    "status": status.as_u16(),
                    "request_bytes": request_bytes,
                    "response_bytes": body.len(),
                    "frames": frame_count,
                    "data_bytes": data_bytes,
                    "queue_wait_us": started.elapsed().as_micros(),
                }),
            );
            let mut response = text_resp(status, "");
            *response.body_mut() = full(body);
            response
        }
        Err(_) => {
            V2_COUNTERS.session_losses.fetch_add(1, Relaxed);
            text_resp(StatusCode::GONE, "session lost\n")
        }
    }
}

fn validate_v2_up(frames: Vec<V2Frame>) -> Result<Vec<V2Frame>> {
    let mut close = false;
    for frame in &frames {
        match frame {
            V2Frame::Data(_) | V2Frame::KeepAlive if !close => {}
            V2Frame::Close if !close => close = true,
            _ => bail!("invalid v2 upstream order"),
        }
    }
    Ok(frames)
}

async fn handle_down_v2(req: Request<Incoming>, reg: &V2Registry) -> Response<BoxBody> {
    let started = Instant::now();
    let sid = match query_param(req.uri(), "s") {
        Some(s) => s,
        None => return text_resp(StatusCode::BAD_REQUEST, "missing session id\n"),
    };
    let seq = match v2_seq(&req) {
        Ok(s) => s,
        Err(_) => return text_resp(StatusCode::BAD_REQUEST, "invalid sequence\n"),
    };
    let (tx, batch_limit) = match v2_sender(reg, &sid).await {
        Ok(value) => value,
        Err(s) => return text_resp(s, "session unavailable\n"),
    };
    let (reply, rx) = tokio::sync::oneshot::channel();
    if tx.send(V2Command::Down { seq, reply }).await.is_err() {
        V2_COUNTERS.session_losses.fetch_add(1, Relaxed);
        return text_resp(StatusCode::GONE, "session lost\n");
    }
    match rx.await {
        Ok((status, body)) if status.is_success() => {
            diagnostic_event(
                "v2_server_recv",
                serde_json::json!({
                    "sid": sid,
                    "seq": seq,
                    "status": status.as_u16(),
                    "response_bytes": body.len(),
                    "batch_limit_bytes": batch_limit,
                    "fill_ratio": body.len() as f64 / batch_limit as f64,
                    "queue_wait_us": started.elapsed().as_micros(),
                }),
            );
            octet_resp(body)
        }
        Ok((status, body)) => {
            diagnostic_event(
                "v2_server_recv",
                serde_json::json!({
                    "sid": sid,
                    "seq": seq,
                    "status": status.as_u16(),
                    "response_bytes": body.len(),
                    "queue_wait_us": started.elapsed().as_micros(),
                }),
            );
            let mut response = text_resp(status, "");
            *response.body_mut() = full(body);
            response
        }
        Err(_) => {
            V2_COUNTERS.session_losses.fetch_add(1, Relaxed);
            text_resp(StatusCode::GONE, "session lost\n")
        }
    }
}

async fn handle_close_v2(
    req: Request<Incoming>,
    reg: &V2Registry,
    opts: &ServerOpts,
) -> Response<BoxBody> {
    let Some(sid) = query_param(req.uri(), "s") else {
        return text_resp(StatusCode::BAD_REQUEST, "missing session id\n");
    };
    let entry = reg.lock().await.remove(&sid);
    if let Some(V2Entry::Ready { generation, .. } | V2Entry::Opening { generation, .. }) = &entry {
        release_claim_if_matches(opts, &sid, WireVersion::V2, *generation).await;
    }
    if let Some(V2Entry::Ready { tx, .. }) = entry {
        let (reply, rx) = tokio::sync::oneshot::channel();
        if tx.send(V2Command::Close { reply }).await.is_ok() {
            let _ = rx.await;
        }
    }
    text_resp(StatusCode::OK, "")
}

async fn create_v2_actor(
    route: &str,
    opts: &ServerOpts,
    permit: tokio::sync::OwnedSemaphorePermit,
    batch_limit: usize,
    coalesce_ready: bool,
) -> Result<tokio::sync::mpsc::Sender<V2Command>> {
    let target = resolve_route(route, opts).ok_or_else(|| anyhow!("unknown route"))?;
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(CHAN_CAP);
    let (writer, event_keepalive) = if target.eq_ignore_ascii_case("echo") || opts.echo_all {
        (V2Writer::Echo, Some(events_tx))
    } else {
        match parse_target(&target).map_err(|(_, e)| anyhow!(e))? {
            TargetSpec::Tcp(address) => {
                let stream = tokio::time::timeout(opts.timeout, TcpStream::connect(&address))
                    .await
                    .context("tcp dial timeout")??;
                let (mut rd, wr) = stream.into_split();
                let tx = events_tx.clone();
                tokio::spawn(async move {
                    let read_size = if coalesce_ready {
                        v2_down_payload_capacity(batch_limit)
                    } else {
                        READ_BUF
                    };
                    let mut buf = vec![0u8; read_size];
                    loop {
                        match rd.read(&mut buf).await {
                            Ok(0) | Err(_) => {
                                let _ = tx.send(V2Event::Eof).await;
                                break;
                            }
                            Ok(n) => {
                                if tx
                                    .send(V2Event::Data(Bytes::copy_from_slice(&buf[..n])))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                });
                (V2Writer::Tcp(wr), None)
            }
            TargetSpec::Udp(address) => {
                let socket = Arc::new(
                    connect_udp(&address, opts.timeout)
                        .await
                        .map_err(|(_, e)| anyhow!(e))?,
                );
                let read_socket = socket.clone();
                let tx = events_tx.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; u16::MAX as usize + 1];
                    loop {
                        match read_socket.recv(&mut buf).await {
                            Ok(n) => {
                                if tx
                                    .send(V2Event::Data(Bytes::copy_from_slice(&buf[..n])))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(_) => {
                                let _ = tx.send(V2Event::Eof).await;
                                break;
                            }
                        }
                    }
                });
                (V2Writer::Udp(socket), None)
            }
            TargetSpec::Echo => (V2Writer::Echo, Some(events_tx)),
        }
    };
    let (tx, rx) = tokio::sync::mpsc::channel(CHAN_CAP);
    tokio::spawn(run_v2_actor(
        V2Actor {
            writer,
            events: events_rx,
            _event_keepalive: event_keepalive,
            queued: VecDeque::new(),
            queued_bytes: 0,
            expected_up: 0,
            expected_down: 0,
            last_up: None,
            cached_down: None,
            pending: None,
            batch_limit,
            coalesce_ready,
            upstream_closed: false,
            eof: false,
            terminal: false,
            _admission: permit,
        },
        rx,
        opts.poll_wait,
    ));
    Ok(tx)
}

fn create_v2_actor_from_tcp(
    stream: TcpStream,
    permit: tokio::sync::OwnedSemaphorePermit,
    poll_wait: Duration,
    batch_limit: usize,
    coalesce_ready: bool,
) -> tokio::sync::mpsc::Sender<V2Command> {
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(CHAN_CAP);
    let (mut rd, wr) = stream.into_split();
    tokio::spawn(async move {
        let read_size = if coalesce_ready {
            v2_down_payload_capacity(batch_limit)
        } else {
            READ_BUF
        };
        let mut buf = vec![0u8; read_size];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = events_tx.send(V2Event::Eof).await;
                    break;
                }
                Ok(n) => {
                    if events_tx
                        .send(V2Event::Data(Bytes::copy_from_slice(&buf[..n])))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    let (tx, rx) = tokio::sync::mpsc::channel(CHAN_CAP);
    tokio::spawn(run_v2_actor(
        V2Actor {
            writer: V2Writer::Tcp(wr),
            events: events_rx,
            _event_keepalive: None,
            queued: VecDeque::new(),
            queued_bytes: 0,
            expected_up: 0,
            expected_down: 0,
            last_up: None,
            cached_down: None,
            pending: None,
            batch_limit,
            coalesce_ready,
            upstream_closed: false,
            eof: false,
            terminal: false,
            _admission: permit,
        },
        rx,
        poll_wait,
    ));
    tx
}

async fn run_v2_actor(
    mut actor: V2Actor,
    mut commands: tokio::sync::mpsc::Receiver<V2Command>,
    poll_wait: Duration,
) {
    loop {
        if let Some(pending) = actor.pending.take() {
            let deadline = pending.deadline;
            tokio::select! {
                command = commands.recv() => { actor.pending = Some(pending); match command { Some(c) => actor_command(&mut actor, c, poll_wait).await, None => break } }
                event = actor.events.recv(), if actor.queued_bytes < MAX_V2_QUEUE => { actor.pending = Some(pending); if let Some(e) = event { actor_event(&mut actor, e); actor_reply_pending(&mut actor); } else { actor.eof = true; actor_reply_pending(&mut actor); } }
                _ = tokio::time::sleep_until(deadline) => { actor.pending = Some(pending); actor_reply_pending(&mut actor); }
            }
        } else {
            tokio::select! {
                command = commands.recv() => match command { Some(c) => actor_command(&mut actor, c, poll_wait).await, None => break },
                event = actor.events.recv(), if actor.queued_bytes < MAX_V2_QUEUE => match event { Some(e) => actor_event(&mut actor, e), None => actor.eof = true },
            }
        }
    }
}

fn actor_event(actor: &mut V2Actor, event: V2Event) {
    match event {
        V2Event::Data(d) => {
            actor.queued_bytes += 5 + d.len();
            actor.queued.push_back(d);
        }
        V2Event::Eof => actor.eof = true,
    }
}

fn v2_down_payload_capacity(batch_limit: usize) -> usize {
    batch_limit.saturating_sub(5 + 8 + 5).max(1)
}

fn actor_drain_ready(actor: &mut V2Actor) {
    if !actor.coalesce_ready {
        return;
    }
    while actor.queued_bytes < MAX_V2_QUEUE {
        match actor.events.try_recv() {
            Ok(event) => actor_event(actor, event),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                actor.eof = true;
                break;
            }
        }
    }
}

fn actor_response(actor: &mut V2Actor, seq: u64) -> Bytes {
    let mut out = BytesMut::from(encode_v2_ack(seq).as_ref());
    while let Some(data) = actor.queued.front() {
        let frame = encode_v2_frame(&V2Frame::Data(data.clone()));
        if out.len() + frame.len() > actor.batch_limit {
            break;
        }
        out.extend_from_slice(&frame);
        if let Some(sent) = actor.queued.pop_front() {
            actor.queued_bytes = actor.queued_bytes.saturating_sub(5 + sent.len());
        }
    }
    if actor.eof && out.len() + 5 <= actor.batch_limit {
        out.extend_from_slice(&encode_v2_frame(&V2Frame::Close));
    }
    out.freeze()
}

fn actor_reply_pending(actor: &mut V2Actor) {
    if let Some(pending) = actor.pending.take() {
        actor_drain_ready(actor);
        let body = actor_response(actor, pending.seq);
        actor.cached_down = Some((pending.seq, body.clone()));
        actor.expected_down = pending.seq + 1;
        let _ = pending.reply.send((StatusCode::OK, body));
    }
}

async fn actor_command(actor: &mut V2Actor, command: V2Command, poll_wait: Duration) {
    match command {
        V2Command::Up {
            seq,
            raw,
            frames,
            _inflight,
            reply,
        } => {
            if actor.terminal {
                let _ = reply.send((StatusCode::GONE, Bytes::new()));
                return;
            }
            if raw.len() > actor.batch_limit {
                let _ = reply.send((StatusCode::PAYLOAD_TOO_LARGE, Bytes::new()));
                return;
            }
            if let Some((last, last_raw, ack)) = &actor.last_up {
                if *last == seq {
                    if *last_raw == raw {
                        V2_COUNTERS.upstream_duplicates.fetch_add(1, Relaxed);
                    } else {
                        V2_COUNTERS.sequence_conflicts.fetch_add(1, Relaxed);
                    }
                    let _ = reply.send(if *last_raw == raw {
                        (StatusCode::OK, ack.clone())
                    } else {
                        (StatusCode::CONFLICT, Bytes::new())
                    });
                    return;
                }
            }
            if seq != actor.expected_up {
                V2_COUNTERS.sequence_conflicts.fetch_add(1, Relaxed);
                let _ = reply.send((StatusCode::CONFLICT, Bytes::new()));
                return;
            }
            if actor.upstream_closed && frames.iter().any(|f| matches!(f, V2Frame::Data(_))) {
                let _ = reply.send((StatusCode::GONE, Bytes::new()));
                return;
            }
            if matches!(&actor.writer, V2Writer::Echo) {
                let queued = frames
                    .iter()
                    .filter_map(|frame| match frame {
                        V2Frame::Data(data) => Some(5 + data.len()),
                        _ => None,
                    })
                    .sum::<usize>();
                if actor.queued_bytes.saturating_add(queued) > MAX_V2_QUEUE {
                    let _ = reply.send((StatusCode::TOO_MANY_REQUESTS, Bytes::new()));
                    return;
                }
            }
            for frame in frames {
                match frame {
                    V2Frame::Data(data) => match &mut actor.writer {
                        V2Writer::Tcp(writer) => {
                            if writer.write_all(&data).await.is_err() {
                                actor.terminal = true;
                                let _ = reply.send((StatusCode::GONE, Bytes::new()));
                                return;
                            }
                        }
                        V2Writer::Udp(socket) => match socket.send(&data).await {
                            Ok(n) if n == data.len() => {}
                            _ => {
                                actor.terminal = true;
                                let _ = reply.send((StatusCode::GONE, Bytes::new()));
                                return;
                            }
                        },
                        V2Writer::Echo => {
                            actor.queued_bytes += 5 + data.len();
                            actor.queued.push_back(data);
                        }
                        #[cfg(test)]
                        V2Writer::Fail => {
                            actor.terminal = true;
                            let _ = reply.send((StatusCode::GONE, Bytes::new()));
                            return;
                        }
                    },
                    V2Frame::Close => {
                        actor.upstream_closed = true;
                        match &mut actor.writer {
                            V2Writer::Tcp(writer) => {
                                if writer.shutdown().await.is_err() {
                                    actor.terminal = true;
                                    let _ = reply.send((StatusCode::GONE, Bytes::new()));
                                    return;
                                }
                            }
                            V2Writer::Echo => actor.eof = true,
                            V2Writer::Udp(_) => {}
                            #[cfg(test)]
                            V2Writer::Fail => {
                                actor.terminal = true;
                                let _ = reply.send((StatusCode::GONE, Bytes::new()));
                                return;
                            }
                        }
                    }
                    V2Frame::KeepAlive => {}
                    V2Frame::Ack(_) => unreachable!(),
                }
            }
            let ack = encode_v2_ack(seq);
            actor.last_up = Some((seq, raw, ack.clone()));
            actor.expected_up += 1;
            // Echo is handled inside this actor, so it has no reader task to
            // wake a pending long-poll. Release that poll after the target
            // effect is committed, just as a TCP/UDP reader event would.
            if !actor.queued.is_empty() || actor.eof {
                actor_reply_pending(actor);
            }
            let _ = reply.send((StatusCode::OK, ack));
        }
        V2Command::Down { seq, reply } => {
            if actor.terminal {
                let _ = reply.send((StatusCode::GONE, Bytes::new()));
                return;
            }
            if let Some((cached_seq, body)) = &actor.cached_down {
                if *cached_seq == seq {
                    V2_COUNTERS.downstream_replays.fetch_add(1, Relaxed);
                    let _ = reply.send((StatusCode::OK, body.clone()));
                    return;
                }
            }
            if actor
                .pending
                .as_ref()
                .map(|p| p.seq == seq)
                .unwrap_or(false)
            {
                let _ = reply.send((StatusCode::TOO_EARLY, Bytes::new()));
                return;
            }
            if seq != actor.expected_down {
                V2_COUNTERS.sequence_conflicts.fetch_add(1, Relaxed);
                let _ = reply.send((StatusCode::CONFLICT, Bytes::new()));
                return;
            }
            if actor.queued.is_empty() && !actor.eof {
                actor.pending = Some(V2Pending {
                    seq,
                    reply,
                    deadline: tokio::time::Instant::now() + jittered_poll_wait(poll_wait),
                });
            } else {
                actor_drain_ready(actor);
                let body = actor_response(actor, seq);
                actor.cached_down = Some((seq, body.clone()));
                actor.expected_down += 1;
                let _ = reply.send((StatusCode::OK, body));
            }
        }
        V2Command::Close { reply } => {
            actor.terminal = true;
            if let Some(pending) = actor.pending.take() {
                let _ = pending.reply.send((StatusCode::GONE, Bytes::new()));
            }
            let _ = reply.send(());
        }
    }
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
    retry_window: Duration,
    experimental_batch_bytes: Option<usize>,
    wire: WireApi,
}

enum Up {
    Stream { tx: fmpsc::Sender<Bytes> },
    Batch { seq: u64 },
    V2 { seq: u64 },
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
            Up::V2 { seq } => {
                let n = *seq;
                v2_post_ack(
                    &self.ctx,
                    &self.sid,
                    n,
                    encode_v2_frame(&V2Frame::Data(data)),
                )
                .await?;
                *seq += 1;
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
            Up::V2 { seq } => {
                let n = *seq;
                if v2_post_ack(&self.ctx, &self.sid, n, encode_v2_frame(&V2Frame::Close))
                    .await
                    .is_ok()
                {
                    *seq += 1;
                }
            }
        }
        if matches!(&self.up, Up::V2 { .. }) {
            // Keep the server-side cached Close available while the downstream
            // driver drains the target's final reply.
            return;
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
    open_tunnel_with_owner(ctx, sid, target, None).await
}

async fn open_tunnel_with_owner(
    ctx: Arc<TunnelCtx>,
    sid: String,
    target: &str,
    owner_id: Option<&str>,
) -> Result<(TunnelSender, TunnelReceiver)> {
    let operation_started = Instant::now();
    let owner_query = owner_id
        .map(|owner| format!("&owner={owner}"))
        .unwrap_or_default();
    let batch_query = ctx
        .experimental_batch_bytes
        .map(|bytes| format!("&batch_bytes={bytes}"))
        .unwrap_or_default();
    let open_url = format!(
        "{}{}?s={}&r={}{}{}",
        ctx.server,
        ctx.wire.open_path(),
        sid,
        target,
        owner_query,
        batch_query,
    );
    let open = ctx.client.post(&open_url);
    let resp = if matches!(ctx.wire, WireApi::V2 { .. }) {
        let deadline = tokio::time::Instant::now() + ctx.retry_window;
        let mut attempt = 0u32;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                bail!("v2 open retry window elapsed");
            }
            match ctx
                .client
                .post(&open_url)
                .timeout(ctx.timeout.min(remaining))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    diagnostic_event(
                        "v2_open",
                        serde_json::json!({
                            "sid": sid,
                            "route": target,
                            "status": response.status().as_u16(),
                            "attempts": attempt.saturating_add(1),
                            "duration_us": operation_started.elapsed().as_micros(),
                            "ok": true,
                        }),
                    );
                    break response;
                }
                Ok(response) if retryable_status(response.status()) => {
                    diagnostic_event(
                        "v2_retry",
                        serde_json::json!({
                            "operation": "open",
                            "sid": sid,
                            "attempt": attempt,
                            "status": response.status().as_u16(),
                        }),
                    );
                    let delay = v2_backoff(attempt);
                    V2_COUNTERS.retries.fetch_add(1, Relaxed);
                    attempt += 1;
                    if delay >= remaining {
                        bail!("v2 open retry window elapsed");
                    }
                    tokio::time::sleep(delay).await;
                }
                Ok(response) => {
                    diagnostic_event(
                        "v2_open",
                        serde_json::json!({
                            "sid": sid,
                            "route": target,
                            "status": response.status().as_u16(),
                            "attempts": attempt.saturating_add(1),
                            "duration_us": operation_started.elapsed().as_micros(),
                            "ok": false,
                            "reason": "terminal_status",
                        }),
                    );
                    bail!("server refused v2 session: {}", response.status())
                }
                Err(_) => {
                    diagnostic_event(
                        "v2_retry",
                        serde_json::json!({
                            "operation": "open",
                            "sid": sid,
                            "attempt": attempt,
                            "reason": "request_error",
                        }),
                    );
                    let delay = v2_backoff(attempt);
                    V2_COUNTERS.retries.fetch_add(1, Relaxed);
                    attempt += 1;
                    if delay >= remaining {
                        bail!("v2 open retry window elapsed");
                    }
                    tokio::time::sleep(delay).await;
                }
            }
        }
    } else {
        open.timeout(ctx.timeout)
            .send()
            .await
            .context("open session")?
    };
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
        Mode::Batch => match ctx.wire {
            WireApi::V2 { .. } => Up::V2 { seq: 0 },
            _ => Up::Batch { seq: 0 },
        },
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
    if matches!(ctx.wire, WireApi::V2 { .. }) {
        down_driver_v2(ctx, sid, down_tx, reconnects, closed).await;
        return;
    }
    match ctx.mode {
        Mode::Stream => down_driver_stream(ctx, sid, down_tx, reconnects, closed).await,
        Mode::Batch => down_driver_batch(ctx, sid, down_tx, reconnects, closed).await,
    }
}

fn retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_EARLY
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn v2_backoff(attempt: u32) -> Duration {
    let base = DOWN_BACKOFF_MIN.mul_f64(2f64.powi(attempt.min(5) as i32));
    let jitter = rand::random::<u16>() % 101;
    base.mul_f64(1.0 + f64::from(jitter) / 500.0)
        .min(DOWN_BACKOFF_MAX)
}

async fn collect_v2_response_with_limit(
    resp: reqwest::Response,
    batch_limit: usize,
) -> Result<Bytes> {
    if resp
        .content_length()
        .map(|len| len as usize > batch_limit)
        .unwrap_or(false)
    {
        bail!("v2 response exceeds batch limit");
    }
    let mut stream = resp.bytes_stream();
    let mut out = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading v2 response body")?;
        if out.len().saturating_add(chunk.len()) > batch_limit {
            bail!("v2 response exceeds batch limit");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}

fn v2_response_is_truncated(body: &[u8]) -> bool {
    let mut at = 0;
    while at < body.len() {
        if body.len() - at < 5 {
            return true;
        }
        let len =
            u32::from_be_bytes([body[at + 1], body[at + 2], body[at + 3], body[at + 4]]) as usize;
        if len > MAX_BATCH {
            return false;
        }
        at += 5;
        if body.len() - at < len {
            return true;
        }
        at += len;
    }
    false
}

struct V2RetryWindow {
    deadline: tokio::time::Instant,
    attempt: u32,
}

impl V2RetryWindow {
    fn new(window: Duration) -> Self {
        Self {
            deadline: tokio::time::Instant::now() + window,
            attempt: 0,
        }
    }

    fn remaining(&self) -> Result<Duration> {
        let remaining = self
            .deadline
            .saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("v2 retry window elapsed");
        }
        Ok(remaining)
    }

    async fn retry_after(&mut self, delay: Duration) -> Result<()> {
        let remaining = self.remaining()?;
        V2_COUNTERS.retries.fetch_add(1, Relaxed);
        self.attempt += 1;
        if delay >= remaining {
            tokio::time::sleep(remaining).await;
            bail!("v2 retry window elapsed");
        }
        tokio::time::sleep(delay).await;
        Ok(())
    }

    async fn retry(&mut self) -> Result<()> {
        self.retry_after(v2_backoff(self.attempt)).await
    }
}

async fn v2_post_ack(ctx: &TunnelCtx, sid: &str, seq: u64, body: Bytes) -> Result<()> {
    let batch_limit = ctx.experimental_batch_bytes.unwrap_or(MAX_BATCH);
    if body.len() > batch_limit {
        bail!("v2 request exceeds configured batch limit");
    }
    let operation_started = Instant::now();
    let mut retries = V2RetryWindow::new(ctx.retry_window);
    let url = format!(
        "{}{}?s={}&seq={}",
        ctx.server,
        ctx.wire.send_path(),
        sid,
        seq
    );
    loop {
        let remaining = retries.remaining().context("v2 upstream retry window")?;
        let result = ctx
            .client
            .post(&url)
            .body(body.clone())
            .timeout(ctx.timeout.min(remaining))
            .send()
            .await;
        match result {
            Ok(resp) if resp.status().is_success() => {
                let bytes = match collect_v2_response_with_limit(resp, batch_limit).await {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        if error.to_string().contains("exceeds batch limit") {
                            return Err(error);
                        }
                        log::debug!("v2 upstream response body cut: {error}");
                        retries.retry().await.context("v2 upstream retry window")?;
                        continue;
                    }
                };
                let frames = match decode_v2_frames(&bytes) {
                    Ok(frames) => frames,
                    Err(error) if v2_response_is_truncated(&bytes) => {
                        log::debug!("malformed v2 upstream ack after success: {error}");
                        retries.retry().await.context("v2 upstream retry window")?;
                        continue;
                    }
                    Err(error) => return Err(error).context("malformed v2 upstream ack"),
                };
                if frames == [V2Frame::Ack(seq)] {
                    diagnostic_event(
                        "v2_send",
                        serde_json::json!({
                            "sid": sid,
                            "seq": seq,
                            "request_bytes": body.len(),
                            "batch_limit_bytes": batch_limit,
                            "fill_ratio": body.len() as f64 / batch_limit as f64,
                            "response_bytes": bytes.len(),
                            "attempts": retries.attempt.saturating_add(1),
                            "ack_wait_us": operation_started.elapsed().as_micros(),
                            "ok": true,
                        }),
                    );
                    return Ok(());
                }
                bail!("missing or mismatched v2 upstream ack");
            }
            Ok(resp) if !retryable_status(resp.status()) => {
                diagnostic_event(
                    "v2_send",
                    serde_json::json!({
                        "sid": sid,
                        "seq": seq,
                        "request_bytes": body.len(),
                        "status": resp.status().as_u16(),
                        "attempts": retries.attempt.saturating_add(1),
                        "ack_wait_us": operation_started.elapsed().as_micros(),
                        "ok": false,
                        "reason": "terminal_status",
                    }),
                );
                bail!("v2 upstream terminal status {}", resp.status())
            }
            Ok(resp) => {
                diagnostic_event(
                    "v2_retry",
                    serde_json::json!({
                        "operation": "send",
                        "sid": sid,
                        "seq": seq,
                        "attempt": retries.attempt,
                        "status": resp.status().as_u16(),
                    }),
                );
                retries.retry().await.context("v2 upstream retry window")?;
            }
            Err(_) => {
                diagnostic_event(
                    "v2_retry",
                    serde_json::json!({
                        "operation": "send",
                        "sid": sid,
                        "seq": seq,
                        "attempt": retries.attempt,
                        "reason": "request_error",
                    }),
                );
                retries.retry().await.context("v2 upstream retry window")?;
            }
        }
    }
}

async fn v2_get_frames(ctx: &TunnelCtx, sid: &str, seq: u64) -> Result<Vec<V2Frame>> {
    let batch_limit = ctx.experimental_batch_bytes.unwrap_or(MAX_BATCH);
    let operation_started = Instant::now();
    let mut retries = V2RetryWindow::new(ctx.retry_window);
    let url = format!(
        "{}{}?s={}&seq={}",
        ctx.server,
        ctx.wire.recv_path(),
        sid,
        seq
    );
    loop {
        let remaining = retries.remaining().context("v2 downstream retry window")?;
        match ctx
            .client
            .get(&url)
            .timeout(ctx.timeout.min(remaining))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                let bytes = match collect_v2_response_with_limit(resp, batch_limit).await {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        if error.to_string().contains("exceeds batch limit") {
                            return Err(error);
                        }
                        log::debug!("v2 downstream response body cut: {error}");
                        retries
                            .retry()
                            .await
                            .context("v2 downstream retry window")?;
                        continue;
                    }
                };
                let frames = match decode_v2_frames(&bytes) {
                    Ok(frames) => frames,
                    Err(error) if v2_response_is_truncated(&bytes) => {
                        log::debug!("malformed v2 downstream body after success: {error}");
                        retries
                            .retry()
                            .await
                            .context("v2 downstream retry window")?;
                        continue;
                    }
                    Err(error) => return Err(error).context("malformed v2 downstream body"),
                };
                if !matches!(frames.first(), Some(V2Frame::Ack(n)) if *n == seq) {
                    bail!("missing or mismatched v2 downstream ack");
                }
                let mut close = false;
                for frame in frames.iter().skip(1) {
                    match frame {
                        V2Frame::Data(_) | V2Frame::KeepAlive if !close => {}
                        V2Frame::Close if !close => close = true,
                        _ => bail!("invalid v2 downstream frames"),
                    }
                }
                diagnostic_event(
                    "v2_recv",
                    serde_json::json!({
                        "sid": sid,
                        "seq": seq,
                        "response_bytes": bytes.len(),
                        "batch_limit_bytes": batch_limit,
                        "fill_ratio": bytes.len() as f64 / batch_limit as f64,
                        "frames": frames.len(),
                        "data_bytes": frames.iter().filter_map(|frame| match frame { V2Frame::Data(data) => Some(data.len()), _ => None }).sum::<usize>(),
                        "empty": frames.len() == 1,
                        "attempts": retries.attempt.saturating_add(1),
                        "wait_us": operation_started.elapsed().as_micros(),
                        "ok": true,
                    }),
                );
                return Ok(frames);
            }
            Ok(resp) if !retryable_status(resp.status()) => {
                diagnostic_event(
                    "v2_recv",
                    serde_json::json!({
                        "sid": sid,
                        "seq": seq,
                        "status": resp.status().as_u16(),
                        "attempts": retries.attempt.saturating_add(1),
                        "wait_us": operation_started.elapsed().as_micros(),
                        "ok": false,
                        "reason": "terminal_status",
                    }),
                );
                bail!("v2 downstream terminal status {}", resp.status())
            }
            Ok(resp) => {
                diagnostic_event(
                    "v2_retry",
                    serde_json::json!({
                        "operation": "recv",
                        "sid": sid,
                        "seq": seq,
                        "attempt": retries.attempt,
                        "status": resp.status().as_u16(),
                    }),
                );
                retries
                    .retry()
                    .await
                    .context("v2 downstream retry window")?;
            }
            Err(_) => {
                diagnostic_event(
                    "v2_retry",
                    serde_json::json!({
                        "operation": "recv",
                        "sid": sid,
                        "seq": seq,
                        "attempt": retries.attempt,
                        "reason": "request_error",
                    }),
                );
                retries
                    .retry()
                    .await
                    .context("v2 downstream retry window")?;
            }
        }
    }
}

async fn down_driver_v2(
    ctx: Arc<TunnelCtx>,
    sid: String,
    down_tx: tokio::sync::mpsc::Sender<Bytes>,
    reconnects: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
) {
    let mut seq = 0;
    while !closed.load(Relaxed) {
        let request = v2_get_frames(&ctx, &sid, seq);
        tokio::pin!(request);
        let result = tokio::select! {
            result = &mut request => Some(result),
            _ = wait_for_closed(closed.clone()) => None,
        };
        let Some(result) = result else {
            return;
        };
        match result {
            Ok(frames) => {
                seq += 1;
                for frame in frames.into_iter().skip(1) {
                    match frame {
                        V2Frame::Data(data) => {
                            if down_tx.send(data).await.is_err() {
                                close_v2_session(&ctx, &sid).await;
                                closed.store(true, Relaxed);
                                return;
                            }
                        }
                        V2Frame::Close => {
                            close_v2_session(&ctx, &sid).await;
                            closed.store(true, Relaxed);
                            return;
                        }
                        V2Frame::KeepAlive => {}
                        V2Frame::Ack(_) => {
                            close_v2_session(&ctx, &sid).await;
                            closed.store(true, Relaxed);
                            return;
                        }
                    }
                }
            }
            Err(error) => {
                reconnects.fetch_add(1, Relaxed);
                log::debug!("v2 downstream ended: {error}");
                close_v2_session(&ctx, &sid).await;
                closed.store(true, Relaxed);
                return;
            }
        }
    }
}

async fn wait_for_closed(closed: Arc<AtomicBool>) {
    while !closed.load(Relaxed) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn close_v2_session(ctx: &TunnelCtx, sid: &str) {
    let url = format!("{}{}?s={}", ctx.server, ctx.wire.close_path(), sid);
    let _ = ctx.client.post(url).timeout(ctx.timeout).send().await;
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
        let url = format!(
            "{}{}?s={}&seq={}",
            ctx.server,
            ctx.wire.recv_path(),
            sid,
            seq
        );
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
    let token = match &cfg.wire {
        WireApi::V1 { token } | WireApi::V2 { token } => token,
    };
    b = b.user_agent(V1_USER_AGENT);
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::ACCEPT, http::HeaderValue::from_static("*/*"));
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
    if matches!(cfg.wire, WireApi::V2 { .. }) && cfg.mode != Mode::Batch {
        bail!("wire api v2 requires batch mode");
    }
    if let Some(bytes) = cfg.experimental_batch_bytes {
        if !matches!(cfg.wire, WireApi::V2 { .. }) {
            bail!("experimental batch size requires wire api v2");
        }
        if !EXPERIMENTAL_BATCH_BYTES.contains(&bytes) {
            bail!("experimental batch size must be 64, 128, or 256 KiB");
        }
    }
    Ok(Arc::new(TunnelCtx {
        client: build_client(cfg)?,
        server: cfg.server.trim_end_matches('/').to_owned(),
        mode: cfg.mode,
        keepalive: cfg.keepalive,
        // Applied both as reqwest connect_timeout (build_client) and as the
        // per-request timeout on the finite requests below.
        timeout: cfg.timeout,
        retry_window: cfg.retry_window,
        experimental_batch_bytes: cfg.experimental_batch_bytes,
        wire: cfg.wire.clone(),
    }))
}

// ---------------------------------------------------------------------------
// Client: reverse TCP endpoints
// ---------------------------------------------------------------------------

pub async fn run_reverse(
    cfg: ClientConfig,
    mappings: Vec<ReverseMap>,
    owner_id: String,
) -> Result<()> {
    if !matches!(cfg.wire, WireApi::V2 { .. }) || cfg.mode != Mode::Batch {
        bail!("reverse mode requires wire api v2 and batch mode");
    }
    if cfg.timeout <= REVERSE_ACCEPT_WAIT {
        bail!("reverse mode requires --timeout-sec greater than 20");
    }
    validate_reverse_id(&owner_id, "owner id").map_err(anyhow::Error::msg)?;
    if mappings.is_empty() {
        bail!("no reverse mappings configured; pass --reverse-map");
    }
    for (index, mapping) in mappings.iter().enumerate() {
        validate_reverse_id(&mapping.endpoint_id, "endpoint id").map_err(anyhow::Error::msg)?;
        validate_host_port(&mapping.dial_target).map_err(anyhow::Error::msg)?;
        if mappings[..index]
            .iter()
            .any(|other| other.endpoint_id == mapping.endpoint_id)
        {
            bail!("duplicate reverse endpoint {}", mapping.endpoint_id);
        }
    }
    let ctx = ctx_from(&cfg)?;
    log::info!(
        "httptun reverse client -> {} (proxy={:?}, endpoints={})",
        ctx.server,
        cfg.proxy,
        mappings.len()
    );
    let mut tasks = tokio::task::JoinSet::new();
    for mapping in mappings {
        tasks.spawn(serve_reverse_endpoint(
            ctx.clone(),
            mapping,
            owner_id.clone(),
        ));
    }
    match tasks.join_next().await {
        Some(Ok(Ok(()))) => bail!("reverse endpoint stopped unexpectedly"),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(error)) => Err(anyhow!("reverse endpoint task failed: {error}")),
        None => bail!("no reverse endpoint tasks started"),
    }
}

async fn collect_reverse_response(resp: reqwest::Response) -> Result<Bytes> {
    let expected = resp
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| anyhow!("reverse response is missing Content-Length"))?;
    if expected > MAX_BATCH {
        bail!("reverse response exceeds batch limit");
    }
    let bytes = resp.bytes().await.context("reading reverse response")?;
    if bytes.len() != expected {
        bail!("reverse response body was truncated");
    }
    Ok(bytes)
}

pub async fn run_reverse_diagnostic(
    cfg: &ClientConfig,
    endpoint_id: &str,
    run_id: &str,
    profile: &str,
    passes: u8,
) -> Result<()> {
    if !matches!(cfg.wire, WireApi::V2 { .. }) || cfg.mode != Mode::Batch {
        bail!("reverse diagnostics require wire api v2 and batch mode");
    }
    validate_reverse_id(endpoint_id, "endpoint id").map_err(anyhow::Error::msg)?;
    validate_reverse_id(run_id, "run id").map_err(anyhow::Error::msg)?;
    if !(1..=3).contains(&passes) {
        bail!("diagnostic passes must be between 1 and 3");
    }
    let ctx = ctx_from(cfg)?;
    let submit_url = format!("{}/api/v2/reverse/diagnostics/run", ctx.server);
    let request = serde_json::json!({
        "endpoint_id": endpoint_id,
        "run_id": run_id,
        "profile": profile,
        "passes": passes,
    });
    let request_body = serde_json::to_vec(&request)?;
    let mut submitted = false;
    for attempt in 0..5u32 {
        let response = ctx
            .client
            .post(&submit_url)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(request_body.clone())
            .timeout(ctx.timeout)
            .send()
            .await;
        match response {
            Ok(response)
                if response.status() == StatusCode::ACCEPTED
                    || response.status() == StatusCode::CONFLICT =>
            {
                submitted = true;
                break;
            }
            Ok(response) if retryable_status(response.status()) => {}
            Ok(response) => bail!("reverse diagnostic submit status {}", response.status()),
            Err(_) => {}
        }
        tokio::time::sleep(v2_backoff(attempt)).await;
    }
    if !submitted {
        bail!("submitting reverse diagnostic run failed after retries");
    }

    let status_url = format!(
        "{}/api/v2/reverse/diagnostics/status?run={run_id}",
        ctx.server
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30 * 60);
    loop {
        if tokio::time::Instant::now() >= deadline {
            bail!("reverse diagnostic status deadline elapsed");
        }
        let response = match ctx
            .client
            .get(&status_url)
            .timeout(ctx.timeout)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        if retryable_status(response.status()) {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        if !response.status().is_success() {
            bail!("reverse diagnostic status {}", response.status());
        }
        let body = match collect_reverse_response(response).await {
            Ok(body) => body,
            Err(error) if !reverse_response_error_is_terminal(&error) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        let job: serde_json::Value =
            serde_json::from_slice(&body).context("decoding reverse diagnostic status")?;
        match job.get("status").and_then(serde_json::Value::as_str) {
            Some("complete" | "error") => {
                println!("{}", serde_json::to_string_pretty(&job)?);
                return if job.get("status").and_then(serde_json::Value::as_str) == Some("complete")
                {
                    Ok(())
                } else {
                    bail!("reverse diagnostic run failed")
                };
            }
            Some("running") => tokio::time::sleep(Duration::from_secs(2)).await,
            _ => bail!("reverse diagnostic returned an invalid state"),
        }
    }
}

fn reverse_response_error_is_terminal(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message.contains("missing Content-Length") || message.contains("exceeds batch limit")
}

async fn claim_reverse(ctx: &TunnelCtx, endpoint_id: &str, owner_id: &str) -> Result<()> {
    let url = format!(
        "{}/api/v2/reverse/claim?ep={endpoint_id}&owner={owner_id}",
        ctx.server
    );
    let mut attempt = 0;
    loop {
        let result = ctx.client.post(&url).timeout(ctx.timeout).send().await;
        match result {
            Ok(response) if response.status().is_success() => {
                match collect_reverse_response(response).await {
                    Ok(body) if body.is_empty() => return Ok(()),
                    Ok(_) => bail!("reverse claim returned an unexpected body"),
                    Err(error) if reverse_response_error_is_terminal(&error) => return Err(error),
                    Err(error) => {
                        log::debug!("reverse endpoint {endpoint_id} claim response failed: {error}")
                    }
                }
            }
            Ok(response)
                if response.status() == StatusCode::CONFLICT
                    || retryable_status(response.status()) =>
            {
                log::debug!(
                    "reverse endpoint {endpoint_id} claim status {}",
                    response.status()
                );
            }
            Ok(response) => {
                bail!(
                    "server refused reverse endpoint {endpoint_id}: {}",
                    response.status()
                )
            }
            Err(error) => log::debug!("reverse endpoint {endpoint_id} claim failed: {error}"),
        }
        tokio::time::sleep(v2_backoff(attempt)).await;
        attempt = attempt.saturating_add(1);
    }
}

enum ReversePoll {
    Accepted(ReverseAcceptResponse),
    Reclaim,
}

async fn poll_reverse(
    ctx: &TunnelCtx,
    endpoint_id: &str,
    owner_id: &str,
    after: u64,
) -> Result<ReversePoll> {
    let url = format!(
        "{}/api/v2/reverse/accept?ep={endpoint_id}&owner={owner_id}&after={after}",
        ctx.server
    );
    let mut attempt = 0;
    loop {
        let result = ctx.client.get(&url).timeout(ctx.timeout).send().await;
        match result {
            Ok(response) if response.status().is_success() => {
                let body = match collect_reverse_response(response).await {
                    Ok(body) => body,
                    Err(error) if reverse_response_error_is_terminal(&error) => return Err(error),
                    Err(error) => {
                        log::debug!(
                            "reverse endpoint {endpoint_id} accept response failed: {error}"
                        );
                        tokio::time::sleep(v2_backoff(attempt)).await;
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                };
                let accepted: ReverseAcceptResponse =
                    serde_json::from_slice(&body).context("decoding reverse accept response")?;
                if accepted.cursor < after {
                    bail!("reverse accept cursor moved backwards");
                }
                return Ok(ReversePoll::Accepted(accepted));
            }
            Ok(response) if response.status() == StatusCode::CONFLICT => {
                return Ok(ReversePoll::Reclaim)
            }
            Ok(response) if retryable_status(response.status()) => {
                log::debug!(
                    "reverse endpoint {endpoint_id} accept status {}",
                    response.status()
                );
            }
            Ok(response) => {
                bail!(
                    "server refused reverse accept for {endpoint_id}: {}",
                    response.status()
                )
            }
            Err(error) => log::debug!("reverse endpoint {endpoint_id} accept failed: {error}"),
        }
        tokio::time::sleep(v2_backoff(attempt)).await;
        attempt = attempt.saturating_add(1);
    }
}

async fn serve_reverse_endpoint(
    ctx: Arc<TunnelCtx>,
    mapping: ReverseMap,
    owner_id: String,
) -> Result<()> {
    loop {
        claim_reverse(&ctx, &mapping.endpoint_id, &owner_id).await?;
        log::info!(
            "reverse endpoint {} claimed; local target {}",
            mapping.endpoint_id,
            mapping.dial_target
        );
        let mut cursor = 0;
        loop {
            let accepted = match poll_reverse(&ctx, &mapping.endpoint_id, &owner_id, cursor).await?
            {
                ReversePoll::Accepted(response) => response,
                ReversePoll::Reclaim => break,
            };
            cursor = accepted.cursor;
            for conn in accepted.conns {
                let ctx = ctx.clone();
                let mapping = mapping.clone();
                let owner_id = owner_id.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        handle_reverse_connection(ctx, mapping, owner_id, conn.id, conn.peer).await
                    {
                        log::debug!("reverse connection ended: {error}");
                    }
                });
            }
        }
    }
}

async fn handle_reverse_connection(
    ctx: Arc<TunnelCtx>,
    mapping: ReverseMap,
    owner_id: String,
    conn_id: String,
    peer: String,
) -> Result<()> {
    let dial_started = Instant::now();
    let tcp = match tokio::time::timeout(ctx.timeout, TcpStream::connect(&mapping.dial_target))
        .await
    {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(error)) => {
            diagnostic_event(
                "reverse_target_dial",
                serde_json::json!({
                    "endpoint_id": mapping.endpoint_id,
                    "conn_id": conn_id,
                    "ok": false,
                    "reason": "connect_error",
                    "duration_us": dial_started.elapsed().as_micros(),
                }),
            );
            return Err(error).with_context(|| format!("dial {} failed", mapping.dial_target));
        }
        Err(error) => {
            diagnostic_event(
                "reverse_target_dial",
                serde_json::json!({
                    "endpoint_id": mapping.endpoint_id,
                    "conn_id": conn_id,
                    "ok": false,
                    "reason": "timeout",
                    "duration_us": dial_started.elapsed().as_micros(),
                }),
            );
            return Err(error).with_context(|| format!("dial {} timed out", mapping.dial_target));
        }
    };
    let sid = new_sid();
    diagnostic_event(
        "reverse_target_dial",
        serde_json::json!({
            "endpoint_id": mapping.endpoint_id,
            "conn_id": conn_id,
            "sid": sid,
            "peer": peer,
            "local_addr": tcp.local_addr().ok().map(|addr| addr.to_string()),
            "ok": true,
            "duration_us": dial_started.elapsed().as_micros(),
        }),
    );
    let route = format!("attach:{}:{conn_id}", mapping.endpoint_id);
    log::debug!(
        "reverse endpoint {} attaching {peer} as session {sid}",
        mapping.endpoint_id
    );
    let open_started = Instant::now();
    let (sender, receiver) =
        match open_tunnel_with_owner(ctx, sid.clone(), &route, Some(&owner_id)).await {
            Ok(tunnel) => tunnel,
            Err(error) => {
                diagnostic_event(
                    "reverse_open",
                    serde_json::json!({
                        "endpoint_id": mapping.endpoint_id,
                        "conn_id": conn_id,
                        "sid": sid,
                        "ok": false,
                        "duration_us": open_started.elapsed().as_micros(),
                    }),
                );
                return Err(error);
            }
        };
    diagnostic_event(
        "reverse_open",
        serde_json::json!({
            "endpoint_id": mapping.endpoint_id,
            "conn_id": conn_id,
            "sid": sid,
            "ok": true,
            "duration_us": open_started.elapsed().as_micros(),
        }),
    );
    bridge_tcp(tcp, sender, receiver).await;
    Ok(())
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
    if matches!(cfg.wire, WireApi::V2 { .. }) && cfg.mode != Mode::Batch {
        bail!("wire api v2 requires batch mode");
    }
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
    log::debug!("TCP mapping -> {target} (session {sid})");
    let (sender, receiver) = open_tunnel(ctx, sid, target).await?;
    bridge_tcp(tcp, sender, receiver).await;
    Ok(())
}

async fn bridge_tcp(tcp: TcpStream, mut sender: TunnelSender, mut receiver: TunnelReceiver) {
    let (mut rd, mut wr) = tcp.into_split();
    let up_sid = sender.sid.clone();
    let down_sid = up_sid.clone();
    let up = async move {
        let batch_payload = sender
            .ctx
            .experimental_batch_bytes
            .map(|limit| limit.saturating_sub(5).max(1));
        let mut buf = vec![0u8; batch_payload.unwrap_or(READ_BUF)];
        let mut first = true;
        let clean_eof = loop {
            match rd.read(&mut buf).await {
                Ok(0) => break true,
                Ok(n) => {
                    diagnostic_event(
                        "tcp_read",
                        serde_json::json!({
                            "sid": up_sid,
                            "direction": "up",
                            "bytes": n,
                            "first": first,
                        }),
                    );
                    first = false;
                    let mut ready = n;
                    let mut eof_after_send = false;
                    let mut read_failed = false;
                    if batch_payload.is_some() {
                        while ready < buf.len() {
                            match rd.try_read(&mut buf[ready..]) {
                                Ok(0) => {
                                    eof_after_send = true;
                                    break;
                                }
                                Ok(m) => {
                                    diagnostic_event(
                                        "tcp_read",
                                        serde_json::json!({
                                            "sid": up_sid,
                                            "direction": "up",
                                            "bytes": m,
                                            "first": false,
                                            "coalesced": true,
                                        }),
                                    );
                                    ready += m;
                                }
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                                Err(error) => {
                                    log::debug!("TCP mapping local ready-read failed: {error}");
                                    read_failed = true;
                                    break;
                                }
                            }
                        }
                    }
                    if let Err(error) = sender.send(Bytes::copy_from_slice(&buf[..ready])).await {
                        log::debug!("TCP mapping upstream ended: {error}");
                        break false;
                    }
                    if eof_after_send {
                        break true;
                    }
                    if read_failed {
                        break false;
                    }
                }
                Err(error) => {
                    log::debug!("TCP mapping local read failed: {error}");
                    break false;
                }
            }
        };
        if clean_eof {
            sender.finish().await;
        } else {
            sender.closed.store(true, Relaxed);
            let ctx = sender.ctx.clone();
            let sid = sender.sid.clone();
            tokio::spawn(async move {
                let url = format!("{}{}?s={}", ctx.server, ctx.wire.close_path(), sid);
                let _ = ctx.client.post(url).timeout(ctx.timeout).send().await;
            });
        }
        clean_eof
    };
    let down = async move {
        let mut first = true;
        while let Some(data) = receiver.recv().await {
            diagnostic_event(
                "tcp_write",
                serde_json::json!({
                    "sid": down_sid,
                    "direction": "down",
                    "bytes": data.len(),
                    "first": first,
                }),
            );
            first = false;
            if let Err(error) = wr.write_all(&data).await {
                log::debug!("TCP mapping local write failed: {error}");
                break;
            }
        }
        if let Err(error) = wr.shutdown().await {
            log::debug!("TCP mapping local shutdown failed: {error}");
        }
    };
    tokio::pin!(up);
    tokio::pin!(down);
    tokio::select! {
        clean_eof = &mut up => if clean_eof { down.await },
        _ = &mut down => {},
    }
}

pub async fn run_udp_mapping_on(
    socket: UdpSocket,
    target: String,
    cfg: ClientConfig,
) -> Result<()> {
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
        if n == 0 && !matches!(ctx.wire, WireApi::V2 { .. }) {
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
    log::debug!("UDP mapping {source} -> {target} (session {sid})");
    let (mut sender, mut receiver) = open_tunnel(ctx, sid, &target).await?;
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

    async fn read_raw_http_request(stream: &mut TcpStream) {
        let mut headers = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let length = std::str::from_utf8(&headers)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap_or("0")
            .parse::<usize>()
            .unwrap();
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
    }

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
    fn v2_codec_is_strict_and_keeps_empty_data() {
        let mut encoded = BytesMut::new();
        encoded.extend_from_slice(&encode_v2_frame(&V2Frame::Ack(7)));
        encoded.extend_from_slice(&encode_v2_frame(&V2Frame::Data(Bytes::new())));
        encoded.extend_from_slice(&encode_v2_frame(&V2Frame::KeepAlive));
        encoded.extend_from_slice(&encode_v2_frame(&V2Frame::Close));
        let mut decoder = V2FrameDecoder::new();
        let mut frames = Vec::new();
        for chunk in encoded.chunks(3) {
            decoder.push(chunk).unwrap();
            while let Some(frame) = decoder.next_frame().unwrap() {
                frames.push(frame);
            }
        }
        decoder.finish().unwrap();
        assert_eq!(
            frames,
            vec![
                V2Frame::Ack(7),
                V2Frame::Data(Bytes::new()),
                V2Frame::KeepAlive,
                V2Frame::Close
            ]
        );
        assert!(decode_v2_frames(&[0x99, 0, 0, 0, 0]).is_err());
        assert!(decode_v2_frames(&[V2_CLOSE, 0, 0, 0, 1, 0]).is_err());
        assert!(decode_v2_frames(&[V2_DATA, 0, 0, 0]).is_err());
        let mut oversized = vec![V2_DATA, 0, 4, 0, 1];
        oversized.resize(MAX_BATCH + 1, 0);
        assert!(decode_v2_frames(&oversized).is_err());
    }

    #[test]
    fn v2_retry_statuses_and_backoff_are_bounded() {
        assert!(retryable_status(StatusCode::REQUEST_TIMEOUT));
        assert!(retryable_status(StatusCode::TOO_EARLY));
        assert!(retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(retryable_status(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(retryable_status(StatusCode::BAD_GATEWAY));
        assert!(retryable_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(retryable_status(StatusCode::GATEWAY_TIMEOUT));
        for terminal in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::CONFLICT,
            StatusCode::GONE,
            StatusCode::PAYLOAD_TOO_LARGE,
        ] {
            assert!(!retryable_status(terminal), "{terminal} must terminate v2");
        }
        for attempt in 0..10 {
            assert!((DOWN_BACKOFF_MIN..=DOWN_BACKOFF_MAX).contains(&v2_backoff(attempt)));
        }
    }

    #[tokio::test]
    async fn v2_retries_after_a_truncated_success_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicU64::new(0));
        let ack = encode_v2_ack(0);
        tokio::spawn({
            let requests = requests.clone();
            async move {
                for attempt in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut headers = Vec::new();
                    loop {
                        let mut byte = [0u8; 1];
                        stream.read_exact(&mut byte).await.unwrap();
                        headers.push(byte[0]);
                        if headers.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = std::str::from_utf8(&headers).unwrap();
                    let length = text
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).await.unwrap();
                    requests.fetch_add(1, Relaxed);
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        ack.len()
                    );
                    stream.write_all(header.as_bytes()).await.unwrap();
                    if attempt == 0 {
                        stream.write_all(&ack[..3]).await.unwrap();
                    } else {
                        stream.write_all(&ack).await.unwrap();
                    }
                }
            }
        });
        let ctx = TunnelCtx {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            server: format!("http://{address}"),
            mode: Mode::Batch,
            keepalive: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            retry_window: Duration::from_secs(2),
            experimental_batch_bytes: None,
            wire: WireApi::V2 { token: None },
        };
        v2_post_ack(
            &ctx,
            "cut",
            0,
            encode_v2_frame(&V2Frame::Data(Bytes::from_static(b"committed"))),
        )
        .await
        .unwrap();
        assert_eq!(requests.load(Relaxed), 2);
    }

    #[tokio::test]
    async fn v2_complete_malformed_success_bodies_are_terminal_not_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicU64::new(0));
        tokio::spawn({
            let requests = requests.clone();
            async move {
                for body in [
                    Bytes::from_static(&[0x99, 0, 0, 0, 0]),
                    Bytes::from_static(&[V2_ACK, 0, 0, 0, 0]),
                ] {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    read_raw_http_request(&mut stream).await;
                    requests.fetch_add(1, Relaxed);
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                    stream.write_all(&body).await.unwrap();
                }
            }
        });
        let ctx = TunnelCtx {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            server: format!("http://{address}"),
            mode: Mode::Batch,
            keepalive: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            retry_window: Duration::from_secs(2),
            experimental_batch_bytes: None,
            wire: WireApi::V2 { token: None },
        };
        for seq in 0..2 {
            assert!(v2_post_ack(&ctx, "malformed", seq, encode_v2_ack(seq))
                .await
                .is_err());
        }
        assert_eq!(requests.load(Relaxed), 2);
    }

    #[tokio::test]
    async fn v2_oversized_success_bodies_are_terminal_without_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicU64::new(0));
        tokio::spawn({
            let requests = requests.clone();
            async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_raw_http_request(&mut stream).await;
                requests.fetch_add(1, Relaxed);
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            MAX_BATCH + 1
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        let ctx = TunnelCtx {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            server: format!("http://{address}"),
            mode: Mode::Batch,
            keepalive: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            retry_window: Duration::from_secs(2),
            experimental_batch_bytes: None,
            wire: WireApi::V2 { token: None },
        };
        assert!(v2_post_ack(&ctx, "large", 0, encode_v2_ack(0))
            .await
            .is_err());
        assert_eq!(requests.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn v2_chunked_oversized_success_body_is_terminal_without_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicU64::new(0));
        tokio::spawn({
            let requests = requests.clone();
            async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_raw_http_request(&mut stream).await;
                requests.fetch_add(1, Relaxed);
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                stream
                    .write_all(format!("{:X}\r\n", MAX_BATCH + 1).as_bytes())
                    .await
                    .unwrap();
                stream.write_all(&vec![0; MAX_BATCH + 1]).await.unwrap();
                stream.write_all(b"\r\n0\r\n\r\n").await.unwrap();
            }
        });
        let ctx = TunnelCtx {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            server: format!("http://{address}"),
            mode: Mode::Batch,
            keepalive: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            retry_window: Duration::from_secs(2),
            experimental_batch_bytes: None,
            wire: WireApi::V2 { token: None },
        };
        assert!(v2_post_ack(&ctx, "chunked", 0, encode_v2_ack(0))
            .await
            .is_err());
        assert_eq!(requests.load(Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn v2_retry_window_cuts_off_at_sixty_seconds_and_new_ack_starts_fresh_window() {
        let exhausted = tokio::spawn(async {
            let mut retries = V2RetryWindow::new(Duration::from_secs(60));
            loop {
                retries.retry_after(Duration::from_secs(5)).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });
        tokio::task::yield_now().await;
        for _ in 0..11 {
            tokio::time::advance(Duration::from_secs(5)).await;
            tokio::task::yield_now().await;
        }
        assert!(!exhausted.is_finished());
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(exhausted.await.unwrap().is_err());

        // A successful Ack finishes its logical operation. The next operation
        // owns a new full window rather than inheriting the prior deadline.
        let fresh = V2RetryWindow::new(Duration::from_secs(60));
        assert_eq!(fresh.remaining().unwrap(), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn v2_echo_wakes_a_pending_downstream_poll() {
        let before = v2_diagnostics();
        let (_events_tx, events) = tokio::sync::mpsc::channel(1);
        let mut actor = V2Actor {
            writer: V2Writer::Echo,
            events,
            _event_keepalive: Some(_events_tx),
            queued: VecDeque::new(),
            queued_bytes: 0,
            expected_up: 0,
            expected_down: 0,
            last_up: None,
            cached_down: None,
            pending: None,
            batch_limit: MAX_BATCH,
            coalesce_ready: false,
            upstream_closed: false,
            eof: false,
            terminal: false,
            _admission: Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
        };
        let (down_reply, down_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Down {
                seq: 0,
                reply: down_reply,
            },
            Duration::from_secs(5),
        )
        .await;
        let raw = encode_v2_frame(&V2Frame::Data(Bytes::from_static(b"wake")));
        let (up_reply, up_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Up {
                seq: 0,
                raw,
                frames: vec![V2Frame::Data(Bytes::from_static(b"wake"))],
                _inflight: V2InFlight(Arc::new(std::sync::Mutex::new(Some((
                    0,
                    encode_v2_frame(&V2Frame::Data(Bytes::from_static(b"wake"))),
                ))))),
                reply: up_reply,
            },
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(up_rx.await.unwrap().0, StatusCode::OK);
        let (_, body) = down_rx.await.unwrap();
        assert_eq!(
            decode_v2_frames(&body).unwrap(),
            vec![V2Frame::Ack(0), V2Frame::Data(Bytes::from_static(b"wake"))]
        );
        let (replay_reply, replay_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Down {
                seq: 0,
                reply: replay_reply,
            },
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(replay_rx.await.unwrap().0, StatusCode::OK);
        assert!(v2_diagnostics().downstream_replays > before.downstream_replays);

        let (pending_reply, pending_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Down {
                seq: 1,
                reply: pending_reply,
            },
            Duration::from_secs(5),
        )
        .await;
        let (close_reply, close_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Close { reply: close_reply },
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(pending_rx.await.unwrap().0, StatusCode::GONE);
        assert!(close_rx.await.is_ok());
    }

    #[tokio::test]
    async fn profile_b_drains_only_ready_events_up_to_its_body_limit() {
        let (events_tx, events) = tokio::sync::mpsc::channel(4);
        events_tx
            .send(V2Event::Data(Bytes::from(vec![1; 30 * 1024])))
            .await
            .unwrap();
        events_tx
            .send(V2Event::Data(Bytes::from(vec![2; 30 * 1024])))
            .await
            .unwrap();
        let mut actor = V2Actor {
            writer: V2Writer::Echo,
            events,
            _event_keepalive: Some(events_tx),
            queued: VecDeque::new(),
            queued_bytes: 0,
            expected_up: 0,
            expected_down: 0,
            last_up: None,
            cached_down: None,
            pending: None,
            batch_limit: 64 * 1024,
            coalesce_ready: true,
            upstream_closed: false,
            eof: false,
            terminal: false,
            _admission: Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
        };

        actor_drain_ready(&mut actor);
        let body = actor_response(&mut actor, 0);
        assert!(body.len() <= 64 * 1024);
        assert_eq!(
            decode_v2_frames(&body).unwrap(),
            vec![
                V2Frame::Ack(0),
                V2Frame::Data(Bytes::from(vec![1; 30 * 1024])),
                V2Frame::Data(Bytes::from(vec![2; 30 * 1024])),
            ]
        );
        assert_eq!(actor.queued_bytes, 0);
    }

    #[tokio::test]
    async fn v2_empty_data_frames_count_their_framing_bytes_against_queue_limit() {
        let (keepalive, events) = tokio::sync::mpsc::channel(1);
        let mut actor = V2Actor {
            writer: V2Writer::Echo,
            events,
            _event_keepalive: Some(keepalive),
            queued: VecDeque::new(),
            queued_bytes: 0,
            expected_up: 0,
            expected_down: 0,
            last_up: None,
            cached_down: None,
            pending: None,
            batch_limit: MAX_BATCH,
            coalesce_ready: false,
            upstream_closed: false,
            eof: false,
            terminal: false,
            _admission: Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
        };
        let empty = encode_v2_frame(&V2Frame::Data(Bytes::new()));
        let empty_len = empty.len();
        let frame_count = MAX_V2_QUEUE / empty_len;
        let mut raw = BytesMut::with_capacity(frame_count * empty_len);
        let mut frames = Vec::with_capacity(frame_count);
        for _ in 0..frame_count {
            raw.extend_from_slice(&empty);
            frames.push(V2Frame::Data(Bytes::new()));
        }
        let raw = raw.freeze();
        let (first_reply, first_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Up {
                seq: 0,
                raw: raw.clone(),
                frames,
                _inflight: V2InFlight(Arc::new(std::sync::Mutex::new(Some((0, raw))))),
                reply: first_reply,
            },
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(first_rx.await.unwrap().0, StatusCode::OK);
        assert_eq!(actor.queued_bytes, frame_count * empty_len);
        assert!(actor.queued_bytes <= MAX_V2_QUEUE);

        let (next_reply, next_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Up {
                seq: 1,
                raw: empty.clone(),
                frames: vec![V2Frame::Data(Bytes::new())],
                _inflight: V2InFlight(Arc::new(std::sync::Mutex::new(Some((1, empty))))),
                reply: next_reply,
            },
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(next_rx.await.unwrap().0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(actor.queued_bytes, frame_count * empty_len);
    }

    #[tokio::test]
    async fn v2_test_writer_failure_is_terminal_gone_not_retryable() {
        let (keepalive, events) = tokio::sync::mpsc::channel(1);
        let mut actor = V2Actor {
            writer: V2Writer::Fail,
            events,
            _event_keepalive: Some(keepalive),
            queued: VecDeque::new(),
            queued_bytes: 0,
            expected_up: 0,
            expected_down: 0,
            last_up: None,
            cached_down: None,
            pending: None,
            batch_limit: MAX_BATCH,
            coalesce_ready: false,
            upstream_closed: false,
            eof: false,
            terminal: false,
            _admission: Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
        };
        let raw = encode_v2_frame(&V2Frame::Data(Bytes::from_static(b"partial")));
        let (reply, rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Up {
                seq: 0,
                raw: raw.clone(),
                frames: vec![V2Frame::Data(Bytes::from_static(b"partial"))],
                _inflight: V2InFlight(Arc::new(std::sync::Mutex::new(Some((0, raw))))),
                reply,
            },
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(rx.await.unwrap().0, StatusCode::GONE);
        let (next_reply, next_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Up {
                seq: 0,
                raw: Bytes::new(),
                frames: Vec::new(),
                _inflight: V2InFlight(Arc::new(std::sync::Mutex::new(None))),
                reply: next_reply,
            },
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(next_rx.await.unwrap().0, StatusCode::GONE);
    }

    #[tokio::test]
    async fn v2_inflight_same_sequence_is_425_and_conflicts_are_409() {
        let reg: V2Registry = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        reg.lock().await.insert(
            "race".into(),
            V2Entry::Ready {
                route: "echo".into(),
                generation: 1,
                tx,
                batch_limit: MAX_BATCH,
                up_inflight: Arc::new(std::sync::Mutex::new(None)),
                last: Arc::new(std::sync::Mutex::new(Instant::now())),
            },
        );
        let raw = encode_v2_frame(&V2Frame::Data(Bytes::from_static(b"same")));
        let (_sender, held) = v2_up_sender(&reg, "race", 0, &raw).await.unwrap();
        assert_eq!(
            v2_up_sender(&reg, "race", 0, &raw).await.unwrap_err(),
            StatusCode::TOO_EARLY
        );
        let different = encode_v2_frame(&V2Frame::Data(Bytes::from_static(b"other")));
        assert_eq!(
            v2_up_sender(&reg, "race", 0, &different).await.unwrap_err(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            v2_up_sender(&reg, "race", 1, &raw).await.unwrap_err(),
            StatusCode::CONFLICT
        );
        drop(held);
    }

    #[tokio::test]
    async fn v2_actor_replays_committed_upstream_and_cached_downstream_after_lost_responses() {
        let (keepalive, events) = tokio::sync::mpsc::channel(1);
        let mut actor = V2Actor {
            writer: V2Writer::Echo,
            events,
            _event_keepalive: Some(keepalive),
            queued: VecDeque::new(),
            queued_bytes: 0,
            expected_up: 0,
            expected_down: 0,
            last_up: None,
            cached_down: None,
            pending: None,
            batch_limit: MAX_BATCH,
            coalesce_ready: false,
            upstream_closed: false,
            eof: false,
            terminal: false,
            _admission: Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
        };
        let raw = encode_v2_frame(&V2Frame::Data(Bytes::from_static(b"once")));
        let (up_reply, up_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Up {
                seq: 0,
                raw: raw.clone(),
                frames: vec![V2Frame::Data(Bytes::from_static(b"once"))],
                _inflight: V2InFlight(Arc::new(std::sync::Mutex::new(Some((0, raw.clone()))))),
                reply: up_reply,
            },
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(up_rx.await.unwrap().1, encode_v2_ack(0));
        let (retry_reply, retry_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Up {
                seq: 0,
                raw,
                frames: Vec::new(),
                _inflight: V2InFlight(Arc::new(std::sync::Mutex::new(None))),
                reply: retry_reply,
            },
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(retry_rx.await.unwrap().1, encode_v2_ack(0));
        assert_eq!(
            actor.queued.len(),
            1,
            "target effect was not dispatched twice"
        );

        let (down_reply, down_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Down {
                seq: 0,
                reply: down_reply,
            },
            Duration::from_secs(1),
        )
        .await;
        let (_, cached) = down_rx.await.unwrap();
        let (replay_reply, replay_rx) = tokio::sync::oneshot::channel();
        actor_command(
            &mut actor,
            V2Command::Down {
                seq: 0,
                reply: replay_reply,
            },
            Duration::from_secs(1),
        )
        .await;
        let (_, replayed) = replay_rx.await.unwrap();
        assert_eq!(replayed, cached);
        assert_eq!(
            decode_v2_frames(&replayed).unwrap(),
            vec![V2Frame::Ack(0), V2Frame::Data(Bytes::from_static(b"once"))]
        );
    }

    #[test]
    fn empty_datagram_would_collide_with_keepalive() {
        // A zero-length payload framed as data ([0,0,0,0]) is byte-identical to
        // a keepalive in the v1 framing. V2 has a kind byte and carries
        // empty UDP datagrams without this ambiguity.
        assert_eq!(&encode_keepalive()[..], &[0u8, 0, 0, 0]);
        let mut dec = FrameDecoder::new();
        dec.push(&[0, 0, 0, 0]); // what encode_data(b"") would produce
        assert_eq!(dec.next_frame(), Some(TunFrame::KeepAlive));
        assert_eq!(dec.next_frame(), None);
    }

    #[test]
    fn batch_poll_jitter_stays_within_configured_bounds() {
        let poll_wait = Duration::from_secs(5);
        assert_eq!(
            jittered_poll_wait_with_percent(poll_wait, 800),
            Duration::from_secs(4)
        );
        assert_eq!(jittered_poll_wait_with_percent(poll_wait, 1000), poll_wait);
        for _ in 0..64 {
            let wait = jittered_poll_wait(poll_wait);
            assert!((Duration::from_secs(4)..=poll_wait).contains(&wait));
        }
    }

    #[tokio::test]
    async fn batch_poll_returns_queued_data_without_waiting_for_timeout() {
        let (to_target, _) = tokio::sync::mpsc::channel(1);
        let (mut down_tx, down_rx) = fmpsc::channel(1);
        down_tx.send(Bytes::from_static(b"ready")).await.unwrap();
        let session = Arc::new(Session {
            to_target,
            down: tokio::sync::Mutex::new(Some(down_rx)),
            closed: Arc::new(AtomicBool::new(false)),
            last: std::sync::Mutex::new(Instant::now()),
            target: String::new(),
            v1_generation: None,
            _admission: Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
        });
        let opts = ServerOpts {
            echo_all: false,
            keepalive: Duration::from_secs(15),
            timeout: Duration::from_secs(30),
            poll_wait: Duration::from_secs(5),
            dashboard: None,
            auth_token: None,
            max_sessions: 1,
            routes: Arc::new(HashMap::new()),
            admission: Arc::new(tokio::sync::Semaphore::new(1)),
            claims: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            next_generation: Arc::new(AtomicU64::new(1)),
            reverse_diagnostics: None,
            experimental_reverse_batches: false,
        };

        let response = handle_down_batch(session, &opts).await;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, encode_data(b"ready"));
    }

    #[test]
    fn dashboard_backend_requires_literal_loopback_http_root() {
        for valid in [
            "http://127.0.0.1:8080",
            "http://127.2.3.4/",
            "http://[::1]:8080/",
        ] {
            assert!(DashboardBackend::new(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "https://127.0.0.1:8080/",
            "http://localhost:8080/",
            "http://127.0.0.1:8080/dashboard",
            "http://user@127.0.0.1:8080/",
            "http://@127.0.0.1:8080/",
            "http://127.0.0.1:8080/?query",
            "http://127.0.0.1:8080/#fragment",
            "http://192.168.1.1:8080/",
        ] {
            assert!(DashboardBackend::new(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn dashboard_url_keeps_path_query_without_accepting_authority() {
        let dashboard = DashboardBackend::new("http://127.0.0.1:8080/").unwrap();
        assert_eq!(
            dashboard
                .url_for(&"/asset?a=1&b=two".parse().unwrap())
                .unwrap()
                .as_str(),
            "http://127.0.0.1:8080/asset?a=1&b=two"
        );
        assert!(dashboard
            .url_for(&"//other.test/path".parse().unwrap())
            .is_none());
        assert!(dashboard
            .url_for(&"http://other.test/path".parse().unwrap())
            .is_none());
    }

    #[test]
    fn dashboard_header_filtering_keeps_end_to_end_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic abc".parse().unwrap());
        headers.append("cookie", "first=1".parse().unwrap());
        headers.append("cookie", "second=2".parse().unwrap());
        headers.insert("host", "public.example".parse().unwrap());
        headers.insert("forwarded", "for=attacker".parse().unwrap());
        headers.insert("x-forwarded-for", "attacker".parse().unwrap());
        headers.insert("connection", "keep-alive, x-remove".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("x-remove", "gone".parse().unwrap());
        headers.append("set-cookie", "one=1".parse().unwrap());
        headers.append("set-cookie", "two=2".parse().unwrap());

        let request = end_to_end_headers(&headers, true);
        assert_eq!(request.get("authorization").unwrap(), "Basic abc");
        assert_eq!(request.get("host").unwrap(), "public.example");
        assert_eq!(request.get_all("cookie").iter().count(), 2);
        assert!(!request.contains_key("forwarded"));
        assert!(!request.contains_key("x-forwarded-for"));
        assert!(!request.contains_key("connection"));
        assert!(!request.contains_key("keep-alive"));
        assert!(!request.contains_key("x-remove"));

        let response = end_to_end_headers(&headers, false);
        assert_eq!(response.get_all("set-cookie").iter().count(), 2);
        assert!(response.contains_key("authorization"));
        assert!(!response.contains_key("connection"));
    }

    #[tokio::test]
    async fn dashboard_header_deadline_returns_gateway_timeout() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = backend.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = backend.accept().await.unwrap();
            let service = service_fn(|_req: Request<Incoming>| async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"late"))))
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let mut dashboard =
            DashboardBackend::new(&format!("http://127.0.0.1:{backend_port}/")).unwrap();
        dashboard.progress_timeout = Duration::from_millis(20);
        let opts = ServerOpts {
            echo_all: false,
            keepalive: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            poll_wait: Duration::from_secs(1),
            dashboard: Some(dashboard),
            auth_token: None,
            max_sessions: 1,
            routes: Arc::new(HashMap::new()),
            admission: Arc::new(tokio::sync::Semaphore::new(1)),
            claims: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            next_generation: Arc::new(AtomicU64::new(1)),
            reverse_diagnostics: None,
            experimental_reverse_batches: false,
        };
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let reg: Registry = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let v2reg: V2Registry = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let reverse: ReverseRegistry = Arc::new(tokio::sync::Mutex::new(ReverseState {
            endpoints: HashMap::new(),
            pending: 0,
            max_pending: 1,
        }));
        tokio::spawn(async move {
            let (stream, _) = proxy.accept().await.unwrap();
            let service = service_fn(move |req| {
                let opts = opts.clone();
                let reg = reg.clone();
                let v2reg = v2reg.clone();
                let reverse = reverse.clone();
                async move { handle(req, reg, v2reg, reverse, opts).await }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let response = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{proxy_port}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn dashboard_upload_progress_extends_header_deadline() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = backend.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = backend.accept().await.unwrap();
            let service = service_fn(|req: Request<Incoming>| async move {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(body, Bytes::from_static(b"xxxx"));
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let mut dashboard =
            DashboardBackend::new(&format!("http://127.0.0.1:{backend_port}/")).unwrap();
        dashboard.progress_timeout = Duration::from_millis(35);
        let opts = ServerOpts {
            echo_all: false,
            keepalive: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            poll_wait: Duration::from_secs(1),
            dashboard: Some(dashboard),
            auth_token: None,
            max_sessions: 1,
            routes: Arc::new(HashMap::new()),
            admission: Arc::new(tokio::sync::Semaphore::new(1)),
            claims: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            next_generation: Arc::new(AtomicU64::new(1)),
            reverse_diagnostics: None,
            experimental_reverse_batches: false,
        };
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let reg: Registry = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let v2reg: V2Registry = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let reverse: ReverseRegistry = Arc::new(tokio::sync::Mutex::new(ReverseState {
            endpoints: HashMap::new(),
            pending: 0,
            max_pending: 1,
        }));
        tokio::spawn(async move {
            let (stream, _) = proxy.accept().await.unwrap();
            let service = service_fn(move |req| {
                let opts = opts.clone();
                let reg = reg.clone();
                let v2reg = v2reg.clone();
                let reverse = reverse.clone();
                async move { handle(req, reg, v2reg, reverse, opts).await }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let stream = futures::stream::unfold(0_u8, |part| async move {
            if part == 4 {
                None
            } else {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Some((Ok::<_, io::Error>(Bytes::from_static(b"x")), part + 1))
            }
        });
        let response = reqwest::Client::new()
            .post(format!("http://127.0.0.1:{proxy_port}/upload"))
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.bytes().await.unwrap(), "ok");
    }

    #[test]
    fn reverse_config_parsers_enforce_fixed_safe_addresses() {
        let endpoint: ReverseEndpointConfig = "probe=127.0.0.1:13129".parse().unwrap();
        assert_eq!(endpoint.id, "probe");
        assert!("probe=0.0.0.0:13129"
            .parse::<ReverseEndpointConfig>()
            .is_err());
        assert!("bad:id=127.0.0.1:13129"
            .parse::<ReverseEndpointConfig>()
            .is_err());

        let mapping: ReverseMap = "probe->127.0.0.1:3128".parse().unwrap();
        assert_eq!(mapping.endpoint_id, "probe");
        assert_eq!(mapping.dial_target, "127.0.0.1:3128");
        assert!("probe->127.0.0.1:0".parse::<ReverseMap>().is_err());
    }

    #[tokio::test]
    async fn reverse_claim_conflicts_until_owner_lease_expires() {
        let registry: ReverseRegistry = Arc::new(tokio::sync::Mutex::new(ReverseState {
            endpoints: HashMap::from([(
                "probe".to_owned(),
                ReverseEndpoint {
                    bind: "127.0.0.1:13129".parse().unwrap(),
                    owner: None,
                    cursor: 0,
                    conns: HashMap::new(),
                    notify: Arc::new(tokio::sync::Notify::new()),
                },
            )]),
            pending: 0,
            max_pending: 1,
        }));
        assert!(matches!(
            claim_reverse_endpoint(&registry, "probe", "owner-one").await,
            ReverseAccess::Ready(())
        ));
        assert!(matches!(
            claim_reverse_endpoint(&registry, "probe", "owner-two").await,
            ReverseAccess::Conflict
        ));
        {
            let mut state = registry.lock().await;
            let owner = state
                .endpoints
                .get_mut("probe")
                .and_then(|endpoint| endpoint.owner.as_mut())
                .unwrap();
            owner.last_seen = Instant::now() - REVERSE_OWNER_IDLE - Duration::from_secs(1);
        }
        assert!(matches!(
            claim_reverse_endpoint(&registry, "probe", "owner-two").await,
            ReverseAccess::Ready(())
        ));
    }

    #[tokio::test]
    async fn reverse_pending_connection_expires_and_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(address));
        let (server, peer) = listener.accept().await.unwrap();
        let mut client = client.await.unwrap().unwrap();
        let conn_id = "0123456789abcdef0123456789abcdef".to_owned();
        let mut endpoint = ReverseEndpoint {
            bind: address,
            owner: Some(ReverseOwner {
                id: "owner-one".to_owned(),
                last_seen: Instant::now(),
            }),
            cursor: 1,
            conns: HashMap::from([(
                conn_id,
                AcceptedReverseConn {
                    stream: server,
                    peer,
                    accepted_at: Instant::now() - REVERSE_PENDING_IDLE - Duration::from_secs(1),
                    owner: "owner-one".to_owned(),
                    cursor: 1,
                },
            )]),
            notify: Arc::new(tokio::sync::Notify::new()),
        };
        assert_eq!(expire_reverse_endpoint(&mut endpoint, Instant::now()), 1);
        assert!(endpoint.conns.is_empty());
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);
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
