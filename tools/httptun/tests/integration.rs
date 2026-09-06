//! End-to-end tests for httptun, all runnable WITHOUT the corp VPN.
//!
//! They exercise fixed TCP/UDP listeners -> HTTP tunnel -> server -> target,
//! plus the measurement-hook JSON via the compiled client binary. Run with:
//!     cargo test -- --test-threads=1

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use httptun::{
    run_server_on, run_tcp_mapping_on, run_udp_mapping_on, ClientConfig, Mode, ProxyOpt, Route,
    ServerConfig, Transport, WireApi,
};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct DashboardRequest {
    method: String,
    path_and_query: String,
    headers: http::HeaderMap,
    body: Bytes,
}

async fn spawn_dashboard_backend() -> (u16, tokio::sync::mpsc::UnboundedReceiver<DashboardRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let tx = tx.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body.collect().await.unwrap().to_bytes();
                        let path_and_query = parts
                            .uri
                            .path_and_query()
                            .map(|v| v.as_str().to_owned())
                            .unwrap_or_default();
                        let _ = tx.send(DashboardRequest {
                            method: parts.method.to_string(),
                            path_and_query: path_and_query.clone(),
                            headers: parts.headers,
                            body,
                        });
                        let mut response = Response::new(Full::new(Bytes::from_static(b"backend-body")));
                        match path_and_query.as_str() {
                            "/auth" => {
                                *response.status_mut() = StatusCode::UNAUTHORIZED;
                                response.headers_mut().append("www-authenticate", "Basic realm=\"test\"".parse().unwrap());
                                response.headers_mut().append("set-cookie", "one=1".parse().unwrap());
                                response.headers_mut().append("set-cookie", "two=2".parse().unwrap());
                            }
                            "/redirect" => {
                                *response.status_mut() = StatusCode::FOUND;
                                response.headers_mut().insert("location", "/next".parse().unwrap());
                            }
                            _ => {}
                        }
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (port, rx)
}

async fn spawn_streaming_dashboard_backend() -> (u16, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let service = service_fn(move |_req: Request<Incoming>| {
            let release = release_rx.lock().ok().and_then(|mut slot| slot.take());
            async move {
                let stream = futures::stream::unfold((false, release), |(sent, release)| async move {
                    if !sent {
                        Some((
                            Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(b"event: ready\n\n"))),
                            (true, release),
                        ))
                    } else {
                        if let Some(release) = release {
                            let _ = release.await;
                        }
                        None
                    }
                });
                let mut response = Response::new(BodyExt::boxed(StreamBody::new(stream)));
                response.headers_mut().insert("content-type", "text/event-stream".parse().unwrap());
                response.headers_mut().insert("cache-control", "no-store".parse().unwrap());
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    (port, release_tx)
}

fn any_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Plain TCP echo server, standing in for a relay target.
async fn spawn_echo_target() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match l.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut b = [0u8; 8192];
                loop {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    a
}

async fn spawn_udp_echo_target() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; u16::MAX as usize + 1];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            if socket.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    address
}

fn base_server_cfg(echo_all: bool) -> ServerConfig {
    ServerConfig {
        listen: any_addr(),
        echo_all,
        mode: Mode::Stream,
        keepalive: Duration::from_secs(5),
        timeout: Duration::from_secs(5),
        poll_wait: Duration::from_secs(1),
        dashboard_backend: None,
        sans: vec!["localhost".into(), "127.0.0.1".into()],
        tls_cert: None,
        tls_key: None,
        auth_token: None,
        max_sessions: 256,
        allow_legacy: true,
        routes: Vec::new(),
    }
}

async fn spawn_server_with(cfg: ServerConfig) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = run_server_on(listener, cfg).await;
    });
    port
}

async fn spawn_server(echo_all: bool) -> u16 {
    spawn_server_with(base_server_cfg(echo_all)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dashboard_proxy_forwards_public_requests_and_preserves_backend_responses() {
    let (backend_port, mut observed) = spawn_dashboard_backend().await;
    let mut cfg = base_server_cfg(false);
    cfg.dashboard_backend = Some(format!("http://127.0.0.1:{backend_port}/"));
    cfg.allow_legacy = false;
    let server_port = spawn_server_with(cfg).await;
    let base = format!("https://127.0.0.1:{server_port}");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let response = client
        .post(format!("{base}/asset?version=7"))
        .header("authorization", "Basic preserved")
        .header("cookie", "session=abc")
        .header("host", "public.example")
        .header("forwarded", "for=spoofed")
        .header("x-forwarded-for", "spoofed")
        .header("connection", "x-remove")
        .header("x-remove", "gone")
        .body("streamed request")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap(), "backend-body");
    let request = tokio::time::timeout(Duration::from_secs(2), observed.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.path_and_query, "/asset?version=7");
    assert_eq!(request.headers.get("authorization").unwrap(), "Basic preserved");
    assert_eq!(request.headers.get("cookie").unwrap(), "session=abc");
    assert_eq!(request.headers.get("host").unwrap(), "public.example");
    assert!(!request.headers.contains_key("forwarded"));
    assert!(!request.headers.contains_key("x-forwarded-for"));
    assert!(!request.headers.contains_key("connection"));
    assert!(!request.headers.contains_key("x-remove"));
    assert_eq!(request.body, "streamed request");

    let response = client.get(format!("{base}/auth")).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers().get_all("www-authenticate").iter().count(), 1);
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);

    let response = client.get(format!("{base}/redirect")).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers().get("location").unwrap(), "/next");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dashboard_proxy_keeps_reserved_paths_local_and_handles_head_and_failures() {
    let (backend_port, mut observed) = spawn_dashboard_backend().await;
    let mut cfg = base_server_cfg(false);
    cfg.dashboard_backend = Some(format!("http://127.0.0.1:{backend_port}/"));
    cfg.allow_legacy = false;
    let server_port = spawn_server_with(cfg).await;
    let base = format!("https://127.0.0.1:{server_port}");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap();

    for path in ["/api/v1", "/api/v1/unknown", "/o"] {
        let response = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
    let response = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = client.head(format!("{base}/health")).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.bytes().await.unwrap().len(), 0);
    let response = client.post(format!("{base}/health")).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers().get("allow").unwrap(), "GET, HEAD");
    assert!(tokio::time::timeout(Duration::from_millis(100), observed.recv())
        .await
        .is_err(), "reserved route reached dashboard backend");

    let response = client.head(format!("{base}/asset")).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-length").unwrap(), "12");
    assert_eq!(response.bytes().await.unwrap().len(), 0);

    let no_backend_port = spawn_server_with(base_server_cfg(false)).await;
    let response = client
        .get(format!("https://127.0.0.1:{no_backend_port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let mut unavailable_cfg = base_server_cfg(false);
    unavailable_cfg.dashboard_backend = Some(format!("http://127.0.0.1:{closed_port}/"));
    let unavailable_port = spawn_server_with(unavailable_cfg).await;
    let response = client
        .get(format!("https://127.0.0.1:{unavailable_port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dashboard_proxy_streams_response_before_backend_eof() {
    let (backend_port, release_eof) = spawn_streaming_dashboard_backend().await;
    let mut cfg = base_server_cfg(false);
    cfg.dashboard_backend = Some(format!("http://127.0.0.1:{backend_port}/"));
    let server_port = spawn_server_with(cfg).await;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap();

    let response = client
        .get(format!("https://127.0.0.1:{server_port}/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/event-stream");
    let mut body = response.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(1), body.next())
        .await
        .expect("first stream chunk was buffered until EOF")
        .unwrap()
        .unwrap();
    assert_eq!(first, "event: ready\n\n");
    release_eof.send(()).unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(1), body.next())
        .await
        .unwrap()
        .is_none());
}

fn client_config(server_port: u16, mode: Mode, proxy: ProxyOpt) -> ClientConfig {
    ClientConfig {
        server: format!("https://127.0.0.1:{server_port}"),
        mode,
        proxy,
        danger: true,
        keepalive: Duration::from_secs(5),
        timeout: Duration::from_secs(5),
        wire: WireApi::Legacy,
    }
}

async fn spawn_tcp_client(
    server_port: u16,
    target: SocketAddr,
    mode: Mode,
    proxy: ProxyOpt,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = client_config(server_port, mode, proxy);
    tokio::spawn(async move {
        let _ = run_tcp_mapping_on(listener, target.to_string(), cfg).await;
    });
    port
}

async fn spawn_udp_client(
    server_port: u16,
    target: SocketAddr,
    mode: Mode,
    proxy: ProxyOpt,
) -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let cfg = client_config(server_port, mode, proxy);
    tokio::spawn(async move {
        let _ = run_udp_mapping_on(socket, target.to_string(), cfg).await;
    });
    port
}

/// Minimal forward CONNECT proxy; counts how many CONNECTs it tunneled.
async fn spawn_connect_proxy() -> (u16, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let count = Arc::new(AtomicU64::new(0));
    let c = count.clone();
    tokio::spawn(async move {
        loop {
            let (mut inb, _) = match l.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let c = c.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut t = [0u8; 1];
                loop {
                    match inb.read(&mut t).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => buf.push(t[0]),
                    }
                    if buf.ends_with(b"\r\n\r\n") || buf.len() > 8192 {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let mut it = head.lines().next().unwrap_or("").split_whitespace();
                let method = it.next().unwrap_or("");
                let hostport = it.next().unwrap_or("");
                if method != "CONNECT" {
                    let _ = inb
                        .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                        .await;
                    return;
                }
                c.fetch_add(1, Relaxed);
                let mut out = match TcpStream::connect(hostport).await {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = inb.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        return;
                    }
                };
                if inb
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut inb, &mut out).await;
            });
        }
    });
    (a.port(), count)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_roundtrip_batch() {
    let target = spawn_echo_target().await;
    let sport = spawn_server(false).await;
    let cport = spawn_tcp_client(sport, target, Mode::Batch, ProxyOpt::Direct).await;
    let mut stream = TcpStream::connect(("127.0.0.1", cport)).await.unwrap();

    stream.write_all(b"hello world").await.unwrap();
    let mut small = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut small))
        .await
        .expect("TCP batch response timed out")
        .unwrap();
    assert_eq!(&small, b"hello world");

    let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    stream.write_all(&big).await.unwrap();
    let mut got = vec![0u8; big.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got))
        .await
        .expect("large TCP batch response timed out")
        .unwrap();
    assert_eq!(got, big, "large payload corrupted in batch mode");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_roundtrip_stream() {
    let target = spawn_echo_target().await;
    let sport = spawn_server(false).await;
    let cport = spawn_tcp_client(sport, target, Mode::Stream, ProxyOpt::Direct).await;
    let mut stream = TcpStream::connect(("127.0.0.1", cport)).await.unwrap();

    stream.write_all(b"stream-tcp").await.unwrap();
    let mut response = [0; 10];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut response))
        .await
        .expect("TCP stream response timed out")
        .unwrap();
    assert_eq!(&response, b"stream-tcp");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_roundtrip_batch_keeps_sources_separate() {
    let target = spawn_udp_echo_target().await;
    let sport = spawn_server(false).await;
    let cport = spawn_udp_client(sport, target, Mode::Batch, ProxyOpt::Direct).await;
    let destination: SocketAddr = format!("127.0.0.1:{cport}").parse().unwrap();
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    first.send_to(b"first-client", destination).await.unwrap();
    second.send_to(b"second-client", destination).await.unwrap();

    let mut first_buf = [0u8; 64];
    let (first_n, first_from) =
        tokio::time::timeout(Duration::from_secs(5), first.recv_from(&mut first_buf))
            .await
            .expect("first UDP batch response timed out")
            .unwrap();
    let mut second_buf = [0u8; 64];
    let (second_n, second_from) =
        tokio::time::timeout(Duration::from_secs(5), second.recv_from(&mut second_buf))
            .await
            .expect("second UDP batch response timed out")
            .unwrap();

    assert_eq!(first_from, destination);
    assert_eq!(second_from, destination);
    assert_eq!(&first_buf[..first_n], b"first-client");
    assert_eq!(&second_buf[..second_n], b"second-client");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_roundtrip_stream() {
    let target = spawn_udp_echo_target().await;
    let sport = spawn_server(false).await;
    let cport = spawn_udp_client(sport, target, Mode::Stream, ProxyOpt::Direct).await;
    let destination: SocketAddr = format!("127.0.0.1:{cport}").parse().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    client.send_to(b"stream-udp", destination).await.unwrap();
    let mut response = [0; 64];
    let (n, source) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut response))
        .await
        .expect("UDP stream response timed out")
        .unwrap();
    assert_eq!(source, destination);
    assert_eq!(&response[..n], b"stream-udp");
}

fn client_bin() -> &'static str {
    env!("CARGO_BIN_EXE_httptun-client")
}

fn last_json_line(out: &[u8]) -> serde_json::Value {
    let s = String::from_utf8_lossy(out);
    let line = s
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .expect("no JSON line on stdout");
    serde_json::from_str(line).expect("stdout is not valid JSON")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bin_selftest_ping_no_proxy() {
    let sport = spawn_server(true).await;
    let out = tokio::process::Command::new(client_bin())
        .args([
            "--selftest-ping",
            "--server",
            &format!("https://127.0.0.1:{sport}"),
            "--danger-accept-invalid-cert",
            "--no-proxy",
            "--count",
            "6",
            "--size",
            "64",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "client failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = last_json_line(&out.stdout);
    assert_eq!(v["lost"], 0, "packets lost: {v}");
    assert_eq!(v["mode"], "batch");
    assert!(v["rtt_ms"]["p50"].is_number());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bin_selftest_ping_via_env_proxy() {
    let sport = spawn_server(true).await;
    let (pport, count) = spawn_connect_proxy().await;
    let out = tokio::process::Command::new(client_bin())
        .args([
            "--selftest-ping",
            "--server",
            &format!("https://127.0.0.1:{sport}"),
            "--danger-accept-invalid-cert",
            "--count",
            "6",
        ])
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{pport}"))
        .env("ALL_PROXY", format!("http://127.0.0.1:{pport}"))
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "client failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = last_json_line(&out.stdout);
    assert_eq!(v["lost"], 0, "packets lost: {v}");
    assert!(
        count.load(Relaxed) > 0,
        "client ignored HTTPS_PROXY env (proxy saw no CONNECT)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bin_selftest_ping_stream_via_env_proxy() {
    let sport = spawn_server(true).await;
    let (pport, count) = spawn_connect_proxy().await;
    let out = tokio::process::Command::new(client_bin())
        .args([
            "--selftest-ping",
            "--mode",
            "stream",
            "--server",
            &format!("https://127.0.0.1:{sport}"),
            "--danger-accept-invalid-cert",
            "--count",
            "6",
        ])
        .env("HTTPS_PROXY", format!("http://127.0.0.1:{pport}"))
        .env("ALL_PROXY", format!("http://127.0.0.1:{pport}"))
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "client failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = last_json_line(&out.stdout);
    assert_eq!(v["lost"], 0, "packets lost: {v}");
    assert_eq!(v["mode"], "stream");
    assert!(
        count.load(Relaxed) > 0,
        "client ignored HTTPS_PROXY env (proxy saw no CONNECT)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bin_throughput_batch() {
    let sport = spawn_server(true).await;
    let out = tokio::process::Command::new(client_bin())
        .args([
            "--throughput",
            "--mode",
            "batch",
            "--server",
            &format!("https://127.0.0.1:{sport}"),
            "--danger-accept-invalid-cert",
            "--no-proxy",
            "--seconds",
            "2",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "client failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = last_json_line(&out.stdout);
    assert!(
        v["mbps"].as_f64().unwrap_or(0.0) > 0.0,
        "throughput was zero: {v}"
    );
    assert!(v["reconnects"].is_number());
}

// ---------------------------------------------------------------------------
// v1 API: fixed routes, bearer auth, session limit
// ---------------------------------------------------------------------------

fn v1_client_config(server_port: u16, mode: Mode, token: Option<String>) -> ClientConfig {
    ClientConfig {
        server: format!("https://127.0.0.1:{server_port}"),
        mode,
        proxy: ProxyOpt::Direct,
        danger: true,
        keepalive: Duration::from_secs(5),
        timeout: Duration::from_secs(5),
        wire: WireApi::V1 { token },
    }
}

/// v1 client -> fixed route id -> server-side TCP target, with a bearer token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_tcp_roundtrip_via_route() {
    let target = spawn_echo_target().await;
    let mut cfg = base_server_cfg(false);
    cfg.auth_token = Some("s3cret".into());
    cfg.allow_legacy = false;
    cfg.routes = vec![Route {
        id: "t1".into(),
        transport: Transport::Tcp,
        target: target.to_string(),
    }];
    let sport = spawn_server_with(cfg).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cport = listener.local_addr().unwrap().port();
    let client = v1_client_config(sport, Mode::Batch, Some("s3cret".into()));
    tokio::spawn(async move {
        let _ = run_tcp_mapping_on(listener, "t1".into(), client).await;
    });

    let mut stream = TcpStream::connect(("127.0.0.1", cport)).await.unwrap();
    stream.write_all(b"via-route").await.unwrap();
    let mut got = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut got))
        .await
        .expect("v1 route response timed out")
        .unwrap();
    assert_eq!(&got, b"via-route");
}

/// A raw HTTP probe of the v1 API: missing token -> 401, unknown route -> 400,
/// known route -> 200, over the cap -> 429, and legacy path gone -> 404.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_enforces_auth_route_and_limit() {
    let target = spawn_echo_target().await;
    let mut cfg = base_server_cfg(false);
    cfg.auth_token = Some("s3cret".into());
    cfg.allow_legacy = false;
    cfg.max_sessions = 2;
    cfg.routes = vec![Route {
        id: "t1".into(),
        transport: Transport::Tcp,
        target: target.to_string(),
    }];
    let sport = spawn_server_with(cfg).await;
    let base = format!("https://127.0.0.1:{sport}");

    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap();

    // No Authorization -> 401.
    let r = http
        .post(format!("{base}/api/v1/session/open?s=a&r=t1"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401, "missing token must be rejected");

    // Authenticated but unknown route -> 400 (arbitrary target refused).
    let r = http
        .post(format!("{base}/api/v1/session/open?s=b&r=bogus"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400, "unknown route must be rejected");

    // Known route -> 200 (session #1).
    let r = http
        .post(format!("{base}/api/v1/session/open?s=c&r=t1"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    // Session #2 fills the cap.
    let r = http
        .post(format!("{base}/api/v1/session/open?s=d&r=t1"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    // Over the cap -> 429.
    let r = http
        .post(format!("{base}/api/v1/session/open?s=e&r=t1"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 429, "session limit must be enforced");

    // Legacy path is gone when allow_legacy is false.
    let r = http
        .post(format!("{base}/o?s=f"))
        .header("x-target", "tcp://127.0.0.1:1")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404, "legacy API must be disabled");
}
