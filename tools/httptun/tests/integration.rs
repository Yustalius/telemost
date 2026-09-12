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
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use httptun::{
    run_server_on, run_tcp_mapping_on, run_udp_mapping_on, ClientConfig, Mode, ProxyOpt, Route,
    ServerConfig, Transport, WireApi,
};
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

struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(signal) = self.0.take() {
            let _ = signal.send(());
        }
    }
}

async fn spawn_dashboard_backend() -> (u16, tokio::sync::mpsc::UnboundedReceiver<DashboardRequest>)
{
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
                        let mut response =
                            Response::new(Full::new(Bytes::from_static(b"backend-body")));
                        match path_and_query.as_str() {
                            "/auth" => {
                                *response.status_mut() = StatusCode::UNAUTHORIZED;
                                response.headers_mut().append(
                                    "www-authenticate",
                                    "Basic realm=\"test\"".parse().unwrap(),
                                );
                                response
                                    .headers_mut()
                                    .append("set-cookie", "one=1".parse().unwrap());
                                response
                                    .headers_mut()
                                    .append("set-cookie", "two=2".parse().unwrap());
                            }
                            "/redirect" => {
                                *response.status_mut() = StatusCode::FOUND;
                                response
                                    .headers_mut()
                                    .insert("location", "/next".parse().unwrap());
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
                let stream =
                    futures::stream::unfold((false, release), |(sent, release)| async move {
                        if !sent {
                            Some((
                                Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(
                                    b"event: ready\n\n",
                                ))),
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
                response
                    .headers_mut()
                    .insert("content-type", "text/event-stream".parse().unwrap());
                response
                    .headers_mut()
                    .insert("cache-control", "no-store".parse().unwrap());
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

async fn spawn_observed_udp_echo_target(
) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<usize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; u16::MAX as usize + 1];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let _ = seen_tx.send(n);
            if socket.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    (address, seen_rx)
}

async fn spawn_counting_tcp_target() -> (SocketAddr, Arc<AtomicU64>, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    tokio::spawn({
        let connections = connections.clone();
        let received = received.clone();
        async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                connections.fetch_add(1, Relaxed);
                let received = received.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                received.fetch_add(n as u64, Relaxed);
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }
    });
    (address, connections, received)
}

async fn spawn_v2_mismatched_ack_server() -> (
    u16,
    Arc<AtomicU64>,
    Arc<AtomicU64>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let recv_requests = Arc::new(AtomicU64::new(0));
    let close_requests = Arc::new(AtomicU64::new(0));
    let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
    let recv_body = Arc::new(std::sync::Mutex::new(Some(DropSignal(Some(dropped_tx)))));
    tokio::spawn({
        let recv_requests = recv_requests.clone();
        let close_requests = close_requests.clone();
        let recv_body = recv_body.clone();
        async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let recv_requests = recv_requests.clone();
                let close_requests = close_requests.clone();
                let recv_body = recv_body.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let recv_requests = recv_requests.clone();
                        let close_requests = close_requests.clone();
                        let recv_body = recv_body.clone();
                        async move {
                            let path = req.uri().path();
                            let response = match path {
                                "/api/v2/session/send" => Response::new(BodyExt::boxed(
                                    Full::new(httptun::encode_v2_ack(99))
                                        .map_err(|never| -> std::io::Error { match never {} }),
                                )),
                                "/api/v2/session/recv" => {
                                    recv_requests.fetch_add(1, Relaxed);
                                    let guard = recv_body.lock().unwrap().take().unwrap();
                                    let stream =
                                        futures::stream::unfold(guard, |guard| async move {
                                            std::future::pending::<()>().await;
                                            Some((
                                                Ok::<_, std::io::Error>(Frame::data(Bytes::new())),
                                                guard,
                                            ))
                                        });
                                    Response::new(BodyExt::boxed(StreamBody::new(stream)))
                                }
                                "/api/v2/session/close" => {
                                    close_requests.fetch_add(1, Relaxed);
                                    Response::new(BodyExt::boxed(
                                        Full::new(Bytes::new())
                                            .map_err(|never| -> std::io::Error { match never {} }),
                                    ))
                                }
                                _ => Response::new(BodyExt::boxed(
                                    Full::new(Bytes::new())
                                        .map_err(|never| -> std::io::Error { match never {} }),
                                )),
                            };
                            Ok::<_, std::convert::Infallible>(response)
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        }
    });
    (port, recv_requests, close_requests, dropped_rx)
}

#[derive(Clone, Copy)]
enum FrontFault {
    TruncateBody,
    DropResponse,
}

async fn spawn_v2_fault_front(
    backend_port: u16,
    cut_path: &'static str,
    fault: FrontFault,
) -> (
    u16,
    Arc<std::sync::Mutex<Vec<DashboardRequest>>>,
    Arc<std::sync::Mutex<Vec<(String, Bytes)>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let backend_bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let cut_once = Arc::new(AtomicU64::new(0));
    tokio::spawn({
        let observed = observed.clone();
        let backend_bodies = backend_bodies.clone();
        let cut_once = cut_once.clone();
        async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let observed = observed.clone();
                let backend_bodies = backend_bodies.clone();
                let cut_once = cut_once.clone();
                tokio::spawn(async move {
                    let backend = reqwest::Client::builder()
                        .danger_accept_invalid_certs(true)
                        .no_proxy()
                        .build()
                        .unwrap();
                    let mut stream = stream;
                    loop {
                        let mut raw_headers = Vec::new();
                        loop {
                            let mut byte = [0u8; 1];
                            if stream.read_exact(&mut byte).await.is_err() {
                                return;
                            }
                            raw_headers.push(byte[0]);
                            if raw_headers.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        let text = match std::str::from_utf8(&raw_headers) {
                            Ok(text) => text,
                            Err(_) => return,
                        };
                        let mut lines = text.lines();
                        let Some(request_line) = lines.next() else {
                            return;
                        };
                        let mut request_line = request_line.split_whitespace();
                        let (Some(method), Some(path_and_query)) =
                            (request_line.next(), request_line.next())
                        else {
                            return;
                        };
                        let method: http::Method = match method.parse() {
                            Ok(method) => method,
                            Err(_) => return,
                        };
                        let mut headers = http::HeaderMap::new();
                        let mut content_length = 0usize;
                        for line in lines {
                            let Some((name, value)) = line.split_once(':') else {
                                continue;
                            };
                            let value = value.trim();
                            if name.eq_ignore_ascii_case("content-length") {
                                content_length = value.parse().unwrap_or_default();
                            }
                            let (Ok(name), Ok(value)) = (
                                http::HeaderName::try_from(name),
                                http::HeaderValue::try_from(value),
                            ) else {
                                return;
                            };
                            headers.append(name, value);
                        }
                        let mut body = vec![0; content_length];
                        if stream.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let body = Bytes::from(body);
                        observed.lock().unwrap().push(DashboardRequest {
                            method: method.to_string(),
                            path_and_query: path_and_query.into(),
                            headers: headers.clone(),
                            body: body.clone(),
                        });
                        let backend_response = match backend
                            .request(
                                method,
                                format!("https://127.0.0.1:{backend_port}{path_and_query}"),
                            )
                            .headers(headers)
                            .body(body)
                            .send()
                            .await
                        {
                            Ok(response) => response,
                            Err(_) => return,
                        };
                        let status = backend_response.status();
                        let bytes = match backend_response.bytes().await {
                            Ok(bytes) => bytes,
                            Err(_) => return,
                        };
                        backend_bodies
                            .lock()
                            .unwrap()
                            .push((path_and_query.into(), bytes.clone()));
                        let cut = status.is_success()
                            && path_and_query.starts_with(cut_path)
                            && cut_once.fetch_add(1, Relaxed) == 0;
                        if cut && matches!(fault, FrontFault::DropResponse) {
                            return;
                        }
                        let header = format!(
                            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
                            status.as_u16(),
                            status.canonical_reason().unwrap_or(""),
                            bytes.len(),
                            if cut { "close" } else { "keep-alive" }
                        );
                        if stream.write_all(header.as_bytes()).await.is_err() {
                            return;
                        }
                        let cut = header.contains("Connection: close");
                        let payload = if cut {
                            &bytes[..bytes.len().min(3)]
                        } else {
                            &bytes
                        };
                        if stream.write_all(payload).await.is_err() || cut {
                            return;
                        }
                    }
                });
            }
        }
    });
    (port, observed, backend_bodies)
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
    assert_eq!(
        request.headers.get("authorization").unwrap(),
        "Basic preserved"
    );
    assert_eq!(request.headers.get("cookie").unwrap(), "session=abc");
    assert_eq!(request.headers.get("host").unwrap(), "public.example");
    assert!(!request.headers.contains_key("forwarded"));
    assert!(!request.headers.contains_key("x-forwarded-for"));
    assert!(!request.headers.contains_key("connection"));
    assert!(!request.headers.contains_key("x-remove"));
    assert_eq!(request.body, "streamed request");

    let response = client.get(format!("{base}/auth")).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get_all("www-authenticate")
            .iter()
            .count(),
        1
    );
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

    for path in [
        "/api/v1",
        "/api/v1/unknown",
        "/api/v2",
        "/api/v2/unknown",
        "/o",
    ] {
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
    assert!(
        tokio::time::timeout(Duration::from_millis(100), observed.recv())
            .await
            .is_err(),
        "reserved route reached dashboard backend"
    );

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
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
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
        retry_window: Duration::from_secs(60),
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
            "--wire-api",
            "v1",
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
        retry_window: Duration::from_secs(60),
        wire: WireApi::V1 { token },
    }
}

fn v2_client_config(server_port: u16) -> ClientConfig {
    ClientConfig {
        server: format!("https://127.0.0.1:{server_port}"),
        mode: Mode::Batch,
        proxy: ProxyOpt::Direct,
        danger: true,
        keepalive: Duration::from_secs(5),
        timeout: Duration::from_secs(5),
        retry_window: Duration::from_secs(60),
        wire: WireApi::V2 { token: None },
    }
}

fn v2_server_for_route(route: &str, transport: Transport, target: SocketAddr) -> ServerConfig {
    let mut cfg = base_server_cfg(false);
    cfg.routes = vec![Route {
        id: route.into(),
        transport,
        target: target.to_string(),
    }];
    cfg
}

fn v2_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap()
}

async fn open_v2_until_ready(client: &reqwest::Client, base: &str, sid: &str, route: &str) {
    let url = format!("{base}/api/v2/session/open?s={sid}&r={route}");
    for _ in 0..50 {
        let response = client.post(&url).send().await.unwrap();
        if response.status() == StatusCode::OK {
            return;
        }
        assert_eq!(response.status(), StatusCode::TOO_EARLY);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("v2 session {sid} did not finish opening");
}

/// Exercises the public mapping client rather than the actor directly.  Two
/// writes are intentional: an Echo session whose event channel was dropped
/// used to return Close after the first reply and lose the second one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_batch_mapping_keeps_echo_open_for_multiple_messages() {
    let sport = spawn_server(true).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cport = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = run_tcp_mapping_on(listener, "echo".into(), v2_client_config(sport)).await;
    });
    let mut stream = TcpStream::connect(("127.0.0.1", cport)).await.unwrap();
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        stream.write_all(payload).await.unwrap();
        let mut got = vec![0; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut got))
            .await
            .expect("v2 echo response timed out")
            .unwrap();
        assert_eq!(got, payload);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_raw_replays_upstream_and_downstream_exactly_once() {
    let before = httptun::v2_diagnostics();
    let mut cfg = base_server_cfg(true);
    cfg.poll_wait = Duration::from_millis(10);
    let sport = spawn_server_with(cfg).await;
    let base = format!("https://127.0.0.1:{sport}");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap();
    let open_url = format!("{base}/api/v2/session/open?s=replay&r=echo");
    let mut opened = false;
    for _ in 0..20 {
        let response = client.post(&open_url).send().await.unwrap();
        if response.status() == StatusCode::OK {
            opened = true;
            break;
        }
        assert_eq!(response.status(), StatusCode::TOO_EARLY);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(opened, "v2 session did not complete opening");

    let raw = httptun::encode_v2_frame(&httptun::V2Frame::Data(Bytes::from_static(b"once")));
    let up = format!("{base}/api/v2/session/send?s=replay&seq=0");
    let first = client.post(&up).body(raw.clone()).send().await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let ack = first.bytes().await.unwrap();
    let replay = client.post(&up).body(raw.clone()).send().await.unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.bytes().await.unwrap(), ack);
    let conflict = client
        .post(&up)
        .body(httptun::encode_v2_frame(&httptun::V2Frame::Data(
            Bytes::from_static(b"twice"),
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let gap = client
        .post(format!("{base}/api/v2/session/send?s=replay&seq=2"))
        .body(raw.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(gap.status(), StatusCode::CONFLICT);
    let seq_one = client
        .post(format!("{base}/api/v2/session/send?s=replay&seq=1"))
        .body(raw.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(seq_one.status(), StatusCode::OK);
    let stale = client.post(&up).body(raw.clone()).send().await.unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);

    let down = format!("{base}/api/v2/session/recv?s=replay&seq=0");
    let first = client.get(&down).send().await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let body = first.bytes().await.unwrap();
    let replay = client.get(&down).send().await.unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(replay.bytes().await.unwrap(), body);
    let next = client
        .get(format!("{base}/api/v2/session/recv?s=replay&seq=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(next.status(), StatusCode::OK);
    let old = client.get(&down).send().await.unwrap();
    assert_eq!(old.status(), StatusCode::CONFLICT);
    let after = httptun::v2_diagnostics();
    assert!(after.upstream_duplicates > before.upstream_duplicates);
    assert!(after.downstream_replays > before.downstream_replays);
    assert!(after.sequence_conflicts > before.sequence_conflicts);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_rejects_malformed_and_oversized_posts_before_target_write() {
    let (target, connections, received) = spawn_counting_tcp_target().await;
    let sport = spawn_server_with(v2_server_for_route("tcp", Transport::Tcp, target)).await;
    let base = format!("https://127.0.0.1:{sport}");
    let client = v2_http_client();
    open_v2_until_ready(&client, &base, "strict", "tcp").await;
    assert_eq!(connections.load(Relaxed), 1, "open dials the target once");

    let malformed = client
        .post(format!("{base}/api/v2/session/send?s=strict&seq=0"))
        .body(Bytes::from_static(&[0x99, 0, 0, 0, 1, 0x5a]))
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        received.load(Relaxed),
        0,
        "malformed frame must not reach target before a valid request"
    );

    let exact = Bytes::from(
        vec![0x01]
            .into_iter()
            .chain(((256 * 1024 - 5) as u32).to_be_bytes())
            .chain(std::iter::repeat(7).take(256 * 1024 - 5))
            .collect::<Vec<_>>(),
    );
    assert_eq!(exact.len(), 256 * 1024);
    let accepted = client
        .post(format!("{base}/api/v2/session/send?s=strict&seq=0"))
        .body(exact)
        .send()
        .await
        .unwrap();
    assert_eq!(
        accepted.status(),
        StatusCode::OK,
        "exact aggregate limit is valid"
    );

    let oversized = client
        .post(format!("{base}/api/v2/session/send?s=strict&seq=1"))
        .body(vec![0; 256 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    tokio::time::timeout(Duration::from_secs(2), async {
        while received.load(Relaxed) != (256 * 1024 - 5) as u64 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("accepted body did not reach target");
    assert_eq!(received.load(Relaxed), (256 * 1024 - 5) as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_open_is_idempotent_and_rejects_route_and_version_conflicts() {
    let (target, connections, _) = spawn_counting_tcp_target().await;
    let mut cfg = v2_server_for_route("tcp", Transport::Tcp, target);
    cfg.routes.push(Route {
        id: "other".into(),
        transport: Transport::Tcp,
        target: target.to_string(),
    });
    let sport = spawn_server_with(cfg).await;
    let base = format!("https://127.0.0.1:{sport}");
    let client = v2_http_client();

    let url = format!("{base}/api/v2/session/open?s=one&r=tcp");
    let attempts = futures::future::join_all((0..8).map(|_| client.post(&url).send())).await;
    for response in attempts {
        let status = response.unwrap().status();
        assert!(matches!(status, StatusCode::OK | StatusCode::TOO_EARLY));
    }
    open_v2_until_ready(&client, &base, "one", "tcp").await;
    assert_eq!(
        connections.load(Relaxed),
        1,
        "repeated open must not redial target"
    );
    assert_eq!(
        client
            .post(format!("{base}/api/v2/session/open?s=one&r=other"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        client
            .post(format!("{base}/api/v1/session/open?s=one&r=tcp"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );

    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let v1 = {
        let client = client.clone();
        let barrier = barrier.clone();
        let url = format!("{base}/api/v1/session/open?s=race&r=tcp");
        tokio::spawn(async move {
            barrier.wait().await;
            client.post(url).send().await.unwrap().status()
        })
    };
    let v2 = {
        let client = client.clone();
        let barrier = barrier.clone();
        let url = format!("{base}/api/v2/session/open?s=race&r=tcp");
        tokio::spawn(async move {
            barrier.wait().await;
            client.post(url).send().await.unwrap().status()
        })
    };
    barrier.wait().await;
    let statuses = [v1.await.unwrap(), v2.await.unwrap()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::CONFLICT)
            .count(),
        1,
        "simultaneous cross-version opens must have one winner"
    );
    assert!(statuses
        .iter()
        .any(|status| matches!(*status, StatusCode::OK | StatusCode::TOO_EARLY)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v1_open_is_atomic_and_failed_claims_release_capacity() {
    let (target, connections, _) = spawn_counting_tcp_target().await;
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_target = unused.local_addr().unwrap();
    drop(unused);
    let mut cfg = v2_server_for_route("tcp", Transport::Tcp, target);
    cfg.routes.push(Route {
        id: "other".into(),
        transport: Transport::Tcp,
        target: target.to_string(),
    });
    cfg.routes.push(Route {
        id: "bad".into(),
        transport: Transport::Tcp,
        target: bad_target.to_string(),
    });
    cfg.max_sessions = 1;
    let sport = spawn_server_with(cfg).await;
    let base = format!("https://127.0.0.1:{sport}");
    let client = v2_http_client();
    let barrier = Arc::new(tokio::sync::Barrier::new(9));
    let opens: Vec<_> = (0..8)
        .map(|_| {
            let client = client.clone();
            let barrier = barrier.clone();
            let url = format!("{base}/api/v1/session/open?s=atomic&r=tcp");
            tokio::spawn(async move {
                barrier.wait().await;
                client.post(url).send().await.unwrap().status()
            })
        })
        .collect();
    barrier.wait().await;
    let statuses = tokio::time::timeout(Duration::from_secs(3), futures::future::join_all(opens))
        .await
        .expect("concurrent v1 opens did not complete");
    for status in statuses {
        assert_eq!(status.unwrap(), StatusCode::OK);
    }
    assert_eq!(connections.load(Relaxed), 1, "v1 opens must share one dial");
    assert_eq!(
        client
            .post(format!("{base}/api/v1/session/open?s=atomic&r=other"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        client
            .post(format!("{base}/api/v2/session/open?s=atomic&r=tcp"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );

    assert_eq!(
        client
            .post(format!("{base}/api/v1/session/close?s=atomic"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let failed_v1 = client
        .post(format!("{base}/api/v1/session/open?s=v1-fail&r=bad"))
        .send()
        .await
        .unwrap();
    assert_eq!(failed_v1.status(), StatusCode::BAD_GATEWAY);
    open_v2_until_ready(&client, &base, "v1-fail", "echo").await;
    assert_eq!(
        client
            .post(format!("{base}/api/v2/session/close?s=v1-fail"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let failed_v2 = client
        .post(format!("{base}/api/v2/session/open?s=v2-fail&r=bad"))
        .send()
        .await
        .unwrap();
    assert_eq!(failed_v2.status(), StatusCode::TOO_EARLY);
    let recovered = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status = client
                .post(format!("{base}/api/v1/session/open?s=v2-fail&r=echo"))
                .send()
                .await
                .unwrap()
                .status();
            if status == StatusCode::OK {
                break status;
            }
            assert_eq!(status, StatusCode::CONFLICT);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed v2 reservation was not released");
    assert_eq!(recovered, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_udp_preserves_empty_datagrams_while_v1_still_drops_them() {
    let (target, mut seen) = spawn_observed_udp_echo_target().await;
    let sport = spawn_server_with(v2_server_for_route("udp", Transport::Udp, target)).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cport = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = run_udp_mapping_on(socket, "udp".into(), v2_client_config(sport)).await;
    });
    let local = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination: SocketAddr = format!("127.0.0.1:{cport}").parse().unwrap();
    local.send_to(&[], destination).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), seen.recv())
            .await
            .expect("v2 empty datagram never reached target"),
        Some(0)
    );
    let mut buf = [0u8; 1];
    let (n, source) = tokio::time::timeout(Duration::from_secs(5), local.recv_from(&mut buf))
        .await
        .expect("v2 target empty datagram never reached local listener")
        .unwrap();
    assert_eq!(n, 0);
    assert_eq!(source, destination);

    for _ in 0..128 {
        local.send_to(&[], destination).await.unwrap();
    }
    local.send_to(b"bounded", destination).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if seen.recv().await == Some(7) {
                break;
            }
        }
    })
    .await
    .expect("empty v2 UDP flood prevented later target delivery");
    let mut bounded = [0u8; 16];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let received = local.recv_from(&mut bounded).await.unwrap();
            if received.0 != 0 {
                return received;
            }
        }
    })
    .await
    .expect("empty v2 UDP flood prevented later local delivery");
    assert_eq!(&bounded[..n], b"bounded");

    let v1_sport = spawn_server_with(v2_server_for_route("udp", Transport::Udp, target)).await;
    let v1_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let v1_port = v1_socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = run_udp_mapping_on(
            v1_socket,
            "udp".into(),
            v1_client_config(v1_sport, Mode::Batch, None),
        )
        .await;
    });
    let v1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    v1.send_to(&[], format!("127.0.0.1:{v1_port}"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(250), seen.recv())
            .await
            .is_err(),
        "v1 must retain its historical empty-datagram drop"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_mismatched_ack_closes_local_tcp_and_stops_downstream_polling() {
    let (server_port, recv_requests, close_requests, mut recv_dropped) =
        spawn_v2_mismatched_ack_server().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let cfg = ClientConfig {
        server: format!("http://127.0.0.1:{server_port}"),
        mode: Mode::Batch,
        proxy: ProxyOpt::Direct,
        danger: true,
        keepalive: Duration::from_secs(1),
        timeout: Duration::from_secs(1),
        retry_window: Duration::from_secs(1),
        wire: WireApi::V2 { token: None },
    };
    tokio::spawn(async move {
        let _ = run_tcp_mapping_on(listener, "ignored".into(), cfg).await;
    });
    let mut local = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while recv_requests.load(Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("downstream poll did not start");
    local.write_all(b"trigger").await.unwrap();
    let mut one = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), local.read(&mut one))
        .await
        .expect("mismatched ACK did not close the local socket")
    {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("terminal v2 error leaked {n} byte(s) to local TCP"),
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        close_requests.load(Relaxed) >= 1,
        "terminal upstream error did not promptly request session close"
    );
    tokio::time::timeout(Duration::from_millis(500), &mut recv_dropped)
        .await
        .expect("terminal upstream error did not cancel in-flight downstream response")
        .expect("in-flight downstream response drop notifier disappeared");
    assert!(
        recv_requests.load(Relaxed) <= 1,
        "downstream driver continued polling after terminal upstream ACK"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_front_cuts_committed_upstream_response_and_retry_writes_target_once() {
    let (target, _, received) = spawn_counting_tcp_target().await;
    let mut backend_cfg = v2_server_for_route("tcp", Transport::Tcp, target);
    backend_cfg.auth_token = Some("proxy-token".into());
    backend_cfg.poll_wait = Duration::from_millis(10);
    let backend_port = spawn_server_with(backend_cfg).await;
    let (front_port, observed, _) = spawn_v2_fault_front(
        backend_port,
        "/api/v2/session/send",
        FrontFault::TruncateBody,
    )
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let cfg = ClientConfig {
        server: format!("http://127.0.0.1:{front_port}"),
        mode: Mode::Batch,
        proxy: ProxyOpt::Direct,
        danger: true,
        keepalive: Duration::from_secs(1),
        timeout: Duration::from_secs(2),
        retry_window: Duration::from_secs(5),
        wire: WireApi::V2 {
            token: Some("proxy-token".into()),
        },
    };
    tokio::spawn(async move {
        let _ = run_tcp_mapping_on(listener, "tcp".into(), cfg).await;
    });
    let mut local = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
    local.write_all(b"commit-once").await.unwrap();
    let mut echoed = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(5), local.read_exact(&mut echoed))
        .await
        .expect("front-cut upstream response did not retry")
        .unwrap();
    assert_eq!(&echoed, b"commit-once");
    assert_eq!(received.load(Relaxed), 11, "target write was duplicated");
    tokio::time::timeout(Duration::from_secs(2), async {
        while observed
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.path_and_query.starts_with("/api/v2/session/send"))
            .count()
            < 2
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client did not retry the truncated upstream response");

    let sends: Vec<_> = observed
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.path_and_query.starts_with("/api/v2/session/send"))
        .map(|request| {
            (
                request.method.clone(),
                request.path_and_query.clone(),
                request.headers.get("authorization").cloned(),
                request.body.clone(),
            )
        })
        .collect();
    assert_eq!(sends.len(), 2);
    assert_eq!(sends[0], sends[1], "front changed retried v2 request");
    assert_eq!(sends[0].0, "POST");
    assert!(sends[0].1.contains("seq=0"));
    assert_eq!(sends[0].2.as_ref().unwrap(), "Bearer proxy-token");
    assert_eq!(
        received.load(Relaxed),
        11,
        "target write was duplicated after the retry completed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_retries_lost_successful_open_without_a_second_target_dial() {
    let (target, connections, _) = spawn_counting_tcp_target().await;
    let backend_port = spawn_server_with(v2_server_for_route("tcp", Transport::Tcp, target)).await;
    let (front_port, observed, _) = spawn_v2_fault_front(
        backend_port,
        "/api/v2/session/open",
        FrontFault::DropResponse,
    )
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let cfg = ClientConfig {
        server: format!("http://127.0.0.1:{front_port}"),
        mode: Mode::Batch,
        proxy: ProxyOpt::Direct,
        danger: true,
        keepalive: Duration::from_secs(1),
        timeout: Duration::from_secs(2),
        retry_window: Duration::from_secs(5),
        wire: WireApi::V2 { token: None },
    };
    tokio::spawn(async move {
        let _ = run_tcp_mapping_on(listener, "tcp".into(), cfg).await;
    });
    let mut local = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
    local.write_all(b"open-once").await.unwrap();
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), local.read_exact(&mut echoed))
        .await
        .expect("client did not recover from lost successful open")
        .unwrap();
    assert_eq!(&echoed, b"open-once");
    tokio::time::timeout(Duration::from_secs(2), async {
        while observed
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.path_and_query.starts_with("/api/v2/session/open"))
            .count()
            < 3
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lost successful open was not retried");
    let opens: Vec<_> = observed
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.path_and_query.starts_with("/api/v2/session/open"))
        .map(|request| (request.method.clone(), request.path_and_query.clone()))
        .collect();
    assert_eq!(opens[1], opens[2]);
    assert_eq!(connections.load(Relaxed), 1, "open retry redialed target");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_front_cuts_cached_downstream_response_and_replays_local_delivery_once() {
    let target = spawn_echo_target().await;
    let mut backend_cfg = v2_server_for_route("tcp", Transport::Tcp, target);
    backend_cfg.auth_token = Some("proxy-token".into());
    backend_cfg.poll_wait = Duration::from_secs(2);
    let backend_port = spawn_server_with(backend_cfg).await;
    let (front_port, observed, backend_bodies) = spawn_v2_fault_front(
        backend_port,
        "/api/v2/session/recv",
        FrontFault::TruncateBody,
    )
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let cfg = ClientConfig {
        server: format!("http://127.0.0.1:{front_port}"),
        mode: Mode::Batch,
        proxy: ProxyOpt::Direct,
        danger: true,
        keepalive: Duration::from_secs(1),
        timeout: Duration::from_secs(3),
        retry_window: Duration::from_secs(5),
        wire: WireApi::V2 {
            token: Some("proxy-token".into()),
        },
    };
    tokio::spawn(async move {
        let _ = run_tcp_mapping_on(listener, "tcp".into(), cfg).await;
    });
    let mut local = TcpStream::connect(("127.0.0.1", local_port)).await.unwrap();
    local.write_all(b"down-once").await.unwrap();
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), local.read_exact(&mut echoed))
        .await
        .expect("front-cut downstream response did not replay")
        .unwrap();
    assert_eq!(&echoed, b"down-once");
    let mut extra = [0u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(250), local.read(&mut extra))
            .await
            .is_err(),
        "cached downstream response was delivered twice"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while observed
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.path_and_query.starts_with("/api/v2/session/recv"))
            .count()
            < 2
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client did not retry the truncated downstream response");

    let receives: Vec<_> = observed
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.path_and_query.starts_with("/api/v2/session/recv"))
        .map(|request| {
            (
                request.method.clone(),
                request.path_and_query.clone(),
                request.headers.get("authorization").cloned(),
            )
        })
        .collect();
    assert!(receives.len() >= 2);
    assert_eq!(receives[0], receives[1], "front changed retried v2 poll");
    assert_eq!(receives[0].0, "GET");
    assert!(receives[0].1.contains("seq=0"));
    assert_eq!(receives[0].2.as_ref().unwrap(), "Bearer proxy-token");
    let bodies: Vec<_> = backend_bodies
        .lock()
        .unwrap()
        .iter()
        .filter(|(path, _)| path.starts_with("/api/v2/session/recv?"))
        .map(|(_, body)| body.clone())
        .collect();
    assert!(bodies.len() >= 2);
    assert_eq!(
        bodies[0], bodies[1],
        "server replay body changed between the cut poll and its retry"
    );
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
