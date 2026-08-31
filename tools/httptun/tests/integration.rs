//! End-to-end tests for httptun, all runnable WITHOUT the corp VPN.
//!
//! They exercise fixed TCP/UDP listeners -> HTTP tunnel -> server -> target,
//! plus the measurement-hook JSON via the compiled client binary. Run with:
//!     cargo test -- --test-threads=1

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use httptun::{
    run_server_on, run_tcp_mapping_on, run_udp_mapping_on, ClientConfig, Mode, ProxyOpt,
    ServerConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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

async fn spawn_server(echo_all: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = ServerConfig {
        listen: any_addr(),
        echo_all,
        mode: Mode::Stream,
        keepalive: Duration::from_secs(5),
        timeout: Duration::from_secs(5),
        poll_wait: Duration::from_secs(1),
        sans: vec!["localhost".into(), "127.0.0.1".into()],
    };
    tokio::spawn(async move {
        let _ = run_server_on(listener, cfg).await;
    });
    port
}

fn client_config(server_port: u16, mode: Mode, proxy: ProxyOpt) -> ClientConfig {
    ClientConfig {
        server: format!("https://127.0.0.1:{server_port}"),
        mode,
        proxy,
        danger: true,
        keepalive: Duration::from_secs(5),
        timeout: Duration::from_secs(5),
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
