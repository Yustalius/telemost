use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use httptun::{run_server, telemost_preset_routes, Mode, ServerConfig};

/// HTTP-streaming tunnel server: bridges each HTTP session to a TCP or UDP target
/// (from the `X-Target` header) or to a built-in echo responder.
#[derive(Parser, Debug)]
#[command(name = "httptun-server", version, about)]
struct Args {
    /// Address to listen on (TLS).
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: SocketAddr,

    /// Route every session to the built-in echo responder, ignoring X-Target.
    #[arg(long)]
    echo: bool,

    /// Wire-shape hint (behavior is driven per-request; this is informational).
    #[arg(long, value_enum, default_value = "batch")]
    mode: Mode,

    /// Downstream keepalive interval, seconds.
    #[arg(long, default_value_t = 15)]
    keepalive_sec: u64,

    /// Target dial timeout, seconds.
    #[arg(long, default_value_t = 30)]
    timeout_sec: u64,

    /// Batch-mode long-poll wait for the first byte, seconds.
    #[arg(long, default_value_t = 5)]
    poll_wait_sec: u64,

    /// Extra Subject Alternative Names for the self-signed cert (repeatable).
    /// Ignored when --tls-cert/--tls-key provide a real certificate.
    #[arg(long = "san", value_name = "HOST")]
    sans: Vec<String>,

    /// PEM certificate chain (e.g. Let's Encrypt fullchain.pem). Requires --tls-key.
    #[arg(long, value_name = "PATH")]
    tls_cert: Option<PathBuf>,

    /// PEM private key paired with --tls-cert.
    #[arg(long, value_name = "PATH")]
    tls_key: Option<PathBuf>,

    /// Shared bearer token required on every /api/v1/* request.
    #[arg(long, value_name = "TOKEN")]
    auth_token: Option<String>,

    /// Maximum concurrent sessions before /api/v1/session/open returns 429.
    #[arg(long, default_value_t = 256)]
    max_sessions: usize,

    /// Also accept the legacy /o /u /d /c + X-Target API (migration only).
    #[arg(long)]
    allow_legacy: bool,

    /// Public host the relay route dials (hbbr rejects loopback-origin relays).
    #[arg(long, default_value = "201.24.52.171")]
    relay_host: String,

    /// -v debug, -vv trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    httptun_init_log(args.verbose);

    let mut sans = args.sans.clone();
    for d in ["localhost", "127.0.0.1", "201.24.52.171"] {
        if !sans.iter().any(|s| s == d) {
            sans.push(d.to_owned());
        }
    }

    let cfg = ServerConfig {
        listen: args.listen,
        echo_all: args.echo,
        mode: args.mode,
        keepalive: Duration::from_secs(args.keepalive_sec.max(1)),
        timeout: Duration::from_secs(args.timeout_sec.max(1)),
        poll_wait: Duration::from_secs(args.poll_wait_sec.max(1)),
        sans,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
        auth_token: args.auth_token.clone(),
        max_sessions: args.max_sessions,
        allow_legacy: args.allow_legacy,
        routes: telemost_preset_routes(&args.relay_host),
    };
    run_server(cfg).await
}

fn httptun_init_log(verbose: u8) {
    let level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| format!("httptun={level}"));
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(filter)).init();
}
