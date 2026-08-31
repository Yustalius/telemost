use std::time::Duration;

use clap::Parser;
use httptun::{
    run_mappings, selftest_ping, telemost_preset_maps, throughput, ClientConfig, Mode, PortMap,
    ProxyOpt,
};

/// Fixed local TCP/UDP listeners tunneled to an httptun-server over ordinary HTTP.
#[derive(Parser, Debug)]
#[command(name = "httptun-client", version, about)]
struct Args {
    /// httptun-server base URL.
    #[arg(long)]
    server: Option<String>,

    /// Fixed mapping, e.g. 'udp:23456->127.0.0.1:21116' (repeatable).
    #[arg(long = "map", value_name = "PROTO:LOCAL_PORT->TARGET")]
    mappings: Vec<PortMap>,

    /// Add telemost's four port mappings and use this host as the HTTPS server.
    #[arg(long, value_name = "VPS_HOST")]
    telemost_preset: Option<String>,

    /// Wire shape: stream (long bodies) or batch (short long-polled requests).
    #[arg(long, value_enum, default_value = "batch")]
    mode: Mode,

    /// Explicit outbound proxy URL. Default: read HTTPS_PROXY/ALL_PROXY from env.
    #[arg(long)]
    proxy: Option<String>,

    /// Ignore proxy env vars and connect directly (for off-VPN testing).
    #[arg(long)]
    no_proxy: bool,

    /// Accept the server's TLS cert even if untrusted (self-signed / MITM).
    #[arg(long = "danger-accept-invalid-cert")]
    danger: bool,

    /// Upstream keepalive interval, seconds.
    #[arg(long, default_value_t = 15)]
    keepalive_sec: u64,

    /// Connect timeout / batch long-poll bound, seconds.
    #[arg(long, default_value_t = 30)]
    timeout_sec: u64,

    /// -v debug, -vv trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    // ----- measurement hooks (run once and exit, printing JSON) -----
    /// Measure round-trip latency through the tunnel to the echo target.
    #[arg(long)]
    selftest_ping: bool,

    /// Measure echoed throughput through the tunnel.
    #[arg(long)]
    throughput: bool,

    /// Target for the measurement hooks ("echo" = server's built-in responder).
    #[arg(long, default_value = "echo")]
    to: String,

    /// selftest-ping: number of messages.
    #[arg(long, default_value_t = 20)]
    count: usize,

    /// selftest-ping: message size in bytes.
    #[arg(long, default_value_t = 64)]
    size: usize,

    /// throughput: duration in seconds.
    #[arg(long = "seconds", default_value_t = 10)]
    seconds: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    httptun_init_log(args.verbose);

    let proxy = if args.no_proxy {
        ProxyOpt::Direct
    } else if let Some(u) = args.proxy.clone() {
        ProxyOpt::Explicit(u)
    } else {
        ProxyOpt::Env
    };

    let server = args.server.clone().unwrap_or_else(|| {
        args.telemost_preset
            .as_deref()
            .map(server_url)
            .unwrap_or_else(|| "https://201.24.52.171:443".to_owned())
    });
    let cfg = ClientConfig {
        server,
        mode: args.mode,
        proxy,
        danger: args.danger,
        keepalive: Duration::from_secs(args.keepalive_sec.max(1)),
        timeout: Duration::from_secs(args.timeout_sec.max(1)),
    };

    if args.selftest_ping {
        selftest_ping(&cfg, &args.to, args.count, args.size).await
    } else if args.throughput {
        throughput(&cfg, &args.to, args.seconds).await
    } else {
        let mut mappings = args.mappings;
        if let Some(host) = args.telemost_preset.as_deref() {
            mappings.extend(telemost_preset_maps(host));
        }
        run_mappings(cfg, mappings).await
    }
}

fn server_url(host: &str) -> String {
    if host.starts_with('[') || !host.contains(':') {
        format!("https://{host}:443")
    } else {
        format!("https://[{host}]:443")
    }
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
