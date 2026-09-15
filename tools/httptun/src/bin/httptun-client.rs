use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use httptun::{
    enable_diagnostics, run_mappings, run_reverse, run_reverse_diagnostic, selftest_ping,
    telemost_preset_maps_v1, throughput, tls_probe, ClientConfig, Mode, PortMap, ProxyOpt,
    ReverseMap, WireApi,
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

    /// Reverse mapping, e.g. 'probe->127.0.0.1:3128' (repeatable).
    #[arg(
        long = "reverse-map",
        value_name = "ENDPOINT->TARGET",
        conflicts_with_all = ["mappings", "telemost_preset", "tls_probe", "selftest_ping", "throughput"]
    )]
    reverse_mappings: Vec<ReverseMap>,

    /// File containing the persistent reverse owner id.
    #[arg(long, value_name = "PATH", requires = "reverse_mappings")]
    reverse_owner_file: Option<PathBuf>,

    /// Run the server-side baseline suite through a claimed reverse endpoint,
    /// print its final JSON report, and exit.
    #[arg(
        long,
        value_name = "ENDPOINT",
        conflicts_with_all = ["mappings", "reverse_mappings", "telemost_preset", "tls_probe", "selftest_ping", "throughput"]
    )]
    reverse_diagnostic_run: Option<String>,

    /// Stable identifier used to correlate one diagnostic package.
    #[arg(long, value_name = "ID", requires = "reverse_diagnostic_run")]
    diagnostic_run_id: Option<String>,

    /// Number of complete baseline passes.
    #[arg(long, default_value_t = 3, requires = "reverse_diagnostic_run")]
    diagnostic_passes: u8,

    /// Profile label embedded in the server-side diagnostic result.
    #[arg(
        long,
        default_value = "A-v2-baseline",
        requires = "reverse_diagnostic_run"
    )]
    diagnostic_profile: String,

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

    /// Protocol API version. v2 is sequenced batch-only; v1 remains available
    /// for migration.
    #[arg(long, value_enum)]
    wire_api: Option<WireChoice>,

    /// Shared bearer token for the /api/v1/* and /api/v2/* APIs.
    #[arg(long, conflicts_with = "token_file")]
    token: Option<String>,

    /// Read the shared bearer token from a one-line file.
    #[arg(long, value_name = "PATH", conflicts_with = "token")]
    token_file: Option<PathBuf>,

    /// Upstream keepalive interval, seconds.
    #[arg(long, default_value_t = 15)]
    keepalive_sec: u64,

    /// Connect timeout / batch long-poll bound, seconds.
    #[arg(long, default_value_t = 30)]
    timeout_sec: u64,

    /// Total retry window for one v2 send or receive operation, seconds.
    #[arg(long, default_value_t = 60)]
    retry_window_sec: u64,

    /// Opt-in profile B finite-body limit in KiB: 64, 128, or 256.
    #[arg(long, value_name = "KIB")]
    experimental_batch_kib: Option<usize>,

    /// -v debug, -vv trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Write sanitized transport events as JSON Lines.
    #[arg(long, value_name = "PATH")]
    diagnostics_jsonl: Option<PathBuf>,

    // ----- measurement hooks (run once and exit, printing JSON) -----
    /// Probe TLS validation to <URL> with the tunnel's exact stack (native root
    /// store, honoring --danger-accept-invalid-cert and the env proxy). Prints
    /// JSON and exits; use it under corp VPN to test MWG TLS interception.
    #[arg(long, value_name = "URL")]
    tls_probe: Option<String>,

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

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum WireChoice {
    V2,
    V1,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    httptun_init_log(args.verbose);
    if let Some(path) = args.diagnostics_jsonl.as_deref() {
        enable_diagnostics(path, "client").await?;
    }

    let token = match args.token_file.as_deref() {
        Some(path) => Some(read_one_line(path, "token")?),
        None => args.token.clone(),
    };
    let reverse_owner = match args.reverse_owner_file.as_deref() {
        Some(path) => Some(read_one_line(path, "reverse owner id")?),
        None if args.reverse_mappings.is_empty() => None,
        None => anyhow::bail!("--reverse-owner-file is required with --reverse-map"),
    };

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
    let choice = args.wire_api.unwrap_or(WireChoice::V2);
    let wire = match choice {
        WireChoice::V2 => WireApi::V2 {
            token: token.clone(),
        },
        WireChoice::V1 => WireApi::V1 { token },
    };
    if matches!(wire, WireApi::V2 { .. }) && args.mode != Mode::Batch {
        anyhow::bail!("--wire-api v2 requires --mode batch");
    }
    let experimental_batch_bytes = match args.experimental_batch_kib {
        Some(kib @ (64 | 128 | 256)) => Some(kib * 1024),
        Some(_) => anyhow::bail!("--experimental-batch-kib must be 64, 128, or 256"),
        None => None,
    };
    if experimental_batch_bytes.is_some() && args.reverse_mappings.is_empty() {
        anyhow::bail!("--experimental-batch-kib requires --reverse-map");
    }
    let cfg = ClientConfig {
        server,
        mode: args.mode,
        proxy,
        danger: args.danger,
        keepalive: Duration::from_secs(args.keepalive_sec.max(1)),
        timeout: Duration::from_secs(args.timeout_sec.max(1)),
        retry_window: Duration::from_secs(args.retry_window_sec.max(1)),
        experimental_batch_bytes,
        wire,
    };

    if let Some(endpoint) = args.reverse_diagnostic_run.as_deref() {
        let run_id = args
            .diagnostic_run_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--diagnostic-run-id is required"))?;
        run_reverse_diagnostic(
            &cfg,
            endpoint,
            run_id,
            &args.diagnostic_profile,
            args.diagnostic_passes,
        )
        .await
    } else if !args.reverse_mappings.is_empty() {
        run_reverse(
            cfg,
            args.reverse_mappings,
            reverse_owner.unwrap_or_default(),
        )
        .await
    } else if let Some(url) = args.tls_probe.as_deref() {
        tls_probe(&cfg, url).await
    } else if args.selftest_ping {
        selftest_ping(&cfg, &args.to, args.count, args.size).await
    } else if args.throughput {
        throughput(&cfg, &args.to, args.seconds).await
    } else {
        let mut mappings = args.mappings;
        if args.telemost_preset.is_some() {
            mappings.extend(telemost_preset_maps_v1());
        }
        run_mappings(cfg, mappings).await
    }
}

fn read_one_line(path: &Path, label: &str) -> anyhow::Result<String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("reading {label} file {}: {error}", path.display()))?;
    let mut lines = contents.lines().filter(|line| !line.trim().is_empty());
    let value = lines
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{label} file {} is empty", path.display()))?;
    if lines.next().is_some() {
        anyhow::bail!(
            "{label} file {} must contain one non-empty line",
            path.display()
        );
    }
    Ok(value.to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_is_default_and_removed_legacy_options_are_rejected() {
        let args = Args::try_parse_from(["httptun-client"]).unwrap();
        assert_eq!(args.wire_api.unwrap_or(WireChoice::V2), WireChoice::V2);
        assert!(Args::try_parse_from(["httptun-client", "--wire-api", "legacy"]).is_err());
        assert!(Args::try_parse_from(["httptun-client", "--legacy"]).is_err());
    }

    #[test]
    fn reverse_cli_is_isolated_from_forward_and_requires_owner_at_runtime() {
        let args = Args::try_parse_from([
            "httptun-client",
            "--reverse-map",
            "probe->127.0.0.1:3128",
            "--reverse-owner-file",
            "owner-id",
        ])
        .unwrap();
        assert_eq!(args.reverse_mappings.len(), 1);
        assert!(Args::try_parse_from([
            "httptun-client",
            "--reverse-map",
            "probe->127.0.0.1:3128",
            "--map",
            "tcp:1234->echo:1234",
        ])
        .is_err());
        assert!(
            Args::try_parse_from(["httptun-client", "--token", "one", "--token-file", "two",])
                .is_err()
        );
    }
}
