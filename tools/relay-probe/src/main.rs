//! relay-probe — headless end-to-end proof that the real hbbr relay carries a
//! bidirectional session between two independent endpoints.
//!
//! Speaks the hbbr relay handshake directly: connect, send `RequestRelay{uuid}`,
//! then exchange raw framed bytes. hbbr pairs the two connections that present
//! the same uuid and pipes bytes verbatim between them.
//!
//! Two roles, same binary:
//!   * `echo` — connect to the relay THROUGH the tunnel (e.g. 127.0.0.1:23457),
//!     send RequestRelay, then reflect every frame back. Start this one FIRST.
//!   * `ping` — connect to the relay DIRECTLY (e.g. 201.24.52.171:21117), send
//!     RequestRelay, push a payload, read the echo, verify, print JSON.
//!
//! If `ping` gets its bytes back, a real relay session flowed end-to-end: one
//! side over the HTTP-batch tunnel, one side direct, meeting on the same hbbr.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use clap::Parser;
use hbb_common::{
    anyhow::{bail, Context, Result},
    bytes::Bytes,
    log,
    rendezvous_proto::*,
    tcp::FramedStream,
    tokio, Stream,
};

/// Relay licence key of this deployment (hbbs/hbbr `-k`). Same value baked into
/// telemost's `RENDEZVOUS_SERVERS` pubkey; overridable with `--key`.
const DEFAULT_KEY: &str = "pleMi5xooFy81jTX2UvLNBW64t1SyJD84XjO1jGfSLo=";

#[derive(Parser, Debug)]
#[command(name = "relay-probe", about)]
struct Args {
    /// Role: "echo" (reflector, via tunnel, start first) or "ping" (initiator).
    #[arg(long)]
    role: String,

    /// Relay server address, e.g. 127.0.0.1:23457 (tunnel) or 201.24.52.171:21117 (direct).
    #[arg(long)]
    relay_server: SocketAddr,

    /// Shared relay uuid; both roles MUST pass the same value.
    #[arg(long)]
    uuid: String,

    /// Relay licence key (hbbr `-k`). Defaults to this deployment's key.
    #[arg(long, default_value = DEFAULT_KEY)]
    key: String,

    /// ping: payload size in bytes.
    #[arg(long, default_value_t = 256)]
    size: usize,

    /// ping: number of echo round-trips.
    #[arg(long, default_value_t = 5)]
    count: usize,

    /// Connect / per-round read timeout, ms.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,

    /// ping: wait before the first payload so hbbr can pair the two sides, ms.
    #[arg(long, default_value_t = 700)]
    pair_delay_ms: u64,

    /// -v debug, -vv trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

async fn open_relay(a: &Args) -> Result<Stream> {
    let fs = FramedStream::new(a.relay_server, None, a.timeout_ms)
        .await
        .with_context(|| format!("connecting to relay {}", a.relay_server))?;
    let mut s = Stream::Tcp(fs);
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        licence_key: a.key.clone(),
        uuid: a.uuid.clone(),
        conn_type: ConnType::PORT_FORWARD.into(),
        ..Default::default()
    });
    s.send(&msg).await.context("sending RequestRelay")?;
    log::info!(
        "RequestRelay sent to {} (uuid={})",
        a.relay_server,
        a.uuid
    );
    Ok(s)
}

async fn run_echo(a: &Args) -> Result<()> {
    let mut s = open_relay(a).await?;
    log::info!("echo: waiting for peer frames via relay (reflecting) ...");
    let idle_ms = 600_000; // 10 min ceiling for the whole test
    loop {
        match s.next_timeout(idle_ms).await {
            Some(Ok(bytes)) => {
                let n = bytes.len();
                s.send_bytes(bytes.freeze())
                    .await
                    .context("reflecting frame")?;
                log::debug!("echo: reflected {n} bytes");
            }
            Some(Err(e)) => {
                log::warn!("echo: read error: {e}");
                break;
            }
            None => {
                log::info!("echo: relay closed / idle");
                break;
            }
        }
    }
    Ok(())
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

async fn run_ping(a: &Args) -> Result<()> {
    let mut s = open_relay(a).await?;
    // Give hbbr time to pair both sides before the first payload so no bytes
    // are sent into an unpaired (buffering) relay.
    tokio::time::sleep(Duration::from_millis(a.pair_delay_ms)).await;

    let payload: Vec<u8> = (0..a.size).map(|i| (i % 251) as u8).collect();
    let mut rtts: Vec<f64> = Vec::with_capacity(a.count);
    let mut ok = 0usize;

    for i in 0..a.count {
        let t = Instant::now();
        s.send_bytes(Bytes::from(payload.clone()))
            .await
            .context("sending payload")?;
        match s.next_timeout(a.timeout_ms).await {
            Some(Ok(b)) => {
                if b.as_ref() == payload.as_slice() {
                    ok += 1;
                    rtts.push(t.elapsed().as_secs_f64() * 1000.0);
                    log::debug!("ping: round {i} ok");
                } else {
                    log::warn!(
                        "ping: round {i} mismatch (got {} bytes, want {})",
                        b.len(),
                        payload.len()
                    );
                }
            }
            Some(Err(e)) => bail!("relay read error on round {i}: {e}"),
            None => bail!(
                "relay closed before echo on round {i} (pairing failed? wrong uuid/key, or echo side not up)"
            ),
        }
    }

    rtts.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let report = serde_json::json!({
        "echo_ok": ok == a.count && a.count > 0,
        "round_trips": a.count,
        "ok": ok,
        "bytes": a.size,
        "rtt_ms": {
            "min": round3(rtts.first().copied().unwrap_or(0.0)),
            "p50": round3(percentile(&rtts, 50.0)),
            "p95": round3(percentile(&rtts, 95.0)),
            "max": round3(rtts.last().copied().unwrap_or(0.0)),
        },
        "relay_server": a.relay_server.to_string(),
        "uuid": a.uuid,
    });
    println!("{report}");
    if ok != a.count {
        bail!("only {ok}/{} round-trips echoed", a.count);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let level = match args.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| format!("relay_probe={level}"));
    hbb_common::env_logger::Builder::from_env(
        hbb_common::env_logger::Env::default().default_filter_or(filter),
    )
    .init();

    match args.role.as_str() {
        "echo" => run_echo(&args).await,
        "ping" => run_ping(&args).await,
        other => bail!("unknown --role {other}; expected echo|ping"),
    }
}
