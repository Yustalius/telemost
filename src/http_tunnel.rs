use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hbb_common::{
    anyhow::{anyhow, Result},
    config::RENDEZVOUS_SERVERS,
    log, tokio,
};
use httptun::{start_mappings, telemost_preset_maps, ClientConfig, Mode, ProxyOpt};

const MAX_START_ATTEMPTS: u32 = 10;
const MAX_RETRY_DELAY_SECS: u64 = 5;

static READY: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

pub async fn start() -> bool {
    // Ports 23455-23457 may still be held by a just-killed predecessor for a
    // few seconds, so retry with backoff instead of failing on the first try.
    let mut last_error = None;
    for attempt in 1..=MAX_START_ATTEMPTS {
        match start_inner().await {
            Ok(()) => {
                READY.store(true, Ordering::Release);
                return true;
            }
            Err(error) => {
                log::warn!("HTTP batch tunnel start attempt {attempt} failed: {error}");
                if attempt < MAX_START_ATTEMPTS {
                    let delay = Duration::from_secs((attempt as u64).min(MAX_RETRY_DELAY_SECS));
                    tokio::time::sleep(delay).await;
                }
                last_error = Some(error);
            }
        }
    }
    match last_error {
        Some(error) => log::error!("HTTP batch tunnel failed to start: {error}"),
        None => log::error!("HTTP batch tunnel failed to start"),
    }
    READY.store(false, Ordering::Release);
    false
}

async fn start_inner() -> Result<()> {
    let host = RENDEZVOUS_SERVERS
        .first()
        .ok_or_else(|| anyhow!("no rendezvous server configured"))?;
    let server = if host.contains(':') {
        format!("https://[{host}]:443")
    } else {
        format!("https://{host}:443")
    };
    let config = ClientConfig {
        server,
        mode: Mode::Batch,
        proxy: ProxyOpt::Env,
        // The current VPS endpoint generates its own certificate at startup.
        danger: true,
        keepalive: Duration::from_secs(15),
        timeout: Duration::from_secs(30),
    };
    let task = start_mappings(config, telemost_preset_maps(host)).await?;
    log::info!("HTTP batch tunnel is ready on 127.0.0.1:23455-23457");
    tokio::spawn(async move {
        match task.await {
            Ok(Ok(())) => log::warn!("HTTP batch tunnel stopped"),
            Ok(Err(error)) => log::error!("HTTP batch tunnel stopped: {error}"),
            Err(error) => log::error!("HTTP batch tunnel task failed: {error}"),
        }
    });
    Ok(())
}
