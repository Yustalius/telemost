use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hbb_common::{
    anyhow::Result,
    config::{HTTP_TUNNEL_AUTH_TOKEN, HTTP_TUNNEL_SERVER_HOST},
    log, tokio,
};
use httptun::{start_mappings, telemost_preset_maps_v1, ClientConfig, Mode, ProxyOpt, WireApi};

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
    // Dial the real domain so TLS carries a valid SNI and publicly-trusted cert
    // (O1). Port 443 is implicit for https, matching an ordinary web app.
    let server = format!("https://{HTTP_TUNNEL_SERVER_HOST}");
    let config = ClientConfig {
        server,
        mode: Mode::Batch,
        proxy: ProxyOpt::Env,
        // The VPS now serves a publicly-trusted certificate for the domain, so
        // validate it (no bare-IP, no self-signed acceptance).
        danger: false,
        keepalive: Duration::from_secs(15),
        timeout: Duration::from_secs(30),
        wire: WireApi::V1 {
            token: Some(HTTP_TUNNEL_AUTH_TOKEN.to_owned()),
        },
    };
    let task = start_mappings(config, telemost_preset_maps_v1()).await?;
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
