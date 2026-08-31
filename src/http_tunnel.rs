use std::time::Duration;

use hbb_common::{
    anyhow::{anyhow, Result},
    config::RENDEZVOUS_SERVERS,
    log, tokio,
};
use httptun::{start_mappings, telemost_preset_maps, ClientConfig, Mode, ProxyOpt};

pub async fn start() {
    if let Err(error) = start_inner().await {
        log::error!("HTTP batch tunnel failed to start: {error}");
    }
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
