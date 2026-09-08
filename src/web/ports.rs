use super::AppState;
use crate::config::Config;
use crate::store::{self, PortEntry};
use std::time::{Duration, Instant};

pub(super) async fn get_ports(state: &AppState) -> Result<Vec<PortEntry>, String> {
    if state.cfg.ports_source != "frps" {
        return store::load_ports(&state.cfg.ports_file)
            .map_err(|error| format!("failed to read ports.json: {error:#}"));
    }
    if let Some((time, ports)) = &*state.ports_cache.lock().unwrap()
        && time.elapsed() < Duration::from_secs(60)
    {
        return Ok(ports.clone());
    }
    let ports = fetch_frps(&state.cfg)
        .await
        .map_err(|error| format!("failed to fetch port list from frps API: {error:#}"))?;
    *state.ports_cache.lock().unwrap() = Some((Instant::now(), ports.clone()));
    Ok(ports)
}

async fn fetch_frps(cfg: &Config) -> anyhow::Result<Vec<PortEntry>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let url = format!("{}/api/proxy/tcp", cfg.frps.api.trim_end_matches('/'));
    let mut request = client.get(&url);
    if !cfg.frps.username.is_empty() {
        request = request.basic_auth(&cfg.frps.username, Some(&cfg.frps.password));
    }
    let response: serde_json::Value = request.send().await?.error_for_status()?.json().await?;
    Ok(parse_frps_ports(&response))
}

pub(super) fn parse_frps_ports(value: &serde_json::Value) -> Vec<PortEntry> {
    let mut ports = Vec::new();
    if let Some(proxies) = value["proxies"].as_array() {
        for proxy in proxies {
            // frp v0.71.0's legacy dashboard endpoint returns each TCP
            // proxy as `{ name, conf: { remotePort }, ... }`. Offline
            // proxies have no `conf`, so they are intentionally omitted.
            let Some(port) = proxy["conf"]["remotePort"].as_u64() else {
                continue;
            };
            if !(1..=65535).contains(&port) {
                continue;
            }
            ports.push(PortEntry {
                port: port as u16,
                name: proxy["name"].as_str().unwrap_or("unknown").to_string(),
                desc: "from frps".into(),
            });
        }
    }
    ports.sort_by_key(|entry| entry.port);
    ports.dedup_by_key(|entry| entry.port);
    ports
}
