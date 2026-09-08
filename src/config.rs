use crate::store::EmailConfig;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize, Clone, Default)]
pub struct ViewerCfg {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    pub listen: String,
    pub base_url: String,
    pub tls: TlsCfg,
    pub viewer: ViewerCfg,
    pub email: EmailConfig,
    pub data_dir: PathBuf,
    pub ports_source: String,
    pub ports_file: PathBuf,
    pub frps: FrpsCfg,
    pub ca_key: PathBuf,
    pub cert_principals: Vec<String>,
    pub cert_validity: String,
    pub gateway_port: u16,
    pub gateway_user: String,
}

#[derive(Deserialize, Clone)]
#[serde(default)]
pub struct TlsCfg {
    pub enabled: bool,
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl Default for TlsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            cert: "tls/fullchain.pem".into(),
            key: "tls/privkey.pem".into(),
        }
    }
}

#[derive(Deserialize, Clone, Default)]
pub struct FrpsCfg {
    pub api: String,
    pub username: String,
    pub password: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".into(),
            base_url: "http://127.0.0.1:8080".into(),
            tls: Default::default(),
            viewer: Default::default(),
            email: Default::default(),
            data_dir: "data".into(),
            ports_source: "frps".into(),
            ports_file: "data/ports.json".into(),
            frps: Default::default(),
            ca_key: "data/ca_ed25519".into(),
            cert_principals: vec!["ssh-auth".into()],
            cert_validity: String::new(),
            gateway_port: 2222,
            gateway_user: "tunnel".into(),
        }
    }
}

impl Config {
    pub fn load(p: &str) -> Result<Self> {
        let s = std::fs::read_to_string(p)
            .with_context(|| format!("failed to read config {p} (copy config.example.toml)"))?;
        Ok(toml::from_str(&s)?)
    }

    pub fn base(&self) -> &str {
        self.base_url.trim_end_matches('/')
    }
}
