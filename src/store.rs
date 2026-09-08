use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::config::Config;

#[derive(Serialize, Deserialize, Clone)]
pub struct PortEntry {
    pub port: u16,
    pub name: String,
    #[serde(default)]
    pub desc: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub username: String,
    pub pass_hash: String,
    pub status: String,
    pub created_at: String,
    #[serde(default)]
    pub decided_at: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
}

impl User {
    pub fn new(username: &str, pass_hash: &str, created_at: String) -> Self {
        Self {
            username: username.into(),
            pass_hash: pass_hash.into(),
            status: "none".into(),
            created_at,
            decided_at: None,
            fingerprint: None,
            cert: None,
            token: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Application {
    pub id: String,
    pub username: String,
    pub approve_token: String,
    pub pubkey: String,
    pub fingerprint: String,
    pub status: String,
    pub created_at: String,
    #[serde(default)]
    pub decided_at: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
}

impl Application {
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ViewerAccount {
    pub username: String,
    pub pass_hash: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct SmtpConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub tls: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EmailConfig {
    pub recipient: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub sender: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub api_base: String,
    #[serde(default)]
    pub smtp: SmtpConfig,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            recipient: "knowaywood@outlook.com".into(),
            provider: "dryrun".into(),
            sender: String::new(),
            api_key: String::new(),
            api_base: String::new(),
            smtp: SmtpConfig {
                enabled: false,
                host: String::new(),
                port: 465,
                username: String::new(),
                password: String::new(),
                from: String::new(),
                tls: "implicit".into(),
            },
        }
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(p: &Path) -> Result<Option<T>> {
    if !p.exists() {
        return Ok(None);
    }
    let s = fs::read_to_string(p).with_context(|| format!("failed to read {}", p.display()))?;
    Ok(Some(serde_json::from_str(&s).with_context(|| {
        format!("failed to parse {}", p.display())
    })?))
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = path.with_extension("tmp");
    fs::write(&temp, contents)?;
    restrict_file(&temp)?;
    fs::rename(&temp, path)?;
    restrict_file(path)?;
    Ok(())
}

fn write_json<T: Serialize + ?Sized>(p: &Path, v: &T) -> Result<()> {
    let mut contents = serde_json::to_vec_pretty(v)?;
    contents.push(b'\n');
    atomic_write(p, &contents)
}

fn read_jsonl<T: for<'de> Deserialize<'de>>(p: &Path) -> Result<Vec<T>> {
    if !p.exists() {
        return Ok(Vec::new());
    }
    let s = fs::read_to_string(p).with_context(|| format!("failed to read {}", p.display()))?;
    s.lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(n, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("failed to parse {} line {}", p.display(), n + 1))
        })
        .collect()
}

fn write_jsonl<T: Serialize>(p: &Path, values: &[T]) -> Result<()> {
    let mut contents = Vec::new();
    for value in values {
        serde_json::to_writer(&mut contents, value)?;
        contents.push(b'\n');
    }
    atomic_write(p, &contents)
}

#[cfg(unix)]
fn restrict_file(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_p: &Path) -> Result<()> {
    Ok(())
}

pub fn load_ports(p: &Path) -> Result<Vec<PortEntry>> {
    Ok(read_json::<Vec<PortEntry>>(p)?.unwrap_or_default())
}

pub fn save_ports(p: &Path, v: &[PortEntry]) -> Result<()> {
    write_json(p, &v)
}

pub fn load_users(p: &Path) -> Result<Vec<User>> {
    if p.exists() {
        return read_jsonl(p);
    }
    let legacy = p.with_file_name("users.json");
    let values = read_json::<Vec<User>>(&legacy)?.unwrap_or_default();
    if legacy.exists() {
        write_jsonl(p, &values)?;
    }
    Ok(values)
}

pub fn save_users(p: &Path, v: &[User]) -> Result<()> {
    write_jsonl(p, v)
}

pub fn load_applications(p: &Path) -> Result<Vec<Application>> {
    if p.exists() {
        return read_jsonl(p);
    }
    let legacy = p.with_file_name("applications.json");
    let values = read_json::<Vec<Application>>(&legacy)?.unwrap_or_default();
    if legacy.exists() {
        write_jsonl(p, &values)?;
    }
    Ok(values)
}

pub fn save_applications(p: &Path, v: &[Application]) -> Result<()> {
    write_jsonl(p, v)
}

pub fn load_viewer(p: &Path) -> Result<Option<ViewerAccount>> {
    read_json(p)
}

pub fn save_viewer(p: &Path, v: &ViewerAccount) -> Result<()> {
    write_json(p, v)
}

pub fn init_files(cfg: &Config) -> Result<()> {
    if !cfg.ports_file.exists() {
        let examples = vec![
            PortEntry {
                port: 10001,
                name: "Internal Server A".into(),
                desc: "Example entry, edit per your frpc config".into(),
            },
            PortEntry {
                port: 10002,
                name: "Internal Server B".into(),
                desc: "Example entry, edit per your frpc config".into(),
            },
        ];
        save_ports(&cfg.ports_file, &examples)?;
    }
    let users_path = cfg.data_dir.join("users.jsonl");
    if !users_path.exists() {
        let legacy = cfg.data_dir.join("users.json");
        if !legacy.exists() {
            save_users(&users_path, &[])?;
        }
    }
    let apps_path = cfg.data_dir.join("applications.jsonl");
    if !apps_path.exists() {
        let legacy = cfg.data_dir.join("applications.json");
        if !legacy.exists() {
            save_applications(&apps_path, &[])?;
        }
    }
    std::fs::create_dir_all(cfg.data_dir.join("keys"))?;
    Ok(())
}
