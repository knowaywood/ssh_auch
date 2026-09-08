mod auth;
mod config;
mod mailer;
mod sshca;
mod store;
mod web;

use anyhow::{Context, Result};
use config::Config;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".into());
    let cfg = Config::load(&cfg_path)?;

    std::fs::create_dir_all(&cfg.data_dir)?;
    std::fs::create_dir_all(cfg.data_dir.join("outbox"))?;
    std::fs::create_dir_all(cfg.data_dir.join("keys"))?;
    restrict_dir(&cfg.data_dir)?;
    restrict_dir(&cfg.data_dir.join("outbox"))?;
    restrict_dir(&cfg.data_dir.join("keys"))?;
    store::init_files(&cfg)?;
    sshca::ensure_ca(&cfg.ca_key, "ssh_auth-ca")?;
    let ca_pub = sshca::ca_pubkey(&cfg.ca_key)?;

    let viewer_path = cfg.data_dir.join("viewer.json");
    let viewer = sync_viewer(&cfg, &viewer_path)?;

    let users_path = cfg.data_dir.join("users.jsonl");
    let users = store::load_users(&users_path)?;
    let apps_path = cfg.data_dir.join("applications.jsonl");
    let apps = store::load_applications(&apps_path)?;

    let state = web::AppState::new(cfg.clone(), ca_pub, users, apps, viewer);
    let app = web::router(state);

    let addr: SocketAddr = cfg
        .listen
        .parse()
        .with_context(|| format!("invalid listen address {}", cfg.listen))?;
    println!(
        "status page: {}/admin (log in with the [viewer] account from config.toml)",
        cfg.base()
    );
    if cfg.tls.enabled {
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cfg.tls.cert, &cfg.tls.key)
            .await
            .with_context(|| {
                format!(
                    "failed to load TLS certificate/key ({}, {})",
                    cfg.tls.cert.display(),
                    cfg.tls.key.display()
                )
            })?;
        println!("ssh_auth listening on https://{}", cfg.listen);
        axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to listen on {}", cfg.listen))?;
        println!("ssh_auth listening on http://{}", cfg.listen);
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

fn sync_viewer(cfg: &Config, path: &std::path::Path) -> Result<Option<store::ViewerAccount>> {
    if cfg.viewer.password.is_empty() {
        println!("warn: [viewer] password is empty in config.toml — viewer login is disabled");
        return Ok(None);
    }
    let username = cfg.viewer.username.trim();
    if username.is_empty() {
        anyhow::bail!("[viewer] username must not be empty");
    }
    let stored = store::load_viewer(path)?;
    let need_write = match &stored {
        None => {
            println!(
                "viewer account \"{username}\" created in {}",
                path.display()
            );
            true
        }
        Some(acc) => {
            if acc.username != username
                || !auth::verify_password(&cfg.viewer.password, &acc.pass_hash)
            {
                println!(
                    "viewer account changed in config.toml — synced to {}",
                    path.display()
                );
                true
            } else {
                false
            }
        }
    };
    if need_write {
        let acc = store::ViewerAccount {
            username: username.to_string(),
            pass_hash: auth::hash_password(&cfg.viewer.password)?,
            updated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        };
        store::save_viewer(path, &acc)?;
        return Ok(Some(acc));
    }
    Ok(stored)
}
