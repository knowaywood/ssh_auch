use anyhow::{Context, Result, bail};
use lettre::{
    Message, SmtpTransport, Transport, message::Mailbox, message::MultiPart,
    transport::smtp::authentication::Credentials,
};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::store::EmailConfig;

pub enum Outcome {
    Sent(String),
    DryRun(PathBuf),
}

const RESEND_BASE: &str = "https://api.resend.com";
const BREVO_BASE: &str = "https://api.brevo.com";

pub async fn send(
    email_cfg: &EmailConfig,
    outbox_dir: &Path,
    subject: &str,
    plain: &str,
    html: &str,
) -> Result<Outcome> {
    match email_cfg.provider.as_str() {
        "resend" => Ok(Outcome::Sent(
            send_resend(email_cfg, subject, plain, html).await?,
        )),
        "brevo" => Ok(Outcome::Sent(
            send_brevo(email_cfg, subject, plain, html).await?,
        )),
        "smtp" => {
            let cfg = email_cfg.clone();
            let subject = subject.to_string();
            let plain = plain.to_string();
            let html = html.to_string();
            let dir = outbox_dir.to_path_buf();
            tokio::task::spawn_blocking(move || send_smtp(&cfg, &dir, &subject, &plain, &html))
                .await
                .map_err(|e| anyhow::anyhow!("email task failed: {e}"))?
        }
        _ => Ok(Outcome::DryRun(dry_run(
            email_cfg, outbox_dir, subject, plain, html,
        )?)),
    }
}

fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?)
}

async fn send_resend(cfg: &EmailConfig, subject: &str, plain: &str, html: &str) -> Result<String> {
    if cfg.api_key.is_empty() {
        bail!("config.toml [email] api_key is not set (get one at resend.com)");
    }
    if cfg.sender.is_empty() {
        bail!(
            "config.toml [email] sender is not set (use onboarding@resend.dev for the free tier)"
        );
    }
    let base = if cfg.api_base.is_empty() {
        RESEND_BASE
    } else {
        cfg.api_base.as_str()
    };
    let resp = http_client()?
        .post(format!("{base}/emails"))
        .bearer_auth(&cfg.api_key)
        .json(&serde_json::json!({
            "from": cfg.sender,
            "to": [cfg.recipient],
            "subject": subject,
            "text": plain,
            "html": html,
        }))
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("resend API {status}: {}", text.trim());
    }
    Ok(format!("resend {status}"))
}

async fn send_brevo(cfg: &EmailConfig, subject: &str, plain: &str, html: &str) -> Result<String> {
    if cfg.api_key.is_empty() {
        bail!("config.toml [email] api_key is not set (get one at brevo.com)");
    }
    if cfg.sender.is_empty() {
        bail!("config.toml [email] sender is not set (verify the sender address in Brevo first)");
    }
    let base = if cfg.api_base.is_empty() {
        BREVO_BASE
    } else {
        cfg.api_base.as_str()
    };
    let resp = http_client()?
        .post(format!("{base}/v3/smtp/email"))
        .header("api-key", &cfg.api_key)
        .header("accept", "application/json")
        .json(&serde_json::json!({
            "sender": {"email": cfg.sender},
            "to": [{"email": cfg.recipient}],
            "subject": subject,
            "textContent": plain,
            "htmlContent": html,
        }))
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("brevo API {status}: {}", text.trim());
    }
    Ok(format!("brevo {status}"))
}

fn send_smtp(
    email_cfg: &EmailConfig,
    outbox_dir: &Path,
    subject: &str,
    plain: &str,
    html: &str,
) -> Result<Outcome> {
    if !email_cfg.smtp.enabled {
        return Ok(Outcome::DryRun(dry_run(
            email_cfg, outbox_dir, subject, plain, html,
        )?));
    }

    let from: Mailbox = email_cfg
        .smtp
        .from
        .parse()
        .context("invalid config.toml [email].smtp.from")?;
    let to: Mailbox = email_cfg
        .recipient
        .parse()
        .context("invalid config.toml [email].recipient")?;
    let msg = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .multipart(MultiPart::alternative_plain_html(
            plain.to_string(),
            html.to_string(),
        ))?;

    let host = email_cfg.smtp.host.clone();
    let builder = match email_cfg.smtp.tls.as_str() {
        "none" => Ok(SmtpTransport::builder_dangerous(&host)),
        "starttls" => SmtpTransport::starttls_relay(&host),
        _ => SmtpTransport::relay(&host),
    }?;
    let builder = builder.port(email_cfg.smtp.port);
    let builder = if !email_cfg.smtp.username.is_empty() {
        builder.credentials(Credentials::new(
            email_cfg.smtp.username.clone(),
            email_cfg.smtp.password.clone(),
        ))
    } else {
        builder
    };
    builder.build().send(&msg).context("SMTP send failed")?;
    Ok(Outcome::Sent("smtp".into()))
}

fn dry_run(
    email_cfg: &EmailConfig,
    outbox_dir: &Path,
    subject: &str,
    plain: &str,
    html: &str,
) -> Result<PathBuf> {
    std::fs::create_dir_all(outbox_dir)?;
    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let name = format!(
        "{}_{}.txt",
        ts,
        chrono::Utc::now().timestamp_subsec_millis()
    );
    let path = outbox_dir.join(name);
    let content = format!(
        "To: {}\r\nSubject: {}\r\n\r\n----- text/plain -----\r\n{}\r\n----- text/html -----\r\n{}\r\n",
        email_cfg.recipient, subject, plain, html
    );
    std::fs::write(&path, content)?;
    Ok(path)
}
