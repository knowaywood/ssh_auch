use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_path(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("ssh_auth_{tag}_{nanos}"))
}

fn run_ssh_keygen(args: &[&str]) -> Result<String> {
    let out = Command::new("ssh-keygen")
        .args(args)
        .output()
        .context("failed to run ssh-keygen (is openssh-client installed?)")?;
    if !out.status.success() {
        bail!(
            "ssh-keygen {} failed: {}",
            args[0],
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub fn ensure_ca(key: &Path, comment: &str) -> Result<()> {
    if !key.exists() {
        if let Some(p) = key.parent() {
            std::fs::create_dir_all(p)?;
        }
        let ks = key.to_string_lossy().to_string();
        run_ssh_keygen(&["-t", "ed25519", "-f", &ks, "-N", "", "-C", comment])?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn ca_pubkey(key: &Path) -> Result<String> {
    let pub_path = key.with_extension("pub");
    let s = std::fs::read_to_string(&pub_path)
        .with_context(|| format!("failed to read {}", pub_path.display()))?;
    Ok(s.trim().to_string())
}

pub fn generate_keypair(key: &Path, comment: &str) -> Result<()> {
    if let Some(p) = key.parent() {
        std::fs::create_dir_all(p)?;
    }
    let _ = std::fs::remove_file(key);
    let _ = std::fs::remove_file(key.with_extension("pub"));
    let ks = key.to_string_lossy().to_string();
    run_ssh_keygen(&["-t", "ed25519", "-f", &ks, "-N", "", "-C", comment])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn validate_pubkey(pubkey: &str) -> Result<String> {
    let line = pubkey.trim();
    if line.is_empty() {
        bail!("public key is empty");
    }
    if line.contains('\n') {
        bail!("public key must be a single line");
    }
    if line.contains("PRIVATE KEY") {
        bail!("that looks like a private key");
    }
    if line.contains("-cert-v01@") {
        bail!("that looks like a certificate, not a raw public key");
    }
    let p = tmp_path("pub");
    std::fs::write(&p, line.as_bytes())?;
    let res = (|| -> Result<String> {
        let out = run_ssh_keygen(&["-l", "-f", &p.to_string_lossy()])?;
        let fp = out
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string();
        if fp.is_empty() {
            bail!("could not parse key fingerprint");
        }
        Ok(fp)
    })();
    let _ = std::fs::remove_file(&p);
    res
}

pub fn cert_valid_note(cert: &str) -> Option<String> {
    let p = tmp_path("certinfo");
    std::fs::write(&p, cert.trim().as_bytes()).ok()?;
    let res = (|| -> Option<String> {
        let out = run_ssh_keygen(&["-L", "-f", &p.to_string_lossy()]).ok()?;
        out.lines()
            .find(|l| l.trim_start().starts_with("Valid:"))
            .map(|l| l.trim().to_string())
    })();
    let _ = std::fs::remove_file(&p);
    res
}

pub fn sign_cert(
    ca_key: &Path,
    pubkey: &str,
    key_id: &str,
    principals: &[String],
    validity: &str,
) -> Result<String> {
    let ps = principals.join(",");
    if ps.is_empty() {
        bail!("cert_principals in config.toml must not be empty");
    }
    let pub_path = tmp_path(&format!("sign_{}", key_id.replace('/', "_")));
    std::fs::write(&pub_path, pubkey.trim().as_bytes())?;
    let cert_path = PathBuf::from(format!("{}-cert.pub", pub_path.display()));
    let mut args: Vec<String> = vec![
        "-s".into(),
        ca_key.to_string_lossy().to_string(),
        "-I".into(),
        key_id.to_string(),
        "-n".into(),
        ps,
    ];
    let v = validity.trim();
    if !v.is_empty() {
        args.push("-V".into());
        args.push(v.to_string());
    }
    args.push(pub_path.to_string_lossy().to_string());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let res = (|| -> Result<String> {
        run_ssh_keygen(&arg_refs)?;
        let cert = std::fs::read_to_string(&cert_path).context("failed to read generated certificate")?;
        Ok(cert.trim().to_string())
    })();
    let _ = std::fs::remove_file(&pub_path);
    let _ = std::fs::remove_file(&cert_path);
    res
}
