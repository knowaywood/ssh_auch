use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Create a private, unique directory for files handed to `ssh-keygen`.
///
/// A timestamp-only path in `/tmp` is predictable and lets another local user
/// pre-create a symlink or file at that path.  `create_dir` is atomic, and the
/// random suffix makes collisions impractical.
fn temp_dir(tag: &str) -> Result<PathBuf> {
    for _ in 0..16 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|e| anyhow::anyhow!("system entropy source unavailable: {e}"))?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("ssh_auth_{tag}_{suffix}"));
        match fs::create_dir(&path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                }
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("failed to create {}", path.display()));
            }
        }
    }
    bail!("failed to create a unique temporary directory")
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
    let dir = temp_dir("pub")?;
    let p = dir.join("key.pub");
    fs::write(&p, line.as_bytes())?;
    let res = (|| -> Result<String> {
        let out = run_ssh_keygen(&["-l", "-f", &p.to_string_lossy()])?;
        let fp = out.split_whitespace().nth(1).unwrap_or("").to_string();
        if fp.is_empty() {
            bail!("could not parse key fingerprint");
        }
        Ok(fp)
    })();
    let _ = fs::remove_dir_all(&dir);
    res
}

pub fn cert_valid_note(cert: &str) -> Option<String> {
    let dir = temp_dir("certinfo").ok()?;
    let p = dir.join("cert.pub");
    fs::write(&p, cert.trim().as_bytes()).ok()?;
    let res = (|| -> Option<String> {
        let out = run_ssh_keygen(&["-L", "-f", &p.to_string_lossy()]).ok()?;
        out.lines()
            .find(|l| l.trim_start().starts_with("Valid:"))
            .map(|l| l.trim().to_string())
    })();
    let _ = fs::remove_dir_all(&dir);
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
    let dir = temp_dir("sign")?;
    let pub_path = dir.join("key.pub");
    fs::write(&pub_path, pubkey.trim().as_bytes())?;
    // ssh-keygen replaces the `.pub` suffix, so `key.pub` produces
    // `key-cert.pub` (not `key.pub-cert.pub`).
    let cert_path = pub_path.with_file_name("key-cert.pub");
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
        let cert =
            std::fs::read_to_string(&cert_path).context("failed to read generated certificate")?;
        Ok(cert.trim().to_string())
    })();
    let _ = fs::remove_dir_all(&dir);
    res
}

#[cfg(test)]
mod tests {
    use super::{ensure_ca, generate_keypair, sign_cert, temp_dir};
    use std::fs;

    #[test]
    fn sign_cert_reads_ssh_keygen_output() {
        let dir = temp_dir("test").expect("create test directory");
        let ca = dir.join("ca");
        let user_key = dir.join("user");
        ensure_ca(&ca, "test-ca").expect("create CA");
        generate_keypair(&user_key, "test-user").expect("create user key");
        let pubkey = fs::read_to_string(user_key.with_extension("pub")).expect("read public key");

        let cert = sign_cert(&ca, &pubkey, "test-user", &["ssh-auth".into()], "")
            .expect("sign certificate");
        assert!(cert.starts_with("ssh-ed25519-cert-v01@openssh.com "));

        fs::remove_dir_all(dir).expect("remove test directory");
    }
}
