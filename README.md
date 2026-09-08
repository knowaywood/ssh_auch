# ssh_auth

SSH access authorization service for frp (fast reverse proxy) tunneling. Users register an account, request a token, and the admin approves via email. Each user gets **one access token** (`sk_auth_...`); one copy-paste command installs everything locally. VSCode then connects through the public **gateway** — password-free via SSH certificate — and logs in to internal machines with their normal username + password. Revocation takes effect immediately.

```
User VSCode ── certificate, password-free ──▶ Gateway sshd (public :2222)   ★ rejection happens here
                                                │ ProxyJump (-W)
                                                ▼
                                    frps tunnel ports (proxyBindAddr=127.0.0.1, unreachable from outside)
                                                ▼ frpc
                                    Internal sshd — plain SSH, normal username + password  ★ zero special setup
```

- **Token = `sk_auth_<43 base62 chars>`** (32 crypto-random bytes), generated at approval, shown on the dashboard, regenerable anytime (like OpenAI `sk-` / Stripe `sk_live_` / GitHub `ghp_` keys)
- The gateway verifies the user's SSH certificate (issued by the service's own CA, valid forever by default) and checks user status in real time — non-active users are denied
- Internal machines need **no special configuration**: no CA keys, no scripts, plain sshd with normal password login; our service being down never locks out their own admins
- Tunnel ports are bound to loopback only, so the gateway is the single public entry point

## Deploy on the public server

Assumes Debian/Ubuntu with frps already running on this machine. Everything below is also copy-paste ready on the `/admin` page.

**1. Build with GitHub Actions**

This repository includes `.github/workflows/release.yml`. The server does not need Rust or Cargo.

Create and push a version tag from a development machine:

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions builds on Ubuntu 22.04 and publishes
`ssh_auth-linux-x86_64.tar.gz` to a GitHub Release. The archive contains only the
binary and `config.example.toml`; it must not contain `config.toml`, `data/`,
TLS private keys, or email API keys.

For a public repository, download a specific release on the server with:

```bash
sudo mkdir -p /opt/ssh_auth
sudo curl -fL \
  https://github.com/OWNER/REPO/releases/download/v0.1.0/ssh_auth-linux-x86_64.tar.gz \
  -o /tmp/ssh_auth.tar.gz
sudo tar -xzf /tmp/ssh_auth.tar.gz -C /opt/ssh_auth
sudo chmod 755 /opt/ssh_auth/ssh_auth
```

Replace `OWNER/REPO` with the actual GitHub repository. For a private repository,
use a short-lived or least-privilege GitHub token via an HTTP authorization header;
do not put the token in this README or a public shell script.

To upgrade, stop the service, download the new version, extract it over the old
binary, and start the service again. Keep the server's `config.toml`, `data/`, and
`tls/` directory unchanged so users, the CA key, and certificates are preserved.

The release workflow builds inside `manylinux_2_28`, so the `x86_64` binary only
requires glibc 2.28 and works on Alibaba Cloud Linux 3 (glibc 2.32) and other
compatible older Linux servers. ARM servers need a separate cross-compilation
target and release asset.

**2. config.toml**

```toml
listen = "0.0.0.0:8443"       # direct HTTPS; use 127.0.0.1:8080 behind an HTTPS reverse proxy
base_url = "https://ssh.example.com"   # used in emails + setup commands; HTTPS recommended
ports_source = "frps"          # live from frps dashboard API
ports_file = "data/ports.json"
gateway_port = 2222
gateway_user = "tunnel"
[tls]
enabled = true
cert = "tls/fullchain.pem"
key = "tls/privkey.pem"
[frps]
api = "http://127.0.0.1:7500"
username = "admin"
password = "..."
[viewer]
username = "viewer"
password = "a-strong-password"   # source of truth; synced to data/viewer.json on restart
```

**3. systemd service** — `/etc/systemd/system/ssh-auth.service`:

```ini
[Unit]
Description=ssh_auth
After=network.target

[Service]
User=ssh-auth
Group=ssh-auth
WorkingDirectory=/opt/ssh_auth
ExecStart=/opt/ssh_auth/ssh_auth /opt/ssh_auth/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now ssh-auth
```

The relative paths in `config.toml` (such as `data/` and `tls/`) are resolved
from `WorkingDirectory=/opt/ssh_auth`. If you change `WorkingDirectory` or run
the binary manually, either start it from the directory containing the config
and data tree or change those paths to absolute paths.

Create the service account manually, or use an existing dedicated non-root
account. Its name must match `User=` and `Group=` in the unit above. Grant it
write access to `data/`, `data/keys/`, and `data/outbox/`, and read access to
`config.toml` plus the configured TLS certificate/private key. Keep the binary
owned by `root:root`; do not recursively `chown` the whole deployment directory.
The service can run as root, but that is not recommended.

Check logs with:

```bash
sudo journalctl -u ssh-auth -f
```

**4. frps: bind tunnel ports to loopback only** — add to frps.toml and restart:

```toml
proxyBindAddr = "127.0.0.1"
```

(if your frp version lacks this option, block the tunnel ports externally with a firewall instead)

**5. Gateway setup — one command**

Open `https://ssh.example.com/admin`, sign in with the `[viewer]` account, and
click **Download one-click gateway installer**. Copy the downloaded file to the
public server and run:

```bash
sudo sh ssh_auth-gateway-setup.sh
```

The generated installer creates the `tunnel` account, installs the CA,
real-time authorization callback, dedicated `sshd` configuration, and systemd
unit. It runs `sshd -t` before enabling the service and includes the current
`PermitOpen` port list. Download it again whenever the frps port list changes.

**6. Finish up**

- Visit `/admin` and log in with the `[viewer]` account from config.toml to verify
- Edit the `[email]` section in `config.toml` (provider `resend`/`brevo`/`smtp`) so approval emails actually send
- Internal machines: **nothing to do** (just keep frpc + normal sshd)

## How it works

```
Register (no approval) → Log in → "Apply for Token" (zero input)
    → server generates an ed25519 keypair, emails the fingerprint to the admin
    → admin clicks "Approve" in the email → certificate issued + token generated
    → dashboard shows the token + one-command setup
    → paste the command in a terminal → files land in ~/.ssh/, config appended
    → VSCode Remote-SSH: Connect to Host → pick frp-10001 → in
```

- Linux/macOS: `curl -fsSL '<base>/api/setup.sh?t=sk_auth_...' | sh`
- Windows PowerShell: `irm '<base>/api/setup.ps1?t=sk_auth_...' | iex`

The setup scripts are idempotent; the config block is wrapped in `# >>> ssh_auth >>> ... # <<< ssh_auth <<<` markers and is refreshed on re-run. First connection asks to confirm two host fingerprints (gateway, internal machine) and prompts for the internal account's password; the gateway hop itself is password-free.

### Email configuration

Configure the `[email]` section in `config.toml`:

| provider | notes |
|---|---|
| `dryrun` | default; writes to `data/outbox/`, no real email |
| `resend` | sign up at resend.com (free 100/day), fill `api_key` (`re_...`) and `sender` |
| `brevo` | sign up at brevo.com (free 300/day), verify the sender address first |
| `smtp` | classic SMTP (QQ/163/Gmail app passwords), fill the `smtp` section with `enabled=true` |

## Self-service

- Dashboard: token + setup commands (always available), regenerate token (old one dies instantly), revoke token (access cut off in real time, can re-apply anytime), withdraw a pending application (invalidates its emailed approval link, can re-apply right away), delete account (password confirmation)
- Information page (`/admin`, log in with the `[viewer]` account from config.toml): application list, user status, recipient and gateway setup status. This account is read-only; approval remains email-only, and revoke/delete/config changes must be performed directly on the server. Change the viewer password by editing `[viewer]` in config.toml and restarting (empty password = status login disabled)

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | Home (port list, login/register links) |
| `GET/POST /register` `/login` | Register (no approval) / log in |
| `GET /dashboard` | Token, setup commands, revoke, delete account |
| `POST /apply` | Request a token (requires login) |
| `POST /withdraw` | Withdraw a pending application (requires login) |
| `POST /regen-token` | Regenerate the access token (requires login) |
| `GET/POST /approve/{id}` `/reject/{id}?token=` | Admin email approval links (the only way to approve/reject) |
| `GET /admin` | Read-only information page + gateway setup guide (viewer session required) |
| `GET /admin/gateway-setup.sh` | Download the generated one-click gateway installer (viewer session required) |
| `GET/POST /admin/login` `/admin/logout` | Information account log in (account from config.toml `[viewer]`) / log out |
| `GET /my/key` `/my/pub` `/my/cert` | Manual downloads (login + active) |
| `GET /api/setup.sh` `/api/setup.ps1` `?t=` | One-command setup scripts (token auth) |
| `GET /api/file/{key,cert,config} ?t=` | Files consumed by the setup scripts (token auth) |
| `GET /api/principals?key_id=` | Gateway auth callback (active → 200 + principals, else 404) |

## Data files (`data/`)

| File | Contents |
|---|---|
| `users.jsonl` | Accounts, one JSON object per line (argon2 password hash, status, fingerprint, certificate, token) |
| `applications.jsonl` | Application records, one JSON object per line (with public key snapshot, kept for audit) |
| `viewer.json` | Read-only information account (argon2 hash only; synced from config.toml `[viewer]` on every start) |
| `keys/<username>_ed25519` | User keypairs (private key 0600, held server-side) |
| `ca_ed25519` | Issuing CA (auto-generated on first start) |
| `ports.json` / `outbox/` | Port list / dryrun emails |

## Security notes

- Passwords hashed with argon2id; in-memory cookie sessions (HttpOnly + SameSite=Lax, 7 days, lost on restart); 5 failed logins lock the account for 5 minutes; register/apply rate-limited to 60s per IP
- Information account login uses a separate session cookie and lockout counter; config.toml holds the viewer password in plaintext (file should be 0600) and `data/viewer.json` only the hash
- Tokens are stored in plaintext in `users.jsonl`; the CA private key lives in the same data directory, so a full data-dir compromise is total anyway — treat `data/` as highly sensitive (it is gitignored)
- Gateway is fail-closed: if this service is down, new gateway logins fail (internal machines' own admin access is unaffected)
- Serve the app behind HTTPS; the setup command contains the token and lands in shell history
