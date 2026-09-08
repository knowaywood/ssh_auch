use crate::auth;
use crate::config::Config;
use crate::mailer;
use crate::sshca;
use crate::store::{self, Application, PortEntry, User, ViewerAccount};
use axum::Router;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use chrono::Utc;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct AppState {
    pub cfg: Config,
    pub ca_pub: String,
    pub users: Mutex<Vec<User>>,
    pub apps: Mutex<Vec<Application>>,
    pub viewer: Mutex<Option<ViewerAccount>>,
    pub sessions: auth::Sessions,
    pub viewer_sessions: auth::Sessions,
    pub login_guard: auth::LoginGuard,
    pub viewer_guard: auth::LoginGuard,
    pub ports_cache: Mutex<Option<(Instant, Vec<PortEntry>)>>,
    pub last_reg: Mutex<HashMap<IpAddr, Instant>>,
    pub last_apply: Mutex<HashMap<IpAddr, Instant>>,
}

impl AppState {
    pub fn new(
        cfg: Config,
        ca_pub: String,
        users: Vec<User>,
        apps: Vec<Application>,
        viewer: Option<ViewerAccount>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            ca_pub,
            users: Mutex::new(users),
            apps: Mutex::new(apps),
            viewer: Mutex::new(viewer),
            sessions: auth::Sessions::new(),
            viewer_sessions: auth::Sessions::new(),
            login_guard: auth::LoginGuard::new(),
            viewer_guard: auth::LoginGuard::new(),
            ports_cache: Mutex::new(None),
            last_reg: Mutex::new(HashMap::new()),
            last_apply: Mutex::new(HashMap::new()),
        })
    }

    pub fn users_path(&self) -> PathBuf {
        self.cfg.data_dir.join("users.jsonl")
    }

    pub fn apps_path(&self) -> PathBuf {
        self.cfg.data_dir.join("applications.jsonl")
    }

    pub fn outbox_dir(&self) -> PathBuf {
        self.cfg.data_dir.join("outbox")
    }

    pub fn key_path(&self, username: &str) -> PathBuf {
        self.cfg
            .data_dir
            .join("keys")
            .join(format!("{username}_ed25519"))
    }

    pub fn validity_display(&self) -> String {
        let v = self.cfg.cert_validity.trim();
        if v.is_empty() {
            "forever".into()
        } else {
            format!("{v} from approval")
        }
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/register", get(register_page).post(register_action))
        .route("/login", get(login_page).post(login_action))
        .route("/logout", get(logout).post(logout))
        .route("/dashboard", get(dashboard))
        .route("/apply", post(apply))
        .route("/withdraw", post(withdraw))
        .route("/revoke-self", post(revoke_self))
        .route("/delete-account", post(delete_account))
        .route("/my/key", get(my_key))
        .route("/my/pub", get(my_pub))
        .route("/my/cert", get(my_cert))
        .route("/approve/{id}", get(approve_page).post(approve_action))
        .route("/reject/{id}", get(reject_page).post(reject_action))
        .route("/admin", get(admin_page))
        .route(
            "/admin/login",
            get(viewer_login_page).post(viewer_login_action),
        )
        .route("/admin/logout", get(viewer_logout).post(viewer_logout))
        .route("/admin/gateway-setup.sh", get(api_gateway_setup))
        .route("/api/principals", get(api_principals))
        .route("/api/setup.sh", get(api_setup_sh))
        .route("/api/setup.ps1", get(api_setup_ps1))
        .route("/api/file/key", get(api_file_key))
        .route("/api/file/cert", get(api_file_cert))
        .route("/api/file/config", get(api_file_config))
        .route("/regen-token", post(regen_token))
        .with_state(state)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const CSS: &str = r#"
body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#f5f6f8;color:#222;margin:0}
.wrap{max-width:820px;margin:24px auto;padding:0 16px}
h1{font-size:1.4rem} h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid #ddd;padding-bottom:6px}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{border:1px solid #dfe1e5;padding:8px 10px;text-align:left;font-size:.92rem;word-break:break-all}
th{background:#eef0f3}
form{background:#fff;border:1px solid #dfe1e5;padding:16px;margin:12px 0}
form.inline{display:inline;border:0;padding:0;margin:0}
label{display:block;margin:10px 0 4px;font-size:.9rem;color:#444}
input,select,textarea{width:100%;box-sizing:border-box;padding:8px;border:1px solid #ccc;border-radius:4px;font:inherit}
textarea{font-family:ui-monospace,monospace}
button{margin-top:14px;padding:8px 22px;border:0;border-radius:4px;background:#1a73e8;color:#fff;font:inherit;cursor:pointer}
form.inline button{margin-top:0}
button.warn{background:#d93025}
pre{background:#f0f1f3;border:1px solid #dfe1e5;padding:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;font-size:.85rem}
.note{color:#666;font-size:.85rem}
.ok{color:#137333;font-weight:600} .bad{color:#c5221f;font-weight:600} .pend{color:#b06000;font-weight:600}
a{color:#1a73e8}
"#;

fn layout(status: StatusCode, title: &str, body: String) -> Response {
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{}</title><style>{CSS}</style></head><body><div class="wrap"><h1>SSH Access Service (frp Tunneling)</h1>{body}</div></body></html>"#,
        esc(title)
    );
    (status, Html(html)).into_response()
}

fn ok_page(title: &str, body: String) -> Response {
    layout(StatusCode::OK, title, body)
}

fn err_page(msg: &str) -> Response {
    layout(
        StatusCode::BAD_REQUEST,
        "Error",
        format!(
            "<p class=\"bad\">{}</p><p><a href=\"/\">Back to home</a></p>",
            esc(msg)
        ),
    )
}

fn internal_page(msg: &str) -> Response {
    layout(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal Server Error",
        format!(
            "<p class=\"bad\">{}</p><p><a href=\"/\">Back to home</a></p>",
            esc(msg)
        ),
    )
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn host_of(base: &str) -> String {
    reqwest::Url::parse(base)
        .ok()
        .and_then(|url| {
            url.host_str().map(|host| {
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned()
            })
        })
        .unwrap_or_else(|| base.trim().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::{build_setup_ps1, build_setup_sh, host_of, parse_frps_ports};
    use serde_json::json;

    #[test]
    fn host_of_handles_ports_and_ipv6() {
        assert_eq!(
            host_of("https://ssh.example.com:8443/path"),
            "ssh.example.com"
        );
        assert_eq!(host_of("https://[2001:db8::1]:8443"), "2001:db8::1");
    }

    #[test]
    fn frps_v071_port_parser_reads_remote_port_from_conf() {
        let ports = parse_frps_ports(&json!({
            "proxies": [
                {"name": "ssh-a", "conf": {"remotePort": 6001}},
                {"name": "ssh-b", "conf": {"remotePort": 6002}},
                {"name": "offline", "status": "offline"},
                {"name": "invalid", "conf": {"remotePort": 70000}}
            ]
        }));
        assert_eq!(
            ports.iter().map(|port| port.port).collect::<Vec<_>>(),
            [6001, 6002]
        );
    }

    #[test]
    fn setup_scripts_keep_lf_line_endings() {
        for script in [
            build_setup_sh("https://example.test", "sk_auth_test"),
            build_setup_ps1("https://example.test", "sk_auth_test"),
        ] {
            assert!(!script.contains('\r'));
            assert!(script.ends_with('\n'));
            assert!(script.lines().count() > 5);
        }
    }
}

fn user_status_html(status: &str) -> &'static str {
    match status {
        "active" => "<span class=\"ok\">Active</span>",
        "pending" => "<span class=\"pend\">Pending review</span>",
        "revoked" => "<span class=\"bad\">Revoked</span>",
        _ => "<span class=\"note\">Not applied</span>",
    }
}

fn app_status_html(status: &str) -> &'static str {
    match status {
        "approved" => "<span class=\"ok\">Approved</span>",
        "rejected" => "<span class=\"bad\">Rejected</span>",
        "withdrawn" => "<span class=\"note\">Withdrawn</span>",
        _ => "<span class=\"pend\">Pending</span>",
    }
}

fn cookie_val(headers: &HeaderMap, name: &str) -> Option<String> {
    for v in headers.get_all(header::COOKIE) {
        let s = v.to_str().ok()?;
        for part in s.split(';') {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix(&format!("{name}=")) {
                return Some(rest.to_string());
            }
        }
    }
    None
}

fn session_user(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let sid = cookie_val(headers, "sid")?;
    state.sessions.get(&sid)
}

fn viewer_session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let sid = cookie_val(headers, "vsid")?;
    state.viewer_sessions.get(&sid)
}

fn require_viewer(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    if viewer_session(state, headers).is_some() {
        Ok(())
    } else {
        Err(Box::new(Redirect::to("/admin/login").into_response()))
    }
}

fn cookie_redirect(loc: &str, name: &str, sid: &str, secure: bool) -> Response {
    let mut resp = Redirect::to(loc).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "{name}={sid}; HttpOnly{}; SameSite=Lax; Path=/; Max-Age={}",
            if secure { "; Secure" } else { "" },
            auth::SESSION_TTL.as_secs()
        )
        .parse()
        .unwrap(),
    );
    resp
}

fn clear_cookie_page(
    status: StatusCode,
    title: &str,
    body: String,
    name: &str,
    secure: bool,
) -> Response {
    let mut resp = layout(status, title, body);
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_bytes(
            format!(
                "{name}=; HttpOnly{}; SameSite=Lax; Path=/; Max-Age=0",
                if secure { "; Secure" } else { "" }
            )
            .as_bytes(),
        )
        .unwrap(),
    );
    resp
}

fn rate_limited(map: &Mutex<HashMap<IpAddr, Instant>>, ip: IpAddr) -> bool {
    let mut g = map.lock().unwrap();
    g.retain(|_, t| t.elapsed() < Duration::from_secs(3600));
    if let Some(t) = g.get(&ip)
        && t.elapsed() < Duration::from_secs(60)
    {
        return true;
    }
    g.insert(ip, Instant::now());
    false
}

fn download_response(filename: &str, content: &str) -> Response {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).unwrap(),
    );
    (h, content.to_string()).into_response()
}

async fn get_ports(state: &AppState) -> Result<Vec<PortEntry>, String> {
    if state.cfg.ports_source == "frps" {
        {
            let cache = state.ports_cache.lock().unwrap();
            if let Some((t, v)) = &*cache
                && t.elapsed() < Duration::from_secs(60)
            {
                return Ok(v.clone());
            }
        }
        let v = fetch_frps(&state.cfg)
            .await
            .map_err(|e| format!("failed to fetch port list from frps API: {e:#}"))?;
        *state.ports_cache.lock().unwrap() = Some((Instant::now(), v.clone()));
        Ok(v)
    } else {
        store::load_ports(&state.cfg.ports_file)
            .map_err(|e| format!("failed to read ports.json: {e:#}"))
    }
}

async fn fetch_frps(cfg: &Config) -> anyhow::Result<Vec<PortEntry>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let url = format!("{}/api/proxy/tcp", cfg.frps.api.trim_end_matches('/'));
    let mut req = client.get(&url);
    if !cfg.frps.username.is_empty() {
        req = req.basic_auth(&cfg.frps.username, Some(&cfg.frps.password));
    }
    let v: serde_json::Value = req.send().await?.error_for_status()?.json().await?;
    Ok(parse_frps_ports(&v))
}

fn parse_frps_ports(v: &serde_json::Value) -> Vec<PortEntry> {
    let mut ports = Vec::new();
    if let Some(arr) = v["proxies"].as_array() {
        for p in arr {
            // frp v0.71.0's legacy dashboard endpoint returns each TCP
            // proxy as `{ name, conf: { remotePort }, ... }`. Offline
            // proxies have no `conf`, so they are intentionally omitted.
            let Some(pn) = p["conf"]["remotePort"].as_u64() else {
                continue;
            };
            if pn == 0 || pn > 65535 {
                continue;
            }
            let name = p["name"].as_str().unwrap_or("unknown").to_string();
            ports.push(PortEntry {
                port: pn as u16,
                name,
                desc: "from frps".into(),
            });
        }
    }
    ports.sort_by_key(|e| e.port);
    ports.dedup_by_key(|e| e.port);
    ports
}

async fn index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if session_user(&state, &headers).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    let ports_block = match get_ports(&state).await {
        Ok(ports) => {
            let mut table = String::from(
                "<table><tr><th>Public port</th><th>Internal server</th><th>Notes</th></tr>",
            );
            for p in &ports {
                table.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    p.port,
                    esc(&p.name),
                    esc(&p.desc)
                ));
            }
            table.push_str("</table>");
            if ports.is_empty() {
                "<p class=\"note\">No tunneled ports available right now.</p>".into()
            } else {
                table
            }
        }
        Err(e) => format!("<p class=\"bad\">{}</p>", esc(&e)),
    };
    let body = format!(
        "<h2>What is this</h2>\
<p>Register, log in and click \"Apply for Token\". Once the admin approves you get a single access token (<code>sk_auth_...</code>): copy one setup command from your dashboard and VSCode connects right away. The gateway hop on the public server is certificate-authenticated and password-free; the internal machines themselves need <b>no special setup</b> — you log in with their normal username + password.</p>\
<h2>Open ports</h2>{ports_block}\
<p><a href=\"/login\">Log in</a> | <a href=\"/register\">Create an account</a></p>"
    );
    ok_page("Home", body)
}

#[derive(serde::Deserialize)]
struct RegForm {
    username: String,
    password: String,
    password2: String,
}

fn auth_form_error(msg: &str) -> Response {
    layout(
        StatusCode::BAD_REQUEST,
        "Error",
        format!(
            "<p class=\"bad\">{}</p><p><a href=\"javascript:history.back()\">Go back</a> | <a href=\"/\">Back to home</a></p>",
            esc(msg)
        ),
    )
}

async fn register_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if session_user(&state, &headers).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    let body = "\
<h2>Create an account</h2>\
<form method=\"post\" action=\"/register\">\
<label>Username (3-32 chars: letters/digits/_/-)</label><input name=\"username\" required maxlength=\"32\">\
<label>Password (at least 8 chars)</label><input type=\"password\" name=\"password\" required minlength=\"8\" maxlength=\"64\">\
<label>Confirm password</label><input type=\"password\" name=\"password2\" required minlength=\"8\" maxlength=\"64\">\
<button>Register</button></form>\
<p class=\"note\">Registration needs no approval. Already have an account? <a href=\"/login\">Log in</a></p>";
    ok_page("Register", body.into())
}

async fn register_action(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(f): Form<RegForm>,
) -> Response {
    if rate_limited(&state.last_reg, addr.ip()) {
        return err_page("Registering too frequently, try again in a minute");
    }
    let username = f.username.trim().to_string();
    if !(3..=32).contains(&username.len())
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return auth_form_error(
            "Username must be 3-32 chars, only letters/digits/underscore/hyphen",
        );
    }
    if f.password.len() < 8 || f.password.len() > 64 {
        return auth_form_error("Password must be 8-64 characters");
    }
    if f.password != f.password2 {
        return auth_form_error("Passwords do not match");
    }
    {
        let users = state.users.lock().unwrap();
        if users.iter().any(|u| u.username == username) {
            return auth_form_error("Username is already taken");
        }
    }
    let pw = f.password.clone();
    let hash = match tokio::task::spawn_blocking(move || auth::hash_password(&pw)).await {
        Ok(Ok(h)) => h,
        _ => return internal_page("failed to hash password"),
    };
    let user = User::new(&username, &hash, now_rfc3339());
    state.users.lock().unwrap().push(user);
    if let Err(e) = store::save_users(&state.users_path(), &state.users.lock().unwrap()) {
        return internal_page(&format!("failed to save user: {e:#}"));
    }
    let sid = state.sessions.create(&username);
    cookie_redirect(
        "/dashboard",
        "sid",
        &sid,
        state.cfg.base_url.starts_with("https://"),
    )
}

#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if session_user(&state, &headers).is_some() {
        return Redirect::to("/dashboard").into_response();
    }
    let body = "\
<h2>Log in</h2>\
<form method=\"post\" action=\"/login\">\
<label>Username</label><input name=\"username\" required maxlength=\"32\">\
<label>Password</label><input type=\"password\" name=\"password\" required maxlength=\"64\">\
<button>Log in</button></form>\
<p class=\"note\">No account yet? <a href=\"/register\">Register</a></p>";
    ok_page("Login", body.into())
}

async fn login_action(State(state): State<Arc<AppState>>, Form(f): Form<LoginForm>) -> Response {
    let username = f.username.trim().to_string();
    if state.login_guard.locked(&username) {
        return err_page("Too many failed attempts, try again in 5 minutes");
    }
    let user = {
        state
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.username == username)
            .cloned()
    };
    let Some(user) = user else {
        state.login_guard.fail(&username);
        return err_page("Incorrect username or password");
    };
    let pw = f.password.clone();
    let phc = user.pass_hash.clone();
    let ok = tokio::task::spawn_blocking(move || auth::verify_password(&pw, &phc))
        .await
        .unwrap_or(false);
    if !ok {
        state.login_guard.fail(&username);
        return err_page("Incorrect username or password");
    }
    state.login_guard.reset(&username);
    let sid = state.sessions.create(&username);
    cookie_redirect(
        "/dashboard",
        "sid",
        &sid,
        state.cfg.base_url.starts_with("https://"),
    )
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(sid) = cookie_val(&headers, "sid") {
        state.sessions.remove(&sid);
    }
    clear_cookie_page(
        StatusCode::OK,
        "Signed out",
        "<p class=\"ok\">You have signed out.</p><p><a href=\"/\">Back to home</a> | <a href=\"/login\">Log in again</a></p>".into(),
        "sid",
        state.cfg.base_url.starts_with("https://"),
    )
}

async fn ssh_config_block(state: &AppState) -> String {
    let host = host_of(&state.cfg.base_url);
    let gw_port = state.cfg.gateway_port;
    let gw_user = &state.cfg.gateway_user;
    let mut s = format!(
        "# >>> ssh_auth >>>\nHost ssh-auth-gateway\n  HostName {host}\n  Port {gw_port}\n  User {gw_user}\n  IdentitiesOnly yes\n  IdentityFile ~/.ssh/id_ed25519\n  CertificateFile ~/.ssh/id_ed25519-cert.pub\n"
    );
    match get_ports(state).await {
        Ok(ports) => {
            for p in &ports {
                s.push_str(&format!(
                    "\nHost frp-{}\n  HostName 127.0.0.1\n  Port {}\n  User root\n  IdentitiesOnly yes\n  ProxyJump ssh-auth-gateway\n",
                    p.port, p.port
                ));
            }
            if ports.is_empty() {
                s.push_str("\n# no open ports right now\n");
            }
        }
        Err(e) => s.push_str(&format!("\n# failed to fetch port list: {e}\n")),
    }
    s.push_str("# <<< ssh_auth <<<\n");
    s
}

async fn dashboard(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(username) = session_user(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let user = {
        state
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.username == username)
            .cloned()
    };
    let Some(user) = user else {
        return err_page("Account not found (it may have been deleted)");
    };

    let mut body = format!(
        "<h2>Account</h2>\
<table><tr><th>Username</th><td>{}</td></tr><tr><th>Status</th><td>{}</td></tr><tr><th>Registered at</th><td>{}</td></tr></table>",
        esc(&user.username),
        user_status_html(&user.status),
        esc(&user.created_at)
    );

    match user.status.as_str() {
        "pending" => {
            let fp = user.fingerprint.clone().unwrap_or_default();
            body.push_str(&format!(
                "<h2>Token application under review</h2>\
<p class=\"pend\">Your application has been submitted and is waiting for admin approval (via the email link). Public key fingerprint: <code>{}</code></p>\
<form method=\"post\" action=\"/withdraw\"><button class=\"warn\">Withdraw application</button></form>\
<p class=\"note\">Withdrawing invalidates the emailed approval link; you can apply again right away.</p>",
                esc(&fp)
            ));
        }
        "active" => {
            let cert = user.cert.clone().unwrap_or_default();
            let fp = user.fingerprint.clone().unwrap_or_default();
            let valid = sshca::cert_valid_note(&cert).unwrap_or_else(|| state.validity_display());
            let token_disp = user
                .token
                .clone()
                .unwrap_or_else(|| "(missing — regenerate to create one)".into());
            body.push_str(&format!(
                "<h2>Your Token</h2>\
<p>Token: <code>{}</code></p>\
<p class=\"note\">This token is your access credential — keep it private. It is used by the one-command setup below. Regenerating immediately invalidates the old token.</p>\
<form method=\"post\" action=\"/regen-token\"><button class=\"warn\">Regenerate token</button></form>",
                esc(&token_disp)
            ));
            let base = esc(state.cfg.base());
            let token_esc = esc(&token_disp);
            body.push_str(&format!(
                "<h2>One-command setup</h2>\
<p>Linux / macOS (Terminal):</p>\
<pre>curl -fsSL '{base}/api/setup.sh?t={token_esc}' | sh</pre>\
<p>Windows (PowerShell):</p>\
<pre>irm '{base}/api/setup.ps1?t={token_esc}' | iex</pre>\
<p class=\"note\">The script installs your private key + certificate into <code>~/.ssh/</code> and appends the ssh config block (gateway + every open port). Idempotent — safe to re-run.</p>\
<p class=\"note\">Connection model: the gateway hop on the public server is certificate-authenticated and password-free; at the internal machine you log in with that machine's normal username + password.</p>"
            ));
            let cfg_block = ssh_config_block(&state).await;
            body.push_str(&format!(
                "<h2>Use it in VSCode</h2>\
<ol><li>Install the <b>Remote - SSH</b> extension.</li>\
<li><code>F1</code> → <b>Remote-SSH: Connect to Host...</b> → pick an alias (e.g. <code>frp-10001</code>).</li>\
<li>First connect: confirm the gateway host fingerprint, then the internal machine's; enter the internal account's password when asked. The gateway hop itself is password-free (certificate).</li></ol>\
<p class=\"note\">Certificate: {} · fingerprint <code>{}</code> · approved at {}</p>\
<details><summary>Advanced: manual download &amp; raw ssh config</summary>\
<p><a href=\"/my/key\">private key</a> | <a href=\"/my/cert\">certificate</a> — save into <code>~/.ssh/</code>, then <code>chmod 600 ~/.ssh/id_ed25519</code> (Linux/Mac).</p>\
<pre>{}</pre>\
</details>",
                esc(&valid),
                esc(&fp),
                esc(user.decided_at.as_deref().unwrap_or("-")),
                esc(&cfg_block)
            ));
            body.push_str(
                "<h2>Revoke Token</h2>\
<p class=\"note\">Revoking immediately cuts off access (the gateway verifies your status in real time at login). You can apply again anytime.</p>\
<form method=\"post\" action=\"/revoke-self\"><button class=\"warn\">Revoke my Token</button></form>",
            );
        }
        _ => {
            if user.status == "revoked" {
                body.push_str(
                    "<h2>Token status</h2><p class=\"bad\">Your token has been revoked. You can apply again; access resumes once approved.</p>",
                );
            }
            body.push_str(
                "<h2>Apply for Token</h2>\
<p class=\"note\">Just click the button — nothing to fill in: the server generates an ed25519 keypair for your account and emails its fingerprint to the admin for approval. Once approved, come back here to download your key and certificate.</p>\
<form method=\"post\" action=\"/apply\"><button>Apply for Token</button></form>",
            );
        }
    }

    body.push_str(
        "<h2>Delete account</h2>\
<p class=\"note\">Deletes this account and its private key on the server (past applications are kept for audit). Password confirmation required.</p>\
<form method=\"post\" action=\"/delete-account\">\
<label>Password</label><input type=\"password\" name=\"password\" required maxlength=\"64\">\
<button class=\"warn\">Delete account</button></form>\
<p><a href=\"/logout\">Sign out</a></p>",
    );
    ok_page("Dashboard", body)
}

async fn apply(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(username) = session_user(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if rate_limited(&state.last_apply, addr.ip()) {
        return err_page("Applying too frequently, try again in a minute");
    }
    let user = {
        state
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.username == username)
            .cloned()
    };
    let Some(user) = user else {
        return err_page("Account not found");
    };
    if !matches!(user.status.as_str(), "none" | "revoked") {
        return err_page("Cannot apply right now (token already active or under review)");
    }
    {
        let apps = state.apps.lock().unwrap();
        if apps.iter().filter(|a| a.is_pending()).count() >= 50 {
            return err_page("Too many pending applications, try again later");
        }
    }

    let key_path = state.key_path(&username);
    if let Err(e) = sshca::generate_keypair(&key_path, &format!("ssh_auth_{username}")) {
        return internal_page(&format!("failed to generate keypair: {e:#}"));
    }
    let pubkey = match std::fs::read_to_string(key_path.with_extension("pub")) {
        Ok(s) => s.trim().to_string(),
        Err(e) => return internal_page(&format!("failed to read public key: {e:#}")),
    };
    let fingerprint = match sshca::validate_pubkey(&pubkey) {
        Ok(f) => f,
        Err(e) => return internal_page(&format!("failed to compute key fingerprint: {e:#}")),
    };

    let app = Application {
        id: auth::rand_hex(8),
        username: username.clone(),
        approve_token: auth::rand_hex(32),
        pubkey,
        fingerprint,
        status: "pending".into(),
        created_at: now_rfc3339(),
        decided_at: None,
        cert: None,
    };
    state.apps.lock().unwrap().push(app.clone());
    if let Err(e) = store::save_applications(&state.apps_path(), &state.apps.lock().unwrap()) {
        return internal_page(&format!("failed to save application: {e:#}"));
    }
    {
        let mut users = state.users.lock().unwrap();
        if let Some(u) = users.iter_mut().find(|u| u.username == username) {
            u.status = "pending".into();
            u.fingerprint = Some(app.fingerprint.clone());
            u.decided_at = None;
            u.cert = None;
        }
    }
    if let Err(e) = store::save_users(&state.users_path(), &state.users.lock().unwrap()) {
        return internal_page(&format!("failed to save user: {e:#}"));
    }

    let email_cfg = state.cfg.email.clone();
    let (subject, plain, html) = app_email(&state, &app);
    let mail_result = mailer::send(&email_cfg, &state.outbox_dir(), &subject, &plain, &html).await;

    let mail_note = match mail_result {
        Ok(mailer::Outcome::Sent(via)) => {
            format!("<p>Request email sent to the admin via {via}.</p>")
        }
        Ok(mailer::Outcome::DryRun(p)) => format!(
            "<p class=\"note\">Email sending is not configured (provider=dryrun); the request email was written to server file {}. Set provider/api_key in config.toml to send real email.</p>",
            esc(&p.display().to_string())
        ),
        Err(e) => format!(
            "<p class=\"bad\">Warning: failed to send request email: {} (application recorded; withdraw it on the dashboard and re-apply once mail sending works, then the admin gets the approval link by email)</p>",
            esc(&format!("{e:#}"))
        ),
    };

    let body = format!(
        "<p class=\"ok\">Application submitted</p>{mail_note}\
<p>Once approved, go back to the <a href=\"/dashboard\">Dashboard</a> to copy your token and the one-command setup.</p><p><a href=\"/\">Back to home</a></p>"
    );
    ok_page("Application Submitted", body)
}

async fn withdraw(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(username) = session_user(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    {
        let mut users = state.users.lock().unwrap();
        let Some(u) = users.iter_mut().find(|u| u.username == username) else {
            return err_page("Account not found");
        };
        if u.status != "pending" {
            return err_page("There is no pending application to withdraw");
        }
        u.status = "none".into();
        u.fingerprint = None;
        u.decided_at = Some(now_rfc3339());
    }
    {
        let mut apps = state.apps.lock().unwrap();
        for a in apps.iter_mut() {
            if a.username == username && a.is_pending() {
                a.status = "withdrawn".into();
                a.decided_at = Some(now_rfc3339());
            }
        }
    }
    if let Err(e) = store::save_users(&state.users_path(), &state.users.lock().unwrap()) {
        return internal_page(&format!("failed to save user: {e:#}"));
    }
    if let Err(e) = store::save_applications(&state.apps_path(), &state.apps.lock().unwrap()) {
        return internal_page(&format!("failed to save application: {e:#}"));
    }
    ok_page(
        "Application Withdrawn",
        "<p class=\"ok\">Your application was withdrawn; its approval email link is now invalid. You can submit a new application from the <a href=\"/dashboard\">Dashboard</a> at any time.</p><p><a href=\"/dashboard\">Back to dashboard</a></p>".into(),
    )
}

async fn revoke_self(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(username) = session_user(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    {
        let mut users = state.users.lock().unwrap();
        let Some(u) = users.iter_mut().find(|u| u.username == username) else {
            return err_page("Account not found");
        };
        if u.status != "active" {
            return err_page("No active token to revoke");
        }
        u.status = "revoked".into();
        u.cert = None;
        u.decided_at = Some(now_rfc3339());
    }
    if let Err(e) = store::save_users(&state.users_path(), &state.users.lock().unwrap()) {
        return internal_page(&format!("failed to save user: {e:#}"));
    }
    ok_page(
        "Revoked",
        "<p class=\"ok\">Your token has been revoked; access is cut off in real time. You can apply again anytime.</p><p><a href=\"/dashboard\">Back to dashboard</a></p>".into(),
    )
}

#[derive(serde::Deserialize)]
struct DeleteForm {
    password: String,
}

async fn delete_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<DeleteForm>,
) -> Response {
    let Some(username) = session_user(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let phc = {
        state
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.username == username)
            .map(|u| u.pass_hash.clone())
    };
    let Some(phc) = phc else {
        return err_page("Account not found");
    };
    let pw = f.password.clone();
    let ok = tokio::task::spawn_blocking(move || auth::verify_password(&pw, &phc))
        .await
        .unwrap_or(false);
    if !ok {
        return err_page("Password is incorrect");
    }
    {
        let mut users = state.users.lock().unwrap();
        users.retain(|u| u.username != username);
    }
    {
        // Invalidate approval links for the deleted account.  Without this,
        // recreating the same username could let an old pending application
        // approve a certificate for the new account.
        let mut apps = state.apps.lock().unwrap();
        for app in apps
            .iter_mut()
            .filter(|app| app.username == username && app.is_pending())
        {
            app.status = "withdrawn".into();
            app.decided_at = Some(now_rfc3339());
        }
    }
    if let Err(e) = store::save_users(&state.users_path(), &state.users.lock().unwrap()) {
        return internal_page(&format!("failed to save user: {e:#}"));
    }
    if let Err(e) = store::save_applications(&state.apps_path(), &state.apps.lock().unwrap()) {
        return internal_page(&format!("failed to save applications: {e:#}"));
    }
    let kp = state.key_path(&username);
    let _ = std::fs::remove_file(&kp);
    let _ = std::fs::remove_file(kp.with_extension("pub"));
    state.sessions.remove_user(&username);
    clear_cookie_page(
        StatusCode::OK,
        "Account Deleted",
        "<p class=\"ok\">Your account has been deleted and its private key removed from the server.</p><p><a href=\"/\">Back to home</a></p>".into(),
        "sid",
        state.cfg.base_url.starts_with("https://"),
    )
}

fn require_active(state: &AppState, headers: &HeaderMap) -> Result<(String, User), Box<Response>> {
    let Some(username) = session_user(state, headers) else {
        return Err(Box::new(Redirect::to("/login").into_response()));
    };
    let user = {
        state
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.username == username)
            .cloned()
    };
    let Some(user) = user else {
        return Err(Box::new(err_page(
            "Account not found (it may have been deleted)",
        )));
    };
    if user.status != "active" {
        return Err(Box::new(err_page(
            "Token is not active, download unavailable",
        )));
    }
    Ok((username, user))
}

async fn my_key(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (username, _) = match require_active(&state, &headers) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let path = state.key_path(&username);
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => return internal_page(&format!("failed to read private key: {e:#}")),
    };
    download_response("id_ed25519", &content)
}

async fn my_pub(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (username, _) = match require_active(&state, &headers) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let path = state.key_path(&username).with_extension("pub");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => return internal_page(&format!("failed to read public key: {e:#}")),
    };
    download_response("id_ed25519.pub", &content)
}

async fn my_cert(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, user) = match require_active(&state, &headers) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(cert) = &user.cert else {
        return err_page("Certificate not found");
    };
    download_response("id_ed25519-cert.pub", cert)
}

fn find_app_and_check(
    state: &AppState,
    id: &str,
    token: &str,
) -> Result<Application, Box<Response>> {
    let app = {
        state
            .apps
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.id == id)
            .cloned()
    };
    let Some(app) = app else {
        return Err(Box::new(err_page("Application not found")));
    };
    if app.approve_token != token {
        return Err(Box::new(layout(
            StatusCode::FORBIDDEN,
            "No Access",
            "<p class=\"bad\">Incorrect link token</p>".into(),
        )));
    }
    Ok(app)
}

fn validity_note(cfg: &Config) -> String {
    let v = cfg.cert_validity.trim();
    if v.is_empty() {
        "valid forever".into()
    } else {
        format!("valid for {v}")
    }
}

async fn approve_page(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let token = q.get("token").map(|s| s.as_str()).unwrap_or("");
    let app = match find_app_and_check(&state, &id, token) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    if !app.is_pending() {
        return ok_page(
            "Already Processed",
            format!(
                "<p>This application is already: {}</p><p><a href=\"/\">Back to home</a></p>",
                app_status_html(&app.status)
            ),
        );
    }
    let body = format!(
        "<h2>Confirm approval</h2>\
<table><tr><th>Username</th><td>{}</td></tr>\
<tr><th>Public key fingerprint</th><td>{}</td></tr>\
<tr><th>Applied at</th><td>{}</td></tr></table>\
<p>On approval, the server CA will issue an SSH certificate for this user ({}, principals: {}) and generate their access token. They connect through the public gateway, whose real-time status check enforces revocation; internal machines keep their normal username + password login.</p>\
<form method=\"post\" action=\"/approve/{}\">\
<input type=\"hidden\" name=\"token\" value=\"{}\">\
<button>Approve</button> \
<a href=\"/reject/{}?token={}\"><button type=\"button\" class=\"warn\">Go to reject</button></a></form>",
        esc(&app.username),
        esc(&app.fingerprint),
        esc(&app.created_at),
        esc(&validity_note(&state.cfg)),
        esc(&state.cfg.cert_principals.join(",")),
        esc(&app.id),
        esc(&app.approve_token),
        esc(&app.id),
        esc(&app.approve_token),
    );
    ok_page("Approval Confirmation", body)
}

async fn decide(state: &Arc<AppState>, id: &str, token: &str, approve: bool) -> Response {
    let app = match find_app_and_check(state, id, token) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    if !app.is_pending() {
        return ok_page(
            "Already Processed",
            format!(
                "<p>This application is already: {}</p><p><a href=\"/\">Back to home</a></p>",
                app_status_html(&app.status)
            ),
        );
    }
    if approve {
        let cert = match sshca::sign_cert(
            &state.cfg.ca_key,
            &app.pubkey,
            &format!("ssh_auth_{}", app.username),
            &state.cfg.cert_principals,
            &state.cfg.cert_validity,
        ) {
            Ok(c) => c,
            Err(e) => return internal_page(&format!("failed to issue certificate: {e:#}")),
        };
        {
            let mut apps = state.apps.lock().unwrap();
            if let Some(a) = apps.iter_mut().find(|a| a.id == id) {
                a.cert = Some(cert.clone());
                a.status = "approved".into();
                a.decided_at = Some(now_rfc3339());
            }
        }
        if let Err(e) = store::save_applications(&state.apps_path(), &state.apps.lock().unwrap()) {
            return internal_page(&format!("failed to save application: {e:#}"));
        }
        {
            let mut users = state.users.lock().unwrap();
            if let Some(u) = users.iter_mut().find(|u| u.username == app.username) {
                u.status = "active".into();
                u.cert = Some(cert);
                u.fingerprint = Some(app.fingerprint.clone());
                u.decided_at = Some(now_rfc3339());
                u.token = Some(auth::generate_token());
            }
        }
        if let Err(e) = store::save_users(&state.users_path(), &state.users.lock().unwrap()) {
            return internal_page(&format!("failed to save user: {e:#}"));
        }
        ok_page(
            "Approved",
            format!(
                "<p class=\"ok\">Approved {}'s token application; certificate issued ({}). The user now finds their access token on the dashboard.</p><p><a href=\"/\">Back to home</a></p>",
                esc(&app.username),
                esc(&validity_note(&state.cfg))
            ),
        )
    } else {
        {
            let mut apps = state.apps.lock().unwrap();
            if let Some(a) = apps.iter_mut().find(|a| a.id == id) {
                a.status = "rejected".into();
                a.decided_at = Some(now_rfc3339());
            }
        }
        if let Err(e) = store::save_applications(&state.apps_path(), &state.apps.lock().unwrap()) {
            return internal_page(&format!("failed to save application: {e:#}"));
        }
        {
            let mut users = state.users.lock().unwrap();
            if let Some(u) = users.iter_mut().find(|u| u.username == app.username)
                && u.status == "pending"
            {
                u.status = "none".into();
                u.fingerprint = None;
                u.decided_at = Some(now_rfc3339());
            }
        }
        if let Err(e) = store::save_users(&state.users_path(), &state.users.lock().unwrap()) {
            return internal_page(&format!("failed to save user: {e:#}"));
        }
        ok_page(
            "Rejected",
            format!(
                "<p class=\"ok\">Rejected {}'s token application.</p><p><a href=\"/\">Back to home</a></p>",
                esc(&app.username)
            ),
        )
    }
}

async fn approve_action(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let token = f.get("token").map(|s| s.as_str()).unwrap_or("");
    decide(&state, &id, token, true).await
}

async fn reject_page(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let token = q.get("token").map(|s| s.as_str()).unwrap_or("");
    let app = match find_app_and_check(&state, &id, token) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    if !app.is_pending() {
        return ok_page(
            "Already Processed",
            format!(
                "<p>This application is already: {}</p><p><a href=\"/\">Back to home</a></p>",
                app_status_html(&app.status)
            ),
        );
    }
    let body = format!(
        "<h2>Confirm rejection</h2><p>Username: {} (fingerprint {})</p>\
<form method=\"post\" action=\"/reject/{}\">\
<input type=\"hidden\" name=\"token\" value=\"{}\">\
<button class=\"warn\">Reject</button> \
<a href=\"/approve/{}?token={}\"><button type=\"button\">Go to approve</button></a></form>",
        esc(&app.username),
        esc(&app.fingerprint),
        esc(&app.id),
        esc(&app.approve_token),
        esc(&app.id),
        esc(&app.approve_token),
    );
    ok_page("Rejection Confirmation", body)
}

async fn reject_action(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Form(f): Form<HashMap<String, String>>,
) -> Response {
    let token = f.get("token").map(|s| s.as_str()).unwrap_or("");
    decide(&state, &id, token, false).await
}

fn app_email(state: &AppState, app: &Application) -> (String, String, String) {
    let base = state.cfg.base();
    let approve_url = format!("{base}/approve/{}?token={}", app.id, app.approve_token);
    let reject_url = format!("{base}/reject/{}?token={}", app.id, app.approve_token);
    let admin_url = format!("{base}/admin");
    let subject = format!("[ssh_auth] Token request: {}", app.username);

    let plain = format!(
        "New token request\n\nUsername: {}\nPublic key fingerprint: {}\nApplied at: {}\n\nApprove: {}\nReject: {}\nAdmin console: {}\n\n(Approving issues an SSH certificate signed by the server CA and generates the user's access token, {}. The user then connects through the public gateway — status is verified in real time, so revocation takes effect immediately. Internal machines keep their normal username + password login.)\n",
        app.username,
        app.fingerprint,
        app.created_at,
        approve_url,
        reject_url,
        admin_url,
        validity_note(&state.cfg),
    );

    fn row(label: &str, value: &str) -> String {
        format!(
            "<tr><th style=\"text-align:left;padding:6px 14px;color:#666;background:#f7f8fa;border:1px solid #e3e5e8;white-space:nowrap\">{label}</th><td style=\"padding:6px 14px;border:1px solid #e3e5e8;font-family:ui-monospace,Consolas,monospace\">{value}</td></tr>"
        )
    }
    let html = format!(
        "<div style=\"font-family:-apple-system,'Segoe UI',sans-serif;max-width:560px;margin:0 auto;color:#222\">\
<h2 style=\"font-size:18px;border-bottom:2px solid #1a73e8;padding-bottom:8px\">Token request</h2>\
<table style=\"border-collapse:collapse;width:100%;font-size:14px\">{}{}{}</table>\
<p style=\"font-size:13px;color:#555\">Approving issues an SSH certificate signed by the server CA ({}, principals {}) and generates the user's access token. The user connects through the public gateway; status is verified in real time, so revocation takes effect immediately. Internal machines keep their normal username + password login.</p>\
<table cellpadding=\"0\" cellspacing=\"0\" style=\"margin:6px 0\"><tr>\
<td bgcolor=\"#137333\" style=\"border-radius:5px\"><a href=\"{}\" style=\"display:inline-block;padding:10px 26px;color:#ffffff;text-decoration:none;font-weight:bold;font-size:14px\">Approve</a></td>\
<td style=\"width:16px\">&nbsp;</td>\
<td bgcolor=\"#c5221f\" style=\"border-radius:5px\"><a href=\"{}\" style=\"display:inline-block;padding:10px 26px;color:#ffffff;text-decoration:none;font-weight:bold;font-size:14px\">Reject</a></td>\
</tr></table>\
<p style=\"font-size:12px;color:#999\">If the buttons don't work, copy the links into a browser:<br>Approve: {}<br>Reject: {}<br>Admin console: {}</p>\
</div>",
        row("Username", &esc(&app.username)),
        row("Public key fingerprint", &esc(&app.fingerprint)),
        row("Applied at", &esc(&app.created_at)),
        esc(&validity_note(&state.cfg)),
        esc(&state.cfg.cert_principals.join(", ")),
        approve_url,
        reject_url,
        esc(&approve_url),
        esc(&reject_url),
        esc(&admin_url),
    );
    (subject, plain, html)
}

async fn viewer_login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if viewer_session(&state, &headers).is_some() {
        return Redirect::to("/admin").into_response();
    }
    let body = "\
<h2>Information account login</h2>\
<form method=\"post\" action=\"/admin/login\">\
<label>Username</label><input name=\"username\" required maxlength=\"32\">\
<label>Password</label><input type=\"password\" name=\"password\" required maxlength=\"64\">\
<button>Log in</button></form>\
<p class=\"note\">The admin account comes from the [admin] section of config.toml (change it there and restart to sync).</p>";
    let body = body
        .replace("[admin]", "[viewer]")
        .replace("The admin account", "The read-only information account");
    ok_page("Information Account Login", body)
}

async fn viewer_login_action(
    State(state): State<Arc<AppState>>,
    Form(f): Form<LoginForm>,
) -> Response {
    let username = f.username.trim().to_string();
    if state.viewer_guard.locked(&username) {
        return err_page("Too many failed attempts, try again in 5 minutes");
    }
    let acc = state.viewer.lock().unwrap().clone();
    let Some(acc) = acc else {
        return err_page(
            "Information account login is disabled — set [viewer] username/password in config.toml and restart",
        );
    };
    let pw = f.password.clone();
    let phc = acc.pass_hash.clone();
    let ok = username == acc.username
        && tokio::task::spawn_blocking(move || auth::verify_password(&pw, &phc))
            .await
            .unwrap_or(false);
    if !ok {
        state.viewer_guard.fail(&username);
        return err_page("Incorrect username or password");
    }
    state.viewer_guard.reset(&username);
    let sid = state.viewer_sessions.create(&acc.username);
    cookie_redirect(
        "/admin",
        "vsid",
        &sid,
        state.cfg.base_url.starts_with("https://"),
    )
}

async fn viewer_logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(sid) = cookie_val(&headers, "vsid") {
        state.viewer_sessions.remove(&sid);
    }
    clear_cookie_page(
        StatusCode::OK,
        "Signed out",
        "<p class=\"ok\">You have signed out of the admin console.</p><p><a href=\"/\">Back to home</a> | <a href=\"/admin/login\">Log in again</a></p>".into(),
        "vsid",
        state.cfg.base_url.starts_with("https://"),
    )
}

async fn admin_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_viewer(&state, &headers) {
        return *r;
    }

    let mut app_rows = String::new();
    {
        let apps = state.apps.lock().unwrap();
        for app in apps.iter().rev() {
            app_rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&app.created_at),
                esc(&app.username),
                esc(&app.fingerprint),
                app_status_html(&app.status),
                esc(app.decided_at.as_deref().unwrap_or("-"))
            ));
        }
    }
    if app_rows.is_empty() {
        app_rows = "<tr><td colspan=\"5\">No applications yet</td></tr>".into();
    }

    let mut user_rows = String::new();
    {
        let users = state.users.lock().unwrap();
        for u in users.iter() {
            user_rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&u.username),
                user_status_html(&u.status),
                esc(u.fingerprint.as_deref().unwrap_or("-")),
                esc(&u.created_at),
                esc(u.decided_at.as_deref().unwrap_or("-"))
            ));
        }
    }
    if user_rows.is_empty() {
        user_rows = "<tr><td colspan=\"5\">No users yet</td></tr>".into();
    }

    let email_cfg = state.cfg.email.clone();
    let mail_desc = if email_cfg.provider == "smtp" {
        if email_cfg.smtp.enabled {
            format!(
                "smtp: {}:{} (tls={})",
                esc(&email_cfg.smtp.host),
                email_cfg.smtp.port,
                esc(&email_cfg.smtp.tls)
            )
        } else {
            "smtp (disabled, mail written to data/outbox/)".to_string()
        }
    } else if email_cfg.provider == "dryrun" {
        "dryrun (not configured, mail written to data/outbox/)".to_string()
    } else {
        format!(
            "{} (sender: {}, api_key: {})",
            esc(&email_cfg.provider),
            esc(if email_cfg.sender.is_empty() {
                "not set"
            } else {
                &email_cfg.sender
            }),
            if email_cfg.api_key.is_empty() {
                "not set"
            } else {
                "configured"
            }
        )
    };

    let script = format!(
        "#!/bin/sh\ncurl -fsS -m 3 \"{}/api/principals?key_id=$1\" || exit 1",
        state.cfg.base()
    );
    let (permit_open, ports_note) = match get_ports(&state).await {
        Ok(ports) if !ports.is_empty() => (
            ports
                .iter()
                .map(|p| format!("127.0.0.1:{}", p.port))
                .collect::<Vec<_>>()
                .join(" "),
            String::new(),
        ),
        Ok(_) => (
            "127.0.0.1:*".to_string(),
            " (port list is empty — update PermitOpen when ports are added; list 127.0.0.1:PORT explicitly if your OpenSSH predates 8.3)".to_string(),
        ),
        Err(e) => (
            "127.0.0.1:*".to_string(),
            format!(
                " (failed to fetch ports: {e} — fix ports_source and regenerate this config)"
            ),
        ),
    };
    let sshd_conf = format!(
        "Port {}\nListenAddress 0.0.0.0\nPidFile /run/sshd-auth-gateway.pid\nTrustedUserCAKeys /etc/ssh/trusted-user-ca.pub\nAuthorizedPrincipalsCommand /usr/local/bin/ssh_auth_principals.sh %i\nAuthorizedPrincipalsCommandUser nobody\nPubkeyAuthentication yes\nPasswordAuthentication no\nChallengeResponseAuthentication no\nAllowTcpForwarding local\nAllowAgentForwarding no\nX11Forwarding no\nPermitTTY no\nPermitOpen {}\nAllowUsers {}",
        state.cfg.gateway_port, permit_open, state.cfg.gateway_user
    );
    let unit = "# /etc/systemd/system/sshd-auth-gateway.service\n[Unit]\nDescription=ssh_auth gateway (sshd)\nAfter=network.target\n\n[Service]\nExecStart=/usr/sbin/sshd -D -f /etc/ssh/sshd_config_gateway\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target";

    let body = format!(
        "<h2>Token applications</h2>\
<p class=\"note\">Approval is <b>email-only</b>: use the Approve/Reject links in the request email (one-time link). This list is for review only.</p>\
<table><tr><th>Time</th><th>Username</th><th>Fingerprint</th><th>Status</th><th>Decided</th></tr>{app_rows}</table>\
<h2>Users</h2>\
<table><tr><th>Username</th><th>Status</th><th>Fingerprint</th><th>Registered</th><th>Last decision</th><th>Actions</th></tr>{user_rows}</table>\
<p class=\"note\">Revocation takes effect immediately (machines verify in real time); revoked users may apply again. Delete also removes their key files.</p>\
<h2>Recipient email</h2>\
<p class=\"note\">Current recipient: <b>{}</b> (from config.toml [email]). Mail provider: {mail_desc}</p>\
<h2>Gateway setup (public server only — internal machines need nothing)</h2>\
<p><a href=\"/admin/gateway-setup.sh\">Download one-click gateway installer</a> — run it on this public server with <code>sudo sh ssh_auth-gateway-setup.sh</code>.</p>\
<p class=\"note\">The installer handles the gateway account, CA, authorization callback, dedicated sshd configuration, and systemd service. You only need to keep frps tunnel ports loopback-only by setting <code>proxyBindAddr = \"127.0.0.1\"</code> in frps.toml and restarting frps (or use a firewall if your frp version lacks this option).</p>\
<pre>{}</pre>\
<pre>{script}</pre>\
<pre>{sshd_conf}</pre>\
<pre>{unit}</pre>\
<p class=\"note\">Then run: <code>systemctl daemon-reload &amp;&amp; systemctl enable --now sshd-auth-gateway</code></p>\
<p class=\"note\">The script queries this service in real time during gateway SSH auth; anything but Active is denied (fail-closed: if this service is down, gateway logins fail — the price for instant revocation). Internal machines keep their normal sshd config and username + password login.{ports_note}</p>\
<p class=\"note\">Config: principals={} , validity={} , ports_source={} , gateway_port={} , gateway_user={}</p>\
<p><a href=\"/admin/logout\">Sign out of admin console</a></p>",
        esc(&email_cfg.recipient),
        esc(&state.ca_pub),
        esc(&state.cfg.cert_principals.join(",")),
        esc(state.cfg.cert_validity.trim()),
        esc(&state.cfg.ports_source),
        state.cfg.gateway_port,
        esc(&state.cfg.gateway_user),
    );
    let body = body
        .replace(
            "Sign out of admin console",
            "Sign out of information account",
        )
        .replace("Admin Console", "Information Status");
    ok_page("Information Status", body)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

async fn api_gateway_setup(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = require_viewer(&state, &headers) {
        return *r;
    }
    let (permit_open, ports_note) = match get_ports(&state).await {
        Ok(ports) if !ports.is_empty() => (
            ports
                .iter()
                .map(|p| format!("127.0.0.1:{}", p.port))
                .collect::<Vec<_>>()
                .join(" "),
            String::new(),
        ),
        Ok(_) => ("127.0.0.1:*".into(), "port list is empty".into()),
        Err(e) => ("127.0.0.1:*".into(), format!("failed to fetch ports: {e}")),
    };
    let callback = format!(
        "#!/bin/sh\nBASE={}\ncurl -fsS -m 3 \"$BASE/api/principals?key_id=$1\" || exit 1\n",
        shell_quote(state.cfg.base())
    );
    let sshd_conf = format!(
        "Port {}\nListenAddress 0.0.0.0\nPidFile /run/sshd-auth-gateway.pid\nTrustedUserCAKeys /etc/ssh/trusted-user-ca.pub\nAuthorizedPrincipalsCommand /usr/local/bin/ssh_auth_principals.sh %i\nAuthorizedPrincipalsCommandUser nobody\nPubkeyAuthentication yes\nPasswordAuthentication no\nChallengeResponseAuthentication no\nAllowTcpForwarding local\nAllowAgentForwarding no\nX11Forwarding no\nPermitTTY no\nPermitOpen {}\nAllowUsers {}\n",
        state.cfg.gateway_port, permit_open, state.cfg.gateway_user
    );
    let unit = "[Unit]\nDescription=ssh_auth gateway (sshd)\nAfter=network.target\n\n[Service]\nExecStart=/usr/sbin/sshd -D -f /etc/ssh/sshd_config_gateway\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n";
    let script = format!(
        "#!/bin/sh\nset -eu\n[ \"$(id -u)\" -eq 0 ] || {{ echo 'run this script with sudo'; exit 1; }}\n\nGATEWAY_USER={user}\nif ! id \"$GATEWAY_USER\" >/dev/null 2>&1; then\n  useradd -m -s /usr/sbin/nologin \"$GATEWAY_USER\"\nfi\nusermod -s /usr/sbin/nologin -p '*' \"$GATEWAY_USER\"\n\ninstall -m 0644 /dev/stdin /etc/ssh/trusted-user-ca.pub <<'SSH_AUTH_CA'\n{ca}\nSSH_AUTH_CA\ninstall -m 0755 /dev/stdin /usr/local/bin/ssh_auth_principals.sh <<'SSH_AUTH_CALLBACK'\n{callback}SSH_AUTH_CALLBACK\ninstall -m 0644 /dev/stdin /etc/ssh/sshd_config_gateway <<'SSH_AUTH_CONFIG'\n{sshd}SSH_AUTH_CONFIG\ninstall -m 0644 /dev/stdin /etc/systemd/system/sshd-auth-gateway.service <<'SSH_AUTH_UNIT'\n{unit}SSH_AUTH_UNIT\n\n/usr/sbin/sshd -t -f /etc/ssh/sshd_config_gateway\nsystemctl daemon-reload\nsystemctl enable --now sshd-auth-gateway\necho 'ssh_auth gateway is ready ({ports_note})'\n",
        user = shell_quote(&state.cfg.gateway_user),
        ca = state.ca_pub,
        callback = callback,
        sshd = sshd_conf,
        unit = unit,
        ports_note = ports_note,
    );
    let script = normalize_script(script);
    let mut response = (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        script,
    )
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=ssh_auth-gateway-setup.sh"),
    );
    response
}

async fn api_principals(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let key_id = q.get("key_id").map(|s| s.as_str()).unwrap_or("");
    let username = key_id.strip_prefix("ssh_auth_").unwrap_or("");
    let active = !username.is_empty() && {
        state
            .users
            .lock()
            .unwrap()
            .iter()
            .any(|u| u.username == username && u.status == "active")
    };
    if active {
        let p = state.cfg.cert_principals.join(",");
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            p,
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "".to_string(),
        )
            .into_response()
    }
}

fn token_user(state: &AppState, token: &str) -> Option<(String, User)> {
    let t = token.trim();
    if !t.starts_with("sk_auth_") || t.len() > 128 {
        return None;
    }
    let users = state.users.lock().unwrap();
    users
        .iter()
        .find(|u| u.token.as_deref() == Some(t) && u.status == "active")
        .map(|u| (u.username.clone(), u.clone()))
}

fn api_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "not found\n".to_string(),
    )
        .into_response()
}

fn normalize_script(script: String) -> String {
    let script = script.replace("\r\n", "\n").replace('\r', "\n");
    if script.ends_with('\n') {
        script
    } else {
        format!("{script}\n")
    }
}

fn build_setup_sh(base: &str, token: &str) -> String {
    normalize_script(format!(
        r#"#!/bin/sh
set -e
BASE="{base}"
T="{token}"
SSH_DIR="$HOME/.ssh"
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
curl -fsSL "$BASE/api/file/key?t=$T" -o "$SSH_DIR/id_ed25519"
curl -fsSL "$BASE/api/file/cert?t=$T" -o "$SSH_DIR/id_ed25519-cert.pub"
chmod 600 "$SSH_DIR/id_ed25519"
touch "$SSH_DIR/config"
awk 'BEGIN{{skip=0}} /^# >>> ssh_auth >>>$/{{skip=1;next}} /^# <<< ssh_auth <<<$/{{skip=0;next}} skip==0{{print}}' "$SSH_DIR/config" > "$SSH_DIR/config.tmp"
curl -fsSL "$BASE/api/file/config?t=$T" >> "$SSH_DIR/config.tmp"
mv "$SSH_DIR/config.tmp" "$SSH_DIR/config"
echo "ssh_auth: files installed to $SSH_DIR and config updated. Connect with 'ssh frp-<port>' or VSCode Remote-SSH."
"#
    ))
}

fn build_setup_ps1(base: &str, token: &str) -> String {
    normalize_script(format!(
        r#"$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$sshDir = Join-Path $env:USERPROFILE ".ssh"
New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri "{base}/api/file/key?t={token}" -OutFile (Join-Path $sshDir "id_ed25519")
Invoke-WebRequest -UseBasicParsing -Uri "{base}/api/file/cert?t={token}" -OutFile (Join-Path $sshDir "id_ed25519-cert.pub")
$block = (Invoke-WebRequest -UseBasicParsing -Uri "{base}/api/file/config?t={token}").Content
$cfg = Join-Path $sshDir "config"
$old = @(if (Test-Path $cfg) {{ Get-Content $cfg }})
$inBlock = $false
$kept = @($old | Where-Object {{
    if ($_ -match '^# >>> ssh_auth >>>$') {{ $inBlock = $true; $false }}
    elseif ($_ -match '^# <<< ssh_auth <<<$') {{ $inBlock = $false; $false }}
    else {{ -not $inBlock }}
}})
Set-Content -Path $cfg -Value ($kept + ($block -split "`r?`n"))
Write-Host "ssh_auth: files installed to $sshDir and config updated. Connect with 'ssh frp-<port>' or VSCode Remote-SSH."
"#
    ))
}

async fn api_setup_sh(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(t) = q.get("t").map(String::as_str) else {
        return api_not_found();
    };
    let Some((_, user)) = token_user(&state, t) else {
        return api_not_found();
    };
    if user.token.is_none() {
        return api_not_found();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        build_setup_sh(state.cfg.base(), t),
    )
        .into_response()
}

async fn api_setup_ps1(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(t) = q.get("t").map(String::as_str) else {
        return api_not_found();
    };
    let Some((_, user)) = token_user(&state, t) else {
        return api_not_found();
    };
    if user.token.is_none() {
        return api_not_found();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        build_setup_ps1(state.cfg.base(), t),
    )
        .into_response()
}

async fn api_file_key(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(t) = q.get("t").map(String::as_str) else {
        return api_not_found();
    };
    let Some((username, _)) = token_user(&state, t) else {
        return api_not_found();
    };
    match std::fs::read_to_string(state.key_path(&username)) {
        Ok(c) => download_response("id_ed25519", &c),
        Err(_) => api_not_found(),
    }
}

async fn api_file_cert(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(t) = q.get("t").map(String::as_str) else {
        return api_not_found();
    };
    let Some((_, user)) = token_user(&state, t) else {
        return api_not_found();
    };
    match &user.cert {
        Some(c) => download_response("id_ed25519-cert.pub", c),
        None => api_not_found(),
    }
}

async fn api_file_config(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(t) = q.get("t").map(String::as_str) else {
        return api_not_found();
    };
    let Some(_) = token_user(&state, t) else {
        return api_not_found();
    };
    let block = ssh_config_block(&state).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        block,
    )
        .into_response()
}

async fn regen_token(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(username) = session_user(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let token = {
        let mut users = state.users.lock().unwrap();
        let Some(u) = users.iter_mut().find(|u| u.username == username) else {
            return err_page("Account not found");
        };
        if u.status != "active" {
            return err_page("Only active users hold a token");
        }
        let t = auth::generate_token();
        u.token = Some(t.clone());
        t
    };
    if let Err(e) = store::save_users(&state.users_path(), &state.users.lock().unwrap()) {
        return internal_page(&format!("failed to save user: {e:#}"));
    }
    ok_page(
        "Token Regenerated",
        format!(
            "<p class=\"ok\">Your new token (the old one is now invalid):</p><p><code>{}</code></p><p>Go back to the dashboard to copy the one-command setup.</p><p><a href=\"/dashboard\">Back to dashboard</a></p>",
            esc(&token)
        ),
    )
}
