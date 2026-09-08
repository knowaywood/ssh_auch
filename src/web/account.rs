use super::*;

#[derive(serde::Deserialize)]
pub(super) struct RegForm {
    username: String,
    password: String,
    password2: String,
}

pub(super) async fn register_page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
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

pub(super) async fn register_action(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<RegForm>,
) -> Response {
    if rate_limited(&state.last_reg, addr.ip()) {
        return err_page("Registering too frequently, try again in a minute");
    }
    let username = form.username.trim().to_string();
    if !(3..=32).contains(&username.len())
        || !username.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
    {
        return auth_form_error(
            "Username must be 3-32 chars, only letters/digits/underscore/hyphen",
        );
    }
    if !(8..=64).contains(&form.password.len()) {
        return auth_form_error("Password must be 8-64 characters");
    }
    if form.password != form.password2 {
        return auth_form_error("Passwords do not match");
    }
    {
        let users = state.users.lock().unwrap();
        if users.iter().any(|user| user.username == username) {
            return auth_form_error("Username is already taken");
        }
    }
    let password = form.password.clone();
    let hash = match tokio::task::spawn_blocking(move || auth::hash_password(&password)).await {
        Ok(Ok(hash)) => hash,
        _ => return internal_page("failed to hash password"),
    };
    state
        .users
        .lock()
        .unwrap()
        .push(User::new(&username, &hash, now_rfc3339()));
    if let Err(error) = store::save_users(&state.users_path(), &state.users.lock().unwrap()) {
        return internal_page(&format!("failed to save user: {error:#}"));
    }
    let session = state.sessions.create(&username);
    cookie_redirect(
        "/dashboard",
        "sid",
        &session,
        state.cfg.base_url.starts_with("https://"),
    )
}

pub(super) async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
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

pub(super) async fn login_action(
    State(state): State<Arc<AppState>>,
    Form(form): Form<LoginForm>,
) -> Response {
    let username = form.username.trim().to_string();
    if state.login_guard.locked(&username) {
        return err_page("Too many failed attempts, try again in 5 minutes");
    }
    let user = {
        state
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|user| user.username == username)
            .cloned()
    };
    let Some(user) = user else {
        state.login_guard.fail(&username);
        return err_page("Incorrect username or password");
    };
    let password = form.password.clone();
    let password_hash = user.pass_hash.clone();
    let valid =
        tokio::task::spawn_blocking(move || auth::verify_password(&password, &password_hash))
            .await
            .unwrap_or(false);
    if !valid {
        state.login_guard.fail(&username);
        return err_page("Incorrect username or password");
    }
    state.login_guard.reset(&username);
    let session = state.sessions.create(&username);
    cookie_redirect(
        "/dashboard",
        "sid",
        &session,
        state.cfg.base_url.starts_with("https://"),
    )
}

pub(super) async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(session) = cookie_val(&headers, "sid") {
        state.sessions.remove(&session);
    }
    clear_cookie_page(
        StatusCode::OK,
        "Signed out",
        "<p class=\"ok\">You have signed out.</p><p><a href=\"/\">Back to home</a> | <a href=\"/login\">Log in again</a></p>".into(),
        "sid",
        state.cfg.base_url.starts_with("https://"),
    )
}
