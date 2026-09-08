use super::{AppState, ui::layout};
use crate::auth;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) fn cookie_val(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all(header::COOKIE) {
        let cookie = value.to_str().ok()?;
        for part in cookie.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix(&format!("{name}=")) {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub(super) fn session_user(state: &AppState, headers: &HeaderMap) -> Option<String> {
    state.sessions.get(&cookie_val(headers, "sid")?)
}

pub(super) fn viewer_session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    state.viewer_sessions.get(&cookie_val(headers, "vsid")?)
}

pub(super) fn require_viewer(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    if viewer_session(state, headers).is_some() {
        Ok(())
    } else {
        Err(Box::new(Redirect::to("/admin/login").into_response()))
    }
}

pub(super) fn cookie_redirect(loc: &str, name: &str, sid: &str, secure: bool) -> Response {
    let mut response = Redirect::to(loc).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "{name}={sid}; HttpOnly{}; SameSite=Lax; Path=/; Max-Age={}",
            if secure { "; Secure" } else { "" },
            auth::SESSION_TTL.as_secs()
        )
        .parse()
        .unwrap(),
    );
    response
}

pub(super) fn clear_cookie_page(
    status: StatusCode,
    title: &str,
    body: String,
    name: &str,
    secure: bool,
) -> Response {
    let mut response = layout(status, title, body);
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_bytes(
            format!(
                "{name}=; HttpOnly{}; SameSite=Lax; Path=/; Max-Age=0",
                if secure { "; Secure" } else { "" },
            )
            .as_bytes(),
        )
        .unwrap(),
    );
    response
}

pub(super) fn rate_limited(map: &Mutex<HashMap<IpAddr, Instant>>, ip: IpAddr) -> bool {
    let mut entries = map.lock().unwrap();
    entries.retain(|_, time| time.elapsed() < Duration::from_secs(3600));
    if entries
        .get(&ip)
        .is_some_and(|time| time.elapsed() < Duration::from_secs(60))
    {
        return true;
    }
    entries.insert(ip, Instant::now());
    false
}
