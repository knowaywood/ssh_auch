use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

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

pub(super) fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub(super) fn layout(status: StatusCode, title: &str, body: String) -> Response {
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{}</title><style>{CSS}</style></head><body><div class="wrap"><h1>SSH Access Service (frp Tunneling)</h1>{body}</div></body></html>"#,
        esc(title)
    );
    (status, Html(html)).into_response()
}

pub(super) fn ok_page(title: &str, body: String) -> Response {
    layout(StatusCode::OK, title, body)
}

pub(super) fn err_page(msg: &str) -> Response {
    layout(
        StatusCode::BAD_REQUEST,
        "Error",
        format!(
            "<p class=\"bad\">{}</p><p><a href=\"/\">Back to home</a></p>",
            esc(msg)
        ),
    )
}

pub(super) fn internal_page(msg: &str) -> Response {
    layout(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal Server Error",
        format!(
            "<p class=\"bad\">{}</p><p><a href=\"/\">Back to home</a></p>",
            esc(msg)
        ),
    )
}

pub(super) fn auth_form_error(msg: &str) -> Response {
    layout(
        StatusCode::BAD_REQUEST,
        "Error",
        format!(
            "<p class=\"bad\">{}</p><p><a href=\"javascript:history.back()\">Go back</a> | <a href=\"/\">Back to home</a></p>",
            esc(msg)
        ),
    )
}

pub(super) fn user_status_html(status: &str) -> &'static str {
    match status {
        "active" => "<span class=\"ok\">Active</span>",
        "pending" => "<span class=\"pend\">Pending review</span>",
        "revoked" => "<span class=\"bad\">Revoked</span>",
        _ => "<span class=\"note\">Not applied</span>",
    }
}

pub(super) fn app_status_html(status: &str) -> &'static str {
    match status {
        "approved" => "<span class=\"ok\">Approved</span>",
        "rejected" => "<span class=\"bad\">Rejected</span>",
        "withdrawn" => "<span class=\"note\">Withdrawn</span>",
        _ => "<span class=\"pend\">Pending</span>",
    }
}
