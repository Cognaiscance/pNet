//! Admin HTTP UI: pages, forms, setup wizard, app approve/reject/rename.
//!
//! Served via `ui_request`. Auth lives in `admin_auth`; fabric mutations go
//! through `request_change` / invitation helpers on sibling modules.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

use super::super::action_queue::WorkerContext;
use super::super::admin_auth::{
    clear_session_cookie_header, csrf_post_ok, hash_password, session_id_from_cookie_header,
    set_session_cookie_header, validate_new_password, verify_password, UiFlash,
    INVITE_CODE_HEADER, MIN_PASSWORD_LEN,
};
use super::super::crypto::generate_ed25519_keypair;
use super::super::data_models::{
    Device, DeviceGrade, Node, Uuid, WRITE_LOG_RETENTION, generate_uuid,
};
use super::super::wire::*;
use super::{
    generate_contact_invitation, generate_device_invitation, initiate_bootstrap,
    initiate_contact_exchange, parse_pnet_hosts, request_change, sync_pull, uuid_hex, Change,
};

// ── UI / HTTP handlers ────────────────────────────────────────────────────────

pub fn ui_request(
    stream: std::net::TcpStream,
    method: String,
    path:   String,
    query:  String,
    cookie: String,
    host:   String,
    origin: String,
    referer: String,
    body:   Vec<u8>,
    ctx:    &WorkerContext,
) {
    use super::super::admin_auth::{
        clear_session_cookie_header, csrf_post_ok, session_id_from_cookie_header,
        set_session_cookie_header, UiFlash, INVITE_CODE_HEADER,
    };

    let (initialized, has_password) = {
        let node = ctx.node.read().unwrap();
        (node.is_initialized(), node.admin_password_hash.is_some())
    };

    let session_id = session_id_from_cookie_header(&cookie);
    let authed = session_id
        .as_ref()
        .map(|id| ctx.sessions.is_valid(id))
        .unwrap_or(false);

    let is_setup_route = matches!(path.as_str(), "/setup" | "/setup/create" | "/setup/join");
    let is_login_route = matches!(path.as_str(), "/login");
    let is_set_password_route = matches!(path.as_str(), "/set-password");
    let is_logout = method == "POST" && path == "/logout";

    // ── Access gates ─────────────────────────────────────────────────────────
    // 1. Uninitialized → setup only.
    // 2. Initialized without password (upgrade path) → set-password only.
    // 3. Initialized with password → login public; everything else needs session.
    if !initialized {
        if !is_setup_route {
            return respond_redirect(&stream, "/setup");
        }
    } else if !has_password {
        if is_setup_route {
            return respond_redirect(&stream, "/set-password");
        }
        if !is_set_password_route {
            return respond_redirect(&stream, "/set-password");
        }
    } else {
        if is_setup_route {
            return respond_redirect(&stream, if authed { "/dashboard" } else { "/login" });
        }
        if is_set_password_route {
            // Password already set — no open reset without auth (out of scope for 1.1).
            return respond_redirect(&stream, if authed { "/dashboard" } else { "/login" });
        }
        if !authed && !is_login_route {
            return respond_redirect(&stream, "/login");
        }
        if authed && is_login_route && method == "GET" {
            return respond_redirect(&stream, "/dashboard");
        }
    }

    // CSRF: SameSite=Strict on the session cookie is the primary defence.
    // When Origin/Referer is present, require it to match Host.
    if method == "POST" && !csrf_post_ok(&host, &origin, &referer) {
        return respond_html(
            &stream,
            403,
            &layout(ctx, "Forbidden", "<h1>403 — CSRF check failed</h1>\
             <p>Origin/Referer does not match this host.</p>"),
            None,
        );
    }

    match (method.as_str(), path.as_str()) {
        ("GET",  "/setup") => respond_html(&stream, 200, &render_setup(&query), None),
        ("POST", "/setup/create") => {
            match complete_setup(&body, ctx) {
                Ok(sid) => respond_redirect_cookie(
                    &stream, "/dashboard", &set_session_cookie_header(&sid),
                ),
                Err(err) => respond_redirect(
                    &stream,
                    &format!("/setup?grade=sg&role=new&error={err}"),
                ),
            }
        }
        ("POST", "/setup/join") => {
            match complete_join_setup(&body, ctx) {
                Ok(sid) => respond_redirect_cookie(
                    &stream, "/setup?waiting=1", &set_session_cookie_header(&sid),
                ),
                Err(err) => {
                    let grade = form_field(&body, "grade").unwrap_or("dg");
                    let role_q = if grade == "sg" { "&role=join" } else { "" };
                    respond_redirect(
                        &stream,
                        &format!("/setup?grade={grade}{role_q}&error={err}"),
                    )
                }
            }
        }
        ("GET",  "/login") => {
            let err = query_param(&query, "error").unwrap_or("");
            respond_html(&stream, 200, &render_login(err), None)
        }
        ("POST", "/login") => {
            match try_login(&body, ctx) {
                Ok(sid) => respond_redirect_cookie(
                    &stream, "/dashboard", &set_session_cookie_header(&sid),
                ),
                Err(()) => respond_redirect(&stream, "/login?error=bad"),
            }
        }
        ("GET",  "/set-password") => {
            let err = query_param(&query, "error").unwrap_or("");
            respond_html(&stream, 200, &render_set_password(err), None)
        }
        ("POST", "/set-password") => {
            match complete_set_password(&body, ctx) {
                Ok(sid) => respond_redirect_cookie(
                    &stream, "/dashboard", &set_session_cookie_header(&sid),
                ),
                Err(err) => respond_redirect(&stream, &format!("/set-password?error={err}")),
            }
        }
        ("POST", "/logout") if is_logout => {
            if let Some(id) = session_id {
                ctx.sessions.revoke(&id);
            }
            respond_redirect_cookie(&stream, "/login", &clear_session_cookie_header())
        }
        ("GET",  "/")                     => respond_redirect(&stream, "/dashboard"),
        ("GET",  "/dashboard")            => respond_html(&stream, 200, &render_dashboard(ctx), None),
        ("GET",  "/pending-apps")         => respond_html(&stream, 200, &render_pending_apps(ctx, &query), None),
        ("POST", "/pending-apps/approve") => {
            let target = redirect_with_error("/pending-apps", approve_app(&body, ctx));
            respond_redirect(&stream, &target);
        }
        ("POST", "/pending-apps/reject")  => {
            let target = redirect_with_error("/pending-apps", reject_app(&body, ctx));
            respond_redirect(&stream, &target);
        }
        ("GET",  "/applications")  => respond_html(&stream, 200, &render_applications(ctx, &query), None),
        ("POST", "/applications/delete") => {
            let target = redirect_with_error("/applications", reject_app(&body, ctx));
            respond_redirect(&stream, &target);
        }
        ("POST", "/applications/rename") => {
            let target = redirect_with_error("/applications", rename_app(&body, ctx));
            respond_redirect(&stream, &target);
        }
        ("GET",  "/contacts")      => respond_html(&stream, 200, &render_contacts(ctx), None),
        ("GET",  "/devices")       => respond_html(&stream, 200, &render_devices(ctx), None),
        ("POST", "/devices/sync")  => {
            // Manual refresh: pull the latest public/private state from the
            // writer SG. No-op when this node is the writer or has no
            // reachable own SG.
            sync_pull(ctx);
            respond_redirect(&stream, "/devices");
        }
        ("GET",  "/diagnostics")   => respond_html(&stream, 200, &render_diagnostics(ctx), None),
        ("GET",  "/invitations")   => {
            let flash = session_id
                .as_ref()
                .and_then(|id| ctx.sessions.take_flash(id));
            respond_html(&stream, 200, &render_invitations(ctx, &query, flash), None)
        }
        ("POST", "/invitations/device") => {
            match generate_device_invitation(ctx) {
                Some(code) => {
                    if let Some(ref id) = session_id {
                        ctx.sessions
                            .set_flash(id, UiFlash::DeviceCode(code.clone()));
                    }
                    respond_redirect_extra(
                        &stream,
                        "/invitations",
                        "",
                        &[(INVITE_CODE_HEADER, code.as_str())],
                    );
                }
                None => respond_redirect(&stream, "/invitations?error=no_host"),
            }
        }
        ("POST", "/invitations/contact") => {
            match generate_contact_invitation(ctx) {
                Some(code) => {
                    if let Some(ref id) = session_id {
                        ctx.sessions
                            .set_flash(id, UiFlash::ContactCode(code.clone()));
                    }
                    respond_redirect_extra(
                        &stream,
                        "/invitations",
                        "",
                        &[(INVITE_CODE_HEADER, code.as_str())],
                    );
                }
                None => respond_redirect(&stream, "/invitations?error=no_host"),
            }
        }
        ("POST", "/invitations/enter") => {
            // Device invitation redeem from an already-configured node is not
            // first-run setup; password was set at setup. Keep bootstrap only.
            initiate_bootstrap(&body, ctx);
            respond_redirect(&stream, "/invitations");
        }
        ("POST", "/contacts/enter") => {
            initiate_contact_exchange(&body, ctx);
            respond_redirect(&stream, "/contacts");
        }
        _ => respond_html(&stream, 404, &layout(ctx, "Not Found", "<h1>404 — Not Found</h1>"), None),
    }
}

// ── Routing helpers ───────────────────────────────────────────────────────────

fn respond_html(stream: &std::net::TcpStream, status: u16, html: &str, set_cookie: Option<&str>) {
    use std::io::Write;
    let status_text = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "OK",
    };
    let body = html.as_bytes();
    let cookie_line = set_cookie
        .map(|c| format!("Set-Cookie: {c}\r\n"))
        .unwrap_or_default();
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         {cookie_line}\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let mut s = stream;
    let _ = s.write_all(header.as_bytes());
    let _ = s.write_all(body);
}

fn respond_redirect(stream: &std::net::TcpStream, location: &str) {
    respond_redirect_cookie(stream, location, "");
}

fn respond_redirect_cookie(stream: &std::net::TcpStream, location: &str, set_cookie: &str) {
    respond_redirect_extra(stream, location, set_cookie, &[]);
}

/// 302 redirect with optional Set-Cookie and extra response headers
/// (e.g. `X-Pnet-Invitation-Code` for harnesses — never put secrets in the URL).
fn respond_redirect_extra(
    stream: &std::net::TcpStream,
    location: &str,
    set_cookie: &str,
    extra: &[(&str, &str)],
) {
    use std::io::Write;
    let cookie_line = if set_cookie.is_empty() {
        String::new()
    } else {
        format!("Set-Cookie: {set_cookie}\r\n")
    };
    let mut extra_lines = String::new();
    for (name, value) in extra {
        extra_lines.push_str(name);
        extra_lines.push_str(": ");
        extra_lines.push_str(value);
        extra_lines.push_str("\r\n");
    }
    let response = format!(
        "HTTP/1.1 302 Found\r\n\
         Location: {location}\r\n\
         {cookie_line}\
         {extra_lines}\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n"
    );
    let mut s = stream;
    let _ = s.write_all(response.as_bytes());
}

/// Store an admin password hash and issue a new session. Call after validation.
fn store_password_and_session(ctx: &WorkerContext, password: &str) -> String {
    use super::super::admin_auth::hash_password;
    let hash = hash_password(password);
    {
        let mut node = ctx.node.write().unwrap();
        node.admin_password_hash = Some(hash);
    }
    ctx.save_node();
    ctx.sessions.create()
}

fn try_login(body: &[u8], ctx: &WorkerContext) -> Result<String, ()> {
    use super::super::admin_auth::verify_password;
    let password = form_field(body, "password")
        .map(url_decode)
        .unwrap_or_default();
    let stored = ctx.node.read().unwrap().admin_password_hash.clone();
    let Some(stored) = stored else { return Err(()) };
    if !verify_password(&password, &stored) {
        return Err(());
    }
    Ok(ctx.sessions.create())
}

fn complete_set_password(body: &[u8], ctx: &WorkerContext) -> Result<String, &'static str> {
    use super::super::admin_auth::validate_new_password;
    // Only when no password exists yet (upgrade / missing env).
    if ctx.node.read().unwrap().admin_password_hash.is_some() {
        return Err("exists");
    }
    let password = form_field(body, "password").map(url_decode).unwrap_or_default();
    let confirm  = form_field(body, "password_confirm").map(url_decode).unwrap_or_default();
    validate_new_password(&password, &confirm)?;
    Ok(store_password_and_session(ctx, &password))
}

/// Helper for POST routes: redirect to `base` on success, or to
/// `base?error=<code>` when the action returned a UI error code.
fn redirect_with_error(base: &str, err: Option<&'static str>) -> String {
    match err {
        Some(code) => format!("{base}?error={code}"),
        None       => base.to_string(),
    }
}

/// Extract a URL-encoded form field value from a POST body (e.g. `id=5`).
pub(crate) fn form_field<'a>(body: &'a [u8], field: &str) -> Option<&'a str> {
    let s = std::str::from_utf8(body).ok()?;
    let prefix = format!("{field}=");
    for part in s.split('&') {
        if let Some(val) = part.strip_prefix(prefix.as_str()) {
            return Some(val);
        }
    }
    None
}

pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

/// Decode a percent-encoded URL form value (e.g. `hello+world` → `hello world`).
pub(crate) fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => { out.push(' '); i += 1; }
            b'%' if i + 2 < b.len() => {
                match (hex_nibble(b[i + 1]), hex_nibble(b[i + 2])) {
                    (Some(hi), Some(lo)) => { out.push(char::from(hi << 4 | lo)); i += 3; }
                    _ => { out.push('%'); i += 1; }
                }
            }
            c => { out.push(char::from(c)); i += 1; }
        }
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Extract a value from a query string (e.g. `grade=sg&role=new`).
pub(crate) fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    for part in query.split('&') {
        if let Some(val) = part.strip_prefix(prefix.as_str()) {
            return Some(val);
        }
    }
    None
}

// ── Page renders ─────────────────────────────────────────────────────────────

fn render_dashboard(ctx: &WorkerContext) -> String {
    let node        = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device      = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid);

    let owner_alias  = html_escape(&node.owner.user.alias);
    let device_alias = html_escape(device.map(|d| d.alias.as_str()).unwrap_or("unknown"));
    let n_contacts   = node.owner.contact_users.len();
    let n_apps: usize = node.owner.user.devices.iter().map(|d| d.applications.len()).sum();
    let n_conns      = node.owner.active_connections.len();

    let hosts_line = match device {
        Some(d) if d.hosts.is_empty() => {
            "<span style='color:#900'>none — set <code>PNET_HOSTS</code> and restart</span>".to_string()
        }
        Some(d) => html_escape(&d.hosts.join(", ")),
        None => "unknown".to_string(),
    };

    let body = format!(
        "<h1>Dashboard</h1>\
         <div class=\"stats\">\
           <div class=\"stat-card\"><div class=\"stat\">{n_contacts}</div><div class=\"label\">Contacts</div></div>\
           <div class=\"stat-card\"><div class=\"stat\">{n_apps}</div><div class=\"label\">Applications</div></div>\
           <div class=\"stat-card\"><div class=\"stat\">{n_conns}</div><div class=\"label\">Active Connections</div></div>\
         </div>\
         <div class=\"card\">\
           <div class=\"label\">Owner</div><div>{owner_alias}</div>\
           <div class=\"label\" style=\"margin-top:.5rem\">Device</div><div>{device_alias}</div>\
           <div class=\"label\" style=\"margin-top:.5rem\">Advertised hosts</div><div>{hosts_line}</div>\
         </div>"
    );
    layout(ctx, "Dashboard", &body)
}

/// Render a red banner for the UI error codes emitted by approve_app /
/// reject_app. Returns an empty string when there's no error to show.
fn ui_error_banner(query: &str) -> String {
    match query_param(query, "error") {
        Some(code) if code == UI_ERR_PUBLISH_FAILED =>
            "<div class='card' style='background:#fee;color:#900;border:1px solid #c66'>\
                <strong>Could not publish change:</strong> no reachable writer SG. \
                The local change has been rolled back; retry when an SG is online.\
            </div>".to_string(),
        _ => String::new(),
    }
}

fn render_pending_apps(ctx: &WorkerContext, query: &str) -> String {
    let node        = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device      = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid);

    let rows: String = device
        .map(|d| {
            d.applications.iter()
                .filter(|a| !a.user_approved)
                .map(|a| format!(
                    "<tr>\
                       <td>{}</td>\
                       <td>{}</td>\
                       <td>{}</td>\
                       <td>\
                         <form method='post' action='/pending-apps/approve'>\
                           <input type='hidden' name='id' value='{}'>\
                           <button class='approve' type='submit'>Approve</button>\
                         </form>\
                         <form method='post' action='/pending-apps/reject'>\
                           <input type='hidden' name='id' value='{}'>\
                           <button class='reject' type='submit'>Reject</button>\
                         </form>\
                       </td>\
                     </tr>",
                    html_escape(&a.alias),
                    html_escape(&a.protocol),
                    html_escape(&a.host.to_string()),
                    uuid_hex(&a.id),
                    uuid_hex(&a.id),
                ))
                .collect()
        })
        .unwrap_or_default();

    let error_banner = ui_error_banner(query);
    let table = if rows.is_empty() {
        "<p class='empty'>No pending applications.</p>".to_string()
    } else {
        format!(
            "<table>\
               <tr><th>Alias</th><th>Protocol</th><th>Host</th><th>Actions</th></tr>\
               {rows}\
             </table>"
        )
    };
    let body = format!("<h1>Pending Apps</h1>{error_banner}{table}");
    layout(ctx, "Pending Apps", &body)
}

fn render_applications(ctx: &WorkerContext, query: &str) -> String {
    let node        = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device      = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid);

    let rows: String = device
        .map(|d| {
            d.applications.iter()
                .filter(|a| a.user_approved)
                .map(|a| format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td>\
                     <td><form method='post' action='/applications/rename' style='margin:0;display:flex;gap:.25rem'>\
                       <input type='hidden' name='id' value='{id_hex}'>\
                       <input type='text' name='alias' value='{alias}' required>\
                       <button type='submit'>Rename</button>\
                     </form></td>\
                     <td><form method='post' action='/applications/delete' style='margin:0'>\
                       <input type='hidden' name='id' value='{id_hex}'>\
                       <button type='submit'>Delete</button>\
                     </form></td></tr>",
                    html_escape(&a.alias),
                    html_escape(&a.protocol),
                    html_escape(&a.host.to_string()),
                    id_hex = uuid_hex(&a.id),
                    alias  = html_escape(&a.alias),
                ))
                .collect()
        })
        .unwrap_or_default();

    let error_banner = ui_error_banner(query);
    let table = if rows.is_empty() {
        "<p class='empty'>No approved applications.</p>".to_string()
    } else {
        format!(
            "<table>\
               <tr><th>Alias</th><th>Protocol</th><th>Host</th><th>Rename</th><th></th></tr>\
               {rows}\
             </table>"
        )
    };
    let body = format!("<h1>Applications</h1>{error_banner}{table}");
    layout(ctx, "Applications", &body)
}

fn render_contacts(ctx: &WorkerContext) -> String {
    let node     = ctx.node.read().unwrap();
    let contacts = &node.owner.contact_users;

    let rows: String = contacts.iter()
        .map(|c| {
            let dev_cells: String = c.user.devices.iter().map(|d| {
                let app_count = d.applications.iter().filter(|a| a.user_approved).count();
                format!(
                    "<li style='font-size:.85rem'>{} — {} app{}</li>",
                    html_escape(&d.alias),
                    app_count,
                    if app_count == 1 { "" } else { "s" },
                )
            }).collect();
            let dev_list = if c.user.devices.is_empty() {
                "<span style='color:#999;font-size:.85rem'>no devices</span>".to_string()
            } else {
                format!("<ul style='margin:0;padding-left:1.2rem'>{dev_cells}</ul>")
            };
            format!(
                "<tr><td>{}</td><td>{dev_list}</td></tr>",
                html_escape(&c.user.alias),
            )
        })
        .collect();

    let table = if rows.is_empty() {
        "<p class='empty'>No contacts yet.</p>".to_string()
    } else {
        format!(
            "<table>\
               <tr><th>Alias</th><th>Devices &amp; Apps</th></tr>\
               {rows}\
             </table>"
        )
    };

    drop(node);

    let body = format!(
        "<h1>Contacts</h1>\
         {table}\
         <div class='card' style='margin-top:1.5rem'>\
           <h2 style='margin-top:0;font-size:1rem'>Add a Contact</h2>\
           <p style='color:#666;font-size:.9rem;margin-top:0'>Paste an invitation code from another pNet user.</p>\
           <form method='post' action='/contacts/enter'>\
             <textarea name='code' rows='3' \
               style='width:100%;font-family:monospace;font-size:.85rem;\
                      box-sizing:border-box;padding:.4rem;border:1px solid #ccc;border-radius:4px' \
               placeholder='Paste contact invitation code here...'></textarea><br>\
             <button type='submit' style='margin-top:.5rem'>Add Contact</button>\
           </form>\
         </div>"
    );
    layout(ctx, "Contacts", &body)
}

fn render_devices(ctx: &WorkerContext) -> String {
    let node        = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;

    let rows: String = node.owner.user.devices.iter()
        .map(|d| {
            let suffix = if d.uuid == device_uuid { " <em>(this device)</em>" } else { "" };
            format!(
                "<tr><td>{}{suffix}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&d.alias),
                html_escape(&d.hosts.join(", ")),
                d.applications.len(),
            )
        })
        .collect();

    let heading = "\
        <div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem'>\
          <h1 style='margin:0'>Devices</h1>\
          <form method='post' action='/devices/sync'>\
            <button type='submit'>Sync</button>\
          </form>\
        </div>";

    let body = if rows.is_empty() {
        format!("{heading}<p class='empty'>No devices.</p>")
    } else {
        format!(
            "{heading}\
             <table>\
               <tr><th>Alias</th><th>Host</th><th>Apps</th></tr>\
               {rows}\
             </table>"
        )
    };
    layout(ctx, "Devices", &body)
}

// ── Sync v2 diagnostics ───────────────────────────────────────────────────────

/// Render `/diagnostics` — surfaces the ephemeral state that drives sync v2
/// partition reconciliation: per-peer reachability, last exchanged watermarks,
/// and buffered inbound merge proposals. Read-only.
pub(crate) fn render_diagnostics(ctx: &WorkerContext) -> String {
    let node = ctx.node.read().unwrap();
    let local_uuid = node.device_uuid;
    let pv = node.owner.public_version;

    let local_section = format!(
        "<div class='card'>\
           <h2 style='margin-top:0'>Local node</h2>\
           <table>\
             <tr><th>Device UUID</th><td><code>{local}</code></td></tr>\
             <tr><th>Public version</th><td>writer=<code>{w}</code> epoch={e} seq={s}</td></tr>\
             <tr><th>Write log</th><td>{n} entries (retention {ret}d)</td></tr>\
           </table>\
         </div>",
        local = uuid_hex(&local_uuid),
        w     = uuid_hex(&pv.writer_sg_uuid),
        e     = pv.epoch,
        s     = pv.seq,
        n     = node.owner.write_log.len(),
        ret   = WRITE_LOG_RETENTION.as_secs() / 86_400,
    );

    // Build an alias lookup so peer-uuid keys in the ephemeral maps render
    // with human-readable names.
    let alias_of = |uuid: &Uuid| -> String {
        if uuid == &local_uuid { return "(this device)".to_string(); }
        for d in &node.owner.user.devices {
            if d.uuid == *uuid { return d.alias.clone(); }
        }
        for c in &node.owner.contact_users {
            for d in &c.user.devices {
                if d.uuid == *uuid { return format!("{}/{}", c.user.alias, d.alias); }
            }
        }
        "(unknown)".to_string()
    };

    // Own-user SG peers + reachability.
    let mut peer_rows = String::new();
    for d in &node.owner.user.devices {
        if !matches!(d.grade, DeviceGrade::SG) || d.uuid == local_uuid { continue; }
        let host_lines: String = d.hosts.iter().map(|h| {
            match node.sg_statuses.get(&(d.uuid, h.clone())) {
                Some(s) => {
                    let rtt = s.last_rtt.map(|r| format!("{}ms", r.as_millis()))
                        .unwrap_or_else(|| "—".to_string());
                    let status = if s.up { "<span style='color:#2d7a3b'>up</span>" }
                                 else    { "<span style='color:#c0392b'>down</span>" };
                    format!("<li><code>{}</code> — {status} (rtt {rtt})</li>", html_escape(h))
                }
                None => format!("<li><code>{}</code> — <span style='color:#888'>not yet polled</span></li>",
                                html_escape(h)),
            }
        }).collect();
        peer_rows.push_str(&format!(
            "<tr><td>{alias}<br><code style='font-size:.75rem;color:#888'>{uuid}</code></td>\
                 <td><ul style='margin:0;padding-left:1.2rem'>{host_lines}</ul></td></tr>",
            alias = html_escape(&d.alias),
            uuid  = uuid_hex(&d.uuid),
        ));
    }
    let peers_section = if peer_rows.is_empty() {
        "<div class='card'><h2 style='margin-top:0'>Own-user SG peers</h2>\
         <p class='empty'>No other own-user SG peers.</p></div>".to_string()
    } else {
        format!(
            "<div class='card'><h2 style='margin-top:0'>Own-user SG peers</h2>\
             <table><tr><th>Peer</th><th>Hosts</th></tr>{peer_rows}</table></div>"
        )
    };

    // Last watermarks: peer_uuid → writer_uuid → SyncVersion.
    let mut wm_rows = String::new();
    let mut peers_with_wm: Vec<&Uuid> = node.owner.last_watermarks.keys().collect();
    peers_with_wm.sort_by_key(|u| uuid_hex(u));
    for peer_uuid in peers_with_wm {
        let writers = &node.owner.last_watermarks[peer_uuid];
        let mut sub_rows: Vec<String> = writers.iter().map(|(wu, sv)| {
            format!(
                "<tr><td><code>{}</code><br><span style='font-size:.75rem;color:#888'>{}</span></td>\
                     <td>epoch={} seq={}</td></tr>",
                alias_of(wu), uuid_hex(wu), sv.epoch, sv.seq,
            )
        }).collect();
        sub_rows.sort();
        wm_rows.push_str(&format!(
            "<tr><td>{alias}<br><code style='font-size:.75rem;color:#888'>{uuid}</code></td>\
                 <td><table style='margin:0;box-shadow:none;background:transparent'>\
                       <tr><th>Writer</th><th>Version</th></tr>{}</table></td></tr>",
            sub_rows.concat(),
            alias = html_escape(&alias_of(peer_uuid)),
            uuid  = uuid_hex(peer_uuid),
        ));
    }
    let wm_section = if wm_rows.is_empty() {
        "<div class='card'><h2 style='margin-top:0'>Last watermarks</h2>\
         <p class='empty'>No watermark exchanges yet.</p></div>".to_string()
    } else {
        format!(
            "<div class='card'><h2 style='margin-top:0'>Last watermarks</h2>\
             <p style='font-size:.85rem;color:#666;margin-top:0'>Per-peer, per-writer agreed reconciliation point. \
                Rebuilt on every watermark-probe round-trip.</p>\
             <table><tr><th>Peer</th><th>Per-writer min</th></tr>{wm_rows}</table></div>"
        )
    };

    // Buffered inbound merge proposals.
    let mut pp_rows = String::new();
    let mut peers_with_pp: Vec<&Uuid> = node.owner.received_merge_proposals.keys().collect();
    peers_with_pp.sort_by_key(|u| uuid_hex(u));
    for peer_uuid in peers_with_pp {
        let entries = &node.owner.received_merge_proposals[peer_uuid];
        pp_rows.push_str(&format!(
            "<tr><td>{alias}<br><code style='font-size:.75rem;color:#888'>{uuid}</code></td>\
                 <td>{n} entr{plural}</td></tr>",
            alias  = html_escape(&alias_of(peer_uuid)),
            uuid   = uuid_hex(peer_uuid),
            n      = entries.len(),
            plural = if entries.len() == 1 { "y" } else { "ies" },
        ));
    }
    let pp_section = if pp_rows.is_empty() {
        "<div class='card'><h2 style='margin-top:0'>Buffered merge proposals</h2>\
         <p class='empty'>No inbound merge proposals buffered.</p></div>".to_string()
    } else {
        format!(
            "<div class='card'><h2 style='margin-top:0'>Buffered merge proposals</h2>\
             <p style='font-size:.85rem;color:#666;margin-top:0'>Entries received from peers and waiting to be \
                merged into the local log.</p>\
             <table><tr><th>Peer</th><th>Buffered</th></tr>{pp_rows}</table></div>"
        )
    };

    drop(node);

    let body = format!(
        "<h1>Diagnostics</h1>{local_section}{peers_section}{wm_section}{pp_section}"
    );
    layout(ctx, "Diagnostics", &body)
}

// ── App approval / rejection ──────────────────────────────────────────────────

/// Error code surfaced to the UI via `?error=` when a UI-driven mutation
/// reaches the sync v1 layer but cannot be published. The handler has
/// already rolled the local mutation back, so the UI state matches reality.
pub(crate) const UI_ERR_PUBLISH_FAILED: &str = "publish_failed";

/// Returns `Some(UI_ERR_*)` if the change could not be published (and the
/// local mutation was rolled back); `None` on success or for the silent
/// no-op cases (bad form, unknown id).
pub(crate) fn approve_app(body: &[u8], ctx: &WorkerContext) -> Option<&'static str> {
    let id_str = form_field(body, "id")?;
    let id = uuid_from_hex(id_str)?;
    let (was_approved, app_alias) = {
        let mut node    = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid)?;
        let app = device.applications.iter_mut().find(|a| a.id == id)?;
        let was_approved = app.user_approved;
        app.user_approved = true;
        (was_approved, app.alias.clone())
    };
    ctx.save_node();

    let device_uuid = ctx.node.read().unwrap().device_uuid;
    if let Err(e) = request_change(Change::AddApplication {
        device_uuid,
        app_id: id,
        app_alias,
    }, ctx) {
        // Roll back the approval — but only if we actually flipped it.
        // Re-approving an already-approved app is a no-op on Err.
        if !was_approved {
            let mut node = ctx.node.write().unwrap();
            if let Some(device) = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == device_uuid)
            {
                if let Some(app) = device.applications.iter_mut().find(|a| a.id == id) {
                    app.user_approved = false;
                }
            }
            drop(node);
            ctx.save_node();
        }
        eprintln!("[approve_app] publish failed for app {}: {e:?}", uuid_hex(&id));
        return Some(UI_ERR_PUBLISH_FAILED);
    }
    None
}

/// Admin UI alias rename. Mirrors `app_update`'s alias path but driven from the
/// admin UI (no app token). App ids are globally unique UUIDs (7c.0), so we
/// look the app up across every own-user device — any own-user SG can publish
/// a rename of any own-user app per the v2 reconciliation design. Same
/// pre-mutate + sync v1 publish + rollback-on-Err shape as `approve_app` /
/// `reject_app`.
pub(crate) fn rename_app(body: &[u8], ctx: &WorkerContext) -> Option<&'static str> {
    let id_str    = form_field(body, "id")?;
    let id        = uuid_from_hex(id_str)?;
    let new_alias = form_field(body, "alias").map(url_decode)?;
    if new_alias.is_empty() { return None; }

    let (device_uuid, prior_alias) = {
        let mut node = ctx.node.write().unwrap();
        let mut found = None;
        for device in node.owner.user.devices.iter_mut() {
            if let Some(app) = device.applications.iter_mut().find(|a| a.id == id) {
                if app.alias == new_alias { return None; }   // no-op
                let prior = std::mem::replace(&mut app.alias, new_alias.clone());
                found = Some((device.uuid, prior));
                break;
            }
        }
        found?
    };
    ctx.save_node();

    if let Err(e) = request_change(Change::UpdateApplicationAlias {
        device_uuid,
        app_id: id,
        new_alias,
    }, ctx) {
        {
            let mut node = ctx.node.write().unwrap();
            if let Some(dev) = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == device_uuid)
            {
                if let Some(app) = dev.applications.iter_mut().find(|a| a.id == id) {
                    app.alias = prior_alias;
                }
            }
        }
        ctx.save_node();
        eprintln!("[rename_app] publish failed for app {}: {e:?}", uuid_hex(&id));
        return Some(UI_ERR_PUBLISH_FAILED);
    }
    None
}

pub(crate) fn reject_app(body: &[u8], ctx: &WorkerContext) -> Option<&'static str> {
    let id_str = form_field(body, "id")?;
    let id = uuid_from_hex(id_str)?;
    let (device_uuid, removed) = {
        let mut node    = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid)?;
        let removed = device.applications.iter().position(|a| a.id == id)
            .map(|pos| device.applications.remove(pos));
        (device_uuid, removed)
    };
    let removed = removed?;       // unknown id → silent no-op
    ctx.save_node();

    if let Err(e) = request_change(Change::RemoveApplication {
        device_uuid,
        app_id: id,
    }, ctx) {
        // Roll back the removal — re-insert the cloned application.
        {
            let mut node = ctx.node.write().unwrap();
            if let Some(device) = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == device_uuid)
            {
                device.applications.push(removed);
            }
        }
        ctx.save_node();
        eprintln!("[reject_app] publish failed for app {}: {e:?}", uuid_hex(&id));
        return Some(UI_ERR_PUBLISH_FAILED);
    }
    None
}

fn render_invitations(
    ctx: &WorkerContext,
    query: &str,
    flash: Option<super::super::admin_auth::UiFlash>,
) -> String {
    use super::super::admin_auth::UiFlash;

    let node = ctx.node.read().unwrap();

    // Codes come from a one-shot session flash (POST → 302 → GET), never from
    // a long-lived query string (history, logs, Referer leakage).
    let error_param = query
        .split('&')
        .find_map(|p| p.strip_prefix("error="))
        .unwrap_or("");

    let error_section = match error_param {
        "no_host" => "<div class='card' style='background:#fee;color:#900;border:1px solid #c66'>\
            <strong>Could not generate invitation:</strong> no reachable host is configured \
            for this device. Set the <code>PNET_HOSTS</code> environment variable before \
            starting the node, then restart. See the server log for details.\
            </div>".to_string(),
        _ => String::new(),
    };

    let (code_section, contact_code_section) = match flash {
        Some(UiFlash::DeviceCode(code)) => (
            format!(
                "<div class='card'>\
                   <div class='label'>Share this code with the new device (expires in 24 h). \
                   It is shown once — copy it now.</div>\
                   <pre style='word-break:break-all;background:#f0f0f0;padding:.75rem;\
                               border-radius:4px;font-size:.85rem;margin:.5rem 0 0'>{}</pre>\
                 </div>",
                html_escape(&code)
            ),
            String::new(),
        ),
        Some(UiFlash::ContactCode(code)) => (
            String::new(),
            format!(
                "<div class='card'>\
                   <div class='label'>Share this code with your new contact (expires in 24 h). \
                   It is shown once — copy it now.</div>\
                   <pre style='word-break:break-all;background:#f0f0f0;padding:.75rem;\
                               border-radius:4px;font-size:.85rem;margin:.5rem 0 0'>{}</pre>\
                 </div>",
                html_escape(&code)
            ),
        ),
        None => (String::new(), String::new()),
    };

    let dev_inv_rows: String = node.owner.device_invitations.iter()
        .map(|inv| {
            let id_hex: String = inv.id.iter().map(|b| format!("{b:02x}")).collect();
            format!("<tr><td style='font-family:monospace'>{}</td></tr>", &id_hex[..16])
        })
        .collect();

    let dev_inv_table = if dev_inv_rows.is_empty() {
        "<p class='empty'>No pending device invitations.</p>".to_string()
    } else {
        format!("<table><tr><th>Invitation ID (first 8 bytes)</th></tr>{dev_inv_rows}</table>")
    };

    let contact_inv_rows: String = node.owner.contact_invitations.iter()
        .map(|inv| {
            let id_hex: String = inv.id.iter().map(|b| format!("{b:02x}")).collect();
            format!("<tr><td style='font-family:monospace'>{}</td></tr>", &id_hex[..16])
        })
        .collect();

    let contact_inv_table = if contact_inv_rows.is_empty() {
        "<p class='empty'>No pending contact invitations.</p>".to_string()
    } else {
        format!("<table><tr><th>Invitation ID (first 8 bytes)</th></tr>{contact_inv_rows}</table>")
    };

    drop(node);

    let body = format!(
        "<h1>Invitations</h1>\
         {error_section}\
         {code_section}\
         {contact_code_section}\
         <div class='card'>\
           <h2 style='margin-top:0;font-size:1rem'>Add a Device</h2>\
           <p style='color:#666;font-size:.9rem;margin-top:0'>Generate a one-time code, then enter it on the new device.</p>\
           {dev_inv_table}\
           <form method='post' action='/invitations/device' style='margin-top:1rem'>\
             <button type='submit'>Generate Device Invitation</button>\
           </form>\
         </div>\
         <div class='card'>\
           <h2 style='margin-top:0;font-size:1rem'>Add a Contact</h2>\
           <p style='color:#666;font-size:.9rem;margin-top:0'>Generate a one-time code and share it with the person you want to add.</p>\
           {contact_inv_table}\
           <form method='post' action='/invitations/contact' style='margin-top:1rem'>\
             <button type='submit'>Generate Contact Invitation</button>\
           </form>\
         </div>\
         <div class='card'>\
           <h2 style='margin-top:0;font-size:1rem'>Enter Invitation Code</h2>\
           <p style='color:#666;font-size:.9rem;margin-top:0'>On this new device, paste a code generated on another device.</p>\
           <form method='post' action='/invitations/enter'>\
             <textarea name='code' rows='3' \
               style='width:100%;font-family:monospace;font-size:.85rem;\
                      box-sizing:border-box;padding:.4rem;border:1px solid #ccc;border-radius:4px' \
               placeholder='Paste invitation code here...'></textarea><br>\
             <button type='submit' style='margin-top:.5rem'>Connect to Network</button>\
           </form>\
         </div>"
    );
    layout(ctx, "Invitations", &body)
}

// ── Setup wizard ─────────────────────────────────────────────────────────────

/// Apply first-run setup from the new-user form.
/// On success returns a new session id (password stored, user logged in).
pub(crate) fn complete_setup(body: &[u8], ctx: &WorkerContext) -> Result<String, &'static str> {
    use super::super::admin_auth::validate_new_password;

    let alias        = form_field(body, "alias").map(url_decode).unwrap_or_default();
    let device_alias = form_field(body, "device_alias").map(url_decode).unwrap_or_default();
    let grade_str    = form_field(body, "grade").unwrap_or("sg");
    let password     = form_field(body, "password").map(url_decode).unwrap_or_default();
    let confirm      = form_field(body, "password_confirm").map(url_decode).unwrap_or_default();

    validate_new_password(&password, &confirm)?;

    let grade = if grade_str == "sg" { DeviceGrade::SG } else { DeviceGrade::DG };
    let sg_rank = if matches!(grade, DeviceGrade::SG) {
        Some(form_field(body, "sg_rank")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1)
            .max(1))
    } else {
        None
    };

    if let Some(err) = apply_new_user_setup(alias.trim(), device_alias.trim(), grade, sg_rank, ctx) {
        return Err(err);
    }
    Ok(store_password_and_session(ctx, &password))
}

/// First-run join path: set admin password, then kick off bootstrap.
/// Returns a session so the waiting page (and dashboard after init) stay authed.
pub(crate) fn complete_join_setup(body: &[u8], ctx: &WorkerContext) -> Result<String, &'static str> {
    use super::super::admin_auth::validate_new_password;

    let password = form_field(body, "password").map(url_decode).unwrap_or_default();
    let confirm  = form_field(body, "password_confirm").map(url_decode).unwrap_or_default();
    validate_new_password(&password, &confirm)?;

    // Stash password before bootstrap so a completed join is never passwordless.
    let session = store_password_and_session(ctx, &password);
    initiate_bootstrap(body, ctx);
    Ok(session)
}

/// Typed entry point for first-run new-user setup. Used by both the HTTP form
/// handler and `main`'s env-driven startup path.
pub fn apply_new_user_setup(
    alias: &str,
    device_alias: &str,
    grade: DeviceGrade,
    sg_rank: Option<u32>,
    ctx: &WorkerContext,
) -> Option<&'static str> {
    if alias.is_empty() || device_alias.is_empty() {
        return Some("fields");
    }

    let key_pair = generate_ed25519_keypair();

    {
        let mut node = ctx.node.write().unwrap();
        node.owner.user.alias = alias.to_string();
        node.owner.key_pair   = key_pair;

        let device_uuid = node.device_uuid;
        if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) {
            dev.alias   = device_alias.to_string();
            dev.grade   = grade;
            dev.sg_rank = sg_rank;
            // Apply PNET_HOSTS here too: main's startup application is skipped
            // on a fresh container (node not yet initialized).
            if matches!(dev.grade, DeviceGrade::SG) {
                let hosts = parse_pnet_hosts();
                if !hosts.is_empty() {
                    dev.hosts = hosts;
                }
            }
        }
    }
    ctx.save_node();
    None
}

fn render_setup(query: &str) -> String {
    let grade   = query_param(query, "grade").unwrap_or("");
    let role    = query_param(query, "role").unwrap_or("");
    let waiting = query_param(query, "waiting").is_some();
    let error   = query_param(query, "error").unwrap_or("");

    let body: String = if waiting {
        // While waiting, allow refresh; once initialized the gate sends to dashboard/login.
        "<meta http-equiv=\"refresh\" content=\"3; url=/setup\">\
         <h1>Connecting\u{2026}</h1>\
         <p class=\"swiz-sub\">Waiting for a response from the server.<br>\
         This page will refresh automatically.</p>\
         <p style=\"color:#888;font-size:.8rem\">Make sure the invitation code was valid \
         and that the server is reachable.</p>"
            .to_string()
    } else {
        match (grade, role) {
            ("", _) => render_setup_grade_step(),
            ("sg", "") => render_setup_role_step(),
            ("sg", "new") => render_setup_new_user_form(error),
            ("sg", "join") | ("dg", _) => render_setup_code_entry(grade, error),
            _ => render_setup_grade_step(),
        }
    };
    setup_layout(&body)
}

fn render_setup_grade_step() -> String {
    "<h1>Welcome to pNet</h1>\
     <p class=\"swiz-sub\">Let\u{2019}s get your node configured. \
     First, what type of device is this?</p>\
     <a class=\"choice-btn\" href=\"/setup?grade=sg\">\
       <span class=\"choice-title\">Server Grade (SG)</span>\
       <span class=\"choice-desc\">A server with a static IP or domain. \
       Acts as a relay for your other devices.</span>\
     </a>\
     <a class=\"choice-btn\" href=\"/setup?grade=dg\">\
       <span class=\"choice-title\">Device Grade (DG)</span>\
       <span class=\"choice-desc\">A laptop, phone, or any device behind a home router. \
       Requires a server to relay connections.</span>\
     </a>"
        .to_string()
}

fn render_setup_role_step() -> String {
    "<h1>Server Grade Setup</h1>\
     <p class=\"swiz-sub\">Is this the first device for a new user, \
     or are you adding it to an existing account?</p>\
     <a class=\"choice-btn\" href=\"/setup?grade=sg&role=new\">\
       <span class=\"choice-title\">New User</span>\
       <span class=\"choice-desc\">Create a new pNet identity on this server.</span>\
     </a>\
     <a class=\"choice-btn\" href=\"/setup?grade=sg&role=join\">\
       <span class=\"choice-title\">Join Existing</span>\
       <span class=\"choice-desc\">Add this server to an existing user\u{2019}s pNet \
       using an invitation code.</span>\
     </a>\
     <a class=\"swiz-back\" href=\"/setup\">\u{2190} Back</a>"
        .to_string()
}

fn render_setup_new_user_form(error: &str) -> String {
    let error_msg = match error {
        "fields" => "<p style=\"color:#c0392b;font-size:.85rem;margin-bottom:1rem\">\
                     Name and device name are required.</p>",
        "password_short" => "<p style=\"color:#c0392b;font-size:.85rem;margin-bottom:1rem\">\
                     Admin password must be at least 8 characters.</p>",
        "password_mismatch" => "<p style=\"color:#c0392b;font-size:.85rem;margin-bottom:1rem\">\
                     Passwords do not match.</p>",
        _ => "",
    };
    format!(
        "<h1>Create Your Identity</h1>\
         <p class=\"swiz-sub\">Set your name and give this server a label. \
         Reachable addresses are configured at startup via the <code>PNET_HOSTS</code> environment variable.</p>\
         {error_msg}\
         <form method=\"post\" action=\"/setup/create\" style=\"display:block\">\
           <input type=\"hidden\" name=\"grade\" value=\"sg\">\
           <label class=\"swiz-label\">Your name or alias</label>\
           <input class=\"swiz-input\" type=\"text\" name=\"alias\" \
                  placeholder=\"e.g. Alice\" required autocomplete=\"off\">\
           <label class=\"swiz-label\">Device name</label>\
           <input class=\"swiz-input\" type=\"text\" name=\"device_alias\" \
                  placeholder=\"e.g. Home Server\" required autocomplete=\"off\">\
           <label class=\"swiz-label\">SG rank (1 = highest priority relay)</label>\
           <input class=\"swiz-input\" type=\"number\" name=\"sg_rank\" \
                  value=\"1\" min=\"1\" max=\"255\" autocomplete=\"off\">\
           <label class=\"swiz-label\">Admin password</label>\
           <input class=\"swiz-input\" type=\"password\" name=\"password\" \
                  required minlength=\"8\" autocomplete=\"new-password\">\
           <label class=\"swiz-label\">Confirm admin password</label>\
           <input class=\"swiz-input\" type=\"password\" name=\"password_confirm\" \
                  required minlength=\"8\" autocomplete=\"new-password\">\
           <button class=\"swiz-btn\" type=\"submit\">Create Identity</button>\
         </form>\
         <a class=\"swiz-back\" href=\"/setup?grade=sg\">\u{2190} Back</a>"
    )
}

fn render_setup_code_entry(grade: &str, error: &str) -> String {
    let back = if grade == "sg" { "/setup?grade=sg" } else { "/setup" };
    let form_grade = if grade == "sg" { "sg" } else { "dg" };
    let error_msg = match error {
        "password_short" => "<p style=\"color:#c0392b;font-size:.85rem;margin-bottom:1rem\">\
                     Admin password must be at least 8 characters.</p>",
        "password_mismatch" => "<p style=\"color:#c0392b;font-size:.85rem;margin-bottom:1rem\">\
                     Passwords do not match.</p>",
        _ => "",
    };
    format!(
        "<h1>Enter Invitation Code</h1>\
         <p class=\"swiz-sub\">Paste the invitation code generated on your existing device. \
         Also set an admin password for this device\u{2019}s web UI.</p>\
         {error_msg}\
         <form method=\"post\" action=\"/setup/join\" style=\"display:block\">\
           <input type=\"hidden\" name=\"grade\" value=\"{form_grade}\">\
           <label class=\"swiz-label\">Device name</label>\
           <input class=\"swiz-input\" name=\"device_alias\" type=\"text\" \
             placeholder=\"e.g. My Laptop\" required autocomplete=\"off\">\
           <label class=\"swiz-label\">Invitation code</label>\
           <textarea name=\"code\" rows=\"4\" class=\"swiz-input\" \
             style=\"font-family:monospace;font-size:.8rem;resize:vertical\" \
             placeholder=\"Paste code here\u{2026}\" required></textarea>\
           <label class=\"swiz-label\">Admin password</label>\
           <input class=\"swiz-input\" type=\"password\" name=\"password\" \
                  required minlength=\"8\" autocomplete=\"new-password\">\
           <label class=\"swiz-label\">Confirm admin password</label>\
           <input class=\"swiz-input\" type=\"password\" name=\"password_confirm\" \
                  required minlength=\"8\" autocomplete=\"new-password\">\
           <button class=\"swiz-btn\" type=\"submit\">Connect</button>\
         </form>\
         <a class=\"swiz-back\" href=\"{back}\">\u{2190} Back</a>"
    )
}

fn render_login(error: &str) -> String {
    let error_msg = if error == "bad" {
        "<p style=\"color:#c0392b;font-size:.85rem;margin-bottom:1rem\">\
         Incorrect password.</p>"
    } else {
        ""
    };
    setup_layout(&format!(
        "<h1>Admin login</h1>\
         <p class=\"swiz-sub\">Enter the admin password for this pNet node.</p>\
         {error_msg}\
         <form method=\"post\" action=\"/login\" style=\"display:block\">\
           <label class=\"swiz-label\">Password</label>\
           <input class=\"swiz-input\" type=\"password\" name=\"password\" \
                  required autocomplete=\"current-password\">\
           <button class=\"swiz-btn\" type=\"submit\">Log in</button>\
         </form>"
    ))
}

fn render_set_password(error: &str) -> String {
    let error_msg = match error {
        "password_short" => "<p style=\"color:#c0392b;font-size:.85rem;margin-bottom:1rem\">\
                     Password must be at least 8 characters.</p>",
        "password_mismatch" => "<p style=\"color:#c0392b;font-size:.85rem;margin-bottom:1rem\">\
                     Passwords do not match.</p>",
        "exists" => "<p style=\"color:#c0392b;font-size:.85rem;margin-bottom:1rem\">\
                     A password is already set. Log in instead.</p>",
        _ => "",
    };
    setup_layout(&format!(
        "<h1>Set admin password</h1>\
         <p class=\"swiz-sub\">This node has no admin password yet. \
         Choose one to protect the control UI.</p>\
         {error_msg}\
         <form method=\"post\" action=\"/set-password\" style=\"display:block\">\
           <label class=\"swiz-label\">Admin password</label>\
           <input class=\"swiz-input\" type=\"password\" name=\"password\" \
                  required minlength=\"8\" autocomplete=\"new-password\">\
           <label class=\"swiz-label\">Confirm password</label>\
           <input class=\"swiz-input\" type=\"password\" name=\"password_confirm\" \
                  required minlength=\"8\" autocomplete=\"new-password\">\
           <button class=\"swiz-btn\" type=\"submit\">Save password</button>\
         </form>"
    ))
}

// ── HTML layout ───────────────────────────────────────────────────────────────

const CSS: &str = "
body { font-family: sans-serif; margin: 0; background: #f5f5f5; color: #222; }
nav { background: #1a1a2e; padding: .75rem 1.5rem; display: flex; align-items: center; gap: 1.5rem; }
nav a { color: #aac; text-decoration: none; font-size: .9rem; }
nav a:hover { color: #fff; }
.brand { color: #fff; font-weight: bold; font-size: 1.1rem; margin-right: 1rem; }
main { padding: 1.5rem 2rem; max-width: 900px; }
h1 { margin-top: 0; font-size: 1.4rem; }
table { border-collapse: collapse; width: 100%; background: white; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
th { background: #eee; text-align: left; padding: .6rem 1rem; font-size: .85rem; color: #555; }
td { padding: .6rem 1rem; border-top: 1px solid #eee; font-size: .9rem; }
.card { background: white; border-radius: 6px; padding: 1.2rem 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); margin-bottom: 1rem; }
.stats { display: flex; gap: 1rem; margin-bottom: 1.5rem; }
.stat-card { background: white; border-radius: 6px; padding: 1rem 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); flex: 1; }
.stat { font-size: 2rem; font-weight: bold; color: #1a1a2e; }
.label { font-size: .8rem; color: #888; }
button { padding: .3rem .8rem; border: none; border-radius: 4px; cursor: pointer; font-size: .85rem; }
.approve { background: #2d7a3b; color: white; }
.reject { background: #c0392b; color: white; margin-left: .4rem; }
form { display: inline; }
.empty { color: #888; font-style: italic; }
";

fn layout(ctx: &WorkerContext, title: &str, body: &str) -> String {
    let banner = partition_banner(ctx);
    let mut html = String::with_capacity(4096);
    html.push_str("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>pNet \u{2014} ");
    html.push_str(title);
    html.push_str("</title>\n<style>");
    html.push_str(CSS);
    html.push_str("</style>\n</head>\n<body>\n");
    html.push_str("<nav>\n");
    html.push_str("  <span class=\"brand\">pNet</span>\n");
    html.push_str("  <a href=\"/dashboard\">Dashboard</a>\n");
    html.push_str("  <a href=\"/pending-apps\">Pending Apps</a>\n");
    html.push_str("  <a href=\"/applications\">Applications</a>\n");
    html.push_str("  <a href=\"/contacts\">Contacts</a>\n");
    html.push_str("  <a href=\"/devices\">Devices</a>\n");
    html.push_str("  <a href=\"/invitations\">Invitations</a>\n");
    html.push_str("  <a href=\"/diagnostics\">Diagnostics</a>\n");
    html.push_str("  <form method=\"post\" action=\"/logout\" style=\"margin-left:auto;display:inline\">\
                   <button type=\"submit\" style=\"background:transparent;color:#aac;border:1px solid #556;\
                   padding:.25rem .6rem;cursor:pointer;font-size:.85rem\">Log out</button></form>\n");
    html.push_str("</nav>\n<main>\n");
    html.push_str(&banner);
    html.push_str(body);
    html.push_str("\n</main>\n</body>\n</html>");
    html
}

/// Yellow banner shown on every admin page whenever any own-user SG peer is
/// currently marked down by poll_sg. Surfaces partition state so a user
/// looking at any tab knows convergence may be paused. Empty string when all
/// own-user SG peers (if any) are reachable.
pub(crate) fn partition_banner(ctx: &WorkerContext) -> String {
    let node = ctx.node.read().unwrap();
    let local_uuid = node.device_uuid;

    let own_sg_uuids: Vec<(Uuid, &str)> = node.owner.user.devices.iter()
        .filter(|d| matches!(d.grade, DeviceGrade::SG) && d.uuid != local_uuid)
        .map(|d| (d.uuid, d.alias.as_str()))
        .collect();
    if own_sg_uuids.is_empty() { return String::new(); }

    // A device is "down" iff *every* polled (uuid, host) entry for it is
    // down. An unpolled device contributes no entries — treat as up so we
    // don't falsely flag a freshly added peer before poll_sg's first round.
    let mut down: Vec<&str> = Vec::new();
    for (uuid, alias) in &own_sg_uuids {
        let polled: Vec<bool> = node.sg_statuses.iter()
            .filter(|((u, _), _)| u == uuid)
            .map(|(_, s)| s.up)
            .collect();
        if !polled.is_empty() && polled.iter().all(|up| !*up) {
            down.push(alias);
        }
    }
    if down.is_empty() { return String::new(); }

    let aliases = down.iter().map(|a| html_escape(a)).collect::<Vec<_>>().join(", ");
    format!(
        "<div class='card' style='background:#fff4d6;color:#7a5a00;border:1px solid #e0c060'>\
            <strong>Partition detected:</strong> own-user SG peer(s) currently unreachable: {aliases}. \
            Sync v2 will reconcile automatically when the peer comes back. \
            See <a href='/diagnostics'>Diagnostics</a> for watermarks and pending proposals.\
        </div>"
    )
}

const SETUP_CSS: &str = "
.swiz-wrap { max-width: 460px; margin: 5rem auto; padding: 0 1.5rem; }
.swiz-brand { color: #1a1a2e; font-weight: bold; font-size: 1.3rem; margin-bottom: 2.5rem; }
.swiz-wrap h1 { font-size: 1.5rem; margin: 0 0 .4rem; }
.swiz-sub { color: #666; font-size: .9rem; margin: 0 0 1.5rem; line-height: 1.5; }
.choice-btn { display: block; background: white; border: 1px solid #ddd; border-radius: 8px;
              padding: 1rem 1.2rem; margin-bottom: .75rem; text-decoration: none; color: #222;
              box-shadow: 0 1px 3px rgba(0,0,0,.07); transition: border-color .15s; }
.choice-btn:hover { border-color: #1a1a2e; }
.choice-title { display: block; font-weight: bold; font-size: .95rem; }
.choice-desc { display: block; font-size: .8rem; color: #666; margin-top: .25rem; line-height: 1.4; }
.swiz-label { display: block; font-size: .85rem; color: #555; margin-bottom: .3rem; }
.swiz-input { display: block; width: 100%; box-sizing: border-box; padding: .55rem .7rem;
              border: 1px solid #ccc; border-radius: 5px; font-size: .95rem; margin-bottom: 1rem; }
.swiz-btn { background: #1a1a2e; color: white; border: none; border-radius: 5px;
            padding: .55rem 1.4rem; font-size: .95rem; cursor: pointer; }
.swiz-btn:hover { background: #2a2a4e; }
.swiz-back { display: inline-block; margin-top: 1.25rem; font-size: .8rem; color: #888;
             text-decoration: none; }
.swiz-back:hover { color: #444; }
";

fn setup_layout(body: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <title>pNet \u{2014} Setup</title>\n\
         <style>{SETUP_CSS}</style>\n\
         </head>\n<body>\n\
         <div class=\"swiz-wrap\">\
           <div class=\"swiz-brand\">pNet</div>\
           {body}\
         </div>\n</body>\n</html>"
    )
}

