use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use super::action_queue::WorkerContext;
use super::data_models::{Application, DeviceGrade, SgStatus, Uuid, generate_uuid};

// ── Reply status bytes ────────────────────────────────────────────────────────
const OK:                u8 = 0x00;
const ERR_BAD_PACKET:    u8 = 0x01;
const ERR_TOKEN_UNKNOWN: u8 = 0x02;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn send(ctx: &WorkerContext, dest: SocketAddr, data: &[u8]) {
    ctx.udp_socket.send_to(data, dest).ok();
}

fn send_error(ctx: &WorkerContext, dest: SocketAddr, code: u8) {
    send(ctx, dest, &[0x01, code]);
}

/// Extract an IPv4 address from a SocketAddr, mapping IPv4-in-IPv6 if needed.
fn ipv4_from(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped(),
    }
}

// ── App handlers ──────────────────────────────────────────────────────────────

/// Op 0 — Application registration.
///
/// Request body (after op byte):
///   [alias_len: u8][alias: alias_len bytes][port: u16 be]
///   [protocol_len: u8][protocol: protocol_len bytes]
///
/// Reply on success:  [0x00][token: 16 bytes]
/// Reply on error:    [0x01][error_code: u8]
pub fn app_register(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    // Parse.
    if buf.is_empty() {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let alias_len = buf[0] as usize;
    if buf.len() < 1 + alias_len + 2 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let alias = match std::str::from_utf8(&buf[1..1 + alias_len]) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => return send_error(ctx, src, ERR_BAD_PACKET),
    };
    let port = u16::from_be_bytes([buf[1 + alias_len], buf[2 + alias_len]]);
    if port == 0 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let mut pos = 3 + alias_len;
    if pos >= buf.len() {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let protocol_len = buf[pos] as usize;
    pos += 1;
    if buf.len() < pos + protocol_len {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let protocol = match std::str::from_utf8(&buf[pos..pos + protocol_len]) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => return send_error(ctx, src, ERR_BAD_PACKET),
    };
    let ip = match ipv4_from(src) {
        Some(ip) => ip,
        None => return send_error(ctx, src, ERR_BAD_PACKET),
    };

    // Update node.
    let token = {
        let mut node = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;

        let device = node
            .owner
            .user
            .devices
            .iter_mut()
            .find(|d| d.uuid == device_uuid)
            .expect("local device not found in node");

        let next_id = device
            .applications
            .iter()
            .map(|a| a.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let token = generate_uuid();
        device.applications.push(Application {
            id: next_id,
            alias,
            protocol,
            host: SocketAddrV4::new(ip, port),
            user_approved: false,
            token,
        });
        token
        // write lock released here
    };

    // TODO: persist — ctx.writer_tx.send(WriteRequest::AppData(serialize_apps(&node))).ok();

    // Reply: [OK][token: 16 bytes]
    let mut reply = [0u8; 17];
    reply[0] = OK;
    reply[1..17].copy_from_slice(&token);
    send(ctx, src, &reply);
}

/// Op 1 — Application update.
///
/// Request body (after op byte):
///   [token: 16 bytes][flags: u8]
///   if flags & 0x01: [alias_len: u8][alias: alias_len bytes]
///   if flags & 0x02: [port: u16 be]  (IP is taken from src)
///
/// Reply on success:  [0x00]
/// Reply on error:    [0x01][error_code: u8]
pub fn app_update(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    // Parse header.
    if buf.len() < 17 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let token: [u8; 16] = buf[0..16].try_into().unwrap();
    let flags = buf[16];
    let mut pos = 17usize;

    let mut new_alias: Option<String> = None;
    let mut new_port:  Option<u16>   = None;

    if flags & 0x01 != 0 {
        if pos >= buf.len() {
            return send_error(ctx, src, ERR_BAD_PACKET);
        }
        let alias_len = buf[pos] as usize;
        pos += 1;
        if pos + alias_len > buf.len() {
            return send_error(ctx, src, ERR_BAD_PACKET);
        }
        match std::str::from_utf8(&buf[pos..pos + alias_len]) {
            Ok(s) if !s.is_empty() => new_alias = Some(s.to_string()),
            _ => return send_error(ctx, src, ERR_BAD_PACKET),
        }
        pos += alias_len;
    }

    if flags & 0x02 != 0 {
        if pos + 2 > buf.len() {
            return send_error(ctx, src, ERR_BAD_PACKET);
        }
        new_port = Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
    }

    // Update node.
    let found = {
        let mut node = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let device = node
            .owner
            .user
            .devices
            .iter_mut()
            .find(|d| d.uuid == device_uuid)
            .expect("local device not found in node");

        if let Some(app) = device.applications.iter_mut().find(|a| a.token == token) {
            if let Some(alias) = new_alias {
                app.alias = alias;
            }
            if let Some(port) = new_port {
                if let Some(ip) = ipv4_from(src) {
                    app.host = SocketAddrV4::new(ip, port);
                }
            }
            true
        } else {
            false
        }
        // write lock released here
    };

    // TODO: persist

    if found {
        send(ctx, src, &[OK]);
    } else {
        send_error(ctx, src, ERR_TOKEN_UNKNOWN);
    }
}

/// Op 2 — Application get data.
///
/// Request body (after op byte):
///   [token: 16 bytes]
///
/// Authenticates the app and returns its view of the node data tree.
/// Serialization format TBD — returns a stub OK for now.
pub fn app_get_data(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 16 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let token: [u8; 16] = buf[0..16].try_into().unwrap();

    let node = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device = node
        .owner
        .user
        .devices
        .iter()
        .find(|d| d.uuid == device_uuid)
        .expect("local device not found in node");

    let app_exists = device.applications.iter().any(|a| a.token == token);
    drop(node);

    if app_exists {
        // TODO: serialize and send the data tree
        send(ctx, src, &[OK]);
    } else {
        send_error(ctx, src, ERR_TOKEN_UNKNOWN);
    }
}

/// Op 3 — Application send packet.
///
/// Request body (after op byte):
///   [token: 16 bytes][target_device_uuid: 16 bytes][target_app_id: u16 be][payload: ...]
///
/// Looks up the active connection for the target device, encrypts the payload,
/// and forwards the packet to the peer pnet node.
/// Not yet implemented — requires ephemeral key exchange to be established first.
pub fn app_send_packet(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let _ = (src, buf, ctx); // TODO
}

// ── Peer pNet node handlers ───────────────────────────────────────────────────

const SG_PING_OP: u8 = 0x10;
const SG_PONG_OP: u8 = 0x11;

/// Respond to an SG ping from another node with the nonce echoed back.
pub fn sg_ping(src: SocketAddr, nonce: [u8; 16], ctx: &WorkerContext) {
    let mut reply = [0u8; 17];
    reply[0] = SG_PONG_OP;
    reply[1..17].copy_from_slice(&nonce);
    send(ctx, src, &reply);
}

// ── Scheduled action handlers ─────────────────────────────────────────────────

const SG_PING_TIMEOUT: Duration = Duration::from_secs(1);

/// Ping every candidate SG, record RTT, and mark each one up or down.
///
/// Candidate pool: all SG-grade devices owned by the local user (excluding the
/// local device itself) plus all SG-grade devices of every contact user.
pub fn poll_sg(ctx: &WorkerContext) {
    // Collect (device_uuid, host) for every candidate SG.
    let candidates: Vec<(Uuid, SocketAddrV4)> = {
        let node = ctx.node.read().unwrap();
        let local_uuid = node.device_uuid;
        let mut v: Vec<(Uuid, SocketAddrV4)> = Vec::new();
        for d in &node.owner.user.devices {
            if matches!(d.grade, DeviceGrade::SG) && d.uuid != local_uuid {
                v.push((d.uuid, d.host));
            }
        }
        for contact in &node.owner.contact_users {
            for d in &contact.user.devices {
                if matches!(d.grade, DeviceGrade::SG) {
                    v.push((d.uuid, d.host));
                }
            }
        }
        v
    };

    if candidates.is_empty() {
        return;
    }

    // Ephemeral socket so pong responses come back here, not to the main listener.
    let ping_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => { eprintln!("[poll_sg] bind failed: {e}"); return; }
    };
    ping_socket.set_read_timeout(Some(SG_PING_TIMEOUT)).ok();

    for (uuid, host) in candidates {
        let nonce = generate_uuid();
        let mut packet = [0u8; 17];
        packet[0] = SG_PING_OP;
        packet[1..17].copy_from_slice(&nonce);

        let start = Instant::now();
        if ping_socket.send_to(&packet, std::net::SocketAddr::V4(host)).is_err() {
            record_sg_status(ctx, uuid, None);
            continue;
        }

        let mut buf = [0u8; 32];
        let up = match ping_socket.recv_from(&mut buf) {
            Ok((len, _)) if len >= 17 && buf[0] == SG_PONG_OP && buf[1..17] == nonce => {
                Some(start.elapsed())
            }
            _ => None,
        };
        record_sg_status(ctx, uuid, up);
    }
}

fn record_sg_status(ctx: &WorkerContext, uuid: Uuid, rtt: Option<Duration>) {
    let mut node = ctx.node.write().unwrap();
    node.sg_statuses.insert(uuid, SgStatus {
        up:          rtt.is_some(),
        last_rtt:    rtt,
        last_polled: Instant::now(),
    });
}

/// Check for active connections whose ephemeral keys are expiring soon and
/// initiate a re-exchange.
pub fn key_rotation(ctx: &WorkerContext) {
    let _ = ctx; // TODO
}

/// Retry an unacknowledged outbound message.
pub fn retry_message(message_id: u64, ctx: &WorkerContext) {
    let _ = (message_id, ctx); // TODO
}

// ── UI / HTTP handlers ────────────────────────────────────────────────────────

pub fn ui_request(
    stream:  std::net::TcpStream,
    method:  String,
    path:    String,
    _query:  String,
    body:    Vec<u8>,
    ctx:     &WorkerContext,
) {
    match (method.as_str(), path.as_str()) {
        ("GET",  "/")                     => respond_redirect(&stream, "/dashboard"),
        ("GET",  "/dashboard")            => respond_html(&stream, 200, &render_dashboard(ctx)),
        ("GET",  "/pending-apps")         => respond_html(&stream, 200, &render_pending_apps(ctx)),
        ("POST", "/pending-apps/approve") => {
            approve_app(&body, ctx);
            respond_redirect(&stream, "/pending-apps");
        }
        ("POST", "/pending-apps/reject")  => {
            reject_app(&body, ctx);
            respond_redirect(&stream, "/pending-apps");
        }
        ("GET",  "/applications")         => respond_html(&stream, 200, &render_applications(ctx)),
        ("GET",  "/contacts")             => respond_html(&stream, 200, &render_contacts(ctx)),
        ("GET",  "/devices")              => respond_html(&stream, 200, &render_devices(ctx)),
        _ => respond_html(&stream, 404, &layout("Not Found", "<h1>404 — Not Found</h1>")),
    }
}

// ── Routing helpers ───────────────────────────────────────────────────────────

fn respond_html(stream: &std::net::TcpStream, status: u16, html: &str) {
    use std::io::Write;
    let status_text = match status { 200 => "OK", 404 => "Not Found", _ => "OK" };
    let body = html.as_bytes();
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let mut s = stream;
    let _ = s.write_all(header.as_bytes());
    let _ = s.write_all(body);
}

fn respond_redirect(stream: &std::net::TcpStream, location: &str) {
    use std::io::Write;
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let mut s = stream;
    let _ = s.write_all(response.as_bytes());
}

/// Extract a URL-encoded form field value from a POST body (e.g. `id=5`).
fn form_field<'a>(body: &'a [u8], field: &str) -> Option<&'a str> {
    let s = std::str::from_utf8(body).ok()?;
    let prefix = format!("{field}=");
    for part in s.split('&') {
        if let Some(val) = part.strip_prefix(prefix.as_str()) {
            return Some(val);
        }
    }
    None
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
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
         </div>"
    );
    layout("Dashboard", &body)
}

fn render_pending_apps(ctx: &WorkerContext) -> String {
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
                    a.id,
                    a.id,
                ))
                .collect()
        })
        .unwrap_or_default();

    let body = if rows.is_empty() {
        "<h1>Pending Apps</h1><p class='empty'>No pending applications.</p>".to_string()
    } else {
        format!(
            "<h1>Pending Apps</h1>\
             <table>\
               <tr><th>Alias</th><th>Protocol</th><th>Host</th><th>Actions</th></tr>\
               {rows}\
             </table>"
        )
    };
    layout("Pending Apps", &body)
}

fn render_applications(ctx: &WorkerContext) -> String {
    let node        = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device      = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid);

    let rows: String = device
        .map(|d| {
            d.applications.iter()
                .filter(|a| a.user_approved)
                .map(|a| format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(&a.alias),
                    html_escape(&a.protocol),
                    html_escape(&a.host.to_string()),
                ))
                .collect()
        })
        .unwrap_or_default();

    let body = if rows.is_empty() {
        "<h1>Applications</h1><p class='empty'>No approved applications.</p>".to_string()
    } else {
        format!(
            "<h1>Applications</h1>\
             <table>\
               <tr><th>Alias</th><th>Protocol</th><th>Host</th></tr>\
               {rows}\
             </table>"
        )
    };
    layout("Applications", &body)
}

fn render_contacts(ctx: &WorkerContext) -> String {
    let node     = ctx.node.read().unwrap();
    let contacts = &node.owner.contact_users;

    let rows: String = contacts.iter()
        .map(|c| format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            html_escape(&c.user.alias),
            c.user.devices.len(),
        ))
        .collect();

    let body = if rows.is_empty() {
        "<h1>Contacts</h1><p class='empty'>No contacts yet.</p>".to_string()
    } else {
        format!(
            "<h1>Contacts</h1>\
             <table>\
               <tr><th>Alias</th><th>Devices</th></tr>\
               {rows}\
             </table>"
        )
    };
    layout("Contacts", &body)
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
                html_escape(&d.host.to_string()),
                d.applications.len(),
            )
        })
        .collect();

    let body = if rows.is_empty() {
        "<h1>Devices</h1><p class='empty'>No devices.</p>".to_string()
    } else {
        format!(
            "<h1>Devices</h1>\
             <table>\
               <tr><th>Alias</th><th>Host</th><th>Apps</th></tr>\
               {rows}\
             </table>"
        )
    };
    layout("Devices", &body)
}

// ── App approval / rejection ──────────────────────────────────────────────────

fn approve_app(body: &[u8], ctx: &WorkerContext) {
    let Some(id_str) = form_field(body, "id") else { return };
    let Ok(id) = id_str.parse::<u16>() else { return };

    let mut node        = ctx.node.write().unwrap();
    let device_uuid     = node.device_uuid;
    let Some(device) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) else { return };
    if let Some(app) = device.applications.iter_mut().find(|a| a.id == id) {
        app.user_approved = true;
    }
}

fn reject_app(body: &[u8], ctx: &WorkerContext) {
    let Some(id_str) = form_field(body, "id") else { return };
    let Ok(id) = id_str.parse::<u16>() else { return };

    let mut node        = ctx.node.write().unwrap();
    let device_uuid     = node.device_uuid;
    let Some(device) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) else { return };
    device.applications.retain(|a| a.id != id);
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

fn layout(title: &str, body: &str) -> String {
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
    html.push_str("</nav>\n<main>\n");
    html.push_str(body);
    html.push_str("\n</main>\n</body>\n</html>");
    html
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::{Arc, RwLock, mpsc};
    use std::time::Duration;
    use super::super::action_queue::WorkerContext;
    use super::super::data_models::Node;
    use super::super::writer::WriteRequest;

    /// All the state needed to exercise a handler in isolation.
    struct TestCtx {
        ctx:        WorkerContext,
        app_socket: UdpSocket,   // receives the handler's reply
        _writer_rx: mpsc::Receiver<WriteRequest>,
        _sched_rx:  mpsc::Receiver<super::super::action_queue::ScheduleRequest>,
    }

    impl TestCtx {
        fn new() -> Self {
            // The "app" receives replies on this socket.
            let app_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            app_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();

            // pnet replies via this socket.
            let pnet_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());

            let node = Arc::new(RwLock::new(Node::new()));
            let (writer_tx, _writer_rx) = mpsc::sync_channel(64);
            let (scheduler_tx, _sched_rx) = mpsc::channel();

            let ctx = WorkerContext { node, udp_socket: pnet_socket, writer_tx, scheduler_tx };
            TestCtx { ctx, app_socket, _writer_rx, _sched_rx }
        }

        /// The SocketAddr the "app" is listening on (used as `src` in requests).
        fn app_addr(&self) -> SocketAddr {
            self.app_socket.local_addr().unwrap()
        }

        /// Block until a reply arrives at the app socket.
        fn recv_reply(&self) -> Vec<u8> {
            let mut buf = [0u8; 64];
            let (len, _) = self.app_socket.recv_from(&mut buf)
                .expect("no reply received within timeout");
            buf[..len].to_vec()
        }
    }

    // ── AppRegister ───────────────────────────────────────────────────────────

    fn register_packet(alias: &str, port: u16, protocol: &str) -> Vec<u8> {
        let mut buf = vec![alias.len() as u8];
        buf.extend_from_slice(alias.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
        buf.push(protocol.len() as u8);
        buf.extend_from_slice(protocol.as_bytes());
        buf
    }

    #[test]
    fn app_register_returns_token() {
        let t = TestCtx::new();
        app_register(t.app_addr(), register_packet("myapp", 9001, "udp"), &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);
        assert_eq!(reply.len(), 17, "reply should be status + 16-byte token");
    }

    #[test]
    fn app_register_adds_application_to_node() {
        let t = TestCtx::new();
        app_register(t.app_addr(), register_packet("myapp", 9001, "udp"), &t.ctx);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications.len(), 1);
        assert_eq!(device.applications[0].alias, "myapp");
        assert_eq!(device.applications[0].host.port(), 9001);
        assert!(!device.applications[0].user_approved);
    }

    #[test]
    fn app_register_each_app_gets_unique_id_and_token() {
        let t = TestCtx::new();
        app_register(t.app_addr(), register_packet("app1", 9001, "udp"), &t.ctx);
        let reply1 = t.recv_reply();
        app_register(t.app_addr(), register_packet("app2", 9002, "udp"), &t.ctx);
        let reply2 = t.recv_reply();

        let token1 = &reply1[1..17];
        let token2 = &reply2[1..17];
        assert_ne!(token1, token2, "tokens must be unique");

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications.len(), 2);
        assert_ne!(device.applications[0].id, device.applications[1].id);
    }

    #[test]
    fn app_register_rejects_bad_packet() {
        let t = TestCtx::new();
        app_register(t.app_addr(), vec![], &t.ctx); // empty buf

        let reply = t.recv_reply();
        assert_eq!(reply[0], 0x01); // error
        assert_eq!(reply[1], ERR_BAD_PACKET);
    }

    // ── AppUpdate ─────────────────────────────────────────────────────────────

    /// Register an app and return its token.
    fn register_and_get_token(t: &TestCtx, alias: &str, port: u16) -> [u8; 16] {
        app_register(t.app_addr(), register_packet(alias, port, "udp"), t.ctx());
        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);
        reply[1..17].try_into().unwrap()
    }

    fn update_packet(token: &[u8; 16], new_alias: Option<&str>, new_port: Option<u16>) -> Vec<u8> {
        let mut buf = token.to_vec();
        let mut flags: u8 = 0;
        let mut extra: Vec<u8> = Vec::new();

        if let Some(alias) = new_alias {
            flags |= 0x01;
            extra.push(alias.len() as u8);
            extra.extend_from_slice(alias.as_bytes());
        }
        if let Some(port) = new_port {
            flags |= 0x02;
            extra.extend_from_slice(&port.to_be_bytes());
        }

        buf.push(flags);
        buf.extend(extra);
        buf
    }

    impl TestCtx {
        fn ctx(&self) -> &WorkerContext { &self.ctx }
    }

    #[test]
    fn app_update_alias() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "original", 9001);

        app_update(t.app_addr(), update_packet(&token, Some("renamed"), None), &t.ctx);
        assert_eq!(t.recv_reply(), vec![OK]);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications[0].alias, "renamed");
    }

    #[test]
    fn app_update_port() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "myapp", 9001);

        app_update(t.app_addr(), update_packet(&token, None, Some(9999)), &t.ctx);
        assert_eq!(t.recv_reply(), vec![OK]);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications[0].host.port(), 9999);
    }

    #[test]
    fn app_update_unknown_token_returns_error() {
        let t = TestCtx::new();
        let bad_token = [0xFFu8; 16];
        app_update(t.app_addr(), update_packet(&bad_token, Some("x"), None), &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], 0x01);
        assert_eq!(reply[1], ERR_TOKEN_UNKNOWN);
    }

    // ── SgPing ────────────────────────────────────────────────────────────────

    #[test]
    fn sg_ping_replies_with_pong_and_echoed_nonce() {
        let t = TestCtx::new();
        let nonce: [u8; 16] = *b"test_nonce_12345";
        sg_ping(t.app_addr(), nonce, &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply.len(), 17);
        assert_eq!(reply[0], SG_PONG_OP);
        assert_eq!(reply[1..17], nonce);
    }

    // ── AppGetData ────────────────────────────────────────────────────────────

    #[test]
    fn app_get_data_valid_token_returns_ok() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "myapp", 9001);

        app_get_data(t.app_addr(), token.to_vec(), &t.ctx);
        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);
    }

    #[test]
    fn app_get_data_unknown_token_returns_error() {
        let t = TestCtx::new();
        app_get_data(t.app_addr(), vec![0xFFu8; 16], &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], 0x01);
        assert_eq!(reply[1], ERR_TOKEN_UNKNOWN);
    }
}
