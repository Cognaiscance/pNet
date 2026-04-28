//! Debug / inspection module.
//!
//! Always-on diagnostics surface. Renders the owner, device list, contacts,
//! active connections, and SG status; appends every received packet to an
//! in-memory inbox; provides a form for firing arbitrary text payloads at any
//! known device.
//!
//! Mounted at `/apps/debug` once the user enables it.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{HttpRequest, HttpResponse, Module, ModuleCtx, ModuleId, PacketSource, PacketTarget, SendError};
use super::super::data_models::{Node, Uuid};

const MODULE_ID:    ModuleId    = 1;
const MODULE_SLUG:  &str        = "debug";
const MODULE_ALIAS: &str        = "Debug";
const INBOX_CAP:    usize       = 100;

pub struct Debug {
    inbox: Mutex<VecDeque<Received>>,
}

struct Received {
    at:          SystemTime,
    from_user:   Uuid,
    from_device: Uuid,
    payload:     Vec<u8>,
}

impl Debug {
    pub fn new() -> Self {
        Self { inbox: Mutex::new(VecDeque::with_capacity(INBOX_CAP)) }
    }
}

impl Default for Debug {
    fn default() -> Self { Self::new() }
}

impl Module for Debug {
    fn id(&self)    -> ModuleId      { MODULE_ID }
    fn slug(&self)  -> &'static str  { MODULE_SLUG }
    fn alias(&self) -> &'static str  { MODULE_ALIAS }

    fn on_receive(&self, from: PacketSource, payload: &[u8], _ctx: &ModuleCtx) {
        let mut inbox = self.inbox.lock().unwrap();
        while inbox.len() >= INBOX_CAP { inbox.pop_front(); }
        inbox.push_back(Received {
            at:          SystemTime::now(),
            from_user:   from.user,
            from_device: from.device,
            payload:     payload.to_vec(),
        });
    }

    fn on_http(&self, req: &HttpRequest, ctx: &ModuleCtx) -> Option<HttpResponse> {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET",  "/")     => Some(self.render_index(ctx, "")),
            ("POST", "/send") => Some(self.handle_send(req, ctx)),
            _ => None,
        }
    }
}

impl Debug {
    fn render_index(&self, ctx: &ModuleCtx, banner: &str) -> HttpResponse {
        let snapshot = ctx.read(build_snapshot);
        let inbox_html: String = {
            let inbox = self.inbox.lock().unwrap();
            if inbox.is_empty() {
                "<p style=\"color:#999\">empty</p>".to_string()
            } else {
                let rows: String = inbox.iter().rev().map(render_inbox_row).collect();
                format!(
                    "<table><tr><th>When (epoch)</th><th>From</th><th>Payload</th></tr>{rows}</table>"
                )
            }
        };
        let n_inbox = self.inbox.lock().unwrap().len();

        let banner_html = if banner.is_empty() {
            String::new()
        } else {
            format!("<div class=\"banner\">{}</div>", html_escape(banner))
        };

        let body = format!(
            "<!DOCTYPE html><html><head><title>Debug</title><meta charset=\"utf-8\"><style>{CSS}</style></head><body>\
             <h1>Debug</h1>\
             <p style=\"color:#666;font-size:.85rem\"><a href=\"/dashboard\">← back to pnet</a></p>\
             {banner_html}\
             <h2>Owner</h2><pre>{owner}</pre>\
             <h2>This device</h2><pre>{this}</pre>\
             <h2>Own devices ({n_own})</h2><pre>{own_devices}</pre>\
             <h2>Contacts ({n_contacts})</h2><pre>{contacts}</pre>\
             <h2>Active connections ({n_conns})</h2><pre>{conns}</pre>\
             <h2>SG statuses ({n_sg})</h2><pre>{sg}</pre>\
             <h2>Send a packet</h2>{send_form}\
             <h2>Inbox ({n_inbox})</h2>{inbox_html}\
             </body></html>",
            owner       = snapshot.owner,
            this        = snapshot.this,
            own_devices = snapshot.own_devices,
            contacts    = snapshot.contacts,
            conns       = snapshot.conns,
            sg          = snapshot.sg,
            n_own       = snapshot.n_own_devices,
            n_contacts  = snapshot.n_contacts,
            n_conns     = snapshot.n_conns,
            n_sg        = snapshot.n_sg,
            send_form   = render_send_form(&snapshot),
        );

        HttpResponse {
            status:       200,
            content_type: "text/html; charset=utf-8",
            body:         body.into_bytes(),
        }
    }

    fn handle_send(&self, req: &HttpRequest, ctx: &ModuleCtx) -> HttpResponse {
        let device_hex  = form_field(&req.body, "device").map(url_decode).unwrap_or_default();
        let payload_str = form_field(&req.body, "payload").map(url_decode).unwrap_or_default();

        let banner = match parse_hex_uuid(&device_hex) {
            None => format!("Bad device id: {device_hex}"),
            Some(target_device) => {
                let target_user = ctx.read(|n| user_for_device(n, &target_device));
                match target_user {
                    None => format!("Unknown device {device_hex}"),
                    Some(target_user) => {
                        let target = PacketTarget {
                            user:   target_user,
                            device: target_device,
                            module: MODULE_ID,
                        };
                        match ctx.send(target, payload_str.as_bytes()) {
                            Ok(())                 => format!("Sent {} bytes to device {}", payload_str.len(), &device_hex),
                            Err(SendError::NoPath) => format!("Failed: no route to device {device_hex}"),
                        }
                    }
                }
            }
        };

        self.render_index(ctx, &banner)
    }
}

// ── Snapshot helpers ──────────────────────────────────────────────────────────

struct Snapshot {
    owner:         String,
    this:          String,
    own_devices:   String,
    contacts:      String,
    conns:         String,
    sg:            String,
    targets:       Vec<TargetEntry>,
    n_own_devices: usize,
    n_contacts:    usize,
    n_conns:       usize,
    n_sg:          usize,
}

struct TargetEntry {
    user_alias:   String,
    device_alias: String,
    device_hex:   String,
}

fn build_snapshot(node: &Node) -> Snapshot {
    let owner = format!(
        "alias:           {}\n\
         uuid:            {}\n\
         public_key:      {}\n\
         enabled_modules: {:?}",
        node.owner.user.alias,
        hex_bytes(&node.owner.user.uuid),
        hex_bytes(&node.owner.key_pair.public_key),
        node.owner.user.enabled_modules,
    );

    let local = node.owner.user.devices.iter().find(|d| d.uuid == node.device_uuid);
    let this = match local {
        Some(d) => format!(
            "uuid:    {}\n\
             alias:   {}\n\
             grade:   {:?}\n\
             sg_rank: {:?}\n\
             hosts:   {:?}",
            hex_bytes(&d.uuid), d.alias, d.grade, d.sg_rank, d.hosts,
        ),
        None => "(this device not in owner.devices)".to_string(),
    };

    let own_devices: String = node.owner.user.devices.iter()
        .map(|d| format!(
            "  {} [{:?}{}]\n  uuid={}\n  hosts={:?}\n",
            d.alias, d.grade,
            d.sg_rank.map(|r| format!(" rank={r}")).unwrap_or_default(),
            hex_bytes(&d.uuid), d.hosts,
        ))
        .collect();

    let contacts: String = if node.owner.contact_users.is_empty() {
        String::new()
    } else {
        node.owner.contact_users.iter().map(|c| {
            let devices: String = c.user.devices.iter()
                .map(|d| format!("    {} [{:?}] uuid={}\n", d.alias, d.grade, hex_bytes(&d.uuid)))
                .collect();
            format!(
                "  {}\n  uuid={}\n  public_key={}\n  enabled_modules={:?}\n{}",
                c.user.alias,
                hex_bytes(&c.user.uuid),
                hex_bytes(&c.public_key),
                c.user.enabled_modules,
                devices,
            )
        }).collect()
    };

    let conns: String = node.owner.active_connections.iter().map(|(id, c)| format!(
        "  conn={id} peer_device={} peer_addr={} timeout=+{}s\n",
        hex_bytes(&c.device_uuid),
        c.peer_addr,
        c.timeout.duration_since(SystemTime::now()).map(|d| d.as_secs() as i64).unwrap_or(-1),
    )).collect();

    let sg: String = node.sg_statuses.iter().map(|((uuid, host), s)| format!(
        "  device={} host={} up={} rtt={:?}\n",
        hex_bytes(uuid), host, s.up, s.last_rtt,
    )).collect();

    let mut targets: Vec<TargetEntry> = Vec::new();
    for d in &node.owner.user.devices {
        if d.uuid == node.device_uuid { continue; }
        targets.push(TargetEntry {
            user_alias:   format!("{} (you)", node.owner.user.alias),
            device_alias: d.alias.clone(),
            device_hex:   hex_bytes(&d.uuid),
        });
    }
    for c in &node.owner.contact_users {
        for d in &c.user.devices {
            targets.push(TargetEntry {
                user_alias:   c.user.alias.clone(),
                device_alias: d.alias.clone(),
                device_hex:   hex_bytes(&d.uuid),
            });
        }
    }

    Snapshot {
        owner, this, own_devices, contacts, conns, sg, targets,
        n_own_devices: node.owner.user.devices.len(),
        n_contacts:    node.owner.contact_users.len(),
        n_conns:       node.owner.active_connections.len(),
        n_sg:          node.sg_statuses.len(),
    }
}

fn render_send_form(snap: &Snapshot) -> String {
    if snap.targets.is_empty() {
        return "<p style=\"color:#999\">No known peer devices to send to yet.</p>".to_string();
    }
    let options: String = snap.targets.iter().map(|t| format!(
        "<option value=\"{}\">{} — {}</option>",
        t.device_hex,
        html_escape(&t.user_alias),
        html_escape(&t.device_alias),
    )).collect();

    format!(
        "<form method=\"post\" action=\"/apps/debug/send\">\
           <select name=\"device\">{options}</select>\
           <input type=\"text\" name=\"payload\" value=\"hello world\">\
           <button type=\"submit\">Send</button>\
         </form>"
    )
}

fn render_inbox_row(r: &Received) -> String {
    let when = r.at.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let payload_text = match std::str::from_utf8(&r.payload) {
        Ok(s)  => s.to_string(),
        Err(_) => format!("<{} bytes, non-utf8>", r.payload.len()),
    };
    format!(
        "<tr>\
           <td>{when}</td>\
           <td><span class=\"k\">device</span> {}<br><span class=\"k\">user</span> {}</td>\
           <td><pre>{}</pre><pre class=\"hex\">{}</pre></td>\
         </tr>",
        hex_bytes(&r.from_device),
        hex_bytes(&r.from_user),
        html_escape(&payload_text),
        hex_bytes(&r.payload),
    )
}

// ── Misc utilities ────────────────────────────────────────────────────────────

fn user_for_device(node: &Node, device: &Uuid) -> Option<Uuid> {
    if node.owner.user.devices.iter().any(|d| d.uuid == *device) {
        return Some(node.owner.user.uuid);
    }
    for c in &node.owner.contact_users {
        if c.user.devices.iter().any(|d| d.uuid == *device) {
            return Some(c.user.uuid);
        }
    }
    None
}

fn hex_bytes(b: &[u8]) -> String {
    const H: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 0xf) as usize] as char);
    }
    s
}

fn parse_hex_uuid(s: &str) -> Option<Uuid> {
    if s.len() != 32 { return None; }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = (nibble(chunk[0])? << 4) | nibble(chunk[1])?;
    }
    Some(out)
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&'  => out.push_str("&amp;"),
            '<'  => out.push_str("&lt;"),
            '>'  => out.push_str("&gt;"),
            '"'  => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _    => out.push(c),
        }
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => { out.push(b' '); i += 1; }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (nibble(bytes[i+1]), nibble(bytes[i+2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => { out.push(b); i += 1; }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

fn form_field<'a>(body: &'a [u8], name: &str) -> Option<&'a str> {
    let s = std::str::from_utf8(body).ok()?;
    let prefix = format!("{name}=");
    s.split('&').find_map(|kv| kv.strip_prefix(&prefix))
}

const CSS: &str = "\
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 1100px; margin: 0 auto; padding: 1rem; color: #222; }\
h1 { margin-top: 0; }\
h2 { margin-top: 1.4rem; border-bottom: 1px solid #ddd; padding-bottom: .25rem; font-size: 1.05rem; }\
pre { font-size: .8rem; background: #f7f7f7; padding: .6rem; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: .25rem 0; }\
pre.hex { color: #888; font-size: .75rem; }\
table { width: 100%; border-collapse: collapse; }\
th, td { border-bottom: 1px solid #eee; padding: .35rem .5rem; vertical-align: top; font-size: .85rem; text-align: left; }\
form { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }\
select, input, button { font-size: .9rem; padding: .35rem .5rem; }\
input[type=text] { flex: 1; min-width: 200px; }\
.banner { background: #eef; border: 1px solid #99c; padding: .5rem .75rem; border-radius: 4px; margin: .8rem 0; }\
.k { color: #888; font-size: .75rem; }\
";
