//! Loopback store UI: catalog, desire (writer), status. Notify only.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::catalog;
use crate::state::{hex16, State, STATE_INSTALLED, STATE_PENDING};
use crate::sync::Engine;

pub fn handle(
    mut stream: TcpStream,
    state: &Arc<Mutex<State>>,
    engine: &Arc<Mutex<Engine>>,
) -> Result<(), String> {
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut head = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&tmp[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if head.len() > 32 * 1024 {
            return Ok(());
        }
    }
    let req = String::from_utf8_lossy(&head);
    let line = req.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_path = parts.next().unwrap_or("/");
    let (path, query) = match raw_path.find('?') {
        Some(i) => (&raw_path[..i], &raw_path[i + 1..]),
        None => (raw_path, ""),
    };
    let content_len = req
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    let header_end = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(head.len());
    let mut body = head[header_end.min(head.len())..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > 64 * 1024 {
            return write_status(&mut stream, 413, "too large");
        }
    }
    body.truncate(content_len);

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            write_html(&mut stream, &render_home(state, engine))
        }
        ("GET", "/app") => {
            let id = query_param(query, "id").unwrap_or("");
            write_html(&mut stream, &render_app(state, engine, &url_decode(id)))
        }
        ("POST", "/enable") => {
            let form = parse_form(&body);
            let id = form_one(&form, "id").unwrap_or_default();
            let enabled = form_one(&form, "enabled").as_deref() == Some("1");
            let devices: Vec<String> = form
                .iter()
                .filter(|(k, _)| k == "device")
                .map(|(_, v)| v.clone())
                .filter(|v| v.len() == 32)
                .collect();
            let err = apply_enable(state, engine, &id, enabled, devices);
            match err {
                None => write_redirect(&mut stream, &format!("app?id={}", form_enc(&id))),
                Some("not_writer") => write_status(
                    &mut stream,
                    403,
                    "Only the rank-1 SG installer writes desire.",
                ),
                Some(_) => write_status(&mut stream, 400, "bad request"),
            }
        }
        _ => write_status(&mut stream, 404, "not found"),
    }
}

fn apply_enable(
    state: &Arc<Mutex<State>>,
    engine: &Arc<Mutex<Engine>>,
    id: &str,
    enabled: bool,
    devices: Vec<String>,
) -> Option<&'static str> {
    let mut st = state.lock().unwrap();
    let mut eng = engine.lock().unwrap();
    let dir = eng.dir.clone();
    let writer = match &dir {
        Some(d) => st.is_writer(d),
        None => true, // skip-fabric / not yet refreshed
    };
    if !writer {
        return Some("not_writer");
    }
    let me = dir
        .as_ref()
        .map(|d| d.device_uuid)
        .unwrap_or(st.replica_id);
    st.set_desire(id, enabled, devices, me).err()?;
    eng.desire_dirty = true;
    eng.status_dirty = true;
    None
}

fn render_home(state: &Arc<Mutex<State>>, engine: &Arc<Mutex<Engine>>) -> String {
    let st = state.lock().unwrap();
    let eng = engine.lock().unwrap();
    let writer = eng
        .dir
        .as_ref()
        .map(|d| st.is_writer(d))
        .unwrap_or(true);
    let role = if writer {
        "This node is the desire writer (rank-1 SG, or the only node)."
    } else {
        "Read-only here. Change enable/devices on the rank-1 SG installer."
    };
    let mut cards = String::new();
    for a in catalog::all() {
        let des = st.desire.iter().find(|d| d.catalog_id == a.id);
        let enabled = des.map(|d| d.enabled).unwrap_or(false);
        let n_dev = des.map(|d| d.device_uuids.len()).unwrap_or(0);
        let pending = st
            .status
            .iter()
            .filter(|s| s.catalog_id == a.id && s.state == STATE_PENDING)
            .count();
        let installed = st
            .status
            .iter()
            .filter(|s| s.catalog_id == a.id && s.state == STATE_INSTALLED)
            .count();
        let flag = if enabled { "enabled" } else { "off" };
        cards.push_str(&format!(
            "<div class=\"card\">\
               <h2><a href=\"app?id={id}\">{name}</a> <span class=\"muted\">({flag})</span></h2>\
               <p>{summary}</p>\
               <p class=\"muted\">{n_dev} device(s) in desire · {installed} installed · {pending} pending</p>\
             </div>",
            id = html_escape(a.id),
            name = html_escape(a.name),
            summary = html_escape(a.summary),
        ));
    }
    format!(
        "{head}\
         <h1>Installer</h1>\
         <p class=\"sub\">Phase 2: desire and status only. \
         <strong>This agent never downloads or starts packages.</strong> \
         Copy the run command on each desired device. {role}</p>\
         {cards}\
         <p class=\"sub\"><a href=\"/\">← Portal Home</a> (when opened via the portal)</p>\
         </main></body></html>",
        head = PAGE_HEAD,
        role = html_escape(role),
    )
}

fn render_app(state: &Arc<Mutex<State>>, engine: &Arc<Mutex<Engine>>, id: &str) -> String {
    let Some(a) = catalog::get(id) else {
        return format!(
            "{PAGE_HEAD}<h1>Unknown app</h1><p><a href=\"./\">Back</a></p></main></body></html>"
        );
    };
    let st = state.lock().unwrap();
    let eng = engine.lock().unwrap();
    let writer = eng
        .dir
        .as_ref()
        .map(|d| st.is_writer(d))
        .unwrap_or(true);
    let des = st.desire.iter().find(|d| d.catalog_id == a.id);
    let enabled = des.map(|d| d.enabled).unwrap_or(false);
    let wanted: Vec<&str> = des
        .map(|d| d.device_uuids.iter().map(|s| s.as_str()).collect())
        .unwrap_or_default();
    let mut checks = String::new();
    if let Some(dir) = &eng.dir {
        for d in &dir.devices {
            let hex = hex16(&d.uuid);
            let on = wanted.iter().any(|w| *w == hex);
            let grade = if d.is_sg {
                format!("SG rank {}", d.sg_rank)
            } else {
                "DG".into()
            };
            checks.push_str(&format!(
                "<label class=\"chk\"><input type=\"checkbox\" name=\"device\" value=\"{hex}\" {on}>\
                 {alias} <span class=\"muted\">({grade})</span></label>",
                on = if on { "checked" } else { "" },
                alias = html_escape(&d.alias),
            ));
        }
    } else {
        checks.push_str("<p class=\"muted\">Directory not loaded yet (approve this app / wait for get-data). \
                         You can still copy the command.</p>");
    }
    let mut rows = String::new();
    let statuses: Vec<_> = st.status.iter().filter(|s| s.catalog_id == a.id).collect();
    if statuses.is_empty() {
        rows.push_str("<tr><td colspan='3' class='muted'>No status yet.</td></tr>");
    } else {
        for s in statuses {
            let alias = eng
                .dir
                .as_ref()
                .and_then(|d| {
                    d.devices.iter().find(|x| hex16(&x.uuid) == s.device_uuid)
                })
                .map(|x| x.alias.clone())
                .unwrap_or_else(|| s.device_uuid[..8].to_string());
            rows.push_str(&format!(
                "<tr><td>{alias}</td><td>{state}</td><td class=\"muted\">{detail}</td></tr>",
                alias = html_escape(&alias),
                state = html_escape(&s.state),
                detail = html_escape(&s.detail),
            ));
        }
    }
    let form = if writer {
        format!(
            "<form method=\"post\" action=\"enable\" class=\"card\">\
               <input type=\"hidden\" name=\"id\" value=\"{id}\">\
               <p><label><input type=\"checkbox\" name=\"enabled\" value=\"1\" {en}> \
               Enable this app</label></p>\
               <p>Devices that should run it:</p>\
               {checks}\
               <p><button class=\"btn\" type=\"submit\">Save desire</button></p>\
               <p class=\"muted\">Saving does not install. Agents only report pending/installed.</p>\
             </form>",
            id = html_escape(a.id),
            en = if enabled { "checked" } else { "" },
        )
    } else {
        format!(
            "<div class=\"card\"><p>Enable/devices can be changed on the rank-1 SG installer.</p>\
             {checks}</div>"
        )
    };
    format!(
        "{head}\
         <h1>{name}</h1>\
         <p class=\"sub\">{summary}</p>\
         <p class=\"sub\">Typical placement: {place}</p>\
         {form}\
         <div class=\"card\">\
           <p><strong>Run on a desired device</strong> (copy; browser does not execute):</p>\
           <pre class=\"cmd\" id=\"cmd\">{cmd}</pre>\
           <p><button type=\"button\" class=\"btn\" onclick=\"\
             navigator.clipboard.writeText(document.getElementById('cmd').innerText)\
             .then(()=>this.textContent='Copied').catch(()=>{{}})\">Copy command</button></p>\
           <p class=\"muted\">{notes}</p>\
         </div>\
         <div class=\"card\">\
           <h2>Status</h2>\
           <table><thead><tr><th>Device</th><th>State</th><th>Detail</th></tr></thead>\
           <tbody>{rows}</tbody></table>\
         </div>\
         <p class=\"sub\"><a href=\"./\">← Catalog</a></p>\
         </main></body></html>",
        head = PAGE_HEAD,
        name = html_escape(a.name),
        summary = html_escape(a.summary),
        place = html_escape(a.placement),
        cmd = html_escape(a.install_cmd),
        notes = html_escape(a.notes),
    )
}

const PAGE_HEAD: &str = "\
<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Installer</title>\
<style>\
body{font-family:sans-serif;margin:0;background:#f5f5f5;color:#222}\
main{max-width:52rem;margin:0 auto;padding:1.5rem}\
h1{color:#1a1a2e;margin:0 0 .4rem}h2{font-size:1.1rem;margin:.2rem 0 .5rem}\
.sub{color:#666;font-size:.9rem;margin:0 0 1rem}\
.card{background:#fff;border-radius:8px;padding:1rem 1.2rem;\
      box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:1rem}\
.muted{color:#888;font-size:.85rem}\
a{color:#1a1a2e}.btn{background:#1a1a2e;color:#fff;border:none;border-radius:5px;\
padding:.4rem .9rem;cursor:pointer;font-size:.9rem}\
.cmd{background:#1a1a2e;color:#e8e8f0;padding:.9rem 1rem;border-radius:6px;\
     white-space:pre-wrap;font-size:.85rem}\
.chk{display:block;margin:.35rem 0}\
table{width:100%;border-collapse:collapse}\
th{text-align:left;font-size:.8rem;color:#666;padding:.35rem 0;border-bottom:1px solid #eee}\
td{padding:.4rem 0;border-bottom:1px solid #f0f0f0;font-size:.9rem}\
</style></head><body><main>";

fn form_one(form: &[(String, String)], key: &str) -> Option<String> {
    form.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
}

fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    let s = String::from_utf8_lossy(body);
    s.split('&')
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((url_decode(k), url_decode(v)))
        })
        .collect()
}

fn query_param<'a>(q: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    q.split('&').find_map(|p| p.strip_prefix(&prefix))
}

fn url_decode(s: &str) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hi = from_hex(b[i + 1]);
                let lo = from_hex(b[i + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push(char::from((hi << 4) | lo));
                    i += 3;
                } else {
                    out.push('%');
                    i += 1;
                }
            }
            c => {
                out.push(char::from(c));
                i += 1;
            }
        }
    }
    out
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn form_enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => o.push(char::from(b)),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn write_html(s: &mut TcpStream, body: &str) -> Result<(), String> {
    let r = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(r.as_bytes()).map_err(|e| e.to_string())
}

fn write_status(s: &mut TcpStream, code: u16, msg: &str) -> Result<(), String> {
    let text = match code {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "OK",
    };
    let r = format!(
        "HTTP/1.1 {code} {text}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{msg}",
        msg.len()
    );
    s.write_all(r.as_bytes()).map_err(|e| e.to_string())
}

fn write_redirect(s: &mut TcpStream, loc: &str) -> Result<(), String> {
    let r = format!(
        "HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    s.write_all(r.as_bytes()).map_err(|e| e.to_string())
}
