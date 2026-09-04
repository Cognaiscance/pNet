//! Loopback HTTP UI: browse, download, upload, delete.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::store::Store;
use crate::sync::Engine;

pub fn handle(
    mut stream: TcpStream,
    store: &Arc<Mutex<Store>>,
    engine: &Arc<Mutex<Engine>>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .ok();
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
        if head.len() > 64 * 1024 {
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
            let l = l.to_ascii_lowercase();
            l.strip_prefix("content-length:")
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
        if body.len() > 4 * 1024 * 1024 + 8 {
            return write_status(&mut stream, 413, "too large");
        }
    }
    if body.len() > content_len {
        body.truncate(content_len);
    }

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            let html = render_home(store);
            write_html(&mut stream, &html)
        }
        ("GET", "/dl") => {
            let p = query_param(query, "p").unwrap_or("");
            let decoded = url_decode(p);
            let st = store.lock().unwrap();
            match st.read_file(&decoded) {
                Some(bytes) => {
                    let name = decoded.rsplit('/').next().unwrap_or("file");
                    write_bytes(&mut stream, name, &bytes)
                }
                None => write_status(&mut stream, 404, "not found"),
            }
        }
        ("POST", "/up") => {
            let name = query_param(query, "name").unwrap_or("");
            let decoded = url_decode(name);
            let mut st = store.lock().unwrap();
            match st.write_file(&decoded, &body) {
                Ok(()) => {
                    bump_index(engine);
                    write_status(&mut stream, 204, "")
                }
                Err("too_large") => write_status(&mut stream, 413, "too large"),
                Err(_) => write_status(&mut stream, 400, "bad path"),
            }
        }
        ("POST", "/rm") => {
            let p = query_param(query, "p").unwrap_or("");
            let decoded = url_decode(p);
            let mut st = store.lock().unwrap();
            match st.remove_file(&decoded) {
                Ok(()) => {
                    bump_index(engine);
                    write_redirect(&mut stream, "./")
                }
                Err(_) => write_status(&mut stream, 400, "bad path"),
            }
        }
        _ => write_status(&mut stream, 404, "not found"),
    }
}

fn bump_index(engine: &Arc<Mutex<Engine>>) {
    if let Ok(mut eng) = engine.lock() {
        eng.invalidate_index();
    }
}

fn render_home(store: &Arc<Mutex<Store>>) -> String {
    let st = store.lock().unwrap();
    let files = st.live_list();
    let root = st.root.display().to_string();
    let n = files.len();
    let mut rows = String::new();
    if files.is_empty() {
        rows.push_str("<tr><td colspan='4' class='empty'>No files yet. Upload one, or drop files into the folder.</td></tr>");
    } else {
        for f in &files {
            let safe = html_escape(&f.path);
            let enc = form_enc(&f.path);
            rows.push_str(&format!(
                "<tr>\
                   <td><a href=\"dl?p={enc}\">{safe}</a></td>\
                   <td class='num'>{size}</td>\
                   <td class='muted'>{mtime}</td>\
                   <td><form method='post' action='rm?p={enc}' style='display:inline'>\
                     <button type='submit' class='danger'>Delete</button></form></td>\
                 </tr>",
                size = f.size,
                mtime = f.mtime,
            ));
        }
    }
    format!(
        "<!DOCTYPE html>\n\
         <html><head><meta charset=\"utf-8\"><title>Filesync</title>\n\
         <style>\
         body{{font-family:sans-serif;margin:0;background:#f5f5f5;color:#222}}\
         main{{max-width:52rem;margin:0 auto;padding:1.5rem}}\
         h1{{color:#1a1a2e;margin:0 0 .4rem}}\
         .sub{{color:#666;font-size:.9rem;margin:0 0 1.2rem}}\
         .card{{background:#fff;border-radius:8px;padding:1rem 1.2rem;\
                box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:1rem}}\
         table{{width:100%;border-collapse:collapse}}\
         th{{text-align:left;font-size:.8rem;color:#666;padding:.4rem 0;border-bottom:1px solid #eee}}\
         td{{padding:.45rem 0;border-bottom:1px solid #f0f0f0;font-size:.92rem}}\
         .num{{font-variant-numeric:tabular-nums}}\
         .muted{{color:#888;font-size:.85rem}}\
         .empty{{color:#888;font-style:italic}}\
         a{{color:#1a1a2e}}\
         button,.btn{{background:#1a1a2e;color:#fff;border:none;border-radius:5px;\
                       padding:.4rem .8rem;cursor:pointer;font-size:.85rem}}\
         .danger{{background:#c0392b}}\
         input[type=file]{{margin-right:.6rem}}\
         code{{background:#eee;padding:.1rem .3rem;border-radius:3px;font-size:.85rem}}\
         </style></head><body><main>\n\
         <h1>Filesync</h1>\
         <p class=\"sub\">Folder replica on this device. Other pNet devices running \
         filesync converge to the same tree. Web is a viewport — the browser is not \
         a fabric peer.</p>\
         <div class=\"card\">\
           <p style=\"margin:.2rem 0 .8rem\">Folder: <code>{root}</code> · {n} file(s)</p>\
           <input id=\"f\" type=\"file\">\
           <button type=\"button\" onclick=\"up()\">Upload</button>\
           <span id=\"st\" class=\"muted\"></span>\
         </div>\
         <div class=\"card\">\
           <table><thead><tr><th>Path</th><th>Bytes</th><th>mtime</th><th></th></tr></thead>\
           <tbody>{rows}</tbody></table>\
         </div>\
         <p class=\"sub\"><a href=\"/\">← Portal Home</a> (when opened via the portal)</p>\
         <script>\
         async function up(){{\
           const i=document.getElementById('f');\
           const s=document.getElementById('st');\
           if(!i.files.length){{s.textContent='choose a file';return;}}\
           const file=i.files[0];\
           s.textContent='uploading…';\
           const r=await fetch('up?name='+encodeURIComponent(file.name),{{method:'POST',body:file}});\
           s.textContent=r.ok?'done':'failed '+r.status;\
           if(r.ok) location.reload();\
         }}\
         </script>\
         </main></body></html>",
        root = html_escape(&root),
    )
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    query.split('&').find_map(|p| p.strip_prefix(&prefix))
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
                let hi = hex(b[i + 1]);
                let lo = hex(b[i + 2]);
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

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn form_enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b));
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn write_html(stream: &mut TcpStream, body: &str) -> Result<(), String> {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).map_err(|e| e.to_string())
}

fn write_bytes(stream: &mut TcpStream, name: &str, bytes: &[u8]) -> Result<(), String> {
    let safe = name.replace(['"', '\r', '\n'], "_");
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
         Content-Disposition: attachment; filename=\"{safe}\"\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream.write_all(resp.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(bytes).map_err(|e| e.to_string())
}

fn write_status(stream: &mut TcpStream, code: u16, msg: &str) -> Result<(), String> {
    let text = match code {
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "OK",
    };
    let body = msg;
    let resp = format!(
        "HTTP/1.1 {code} {text}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).map_err(|e| e.to_string())
}

fn write_redirect(stream: &mut TcpStream, loc: &str) -> Result<(), String> {
    let resp = format!(
        "HTTP/1.1 302 Found\r\nLocation: {loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(resp.as_bytes()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_used_on_query_names() {
        use crate::paths::sanitize_rel;
        assert!(sanitize_rel(&url_decode("ok.txt")).is_some());
        assert!(sanitize_rel(&url_decode("..%2Fetc%2Fpasswd")).is_none());
    }
}
