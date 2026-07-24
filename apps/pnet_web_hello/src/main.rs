//! Sample hybrid app for the owner portal.
//!
//! 1. Serves a small HTML page on loopback (`PNET_WEB_PORT`, default 9080).
//! 2. Registers that page with the pNet portal via
//!    `POST /api/app-web/register` (loopback only on the node).
//! 3. Optionally registers as a fabric app (`PNET_ADDR`, default 127.0.0.1:7777)
//!    so it shows up under Applications when auto-approve is on.
//!
//! Env:
//!   PNET_WEB_PORT      HTTP listen port (default 9080)
//!   PNET_WEB_SLUG      portal mount slug (default "hello")
//!   PNET_WEB_TITLE     display title (default "Hello")
//!   PNET_PORTAL        portal base URL (default http://127.0.0.1:8777)
//!   PNET_ADDR          fabric host:port for app register (default 127.0.0.1:7777)
//!   PNET_WEB_ALIAS     fabric app alias (default "web-hello")
//!   PNET_SKIP_FABRIC=1 skip UDP app registration

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const OP_REGISTER: u8 = 0x00;
const STATUS_OK: u8 = 0x00;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let web_port: u16 = env_or("PNET_WEB_PORT", "9080").parse().unwrap_or(9080);
    let slug = env_or("PNET_WEB_SLUG", "hello");
    let title = env_or("PNET_WEB_TITLE", "Hello");
    let portal = env_or("PNET_PORTAL", "http://127.0.0.1:8777");
    let pnet_addr = env_or("PNET_ADDR", "127.0.0.1:7777");
    let app_alias = env_or("PNET_WEB_ALIAS", "web-hello");
    let skip_fabric = std::env::var("PNET_SKIP_FABRIC").ok().as_deref() == Some("1");

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        ctrlc::set_handler(move || {
            stop.store(true, Ordering::SeqCst);
        })
        .expect("ctrlc");
    }

    // Bind first so register only happens when we can accept.
    let listener = TcpListener::bind(("127.0.0.1", web_port))
        .unwrap_or_else(|e| panic!("bind 127.0.0.1:{web_port}: {e}"));
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking");
    println!("[web-hello] HTTP http://127.0.0.1:{web_port}/");

    if !skip_fabric {
        match fabric_register(&pnet_addr, &app_alias, web_port) {
            Ok(token) => println!(
                "[web-hello] fabric register ok token={}…",
                &hex(&token)[..8.min(hex(&token).len())]
            ),
            Err(e) => eprintln!("[web-hello] fabric register skipped/failed: {e}"),
        }
    }

    // Retry portal mount a few times (pNet may still be starting).
    let mut registered = false;
    for attempt in 1..=10 {
        match portal_register(&portal, &slug, web_port, &title) {
            Ok(()) => {
                println!("[web-hello] portal mount /apps/{slug}/ → 127.0.0.1:{web_port}");
                registered = true;
                break;
            }
            Err(e) => {
                eprintln!("[web-hello] portal register attempt {attempt}: {e}");
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
    if !registered {
        eprintln!("[web-hello] continuing without portal mount (register failed)");
    }

    println!("[web-hello] running — open portal Home then /apps/{slug}/ (signed in)");

    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let slug = slug.clone();
                let title = title.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_http(stream, &slug, &title) {
                        eprintln!("[web-hello] request error: {e}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("[web-hello] accept: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    if registered {
        if let Err(e) = portal_unregister(&portal, &slug) {
            eprintln!("[web-hello] portal unregister: {e}");
        } else {
            println!("[web-hello] portal mount /apps/{slug}/ removed");
        }
    }
    println!("[web-hello] shutdown");
}

fn handle_http(mut stream: TcpStream, slug: &str, title: &str) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let line = req.lines().next().unwrap_or("");
    // Only serve a simple page for GET / (and ignore favicon noise).
    if line.contains("GET /favicon") {
        let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(resp).map_err(|e| e.to_string())?;
        return Ok(());
    }

    let body = format!(
        "<!DOCTYPE html>\n\
         <html><head><meta charset=\"utf-8\"><title>{title}</title>\n\
         <style>\
         body{{font-family:sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;color:#222}}\
         h1{{color:#1a1a2e}}\
         .card{{background:#f5f5f5;border-radius:8px;padding:1.2rem 1.4rem}}\
         a{{color:#1a1a2e}}\
         code{{background:#e8e8e8;padding:.1rem .35rem;border-radius:3px}}\
         </style></head><body>\n\
         <h1>{title}</h1>\n\
         <div class=\"card\">\n\
           <p>This page is served by <strong>pnet_web_hello</strong> on the SG \
           (loopback HTTP), and reached through the pNet portal reverse proxy.</p>\n\
           <p>Mount slug: <code>{slug}</code></p>\n\
           <p><a href=\"/\">← Portal Home</a> \
           (works when opened via the portal host)</p>\n\
         </div>\n\
         </body></html>"
    );
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {body}",
        body.len()
    );
    stream
        .write_all(resp.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn portal_register(portal: &str, slug: &str, port: u16, title: &str) -> Result<(), String> {
    let body = format!(
        "slug={}&port={}&title={}",
        form_enc(slug),
        port,
        form_enc(title)
    );
    http_post_form(portal, "/api/app-web/register", &body)
}

fn portal_unregister(portal: &str, slug: &str) -> Result<(), String> {
    let body = format!("slug={}", form_enc(slug));
    http_post_form(portal, "/api/app-web/unregister", &body)
}

fn http_post_form(base: &str, path: &str, body: &str) -> Result<(), String> {
    let base = base.trim_end_matches('/');
    let url = format!("{base}{path}");
    let (host, port, _) = parse_http_url(&url)?;
    let mut stream = TcpStream::connect((host.as_str(), port))
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| format!("read: {e}"))?;
    if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        let first = resp.lines().next().unwrap_or(&resp);
        Err(first.to_string())
    }
}

fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// supported: {url}"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "bad port")?),
        None => (hostport.to_string(), 80u16),
    };
    Ok((host, port, path.to_string()))
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

/// Register with the local pNet fabric (op 0x00) so the app appears under Applications.
fn fabric_register(pnet_addr: &str, alias: &str, push_port: u16) -> Result<[u8; 16], String> {
    let dest: SocketAddr = pnet_addr
        .parse()
        .map_err(|e| format!("PNET_ADDR: {e}"))?;
    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))
        .ok();
    // Wire: [op][alias_len u8][alias][port u16 be][protocol_len u8][protocol]
    let protocol = b"text/html";
    let mut pkt = Vec::new();
    pkt.push(OP_REGISTER);
    pkt.push(alias.len() as u8);
    pkt.extend_from_slice(alias.as_bytes());
    pkt.extend_from_slice(&push_port.to_be_bytes());
    pkt.push(protocol.len() as u8);
    pkt.extend_from_slice(protocol);
    sock.send_to(&pkt, dest).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 64];
    let (n, _) = sock.recv_from(&mut buf).map_err(|e| e.to_string())?;
    if n < 17 || buf[0] != STATUS_OK {
        return Err(format!("bad register reply len={n} status={}", buf.first().copied().unwrap_or(0xff)));
    }
    let mut token = [0u8; 16];
    token.copy_from_slice(&buf[1..17]);
    Ok(token)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
