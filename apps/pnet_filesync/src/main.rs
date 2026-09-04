//! pnet_filesync — hybrid folder replica + owner-portal web UI.
//!
//! See `apps/pnet_filesync/description.md`.

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use pnet_filesync::fabric::{self, APP_ALIAS};
use pnet_filesync::proto;
use pnet_filesync::store::Store;
use pnet_filesync::sync::Engine;
use pnet_filesync::web;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn main() {
    let web_port: u16 = env_or("PNET_FILESYNC_WEB_PORT", "9090")
        .parse()
        .unwrap_or(9090);
    let slug = env_or("PNET_FILESYNC_SLUG", "filesync");
    let title = env_or("PNET_FILESYNC_TITLE", "Filesync");
    let portal = env_or("PNET_PORTAL", "http://127.0.0.1:8777");
    let pnet_addr = env_or("PNET_ADDR", "127.0.0.1:7777");
    let alias = env_or("PNET_FILESYNC_ALIAS", APP_ALIAS);
    let skip_fabric = std::env::var("PNET_SKIP_FABRIC").ok().as_deref() == Some("1");
    let skip_web = std::env::var("PNET_FILESYNC_NO_WEB").ok().as_deref() == Some("1");

    let root = std::env::var("PNET_FILESYNC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_dir().join("pnet-filesync"));
    let state_dir = std::env::var("PNET_FILESYNC_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_dir().join(".pnet").join("filesync"));

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst));
    }

    let store = Store::open(root.clone(), state_dir).unwrap_or_else(|e| {
        panic!("open store: {e}");
    });
    println!(
        "[filesync] folder {}  state {}  replica {}",
        store.root.display(),
        store.state_dir.display(),
        pnet_filesync::store::hex16(&store.replica_id)
    );
    let store = Arc::new(Mutex::new(store));
    store.lock().unwrap().scan();

    let dest: SocketAddr = pnet_addr.parse().unwrap_or_else(|e| panic!("PNET_ADDR: {e}"));
    let ctrl = fabric::bind_udp().expect("ctrl udp");
    let push = fabric::bind_udp().expect("push udp");
    push.set_nonblocking(true).ok();
    let push_port = push.local_addr().expect("push addr").port();

    let mut token = [0u8; 16];
    if !skip_fabric {
        match fabric::register(&ctrl, dest, &alias, push_port) {
            Ok(t) => {
                token = t;
                println!("[filesync] fabric register ok (approve in Config if needed)");
            }
            Err(e) => eprintln!("[filesync] fabric register: {e}"),
        }
    }
    let engine = Arc::new(Mutex::new(Engine::new(token)));

    let portal_ok = Arc::new(std::sync::atomic::AtomicBool::new(false));
    if !skip_web {
        let portal = portal.clone();
        let slug = slug.clone();
        let title = title.clone();
        let portal_ok = Arc::clone(&portal_ok);
        thread::spawn(move || {
            for attempt in 1..=8 {
                match portal_register(&portal, &slug, web_port, &title) {
                    Ok(()) => {
                        println!("[filesync] portal /apps/{slug}/ → 127.0.0.1:{web_port}");
                        portal_ok.store(true, Ordering::SeqCst);
                        return;
                    }
                    Err(e) => {
                        eprintln!("[filesync] portal register {attempt}: {e}");
                        thread::sleep(Duration::from_millis(400));
                    }
                }
            }
        });
    }

    // Push receiver.
    {
        let stop = Arc::clone(&stop);
        let store = Arc::clone(&store);
        let engine = Arc::clone(&engine);
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while !stop.load(Ordering::Acquire) {
                match push.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        if let Some((sender, payload)) = fabric::parse_push(&buf[..n]) {
                            if let Some(pkt) = proto::decode(payload) {
                                let mut st = store.lock().unwrap();
                                let mut eng = engine.lock().unwrap();
                                eng.on_packet(&mut st, sender, pkt);
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(50)),
                }
            }
        });
    }

    // Scan + sync tick.
    {
        let stop = Arc::clone(&stop);
        let store = Arc::clone(&store);
        let engine = Arc::clone(&engine);
        let ctrl = ctrl.try_clone().expect("clone ctrl");
        let alias = alias.clone();
        thread::spawn(move || {
            let mut ticks = 0u64;
            while !stop.load(Ordering::Acquire) {
                let changed = store.lock().unwrap().scan();
                if !skip_fabric {
                    if ticks % 8 == 0 {
                        let mut eng = engine.lock().unwrap();
                        if eng.token != [0u8; 16] {
                            if let Err(e) = eng.refresh_dir(&ctrl, dest, &alias) {
                                if ticks % 32 == 0 {
                                    eprintln!("[filesync] get_data: {e}");
                                }
                            }
                        }
                    }
                    // Always store then engine (same order as the HTTP and push threads).
                    let st = store.lock().unwrap();
                    let mut eng = engine.lock().unwrap();
                    if eng.token != [0u8; 16] {
                        if changed {
                            eng.invalidate_index();
                        }
                        if eng.approved && (changed || ticks % 16 == 0) {
                            eng.broadcast_index(&st);
                        }
                        eng.request_missing();
                        eng.flush(&ctrl, dest);
                    }
                }
                ticks = ticks.saturating_add(1);
                thread::sleep(Duration::from_millis(500));
            }
        });
    }

    if skip_web {
        println!("[filesync] running (web disabled)");
        while !stop.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(200));
        }
    } else {
        let listener = TcpListener::bind(("127.0.0.1", web_port))
            .unwrap_or_else(|e| panic!("bind 127.0.0.1:{web_port}: {e}"));
        listener.set_nonblocking(true).expect("nonblocking");
        println!("[filesync] web http://127.0.0.1:{web_port}/  (portal /apps/{slug}/)");
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let store = Arc::clone(&store);
                    let engine = Arc::clone(&engine);
                    thread::spawn(move || {
                        if let Err(e) = web::handle(stream, &store, &engine) {
                            eprintln!("[filesync] http: {e}");
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(40));
                }
                Err(e) => {
                    eprintln!("[filesync] accept: {e}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    if portal_ok.load(Ordering::SeqCst) {
        if let Err(e) = portal_unregister(&portal, &slug) {
            eprintln!("[filesync] portal unregister: {e}");
        }
    }
    println!("[filesync] shutdown");
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
    let rest = base
        .strip_prefix("http://")
        .ok_or_else(|| format!("only http:// supported: {base}"))?;
    let (hostport, _) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| "bad port")?),
        None => (hostport, 80u16),
    };
    let mut stream = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut resp = String::new();
    use std::io::Read;
    stream.read_to_string(&mut resp).map_err(|e| e.to_string())?;
    if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        Err(resp.lines().next().unwrap_or(&resp).to_string())
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
