//! pnet_installer — catalog, desire, status; `bootstrap` installs pNet + agent.
//!
//! See `apps/pnet_installer/description.md`.

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use pnet_installer::bootstrap::{self, Cmd};
use pnet_installer::fabric::{self, APP_ALIAS};
use pnet_installer::proto;
use pnet_installer::state::State;
use pnet_installer::sync::Engine;
use pnet_installer::web;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match bootstrap::parse_args(&args) {
        Ok(Cmd::Help) => {
            print!("{}", bootstrap::help_text());
            return;
        }
        Ok(Cmd::Bootstrap(mut opts)) => {
            let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("pnet_installer"));
            if let Err(e) = bootstrap::resolve_from(&mut opts, &exe) {
                eprintln!("[bootstrap] {e}");
                std::process::exit(1);
            }
            match bootstrap::plan(&opts).and_then(|p| bootstrap::execute(&opts, &p)) {
                Ok(log) => print!("{log}"),
                Err(e) => {
                    eprintln!("[bootstrap] {e}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Ok(Cmd::Run) => {}
        Err(e) => {
            eprintln!("[installer] {e}\n");
            print!("{}", bootstrap::help_text());
            std::process::exit(1);
        }
    }
    run_agent();
}

fn run_agent() {
    let web_port: u16 = env_or("PNET_INSTALLER_WEB_PORT", "9091")
        .parse()
        .unwrap_or(9091);
    let slug = env_or("PNET_INSTALLER_SLUG", "installer");
    let title = env_or("PNET_INSTALLER_TITLE", "Installer");
    let portal = env_or("PNET_PORTAL", "http://127.0.0.1:8777");
    let pnet_addr = env_or("PNET_ADDR", "127.0.0.1:7777");
    let alias = env_or("PNET_INSTALLER_ALIAS", APP_ALIAS);
    let skip_fabric = std::env::var("PNET_SKIP_FABRIC").ok().as_deref() == Some("1");

    let state_dir = std::env::var("PNET_INSTALLER_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_dir().join(".pnet").join("installer"));

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst));
    }

    let state = State::open(state_dir).unwrap_or_else(|e| panic!("open state: {e}"));
    println!(
        "[installer] state {}  replica {}  (notify only — will not exec packages)",
        state.dir.display(),
        pnet_installer::state::hex16(&state.replica_id)
    );
    let state = Arc::new(Mutex::new(state));

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
                println!("[installer] fabric register ok (approve in Config if needed)");
            }
            Err(e) => eprintln!("[installer] fabric register: {e}"),
        }
    }
    let engine = Arc::new(Mutex::new(Engine::new(token)));

    let portal_ok = Arc::new(AtomicBool::new(false));
    {
        let portal = portal.clone();
        let slug = slug.clone();
        let title = title.clone();
        let portal_ok = Arc::clone(&portal_ok);
        thread::spawn(move || {
            for attempt in 1..=8 {
                match portal_register(&portal, &slug, web_port, &title) {
                    Ok(()) => {
                        println!("[installer] portal /apps/{slug}/ → 127.0.0.1:{web_port}");
                        portal_ok.store(true, Ordering::SeqCst);
                        return;
                    }
                    Err(e) => {
                        eprintln!("[installer] portal register {attempt}: {e}");
                        thread::sleep(Duration::from_millis(400));
                    }
                }
            }
        });
    }

    {
        let stop = Arc::clone(&stop);
        let state = Arc::clone(&state);
        let engine = Arc::clone(&engine);
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while !stop.load(Ordering::Acquire) {
                match push.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        if let Some((sender, payload)) = fabric::parse_push(&buf[..n]) {
                            if let Some(pkt) = proto::decode(payload) {
                                let mut st = state.lock().unwrap();
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

    {
        let stop = Arc::clone(&stop);
        let state = Arc::clone(&state);
        let engine = Arc::clone(&engine);
        let ctrl = ctrl.try_clone().expect("clone ctrl");
        let alias = alias.clone();
        thread::spawn(move || {
            let mut ticks = 0u64;
            while !stop.load(Ordering::Acquire) {
                if !skip_fabric {
                    if ticks % 8 == 0 {
                        let mut eng = engine.lock().unwrap();
                        if eng.token != [0u8; 16] {
                            if let Err(e) = eng.refresh_dir(&ctrl, dest, &alias) {
                                if ticks % 32 == 0 {
                                    eprintln!("[installer] get_data: {e}");
                                }
                            }
                        }
                    }
                    let mut st = state.lock().unwrap();
                    let mut eng = engine.lock().unwrap();
                    if eng.token != [0u8; 16] {
                        if let Some(dir) = eng.dir.clone() {
                            if st.observe_local(&dir) {
                                eng.status_dirty = true;
                            }
                        }
                        if eng.approved {
                            eng.broadcast(&st);
                        }
                        eng.flush(&ctrl, dest);
                    }
                }
                ticks = ticks.saturating_add(1);
                thread::sleep(Duration::from_millis(500));
            }
        });
    }

    let listener = TcpListener::bind(("127.0.0.1", web_port))
        .unwrap_or_else(|e| panic!("bind 127.0.0.1:{web_port}: {e}"));
    listener.set_nonblocking(true).expect("nonblocking");
    println!("[installer] web http://127.0.0.1:{web_port}/  (portal /apps/{slug}/)");

    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let state = Arc::clone(&state);
                let engine = Arc::clone(&engine);
                thread::spawn(move || {
                    if let Err(e) = web::handle(stream, &state, &engine) {
                        eprintln!("[installer] http: {e}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(40));
            }
            Err(e) => {
                eprintln!("[installer] accept: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    if portal_ok.load(Ordering::SeqCst) {
        if let Err(e) = portal_unregister(&portal, &slug) {
            eprintln!("[installer] portal unregister: {e}");
        }
    }
    println!("[installer] shutdown");
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
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
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
