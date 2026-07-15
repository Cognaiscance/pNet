use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::action_queue::{Action, PRIORITY_NORMAL};
use super::thread_pool::SharedQueue;

/// Default admin-UI HTTP port, overridable via `PNET_HTTP_PORT`.
pub const DEFAULT_HTTP_PORT: u16 = 8777;

pub struct HttpServer {
    handle: thread::JoinHandle<()>,
}

/// Admin-UI HTTP port: `PNET_HTTP_PORT` if set and parseable, else
/// `DEFAULT_HTTP_PORT`. Mirrors `udp_listener::udp_port`. Lets two node
/// instances coexist on one host (distinct `PNET_UDP_PORT` + `PNET_HTTP_PORT`
/// + `HOME`).
pub fn http_port() -> u16 {
    std::env::var("PNET_HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_HTTP_PORT)
}

/// Resolve the admin-UI bind address from env values (pure; used by
/// [`http_bind_ip`] and unit tests).
///
/// * `bind` — raw `PNET_HTTP_BIND` value (`None` if unset).
/// * `bind_all` — true when legacy `PNET_HTTP_BIND_ALL` is `1`/`true`.
///
/// Default is loopback for every grade. Remote admin is opt-in only.
pub fn parse_http_bind(bind: Option<&str>, bind_all: bool) -> Ipv4Addr {
    if let Some(raw) = bind {
        let s = raw.trim();
        if !s.is_empty() {
            if s.eq_ignore_ascii_case("localhost") {
                return Ipv4Addr::LOCALHOST;
            }
            match s.parse::<Ipv4Addr>() {
                Ok(ip) => return ip,
                Err(_) => {
                    eprintln!(
                        "[http] PNET_HTTP_BIND={s:?} is not a valid IPv4 address; using 127.0.0.1"
                    );
                    return Ipv4Addr::LOCALHOST;
                }
            }
        }
    }
    if bind_all {
        return Ipv4Addr::UNSPECIFIED;
    }
    Ipv4Addr::LOCALHOST
}

/// Admin-UI HTTP bind address.
///
/// **Default:** `127.0.0.1` (loopback) for all grades — SG and DG alike.
///
/// **Opt-in remote admin:** set `PNET_HTTP_BIND` to an IPv4 address, typically
/// `0.0.0.0` for container port-publish or LAN access. Examples:
/// `PNET_HTTP_BIND=0.0.0.0`, `PNET_HTTP_BIND=192.168.1.10`.
///
/// **Legacy:** `PNET_HTTP_BIND_ALL=1` (or `true`) is still accepted as an alias
/// for binding `0.0.0.0` when `PNET_HTTP_BIND` is unset. Prefer `PNET_HTTP_BIND`.
pub fn http_bind_ip() -> Ipv4Addr {
    let bind = std::env::var("PNET_HTTP_BIND").ok();
    let bind_all = std::env::var("PNET_HTTP_BIND_ALL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    parse_http_bind(bind.as_deref(), bind_all)
}

impl HttpServer {
    pub fn start(bind_ip: Ipv4Addr, port: u16, queue: SharedQueue, stop: Arc<AtomicBool>) -> HttpServer {
        let handle = thread::spawn(move || {
            let listener = TcpListener::bind((bind_ip, port))
                .unwrap_or_else(|e| panic!("HTTP bind on {bind_ip}:{port} failed: {e}"));
            listener
                .set_nonblocking(true)
                .expect("set_nonblocking failed");

            while !stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        enqueue_request(stream, &queue);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        eprintln!("[http] accept error: {e}");
                    }
                }
            }
        });

        HttpServer { handle }
    }

    pub fn join(self) {
        self.handle.join().expect("HTTP server thread panicked");
    }
}

fn enqueue_request(stream: TcpStream, queue: &SharedQueue) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    // BufReader borrows &stream; borrow ends at the closing brace so stream
    // can be moved into the Action below.
    let result = {
        let mut reader = BufReader::new(&stream);
        parse_request(&mut reader)
    };

    // If parsing fails, drop the stream (connection reset — acceptable for
    // malformed requests against a localhost admin UI).
    let Some((method, path, query, cookie, body)) = result else { return };

    let (lock, cvar) = &**queue;
    let mut guard = lock.lock().unwrap();
    guard.push(PRIORITY_NORMAL, Action::UiRequest {
        stream, method, path, query, cookie, body,
    });
    cvar.notify_one();
}

fn parse_request(
    reader: &mut BufReader<&TcpStream>,
) -> Option<(String, String, String, String, Vec<u8>)> {
    // Request line.
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let parts: Vec<&str> = line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let method   = parts[0].to_string();
    let raw_path = parts[1].to_string();

    let (path, query) = match raw_path.find('?') {
        Some(pos) => (raw_path[..pos].to_string(), raw_path[pos + 1..].to_string()),
        None      => (raw_path, String::new()),
    };

    // Headers — scan for Content-Length and Cookie.
    let mut content_length: usize = 0;
    let mut cookie = String::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).is_err() {
            break;
        }
        let trimmed = h.trim();
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            content_length = lower["content-length:".len()..].trim().parse().unwrap_or(0);
        } else if lower.starts_with("cookie:") {
            cookie = trimmed
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
        }
    }

    // Body (cap at 64 KiB — more than enough for a form submission).
    let body = if content_length > 0 {
        let mut buf = vec![0u8; content_length.min(65_536)];
        reader.read_exact(&mut buf).ok()?;
        buf
    } else {
        Vec::new()
    };

    Some((method, path, query, cookie, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn http_bind_defaults_to_loopback() {
        assert_eq!(parse_http_bind(None, false), Ipv4Addr::LOCALHOST);
        assert_eq!(parse_http_bind(Some(""), false), Ipv4Addr::LOCALHOST);
        assert_eq!(parse_http_bind(Some("   "), false), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn http_bind_opt_in_all_interfaces() {
        assert_eq!(parse_http_bind(Some("0.0.0.0"), false), Ipv4Addr::UNSPECIFIED);
        assert_eq!(parse_http_bind(Some(" 0.0.0.0 "), false), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn http_bind_accepts_localhost_alias_and_specific_ip() {
        assert_eq!(parse_http_bind(Some("localhost"), false), Ipv4Addr::LOCALHOST);
        assert_eq!(parse_http_bind(Some("127.0.0.1"), false), Ipv4Addr::LOCALHOST);
        assert_eq!(
            parse_http_bind(Some("192.168.1.10"), false),
            Ipv4Addr::new(192, 168, 1, 10)
        );
    }

    #[test]
    fn http_bind_invalid_falls_back_to_loopback() {
        assert_eq!(parse_http_bind(Some("not-an-ip"), false), Ipv4Addr::LOCALHOST);
        assert_eq!(parse_http_bind(Some("::1"), false), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn http_bind_legacy_bind_all_alias() {
        assert_eq!(parse_http_bind(None, true), Ipv4Addr::UNSPECIFIED);
        // Explicit PNET_HTTP_BIND wins over legacy BIND_ALL.
        assert_eq!(parse_http_bind(Some("127.0.0.1"), true), Ipv4Addr::LOCALHOST);
    }
}
