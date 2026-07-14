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
