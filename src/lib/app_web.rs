//! Owner portal app web mounts: registry + localhost reverse proxy.
//!
//! Apps on this node may register a **slug** and a **loopback TCP port**. The
//! portal proxies `GET|POST|… /apps/<slug>/…` to `http://127.0.0.1:<port>/…`.
//! Registration is accepted only from loopback peers (the app process itself).
//!
//! See `descriptions/app-web-surfaces.md`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// One reverse-proxied app web surface on this node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppWebMount {
    /// URL segment under `/apps/<slug>/…` (lowercase alphanumeric + hyphens).
    pub slug: String,
    /// Loopback port the app HTTP server listens on.
    pub port: u16,
    /// Optional display title for the portal home page.
    pub title: String,
}

/// Mount table for this node. Not fabric-synced. When `load` is used, the
/// table is also written to `app_web.toml` in the data directory.
#[derive(Default)]
pub struct AppWebRegistry {
    inner: Mutex<HashMap<String, AppWebMount>>,
    path: Option<PathBuf>,
}

#[derive(Default, Serialize, Deserialize)]
struct AppWebFile {
    #[serde(default)]
    mounts: Vec<AppWebMount>,
}

impl AppWebRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load `data_dir/app_web.toml`. A missing file is an empty table. A file
    /// that cannot be read or parsed is logged and ignored.
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("app_web.toml");
        let registry = Self {
            inner: Mutex::new(HashMap::new()),
            path: Some(path.clone()),
        };
        if !path.is_file() {
            return registry;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                log::error!("[app-web] app_web.toml unreadable: {err}");
                return registry;
            }
        };
        let file: AppWebFile = match toml::from_str(&text) {
            Ok(file) => file,
            Err(err) => {
                log::error!("[app-web] app_web.toml ignored: {err}");
                return registry;
            }
        };
        let mut table = registry.inner.lock().unwrap_or_else(|e| e.into_inner());
        for mount in file.mounts {
            if validate_slug(&mount.slug).is_ok() && mount.port != 0 {
                table.insert(mount.slug.clone(), mount);
            }
        }
        drop(table);
        registry
    }

    /// Insert or replace a mount. `slug` must already be validated.
    pub fn upsert(&self, mount: AppWebMount) {
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.insert(mount.slug.clone(), mount);
        }
        self.save();
    }

    pub fn remove(&self, slug: &str) -> bool {
        let removed = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.remove(slug).is_some()
        };
        if removed {
            self.save();
        }
        removed
    }

    /// Remove mounts whose loopback port refuses a connection, and save when
    /// the table changed. A listening socket accepts this connect.
    pub fn drop_unreachable(&self) -> usize {
        let live: Vec<(String, u16)> = {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.values().map(|m| (m.slug.clone(), m.port)).collect()
        };
        let dead: Vec<String> = live
            .into_iter()
            .filter(|(_, port)| !loopback_accepts(*port))
            .map(|(slug, _)| slug)
            .collect();
        if dead.is_empty() {
            return 0;
        }
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            for slug in &dead {
                g.remove(slug);
            }
        }
        self.save();
        dead.len()
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let file = AppWebFile { mounts: self.list() };
        let text = match toml::to_string(&file) {
            Ok(text) => text,
            Err(err) => {
                log::error!("[app-web] could not encode app_web.toml: {err}");
                return;
            }
        };
        if let Err(err) = super::writer::write_atomic(path, &text) {
            log::error!("[app-web] could not write {}: {err}", path.display());
        }
    }

    pub fn get(&self, slug: &str) -> Option<AppWebMount> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.get(slug).cloned()
    }

    pub fn list(&self) -> Vec<AppWebMount> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<_> = g.values().cloned().collect();
        v.sort_by(|a, b| a.slug.cmp(&b.slug));
        v
    }
}

fn loopback_accepts(port: u16) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

/// True if `addr` is IPv4/IPv6 loopback (app registration source check).
pub fn is_loopback_addr(addr: SocketAddr) -> bool {
    match addr {
        SocketAddr::V4(v4) => v4.ip().is_loopback(),
        SocketAddr::V6(v6) => v6.ip().is_loopback(),
    }
}

/// Validate slug: 1–32 chars, `[a-z0-9]` with internal single hyphens.
pub fn validate_slug(slug: &str) -> Result<(), &'static str> {
    if slug.is_empty() || slug.len() > 32 {
        return Err("slug_len");
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        return Err("slug_hyphen");
    }
    let mut prev_hyphen = false;
    for c in slug.chars() {
        match c {
            'a'..='z' | '0'..='9' => prev_hyphen = false,
            '-' if !prev_hyphen => prev_hyphen = true,
            _ => return Err("slug_chars"),
        }
    }
    Ok(())
}

/// Split `/apps/<slug>` or `/apps/<slug>/rest` → `(slug, path_for_upstream)`.
/// Upstream path always starts with `/`.
pub fn parse_apps_path(path: &str) -> Option<(&str, String)> {
    let rest = path.strip_prefix("/apps/")?;
    if rest.is_empty() {
        return None;
    }
    let (slug, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if slug.is_empty() || validate_slug(slug).is_err() {
        return None;
    }
    let upstream = if tail.is_empty() {
        "/".to_string()
    } else {
        tail.to_string()
    };
    Some((slug, upstream))
}

/// The portal draws its own header for the app's main page. `?raw=1` and every
/// other path or method are the app document, its assets, and its form posts.
pub fn is_app_shell_request(method: &str, upstream_path: &str, query: &str) -> bool {
    method == "GET"
        && upstream_path == "/"
        && !query.split('&').any(|part| part == "raw=1")
}

/// Proxy one HTTP request to `127.0.0.1:port` and write the response to `client`.
///
/// Uses `Connection: close` and a short timeout. Not a full HTTP/1.1 proxy
/// (no hop-by-hop filtering beyond Host rewrite); enough for app UIs on loopback.
pub fn proxy_to_loopback(
    client: &mut TcpStream,
    method: &str,
    upstream_path: &str,
    query: &str,
    content_type: &str,
    body: &[u8],
    port: u16,
) -> Result<(), String> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut upstream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("connect {addr}: {e}"))?;
    upstream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();
    upstream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok();

    let path_q = if query.is_empty() {
        upstream_path.to_string()
    } else {
        format!("{upstream_path}?{query}")
    };

    let type_header = if content_type.is_empty() {
        String::new()
    } else {
        format!("Content-Type: {content_type}\r\n")
    };
    let req = format!(
        "{method} {path_q} HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         {type_header}\
         Connection: close\r\n\
         Content-Length: {}\r\n\
         \r\n",
        body.len()
    );
    // Avoid huge allocations when body is empty.
    let mut req_bytes = req.into_bytes();
    req_bytes.extend_from_slice(body);
    upstream
        .write_all(&req_bytes)
        .map_err(|e| format!("write upstream: {e}"))?;

    let mut buf = [0u8; 8192];
    loop {
        match upstream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                client
                    .write_all(&buf[..n])
                    .map_err(|e| format!("write client: {e}"))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(format!("read upstream: {e}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn slug_validation() {
        assert!(validate_slug("filesync").is_ok());
        assert!(validate_slug("a").is_ok());
        assert!(validate_slug("chat-v2").is_ok());
        assert!(validate_slug("").is_err());
        assert!(validate_slug("-bad").is_err());
        assert!(validate_slug("Bad").is_err());
        assert!(validate_slug("has_under").is_err());
        assert!(validate_slug(&"a".repeat(33)).is_err());
    }

    #[test]
    fn parse_apps_path_ok() {
        let (s, p) = parse_apps_path("/apps/filesync").unwrap();
        assert_eq!(s, "filesync");
        assert_eq!(p, "/");
        let (s, p) = parse_apps_path("/apps/filesync/").unwrap();
        assert_eq!(s, "filesync");
        assert_eq!(p, "/");
        // Query string is not part of `path` (split earlier in the HTTP parser).
        let (s, p) = parse_apps_path("/apps/filesync/tree").unwrap();
        assert_eq!(s, "filesync");
        assert_eq!(p, "/tree");
    }

    #[test]
    fn parse_apps_path_rejects() {
        assert!(is_app_shell_request("GET", "/", ""));
        assert!(!is_app_shell_request("GET", "/", "raw=1"));
        assert!(!is_app_shell_request("GET", "/", "raw=1&x=2"));
        assert!(!is_app_shell_request("POST", "/", ""));
        assert!(!is_app_shell_request("GET", "/tree", ""));
        assert!(parse_apps_path("/apps/").is_none());
        assert!(parse_apps_path("/apps").is_none());
        assert!(parse_apps_path("/config").is_none());
        assert!(parse_apps_path("/apps/Bad").is_none());
    }

    #[test]
    fn registry_upsert_list_remove() {
        let r = AppWebRegistry::new();
        r.upsert(AppWebMount {
            slug: "chat".into(),
            port: 9001,
            title: "Chat".into(),
        });
        r.upsert(AppWebMount {
            slug: "filesync".into(),
            port: 9002,
            title: "Files".into(),
        });
        assert_eq!(r.list().len(), 2);
        assert_eq!(r.get("chat").unwrap().port, 9001);
        assert!(r.remove("chat"));
        assert!(r.get("chat").is_none());
        assert_eq!(r.list().len(), 1);
    }

    #[test]
    fn registry_persists_and_drops_a_closed_port() {
        let dir = std::env::temp_dir().join(format!("pnet-app-web-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let registry = AppWebRegistry::load(&dir);
        registry.upsert(AppWebMount {
            slug: "lan".into(),
            port: open,
            title: "pNet LAN".into(),
        });
        registry.upsert(AppWebMount {
            slug: "gone".into(),
            port: 1,
            title: "Gone".into(),
        });
        assert_eq!(registry.drop_unreachable(), 1);
        let loaded = AppWebRegistry::load(&dir);
        let mounts = loaded.list();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].slug, "lan");
        assert_eq!(mounts[0].port, open);
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proxy_roundtrip_local_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&mut s);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("GET /hello "));
            // drain headers
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line == "\n" || line.is_empty() {
                    break;
                }
            }
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
            s.write_all(resp).unwrap();
        });

        let client_l = TcpListener::bind("127.0.0.1:0").unwrap();
        // Simulate client side of portal: connect as the "browser" end
        let server_addr = client_l.local_addr().unwrap();
        let mut client = TcpStream::connect(server_addr).unwrap();
        // Accept on another thread so proxy can write to client while we read
        let join = thread::spawn(move || {
            let (mut portal_half, _) = client_l.accept().unwrap();
            proxy_to_loopback(&mut portal_half, "GET", "/hello", "", "", b"", port).unwrap();
        });
        // Wait for proxy to finish writing
        join.join().unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut out = Vec::new();
        client.read_to_end(&mut out).ok();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("hello"), "got: {text:?}");
    }
}
