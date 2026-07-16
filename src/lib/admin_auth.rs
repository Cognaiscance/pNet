//! Admin UI password hashing and in-memory session tokens.
//!
//! Password hashes are node-local (never synced). Sessions live only in process
//! memory and are identified by an HttpOnly cookie (`pnet_session`).
//!
//! ## CSRF policy
//!
//! Session cookies are issued with `SameSite=Strict` so browsers do not attach
//! them to cross-site POSTs. That is the primary CSRF defence for remote admin
//! (`PNET_HTTP_BIND` non-loopback). When a browser also sends `Origin` or
//! `Referer`, handlers reject the POST unless the host matches the `Host`
//! header. Clients that send neither (curl, scripts) are allowed; they must
//! still present a valid session cookie when auth is required.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::data_models::{generate_uuid, serde_bytes_32};

/// Cookie name used for the admin session.
pub const SESSION_COOKIE: &str = "pnet_session";

/// How long a session remains valid after login / setup.
pub const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

/// Minimum password length accepted by setup / set-password / change paths.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Response header carrying a freshly minted invitation code (for harnesses).
/// The human UI uses a one-shot flash; this header avoids putting the secret
/// in a redirect URL / query string / browser history.
pub const INVITE_CODE_HEADER: &str = "X-Pnet-Invitation-Code";

/// One-shot UI message after a state-changing POST (consumed on next GET).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiFlash {
    /// Device invitation code to display once.
    DeviceCode(String),
    /// Contact invitation code to display once.
    ContactCode(String),
}

/// Ephemeral session map: session id (32-char hex) → expiry instant,
/// plus per-session one-shot flash messages for the admin UI.
#[derive(Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Instant>>,
    flashes: Mutex<HashMap<String, UiFlash>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a new session; returns the opaque session id (hex).
    pub fn create(&self) -> String {
        let id = hex16(&generate_uuid());
        let expires = Instant::now() + SESSION_TTL;
        self.inner.lock().unwrap().insert(id.clone(), expires);
        id
    }

    /// True if `id` is a known, non-expired session. Expired entries are dropped.
    pub fn is_valid(&self, id: &str) -> bool {
        if id.is_empty() {
            return false;
        }
        let mut map = self.inner.lock().unwrap();
        match map.get(id) {
            Some(exp) if *exp > Instant::now() => true,
            Some(_) => {
                map.remove(id);
                false
            }
            None => false,
        }
    }

    pub fn revoke(&self, id: &str) {
        self.inner.lock().unwrap().remove(id);
        self.flashes.lock().unwrap().remove(id);
    }

    /// Store a one-shot flash for this session (overwrites any previous).
    pub fn set_flash(&self, session_id: &str, flash: UiFlash) {
        if session_id.is_empty() {
            return;
        }
        self.flashes
            .lock()
            .unwrap()
            .insert(session_id.to_string(), flash);
    }

    /// Take and clear the flash for this session, if any.
    pub fn take_flash(&self, session_id: &str) -> Option<UiFlash> {
        if session_id.is_empty() {
            return None;
        }
        self.flashes.lock().unwrap().remove(session_id)
    }
}

/// Hash a password for durable storage. Format: `v1$<salt_hex>$<hash_hex>`.
///
/// Uses SHA-256 with a random 16-byte salt and a fixed iteration stretch.
/// Node-local admin only — not a substitute for a full argon2 migration later.
pub fn hash_password(password: &str) -> String {
    let salt = generate_uuid();
    let digest = stretch(password.as_bytes(), &salt);
    format!(
        "v1${}${}",
        hex16(&salt),
        serde_bytes_32::hex(&digest)
    )
}

/// Verify `password` against a stored hash from [`hash_password`].
pub fn verify_password(password: &str, stored: &str) -> bool {
    let Some((salt, expected)) = parse_stored(stored) else {
        return false;
    };
    let digest = stretch(password.as_bytes(), &salt);
    // Constant-time-ish compare for equal-length digests.
    if digest.len() != expected.len() {
        return false;
    }
    digest.iter().zip(expected.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

fn stretch(password: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    // 100k rounds is enough to slow offline guessing for a local admin password
    // without making setup feel heavy on modest hardware.
    const ROUNDS: u32 = 100_000;
    let mut acc = {
        let mut h = Sha256::new();
        h.update(b"pnet-admin-v1");
        h.update(salt);
        h.update(password);
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    };
    for _ in 0..ROUNDS {
        let mut h = Sha256::new();
        h.update(&acc);
        h.update(password);
        h.update(salt);
        let out = h.finalize();
        acc.copy_from_slice(&out);
    }
    acc
}

fn parse_stored(stored: &str) -> Option<([u8; 16], [u8; 32])> {
    let mut parts = stored.splitn(3, '$');
    let ver = parts.next()?;
    let salt_hex = parts.next()?;
    let hash_hex = parts.next()?;
    if ver != "v1" || salt_hex.len() != 32 || hash_hex.len() != 64 {
        return None;
    }
    let salt = unhex16(salt_hex)?;
    let hash = {
        let mut out = [0u8; 32];
        for (i, chunk) in hash_hex.as_bytes().chunks(2).enumerate() {
            let hi = nibble(chunk[0])?;
            let lo = nibble(chunk[1])?;
            out[i] = (hi << 4) | lo;
        }
        out
    };
    Some((salt, hash))
}

fn hex16(bytes: &[u8; 16]) -> String {
    const H: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

fn unhex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
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

/// Pull the `pnet_session` value out of a raw `Cookie` header (may contain several cookies).
pub fn session_id_from_cookie_header(cookie_header: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix(SESSION_COOKIE) {
            let val = val.strip_prefix('=').unwrap_or(val);
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// `Set-Cookie` header value that installs a session.
///
/// `SameSite=Strict` is intentional CSRF mitigation: the cookie is not sent
/// on cross-site requests (including cross-site form POSTs).
pub fn set_session_cookie_header(session_id: &str) -> String {
    format!(
        "{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        SESSION_TTL.as_secs()
    )
}

/// `Set-Cookie` header value that clears the session cookie.
pub fn clear_session_cookie_header() -> String {
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// Validate password length / non-empty confirm match for form handlers.
pub fn validate_new_password(password: &str, confirm: &str) -> Result<(), &'static str> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err("password_short");
    }
    if password != confirm {
        return Err("password_mismatch");
    }
    Ok(())
}

/// Extract host[:port] from a `Host` header or an absolute URL (`Origin`/`Referer`).
pub fn authority_host(value: &str) -> Option<&str> {
    let v = value.trim();
    if v.is_empty() || v == "null" {
        return None;
    }
    let rest = if let Some(r) = v.strip_prefix("https://") {
        r
    } else if let Some(r) = v.strip_prefix("http://") {
        r
    } else {
        // Host header form (no scheme).
        return Some(v.split('/').next().unwrap_or(v));
    };
    // Drop path/query from Origin/Referer.
    let hostport = rest.split('/').next().unwrap_or(rest);
    if hostport.is_empty() {
        None
    } else {
        Some(hostport)
    }
}

/// CSRF check for admin POSTs.
///
/// * Primary: session cookie is `SameSite=Strict` (browser will not send it
///   cross-site).
/// * Secondary: if `Origin` or `Referer` is present, its host must match `Host`.
/// * If neither Origin nor Referer is sent (typical for curl/scripts), allow.
pub fn csrf_post_ok(host: &str, origin: &str, referer: &str) -> bool {
    let Some(expected) = authority_host(host) else {
        // No Host header — rare; allow so we do not brick odd clients.
        return true;
    };
    if let Some(o) = authority_host(origin) {
        return o.eq_ignore_ascii_case(expected);
    }
    if let Some(r) = authority_host(referer) {
        return r.eq_ignore_ascii_case(expected);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hash_password("correct horse battery");
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong password here", &h));
    }

    #[test]
    fn different_salts_different_hashes() {
        let a = hash_password("same-password-ok");
        let b = hash_password("same-password-ok");
        assert_ne!(a, b);
        assert!(verify_password("same-password-ok", &a));
        assert!(verify_password("same-password-ok", &b));
    }

    #[test]
    fn session_store_create_valid_revoke() {
        let store = SessionStore::new();
        let id = store.create();
        assert!(store.is_valid(&id));
        store.revoke(&id);
        assert!(!store.is_valid(&id));
        assert!(!store.is_valid(""));
        assert!(!store.is_valid("deadbeef"));
    }

    #[test]
    fn flash_set_take_once() {
        let store = SessionStore::new();
        let id = store.create();
        store.set_flash(&id, UiFlash::DeviceCode("abc".into()));
        assert_eq!(
            store.take_flash(&id),
            Some(UiFlash::DeviceCode("abc".into()))
        );
        assert_eq!(store.take_flash(&id), None);
    }

    #[test]
    fn revoke_clears_flash() {
        let store = SessionStore::new();
        let id = store.create();
        store.set_flash(&id, UiFlash::ContactCode("xyz".into()));
        store.revoke(&id);
        assert_eq!(store.take_flash(&id), None);
    }

    #[test]
    fn parse_session_cookie_among_others() {
        let h = "foo=bar; pnet_session=abc123; other=1";
        assert_eq!(session_id_from_cookie_header(h).as_deref(), Some("abc123"));
        assert!(session_id_from_cookie_header("nope=1").is_none());
    }

    #[test]
    fn validate_new_password_rules() {
        assert_eq!(validate_new_password("short", "short"), Err("password_short"));
        assert_eq!(
            validate_new_password("longenough", "different1"),
            Err("password_mismatch")
        );
        assert!(validate_new_password("longenough", "longenough").is_ok());
    }

    #[test]
    fn authority_host_from_host_and_urls() {
        assert_eq!(authority_host("localhost:8801"), Some("localhost:8801"));
        assert_eq!(
            authority_host("http://localhost:8801/path"),
            Some("localhost:8801")
        );
        assert_eq!(
            authority_host("https://admin.example/"),
            Some("admin.example")
        );
        assert_eq!(authority_host(""), None);
        assert_eq!(authority_host("null"), None);
    }

    #[test]
    fn csrf_post_ok_matches_origin_and_allows_missing() {
        assert!(csrf_post_ok("localhost:8801", "", ""));
        assert!(csrf_post_ok(
            "localhost:8801",
            "http://localhost:8801",
            ""
        ));
        assert!(csrf_post_ok(
            "localhost:8801",
            "",
            "http://localhost:8801/invitations"
        ));
        assert!(!csrf_post_ok(
            "localhost:8801",
            "http://evil.example",
            ""
        ));
        assert!(!csrf_post_ok(
            "localhost:8801",
            "",
            "https://evil.example/x"
        ));
    }

    #[test]
    fn session_cookie_is_samesite_strict() {
        let h = set_session_cookie_header("deadbeef");
        assert!(h.contains("SameSite=Strict"));
        assert!(h.contains("HttpOnly"));
        let c = clear_session_cookie_header();
        assert!(c.contains("SameSite=Strict"));
    }
}
