//! Local app UDP API exposure policy and rate limits.
//!
//! App control ops (register / update / get-data / send) are intended for
//! co-located apps on the same host. Default: only accept them from loopback.
//! Opt in to remote sources with `PNET_APP_API_REMOTE=1` (required when the
//! app runs in another container). See `descriptions/communication methods.md`.
//!
//! Register and send are additionally rate-limited (token bucket per source
//! IP, and per app token for send).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

// ── Source policy ─────────────────────────────────────────────────────────────

/// True when `src` is a loopback address (IPv4 or IPv6, including IPv4-mapped).
pub fn is_loopback_src(src: SocketAddr) -> bool {
    match src.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip
                    .to_ipv4_mapped()
                    .map(|v4| v4.is_loopback())
                    .unwrap_or(false)
        }
    }
}

/// Parse the raw env value for remote app-API access.
///
/// `true` when set to `1` / `true` / `yes` (case-insensitive). Anything else
/// (including unset) is `false` — loopback-only.
pub fn parse_app_api_remote(raw: Option<&str>) -> bool {
    raw.map(|s| {
        let t = s.trim();
        t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
    })
    .unwrap_or(false)
}

/// Whether non-loopback sources may use local app ops (0x00–0x03).
pub fn app_api_remote_enabled() -> bool {
    parse_app_api_remote(std::env::var("PNET_APP_API_REMOTE").ok().as_deref())
}

/// Accept this source for local app control/data ops?
pub fn app_api_source_allowed(src: SocketAddr) -> bool {
    is_loopback_src(src) || app_api_remote_enabled()
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

/// Token-bucket parameters for one class of app API traffic.
#[derive(Clone, Copy, Debug)]
pub struct BucketConfig {
    pub capacity: f64,
    pub refill_per_sec: f64,
}

/// Defaults: register is rare; send is chatty but still capped.
pub const REGISTER_LIMIT: BucketConfig = BucketConfig {
    capacity: 10.0,
    refill_per_sec: 2.0,
};
pub const SEND_LIMIT: BucketConfig = BucketConfig {
    capacity: 200.0,
    refill_per_sec: 100.0,
};

struct Bucket {
    tokens: f64,
    last: Instant,
    config: BucketConfig,
}

impl Bucket {
    fn new(config: BucketConfig) -> Self {
        Self {
            tokens: config.capacity,
            last: Instant::now(),
            config,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.config.refill_per_sec)
                .min(self.config.capacity);
            self.last = now;
        }
    }

    /// Consume one token if available.
    fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shared rate-limit state for the local app API.
#[derive(Default)]
pub struct AppRateLimiter {
    register_by_ip: HashMap<IpAddr, Bucket>,
    send_by_ip: HashMap<IpAddr, Bucket>,
    send_by_token: HashMap<[u8; 16], Bucket>,
    /// Rough GC counter: prune idle buckets occasionally.
    ops_since_gc: u32,
}

impl AppRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow one `app_register` from `src`?
    pub fn allow_register(&mut self, src: SocketAddr) -> bool {
        let now = Instant::now();
        let ip = src.ip();
        let ok = self
            .register_by_ip
            .entry(ip)
            .or_insert_with(|| Bucket::new(REGISTER_LIMIT))
            .try_take(now);
        self.maybe_gc(now);
        ok
    }

    /// Allow one `app_send_packet` from `src` (and optional token)?
    ///
    /// Both the source-IP bucket and the token bucket (when `token` is set)
    /// must have capacity — limits abuse by one IP and by one app token.
    pub fn allow_send(&mut self, src: SocketAddr, token: Option<[u8; 16]>) -> bool {
        let now = Instant::now();
        let ip = src.ip();
        let ip_ok = self
            .send_by_ip
            .entry(ip)
            .or_insert_with(|| Bucket::new(SEND_LIMIT))
            .try_take(now);
        if !ip_ok {
            self.maybe_gc(now);
            return false;
        }
        if let Some(tok) = token {
            let tok_ok = self
                .send_by_token
                .entry(tok)
                .or_insert_with(|| Bucket::new(SEND_LIMIT))
                .try_take(now);
            self.maybe_gc(now);
            return tok_ok;
        }
        self.maybe_gc(now);
        true
    }

    fn maybe_gc(&mut self, now: Instant) {
        self.ops_since_gc = self.ops_since_gc.wrapping_add(1);
        if self.ops_since_gc % 256 != 0 {
            return;
        }
        // Drop buckets that are full and idle for > 60s (no recent traffic).
        const IDLE: std::time::Duration = std::time::Duration::from_secs(60);
        self.register_by_ip
            .retain(|_, b| now.saturating_duration_since(b.last) < IDLE || b.tokens < b.config.capacity);
        self.send_by_ip
            .retain(|_, b| now.saturating_duration_since(b.last) < IDLE || b.tokens < b.config.capacity);
        self.send_by_token
            .retain(|_, b| now.saturating_duration_since(b.last) < IDLE || b.tokens < b.config.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn loopback_v4_and_v6_detected() {
        let v4: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let v6: SocketAddr = "[::1]:9".parse().unwrap();
        let lan: SocketAddr = "192.168.1.5:9".parse().unwrap();
        assert!(is_loopback_src(v4));
        assert!(is_loopback_src(v6));
        assert!(!is_loopback_src(lan));
    }

    #[test]
    fn parse_remote_flag() {
        assert!(!parse_app_api_remote(None));
        assert!(!parse_app_api_remote(Some("")));
        assert!(!parse_app_api_remote(Some("0")));
        assert!(parse_app_api_remote(Some("1")));
        assert!(parse_app_api_remote(Some("true")));
        assert!(parse_app_api_remote(Some("YES")));
    }

    #[test]
    fn register_bucket_exhausts() {
        let mut lim = AppRateLimiter::new();
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000));
        let cap = REGISTER_LIMIT.capacity as u32;
        for _ in 0..cap {
            assert!(lim.allow_register(src));
        }
        assert!(!lim.allow_register(src));
        // Different IP has its own bucket.
        let other = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 40000));
        assert!(lim.allow_register(other));
    }

    #[test]
    fn send_limited_by_token() {
        let mut lim = AppRateLimiter::new();
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40001));
        let token = [0xABu8; 16];
        let cap = SEND_LIMIT.capacity as u32;
        for _ in 0..cap {
            assert!(lim.allow_send(src, Some(token)));
        }
        assert!(!lim.allow_send(src, Some(token)));
        // Different token still allowed (IP has capacity left after token-only drain... wait)
        // Actually IP bucket was also drained to zero. Use a fresh IP for the other token.
        let src2 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 3), 40001));
        assert!(lim.allow_send(src2, Some([0xCDu8; 16])));
    }
}
