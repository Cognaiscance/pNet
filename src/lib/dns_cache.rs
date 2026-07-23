//! Host-name resolution cache for the fabric.
//!
//! Goal (§5.3): keep blocking OS DNS off the send/routing hot path.
//!
//! * **Hot path** ([`DnsCache::lookup`]): cache only (plus IPv4 literals, which
//!   never need DNS).
//! * **Maintain / poll / bootstrap** ([`DnsCache::resolve`]): may call the OS
//!   resolver and refresh the cache when the entry is missing or expired.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::time::{Duration, Instant};

/// How long a successful resolve stays valid.
pub const DNS_POSITIVE_TTL: Duration = Duration::from_secs(60);

/// How long a failed resolve is remembered (avoids hammering DNS on bad names).
pub const DNS_NEGATIVE_TTL: Duration = Duration::from_secs(15);

struct CacheEntry {
    /// `None` means negative cache (resolve failed).
    addr: Option<SocketAddrV4>,
    expires: Instant,
}

/// In-memory host → IPv4 cache shared by workers via `WorkerContext`.
#[derive(Default)]
pub struct DnsCache {
    map: HashMap<String, CacheEntry>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Cache-only lookup. Never blocks on DNS.
    ///
    /// IPv4 literals (with optional port) always parse without the map.
    /// Hostnames return a cached address only while the entry is unexpired.
    pub fn lookup(&self, entry: &str) -> Option<SocketAddrV4> {
        if let Some(lit) = parse_ipv4_literal(entry) {
            return Some(lit);
        }
        let key = normalize_key(entry)?;
        let now = Instant::now();
        match self.map.get(&key) {
            Some(e) if e.expires > now => e.addr,
            _ => None,
        }
    }

    /// Resolve via OS if missing or expired; update the cache. Suitable for
    /// maintain / poll / one-shot bootstrap paths.
    pub fn resolve(&mut self, entry: &str) -> Option<SocketAddrV4> {
        if let Some(lit) = parse_ipv4_literal(entry) {
            return Some(lit);
        }
        let key = normalize_key(entry)?;
        let now = Instant::now();
        if let Some(e) = self.map.get(&key) {
            if e.expires > now {
                return e.addr;
            }
        }
        let addr = resolve_host_uncached(entry);
        let ttl = if addr.is_some() {
            DNS_POSITIVE_TTL
        } else {
            DNS_NEGATIVE_TTL
        };
        self.map.insert(
            key,
            CacheEntry {
                addr,
                expires: now + ttl,
            },
        );
        addr
    }

    /// Insert a positive mapping (tests / forced warm).
    #[cfg(test)]
    pub fn insert_for_test(&mut self, entry: &str, addr: SocketAddrV4, ttl: Duration) {
        if let Some(key) = normalize_key(entry) {
            self.map.insert(
                key,
                CacheEntry {
                    addr: Some(addr),
                    expires: Instant::now() + ttl,
                },
            );
        }
    }
}

/// Trim and require non-empty. Key is the full host entry including port suffix
/// when present, so `sg.example` and `sg.example:9000` stay distinct.
fn normalize_key(entry: &str) -> Option<String> {
    let entry = entry.trim();
    if entry.is_empty() {
        None
    } else {
        Some(entry.to_string())
    }
}

/// Parse `a.b.c.d` or `a.b.c.d:port` without DNS. Default port 7777.
pub(crate) fn parse_ipv4_literal(entry: &str) -> Option<SocketAddrV4> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    if let Ok(addr) = entry.parse::<SocketAddrV4>() {
        return Some(addr);
    }
    // "1.2.3.4" without port
    if let Ok(ip) = entry.parse::<std::net::Ipv4Addr>() {
        return Some(SocketAddrV4::new(ip, 7777));
    }
    None
}

/// Blocking OS resolve (no cache). Prefer [`DnsCache::resolve`] / [`DnsCache::lookup`].
pub(crate) fn resolve_host_uncached(entry: &str) -> Option<SocketAddrV4> {
    if let Some(lit) = parse_ipv4_literal(entry) {
        return Some(lit);
    }

    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }

    let (host_part, port) = match entry.rfind(':') {
        Some(pos) => {
            // Avoid treating IPv6-style nonsense; we only support hostname:port.
            let port: u16 = entry[pos + 1..].parse().ok()?;
            (&entry[..pos], port)
        }
        None => (entry, 7777u16),
    };

    if host_part.is_empty() {
        return None;
    }

    let addr_str = format!("{host_part}:{port}");
    addr_str.to_socket_addrs().ok()?.find_map(|a| match a {
        SocketAddr::V4(v4) => Some(v4),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn literal_lookup_needs_no_cache() {
        let cache = DnsCache::new();
        let a = cache.lookup("127.0.0.1:9001").unwrap();
        assert_eq!(*a.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(a.port(), 9001);
        let b = cache.lookup("10.0.0.1").unwrap();
        assert_eq!(b.port(), 7777);
    }

    #[test]
    fn hostname_lookup_misses_until_warmed() {
        let mut cache = DnsCache::new();
        assert!(cache.lookup("unwarmed.example:7777").is_none());
        // Literals resolve without map; lookup matches.
        let resolved = cache.resolve("127.0.0.1:1234");
        assert!(resolved.is_some());
        assert_eq!(cache.lookup("127.0.0.1:1234"), resolved);
    }

    #[test]
    fn insert_for_test_serves_lookup() {
        let mut cache = DnsCache::new();
        let addr = SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 7777);
        cache.insert_for_test("peer.example:7777", addr, Duration::from_secs(60));
        assert_eq!(cache.lookup("peer.example:7777"), Some(addr));
        // Expired / missing host name without insert → None
        assert!(cache.lookup("other.example").is_none());
    }

    #[test]
    fn negative_cache_returns_none_from_lookup() {
        let mut cache = DnsCache::new();
        let miss = cache.resolve("this.name.definitely.does.not.exist.invalid");
        assert!(miss.is_none());
        assert!(cache.lookup("this.name.definitely.does.not.exist.invalid").is_none());
        // Entry still present (negative) so we don't re-hit DNS on resolve while fresh.
        assert_eq!(cache.len(), 1);
        assert!(cache.resolve("this.name.definitely.does.not.exist.invalid").is_none());
    }
}
