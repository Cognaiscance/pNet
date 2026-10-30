//! Memory of addresses an SG has seen, and later the direct-path probes.
//!
//! Nothing here is written into the directory snapshot. See
//! `descriptions/direct-path.md`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// What `note_observed` did with this datagram's source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observe {
    /// First time this device has been seen.
    New,
    /// Same address as the one already stored.
    Same,
    /// A different address replaced the stored one.
    Replaced,
}

/// One device's observed UDP source, plus the direct-path flags filled in
/// by later steps. Those flags stay down until a probe answer.
#[derive(Debug, Clone)]
pub struct PeerPath {
    pub observed: SocketAddr,
    pub changes: Vec<Instant>,
    pub unstable: bool,
    pub lan_up_until: Option<Instant>,
    pub punch_up_until: Option<Instant>,
    pub lan_probe_sent: bool,
    pub punch_probe_sent: bool,
}

/// In-memory book shared by workers. Not persisted.
#[derive(Debug, Default)]
pub struct DirectBook {
    peers: HashMap<[u8; 16], PeerPath>,
    // Filled in when a node records its own address changes (later step).
    #[allow(dead_code)]
    self_unstable: bool,
    #[allow(dead_code)]
    self_changes: Vec<Instant>,
}

impl DirectBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the UDP source the SG saw for `device`.
    /// A repeat of the same address is not an address change.
    pub fn note_observed(&mut self, device: [u8; 16], addr: SocketAddr, now: Instant) -> Observe {
        match self.peers.get_mut(&device) {
            None => {
                self.peers.insert(
                    device,
                    PeerPath {
                        observed: addr,
                        changes: vec![now],
                        unstable: false,
                        lan_up_until: None,
                        punch_up_until: None,
                        lan_probe_sent: false,
                        punch_probe_sent: false,
                    },
                );
                Observe::New
            }
            Some(peer) if peer.observed == addr => Observe::Same,
            Some(peer) => {
                peer.observed = addr;
                peer.changes.push(now);
                if peer.changes.len() > 3 {
                    peer.changes.drain(0..peer.changes.len() - 3);
                }
                // A new address drops any direct path that was aimed at the old one.
                peer.lan_up_until = None;
                peer.punch_up_until = None;
                peer.lan_probe_sent = false;
                peer.punch_probe_sent = false;
                Observe::Replaced
            }
        }
    }

    pub fn observed(&self, device: &[u8; 16]) -> Option<SocketAddr> {
        self.peers.get(device).map(|p| p.observed)
    }

    pub fn peer(&self, device: &[u8; 16]) -> Option<&PeerPath> {
        self.peers.get(device)
    }

    pub fn peer_mut(&mut self, device: &[u8; 16]) -> Option<&mut PeerPath> {
        self.peers.get_mut(device)
    }
}

/// Body an SG sends so the other side learns `{device}` was seen at `addr`.
/// Layout: device uuid (16) || ipv4 (4) || port (2). 22 bytes.
pub fn encode_observation(device: &[u8; 16], addr: SocketAddr) -> Option<[u8; 22]> {
    let SocketAddr::V4(v4) = addr else {
        return None;
    };
    let mut out = [0u8; 22];
    out[..16].copy_from_slice(device);
    out[16..20].copy_from_slice(&v4.ip().octets());
    out[20..22].copy_from_slice(&v4.port().to_be_bytes());
    Some(out)
}

pub fn decode_observation(body: &[u8]) -> Option<([u8; 16], SocketAddr)> {
    if body.len() < 22 {
        return None;
    }
    let mut device = [0u8; 16];
    device.copy_from_slice(&body[..16]);
    let ip = std::net::Ipv4Addr::new(body[16], body[17], body[18], body[19]);
    let port = u16::from_be_bytes([body[20], body[21]]);
    Some((device, SocketAddr::from((ip, port))))
}

/// How long a direct probe stays up after the last answer.
/// Both addresses are private and sit in the same RFC1918 block.
pub fn same_lan(a: SocketAddr, b: SocketAddr) -> bool {
    let (Some(ao), Some(bo)) = (v4_octets(a), v4_octets(b)) else {
        return false;
    };
    match (private_block(ao), private_block(bo)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn v4_octets(addr: SocketAddr) -> Option<[u8; 4]> {
    match addr {
        SocketAddr::V4(v) => Some(v.ip().octets()),
        SocketAddr::V6(_) => None,
    }
}

/// 1 = 10/8, 2 = 172.16/12, 3 = 192.168/16.
fn private_block(o: [u8; 4]) -> Option<u8> {
    if o[0] == 10 {
        Some(1)
    } else if o[0] == 172 && (o[1] & 0xf0) == 16 {
        Some(2)
    } else if o[0] == 192 && o[1] == 168 {
        Some(3)
    } else {
        None
    }
}

impl DirectBook {
    /// Start a LAN probe when both observed addresses share a private range.
    /// Returns false when the ranges do not match. Does not mark the path up.
    pub fn begin_lan_probe(&mut self, device: &[u8; 16], local_observed: SocketAddr) -> bool {
        let Some(peer) = self.peers.get_mut(device) else {
            return false;
        };
        if !same_lan(peer.observed, local_observed) {
            return false;
        }
        peer.lan_probe_sent = true;
        true
    }

    /// The LAN probe was answered. The path stays down until this is called.
    pub fn answer_lan(&mut self, device: &[u8; 16], now: Instant, ttl: Duration) -> bool {
        let Some(peer) = self.peers.get_mut(device) else {
            return false;
        };
        if !peer.lan_probe_sent {
            return false;
        }
        peer.lan_up_until = Some(now + ttl);
        true
    }

    pub fn lan_is_up(&self, device: &[u8; 16], now: Instant) -> bool {
        self.peers
            .get(device)
            .and_then(|p| p.lan_up_until)
            .map(|until| until > now)
            .unwrap_or(false)
    }
}

pub fn probe_ttl(cellphone: bool) -> Duration {
    if cellphone {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        format!("203.0.113.5:{port}").parse().unwrap()
    }

    #[test]
    fn observation_stores_repeats_and_replaces() {
        let mut book = DirectBook::new();
        let dev = [7u8; 16];
        let t0 = Instant::now();
        assert_eq!(book.note_observed(dev, addr(1), t0), Observe::New);
        assert_eq!(book.observed(&dev), Some(addr(1)));
        assert_eq!(book.note_observed(dev, addr(1), t0), Observe::Same);
        assert_eq!(book.peer(&dev).unwrap().changes.len(), 1);
        assert_eq!(book.note_observed(dev, addr(2), t0), Observe::Replaced);
        assert_eq!(book.observed(&dev), Some(addr(2)));
        assert_eq!(book.peer(&dev).unwrap().changes.len(), 2);
    }

    #[test]
    fn lan_probe_only_when_ranges_match() {
        let mut book = DirectBook::new();
        let dev = [1u8; 16];
        let t0 = Instant::now();
        let lan_a: SocketAddr = "192.168.1.10:7777".parse().unwrap();
        let lan_b: SocketAddr = "192.168.1.20:7777".parse().unwrap();
        let other: SocketAddr = "10.1.1.5:7777".parse().unwrap();
        let public: SocketAddr = "203.0.113.8:7777".parse().unwrap();
        book.note_observed(dev, lan_a, t0);
        assert!(book.begin_lan_probe(&dev, lan_b));
        assert!(!book.lan_is_up(&dev, t0));
        assert!(book.answer_lan(&dev, t0, Duration::from_secs(30)));
        assert!(book.lan_is_up(&dev, t0));

        book.note_observed(dev, other, t0);
        assert!(!book.begin_lan_probe(&dev, lan_b));
        assert!(!book.lan_is_up(&dev, t0));

        book.note_observed(dev, public, t0);
        assert!(!book.begin_lan_probe(&dev, lan_b));
        assert!(!same_lan(public, lan_b));
        assert!(same_lan(lan_a, lan_b));
    }

    #[test]
    fn observation_body_round_trips() {
        let dev = [9u8; 16];
        let a = addr(7777);
        let bytes = encode_observation(&dev, a).unwrap();
        assert_eq!(decode_observation(&bytes), Some((dev, a)));
        assert!(decode_observation(&[0u8; 10]).is_none());
    }
}
