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

/// Where the next app packet goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathChoice {
    Sg,
    Lan,
    Punch,
}

/// Grade an app names on send. Missing and unknown bytes are stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grade {
    Stable,
    Fast,
    Cellphone,
}

impl Grade {
    /// `0` and any unknown byte are stable. `1` is fast. `2` is cellphone.
    pub fn from_byte(b: u8) -> Self {
        match b {
            1 => Grade::Fast,
            2 => Grade::Cellphone,
            _ => Grade::Stable,
        }
    }

    /// Historical op `0x03` has no grade byte. Op `0x09` puts one byte in
    /// front of the payload. An empty graded tail is not a packet.
    pub fn split_tail(tail: &[u8], explicit: bool) -> Option<(Grade, &[u8])> {
        if !explicit {
            return Some((Grade::Stable, tail));
        }
        let (b, rest) = tail.split_first()?;
        Some((Grade::from_byte(*b), rest))
    }

    pub fn cellphone(self) -> bool {
        matches!(self, Grade::Cellphone)
    }
}

/// Pick a path. Stable never leaves the SG. Fast and cellphone use LAN when
/// the probe is up. Punch is chosen only in a later step, when LAN is down.
pub fn choose_path(grade: Grade, lan_up: bool, punch_up: bool, peer_unstable: bool) -> PathChoice {
    if matches!(grade, Grade::Stable) {
        return PathChoice::Sg;
    }
    if grade.cellphone() && peer_unstable {
        return PathChoice::Sg;
    }
    if lan_up {
        PathChoice::Lan
    } else if punch_up {
        PathChoice::Punch
    } else {
        PathChoice::Sg
    }
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

    /// Ask this side to punch toward `peer_public`. The path stays down
    /// until `answer_punch`. A LAN that already matches is not a punch.
    pub fn begin_punch(&mut self, device: &[u8; 16], local_observed: SocketAddr) -> bool {
        let Some(peer) = self.peers.get_mut(device) else {
            return false;
        };
        if same_lan(peer.observed, local_observed) {
            return false;
        }
        peer.punch_probe_sent = true;
        true
    }

    pub fn answer_punch(&mut self, device: &[u8; 16], now: Instant, ttl: Duration) -> bool {
        let Some(peer) = self.peers.get_mut(device) else {
            return false;
        };
        if !peer.punch_probe_sent {
            return false;
        }
        peer.punch_up_until = Some(now + ttl);
        true
    }

    pub fn punch_is_up(&self, device: &[u8; 16], now: Instant) -> bool {
        self.peers
            .get(device)
            .and_then(|p| p.punch_up_until)
            .map(|until| until > now)
            .unwrap_or(false)
    }

    /// A peer reported that its address moved or its link went down.
    /// The direct path drops now, before the probe time-to-live.
    pub fn note_peer_down(&mut self, device: &[u8; 16]) {
        self.drop_direct(device);
    }

    pub fn drop_direct(&mut self, device: &[u8; 16]) {
        if let Some(peer) = self.peers.get_mut(device) {
            peer.lan_up_until = None;
            peer.punch_up_until = None;
            peer.lan_probe_sent = false;
            peer.punch_probe_sent = false;
        }
    }
}

/// One instruction the SG sends to each side: the other side's observed
/// IPv4 address. 6 bytes, ipv4 || port.
pub fn encode_punch_invite(peer_public: SocketAddr) -> Option<[u8; 6]> {
    let SocketAddr::V4(v4) = peer_public else {
        return None;
    };
    let mut out = [0u8; 6];
    out[..4].copy_from_slice(&v4.ip().octets());
    out[4..6].copy_from_slice(&v4.port().to_be_bytes());
    Some(out)
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
    fn punch_stays_down_until_answered() {
        let mut book = DirectBook::new();
        let dev = [2u8; 16];
        let t0 = Instant::now();
        let public_a: SocketAddr = "198.51.100.4:7777".parse().unwrap();
        let public_b: SocketAddr = "198.51.100.9:7777".parse().unwrap();
        let lan: SocketAddr = "192.168.0.4:7777".parse().unwrap();
        book.note_observed(dev, public_a, t0);
        let left = encode_punch_invite(public_a).unwrap();
        let right = encode_punch_invite(public_b).unwrap();
        assert_ne!(left, right);
        assert!(book.begin_punch(&dev, public_b));
        assert!(!book.punch_is_up(&dev, t0));
        assert!(book.answer_punch(&dev, t0, Duration::from_secs(30)));
        assert!(book.punch_is_up(&dev, t0));

        book.note_observed(dev, lan, t0);
        assert!(!book.begin_punch(&dev, "192.168.0.8:7777".parse().unwrap()));
        assert!(!book.punch_is_up(&dev, t0));
    }

    #[test]
    fn late_probe_goes_cold_and_a_notify_drops_sooner() {
        let mut book = DirectBook::new();
        let dev = [4u8; 16];
        let t0 = Instant::now();
        let lan_a: SocketAddr = "10.0.0.2:7777".parse().unwrap();
        let lan_b: SocketAddr = "10.0.0.3:7777".parse().unwrap();
        book.note_observed(dev, lan_a, t0);
        assert!(book.begin_lan_probe(&dev, lan_b));
        assert!(book.answer_lan(&dev, t0, Duration::from_secs(30)));
        let later = t0 + Duration::from_secs(31);
        assert!(!book.lan_is_up(&dev, later));
        assert_eq!(
            choose_path(Grade::Fast, book.lan_is_up(&dev, later), false, false),
            PathChoice::Sg
        );

        assert!(book.begin_lan_probe(&dev, lan_b));
        assert!(book.answer_lan(&dev, t0, Duration::from_secs(30)));
        assert!(book.lan_is_up(&dev, t0 + Duration::from_secs(5)));
        book.note_peer_down(&dev);
        assert!(!book.lan_is_up(&dev, t0 + Duration::from_secs(5)));
        assert_eq!(
            choose_path(Grade::Fast, false, false, false),
            PathChoice::Sg
        );
    }

    #[test]
    fn missing_or_unknown_grade_is_stable() {
        let tail = b"payload";
        assert_eq!(
            Grade::split_tail(tail, false).unwrap().0,
            Grade::Stable
        );
        assert_eq!(Grade::split_tail(tail, false).unwrap().1, tail);
        assert!(Grade::split_tail(&[], true).is_none());
        let mut graded = vec![1u8];
        graded.extend_from_slice(tail);
        let (g, p) = Grade::split_tail(&graded, true).unwrap();
        assert_eq!(g, Grade::Fast);
        assert_eq!(p, tail);
        assert_eq!(Grade::from_byte(2), Grade::Cellphone);
        assert_eq!(Grade::from_byte(9), Grade::Stable);
        assert_eq!(
            choose_path(Grade::from_byte(0), true, true, false),
            PathChoice::Sg
        );
        assert_eq!(
            choose_path(Grade::Fast, true, true, false),
            PathChoice::Lan
        );
        assert_eq!(
            choose_path(Grade::Cellphone, false, true, false),
            PathChoice::Punch
        );
    }

    #[test]
    fn punch_is_chosen_only_when_lan_is_down() {
        assert_eq!(
            choose_path(Grade::Fast, false, true, false),
            PathChoice::Punch
        );
        assert_eq!(
            choose_path(Grade::Fast, true, true, false),
            PathChoice::Lan
        );
        assert_eq!(
            choose_path(Grade::Fast, false, false, false),
            PathChoice::Sg
        );
    }

    #[test]
    fn lan_is_chosen_only_when_up_and_stable_stays_on_sg() {
        assert_eq!(
            choose_path(Grade::Fast, true, false, false),
            PathChoice::Lan
        );
        assert_eq!(
            choose_path(Grade::Fast, false, false, false),
            PathChoice::Sg
        );
        assert_eq!(
            choose_path(Grade::Stable, true, true, false),
            PathChoice::Sg
        );
        assert_eq!(
            choose_path(Grade::Cellphone, true, false, false),
            PathChoice::Lan
        );
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
