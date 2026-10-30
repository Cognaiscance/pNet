//! Memory of addresses an SG has seen, and later the direct-path probes.
//!
//! Nothing here is written into the directory snapshot. See
//! `descriptions/direct-path.md`.

use std::collections::{HashMap, HashSet};
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
    self_unstable: bool,
    self_changes: Vec<Instant>,
    /// Pairs already told to punch. Order-independent.
    punch_invited: HashSet<([u8; 16], [u8; 16])>,
    /// Unstable flags to publish. The bool is the new value.
    flag_notices: Vec<([u8; 16], bool)>,
    self_notice: Option<bool>,
    /// Flags learned from a peer before we have stored an address for them.
    remote_unstable: HashSet<[u8; 16]>,
}

const UNSTABLE_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Three address changes inside five minutes, and the newest still inside
/// that window, marks the node unstable.
pub fn unstable_window(stamps: &[Instant], now: Instant) -> bool {
    if stamps.len() < 3 {
        return false;
    }
    let last = &stamps[stamps.len() - 3..];
    now.saturating_duration_since(last[0]) <= UNSTABLE_WINDOW
        && now.saturating_duration_since(last[2]) <= UNSTABLE_WINDOW
}

impl DirectBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the UDP source the SG saw for `device`.
    /// A repeat of the same address is not an address change.
    pub fn note_observed(&mut self, device: [u8; 16], addr: SocketAddr, now: Instant) -> Observe {
        let mut flipped = None;
        let result = match self.peers.get_mut(&device) {
            None => {
                self.peers.insert(
                    device,
                    PeerPath {
                        observed: addr,
                        changes: Vec::new(),
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
                let next = unstable_window(&peer.changes, now);
                if next != peer.unstable {
                    peer.unstable = next;
                    flipped = Some(next);
                }
                Observe::Replaced
            }
        };
        if result == Observe::Replaced {
            self.forget_punch_pair(device);
        }
        if let Some(flag) = flipped {
            self.flag_notices.push((device, flag));
        }
        result
    }

    fn forget_punch_pair(&mut self, device: [u8; 16]) {
        self.punch_invited.retain(|(x, y)| *x != device && *y != device);
    }

    /// This node's own address moved. Returns whether it is now unstable.
    pub fn note_self_change(&mut self, now: Instant) -> bool {
        self.self_changes.push(now);
        if self.self_changes.len() > 3 {
            self.self_changes.drain(0..self.self_changes.len() - 3);
        }
        let next = unstable_window(&self.self_changes, now);
        if next != self.self_unstable {
            self.self_notice = Some(next);
        }
        self.self_unstable = next;
        self.self_unstable
    }

    pub fn self_unstable(&self) -> bool {
        self.self_unstable
    }

    /// Five-minute maintenance. Clears the flag when the window no longer holds.
    pub fn sweep_unstable(&mut self, now: Instant) {
        let next = unstable_window(&self.self_changes, now);
        if next != self.self_unstable {
            self.self_unstable = next;
            self.self_notice = Some(next);
        }
        let mut flipped = Vec::new();
        for (id, peer) in self.peers.iter_mut() {
            let next = unstable_window(&peer.changes, now);
            if next != peer.unstable {
                peer.unstable = next;
                flipped.push((*id, next));
            }
        }
        self.flag_notices.extend(flipped);
    }

    /// Notices queued since the last take. `local` is this node's own id,
    /// used when its own flag changed.
    pub fn take_unstable_notices(&mut self, local: [u8; 16]) -> Vec<([u8; 16], bool)> {
        let mut out = std::mem::take(&mut self.flag_notices);
        if let Some(flag) = self.self_notice.take() {
            out.push((local, flag));
        }
        out
    }

    /// Apply a flag learned from a peer. Does not queue another notice.
    pub fn set_unstable(&mut self, device: [u8; 16], unstable: bool) {
        if let Some(peer) = self.peers.get_mut(&device) {
            peer.unstable = unstable;
        }
        if unstable {
            self.remote_unstable.insert(device);
        } else {
            self.remote_unstable.remove(&device);
        }
    }

    pub fn is_unstable(&self, device: &[u8; 16]) -> bool {
        self.remote_unstable.contains(device)
            || self.peers.get(device).map(|p| p.unstable).unwrap_or(false)
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

/// Who hears that `down` lost its direct path.
/// A node that is not rank-1 tells rank-1. Rank-1 tells every other connected peer.
pub fn path_down_recipients(
    local: [u8; 16],
    down: [u8; 16],
    we_are_rank1: bool,
    rank1: Option<[u8; 16]>,
    connected: &[[u8; 16]],
) -> Vec<[u8; 16]> {
    if !we_are_rank1 {
        return match rank1 {
            Some(rank1) if rank1 != local && rank1 != down => vec![rank1],
            _ => Vec::new(),
        };
    }
    connected
        .iter()
        .copied()
        .filter(|id| *id != local && *id != down)
        .collect()
}

/// Who should be told about an address the local node just observed.
/// The destination hears it once. The sender hears the address the SG saw
/// for them, so they can compare ranges. The sender's rank-1 SG hears it
/// when that SG is someone else.
pub fn observation_recipients(
    local: [u8; 16],
    sender: [u8; 16],
    dest: [u8; 16],
    rank1: Option<[u8; 16]>,
) -> Vec<[u8; 16]> {
    let mut out = Vec::new();
    for id in [dest, sender] {
        if id != local && !out.contains(&id) {
            out.push(id);
        }
    }
    if let Some(rank1) = rank1 {
        if rank1 != local && !out.contains(&rank1) {
            out.push(rank1);
        }
    }
    out
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

pub fn is_private(addr: SocketAddr) -> bool {
    v4_octets(addr).and_then(private_block).is_some()
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
    pub fn begin_lan_probe(
        &mut self,
        device: &[u8; 16],
        local_observed: SocketAddr,
        now: Instant,
    ) -> bool {
        let Some(peer) = self.peers.get_mut(device) else {
            return false;
        };
        if !same_lan(peer.observed, local_observed) {
            return false;
        }
        if peer.lan_probe_sent {
            match peer.lan_up_until {
                Some(until) if until > now => return false,
                Some(_) => peer.lan_probe_sent = false,
                None => return false,
            }
        }
        peer.lan_probe_sent = true;
        true
    }

    /// Peers that should be probed now. A peer already probed is skipped.
    pub fn lan_probes_due(&mut self, local: &[u8; 16]) -> Vec<([u8; 16], SocketAddr)> {
        let ids: Vec<[u8; 16]> = self
            .peers
            .keys()
            .copied()
            .filter(|id| id != local)
            .collect();
        let mut out = Vec::new();
        for id in ids {
            let ours = self.observed(local);
            let theirs = self.observed(&id);
            let (Some(ours), Some(theirs)) = (ours, theirs) else {
                continue;
            };
            if self.begin_lan_probe(&id, ours, Instant::now()) {
                out.push((id, theirs));
            }
        }
        out
    }

    /// The probe answer counts only from the address we stored for that peer.
    pub fn accept_lan_ack(
        &mut self,
        peer: &[u8; 16],
        from: SocketAddr,
        now: Instant,
        ttl: Duration,
    ) -> bool {
        let Some(expected) = self.observed(peer) else {
            return false;
        };
        if expected != from {
            return false;
        }
        self.answer_lan(peer, now, ttl)
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
        if peer.punch_probe_sent {
            return false;
        }
        peer.punch_probe_sent = true;
        true
    }

    /// Both addresses are known and not on the same LAN. Returns each side's
    /// address once: `(addr_a, addr_b)` matching the arguments.
    pub fn take_punch_invite(
        &mut self,
        a: [u8; 16],
        b: [u8; 16],
    ) -> Option<(SocketAddr, SocketAddr)> {
        if a == b {
            return None;
        }
        let addr_a = self.observed(&a)?;
        let addr_b = self.observed(&b)?;
        if same_lan(addr_a, addr_b) {
            return None;
        }
        let key = if a <= b { (a, b) } else { (b, a) };
        if !self.punch_invited.insert(key) {
            return None;
        }
        Some((addr_a, addr_b))
    }

    pub fn accept_punch_ack(
        &mut self,
        peer: &[u8; 16],
        from: SocketAddr,
        now: Instant,
        ttl: Duration,
    ) -> bool {
        let Some(expected) = self.observed(peer) else {
            return false;
        };
        if expected != from {
            return false;
        }
        self.answer_punch(peer, now, ttl)
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
        assert!(book.peer(&dev).unwrap().changes.is_empty());
        assert_eq!(book.note_observed(dev, addr(2), t0), Observe::Replaced);
        assert_eq!(book.observed(&dev), Some(addr(2)));
        assert_eq!(book.peer(&dev).unwrap().changes.len(), 1);
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
        assert!(book.begin_lan_probe(&dev, lan_b, t0));
        assert!(!book.lan_is_up(&dev, t0));
        assert!(book.answer_lan(&dev, t0, Duration::from_secs(30)));
        assert!(book.lan_is_up(&dev, t0));

        book.note_observed(dev, other, t0);
        assert!(!book.begin_lan_probe(&dev, lan_b, t0));
        assert!(!book.lan_is_up(&dev, t0));

        book.note_observed(dev, public, t0);
        assert!(!book.begin_lan_probe(&dev, lan_b, t0));
        assert!(!same_lan(public, lan_b));
        assert!(same_lan(lan_a, lan_b));
    }

    #[test]
    fn punch_invite_is_one_pair_when_ranges_differ() {
        let mut book = DirectBook::new();
        let a = [1u8; 16];
        let b = [2u8; 16];
        let t0 = Instant::now();
        let addr_a: SocketAddr = "198.51.100.4:7777".parse().unwrap();
        let addr_b: SocketAddr = "203.0.113.9:7777".parse().unwrap();
        let lan_a: SocketAddr = "192.168.1.4:7777".parse().unwrap();
        let lan_b: SocketAddr = "192.168.1.9:7777".parse().unwrap();
        assert!(book.take_punch_invite(a, b).is_none());
        book.note_observed(a, addr_a, t0);
        book.note_observed(b, addr_b, t0);
        assert_eq!(book.take_punch_invite(a, b), Some((addr_a, addr_b)));
        assert!(book.take_punch_invite(b, a).is_none());
        book.note_observed(a, lan_a, t0);
        book.note_observed(b, lan_b, t0);
        assert!(book.take_punch_invite(a, b).is_none());
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
    fn three_changes_in_five_minutes_marks_unstable_and_a_quiet_window_clears_it() {
        let mut book = DirectBook::new();
        let t0 = Instant::now();
        assert!(!book.note_self_change(t0));
        assert!(!book.note_self_change(t0 + Duration::from_secs(10)));
        assert!(book.note_self_change(t0 + Duration::from_secs(20)));
        assert!(book.self_unstable());
        // Fast may still use a direct path. Cellphone may not.
        assert_eq!(
            choose_path(Grade::Fast, true, false, book.self_unstable()),
            PathChoice::Lan
        );
        assert_eq!(
            choose_path(Grade::Cellphone, true, false, true),
            PathChoice::Sg
        );
        let local = [9u8; 16];
        let notices = book.take_unstable_notices(local);
        assert_eq!(notices, vec![(local, true)]);
        book.sweep_unstable(t0 + Duration::from_secs(5 * 60 + 1));
        assert!(!book.self_unstable());
        assert_eq!(book.take_unstable_notices(local), vec![(local, false)]);

        let dev = [8u8; 16];
        let a = addr(1);
        book.note_observed(dev, a, t0);
        book.note_observed(dev, addr(2), t0);
        book.note_observed(dev, addr(3), t0 + Duration::from_secs(1));
        assert!(!book.peer(&dev).unwrap().unstable);
        assert!(book.take_unstable_notices(local).is_empty());
        book.note_observed(dev, addr(4), t0 + Duration::from_secs(2));
        assert!(book.peer(&dev).unwrap().unstable);
        assert_eq!(book.take_unstable_notices(local), vec![(dev, true)]);
        book.set_unstable([7u8; 16], true);
        assert!(book.is_unstable(&[7u8; 16]));
    }

    #[test]
    fn late_probe_goes_cold_and_a_notify_drops_sooner() {
        let mut book = DirectBook::new();
        let dev = [4u8; 16];
        let t0 = Instant::now();
        let lan_a: SocketAddr = "10.0.0.2:7777".parse().unwrap();
        let lan_b: SocketAddr = "10.0.0.3:7777".parse().unwrap();
        book.note_observed(dev, lan_a, t0);
        assert!(book.begin_lan_probe(&dev, lan_b, t0));
        assert!(book.answer_lan(&dev, t0, Duration::from_secs(30)));
        let later = t0 + Duration::from_secs(31);
        assert!(!book.lan_is_up(&dev, later));
        assert_eq!(
            choose_path(Grade::Fast, book.lan_is_up(&dev, later), false, false),
            PathChoice::Sg
        );

        assert!(book.begin_lan_probe(&dev, lan_b, later));
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
    fn path_down_goes_to_rank1_then_the_other_peers() {
        let local = [1u8; 16];
        let down = [2u8; 16];
        let rank1 = [3u8; 16];
        let peer = [4u8; 16];
        assert_eq!(
            path_down_recipients(local, down, false, Some(rank1), &[rank1, peer]),
            vec![rank1]
        );
        assert_eq!(
            path_down_recipients(rank1, down, true, Some(rank1), &[local, down, peer]),
            vec![local, peer]
        );
        assert!(path_down_recipients(local, down, false, None, &[peer]).is_empty());
    }

    #[test]
    fn observation_goes_to_dest_and_rank1_once_each() {
        let local = [1u8; 16];
        let dest = [2u8; 16];
        let rank1 = [3u8; 16];
        let sender = [4u8; 16];
        assert_eq!(
            observation_recipients(local, sender, dest, Some(rank1)),
            vec![dest, sender, rank1]
        );
        assert_eq!(
            observation_recipients(local, sender, dest, Some(dest)),
            vec![dest, sender]
        );
        assert_eq!(
            observation_recipients(local, dest, local, Some(rank1)),
            vec![dest, rank1]
        );
        assert!(observation_recipients(local, local, local, Some(local)).is_empty());
    }

    #[test]
    fn lan_probe_is_sent_once_and_ack_must_come_from_that_address() {
        let mut book = DirectBook::new();
        let local = [1u8; 16];
        let peer = [2u8; 16];
        let t0 = Instant::now();
        let mine: SocketAddr = "192.168.1.10:7777".parse().unwrap();
        let theirs: SocketAddr = "192.168.1.20:7777".parse().unwrap();
        let other: SocketAddr = "10.1.0.5:7777".parse().unwrap();
        book.note_observed(local, mine, t0);
        book.note_observed(peer, theirs, t0);
        assert_eq!(book.lan_probes_due(&local), vec![(peer, theirs)]);
        assert!(book.lan_probes_due(&local).is_empty());
        assert!(!book.lan_is_up(&peer, t0));
        assert!(!book.accept_lan_ack(&peer, other, t0, Duration::from_secs(30)));
        assert!(!book.lan_is_up(&peer, t0));
        assert!(book.accept_lan_ack(&peer, theirs, t0, Duration::from_secs(30)));
        assert!(book.lan_is_up(&peer, t0));
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
