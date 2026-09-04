//! Peer sync: HELLO / INDEX / WANT / CHUNK with ACK + retry.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::fabric::{self, Peer};
use crate::proto::{self, Packet, CHUNK_SIZE, T_ACK, T_CHUNK, T_HELLO, T_INDEX, T_WANT};
use crate::store::{Store, MAX_FILE_BYTES};

const MAX_TRIES: u32 = 16;
const RETRY: Duration = Duration::from_millis(400);

struct Pending {
    dest_device: [u8; 16],
    dest_app: [u8; 16],
    encoded: Vec<u8>,
    last: Instant,
    tries: u32,
}

struct Incoming {
    total: u64,
    buf: Vec<u8>,
    got: HashSet<u64>,
}

pub struct Engine {
    pub token: [u8; 16],
    pub app_id: [u8; 16],
    pub device_uuid: [u8; 16],
    pub approved: bool,
    pub peers: Vec<Peer>,
    next_msg: u64,
    pending: HashMap<u64, Pending>,
    incoming: HashMap<[u8; 32], Incoming>,
    /// Hashes we still need from the network.
    pub missing: HashSet<[u8; 32]>,
    last_index_sent: u64,
    /// Immediate ACKs to flush (not retried).
    acks: Vec<(Peer, u64)>,
}

impl Engine {
    /// Force the next tick to re-broadcast INDEX (after a local web write).
    pub fn invalidate_index(&mut self) {
        self.last_index_sent = 0;
    }

    pub fn new(token: [u8; 16]) -> Self {
        Engine {
            token,
            app_id: [0u8; 16],
            device_uuid: [0u8; 16],
            approved: false,
            peers: Vec::new(),
            next_msg: 1,
            pending: HashMap::new(),
            incoming: HashMap::new(),
            missing: HashSet::new(),
            last_index_sent: 0,
            acks: Vec::new(),
        }
    }

    pub fn refresh_dir(
        &mut self,
        ctrl: &UdpSocket,
        pnet: SocketAddr,
        alias: &str,
    ) -> Result<(), String> {
        let raw = fabric::get_data(ctrl, pnet, &self.token)?;
        let dir = fabric::parse_directory(&raw, alias).ok_or("bad directory")?;
        self.app_id = dir.app_id;
        self.device_uuid = dir.device_uuid;
        self.approved = dir.approved;
        self.peers = dir.peers;
        Ok(())
    }

    fn enqueue(&mut self, dest: &Peer, mut pkt: Packet) {
        let id = self.next_msg;
        self.next_msg = self.next_msg.saturating_add(1);
        pkt.msg_id = id;
        let encoded = proto::encode(&pkt);
        self.pending.insert(
            id,
            Pending {
                dest_device: dest.device,
                dest_app: dest.app_id,
                encoded,
                last: Instant::now() - RETRY,
                tries: 0,
            },
        );
    }

    fn peer_for_app(&self, app_id: [u8; 16]) -> Option<Peer> {
        self.peers.iter().find(|p| p.app_id == app_id).cloned()
    }

    fn queue_ack(&mut self, sender_app: [u8; 16], msg_id: u64) {
        if msg_id == 0 {
            return;
        }
        let Some(peer) = self.peer_for_app(sender_app) else {
            return;
        };
        self.acks.push((peer, msg_id));
    }

    pub fn broadcast_index(&mut self, store: &Store) {
        if self.peers.is_empty() {
            return;
        }
        if self.last_index_sent == store.gen {
            return;
        }
        let recs: Vec<_> = store.files.values().cloned().collect();
        let bodies = proto::encode_index(store.gen, &recs);
        let peers = self.peers.clone();
        for peer in &peers {
            self.enqueue(peer, proto::hello(&store.replica_id, store.gen));
            for b in &bodies {
                self.enqueue(
                    peer,
                    Packet {
                        typ: T_INDEX,
                        msg_id: 0,
                        body: b.clone(),
                    },
                );
            }
        }
        self.last_index_sent = store.gen;
    }

    pub fn request_missing(&mut self) {
        if self.missing.is_empty() || self.peers.is_empty() {
            return;
        }
        let hashes: Vec<_> = self.missing.iter().copied().take(4).collect();
        let peers = self.peers.clone();
        for h in hashes {
            for peer in &peers {
                self.enqueue(peer, proto::want(&h));
            }
        }
    }

    pub fn on_packet(&mut self, store: &mut Store, sender_app: [u8; 16], pkt: Packet) {
        match pkt.typ {
            T_ACK => {
                if let Some(id) = proto::parse_ack(&pkt.body) {
                    self.pending.remove(&id);
                }
            }
            T_HELLO => {
                self.queue_ack(sender_app, pkt.msg_id);
            }
            T_INDEX => {
                self.queue_ack(sender_app, pkt.msg_id);
                if let Some((_gen, _part, _parts, recs)) = proto::parse_index(&pkt.body) {
                    for h in store.merge_remote(&recs) {
                        self.missing.insert(h);
                    }
                }
            }
            T_WANT => {
                self.queue_ack(sender_app, pkt.msg_id);
                if let Some(hash) = proto::parse_want(&pkt.body) {
                    self.send_chunks(store, sender_app, hash);
                }
            }
            T_CHUNK => {
                self.queue_ack(sender_app, pkt.msg_id);
                if let Some((hash, total, offset, data)) = proto::parse_chunk(&pkt.body) {
                    self.on_chunk(store, hash, total, offset, data);
                }
            }
            _ => {}
        }
    }

    fn send_chunks(&mut self, store: &Store, sender_app: [u8; 16], hash: [u8; 32]) {
        let Some(peer) = self.peer_for_app(sender_app) else {
            return;
        };
        let Some(data) = store.blob(&hash) else {
            return;
        };
        if data.len() as u64 > MAX_FILE_BYTES {
            return;
        }
        let total = data.len() as u64;
        if total == 0 {
            self.enqueue(&peer, proto::chunk(&hash, 0, 0, &[]));
            return;
        }
        let mut off = 0usize;
        while off < data.len() {
            let end = (off + CHUNK_SIZE).min(data.len());
            self.enqueue(&peer, proto::chunk(&hash, total, off as u64, &data[off..end]));
            off = end;
        }
    }

    fn on_chunk(&mut self, store: &mut Store, hash: [u8; 32], total: u64, offset: u64, data: &[u8]) {
        if total > MAX_FILE_BYTES {
            return;
        }
        if offset.saturating_add(data.len() as u64) > total {
            return;
        }
        let entry = self.incoming.entry(hash).or_insert_with(|| Incoming {
            total,
            buf: vec![0u8; total as usize],
            got: HashSet::new(),
        });
        if entry.total != total || entry.buf.len() != total as usize {
            return;
        }
        let start = offset as usize;
        let end = start + data.len();
        if end > entry.buf.len() {
            return;
        }
        entry.buf[start..end].copy_from_slice(data);
        entry.got.insert(offset);
        let mut covered = 0u64;
        let mut o = 0u64;
        while o < total {
            if !entry.got.contains(&o) {
                return;
            }
            let n = CHUNK_SIZE.min((total - o) as usize) as u64;
            covered += n;
            o += n;
        }
        if covered < total {
            return;
        }
        if let Some(done) = self.incoming.remove(&hash) {
            let _ = store.install_blob(&hash, &done.buf);
            self.missing.remove(&hash);
        }
    }

    /// Send due retries and queued ACKs.
    pub fn flush(&mut self, ctrl: &UdpSocket, pnet: SocketAddr) {
        let token = self.token;
        let now = Instant::now();
        let mut drop_ids = Vec::new();
        for (id, p) in self.pending.iter_mut() {
            if now.saturating_duration_since(p.last) < RETRY {
                continue;
            }
            if p.tries >= MAX_TRIES {
                drop_ids.push(*id);
                continue;
            }
            let _ = fabric::send_payload(
                ctrl,
                pnet,
                &token,
                &p.dest_device,
                &p.dest_app,
                &p.encoded,
            );
            p.last = now;
            p.tries += 1;
        }
        for id in drop_ids {
            self.pending.remove(&id);
        }
        let acks = std::mem::take(&mut self.acks);
        for (peer, msg_id) in acks {
            let pkt = proto::encode(&proto::ack(msg_id));
            let _ = fabric::send_payload(ctrl, pnet, &token, &peer.device, &peer.app_id, &pkt);
        }
    }
}
