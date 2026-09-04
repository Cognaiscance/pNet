//! Sync desire (writer) and status (every agent) with ACK + retry.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::fabric::{self, DirView, Peer};
use crate::proto::{
    self, Packet, T_ACK, T_DESIRE, T_HELLO, T_STATUS,
};
use crate::state::State;

const MAX_TRIES: u32 = 16;
const RETRY: Duration = Duration::from_millis(400);

struct Pending {
    dest_device: [u8; 16],
    dest_app: [u8; 16],
    encoded: Vec<u8>,
    last: Instant,
    tries: u32,
}

pub struct Engine {
    pub token: [u8; 16],
    pub app_id: [u8; 16],
    pub device_uuid: [u8; 16],
    pub approved: bool,
    pub dir: Option<DirView>,
    next_msg: u64,
    pending: HashMap<u64, Pending>,
    acks: Vec<(Peer, u64)>,
    pub desire_dirty: bool,
    pub status_dirty: bool,
}

impl Engine {
    pub fn new(token: [u8; 16]) -> Self {
        Engine {
            token,
            app_id: [0u8; 16],
            device_uuid: [0u8; 16],
            approved: false,
            dir: None,
            next_msg: 1,
            pending: HashMap::new(),
            acks: Vec::new(),
            desire_dirty: true,
            status_dirty: true,
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
        self.dir = Some(dir);
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

    fn peers(&self) -> Vec<Peer> {
        self.dir
            .as_ref()
            .map(|d| d.installer_peers.clone())
            .unwrap_or_default()
    }

    pub fn broadcast(&mut self, state: &State) {
        let peers = self.peers();
        if peers.is_empty() || !self.approved {
            return;
        }
        let writer = self
            .dir
            .as_ref()
            .map(|d| state.is_writer(d))
            .unwrap_or(false);
        if self.desire_dirty || self.status_dirty {
            for p in &peers {
                self.enqueue(p, proto::hello(&state.replica_id, writer));
            }
        }
        if writer && self.desire_dirty {
            if let Some(pkt) = proto::desire_packet(&state.desire) {
                for p in &peers {
                    self.enqueue(p, pkt.clone());
                }
            }
            self.desire_dirty = false;
        }
        if self.status_dirty {
            let local = crate::state::hex16(&self.device_uuid);
            let mine: Vec<_> = state
                .status
                .iter()
                .filter(|s| s.device_uuid == local)
                .cloned()
                .collect();
            if let Some(pkt) = proto::status_packet(&mine) {
                for p in &peers {
                    self.enqueue(p, pkt.clone());
                }
            }
            self.status_dirty = false;
        }
    }

    pub fn on_packet(&mut self, state: &mut State, sender: [u8; 16], pkt: Packet) {
        match pkt.typ {
            T_ACK => {
                if let Some(id) = proto::parse_ack(&pkt.body) {
                    self.pending.remove(&id);
                }
            }
            T_HELLO => {
                self.queue_ack(sender, pkt.msg_id);
            }
            T_DESIRE => {
                self.queue_ack(sender, pkt.msg_id);
                if let Some(list) = proto::parse_desire(&pkt.body) {
                    if state.merge_desire(&list) {
                        self.status_dirty = true;
                    }
                }
            }
            T_STATUS => {
                self.queue_ack(sender, pkt.msg_id);
                if let Some(list) = proto::parse_status(&pkt.body) {
                    let _ = state.merge_status(&list);
                }
            }
            _ => {}
        }
    }

    fn queue_ack(&mut self, sender_app: [u8; 16], msg_id: u64) {
        if msg_id == 0 {
            return;
        }
        let Some(peer) = self.peers().into_iter().find(|p| p.app_id == sender_app) else {
            return;
        };
        self.acks.push((peer, msg_id));
    }

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
