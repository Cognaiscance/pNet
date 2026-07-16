//! Sessions: connect handshake, maintain, poll SG, DG keepalive, conn-reset.
//!
//! Fabric session lifecycle lives here. Tunnel and sync reconnect hooks stay
//! in the parent module and are called via `super::`.

use std::collections::HashSet;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

use super::super::action_queue::{Action, ScheduleRequest, WorkerContext};
use super::super::crypto::{
    build_encrypted_packet, decrypt_packet_body, ed25519_sign, ed25519_verify,
    generate_x25519_keypair,
};
use super::super::data_models::{
    ActiveConnection, Device, DeviceGrade, Node, PendingConnection, PublicKey, SgStatus, Uuid,
    generate_uuid, CONNECTION_LIFETIME, PENDING_CONNECTION_TIMEOUT, RENEW_THRESHOLD,
};
use super::super::wire::*;
use super::{
    allocate_conn_id, best_address_for_device, cross_user_pull_on_reconnect, ipv4_from,
    partition_reconcile_on_reconnect, resolve_host_entry, send, sync_pull,
};

/// Find the device UUID for an incoming connection request, given the peer's
/// long-term public key and claimed device UUID.  Returns `Some(uuid)` if both
/// the key and the UUID are known (own devices or a contact's devices).
fn find_device_uuid_for_pk(node: &Node, longterm_pk: &PublicKey, device_uuid: &Uuid) -> Option<Uuid> {
    // Own devices share the owner's long-term public key.
    if node.owner.key_pair.public_key == *longterm_pk {
        if node.owner.user.devices.iter().any(|d| d.uuid == *device_uuid) {
            return Some(*device_uuid);
        }
    }
    // Contact devices use the contact's public key.
    for contact in &node.owner.contact_users {
        if contact.public_key == *longterm_pk {
            if contact.user.devices.iter().any(|d| d.uuid == *device_uuid) {
                return Some(*device_uuid);
            }
        }
    }
    None
}


/// Respond to an SG ping from another node with the nonce echoed back.
pub fn sg_ping(src: SocketAddr, nonce: [u8; 16], ctx: &WorkerContext) {
    let mut reply = [0u8; 17];
    reply[0] = SG_PONG_OP;
    reply[1..17].copy_from_slice(&nonce);
    send(ctx, src, &reply);
}

/// Op 0x20 — Incoming connection request from a peer node.
///
/// Payload layout (after op byte):
///   [initiator_conn_id: u16 be]
///   [initiator_device_uuid: 16 bytes]
///   [initiator_ephemeral_pk: 32 bytes]
///   [initiator_longterm_pk: 32 bytes]
///   [signature: 64 bytes]             — Ed25519 over [op=0x20 || fields above]
///
/// If the initiator is a known device, stores an ActiveConnection and replies
/// with a ConnectAck containing our ephemeral public key.
pub fn connect_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < CONNECT_REQUEST_MIN_LEN {
        eprintln!("[connect_request] packet too short ({} bytes) from {src}", buf.len());
        return;
    }

    let initiator_conn_id                   = u16::from_be_bytes([buf[0], buf[1]]);
    let initiator_device_uuid: Uuid         = buf[2..18].try_into().unwrap();
    let initiator_ephemeral_pk: PublicKey   = buf[18..50].try_into().unwrap();
    let initiator_longterm_pk: PublicKey    = buf[50..82].try_into().unwrap();
    let signature: [u8; 64]                 = buf[82..146].try_into().unwrap();

    // Verify Ed25519 signature over [op=0x20] || buf[0..82].
    let mut signed_msg = [0u8; 83];
    signed_msg[0] = CONNECT_REQUEST_OP;
    signed_msg[1..83].copy_from_slice(&buf[0..82]);
    if !ed25519_verify(&initiator_longterm_pk, &signed_msg, &signature) {
        eprintln!("[connect_request] invalid signature from {src}");
        return;
    }

    // Verify the initiator is a known device.
    let known = {
        let node = ctx.node.read().unwrap();
        find_device_uuid_for_pk(&node, &initiator_longterm_pk, &initiator_device_uuid).is_some()
    };
    if !known {
        eprintln!("[connect_request] unknown public key or device UUID from {src}");
        return;
    }

    // Allocate our ephemeral key pair and connection ID, then store the active connection.
    let (our_conn_id, our_ephemeral_pk, our_longterm_sk) = {
        let mut node = ctx.node.write().unwrap();
        let conn_id  = allocate_conn_id(&node);
        let key_pair = generate_x25519_keypair();
        let pk_copy  = key_pair.public_key;
        let sk_copy  = node.owner.key_pair.private_key;
        // Evict any stale connections to this device before inserting the new one.
        node.owner.active_connections.retain(|_, c| c.device_uuid != initiator_device_uuid);
        node.owner.active_connections.insert(conn_id, ActiveConnection {
            id:                        conn_id,
            timeout:                   SystemTime::now() + CONNECTION_LIFETIME,
            key_pair,
            peer_public_key:           initiator_ephemeral_pk,
            peer_active_connection_id: initiator_conn_id,
            device_uuid:               initiator_device_uuid,
            peer_addr:                 src,
        });
        (conn_id, pk_copy, sk_copy)
    };

    // Reply with ConnectAck:
    //   [op=0x21][our_conn_id: u16][initiator_conn_id: u16][our_ephemeral_pk: 32][sig: 64]
    let mut pkt = [0u8; 101];
    pkt[0]       = CONNECT_ACK_OP;
    pkt[1..3].copy_from_slice(&our_conn_id.to_be_bytes());
    pkt[3..5].copy_from_slice(&initiator_conn_id.to_be_bytes());
    pkt[5..37].copy_from_slice(&our_ephemeral_pk);
    let sig = ed25519_sign(&our_longterm_sk, &pkt[0..37]);
    pkt[37..101].copy_from_slice(&sig);
    send(ctx, src, &pkt);

    // No push needed on a new DG connection: state hasn't changed. The
    // writer SG already published any prior state via sync v1
    // SyncUpdateAvailable, and the joining DG pulls on its side.

    // Sync v2: mirror the initiator-side reconciliation kickoff. Either side
    // can initiate the probe; running it from both ends just means both sides
    // populate `last_watermarks` and ship their proposal in parallel.
    partition_reconcile_on_reconnect(our_conn_id, ctx);
}

/// Op 0x21 — Acknowledgement from a peer node in response to our ConnectRequest.
///
/// Payload layout (after op byte):
///   [responder_conn_id: u16 be]
///   [our_conn_id: u16 be]             — echoed back so we correlate to pending entry
///   [responder_ephemeral_pk: 32 bytes]
///   [signature: 64 bytes]             — Ed25519 over [op=0x21 || fields above]
///
/// Promotes the matching PendingConnection to an ActiveConnection.
pub fn connect_ack(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < CONNECT_ACK_MIN_LEN {
        eprintln!("[connect_ack] packet too short ({} bytes) from {src}", buf.len());
        return;
    }

    let responder_conn_id               = u16::from_be_bytes([buf[0], buf[1]]);
    let our_conn_id                     = u16::from_be_bytes([buf[2], buf[3]]);
    let responder_ephemeral_pk: PublicKey = buf[4..36].try_into().unwrap();
    let signature: [u8; 64]             = buf[36..100].try_into().unwrap();

    let mut node = ctx.node.write().unwrap();
    let Some(pending) = node.owner.pending_connections.remove(&our_conn_id) else {
        eprintln!("[connect_ack] no pending connection for id {our_conn_id} from {src}");
        return;
    };

    // Verify Ed25519 signature over [op=0x21] || buf[0..36].
    let mut signed_msg = [0u8; 37];
    signed_msg[0] = CONNECT_ACK_OP;
    signed_msg[1..37].copy_from_slice(&buf[0..36]);
    if !ed25519_verify(&pending.peer_longterm_pk, &signed_msg, &signature) {
        eprintln!("[connect_ack] invalid signature from {src}");
        // Put the pending connection back so we don't lose the slot.
        node.owner.pending_connections.insert(our_conn_id, pending);
        return;
    }

    println!("[connect_ack] connection established with {src} (peer {:02x?})", &pending.peer_device_uuid[..4]);
    // Evict any stale connections to this device before inserting the new one.
    let peer_uuid = pending.peer_device_uuid;
    node.owner.active_connections.retain(|_, c| c.device_uuid != peer_uuid);
    node.owner.active_connections.insert(our_conn_id, ActiveConnection {
        id:                        our_conn_id,
        timeout:                   SystemTime::now() + CONNECTION_LIFETIME,
        key_pair:                  pending.our_key_pair,
        peer_public_key:           responder_ephemeral_pk,
        peer_active_connection_id: responder_conn_id,
        device_uuid:               pending.peer_device_uuid,
        peer_addr:                 src,
    });
    drop(node);

    // Sync v1: if the freshly-connected peer is our writer SG, immediately
    // catch up on any `SyncUpdateAvailable` notifications missed while
    // disconnected. `sync_pull` is a no-op when the writer is `Local` or no
    // writer is reachable, so it's safe to call unconditionally.
    sync_pull(ctx);
    // If the freshly-connected peer is one of our contacts' devices, also
    // fire a CrossUserPullRequest so we catch up on cross-user public state
    // (e.g. contact's apps) that may have been published while the
    // SG↔SG connection didn't yet exist. No-op for own-user peers.
    cross_user_pull_on_reconnect(our_conn_id, ctx);
    // Sync v2: if the peer is an own-user SG, kick off partition reconciliation
    // (watermark probe → merge proposal exchange). No-op otherwise.
    partition_reconcile_on_reconnect(our_conn_id, ctx);
}

const SG_PING_TIMEOUT: Duration = Duration::from_secs(1);

/// Ping every candidate SG, record RTT, and mark each one up or down.
///
/// Candidate pool: all SG-grade devices owned by the local user (excluding the
/// local device itself) plus all SG-grade devices of every contact user.
///
/// Every advertised host is recorded — including hosts whose name fails to
/// resolve. An unresolvable host is treated as down (not "no data"), so
/// `top_ranked_sg_for_device`'s optimistic "no poll data" branch doesn't
/// mistakenly pick a peer whose DNS entry just vanished (e.g. a stopped
/// docker container).
pub fn poll_sg(ctx: &WorkerContext) {
    // Collect (device_uuid, host_entry, resolved_addr_opt) for every advertised
    // address on every candidate SG. `None` addr means the host failed to
    // resolve and will be recorded as down without a ping attempt.
    let candidates: Vec<(Uuid, String, Option<SocketAddrV4>)> = {
        let node = ctx.node.read().unwrap();
        let local_uuid = node.device_uuid;
        let mut v: Vec<(Uuid, String, Option<SocketAddrV4>)> = Vec::new();
        for d in &node.owner.user.devices {
            if matches!(d.grade, DeviceGrade::SG) && d.uuid != local_uuid {
                for h in &d.hosts {
                    v.push((d.uuid, h.clone(), resolve_host_entry(h)));
                }
            }
        }
        for contact in &node.owner.contact_users {
            for d in &contact.user.devices {
                if matches!(d.grade, DeviceGrade::SG) {
                    for h in &d.hosts {
                        v.push((d.uuid, h.clone(), resolve_host_entry(h)));
                    }
                }
            }
        }
        v
    };

    if candidates.is_empty() {
        return;
    }

    // Ephemeral socket so pong responses come back here, not to the main listener.
    let ping_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => { eprintln!("[poll_sg] bind failed: {e}"); return; }
    };
    ping_socket.set_read_timeout(Some(SG_PING_TIMEOUT)).ok();

    for (uuid, host, addr_opt) in candidates {
        let Some(addr) = addr_opt else {
            // Unresolvable host: record down without attempting a ping.
            record_sg_status(ctx, uuid, host, None);
            continue;
        };
        let nonce = generate_uuid();
        let mut packet = [0u8; 17];
        packet[0] = SG_PING_OP;
        packet[1..17].copy_from_slice(&nonce);

        let start = Instant::now();
        if ping_socket.send_to(&packet, std::net::SocketAddr::V4(addr)).is_err() {
            record_sg_status(ctx, uuid, host, None);
            continue;
        }

        let mut buf = [0u8; 32];
        let up = match ping_socket.recv_from(&mut buf) {
            Ok((len, _)) if len >= 17 && buf[0] == SG_PONG_OP && buf[1..17] == nonce => {
                Some(start.elapsed())
            }
            _ => None,
        };
        record_sg_status(ctx, uuid, host, up);
    }
}

fn record_sg_status(ctx: &WorkerContext, uuid: Uuid, host: String, rtt: Option<Duration>) {
    let mut node = ctx.node.write().unwrap();
    node.sg_statuses.insert((uuid, host), SgStatus {
        up:          rtt.is_some(),
        last_rtt:    rtt,
        last_polled: Instant::now(),
    });
}

/// Ensure active connections exist to all peers that require them.
///
/// For each desired peer (own SGs/DGs and contact SGs/DGs, depending on local
/// device grade) this checks whether a healthy ActiveConnection already exists.
/// If not — and no ConnectRequest is already pending — it generates an ephemeral
/// key pair, stores a PendingConnection, and sends a ConnectRequest.
///
/// Also handles renewal: connections within RENEW_THRESHOLD of expiry are treated
/// as missing so the new session is established before the old one lapses.
///
/// Triggered at startup and then every MAINTAIN_CONNECTIONS_INTERVAL.
pub fn maintain_connections(ctx: &WorkerContext) {
    let now = SystemTime::now();

    // ── Evict PendingConnections whose ConnectAck never arrived ───────────────
    // A silent rejection on the SG side (e.g. a ConnectRequest that lost the
    // race with its own DeviceRegistration) leaves us stuck — clear the entry
    // here so the peer falls out of `pending` below and gets a fresh attempt.
    {
        let mut node = ctx.node.write().unwrap();
        let expired: Vec<u16> = node.owner.pending_connections.iter()
            .filter(|(_, p)| now.duration_since(p.created_at)
                .map(|d| d >= PENDING_CONNECTION_TIMEOUT)
                .unwrap_or(false))
            .map(|(k, _)| *k)
            .collect();
        for id in expired {
            if let Some(p) = node.owner.pending_connections.remove(&id) {
                println!("[poll_connections] evicting stale pending conn {id} to peer {:02x?}",
                    &p.peer_device_uuid[..4]);
            }
        }
    }

    // ── Collect desired peers and current state (read lock) ───────────────────
    let (need_conn, our_longterm_pk, our_longterm_sk, our_device_uuid) = {
        let node = ctx.node.read().unwrap();
        let our_device_uuid = node.device_uuid;
        let our_longterm_pk = node.owner.key_pair.public_key;
        let our_longterm_sk = node.owner.key_pair.private_key;

        let is_sg = node.owner.user.devices.iter()
            .find(|d| d.uuid == our_device_uuid)
            .map(|d| matches!(d.grade, DeviceGrade::SG))
            .unwrap_or(false);

        // Desired peers — who WE initiate connections to. Directional, to avoid
        // connection glare (both peers initiating at once, whose crossed
        // handshakes leave each side keyed on a connection the other evicted,
        // breaking all later encrypted traffic — and SG↔SG never self-heals).
        //
        // Rule: only ever initiate TO an SG, and to a peer SG only when we are a
        // DG, or we are an SG with the lower device_uuid. So:
        //   - DG → SG: only the DG initiates (an SG never initiates to a DG; it
        //     gets the reciprocal connection when the DG connects to it).
        //   - SG ↔ SG: only the lower-uuid SG initiates.
        // Exactly one side of any pair initiates, so connect_request only ever
        // sees requests from the rightful initiator and its evict-rebuild is safe.
        let want_initiate = |d: &Device| -> bool {
            matches!(d.grade, DeviceGrade::SG) && (!is_sg || our_device_uuid < d.uuid)
        };
        // Skip peers with no resolvable address — happy eyeballs data, if present,
        // picks the lowest-RTT up address; otherwise we fall back to the first
        // resolvable entry in the peer's host list.
        let mut desired: Vec<(Uuid, SocketAddrV4, PublicKey)> = Vec::new();
        for d in &node.owner.user.devices {
            if d.uuid == our_device_uuid { continue; }
            if want_initiate(d) {
                if let Some(addr) = best_address_for_device(&node, &d.uuid) {
                    desired.push((d.uuid, addr, our_longterm_pk));
                }
            }
        }
        for contact in &node.owner.contact_users {
            for d in &contact.user.devices {
                if want_initiate(d) {
                    if let Some(addr) = best_address_for_device(&node, &d.uuid) {
                        desired.push((d.uuid, addr, contact.public_key));
                    }
                }
            }
        }

        // Devices with connections healthy enough to not need renewal.
        let healthy: HashSet<Uuid> = node.owner.active_connections.values()
            .filter(|c| c.timeout.duration_since(now)
                .map(|r| r >= RENEW_THRESHOLD)
                .unwrap_or(false))
            .map(|c| c.device_uuid)
            .collect();

        // Devices already waiting for a ConnectAck.
        let pending: HashSet<Uuid> = node.owner.pending_connections.values()
            .map(|p| p.peer_device_uuid)
            .collect();

        let need_conn: Vec<(Uuid, SocketAddrV4, PublicKey)> = desired.into_iter()
            .filter(|(uuid, _, _)| !healthy.contains(uuid) && !pending.contains(uuid))
            .collect();

        (need_conn, our_longterm_pk, our_longterm_sk, our_device_uuid)
    };

    // ── For each peer that needs a connection, allocate state and send ────────
    let mut issued: u32 = 0;
    for (peer_uuid, peer_host, peer_longterm_pk) in need_conn {
        let result: Option<(u16, PublicKey)> = {
            let mut node = ctx.node.write().unwrap();

            // Re-check under write lock to avoid TOCTOU if this action fires twice.
            let already_covered =
                node.owner.pending_connections.values().any(|p| p.peer_device_uuid == peer_uuid)
                || node.owner.active_connections.values().any(|c| c.device_uuid == peer_uuid
                    && c.timeout.duration_since(now)
                        .map(|r| r >= RENEW_THRESHOLD)
                        .unwrap_or(false));

            if already_covered {
                None
            } else {
                let conn_id  = allocate_conn_id(&node);
                let key_pair = generate_x25519_keypair();
                let pk_copy  = key_pair.public_key;
                node.owner.pending_connections.insert(conn_id, PendingConnection {
                    our_conn_id:      conn_id,
                    our_key_pair:     key_pair,
                    peer_device_uuid: peer_uuid,
                    peer_longterm_pk,
                    created_at:       now,
                });
                Some((conn_id, pk_copy))
            }
        };

        let Some((conn_id, our_ephemeral_pk)) = result else { continue; };

        // Build ConnectRequest:
        //   [op=0x20][conn_id: u16][our_device_uuid: 16][our_ephemeral_pk: 32][our_longterm_pk: 32][sig: 64]
        let mut pkt = [0u8; 147];
        pkt[0]        = CONNECT_REQUEST_OP;
        pkt[1..3].copy_from_slice(&conn_id.to_be_bytes());
        pkt[3..19].copy_from_slice(&our_device_uuid);
        pkt[19..51].copy_from_slice(&our_ephemeral_pk);
        pkt[51..83].copy_from_slice(&our_longterm_pk);
        let sig = ed25519_sign(&our_longterm_sk, &pkt[0..83]);
        pkt[83..147].copy_from_slice(&sig);

        println!("[poll_connections] sending connect request to {peer_host} (peer {:02x?})", &peer_uuid[..4]);
        send(ctx, SocketAddr::V4(peer_host), &pkt);
        issued += 1;
    }

    // If we just issued any ConnectRequests, schedule a follow-up pass shortly
    // after PENDING_CONNECTION_TIMEOUT so silent failures are retried without
    // waiting the full MAINTAIN_CONNECTIONS_INTERVAL (5 minutes).
    if issued > 0 {
        ctx.scheduler_tx.send(ScheduleRequest {
            action: Action::MaintainConnections,
            delay:  PENDING_CONNECTION_TIMEOUT + Duration::from_millis(500),
        }).ok();
    }
}

/// Scheduled every 20 seconds on DG devices.
///
/// Sends encrypted keepalive packets (op `0x12`) to **every** SG this DG holds
/// an active connection to — its own SGs of any rank *and* each contact's SG.
///
/// A DG is reachable for inbound delivery only on NAT mappings it keeps warm.
/// It holds connections to several SGs: its own SGs, plus every contact's SG
/// (those deliver cross-user app packets straight to this DG via `relay_packet`).
/// Keeping only one mapping warm — the top-ranked own SG, as this used to —
/// means any *other* SG's sends to this DG are silently dropped by NAT once its
/// idle mapping closes, and aren't refreshed until the next ~22h connection
/// renewal. So fan the keepalive out to every connected SG at the keepalive
/// cadence.
///
/// Encrypting each keepalive with that connection's DG↔SG shared key also lets
/// the SG detect a stale/unknown connection and reply with a conn-reset
/// (op `0x13`) so the DG reconnects immediately.
pub fn keepalive_dg(ctx: &WorkerContext) {
    let outs: Vec<(Vec<u8>, SocketAddr)> = {
        let node       = ctx.node.read().unwrap();
        let local_uuid = node.device_uuid;

        // Only DGs need to send keepalives.
        let is_dg = node.owner.user.devices.iter()
            .find(|d| d.uuid == local_uuid)
            .map(|d| matches!(d.grade, DeviceGrade::DG))
            .unwrap_or(false);
        if !is_dg { return; }

        // Is `uuid` an SG we know — one of our own, or any contact's?
        let is_known_sg = |uuid: &Uuid| -> bool {
            node.owner.user.devices.iter()
                .any(|d| d.uuid == *uuid && matches!(d.grade, DeviceGrade::SG))
            || node.owner.contact_users.iter().any(|c| c.user.devices.iter()
                .any(|d| d.uuid == *uuid && matches!(d.grade, DeviceGrade::SG)))
        };

        // poll_sg up-test (treat an unpolled SG — e.g. a contact's SG we don't
        // actively poll — as up). Mirrors the test used by writer/relay selection.
        let is_up = |uuid: &Uuid| -> bool {
            let mut any_entry = false;
            let mut any_up = false;
            for ((u, _), status) in &node.sg_statuses {
                if *u == *uuid {
                    any_entry = true;
                    if status.up { any_up = true; }
                }
            }
            !any_entry || any_up
        };

        // One keepalive per connected SG that's up (or unpolled).
        node.owner.active_connections.values()
            .filter(|c| is_known_sg(&c.device_uuid) && is_up(&c.device_uuid))
            .map(|conn| (build_encrypted_packet(DG_KEEPALIVE_OP, conn, &[]), conn.peer_addr))
            .collect()
    };

    for (pkt, dest) in outs {
        send(ctx, dest, &pkt);
    }
}

/// Op 0x12 — DG encrypted keepalive, received on the SG side.
///
/// Attempts to decrypt the keepalive using the named connection.  If the
/// conn_id is unknown or decryption fails the SG replies with a conn-reset
/// (op `0x13`) so the DG evicts the stale connection and reconnects.
///
/// On success, refresh the connection's `peer_addr` and lifetime from this
/// packet: the keepalive's source is authoritative for where to reach the DG
/// right now (DGs roam and NAT bindings rebind), so app packets and relays to
/// this DG always target its current mapping rather than a fixed address
/// captured at connect time. The conn_id is the receiver-side id in the packet
/// header (see `decrypt_packet_body`).
pub fn dg_keepalive_receive(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let ok = {
        let node = ctx.node.read().unwrap();
        decrypt_packet_body(&node, &buf).is_some()
    };
    if !ok {
        send(ctx, src, &[CONN_RESET_OP]);
        return;
    }

    if buf.len() >= 2 {
        let conn_id = u16::from_be_bytes([buf[0], buf[1]]);
        let mut node = ctx.node.write().unwrap();
        if let Some(conn) = node.owner.active_connections.get_mut(&conn_id) {
            conn.peer_addr = src;
            conn.timeout   = SystemTime::now() + CONNECTION_LIFETIME;
        }
    }
}

/// Op 0x13 — SG conn-reset, received on the DG side.
///
/// The SG couldn't decrypt our keepalive, meaning it has no record of this
/// connection (e.g. it restarted).  Evict all active connections whose device
/// lives at the SG's IP so that `maintain_connections` can establish fresh ones.
pub fn conn_reset(src: SocketAddr, ctx: &WorkerContext) {
    let src_ip = match ipv4_from(src) {
        Some(ip) => ip,
        None => return,
    };

    let evicted = {
        let mut node = ctx.node.write().unwrap();
        // Evict any connection whose peer_addr matches the reset source IP.
        // This is strictly more correct than matching on a stored Device host
        // — the connection already knows what address it's talking to.
        let before = node.owner.active_connections.len();
        node.owner.active_connections.retain(|_, c| {
            match c.peer_addr {
                SocketAddr::V4(a) => *a.ip() != src_ip,
                _ => true,
            }
        });
        node.owner.active_connections.len() < before
    };

    if evicted {
        ctx.scheduler_tx.send(ScheduleRequest {
            action: Action::MaintainConnections,
            delay: Duration::ZERO,
        }).ok();
    }
}
