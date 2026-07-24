//! DG↔DG tunnels via SG: setup, key exchange, forward, delivery, cleanup.
//!
//! Ops 0x50–0x54 plus scheduled `setup_tunnel` / `cleanup_tunnels`.
//! Connection IDs come from the parent `allocate_conn_id`.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

use super::super::action_queue::WorkerContext;
use super::super::crypto::{
    aead_domain, aead_key_from_dh, generate_x25519_keypair, xchacha20_decrypt,
};
use super::super::data_models::{
    ActiveConnection, ActiveTunnel, Node, PendingTunnel, PendingTunnelConnection, X25519PublicKey,
    Uuid, CONNECTION_LIFETIME, TUNNEL_COUNTER_WINDOW,
};
use super::super::wire::*;
use super::super::wire::uuid_hex;
use super::{allocate_conn_id, fabric_event, local_approved_app_host, send};

// ── Tunnel handlers ───────────────────────────────────────────────────────────

/// Allocate a tunnel ID not already used in active or pending tunnel maps.
fn allocate_tunnel_id(node: &Node) -> u16 {
    let max = node.owner.active_tunnels.keys()
        .chain(node.owner.pending_tunnels.keys())
        .copied()
        .max()
        .unwrap_or(0);
    max.wrapping_add(1)
}

/// Scheduled by `relay_packet` once the per-pair threshold is reached.
///
/// Allocates a tunnel ID, stores a `PendingTunnel`, and sends `TUNNEL_INIT`
/// (op 0x50) to the sender DG to kick off the DG-to-DG key exchange.
pub fn setup_tunnel(sender_uuid: Uuid, dest_uuid: Uuid, ctx: &WorkerContext) {
    let (tunnel_id, sender_addr) = {
        let mut node = ctx.node.write().unwrap();

        // Abort if connections to either DG are gone.
        let has_sender = node.owner.active_connections.values()
            .any(|c| c.device_uuid == sender_uuid);
        let has_dest   = node.owner.active_connections.values()
            .any(|c| c.device_uuid == dest_uuid);
        if !has_sender || !has_dest { return; }

        let tunnel_id = allocate_tunnel_id(&node);
        node.owner.pending_tunnels.insert(tunnel_id, PendingTunnel {
            tunnel_id,
            sender_device_uuid: sender_uuid,
            dest_device_uuid:   dest_uuid,
            sender_ephem_pk:    None,
        });

        let sender_addr = node.owner.active_connections.values()
            .find(|c| c.device_uuid == sender_uuid)
            .map(|c| c.peer_addr);

        (tunnel_id, sender_addr)
    };

    if let Some(dest) = sender_addr {
        // TUNNEL_INIT: [op=0x50][tunnel_id: u16][dest_device_uuid: 16]
        let mut pkt = [0u8; 19];
        pkt[0]     = TUNNEL_INIT_OP;
        pkt[1..3].copy_from_slice(&tunnel_id.to_be_bytes());
        pkt[3..19].copy_from_slice(&dest_uuid);
        fabric_event(
            "tunnel_init",
            &[
                ("tunnel_id", &tunnel_id.to_string()),
                ("sender", &uuid_hex(&sender_uuid)),
                ("dest", &uuid_hex(&dest_uuid)),
                ("to", &dest.to_string()),
            ],
        );
        send(ctx, dest, &pkt);
    }
}

/// Op 0x50 — Tunnel init (SG → DG_sender).
///
/// DG_sender generates an ephemeral X25519 key pair, stores it as a
/// `PendingTunnelConnection`, and sends `TUNNEL_CONNECT_REQUEST` (0x52) back
/// to the SG so the key exchange can be relayed to DG_dest.
///
/// Payload: [tunnel_id: u16][dest_device_uuid: 16]
pub fn tunnel_init(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 18 {
        eprintln!("[tunnel_init] packet too short from {src}");
        return;
    }
    let tunnel_id        = u16::from_be_bytes([buf[0], buf[1]]);
    let Some(dest_device_uuid) = slice_arr::<16>(&buf, 2) else { return; };

    let (our_conn_id, our_ephem_pk) = {
        let mut node = ctx.node.write().unwrap();
        let conn_id  = allocate_conn_id(&node);
        let key_pair = generate_x25519_keypair();
        let pk_copy  = key_pair.public_key;
        node.owner.pending_tunnel_connections.insert(tunnel_id, PendingTunnelConnection {
            tunnel_id,
            our_conn_id: conn_id,
            our_key_pair: key_pair,
            dest_device_uuid,
        });
        (conn_id, pk_copy)
    };

    let _ = our_conn_id; // conn_id is stored in the pending struct; not sent in this packet.

    // Send TUNNEL_CONNECT_REQUEST back to the SG that sent TUNNEL_INIT.
    // Format: [op=0x52][tunnel_id: u16][our_ephem_pk: 32]
    let mut pkt = [0u8; 35];
    pkt[0]     = TUNNEL_CONNECT_REQUEST_OP;
    pkt[1..3].copy_from_slice(&tunnel_id.to_be_bytes());
    pkt[3..35].copy_from_slice(our_ephem_pk.as_bytes());
    send(ctx, src, &pkt);
}

/// Op 0x52 — Tunnel connect request.
///
/// Two roles, distinguished by packet length:
///
/// **SG relay** (buf len == 34): received from DG_sender `[tunnel_id: u16][sender_ephem_pk: 32]`.
/// Stores the sender's ephemeral PK in the pending tunnel and forwards the
/// request to DG_dest with the extended format (+ sender_device_uuid).
///
/// **DG_dest** (buf len >= 50): received from SG `[tunnel_id: u16][sender_ephem_pk: 32][sender_device_uuid: 16]`.
/// Generates own ephemeral key pair, derives shared secret, stores an
/// `ActiveConnection` to DG_sender, updates `dg_tunnel_map`, and replies with
/// `TUNNEL_CONNECT_ACK` (0x53) to the SG.
pub fn tunnel_connect_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 34 {
        eprintln!("[tunnel_connect_request] packet too short from {src}");
        return;
    }
    let tunnel_id       = u16::from_be_bytes([buf[0], buf[1]]);
    let Some(sender_ephem_pk) = slice_arr::<32>(&buf, 2).map(X25519PublicKey) else { return; };

    // Determine role by checking which pending map has this tunnel_id.
    let is_sg_relay = ctx.node.read().unwrap()
        .owner.pending_tunnels.contains_key(&tunnel_id);

    if is_sg_relay {
        // ── SG relay path ─────────────────────────────────────────────────────
        let dest_host = {
            let mut node = ctx.node.write().unwrap();
            let Some(pending) = node.owner.pending_tunnels.get_mut(&tunnel_id) else {
                eprintln!("[tunnel_connect_request] no pending tunnel {tunnel_id} from {src}");
                return;
            };
            pending.sender_ephem_pk = Some(sender_ephem_pk);
            let dest_uuid   = pending.dest_device_uuid;
            let sender_uuid = pending.sender_device_uuid;

            let addr = node.owner.active_connections.values()
                .find(|c| c.device_uuid == dest_uuid)
                .map(|c| c.peer_addr);
            (addr, sender_uuid)
        };

        if let (Some(dest), sender_uuid) = dest_host {
            // Forward to DG_dest: [op=0x52][tunnel_id: u16][sender_ephem_pk: 32][sender_device_uuid: 16]
            let mut pkt = [0u8; 51];
            pkt[0]      = TUNNEL_CONNECT_REQUEST_OP;
            pkt[1..3].copy_from_slice(&tunnel_id.to_be_bytes());
            pkt[3..35].copy_from_slice(sender_ephem_pk.as_bytes());
            pkt[35..51].copy_from_slice(&sender_uuid);
            send(ctx, dest, &pkt);
        }
    } else if buf.len() >= 50 {
        // ── DG_dest path ──────────────────────────────────────────────────────
        let Some(sender_device_uuid) = slice_arr::<16>(&buf, 34) else { return; };

        let (conn_id, our_ephem_pk) = {
            let mut node    = ctx.node.write().unwrap();
            let conn_id     = allocate_conn_id(&node);
            let key_pair    = generate_x25519_keypair();
            let pk_copy     = key_pair.public_key;

            node.owner.active_connections.insert(conn_id, ActiveConnection {
                id:                        conn_id,
                timeout:                   SystemTime::now() + CONNECTION_LIFETIME,
                key_pair,
                peer_public_key:           sender_ephem_pk,
                peer_active_connection_id: 0, // not used for tunnel decryption
                device_uuid:               sender_device_uuid,
                peer_addr:                 src,
            });
            node.owner.dg_tunnel_map.insert(tunnel_id, conn_id);
            fabric_event(
                "tunnel_ready",
                &[
                    ("role", "dg_dest"),
                    ("tunnel_id", &tunnel_id.to_string()),
                    ("peer", &uuid_hex(&sender_device_uuid)),
                ],
            );
            (conn_id, pk_copy)
        };

        let _ = conn_id;

        // Reply TUNNEL_CONNECT_ACK to the SG that forwarded this request.
        // Format: [op=0x53][tunnel_id: u16][our_ephem_pk: 32]
        let mut pkt = [0u8; 35];
        pkt[0]     = TUNNEL_CONNECT_ACK_OP;
        pkt[1..3].copy_from_slice(&tunnel_id.to_be_bytes());
        pkt[3..35].copy_from_slice(our_ephem_pk.as_bytes());
        send(ctx, src, &pkt);
    } else {
        eprintln!("[tunnel_connect_request] unexpected packet length {} from {src}", buf.len());
    }
}

/// Op 0x53 — Tunnel connect ack.
///
/// Two roles, distinguished by which pending map holds the tunnel_id:
///
/// **SG relay** (`pending_tunnels` has tunnel_id): received from DG_dest.
/// Promotes the `PendingTunnel` to an `ActiveTunnel`, then forwards the ack
/// to DG_sender.
///
/// **DG_sender** (`pending_tunnel_connections` has tunnel_id): received from SG.
/// Completes the key exchange: stores an `ActiveConnection` to DG_dest and
/// updates `dg_tunnel_map`.
///
/// Payload: [tunnel_id: u16][ephem_pk: 32]
pub fn tunnel_connect_ack(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 34 {
        eprintln!("[tunnel_connect_ack] packet too short from {src}");
        return;
    }
    let tunnel_id    = u16::from_be_bytes([buf[0], buf[1]]);
    let Some(dest_ephem_pk) = slice_arr::<32>(&buf, 2).map(X25519PublicKey) else { return; };

    let is_sg_relay = ctx.node.read().unwrap()
        .owner.pending_tunnels.contains_key(&tunnel_id);
    let is_dg_sender = ctx.node.read().unwrap()
        .owner.pending_tunnel_connections.contains_key(&tunnel_id);

    if is_sg_relay {
        // ── SG relay path ─────────────────────────────────────────────────────
        let sender_host = {
            let mut node = ctx.node.write().unwrap();
            let Some(pending) = node.owner.pending_tunnels.remove(&tunnel_id) else { return; };

            // Link the two active connections as an ActiveTunnel.
            let conn_a = node.owner.active_connections.values()
                .find(|c| c.device_uuid == pending.sender_device_uuid)
                .map(|c| c.id);
            let conn_b = node.owner.active_connections.values()
                .find(|c| c.device_uuid == pending.dest_device_uuid)
                .map(|c| c.id);

            if let (Some(a), Some(b)) = (conn_a, conn_b) {
                node.owner.active_tunnels.insert(tunnel_id, ActiveTunnel {
                    id:              tunnel_id,
                    connection_a_id: a,
                    connection_b_id: b,
                    last_used_at:    Instant::now(),
                });
                fabric_event(
                    "tunnel_up",
                    &[
                        ("role", "sg"),
                        ("tunnel_id", &tunnel_id.to_string()),
                        ("sender", &uuid_hex(&pending.sender_device_uuid)),
                        ("dest", &uuid_hex(&pending.dest_device_uuid)),
                        ("conn_a", &a.to_string()),
                        ("conn_b", &b.to_string()),
                    ],
                );
            } else {
                eprintln!(
                    "[tunnel_connect_ack] tunnel {tunnel_id} missing conn for sender/dest on SG"
                );
            }

            node.owner.active_connections.values()
                .find(|c| c.device_uuid == pending.sender_device_uuid)
                .map(|c| c.peer_addr)
        };

        if let Some(dest) = sender_host {
            // Forward ack to DG_sender: [op=0x53][tunnel_id: u16][dest_ephem_pk: 32]
            let mut pkt = [0u8; 35];
            pkt[0]     = TUNNEL_CONNECT_ACK_OP;
            pkt[1..3].copy_from_slice(&tunnel_id.to_be_bytes());
            pkt[3..35].copy_from_slice(dest_ephem_pk.as_bytes());
            send(ctx, dest, &pkt);
        }
    } else if is_dg_sender {
        // ── DG_sender path ────────────────────────────────────────────────────
        let mut node = ctx.node.write().unwrap();
        let Some(ptc) = node.owner.pending_tunnel_connections.remove(&tunnel_id) else { return; };
        let dest_uuid = ptc.dest_device_uuid;

        node.owner.active_connections.insert(ptc.our_conn_id, ActiveConnection {
            id:                        ptc.our_conn_id,
            timeout:                   SystemTime::now() + CONNECTION_LIFETIME,
            key_pair:                  ptc.our_key_pair,
            peer_public_key:           dest_ephem_pk,
            peer_active_connection_id: 0, // not used for tunnel packets
            device_uuid:               ptc.dest_device_uuid,
            peer_addr:                 src,
        });
        node.owner.dg_tunnel_map.insert(tunnel_id, ptc.our_conn_id);
        fabric_event(
            "tunnel_ready",
            &[
                ("role", "dg_sender"),
                ("tunnel_id", &tunnel_id.to_string()),
                ("peer", &uuid_hex(&dest_uuid)),
            ],
        );
    } else {
        eprintln!("[tunnel_connect_ack] unknown tunnel_id {tunnel_id} from {src}");
    }
}

/// Op 0x51 — Tunnel forward (DG → SG).
///
/// The SG looks up the tunnel by ID, identifies the outbound leg, and forwards
/// the nonce+ciphertext payload as-is without decryption (op 0x54).
///
/// Payload: [sender_sg_conn_id: u16][tunnel_id: u16][nonce: 24][ciphertext...]
///
/// The SG does not decrypt; it still caps the blob at
/// [`MAX_TUNNEL_FORWARD_BLOB`] so an oversized opaque cannot be amplified.
pub fn tunnel_forward(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 28 {
        eprintln!("[tunnel_forward] packet too short from {src}");
        return;
    }
    let sender_sg_conn_id = u16::from_be_bytes([buf[0], buf[1]]);
    let tunnel_id         = u16::from_be_bytes([buf[2], buf[3]]);
    let payload           = &buf[4..]; // nonce + ciphertext, forwarded as-is
    if payload.len() > MAX_TUNNEL_FORWARD_BLOB {
        eprintln!(
            "[tunnel_forward] blob too large ({} > {MAX_TUNNEL_FORWARD_BLOB}) tunnel {tunnel_id} from {src}",
            payload.len()
        );
        return;
    }

    let dest_host = {
        let mut node = ctx.node.write().unwrap();
        let Some(tunnel) = node.owner.active_tunnels.get_mut(&tunnel_id) else {
            eprintln!("[tunnel_forward] unknown tunnel_id {tunnel_id} from {src}");
            return;
        };

        let out_conn_id = if tunnel.connection_a_id == sender_sg_conn_id {
            tunnel.connection_b_id
        } else if tunnel.connection_b_id == sender_sg_conn_id {
            tunnel.connection_a_id
        } else {
            eprintln!("[tunnel_forward] conn_id {sender_sg_conn_id} not in tunnel {tunnel_id}");
            return;
        };

        tunnel.last_used_at = Instant::now();

        node.owner.active_connections.get(&out_conn_id)
            .map(|c| c.peer_addr)
    };

    if let Some(dest) = dest_host {
        // Forward as TUNNEL_DELIVERY (0x54): [op][tunnel_id: u16][nonce+ciphertext]
        let mut pkt = Vec::with_capacity(3 + payload.len());
        pkt.push(TUNNEL_DELIVERY_OP);
        pkt.extend_from_slice(&tunnel_id.to_be_bytes());
        pkt.extend_from_slice(payload);
        fabric_event(
            "tunnel_forward",
            &[
                ("tunnel_id", &tunnel_id.to_string()),
                ("from", &src.to_string()),
                ("to", &dest.to_string()),
                ("blob_len", &payload.len().to_string()),
            ],
        );
        send(ctx, dest, &pkt);
    }
}

/// Op 0x54 — Tunnel delivery (SG → DG).
///
/// DG_dest decrypts the payload with the DG-to-DG shared secret (looked up via
/// `dg_tunnel_map`) and pushes it to the target local app.
///
/// Payload: [tunnel_id: u16][nonce: 24][ciphertext...]
///
/// Decrypted app payload must be ≤ [`MAX_APP_PAYLOAD`].
/// Destination app must be **user-approved** or the push is dropped.
pub fn tunnel_delivery(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 26 {
        eprintln!("[tunnel_delivery] packet too short from {src}");
        return;
    }
    let tunnel_id       = u16::from_be_bytes([buf[0], buf[1]]);
    let Some(nonce) = slice_arr::<24>(&buf, 2) else { return; };
    let ciphertext      = &buf[26..];

    let (push_pkt, app_host) = {
        let node = ctx.node.read().unwrap();

        let Some(&conn_id) = node.owner.dg_tunnel_map.get(&tunnel_id) else {
            eprintln!("[tunnel_delivery] unknown tunnel_id {tunnel_id} from {src}");
            return;
        };
        let Some(conn) = node.owner.active_connections.get(&conn_id) else {
            eprintln!("[tunnel_delivery] no active connection for tunnel {tunnel_id}");
            return;
        };

        let aead_key = aead_key_from_dh(
            &conn.key_pair.private_key,
            &conn.peer_public_key,
            aead_domain::TUNNEL,
        );
        let Some(plaintext) = xchacha20_decrypt(&aead_key, &nonce, ciphertext) else {
            eprintln!("[tunnel_delivery] decryption failed for tunnel {tunnel_id} from {src}");
            return;
        };
        if plaintext.len() < 32 {
            eprintln!("[tunnel_delivery] plaintext too short for tunnel {tunnel_id}");
            return;
        }

        let Some(dest_app_id) = slice_arr::<16>(&plaintext, 0) else { return; };
        let Some(sender_app_id) = slice_arr::<16>(&plaintext, 16) else { return; };
        let payload             = &plaintext[32..];
        if payload.len() > MAX_APP_PAYLOAD {
            eprintln!(
                "[tunnel_delivery] app payload too large ({} > {MAX_APP_PAYLOAD}) tunnel {tunnel_id}",
                payload.len()
            );
            return;
        }

        let Some(app_host) = local_approved_app_host(&node, dest_app_id) else {
            eprintln!(
                "[tunnel_delivery] no approved app {} for tunnel {tunnel_id}",
                uuid_hex(&dest_app_id)
            );
            return;
        };

        let mut push = Vec::with_capacity(17 + payload.len());
        push.push(APP_PUSH_OP);
        push.extend_from_slice(&sender_app_id);
        push.extend_from_slice(payload);

        (push, app_host)
    };

    send(ctx, SocketAddr::V4(app_host), &push_pkt);
}

/// Recurring cleanup: remove idle tunnels and stale counters.
///
/// After teardown, send path must still deliver via standard relay (§6.4):
/// DG drops `dg_tunnel_map` when the DG↔DG session expires; SG drops idle
/// `active_tunnels`. Neither blocks `app_send_packet` relay fallback.
pub fn cleanup_tunnels(ctx: &WorkerContext) {
    const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
    let now     = Instant::now();
    let now_sys = SystemTime::now();

    let mut node = ctx.node.write().unwrap();

    // SG: remove idle ActiveTunnels.
    let before_sg = node.owner.active_tunnels.len();
    node.owner.active_tunnels.retain(|_, t| {
        now.duration_since(t.last_used_at) < TUNNEL_IDLE_TIMEOUT
    });
    let removed_sg = before_sg.saturating_sub(node.owner.active_tunnels.len());

    // SG: drop pending setups when either leg connection is gone.
    let stale_pending: Vec<u16> = node
        .owner
        .pending_tunnels
        .iter()
        .filter(|(_, p)| {
            let a = node
                .owner
                .active_connections
                .values()
                .any(|c| c.device_uuid == p.sender_device_uuid);
            let b = node
                .owner
                .active_connections
                .values()
                .any(|c| c.device_uuid == p.dest_device_uuid);
            !(a && b)
        })
        .map(|(&id, _)| id)
        .collect();
    for id in stale_pending {
        node.owner.pending_tunnels.remove(&id);
    }

    // SG: clear stale tunnel counters (window expired).
    node.owner.tunnel_counters.retain(|_, c| {
        now.duration_since(c.window_start) < TUNNEL_COUNTER_WINDOW
    });

    // DG: remove dg_tunnel_map entries whose ActiveConnection has expired
    // or vanished — after this, app_send uses relay (§6.4).
    let expired_tunnels: Vec<u16> = node
        .owner
        .dg_tunnel_map
        .iter()
        .filter(|(_, conn_id)| {
            !node
                .owner
                .active_connections
                .get(*conn_id)
                .map(|c| c.timeout > now_sys)
                .unwrap_or(false)
        })
        .map(|(&tid, _)| tid)
        .collect();
    let removed_dg = expired_tunnels.len();
    for tid in &expired_tunnels {
        node.owner.dg_tunnel_map.remove(tid);
        node.owner.pending_tunnel_connections.remove(tid);
    }

    if removed_sg > 0 || removed_dg > 0 {
        drop(node);
        super::fabric_event(
            "tunnel_teardown",
            &[
                ("sg_idle_removed", &removed_sg.to_string()),
                ("dg_map_removed", &removed_dg.to_string()),
            ],
        );
    }
}


