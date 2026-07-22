use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant, SystemTime};

use super::action_queue::WorkerContext;
use super::crypto::{
    aead_domain, aead_key_from_dh, build_encrypted_packet, decrypt_packet_body, ed25519_sign,
    ed25519_verify, generate_ed25519_keypair, generate_x25519_keypair, xchacha20_decrypt,
    xchacha20_encrypt,
};
use super::data_models::{
    ActiveConnection, ActiveTunnel, Application, Contact, Device, DeviceGrade,
    Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey, Invitation, Owner, PendingBootstrap,
    PendingConnection, PendingContactExchange, PendingDeviceAcceptance, PendingTunnel,
    PendingTunnelConnection, Scope, SgStatus, SyncVersion, TunnelCounter, User, Uuid,
    WriteLogEntry, X25519KeyPair, X25519PublicKey, WRITE_LOG_RETENTION,
    CONNECTION_LIFETIME, TUNNEL_COUNTER_WINDOW, TUNNEL_THRESHOLD, generate_key_bytes, generate_uuid,
};
// Op bytes, reply codes, and shared binary parse helpers.
use super::wire::*;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse the `PNET_HOSTS` env var into an advertised-hostname list.
/// Comma-separated entries with optional `:port` suffix (default 7777).
/// Returns empty vec if unset or contains only whitespace.
pub fn parse_pnet_hosts() -> Vec<String> {
    std::env::var("PNET_HOSTS")
        .ok()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn send(ctx: &WorkerContext, dest: SocketAddr, data: &[u8]) {
    if let Err(e) = ctx.udp_socket.send_to(data, dest) {
        eprintln!("[send] send_to {dest} failed: {e}");
    }
}

fn send_error(ctx: &WorkerContext, dest: SocketAddr, code: u8) {
    send(ctx, dest, &[STATUS_ERR, code]);
}

/// Extract an IPv4 address from a SocketAddr, mapping IPv4-in-IPv6 if needed.

// Local app edge (register/update/get-data/send + inbound app_packet push).
mod app_edge;
pub use app_edge::{app_get_data, app_packet, app_register, app_send_packet, app_update};

mod sessions;
pub use sessions::{
    conn_reset, connect_ack, connect_request, dg_keepalive_receive,
    keepalive_dg, maintain_connections, poll_sg, sg_ping,
};

mod bootstrap;
pub use bootstrap::{
    bootstrap_request, bootstrap_response, contact_request, contact_response,
    device_registration, generate_invitation_request, generate_invitation_response,
    start_bootstrap,
};
// UI / invite helpers + test-facing wire helpers (handlers-tree private).
pub(crate) use bootstrap::{
    decode_invitation_code, encode_invitation_code, generate_contact_invitation,
    generate_device_invitation, initiate_bootstrap, initiate_contact_exchange,
    serialize_contact_payload, top_online_sg,
};

mod routing;
pub use routing::{WriterTarget, find_writer_sg};
pub(crate) use routing::{
    best_address_for_device, best_sg_connection, find_pull_source, find_writer_sg_probing,
    ipv4_from, resolve_host_entry, resolve_hosts, sg_candidates_for_dest,
    top_ranked_sg_for_device,
};

mod sync;
pub use sync::{
    Change, ContactDeviceCard, MergeOutput, WriteError, cross_user_pull_request,
    cross_user_pull_response, cross_user_update_available, merge_ack, merge_logs,
    merge_proposal, partition_reconcile_tick, request_change, request_change_idempotent,
    sync_pull, sync_pull_request, sync_pull_response, sync_update_available,
    sync_write_ack, sync_write_request, watermark_probe_request, watermark_probe_response,
};
pub(crate) use sync::{
    apply_change_locally, apply_public_state, build_merge_ack_body,
    build_merge_proposal_body, build_merge_proposal_for_peer, bumped_scopes,
    ContactData, cross_user_pull_for_contact, cross_user_pull_on_reconnect, deserialize_change,
    deserialize_contact_data, devices_to_cards, notify_contacts, parse_merge_ack_body,
    parse_merge_proposal_body, parse_watermark_map, partition_reconcile_on_reconnect,
    serialize_change, serialize_contact_data, serialize_public_state, serialize_watermark_map,
};

mod tunnels;
pub use tunnels::{
    cleanup_tunnels, setup_tunnel, tunnel_connect_ack, tunnel_connect_request,
    tunnel_delivery, tunnel_forward, tunnel_init,
};

mod admin_ui;
pub use admin_ui::{apply_new_user_setup, ui_request};
pub(crate) use admin_ui::{
    UI_ERR_PUBLISH_FAILED, approve_app, complete_setup, form_field, partition_banner,
    reject_app, rename_app, render_diagnostics, url_decode,
};


// ── Peer pNet node handlers ───────────────────────────────────────────────────
// Op bytes and shared wire parse helpers: `crate::lib::wire`.

/// How long the SG keeps a PendingDeviceAcceptance waiting for DeviceRegistration.

/// Allocate a connection ID that is not already in use in either the active or
/// pending connection maps.  Increments from the current maximum; wraps on overflow.
fn allocate_conn_id(node: &super::data_models::Node) -> u16 {
    let max = node.owner.active_connections.keys()
        .chain(node.owner.pending_connections.keys())
        .copied()
        .max()
        .unwrap_or(0);
    let mut candidate = max.wrapping_add(1);
    loop {
        if !node.owner.active_connections.contains_key(&candidate)
            && !node.owner.pending_connections.contains_key(&candidate)
        {
            return candidate;
        }
        candidate = candidate.wrapping_add(1);
    }
}


// ── Bootstrap payload serialization ──────────────────────────────────────────
//
// Format of the bootstrap payload (user data, encrypted in BootstrapResponse):
//   [alias: u8 len + bytes]
//   [uuid: 16]
//   [long_term_pk: 32]
//   [long_term_sk: 32]
//   [device_count: u8]
//     each device: [uuid:16][alias: u8+bytes][grade:u8 (0=DG,1=SG)][rank:u8]
//                  [host_count:u8][each host: u8+bytes]
//   [contact_count: u8]
//     each contact: [uuid:16][alias: u8+bytes][public_key:32][device_count:u8][...devices...]
//
// Format of the DeviceRegistration payload (encrypted in DeviceRegistration):
//   single device entry (same layout as above)

// push_str / read_str / read_arr / uuid_hex / uuid_from_hex: `wire`.

fn push_device(buf: &mut Vec<u8>, d: &Device) {
    buf.extend_from_slice(&d.uuid);
    push_str(buf, &d.alias);
    buf.push(if matches!(d.grade, DeviceGrade::SG) { 1 } else { 0 });
    // sg_rank: 0 = None/DG, 1–255 = rank value (clamped to u8).
    buf.push(d.sg_rank.map(|r| r.min(255) as u8).unwrap_or(0));
    // hosts: length-prefixed list of length-prefixed hostname strings.
    buf.push(d.hosts.len().min(u8::MAX as usize) as u8);
    for h in d.hosts.iter().take(u8::MAX as usize) {
        push_str(buf, h);
    }
}

/// Local UDP host for a **user-approved** app on this device, if any.
///
/// Every inbound push path (`relay_packet` local delivery, `app_packet`,
/// `tunnel_delivery`) must use this so unapproved apps never receive traffic.
fn local_approved_app_host(
    node: &super::data_models::Node,
    dest_app_id: Uuid,
) -> Option<SocketAddrV4> {
    let device_uuid = node.device_uuid;
    node.owner
        .user
        .devices
        .iter()
        .find(|d| d.uuid == device_uuid)
        .and_then(|d| {
            d.applications
                .iter()
                .find(|a| a.id == dest_app_id && a.user_approved)
                .map(|a| a.host)
        })
}

fn read_device(data: &[u8], pos: &mut usize) -> Option<Device> {
    let uuid: Uuid   = read_arr(data, pos)?;
    let alias        = read_str(data, pos)?;
    let grade_byte   = *data.get(*pos)?; *pos += 1;
    let grade        = if grade_byte == 1 { DeviceGrade::SG } else { DeviceGrade::DG };
    let rank_byte    = *data.get(*pos)?; *pos += 1;
    let sg_rank      = if rank_byte == 0 { None } else { Some(rank_byte as u32) };
    let host_count   = *data.get(*pos)? as usize; *pos += 1;
    let mut hosts    = Vec::with_capacity(host_count);
    for _ in 0..host_count {
        hosts.push(read_str(data, pos)?);
    }
    Some(Device {
        uuid,
        alias,
        grade,
        sg_rank,
        hosts,
        applications: Vec::new(),
    })
}


// ── Scheduled action handlers ─────────────────────────────────────────────────


/// Op 0x40 — Relay packet (DG → SG).
///
/// The SG decrypts the body, reads the destination device UUID, re-encrypts
/// the inner payload for the destination, and forwards it as an AppPacket (0x41).
/// Also maintains a rolling per-pair packet count; once the threshold is reached
/// a `SetupTunnel` action is scheduled so subsequent traffic can bypass the
/// decrypt/re-encrypt step.
///
/// Encrypted body: [dest_device_uuid: 16][dest_app_id: 16][sender_app_id: 16][payload]
///
/// App `payload` must be ≤ [`MAX_APP_PAYLOAD`]; oversized bodies are dropped
/// (same budget as local `app_send_packet`).
pub fn relay_packet(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    // Extract the sender device UUID from the connection ID in the packet header
    // before taking the read lock, so we can update the tunnel counter later.
    let sender_uuid = if buf.len() >= 2 {
        let conn_id = u16::from_be_bytes([buf[0], buf[1]]);
        ctx.node.read().unwrap()
            .owner.active_connections.get(&conn_id)
            .map(|c| c.device_uuid)
    } else {
        None
    };

    // Decrypt and parse the body into owned values so we can branch on dest after
    // releasing the lock.
    let (local_uuid, dest_device_uuid, dest_app_id, sender_app_id, payload) = {
        let node = ctx.node.read().unwrap();

        let Some(plaintext) = decrypt_packet_body(&node, &buf) else {
            eprintln!("[relay_packet] decryption failed from {src}");
            return;
        };

        // Parse body.
        if plaintext.len() < 48 {
            eprintln!("[relay_packet] plaintext too short from {src}");
            return;
        }
        let dest_device_uuid: Uuid = plaintext[0..16].try_into().unwrap();
        let dest_app_id:      Uuid = plaintext[16..32].try_into().unwrap();
        let sender_app_id:    Uuid = plaintext[32..48].try_into().unwrap();
        let payload                = plaintext[48..].to_vec();
        if payload.len() > MAX_APP_PAYLOAD {
            eprintln!(
                "[relay_packet] app payload too large ({} > {MAX_APP_PAYLOAD}) from {src}",
                payload.len()
            );
            return;
        }

        (node.device_uuid, dest_device_uuid, dest_app_id, sender_app_id, payload)
    };

    // If the destination is this device (i.e. the SG is both relay and recipient),
    // deliver directly to the local app without going through active_connections.
    if dest_device_uuid == local_uuid {
        let app_host = {
            let node = ctx.node.read().unwrap();
            local_approved_app_host(&node, dest_app_id)
        };
        let Some(app_host) = app_host else {
            eprintln!("[relay_packet] no approved local app with id {}", uuid_hex(&dest_app_id));
            return;
        };
        let mut push = Vec::with_capacity(17 + payload.len());
        push.push(APP_PUSH_OP);
        push.extend_from_slice(&sender_app_id);
        push.extend_from_slice(&payload);
        send(ctx, SocketAddr::V4(app_host), &push);
        return;
    }

    let (pkt, dest, dest_uuid) = {
        let node = ctx.node.read().unwrap();

        // Find active connection to destination.
        let Some(dest_conn) = node.owner.active_connections.values()
            .find(|c| c.device_uuid == dest_device_uuid)
        else {
            eprintln!("[relay_packet] no active connection to dest {:?}", dest_device_uuid);
            return;
        };

        // AppPacket body: [dest_app_id: 16][sender_app_id: 16][payload]
        let mut app_body = Vec::with_capacity(32 + payload.len());
        app_body.extend_from_slice(&dest_app_id);
        app_body.extend_from_slice(&sender_app_id);
        app_body.extend_from_slice(&payload);

        let pkt = build_encrypted_packet(APP_PACKET_OP, dest_conn, &app_body);
        (pkt, dest_conn.peer_addr, dest_device_uuid)
    };

    send(ctx, dest, &pkt);

    // Tunnel threshold: count relay packets per (sender, dest) pair on this SG.
    // Once the threshold is reached within the window, schedule tunnel setup.
    let Some(sender_uuid) = sender_uuid else { return; };
    let pair = (sender_uuid, dest_uuid);
    let now  = Instant::now();

    let schedule_setup = {
        let mut node = ctx.node.write().unwrap();

        // Skip if a tunnel already exists for this pair.
        let tunnel_exists = node.owner.active_tunnels.values()
            .any(|t| {
                let a = node.owner.active_connections.get(&t.connection_a_id)
                    .map(|c| c.device_uuid);
                let b = node.owner.active_connections.get(&t.connection_b_id)
                    .map(|c| c.device_uuid);
                (a == Some(sender_uuid) && b == Some(dest_uuid))
                || (a == Some(dest_uuid)   && b == Some(sender_uuid))
            });
        let pending_exists = node.owner.pending_tunnels.values()
            .any(|p| p.sender_device_uuid == sender_uuid && p.dest_device_uuid == dest_uuid);

        if tunnel_exists || pending_exists {
            false
        } else {
            let counter = node.owner.tunnel_counters.entry(pair).or_insert(TunnelCounter {
                count:        0,
                window_start: now,
            });
            if now.duration_since(counter.window_start) >= TUNNEL_COUNTER_WINDOW {
                // Window expired — reset.
                counter.count        = 1;
                counter.window_start = now;
                false
            } else {
                counter.count += 1;
                if counter.count >= TUNNEL_THRESHOLD {
                    node.owner.tunnel_counters.remove(&pair);
                    true
                } else {
                    false
                }
            }
        }
    };

    if schedule_setup {
        ctx.scheduler_tx.send(super::action_queue::ScheduleRequest {
            action: super::action_queue::Action::SetupTunnel { sender_uuid, dest_uuid },
            delay:  std::time::Duration::ZERO,
        }).ok();
    }
}


// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::{Arc, RwLock, mpsc};
    use std::time::Duration;
    use super::super::action_queue::WorkerContext;
    use super::super::data_models::Node;
    use super::super::writer::WriteRequest;

    /// All the state needed to exercise a handler in isolation.
    struct TestCtx {
        ctx:        WorkerContext,
        app_socket: UdpSocket,   // receives the handler's reply
        _writer_rx: mpsc::Receiver<WriteRequest>,
        _sched_rx:  mpsc::Receiver<super::super::action_queue::ScheduleRequest>,
    }

    impl TestCtx {
        fn new() -> Self {
            // The "app" receives replies on this socket.
            let app_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            app_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();

            // pnet replies via this socket.
            let pnet_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());

            let node = Arc::new(RwLock::new(Node::new()));
            let (writer_tx, _writer_rx) = mpsc::sync_channel(64);
            let (scheduler_tx, _sched_rx) = mpsc::channel();

            let ctx = WorkerContext {
                node,
                udp_socket: pnet_socket,
                writer_tx,
                scheduler_tx,
                pending_invites: Default::default(),
                sessions: Arc::new(super::super::admin_auth::SessionStore::new()),
                app_rate_limits: Arc::new(std::sync::Mutex::new(
                    super::super::app_api::AppRateLimiter::new(),
                )),
            };
            TestCtx { ctx, app_socket, _writer_rx, _sched_rx }
        }

        /// The SocketAddr the "app" is listening on (used as `src` in requests).
        fn app_addr(&self) -> SocketAddr {
            self.app_socket.local_addr().unwrap()
        }

        /// Block until a reply arrives at the app socket.
        fn recv_reply(&self) -> Vec<u8> {
            let mut buf = [0u8; 4096];
            let (len, _) = self.app_socket.recv_from(&mut buf)
                .expect("no reply received within timeout");
            buf[..len].to_vec()
        }
    }

    // ── AppRegister ───────────────────────────────────────────────────────────

    fn register_packet(alias: &str, port: u16, protocol: &str) -> Vec<u8> {
        let mut buf = vec![alias.len() as u8];
        buf.extend_from_slice(alias.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
        buf.push(protocol.len() as u8);
        buf.extend_from_slice(protocol.as_bytes());
        buf
    }

    #[test]
    fn app_register_returns_token() {
        let t = TestCtx::new();
        app_register(t.app_addr(), register_packet("myapp", 9001, "udp"), &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);
        assert_eq!(reply.len(), 17, "reply should be status + 16-byte token");
    }

    #[test]
    fn app_register_adds_application_to_node() {
        let t = TestCtx::new();
        app_register(t.app_addr(), register_packet("myapp", 9001, "udp"), &t.ctx);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications.len(), 1);
        assert_eq!(device.applications[0].alias, "myapp");
        assert_eq!(device.applications[0].host.port(), 9001);
        assert!(!device.applications[0].user_approved);
    }

    #[test]
    fn app_register_each_app_gets_unique_id_and_token() {
        let t = TestCtx::new();
        app_register(t.app_addr(), register_packet("app1", 9001, "udp"), &t.ctx);
        let reply1 = t.recv_reply();
        app_register(t.app_addr(), register_packet("app2", 9002, "udp"), &t.ctx);
        let reply2 = t.recv_reply();

        let token1 = &reply1[1..17];
        let token2 = &reply2[1..17];
        assert_ne!(token1, token2, "tokens must be unique");

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications.len(), 2);
        assert_ne!(device.applications[0].id, device.applications[1].id);
    }

    #[test]
    fn app_register_is_idempotent_on_repeat() {
        // OP_REGISTER is UDP; an app re-sends when its ACK is lost. A repeat of
        // the same (alias, host) must reuse the app, not spawn a duplicate.
        let t = TestCtx::new();
        app_register(t.app_addr(), register_packet("probe", 9001, "udp"), &t.ctx);
        let reply1 = t.recv_reply();
        app_register(t.app_addr(), register_packet("probe", 9001, "udp"), &t.ctx);
        let reply2 = t.recv_reply();

        assert_eq!(&reply1[1..17], &reply2[1..17], "retry must return the same token");

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        let probes = device.applications.iter().filter(|a| a.alias == "probe").count();
        assert_eq!(probes, 1, "re-registration must not create a duplicate app");
    }

    #[test]
    fn app_register_rejects_bad_packet() {
        let t = TestCtx::new();
        app_register(t.app_addr(), vec![], &t.ctx); // empty buf

        let reply = t.recv_reply();
        assert_eq!(reply[0], STATUS_ERR);
        assert_eq!(reply[1], ERR_BAD_PACKET);
    }

    // ── AppUpdate ─────────────────────────────────────────────────────────────

    /// Register an app and return its token.
    fn register_and_get_token(t: &TestCtx, alias: &str, port: u16) -> [u8; 16] {
        app_register(t.app_addr(), register_packet(alias, port, "udp"), t.ctx());
        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);
        reply[1..17].try_into().unwrap()
    }

    fn update_packet(token: &[u8; 16], new_alias: Option<&str>, new_port: Option<u16>) -> Vec<u8> {
        let mut buf = token.to_vec();
        let mut flags: u8 = 0;
        let mut extra: Vec<u8> = Vec::new();

        if let Some(alias) = new_alias {
            flags |= 0x01;
            extra.push(alias.len() as u8);
            extra.extend_from_slice(alias.as_bytes());
        }
        if let Some(port) = new_port {
            flags |= 0x02;
            extra.extend_from_slice(&port.to_be_bytes());
        }

        buf.push(flags);
        buf.extend(extra);
        buf
    }

    impl TestCtx {
        fn ctx(&self) -> &WorkerContext { &self.ctx }
    }

    #[test]
    fn app_update_alias() {
        let t = TestCtx::new();
        // Alias is public-scope under sync v1, so the change must route to a
        // writer SG. Promoting the local device to SG makes it the writer.
        promote_local_to_sg(&t, 1);
        let token = register_and_get_token(&t, "original", 9001);

        app_update(t.app_addr(), update_packet(&token, Some("renamed"), None), &t.ctx);
        assert_eq!(t.recv_reply(), vec![OK]);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications[0].alias, "renamed");
    }

    #[test]
    fn app_update_port() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "myapp", 9001);

        app_update(t.app_addr(), update_packet(&token, None, Some(9999)), &t.ctx);
        assert_eq!(t.recv_reply(), vec![OK]);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(device.applications[0].host.port(), 9999);
    }

    #[test]
    fn app_update_unknown_token_returns_error() {
        let t = TestCtx::new();
        let bad_token = [0xFFu8; 16];
        app_update(t.app_addr(), update_packet(&bad_token, Some("x"), None), &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], STATUS_ERR);
        assert_eq!(reply[1], ERR_TOKEN_UNKNOWN);
    }

    // ── SgPing ────────────────────────────────────────────────────────────────

    #[test]
    fn sg_ping_replies_with_pong_and_echoed_nonce() {
        let t = TestCtx::new();
        let nonce: [u8; 16] = *b"test_nonce_12345";
        sg_ping(t.app_addr(), nonce, &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply.len(), 17);
        assert_eq!(reply[0], SG_PONG_OP);
        assert_eq!(reply[1..17], nonce);
    }

    // ── AppGetData ────────────────────────────────────────────────────────────

    #[test]
    fn app_get_data_returns_app_and_node_tree() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "myapp", 9001);

        app_get_data(t.app_addr(), token.to_vec(), &t.ctx);
        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);

        let mut pos = 1usize;

        // App's own data — id is now a 16-byte UUID, not a u16.
        pos += 16; // app uuid
        let alias = read_str(&reply, &mut pos).unwrap();
        assert_eq!(alias, "myapp");
        pos += 4 + 2; // host ip + port
        let user_approved = reply[pos]; pos += 1;
        assert_eq!(user_approved, 0); // not yet approved
        let token_back: [u8; 16] = reply[pos..pos + 16].try_into().unwrap(); pos += 16;
        assert_eq!(token_back, token.as_slice());
        pos += 16; // local device uuid

        // Owner alias + uuid.
        let owner_alias = read_str(&reply, &mut pos).unwrap();
        assert!(!owner_alias.is_empty());
        pos += 16; // owner uuid

        // Own devices.
        let device_count = reply[pos] as usize; pos += 1;
        assert_eq!(device_count, 1);
        pos += 16; // device uuid
        let _dev_alias = read_str(&reply, &mut pos).unwrap();
        pos += 1 + 1; // grade + sg_rank
        let host_count = reply[pos] as usize; pos += 1;
        for _ in 0..host_count {
            let _h = read_str(&reply, &mut pos).unwrap();
        }
        let app_count = reply[pos] as usize; pos += 1;
        assert_eq!(app_count, 1); // the app we just registered
        // Skip the one app entry to reach the contact count: [id:16][alias:1+N][ip:4][port:2][approved:1].
        for _ in 0..app_count {
            pos += 16; // app uuid
            let _alias = read_str(&reply, &mut pos).unwrap();
            pos += 4 + 2 + 1; // ip + port + approved
        }

        // Contact count (none registered).
        let contact_count = reply[pos] as usize;
        assert_eq!(contact_count, 0);
    }

    #[test]
    fn app_get_data_unknown_token_returns_error() {
        let t = TestCtx::new();
        app_get_data(t.app_addr(), vec![0xFFu8; 16], &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], STATUS_ERR);
        assert_eq!(reply[1], ERR_TOKEN_UNKNOWN);
    }

    // ── AppSendPacket ─────────────────────────────────────────────────────────

    fn send_packet(token: &[u8; 16], dest_device: Uuid, dest_app: Uuid, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(48 + payload.len());
        buf.extend_from_slice(token);
        buf.extend_from_slice(&dest_device);
        buf.extend_from_slice(&dest_app);
        buf.extend_from_slice(payload);
        buf
    }

    fn approve_local_app(t: &TestCtx, token: &[u8; 16]) {
        let mut node = t.ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter_mut()
            .find(|d| d.uuid == device_uuid)
            .expect("local device");
        let app = device.applications.iter_mut()
            .find(|a| a.token == *token)
            .expect("app by token");
        app.user_approved = true;
    }

    #[test]
    fn app_send_packet_rejects_bad_packet() {
        let t = TestCtx::new();
        app_send_packet(t.app_addr(), vec![0u8; 10], &t.ctx);
        let reply = t.recv_reply();
        assert_eq!(reply, vec![STATUS_ERR, ERR_BAD_PACKET]);
    }

    #[test]
    fn app_send_packet_rejects_unknown_token() {
        let t = TestCtx::new();
        let dest = [0xAAu8; 16];
        app_send_packet(
            t.app_addr(),
            send_packet(&[0xFFu8; 16], dest, dest, b"hi"),
            &t.ctx,
        );
        let reply = t.recv_reply();
        assert_eq!(reply, vec![STATUS_ERR, ERR_TOKEN_UNKNOWN]);
    }

    #[test]
    fn app_send_packet_rejects_unapproved_app() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "pending", 9001);
        // Registered but not approved — send must fail with NOT_APPROVED, not TOKEN_UNKNOWN.
        let dest = [0xBBu8; 16];
        app_send_packet(
            t.app_addr(),
            send_packet(&token, dest, dest, b"hi"),
            &t.ctx,
        );
        let reply = t.recv_reply();
        assert_eq!(reply, vec![STATUS_ERR, ERR_NOT_APPROVED]);
    }

    #[test]
    fn app_send_packet_rejects_no_route() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "sender", 9001);
        approve_local_app(&t, &token);
        // No sessions and no SGs → nowhere to send.
        let dest_device = [0xCCu8; 16];
        let dest_app = [0xDDu8; 16];
        app_send_packet(
            t.app_addr(),
            send_packet(&token, dest_device, dest_app, b"hi"),
            &t.ctx,
        );
        let reply = t.recv_reply();
        assert_eq!(reply, vec![STATUS_ERR, ERR_NO_ROUTE]);
    }

    #[test]
    fn app_send_packet_rejects_payload_too_large() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "big", 9001);
        approve_local_app(&t, &token);
        let oversized = vec![0u8; MAX_APP_PAYLOAD + 1];
        let dest = [0xEEu8; 16];
        app_send_packet(
            t.app_addr(),
            send_packet(&token, dest, dest, &oversized),
            &t.ctx,
        );
        let reply = t.recv_reply();
        assert_eq!(reply, vec![STATUS_ERR, ERR_PAYLOAD_TOO_LARGE]);
    }

    #[test]
    fn app_register_rate_limited() {
        let t = TestCtx::new();
        // Exhaust the register bucket for this source.
        let cap = super::super::app_api::REGISTER_LIMIT.capacity as usize;
        for i in 0..cap {
            app_register(
                t.app_addr(),
                register_packet(&format!("app{i}"), 9000 + i as u16, "udp"),
                &t.ctx,
            );
            let _ = t.recv_reply();
        }
        app_register(t.app_addr(), register_packet("overflow", 9999, "udp"), &t.ctx);
        let reply = t.recv_reply();
        assert_eq!(reply, vec![STATUS_ERR, ERR_RATE_LIMITED]);
    }

    // ── ConnectRequest ────────────────────────────────────────────────────────

    /// Add a contact with its own Ed25519 key pair to the node.
    /// Returns the contact's device UUID and key pair.
    fn add_contact_with_device(node: &mut Node) -> (Uuid, Ed25519KeyPair) {
        let kp          = generate_ed25519_keypair();
        let device_uuid = generate_uuid();
        node.owner.contact_users.push(Contact {
            public_key: kp.public_key,
            user: User {
                alias:   "peer".to_string(),
                uuid:    generate_uuid(),
                devices: vec![Device {
                    alias:           "peer-device".to_string(),
                    uuid:            device_uuid,
                    grade:           DeviceGrade::SG,
                    sg_rank:         Some(1),
                    hosts:           vec!["127.0.0.1:9999".into()],
                    applications:    Vec::new(),
                }],
            },
            last_seen_public_version: SyncVersion::default(),
        });
        (device_uuid, kp)
    }

    // ── DG keepalive (NAT-mapping maintenance) ────────────────────────────────

    /// A DG must keep an inbound NAT mapping warm on *every* SG it holds a
    /// connection to — its own SGs and each contact's SG — not just the
    /// top-ranked own SG, or another SG's app/relay sends are dropped by NAT.
    #[test]
    fn keepalive_dg_fans_out_to_own_and_contact_sgs() {
        let t = TestCtx::new();

        // Stand-in receiving sockets for the two SGs the DG connects to.
        let own_sg_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        own_sg_sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let contact_sg_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        contact_sg_sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();

        let own_sg_uuid = generate_uuid();
        let contact_sg_uuid;
        {
            let mut node = t.ctx.node.write().unwrap();
            // Local device stays a DG (Node::new default). Add one own SG...
            node.owner.user.devices.push(Device {
                alias:        "own-sg".to_string(),
                uuid:         own_sg_uuid,
                grade:        DeviceGrade::SG,
                sg_rank:      Some(1),
                hosts:        vec!["127.0.0.1:7777".into()],
                applications: Vec::new(),
            });
            // ...and a contact whose device is an SG.
            let (csg, _kp) = add_contact_with_device(&mut node);
            contact_sg_uuid = csg;

            // Active connections to both, aimed at the receiving sockets.
            node.owner.active_connections.insert(1, ActiveConnection {
                id: 1,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: generate_x25519_keypair(),
                peer_public_key: X25519PublicKey(generate_key_bytes()),
                peer_active_connection_id: 10,
                device_uuid: own_sg_uuid,
                peer_addr: own_sg_sock.local_addr().unwrap(),
            });
            node.owner.active_connections.insert(2, ActiveConnection {
                id: 2,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: generate_x25519_keypair(),
                peer_public_key: X25519PublicKey(generate_key_bytes()),
                peer_active_connection_id: 20,
                device_uuid: contact_sg_uuid,
                peer_addr: contact_sg_sock.local_addr().unwrap(),
            });
            // sg_statuses left empty → both treated as up.
        }

        keepalive_dg(&t.ctx);

        let mut buf = [0u8; 64];
        let (_n, _) = own_sg_sock.recv_from(&mut buf).expect("own SG should get a keepalive");
        assert_eq!(buf[0], DG_KEEPALIVE_OP);
        let (_n, _) = contact_sg_sock.recv_from(&mut buf).expect("contact SG should get a keepalive");
        assert_eq!(buf[0], DG_KEEPALIVE_OP);
    }

    /// A verified keepalive updates the SG's stored address for the DG, so app
    /// packets/relays follow the DG through a NAT rebind or roam.
    #[test]
    fn dg_keepalive_receive_refreshes_peer_addr() {
        let t = TestCtx::new();

        let sg_kp  = generate_x25519_keypair();
        let dg_kp  = generate_x25519_keypair();
        let sg_pub = sg_kp.public_key;
        let dg_pub = dg_kp.public_key;
        let sg_conn_id: u16 = 5;
        let old_addr: SocketAddr = "127.0.0.1:1111".parse().unwrap();

        {
            let mut node = t.ctx.node.write().unwrap();
            // SG-side record of the DG connection, at a now-stale address.
            node.owner.active_connections.insert(sg_conn_id, ActiveConnection {
                id: sg_conn_id,
                timeout: SystemTime::now() + Duration::from_secs(60),
                key_pair: sg_kp,
                peer_public_key: dg_pub,
                peer_active_connection_id: 99,
                device_uuid: generate_uuid(),
                peer_addr: old_addr,
            });
        }

        // DG builds a keepalive addressed to the SG's conn id.
        let dg_side_conn = ActiveConnection {
            id: 99,
            timeout: SystemTime::now() + Duration::from_secs(60),
            key_pair: dg_kp,
            peer_public_key: sg_pub,
            peer_active_connection_id: sg_conn_id,
            device_uuid: generate_uuid(),
            peer_addr: old_addr,
        };
        let pkt = build_encrypted_packet(DG_KEEPALIVE_OP, &dg_side_conn, &[]);

        let before = t.ctx.node.read().unwrap()
            .owner.active_connections[&sg_conn_id].timeout;
        // Arrives from a NEW source address (NAT rebind / roam).
        let new_addr: SocketAddr = "127.0.0.1:2222".parse().unwrap();
        dg_keepalive_receive(new_addr, pkt[1..].to_vec(), &t.ctx);

        let node = t.ctx.node.read().unwrap();
        let conn = &node.owner.active_connections[&sg_conn_id];
        assert_eq!(conn.peer_addr, new_addr, "peer_addr should track the keepalive source");
        assert!(conn.timeout > before, "timeout should be refreshed");
    }

    // ── Connection glare avoidance (directional initiation) ───────────────────

    /// Teach `t` about a contact SG device under the peer's long-term key.
    fn add_specific_contact(t: &TestCtx, peer_dev: Uuid, peer_lt_pub: Ed25519PublicKey) {
        let mut n = t.ctx.node.write().unwrap();
        n.owner.contact_users.push(Contact {
            public_key: peer_lt_pub,
            user: User { alias: "peer".into(), uuid: generate_uuid(), devices: vec![make_sg_device(peer_dev)] },
            last_seen_public_version: SyncVersion::default(),
        });
    }

    /// Force this node's local device to a known uuid and grade.
    fn set_local_identity(t: &TestCtx, uuid: Uuid, grade: DeviceGrade) {
        let mut n = t.ctx.node.write().unwrap();
        let old = n.device_uuid;
        n.device_uuid = uuid;
        for d in n.owner.user.devices.iter_mut() {
            if d.uuid == old {
                d.uuid = uuid;
                d.grade = grade;
                d.sg_rank = if matches!(grade, DeviceGrade::SG) { Some(1) } else { None };
            }
        }
        n.owner.key_pair = generate_ed25519_keypair();
    }

    fn pending_peers(t: &TestCtx) -> Vec<Uuid> {
        t.ctx.node.read().unwrap().owner.pending_connections.values()
            .map(|p| p.peer_device_uuid).collect()
    }

    /// Connection glare (both peers initiating at once) leaves each side keyed
    /// on a connection the other evicted, breaking all later encrypted traffic
    /// (observed live as `[cross_user_*] decryption failed`, and SG↔SG never
    /// self-heals). The cure is directional initiation: an SG initiates only to
    /// a *higher*-uuid SG, so exactly one side of every SG↔SG pair initiates.
    #[test]
    fn sg_initiates_only_to_higher_uuid_sg() {
        let t = TestCtx::new();
        set_local_identity(&t, [0x80; 16], DeviceGrade::SG);

        let higher: Uuid = [0xff; 16];
        let lower:  Uuid = [0x00; 16];
        add_specific_contact(&t, higher, generate_ed25519_keypair().public_key);
        add_specific_contact(&t, lower,  generate_ed25519_keypair().public_key);

        maintain_connections(&t.ctx);

        let pend = pending_peers(&t);
        assert!(pend.contains(&higher), "SG must initiate to a higher-uuid SG peer");
        assert!(!pend.contains(&lower), "SG must NOT initiate to a lower-uuid SG peer — it responds instead (else glare)");
    }

    /// A DG must always initiate to its contacts' SGs (it punches out through
    /// NAT), regardless of uuid order — the uuid tiebreak is SG↔SG only.
    #[test]
    fn dg_initiates_to_sg_regardless_of_uuid() {
        let t = TestCtx::new();
        set_local_identity(&t, [0x80; 16], DeviceGrade::DG);

        let lower_sg: Uuid = [0x00; 16];
        add_specific_contact(&t, lower_sg, generate_ed25519_keypair().public_key);

        maintain_connections(&t.ctx);

        assert!(pending_peers(&t).contains(&lower_sg),
            "a DG must initiate to a contact SG even when the SG's uuid is lower");
    }

    /// Build the buf for connect_request (op byte already stripped).
    fn connect_request_buf(
        conn_id:      u16,
        device_uuid:  &Uuid,
        ephemeral_pk: &X25519PublicKey,
        longterm_pk:  &Ed25519PublicKey,
        longterm_sk:  &Ed25519SecretKey,
        tamper_sig:   bool,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 146];
        buf[0..2].copy_from_slice(&conn_id.to_be_bytes());
        buf[2..18].copy_from_slice(device_uuid);
        buf[18..50].copy_from_slice(ephemeral_pk.as_bytes());
        buf[50..82].copy_from_slice(longterm_pk.as_bytes());

        let mut signed_msg = [0u8; 83];
        signed_msg[0] = CONNECT_REQUEST_OP;
        signed_msg[1..83].copy_from_slice(&buf[0..82]);
        let mut sig = ed25519_sign(longterm_sk, &signed_msg);
        if tamper_sig { sig[0] ^= 0xFF; }
        buf[82..146].copy_from_slice(&sig);
        buf
    }

    #[test]
    fn connect_request_valid_signature_accepted() {
        let t = TestCtx::new();
        let (device_uuid, peer_kp) = {
            let mut node = t.ctx.node.write().unwrap();
            add_contact_with_device(&mut node)
        };
        let eph_kp = generate_x25519_keypair();

        connect_request(
            t.app_addr(),
            connect_request_buf(1, &device_uuid, &eph_kp.public_key,
                                 &peer_kp.public_key, &peer_kp.private_key, false),
            &t.ctx,
        );

        // Node must have stored an active connection for the peer device.
        let node = t.ctx.node.read().unwrap();
        assert_eq!(node.owner.active_connections.len(), 1);
        let conn = node.owner.active_connections.values().next().unwrap();
        assert_eq!(conn.device_uuid, device_uuid);

        // Reply must be a ConnectAck (op 0x21).
        // recv_reply uses a 64-byte buffer which truncates the 101-byte packet; check op only.
        let reply = t.recv_reply();
        assert_eq!(reply[0], CONNECT_ACK_OP);
    }

    #[test]
    fn connect_request_invalid_signature_rejected() {
        let t = TestCtx::new();
        let (device_uuid, peer_kp) = {
            let mut node = t.ctx.node.write().unwrap();
            add_contact_with_device(&mut node)
        };
        let eph_kp = generate_x25519_keypair();

        connect_request(
            t.app_addr(),
            connect_request_buf(1, &device_uuid, &eph_kp.public_key,
                                 &peer_kp.public_key, &peer_kp.private_key, true),
            &t.ctx,
        );

        let node = t.ctx.node.read().unwrap();
        assert!(node.owner.active_connections.is_empty());
    }

    // ── ConnectAck ────────────────────────────────────────────────────────────

    /// Build the buf for connect_ack (op byte already stripped).
    fn connect_ack_buf(
        responder_conn_id: u16,
        our_conn_id:       u16,
        eph_pk:            &X25519PublicKey,
        responder_sk:      &Ed25519SecretKey,
        tamper_sig:        bool,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 100];
        buf[0..2].copy_from_slice(&responder_conn_id.to_be_bytes());
        buf[2..4].copy_from_slice(&our_conn_id.to_be_bytes());
        buf[4..36].copy_from_slice(eph_pk.as_bytes());

        let mut signed_msg = [0u8; 37];
        signed_msg[0] = CONNECT_ACK_OP;
        signed_msg[1..37].copy_from_slice(&buf[0..36]);
        let mut sig = ed25519_sign(responder_sk, &signed_msg);
        if tamper_sig { sig[0] ^= 0xFF; }
        buf[36..100].copy_from_slice(&sig);
        buf
    }

    #[test]
    fn connect_ack_valid_signature_promotes_pending() {
        let t = TestCtx::new();
        let peer_kp     = generate_ed25519_keypair();
        let peer_uuid   = generate_uuid();
        let our_conn_id = 42u16;

        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.pending_connections.insert(our_conn_id, PendingConnection {
                our_conn_id,
                our_key_pair:     generate_x25519_keypair(),
                peer_device_uuid: peer_uuid,
                peer_longterm_pk: peer_kp.public_key,
                created_at:       SystemTime::now(),
            });
        }

        let eph_kp = generate_x25519_keypair();
        connect_ack(
            t.app_addr(),
            connect_ack_buf(7, our_conn_id, &eph_kp.public_key,
                            &peer_kp.private_key, false),
            &t.ctx,
        );

        let node = t.ctx.node.read().unwrap();
        assert!(node.owner.pending_connections.is_empty());
        assert_eq!(node.owner.active_connections.len(), 1);
        let conn = node.owner.active_connections.values().next().unwrap();
        assert_eq!(conn.device_uuid, peer_uuid);
        assert_eq!(conn.peer_active_connection_id, 7);
    }

    #[test]
    fn connect_ack_invalid_signature_preserves_pending() {
        let t = TestCtx::new();
        let peer_kp     = generate_ed25519_keypair();
        let peer_uuid   = generate_uuid();
        let our_conn_id = 42u16;

        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.pending_connections.insert(our_conn_id, PendingConnection {
                our_conn_id,
                our_key_pair:     generate_x25519_keypair(),
                peer_device_uuid: peer_uuid,
                peer_longterm_pk: peer_kp.public_key,
                created_at:       SystemTime::now(),
            });
        }

        let eph_kp = generate_x25519_keypair();
        connect_ack(
            t.app_addr(),
            connect_ack_buf(7, our_conn_id, &eph_kp.public_key,
                            &peer_kp.private_key, true),
            &t.ctx,
        );

        let node = t.ctx.node.read().unwrap();
        assert!(node.owner.active_connections.is_empty());
        assert!(node.owner.pending_connections.contains_key(&our_conn_id));
    }

    // ── Routing helpers ───────────────────────────────────────────────────────

    fn make_sg_device(uuid: Uuid) -> Device {
        Device {
            alias:           "sg".to_string(),
            uuid,
            grade:           DeviceGrade::SG,
            sg_rank:         Some(1),
            hosts:           vec!["127.0.0.1:9000".into()],
            applications:    Vec::new(),
        }
    }

    #[test]
    fn sg_candidates_for_dest_includes_own_and_contact_sgs() {
        let t = TestCtx::new();
        let own_sg_uuid     = generate_uuid();
        let contact_sg_uuid = generate_uuid();
        let dest_uuid       = generate_uuid();

        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(make_sg_device(own_sg_uuid));
            node.owner.contact_users.push(Contact {
                public_key: Ed25519PublicKey(generate_key_bytes()),
                user: User {
                    alias:   "contact".to_string(),
                    uuid:    generate_uuid(),
                    devices: vec![
                        make_sg_device(contact_sg_uuid),
                        Device {
                            alias:           "dest".to_string(),
                            uuid:            dest_uuid,
                            grade:           DeviceGrade::DG,
                            sg_rank:         None,
                            hosts:           vec!["127.0.0.1:9001".into()],
                            applications:    Vec::new(),
                        },
                    ],
                },
                last_seen_public_version: SyncVersion::default(),
            });
        }

        let node       = t.ctx.node.read().unwrap();
        let candidates = sg_candidates_for_dest(&node, &dest_uuid);
        assert!(candidates.contains(&own_sg_uuid));
        assert!(candidates.contains(&contact_sg_uuid));
        assert!(!candidates.contains(&dest_uuid));
    }

    #[test]
    fn best_sg_connection_picks_lowest_rtt() {
        use std::time::Instant;
        let t = TestCtx::new();
        let slow_uuid = generate_uuid();
        let fast_uuid = generate_uuid();

        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.active_connections.insert(1, ActiveConnection {
                id: 1,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: generate_x25519_keypair(),
                peer_public_key: X25519PublicKey(generate_key_bytes()),
                peer_active_connection_id: 10,
                device_uuid: slow_uuid,
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
            node.owner.active_connections.insert(2, ActiveConnection {
                id: 2,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: generate_x25519_keypair(),
                peer_public_key: X25519PublicKey(generate_key_bytes()),
                peer_active_connection_id: 20,
                device_uuid: fast_uuid,
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
            node.sg_statuses.insert((slow_uuid, "slow".to_string()), super::super::data_models::SgStatus {
                up: true,
                last_rtt: Some(Duration::from_millis(80)),
                last_polled: Instant::now(),
            });
            node.sg_statuses.insert((fast_uuid, "fast".to_string()), super::super::data_models::SgStatus {
                up: true,
                last_rtt: Some(Duration::from_millis(20)),
                last_polled: Instant::now(),
            });
        }

        let node = t.ctx.node.read().unwrap();
        let candidates = vec![slow_uuid, fast_uuid];
        let best = best_sg_connection(&node, &candidates).unwrap();
        assert_eq!(best.device_uuid, fast_uuid);
    }

    #[test]
    fn best_sg_connection_falls_back_when_unpolled() {
        let t = TestCtx::new();
        let sg_uuid = generate_uuid();

        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.active_connections.insert(1, ActiveConnection {
                id: 1,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: generate_x25519_keypair(),
                peer_public_key: X25519PublicKey(generate_key_bytes()),
                peer_active_connection_id: 10,
                device_uuid: sg_uuid,
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
            // No sg_statuses entry — PollSG hasn't run.
        }

        let node = t.ctx.node.read().unwrap();
        let best = best_sg_connection(&node, &[sg_uuid]);
        assert!(best.is_some());
        assert_eq!(best.unwrap().device_uuid, sg_uuid);
    }

    // ── Writer election ───────────────────────────────────────────────────────

    /// Add a peer SG device to the node, optionally with an active connection
    /// and an `sg_statuses` entry. Returns the peer's UUID for assertions.
    fn add_peer_sg(
        t: &TestCtx,
        rank: u32,
        with_conn: bool,
        polled_up: Option<bool>,
    ) -> Uuid {
        use std::time::Instant;
        let uuid = generate_uuid();
        let mut node = t.ctx.node.write().unwrap();
        node.owner.user.devices.push(Device {
            alias:        format!("sg-{rank}"),
            uuid,
            grade:        DeviceGrade::SG,
            sg_rank:      Some(rank),
            hosts:        vec![format!("127.0.0.1:{}", 9000 + rank)],
            applications: Vec::new(),
        });
        if with_conn {
            // Insert at a unique connection-ID slot (rank doubles as a stand-in).
            node.owner.active_connections.insert(rank as u16, ActiveConnection {
                id: rank as u16,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: generate_x25519_keypair(),
                peer_public_key: X25519PublicKey(generate_key_bytes()),
                peer_active_connection_id: 100 + rank as u16,
                device_uuid: uuid,
                peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
        }
        if let Some(up) = polled_up {
            node.sg_statuses.insert(
                (uuid, format!("127.0.0.1:{}", 9000 + rank)),
                super::super::data_models::SgStatus {
                    up,
                    last_rtt: Some(Duration::from_millis(20)),
                    last_polled: Instant::now(),
                },
            );
        }
        uuid
    }

    /// Build a deterministic Uuid from a small seed for test readability.
    /// Distinct seeds produce distinct uuids — sufficient for comparison
    /// assertions that previously used u16 app-id literals like `7` or
    /// `0xCAFE`.
    fn app_uuid(seed: u16) -> Uuid {
        let mut u = [0u8; 16];
        u[14..16].copy_from_slice(&seed.to_be_bytes());
        u
    }

    /// Promote the local device to SG with the given rank.
    fn promote_local_to_sg(t: &TestCtx, rank: u32) -> Uuid {
        let mut node = t.ctx.node.write().unwrap();
        let local_uuid = node.device_uuid;
        let dev = node.owner.user.devices.iter_mut()
            .find(|d| d.uuid == local_uuid)
            .expect("local device exists");
        dev.grade   = DeviceGrade::SG;
        dev.sg_rank = Some(rank);
        local_uuid
    }

    /// Count how many `UpsertContact` changes are in the owner's write log.
    fn upsert_contact_log_count(node: &Node) -> usize {
        node.owner.write_log.iter()
            .filter_map(|e| deserialize_change(&e.change_payload))
            .filter(|c| matches!(c, Change::UpsertContact { .. }))
            .count()
    }

    #[test]
    fn find_writer_dg_with_no_own_sgs_is_unreachable() {
        let t = TestCtx::new();
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Unreachable);
    }

    #[test]
    fn find_writer_dg_with_one_reachable_sg_returns_remote() {
        let t = TestCtx::new();
        let sg = add_peer_sg(&t, 1, /*conn*/ true, /*polled_up*/ Some(true));
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Remote(sg));
    }

    #[test]
    fn find_writer_dg_optimistic_when_unpolled() {
        // No sg_statuses entry yet (cold boot) — should still pick the SG.
        let t = TestCtx::new();
        let sg = add_peer_sg(&t, 1, /*conn*/ true, /*polled_up*/ None);
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Remote(sg));
    }

    #[test]
    fn find_writer_dg_skips_sg_marked_down() {
        let t = TestCtx::new();
        add_peer_sg(&t, 1, /*conn*/ true, /*polled_up*/ Some(false));
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Unreachable);
    }

    #[test]
    fn find_writer_dg_skips_sg_with_no_connection() {
        let t = TestCtx::new();
        add_peer_sg(&t, 1, /*conn*/ false, /*polled_up*/ Some(true));
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Unreachable);
    }

    #[test]
    fn find_writer_dg_prefers_lower_rank() {
        let t = TestCtx::new();
        let sg1 = add_peer_sg(&t, 1, true, Some(true));
        let _sg2 = add_peer_sg(&t, 2, true, Some(true));
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Remote(sg1));
    }

    #[test]
    fn find_writer_dg_falls_over_when_top_rank_down() {
        let t = TestCtx::new();
        let _sg1 = add_peer_sg(&t, 1, true, Some(false)); // rank 1 down
        let sg2  = add_peer_sg(&t, 2, true, Some(true));  // rank 2 up
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Remote(sg2));
    }

    #[test]
    fn find_writer_local_sg_alone_is_local() {
        let t = TestCtx::new();
        promote_local_to_sg(&t, 1);
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Local);
    }

    #[test]
    fn find_writer_local_rank2_with_rank1_reachable_returns_remote() {
        let t = TestCtx::new();
        promote_local_to_sg(&t, 2);
        let sg1 = add_peer_sg(&t, 1, true, Some(true));
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Remote(sg1));
    }

    #[test]
    fn find_writer_local_rank2_takes_over_when_rank1_down() {
        let t = TestCtx::new();
        promote_local_to_sg(&t, 2);
        add_peer_sg(&t, 1, true, Some(false));
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Local);
    }

    #[test]
    fn find_writer_local_rank2_disconnected_from_rank1_is_unreachable() {
        // No active_connection to the rank-1 peer, but poll data still shows
        // it alive: this is a transient disconnection, not failover. Self-
        // electing as writer here would diverge from SG-1's still-active
        // writes — wait for the connection to recover or for poll data to
        // confirm SG-1 is down.
        let t = TestCtx::new();
        promote_local_to_sg(&t, 2);
        add_peer_sg(&t, 1, false, Some(true));
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Unreachable);
    }

    // ── Change serialization & apply ──────────────────────────────────────────

    #[test]
    fn change_add_application_roundtrips() {
        let dev_uuid = generate_uuid();
        let original = Change::AddApplication {
            device_uuid: dev_uuid,
            app_id:      app_uuid(0xCAFE),
            app_alias:   "messenger".to_string(),
        };
        let bytes = serialize_change(&original);
        assert_eq!(bytes[0], CHANGE_KIND_ADD_APPLICATION);
        let parsed = deserialize_change(&bytes).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn deserialize_change_rejects_unknown_kind() {
        // A buffer with an unknown change_kind byte should fail cleanly,
        // not panic. Future variants can be added without breaking older
        // peers — they'll see this error and emit WRITE_ACK_VALIDATION_ERROR.
        assert!(deserialize_change(&[0xFE, 0x00, 0x00]).is_none());
    }

    #[test]
    fn deserialize_change_rejects_truncated_payload() {
        let dev_uuid = generate_uuid();
        let original = Change::AddApplication {
            device_uuid: dev_uuid,
            app_id:      app_uuid(1),
            app_alias:   "foo".to_string(),
        };
        let mut bytes = serialize_change(&original);
        bytes.truncate(bytes.len() - 1); // chop last byte of alias
        assert!(deserialize_change(&bytes).is_none());
    }

    #[test]
    fn apply_add_application_appends_app_and_bumps_public_only() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);
        let writer = local;

        let change = Change::AddApplication {
            device_uuid: local,
            app_id:      app_uuid(7),
            app_alias:   "myapp".to_string(),
        };
        let (priv_v, pub_v) = apply_change_locally(&change, writer, &t.ctx).expect("apply");

        // Public bumped, private untouched.
        assert!(priv_v.is_initial(), "private should not bump for public-only change");
        assert_eq!(pub_v.writer_sg_uuid, writer);
        assert_eq!(pub_v.epoch, 1);
        assert_eq!(pub_v.seq,   1);

        // App was actually appended.
        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == local).unwrap();
        assert_eq!(dev.applications.len(), 1);
        assert_eq!(dev.applications[0].id, app_uuid(7));
        assert_eq!(dev.applications[0].alias, "myapp");
        // Token/host stay zero on the writer's record by design.
        assert_eq!(dev.applications[0].token, [0u8; 16]);
    }

    #[test]
    fn apply_add_application_is_idempotent() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);
        let writer = local;

        let change = Change::AddApplication {
            device_uuid: local,
            app_id:      app_uuid(7),
            app_alias:   "myapp".to_string(),
        };
        apply_change_locally(&change, writer, &t.ctx).expect("first apply");
        let pub_after_first = t.ctx.node.read().unwrap().owner.public_version;

        // Second apply should be a no-op — same id is already present.
        apply_change_locally(&change, writer, &t.ctx).expect("second apply");
        let pub_after_second = t.ctx.node.read().unwrap().owner.public_version;
        assert_eq!(pub_after_first, pub_after_second, "no-op apply must not bump");

        // App list unchanged.
        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == local).unwrap();
        assert_eq!(dev.applications.len(), 1);
    }

    #[test]
    fn apply_add_application_unknown_device_returns_validation_error() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);
        let bogus_uuid = generate_uuid();

        let change = Change::AddApplication {
            device_uuid: bogus_uuid,
            app_id:      app_uuid(1),
            app_alias:   "x".to_string(),
        };
        let res = apply_change_locally(&change, local, &t.ctx);
        assert!(matches!(res, Err(WriteError::Validation(_))));

        // No version bumped.
        let node = t.ctx.node.read().unwrap();
        assert!(node.owner.public_version.is_initial());
    }

    #[test]
    fn change_remove_application_roundtrips() {
        let dev_uuid = generate_uuid();
        let original = Change::RemoveApplication {
            device_uuid: dev_uuid,
            app_id:      app_uuid(0xCAFE),
        };
        let bytes = serialize_change(&original);
        assert_eq!(bytes[0], CHANGE_KIND_REMOVE_APPLICATION);
        let parsed = deserialize_change(&bytes).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn apply_remove_application_drops_app_and_bumps_public() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);
        let writer = local;

        // Seed an app so there's something to remove.
        apply_change_locally(
            &Change::AddApplication {
                device_uuid: local, app_id: app_uuid(3), app_alias: "doomed".into(),
            },
            writer, &t.ctx,
        ).expect("seed");
        let pub_after_add = t.ctx.node.read().unwrap().owner.public_version;

        let (priv_v, pub_v) = apply_change_locally(
            &Change::RemoveApplication { device_uuid: local, app_id: app_uuid(3) },
            writer, &t.ctx,
        ).expect("remove");

        // Private untouched; public bumped from the seed-add value.
        assert!(priv_v.is_initial());
        assert_eq!(pub_v.writer_sg_uuid, writer);
        assert_eq!(pub_v.epoch, pub_after_add.epoch);
        assert_eq!(pub_v.seq,   pub_after_add.seq + 1);

        // App actually gone.
        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == local).unwrap();
        assert!(dev.applications.iter().all(|a| a.id != app_uuid(3)));
    }

    #[test]
    fn apply_remove_application_is_idempotent_for_missing_app() {
        // Removing an app id that's already absent must NOT bump the version —
        // matches AddApplication's idempotency contract so retries don't
        // inflate seq.
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);
        let writer = local;

        let pub_before = t.ctx.node.read().unwrap().owner.public_version;
        apply_change_locally(
            &Change::RemoveApplication { device_uuid: local, app_id: app_uuid(999) },
            writer, &t.ctx,
        ).expect("idempotent remove ok");
        let pub_after = t.ctx.node.read().unwrap().owner.public_version;
        assert_eq!(pub_before, pub_after, "no-op remove must not bump");
    }

    #[test]
    fn change_add_device_roundtrips() {
        let dev_uuid = generate_uuid();
        let original = Change::AddDevice {
            uuid:    dev_uuid,
            alias:   "laptop".to_string(),
            grade:   DeviceGrade::DG,
            sg_rank: None,
            hosts:   vec!["10.0.0.5".to_string()],
        };
        let bytes = serialize_change(&original);
        assert_eq!(bytes[0], CHANGE_KIND_ADD_DEVICE);
        let parsed = deserialize_change(&bytes).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn apply_add_device_appends_and_bumps_public() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);
        let writer = local;
        let new_uuid = generate_uuid();

        let change = Change::AddDevice {
            uuid:    new_uuid,
            alias:   "phone".to_string(),
            grade:   DeviceGrade::DG,
            sg_rank: None,
            hosts:   Vec::new(),
        };
        let (priv_v, pub_v) = apply_change_locally(&change, writer, &t.ctx).expect("apply");

        assert!(priv_v.is_initial());
        assert_eq!(pub_v.writer_sg_uuid, writer);
        assert_eq!(pub_v.epoch, 1);
        assert_eq!(pub_v.seq,   1);

        let node = t.ctx.node.read().unwrap();
        assert!(node.owner.user.devices.iter().any(|d| d.uuid == new_uuid));
    }

    #[test]
    fn apply_add_device_is_idempotent() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);
        let writer = local;
        let new_uuid = generate_uuid();

        let change = Change::AddDevice {
            uuid:    new_uuid,
            alias:   "phone".to_string(),
            grade:   DeviceGrade::DG,
            sg_rank: None,
            hosts:   Vec::new(),
        };
        apply_change_locally(&change, writer, &t.ctx).expect("first apply");
        let pub_after_first = t.ctx.node.read().unwrap().owner.public_version;

        apply_change_locally(&change, writer, &t.ctx).expect("second apply");
        let pub_after_second = t.ctx.node.read().unwrap().owner.public_version;
        assert_eq!(pub_after_first, pub_after_second, "no-op re-add must not bump");

        let node = t.ctx.node.read().unwrap();
        let count = node.owner.user.devices.iter().filter(|d| d.uuid == new_uuid).count();
        assert_eq!(count, 1, "device must not be duplicated");
    }

    #[test]
    fn change_update_application_alias_roundtrips() {
        let dev_uuid = generate_uuid();
        let original = Change::UpdateApplicationAlias {
            device_uuid: dev_uuid,
            app_id:      app_uuid(0xBEEF),
            new_alias:   "renamed".to_string(),
        };
        let bytes = serialize_change(&original);
        assert_eq!(bytes[0], CHANGE_KIND_UPDATE_APPLICATION_ALIAS);
        let parsed = deserialize_change(&bytes).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn apply_update_application_alias_renames_and_bumps_public() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);
        let writer = local;

        apply_change_locally(
            &Change::AddApplication {
                device_uuid: local, app_id: app_uuid(5), app_alias: "old".into(),
            },
            writer, &t.ctx,
        ).expect("seed");
        let pub_after_add = t.ctx.node.read().unwrap().owner.public_version;

        let (_, pub_v) = apply_change_locally(
            &Change::UpdateApplicationAlias {
                device_uuid: local, app_id: app_uuid(5), new_alias: "new".into(),
            },
            writer, &t.ctx,
        ).expect("rename");

        assert_eq!(pub_v.epoch, pub_after_add.epoch);
        assert_eq!(pub_v.seq,   pub_after_add.seq + 1);

        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == local).unwrap();
        let app = dev.applications.iter().find(|a| a.id == app_uuid(5)).unwrap();
        assert_eq!(app.alias, "new");
    }

    #[test]
    fn apply_update_application_alias_is_idempotent_when_unchanged() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);
        let writer = local;

        apply_change_locally(
            &Change::AddApplication {
                device_uuid: local, app_id: app_uuid(5), app_alias: "same".into(),
            },
            writer, &t.ctx,
        ).expect("seed");
        let pub_before = t.ctx.node.read().unwrap().owner.public_version;

        apply_change_locally(
            &Change::UpdateApplicationAlias {
                device_uuid: local, app_id: app_uuid(5), new_alias: "same".into(),
            },
            writer, &t.ctx,
        ).expect("no-op rename");
        let pub_after = t.ctx.node.read().unwrap().owner.public_version;
        assert_eq!(pub_before, pub_after, "no-op rename must not bump");
    }

    #[test]
    fn apply_update_application_alias_no_op_for_missing_app() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);
        let writer = local;

        let pub_before = t.ctx.node.read().unwrap().owner.public_version;
        apply_change_locally(
            &Change::UpdateApplicationAlias {
                device_uuid: local, app_id: app_uuid(999), new_alias: "nope".into(),
            },
            writer, &t.ctx,
        ).expect("missing app is no-op, not error");
        let pub_after = t.ctx.node.read().unwrap().owner.public_version;
        assert_eq!(pub_before, pub_after);
    }

    // ── request_change driver ────────────────────────────────────────────────

    #[test]
    fn request_change_local_path_applies_directly() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);

        let change = Change::AddApplication {
            device_uuid: local,
            app_id:      app_uuid(9),
            app_alias:   "ui-app".to_string(),
        };
        request_change(change, &t.ctx).expect("request_change ok");

        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == local).unwrap();
        assert_eq!(dev.applications.len(), 1);
        assert_eq!(node.owner.public_version.epoch, 1);
    }

    #[test]
    fn request_change_unreachable_returns_error() {
        // Default test ctx is a DG with no own SGs.
        let t = TestCtx::new();
        let dev_uuid = t.ctx.node.read().unwrap().device_uuid;
        let change = Change::AddApplication {
            device_uuid: dev_uuid,
            app_id:      app_uuid(1),
            app_alias:   "x".to_string(),
        };
        assert_eq!(request_change(change, &t.ctx), Err(WriteError::Unreachable));
    }

    #[test]
    fn request_change_remote_path_sends_packet() {
        // Set up a DG (local) with one reachable own SG. request_change
        // should send a SyncWriteRequest to that SG's address.
        let t = TestCtx::new();

        // Bind a socket at the SG-side address; this is where the packet should land.
        let sg_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        sg_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let sg_addr = sg_socket.local_addr().unwrap();

        let dg_uuid = t.ctx.node.read().unwrap().device_uuid;
        let sg_uuid = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:        "my-sg".to_string(),
                uuid:         sg_uuid,
                grade:        DeviceGrade::SG,
                sg_rank:      Some(1),
                hosts:        vec![sg_addr.to_string()],
                applications: Vec::new(),
            });
            // Active connection to the SG with peer_addr matching the test socket.
            node.owner.active_connections.insert(11, ActiveConnection {
                id:                        11,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  generate_x25519_keypair(),
                peer_public_key:           X25519PublicKey(generate_key_bytes()),
                peer_active_connection_id: 22,
                device_uuid:               sg_uuid,
                peer_addr:                 sg_addr,
            });
        }

        let change = Change::AddApplication {
            device_uuid: dg_uuid,
            app_id:      app_uuid(3),
            app_alias:   "x".to_string(),
        };
        request_change(change, &t.ctx).expect("request_change ok");

        // The SG socket should receive a SyncWriteRequest packet (op 0x70).
        let mut buf = [0u8; 1024];
        let (len, _) = sg_socket.recv_from(&mut buf).expect("packet should arrive");
        assert!(len >= 1);
        assert_eq!(buf[0], SYNC_WRITE_REQUEST_OP);
    }

    // ── sync_write_request handler ───────────────────────────────────────────

    /// Set up a local SG with an active connection from a peer DG and return
    /// the (conn_id_on_sg, dg_conn_for_sender_side, dg_uuid) so a test can
    /// build packets the SG will decrypt and address acks back to the DG.
    fn setup_writer_sg_with_dg_peer(t: &TestCtx) -> (u16, ActiveConnection, Uuid, std::net::SocketAddr) {
        let sg_kp = generate_x25519_keypair();
        let dg_kp = generate_x25519_keypair();
        let conn_id = 5u16;
        let dg_uuid = generate_uuid();
        let dg_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

        {
            let mut node = t.ctx.node.write().unwrap();
            let local_uuid = node.device_uuid;
            if let Some(d) = node.owner.user.devices.iter_mut().find(|d| d.uuid == local_uuid) {
                d.grade   = DeviceGrade::SG;
                d.sg_rank = Some(1);
            }
            node.owner.user.devices.push(Device {
                alias:        "peer-dg".to_string(),
                uuid:         dg_uuid,
                grade:        DeviceGrade::DG,
                sg_rank:      None,
                hosts:        Vec::new(),
                applications: Vec::new(),
            });
            node.owner.active_connections.insert(conn_id, ActiveConnection {
                id: conn_id,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: sg_kp.clone(),
                peer_public_key: dg_kp.public_key,
                peer_active_connection_id: 99,
                device_uuid: dg_uuid,
                peer_addr: dg_addr,
            });
        }
        let dg_conn = ActiveConnection {
            id: 99,
            timeout: SystemTime::now() + Duration::from_secs(3600),
            key_pair: dg_kp,
            peer_public_key: sg_kp.public_key,
            peer_active_connection_id: conn_id,
            device_uuid: dg_uuid,
            peer_addr: "127.0.0.1:0".parse().unwrap(),
        };
        (conn_id, dg_conn, dg_uuid, dg_addr)
    }

    /// Parse a SyncWriteAck payload (everything after the op byte) using a
    /// peer-side ActiveConnection. Returns (result, private_version, public_version).
    fn parse_write_ack(buf: &[u8], conn: &ActiveConnection) -> (u8, SyncVersion, SyncVersion) {
        // Mock a node with this connection so we can call decrypt_packet_body.
        let mut node = super::super::data_models::Node::new();
        node.owner.active_connections.insert(conn.id, ActiveConnection {
            id: conn.id,
            timeout: conn.timeout,
            key_pair: conn.key_pair.clone(),
            peer_public_key: conn.peer_public_key,
            peer_active_connection_id: conn.peer_active_connection_id,
            device_uuid: conn.device_uuid,
            peer_addr: conn.peer_addr,
        });
        let plaintext = decrypt_packet_body(&node, buf).expect("decrypt ack");
        let mut pos = 0usize;
        let result = plaintext[pos]; pos += 1;
        let private_v = read_sync_version(&plaintext, &mut pos).unwrap();
        let public_v  = read_sync_version(&plaintext, &mut pos).unwrap();
        (result, private_v, public_v)
    }

    /// Bind a socket and use it as the DG's address so the SG's ack is captured.
    fn writer_setup_with_capture(t: &TestCtx) -> (u16, ActiveConnection, UdpSocket) {
        let dg_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        dg_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let dg_addr = dg_socket.local_addr().unwrap();

        let (_, dg_conn, dg_uuid, _) = setup_writer_sg_with_dg_peer(t);
        // Replace the SG-side connection's peer_addr so acks land on dg_socket.
        {
            let mut node = t.ctx.node.write().unwrap();
            for c in node.owner.active_connections.values_mut() {
                if c.device_uuid == dg_uuid {
                    c.peer_addr = dg_addr;
                }
            }
        }
        let conn_id = dg_conn.peer_active_connection_id;
        (conn_id, dg_conn, dg_socket)
    }

    #[test]
    fn top_online_sg_defers_to_connected_top_rank_sg() {
        // Local node is a rank-2 SG; a rank-1 SG is connected. Even though the
        // local node is itself an SG, the more-preferred connected SG must win.
        let t = TestCtx::new();
        let rank1_uuid = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            let local_uuid = node.device_uuid;
            let d = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == local_uuid).unwrap();
            d.grade = DeviceGrade::SG;
            d.sg_rank = Some(2);
            d.hosts = vec!["sg2:7777".into()];
            node.owner.user.devices.push(Device {
                alias: "sg1".into(), uuid: rank1_uuid, grade: DeviceGrade::SG,
                sg_rank: Some(1), hosts: vec!["sg1:7777".into()], applications: vec![],
            });
            node.owner.active_connections.insert(7, ActiveConnection {
                id: 7, timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: generate_x25519_keypair(),
                peer_public_key: generate_x25519_keypair().public_key,
                peer_active_connection_id: 1, device_uuid: rank1_uuid,
                peer_addr: "127.0.0.1:0".parse().unwrap(),
            });
        }
        let node = t.ctx.node.read().unwrap();
        assert_eq!(top_online_sg(&node), Some(rank1_uuid),
            "a non-top SG must defer to the connected top-ranked SG");
    }

    #[test]
    fn top_online_sg_falls_back_to_local_when_top_rank_offline() {
        // Same topology, but the rank-1 SG has no active connection. The local
        // rank-2 SG can still mint for itself rather than failing.
        let t = TestCtx::new();
        let rank1_uuid = generate_uuid();
        let local_uuid = {
            let mut node = t.ctx.node.write().unwrap();
            let local_uuid = node.device_uuid;
            let d = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == local_uuid).unwrap();
            d.grade = DeviceGrade::SG;
            d.sg_rank = Some(2);
            d.hosts = vec!["sg2:7777".into()];
            node.owner.user.devices.push(Device {
                alias: "sg1".into(), uuid: rank1_uuid, grade: DeviceGrade::SG,
                sg_rank: Some(1), hosts: vec!["sg1:7777".into()], applications: vec![],
            });
            local_uuid
        };
        let node = t.ctx.node.read().unwrap();
        assert_eq!(top_online_sg(&node), Some(local_uuid),
            "an unreachable top SG must not strand the local SG");
    }

    #[test]
    fn generate_invitation_request_mints_locally_and_replies_with_code() {
        // SG side of the DG→SG invitation flow: an SG receives a 0x35 request,
        // must store a fresh invitation locally and reply (0x36) with a code
        // that embeds the SG's own hosts and references the stored invitation.
        let t = TestCtx::new();
        let (_conn_id, dg_conn, dg_socket) = writer_setup_with_capture(&t);

        // The SG needs advertised hosts to embed in the code.
        {
            let mut node = t.ctx.node.write().unwrap();
            let local_uuid = node.device_uuid;
            let d = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == local_uuid).unwrap();
            d.hosts = vec!["sg.example:7777".to_string()];
        }

        // Craft the 0x35 request exactly as a DG would: [kind][token].
        let token = generate_uuid();
        let mut body = vec![INVITE_TYPE_DEVICE];
        body.extend_from_slice(&token);
        let pkt = build_encrypted_packet(GENERATE_INVITATION_REQUEST_OP, &dg_conn, &body);
        generate_invitation_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        // The SG must have stored exactly one device invitation.
        let stored_id = {
            let node = t.ctx.node.read().unwrap();
            assert_eq!(node.owner.device_invitations.len(), 1,
                "SG should store the minted invitation");
            assert!(node.owner.contact_invitations.is_empty(),
                "device kind must not touch contact_invitations");
            node.owner.device_invitations[0].id
        };

        // The SG must have replied with a 0x36 carrying OK + a decodable code.
        let mut buf = [0u8; 1024];
        let (len, _) = dg_socket.recv_from(&mut buf).expect("expected a 0x36 reply");
        assert_eq!(buf[0], GENERATE_INVITATION_RESPONSE_OP);

        // Decrypt the reply using the DG-side connection.
        let plaintext = {
            let mut node = super::super::data_models::Node::new();
            node.owner.active_connections.insert(dg_conn.id, ActiveConnection {
                id: dg_conn.id, timeout: dg_conn.timeout,
                key_pair: dg_conn.key_pair.clone(),
                peer_public_key: dg_conn.peer_public_key,
                peer_active_connection_id: dg_conn.peer_active_connection_id,
                device_uuid: dg_conn.device_uuid,
                peer_addr: dg_conn.peer_addr,
            });
            decrypt_packet_body(&node, &buf[1..len]).expect("decrypt reply")
        };

        // Body: [token:16][result:1][code...].
        assert_eq!(&plaintext[0..16], &token[..], "token must be echoed for matching");
        assert_eq!(plaintext[16], INVITE_RESULT_OK);
        let code = std::str::from_utf8(&plaintext[17..]).unwrap();
        let (inv_id, _pk, hosts) = decode_invitation_code(code).expect("code must decode");
        assert_eq!(inv_id, stored_id, "code must reference the stored invitation");
        assert_eq!(hosts, vec!["sg.example:7777".to_string()],
            "code must embed the SG's own hosts");
    }

    #[test]
    fn generate_invitation_response_fills_waiting_slot() {
        // DG side: a 0x36 reply must fill the rendezvous slot keyed by token and
        // make the encoded code available to the parked requester.
        let t = TestCtx::new();
        let (_conn_id, dg_conn, _dg_socket) = writer_setup_with_capture(&t);

        let token = generate_uuid();
        t.ctx.pending_invites.slots.lock().unwrap().insert(token, None);

        // Encrypt the 0x36 reply from the DG-side connection; the local node
        // holds the matching connection (inserted by writer_setup_with_capture)
        // so decrypt_packet_body recovers it via the header conn id.
        let mut reply_body = Vec::new();
        reply_body.extend_from_slice(&token);
        reply_body.push(INVITE_RESULT_OK);
        reply_body.extend_from_slice(b"THECODE");
        let pkt = build_encrypted_packet(GENERATE_INVITATION_RESPONSE_OP, &dg_conn, &reply_body);
        generate_invitation_response("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let slots = t.ctx.pending_invites.slots.lock().unwrap();
        assert_eq!(slots.get(&token), Some(&Some(Ok("THECODE".to_string()))),
            "slot must hold the decoded code for the parked requester");
    }

    #[test]
    fn sync_write_request_writer_accepts_and_acks_ok() {
        let t = TestCtx::new();
        let (_, dg_conn, dg_socket) = writer_setup_with_capture(&t);
        let dg_uuid = dg_conn.device_uuid;

        let change = Change::AddApplication {
            device_uuid: dg_uuid,
            app_id:      app_uuid(42),
            app_alias:   "acked".to_string(),
        };
        let payload = serialize_change(&change);
        let pkt = build_encrypted_packet(SYNC_WRITE_REQUEST_OP, &dg_conn, &payload);

        sync_write_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        // SG should have appended the app and bumped public_version.
        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == dg_uuid).unwrap();
        assert_eq!(dev.applications.len(), 1);
        assert_eq!(node.owner.public_version.epoch, 1);
        drop(node);

        // Capture the ack and verify result + bumped public version.
        let mut buf = [0u8; 1024];
        let (len, _) = dg_socket.recv_from(&mut buf).expect("ack received");
        assert_eq!(buf[0], SYNC_WRITE_ACK_OP);
        let (result, priv_v, pub_v) = parse_write_ack(&buf[1..len], &dg_conn);
        assert_eq!(result, WRITE_ACK_OK);
        assert!(priv_v.is_initial());
        assert_eq!(pub_v.epoch, 1);
        assert_eq!(pub_v.seq,   1);
    }

    #[test]
    fn sync_write_request_validation_error_for_unknown_device() {
        let t = TestCtx::new();
        let (_, dg_conn, dg_socket) = writer_setup_with_capture(&t);
        let bogus = generate_uuid();

        let change = Change::AddApplication {
            device_uuid: bogus,
            app_id:      app_uuid(1),
            app_alias:   "nope".to_string(),
        };
        let payload = serialize_change(&change);
        let pkt = build_encrypted_packet(SYNC_WRITE_REQUEST_OP, &dg_conn, &payload);
        sync_write_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 1024];
        let (len, _) = dg_socket.recv_from(&mut buf).expect("ack received");
        assert_eq!(buf[0], SYNC_WRITE_ACK_OP);
        let (result, priv_v, pub_v) = parse_write_ack(&buf[1..len], &dg_conn);
        assert_eq!(result, WRITE_ACK_VALIDATION_ERROR);
        assert!(priv_v.is_initial());
        assert!(pub_v.is_initial(), "validation failure must not bump version");
    }

    #[test]
    fn sync_write_request_non_writer_acks_not_writer() {
        // SG with rank 2; rank 1 is reachable. find_writer_sg returns Remote(rank-1),
        // so this SG should reject any write request with NOT_WRITER.
        let t = TestCtx::new();
        let (_, dg_conn, dg_socket) = writer_setup_with_capture(&t);
        let dg_uuid = dg_conn.device_uuid;

        // Demote local to rank 2 and add a reachable rank-1 peer SG.
        {
            let mut node = t.ctx.node.write().unwrap();
            let local_uuid = node.device_uuid;
            for d in node.owner.user.devices.iter_mut() {
                if d.uuid == local_uuid {
                    d.sg_rank = Some(2);
                }
            }
        }
        let _ = add_peer_sg(&t, 1, /*conn*/ true, /*polled_up*/ Some(true));

        let change = Change::AddApplication {
            device_uuid: dg_uuid,
            app_id:      app_uuid(1),
            app_alias:   "nope".to_string(),
        };
        let payload = serialize_change(&change);
        let pkt = build_encrypted_packet(SYNC_WRITE_REQUEST_OP, &dg_conn, &payload);
        sync_write_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        // Local state must not have been mutated.
        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == dg_uuid).unwrap();
        assert!(dev.applications.is_empty());
        drop(node);

        let mut buf = [0u8; 1024];
        let (len, _) = dg_socket.recv_from(&mut buf).expect("ack received");
        let (result, _, pub_v) = parse_write_ack(&buf[1..len], &dg_conn);
        assert_eq!(result, WRITE_ACK_NOT_WRITER);
        assert!(pub_v.is_initial());
    }

    // ── Phase 5: notify, pull, public-state ───────────────────────────────────

    #[test]
    fn bumped_scopes_detects_what_changed() {
        let z = SyncVersion::zero();
        let v = SyncVersion { writer_sg_uuid: [1; 16], epoch: 1, seq: 1 };
        assert!(bumped_scopes(z, z, z, z).is_empty());
        assert_eq!(bumped_scopes(z, z, v, z), vec![Scope::Private]);
        assert_eq!(bumped_scopes(z, z, z, v), vec![Scope::Public]);
        assert_eq!(bumped_scopes(z, z, v, v), vec![Scope::Private, Scope::Public]);
    }

    #[test]
    fn public_state_serialize_apply_roundtrip() {
        // Build a populated source node, serialize, apply onto a fresh target
        // node, and verify both look the same in their public-scope view.
        let src = TestCtx::new();
        let local = promote_local_to_sg(&src, 1);
        let app1 = Change::AddApplication { device_uuid: local, app_id: app_uuid(11), app_alias: "a1".into() };
        let app2 = Change::AddApplication { device_uuid: local, app_id: app_uuid(22), app_alias: "a2".into() };
        apply_change_locally(&app1, local, &src.ctx).unwrap();
        apply_change_locally(&app2, local, &src.ctx).unwrap();

        let blob = serialize_public_state(&src.ctx.node.read().unwrap());

        let dst = TestCtx::new();
        assert!(apply_public_state(&blob, &dst.ctx));

        let dst_node = dst.ctx.node.read().unwrap();
        let src_node = src.ctx.node.read().unwrap();
        assert_eq!(dst_node.owner.user.alias, src_node.owner.user.alias);
        assert_eq!(dst_node.owner.user.uuid,  src_node.owner.user.uuid);
        // Source has the local device in its list; the destination should now
        // have an entry for that uuid with the same public fields and apps.
        let src_dev = src_node.owner.user.devices.iter().find(|d| d.uuid == local).unwrap();
        let dst_dev = dst_node.owner.user.devices.iter().find(|d| d.uuid == local).unwrap();
        assert_eq!(dst_dev.alias, src_dev.alias);
        assert_eq!(dst_dev.applications.len(), 2);
        let mut ids: Vec<Uuid> = dst_dev.applications.iter().map(|a| a.id).collect();
        ids.sort();
        let mut expected = vec![app_uuid(11), app_uuid(22)];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn apply_public_state_preserves_local_app_token_and_host() {
        // The local node is the writer for its own device under sync v2 —
        // a Public-state pull from a peer SG must NOT touch existing local
        // apps (alias, token, host all stay). Only absent apps get added.
        let t = TestCtx::new();
        let local_uuid = t.ctx.node.read().unwrap().device_uuid;
        let real_host: SocketAddrV4 = "10.0.0.1:5555".parse().unwrap();
        let real_token: Uuid = [0x42; 16];
        {
            let mut node = t.ctx.node.write().unwrap();
            let dev = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == local_uuid).unwrap();
            dev.applications.push(Application {
                id: app_uuid(7), alias: "old-alias".into(),
                protocol: "udp".into(), host: real_host,
                user_approved: true, token: real_token,
            });
        }

        // Build a public-state blob that reports the same app id with a new alias.
        let mut blob = Vec::new();
        let user_alias = t.ctx.node.read().unwrap().owner.user.alias.clone();
        let user_uuid  = t.ctx.node.read().unwrap().owner.user.uuid;
        push_str(&mut blob, &user_alias);
        blob.extend_from_slice(&user_uuid);
        blob.push(1u8); // 1 device
        // device record (matches the local device's uuid)
        let dev_clone = {
            let node = t.ctx.node.read().unwrap();
            let d = node.owner.user.devices.iter().find(|d| d.uuid == local_uuid).unwrap();
            (d.alias.clone(), d.uuid, matches!(d.grade, DeviceGrade::SG), d.sg_rank, d.hosts.clone())
        };
        blob.extend_from_slice(&dev_clone.1);
        push_str(&mut blob, &dev_clone.0);
        blob.push(if dev_clone.2 { 1 } else { 0 });
        blob.push(dev_clone.3.map(|r| r.min(255) as u8).unwrap_or(0));
        blob.push(dev_clone.4.len() as u8);
        for h in &dev_clone.4 { push_str(&mut blob, h); }
        blob.push(1u8); // 1 app
        blob.extend_from_slice(&app_uuid(7));
        push_str(&mut blob, "new-alias");
        blob.push(0u8); // 0 contacts

        assert!(apply_public_state(&blob, &t.ctx));

        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == local_uuid).unwrap();
        assert_eq!(dev.applications.len(), 1);
        let app = &dev.applications[0];
        assert_eq!(app.alias, "old-alias", "local alias must be preserved (sync v2 owns this)");
        assert_eq!(app.host, real_host,    "local host must be preserved");
        assert_eq!(app.token, real_token,  "local token must be preserved");
        assert_eq!(app.protocol, "udp",    "protocol stays local");
    }

    #[test]
    fn apply_public_state_rejects_truncated_blob() {
        let t = TestCtx::new();
        let blob = vec![5u8, b'h', b'i']; // claims 5-byte alias but has 2
        assert!(!apply_public_state(&blob, &t.ctx));
    }

    /// Build a minimal Public-state blob for `apply_public_state` tests:
    ///   - keeps the existing local user alias/uuid
    ///   - includes exactly the (device, apps) entries listed
    ///   - zero contacts
    /// Each device is rendered as DG, sg_rank=0, hosts=[], for compactness.
    fn build_public_state_blob(t: &TestCtx, devs: &[(Uuid, &str, Vec<(u16, &str)>)]) -> Vec<u8> {
        let (user_alias, user_uuid) = {
            let node = t.ctx.node.read().unwrap();
            (node.owner.user.alias.clone(), node.owner.user.uuid)
        };
        let mut blob = Vec::new();
        push_str(&mut blob, &user_alias);
        blob.extend_from_slice(&user_uuid);
        blob.push(devs.len() as u8);
        for (uuid, alias, apps) in devs {
            blob.extend_from_slice(uuid);
            push_str(&mut blob, alias);
            blob.push(0u8);      // grade = DG (0)
            blob.push(0u8);      // sg_rank = 0
            blob.push(0u8);      // host_count = 0
            blob.push(apps.len() as u8);
            for (id, app_alias) in apps {
                blob.extend_from_slice(&id.to_be_bytes());
                push_str(&mut blob, app_alias);
            }
        }
        blob.push(0u8);          // 0 contacts
        blob
    }

    #[test]
    fn apply_public_state_drops_peer_apps_not_in_incoming() {
        // Peer device has app 5 locally. Incoming blob doesn't list app 5 for
        // that peer — apply_public_state must remove it (RemoveApplication
        // propagation via FullState pull).
        let t = TestCtx::new();
        let peer_uuid = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:        "peer".into(),
                uuid:         peer_uuid,
                grade:        DeviceGrade::DG,
                sg_rank:      None,
                hosts:        vec![],
                applications: vec![Application {
                    id: app_uuid(5), alias: "stale".into(),
                    protocol: "".into(),
                    host: "0.0.0.0:0".parse().unwrap(),
                    user_approved: true, token: [0u8; 16],
                }],
            });
        }

        let blob = build_public_state_blob(&t, &[(peer_uuid, "peer", vec![])]);
        assert!(apply_public_state(&blob, &t.ctx));

        let node = t.ctx.node.read().unwrap();
        let peer = node.owner.user.devices.iter().find(|d| d.uuid == peer_uuid).unwrap();
        assert!(peer.applications.is_empty(),
            "incoming was authoritative for peer device — stale app should be dropped");
    }

    #[test]
    fn apply_public_state_preserves_local_apps_not_in_incoming() {
        // Local device has an in-flight pre-mutated app that the writer hasn't
        // acknowledged yet. A pull that races ahead of the ack would receive
        // a blob without that app — apply_public_state must NOT drop it,
        // otherwise the user's pending registration would briefly vanish.
        let t = TestCtx::new();
        let local_uuid = t.ctx.node.read().unwrap().device_uuid;
        {
            let mut node = t.ctx.node.write().unwrap();
            let dev = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == local_uuid).unwrap();
            dev.applications.push(Application {
                id: app_uuid(9), alias: "in-flight".into(),
                protocol: "udp".into(),
                host: "10.0.0.1:9999".parse().unwrap(),
                user_approved: true, token: [0xCC; 16],
            });
        }

        let blob = build_public_state_blob(&t, &[(local_uuid, "local", vec![])]);
        assert!(apply_public_state(&blob, &t.ctx));

        let node = t.ctx.node.read().unwrap();
        let local = node.owner.user.devices.iter().find(|d| d.uuid == local_uuid).unwrap();
        assert_eq!(local.applications.len(), 1, "in-flight local app must survive");
        assert_eq!(local.applications[0].id, app_uuid(9));
    }

    #[test]
    fn sync_write_request_fans_out_update_available() {
        // Writer SG accepts a SyncWriteRequest and should emit BOTH a WriteAck
        // (back to the originator) and a SyncUpdateAvailable (to all own peers).
        // Originator's connection captures both — the ack arrives via the
        // request connection, the notification arrives because the originator
        // is itself an own-user peer.
        let t = TestCtx::new();
        let (_, dg_conn, dg_socket) = writer_setup_with_capture(&t);
        let dg_uuid = dg_conn.device_uuid;

        let change = Change::AddApplication {
            device_uuid: dg_uuid, app_id: app_uuid(5), app_alias: "fan".into(),
        };
        let payload = serialize_change(&change);
        let pkt = build_encrypted_packet(SYNC_WRITE_REQUEST_OP, &dg_conn, &payload);
        sync_write_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        // Collect both packets (order is implementation-defined).
        let mut got_ack = false;
        let mut got_notify = false;
        for _ in 0..2 {
            let mut buf = [0u8; 1024];
            let (len, _) = dg_socket.recv_from(&mut buf).expect("expected packet");
            match buf[0] {
                op if op == SYNC_WRITE_ACK_OP        => got_ack = true,
                op if op == SYNC_UPDATE_AVAILABLE_OP => {
                    // Decrypt and verify the announced version is the bumped one.
                    let plaintext = decrypt_packet_body(
                        &{
                            let mut node = super::super::data_models::Node::new();
                            node.owner.active_connections.insert(dg_conn.id, ActiveConnection {
                                id: dg_conn.id, timeout: dg_conn.timeout,
                                key_pair: dg_conn.key_pair.clone(),
                                peer_public_key: dg_conn.peer_public_key,
                                peer_active_connection_id: dg_conn.peer_active_connection_id,
                                device_uuid: dg_conn.device_uuid,
                                peer_addr: dg_conn.peer_addr,
                            });
                            node
                        },
                        &buf[1..len],
                    ).unwrap();
                    let mut pos = 0;
                    let scope = read_scope(&plaintext, &mut pos).unwrap();
                    let v = read_sync_version(&plaintext, &mut pos).unwrap();
                    assert_eq!(scope, Scope::Public);
                    assert_eq!(v.epoch, 1);
                    assert_eq!(v.seq,   1);
                    got_notify = true;
                }
                other => panic!("unexpected op byte {other}"),
            }
        }
        assert!(got_ack, "WriteAck missing");
        assert!(got_notify, "UpdateAvailable missing");
    }

    /// Set up a local DG with an active connection to a "writer SG" peer
    /// whose address is a captured UDP socket. Returns
    /// (sg_conn_for_encrypting, sg_socket_for_capture).
    fn dg_setup_with_writer_capture(t: &TestCtx) -> (ActiveConnection, UdpSocket) {
        let sg_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        sg_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let sg_addr = sg_socket.local_addr().unwrap();

        let dg_kp  = generate_x25519_keypair();
        let sg_kp  = generate_x25519_keypair();
        let conn_id = 5u16;
        let sg_uuid = generate_uuid();

        {
            let mut node = t.ctx.node.write().unwrap();
            // Local stays a DG (TestCtx default); add the SG as a known device.
            node.owner.user.devices.push(Device {
                alias: "writer-sg".into(),
                uuid: sg_uuid,
                grade: DeviceGrade::SG,
                sg_rank: Some(1),
                hosts: vec![sg_addr.to_string()],
                applications: Vec::new(),
            });
            node.owner.active_connections.insert(conn_id, ActiveConnection {
                id: conn_id,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: dg_kp.clone(),
                peer_public_key: sg_kp.public_key,
                peer_active_connection_id: 99,
                device_uuid: sg_uuid,
                peer_addr: sg_addr,
            });
        }
        let sg_conn = ActiveConnection {
            id: 99,
            timeout: SystemTime::now() + Duration::from_secs(3600),
            key_pair: sg_kp,
            peer_public_key: dg_kp.public_key,
            peer_active_connection_id: conn_id,
            device_uuid: sg_uuid,
            peer_addr: "127.0.0.1:0".parse().unwrap(),
        };
        (sg_conn, sg_socket)
    }

    #[test]
    fn sync_update_available_triggers_pull_when_announced_is_newer() {
        let t = TestCtx::new();
        let (sg_conn, sg_socket) = dg_setup_with_writer_capture(&t);

        // Announce a version newer than the DG's local zero.
        let announced = SyncVersion {
            writer_sg_uuid: sg_conn.device_uuid, epoch: 1, seq: 5,
        };
        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        write_sync_version(&mut body, &announced);
        let pkt = build_encrypted_packet(SYNC_UPDATE_AVAILABLE_OP, &sg_conn, &body);

        sync_update_available("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 1024];
        let (len, _) = sg_socket.recv_from(&mut buf).expect("PullRequest expected");
        assert_eq!(buf[0], SYNC_PULL_REQUEST_OP);
        assert!(len > 1, "non-empty body");
    }

    #[test]
    fn sync_update_available_skips_pull_when_both_sides_are_own_user_sgs() {
        // Sync v2 (7c.6+) is the sole authority for Public-scope propagation
        // between two own-user SGs — sync v1's cross-writer pull corrupts
        // the multi-writer model. So a SyncUpdateAvailable from a peer that
        // is also an own-user SG must NOT trigger send_pull_request.
        let t = TestCtx::new();
        let (sg_conn, sg_socket) = dg_setup_with_writer_capture(&t);
        // Promote local to SG and the peer to also be an own-user SG.
        promote_local_to_sg(&t, 1);
        promote_peer_to_sg(&t, sg_conn.device_uuid, 2);

        let announced = SyncVersion {
            writer_sg_uuid: sg_conn.device_uuid, epoch: 2, seq: 5,
        };
        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        write_sync_version(&mut body, &announced);
        let pkt = build_encrypted_packet(SYNC_UPDATE_AVAILABLE_OP, &sg_conn, &body);

        sync_update_available("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 1024];
        assert!(sg_socket.recv_from(&mut buf).is_err(),
            "no PullRequest expected — sync v2 handles own-user-SG propagation");
    }

    #[test]
    fn sync_update_available_skips_pull_when_caught_up() {
        let t = TestCtx::new();
        let (sg_conn, sg_socket) = dg_setup_with_writer_capture(&t);

        let v = SyncVersion {
            writer_sg_uuid: sg_conn.device_uuid, epoch: 1, seq: 5,
        };
        // Pin local to the same version the SG will announce.
        t.ctx.node.write().unwrap().owner.public_version = v;

        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        write_sync_version(&mut body, &v);
        let pkt = build_encrypted_packet(SYNC_UPDATE_AVAILABLE_OP, &sg_conn, &body);

        sync_update_available("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 1024];
        assert!(sg_socket.recv_from(&mut buf).is_err(), "no PullRequest expected");
    }

    #[test]
    fn sync_pull_request_returns_full_state_when_stale() {
        // Writer SG with a populated public state. A pull from a DG with a
        // zero last_seen should get FullState back with a non-empty blob.
        let t = TestCtx::new();
        let (_, dg_conn, dg_socket) = writer_setup_with_capture(&t);
        // Add an app so the public state is non-empty.
        let local_uuid = t.ctx.node.read().unwrap().device_uuid;
        apply_change_locally(&Change::AddApplication {
            device_uuid: local_uuid, app_id: app_uuid(1), app_alias: "ax".into(),
        }, local_uuid, &t.ctx).unwrap();

        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        write_sync_version(&mut body, &SyncVersion::zero());
        let pkt = build_encrypted_packet(SYNC_PULL_REQUEST_OP, &dg_conn, &body);
        sync_pull_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 4096];
        let (len, _) = dg_socket.recv_from(&mut buf).expect("response expected");
        assert_eq!(buf[0], SYNC_PULL_RESPONSE_OP);

        // Decrypt and inspect.
        let plaintext = {
            let mut node = super::super::data_models::Node::new();
            node.owner.active_connections.insert(dg_conn.id, ActiveConnection {
                id: dg_conn.id, timeout: dg_conn.timeout,
                key_pair: dg_conn.key_pair.clone(),
                peer_public_key: dg_conn.peer_public_key,
                peer_active_connection_id: dg_conn.peer_active_connection_id,
                device_uuid: dg_conn.device_uuid,
                peer_addr: dg_conn.peer_addr,
            });
            decrypt_packet_body(&node, &buf[1..len]).unwrap()
        };
        let mut pos = 0;
        let scope = read_scope(&plaintext, &mut pos).unwrap();
        let result = plaintext[pos]; pos += 1;
        let v      = read_sync_version(&plaintext, &mut pos).unwrap();
        assert_eq!(scope, Scope::Public);
        assert_eq!(result, PULL_RESULT_FULL_STATE);
        assert_eq!(v.epoch, 1);
        assert!(plaintext.len() > pos, "FullState should carry a state blob");
    }

    #[test]
    fn sync_pull_request_returns_no_updates_when_caught_up() {
        let t = TestCtx::new();
        let (_, dg_conn, dg_socket) = writer_setup_with_capture(&t);
        let local_uuid = t.ctx.node.read().unwrap().device_uuid;
        apply_change_locally(&Change::AddApplication {
            device_uuid: local_uuid, app_id: app_uuid(1), app_alias: "ax".into(),
        }, local_uuid, &t.ctx).unwrap();
        let current = t.ctx.node.read().unwrap().owner.public_version;

        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        write_sync_version(&mut body, &current); // already up to date
        let pkt = build_encrypted_packet(SYNC_PULL_REQUEST_OP, &dg_conn, &body);
        sync_pull_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 4096];
        let (len, _) = dg_socket.recv_from(&mut buf).expect("response expected");
        let plaintext = {
            let mut node = super::super::data_models::Node::new();
            node.owner.active_connections.insert(dg_conn.id, ActiveConnection {
                id: dg_conn.id, timeout: dg_conn.timeout,
                key_pair: dg_conn.key_pair.clone(),
                peer_public_key: dg_conn.peer_public_key,
                peer_active_connection_id: dg_conn.peer_active_connection_id,
                device_uuid: dg_conn.device_uuid,
                peer_addr: dg_conn.peer_addr,
            });
            decrypt_packet_body(&node, &buf[1..len]).unwrap()
        };
        let mut pos = 0;
        let _scope  = read_scope(&plaintext, &mut pos).unwrap();
        let result  = plaintext[pos]; pos += 1;
        let _v      = read_sync_version(&plaintext, &mut pos).unwrap();
        assert_eq!(result, PULL_RESULT_NO_UPDATES);
        // No state blob on NoUpdates.
        assert_eq!(plaintext.len(), pos);
    }

    #[test]
    fn sync_pull_response_full_state_applies_and_pins_version() {
        // Build a writer's view of state by populating a temp node, then
        // package it as a SyncPullResponse and feed it to a fresh DG.
        let writer = TestCtx::new();
        let writer_local = promote_local_to_sg(&writer, 1);
        apply_change_locally(&Change::AddApplication {
            device_uuid: writer_local, app_id: app_uuid(99), app_alias: "ww".into(),
        }, writer_local, &writer.ctx).unwrap();
        let writer_pub_v = writer.ctx.node.read().unwrap().owner.public_version;
        let blob = serialize_public_state(&writer.ctx.node.read().unwrap());

        let dg = TestCtx::new();
        let (sg_conn, _sg_socket) = dg_setup_with_writer_capture(&dg);

        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        body.push(PULL_RESULT_FULL_STATE);
        write_sync_version(&mut body, &writer_pub_v);
        body.extend_from_slice(&blob);
        let pkt = build_encrypted_packet(SYNC_PULL_RESPONSE_OP, &sg_conn, &body);

        sync_pull_response("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &dg.ctx);

        let node = dg.ctx.node.read().unwrap();
        // Version pinned.
        assert_eq!(node.owner.public_version, writer_pub_v);
        // Writer's device record is now in our state with the new app.
        let writer_dev = node.owner.user.devices.iter().find(|d| d.uuid == writer_local).unwrap();
        assert_eq!(writer_dev.applications.len(), 1);
        assert_eq!(writer_dev.applications[0].id, app_uuid(99));
        assert_eq!(writer_dev.applications[0].alias, "ww");
    }

    #[test]
    fn request_change_local_bumps_even_on_idempotent_apply() {
        // Originator semantics: when local state already reflects the change
        // (e.g., app_register added the app with token+host before publishing
        // id+alias), request_change must still bump the version so peers
        // find out. The receiver-side handler (sync_write_request) keeps the
        // stricter "bump only on actual mutation" rule.
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);

        // Pre-mutate: add the app directly to local state (no version bump).
        {
            let mut node = t.ctx.node.write().unwrap();
            let dev = node.owner.user.devices.iter_mut().find(|d| d.uuid == local).unwrap();
            dev.applications.push(Application {
                id: app_uuid(17), alias: "preadded".into(),
                protocol: "udp".into(),
                host: "127.0.0.1:9000".parse().unwrap(),
                user_approved: true,
                token: [0xAB; 16],
            });
        }
        assert!(t.ctx.node.read().unwrap().owner.public_version.is_initial());

        // Call request_change for the SAME change. apply_change_locally
        // returns idempotent no-op, but request_change must still bump.
        request_change(Change::AddApplication {
            device_uuid: local, app_id: app_uuid(17), app_alias: "preadded".into(),
        }, &t.ctx).expect("request_change ok");

        let node = t.ctx.node.read().unwrap();
        assert_eq!(node.owner.public_version.writer_sg_uuid, local);
        assert_eq!(node.owner.public_version.epoch, 1);
        assert_eq!(node.owner.public_version.seq,   1);

        // App's private fields preserved (apply_change_locally never wrote
        // over them since it was a no-op).
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == local).unwrap();
        let app = dev.applications.iter().find(|a| a.id == app_uuid(17)).unwrap();
        assert_eq!(app.token, [0xAB; 16]);
        assert_eq!(app.host, "127.0.0.1:9000".parse::<SocketAddrV4>().unwrap());
    }

    #[test]
    fn sync_pull_remote_writer_sends_pull_for_both_scopes() {
        // DG with a reachable writer SG: sync_pull should emit one
        // SyncPullRequest per scope (Public + Private) on the SG connection.
        let t = TestCtx::new();
        let (sg_conn, sg_socket) = dg_setup_with_writer_capture(&t);

        sync_pull(&t.ctx);

        let mut got_public  = false;
        let mut got_private = false;
        for _ in 0..2 {
            let mut buf = [0u8; 1024];
            let (len, _) = sg_socket.recv_from(&mut buf).expect("PullRequest expected");
            assert_eq!(buf[0], SYNC_PULL_REQUEST_OP);

            let plaintext = {
                let mut node = super::super::data_models::Node::new();
                node.owner.active_connections.insert(sg_conn.id, ActiveConnection {
                    id: sg_conn.id, timeout: sg_conn.timeout,
                    key_pair: sg_conn.key_pair.clone(),
                    peer_public_key: sg_conn.peer_public_key,
                    peer_active_connection_id: sg_conn.peer_active_connection_id,
                    device_uuid: sg_conn.device_uuid,
                    peer_addr: sg_conn.peer_addr,
                });
                decrypt_packet_body(&node, &buf[1..len]).unwrap()
            };
            let mut pos = 0;
            let scope = read_scope(&plaintext, &mut pos).unwrap();
            match scope {
                Scope::Public  => got_public = true,
                Scope::Private => got_private = true,
            }
        }
        assert!(got_public  && got_private, "expected both Public and Private pulls");
    }

    #[test]
    fn sync_pull_local_writer_is_noop() {
        // Promote local to SG so find_writer_sg returns Local. sync_pull must
        // not attempt to send anything.
        let t = TestCtx::new();
        promote_local_to_sg(&t, 1);

        // No connections to capture on; just assert sync_pull doesn't panic.
        sync_pull(&t.ctx);
        // Reaching here means no panic; nothing observable to assert further.
    }

    #[test]
    fn sync_pull_unreachable_is_noop() {
        // DG with no own SGs at all.
        let t = TestCtx::new();
        sync_pull(&t.ctx);
    }

    #[test]
    fn sync_pull_response_no_updates_pins_version_without_changing_state() {
        let dg = TestCtx::new();
        let (sg_conn, _) = dg_setup_with_writer_capture(&dg);

        // Capture pre-state to compare.
        let pre_devices_len = dg.ctx.node.read().unwrap().owner.user.devices.len();

        let pinned = SyncVersion { writer_sg_uuid: sg_conn.device_uuid, epoch: 7, seq: 3 };
        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        body.push(PULL_RESULT_NO_UPDATES);
        write_sync_version(&mut body, &pinned);
        let pkt = build_encrypted_packet(SYNC_PULL_RESPONSE_OP, &sg_conn, &body);

        sync_pull_response("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &dg.ctx);

        let node = dg.ctx.node.read().unwrap();
        assert_eq!(node.owner.public_version, pinned);
        assert_eq!(node.owner.user.devices.len(), pre_devices_len);
    }

    // ── Host resolution ───────────────────────────────────────────────────────

    #[test]
    fn resolve_host_entry_parses_ip_port() {
        let addr = resolve_host_entry("127.0.0.1:9001").unwrap();
        assert_eq!(addr.port(), 9001);
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn resolve_host_entry_defaults_port() {
        let addr = resolve_host_entry("127.0.0.1").unwrap();
        assert_eq!(addr.port(), 7777);
    }

    #[test]
    fn resolve_host_entry_rejects_unresolvable() {
        assert!(resolve_host_entry("this.name.definitely.does.not.exist.invalid").is_none());
    }

    #[test]
    fn best_address_for_device_picks_lowest_rtt_up() {
        let t = TestCtx::new();
        let dev_uuid = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:        "sg".to_string(),
                uuid:         dev_uuid,
                grade:        DeviceGrade::SG,
                sg_rank:      Some(1),
                hosts:        vec!["127.0.0.1:9001".into(), "127.0.0.1:9002".into()],
                applications: Vec::new(),
            });
            node.sg_statuses.insert((dev_uuid, "127.0.0.1:9001".into()), super::super::data_models::SgStatus {
                up: true,
                last_rtt: Some(Duration::from_millis(80)),
                last_polled: Instant::now(),
            });
            node.sg_statuses.insert((dev_uuid, "127.0.0.1:9002".into()), super::super::data_models::SgStatus {
                up: true,
                last_rtt: Some(Duration::from_millis(20)),
                last_polled: Instant::now(),
            });
        }
        let node = t.ctx.node.read().unwrap();
        let addr = best_address_for_device(&node, &dev_uuid).unwrap();
        assert_eq!(addr.port(), 9002);
    }

    #[test]
    fn best_address_for_device_falls_back_to_first_resolvable() {
        let t = TestCtx::new();
        let dev_uuid = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:        "sg".to_string(),
                uuid:         dev_uuid,
                grade:        DeviceGrade::SG,
                sg_rank:      Some(1),
                hosts:        vec!["127.0.0.1:9003".into()],
                applications: Vec::new(),
            });
            // No sg_statuses entry — cold-boot fallback should kick in.
        }
        let node = t.ctx.node.read().unwrap();
        let addr = best_address_for_device(&node, &dev_uuid).unwrap();
        assert_eq!(addr.port(), 9003);
    }

    // Packet encrypt/decrypt round-trip lives in `crypto::tests`.

    // ── relay_packet forwards AppPacket to destination ────────────────────────

    #[test]
    fn relay_packet_forwards_app_packet_to_dest() {
        // The "SG" node is the TestCtx node.
        // dg_sender_kp  — sender DG's side of its connection with the SG
        // sg_from_dg_kp — SG's side of the same connection
        // sg_to_dest_kp — SG's side of its connection with the dest DG
        // dest_kp        — dest DG's side of its connection with the SG
        let dg_sender_kp  = generate_x25519_keypair();
        let sg_from_dg_kp = generate_x25519_keypair();
        let sg_to_dest_kp = generate_x25519_keypair();
        let dest_kp        = generate_x25519_keypair();

        let dest_device_uuid = generate_uuid();
        let dest_app_id: Uuid = app_uuid(5);
        let sender_app_id: Uuid = app_uuid(3);

        // The "destination" app socket — we'll receive the AppPacket here.
        let dest_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        dest_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let dest_addr: std::net::SocketAddrV4 = dest_socket.local_addr().unwrap()
            .to_string().parse().unwrap();

        let t = TestCtx::new();
        {
            let mut node = t.ctx.node.write().unwrap();

            // SG active connection #1: toward sender DG (SG's view).
            node.owner.active_connections.insert(1, ActiveConnection {
                id:                        1,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  sg_from_dg_kp.clone(),
                peer_public_key:           dg_sender_kp.public_key,
                peer_active_connection_id: 10, // sender DG's local conn id
                device_uuid:               generate_uuid(),
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });

            // SG active connection #2: toward dest DG.
            node.owner.active_connections.insert(2, ActiveConnection {
                id:                        2,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  sg_to_dest_kp.clone(),
                peer_public_key:           dest_kp.public_key,
                peer_active_connection_id: 20, // dest DG's local conn id
                device_uuid:               dest_device_uuid,
                peer_addr:                 SocketAddr::V4(dest_addr),
            });

            // Dest device must be in the node's known devices/contacts.
            node.owner.contact_users.push(Contact {
                public_key: Ed25519PublicKey(generate_key_bytes()),
                user: User {
                    alias:   "contact".to_string(),
                    uuid:    generate_uuid(),
                    devices: vec![Device {
                        alias:           "dest-dg".to_string(),
                        uuid:            dest_device_uuid,
                        grade:           DeviceGrade::DG,
                        sg_rank:         None,
                        hosts:           vec![dest_addr.to_string()],
                        applications:    Vec::new(),
                    }],
                },
                last_seen_public_version: SyncVersion::default(),
            });
        }

        // Build a RelayPacket as if sent by the sender DG.
        // Session AEAD key for SG conn #1 is domain-separated HKDF over the
        // X25519 DH of (dg_sender_sk, sg_from_dg_pk) — symmetric with the SG side.
        let mut relay_body = Vec::new();
        relay_body.extend_from_slice(&dest_device_uuid);
        relay_body.extend_from_slice(&dest_app_id);
        relay_body.extend_from_slice(&sender_app_id);
        relay_body.extend_from_slice(b"payload");

        // Use dg_sender_kp to encrypt for SG's conn #1 (peer_active_conn_id = 1 on SG side).
        let sender_side_conn = ActiveConnection {
            id:                        10,
            timeout:                   SystemTime::now() + Duration::from_secs(3600),
            key_pair:                  dg_sender_kp,
            peer_public_key:           sg_from_dg_kp.public_key,
            peer_active_connection_id: 1, // SG's local conn ID
            device_uuid:               generate_uuid(),
        peer_addr:   "127.0.0.1:0".parse().unwrap(),
        };
        let relay_pkt = build_encrypted_packet(RELAY_PACKET_OP, &sender_side_conn, &relay_body);

        // Feed the relay packet (buf = everything after op byte) to the SG handler.
        relay_packet(t.app_addr(), relay_pkt[1..].to_vec(), &t.ctx);

        // Dest socket should have received an AppPacket (op 0x41).
        let mut buf = [0u8; 512];
        let (len, _) = dest_socket.recv_from(&mut buf).expect("no AppPacket received");
        assert_eq!(buf[0], APP_PACKET_OP);

        // Decrypt the AppPacket using dest DG's view of its connection with the SG.
        let dest_side_conn = ActiveConnection {
            id:                        20,
            timeout:                   SystemTime::now() + Duration::from_secs(3600),
            key_pair:                  dest_kp,
            peer_public_key:           sg_to_dest_kp.public_key,
            peer_active_connection_id: 2,
            device_uuid:               generate_uuid(),
        peer_addr:   "127.0.0.1:0".parse().unwrap(),
        };
        let t2 = TestCtx::new();
        {
            let mut node = t2.ctx.node.write().unwrap();
            node.owner.active_connections.insert(20, ActiveConnection {
                id:                        dest_side_conn.id,
                timeout:                   dest_side_conn.timeout,
                key_pair:                  dest_side_conn.key_pair,
                peer_public_key:           dest_side_conn.peer_public_key,
                peer_active_connection_id: dest_side_conn.peer_active_connection_id,
                device_uuid:               dest_side_conn.device_uuid,
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
        }
        let node     = t2.ctx.node.read().unwrap();
        let decrypted = decrypt_packet_body(&node, &buf[1..len]).unwrap();

        // Decrypted body: [dest_app_id: 16][sender_app_id: 16][payload]
        let dest_id_bytes:   [u8; 16] = decrypted[0..16].try_into().unwrap();
        let sender_id_bytes: [u8; 16] = decrypted[16..32].try_into().unwrap();
        assert_eq!(dest_id_bytes,   dest_app_id);
        assert_eq!(sender_id_bytes, sender_app_id);
        assert_eq!(&decrypted[32..], b"payload");
    }

    #[test]
    fn relay_packet_drops_oversized_app_payload() {
        // Same topology as the happy-path relay test, but payload > MAX_APP_PAYLOAD
        // must not produce an AppPacket on the dest socket.
        let dg_sender_kp  = generate_x25519_keypair();
        let sg_from_dg_kp = generate_x25519_keypair();
        let sg_to_dest_kp = generate_x25519_keypair();
        let dest_kp        = generate_x25519_keypair();

        let dest_device_uuid = generate_uuid();
        let dest_app_id: Uuid = app_uuid(5);
        let sender_app_id: Uuid = app_uuid(3);

        let dest_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        dest_socket.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
        let dest_addr: std::net::SocketAddrV4 = dest_socket.local_addr().unwrap()
            .to_string().parse().unwrap();

        let t = TestCtx::new();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.active_connections.insert(1, ActiveConnection {
                id: 1,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: sg_from_dg_kp.clone(),
                peer_public_key: dg_sender_kp.public_key,
                peer_active_connection_id: 10,
                device_uuid: generate_uuid(),
                peer_addr: "127.0.0.1:0".parse().unwrap(),
            });
            node.owner.active_connections.insert(2, ActiveConnection {
                id: 2,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: sg_to_dest_kp.clone(),
                peer_public_key: dest_kp.public_key,
                peer_active_connection_id: 20,
                device_uuid: dest_device_uuid,
                peer_addr: SocketAddr::V4(dest_addr),
            });
            node.owner.contact_users.push(Contact {
                public_key: Ed25519PublicKey(generate_key_bytes()),
                user: User {
                    alias: "contact".to_string(),
                    uuid: generate_uuid(),
                    devices: vec![Device {
                        alias: "dest-dg".to_string(),
                        uuid: dest_device_uuid,
                        grade: DeviceGrade::DG,
                        sg_rank: None,
                        hosts: vec![dest_addr.to_string()],
                        applications: Vec::new(),
                    }],
                },
                last_seen_public_version: SyncVersion::default(),
            });
        }

        let mut relay_body = Vec::new();
        relay_body.extend_from_slice(&dest_device_uuid);
        relay_body.extend_from_slice(&dest_app_id);
        relay_body.extend_from_slice(&sender_app_id);
        relay_body.extend_from_slice(&vec![0u8; MAX_APP_PAYLOAD + 1]);

        let sender_side_conn = ActiveConnection {
            id: 10,
            timeout: SystemTime::now() + Duration::from_secs(3600),
            key_pair: dg_sender_kp,
            peer_public_key: sg_from_dg_kp.public_key,
            peer_active_connection_id: 1,
            device_uuid: generate_uuid(),
            peer_addr: "127.0.0.1:0".parse().unwrap(),
        };
        let relay_pkt = build_encrypted_packet(RELAY_PACKET_OP, &sender_side_conn, &relay_body);
        relay_packet(t.app_addr(), relay_pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 512];
        assert!(
            dest_socket.recv_from(&mut buf).is_err(),
            "oversized relay body must not be forwarded as AppPacket"
        );
    }

    // ── app_packet delivers to local app ──────────────────────────────────────

    #[test]
    fn app_packet_delivers_to_local_app() {
        let t = TestCtx::new();

        // Set up: an approved app on the local device.
        let app_id: Uuid    = app_uuid(9);
        let sender_app_id   = app_uuid(3);
        let sg_kp           = generate_x25519_keypair();
        let local_kp        = generate_x25519_keypair();

        // Register the app first so we have an approved app with a known port.
        let app_addr = t.app_addr(); // we'll use app_socket as the "app"
        {
            let mut node = t.ctx.node.write().unwrap();
            let device_uuid = node.device_uuid;
            let dev = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == device_uuid).unwrap();
            dev.applications.push(super::super::data_models::Application {
                id:            app_id,
                alias:         "myapp".to_string(),
                protocol:      "udp".to_string(),
                host:          app_addr.to_string().parse().unwrap(),
                user_approved: true,
                token:         generate_uuid(),
            });

            // Active connection #5: from SG (our peer is the SG).
            node.owner.active_connections.insert(5, ActiveConnection {
                id:                        5,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  local_kp.clone(),
                peer_public_key:           sg_kp.public_key,
                peer_active_connection_id: 99,
                device_uuid:               generate_uuid(),
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
        }

        // Build AppPacket body: [dest_app_id: 16][sender_app_id: 16][payload]
        let mut body = Vec::new();
        body.extend_from_slice(&app_id);
        body.extend_from_slice(&sender_app_id);
        body.extend_from_slice(b"hello app");

        // SG encrypts using its side of conn #5.
        let sg_side = ActiveConnection {
            id:                        99,
            timeout:                   SystemTime::now() + Duration::from_secs(3600),
            key_pair:                  sg_kp,
            peer_public_key:           local_kp.public_key,
            peer_active_connection_id: 5,
            device_uuid:               generate_uuid(),
        peer_addr:   "127.0.0.1:0".parse().unwrap(),
        };
        let pkt = build_encrypted_packet(APP_PACKET_OP, &sg_side, &body);

        // Feed the AppPacket (buf after op byte) to the handler.
        app_packet(t.app_addr(), pkt[1..].to_vec(), &t.ctx);

        // app_socket should receive the push.
        let push = t.recv_reply();
        assert_eq!(push[0], APP_PUSH_OP);
        let sender_id_bytes: [u8; 16] = push[1..17].try_into().unwrap();
        assert_eq!(sender_id_bytes, sender_app_id);
        assert_eq!(&push[17..], b"hello app");
    }

    #[test]
    fn app_packet_drops_oversized_app_payload() {
        let t = TestCtx::new();
        let app_id: Uuid = app_uuid(9);
        let sender_app_id = app_uuid(3);
        let sg_kp = generate_x25519_keypair();
        let local_kp = generate_x25519_keypair();
        let app_addr = t.app_addr();
        {
            let mut node = t.ctx.node.write().unwrap();
            let device_uuid = node.device_uuid;
            let dev = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == device_uuid).unwrap();
            dev.applications.push(super::super::data_models::Application {
                id: app_id,
                alias: "myapp".to_string(),
                protocol: "udp".to_string(),
                host: app_addr.to_string().parse().unwrap(),
                user_approved: true,
                token: generate_uuid(),
            });
            node.owner.active_connections.insert(5, ActiveConnection {
                id: 5,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: local_kp.clone(),
                peer_public_key: sg_kp.public_key,
                peer_active_connection_id: 99,
                device_uuid: generate_uuid(),
                peer_addr: "127.0.0.1:0".parse().unwrap(),
            });
        }

        let mut body = Vec::new();
        body.extend_from_slice(&app_id);
        body.extend_from_slice(&sender_app_id);
        body.extend_from_slice(&vec![0u8; MAX_APP_PAYLOAD + 1]);

        let sg_side = ActiveConnection {
            id: 99,
            timeout: SystemTime::now() + Duration::from_secs(3600),
            key_pair: sg_kp,
            peer_public_key: local_kp.public_key,
            peer_active_connection_id: 5,
            device_uuid: generate_uuid(),
            peer_addr: "127.0.0.1:0".parse().unwrap(),
        };
        let pkt = build_encrypted_packet(APP_PACKET_OP, &sg_side, &body);
        app_packet(t.app_addr(), pkt[1..].to_vec(), &t.ctx);

        // No push should arrive (recv_reply times out).
        let mut buf = [0u8; 64];
        assert!(
            t.app_socket.recv_from(&mut buf).is_err(),
            "oversized AppPacket must not be pushed to the local app"
        );
    }

    #[test]
    fn app_packet_skips_unapproved_app() {
        let t = TestCtx::new();
        let app_id: Uuid = app_uuid(9);
        let sender_app_id = app_uuid(3);
        let sg_kp = generate_x25519_keypair();
        let local_kp = generate_x25519_keypair();
        let app_addr = t.app_addr();
        {
            let mut node = t.ctx.node.write().unwrap();
            let device_uuid = node.device_uuid;
            let dev = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == device_uuid).unwrap();
            dev.applications.push(super::super::data_models::Application {
                id: app_id,
                alias: "pending".to_string(),
                protocol: "udp".to_string(),
                host: app_addr.to_string().parse().unwrap(),
                user_approved: false, // not approved → no push
                token: generate_uuid(),
            });
            node.owner.active_connections.insert(5, ActiveConnection {
                id: 5,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: local_kp.clone(),
                peer_public_key: sg_kp.public_key,
                peer_active_connection_id: 99,
                device_uuid: generate_uuid(),
                peer_addr: "127.0.0.1:0".parse().unwrap(),
            });
        }

        let mut body = Vec::new();
        body.extend_from_slice(&app_id);
        body.extend_from_slice(&sender_app_id);
        body.extend_from_slice(b"should not land");

        let sg_side = ActiveConnection {
            id: 99,
            timeout: SystemTime::now() + Duration::from_secs(3600),
            key_pair: sg_kp,
            peer_public_key: local_kp.public_key,
            peer_active_connection_id: 5,
            device_uuid: generate_uuid(),
            peer_addr: "127.0.0.1:0".parse().unwrap(),
        };
        let pkt = build_encrypted_packet(APP_PACKET_OP, &sg_side, &body);
        app_packet(t.app_addr(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 64];
        assert!(
            t.app_socket.recv_from(&mut buf).is_err(),
            "unapproved apps must never receive app_packet pushes"
        );
    }

    #[test]
    fn tunnel_delivery_skips_unapproved_app() {
        let t = TestCtx::new();
        let app_id: Uuid = app_uuid(11);
        let sender_app_id = app_uuid(4);
        let peer_kp = generate_x25519_keypair();
        let local_kp = generate_x25519_keypair();
        let app_addr = t.app_addr();
        let tunnel_id: u16 = 7;
        let conn_id: u16 = 42;
        {
            let mut node = t.ctx.node.write().unwrap();
            let device_uuid = node.device_uuid;
            let dev = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == device_uuid).unwrap();
            dev.applications.push(super::super::data_models::Application {
                id: app_id,
                alias: "pending".to_string(),
                protocol: "udp".to_string(),
                host: app_addr.to_string().parse().unwrap(),
                user_approved: false,
                token: generate_uuid(),
            });
            node.owner.active_connections.insert(conn_id, ActiveConnection {
                id: conn_id,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: local_kp.clone(),
                peer_public_key: peer_kp.public_key,
                peer_active_connection_id: 1,
                device_uuid: generate_uuid(),
                peer_addr: "127.0.0.1:0".parse().unwrap(),
            });
            node.owner.dg_tunnel_map.insert(tunnel_id, conn_id);
        }

        let aead_key = aead_key_from_dh(
            &local_kp.private_key,
            &peer_kp.public_key,
            aead_domain::TUNNEL,
        );
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&app_id);
        plaintext.extend_from_slice(&sender_app_id);
        plaintext.extend_from_slice(b"tunnel payload");
        let (ciphertext, nonce) = xchacha20_encrypt(&aead_key, &plaintext);

        let mut buf = Vec::new();
        buf.extend_from_slice(&tunnel_id.to_be_bytes());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ciphertext);

        tunnel_delivery(t.app_addr(), buf, &t.ctx);

        let mut rx = [0u8; 64];
        assert!(
            t.app_socket.recv_from(&mut rx).is_err(),
            "unapproved apps must never receive tunnel_delivery pushes"
        );
    }

    #[test]
    fn relay_packet_local_delivery_skips_unapproved_app() {
        // SG is both relay and destination; unapproved local app must not get a push.
        let dg_sender_kp = generate_x25519_keypair();
        let sg_from_dg_kp = generate_x25519_keypair();
        let dest_app_id: Uuid = app_uuid(5);
        let sender_app_id: Uuid = app_uuid(3);

        let t = TestCtx::new();
        let local_uuid = {
            let mut node = t.ctx.node.write().unwrap();
            let local_uuid = node.device_uuid;
            node.owner.active_connections.insert(1, ActiveConnection {
                id: 1,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: sg_from_dg_kp.clone(),
                peer_public_key: dg_sender_kp.public_key,
                peer_active_connection_id: 10,
                device_uuid: generate_uuid(),
                peer_addr: "127.0.0.1:0".parse().unwrap(),
            });
            let dev = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == local_uuid).unwrap();
            dev.applications.push(super::super::data_models::Application {
                id: dest_app_id,
                alias: "pending".to_string(),
                protocol: "udp".to_string(),
                host: t.app_addr().to_string().parse().unwrap(),
                user_approved: false,
                token: generate_uuid(),
            });
            local_uuid
        };

        let mut relay_body = Vec::new();
        relay_body.extend_from_slice(&local_uuid);
        relay_body.extend_from_slice(&dest_app_id);
        relay_body.extend_from_slice(&sender_app_id);
        relay_body.extend_from_slice(b"nope");

        let sender_side = ActiveConnection {
            id: 10,
            timeout: SystemTime::now() + Duration::from_secs(3600),
            key_pair: dg_sender_kp,
            peer_public_key: sg_from_dg_kp.public_key,
            peer_active_connection_id: 1,
            device_uuid: generate_uuid(),
            peer_addr: "127.0.0.1:0".parse().unwrap(),
        };
        let relay_pkt = build_encrypted_packet(RELAY_PACKET_OP, &sender_side, &relay_body);
        relay_packet(t.app_addr(), relay_pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 64];
        assert!(
            t.app_socket.recv_from(&mut buf).is_err(),
            "unapproved apps must never receive local relay pushes"
        );
    }

    #[test]
    fn app_get_data_does_not_leak_foreign_tokens_or_keys() {
        let t = TestCtx::new();
        let token_a = register_and_get_token(&t, "app-a", 9001);
        let token_b = register_and_get_token(&t, "app-b", 9002);

        // Distinct owner private key (non-zero) so we can search for it in the reply.
        let owner_sk = {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.key_pair.private_key = Ed25519SecretKey([0x5Au8; 32]);
            node.owner.key_pair.public_key = Ed25519PublicKey([0xA5u8; 32]);
            let contact_pk = Ed25519PublicKey([0xCCu8; 32]);
            let pending_app_id = app_uuid(77);
            let approved_app_id = app_uuid(78);
            let foreign_token = [0xF1u8; 16];
            node.owner.contact_users.push(Contact {
                public_key: contact_pk,
                user: User {
                    alias: "bob".to_string(),
                    uuid: generate_uuid(),
                    devices: vec![Device {
                        alias: "bob-phone".to_string(),
                        uuid: generate_uuid(),
                        grade: DeviceGrade::DG,
                        sg_rank: None,
                        hosts: vec!["10.0.0.9:7777".into()],
                        applications: vec![
                            Application {
                                id: pending_app_id,
                                alias: "secret-pending".to_string(),
                                protocol: "udp".to_string(),
                                host: "10.0.0.9:9000".parse().unwrap(),
                                user_approved: false,
                                token: foreign_token,
                            },
                            Application {
                                id: approved_app_id,
                                alias: "bob-chat".to_string(),
                                protocol: "udp".to_string(),
                                host: "10.0.0.9:9001".parse().unwrap(),
                                user_approved: true,
                                token: [0xF2u8; 16],
                            },
                        ],
                    }],
                },
                last_seen_public_version: SyncVersion::default(),
            });
            node.owner.key_pair.private_key
        };

        app_get_data(t.app_addr(), token_a.to_vec(), &t.ctx);
        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);

        let has16 = |needle: [u8; 16]| reply.windows(16).any(|w| w == needle);
        let count16 = |needle: [u8; 16]| reply.windows(16).filter(|w| *w == needle).count();
        let has32 = |needle: [u8; 32]| reply.windows(32).any(|w| w == needle);

        // Own token appears exactly once (echo in own-app section).
        assert_eq!(count16(token_a), 1, "own token should appear once");

        // Sibling app token must not appear.
        assert!(!has16(token_b), "must not leak sibling app token");

        // Contact app tokens must not appear.
        assert!(!has16([0xF1u8; 16]), "must not leak unapproved contact app token");
        assert!(!has16([0xF2u8; 16]), "must not leak approved contact app token");

        // Owner private key must not appear.
        assert!(!has32(owner_sk.0), "must not leak owner private key");
        // Contact long-term public key must not appear (apps do not get contact crypto).
        assert!(!has32([0xCCu8; 32]), "must not leak contact public keys");

        // Unapproved contact app id should not be listed; approved id may appear.
        assert!(!has16(app_uuid(77)), "unapproved contact apps must be omitted from get-data");
        assert!(has16(app_uuid(78)), "approved contact apps should be visible by id");
    }

    // ── Contact exchange (0x33 / 0x34) ───────────────────────────────────────

    /// Build a ContactRequest buf (after op byte) from the requester's node and
    /// the invitation stored on the target.
    fn contact_request_buf(requester_node: &Node, inv: &Invitation) -> Vec<u8> {
        let ephem_kp = generate_x25519_keypair();
        let aead_key = aead_key_from_dh(
            &ephem_kp.private_key,
            &inv.key_pair.public_key,
            aead_domain::BOOTSTRAP,
        );
        let payload = serialize_contact_payload(requester_node);
        let (ciphertext, nonce) = xchacha20_encrypt(&aead_key, &payload);

        let mut buf = Vec::new();
        buf.extend_from_slice(&inv.id);
        buf.extend_from_slice(ephem_kp.public_key.as_bytes());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ciphertext);
        buf
    }

    /// Add a fresh contact invitation to a node and return a clone for use in tests.
    fn add_contact_invitation(node: &mut Node) -> Invitation {
        let kp = generate_x25519_keypair();
        let inv = Invitation {
            id:         generate_uuid(),
            key_pair:   kp,
            expires_at: SystemTime::now() + Duration::from_secs(3600),
        };
        node.owner.contact_invitations.push(inv.clone());
        inv
    }

    impl Clone for Invitation {
        fn clone(&self) -> Self {
            Invitation {
                id:         self.id,
                key_pair:   X25519KeyPair {
                    public_key:  self.key_pair.public_key,
                    private_key: self.key_pair.private_key,
                },
                expires_at: self.expires_at,
            }
        }
    }

    #[test]
    fn contact_request_valid_adds_contact_and_replies() {
        let target    = TestCtx::new();
        let requester = TestCtx::new();

        // The contact add now routes through request_change (Gap #2), so the
        // target needs a writer. Promote its local device to a rank-1 SG so the
        // upsert applies + logs locally.
        promote_local_to_sg(&target, 1);

        // Complete setup so key_pair is non-zero.
        {
            let mut node = requester.ctx.node.write().unwrap();
            node.owner.key_pair = generate_ed25519_keypair();
            node.owner.user.alias = "chad".to_string();
        }

        let inv = {
            let mut node = target.ctx.node.write().unwrap();
            add_contact_invitation(&mut node)
        };

        let buf = {
            let node = requester.ctx.node.read().unwrap();
            contact_request_buf(&node, &inv)
        };

        contact_request(target.app_addr(), buf, &target.ctx);

        // Requester should have been added as a contact.
        let node = target.ctx.node.read().unwrap();
        assert_eq!(node.owner.contact_users.len(), 1);
        assert_eq!(node.owner.contact_users[0].user.alias, "chad");

        // The add must have been logged as exactly one UpsertContact (Gap #2).
        assert_eq!(upsert_contact_log_count(&node), 1,
            "contact add must append exactly one UpsertContact write-log entry");

        // Invitation must be consumed.
        assert!(node.owner.contact_invitations.is_empty());
        drop(node);

        // A ContactResponse (op 0x34) must have been sent back.
        let reply = target.recv_reply();
        assert_eq!(reply[0], CONTACT_RESPONSE_OP);
    }

    #[test]
    fn contact_request_unknown_invitation_is_rejected() {
        let target = TestCtx::new();

        // No invitations stored — use a random invitation ID.
        let fake_inv = Invitation {
            id:         generate_uuid(),
            key_pair:   generate_x25519_keypair(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
        };

        let requester_node = {
            let mut n = Node::new();
            n.owner.key_pair = generate_ed25519_keypair();
            n
        };
        let buf = contact_request_buf(&requester_node, &fake_inv);

        contact_request(target.app_addr(), buf, &target.ctx);

        let node = target.ctx.node.read().unwrap();
        assert!(node.owner.contact_users.is_empty());
    }

    #[test]
    fn contact_request_expired_invitation_is_rejected() {
        let target = TestCtx::new();

        let inv = {
            let mut node = target.ctx.node.write().unwrap();
            let kp = generate_x25519_keypair();
            let inv = Invitation {
                id:         generate_uuid(),
                key_pair:   kp,
                expires_at: SystemTime::now() - Duration::from_secs(1), // already expired
            };
            node.owner.contact_invitations.push(inv.clone());
            inv
        };

        let requester_node = {
            let mut n = Node::new();
            n.owner.key_pair = generate_ed25519_keypair();
            n
        };
        let buf = contact_request_buf(&requester_node, &inv);

        contact_request(target.app_addr(), buf, &target.ctx);

        let node = target.ctx.node.read().unwrap();
        assert!(node.owner.contact_users.is_empty());
        // Expired invitation must be removed.
        assert!(node.owner.contact_invitations.is_empty());
    }

    #[test]
    fn contact_request_duplicate_not_added_twice() {
        let target    = TestCtx::new();
        let requester = TestCtx::new();

        // Contact add routes through request_change (Gap #2) — target needs a writer.
        promote_local_to_sg(&target, 1);

        {
            let mut node = requester.ctx.node.write().unwrap();
            node.owner.key_pair       = generate_ed25519_keypair();
            node.owner.user.alias     = "chad".to_string();
        }

        // First request.
        let inv1 = {
            let mut node = target.ctx.node.write().unwrap();
            add_contact_invitation(&mut node)
        };
        let buf1 = {
            let node = requester.ctx.node.read().unwrap();
            contact_request_buf(&node, &inv1)
        };
        contact_request(target.app_addr(), buf1, &target.ctx);
        let _ = target.recv_reply();

        // Second request with a fresh invitation but same requester UUID.
        let inv2 = {
            let mut node = target.ctx.node.write().unwrap();
            add_contact_invitation(&mut node)
        };
        let buf2 = {
            let node = requester.ctx.node.read().unwrap();
            contact_request_buf(&node, &inv2)
        };
        contact_request(target.app_addr(), buf2, &target.ctx);
        let _ = target.recv_reply();

        let node = target.ctx.node.read().unwrap();
        assert_eq!(node.owner.contact_users.len(), 1, "duplicate contact must not be added");
        // The duplicate upsert is an idempotent no-op — still exactly one log entry.
        assert_eq!(upsert_contact_log_count(&node), 1,
            "duplicate contact must not append a second UpsertContact write-log entry");
    }

    #[test]
    fn contact_response_valid_adds_contact_and_clears_pending() {
        let requester = TestCtx::new();

        // Contact add routes through request_change (Gap #2) — requester needs a writer.
        promote_local_to_sg(&requester, 1);

        // Set up the requester's side of a pending exchange.
        let inv_kp    = generate_x25519_keypair();
        let ephem_kp  = generate_x25519_keypair();
        let sg_addr: std::net::SocketAddrV4 = "127.0.0.1:19000".parse().unwrap();

        {
            let mut node = requester.ctx.node.write().unwrap();
            node.owner.pending_contact_exchange = Some(PendingContactExchange {
                our_ephem_key_pair: ephem_kp.clone(),
                invitation_pk:      inv_kp.public_key,
                sg_addr,
            });
        }

        // Bootstrap AEAD key from requester's perspective.
        let aead_key = aead_key_from_dh(
            &ephem_kp.private_key,
            &inv_kp.public_key,
            aead_domain::BOOTSTRAP,
        );

        // Build the target's contact payload.
        let target_uuid = generate_uuid();
        let target_pk   = generate_ed25519_keypair().public_key;
        let mut payload = Vec::new();
        push_str(&mut payload, "will");
        payload.extend_from_slice(&target_uuid);
        payload.extend_from_slice(target_pk.as_bytes());
        payload.push(0u8); // 0 devices

        let (ciphertext, nonce) = xchacha20_encrypt(&aead_key, &payload);
        let mut buf = Vec::new();
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ciphertext);

        contact_response(SocketAddr::V4(sg_addr), buf, &requester.ctx);

        let node = requester.ctx.node.read().unwrap();
        assert_eq!(node.owner.contact_users.len(), 1);
        assert_eq!(node.owner.contact_users[0].user.alias, "will");
        assert_eq!(node.owner.contact_users[0].user.uuid, target_uuid);
        // Pending exchange must be cleared.
        assert!(node.owner.pending_contact_exchange.is_none());
    }

    #[test]
    fn contact_response_wrong_source_is_rejected() {
        let requester = TestCtx::new();

        let inv_kp   = generate_x25519_keypair();
        let ephem_kp = generate_x25519_keypair();
        let sg_addr: std::net::SocketAddrV4 = "127.0.0.1:19001".parse().unwrap();

        {
            let mut node = requester.ctx.node.write().unwrap();
            node.owner.pending_contact_exchange = Some(PendingContactExchange {
                our_ephem_key_pair: ephem_kp.clone(),
                invitation_pk:      inv_kp.public_key,
                sg_addr,
            });
        }

        let aead_key = aead_key_from_dh(
            &ephem_kp.private_key,
            &inv_kp.public_key,
            aead_domain::BOOTSTRAP,
        );
        let mut payload = Vec::new();
        push_str(&mut payload, "will");
        payload.extend_from_slice(&generate_uuid());
        payload.extend_from_slice(&generate_key_bytes());
        payload.push(0u8);
        let (ciphertext, nonce) = xchacha20_encrypt(&aead_key, &payload);
        let mut buf = Vec::new();
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ciphertext);

        // Deliver from a different address.
        let wrong_addr: SocketAddr = "127.0.0.1:19002".parse().unwrap();
        contact_response(wrong_addr, buf, &requester.ctx);

        let node = requester.ctx.node.read().unwrap();
        assert!(node.owner.contact_users.is_empty());
        // Pending exchange must still be intact.
        assert!(node.owner.pending_contact_exchange.is_some());
    }

    #[test]
    fn contact_response_no_pending_exchange_is_rejected() {
        let requester = TestCtx::new();
        // No pending_contact_exchange set — handler should be a no-op.

        let shared_secret = generate_key_bytes();
        let mut payload   = Vec::new();
        push_str(&mut payload, "will");
        payload.extend_from_slice(&generate_uuid());
        payload.extend_from_slice(&generate_key_bytes());
        payload.push(0u8);
        let (ciphertext, nonce) = xchacha20_encrypt(&shared_secret, &payload);
        let mut buf = Vec::new();
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&ciphertext);

        let src: SocketAddr = "127.0.0.1:19003".parse().unwrap();
        contact_response(src, buf, &requester.ctx);

        let node = requester.ctx.node.read().unwrap();
        assert!(node.owner.contact_users.is_empty());
    }

    // ── Contact data sync ─────────────────────────────────────────────────────

    /// Set up the test node as an SG and return the active connection ID and
    /// a matching "sender-side" connection that can encrypt packets for this node.
    fn setup_sg_node_with_contact_conn(
        t: &TestCtx,
        contact_user_uuid: Uuid,
        contact_sg_uuid:   Uuid,
        contact_sg_host:   std::net::SocketAddrV4,
    ) -> (u16, ActiveConnection) {
        let sg_kp     = generate_x25519_keypair();
        let sender_kp = generate_x25519_keypair();
        let conn_id   = 7u16;

        {
            let mut node = t.ctx.node.write().unwrap();

            // Make this node an SG.
            let device_uuid = node.device_uuid;
            if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) {
                dev.grade   = DeviceGrade::SG;
                dev.sg_rank = Some(1);
            }

            // Add the contact.
            node.owner.contact_users.push(Contact {
                public_key: Ed25519PublicKey(generate_key_bytes()),
                user: User {
                    alias:   "chad".to_string(),
                    uuid:    contact_user_uuid,
                    devices: vec![Device {
                        alias:           "chad-sg".to_string(),
                        uuid:            contact_sg_uuid,
                        grade:           DeviceGrade::SG,
                        sg_rank:         Some(1),
                        hosts:           vec![contact_sg_host.to_string()],
                        applications:    Vec::new(),
                    }],
                },
                last_seen_public_version: SyncVersion::default(),
            });

            // Active connection to the contact's SG.
            node.owner.active_connections.insert(conn_id, ActiveConnection {
                id:                        conn_id,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  sg_kp.clone(),
                peer_public_key:           sender_kp.public_key,
                peer_active_connection_id: 42,
                device_uuid:               contact_sg_uuid,
                peer_addr:                 SocketAddr::V4(contact_sg_host),
            });
        }

        // Sender-side connection that can encrypt packets this node will decrypt.
        let sender_conn = ActiveConnection {
            id:                        42,
            timeout:                   SystemTime::now() + Duration::from_secs(3600),
            key_pair:                  sender_kp,
            peer_public_key:           sg_kp.public_key,
            peer_active_connection_id: conn_id,
            device_uuid:               contact_sg_uuid,
        peer_addr:   "127.0.0.1:0".parse().unwrap(),
        };

        (conn_id, sender_conn)
    }


    #[test]
    fn contact_data_roundtrip_serialization() {
        // Verify serialize → deserialize preserves all fields.
        let t = TestCtx::new();
        {
            let mut node = t.ctx.node.write().unwrap();
            let device_uuid = node.device_uuid;
            if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) {
                dev.applications.push(Application {
                    id:            app_uuid(7),
                    alias:         "test-app".to_string(),
                    protocol:      "udp".to_string(),
                    host:          "127.0.0.1:5000".parse().unwrap(),
                    user_approved: true,
                    token:         generate_uuid(),
                });
                dev.applications.push(Application {
                    id:            app_uuid(8),
                    alias:         "pending-app".to_string(),
                    protocol:      "udp".to_string(),
                    host:          "127.0.0.1:5001".parse().unwrap(),
                    user_approved: false, // should be excluded from sync
                    token:         generate_uuid(),
                });
            }
        }

        let payload = {
            let node = t.ctx.node.read().unwrap();
            serialize_contact_data(&node)
        };

        let data = deserialize_contact_data(&payload).expect("deserialization failed");

        let node = t.ctx.node.read().unwrap();
        assert_eq!(data.user_uuid, node.owner.user.uuid);
        assert_eq!(data.devices.len(), 1);
        let (_, apps) = &data.devices[0];
        // Only the approved app should be present.
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].0, app_uuid(7));
        assert_eq!(apps[0].1, "test-app");
    }

    // ── Headless first-run setup ──────────────────────────────────────────────

    #[test]
    fn apply_new_user_setup_initializes_node_and_local_device() {
        let t = TestCtx::new();
        assert!(!t.ctx.node.read().unwrap().is_initialized());

        let res = apply_new_user_setup("alice", "alice-laptop", DeviceGrade::SG, Some(2), &t.ctx);
        assert!(res.is_none(), "setup should succeed");

        let node = t.ctx.node.read().unwrap();
        assert!(node.is_initialized(), "key_pair should be populated");
        assert_eq!(node.owner.user.alias, "alice");

        let device_uuid = node.device_uuid;
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert_eq!(dev.alias, "alice-laptop");
        assert!(matches!(dev.grade, DeviceGrade::SG));
        assert_eq!(dev.sg_rank, Some(2));
    }

    #[test]
    fn apply_new_user_setup_dg_clears_sg_rank() {
        let t = TestCtx::new();
        let res = apply_new_user_setup("bob", "bob-phone", DeviceGrade::DG, None, &t.ctx);
        assert!(res.is_none());

        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == node.device_uuid).unwrap();
        assert!(matches!(dev.grade, DeviceGrade::DG));
        assert_eq!(dev.sg_rank, None);
    }

    #[test]
    fn apply_new_user_setup_rejects_empty_aliases() {
        let t = TestCtx::new();
        assert_eq!(
            apply_new_user_setup("", "device", DeviceGrade::SG, Some(1), &t.ctx),
            Some("fields"),
        );
        assert_eq!(
            apply_new_user_setup("user", "", DeviceGrade::SG, Some(1), &t.ctx),
            Some("fields"),
        );
        assert!(!t.ctx.node.read().unwrap().is_initialized(),
            "failed setup must not flip the node to initialized");
    }

    #[test]
    fn complete_setup_stores_password_hash_and_returns_session() {
        let t = TestCtx::new();
        let body = b"alias=Alice&device_alias=Home&grade=sg&sg_rank=1\
            &password=secretpass&password_confirm=secretpass";
        let sid = complete_setup(body, &t.ctx).expect("setup should succeed");
        assert!(!sid.is_empty());
        assert!(t.ctx.sessions.is_valid(&sid));
        let node = t.ctx.node.read().unwrap();
        assert!(node.is_initialized());
        let hash = node.admin_password_hash.as_ref().expect("hash stored");
        assert!(super::super::admin_auth::verify_password("secretpass", hash));
        assert!(!super::super::admin_auth::verify_password("wrongwrong", hash));
    }

    #[test]
    fn complete_setup_rejects_short_password() {
        let t = TestCtx::new();
        let body = b"alias=Alice&device_alias=Home&grade=sg&password=short&password_confirm=short";
        assert_eq!(complete_setup(body, &t.ctx), Err("password_short"));
        assert!(!t.ctx.node.read().unwrap().is_initialized());
    }

    #[test]
    fn start_bootstrap_stashes_pending_with_grade_and_rank() {
        let t = TestCtx::new();
        let inv_id = generate_uuid();
        let inv_pk = generate_x25519_keypair().public_key;
        // Resolvable host so resolve_hosts returns at least one entry. The
        // socket send may fail (nothing's listening) but pending_bootstrap
        // is stashed before the send.
        let hosts = vec!["127.0.0.1:65530".to_string()];
        let code = encode_invitation_code(&inv_id, &inv_pk, &hosts);

        start_bootstrap("my-laptop", &code, DeviceGrade::DG, None, &t.ctx)
            .expect("bootstrap should succeed");

        let node = t.ctx.node.read().unwrap();
        let pb = node.owner.pending_bootstrap.as_ref()
            .expect("pending_bootstrap should be set");
        assert_eq!(pb.invitation_id, inv_id);
        assert_eq!(pb.invitation_pk, inv_pk);
        assert_eq!(pb.device_alias, "my-laptop");
        assert!(matches!(pb.desired_grade, DeviceGrade::DG));
        assert_eq!(pb.desired_sg_rank, None);
    }

    #[test]
    fn start_bootstrap_preserves_sg_grade_and_rank() {
        let t = TestCtx::new();
        let inv_id = generate_uuid();
        let inv_pk = generate_x25519_keypair().public_key;
        let hosts = vec!["127.0.0.1:65531".to_string()];
        let code = encode_invitation_code(&inv_id, &inv_pk, &hosts);

        start_bootstrap("backup-sg", &code, DeviceGrade::SG, Some(3), &t.ctx)
            .expect("bootstrap should succeed");

        let node = t.ctx.node.read().unwrap();
        let pb = node.owner.pending_bootstrap.as_ref().unwrap();
        assert!(matches!(pb.desired_grade, DeviceGrade::SG));
        assert_eq!(pb.desired_sg_rank, Some(3));
    }

    #[test]
    fn start_bootstrap_rejects_garbage_invitation_code() {
        let t = TestCtx::new();
        let res = start_bootstrap("my-laptop", "not-a-real-code", DeviceGrade::DG, None, &t.ctx);
        assert!(res.is_err());
        assert!(t.ctx.node.read().unwrap().owner.pending_bootstrap.is_none());
    }

    // SyncVersion / scope wire-format helpers: `wire::tests`.

    // ── Cross-user sync v1 (ops 0x75 / 0x76 / 0x77) ──────────────────────────

    /// Set up the local node as an SG with one contact + active connection,
    /// binding a UDP socket at the contact's SG address so outbound packets
    /// can be captured.
    fn setup_writer_sg_with_contact_capture(t: &TestCtx) -> (u16, Uuid, ActiveConnection, UdpSocket) {
        let contact_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        contact_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let contact_addr = contact_socket.local_addr().unwrap();
        let contact_v4: std::net::SocketAddrV4 = match contact_addr {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_)  => panic!("expected ipv4"),
        };
        let contact_user_uuid = generate_uuid();
        let contact_sg_uuid   = generate_uuid();
        let (conn_id, sender_conn) = setup_sg_node_with_contact_conn(
            t, contact_user_uuid, contact_sg_uuid, contact_v4,
        );
        (conn_id, contact_user_uuid, sender_conn, contact_socket)
    }

    #[test]
    fn cross_user_update_available_triggers_pull_when_announced_is_newer() {
        let t = TestCtx::new();
        let (_, _, sender_conn, contact_socket) = setup_writer_sg_with_contact_capture(&t);

        let announced = SyncVersion {
            writer_sg_uuid: generate_uuid(), epoch: 1, seq: 3,
        };
        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        write_sync_version(&mut body, &announced);
        let pkt = build_encrypted_packet(CROSS_USER_UPDATE_AVAILABLE_OP, &sender_conn, &body);

        cross_user_update_available("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 1024];
        let (len, _) = contact_socket.recv_from(&mut buf).expect("CrossUserPullRequest expected");
        assert_eq!(buf[0], CROSS_USER_PULL_REQUEST_OP);
        assert!(len > 1);
    }

    #[test]
    fn cross_user_update_available_skips_pull_when_caught_up() {
        let t = TestCtx::new();
        let (_, contact_user_uuid, sender_conn, contact_socket) =
            setup_writer_sg_with_contact_capture(&t);

        let v = SyncVersion {
            writer_sg_uuid: generate_uuid(), epoch: 1, seq: 3,
        };
        // Pin the contact's last_seen to the same version the peer will announce.
        {
            let mut node = t.ctx.node.write().unwrap();
            let c = node.owner.contact_users.iter_mut()
                .find(|c| c.user.uuid == contact_user_uuid).unwrap();
            c.last_seen_public_version = v;
        }

        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        write_sync_version(&mut body, &v);
        let pkt = build_encrypted_packet(CROSS_USER_UPDATE_AVAILABLE_OP, &sender_conn, &body);

        cross_user_update_available("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 1024];
        assert!(contact_socket.recv_from(&mut buf).is_err(), "no pull request expected");
    }

    #[test]
    fn cross_user_pull_request_returns_no_updates_when_peer_is_caught_up() {
        let t = TestCtx::new();
        let (_, _, sender_conn, contact_socket) = setup_writer_sg_with_contact_capture(&t);

        // Bump our public_version so it's non-initial, then have the peer
        // claim the same version.
        let writer_uuid = t.ctx.node.read().unwrap().device_uuid;
        t.ctx.node.write().unwrap().owner.bump_version(Scope::Public, writer_uuid);
        let v = t.ctx.node.read().unwrap().owner.public_version;

        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        write_sync_version(&mut body, &v);
        let pkt = build_encrypted_packet(CROSS_USER_PULL_REQUEST_OP, &sender_conn, &body);

        cross_user_pull_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 4096];
        let (len, _) = contact_socket.recv_from(&mut buf).expect("response expected");
        assert_eq!(buf[0], CROSS_USER_PULL_RESPONSE_OP);

        // Decrypt to confirm NoUpdates result.
        let plaintext = {
            let mut node = super::super::data_models::Node::new();
            node.owner.active_connections.insert(sender_conn.id, ActiveConnection {
                id: sender_conn.id, timeout: sender_conn.timeout,
                key_pair: sender_conn.key_pair.clone(),
                peer_public_key: sender_conn.peer_public_key,
                peer_active_connection_id: sender_conn.peer_active_connection_id,
                device_uuid: sender_conn.device_uuid,
                peer_addr: sender_conn.peer_addr,
            });
            decrypt_packet_body(&node, &buf[1..len]).unwrap()
        };
        let mut pos = 0usize;
        let scope = read_scope(&plaintext, &mut pos).unwrap();
        assert_eq!(scope, Scope::Public);
        let result = plaintext[pos]; pos += 1;
        assert_eq!(result, PULL_RESULT_NO_UPDATES);
    }

    #[test]
    fn cross_user_pull_response_full_state_updates_contact_and_bumps_local() {
        let t = TestCtx::new();
        let (_, contact_user_uuid, sender_conn, _) = setup_writer_sg_with_contact_capture(&t);
        let new_device_uuid = generate_uuid();

        // Build a CrossUserPullResponse(FullState) payload from the contact.
        // State blob is in serialize_contact_data's shape: user_uuid + devices.
        let mut state = Vec::new();
        state.extend_from_slice(&contact_user_uuid);
        state.push(1u8); // one device
        push_device(&mut state, &Device {
            uuid:         new_device_uuid,
            alias:        "new-dev".into(),
            grade:        DeviceGrade::DG,
            sg_rank:      None,
            hosts:        Vec::new(),
            applications: Vec::new(),
        });
        state.push(0u8); // zero apps

        let new_v = SyncVersion {
            writer_sg_uuid: generate_uuid(), epoch: 2, seq: 4,
        };
        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        body.push(PULL_RESULT_FULL_STATE);
        write_sync_version(&mut body, &new_v);
        body.extend_from_slice(&state);
        let pkt = build_encrypted_packet(CROSS_USER_PULL_RESPONSE_OP, &sender_conn, &body);

        let pub_before = t.ctx.node.read().unwrap().owner.public_version;
        cross_user_pull_response("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let node = t.ctx.node.read().unwrap();

        // Contact's devices updated to the new state.
        let contact = node.owner.contact_users.iter()
            .find(|c| c.user.uuid == contact_user_uuid).unwrap();
        assert_eq!(contact.user.devices.len(), 1);
        assert_eq!(contact.user.devices[0].uuid, new_device_uuid);
        // last_seen advanced.
        assert_eq!(contact.last_seen_public_version, new_v);
        // Local writer SG bumped own public_version (so own DGs pull the
        // refreshed contact list via apply_public_state).
        assert!(node.owner.public_version.cmp_same_writer(&pub_before)
                    .map(|o| o.is_gt()).unwrap_or(true),
                "writer SG must bump own public_version after applying cross-user state");
    }

    #[test]
    fn cross_user_pull_response_no_updates_pins_contact_version_only() {
        let t = TestCtx::new();
        let (_, contact_user_uuid, sender_conn, _) = setup_writer_sg_with_contact_capture(&t);

        let new_v = SyncVersion {
            writer_sg_uuid: generate_uuid(), epoch: 1, seq: 7,
        };
        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        body.push(PULL_RESULT_NO_UPDATES);
        write_sync_version(&mut body, &new_v);
        let pkt = build_encrypted_packet(CROSS_USER_PULL_RESPONSE_OP, &sender_conn, &body);

        let pub_before = t.ctx.node.read().unwrap().owner.public_version;
        cross_user_pull_response("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let node = t.ctx.node.read().unwrap();
        let contact = node.owner.contact_users.iter()
            .find(|c| c.user.uuid == contact_user_uuid).unwrap();
        assert_eq!(contact.last_seen_public_version, new_v);
        // NoUpdates must NOT bump our own public_version.
        assert_eq!(node.owner.public_version, pub_before);
    }

    #[test]
    fn notify_contacts_sends_cross_user_update_to_top_ranked_contact_sg() {
        let t = TestCtx::new();
        let (_, _, _, contact_socket) = setup_writer_sg_with_contact_capture(&t);

        let v = SyncVersion {
            writer_sg_uuid: generate_uuid(), epoch: 3, seq: 1,
        };
        notify_contacts(v, &t.ctx);

        let mut buf = [0u8; 1024];
        let (len, _) = contact_socket.recv_from(&mut buf).expect("notify expected");
        assert_eq!(buf[0], CROSS_USER_UPDATE_AVAILABLE_OP);
        assert!(len > 1);
    }

    // ── UI handlers: approve_app / reject_app error surfacing ───────────────

    /// Seed a pending app (user_approved=false) on the local device and
    /// return its id.
    fn seed_pending_app(t: &TestCtx, alias: &str) -> Uuid {
        let mut node = t.ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let dev = node.owner.user.devices.iter_mut()
            .find(|d| d.uuid == device_uuid).unwrap();
        let id = generate_uuid();
        dev.applications.push(Application {
            id,
            alias:         alias.to_string(),
            protocol:      "udp".to_string(),
            host:          "127.0.0.1:9000".parse().unwrap(),
            user_approved: false,
            token:         generate_uuid(),
        });
        id
    }

    /// Seed an approved app and return its id.
    fn seed_approved_app(t: &TestCtx, alias: &str) -> Uuid {
        let id = seed_pending_app(t, alias);
        let mut node = t.ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let dev = node.owner.user.devices.iter_mut()
            .find(|d| d.uuid == device_uuid).unwrap();
        dev.applications.iter_mut().find(|a| a.id == id).unwrap().user_approved = true;
        id
    }

    #[test]
    fn approve_app_success_publishes_and_returns_none() {
        let t = TestCtx::new();
        promote_local_to_sg(&t, 1);
        let id = seed_pending_app(&t, "pending");

        let body = format!("id={}", uuid_hex(&id));
        let res = approve_app(body.as_bytes(), &t.ctx);
        assert_eq!(res, None);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        let app = dev.applications.iter().find(|a| a.id == id).unwrap();
        assert!(app.user_approved, "approve should flip user_approved");
        assert_eq!(node.owner.public_version.epoch, 1,
                   "successful publish should bump public_version");
    }

    #[test]
    fn approve_app_unreachable_rolls_back_and_returns_publish_failed() {
        // Default TestCtx is a DG with no own SG — request_change Unreachable.
        let t = TestCtx::new();
        let id = seed_pending_app(&t, "pending");

        let body = format!("id={}", uuid_hex(&id));
        let res = approve_app(body.as_bytes(), &t.ctx);
        assert_eq!(res, Some(UI_ERR_PUBLISH_FAILED));

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        let app = dev.applications.iter().find(|a| a.id == id).unwrap();
        assert!(!app.user_approved, "rollback should restore user_approved=false");
    }

    #[test]
    fn reject_app_success_publishes_and_returns_none() {
        let t = TestCtx::new();
        promote_local_to_sg(&t, 1);
        let id = seed_approved_app(&t, "doomed");
        // The seed itself isn't published via sync v1; bump public_version
        // manually so the post-reject delta is unambiguous.
        let writer_uuid = t.ctx.node.read().unwrap().device_uuid;
        t.ctx.node.write().unwrap().owner.bump_version(Scope::Public, writer_uuid);
        let pub_before = t.ctx.node.read().unwrap().owner.public_version;

        let body = format!("id={}", uuid_hex(&id));
        let res = reject_app(body.as_bytes(), &t.ctx);
        assert_eq!(res, None);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        assert!(dev.applications.iter().all(|a| a.id != id),
                "reject should remove the app");
        let pub_after = node.owner.public_version;
        assert_eq!(pub_after.seq, pub_before.seq + 1,
                   "successful publish should bump public_version");
    }

    #[test]
    fn reject_app_unreachable_rolls_back_and_returns_publish_failed() {
        // DG with no writer.
        let t = TestCtx::new();
        let id = seed_approved_app(&t, "doomed");
        let original_alias = "doomed".to_string();

        let body = format!("id={}", uuid_hex(&id));
        let res = reject_app(body.as_bytes(), &t.ctx);
        assert_eq!(res, Some(UI_ERR_PUBLISH_FAILED));

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        let app = dev.applications.iter().find(|a| a.id == id)
            .expect("rollback should restore the app");
        assert_eq!(app.alias, original_alias,
                   "rollback should preserve the original alias");
    }

    #[test]
    fn rename_app_success_publishes_and_returns_none() {
        let t = TestCtx::new();
        promote_local_to_sg(&t, 1);
        let id = seed_approved_app(&t, "old");
        let writer_uuid = t.ctx.node.read().unwrap().device_uuid;
        t.ctx.node.write().unwrap().owner.bump_version(Scope::Public, writer_uuid);
        let pub_before = t.ctx.node.read().unwrap().owner.public_version;

        let body = format!("id={}&alias=new+name", uuid_hex(&id));
        let res = rename_app(body.as_bytes(), &t.ctx);
        assert_eq!(res, None);

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        let app = dev.applications.iter().find(|a| a.id == id).unwrap();
        assert_eq!(app.alias, "new name", "rename should apply the new alias");
        assert_eq!(node.owner.public_version.seq, pub_before.seq + 1,
                   "successful publish should bump public_version");
    }

    #[test]
    fn rename_app_unreachable_rolls_back_and_returns_publish_failed() {
        // DG with no writer.
        let t = TestCtx::new();
        let id = seed_approved_app(&t, "stays");

        let body = format!("id={}&alias=attempted", uuid_hex(&id));
        let res = rename_app(body.as_bytes(), &t.ctx);
        assert_eq!(res, Some(UI_ERR_PUBLISH_FAILED));

        let node = t.ctx.node.read().unwrap();
        let device_uuid = node.device_uuid;
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid).unwrap();
        let app = dev.applications.iter().find(|a| a.id == id).unwrap();
        assert_eq!(app.alias, "stays", "rollback should preserve the original alias");
    }

    #[test]
    fn rename_app_can_rename_peer_own_sg_device_app() {
        // Per the v2 design, any own-user SG can publish a rename for any
        // own-user app — not just apps on the local device. Required by the
        // Stage C scalar-conflict scenario where the rank-2 SG renames the
        // rank-1 SG's app while partitioned.
        let t = TestCtx::new();
        promote_local_to_sg(&t, 1);

        // Add a second own-user SG device with one app on it.
        let peer_uuid = generate_uuid();
        let app_id    = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:   "sg-peer".to_string(),
                uuid:    peer_uuid,
                grade:   DeviceGrade::SG,
                sg_rank: Some(2),
                hosts:   vec!["peer-host:7777".to_string()],
                applications: vec![Application {
                    id:            app_id,
                    alias:         "peer-app".to_string(),
                    protocol:      "udp".to_string(),
                    host:          "127.0.0.1:9001".parse().unwrap(),
                    user_approved: true,
                    token:         generate_uuid(),
                }],
            });
        }

        let body = format!("id={}&alias=renamed", uuid_hex(&app_id));
        let res = rename_app(body.as_bytes(), &t.ctx);
        assert_eq!(res, None);

        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == peer_uuid).unwrap();
        let app = dev.applications.iter().find(|a| a.id == app_id).unwrap();
        assert_eq!(app.alias, "renamed",
                   "rename should apply on the peer SG device's app");
    }

    // ── Partition banner + diagnostics (7c.8b) ──────────────────────────────

    #[test]
    fn partition_banner_empty_with_no_own_sg_peers() {
        let t = TestCtx::new();
        assert!(partition_banner(&t.ctx).is_empty());
    }

    #[test]
    fn partition_banner_empty_when_peer_unpolled() {
        let t = TestCtx::new();
        let peer = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:        "sg-peer".to_string(),
                uuid:         peer,
                grade:        DeviceGrade::SG,
                sg_rank:      Some(2),
                hosts:        vec!["peer-host:7777".to_string()],
                applications: Vec::new(),
            });
        }
        assert!(partition_banner(&t.ctx).is_empty(),
            "an unpolled peer should not falsely trigger the banner");
    }

    #[test]
    fn partition_banner_fires_when_all_peer_hosts_down() {
        let t = TestCtx::new();
        let peer = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:        "sg-peer".to_string(),
                uuid:         peer,
                grade:        DeviceGrade::SG,
                sg_rank:      Some(2),
                hosts:        vec!["peer-host:7777".to_string()],
                applications: Vec::new(),
            });
            node.sg_statuses.insert((peer, "peer-host:7777".to_string()), SgStatus {
                last_rtt: None, up: false, last_polled: Instant::now(),
            });
        }
        let banner = partition_banner(&t.ctx);
        assert!(banner.contains("sg-peer"),
            "banner should name the down peer; got: {banner}");
        assert!(banner.contains("Partition detected"));
    }

    #[test]
    fn partition_banner_silent_when_any_host_up() {
        let t = TestCtx::new();
        let peer = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:        "sg-peer".to_string(),
                uuid:         peer,
                grade:        DeviceGrade::SG,
                sg_rank:      Some(2),
                hosts:        vec!["host-a:7777".to_string(), "host-b:7777".to_string()],
                applications: Vec::new(),
            });
            node.sg_statuses.insert((peer, "host-a:7777".to_string()), SgStatus {
                last_rtt: None, up: false, last_polled: Instant::now(),
            });
            node.sg_statuses.insert((peer, "host-b:7777".to_string()), SgStatus {
                last_rtt: Some(Duration::from_millis(8)), up: true, last_polled: Instant::now(),
            });
        }
        assert!(partition_banner(&t.ctx).is_empty(),
            "peer reachable via any host should not trigger the banner");
    }

    #[test]
    fn render_diagnostics_smoke() {
        let t = TestCtx::new();
        let peer = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:        "sg-peer".to_string(),
                uuid:         peer,
                grade:        DeviceGrade::SG,
                sg_rank:      Some(2),
                hosts:        vec!["peer-host:7777".to_string()],
                applications: Vec::new(),
            });
            let mut wm = HashMap::new();
            wm.insert(peer, SyncVersion { writer_sg_uuid: peer, epoch: 3, seq: 17 });
            node.owner.last_watermarks.insert(peer, wm);
            node.owner.received_merge_proposals.insert(peer, Vec::new());
        }
        let html = render_diagnostics(&t.ctx);
        assert!(html.contains("Diagnostics"));
        assert!(html.contains("Local node"));
        assert!(html.contains("sg-peer"));
        assert!(html.contains("epoch=3"));
        assert!(html.contains("seq=17"));
        assert!(html.contains("Buffered merge proposals"));
    }

    #[test]
    fn rename_app_no_op_when_alias_unchanged() {
        let t = TestCtx::new();
        promote_local_to_sg(&t, 1);
        let id = seed_approved_app(&t, "same");
        let pub_before = t.ctx.node.read().unwrap().owner.public_version;

        let body = format!("id={}&alias=same", uuid_hex(&id));
        let res = rename_app(body.as_bytes(), &t.ctx);
        assert_eq!(res, None);

        // No publish → no version bump, no write_log entry.
        let node = t.ctx.node.read().unwrap();
        assert_eq!(node.owner.public_version, pub_before,
                   "no-op rename must not bump public_version");
        assert!(node.owner.write_log.is_empty(),
                "no-op rename must not append to write_log");
    }

    // ── Write log (7c.2) ────────────────────────────────────────────────────

    #[test]
    fn request_change_local_path_appends_one_write_log_entry() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);

        let change = Change::AddApplication {
            device_uuid: local,
            app_id:      app_uuid(42),
            app_alias:   "logged".into(),
        };
        request_change(change.clone(), &t.ctx).expect("request_change ok");

        let node = t.ctx.node.read().unwrap();
        assert_eq!(node.owner.write_log.len(), 1);
        let entry = &node.owner.write_log[0];
        assert_eq!(entry.scope, Scope::Public);
        assert_eq!(entry.version, node.owner.public_version);
        let roundtripped = deserialize_change(&entry.change_payload)
            .expect("change_payload should be deserializable");
        assert_eq!(roundtripped, change);
    }

    #[test]
    fn sync_write_request_accepted_change_appends_one_write_log_entry() {
        let t = TestCtx::new();
        let (_, dg_conn, _dg_socket) = writer_setup_with_capture(&t);
        let dg_uuid = dg_conn.device_uuid;

        let change = Change::AddApplication {
            device_uuid: dg_uuid,
            app_id:      app_uuid(77),
            app_alias:   "from-dg".into(),
        };
        let payload = serialize_change(&change);
        let pkt = build_encrypted_packet(SYNC_WRITE_REQUEST_OP, &dg_conn, &payload);

        sync_write_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let node = t.ctx.node.read().unwrap();
        assert_eq!(node.owner.write_log.len(), 1);
        let entry = &node.owner.write_log[0];
        assert_eq!(entry.scope, Scope::Public);
        let roundtripped = deserialize_change(&entry.change_payload).expect("parse");
        assert_eq!(roundtripped, change);
    }

    #[test]
    fn sync_write_request_idempotent_retry_does_not_append_duplicate() {
        let t = TestCtx::new();
        let (_, dg_conn, _dg_socket) = writer_setup_with_capture(&t);
        let dg_uuid = dg_conn.device_uuid;

        let change = Change::AddApplication {
            device_uuid: dg_uuid,
            app_id:      app_uuid(7),
            app_alias:   "once".into(),
        };
        let payload = serialize_change(&change);
        let pkt = build_encrypted_packet(SYNC_WRITE_REQUEST_OP, &dg_conn, &payload);

        // First receive: applies, logs.
        sync_write_request("127.0.0.1:1".parse().unwrap(), pkt.clone()[1..].to_vec(), &t.ctx);
        assert_eq!(t.ctx.node.read().unwrap().owner.write_log.len(), 1);

        // Second receive (identical packet): apply_change_locally is a no-op
        // (app id already present), `bumped` is empty, so no log append.
        sync_write_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);
        assert_eq!(t.ctx.node.read().unwrap().owner.write_log.len(), 1,
                   "idempotent retry must not append a duplicate entry");
    }

    #[test]
    fn write_log_retention_prunes_entries_older_than_cutoff() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);

        // Seed an entry well past the retention cutoff.
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.write_log.push(WriteLogEntry {
                version:        SyncVersion::zero(),
                scope:          Scope::Public,
                change_payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
                committed_at:   SystemTime::now()
                    - WRITE_LOG_RETENTION
                    - Duration::from_secs(60),
            });
        }

        // Trigger an append via a real Change — pruning runs there.
        let change = Change::AddApplication {
            device_uuid: local,
            app_id:      app_uuid(1),
            app_alias:   "fresh".into(),
        };
        request_change(change, &t.ctx).expect("request_change ok");

        let node = t.ctx.node.read().unwrap();
        assert_eq!(node.owner.write_log.len(), 1,
                   "stale entry should be pruned, only the fresh one survives");
        assert_ne!(node.owner.write_log[0].change_payload, vec![0xDE, 0xAD, 0xBE, 0xEF],
                   "the surviving entry must be the freshly appended one");
    }

    // ── Watermark probe (7c.3) ──────────────────────────────────────────────

    /// Decrypt a probe-response packet captured on the peer side and parse
    /// it into (scope, writer-map).
    fn decode_probe_response(buf: &[u8], peer_conn: &ActiveConnection)
        -> (Scope, Vec<(Uuid, SyncVersion)>)
    {
        let mut node = super::super::data_models::Node::new();
        node.owner.active_connections.insert(peer_conn.id, ActiveConnection {
            id: peer_conn.id, timeout: peer_conn.timeout,
            key_pair: peer_conn.key_pair.clone(),
            peer_public_key: peer_conn.peer_public_key,
            peer_active_connection_id: peer_conn.peer_active_connection_id,
            device_uuid: peer_conn.device_uuid,
            peer_addr: peer_conn.peer_addr,
        });
        let plaintext = decrypt_packet_body(&node, &buf[1..]).expect("decrypt");
        parse_watermark_map(&plaintext).expect("parse")
    }

    #[test]
    fn watermark_probe_request_replies_with_empty_map_when_log_is_empty() {
        let t = TestCtx::new();
        let (_, dg_conn, dg_socket) = writer_setup_with_capture(&t);
        // A watermark probe is an SG↔SG message: make the peer an own-user SG.
        promote_peer_to_sg(&t, dg_conn.device_uuid, 2);

        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        let pkt = build_encrypted_packet(WATERMARK_PROBE_REQUEST_OP, &dg_conn, &body);
        watermark_probe_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut rx = [0u8; 2048];
        let (len, _) = dg_socket.recv_from(&mut rx).expect("response expected");
        assert_eq!(rx[0], WATERMARK_PROBE_RESPONSE_OP);
        let (scope, map) = decode_probe_response(&rx[..len], &dg_conn);
        assert_eq!(scope, Scope::Public);
        assert!(map.is_empty(), "empty write log → empty watermark map");
    }

    #[test]
    fn watermark_probe_request_reports_max_per_writer_in_log() {
        let t = TestCtx::new();
        let (_, dg_conn, dg_socket) = writer_setup_with_capture(&t);
        // A watermark probe is an SG↔SG message: make the peer an own-user SG.
        promote_peer_to_sg(&t, dg_conn.device_uuid, 2);

        // Seed two writers into the local write log.
        let w1: Uuid = [0x11; 16];
        let w2: Uuid = [0x22; 16];
        {
            let mut node = t.ctx.node.write().unwrap();
            // w1: bumps up to (epoch 1, seq 5)
            for seq in 1..=5u64 {
                node.owner.write_log.push(WriteLogEntry {
                    version: SyncVersion { writer_sg_uuid: w1, epoch: 1, seq },
                    scope:   Scope::Public,
                    change_payload: vec![],
                    committed_at: SystemTime::now(),
                });
            }
            // w2: a single (epoch 3, seq 7)
            node.owner.write_log.push(WriteLogEntry {
                version: SyncVersion { writer_sg_uuid: w2, epoch: 3, seq: 7 },
                scope:   Scope::Public,
                change_payload: vec![],
                committed_at: SystemTime::now(),
            });
            // A Private-scope entry that must be ignored for a Public probe.
            node.owner.write_log.push(WriteLogEntry {
                version: SyncVersion { writer_sg_uuid: w1, epoch: 99, seq: 99 },
                scope:   Scope::Private,
                change_payload: vec![],
                committed_at: SystemTime::now(),
            });
        }

        let mut body = Vec::new();
        write_scope(&mut body, Scope::Public);
        let pkt = build_encrypted_packet(WATERMARK_PROBE_REQUEST_OP, &dg_conn, &body);
        watermark_probe_request("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut rx = [0u8; 2048];
        let (len, _) = dg_socket.recv_from(&mut rx).expect("response expected");
        let (scope, map) = decode_probe_response(&rx[..len], &dg_conn);
        assert_eq!(scope, Scope::Public);
        assert_eq!(map.len(), 2);
        let v1 = map.iter().find(|(w, _)| *w == w1).expect("w1 present").1;
        let v2 = map.iter().find(|(w, _)| *w == w2).expect("w2 present").1;
        assert_eq!((v1.epoch, v1.seq), (1, 5),
                   "w1 should be the max of its in-log entries");
        assert_eq!((v2.epoch, v2.seq), (3, 7));
    }

    /// Regression: a DG must never initiate partition reconciliation, even
    /// against its own SG. Before the fix, the reconcile kickoff only checked
    /// the peer's grade, so a DG probed its own SG and got a `malformed` merge
    /// ack once per tick, forever.
    #[test]
    fn dg_does_not_initiate_partition_reconcile_against_own_sg() {
        let t = TestCtx::new();
        // Local device stays a DG (Node::new default).
        let sg_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sg_sock.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let own_sg_uuid = generate_uuid();
        let conn_id = 7u16;
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:        "own-sg".to_string(),
                uuid:         own_sg_uuid,
                grade:        DeviceGrade::SG,
                sg_rank:      Some(1),
                hosts:        vec!["127.0.0.1:7777".into()],
                applications: Vec::new(),
            });
            node.owner.active_connections.insert(conn_id, ActiveConnection {
                id: conn_id,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: generate_x25519_keypair(),
                peer_public_key: X25519PublicKey(generate_key_bytes()),
                peer_active_connection_id: 1,
                device_uuid: own_sg_uuid,
                peer_addr: sg_sock.local_addr().unwrap(),
            });
        }

        // Neither the on-reconnect kickoff nor the periodic tick may emit a probe.
        partition_reconcile_on_reconnect(conn_id, &t.ctx);
        partition_reconcile_tick(&t.ctx);

        let mut rx = [0u8; 64];
        assert!(sg_sock.recv_from(&mut rx).is_err(),
                "a DG must not send a watermark probe to its own SG");
    }

    #[test]
    fn watermark_probe_response_stores_per_writer_min_in_last_watermarks() {
        let t = TestCtx::new();
        let (_, dg_conn, _) = writer_setup_with_capture(&t);
        let peer_uuid = dg_conn.device_uuid;

        // Seed our log: w1 → (1, 10), w3 → (2, 3).
        let w1: Uuid = [0x11; 16];
        let w2: Uuid = [0x22; 16];
        let w3: Uuid = [0x33; 16];
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.write_log.push(WriteLogEntry {
                version: SyncVersion { writer_sg_uuid: w1, epoch: 1, seq: 10 },
                scope:   Scope::Public, change_payload: vec![],
                committed_at: SystemTime::now(),
            });
            node.owner.write_log.push(WriteLogEntry {
                version: SyncVersion { writer_sg_uuid: w3, epoch: 2, seq: 3 },
                scope:   Scope::Public, change_payload: vec![],
                committed_at: SystemTime::now(),
            });
        }

        // Peer reports: w1 → (1, 4)  [lower, we win],
        //                w2 → (5, 1) [peer-only, our implicit 0 means merged = (0,0)],
        //                w3 → (2, 9) [higher, peer wins].
        // Also seed a w4 in OUR log only — peer's implicit 0 means merged
        // should be (0,0) so our subsequent merge proposal ships all our w4
        // entries (the bilateral-mutation case that 7c.8c exercises).
        let w4: Uuid = [0x44; 16];
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.write_log.push(WriteLogEntry {
                version: SyncVersion { writer_sg_uuid: w4, epoch: 7, seq: 1 },
                scope:   Scope::Public, change_payload: vec![],
                committed_at: SystemTime::now(),
            });
        }
        let peer_map: Vec<(Uuid, SyncVersion)> = vec![
            (w1, SyncVersion { writer_sg_uuid: w1, epoch: 1, seq: 4 }),
            (w2, SyncVersion { writer_sg_uuid: w2, epoch: 5, seq: 1 }),
            (w3, SyncVersion { writer_sg_uuid: w3, epoch: 2, seq: 9 }),
        ];
        let body = serialize_watermark_map(Scope::Public, &peer_map);
        let pkt = build_encrypted_packet(WATERMARK_PROBE_RESPONSE_OP, &dg_conn, &body);
        watermark_probe_response("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let node = t.ctx.node.read().unwrap();
        let stored = node.owner.last_watermarks.get(&peer_uuid)
            .expect("entry for peer");
        // w1: min((1,10), (1,4)) = (1,4)
        assert_eq!((stored[&w1].epoch, stored[&w1].seq), (1, 4));
        // w2: peer-only — our implicit 0 → merged is (0,0)
        assert_eq!((stored[&w2].epoch, stored[&w2].seq), (0, 0));
        // w3: min((2,3), (2,9)) = (2,3)
        assert_eq!((stored[&w3].epoch, stored[&w3].seq), (2, 3));
        // w4: ours-only — peer's implicit 0 → merged is (0,0) so we ship our entries.
        assert_eq!((stored[&w4].epoch, stored[&w4].seq), (0, 0));
    }

    // ── Merge proposal exchange (7c.4) ──────────────────────────────────────

    fn sample_entry(writer: Uuid, epoch: u32, seq: u64, payload: &[u8]) -> WriteLogEntry {
        WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: writer, epoch, seq },
            scope:   Scope::Public,
            change_payload: payload.to_vec(),
            committed_at: SystemTime::now(),
        }
    }

    #[test]
    fn merge_proposal_body_roundtrips() {
        let sender_v = SyncVersion { writer_sg_uuid: [0xAA; 16], epoch: 2, seq: 17 };
        let entries = vec![
            sample_entry([0x11; 16], 1, 4, &[0xCA, 0xFE]),
            sample_entry([0x22; 16], 3, 9, b"hello"),
        ];
        let body = build_merge_proposal_body(Scope::Public, sender_v, &entries);
        let (scope, sender, parsed) =
            parse_merge_proposal_body(&body).expect("parse");
        assert_eq!(scope, Scope::Public);
        assert_eq!(sender, sender_v);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].version, entries[0].version);
        assert_eq!(parsed[0].change_payload, entries[0].change_payload);
        assert_eq!(parsed[1].version, entries[1].version);
        assert_eq!(parsed[1].change_payload, entries[1].change_payload);
    }

    #[test]
    fn merge_ack_body_roundtrips() {
        let v = SyncVersion { writer_sg_uuid: [0xBB; 16], epoch: 7, seq: 42 };
        let body = build_merge_ack_body(Scope::Public, v, MERGE_ACK_RESULT_APPLIED);
        let (scope, parsed_v, result) = parse_merge_ack_body(&body).expect("parse");
        assert_eq!(scope, Scope::Public);
        assert_eq!(parsed_v, v);
        assert_eq!(result, MERGE_ACK_RESULT_APPLIED);
    }

    /// Promote the connected peer (set up as DG by `writer_setup_with_capture`)
    /// to SG with `rank`, so it satisfies `is_own_user_sg` for 7c.6 tests.
    fn promote_peer_to_sg(t: &TestCtx, peer_uuid: Uuid, rank: u32) {
        let mut node = t.ctx.node.write().unwrap();
        if let Some(d) = node.owner.user.devices.iter_mut().find(|d| d.uuid == peer_uuid) {
            d.grade   = DeviceGrade::SG;
            d.sg_rank = Some(rank);
        }
    }

    #[test]
    fn merge_proposal_rejects_non_own_user_sg_peer() {
        // Peer is set up as a DG. The 7c.6 handler must refuse to merge and
        // ack `malformed`.
        let t = TestCtx::new();
        let (_, dg_conn, dg_socket) = writer_setup_with_capture(&t);

        let body = build_merge_proposal_body(
            Scope::Public,
            SyncVersion { writer_sg_uuid: [0x11; 16], epoch: 1, seq: 1 },
            &[],
        );
        let pkt = build_encrypted_packet(MERGE_PROPOSAL_OP, &dg_conn, &body);
        merge_proposal("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let mut buf = [0u8; 1024];
        let (len, _) = dg_socket.recv_from(&mut buf).expect("ack received");
        assert_eq!(buf[0], MERGE_ACK_OP);
        let plaintext = decrypt_packet_body_for(&dg_conn, &buf[1..len]);
        let (_, _, result) = parse_merge_ack_body(&plaintext).expect("parse");
        assert_eq!(result, MERGE_ACK_RESULT_MALFORMED);
    }

    #[test]
    fn merge_proposal_applies_changes_appends_log_bumps_version_and_acks() {
        let t = TestCtx::new();
        let (_, peer_conn, peer_socket) = writer_setup_with_capture(&t);
        let peer_uuid = peer_conn.device_uuid;
        promote_peer_to_sg(&t, peer_uuid, 2);  // local stays rank 1.

        let peer_writer = [0xC0; 16];
        let added_device = [0xDE; 16];
        let added_app    = app_uuid(909);

        let entries = vec![
            change_entry(peer_writer, 1, 1, &Change::AddDevice {
                uuid: added_device, alias: "peer-dev".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
            }),
            change_entry(peer_writer, 1, 2, &Change::AddApplication {
                device_uuid: added_device,
                app_id:      added_app,
                app_alias:   "remote-app".into(),
            }),
        ];

        let pre_pub = t.ctx.node.read().unwrap().owner.public_version;

        let body = build_merge_proposal_body(
            Scope::Public,
            SyncVersion { writer_sg_uuid: peer_writer, epoch: 1, seq: 2 },
            &entries,
        );
        let pkt = build_encrypted_packet(MERGE_PROPOSAL_OP, &peer_conn, &body);
        merge_proposal("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        // State + log + version all moved.
        let node = t.ctx.node.read().unwrap();
        assert!(node.owner.user.devices.iter().any(|d| d.uuid == added_device),
                "AddDevice applied");
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == added_device).unwrap();
        assert!(dev.applications.iter().any(|a| a.id == added_app && a.alias == "remote-app"),
                "AddApplication applied");
        assert_eq!(node.owner.write_log.len(), 2, "both peer entries appended");
        assert!(
            node.owner.public_version != pre_pub,
            "public_version bumped after merge",
        );
        drop(node);

        // MergeAck back to peer. (The merge also triggers notify_own_peers,
        // which sends a SyncUpdateAvailable to this same peer because we
        // promoted it to an own-user SG — drain until we find the ack.)
        let ack_payload = recv_until_op(&peer_socket, MERGE_ACK_OP);
        let plaintext = decrypt_packet_body_for(&peer_conn, &ack_payload);
        let (scope, _wm, result) = parse_merge_ack_body(&plaintext).expect("parse");
        assert_eq!(scope, Scope::Public);
        assert_eq!(result, MERGE_ACK_RESULT_APPLIED);
    }

    /// Gap #2 end-to-end: a contact the writer SG logged as an `UpsertContact`
    /// reaches a non-writer own SG through the merge channel. The receiver must
    /// gain the contact in `contact_users` with its public_key and cached apps,
    /// so it can validate that contact's later connect_requests.
    #[test]
    fn merge_proposal_upsert_contact_reaches_non_writer_sg() {
        let t = TestCtx::new();
        let (_, peer_conn, _peer_socket) = writer_setup_with_capture(&t);
        let peer_uuid = peer_conn.device_uuid;
        promote_peer_to_sg(&t, peer_uuid, 2);  // the proposing peer is a rank-2 own SG.

        // The contact as the writer logged it: identity + one device carrying apps.
        let writer        = [0xC0; 16];
        let contact_uuid  = [0xCA; 16];
        let contact_pk    = Ed25519PublicKey([0x77; 32]);
        let contact_dev   = [0xDE; 16];
        let contact_app   = app_uuid(909);
        let card = ContactDeviceCard {
            uuid:    contact_dev,
            alias:   "chad-phone".into(),
            grade:   DeviceGrade::DG,
            sg_rank: None,
            hosts:   vec![],
            apps:    vec![(contact_app, "chess".into())],
        };
        let entries = vec![change_entry(writer, 1, 1, &Change::UpsertContact {
            uuid:       contact_uuid,
            alias:      "chad".into(),
            public_key: contact_pk,
            devices:    vec![card],
        })];

        // Receiver has no such contact yet.
        assert!(t.ctx.node.read().unwrap().owner.contact_users.is_empty());

        let body = build_merge_proposal_body(
            Scope::Public,
            SyncVersion { writer_sg_uuid: writer, epoch: 1, seq: 1 },
            &entries,
        );
        let pkt = build_encrypted_packet(MERGE_PROPOSAL_OP, &peer_conn, &body);
        merge_proposal("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let node = t.ctx.node.read().unwrap();
        let contact = node.owner.contact_users.iter()
            .find(|c| c.user.uuid == contact_uuid)
            .expect("UpsertContact must have created the contact via merge");
        assert_eq!(contact.user.alias, "chad");
        assert_eq!(contact.public_key, contact_pk,
            "public_key must propagate so connect_requests validate (Gap #2)");
        let dev = contact.user.devices.iter()
            .find(|d| d.uuid == contact_dev)
            .expect("contact device must propagate");
        assert!(dev.applications.iter().any(|a| a.id == contact_app && a.alias == "chess"),
            "cached contact apps must propagate");
        // The peer's entry is recorded so this SG fans the contact onward.
        assert_eq!(upsert_contact_log_count(&node), 1);
    }

    #[test]
    fn merge_proposal_no_op_when_peer_entries_already_known() {
        // We already have all peer entries in our log; merge is a no-op for
        // state. Version must NOT bump (no actual state change), but the
        // ack still reports `applied`.
        let t = TestCtx::new();
        let (_, peer_conn, peer_socket) = writer_setup_with_capture(&t);
        let peer_uuid = peer_conn.device_uuid;
        promote_peer_to_sg(&t, peer_uuid, 2);

        let peer_writer = [0xC1; 16];
        // Pre-seed local with the same entry the peer will propose.
        let local_uuid = t.ctx.node.read().unwrap().device_uuid;
        let entry = change_entry(peer_writer, 1, 1, &Change::AddDevice {
            uuid: [0xAB; 16], alias: "already-known".into(),
            grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
        });
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.write_log.push(entry.clone());
            node.owner.user.devices.push(Device {
                uuid: [0xAB; 16], alias: "already-known".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
                applications: Vec::new(),
            });
        }
        let pre_pub = t.ctx.node.read().unwrap().owner.public_version;

        let body = build_merge_proposal_body(
            Scope::Public,
            SyncVersion { writer_sg_uuid: peer_writer, epoch: 1, seq: 1 },
            &[entry],
        );
        let pkt = build_encrypted_packet(MERGE_PROPOSAL_OP, &peer_conn, &body);
        merge_proposal("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let node = t.ctx.node.read().unwrap();
        assert_eq!(node.owner.public_version, pre_pub,
                   "no state change → no version bump");
        // No new log entry — peer's was a duplicate of ours by version key.
        assert_eq!(node.owner.write_log.len(), 1);
        drop(node);

        // Still acks applied (nothing failed; nothing needed doing).
        let mut buf = [0u8; 1024];
        let (len, _) = peer_socket.recv_from(&mut buf).expect("ack received");
        assert_eq!(buf[0], MERGE_ACK_OP);
        let plaintext = decrypt_packet_body_for(&peer_conn, &buf[1..len]);
        let (_, _, result) = parse_merge_ack_body(&plaintext).expect("parse");
        assert_eq!(result, MERGE_ACK_RESULT_APPLIED);
        let _ = local_uuid; // silence unused warning if any
    }

    #[test]
    fn merge_bump_stamps_elected_rank1_writer_not_local() {
        // Gap 2 (writer-identity pollution): a rank-2 SG (zeus, local) that
        // self-elected and wrote during a partition heals against its rank-1
        // SG (golden, the reachable peer). When zeus applies golden's merge,
        // the resulting head must be stamped under golden (the elected rank-1
        // writer), NOT under zeus — otherwise both survivors claim writer and
        // routing disagrees until the next poll. Pre-fix this asserted local.
        let t = TestCtx::new();
        let (_, peer_conn, _peer_socket) = writer_setup_with_capture(&t);
        let golden_uuid = peer_conn.device_uuid;     // reachable peer (active conn)
        promote_local_to_sg(&t, 2);                  // zeus, rank 2
        promote_peer_to_sg(&t, golden_uuid, 1);      // golden, rank 1
        let local_uuid = t.ctx.node.read().unwrap().device_uuid;
        {
            // Simulate zeus having self-elected + written during the partition:
            // its head currently points at itself.
            let mut node = t.ctx.node.write().unwrap();
            node.owner.public_version =
                SyncVersion { writer_sg_uuid: local_uuid, epoch: 2, seq: 3 };
        }

        // golden proposes a state-changing entry under its own writer uuid.
        let added_device = [0xDE; 16];
        let entries = vec![change_entry(golden_uuid, 1, 1, &Change::AddDevice {
            uuid: added_device, alias: "golden-dev".into(),
            grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
        })];
        let body = build_merge_proposal_body(
            Scope::Public,
            SyncVersion { writer_sg_uuid: golden_uuid, epoch: 1, seq: 1 },
            &entries,
        );
        let pkt = build_encrypted_packet(MERGE_PROPOSAL_OP, &peer_conn, &body);
        merge_proposal("127.0.0.1:1".parse().unwrap(), pkt[1..].to_vec(), &t.ctx);

        let node = t.ctx.node.read().unwrap();
        assert!(node.owner.user.devices.iter().any(|d| d.uuid == added_device),
            "merge applied golden's change");
        assert_eq!(node.owner.public_version.writer_sg_uuid, golden_uuid,
            "head must be stamped under the elected rank-1 writer (golden), not local");
        assert_ne!(node.owner.public_version.writer_sg_uuid, local_uuid,
            "must no longer claim self as writer after healing to a rank-1 SG");
    }

    #[test]
    fn partition_reconcile_tick_probes_only_own_user_sg_peers() {
        // Peer set up as DG → no probe should fire.
        let t = TestCtx::new();
        let (_, peer_conn, peer_socket) = writer_setup_with_capture(&t);
        partition_reconcile_tick(&t.ctx);
        let mut buf = [0u8; 1024];
        let dg_recv = peer_socket.recv_from(&mut buf);
        assert!(dg_recv.is_err(),
                "DG peer must not receive a watermark probe; got {dg_recv:?}");

        // Promote to own-user SG and tick again — should now receive 0x7A.
        promote_peer_to_sg(&t, peer_conn.device_uuid, 2);
        partition_reconcile_tick(&t.ctx);
        let (len, _) = peer_socket.recv_from(&mut buf).expect("probe sent");
        assert!(len >= 1);
        assert_eq!(buf[0], WATERMARK_PROBE_REQUEST_OP);
    }

    #[test]
    fn request_change_rank2_sg_self_elects_via_on_demand_probe_during_partition() {
        // P5 lost-write bug: a rank-2 SG (zeus) whose rank-1 writer (golden)
        // is partitioned away but NOT yet polled-down must still be able to
        // write. `find_writer_sg` alone returns Unreachable (no status yet);
        // the write path's on-demand probe re-polls (golden's ping to a dead
        // host times out / refuses → recorded down), then re-elects zeus. The
        // change applies, bumps under zeus's own uuid, and lands in the write
        // log so partition reconciliation can propose it back to golden on heal.
        let t = TestCtx::new();
        let local_uuid = promote_local_to_sg(&t, 2);
        let app_id = app_uuid(77);
        // golden: rank-1, partitioned (no conn), and unpolled (no sg_status).
        // Its advertised host has no listener, so the on-demand ping fails.
        let golden = add_peer_sg(&t, 1, /*conn*/ false, /*polled_up*/ None);
        {
            let mut node = t.ctx.node.write().unwrap();
            let dev = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == local_uuid).unwrap();
            dev.applications.push(Application {
                id: app_id, alias: "before".into(), protocol: "udp".into(),
                host: "127.0.0.1:7001".parse().unwrap(),
                user_approved: true, token: [0u8; 16],
            });
            // Pre-partition, the network told us golden was the writer.
            node.owner.public_version =
                SyncVersion { writer_sg_uuid: golden, epoch: 1, seq: 5 };
        }

        request_change(Change::UpdateApplicationAlias {
            device_uuid: local_uuid, app_id, new_alias: "after".into(),
        }, &t.ctx).expect("rank-2 SG should self-elect via probe and accept the write");

        let node = t.ctx.node.read().unwrap();
        assert_eq!(node.owner.public_version.writer_sg_uuid, local_uuid,
            "write must be stamped under the self-elected writer");
        assert_eq!(node.owner.write_log.len(), 1, "self-write must be logged");
        assert_eq!(node.owner.write_log[0].version.writer_sg_uuid, local_uuid,
            "log entry under own uuid so heal can propose it to the rank-1 SG");
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == local_uuid).unwrap();
        assert_eq!(dev.applications[0].alias, "after", "rename applied locally");
    }

    /// Drain packets from `socket` until one with op byte == `wanted_op` is
    /// seen, returning the payload after the op byte. Used by tests that
    /// expect a specific reply when prior fan-outs (e.g. SyncUpdateAvailable)
    /// land on the same socket first.
    fn recv_until_op(socket: &UdpSocket, wanted_op: u8) -> Vec<u8> {
        let mut buf = [0u8; 2048];
        for _ in 0..16 {
            let (len, _) = socket.recv_from(&mut buf).expect("recv");
            if buf[0] == wanted_op {
                return buf[1..len].to_vec();
            }
        }
        panic!("did not see op byte {wanted_op:#04x} after 16 packets");
    }

    /// Decrypt a packet body using a peer-side ActiveConnection. Mirrors
    /// `parse_write_ack`'s pattern.
    fn decrypt_packet_body_for(conn: &ActiveConnection, buf: &[u8]) -> Vec<u8> {
        let mut node = super::super::data_models::Node::new();
        node.owner.active_connections.insert(conn.id, ActiveConnection {
            id: conn.id,
            timeout: conn.timeout,
            key_pair: conn.key_pair.clone(),
            peer_public_key: conn.peer_public_key,
            peer_active_connection_id: conn.peer_active_connection_id,
            device_uuid: conn.device_uuid,
            peer_addr: conn.peer_addr,
        });
        decrypt_packet_body(&node, buf).expect("decrypt")
    }

    #[test]
    fn build_merge_proposal_for_peer_filters_against_last_watermarks() {
        // Seed our log with two writers and three entries. Peer's watermark
        // map: w1 → (1, 1) [we ship anything strictly above], w2 absent
        // [ship everything for w2].
        let t = TestCtx::new();
        let (_, dg_conn, _) = writer_setup_with_capture(&t);
        let peer_uuid = dg_conn.device_uuid;
        let w1: Uuid = [0x11; 16];
        let w2: Uuid = [0x22; 16];
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.write_log.extend([
                sample_entry(w1, 1, 1, &[0xAA]),  // == watermark → filtered out
                sample_entry(w1, 1, 2, &[0xBB]),  // >  watermark → shipped
                sample_entry(w2, 5, 1, &[0xCC]),  // no watermark → shipped
            ]);
            let mut wm = HashMap::new();
            wm.insert(w1, SyncVersion { writer_sg_uuid: w1, epoch: 1, seq: 1 });
            node.owner.last_watermarks.insert(peer_uuid, wm);
        }

        let (_sender_v, entries) =
            build_merge_proposal_for_peer(peer_uuid, Scope::Public, &t.ctx);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.change_payload == vec![0xBB]),
                "(w1, 1, 2) must be shipped");
        assert!(entries.iter().any(|e| e.change_payload == vec![0xCC]),
                "(w2, 5, 1) must be shipped (no watermark for w2)");
        assert!(entries.iter().all(|e| e.change_payload != vec![0xAA]),
                "(w1, 1, 1) must be filtered out — equal to watermark");
    }

    // ── Merge engine (7c.5) ──────────────────────────────────────────────────

    fn change_entry(writer: Uuid, epoch: u32, seq: u64, change: &Change) -> WriteLogEntry {
        WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: writer, epoch, seq },
            scope:   Scope::Public,
            change_payload: serialize_change(change),
            committed_at: SystemTime::now(),
        }
    }

    fn merge_writer_a() -> Uuid { [0xA1; 16] }
    fn merge_writer_b() -> Uuid { [0xB2; 16] }
    fn merge_dev_a()    -> Uuid { [0xD0; 16] }
    fn merge_dev_b()    -> Uuid { [0xD1; 16] }

    #[test]
    fn merge_logs_empty_inputs_produce_nothing() {
        let ranks = HashMap::new();
        let out = merge_logs(&[], &[], &ranks);
        assert!(out.new_entries.is_empty());
        assert!(out.changes_to_apply.is_empty());
    }

    #[test]
    fn merge_logs_idempotent_when_peer_already_in_local() {
        let wa = merge_writer_a();
        let entry = change_entry(wa, 1, 1, &Change::AddDevice {
            uuid:    merge_dev_a(),
            alias:   "phone".into(),
            grade:   DeviceGrade::DG,
            sg_rank: None,
            hosts:   Vec::new(),
        });
        let local = vec![entry.clone()];
        let peer  = vec![entry];
        let ranks = HashMap::new();
        let out = merge_logs(&local, &peer, &ranks);
        assert!(out.new_entries.is_empty(),
                "peer entry already present locally — no new entries");
        assert!(out.changes_to_apply.is_empty());
    }

    #[test]
    fn merge_logs_unions_adds_from_both_sides() {
        let wa = merge_writer_a();
        let wb = merge_writer_b();
        let local = vec![change_entry(wa, 1, 1, &Change::AddDevice {
            uuid: merge_dev_a(), alias: "a".into(),
            grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
        })];
        let peer = vec![change_entry(wb, 1, 1, &Change::AddDevice {
            uuid: merge_dev_b(), alias: "b".into(),
            grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
        })];
        let ranks = HashMap::new();
        let out = merge_logs(&local, &peer, &ranks);
        assert_eq!(out.new_entries.len(), 1);
        assert_eq!(out.changes_to_apply.len(), 1);
        assert!(matches!(out.changes_to_apply[0],
            Change::AddDevice { ref alias, .. } if alias == "b"));
    }

    #[test]
    fn merge_logs_peer_tombstone_removes_local_app() {
        let wa = merge_writer_a();
        let wb = merge_writer_b();
        let app = app_uuid(101);
        let local = vec![
            change_entry(wa, 1, 1, &Change::AddDevice {
                uuid: merge_dev_a(), alias: "phone".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
            }),
            change_entry(wa, 1, 2, &Change::AddApplication {
                device_uuid: merge_dev_a(),
                app_id:      app,
                app_alias:   "chess".into(),
            }),
        ];
        let peer = vec![change_entry(wb, 5, 1, &Change::RemoveApplication {
            device_uuid: merge_dev_a(),
            app_id:      app,
        })];
        let ranks = HashMap::new();
        let out = merge_logs(&local, &peer, &ranks);
        assert_eq!(out.new_entries.len(), 1);
        assert_eq!(out.changes_to_apply, vec![Change::RemoveApplication {
            device_uuid: merge_dev_a(),
            app_id:      app,
        }]);
    }

    #[test]
    fn merge_logs_local_tombstone_keeps_peer_add_from_winning() {
        // Mirror case: we have the Remove, peer proposes a (later by epoch/seq)
        // Add. UUID-based ids make the Add for an already-removed id a
        // protocol-violation, but the design still mandates "tombstone wins" —
        // verify we don't resurrect the app.
        let wa = merge_writer_a();
        let wb = merge_writer_b();
        let app = app_uuid(202);
        let local = vec![
            change_entry(wa, 1, 1, &Change::AddDevice {
                uuid: merge_dev_a(), alias: "phone".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
            }),
            change_entry(wa, 1, 2, &Change::AddApplication {
                device_uuid: merge_dev_a(), app_id: app,
                app_alias: "chess".into(),
            }),
            change_entry(wa, 1, 3, &Change::RemoveApplication {
                device_uuid: merge_dev_a(), app_id: app,
            }),
        ];
        let peer = vec![change_entry(wb, 9, 9, &Change::AddApplication {
            device_uuid: merge_dev_a(), app_id: app,
            app_alias: "resurrected".into(),
        })];
        let ranks = HashMap::new();
        let out = merge_logs(&local, &peer, &ranks);
        assert_eq!(out.new_entries.len(), 1, "peer entry recorded in log");
        assert!(out.changes_to_apply.is_empty(),
                "tombstone wins — peer Add must not be applied");
    }

    #[test]
    fn merge_logs_scalar_update_higher_rank_update_wins_over_lower_rank_update() {
        let wa = merge_writer_a();   // rank 1 — top
        let wb = merge_writer_b();   // rank 2
        let app = app_uuid(303);
        // Local: rank-1 writer added the app, then renamed to "ours" via
        // Update. Both Add and Update are from rank-1.
        let local = vec![
            change_entry(wa, 1, 1, &Change::AddDevice {
                uuid: merge_dev_a(), alias: "phone".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
            }),
            change_entry(wa, 1, 2, &Change::AddApplication {
                device_uuid: merge_dev_a(), app_id: app,
                app_alias: "initial".into(),
            }),
            change_entry(wa, 1, 3, &Change::UpdateApplicationAlias {
                device_uuid: merge_dev_a(), app_id: app,
                new_alias: "ours".into(),
            }),
        ];
        // Peer: rank-2 writer ran an Update at "later" (epoch, seq) but
        // lower rank. Among Updates, higher rank wins → "ours" stays.
        let peer = vec![change_entry(wb, 9, 9, &Change::UpdateApplicationAlias {
            device_uuid: merge_dev_a(), app_id: app,
            new_alias: "theirs".into(),
        })];
        let mut ranks = HashMap::new();
        ranks.insert(wa, 1);
        ranks.insert(wb, 2);
        let out = merge_logs(&local, &peer, &ranks);
        assert_eq!(out.new_entries.len(), 1, "peer entry recorded");
        assert!(out.changes_to_apply.is_empty(),
                "higher-rank Update wins over lower-rank Update; no local state change");
    }

    #[test]
    fn merge_logs_update_beats_add_regardless_of_rank() {
        // Bilateral partition recovery case: local high-rank writer Added
        // the app pre-partition; peer low-rank writer Updated the alias
        // during partition. The Update is the explicit alias change and
        // must beat the Add's incidental alias regardless of rank.
        let wa = merge_writer_a();   // rank 1 — top, did the Add
        let wb = merge_writer_b();   // rank 2, did the Update
        let app = app_uuid(909);
        let local = vec![
            change_entry(wa, 1, 1, &Change::AddDevice {
                uuid: merge_dev_a(), alias: "phone".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
            }),
            change_entry(wa, 1, 2, &Change::AddApplication {
                device_uuid: merge_dev_a(), app_id: app,
                app_alias: "initial".into(),
            }),
        ];
        let peer = vec![change_entry(wb, 2, 1, &Change::UpdateApplicationAlias {
            device_uuid: merge_dev_a(), app_id: app,
            new_alias: "renamed".into(),
        })];
        let mut ranks = HashMap::new();
        ranks.insert(wa, 1);
        ranks.insert(wb, 2);
        let out = merge_logs(&local, &peer, &ranks);
        assert_eq!(out.changes_to_apply, vec![Change::UpdateApplicationAlias {
            device_uuid: merge_dev_a(), app_id: app,
            new_alias: "renamed".into(),
        }]);
    }

    #[test]
    fn merge_logs_scalar_update_lower_rank_local_loses() {
        let wa = merge_writer_a();   // rank 2
        let wb = merge_writer_b();   // rank 1 — top
        let app = app_uuid(404);
        let local = vec![
            change_entry(wa, 5, 5, &Change::AddDevice {
                uuid: merge_dev_a(), alias: "phone".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
            }),
            change_entry(wa, 5, 6, &Change::AddApplication {
                device_uuid: merge_dev_a(), app_id: app,
                app_alias: "ours".into(),
            }),
        ];
        let peer = vec![change_entry(wb, 1, 1, &Change::UpdateApplicationAlias {
            device_uuid: merge_dev_a(), app_id: app,
            new_alias: "theirs".into(),
        })];
        let mut ranks = HashMap::new();
        ranks.insert(wa, 2);
        ranks.insert(wb, 1);
        let out = merge_logs(&local, &peer, &ranks);
        assert_eq!(out.new_entries.len(), 1);
        assert_eq!(out.changes_to_apply, vec![Change::UpdateApplicationAlias {
            device_uuid: merge_dev_a(), app_id: app,
            new_alias: "theirs".into(),
        }]);
    }

    #[test]
    fn merge_logs_scalar_update_same_rank_higher_version_wins() {
        let wa = merge_writer_a();
        let wb = merge_writer_b();
        let app = app_uuid(505);
        let local = vec![
            change_entry(wa, 1, 1, &Change::AddDevice {
                uuid: merge_dev_a(), alias: "phone".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
            }),
            change_entry(wa, 1, 2, &Change::AddApplication {
                device_uuid: merge_dev_a(), app_id: app,
                app_alias: "v1".into(),
            }),
            change_entry(wa, 1, 3, &Change::UpdateApplicationAlias {
                device_uuid: merge_dev_a(), app_id: app,
                new_alias: "v2-local".into(),
            }),
        ];
        // Same rank, but peer's update has higher (epoch, seq).
        let peer = vec![change_entry(wb, 1, 4, &Change::UpdateApplicationAlias {
            device_uuid: merge_dev_a(), app_id: app,
            new_alias: "v3-peer".into(),
        })];
        let mut ranks = HashMap::new();
        ranks.insert(wa, 1);
        ranks.insert(wb, 1);
        let out = merge_logs(&local, &peer, &ranks);
        assert_eq!(out.changes_to_apply, vec![Change::UpdateApplicationAlias {
            device_uuid: merge_dev_a(), app_id: app,
            new_alias: "v3-peer".into(),
        }]);
    }

    #[test]
    fn merge_logs_collapses_peer_add_then_update_into_single_add() {
        // Brand-new device + app + rename on peer side; we have none of it.
        // Diff should emit AddDevice, then AddApplication with the final
        // (post-rename) alias — not Add + separate Update.
        let wb = merge_writer_b();
        let app = app_uuid(606);
        let local = Vec::new();
        let peer = vec![
            change_entry(wb, 1, 1, &Change::AddDevice {
                uuid: merge_dev_b(), alias: "tablet".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
            }),
            change_entry(wb, 1, 2, &Change::AddApplication {
                device_uuid: merge_dev_b(), app_id: app,
                app_alias: "original".into(),
            }),
            change_entry(wb, 1, 3, &Change::UpdateApplicationAlias {
                device_uuid: merge_dev_b(), app_id: app,
                new_alias: "final".into(),
            }),
        ];
        let ranks = HashMap::new();
        let out = merge_logs(&local, &peer, &ranks);
        assert_eq!(out.new_entries.len(), 3);
        assert_eq!(out.changes_to_apply.len(), 2);
        assert!(matches!(&out.changes_to_apply[0],
            Change::AddDevice { uuid, .. } if uuid == &merge_dev_b()));
        match &out.changes_to_apply[1] {
            Change::AddApplication { app_alias, .. } => {
                assert_eq!(app_alias, "final",
                    "peer Add+Update collapse to a single AddApplication with the post-Update alias");
            }
            other => panic!("expected AddApplication, got {other:?}"),
        }
    }

    #[test]
    fn merge_logs_device_add_emitted_before_app_add() {
        // Diff order matters because apply_change_locally for AddApplication
        // validates that the device exists.
        let wb = merge_writer_b();
        let local = Vec::new();
        let peer = vec![
            change_entry(wb, 1, 2, &Change::AddApplication {
                device_uuid: merge_dev_b(),
                app_id: app_uuid(707),
                app_alias: "x".into(),
            }),
            change_entry(wb, 1, 1, &Change::AddDevice {
                uuid: merge_dev_b(), alias: "x-dev".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
            }),
        ];
        let ranks = HashMap::new();
        let out = merge_logs(&local, &peer, &ranks);
        assert!(matches!(out.changes_to_apply[0], Change::AddDevice { .. }));
        assert!(matches!(out.changes_to_apply[1], Change::AddApplication { .. }));
    }

    #[test]
    fn merge_logs_peer_subset_already_known_emits_only_diff() {
        // Peer ships [e1, e2] but we already have e1 (same version key).
        // Only e2 lands in new_entries, and changes_to_apply reflects only e2.
        let wa = merge_writer_a();
        let wb = merge_writer_b();
        let e1 = change_entry(wb, 1, 1, &Change::AddDevice {
            uuid: merge_dev_b(), alias: "shared".into(),
            grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
        });
        let local = vec![
            change_entry(wa, 1, 1, &Change::AddDevice {
                uuid: merge_dev_a(), alias: "local-only".into(),
                grade: DeviceGrade::DG, sg_rank: None, hosts: vec![],
            }),
            e1.clone(),
        ];
        let peer = vec![
            e1,
            change_entry(wb, 1, 2, &Change::AddApplication {
                device_uuid: merge_dev_b(),
                app_id: app_uuid(808),
                app_alias: "new-app".into(),
            }),
        ];
        let ranks = HashMap::new();
        let out = merge_logs(&local, &peer, &ranks);
        assert_eq!(out.new_entries.len(), 1, "only the unseen entry is new");
        assert_eq!(out.changes_to_apply.len(), 1);
        assert!(matches!(&out.changes_to_apply[0],
            Change::AddApplication { app_alias, .. } if app_alias == "new-app"));
    }
}
