use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

use super::action_queue::WorkerContext;
use super::data_models::{
    ActiveConnection, ActiveTunnel, Application, Contact, Device, DeviceGrade, Invitation,
    KeyPair, PendingBootstrap, PendingConnection, PendingContactExchange, PendingDeviceAcceptance,
    PendingTunnel, PendingTunnelConnection, PublicKey, Scope, SgStatus, SyncVersion,
    TunnelCounter, User, Uuid, CONNECTION_LIFETIME, RENEW_THRESHOLD, TUNNEL_COUNTER_WINDOW,
    TUNNEL_THRESHOLD, generate_key_bytes, generate_uuid,
};

// ── Reply status bytes ────────────────────────────────────────────────────────
const OK:                u8 = 0x00;
const ERR_BAD_PACKET:    u8 = 0x01;
const ERR_TOKEN_UNKNOWN: u8 = 0x02;

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
    send(ctx, dest, &[0x01, code]);
}

/// Extract an IPv4 address from a SocketAddr, mapping IPv4-in-IPv6 if needed.
fn ipv4_from(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped(),
    }
}

/// Resolve a `Device.hosts` entry (hostname or IP, optional ":port", default 7777)
/// to an IPv4 socket address via the OS DNS resolver. Returns `None` if the entry
/// is malformed or fails to resolve — callers should treat that as "skip this
/// address" silently; it's expected behaviour when a name only resolves inside
/// certain networks.
fn resolve_host_entry(entry: &str) -> Option<SocketAddrV4> {
    use std::net::ToSocketAddrs;

    let entry = entry.trim();
    if entry.is_empty() { return None; }

    // Direct "1.2.3.4:port" parse first.
    if let Ok(addr) = entry.parse::<SocketAddrV4>() {
        return Some(addr);
    }

    // Split optional ":port", default 7777.
    let (host_part, port) = match entry.rfind(':') {
        Some(pos) => {
            let port: u16 = entry[pos + 1..].parse().ok()?;
            (&entry[..pos], port)
        }
        None => (entry, 7777u16),
    };

    let addr_str = format!("{host_part}:{port}");
    addr_str.to_socket_addrs().ok()?.find_map(|a| match a {
        SocketAddr::V4(v4) => Some(v4),
        _ => None,
    })
}

/// Resolve every entry in a hosts list, dropping any that fail to resolve.
/// Returns `(original_entry, resolved_addr)` pairs so downstream code (e.g.
/// `sg_statuses`) can still key by the hostname string the operator
/// configured, rather than by a transient resolved IP.
fn resolve_hosts(hosts: &[String]) -> Vec<(String, SocketAddrV4)> {
    hosts.iter()
        .filter_map(|h| resolve_host_entry(h).map(|a| (h.clone(), a)))
        .collect()
}

// ── App handlers ──────────────────────────────────────────────────────────────

/// Op 0 — Application registration.
///
/// Request body (after op byte):
///   [alias_len: u8][alias: alias_len bytes][port: u16 be]
///   [protocol_len: u8][protocol: protocol_len bytes]
///
/// Reply on success:  [0x00][token: 16 bytes]
/// Reply on error:    [0x01][error_code: u8]
pub fn app_register(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    // Parse.
    if buf.is_empty() {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let alias_len = buf[0] as usize;
    if buf.len() < 1 + alias_len + 2 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let alias = match std::str::from_utf8(&buf[1..1 + alias_len]) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => return send_error(ctx, src, ERR_BAD_PACKET),
    };
    let port = u16::from_be_bytes([buf[1 + alias_len], buf[2 + alias_len]]);
    if port == 0 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let mut pos = 3 + alias_len;
    if pos >= buf.len() {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let protocol_len = buf[pos] as usize;
    pos += 1;
    if buf.len() < pos + protocol_len {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let protocol = match std::str::from_utf8(&buf[pos..pos + protocol_len]) {
        Ok(s) if !s.is_empty() => s.to_string(),
        _ => return send_error(ctx, src, ERR_BAD_PACKET),
    };
    let ip = match ipv4_from(src) {
        Some(ip) => ip,
        None => return send_error(ctx, src, ERR_BAD_PACKET),
    };

    // PNET_AUTO_APPROVE_APPS=1 (testing only) skips the manual approval step so
    // headless harnesses can register apps without UI interaction.
    let auto_approve = std::env::var("PNET_AUTO_APPROVE_APPS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let alias_for_log = alias.clone();

    // Update node.
    let (token, next_id, device_uuid) = {
        let mut node = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;

        let device = node
            .owner
            .user
            .devices
            .iter_mut()
            .find(|d| d.uuid == device_uuid)
            .expect("local device not found in node");

        let next_id = device
            .applications
            .iter()
            .map(|a| a.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let token = generate_uuid();
        device.applications.push(Application {
            id: next_id,
            alias,
            protocol,
            host: SocketAddrV4::new(ip, port),
            user_approved: auto_approve,
            token,
        });
        (token, next_id, device_uuid)
        // write lock released here
    };

    ctx.save_node();
    sync_devices(ctx);
    if auto_approve {
        push_data_to_contacts(ctx);
        println!("[app_register] auto-approved '{alias_for_log}' via PNET_AUTO_APPROVE_APPS");
        // Sync v1: publish id+alias to peers via the writer SG. Runs
        // alongside the legacy sync_devices/push_data_to_contacts above
        // until phase 7b removes the legacy paths.
        let _ = request_change(Change::AddApplication {
            device_uuid,
            app_id:    next_id,
            app_alias: alias_for_log.clone(),
        }, ctx);
    }

    // Reply: [OK][token: 16 bytes]
    let mut reply = [0u8; 17];
    reply[0] = OK;
    reply[1..17].copy_from_slice(&token);
    send(ctx, src, &reply);
}

/// Op 1 — Application update.
///
/// Request body (after op byte):
///   [token: 16 bytes][flags: u8]
///   if flags & 0x01: [alias_len: u8][alias: alias_len bytes]
///   if flags & 0x02: [port: u16 be]  (IP is taken from src)
///
/// Reply on success:  [0x00]
/// Reply on error:    [0x01][error_code: u8]
pub fn app_update(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    // Parse header.
    if buf.len() < 17 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let token: [u8; 16] = buf[0..16].try_into().unwrap();
    let flags = buf[16];
    let mut pos = 17usize;

    let mut new_alias: Option<String> = None;
    let mut new_port:  Option<u16>   = None;

    if flags & 0x01 != 0 {
        if pos >= buf.len() {
            return send_error(ctx, src, ERR_BAD_PACKET);
        }
        let alias_len = buf[pos] as usize;
        pos += 1;
        if pos + alias_len > buf.len() {
            return send_error(ctx, src, ERR_BAD_PACKET);
        }
        match std::str::from_utf8(&buf[pos..pos + alias_len]) {
            Ok(s) if !s.is_empty() => new_alias = Some(s.to_string()),
            _ => return send_error(ctx, src, ERR_BAD_PACKET),
        }
        pos += alias_len;
    }

    if flags & 0x02 != 0 {
        if pos + 2 > buf.len() {
            return send_error(ctx, src, ERR_BAD_PACKET);
        }
        new_port = Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
    }

    // Update node.
    let found = {
        let mut node = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let device = node
            .owner
            .user
            .devices
            .iter_mut()
            .find(|d| d.uuid == device_uuid)
            .expect("local device not found in node");

        if let Some(app) = device.applications.iter_mut().find(|a| a.token == token) {
            if let Some(alias) = new_alias {
                app.alias = alias;
            }
            if let Some(port) = new_port {
                if let Some(ip) = ipv4_from(src) {
                    app.host = SocketAddrV4::new(ip, port);
                }
            }
            true
        } else {
            false
        }
        // write lock released here
    };

    if found {
        ctx.save_node();
        sync_devices(ctx);
        send(ctx, src, &[OK]);
    } else {
        send_error(ctx, src, ERR_TOKEN_UNKNOWN);
    }
}

/// Op 2 — Application get data.
///
/// Request body (after op byte):
///   [token: 16 bytes]
///
/// Authenticates the app via its token and returns its view of the node data tree.
///
/// Response format:
///   [OK: 1]
///   -- Requesting app's own data (full Application struct) --
///   [app_id: u16 BE][app_alias: u8+bytes][app_host_ip: 4][app_host_port: 2 BE]
///   [app_user_approved: u8][app_token: 16]
///   -- Owner data tree (no crypto keys) --
///   [owner_alias: u8+bytes][owner_uuid: 16]
///   [device_count: u8]
///     each device:
///       [uuid: 16][alias: u8+bytes][grade: u8][sg_rank: u8]
///       [host_count: u8][each host: u8+bytes]
///       [app_count: u8]
///         each app: [id: u16 BE][alias: u8+bytes][ip: 4][port: 2 BE][user_approved: u8]
///   [contact_count: u8]
///     each contact:
///       [alias: u8+bytes][uuid: 16]
///       [device_count: u8]
///         each device:
///           [uuid: 16][alias: u8+bytes][grade: u8][sg_rank: u8]
///           [host_count: u8][each host: u8+bytes]
///           [app_count: u8]
///             each app: [id: u16 BE][alias: u8+bytes]
pub fn app_get_data(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 16 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let token: [u8; 16] = buf[0..16].try_into().unwrap();

    let node = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device = node
        .owner
        .user
        .devices
        .iter()
        .find(|d| d.uuid == device_uuid)
        .expect("local device not found in node");

    let app = device.applications.iter().find(|a| a.token == token).cloned();
    drop(node);

    let app = match app {
        Some(a) => a,
        None    => return send_error(ctx, src, ERR_TOKEN_UNKNOWN),
    };

    let node = ctx.node.read().unwrap();
    let mut reply = vec![OK];

    // Requesting app's own data.
    reply.extend_from_slice(&app.id.to_be_bytes());
    push_str(&mut reply, &app.alias);
    reply.extend_from_slice(&app.host.ip().octets());
    reply.extend_from_slice(&app.host.port().to_be_bytes());
    reply.push(app.user_approved as u8);
    reply.extend_from_slice(&app.token);
    reply.extend_from_slice(&device_uuid);

    // Owner alias and UUID.
    push_str(&mut reply, &node.owner.user.alias);
    reply.extend_from_slice(&node.owner.user.uuid);

    // Own devices with apps.
    reply.push(node.owner.user.devices.len() as u8);
    for d in &node.owner.user.devices {
        push_device(&mut reply, d);
        reply.push(d.applications.len() as u8);
        for a in &d.applications {
            reply.extend_from_slice(&a.id.to_be_bytes());
            push_str(&mut reply, &a.alias);
            reply.extend_from_slice(&a.host.ip().octets());
            reply.extend_from_slice(&a.host.port().to_be_bytes());
            reply.push(a.user_approved as u8);
        }
    }

    // Contacts with devices and apps.
    reply.push(node.owner.contact_users.len() as u8);
    for contact in &node.owner.contact_users {
        push_str(&mut reply, &contact.user.alias);
        reply.extend_from_slice(&contact.user.uuid);
        reply.push(contact.user.devices.len() as u8);
        for d in &contact.user.devices {
            push_device(&mut reply, d);
            let approved: Vec<&Application> = d.applications.iter()
                .filter(|a| a.user_approved)
                .collect();
            reply.push(approved.len() as u8);
            for a in approved {
                reply.extend_from_slice(&a.id.to_be_bytes());
                push_str(&mut reply, &a.alias);
            }
        }
    }

    drop(node);
    send(ctx, src, &reply);
}

/// Op 3 — Application send packet.
///
/// Request body (after op byte):
///   [token: 16 bytes][target_device_uuid: 16 bytes][target_app_id: u16 be][payload: ...]
///
/// Looks up the active connection for the target device, encrypts the payload,
/// and forwards the packet to the peer pnet node.
/// Not yet implemented — requires ephemeral key exchange to be established first.
/// Op 3 — Application send packet.
///
/// Request body (after op byte):
///   [token: 16][dest_device_uuid: 16][dest_app_id: u16][payload: rest]
///
/// Builds a RelayPacket (op 0x40) and sends it to the lowest-RTT reachable SG
/// from the combined pool of the local user's SGs and the destination user's SGs.
pub fn app_send_packet(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    const MIN_LEN: usize = 16 + 16 + 2;
    if buf.len() < MIN_LEN {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }

    let token: Uuid            = buf[0..16].try_into().unwrap();
    let dest_device_uuid: Uuid = buf[16..32].try_into().unwrap();
    let dest_app_id            = u16::from_be_bytes([buf[32], buf[33]]);
    let payload                = &buf[34..];

    // Build packet and look up the SG address under a single read lock.
    let out: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();

        // Find the sending app by token.
        let device_uuid = node.device_uuid;
        let Some(sender_app_id) = node.owner.user.devices.iter()
            .find(|d| d.uuid == device_uuid)
            .and_then(|d| d.applications.iter()
                .find(|a| a.token == token && a.user_approved))
            .map(|a| a.id)
        else {
            return send_error(ctx, src, ERR_TOKEN_UNKNOWN);
        };

        // ── Tunnel path (if a DG-to-DG tunnel is active for this destination) ──
        // Only use if the tunnel's ActiveConnection still exists.
        let tunnel_info: Option<(u16, u16)> = node.owner.dg_tunnel_map.iter()
            .find(|(tid, conn_id)| {
                let _ = *tid;
                node.owner.active_connections.get(*conn_id)
                    .map(|c| c.device_uuid == dest_device_uuid)
                    .unwrap_or(false)
            })
            .map(|(tid, cid)| (*tid, *cid))
            .filter(|(_, cid)| node.owner.active_connections.contains_key(cid));

        if let Some((tunnel_id, dg_dg_conn_id)) = tunnel_info {
            // Encrypt with the DG-to-DG shared secret.
            let Some(dg_dg_conn) = node.owner.active_connections.get(&dg_dg_conn_id) else {
                unreachable!("filtered above");
            };
            let shared = x25519_shared(&dg_dg_conn.key_pair.private_key, &dg_dg_conn.peer_public_key);

            // Plaintext format: [dest_app_id: u16][sender_app_id: u16][payload]
            let mut plaintext = Vec::with_capacity(4 + payload.len());
            plaintext.extend_from_slice(&dest_app_id.to_be_bytes());
            plaintext.extend_from_slice(&sender_app_id.to_be_bytes());
            plaintext.extend_from_slice(payload);

            let (ciphertext, nonce) = xchacha20_encrypt(&shared, &plaintext);

            // Route the tunnel forward packet via the relay SG.
            let sg_conn = top_ranked_sg_for_device(&node, &dest_device_uuid)
                .or_else(|| {
                    let candidates = sg_candidates_for_dest(&node, &dest_device_uuid);
                    best_sg_connection(&node, &candidates)
                });
            let Some(sg_conn) = sg_conn else {
                eprintln!("[app_send_packet] no reachable SG for tunnel dest {:?}", dest_device_uuid);
                return;
            };

            // `peer_active_connection_id` is the SG's local conn_id for this DG's connection.
            let sender_sg_conn_id = sg_conn.peer_active_connection_id;

            // TUNNEL_FORWARD: [op=0x51][sender_sg_conn_id: u16][tunnel_id: u16][nonce: 24][ciphertext]
            let mut pkt = Vec::with_capacity(4 + 24 + ciphertext.len());
            pkt.push(TUNNEL_FORWARD_OP);
            pkt.extend_from_slice(&sender_sg_conn_id.to_be_bytes());
            pkt.extend_from_slice(&tunnel_id.to_be_bytes());
            pkt.extend_from_slice(&nonce);
            pkt.extend_from_slice(&ciphertext);

            Some((pkt, sg_conn.peer_addr))
        } else if let Some(dest_conn) = node.owner.active_connections.values()
            .find(|c| c.device_uuid == dest_device_uuid)
        {
            // ── Direct path (this node has an active connection to dest) ──────
            // When the local device is an SG it may already hold a direct
            // connection to the destination DG.  Skip the relay and send an
            // AppPacket straight to the destination using the peer's actual
            // source address (not the potentially-stale d.host).
            let mut app_body = Vec::with_capacity(4 + payload.len());
            app_body.extend_from_slice(&dest_app_id.to_be_bytes());
            app_body.extend_from_slice(&sender_app_id.to_be_bytes());
            app_body.extend_from_slice(payload);

            let pkt  = build_encrypted_packet(APP_PACKET_OP, dest_conn, &app_body);
            let dest = dest_conn.peer_addr;
            Some((pkt, dest))
        } else {
            // ── Standard relay path ───────────────────────────────────────────
            // Prefer the recipient's top-ranked SG (only one with a keep-alive
            // tunnel to the destination DG). Fall back to lowest-RTT SG.
            let sg_conn = top_ranked_sg_for_device(&node, &dest_device_uuid)
                .or_else(|| {
                    let candidates = sg_candidates_for_dest(&node, &dest_device_uuid);
                    best_sg_connection(&node, &candidates)
                });
            let Some(sg_conn) = sg_conn else {
                eprintln!("[app_send_packet] no reachable SG for dest {:?}", dest_device_uuid);
                return;
            };

            // RelayPacket body: [dest_device_uuid: 16][dest_app_id: u16][sender_app_id: u16][payload]
            let mut plaintext = Vec::with_capacity(20 + payload.len());
            plaintext.extend_from_slice(&dest_device_uuid);
            plaintext.extend_from_slice(&dest_app_id.to_be_bytes());
            plaintext.extend_from_slice(&sender_app_id.to_be_bytes());
            plaintext.extend_from_slice(payload);

            let pkt = build_encrypted_packet(RELAY_PACKET_OP, sg_conn, &plaintext);

            Some((pkt, sg_conn.peer_addr))
        }
    };

    if let Some((pkt, dest)) = out {
        send(ctx, dest, &pkt);
    }
}

// ── Peer pNet node handlers ───────────────────────────────────────────────────

const SG_PING_OP:          u8 = 0x10;
const SG_PONG_OP:          u8 = 0x11;
const DG_KEEPALIVE_OP:     u8 = 0x12;
const CONN_RESET_OP:       u8 = 0x13;
const CONNECT_REQUEST_OP:  u8 = 0x20;
const CONNECT_ACK_OP:      u8 = 0x21;
const BOOTSTRAP_REQUEST_OP:  u8 = 0x30;
const BOOTSTRAP_RESPONSE_OP: u8 = 0x31;
const DEVICE_REGISTER_OP:    u8 = 0x32;
const CONTACT_REQUEST_OP:         u8 = 0x33;
const CONTACT_RESPONSE_OP:        u8 = 0x34;
const CONTACT_DATA_PUSH_OP:       u8 = 0x60;
const CONTACT_DATA_PULL_REQ_OP:   u8 = 0x61;
const DEVICE_DATA_PUSH_OP:        u8 = 0x62;
const DEVICE_DATA_PULL_REQ_OP:    u8 = 0x63;
// Sync v1 ops (see descriptions/data sync.md).
// 0x70/0x71 — DG/SG→writer write request and writer→originator ack.
// 0x72      — writer→peers "you have a stale version, pull when ready".
// 0x73/0x74 — any node→writer pull request and writer's response (delta or NoUpdates).
const SYNC_WRITE_REQUEST_OP:    u8 = 0x70;
const SYNC_WRITE_ACK_OP:        u8 = 0x71;
const SYNC_UPDATE_AVAILABLE_OP: u8 = 0x72;
const SYNC_PULL_REQUEST_OP:     u8 = 0x73;
const SYNC_PULL_RESPONSE_OP:    u8 = 0x74;
const RELAY_PACKET_OP:            u8 = 0x40;
const APP_PACKET_OP:              u8 = 0x41;
const APP_PUSH_OP:                u8 = 0x04;
const TUNNEL_INIT_OP:             u8 = 0x50;
const TUNNEL_FORWARD_OP:          u8 = 0x51;
const TUNNEL_CONNECT_REQUEST_OP:  u8 = 0x52;
const TUNNEL_CONNECT_ACK_OP:      u8 = 0x53;
const TUNNEL_DELIVERY_OP:         u8 = 0x54;

/// How long the SG keeps a PendingDeviceAcceptance waiting for DeviceRegistration.
const PENDING_ACCEPTANCE_TTL: Duration = Duration::from_secs(5 * 60);

/// Find the device UUID for an incoming connection request, given the peer's
/// long-term public key and claimed device UUID.  Returns `Some(uuid)` if both
/// the key and the UUID are known (own devices or a contact's devices).
fn find_device_uuid_for_pk(node: &super::data_models::Node, longterm_pk: &PublicKey, device_uuid: &Uuid) -> Option<Uuid> {
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
///   [signature: 64 bytes]             — TODO: verify with Ed25519
///
/// If the initiator is a known device, stores an ActiveConnection and replies
/// with a ConnectAck containing our ephemeral public key.
pub fn connect_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    const MIN_LEN: usize = 2 + 16 + 32 + 32 + 64;
    if buf.len() < MIN_LEN {
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

    // Push fresh device data to all connected own devices now that this one
    // has just joined.  Safe to call even if the connection list is small;
    // sync_devices guards against non-SG callers internally.
    sync_devices(ctx);
    push_data_to_contacts(ctx);
}

/// Op 0x21 — Acknowledgement from a peer node in response to our ConnectRequest.
///
/// Payload layout (after op byte):
///   [responder_conn_id: u16 be]
///   [our_conn_id: u16 be]             — echoed back so we correlate to pending entry
///   [responder_ephemeral_pk: 32 bytes]
///   [signature: 64 bytes]             — TODO: verify with Ed25519
///
/// Promotes the matching PendingConnection to an ActiveConnection.
pub fn connect_ack(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    const MIN_LEN: usize = 2 + 2 + 32 + 64;
    if buf.len() < MIN_LEN {
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

    // Pull fresh device data from the SG now that the connection is live.
    // This corrects any stale app counts that persisted from a previous session.
    sync_devices(ctx);
    push_data_to_contacts(ctx);
    // Sync v1: if the freshly-connected peer is our writer SG, immediately
    // catch up on any `SyncUpdateAvailable` notifications missed while
    // disconnected. `sync_pull` is a no-op when the writer is `Local` or no
    // writer is reachable, so it's safe to call unconditionally.
    sync_pull(ctx);
}

// ── Bootstrap crypto helpers ──────────────────────────────────────────────────

/// X25519 Diffie-Hellman: returns the 32-byte shared secret.
fn x25519_shared(our_sk: &[u8; 32], their_pk: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey as X25519Pk, StaticSecret};
    StaticSecret::from(*our_sk)
        .diffie_hellman(&X25519Pk::from(*their_pk))
        .to_bytes()
}

/// Generate a proper X25519 key pair: random scalar + corresponding public point.
fn generate_x25519_keypair() -> KeyPair {
    use x25519_dalek::{PublicKey as X25519Pk, StaticSecret};
    let sk = StaticSecret::from(generate_key_bytes());
    KeyPair {
        private_key: sk.to_bytes(),
        public_key:  *X25519Pk::from(&sk).as_bytes(),
    }
}

/// Generate a proper Ed25519 key pair for long-term identity signing.
fn generate_ed25519_keypair() -> KeyPair {
    use ed25519_dalek::SigningKey;
    let seed = generate_key_bytes();
    let signing_key = SigningKey::from_bytes(&seed);
    KeyPair {
        private_key: seed,
        public_key:  *signing_key.verifying_key().as_bytes(),
    }
}

/// Ed25519 sign: returns a 64-byte signature over `message` using a 32-byte seed.
fn ed25519_sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{SigningKey, Signer};
    SigningKey::from_bytes(private_key).sign(message).to_bytes()
}

/// Ed25519 verify: returns true if the 64-byte signature is valid over `message`.
fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    let Ok(vk)  = VerifyingKey::from_bytes(public_key) else { return false };
    let sig     = Signature::from_bytes(signature);
    vk.verify(message, &sig).is_ok()
}

/// XChaCha20-Poly1305 authenticated encryption.  Returns (ciphertext, 24-byte nonce).
fn xchacha20_encrypt(key: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, [u8; 24]) {
    use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::{Aead, KeyInit}};
    let nonce_bytes: [u8; 24] = {
        use std::io::Read;
        let mut b = [0u8; 24];
        std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut b).unwrap();
        b
    };
    let cipher     = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let nonce      = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).expect("encryption failed");
    (ciphertext, nonce_bytes)
}

/// XChaCha20-Poly1305 authenticated decryption.  Returns `None` on auth failure.
fn xchacha20_decrypt(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::{XChaCha20Poly1305, XNonce, aead::{Aead, KeyInit}};
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce  = XNonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext).ok()
}

// ── Packet routing helpers ────────────────────────────────────────────────────

/// Build a complete relay or app packet: unencrypted header + encrypted body.
///
/// Header: [op: 1][peer_active_conn_id: u16][nonce: 24]
/// Body:   XChaCha20-Poly1305 encrypted plaintext using the X25519 shared secret.
fn build_encrypted_packet(op: u8, conn: &ActiveConnection, plaintext: &[u8]) -> Vec<u8> {
    let shared  = x25519_shared(&conn.key_pair.private_key, &conn.peer_public_key);
    let (ct, nonce) = xchacha20_encrypt(&shared, plaintext);
    let mut pkt = Vec::with_capacity(1 + 2 + 24 + ct.len());
    pkt.push(op);
    pkt.extend_from_slice(&conn.peer_active_connection_id.to_be_bytes());
    pkt.extend_from_slice(&nonce);
    pkt.extend_from_slice(&ct);
    pkt
}

/// Decrypt the body of a relay or app packet (buf starts after the op byte).
///
/// buf layout: [receiver_active_conn_id: u16][nonce: 24][ciphertext]
///
/// Looks up the named active connection in the node's map and decrypts using
/// the X25519 shared secret derived from that connection's key pair.
fn decrypt_packet_body(node: &super::data_models::Node, buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 26 { return None; }
    let conn_id           = u16::from_be_bytes([buf[0], buf[1]]);
    let nonce: [u8; 24]   = buf[2..26].try_into().unwrap();
    let ciphertext        = &buf[26..];
    let conn              = node.owner.active_connections.get(&conn_id)?;
    let shared            = x25519_shared(&conn.key_pair.private_key, &conn.peer_public_key);
    xchacha20_decrypt(&shared, &nonce, ciphertext)
}

/// Pick the best address for reaching `device_uuid`: the up entry with the
/// lowest recorded RTT in `sg_statuses`. Falls back to the first resolvable
/// entry in the device's host list when no poll data exists yet.
///
/// Cold-boot note: the first ConnectRequest after startup may land on a dead
/// address if the happy-eyeballs data isn't populated yet; the next `poll_sg`
/// cycle (≤30s) corrects that.
fn best_address_for_device(
    node: &super::data_models::Node,
    device_uuid: &Uuid,
) -> Option<SocketAddrV4> {
    let best_polled: Option<SocketAddrV4> = node.sg_statuses.iter()
        .filter(|((u, _), s)| *u == *device_uuid && s.up && s.last_rtt.is_some())
        .min_by_key(|(_, s)| s.last_rtt.unwrap())
        .and_then(|((_, host), _)| resolve_host_entry(host));

    if best_polled.is_some() {
        return best_polled;
    }

    let dev = node.owner.user.devices.iter()
        .chain(node.owner.contact_users.iter().flat_map(|c| c.user.devices.iter()))
        .find(|d| d.uuid == *device_uuid)?;

    resolve_hosts(&dev.hosts).into_iter().next().map(|(_, a)| a)
}

/// Build the pool of candidate SG UUIDs for routing a packet to `dest_device_uuid`.
/// Pool = all SGs owned by the local user + all SGs owned by the contact who holds that device.
fn sg_candidates_for_dest(node: &super::data_models::Node, dest_device_uuid: &Uuid) -> Vec<Uuid> {
    let mut uuids = Vec::new();
    for d in &node.owner.user.devices {
        if matches!(d.grade, DeviceGrade::SG) {
            uuids.push(d.uuid);
        }
    }
    for contact in &node.owner.contact_users {
        if contact.user.devices.iter().any(|d| d.uuid == *dest_device_uuid) {
            for d in &contact.user.devices {
                if matches!(d.grade, DeviceGrade::SG) {
                    uuids.push(d.uuid);
                }
            }
            break; // a device belongs to exactly one contact
        }
    }
    uuids
}

/// Identifies the writer SG from this node's perspective per the design rule
/// in `descriptions/data sync.md`: "the highest-rank reachable own SG,
/// including this node if it is itself an SG." See `find_writer_sg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterTarget {
    /// This node is the writer — accept writes locally.
    Local,
    /// A peer SG is the writer; send writes to its UUID.
    Remote(Uuid),
    /// No own SG is reachable. Only happens on a DG that has lost contact
    /// with all of its user's SGs. Writes from such a DG must error to the app.
    Unreachable,
}

/// Determine the writer SG from this node's perspective.
///
/// Walks all of the user's own SGs in rank order (lowest = best) and returns
/// the first one that is reachable. Reachability rules:
///
/// - **Self** (when this node is an SG): always reachable to itself.
/// - **Peer SG**: must have an active connection AND, if `sg_statuses` has
///   entries for it, at least one address marked up. Optimistic when no poll
///   data exists yet — matches the convention used by `top_ranked_sg_for_device`.
///
/// Used both for issuing writes (find where to send a SyncWriteRequest) and
/// for the SG-side forward-up-the-rank rule (an SG receiving a write returns
/// `Local` only when no higher-rank peer is reachable to it).
pub fn find_writer_sg(node: &super::data_models::Node) -> WriterTarget {
    let local_uuid = node.device_uuid;

    let mut sgs: Vec<&Device> = node.owner.user.devices.iter()
        .filter(|d| matches!(d.grade, DeviceGrade::SG))
        .collect();
    sgs.sort_by_key(|d| d.sg_rank.unwrap_or(u32::MAX));

    for d in &sgs {
        if d.uuid == local_uuid {
            return WriterTarget::Local;
        }
        let has_conn = node.owner.active_connections.values()
            .any(|c| c.device_uuid == d.uuid);
        if !has_conn { continue; }

        let mut any_entry = false;
        let mut any_up    = false;
        for ((uuid, _), status) in &node.sg_statuses {
            if *uuid == d.uuid {
                any_entry = true;
                if status.up { any_up = true; }
            }
        }
        let polled_up = !any_entry || any_up;
        if polled_up {
            return WriterTarget::Remote(d.uuid);
        }
    }
    WriterTarget::Unreachable
}

/// Return the UUID of the highest-ranked SG that owns `dest_device_uuid` and
/// currently has an active connection on this node.  Returns `None` if no
/// ranked SG with an active connection is found.
fn top_ranked_sg_for_device<'a>(
    node: &'a super::data_models::Node,
    dest_device_uuid: &Uuid,
) -> Option<&'a ActiveConnection> {
    // Find the user (own or contact) who owns dest_device_uuid.
    let dest_user_devices: Option<&Vec<super::data_models::Device>> =
        if node.owner.user.devices.iter().any(|d| d.uuid == *dest_device_uuid) {
            Some(&node.owner.user.devices)
        } else {
            node.owner.contact_users.iter()
                .find(|c| c.user.devices.iter().any(|d| d.uuid == *dest_device_uuid))
                .map(|c| &c.user.devices)
        };

    let devices = dest_user_devices?;

    // Collect SGs with active connections, sorted by rank ascending (None last).
    let mut sgs: Vec<&super::data_models::Device> = devices.iter()
        .filter(|d| matches!(d.grade, DeviceGrade::SG))
        .filter(|d| node.owner.active_connections.values().any(|c| c.device_uuid == d.uuid))
        .collect();
    sgs.sort_by_key(|d| d.sg_rank.unwrap_or(u32::MAX));

    // Return the active connection to the highest-ranked SG that has at least
    // one address marked up (or no poll data yet — be optimistic).
    sgs.iter()
        .find(|d| {
            let mut any_entry = false;
            let mut any_up = false;
            for ((uuid, _), status) in &node.sg_statuses {
                if *uuid == d.uuid {
                    any_entry = true;
                    if status.up { any_up = true; }
                }
            }
            !any_entry || any_up
        })
        .and_then(|d| node.owner.active_connections.values().find(|c| c.device_uuid == d.uuid))
}

/// Select the best SG from a list of candidate device UUIDs.
///
/// Prefers the lowest-RTT SG that is marked up in `sg_statuses` and has an
/// active connection.  Falls back to any candidate with an active connection
/// when PollSG has not yet run.
fn best_sg_connection<'a>(
    node: &'a super::data_models::Node,
    candidates: &[Uuid],
) -> Option<&'a ActiveConnection> {
    // Primary: lowest RTT across any address for that device, must be up and
    // have an active connection.
    let polled = candidates.iter()
        .filter_map(|uuid| {
            let best_rtt = node.sg_statuses.iter()
                .filter(|((u, _), s)| *u == *uuid && s.up)
                .filter_map(|(_, s)| s.last_rtt)
                .min()?;
            node.owner.active_connections.values()
                .find(|c| c.device_uuid == *uuid)
                .map(|c| (best_rtt, c))
        })
        .min_by_key(|(rtt, _)| *rtt)
        .map(|(_, c)| c);

    if polled.is_some() {
        return polled;
    }

    // Fallback: any candidate with an active connection (PollSG not yet run).
    candidates.iter().find_map(|uuid| {
        node.owner.active_connections.values()
            .find(|c| c.device_uuid == *uuid)
    })
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

fn push_str(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    buf.push(b.len() as u8);
    buf.extend_from_slice(b);
}

fn read_str(data: &[u8], pos: &mut usize) -> Option<String> {
    let len = *data.get(*pos)? as usize;
    *pos += 1;
    let s = std::str::from_utf8(data.get(*pos..*pos + len)?).ok()?.to_string();
    *pos += len;
    Some(s)
}

fn read_arr<const N: usize>(data: &[u8], pos: &mut usize) -> Option<[u8; N]> {
    let slice: [u8; N] = data.get(*pos..*pos + N)?.try_into().ok()?;
    *pos += N;
    Some(slice)
}

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

fn serialize_bootstrap_payload(node: &super::data_models::Node) -> Vec<u8> {
    let mut buf = Vec::new();
    let owner = &node.owner;
    let user  = &owner.user;
    push_str(&mut buf, &user.alias);
    buf.extend_from_slice(&user.uuid);
    buf.extend_from_slice(&owner.key_pair.public_key);
    buf.extend_from_slice(&owner.key_pair.private_key);
    buf.push(user.devices.len() as u8);
    for d in &user.devices { push_device(&mut buf, d); }
    buf.push(owner.contact_users.len() as u8);
    for c in &owner.contact_users {
        buf.extend_from_slice(&c.user.uuid);
        push_str(&mut buf, &c.user.alias);
        buf.extend_from_slice(&c.public_key);
        buf.push(c.user.devices.len() as u8);
        for d in &c.user.devices { push_device(&mut buf, d); }
    }
    buf
}

struct BootstrapPayload {
    user_alias: String,
    user_uuid:  Uuid,
    key_pair:   KeyPair,
    devices:    Vec<Device>,
    contacts:   Vec<Contact>,
}

fn deserialize_bootstrap_payload(data: &[u8]) -> Option<BootstrapPayload> {
    let mut pos = 0usize;
    let user_alias  = read_str(data, &mut pos)?;
    let user_uuid:  Uuid      = read_arr(data, &mut pos)?;
    let pk: PublicKey         = read_arr(data, &mut pos)?;
    let sk: [u8; 32]          = read_arr(data, &mut pos)?;
    let key_pair = KeyPair { public_key: pk, private_key: sk };
    let device_count = *data.get(pos)? as usize; pos += 1;
    let mut devices = Vec::new();
    for _ in 0..device_count { devices.push(read_device(data, &mut pos)?); }
    let contact_count = *data.get(pos)? as usize; pos += 1;
    let mut contacts = Vec::new();
    for _ in 0..contact_count {
        let c_uuid: Uuid   = read_arr(data, &mut pos)?;
        let c_alias        = read_str(data, &mut pos)?;
        let c_pk: PublicKey = read_arr(data, &mut pos)?;
        let c_dev_count = *data.get(pos)? as usize; pos += 1;
        let mut c_devices = Vec::new();
        for _ in 0..c_dev_count { c_devices.push(read_device(data, &mut pos)?); }
        contacts.push(Contact {
            user:       User { alias: c_alias, uuid: c_uuid, devices: c_devices },
            public_key: c_pk,
        });
    }
    Some(BootstrapPayload { user_alias, user_uuid, key_pair, devices, contacts })
}

// ── Bootstrap handlers ────────────────────────────────────────────────────────

/// Op 0x30 — Bootstrap request (new device → SG).
///
/// Payload (after op byte):
///   [invitation_id: 16][new_device_ephem_pk: 32]
///
/// The SG validates the invitation, derives X25519(invitation_sk, new_device_ephem_pk),
/// encrypts the full user data with that key, and replies with a BootstrapResponse.
/// The invitation is consumed (single-use).
pub fn bootstrap_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 48 {
        eprintln!("[bootstrap_request] packet too short ({}) from {src}", buf.len());
        return;
    }
    let invitation_id:    Uuid      = buf[0..16].try_into().unwrap();
    let new_dev_ephem_pk: PublicKey = buf[16..48].try_into().unwrap();

    // Validate invitation, derive shared secret, serialize payload — all under write lock.
    let (shared_secret, payload) = {
        let mut node = ctx.node.write().unwrap();
        let now = SystemTime::now();

        let pos = match node.owner.device_invitations.iter().position(|inv| inv.id == invitation_id) {
            Some(p) => p,
            None => {
                eprintln!("[bootstrap_request] unknown invitation from {src}");
                return;
            }
        };
        if node.owner.device_invitations[pos].expires_at <= now {
            eprintln!("[bootstrap_request] expired invitation from {src}");
            node.owner.device_invitations.remove(pos);
            return;
        }

        let inv:           Invitation = node.owner.device_invitations.remove(pos);
        let shared_secret: [u8; 32]   = x25519_shared(&inv.key_pair.private_key, &new_dev_ephem_pk);
        let payload:       Vec<u8>    = serialize_bootstrap_payload(&node);

        // Remember the shared secret so we can decrypt the incoming DeviceRegistration.
        node.owner.pending_device_acceptances.insert(invitation_id, PendingDeviceAcceptance {
            shared_secret,
            expires_at: now + PENDING_ACCEPTANCE_TTL,
        });

        (shared_secret, payload)
        // write lock released here
    };

    ctx.save_node(); // consumed the device invitation

    // Encrypt and send outside the lock.
    let (ciphertext, nonce) = xchacha20_encrypt(&shared_secret, &payload);
    let mut pkt = Vec::with_capacity(1 + 24 + ciphertext.len());
    pkt.push(BOOTSTRAP_RESPONSE_OP);
    pkt.extend_from_slice(&nonce);
    pkt.extend_from_slice(&ciphertext);
    println!("[bootstrap_request] sending bootstrap response to {src}");
    send(ctx, src, &pkt);
}

/// Op 0x31 — Bootstrap response (SG → new device).
///
/// Payload (after op byte):
///   [nonce: 24][encrypted user data]
///
/// Decrypts using the pending bootstrap's shared secret, populates the node with
/// the received user data, then sends a DeviceRegistration back to the SG.
pub fn bootstrap_response(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 24 {
        eprintln!("[bootstrap_response] packet too short ({}) from {src}", buf.len());
        return;
    }
    let nonce:      [u8; 24] = buf[0..24].try_into().unwrap();
    let ciphertext: &[u8]    = &buf[24..];

    // Retrieve pending bootstrap state — we need it before taking the write lock.
    let (shared_secret, invitation_id, sg_addr, device_alias, desired_grade, desired_sg_rank) = {
        let node = ctx.node.read().unwrap();
        let Some(pb) = &node.owner.pending_bootstrap else {
            eprintln!("[bootstrap_response] no pending bootstrap, ignoring from {src}");
            return;
        };
        if SocketAddr::V4(pb.sg_addr) != src {
            eprintln!("[bootstrap_response] unexpected source {src}, ignoring");
            return;
        }
        let ss = x25519_shared(&pb.our_ephem_key_pair.private_key, &pb.invitation_pk);
        (ss, pb.invitation_id, pb.sg_addr, pb.device_alias.clone(), pb.desired_grade, pb.desired_sg_rank)
    };

    let Some(plaintext) = xchacha20_decrypt(&shared_secret, &nonce, ciphertext) else {
        eprintln!("[bootstrap_response] decryption failed from {src}");
        return;
    };
    let Some(data) = deserialize_bootstrap_payload(&plaintext) else {
        eprintln!("[bootstrap_response] deserialization failed from {src}");
        return;
    };

    // Apply received user data and clear pending bootstrap.
    let device_reg_payload = {
        let mut node = ctx.node.write().unwrap();
        let local_uuid = node.device_uuid;
        node.owner.user.alias  = data.user_alias;
        node.owner.user.uuid   = data.user_uuid;
        node.owner.key_pair    = data.key_pair;
        // Add received devices, skipping any that share our local UUID.
        for d in data.devices {
            if d.uuid != local_uuid && !node.owner.user.devices.iter().any(|x| x.uuid == d.uuid) {
                node.owner.user.devices.push(d);
            }
        }
        node.owner.contact_users  = data.contacts;
        node.owner.pending_bootstrap = None;

        // Apply the user-chosen alias, grade, and rank to the local device.
        if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == local_uuid) {
            if !device_alias.is_empty() {
                dev.alias = device_alias;
            }
            dev.grade   = desired_grade;
            dev.sg_rank = desired_sg_rank;
            // For SG joiners, PNET_HOSTS is authoritative for advertised hosts.
            if matches!(dev.grade, DeviceGrade::SG) {
                let hosts = parse_pnet_hosts();
                if !hosts.is_empty() {
                    dev.hosts = hosts;
                }
            }
        }

        // Serialize our own device entry to send as DeviceRegistration.
        let mut buf = Vec::new();
        if let Some(dev) = node.owner.user.devices.iter().find(|d| d.uuid == local_uuid) {
            push_device(&mut buf, dev);
        }
        buf
        // write lock released here
    };

    ctx.save_node(); // applied user data from bootstrap

    if device_reg_payload.is_empty() {
        eprintln!("[bootstrap_response] local device not found, cannot register");
        return;
    }

    println!("[bootstrap_response] bootstrap complete, sending device registration to {sg_addr}");
    // Send DeviceRegistration: [op=0x32][invitation_id:16][nonce:24][encrypted device info]
    let (ciphertext, reg_nonce) = xchacha20_encrypt(&shared_secret, &device_reg_payload);
    let mut pkt = Vec::with_capacity(1 + 16 + 24 + ciphertext.len());
    pkt.push(DEVICE_REGISTER_OP);
    pkt.extend_from_slice(&invitation_id);
    pkt.extend_from_slice(&reg_nonce);
    pkt.extend_from_slice(&ciphertext);
    send(ctx, SocketAddr::V4(sg_addr), &pkt);

    // Trigger connection maintenance now that we have peer data.
    ctx.scheduler_tx.send(super::action_queue::ScheduleRequest {
        action: super::action_queue::Action::MaintainConnections,
        delay:  Duration::ZERO,
    }).ok();
}

/// Op 0x32 — Device registration (new device → SG).
///
/// Payload (after op byte):
///   [invitation_id: 16][nonce: 24][encrypted device info]
///
/// The SG decrypts using the shared secret it stored for this invitation,
/// and adds the new device to `owner.user.devices`.
pub fn device_registration(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 16 + 24 {
        eprintln!("[device_registration] packet too short ({}) from {src}", buf.len());
        return;
    }
    let invitation_id: Uuid    = buf[0..16].try_into().unwrap();
    let nonce:         [u8; 24] = buf[16..40].try_into().unwrap();
    let ciphertext:    &[u8]   = &buf[40..];

    // Look up and consume the pending acceptance under write lock.
    let shared_secret: [u8; 32] = {
        let mut node = ctx.node.write().unwrap();
        let now = SystemTime::now();
        // Evict expired entries while we're here.
        node.owner.pending_device_acceptances.retain(|_, v| v.expires_at > now);
        match node.owner.pending_device_acceptances.remove(&invitation_id) {
            Some(pda) => pda.shared_secret,
            None => {
                eprintln!("[device_registration] no pending acceptance for invitation from {src}");
                return;
            }
        }
        // write lock released here
    };

    let Some(plaintext) = xchacha20_decrypt(&shared_secret, &nonce, ciphertext) else {
        eprintln!("[device_registration] decryption failed from {src}");
        return;
    };
    let mut pos = 0usize;
    let Some(device) = read_device(&plaintext, &mut pos) else {
        eprintln!("[device_registration] deserialization failed from {src}");
        return;
    };

    {
        let mut node = ctx.node.write().unwrap();
        if !node.owner.user.devices.iter().any(|d| d.uuid == device.uuid) {
            println!("[device_registration] new device '{}' registered from {src}", device.alias);
            node.owner.user.devices.push(device);
        }
    }
    ctx.save_node();
    push_data_to_contacts(ctx);
    push_data_to_devices(ctx);
}

// ── Contact exchange payload serialization ────────────────────────────────────
//
// Format (used in both ContactRequest and ContactResponse):
//   [alias: u8 len + bytes]
//   [uuid: 16]
//   [long_term_pk: 32]
//   [device_count: u8]
//     each device: [uuid:16][alias: u8+bytes][grade:u8][sg_rank:u8]
//                  [host_count:u8][each host: u8+bytes]

fn serialize_contact_payload(node: &super::data_models::Node) -> Vec<u8> {
    let mut buf = Vec::new();
    let user = &node.owner.user;
    push_str(&mut buf, &user.alias);
    buf.extend_from_slice(&user.uuid);
    buf.extend_from_slice(&node.owner.key_pair.public_key);
    buf.push(user.devices.len() as u8);
    for d in &user.devices { push_device(&mut buf, d); }
    buf
}

struct ContactPayload {
    alias:      String,
    uuid:       Uuid,
    public_key: PublicKey,
    devices:    Vec<Device>,
}

fn deserialize_contact_payload(data: &[u8]) -> Option<ContactPayload> {
    let mut pos = 0usize;
    let alias       = read_str(data, &mut pos)?;
    let uuid: Uuid  = read_arr(data, &mut pos)?;
    let pk: PublicKey = read_arr(data, &mut pos)?;
    let device_count = *data.get(pos)? as usize; pos += 1;
    let mut devices = Vec::new();
    for _ in 0..device_count { devices.push(read_device(data, &mut pos)?); }
    Some(ContactPayload { alias, uuid, public_key: pk, devices })
}

// ── Contact exchange handlers ─────────────────────────────────────────────────

/// Op 0x33 — Contact request (requester → target's SG).
///
/// Payload (after op byte):
///   [invitation_id: 16][requester_ephem_pk: 32][nonce: 24][encrypted contact card]
///
/// The SG validates the invitation, derives the shared secret, decrypts the
/// requester's contact card, adds them as a contact, and replies with a
/// ContactResponse containing this user's contact card encrypted with the same
/// shared secret.  The invitation is consumed (single-use).
pub fn contact_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    const MIN_LEN: usize = 16 + 32 + 24;
    if buf.len() < MIN_LEN {
        eprintln!("[contact_request] packet too short ({}) from {src}", buf.len());
        return;
    }

    let invitation_id:   Uuid      = buf[0..16].try_into().unwrap();
    let requester_ephem_pk: PublicKey = buf[16..48].try_into().unwrap();
    let nonce:           [u8; 24]  = buf[48..72].try_into().unwrap();
    let ciphertext:      &[u8]     = &buf[72..];

    let (shared_secret, response_payload) = {
        let mut node = ctx.node.write().unwrap();
        let now = SystemTime::now();

        let pos = match node.owner.contact_invitations.iter().position(|inv| inv.id == invitation_id) {
            Some(p) => p,
            None => {
                eprintln!("[contact_request] unknown invitation from {src}");
                return;
            }
        };
        if node.owner.contact_invitations[pos].expires_at <= now {
            eprintln!("[contact_request] expired invitation from {src}");
            node.owner.contact_invitations.remove(pos);
            return;
        }

        let inv = node.owner.contact_invitations.remove(pos);
        let shared_secret: [u8; 32] = x25519_shared(&inv.key_pair.private_key, &requester_ephem_pk);

        let Some(plaintext) = xchacha20_decrypt(&shared_secret, &nonce, ciphertext) else {
            eprintln!("[contact_request] decryption failed from {src}");
            return;
        };
        let Some(data) = deserialize_contact_payload(&plaintext) else {
            eprintln!("[contact_request] deserialization failed from {src}");
            return;
        };

        // Add requester as a contact if not already present.
        if !node.owner.contact_users.iter().any(|c| c.user.uuid == data.uuid) {
            eprintln!("[contact_request] adding contact '{}' from {src}", data.alias);
            node.owner.contact_users.push(Contact {
                user:       User { alias: data.alias, uuid: data.uuid, devices: data.devices },
                public_key: data.public_key,
            });
        }

        let response_payload = serialize_contact_payload(&node);
        (shared_secret, response_payload)
    };

    ctx.save_node();
    push_data_to_contacts(ctx);

    // Encrypt and send ContactResponse.
    let (ciphertext, resp_nonce) = xchacha20_encrypt(&shared_secret, &response_payload);
    let mut pkt = Vec::with_capacity(1 + 24 + ciphertext.len());
    pkt.push(CONTACT_RESPONSE_OP);
    pkt.extend_from_slice(&resp_nonce);
    pkt.extend_from_slice(&ciphertext);
    send(ctx, src, &pkt);

    // Trigger connection maintenance — we have a new contact.
    ctx.scheduler_tx.send(super::action_queue::ScheduleRequest {
        action: super::action_queue::Action::MaintainConnections,
        delay:  Duration::ZERO,
    }).ok();
}

/// Op 0x34 — Contact response (target's SG → requester).
///
/// Payload (after op byte):
///   [nonce: 24][encrypted contact card]
///
/// Decrypts using the pending contact exchange's shared secret and adds the
/// target as a contact.
pub fn contact_response(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 24 {
        eprintln!("[contact_response] packet too short ({}) from {src}", buf.len());
        return;
    }

    let nonce:      [u8; 24] = buf[0..24].try_into().unwrap();
    let ciphertext: &[u8]    = &buf[24..];

    let shared_secret = {
        let node = ctx.node.read().unwrap();
        let Some(pce) = &node.owner.pending_contact_exchange else {
            eprintln!("[contact_response] no pending contact exchange, ignoring from {src}");
            return;
        };
        if SocketAddr::V4(pce.sg_addr) != src {
            eprintln!("[contact_response] unexpected source {src}, ignoring");
            return;
        }
        x25519_shared(&pce.our_ephem_key_pair.private_key, &pce.invitation_pk)
    };

    let Some(plaintext) = xchacha20_decrypt(&shared_secret, &nonce, ciphertext) else {
        eprintln!("[contact_response] decryption failed from {src}");
        return;
    };
    let Some(data) = deserialize_contact_payload(&plaintext) else {
        eprintln!("[contact_response] deserialization failed from {src}");
        return;
    };

    {
        let mut node = ctx.node.write().unwrap();
        if !node.owner.contact_users.iter().any(|c| c.user.uuid == data.uuid) {
            eprintln!("[contact_response] adding contact '{}' from {src}", data.alias);
            node.owner.contact_users.push(Contact {
                user:       User { alias: data.alias, uuid: data.uuid, devices: data.devices },
                public_key: data.public_key,
            });
        }
        node.owner.pending_contact_exchange = None;
    }

    ctx.save_node();
    push_data_to_contacts(ctx);

    // Trigger connection maintenance — we have a new contact.
    ctx.scheduler_tx.send(super::action_queue::ScheduleRequest {
        action: super::action_queue::Action::MaintainConnections,
        delay:  Duration::ZERO,
    }).ok();
}

// ── Contact data sync ─────────────────────────────────────────────────────────
//
// Keeps each user's device and app list up-to-date on all contacts' nodes.
//
// Push payload format (encrypted body of ContactDataPush, op 0x60):
//   [user_uuid: 16]
//   [device_count: u8]
//     each device: [uuid:16][alias: u8+bytes][grade:u8][sg_rank:u8]
//                  [host_count:u8][each host: u8+bytes]
//       [app_count: u8]
//         each approved app: [id: u16 BE][alias: u8+bytes]
//
// Pull request payload (encrypted body of ContactDataPullRequest, op 0x61):
//   [user_uuid: 16]   — identifies the requesting user; connection provides auth

fn serialize_contact_data(node: &super::data_models::Node) -> Vec<u8> {
    let mut buf = Vec::new();
    let user = &node.owner.user;
    buf.extend_from_slice(&user.uuid);
    buf.push(user.devices.len() as u8);
    for d in &user.devices {
        push_device(&mut buf, d);
        let approved: Vec<&Application> = d.applications.iter()
            .filter(|a| a.user_approved)
            .collect();
        buf.push(approved.len() as u8);
        for a in approved {
            buf.extend_from_slice(&a.id.to_be_bytes());
            push_str(&mut buf, &a.alias);
        }
    }
    buf
}

struct ContactData {
    user_uuid: Uuid,
    devices:   Vec<(Device, Vec<(u16, String)>)>, // (device, vec of (app_id, app_alias))
}

fn deserialize_contact_data(data: &[u8]) -> Option<ContactData> {
    let mut pos = 0usize;
    let user_uuid: Uuid    = read_arr(data, &mut pos)?;
    let device_count = *data.get(pos)? as usize; pos += 1;
    let mut devices = Vec::new();
    for _ in 0..device_count {
        let device = read_device(data, &mut pos)?;
        let app_count = *data.get(pos)? as usize; pos += 1;
        let mut apps = Vec::new();
        for _ in 0..app_count {
            let id_bytes: [u8; 2] = read_arr(data, &mut pos)?;
            let id    = u16::from_be_bytes(id_bytes);
            let alias = read_str(data, &mut pos)?;
            apps.push((id, alias));
        }
        devices.push((device, apps));
    }
    Some(ContactData { user_uuid, devices })
}

/// Send a ContactDataPush to the top-ranked reachable SG of every contact.
/// Silently skips contacts with no active connection — the daily pull will catch them.
fn push_data_to_contacts(ctx: &WorkerContext) {
    let node = ctx.node.read().unwrap();
    // Only SGs originate pushes — DGs don't have direct connections to contact SGs.
    let local_uuid = node.device_uuid;
    let local_device = node.owner.user.devices.iter().find(|d| d.uuid == local_uuid);
    if !local_device.map(|d| matches!(d.grade, DeviceGrade::SG)).unwrap_or(false) {
        return;
    }

    let payload = serialize_contact_data(&node);

    let mut packets: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
    for contact in &node.owner.contact_users {
        // Find the contact's top-ranked SG that we have an active connection to.
        let mut sgs: Vec<&Device> = contact.user.devices.iter()
            .filter(|d| matches!(d.grade, DeviceGrade::SG))
            .filter(|d| node.owner.active_connections.values().any(|c| c.device_uuid == d.uuid))
            .collect();
        sgs.sort_by_key(|d| d.sg_rank.unwrap_or(u32::MAX));

        let Some(sg) = sgs.first() else { continue };
        let Some(conn) = node.owner.active_connections.values()
            .find(|c| c.device_uuid == sg.uuid)
        else { continue };

        let pkt = build_encrypted_packet(CONTACT_DATA_PUSH_OP, conn, &payload);
        println!("[push_data_to_contacts] pushing to {} at {}", contact.user.alias, conn.peer_addr);
        packets.push((pkt, conn.peer_addr));
    }
    drop(node);

    for (pkt, dest) in packets {
        send(ctx, dest, &pkt);
    }
}

/// Apply received contact data, updating the matching contact's device and app lists.
fn apply_contact_data(data: ContactData, ctx: &WorkerContext) {
    let mut node = ctx.node.write().unwrap();
    let Some(contact) = node.owner.contact_users.iter_mut()
        .find(|c| c.user.uuid == data.user_uuid)
    else {
        eprintln!("[contact_data] received data for unknown contact {:?}", data.user_uuid);
        return;
    };

    contact.user.devices = data.devices.into_iter().map(|(mut dev, apps)| {
        dev.applications = apps.into_iter().map(|(id, alias)| Application {
            id,
            alias,
            protocol:      String::new(),
            host:          "0.0.0.0:0".parse().unwrap(),
            user_approved: true,
            token:         [0u8; 16],
        }).collect();
        dev
    }).collect();
}

/// Op 0x60 — Contact data push (SG → contact's SG).
///
/// Encrypted body: [user_uuid:16][device_count:u8][ ...devices+apps... ]
///
/// Updates the sender's entry in the receiver's contact list.
pub fn contact_data_push(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    println!("[contact_data_push] handling from {src} (len={})", buf.len());
    let node = ctx.node.read().unwrap();
    let Some(plaintext) = decrypt_packet_body(&node, &buf) else {
        eprintln!("[contact_data_push] decryption failed from {src}");
        return;
    };
    drop(node);

    let Some(data) = deserialize_contact_data(&plaintext) else {
        eprintln!("[contact_data_push] deserialization failed from {src}");
        return;
    };

    println!("[contact_data_push] received from {src}");
    apply_contact_data(data, ctx);
    ctx.save_node();
    push_data_to_devices(ctx);
}

/// Op 0x61 — Contact data pull request (SG → contact's SG).
///
/// Encrypted body: [user_uuid: 16]
///
/// The receiver replies with a ContactDataPush containing its current data.
pub fn contact_data_pull_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let (plaintext, payload) = {
        let node = ctx.node.read().unwrap();
        let Some(pt) = decrypt_packet_body(&node, &buf) else {
            eprintln!("[contact_data_pull_request] decryption failed from {src}");
            return;
        };
        let payload = serialize_contact_data(&node);
        (pt, payload)
    };

    if plaintext.len() < 16 {
        eprintln!("[contact_data_pull_request] body too short from {src}");
        return;
    }

    // Look up the connection the request arrived on so we can reply.
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);
    let reply_pkt = {
        let node = ctx.node.read().unwrap();
        let Some(conn) = node.owner.active_connections.get(&conn_id) else {
            eprintln!("[contact_data_pull_request] no active connection for id {conn_id}");
            return;
        };
        build_encrypted_packet(CONTACT_DATA_PUSH_OP, conn, &payload)
    };

    send(ctx, src, &reply_pkt);
}

/// Scheduled daily: send a ContactDataPullRequest to the top SG of every contact.
pub fn sync_contacts(ctx: &WorkerContext) {
    let node = ctx.node.read().unwrap();

    // Only SGs run this — DGs don't have direct connections to contact SGs.
    let local_uuid = node.device_uuid;
    let local_device = node.owner.user.devices.iter().find(|d| d.uuid == local_uuid);
    if !local_device.map(|d| matches!(d.grade, DeviceGrade::SG)).unwrap_or(false) {
        return;
    }

    let our_uuid = node.owner.user.uuid;
    let mut packets: Vec<(Vec<u8>, SocketAddr)> = Vec::new();

    for contact in &node.owner.contact_users {
        let mut sgs: Vec<&Device> = contact.user.devices.iter()
            .filter(|d| matches!(d.grade, DeviceGrade::SG))
            .filter(|d| node.owner.active_connections.values().any(|c| c.device_uuid == d.uuid))
            .collect();
        sgs.sort_by_key(|d| d.sg_rank.unwrap_or(u32::MAX));

        let Some(sg) = sgs.first() else { continue };
        let Some(conn) = node.owner.active_connections.values()
            .find(|c| c.device_uuid == sg.uuid)
        else { continue };

        let pkt = build_encrypted_packet(CONTACT_DATA_PULL_REQ_OP, conn, &our_uuid);
        packets.push((pkt, conn.peer_addr));
    }
    drop(node);

    for (pkt, dest) in packets {
        send(ctx, dest, &pkt);
    }
}

// ── Device data sync (ops 0x62 / 0x63) ───────────────────────────────────────
//
// Keeps all of a user's own devices current with the latest device list and
// contact list.  The SG is authoritative; DGs pull from it and receive pushes.
//
// Push payload format (encrypted body of DeviceDataPush, op 0x62):
//   [device_count: u8]
//     each device: [uuid:16][alias: u8+bytes][grade:u8][sg_rank:u8]
//                  [host_count:u8][each host: u8+bytes]
//   [contact_count: u8]
//     each contact:
//       [user_alias: u8+bytes][user_uuid: 16][contact_pk: 32]
//       [device_count: u8]
//         each device: [uuid:16][alias: u8+bytes][grade:u8][sg_rank:u8]
//                      [host_count:u8][each host: u8+bytes]
//           [app_count: u8]
//             each app: [id: u16 BE][alias: u8+bytes]
//
// Pull request payload (encrypted body of DeviceDataPullRequest, op 0x63):
//   (empty — active connection provides authentication)

fn serialize_device_sync_payload(node: &super::data_models::Node) -> Vec<u8> {
    let mut buf = Vec::new();
    let user = &node.owner.user;

    // Own device list with apps.
    buf.push(user.devices.len() as u8);
    for d in &user.devices {
        push_device(&mut buf, d);
        buf.push(d.applications.len() as u8);
        for a in &d.applications {
            buf.extend_from_slice(&a.id.to_be_bytes());
            push_str(&mut buf, &a.alias);
        }
    }

    // Contact list with devices and apps.
    buf.push(node.owner.contact_users.len() as u8);
    for contact in &node.owner.contact_users {
        push_str(&mut buf, &contact.user.alias);
        buf.extend_from_slice(&contact.user.uuid);
        buf.extend_from_slice(&contact.public_key);
        buf.push(contact.user.devices.len() as u8);
        for d in &contact.user.devices {
            push_device(&mut buf, d);
            let approved: Vec<&Application> = d.applications.iter()
                .filter(|a| a.user_approved)
                .collect();
            buf.push(approved.len() as u8);
            for a in approved {
                buf.extend_from_slice(&a.id.to_be_bytes());
                push_str(&mut buf, &a.alias);
            }
        }
    }
    buf
}

struct DeviceSyncData {
    devices:  Vec<Device>,
    contacts: Vec<Contact>,
}

fn deserialize_device_sync_payload(data: &[u8]) -> Option<DeviceSyncData> {
    let mut pos = 0usize;

    let device_count = *data.get(pos)? as usize; pos += 1;
    let mut devices = Vec::new();
    for _ in 0..device_count {
        let mut dev = read_device(data, &mut pos)?;
        let app_count = *data.get(pos)? as usize; pos += 1;
        for _ in 0..app_count {
            let id_bytes: [u8; 2] = read_arr(data, &mut pos)?;
            let id    = u16::from_be_bytes(id_bytes);
            let alias = read_str(data, &mut pos)?;
            dev.applications.push(Application {
                id,
                alias,
                protocol:      String::new(),
                host:          "0.0.0.0:0".parse().unwrap(),
                user_approved: true,
                token:         [0u8; 16],
            });
        }
        devices.push(dev);
    }

    let contact_count = *data.get(pos)? as usize; pos += 1;
    let mut contacts = Vec::new();
    for _ in 0..contact_count {
        let user_alias  = read_str(data, &mut pos)?;
        let user_uuid: Uuid      = read_arr(data, &mut pos)?;
        let public_key: PublicKey = read_arr(data, &mut pos)?;
        let dev_count   = *data.get(pos)? as usize; pos += 1;
        let mut contact_devices = Vec::new();
        for _ in 0..dev_count {
            let mut dev = read_device(data, &mut pos)?;
            let app_count = *data.get(pos)? as usize; pos += 1;
            for _ in 0..app_count {
                let id_bytes: [u8; 2] = read_arr(data, &mut pos)?;
                let id    = u16::from_be_bytes(id_bytes);
                let alias = read_str(data, &mut pos)?;
                dev.applications.push(Application {
                    id,
                    alias,
                    protocol:      String::new(),
                    host:          "0.0.0.0:0".parse().unwrap(),
                    user_approved: true,
                    token:         [0u8; 16],
                });
            }
            contact_devices.push(dev);
        }
        contacts.push(Contact {
            public_key,
            user: User { alias: user_alias, uuid: user_uuid, devices: contact_devices },
        });
    }
    Some(DeviceSyncData { devices, contacts })
}

/// Apply received device sync data to the node.
/// Replaces all device and contact entries from the SG.  The local device's
/// own application list is preserved: the SG's view of it may be stale if an
/// app was just registered locally before the push arrived.
fn apply_device_sync_data(data: DeviceSyncData, ctx: &WorkerContext) {
    let mut node = ctx.node.write().unwrap();
    let local_uuid = node.device_uuid;

    // Preserve own apps before replacing the device list; the local device is
    // always authoritative for its own apps.
    let local_apps = node.owner.user.devices.iter()
        .find(|d| d.uuid == local_uuid)
        .map(|d| d.applications.clone())
        .unwrap_or_default();

    node.owner.user.devices  = data.devices;
    node.owner.contact_users = data.contacts;

    // Restore own app list.
    if let Some(d) = node.owner.user.devices.iter_mut().find(|d| d.uuid == local_uuid) {
        d.applications = local_apps;
    }
}

/// Parse an app list from a pull-request body: `[count: u8][ [id: u16][alias: u8+str] ... ]`.
/// Returns an empty list if the body is empty or malformed.
fn parse_app_list(data: &[u8]) -> Vec<Application> {
    if data.is_empty() { return Vec::new(); }
    let mut pos = 0usize;
    let count = data[pos] as usize; pos += 1;
    let mut apps = Vec::new();
    for _ in 0..count {
        let id_bytes: [u8; 2] = match read_arr(data, &mut pos) { Some(b) => b, None => break };
        let id    = u16::from_be_bytes(id_bytes);
        let alias = match read_str(data, &mut pos) { Some(s) => s, None => break };
        apps.push(Application {
            id,
            alias,
            protocol:      String::new(),
            host:          "0.0.0.0:0".parse().unwrap(),
            user_approved: true,
            token:         [0u8; 16],
        });
    }
    apps
}

/// Serialize the local device's app list for inclusion in a pull request body.
fn serialize_own_app_list(node: &super::data_models::Node) -> Vec<u8> {
    let local_uuid = node.device_uuid;
    let apps: Vec<&Application> = node.owner.user.devices.iter()
        .find(|d| d.uuid == local_uuid)
        .map(|d| d.applications.iter().collect())
        .unwrap_or_default();
    let mut buf = Vec::new();
    buf.push(apps.len() as u8);
    for a in apps {
        buf.extend_from_slice(&a.id.to_be_bytes());
        push_str(&mut buf, &a.alias);
    }
    buf
}

/// Send a DeviceDataPush (0x62) to every own-user device (excluding self) that
/// has an active connection.  Only called on SGs — DGs don't have connections
/// to other own-user devices.
fn push_data_to_devices(ctx: &WorkerContext) {
    let node = ctx.node.read().unwrap();

    // Guard: only SGs push.
    let local_uuid = node.device_uuid;
    let is_sg = node.owner.user.devices.iter()
        .find(|d| d.uuid == local_uuid)
        .map(|d| matches!(d.grade, DeviceGrade::SG))
        .unwrap_or(false);
    if !is_sg { return; }

    let payload = serialize_device_sync_payload(&node);

    // Build packets for every own-user device (except self) that has an active connection.
    let own_device_uuids: Vec<Uuid> = node.owner.user.devices.iter()
        .filter(|d| d.uuid != local_uuid)
        .map(|d| d.uuid)
        .collect();

    let mut packets: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
    for uuid in &own_device_uuids {
        let Some(conn) = node.owner.active_connections.values()
            .find(|c| c.device_uuid == *uuid)
        else { continue };
        let pkt = build_encrypted_packet(DEVICE_DATA_PUSH_OP, conn, &payload);
        packets.push((pkt, conn.peer_addr));
    }
    drop(node);

    for (pkt, dest) in packets {
        send(ctx, dest, &pkt);
    }
}

/// Op 0x62 — Device data push (SG → own device).
///
/// Encrypted body: device list + full contact list.
///
/// Updates the receiver's own device list and contact list.
pub fn device_data_push(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let node = ctx.node.read().unwrap();
    let Some(plaintext) = decrypt_packet_body(&node, &buf) else {
        eprintln!("[device_data_push] decryption failed from {src}");
        return;
    };
    drop(node);

    let Some(data) = deserialize_device_sync_payload(&plaintext) else {
        eprintln!("[device_data_push] deserialization failed from {src}");
        return;
    };

    apply_device_sync_data(data, ctx);
    ctx.save_node();
}

/// Op 0x63 — Device data pull request (device → own SG).
///
/// Encrypted body: `[app_count: u8][ [id: u16][alias: u8+str] ... ]`
///
/// The sender includes its current app list so the SG can update its record.
/// The SG replies with a DeviceDataPush containing the full device and contact lists.
pub fn device_data_pull_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    // Decrypt and parse the sender's app list.
    let sender_apps: Vec<Application> = {
        let node = ctx.node.read().unwrap();
        let Some(plaintext) = decrypt_packet_body(&node, &buf) else {
            eprintln!("[device_data_pull_request] decryption failed from {src}");
            return;
        };
        parse_app_list(&plaintext)
    };

    // Update the sender device's app list in our node so the reply payload reflects it.
    {
        let mut node = ctx.node.write().unwrap();
        let sender_uuid = node.owner.active_connections.get(&conn_id).map(|c| c.device_uuid);
        if let Some(uuid) = sender_uuid {
            if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == uuid) {
                dev.applications = sender_apps;
            }
        }
    }
    ctx.save_node();
    push_data_to_contacts(ctx);

    let payload = {
        let node = ctx.node.read().unwrap();
        serialize_device_sync_payload(&node)
    };

    let reply_pkt = {
        let node = ctx.node.read().unwrap();
        let Some(conn) = node.owner.active_connections.get(&conn_id) else {
            eprintln!("[device_data_pull_request] no active connection for id {conn_id}");
            return;
        };
        build_encrypted_packet(DEVICE_DATA_PUSH_OP, conn, &payload)
    };

    send(ctx, src, &reply_pkt);
}

/// Scheduled daily: push device and contact data to all own devices (SG),
/// or pull from own SG (DG).
pub fn sync_devices(ctx: &WorkerContext) {
    let node = ctx.node.read().unwrap();
    let local_uuid = node.device_uuid;
    let is_sg = node.owner.user.devices.iter()
        .find(|d| d.uuid == local_uuid)
        .map(|d| matches!(d.grade, DeviceGrade::SG))
        .unwrap_or(false);

    if is_sg {
        drop(node);
        push_data_to_devices(ctx);
        push_data_to_contacts(ctx);
        return;
    }

    // DG: send a pull request to the top-ranked own SG with an active connection.
    let mut own_sgs: Vec<&Device> = node.owner.user.devices.iter()
        .filter(|d| matches!(d.grade, DeviceGrade::SG))
        .filter(|d| node.owner.active_connections.values().any(|c| c.device_uuid == d.uuid))
        .collect();
    own_sgs.sort_by_key(|d| d.sg_rank.unwrap_or(u32::MAX));

    let Some(sg) = own_sgs.first() else { return };
    let Some(conn) = node.owner.active_connections.values()
        .find(|c| c.device_uuid == sg.uuid)
    else { return };

    // Pull request body carries the local device's app list so the SG can
    // update its record before replying.
    let body = serialize_own_app_list(&node);
    let pkt  = build_encrypted_packet(DEVICE_DATA_PULL_REQ_OP, conn, &body);
    let dest = conn.peer_addr;
    drop(node);

    send(ctx, dest, &pkt);
}

// ── Sync v1 (ops 0x70 – 0x74) ────────────────────────────────────────────────
//
// Version-aware sync protocol described in `descriptions/data sync.md`.
// Phase 4 lands the writer-side acceptance pipeline for AddApplication;
// other Change variants and the originator-side ack handling land in 5–7.
//
// Encrypted body layouts:
//
//   SyncWriteRequest    (0x70)  [change_kind:1][change_payload:var]
//   SyncWriteAck        (0x71)  [result:1][private_version:28][public_version:28]
//   SyncUpdateAvailable (0x72)  [scope:1][version:28]
//   SyncPullRequest     (0x73)  [scope:1][last_seen_version:28]
//   SyncPullResponse    (0x74)  [scope:1][result:1][version:28][state:var]
//
// Where `version:28` = [writer_sg_uuid:16][epoch:u32 BE][seq:u64 BE].
// WriteAck always returns the writer's current versions for both scopes so
// originators have an authoritative pin regardless of which scope the change
// touched (or whether it was rejected). Result bytes:
//   WriteAck:    0=accepted, 1=not_writer, 2=validation_error
//   PullResponse: 0=NoUpdates, 1=FullState  (delta encoding deferred)

const SCOPE_PRIVATE: u8 = 0;
const SCOPE_PUBLIC:  u8 = 1;

const WRITE_ACK_OK:                u8 = 0;
const WRITE_ACK_NOT_WRITER:        u8 = 1;
const WRITE_ACK_VALIDATION_ERROR:  u8 = 2;

const PULL_RESULT_NO_UPDATES: u8 = 0;
const PULL_RESULT_FULL_STATE: u8 = 1;

/// Wire size of `SyncVersion` on the wire: 16 (uuid) + 4 (epoch) + 8 (seq).
const SYNC_VERSION_WIRE_LEN: usize = 28;

fn write_scope(buf: &mut Vec<u8>, scope: Scope) {
    buf.push(match scope {
        Scope::Private => SCOPE_PRIVATE,
        Scope::Public  => SCOPE_PUBLIC,
    });
}

fn read_scope(data: &[u8], pos: &mut usize) -> Option<Scope> {
    let b = *data.get(*pos)?;
    *pos += 1;
    match b {
        SCOPE_PRIVATE => Some(Scope::Private),
        SCOPE_PUBLIC  => Some(Scope::Public),
        _             => None,
    }
}

fn write_sync_version(buf: &mut Vec<u8>, v: &SyncVersion) {
    buf.extend_from_slice(&v.writer_sg_uuid);
    buf.extend_from_slice(&v.epoch.to_be_bytes());
    buf.extend_from_slice(&v.seq.to_be_bytes());
}

fn read_sync_version(data: &[u8], pos: &mut usize) -> Option<SyncVersion> {
    let writer_sg_uuid: Uuid     = read_arr(data, pos)?;
    let epoch_bytes:    [u8; 4]  = read_arr(data, pos)?;
    let seq_bytes:      [u8; 8]  = read_arr(data, pos)?;
    Some(SyncVersion {
        writer_sg_uuid,
        epoch: u32::from_be_bytes(epoch_bytes),
        seq:   u64::from_be_bytes(seq_bytes),
    })
}

// ── Change types ──────────────────────────────────────────────────────────────
//
// A `Change` is the unit of state mutation the writer SG accepts. Each variant
// declares which scope(s) it touches via `change_scopes`, so the writer bumps
// the right counter(s) on accept. Wire `change_kind` is a single byte — the
// payload after it is variant-specific.

const CHANGE_KIND_ADD_APPLICATION: u8 = 0x01;

/// State mutations that flow through the writer SG.
///
/// `AddApplication` is the only variant in v1 of v1; remove/update/contact
/// variants land in follow-up phases without architectural changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Public-scope: add an app entry (id + alias + approval flag) to the
    /// device identified by `device_uuid` in the user's device list. The
    /// originating DG keeps the private fields (token, host, port) locally —
    /// they are not shared with the writer SG or peers.
    AddApplication {
        device_uuid: Uuid,
        app_id:      u16,
        app_alias:   String,
    },
}

/// Returns the scope(s) a given change is expected to bump on accept. Used
/// by `apply_change_locally` and (in phase 5) by the notify fan-out to know
/// which `UpdateAvailable` notifications to emit.
fn change_scopes(c: &Change) -> &'static [Scope] {
    match c {
        // Only the public fields (id+alias) are recorded at the writer; the
        // originating DG's private fields stay local.
        Change::AddApplication { .. } => &[Scope::Public],
    }
}

fn serialize_change(c: &Change) -> Vec<u8> {
    let mut buf = Vec::new();
    match c {
        Change::AddApplication { device_uuid, app_id, app_alias } => {
            buf.push(CHANGE_KIND_ADD_APPLICATION);
            buf.extend_from_slice(device_uuid);
            buf.extend_from_slice(&app_id.to_be_bytes());
            push_str(&mut buf, app_alias);
        }
    }
    buf
}

fn deserialize_change(data: &[u8]) -> Option<Change> {
    let mut pos = 0usize;
    let kind = *data.get(pos)?;
    pos += 1;
    match kind {
        CHANGE_KIND_ADD_APPLICATION => {
            let device_uuid: Uuid = read_arr(data, &mut pos)?;
            let id_bytes:  [u8; 2] = read_arr(data, &mut pos)?;
            let app_id    = u16::from_be_bytes(id_bytes);
            let app_alias = read_str(data, &mut pos)?;
            Some(Change::AddApplication { device_uuid, app_id, app_alias })
        }
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteError {
    /// No reachable own SG. Caller should report the error to the requesting app.
    Unreachable,
    /// Change refers to state the writer doesn't have (e.g., unknown device_uuid).
    Validation(String),
}

/// Apply a `Change` to local state, bump the relevant scope version(s), and
/// queue the result for persistence.
///
/// Idempotent at the data level: calling with a change that's already
/// reflected (e.g., AddApplication for an `app_id` that already exists on the
/// device) is a no-op and does NOT bump versions — so retries don't inflate
/// the seq counter.
///
/// Returns the (private, public) versions after the operation (current values
/// when no-op, post-bump values when applied).
fn apply_change_locally(
    change: &Change,
    writer_uuid: Uuid,
    ctx: &WorkerContext,
) -> Result<(SyncVersion, SyncVersion), WriteError> {
    let mut node = ctx.node.write().unwrap();
    let applied = match change {
        Change::AddApplication { device_uuid, app_id, app_alias } => {
            let dev = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == *device_uuid)
                .ok_or_else(|| WriteError::Validation(format!(
                    "unknown device_uuid {device_uuid:?}"
                )))?;
            if dev.applications.iter().any(|a| a.id == *app_id) {
                false
            } else {
                dev.applications.push(Application {
                    id:            *app_id,
                    alias:         app_alias.clone(),
                    protocol:      String::new(),
                    // Private-scope fields stay zero on the writer SG — the
                    // originating DG holds the real token/host locally.
                    host:          "0.0.0.0:0".parse().unwrap(),
                    user_approved: true,
                    token:         [0u8; 16],
                });
                true
            }
        }
    };

    if applied {
        for scope in change_scopes(change) {
            node.owner.bump_version(*scope, writer_uuid);
        }
    }
    let private = node.owner.private_version;
    let public  = node.owner.public_version;
    drop(node);
    if applied {
        ctx.save_node();
    }
    Ok((private, public))
}

/// Drive a state change through the writer-SG model. Used by any node that
/// wants to mutate state (UI, app-approval flow in phase 7, etc.):
///
/// - `WriterTarget::Local`  — apply locally; returns `Ok(())` after persist.
/// - `WriterTarget::Remote` — send a SyncWriteRequest to the elected writer
///   and return `Ok(())` immediately. The matching ack arrives later via
///   `sync_write_ack`. Phase 5 will turn the ack into "trigger a pull to
///   refresh local state and clear pending UI."
/// - `WriterTarget::Unreachable` — return `Err(Unreachable)`.
pub fn request_change(change: Change, ctx: &WorkerContext) -> Result<(), WriteError> {
    let target = {
        let node = ctx.node.read().unwrap();
        find_writer_sg(&node)
    };
    match target {
        WriterTarget::Local => {
            let local_uuid = ctx.node.read().unwrap().device_uuid;
            apply_change_locally(&change, local_uuid, ctx)?;
            // Originator semantics: advance the scope's version even when
            // `apply_change_locally` was a data-level no-op. This is the
            // common path when the originator pre-mutated the local record
            // (e.g. `app_register` adding the app with token+host before
            // calling `request_change` to publish id+alias). The receiver
            // path (`sync_write_request`) keeps the stricter
            // bump-only-on-actual-mutation rule for retry idempotency.
            let scopes_to_bump = change_scopes(&change);
            let (post_priv, post_pub) = {
                let mut node = ctx.node.write().unwrap();
                for &scope in scopes_to_bump {
                    node.owner.bump_version(scope, local_uuid);
                }
                (node.owner.private_version, node.owner.public_version)
            };
            ctx.save_node();
            let bumped: Vec<Scope> = scopes_to_bump.iter().copied().collect();
            notify_own_peers(&bumped, post_priv, post_pub, ctx);
            Ok(())
        }
        WriterTarget::Remote(writer_uuid) => {
            send_sync_write_request(&change, writer_uuid, ctx);
            Ok(())
        }
        WriterTarget::Unreachable => Err(WriteError::Unreachable),
    }
}

/// Compare pre/post versions to determine which scopes were bumped by an
/// `apply_change_locally` call. Empty vec means the apply was a no-op
/// (idempotent retry — see the AddApplication idempotency contract).
fn bumped_scopes(
    pre_priv: SyncVersion,
    pre_pub:  SyncVersion,
    post_priv: SyncVersion,
    post_pub:  SyncVersion,
) -> Vec<Scope> {
    let mut out = Vec::new();
    if pre_priv != post_priv { out.push(Scope::Private); }
    if pre_pub  != post_pub  { out.push(Scope::Public);  }
    out
}

/// Fan out `SyncUpdateAvailable` notifications to every own-user peer device
/// that this node has an active connection to, for each bumped scope.
///
/// Phase 5 only notifies own-user devices. Cross-user notification (writer SG
/// → contacts' SGs for public-scope changes) lands in a follow-up phase.
fn notify_own_peers(
    bumped: &[Scope],
    private: SyncVersion,
    public:  SyncVersion,
    ctx:     &WorkerContext,
) {
    let packets: Vec<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        let local_uuid = node.device_uuid;
        let own_uuids: Vec<Uuid> = node.owner.user.devices.iter()
            .filter(|d| d.uuid != local_uuid)
            .map(|d| d.uuid)
            .collect();
        let mut out = Vec::new();
        for &scope in bumped {
            let v = match scope { Scope::Private => private, Scope::Public => public };
            for uuid in &own_uuids {
                let Some(conn) = node.owner.active_connections.values()
                    .find(|c| c.device_uuid == *uuid)
                else { continue };
                let mut body = Vec::with_capacity(1 + SYNC_VERSION_WIRE_LEN);
                write_scope(&mut body, scope);
                write_sync_version(&mut body, &v);
                let pkt = build_encrypted_packet(SYNC_UPDATE_AVAILABLE_OP, conn, &body);
                out.push((pkt, conn.peer_addr));
            }
        }
        out
    };
    for (pkt, dest) in packets {
        send(ctx, dest, &pkt);
    }
}

/// Periodic / on-reconnect pull entry point. Called by the scheduler on its
/// `SYNC_PULL_INTERVAL` tick and by `connect_ack` immediately after a fresh
/// active connection lands. Sends one `SyncPullRequest` per scope to the
/// elected writer SG; no-op if this node is itself the writer (`Local`) or
/// has no reachable own SG (`Unreachable`).
pub fn sync_pull(ctx: &WorkerContext) {
    let (target, last_priv, last_pub) = {
        let node = ctx.node.read().unwrap();
        (find_writer_sg(&node), node.owner.private_version, node.owner.public_version)
    };
    let writer_uuid = match target {
        WriterTarget::Local       => return,
        WriterTarget::Unreachable => {
            println!("[sync_pull] no reachable writer SG — skipping");
            return;
        }
        WriterTarget::Remote(u)   => u,
    };

    let conn_id = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.values()
            .find(|c| c.device_uuid == writer_uuid)
            .map(|c| c.id)
    };
    let Some(conn_id) = conn_id else {
        eprintln!("[sync_pull] writer {writer_uuid:?} has no active connection");
        return;
    };

    send_pull_request(Scope::Public,  last_pub,  conn_id, ctx);
    send_pull_request(Scope::Private, last_priv, conn_id, ctx);
}

/// Send a `SyncPullRequest` for `scope` to a specific peer connection.
/// Used both as the immediate response to `SyncUpdateAvailable` and by the
/// periodic / on-reconnect pull (`sync_pull`).
fn send_pull_request(scope: Scope, last_seen: SyncVersion, conn_id: u16, ctx: &WorkerContext) {
    let mut body = Vec::with_capacity(1 + SYNC_VERSION_WIRE_LEN);
    write_scope(&mut body, scope);
    write_sync_version(&mut body, &last_seen);

    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.get(&conn_id)
            .map(|conn| (
                build_encrypted_packet(SYNC_PULL_REQUEST_OP, conn, &body),
                conn.peer_addr,
            ))
    };
    let Some((pkt, addr)) = pkt_and_addr else {
        eprintln!("[send_pull_request] no active connection {conn_id}");
        return;
    };
    send(ctx, addr, &pkt);
}

// ── Scoped state serialization ───────────────────────────────────────────────
//
// Wire format for a Public-scope state blob (carried in a SyncPullResponse
// when the writer has new state for the puller):
//
//   [user_alias: u8+bytes]
//   [user_uuid: 16]
//   [device_count: u8]
//     each device:
//       [uuid:16][alias: u8+bytes][grade:u8][sg_rank:u8]
//       [host_count:u8] each [host: u8+bytes]
//       [app_count: u8] each [id: u16 BE][alias: u8+bytes]
//   [contact_count: u8]
//     each contact:
//       [user_alias: u8+bytes][user_uuid:16][public_key:32]
//       [device_count: u8] each device (same shape as own devices, apps included)
//
// Apps in the Public-scope blob carry only `id` and `alias`; the originating
// DG's private fields (`token`, `host`, `protocol`) stay local and are
// merged in by `apply_public_state` rather than overwritten.
//
// The Private-scope state blob is intentionally empty in Phase 5 — no
// Change variant currently bumps Private. Future phases (RemoveApplication,
// invitation sync) will populate it.

fn serialize_public_state(node: &super::data_models::Node) -> Vec<u8> {
    let mut buf = Vec::new();
    let user = &node.owner.user;
    push_str(&mut buf, &user.alias);
    buf.extend_from_slice(&user.uuid);

    buf.push(user.devices.len().min(u8::MAX as usize) as u8);
    for d in user.devices.iter().take(u8::MAX as usize) {
        push_device(&mut buf, d);
        buf.push(d.applications.len().min(u8::MAX as usize) as u8);
        for a in d.applications.iter().take(u8::MAX as usize) {
            buf.extend_from_slice(&a.id.to_be_bytes());
            push_str(&mut buf, &a.alias);
        }
    }

    buf.push(node.owner.contact_users.len().min(u8::MAX as usize) as u8);
    for contact in node.owner.contact_users.iter().take(u8::MAX as usize) {
        push_str(&mut buf, &contact.user.alias);
        buf.extend_from_slice(&contact.user.uuid);
        buf.extend_from_slice(&contact.public_key);
        buf.push(contact.user.devices.len().min(u8::MAX as usize) as u8);
        for d in contact.user.devices.iter().take(u8::MAX as usize) {
            push_device(&mut buf, d);
            buf.push(d.applications.len().min(u8::MAX as usize) as u8);
            for a in d.applications.iter().take(u8::MAX as usize) {
                buf.extend_from_slice(&a.id.to_be_bytes());
                push_str(&mut buf, &a.alias);
            }
        }
    }
    buf
}

/// Parse a Public-state blob and apply it to the node, merging additively:
///
/// - Own user `alias`/`uuid`: replace.
/// - Own devices, by `uuid`: existing entries get public fields refreshed
///   (alias/grade/sg_rank/hosts) but their local app `token`/`host`/
///   `protocol` stay untouched. Apps are merged by id — incoming alias
///   overwrites; new apps land with zeroed token/host. Apps not in the
///   incoming blob are NOT removed (RemoveApplication change is not in Phase 5).
/// - Contacts, by `uuid`: existing get updated public fields, new are added,
///   none removed.
///
/// Returns `true` on a clean apply, `false` if the blob is malformed (in
/// which case node state is unchanged).
fn apply_public_state(state: &[u8], ctx: &WorkerContext) -> bool {
    let mut pos = 0usize;

    let Some(user_alias) = read_str(state, &mut pos) else { return false; };
    let Some(user_uuid)  = read_arr::<16>(state, &mut pos) else { return false; };

    let Some(&dev_count) = state.get(pos) else { return false; };
    pos += 1;

    // Parse all devices into a temp vec first so a malformed blob can't
    // half-apply.
    struct ParsedDevice {
        device: Device,
        apps:   Vec<(u16, String)>,
    }
    let mut devices: Vec<ParsedDevice> = Vec::with_capacity(dev_count as usize);
    for _ in 0..dev_count {
        let Some(d) = read_device(state, &mut pos) else { return false; };
        let Some(&app_count) = state.get(pos) else { return false; };
        pos += 1;
        let mut apps = Vec::with_capacity(app_count as usize);
        for _ in 0..app_count {
            let Some(id_bytes) = read_arr::<2>(state, &mut pos) else { return false; };
            let Some(alias)    = read_str(state, &mut pos)       else { return false; };
            apps.push((u16::from_be_bytes(id_bytes), alias));
        }
        devices.push(ParsedDevice { device: d, apps });
    }

    let Some(&contact_count) = state.get(pos) else { return false; };
    pos += 1;

    struct ParsedContact {
        alias:      String,
        uuid:       Uuid,
        public_key: PublicKey,
        devices:    Vec<ParsedDevice>,
    }
    let mut contacts: Vec<ParsedContact> = Vec::with_capacity(contact_count as usize);
    for _ in 0..contact_count {
        let Some(alias)      = read_str(state, &mut pos) else { return false; };
        let Some(uuid)       = read_arr::<16>(state, &mut pos) else { return false; };
        let Some(public_key) = read_arr::<32>(state, &mut pos) else { return false; };
        let Some(&dc) = state.get(pos) else { return false; };
        pos += 1;
        let mut devs = Vec::with_capacity(dc as usize);
        for _ in 0..dc {
            let Some(d) = read_device(state, &mut pos) else { return false; };
            let Some(&ac) = state.get(pos) else { return false; };
            pos += 1;
            let mut apps = Vec::with_capacity(ac as usize);
            for _ in 0..ac {
                let Some(id_bytes) = read_arr::<2>(state, &mut pos) else { return false; };
                let Some(alias)    = read_str(state, &mut pos)       else { return false; };
                apps.push((u16::from_be_bytes(id_bytes), alias));
            }
            devs.push(ParsedDevice { device: d, apps });
        }
        contacts.push(ParsedContact { alias, uuid, public_key, devices: devs });
    }

    // Apply (merge additively).
    let mut node = ctx.node.write().unwrap();
    node.owner.user.alias = user_alias;
    node.owner.user.uuid  = user_uuid;

    for parsed in devices {
        let p = parsed.device;
        let apps = parsed.apps;
        if let Some(existing) = node.owner.user.devices.iter_mut().find(|d| d.uuid == p.uuid) {
            existing.alias   = p.alias;
            existing.grade   = p.grade;
            existing.sg_rank = p.sg_rank;
            existing.hosts   = p.hosts;
            for (id, alias) in apps {
                if let Some(local_app) = existing.applications.iter_mut().find(|a| a.id == id) {
                    local_app.alias = alias;
                    // token/host/protocol/user_approved preserved
                } else {
                    existing.applications.push(Application {
                        id,
                        alias,
                        protocol:      String::new(),
                        host:          "0.0.0.0:0".parse().unwrap(),
                        user_approved: true,
                        token:         [0u8; 16],
                    });
                }
            }
        } else {
            let mut new_dev = p;
            for (id, alias) in apps {
                new_dev.applications.push(Application {
                    id,
                    alias,
                    protocol:      String::new(),
                    host:          "0.0.0.0:0".parse().unwrap(),
                    user_approved: true,
                    token:         [0u8; 16],
                });
            }
            node.owner.user.devices.push(new_dev);
        }
    }

    for c in contacts {
        if let Some(existing) = node.owner.contact_users.iter_mut().find(|x| x.user.uuid == c.uuid) {
            existing.user.alias = c.alias;
            existing.public_key = c.public_key;
            // Replace the contact's device list — we don't have local
            // private fields to preserve for contact-owned apps.
            existing.user.devices = c.devices.into_iter().map(|p| {
                let mut dev = p.device;
                for (id, alias) in p.apps {
                    dev.applications.push(Application {
                        id, alias,
                        protocol:      String::new(),
                        host:          "0.0.0.0:0".parse().unwrap(),
                        user_approved: true,
                        token:         [0u8; 16],
                    });
                }
                dev
            }).collect();
        } else {
            let devs = c.devices.into_iter().map(|p| {
                let mut dev = p.device;
                for (id, alias) in p.apps {
                    dev.applications.push(Application {
                        id, alias,
                        protocol:      String::new(),
                        host:          "0.0.0.0:0".parse().unwrap(),
                        user_approved: true,
                        token:         [0u8; 16],
                    });
                }
                dev
            }).collect();
            node.owner.contact_users.push(Contact {
                public_key: c.public_key,
                user: User { alias: c.alias, uuid: c.uuid, devices: devs },
            });
        }
    }

    drop(node);
    ctx.save_node();
    true
}

/// Send a SyncWriteRequest (op 0x70) to the writer SG identified by `writer_uuid`.
fn send_sync_write_request(change: &Change, writer_uuid: Uuid, ctx: &WorkerContext) {
    let payload = serialize_change(change);
    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.values()
            .find(|c| c.device_uuid == writer_uuid)
            .map(|conn| (
                build_encrypted_packet(SYNC_WRITE_REQUEST_OP, conn, &payload),
                conn.peer_addr,
            ))
    };
    let Some((pkt, addr)) = pkt_and_addr else {
        eprintln!("[send_sync_write_request] no active connection to writer {writer_uuid:?}");
        return;
    };
    send(ctx, addr, &pkt);
}

fn build_write_ack_body(result: u8, private: SyncVersion, public: SyncVersion) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + SYNC_VERSION_WIRE_LEN * 2);
    body.push(result);
    write_sync_version(&mut body, &private);
    write_sync_version(&mut body, &public);
    body
}

/// Op 0x70 — Sync write request (DG/SG → writer SG).
///
/// Decrypts, parses the change, and either accepts (if this node is the
/// elected writer per `find_writer_sg`) or rejects with `WRITE_ACK_NOT_WRITER`.
/// Forwarding up the rank chain is documented in `descriptions/data sync.md`
/// but deferred — for now an originator that picked the wrong SG will see
/// NOT_WRITER and (in phase 5+6) re-elect on its next pull.
pub fn sync_write_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[sync_write_request] header too short from {src}");
        return;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[sync_write_request] decryption failed from {src}");
                return;
            }
        }
    };

    let Some(change) = deserialize_change(&plaintext) else {
        eprintln!("[sync_write_request] unparseable change from {src}");
        return;
    };

    let (target, local_uuid) = {
        let node = ctx.node.read().unwrap();
        (find_writer_sg(&node), node.device_uuid)
    };

    let (result, private_v, public_v, bumped) = match target {
        WriterTarget::Local => {
            let (pre_priv, pre_pub) = {
                let node = ctx.node.read().unwrap();
                (node.owner.private_version, node.owner.public_version)
            };
            match apply_change_locally(&change, local_uuid, ctx) {
                Ok((priv_v, pub_v)) => {
                    let bumped = bumped_scopes(pre_priv, pre_pub, priv_v, pub_v);
                    (WRITE_ACK_OK, priv_v, pub_v, bumped)
                }
                Err(WriteError::Validation(msg)) => {
                    eprintln!("[sync_write_request] validation error from {src}: {msg}");
                    let node = ctx.node.read().unwrap();
                    (WRITE_ACK_VALIDATION_ERROR, node.owner.private_version, node.owner.public_version, Vec::new())
                }
                Err(WriteError::Unreachable) => {
                    // Cannot occur in the Local branch — defensive only.
                    let node = ctx.node.read().unwrap();
                    (WRITE_ACK_VALIDATION_ERROR, node.owner.private_version, node.owner.public_version, Vec::new())
                }
            }
        }
        WriterTarget::Remote(_) | WriterTarget::Unreachable => {
            let node = ctx.node.read().unwrap();
            (WRITE_ACK_NOT_WRITER, node.owner.private_version, node.owner.public_version, Vec::new())
        }
    };

    let body = build_write_ack_body(result, private_v, public_v);
    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.get(&conn_id)
            .map(|conn| (
                build_encrypted_packet(SYNC_WRITE_ACK_OP, conn, &body),
                conn.peer_addr,
            ))
    };
    let Some((pkt, addr)) = pkt_and_addr else {
        eprintln!("[sync_write_request] no connection {conn_id} to ack from {src}");
        return;
    };
    send(ctx, addr, &pkt);

    // Fan out UpdateAvailable notifications to peers when the write actually
    // changed state. The originator gets one too — its `sync_update_available`
    // handler will trigger the confirming pull, replacing the simple ack-only
    // path used in phase 4.
    if !bumped.is_empty() {
        notify_own_peers(&bumped, private_v, public_v, ctx);
    }
}

/// Op 0x71 — Sync write ack (writer SG → originator).
///
/// Phase 4: decrypt + parse + log. Phase 5 will use the returned versions to
/// trigger an immediate `SyncPullRequest` so the originator's view of the
/// state catches up with the authoritative writer record.
pub fn sync_write_ack(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[sync_write_ack] decryption failed from {src}");
                return;
            }
        }
    };
    let mut pos = 0usize;
    let Some(&result) = plaintext.get(pos) else {
        eprintln!("[sync_write_ack] missing result from {src}");
        return;
    };
    pos += 1;
    let Some(private_v) = read_sync_version(&plaintext, &mut pos) else {
        eprintln!("[sync_write_ack] truncated private_version from {src}");
        return;
    };
    let Some(public_v) = read_sync_version(&plaintext, &mut pos) else {
        eprintln!("[sync_write_ack] truncated public_version from {src}");
        return;
    };
    println!(
        "[sync_write_ack] from {src} result={result} private=(e={},s={}) public=(e={},s={}) (phase 5: pull on accepted)",
        private_v.epoch, private_v.seq, public_v.epoch, public_v.seq,
    );
}

/// Op 0x72 — Sync update available (writer SG → notify list).
///
/// Decrypts the announced `(scope, version)` and, if it is strictly newer
/// than the local last-applied version for that scope, immediately sends a
/// `SyncPullRequest` back to the source. A "newer from a different writer"
/// (cross-writer comparison) is also treated as needing a pull — that
/// surfaces partition-recovery situations the design doc covers.
pub fn sync_update_available(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[sync_update_available] header too short from {src}");
        return;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[sync_update_available] decryption failed from {src}");
                return;
            }
        }
    };

    let mut pos = 0usize;
    let Some(scope) = read_scope(&plaintext, &mut pos) else {
        eprintln!("[sync_update_available] bad scope from {src}");
        return;
    };
    let Some(announced) = read_sync_version(&plaintext, &mut pos) else {
        eprintln!("[sync_update_available] truncated version from {src}");
        return;
    };

    let local_v = {
        let node = ctx.node.read().unwrap();
        node.owner.version(scope)
    };

    use std::cmp::Ordering;
    let needs_pull = match announced.cmp_same_writer(&local_v) {
        Some(Ordering::Greater) => true,
        Some(_)                 => false,
        None                    => true, // cross-writer: pull and let the writer's state win.
    };
    if needs_pull {
        send_pull_request(scope, local_v, conn_id, ctx);
    }
}

/// Op 0x73 — Sync pull request (any node → writer SG).
///
/// Compares the sender's `last_seen` against this node's current version for
/// `scope` and replies with either `NoUpdates` (versions equal) or
/// `FullState` carrying a serialized state blob. Cross-writer comparisons
/// also send `FullState` so the puller adopts the local writer's state.
///
/// Private-scope pulls return an empty state blob in Phase 5 (no Change
/// variant currently bumps Private). Future phases will populate it.
pub fn sync_pull_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[sync_pull_request] header too short from {src}");
        return;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[sync_pull_request] decryption failed from {src}");
                return;
            }
        }
    };

    let mut pos = 0usize;
    let Some(scope) = read_scope(&plaintext, &mut pos) else {
        eprintln!("[sync_pull_request] bad scope from {src}");
        return;
    };
    let Some(last_seen) = read_sync_version(&plaintext, &mut pos) else {
        eprintln!("[sync_pull_request] truncated version from {src}");
        return;
    };

    let (current_v, state_blob) = {
        let node = ctx.node.read().unwrap();
        let v = node.owner.version(scope);
        let blob = match scope {
            Scope::Public  => serialize_public_state(&node),
            Scope::Private => Vec::new(), // empty in phase 5
        };
        (v, blob)
    };

    use std::cmp::Ordering;
    let send_full = match last_seen.cmp_same_writer(&current_v) {
        Some(Ordering::Equal) => false,
        Some(_) | None        => true,
    };

    let mut body = Vec::new();
    write_scope(&mut body, scope);
    if send_full {
        body.push(PULL_RESULT_FULL_STATE);
        write_sync_version(&mut body, &current_v);
        body.extend_from_slice(&state_blob);
    } else {
        body.push(PULL_RESULT_NO_UPDATES);
        write_sync_version(&mut body, &current_v);
        // No state blob on NoUpdates.
    }

    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.get(&conn_id)
            .map(|conn| (
                build_encrypted_packet(SYNC_PULL_RESPONSE_OP, conn, &body),
                conn.peer_addr,
            ))
    };
    let Some((pkt, addr)) = pkt_and_addr else {
        eprintln!("[sync_pull_request] no connection {conn_id} to reply to from {src}");
        return;
    };
    send(ctx, addr, &pkt);
}

/// Op 0x74 — Sync pull response (writer SG → puller).
///
/// `NoUpdates`: pin our local last-applied version to the writer's current
/// version (we are caught up). `FullState`: parse and merge the state blob
/// for `scope`, then advance the local version. A malformed blob leaves
/// state and version unchanged.
pub fn sync_pull_response(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[sync_pull_response] decryption failed from {src}");
                return;
            }
        }
    };

    let mut pos = 0usize;
    let Some(scope) = read_scope(&plaintext, &mut pos) else {
        eprintln!("[sync_pull_response] bad scope from {src}");
        return;
    };
    let Some(&result) = plaintext.get(pos) else {
        eprintln!("[sync_pull_response] missing result from {src}");
        return;
    };
    pos += 1;
    let Some(new_version) = read_sync_version(&plaintext, &mut pos) else {
        eprintln!("[sync_pull_response] truncated version from {src}");
        return;
    };

    match result {
        PULL_RESULT_NO_UPDATES => {
            // Caught up — pin the local version to the writer's current.
            let mut node = ctx.node.write().unwrap();
            match scope {
                Scope::Private => node.owner.private_version = new_version,
                Scope::Public  => node.owner.public_version  = new_version,
            }
            drop(node);
            ctx.save_node();
        }
        PULL_RESULT_FULL_STATE => {
            let state_blob = &plaintext[pos..];
            let applied = match scope {
                Scope::Public  => apply_public_state(state_blob, ctx),
                // Private state blob is empty in Phase 5 — nothing to apply.
                Scope::Private => state_blob.is_empty(),
            };
            if !applied {
                eprintln!("[sync_pull_response] failed to apply state for {scope:?} from {src}");
                return;
            }
            let mut node = ctx.node.write().unwrap();
            match scope {
                Scope::Private => node.owner.private_version = new_version,
                Scope::Public  => node.owner.public_version  = new_version,
            }
            drop(node);
            ctx.save_node();
        }
        other => {
            eprintln!("[sync_pull_response] unknown result {other} from {src}");
        }
    }
}

// ── Scheduled action handlers ─────────────────────────────────────────────────

const SG_PING_TIMEOUT: Duration = Duration::from_secs(1);

/// Op 0x40 — Relay packet (DG → SG).
///
/// The SG decrypts the body, reads the destination device UUID, re-encrypts
/// the inner payload for the destination, and forwards it as an AppPacket (0x41).
/// Also maintains a rolling per-pair packet count; once the threshold is reached
/// a `SetupTunnel` action is scheduled so subsequent traffic can bypass the
/// decrypt/re-encrypt step.
///
/// Encrypted body: [dest_device_uuid: 16][dest_app_id: u16][sender_app_id: u16][payload]
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
        if plaintext.len() < 20 {
            eprintln!("[relay_packet] plaintext too short from {src}");
            return;
        }
        let dest_device_uuid: Uuid = plaintext[0..16].try_into().unwrap();
        let dest_app_id            = u16::from_be_bytes([plaintext[16], plaintext[17]]);
        let sender_app_id          = u16::from_be_bytes([plaintext[18], plaintext[19]]);
        let payload                = plaintext[20..].to_vec();

        (node.device_uuid, dest_device_uuid, dest_app_id, sender_app_id, payload)
    };

    // If the destination is this device (i.e. the SG is both relay and recipient),
    // deliver directly to the local app without going through active_connections.
    if dest_device_uuid == local_uuid {
        let app_host = {
            let node = ctx.node.read().unwrap();
            node.owner.user.devices.iter()
                .find(|d| d.uuid == local_uuid)
                .and_then(|d| d.applications.iter()
                    .find(|a| a.id == dest_app_id && a.user_approved))
                .map(|a| a.host)
        };
        let Some(app_host) = app_host else {
            eprintln!("[relay_packet] no approved local app with id {dest_app_id}");
            return;
        };
        let mut push = Vec::with_capacity(3 + payload.len());
        push.push(APP_PUSH_OP);
        push.extend_from_slice(&sender_app_id.to_be_bytes());
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

        // AppPacket body: [dest_app_id: u16][sender_app_id: u16][payload]
        let mut app_body = Vec::with_capacity(4 + payload.len());
        app_body.extend_from_slice(&dest_app_id.to_be_bytes());
        app_body.extend_from_slice(&sender_app_id.to_be_bytes());
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

/// Op 0x41 — App packet (SG → destination node).
///
/// The destination node decrypts the body, finds the local app by dest_app_id,
/// and pushes the payload to the app via UDP.
///
/// Encrypted body: [dest_app_id: u16][sender_app_id: u16][payload]
/// Push to app:    [0x04][sender_app_id: u16][payload]
pub fn app_packet(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let (push_pkt, app_host) = {
        let node = ctx.node.read().unwrap();

        let Some(plaintext) = decrypt_packet_body(&node, &buf) else {
            eprintln!("[app_packet] decryption failed from {src}");
            return;
        };

        if plaintext.len() < 4 {
            eprintln!("[app_packet] plaintext too short from {src}");
            return;
        }
        let dest_app_id   = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        let sender_app_id = u16::from_be_bytes([plaintext[2], plaintext[3]]);
        let payload       = &plaintext[4..];

        // Find the destination app on this node.
        let device_uuid = node.device_uuid;
        let Some(app_host) = node.owner.user.devices.iter()
            .find(|d| d.uuid == device_uuid)
            .and_then(|d| d.applications.iter()
                .find(|a| a.id == dest_app_id && a.user_approved))
            .map(|a| a.host)
        else {
            eprintln!("[app_packet] no approved app with id {dest_app_id}");
            return;
        };

        // Build push packet: [0x04][sender_app_id: u16][payload]
        let mut push = Vec::with_capacity(3 + payload.len());
        push.push(APP_PUSH_OP);
        push.extend_from_slice(&sender_app_id.to_be_bytes());
        push.extend_from_slice(payload);

        (push, app_host)
    };

    send(ctx, SocketAddr::V4(app_host), &push_pkt);
}

/// Ping every candidate SG, record RTT, and mark each one up or down.
///
/// Candidate pool: all SG-grade devices owned by the local user (excluding the
/// local device itself) plus all SG-grade devices of every contact user.
pub fn poll_sg(ctx: &WorkerContext) {
    // Collect (device_uuid, host_entry, resolved_addr) for every advertised
    // address on every candidate SG. Unresolvable entries are silently skipped
    // — expected when a name only resolves inside one network.
    let candidates: Vec<(Uuid, String, SocketAddrV4)> = {
        let node = ctx.node.read().unwrap();
        let local_uuid = node.device_uuid;
        let mut v: Vec<(Uuid, String, SocketAddrV4)> = Vec::new();
        for d in &node.owner.user.devices {
            if matches!(d.grade, DeviceGrade::SG) && d.uuid != local_uuid {
                for (h, addr) in resolve_hosts(&d.hosts) {
                    v.push((d.uuid, h, addr));
                }
            }
        }
        for contact in &node.owner.contact_users {
            for d in &contact.user.devices {
                if matches!(d.grade, DeviceGrade::SG) {
                    for (h, addr) in resolve_hosts(&d.hosts) {
                        v.push((d.uuid, h, addr));
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

    for (uuid, host, addr) in candidates {
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

        // Desired peers: own devices (all if SG, SGs-only if DG) + contact devices (same rule).
        // Skip peers with no resolvable address — happy eyeballs data, if present,
        // picks the lowest-RTT up address; otherwise we fall back to the first
        // resolvable entry in the peer's host list.
        let mut desired: Vec<(Uuid, SocketAddrV4, PublicKey)> = Vec::new();
        for d in &node.owner.user.devices {
            if d.uuid == our_device_uuid { continue; }
            if is_sg || matches!(d.grade, DeviceGrade::SG) {
                if let Some(addr) = best_address_for_device(&node, &d.uuid) {
                    desired.push((d.uuid, addr, our_longterm_pk));
                }
            }
        }
        for contact in &node.owner.contact_users {
            for d in &contact.user.devices {
                if is_sg || matches!(d.grade, DeviceGrade::SG) {
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
    }
}

// ── Tunnel handlers ───────────────────────────────────────────────────────────

/// Allocate a tunnel ID not already used in active or pending tunnel maps.
fn allocate_tunnel_id(node: &super::data_models::Node) -> u16 {
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
    let dest_device_uuid: Uuid = buf[2..18].try_into().unwrap();

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
    pkt[3..35].copy_from_slice(&our_ephem_pk);
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
    let sender_ephem_pk: PublicKey = buf[2..34].try_into().unwrap();

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
            pkt[3..35].copy_from_slice(&sender_ephem_pk);
            pkt[35..51].copy_from_slice(&sender_uuid);
            send(ctx, dest, &pkt);
        }
    } else if buf.len() >= 50 {
        // ── DG_dest path ──────────────────────────────────────────────────────
        let sender_device_uuid: Uuid = buf[34..50].try_into().unwrap();

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
            (conn_id, pk_copy)
        };

        let _ = conn_id;

        // Reply TUNNEL_CONNECT_ACK to the SG that forwarded this request.
        // Format: [op=0x53][tunnel_id: u16][our_ephem_pk: 32]
        let mut pkt = [0u8; 35];
        pkt[0]     = TUNNEL_CONNECT_ACK_OP;
        pkt[1..3].copy_from_slice(&tunnel_id.to_be_bytes());
        pkt[3..35].copy_from_slice(&our_ephem_pk);
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
    let dest_ephem_pk: PublicKey = buf[2..34].try_into().unwrap();

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
            pkt[3..35].copy_from_slice(&dest_ephem_pk);
            send(ctx, dest, &pkt);
        }
    } else if is_dg_sender {
        // ── DG_sender path ────────────────────────────────────────────────────
        let mut node = ctx.node.write().unwrap();
        let Some(ptc) = node.owner.pending_tunnel_connections.remove(&tunnel_id) else { return; };

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
pub fn tunnel_forward(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 28 {
        eprintln!("[tunnel_forward] packet too short from {src}");
        return;
    }
    let sender_sg_conn_id = u16::from_be_bytes([buf[0], buf[1]]);
    let tunnel_id         = u16::from_be_bytes([buf[2], buf[3]]);
    let payload           = &buf[4..]; // nonce + ciphertext, forwarded as-is

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
        send(ctx, dest, &pkt);
    }
}

/// Op 0x54 — Tunnel delivery (SG → DG).
///
/// DG_dest decrypts the payload with the DG-to-DG shared secret (looked up via
/// `dg_tunnel_map`) and pushes it to the target local app.
///
/// Payload: [tunnel_id: u16][nonce: 24][ciphertext...]
pub fn tunnel_delivery(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 26 {
        eprintln!("[tunnel_delivery] packet too short from {src}");
        return;
    }
    let tunnel_id       = u16::from_be_bytes([buf[0], buf[1]]);
    let nonce: [u8; 24] = buf[2..26].try_into().unwrap();
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

        let shared = x25519_shared(&conn.key_pair.private_key, &conn.peer_public_key);
        let Some(plaintext) = xchacha20_decrypt(&shared, &nonce, ciphertext) else {
            eprintln!("[tunnel_delivery] decryption failed for tunnel {tunnel_id} from {src}");
            return;
        };
        if plaintext.len() < 4 {
            eprintln!("[tunnel_delivery] plaintext too short for tunnel {tunnel_id}");
            return;
        }

        let dest_app_id   = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        let sender_app_id = u16::from_be_bytes([plaintext[2], plaintext[3]]);
        let payload       = &plaintext[4..];

        let device_uuid = node.device_uuid;
        let Some(app_host) = node.owner.user.devices.iter()
            .find(|d| d.uuid == device_uuid)
            .and_then(|d| d.applications.iter().find(|a| a.id == dest_app_id))
            .map(|a| a.host)
        else {
            eprintln!("[tunnel_delivery] no app {dest_app_id} for tunnel {tunnel_id}");
            return;
        };

        let mut push = Vec::with_capacity(3 + payload.len());
        push.push(APP_PUSH_OP);
        push.extend_from_slice(&sender_app_id.to_be_bytes());
        push.extend_from_slice(payload);

        (push, app_host)
    };

    send(ctx, SocketAddr::V4(app_host), &push_pkt);
}

/// Recurring cleanup: remove idle tunnels and stale counters.
pub fn cleanup_tunnels(ctx: &WorkerContext) {
    const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
    let now     = Instant::now();
    let now_sys = SystemTime::now();

    let mut node = ctx.node.write().unwrap();

    // SG: remove idle ActiveTunnels.
    node.owner.active_tunnels.retain(|_, t| {
        now.duration_since(t.last_used_at) < TUNNEL_IDLE_TIMEOUT
    });

    // SG: clear stale tunnel counters (window expired).
    node.owner.tunnel_counters.retain(|_, c| {
        now.duration_since(c.window_start) < TUNNEL_COUNTER_WINDOW
    });

    // DG: remove dg_tunnel_map entries whose ActiveConnection has expired.
    let expired_tunnels: Vec<u16> = node.owner.dg_tunnel_map.iter()
        .filter(|(_, conn_id)| {
            !node.owner.active_connections.get(*conn_id)
                .map(|c| c.timeout > now_sys)
                .unwrap_or(false)
        })
        .map(|(&tid, _)| tid)
        .collect();
    for tid in expired_tunnels {
        node.owner.dg_tunnel_map.remove(&tid);
    }
}

/// Scheduled every 20 seconds on DG devices.
///
/// Sends an encrypted keepalive packet (op `0x12`) to the highest-ranked
/// reachable SG owned by this device's user.  Encrypting the keepalive with
/// the DG↔SG shared key lets the SG detect a stale/unknown connection and
/// reply with a conn-reset (op `0x13`) so the DG can reconnect immediately
/// instead of waiting up to 24 hours for the connection to expire.
///
/// Only one SG receives the keepalive at a time: the top-ranked SG that is
/// currently marked up by `poll_sg`. If the top-ranked SG is down, falls
/// through to the next rank.
pub fn keepalive_dg(ctx: &WorkerContext) {
    let out: Option<(Vec<u8>, SocketAddr)> = {
        let node       = ctx.node.read().unwrap();
        let local_uuid = node.device_uuid;

        // Only DGs need to send keepalives.
        let is_dg = node.owner.user.devices.iter()
            .find(|d| d.uuid == local_uuid)
            .map(|d| matches!(d.grade, DeviceGrade::DG))
            .unwrap_or(false);
        if !is_dg { return; }

        // UUIDs of own SGs that have an active connection, sorted by rank ascending.
        // None-rank SGs sort last (treat as u32::MAX).
        let connected: HashSet<Uuid> = node.owner.active_connections.values()
            .map(|c| c.device_uuid)
            .collect();

        let mut own_sgs: Vec<&super::data_models::Device> = node.owner.user.devices.iter()
            .filter(|d| matches!(d.grade, DeviceGrade::SG) && connected.contains(&d.uuid))
            .collect();
        own_sgs.sort_by_key(|d| d.sg_rank.unwrap_or(u32::MAX));

        // Pick the highest-ranked SG that poll_sg considers up (treat unpolled as up).
        let Some(sg) = own_sgs.iter()
            .find(|d| {
                let mut any_entry = false;
                let mut any_up = false;
                for ((uuid, _), status) in &node.sg_statuses {
                    if *uuid == d.uuid {
                        any_entry = true;
                        if status.up { any_up = true; }
                    }
                }
                !any_entry || any_up
            })
        else { return; };

        // Find the active connection to that SG.
        let Some(conn) = node.owner.active_connections.values()
            .find(|c| c.device_uuid == sg.uuid)
        else { return; };

        // Encrypt an empty plaintext so the SG can verify the connection is live.
        let pkt = build_encrypted_packet(DG_KEEPALIVE_OP, conn, &[]);
        Some((pkt, conn.peer_addr))
    };

    if let Some((pkt, dest)) = out {
        send(ctx, dest, &pkt);
    }
}

/// Op 0x12 — DG encrypted keepalive, received on the SG side.
///
/// Attempts to decrypt the keepalive using the named connection.  If the
/// conn_id is unknown or decryption fails the SG replies with a conn-reset
/// (op `0x13`) so the DG evicts the stale connection and reconnects.
pub fn dg_keepalive_receive(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let ok = {
        let node = ctx.node.read().unwrap();
        decrypt_packet_body(&node, &buf).is_some()
    };
    if !ok {
        send(ctx, src, &[CONN_RESET_OP]);
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
        ctx.scheduler_tx.send(super::action_queue::ScheduleRequest {
            action: super::action_queue::Action::MaintainConnections,
            delay:  Duration::ZERO,
        }).ok();
    }
}

// ── UI / HTTP handlers ────────────────────────────────────────────────────────

pub fn ui_request(
    stream: std::net::TcpStream,
    method: String,
    path:   String,
    query:  String,
    body:   Vec<u8>,
    ctx:    &WorkerContext,
) {
    // Setup guard — redirect to /setup when not yet initialized, and redirect
    // away from /setup once initialization is complete.
    let is_setup_route = matches!(path.as_str(), "/setup" | "/setup/create" | "/setup/join");
    if is_setup_route {
        if ctx.node.read().unwrap().is_initialized() {
            return respond_redirect(&stream, "/dashboard");
        }
    } else if !ctx.node.read().unwrap().is_initialized() {
        return respond_redirect(&stream, "/setup");
    }

    match (method.as_str(), path.as_str()) {
        ("GET",  "/setup") => respond_html(&stream, 200, &render_setup(&query)),
        ("POST", "/setup/create") => {
            match complete_setup(&body, ctx) {
                None      => respond_redirect(&stream, "/dashboard"),
                Some(err) => respond_redirect(&stream, &format!("/setup?grade=sg&role=new&error={err}")),
            }
        }
        ("POST", "/setup/join") => {
            initiate_bootstrap(&body, ctx);
            respond_redirect(&stream, "/setup?waiting=1")
        }
        ("GET",  "/")                     => respond_redirect(&stream, "/dashboard"),
        ("GET",  "/dashboard")            => respond_html(&stream, 200, &render_dashboard(ctx)),
        ("GET",  "/pending-apps")         => respond_html(&stream, 200, &render_pending_apps(ctx)),
        ("POST", "/pending-apps/approve") => {
            approve_app(&body, ctx);
            respond_redirect(&stream, "/pending-apps");
        }
        ("POST", "/pending-apps/reject")  => {
            reject_app(&body, ctx);
            respond_redirect(&stream, "/pending-apps");
        }
        ("GET",  "/applications")  => respond_html(&stream, 200, &render_applications(ctx)),
        ("POST", "/applications/delete") => {
            reject_app(&body, ctx);
            respond_redirect(&stream, "/applications");
        }
        ("GET",  "/contacts")      => respond_html(&stream, 200, &render_contacts(ctx)),
        ("GET",  "/devices")       => respond_html(&stream, 200, &render_devices(ctx)),
        ("POST", "/devices/sync")  => {
            sync_devices(ctx);
            respond_redirect(&stream, "/devices");
        }
        ("GET",  "/invitations")   => respond_html(&stream, 200, &render_invitations(ctx, &query)),
        ("POST", "/invitations/device") => {
            match generate_device_invitation(ctx) {
                Some(code) => respond_redirect(&stream, &format!("/invitations?code={code}")),
                None       => respond_redirect(&stream, "/invitations?error=no_host"),
            }
        }
        ("POST", "/invitations/contact") => {
            match generate_contact_invitation(ctx) {
                Some(code) => respond_redirect(&stream, &format!("/invitations?contact_code={code}")),
                None       => respond_redirect(&stream, "/invitations?error=no_host"),
            }
        }
        ("POST", "/invitations/enter") => {
            initiate_bootstrap(&body, ctx);
            respond_redirect(&stream, "/invitations");
        }
        ("POST", "/contacts/enter") => {
            initiate_contact_exchange(&body, ctx);
            respond_redirect(&stream, "/contacts");
        }
        _ => respond_html(&stream, 404, &layout("Not Found", "<h1>404 — Not Found</h1>")),
    }
}

// ── Routing helpers ───────────────────────────────────────────────────────────

fn respond_html(stream: &std::net::TcpStream, status: u16, html: &str) {
    use std::io::Write;
    let status_text = match status { 200 => "OK", 404 => "Not Found", _ => "OK" };
    let body = html.as_bytes();
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let mut s = stream;
    let _ = s.write_all(header.as_bytes());
    let _ = s.write_all(body);
}

fn respond_redirect(stream: &std::net::TcpStream, location: &str) {
    use std::io::Write;
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let mut s = stream;
    let _ = s.write_all(response.as_bytes());
}

/// Extract a URL-encoded form field value from a POST body (e.g. `id=5`).
fn form_field<'a>(body: &'a [u8], field: &str) -> Option<&'a str> {
    let s = std::str::from_utf8(body).ok()?;
    let prefix = format!("{field}=");
    for part in s.split('&') {
        if let Some(val) = part.strip_prefix(prefix.as_str()) {
            return Some(val);
        }
    }
    None
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

/// Decode a percent-encoded URL form value (e.g. `hello+world` → `hello world`).
fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => { out.push(' '); i += 1; }
            b'%' if i + 2 < b.len() => {
                match (hex_nibble(b[i + 1]), hex_nibble(b[i + 2])) {
                    (Some(hi), Some(lo)) => { out.push(char::from(hi << 4 | lo)); i += 3; }
                    _ => { out.push('%'); i += 1; }
                }
            }
            c => { out.push(char::from(c)); i += 1; }
        }
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Extract a value from a query string (e.g. `grade=sg&role=new`).
fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    for part in query.split('&') {
        if let Some(val) = part.strip_prefix(prefix.as_str()) {
            return Some(val);
        }
    }
    None
}

// ── Page renders ─────────────────────────────────────────────────────────────

fn render_dashboard(ctx: &WorkerContext) -> String {
    let node        = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device      = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid);

    let owner_alias  = html_escape(&node.owner.user.alias);
    let device_alias = html_escape(device.map(|d| d.alias.as_str()).unwrap_or("unknown"));
    let n_contacts   = node.owner.contact_users.len();
    let n_apps: usize = node.owner.user.devices.iter().map(|d| d.applications.len()).sum();
    let n_conns      = node.owner.active_connections.len();

    let hosts_line = match device {
        Some(d) if d.hosts.is_empty() => {
            "<span style='color:#900'>none — set <code>PNET_HOSTS</code> and restart</span>".to_string()
        }
        Some(d) => html_escape(&d.hosts.join(", ")),
        None => "unknown".to_string(),
    };

    let body = format!(
        "<h1>Dashboard</h1>\
         <div class=\"stats\">\
           <div class=\"stat-card\"><div class=\"stat\">{n_contacts}</div><div class=\"label\">Contacts</div></div>\
           <div class=\"stat-card\"><div class=\"stat\">{n_apps}</div><div class=\"label\">Applications</div></div>\
           <div class=\"stat-card\"><div class=\"stat\">{n_conns}</div><div class=\"label\">Active Connections</div></div>\
         </div>\
         <div class=\"card\">\
           <div class=\"label\">Owner</div><div>{owner_alias}</div>\
           <div class=\"label\" style=\"margin-top:.5rem\">Device</div><div>{device_alias}</div>\
           <div class=\"label\" style=\"margin-top:.5rem\">Advertised hosts</div><div>{hosts_line}</div>\
         </div>"
    );
    layout("Dashboard", &body)
}

fn render_pending_apps(ctx: &WorkerContext) -> String {
    let node        = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device      = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid);

    let rows: String = device
        .map(|d| {
            d.applications.iter()
                .filter(|a| !a.user_approved)
                .map(|a| format!(
                    "<tr>\
                       <td>{}</td>\
                       <td>{}</td>\
                       <td>{}</td>\
                       <td>\
                         <form method='post' action='/pending-apps/approve'>\
                           <input type='hidden' name='id' value='{}'>\
                           <button class='approve' type='submit'>Approve</button>\
                         </form>\
                         <form method='post' action='/pending-apps/reject'>\
                           <input type='hidden' name='id' value='{}'>\
                           <button class='reject' type='submit'>Reject</button>\
                         </form>\
                       </td>\
                     </tr>",
                    html_escape(&a.alias),
                    html_escape(&a.protocol),
                    html_escape(&a.host.to_string()),
                    a.id,
                    a.id,
                ))
                .collect()
        })
        .unwrap_or_default();

    let body = if rows.is_empty() {
        "<h1>Pending Apps</h1><p class='empty'>No pending applications.</p>".to_string()
    } else {
        format!(
            "<h1>Pending Apps</h1>\
             <table>\
               <tr><th>Alias</th><th>Protocol</th><th>Host</th><th>Actions</th></tr>\
               {rows}\
             </table>"
        )
    };
    layout("Pending Apps", &body)
}

fn render_applications(ctx: &WorkerContext) -> String {
    let node        = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device      = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid);

    let rows: String = device
        .map(|d| {
            d.applications.iter()
                .filter(|a| a.user_approved)
                .map(|a| format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td>\
                     <td><form method='post' action='/applications/delete' style='margin:0'>\
                       <input type='hidden' name='id' value='{}'>\
                       <button type='submit'>Delete</button>\
                     </form></td></tr>",
                    html_escape(&a.alias),
                    html_escape(&a.protocol),
                    html_escape(&a.host.to_string()),
                    a.id,
                ))
                .collect()
        })
        .unwrap_or_default();

    let body = if rows.is_empty() {
        "<h1>Applications</h1><p class='empty'>No approved applications.</p>".to_string()
    } else {
        format!(
            "<h1>Applications</h1>\
             <table>\
               <tr><th>Alias</th><th>Protocol</th><th>Host</th><th></th></tr>\
               {rows}\
             </table>"
        )
    };
    layout("Applications", &body)
}

fn render_contacts(ctx: &WorkerContext) -> String {
    let node     = ctx.node.read().unwrap();
    let contacts = &node.owner.contact_users;

    let rows: String = contacts.iter()
        .map(|c| {
            let dev_cells: String = c.user.devices.iter().map(|d| {
                let app_count = d.applications.iter().filter(|a| a.user_approved).count();
                format!(
                    "<li style='font-size:.85rem'>{} — {} app{}</li>",
                    html_escape(&d.alias),
                    app_count,
                    if app_count == 1 { "" } else { "s" },
                )
            }).collect();
            let dev_list = if c.user.devices.is_empty() {
                "<span style='color:#999;font-size:.85rem'>no devices</span>".to_string()
            } else {
                format!("<ul style='margin:0;padding-left:1.2rem'>{dev_cells}</ul>")
            };
            format!(
                "<tr><td>{}</td><td>{dev_list}</td></tr>",
                html_escape(&c.user.alias),
            )
        })
        .collect();

    let table = if rows.is_empty() {
        "<p class='empty'>No contacts yet.</p>".to_string()
    } else {
        format!(
            "<table>\
               <tr><th>Alias</th><th>Devices &amp; Apps</th></tr>\
               {rows}\
             </table>"
        )
    };

    drop(node);

    let body = format!(
        "<h1>Contacts</h1>\
         {table}\
         <div class='card' style='margin-top:1.5rem'>\
           <h2 style='margin-top:0;font-size:1rem'>Add a Contact</h2>\
           <p style='color:#666;font-size:.9rem;margin-top:0'>Paste an invitation code from another pNet user.</p>\
           <form method='post' action='/contacts/enter'>\
             <textarea name='code' rows='3' \
               style='width:100%;font-family:monospace;font-size:.85rem;\
                      box-sizing:border-box;padding:.4rem;border:1px solid #ccc;border-radius:4px' \
               placeholder='Paste contact invitation code here...'></textarea><br>\
             <button type='submit' style='margin-top:.5rem'>Add Contact</button>\
           </form>\
         </div>"
    );
    layout("Contacts", &body)
}

fn render_devices(ctx: &WorkerContext) -> String {
    let node        = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;

    let rows: String = node.owner.user.devices.iter()
        .map(|d| {
            let suffix = if d.uuid == device_uuid { " <em>(this device)</em>" } else { "" };
            format!(
                "<tr><td>{}{suffix}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&d.alias),
                html_escape(&d.hosts.join(", ")),
                d.applications.len(),
            )
        })
        .collect();

    let heading = "\
        <div style='display:flex;align-items:center;justify-content:space-between;margin-bottom:.75rem'>\
          <h1 style='margin:0'>Devices</h1>\
          <form method='post' action='/devices/sync'>\
            <button type='submit'>Sync</button>\
          </form>\
        </div>";

    let body = if rows.is_empty() {
        format!("{heading}<p class='empty'>No devices.</p>")
    } else {
        format!(
            "{heading}\
             <table>\
               <tr><th>Alias</th><th>Host</th><th>Apps</th></tr>\
               {rows}\
             </table>"
        )
    };
    layout("Devices", &body)
}

// ── App approval / rejection ──────────────────────────────────────────────────

fn approve_app(body: &[u8], ctx: &WorkerContext) {
    let Some(id_str) = form_field(body, "id") else { return };
    let Ok(id) = id_str.parse::<u16>() else { return };
    let approved_alias: Option<String> = {
        let mut node    = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let Some(device) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) else { return };
        match device.applications.iter_mut().find(|a| a.id == id) {
            Some(app) => {
                app.user_approved = true;
                Some(app.alias.clone())
            }
            None => None,
        }
    };
    ctx.save_node();
    push_data_to_contacts(ctx);
    sync_devices(ctx);

    // Sync v1: publish id+alias to peers via the writer SG. Only fire when
    // the app actually existed and was approved — guards against a stray UI
    // POST for an unknown id. Runs alongside the legacy paths until 7b.
    if let Some(app_alias) = approved_alias {
        let device_uuid = ctx.node.read().unwrap().device_uuid;
        let _ = request_change(Change::AddApplication {
            device_uuid,
            app_id: id,
            app_alias,
        }, ctx);
    }
}

fn reject_app(body: &[u8], ctx: &WorkerContext) {
    let Some(id_str) = form_field(body, "id") else { return };
    let Ok(id) = id_str.parse::<u16>() else { return };
    {
        let mut node    = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let Some(device) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) else { return };
        device.applications.retain(|a| a.id != id);
    }
    ctx.save_node();
    push_data_to_contacts(ctx);
    sync_devices(ctx);
}

// ── Invitation generation and bootstrap initiation ───────────────────────────

/// Select the SG hosts list to embed in an outbound invitation code.
/// SG devices embed their own hosts; DG devices embed the lowest-RTT up SG's
/// hosts.  Returns `None` (after logging) if no reachable SG is known.
fn pick_invitation_hosts(ctx: &WorkerContext, label: &str) -> Option<Vec<String>> {
    let node = ctx.node.read().unwrap();
    let local_uuid = node.device_uuid;
    let local_device = node.owner.user.devices.iter().find(|d| d.uuid == local_uuid)?;

    let hosts = if matches!(local_device.grade, DeviceGrade::SG) {
        local_device.hosts.clone()
    } else {
        let mut best: Option<(Duration, Vec<String>)> = None;
        for d in &node.owner.user.devices {
            if !matches!(d.grade, DeviceGrade::SG) { continue; }
            if d.hosts.is_empty() { continue; }
            for ((uuid, _), s) in &node.sg_statuses {
                if *uuid != d.uuid || !s.up { continue; }
                let rtt = s.last_rtt.unwrap_or(Duration::MAX);
                if best.as_ref().map_or(true, |(br, _)| rtt < *br) {
                    best = Some((rtt, d.hosts.clone()));
                }
            }
        }
        best.map(|(_, h)| h).unwrap_or_default()
    };

    if hosts.is_empty() {
        eprintln!(
            "[{label}] no SG host configured — local device hosts: {:?}. \
             Set PNET_HOSTS and restart.",
            local_device.hosts,
        );
        return None;
    }
    Some(hosts)
}

/// Encode an invitation code with the full SG hosts list so the receiver can
/// pick whichever entry is resolvable in its own DNS context (docker service
/// name when co-located, public hostname when remote).
///
/// Format: `[inv_id:16][inv_pk:32][host_count:1] { [host_len:1][host_str:N] }*`
/// Each `host_str` carries its own optional `:port` suffix (same grammar as
/// `Device.hosts`); default port 7777 is applied at resolve time.
fn encode_invitation_code(inv_id: &Uuid, inv_pk: &PublicKey, hosts: &[String]) -> String {
    use base64::Engine;
    let host_count = hosts.len().min(u8::MAX as usize);
    let mut raw = Vec::with_capacity(16 + 32 + 1 + host_count * 32);
    raw.extend_from_slice(inv_id);
    raw.extend_from_slice(inv_pk);
    raw.push(host_count as u8);
    for h in hosts.iter().take(host_count) {
        let b = h.as_bytes();
        let len = b.len().min(u8::MAX as usize);
        raw.push(len as u8);
        raw.extend_from_slice(&b[..len]);
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw)
}

/// Decode an invitation code. Returns `(inv_id, inv_pk, hosts)`.
fn decode_invitation_code(code_str: &str) -> Option<(Uuid, PublicKey, Vec<String>)> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(code_str.trim()).ok()?;
    if raw.len() < 49 { return None; }
    let inv_id:    Uuid      = raw[0..16].try_into().ok()?;
    let inv_pk:    PublicKey = raw[16..48].try_into().ok()?;
    let host_count = raw[48] as usize;
    let mut off = 49;
    let mut hosts = Vec::with_capacity(host_count);
    for _ in 0..host_count {
        if off >= raw.len() { return None; }
        let len = raw[off] as usize;
        off += 1;
        if off + len > raw.len() { return None; }
        let s = std::str::from_utf8(&raw[off..off + len]).ok()?.to_string();
        off += len;
        hosts.push(s);
    }
    Some((inv_id, inv_pk, hosts))
}

/// Generate a device invitation on the UI.  Picks the best SG (self if SG, else
/// lowest-RTT up SG), creates an invitation, and returns the base64-encoded code.
///
/// Embeds the full `hosts` list of the chosen SG so the receiver can pick
/// whichever entry resolves in its own network.
fn generate_device_invitation(ctx: &WorkerContext) -> Option<String> {
    let hosts = pick_invitation_hosts(ctx, "generate_device_invitation")?;

    let (inv_id, inv_pk) = {
        let mut node = ctx.node.write().unwrap();
        let kp    = generate_x25519_keypair();
        let pk    = kp.public_key;
        let id    = generate_uuid();
        node.owner.device_invitations.push(Invitation {
            id,
            key_pair:   kp,
            expires_at: SystemTime::now() + Duration::from_secs(24 * 3600),
        });
        (id, pk)
    };

    ctx.save_node();
    Some(encode_invitation_code(&inv_id, &inv_pk, &hosts))
}

/// Parse an invitation code entered via the UI and send a BootstrapRequest to the SG.
fn initiate_bootstrap(body: &[u8], ctx: &WorkerContext) {
    let device_alias = form_field(body, "device_alias")
        .map(url_decode)
        .unwrap_or_default();
    let Some(code_str) = form_field(body, "code") else { return };
    let grade_str = form_field(body, "grade").unwrap_or("dg");
    let grade = if grade_str == "sg" { DeviceGrade::SG } else { DeviceGrade::DG };
    let sg_rank = if matches!(grade, DeviceGrade::SG) {
        Some(form_field(body, "sg_rank")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1)
            .max(1))
    } else {
        None
    };

    if let Err(e) = start_bootstrap(device_alias.trim(), code_str, grade, sg_rank, ctx) {
        eprintln!("[initiate_bootstrap] {e}");
    }
}

/// Typed entry point for kicking off a bootstrap join. Used by both the HTTP
/// form handler and `main`'s env-driven startup path. Decodes the invitation
/// code, stashes `PendingBootstrap`, and sends the BootstrapRequest packet.
pub fn start_bootstrap(
    device_alias: &str,
    code_str: &str,
    desired_grade: DeviceGrade,
    desired_sg_rank: Option<u32>,
    ctx: &WorkerContext,
) -> Result<(), &'static str> {
    let Some((invitation_id, invitation_pk, hosts)) = decode_invitation_code(code_str) else {
        return Err("invalid invitation code");
    };

    let Some((picked_host, sg_addr)) = resolve_hosts(&hosts).into_iter().next() else {
        eprintln!("[start_bootstrap] no host in invitation code resolved: {hosts:?}");
        return Err("no host resolved from invitation code");
    };

    let ephem_kp = generate_x25519_keypair();
    let ephem_pk = ephem_kp.public_key;
    {
        let mut node = ctx.node.write().unwrap();
        node.owner.pending_bootstrap = Some(PendingBootstrap {
            invitation_id,
            our_ephem_key_pair: ephem_kp,
            invitation_pk,
            sg_addr,
            device_alias: device_alias.to_string(),
            desired_grade,
            desired_sg_rank,
        });
    }

    // Send BootstrapRequest: [op=0x30][invitation_id:16][our_ephem_pk:32]
    let mut pkt = [0u8; 49];
    pkt[0] = BOOTSTRAP_REQUEST_OP;
    pkt[1..17].copy_from_slice(&invitation_id);
    pkt[17..49].copy_from_slice(&ephem_pk);
    println!("[start_bootstrap] sending bootstrap request to {sg_addr} (picked {picked_host} from {hosts:?})");
    send(ctx, SocketAddr::V4(sg_addr), &pkt);
    Ok(())
}

/// Generate a contact invitation code: stores the invitation in
/// `contact_invitations` and returns the base64-encoded shareable code.
///
/// Embeds the full `hosts` list of the chosen SG so the receiver can pick
/// whichever entry resolves in its own network.
fn generate_contact_invitation(ctx: &WorkerContext) -> Option<String> {
    let hosts = pick_invitation_hosts(ctx, "generate_contact_invitation")?;

    let (inv_id, inv_pk) = {
        let mut node = ctx.node.write().unwrap();
        let kp = generate_x25519_keypair();
        let pk = kp.public_key;
        let id = generate_uuid();
        node.owner.contact_invitations.push(Invitation {
            id,
            key_pair:   kp,
            expires_at: SystemTime::now() + Duration::from_secs(24 * 3600),
        });
        (id, pk)
    };

    ctx.save_node();
    Some(encode_invitation_code(&inv_id, &inv_pk, &hosts))
}

/// Parse a contact invitation code and send a ContactRequest to the target's SG.
fn initiate_contact_exchange(body: &[u8], ctx: &WorkerContext) {
    let Some(code_str) = form_field(body, "code") else { return };
    let Some((invitation_id, invitation_pk, hosts)) = decode_invitation_code(code_str) else {
        eprintln!("[initiate_contact_exchange] invalid invitation code");
        return;
    };

    let Some((picked_host, sg_addr)) = resolve_hosts(&hosts).into_iter().next() else {
        eprintln!("[initiate_contact_exchange] no host in invitation code resolved: {hosts:?}");
        return;
    };
    println!("[initiate_contact_exchange] sending contact request to {sg_addr} (picked {picked_host} from {hosts:?})");

    let ephem_kp = generate_x25519_keypair();
    let ephem_pk = ephem_kp.public_key;
    let shared_secret = x25519_shared(&ephem_kp.private_key, &invitation_pk);

    // Serialize and encrypt our contact card.
    let payload = {
        let node = ctx.node.read().unwrap();
        serialize_contact_payload(&node)
    };
    let (ciphertext, nonce) = xchacha20_encrypt(&shared_secret, &payload);

    {
        let mut node = ctx.node.write().unwrap();
        node.owner.pending_contact_exchange = Some(PendingContactExchange {
            our_ephem_key_pair: ephem_kp,
            invitation_pk,
            sg_addr,
        });
    }

    // Send ContactRequest: [op=0x33][invitation_id:16][ephem_pk:32][nonce:24][ciphertext]
    let mut pkt = Vec::with_capacity(1 + 16 + 32 + 24 + ciphertext.len());
    pkt.push(CONTACT_REQUEST_OP);
    pkt.extend_from_slice(&invitation_id);
    pkt.extend_from_slice(&ephem_pk);
    pkt.extend_from_slice(&nonce);
    pkt.extend_from_slice(&ciphertext);
    send(ctx, SocketAddr::V4(sg_addr), &pkt);
}

fn render_invitations(ctx: &WorkerContext, query: &str) -> String {
    let node = ctx.node.read().unwrap();

    // Show a generated code if one was passed back via the redirect query string.
    let code_param = query.split('&')
        .find_map(|p| p.strip_prefix("code="))
        .unwrap_or("");
    let contact_code_param = query.split('&')
        .find_map(|p| p.strip_prefix("contact_code="))
        .unwrap_or("");
    let error_param = query.split('&')
        .find_map(|p| p.strip_prefix("error="))
        .unwrap_or("");

    let error_section = match error_param {
        "no_host" => "<div class='card' style='background:#fee;color:#900;border:1px solid #c66'>\
            <strong>Could not generate invitation:</strong> no reachable host is configured \
            for this device. Set the <code>PNET_HOSTS</code> environment variable before \
            starting the node, then restart. See the server log for details.\
            </div>".to_string(),
        _ => String::new(),
    };

    let code_section = if !code_param.is_empty() {
        format!(
            "<div class='card'>\
               <div class='label'>Share this code with the new device (expires in 24 h):</div>\
               <pre style='word-break:break-all;background:#f0f0f0;padding:.75rem;\
                           border-radius:4px;font-size:.85rem;margin:.5rem 0 0'>{}</pre>\
             </div>",
            html_escape(code_param)
        )
    } else {
        String::new()
    };

    let contact_code_section = if !contact_code_param.is_empty() {
        format!(
            "<div class='card'>\
               <div class='label'>Share this code with your new contact (expires in 24 h):</div>\
               <pre style='word-break:break-all;background:#f0f0f0;padding:.75rem;\
                           border-radius:4px;font-size:.85rem;margin:.5rem 0 0'>{}</pre>\
             </div>",
            html_escape(contact_code_param)
        )
    } else {
        String::new()
    };

    let dev_inv_rows: String = node.owner.device_invitations.iter()
        .map(|inv| {
            let id_hex: String = inv.id.iter().map(|b| format!("{b:02x}")).collect();
            format!("<tr><td style='font-family:monospace'>{}</td></tr>", &id_hex[..16])
        })
        .collect();

    let dev_inv_table = if dev_inv_rows.is_empty() {
        "<p class='empty'>No pending device invitations.</p>".to_string()
    } else {
        format!("<table><tr><th>Invitation ID (first 8 bytes)</th></tr>{dev_inv_rows}</table>")
    };

    let contact_inv_rows: String = node.owner.contact_invitations.iter()
        .map(|inv| {
            let id_hex: String = inv.id.iter().map(|b| format!("{b:02x}")).collect();
            format!("<tr><td style='font-family:monospace'>{}</td></tr>", &id_hex[..16])
        })
        .collect();

    let contact_inv_table = if contact_inv_rows.is_empty() {
        "<p class='empty'>No pending contact invitations.</p>".to_string()
    } else {
        format!("<table><tr><th>Invitation ID (first 8 bytes)</th></tr>{contact_inv_rows}</table>")
    };

    drop(node);

    let body = format!(
        "<h1>Invitations</h1>\
         {error_section}\
         {code_section}\
         {contact_code_section}\
         <div class='card'>\
           <h2 style='margin-top:0;font-size:1rem'>Add a Device</h2>\
           <p style='color:#666;font-size:.9rem;margin-top:0'>Generate a one-time code, then enter it on the new device.</p>\
           {dev_inv_table}\
           <form method='post' action='/invitations/device' style='margin-top:1rem'>\
             <button type='submit'>Generate Device Invitation</button>\
           </form>\
         </div>\
         <div class='card'>\
           <h2 style='margin-top:0;font-size:1rem'>Add a Contact</h2>\
           <p style='color:#666;font-size:.9rem;margin-top:0'>Generate a one-time code and share it with the person you want to add.</p>\
           {contact_inv_table}\
           <form method='post' action='/invitations/contact' style='margin-top:1rem'>\
             <button type='submit'>Generate Contact Invitation</button>\
           </form>\
         </div>\
         <div class='card'>\
           <h2 style='margin-top:0;font-size:1rem'>Enter Invitation Code</h2>\
           <p style='color:#666;font-size:.9rem;margin-top:0'>On this new device, paste a code generated on another device.</p>\
           <form method='post' action='/invitations/enter'>\
             <textarea name='code' rows='3' \
               style='width:100%;font-family:monospace;font-size:.85rem;\
                      box-sizing:border-box;padding:.4rem;border:1px solid #ccc;border-radius:4px' \
               placeholder='Paste invitation code here...'></textarea><br>\
             <button type='submit' style='margin-top:.5rem'>Connect to Network</button>\
           </form>\
         </div>"
    );
    layout("Invitations", &body)
}

// ── Setup wizard ─────────────────────────────────────────────────────────────

/// Apply first-run setup from the new-user form.
/// Returns `None` on success, or `Some(error_code)` if a field is invalid.
fn complete_setup(body: &[u8], ctx: &WorkerContext) -> Option<&'static str> {
    let alias        = form_field(body, "alias").map(url_decode).unwrap_or_default();
    let device_alias = form_field(body, "device_alias").map(url_decode).unwrap_or_default();
    let grade_str    = form_field(body, "grade").unwrap_or("sg");

    let grade = if grade_str == "sg" { DeviceGrade::SG } else { DeviceGrade::DG };
    let sg_rank = if matches!(grade, DeviceGrade::SG) {
        Some(form_field(body, "sg_rank")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1)
            .max(1))
    } else {
        None
    };

    apply_new_user_setup(alias.trim(), device_alias.trim(), grade, sg_rank, ctx)
}

/// Typed entry point for first-run new-user setup. Used by both the HTTP form
/// handler and `main`'s env-driven startup path.
pub fn apply_new_user_setup(
    alias: &str,
    device_alias: &str,
    grade: DeviceGrade,
    sg_rank: Option<u32>,
    ctx: &WorkerContext,
) -> Option<&'static str> {
    if alias.is_empty() || device_alias.is_empty() {
        return Some("fields");
    }

    let key_pair = generate_ed25519_keypair();

    {
        let mut node = ctx.node.write().unwrap();
        node.owner.user.alias = alias.to_string();
        node.owner.key_pair   = key_pair;

        let device_uuid = node.device_uuid;
        if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) {
            dev.alias   = device_alias.to_string();
            dev.grade   = grade;
            dev.sg_rank = sg_rank;
            // Apply PNET_HOSTS here too: main's startup application is skipped
            // on a fresh container (node not yet initialized).
            if matches!(dev.grade, DeviceGrade::SG) {
                let hosts = parse_pnet_hosts();
                if !hosts.is_empty() {
                    dev.hosts = hosts;
                }
            }
        }
    }
    ctx.save_node();
    None
}

fn render_setup(query: &str) -> String {
    let grade   = query_param(query, "grade").unwrap_or("");
    let role    = query_param(query, "role").unwrap_or("");
    let waiting = query_param(query, "waiting").is_some();

    let body: String = if waiting {
        "<meta http-equiv=\"refresh\" content=\"3; url=/setup\">\
         <h1>Connecting\u{2026}</h1>\
         <p class=\"swiz-sub\">Waiting for a response from the server.<br>\
         This page will refresh automatically.</p>\
         <p style=\"color:#888;font-size:.8rem\">Make sure the invitation code was valid \
         and that the server is reachable.</p>"
            .to_string()
    } else {
        match (grade, role) {
            ("", _) => render_setup_grade_step(),
            ("sg", "") => render_setup_role_step(),
            ("sg", "new") => render_setup_new_user_form(&query_param(query, "error").unwrap_or("")),
            ("sg", "join") | ("dg", _) => render_setup_code_entry(grade),
            _ => render_setup_grade_step(),
        }
    };
    setup_layout(&body)
}

fn render_setup_grade_step() -> String {
    "<h1>Welcome to pNet</h1>\
     <p class=\"swiz-sub\">Let\u{2019}s get your node configured. \
     First, what type of device is this?</p>\
     <a class=\"choice-btn\" href=\"/setup?grade=sg\">\
       <span class=\"choice-title\">Server Grade (SG)</span>\
       <span class=\"choice-desc\">A server with a static IP or domain. \
       Acts as a relay for your other devices.</span>\
     </a>\
     <a class=\"choice-btn\" href=\"/setup?grade=dg\">\
       <span class=\"choice-title\">Device Grade (DG)</span>\
       <span class=\"choice-desc\">A laptop, phone, or any device behind a home router. \
       Requires a server to relay connections.</span>\
     </a>"
        .to_string()
}

fn render_setup_role_step() -> String {
    "<h1>Server Grade Setup</h1>\
     <p class=\"swiz-sub\">Is this the first device for a new user, \
     or are you adding it to an existing account?</p>\
     <a class=\"choice-btn\" href=\"/setup?grade=sg&role=new\">\
       <span class=\"choice-title\">New User</span>\
       <span class=\"choice-desc\">Create a new pNet identity on this server.</span>\
     </a>\
     <a class=\"choice-btn\" href=\"/setup?grade=sg&role=join\">\
       <span class=\"choice-title\">Join Existing</span>\
       <span class=\"choice-desc\">Add this server to an existing user\u{2019}s pNet \
       using an invitation code.</span>\
     </a>\
     <a class=\"swiz-back\" href=\"/setup\">\u{2190} Back</a>"
        .to_string()
}

fn render_setup_new_user_form(error: &str) -> String {
    let error_msg = match error {
        "fields" => "<p style=\"color:#c0392b;font-size:.85rem;margin-bottom:1rem\">\
                     Name and device name are required.</p>",
        _        => "",
    };
    format!(
        "<h1>Create Your Identity</h1>\
         <p class=\"swiz-sub\">Set your name and give this server a label. \
         Reachable addresses are configured at startup via the <code>PNET_HOSTS</code> environment variable.</p>\
         {error_msg}\
         <form method=\"post\" action=\"/setup/create\" style=\"display:block\">\
           <input type=\"hidden\" name=\"grade\" value=\"sg\">\
           <label class=\"swiz-label\">Your name or alias</label>\
           <input class=\"swiz-input\" type=\"text\" name=\"alias\" \
                  placeholder=\"e.g. Alice\" required autocomplete=\"off\">\
           <label class=\"swiz-label\">Device name</label>\
           <input class=\"swiz-input\" type=\"text\" name=\"device_alias\" \
                  placeholder=\"e.g. Home Server\" required autocomplete=\"off\">\
           <label class=\"swiz-label\">SG rank (1 = highest priority relay)</label>\
           <input class=\"swiz-input\" type=\"number\" name=\"sg_rank\" \
                  value=\"1\" min=\"1\" max=\"255\" autocomplete=\"off\">\
           <button class=\"swiz-btn\" type=\"submit\">Create Identity</button>\
         </form>\
         <a class=\"swiz-back\" href=\"/setup?grade=sg\">\u{2190} Back</a>"
    )
}

fn render_setup_code_entry(grade: &str) -> String {
    let back = if grade == "sg" { "/setup?grade=sg" } else { "/setup" };
    let form_grade = if grade == "sg" { "sg" } else { "dg" };
    format!(
        "<h1>Enter Invitation Code</h1>\
         <p class=\"swiz-sub\">Paste the invitation code generated on your existing device.</p>\
         <form method=\"post\" action=\"/setup/join\" style=\"display:block\">\
           <input type=\"hidden\" name=\"grade\" value=\"{form_grade}\">\
           <label class=\"swiz-label\">Device name</label>\
           <input name=\"device_alias\" type=\"text\" \
             style=\"width:100%;box-sizing:border-box;padding:.5rem;border:1px solid #ccc;\
                    border-radius:4px;margin-bottom:.75rem;font-size:1rem\" \
             placeholder=\"e.g. My Laptop\" required><br>\
           <label class=\"swiz-label\">Invitation code</label>\
           <textarea name=\"code\" rows=\"4\" \
             style=\"width:100%;box-sizing:border-box;font-family:monospace;\
                    font-size:.8rem;padding:.5rem;border:1px solid #ccc;\
                    border-radius:4px;margin-bottom:.75rem;resize:vertical\" \
             placeholder=\"Paste code here\u{2026}\" required></textarea>\
           <button class=\"swiz-btn\" type=\"submit\">Connect</button>\
         </form>\
         <a class=\"swiz-back\" href=\"{back}\">\u{2190} Back</a>"
    )
}

// ── HTML layout ───────────────────────────────────────────────────────────────

const CSS: &str = "
body { font-family: sans-serif; margin: 0; background: #f5f5f5; color: #222; }
nav { background: #1a1a2e; padding: .75rem 1.5rem; display: flex; align-items: center; gap: 1.5rem; }
nav a { color: #aac; text-decoration: none; font-size: .9rem; }
nav a:hover { color: #fff; }
.brand { color: #fff; font-weight: bold; font-size: 1.1rem; margin-right: 1rem; }
main { padding: 1.5rem 2rem; max-width: 900px; }
h1 { margin-top: 0; font-size: 1.4rem; }
table { border-collapse: collapse; width: 100%; background: white; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
th { background: #eee; text-align: left; padding: .6rem 1rem; font-size: .85rem; color: #555; }
td { padding: .6rem 1rem; border-top: 1px solid #eee; font-size: .9rem; }
.card { background: white; border-radius: 6px; padding: 1.2rem 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); margin-bottom: 1rem; }
.stats { display: flex; gap: 1rem; margin-bottom: 1.5rem; }
.stat-card { background: white; border-radius: 6px; padding: 1rem 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); flex: 1; }
.stat { font-size: 2rem; font-weight: bold; color: #1a1a2e; }
.label { font-size: .8rem; color: #888; }
button { padding: .3rem .8rem; border: none; border-radius: 4px; cursor: pointer; font-size: .85rem; }
.approve { background: #2d7a3b; color: white; }
.reject { background: #c0392b; color: white; margin-left: .4rem; }
form { display: inline; }
.empty { color: #888; font-style: italic; }
";

fn layout(title: &str, body: &str) -> String {
    let mut html = String::with_capacity(4096);
    html.push_str("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>pNet \u{2014} ");
    html.push_str(title);
    html.push_str("</title>\n<style>");
    html.push_str(CSS);
    html.push_str("</style>\n</head>\n<body>\n");
    html.push_str("<nav>\n");
    html.push_str("  <span class=\"brand\">pNet</span>\n");
    html.push_str("  <a href=\"/dashboard\">Dashboard</a>\n");
    html.push_str("  <a href=\"/pending-apps\">Pending Apps</a>\n");
    html.push_str("  <a href=\"/applications\">Applications</a>\n");
    html.push_str("  <a href=\"/contacts\">Contacts</a>\n");
    html.push_str("  <a href=\"/devices\">Devices</a>\n");
    html.push_str("  <a href=\"/invitations\">Invitations</a>\n");
    html.push_str("</nav>\n<main>\n");
    html.push_str(body);
    html.push_str("\n</main>\n</body>\n</html>");
    html
}

const SETUP_CSS: &str = "
.swiz-wrap { max-width: 460px; margin: 5rem auto; padding: 0 1.5rem; }
.swiz-brand { color: #1a1a2e; font-weight: bold; font-size: 1.3rem; margin-bottom: 2.5rem; }
.swiz-wrap h1 { font-size: 1.5rem; margin: 0 0 .4rem; }
.swiz-sub { color: #666; font-size: .9rem; margin: 0 0 1.5rem; line-height: 1.5; }
.choice-btn { display: block; background: white; border: 1px solid #ddd; border-radius: 8px;
              padding: 1rem 1.2rem; margin-bottom: .75rem; text-decoration: none; color: #222;
              box-shadow: 0 1px 3px rgba(0,0,0,.07); transition: border-color .15s; }
.choice-btn:hover { border-color: #1a1a2e; }
.choice-title { display: block; font-weight: bold; font-size: .95rem; }
.choice-desc { display: block; font-size: .8rem; color: #666; margin-top: .25rem; line-height: 1.4; }
.swiz-label { display: block; font-size: .85rem; color: #555; margin-bottom: .3rem; }
.swiz-input { display: block; width: 100%; box-sizing: border-box; padding: .55rem .7rem;
              border: 1px solid #ccc; border-radius: 5px; font-size: .95rem; margin-bottom: 1rem; }
.swiz-btn { background: #1a1a2e; color: white; border: none; border-radius: 5px;
            padding: .55rem 1.4rem; font-size: .95rem; cursor: pointer; }
.swiz-btn:hover { background: #2a2a4e; }
.swiz-back { display: inline-block; margin-top: 1.25rem; font-size: .8rem; color: #888;
             text-decoration: none; }
.swiz-back:hover { color: #444; }
";

fn setup_layout(body: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <title>pNet \u{2014} Setup</title>\n\
         <style>{SETUP_CSS}</style>\n\
         </head>\n<body>\n\
         <div class=\"swiz-wrap\">\
           <div class=\"swiz-brand\">pNet</div>\
           {body}\
         </div>\n</body>\n</html>"
    )
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

            let ctx = WorkerContext { node, udp_socket: pnet_socket, writer_tx, scheduler_tx };
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
    fn app_register_rejects_bad_packet() {
        let t = TestCtx::new();
        app_register(t.app_addr(), vec![], &t.ctx); // empty buf

        let reply = t.recv_reply();
        assert_eq!(reply[0], 0x01); // error
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
        assert_eq!(reply[0], 0x01);
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

        // App's own data.
        let app_id = u16::from_be_bytes([reply[pos], reply[pos + 1]]); pos += 2;
        assert!(app_id > 0);
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

        // Contact count (none registered).
        let contact_count = reply[pos] as usize;
        assert_eq!(contact_count, 0);
    }

    #[test]
    fn app_get_data_unknown_token_returns_error() {
        let t = TestCtx::new();
        app_get_data(t.app_addr(), vec![0xFFu8; 16], &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], 0x01);
        assert_eq!(reply[1], ERR_TOKEN_UNKNOWN);
    }

    // ── Ed25519 helpers ───────────────────────────────────────────────────────

    #[test]
    fn ed25519_roundtrip_valid_signature() {
        let kp  = generate_ed25519_keypair();
        let msg = b"hello pnet";
        let sig = ed25519_sign(&kp.private_key, msg);
        assert!(ed25519_verify(&kp.public_key, msg, &sig));
    }

    #[test]
    fn ed25519_verify_rejects_wrong_key() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();
        let sig  = ed25519_sign(&kp1.private_key, b"msg");
        assert!(!ed25519_verify(&kp2.public_key, b"msg", &sig));
    }

    #[test]
    fn ed25519_verify_rejects_tampered_signature() {
        let kp  = generate_ed25519_keypair();
        let mut sig = ed25519_sign(&kp.private_key, b"msg");
        sig[0] ^= 0xFF;
        assert!(!ed25519_verify(&kp.public_key, b"msg", &sig));
    }

    // ── ConnectRequest ────────────────────────────────────────────────────────

    /// Add a contact with its own Ed25519 key pair to the node.
    /// Returns the contact's device UUID and key pair.
    fn add_contact_with_device(node: &mut Node) -> (Uuid, KeyPair) {
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
        });
        (device_uuid, kp)
    }

    /// Build the buf for connect_request (op byte already stripped).
    fn connect_request_buf(
        conn_id:      u16,
        device_uuid:  &Uuid,
        ephemeral_pk: &PublicKey,
        longterm_pk:  &PublicKey,
        longterm_sk:  &[u8; 32],
        tamper_sig:   bool,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 146];
        buf[0..2].copy_from_slice(&conn_id.to_be_bytes());
        buf[2..18].copy_from_slice(device_uuid);
        buf[18..50].copy_from_slice(ephemeral_pk);
        buf[50..82].copy_from_slice(longterm_pk);

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
        eph_pk:            &PublicKey,
        responder_sk:      &[u8; 32],
        tamper_sig:        bool,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 100];
        buf[0..2].copy_from_slice(&responder_conn_id.to_be_bytes());
        buf[2..4].copy_from_slice(&our_conn_id.to_be_bytes());
        buf[4..36].copy_from_slice(eph_pk);

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
                public_key: generate_key_bytes(),
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
                peer_public_key: generate_key_bytes(),
                peer_active_connection_id: 10,
                device_uuid: slow_uuid,
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
            node.owner.active_connections.insert(2, ActiveConnection {
                id: 2,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: generate_x25519_keypair(),
                peer_public_key: generate_key_bytes(),
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
                peer_public_key: generate_key_bytes(),
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
                peer_public_key: generate_key_bytes(),
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
    fn find_writer_local_rank2_takes_over_when_rank1_disconnected() {
        // No active_connection to the rank-1 peer.
        let t = TestCtx::new();
        promote_local_to_sg(&t, 2);
        add_peer_sg(&t, 1, false, Some(true));
        let node = t.ctx.node.read().unwrap();
        assert_eq!(find_writer_sg(&node), WriterTarget::Local);
    }

    // ── Change serialization & apply ──────────────────────────────────────────

    #[test]
    fn change_add_application_roundtrips() {
        let dev_uuid = generate_uuid();
        let original = Change::AddApplication {
            device_uuid: dev_uuid,
            app_id:      0xCAFE,
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
            app_id:      1,
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
            app_id:      7,
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
        assert_eq!(dev.applications[0].id, 7);
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
            app_id:      7,
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
            app_id:      1,
            app_alias:   "x".to_string(),
        };
        let res = apply_change_locally(&change, local, &t.ctx);
        assert!(matches!(res, Err(WriteError::Validation(_))));

        // No version bumped.
        let node = t.ctx.node.read().unwrap();
        assert!(node.owner.public_version.is_initial());
    }

    // ── request_change driver ────────────────────────────────────────────────

    #[test]
    fn request_change_local_path_applies_directly() {
        let t = TestCtx::new();
        let local = promote_local_to_sg(&t, 1);

        let change = Change::AddApplication {
            device_uuid: local,
            app_id:      9,
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
            app_id:      1,
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
                peer_public_key:           generate_key_bytes(),
                peer_active_connection_id: 22,
                device_uuid:               sg_uuid,
                peer_addr:                 sg_addr,
            });
        }

        let change = Change::AddApplication {
            device_uuid: dg_uuid,
            app_id:      3,
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
    fn sync_write_request_writer_accepts_and_acks_ok() {
        let t = TestCtx::new();
        let (_, dg_conn, dg_socket) = writer_setup_with_capture(&t);
        let dg_uuid = dg_conn.device_uuid;

        let change = Change::AddApplication {
            device_uuid: dg_uuid,
            app_id:      42,
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
            app_id:      1,
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
            app_id:      1,
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
        let app1 = Change::AddApplication { device_uuid: local, app_id: 11, app_alias: "a1".into() };
        let app2 = Change::AddApplication { device_uuid: local, app_id: 22, app_alias: "a2".into() };
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
        let mut ids: Vec<u16> = dst_dev.applications.iter().map(|a| a.id).collect();
        ids.sort();
        assert_eq!(ids, vec![11, 22]);
    }

    #[test]
    fn apply_public_state_preserves_local_app_token_and_host() {
        // The originating DG holds a real token and host for an app it owns.
        // When a Public-state pull lands, alias may update but token/host stay.
        let t = TestCtx::new();
        let local_uuid = t.ctx.node.read().unwrap().device_uuid;
        let real_host: SocketAddrV4 = "10.0.0.1:5555".parse().unwrap();
        let real_token: Uuid = [0x42; 16];
        {
            let mut node = t.ctx.node.write().unwrap();
            let dev = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == local_uuid).unwrap();
            dev.applications.push(Application {
                id: 7, alias: "old-alias".into(),
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
        blob.extend_from_slice(&7u16.to_be_bytes());
        push_str(&mut blob, "new-alias");
        blob.push(0u8); // 0 contacts

        assert!(apply_public_state(&blob, &t.ctx));

        let node = t.ctx.node.read().unwrap();
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == local_uuid).unwrap();
        assert_eq!(dev.applications.len(), 1);
        let app = &dev.applications[0];
        assert_eq!(app.alias, "new-alias", "alias should update from wire");
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
            device_uuid: dg_uuid, app_id: 5, app_alias: "fan".into(),
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
            device_uuid: local_uuid, app_id: 1, app_alias: "ax".into(),
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
            device_uuid: local_uuid, app_id: 1, app_alias: "ax".into(),
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
            device_uuid: writer_local, app_id: 99, app_alias: "ww".into(),
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
        assert_eq!(writer_dev.applications[0].id, 99);
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
                id: 17, alias: "preadded".into(),
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
            device_uuid: local, app_id: 17, app_alias: "preadded".into(),
        }, &t.ctx).expect("request_change ok");

        let node = t.ctx.node.read().unwrap();
        assert_eq!(node.owner.public_version.writer_sg_uuid, local);
        assert_eq!(node.owner.public_version.epoch, 1);
        assert_eq!(node.owner.public_version.seq,   1);

        // App's private fields preserved (apply_change_locally never wrote
        // over them since it was a no-op).
        let dev = node.owner.user.devices.iter().find(|d| d.uuid == local).unwrap();
        let app = dev.applications.iter().find(|a| a.id == 17).unwrap();
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

    // ── Packet encrypt/decrypt round-trip ─────────────────────────────────────

    #[test]
    fn build_and_decrypt_packet_roundtrip() {
        // Simulate two sides of a connection with known key pairs.
        let sender_kp   = generate_x25519_keypair();
        let receiver_kp = generate_x25519_keypair();

        // sender builds a packet addressed to receiver's conn ID 7.
        let conn = ActiveConnection {
            id:                        1,
            timeout:                   SystemTime::now() + Duration::from_secs(3600),
            key_pair:                  sender_kp.clone(),
            peer_public_key:           receiver_kp.public_key,
            peer_active_connection_id: 7,
            device_uuid:               generate_uuid(),
        peer_addr:   "127.0.0.1:0".parse().unwrap(),
        };
        let plaintext = b"hello relay";
        let pkt = build_encrypted_packet(RELAY_PACKET_OP, &conn, plaintext);

        assert_eq!(pkt[0], RELAY_PACKET_OP);
        assert_eq!(u16::from_be_bytes([pkt[1], pkt[2]]), 7);

        // Receiver decrypts: its active connection uses receiver_kp, peer pk = sender_kp.public_key.
        // Receiver stored this connection under its own local ID, which was placed in pkt[1..3] (=7).
        let t = TestCtx::new();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.active_connections.insert(7, ActiveConnection {
                id:                        7,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  receiver_kp,
                peer_public_key:           sender_kp.public_key,
                peer_active_connection_id: 1,
                device_uuid:               generate_uuid(),
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
        }

        let node      = t.ctx.node.read().unwrap();
        let decrypted = decrypt_packet_body(&node, &pkt[1..]).unwrap(); // strip op byte
        assert_eq!(decrypted, plaintext);
    }

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
        let dest_app_id: u16 = 5;
        let sender_app_id: u16 = 3;

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
                public_key: generate_key_bytes(),
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
            });
        }

        // Build a RelayPacket as if sent by the sender DG.
        // Shared secret for SG conn #1 = x25519_shared(dg_sender_sk, sg_from_dg_pk)
        //                               = x25519_shared(sg_from_dg_sk, dg_sender_pk) — same
        let mut relay_body = Vec::new();
        relay_body.extend_from_slice(&dest_device_uuid);
        relay_body.extend_from_slice(&dest_app_id.to_be_bytes());
        relay_body.extend_from_slice(&sender_app_id.to_be_bytes());
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

        // Decrypted body: [dest_app_id: u16][sender_app_id: u16][payload]
        assert_eq!(u16::from_be_bytes([decrypted[0], decrypted[1]]), dest_app_id);
        assert_eq!(u16::from_be_bytes([decrypted[2], decrypted[3]]), sender_app_id);
        assert_eq!(&decrypted[4..], b"payload");
    }

    // ── app_packet delivers to local app ──────────────────────────────────────

    #[test]
    fn app_packet_delivers_to_local_app() {
        let t = TestCtx::new();

        // Set up: an approved app on the local device.
        let app_id: u16     = 9;
        let sender_app_id   = 3u16;
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

        // Build AppPacket body: [dest_app_id: u16][sender_app_id: u16][payload]
        let mut body = Vec::new();
        body.extend_from_slice(&app_id.to_be_bytes());
        body.extend_from_slice(&sender_app_id.to_be_bytes());
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
        assert_eq!(u16::from_be_bytes([push[1], push[2]]), sender_app_id);
        assert_eq!(&push[3..], b"hello app");
    }

    // ── Contact exchange (0x33 / 0x34) ───────────────────────────────────────

    /// Build a ContactRequest buf (after op byte) from the requester's node and
    /// the invitation stored on the target.
    fn contact_request_buf(requester_node: &Node, inv: &Invitation) -> Vec<u8> {
        let ephem_kp      = generate_x25519_keypair();
        let shared_secret = x25519_shared(&ephem_kp.private_key, &inv.key_pair.public_key);
        let payload       = serialize_contact_payload(requester_node);
        let (ciphertext, nonce) = xchacha20_encrypt(&shared_secret, &payload);

        let mut buf = Vec::new();
        buf.extend_from_slice(&inv.id);
        buf.extend_from_slice(&ephem_kp.public_key);
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
                key_pair:   KeyPair {
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
    }

    #[test]
    fn contact_response_valid_adds_contact_and_clears_pending() {
        let requester = TestCtx::new();

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

        // Shared secret from requester's perspective.
        let shared_secret = x25519_shared(&ephem_kp.private_key, &inv_kp.public_key);

        // Build the target's contact payload.
        let target_uuid = generate_uuid();
        let target_pk   = generate_ed25519_keypair().public_key;
        let mut payload = Vec::new();
        push_str(&mut payload, "will");
        payload.extend_from_slice(&target_uuid);
        payload.extend_from_slice(&target_pk);
        payload.push(0u8); // 0 devices

        let (ciphertext, nonce) = xchacha20_encrypt(&shared_secret, &payload);
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

        let shared_secret = x25519_shared(&ephem_kp.private_key, &inv_kp.public_key);
        let mut payload = Vec::new();
        push_str(&mut payload, "will");
        payload.extend_from_slice(&generate_uuid());
        payload.extend_from_slice(&generate_key_bytes());
        payload.push(0u8);
        let (ciphertext, nonce) = xchacha20_encrypt(&shared_secret, &payload);
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
                public_key: generate_key_bytes(),
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
    fn contact_data_push_updates_contact_devices() {
        let t = TestCtx::new();
        let contact_uuid    = generate_uuid();
        let contact_sg_uuid = generate_uuid();
        // contact_sg_host doesn't need to be reachable; we just check state changes.
        let contact_sg_host: std::net::SocketAddrV4 = "127.0.0.1:19900".parse().unwrap();

        let (_, sender_conn) = setup_sg_node_with_contact_conn(
            &t, contact_uuid, contact_sg_uuid, contact_sg_host,
        );

        // Build a ContactDataPush payload: contact user has 1 device + 1 approved app.
        let new_device_uuid = generate_uuid();
        let mut payload = Vec::new();
        payload.extend_from_slice(&contact_uuid); // user_uuid
        payload.push(1u8);                        // device_count
        // device: uuid + alias + grade(SG=1) + sg_rank(1) + ip + port
        push_device(&mut payload, &Device {
            alias:           "chad-laptop".to_string(),
            uuid:            new_device_uuid,
            grade:           DeviceGrade::SG,
            sg_rank:         Some(1),
            hosts:           vec!["127.0.0.1:8888".into()],
            applications:    Vec::new(),
        });
        payload.push(1u8);              // app_count
        payload.extend_from_slice(&42u16.to_be_bytes()); // app id
        push_str(&mut payload, "chad-app");

        let pkt = build_encrypted_packet(CONTACT_DATA_PUSH_OP, &sender_conn, &payload);
        contact_data_push(t.app_addr(), pkt[1..].to_vec(), &t.ctx);

        // Contact's device list should now reflect the pushed data.
        let node = t.ctx.node.read().unwrap();
        let contact = node.owner.contact_users.iter()
            .find(|c| c.user.uuid == contact_uuid)
            .expect("contact not found");
        assert_eq!(contact.user.devices.len(), 1);
        assert_eq!(contact.user.devices[0].alias, "chad-laptop");
        assert_eq!(contact.user.devices[0].applications.len(), 1);
        assert_eq!(contact.user.devices[0].applications[0].id, 42);
        assert_eq!(contact.user.devices[0].applications[0].alias, "chad-app");
    }

    #[test]
    fn contact_data_push_ignores_unknown_user() {
        let t = TestCtx::new();
        let contact_uuid    = generate_uuid();
        let contact_sg_uuid = generate_uuid();
        let contact_sg_host: std::net::SocketAddrV4 = "127.0.0.1:19901".parse().unwrap();

        let (_, sender_conn) = setup_sg_node_with_contact_conn(
            &t, contact_uuid, contact_sg_uuid, contact_sg_host,
        );

        // Push data for a UUID that is not in our contacts.
        let unknown_uuid = generate_uuid();
        let mut payload = Vec::new();
        payload.extend_from_slice(&unknown_uuid);
        payload.push(0u8); // 0 devices
        let pkt = build_encrypted_packet(CONTACT_DATA_PUSH_OP, &sender_conn, &payload);
        contact_data_push(t.app_addr(), pkt[1..].to_vec(), &t.ctx);

        // Contact list should be unchanged.
        let node = t.ctx.node.read().unwrap();
        assert_eq!(node.owner.contact_users.len(), 1);
        assert_eq!(node.owner.contact_users[0].user.uuid, contact_uuid);
    }

    #[test]
    fn contact_data_pull_request_replies_with_push() {
        let contact_sg_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        contact_sg_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let contact_sg_addr: std::net::SocketAddrV4 =
            contact_sg_socket.local_addr().unwrap().to_string().parse().unwrap();

        let t = TestCtx::new();
        let contact_uuid    = generate_uuid();
        let contact_sg_uuid = generate_uuid();

        let (conn_id, sender_conn) = setup_sg_node_with_contact_conn(
            &t, contact_uuid, contact_sg_uuid, contact_sg_addr,
        );

        // Encrypt a pull request: body is just our user_uuid.
        let our_uuid = t.ctx.node.read().unwrap().owner.user.uuid;
        let pkt = build_encrypted_packet(CONTACT_DATA_PULL_REQ_OP, &sender_conn, &our_uuid);

        // Handler receives from contact_sg_addr so the reply goes there.
        contact_data_pull_request(
            SocketAddr::V4(contact_sg_addr),
            pkt[1..].to_vec(),
            &t.ctx,
        );

        // Contact's SG socket should have received a ContactDataPush.
        let mut buf = [0u8; 1024];
        let (len, _) = contact_sg_socket.recv_from(&mut buf)
            .expect("no ContactDataPush reply received");
        assert_eq!(buf[0], CONTACT_DATA_PUSH_OP);

        // The reply must decrypt correctly from the contact SG's perspective.
        // The reply header carries sender_conn.id (42) as the connection ID,
        // so decrypt_packet_body will look up that key in active_connections.
        let sender_conn_id = sender_conn.id;
        let mut reply_node = Node::new();
        reply_node.owner.active_connections.insert(sender_conn_id, ActiveConnection {
            id:                        sender_conn_id,
            timeout:                   SystemTime::now() + Duration::from_secs(3600),
            key_pair:                  sender_conn.key_pair,
            peer_public_key:           sender_conn.peer_public_key,
            peer_active_connection_id: sender_conn.peer_active_connection_id,
            device_uuid:               sender_conn.device_uuid,
        peer_addr:   "127.0.0.1:0".parse().unwrap(),
        });
        let plaintext = decrypt_packet_body(&reply_node, &buf[1..len])
            .expect("reply decryption failed");

        // Payload starts with this node's user UUID.
        let reply_uuid: Uuid = plaintext[0..16].try_into().unwrap();
        assert_eq!(reply_uuid, our_uuid);
    }

    #[test]
    fn push_data_to_contacts_sends_to_active_sg_connections() {
        let contact_sg_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        contact_sg_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let contact_sg_addr: std::net::SocketAddrV4 =
            contact_sg_socket.local_addr().unwrap().to_string().parse().unwrap();

        let t = TestCtx::new();
        let contact_uuid    = generate_uuid();
        let contact_sg_uuid = generate_uuid();

        setup_sg_node_with_contact_conn(&t, contact_uuid, contact_sg_uuid, contact_sg_addr);

        push_data_to_contacts(&t.ctx);

        let mut buf = [0u8; 512];
        let (len, _) = contact_sg_socket.recv_from(&mut buf)
            .expect("no ContactDataPush received");
        assert_eq!(buf[0], CONTACT_DATA_PUSH_OP);
        assert!(len > 1);
    }

    #[test]
    fn push_data_to_contacts_skips_dg_nodes() {
        // If this node is a DG, push_data_to_contacts should be a no-op.
        let contact_sg_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        contact_sg_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let contact_sg_addr: std::net::SocketAddrV4 =
            contact_sg_socket.local_addr().unwrap().to_string().parse().unwrap();

        let t = TestCtx::new();
        // Node defaults to DG — do NOT call setup_sg_node_with_contact_conn
        // (which upgrades to SG).  Add a contact manually.
        {
            let mut node = t.ctx.node.write().unwrap();
            let contact_sg_uuid = generate_uuid();
            node.owner.contact_users.push(Contact {
                public_key: generate_key_bytes(),
                user: User {
                    alias:   "chad".to_string(),
                    uuid:    generate_uuid(),
                    devices: vec![Device {
                        alias:           "chad-sg".to_string(),
                        uuid:            contact_sg_uuid,
                        grade:           DeviceGrade::SG,
                        sg_rank:         Some(1),
                        hosts:           vec![contact_sg_addr.to_string()],
                        applications:    Vec::new(),
                    }],
                },
            });
            node.owner.active_connections.insert(1, ActiveConnection {
                id:                        1,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  generate_x25519_keypair(),
                peer_public_key:           generate_key_bytes(),
                peer_active_connection_id: 10,
                device_uuid:               contact_sg_uuid,
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
        }

        push_data_to_contacts(&t.ctx);

        // No packet should arrive.
        let mut buf = [0u8; 64];
        assert!(
            contact_sg_socket.recv_from(&mut buf).is_err(),
            "DG should not push contact data"
        );
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
                    id:            7,
                    alias:         "test-app".to_string(),
                    protocol:      "udp".to_string(),
                    host:          "127.0.0.1:5000".parse().unwrap(),
                    user_approved: true,
                    token:         generate_uuid(),
                });
                dev.applications.push(Application {
                    id:            8,
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
        assert_eq!(apps[0].0, 7);
        assert_eq!(apps[0].1, "test-app");
    }

    // ── Device data sync ──────────────────────────────────────────────────────

    /// Set up the test node as an SG with a second own device (DG) that has an
    /// active connection.  Returns the DG's UUID and the connection.
    fn setup_sg_with_own_dg_conn(t: &TestCtx) -> (Uuid, std::net::SocketAddrV4, ActiveConnection) {
        let sg_kp  = generate_x25519_keypair();
        let dg_kp  = generate_x25519_keypair();
        let conn_id = 5u16;

        let dg_uuid: Uuid = generate_uuid();
        let dg_addr: std::net::SocketAddrV4 = "127.0.0.1:0".parse().unwrap();

        {
            let mut node = t.ctx.node.write().unwrap();
            let local_uuid = node.device_uuid;

            // Upgrade local device to SG.
            if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == local_uuid) {
                dev.grade   = DeviceGrade::SG;
                dev.sg_rank = Some(1);
            }

            // Add the DG to the owner's device list.
            node.owner.user.devices.push(Device {
                alias:           "my-dg".to_string(),
                uuid:            dg_uuid,
                grade:           DeviceGrade::DG,
                sg_rank:         None,
                hosts:           vec![dg_addr.to_string()],
                applications:    Vec::new(),
            });

            // Active connection to the DG.
            node.owner.active_connections.insert(conn_id, ActiveConnection {
                id:                        conn_id,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  sg_kp.clone(),
                peer_public_key:           dg_kp.public_key,
                peer_active_connection_id: 99,
                device_uuid:               dg_uuid,
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
        }

        // Connection from DG's perspective (for encrypting packets to the SG).
        let dg_conn = ActiveConnection {
            id:                        99,
            timeout:                   SystemTime::now() + Duration::from_secs(3600),
            key_pair:                  dg_kp,
            peer_public_key:           sg_kp.public_key,
            peer_active_connection_id: conn_id,
            device_uuid:               dg_uuid,
        peer_addr:   "127.0.0.1:0".parse().unwrap(),
        };

        (dg_uuid, dg_addr, dg_conn)
    }

    #[test]
    fn device_data_push_updates_device_and_contact_lists() {
        let t = TestCtx::new();
        let contact_uuid    = generate_uuid();
        let contact_sg_uuid = generate_uuid();
        let contact_sg_host: std::net::SocketAddrV4 = "127.0.0.1:19910".parse().unwrap();

        let (_, sender_conn) = setup_sg_node_with_contact_conn(
            &t, contact_uuid, contact_sg_uuid, contact_sg_host,
        );

        // Add a second own device to the sender_conn's node so the push payload
        // carries both devices and the contact.
        let new_device_uuid = generate_uuid();
        {
            let mut node = t.ctx.node.write().unwrap();
            node.owner.user.devices.push(Device {
                alias:           "my-phone".to_string(),
                uuid:            new_device_uuid,
                grade:           DeviceGrade::DG,
                sg_rank:         None,
                hosts:           vec!["127.0.0.1:0".into()],
                applications:    Vec::new(),
            });
        }

        // Build and send a DeviceDataPush packet.
        let payload = serialize_device_sync_payload(&t.ctx.node.read().unwrap());
        let pkt = build_encrypted_packet(DEVICE_DATA_PUSH_OP, &sender_conn, &payload);

        // Create a fresh node to receive the push (simulates the DG).
        let receiver = TestCtx::new();
        {
            // Give the receiver an active connection that can decrypt the push.
            let mut node = receiver.ctx.node.write().unwrap();
            let recv_conn_id = u16::from_be_bytes([pkt[1], pkt[2]]);
            node.owner.active_connections.insert(recv_conn_id, ActiveConnection {
                id:                        recv_conn_id,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  sender_conn.key_pair.clone(),
                peer_public_key:           sender_conn.peer_public_key,
                peer_active_connection_id: sender_conn.peer_active_connection_id,
                device_uuid:               sender_conn.device_uuid,
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
        }

        device_data_push(t.app_addr(), pkt[1..].to_vec(), &receiver.ctx);

        let node = receiver.ctx.node.read().unwrap();
        // Device list should now include the new device.
        assert!(node.owner.user.devices.iter().any(|d| d.uuid == new_device_uuid));
        // Contact list should be populated.
        assert_eq!(node.owner.contact_users.len(), 1);
        assert_eq!(node.owner.contact_users[0].user.uuid, contact_uuid);
    }

    #[test]
    fn device_data_push_preserves_own_apps() {
        // When a DG receives a DeviceDataPush, its locally registered apps must
        // not be wiped even though the SG doesn't include them in the payload.
        let t = TestCtx::new();
        let (_, _, sender_conn) = setup_sg_with_own_dg_conn(&t);

        // The receiver is the DG — give it a local app.
        let receiver = TestCtx::new();
        let receiver_uuid = receiver.ctx.node.read().unwrap().device_uuid;
        {
            let mut node = receiver.ctx.node.write().unwrap();
            if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == receiver_uuid) {
                dev.applications.push(Application {
                    id:            55,
                    alias:         "local-app".to_string(),
                    protocol:      "udp".to_string(),
                    host:          "127.0.0.1:9000".parse().unwrap(),
                    user_approved: true,
                    token:         generate_uuid(),
                });
            }
            // Add the receiver's own device to the sender's device list so it
            // appears in the payload (SG knows about this device).
            let dg_device = Device {
                alias:           "my-dg".to_string(),
                uuid:            receiver_uuid,
                grade:           DeviceGrade::DG,
                sg_rank:         None,
                hosts:           vec!["127.0.0.1:0".into()],
                applications:    Vec::new(), // SG has no apps for this device
            };
            // Insert into the sender's node as well.
            drop(node);
            t.ctx.node.write().unwrap().owner.user.devices.push(dg_device);
        }

        let payload = serialize_device_sync_payload(&t.ctx.node.read().unwrap());
        let pkt = build_encrypted_packet(DEVICE_DATA_PUSH_OP, &sender_conn, &payload);

        {
            let mut node = receiver.ctx.node.write().unwrap();
            let recv_conn_id = u16::from_be_bytes([pkt[1], pkt[2]]);
            node.owner.active_connections.insert(recv_conn_id, ActiveConnection {
                id:                        recv_conn_id,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  sender_conn.key_pair.clone(),
                peer_public_key:           sender_conn.peer_public_key,
                peer_active_connection_id: sender_conn.peer_active_connection_id,
                device_uuid:               sender_conn.device_uuid,
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
        }

        device_data_push(t.app_addr(), pkt[1..].to_vec(), &receiver.ctx);

        let node = receiver.ctx.node.read().unwrap();
        let own_dev = node.owner.user.devices.iter()
            .find(|d| d.uuid == receiver_uuid)
            .expect("own device missing after push");
        assert_eq!(own_dev.applications.len(), 1, "local app was wiped by device sync");
        assert_eq!(own_dev.applications[0].id, 55);
    }

    #[test]
    fn device_data_pull_request_replies_with_push() {
        let dg_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        dg_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let dg_addr: std::net::SocketAddrV4 =
            dg_socket.local_addr().unwrap().to_string().parse().unwrap();

        let t = TestCtx::new();
        let (dg_uuid, _, dg_conn) = setup_sg_with_own_dg_conn(&t);
        // Retarget the DG's active connection so the reply packet reaches our
        // listening socket.  `dev.hosts` no longer drives outgoing routing —
        // the active connection's `peer_addr` does.
        {
            let mut node = t.ctx.node.write().unwrap();
            if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == dg_uuid) {
                dev.hosts = vec![dg_addr.to_string()];
            }
            for c in node.owner.active_connections.values_mut() {
                if c.device_uuid == dg_uuid {
                    c.peer_addr = SocketAddr::V4(dg_addr);
                }
            }
        }

        // DG sends a pull request with an empty app list (no apps registered yet).
        let pkt = build_encrypted_packet(DEVICE_DATA_PULL_REQ_OP, &dg_conn, &[0u8]);
        device_data_pull_request(SocketAddr::V4(dg_addr), pkt[1..].to_vec(), &t.ctx);

        // DG socket should receive a DeviceDataPush.
        let mut buf = [0u8; 4096];
        let (len, _) = dg_socket.recv_from(&mut buf)
            .expect("no DeviceDataPush reply received");
        assert_eq!(buf[0], DEVICE_DATA_PUSH_OP);

        // Reply must decrypt correctly from the DG's perspective.
        let mut reply_node = Node::new();
        let reply_conn_id = u16::from_be_bytes([buf[1], buf[2]]);
        reply_node.owner.active_connections.insert(reply_conn_id, ActiveConnection {
            id:                        reply_conn_id,
            timeout:                   SystemTime::now() + Duration::from_secs(3600),
            key_pair:                  dg_conn.key_pair,
            peer_public_key:           dg_conn.peer_public_key,
            peer_active_connection_id: dg_conn.peer_active_connection_id,
            device_uuid:               dg_conn.device_uuid,
        peer_addr:   "127.0.0.1:0".parse().unwrap(),
        });
        let plaintext = decrypt_packet_body(&reply_node, &buf[1..len])
            .expect("reply decryption failed");

        let data = deserialize_device_sync_payload(&plaintext)
            .expect("deserialization of pull reply failed");
        assert!(!data.devices.is_empty());
    }

    #[test]
    fn push_data_to_devices_sends_to_own_dg_connections() {
        let dg_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        dg_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let dg_addr: std::net::SocketAddrV4 =
            dg_socket.local_addr().unwrap().to_string().parse().unwrap();

        let t = TestCtx::new();
        let (dg_uuid, _, _) = setup_sg_with_own_dg_conn(&t);
        // Retarget the DG's active connection so the reply packet reaches our
        // listening socket.  `dev.hosts` no longer drives outgoing routing —
        // the active connection's `peer_addr` does.
        {
            let mut node = t.ctx.node.write().unwrap();
            if let Some(dev) = node.owner.user.devices.iter_mut().find(|d| d.uuid == dg_uuid) {
                dev.hosts = vec![dg_addr.to_string()];
            }
            for c in node.owner.active_connections.values_mut() {
                if c.device_uuid == dg_uuid {
                    c.peer_addr = SocketAddr::V4(dg_addr);
                }
            }
        }

        push_data_to_devices(&t.ctx);

        let mut buf = [0u8; 512];
        let (len, _) = dg_socket.recv_from(&mut buf)
            .expect("no DeviceDataPush received");
        assert_eq!(buf[0], DEVICE_DATA_PUSH_OP);
        assert!(len > 1);
    }

    #[test]
    fn push_data_to_devices_skips_dg_nodes() {
        // A DG should never push device data.
        let peer_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer_socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let peer_addr: std::net::SocketAddrV4 =
            peer_socket.local_addr().unwrap().to_string().parse().unwrap();

        let t = TestCtx::new();
        // Node starts as DG; add a peer device with a connection but don't upgrade to SG.
        {
            let mut node = t.ctx.node.write().unwrap();
            let peer_uuid = generate_uuid();
            node.owner.user.devices.push(Device {
                alias:           "peer".to_string(),
                uuid:            peer_uuid,
                grade:           DeviceGrade::SG,
                sg_rank:         Some(1),
                hosts:           vec![peer_addr.to_string()],
                applications:    Vec::new(),
            });
            node.owner.active_connections.insert(1, ActiveConnection {
                id:                        1,
                timeout:                   SystemTime::now() + Duration::from_secs(3600),
                key_pair:                  generate_x25519_keypair(),
                peer_public_key:           generate_key_bytes(),
                peer_active_connection_id: 10,
                device_uuid:               peer_uuid,
            peer_addr:   "127.0.0.1:0".parse().unwrap(),
            });
        }

        push_data_to_devices(&t.ctx);

        let mut buf = [0u8; 64];
        assert!(
            peer_socket.recv_from(&mut buf).is_err(),
            "DG should not push device data"
        );
    }

    #[test]
    fn device_sync_roundtrip_serialization() {
        let t = TestCtx::new();
        let contact_uuid    = generate_uuid();
        let contact_sg_uuid = generate_uuid();
        let contact_sg_host: std::net::SocketAddrV4 = "127.0.0.1:19920".parse().unwrap();

        setup_sg_node_with_contact_conn(&t, contact_uuid, contact_sg_uuid, contact_sg_host);

        // Add an app to the contact's device so it appears in the serialized payload.
        {
            let mut node = t.ctx.node.write().unwrap();
            if let Some(contact) = node.owner.contact_users.iter_mut().find(|c| c.user.uuid == contact_uuid) {
                if let Some(dev) = contact.user.devices.first_mut() {
                    dev.applications.push(Application {
                        id:            11,
                        alias:         "contact-app".to_string(),
                        protocol:      "udp".to_string(),
                        host:          "127.0.0.1:0".parse().unwrap(),
                        user_approved: true,
                        token:         generate_uuid(),
                    });
                }
            }
        }

        let payload = serialize_device_sync_payload(&t.ctx.node.read().unwrap());
        let data = deserialize_device_sync_payload(&payload).expect("deserialization failed");

        let node = t.ctx.node.read().unwrap();
        assert_eq!(data.devices.len(), node.owner.user.devices.len());
        assert_eq!(data.contacts.len(), 1);
        assert_eq!(data.contacts[0].user.uuid, contact_uuid);
        assert_eq!(data.contacts[0].user.devices.len(), 1);
        assert_eq!(data.contacts[0].user.devices[0].applications.len(), 1);
        assert_eq!(data.contacts[0].user.devices[0].applications[0].id, 11);
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

    // ── Sync v1 wire-format helpers ───────────────────────────────────────────

    #[test]
    fn sync_version_roundtrips_through_wire_format() {
        let v = SyncVersion {
            writer_sg_uuid: [0xAB; 16],
            epoch: 0xCAFEBABE,
            seq:   0x0102_0304_0506_0708,
        };
        let mut buf = Vec::new();
        write_sync_version(&mut buf, &v);
        assert_eq!(buf.len(), SYNC_VERSION_WIRE_LEN);

        let mut pos = 0usize;
        let restored = read_sync_version(&buf, &mut pos).expect("read version");
        assert_eq!(pos, SYNC_VERSION_WIRE_LEN);
        assert_eq!(restored, v);
    }

    #[test]
    fn sync_version_zero_roundtrips() {
        let v = SyncVersion::zero();
        let mut buf = Vec::new();
        write_sync_version(&mut buf, &v);
        let mut pos = 0usize;
        let restored = read_sync_version(&buf, &mut pos).expect("read zero");
        assert_eq!(restored, v);
        assert!(restored.is_initial());
    }

    #[test]
    fn sync_version_truncated_returns_none() {
        // Write a full version, then truncate by one byte and confirm read fails.
        let v = SyncVersion { writer_sg_uuid: [1; 16], epoch: 7, seq: 9 };
        let mut buf = Vec::new();
        write_sync_version(&mut buf, &v);
        buf.pop();
        let mut pos = 0usize;
        assert!(read_sync_version(&buf, &mut pos).is_none());
    }

    #[test]
    fn scope_roundtrips_both_variants() {
        for scope in [Scope::Private, Scope::Public] {
            let mut buf = Vec::new();
            write_scope(&mut buf, scope);
            assert_eq!(buf.len(), 1);
            let mut pos = 0usize;
            let restored = read_scope(&buf, &mut pos).expect("read scope");
            assert_eq!(restored, scope);
            assert_eq!(pos, 1);
        }
    }

    #[test]
    fn read_scope_rejects_unknown_byte() {
        let buf = [0x99u8];
        let mut pos = 0usize;
        assert!(read_scope(&buf, &mut pos).is_none());
    }
}
