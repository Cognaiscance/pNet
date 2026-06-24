use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

use super::action_queue::WorkerContext;
use super::data_models::{
    ActiveConnection, ActiveTunnel, Application, Contact, Device, DeviceGrade, Invitation,
    KeyPair, Owner, PendingBootstrap, PendingConnection, PendingContactExchange,
    PendingDeviceAcceptance, PendingTunnel, PendingTunnelConnection, PublicKey, Scope, SgStatus,
    SyncVersion, TunnelCounter, User, Uuid, WriteLogEntry, WRITE_LOG_RETENTION,
    CONNECTION_LIFETIME, PENDING_CONNECTION_TIMEOUT,
    RENEW_THRESHOLD, TUNNEL_COUNTER_WINDOW, TUNNEL_THRESHOLD, generate_key_bytes, generate_uuid,
};

// ── Reply status bytes ────────────────────────────────────────────────────────
const OK:                u8 = 0x00;
const ERR_BAD_PACKET:    u8 = 0x01;
const ERR_TOKEN_UNKNOWN: u8 = 0x02;
const ERR_NO_WRITER:     u8 = 0x03;

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

    let host_addr = SocketAddrV4::new(ip, port);

    // Update node.
    let (token, next_id, device_uuid, is_new) = {
        let mut node = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;

        let device = node
            .owner
            .user
            .devices
            .iter_mut()
            .find(|d| d.uuid == device_uuid)
            .expect("local device not found in node");

        // Idempotent re-registration. OP_REGISTER is UDP and the app re-sends
        // when its ACK is lost (and on restart from the same endpoint); without
        // this each retry would spawn a duplicate app, since ids are UUIDs
        // minted per call. Key on (alias, host): the same app at the same
        // endpoint is one logical app — reuse its id+token.
        if let Some(existing) = device
            .applications
            .iter()
            .find(|a| a.alias == alias && a.host == host_addr)
        {
            (existing.token, existing.id, device_uuid, false)
        } else {
            // App ids are UUIDs (see Application.id docs) — partition-safe by
            // construction. Generate fresh; collision probability is negligible.
            let next_id = generate_uuid();
            let token = generate_uuid();
            device.applications.push(Application {
                id: next_id,
                alias,
                protocol,
                host: host_addr,
                user_approved: auto_approve,
                token,
            });
            (token, next_id, device_uuid, true)
        }
        // write lock released here
    };

    if auto_approve && is_new {
        // Sync v1: publish id+alias to peers via the writer SG. A DG without
        // a reachable writer SG cannot publish state changes — roll back the
        // local app and reject the registration. The caller is responsible
        // for retrying when a writer is online.
        if let Err(e) = request_change(Change::AddApplication {
            device_uuid,
            app_id:    next_id,
            app_alias: alias_for_log.clone(),
        }, ctx) {
            {
                let mut node = ctx.node.write().unwrap();
                if let Some(device) = node.owner.user.devices.iter_mut()
                    .find(|d| d.uuid == device_uuid)
                {
                    device.applications.retain(|a| a.id != next_id);
                }
            }
            ctx.save_node();
            eprintln!("[app_register] rejecting '{alias_for_log}': {e:?}");
            return send_error(ctx, src, ERR_NO_WRITER);
        }
        println!("[app_register] auto-approved '{alias_for_log}' via PNET_AUTO_APPROVE_APPS");
    }

    ctx.save_node();

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

    // Update node. Capture (device_uuid, app_id, old_alias) so an
    // unsuccessful sync v1 publish can roll back to the prior alias.
    // Port/host is private-scope — local-only, no sync v1 traffic.
    enum Outcome {
        NotFound,
        Updated { device_uuid: Uuid, app_id: Uuid, old_alias: Option<String> },
    }
    let outcome = {
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
            let app_id = app.id;
            let mut old_alias = None;
            if let Some(alias) = new_alias {
                if app.alias != alias {
                    old_alias = Some(std::mem::replace(&mut app.alias, alias));
                }
            }
            if let Some(port) = new_port {
                if let Some(ip) = ipv4_from(src) {
                    app.host = SocketAddrV4::new(ip, port);
                }
            }
            Outcome::Updated { device_uuid, app_id, old_alias }
        } else {
            Outcome::NotFound
        }
        // write lock released here
    };

    match outcome {
        Outcome::NotFound => send_error(ctx, src, ERR_TOKEN_UNKNOWN),
        Outcome::Updated { device_uuid, app_id, old_alias } => {
            ctx.save_node();

            // Publish the alias change via sync v1 only if the alias actually
            // changed. Port/host is private — never goes over the wire.
            if let Some(prior_alias) = old_alias {
                let new_alias = {
                    let node = ctx.node.read().unwrap();
                    node.owner.user.devices.iter()
                        .find(|d| d.uuid == device_uuid)
                        .and_then(|d| d.applications.iter().find(|a| a.id == app_id))
                        .map(|a| a.alias.clone())
                        .unwrap_or_default()
                };
                if let Err(e) = request_change(Change::UpdateApplicationAlias {
                    device_uuid,
                    app_id,
                    new_alias,
                }, ctx) {
                    // Roll back the alias only; port/host change (if any) was
                    // private-scope and stays.
                    {
                        let mut node = ctx.node.write().unwrap();
                        if let Some(dev) = node.owner.user.devices.iter_mut()
                            .find(|d| d.uuid == device_uuid)
                        {
                            if let Some(app) = dev.applications.iter_mut().find(|a| a.id == app_id) {
                                app.alias = prior_alias;
                            }
                        }
                    }
                    ctx.save_node();
                    eprintln!("[app_update] alias rollback for app {}: {e:?}", uuid_hex(&app_id));
                    return send_error(ctx, src, ERR_NO_WRITER);
                }
            }

            send(ctx, src, &[OK]);
        }
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
    reply.extend_from_slice(&app.id);
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
            reply.extend_from_slice(&a.id);
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
                reply.extend_from_slice(&a.id);
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
    const MIN_LEN: usize = 16 + 16 + 16;
    if buf.len() < MIN_LEN {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }

    let token: Uuid            = buf[0..16].try_into().unwrap();
    let dest_device_uuid: Uuid = buf[16..32].try_into().unwrap();
    let dest_app_id: Uuid      = buf[32..48].try_into().unwrap();
    let payload                = &buf[48..];

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

            // Plaintext format: [dest_app_id: 16][sender_app_id: 16][payload]
            let mut plaintext = Vec::with_capacity(32 + payload.len());
            plaintext.extend_from_slice(&dest_app_id);
            plaintext.extend_from_slice(&sender_app_id);
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
            let mut app_body = Vec::with_capacity(32 + payload.len());
            app_body.extend_from_slice(&dest_app_id);
            app_body.extend_from_slice(&sender_app_id);
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

            // RelayPacket body: [dest_device_uuid: 16][dest_app_id: 16][sender_app_id: 16][payload]
            let mut plaintext = Vec::with_capacity(48 + payload.len());
            plaintext.extend_from_slice(&dest_device_uuid);
            plaintext.extend_from_slice(&dest_app_id);
            plaintext.extend_from_slice(&sender_app_id);
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
// 0x35/0x36 — a DG asks its top-ranked online SG to mint an invitation and
// return the encoded code. Invitations are device-local (never synced), so the
// SG that the code points to must be the one that stores it; having that SG
// mint it guarantees the invitation exists before the code can be used.
const GENERATE_INVITATION_REQUEST_OP:  u8 = 0x35;
const GENERATE_INVITATION_RESPONSE_OP: u8 = 0x36;

// Invitation kind byte in the 0x35 request / local mint path.
const INVITE_TYPE_DEVICE:  u8 = 0x00;
const INVITE_TYPE_CONTACT: u8 = 0x01;
// Result byte in the 0x36 response.
const INVITE_RESULT_OK:    u8 = 0x00;
const INVITE_RESULT_ERROR: u8 = 0x01;
// Sync v1 ops (see descriptions/data sync.md).
// 0x70/0x71 — DG/SG→writer write request and writer→originator ack.
// 0x72      — writer→peers "you have a stale version, pull when ready".
// 0x73/0x74 — any node→writer pull request and writer's response (delta or NoUpdates).
const SYNC_WRITE_REQUEST_OP:    u8 = 0x70;
const SYNC_WRITE_ACK_OP:        u8 = 0x71;
const SYNC_UPDATE_AVAILABLE_OP: u8 = 0x72;
const SYNC_PULL_REQUEST_OP:     u8 = 0x73;
const SYNC_PULL_RESPONSE_OP:    u8 = 0x74;
// 0x75/0x76/0x77 — cross-user public-scope sync: writer SG → contacts' SGs
// for UpdateAvailable, and the contact's SG → writer SG round trip for the
// pull request/response. Body layouts mirror the intra-user variants, but
// the receiver identifies the *sender's user* via the active connection's
// contact mapping rather than treating the payload as local user state.
const CROSS_USER_UPDATE_AVAILABLE_OP: u8 = 0x75;
const CROSS_USER_PULL_REQUEST_OP:     u8 = 0x76;
const CROSS_USER_PULL_RESPONSE_OP:    u8 = 0x77;
// 0x7A/0x7B — sync v2 watermark exchange between own-user SGs. Sent on
// SG↔SG reconnect to find the per-writer agreed-point used by the merge
// protocol (0x78/0x79).
const WATERMARK_PROBE_REQUEST_OP:  u8 = 0x7A;
const WATERMARK_PROBE_RESPONSE_OP: u8 = 0x7B;
// 0x78/0x79 — sync v2 merge proposal exchange. After watermark discovery,
// each side ships its write-log entries above the agreed per-writer
// watermark; the receiver merges and acks. 7c.4 wires the receive-and-
// store path; the actual merge logic lands in 7c.5/7c.6.
const MERGE_PROPOSAL_OP: u8 = 0x78;
const MERGE_ACK_OP:      u8 = 0x79;

const MERGE_ACK_RESULT_APPLIED:            u8 = 0;
const MERGE_ACK_RESULT_RETENTION_EXHAUSTED: u8 = 1;
const MERGE_ACK_RESULT_MALFORMED:          u8 = 2;
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

/// Determine the writer SG from this node's perspective, for the write path.
///
/// Two-tier selection:
///
/// 1. **Known-writer fast path**: if our `public_version.writer_sg_uuid` is
///    populated from a prior `SyncPullResponse` or `SyncWriteAck`, the network
///    has told us who the writer is. Use that — return `Remote` if reachable,
///    fall through to the rank walk if not (so partition recovery / failover
///    can elect a new writer).
/// 2. **Rank walk** (fresh node, or known writer down): walk SGs by rank.
///    At our own UUID return `Local`. At a higher-rank peer:
///    - If `sg_statuses` has entries that unanimously say down, skip it —
///      failover treats it as out of the network.
///    - Else if reachable (active connection + not polled-down), return `Remote`.
///    - Else return `Unreachable`. Do **not** fall through to lower-rank
///      SGs: writing to a non-writer would just elicit `NOT_WRITER` acks that
///      currently fall on the floor (see [[pnet-sync-v1-design-rules]]).
///
/// Used for both originating writes (where to send `SyncWriteRequest`) and
/// for the SG-side accept decision (`Local` ↔ I'll accept this write).
pub fn find_writer_sg(node: &super::data_models::Node) -> WriterTarget {
    let local_uuid = node.device_uuid;

    if !node.owner.public_version.is_initial() {
        let known = node.owner.public_version.writer_sg_uuid;
        if known == local_uuid {
            return WriterTarget::Local;
        }
        if let Some(t) = remote_if_reachable(node, &known) {
            return t;
        }
        // Known writer unreachable — fall through to rank walk for failover.
    }

    let mut sgs: Vec<&Device> = node.owner.user.devices.iter()
        .filter(|d| matches!(d.grade, DeviceGrade::SG))
        .collect();
    sgs.sort_by_key(|d| d.sg_rank.unwrap_or(u32::MAX));

    for d in &sgs {
        if d.uuid == local_uuid {
            return WriterTarget::Local;
        }
        if is_polled_down(node, &d.uuid) {
            continue;
        }
        if let Some(t) = remote_if_reachable(node, &d.uuid) {
            return t;
        }
        return WriterTarget::Unreachable;
    }
    WriterTarget::Unreachable
}

/// `Some(Remote(uuid))` iff we have an active connection to `uuid` AND poll
/// data either doesn't exist yet OR has at least one entry marked up. Helper
/// shared by `find_writer_sg` and `find_pull_source`.
fn remote_if_reachable(node: &super::data_models::Node, uuid: &Uuid) -> Option<WriterTarget> {
    let has_conn = node.owner.active_connections.values()
        .any(|c| c.device_uuid == *uuid);
    if !has_conn { return None; }
    let mut any_entry = false;
    let mut any_up    = false;
    for ((u, _), status) in &node.sg_statuses {
        if u == uuid {
            any_entry = true;
            if status.up { any_up = true; }
        }
    }
    let polled_up = !any_entry || any_up;
    if polled_up { Some(WriterTarget::Remote(*uuid)) } else { None }
}

/// True iff we have poll entries for `uuid` and they are *all* marked down.
/// Used by `find_writer_sg` to detect a higher-rank SG that has dropped out
/// (failover), and skip past it in the rank walk.
fn is_polled_down(node: &super::data_models::Node, uuid: &Uuid) -> bool {
    let mut any_entry = false;
    let mut any_up    = false;
    for ((u, _), status) in &node.sg_statuses {
        if u == uuid {
            any_entry = true;
            if status.up { any_up = true; }
        }
    }
    any_entry && !any_up
}

/// Permissive variant of `find_writer_sg` for the pull path. Returns the
/// best reachable own SG without requiring it to be the actual writer —
/// `sync_pull` just needs *some* peer's state to bootstrap `writer_sg_uuid`
/// before the strict write-path selection can work.
fn find_pull_source(node: &super::data_models::Node) -> WriterTarget {
    let local_uuid = node.device_uuid;
    let mut sgs: Vec<&Device> = node.owner.user.devices.iter()
        .filter(|d| matches!(d.grade, DeviceGrade::SG))
        .collect();
    sgs.sort_by_key(|d| d.sg_rank.unwrap_or(u32::MAX));
    for d in &sgs {
        if d.uuid == local_uuid {
            return WriterTarget::Local;
        }
        if let Some(t) = remote_if_reachable(node, &d.uuid) {
            return t;
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

/// 32-char lowercase hex of a 16-byte uuid. Used for log messages and as
/// the wire form for HTML form values (app id buttons, etc.) since `Uuid`
/// is a raw `[u8; 16]` with no Display impl.
fn uuid_hex(uuid: &Uuid) -> String {
    uuid.iter().map(|b| format!("{b:02x}")).collect()
}

/// Inverse of `uuid_hex`. Returns `None` for malformed input.
fn uuid_from_hex(s: &str) -> Option<Uuid> {
    if s.len() != 32 { return None; }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
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
            last_seen_public_version: SyncVersion::default(),
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

    // Trigger connection maintenance now that we have peer data. Brief delay
    // gives the SG time to process our DeviceRegistration before our
    // ConnectRequest lands — they race on the SG's worker pool otherwise and
    // a connect_request that wins is silently rejected as "unknown device".
    ctx.scheduler_tx.send(super::action_queue::ScheduleRequest {
        action: super::action_queue::Action::MaintainConnections,
        delay:  Duration::from_millis(500),
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

    let device_uuid = device.uuid;
    let device_alias = device.alias.clone();
    let device_grade = device.grade;
    let device_sg_rank = device.sg_rank;
    let device_hosts = device.hosts.clone();

    let inserted = {
        let mut node = ctx.node.write().unwrap();
        if !node.owner.user.devices.iter().any(|d| d.uuid == device.uuid) {
            println!("[device_registration] new device '{}' registered from {src}", device.alias);
            node.owner.user.devices.push(device);
            true
        } else {
            false
        }
    };
    ctx.save_node();

    if inserted {
        // Sync v1: publish the new device to peer DGs via the writer SG.
        // Rolls back the local add if no writer is reachable, mirroring
        // app_register's originator pattern.
        if let Err(e) = request_change(Change::AddDevice {
            uuid:    device_uuid,
            alias:   device_alias.clone(),
            grade:   device_grade,
            sg_rank: device_sg_rank,
            hosts:   device_hosts,
        }, ctx) {
            {
                let mut node = ctx.node.write().unwrap();
                node.owner.user.devices.retain(|d| d.uuid != device_uuid);
            }
            ctx.save_node();
            eprintln!("[device_registration] rejecting device '{device_alias}': {e:?}");
            return;
        }
    }
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

    let (shared_secret, response_payload, contact_uuid, contact_change) = {
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

        // Build the contact upsert from the handshake payload. Don't mutate
        // contact_users inline — route it through request_change below so the
        // writer logs it and non-writer own SGs reconcile it via merge (Gap #2).
        eprintln!("[contact_request] adding contact '{}' from {src}", data.alias);
        let contact_uuid = data.uuid;
        let contact_change = Change::UpsertContact {
            uuid:       data.uuid,
            alias:      data.alias,
            public_key: data.public_key,
            devices:    devices_to_cards(&data.devices),
        };

        let response_payload = serialize_contact_payload(&node);
        (shared_secret, response_payload, contact_uuid, contact_change)
    };

    ctx.save_node(); // invitation was consumed above
    // Route the contact add through the write log (Gap #2): on the writer this
    // adds + logs + fans out; on a non-writer it forwards to the writer, which
    // logs and merges it back. Either way every own SG converges on the
    // contact, so all of them can validate its later connect_requests.
    if let Err(WriteError::Unreachable) = request_change_idempotent(contact_change, ctx) {
        eprintln!("[contact_request] no reachable writer SG; contact {contact_uuid:?} \
                   not yet logged — own SGs will reconcile once a writer is online");
    }
    // Catch up on the new contact's public state now, in case the SG↔SG
    // connection already exists (its connect_ack pull may have run before this
    // contact was registered).
    cross_user_pull_for_contact(contact_uuid, ctx);

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

    eprintln!("[contact_response] adding contact '{}' from {src}", data.alias);
    let contact_uuid = data.uuid;
    let contact_change = Change::UpsertContact {
        uuid:       data.uuid,
        alias:      data.alias,
        public_key: data.public_key,
        devices:    devices_to_cards(&data.devices),
    };
    {
        let mut node = ctx.node.write().unwrap();
        node.owner.pending_contact_exchange = None;
    }

    ctx.save_node(); // pending exchange cleared above
    // Route the contact add through the write log (Gap #2): on the writer this
    // adds + logs + fans out; on a non-writer it forwards to the writer, which
    // logs and merges it back. Either way every own SG converges on the contact.
    if let Err(WriteError::Unreachable) = request_change_idempotent(contact_change, ctx) {
        eprintln!("[contact_response] no reachable writer SG; contact {contact_uuid:?} \
                   not yet logged — own SGs will reconcile once a writer is online");
    }
    // Catch up on the new contact's public state now, in case the SG↔SG
    // connection already exists (its connect_ack pull may have run before this
    // contact was registered).
    cross_user_pull_for_contact(contact_uuid, ctx);

    // Trigger connection maintenance — we have a new contact.
    ctx.scheduler_tx.send(super::action_queue::ScheduleRequest {
        action: super::action_queue::Action::MaintainConnections,
        delay:  Duration::ZERO,
    }).ok();
}

// ── Contact data serialization (cross-user public-scope payload) ─────────────
//
// Wire shape used for the FullState body of a CrossUserPullResponse (op 0x77).
// Carries one user's public state from their writer SG to a contact's SG:
//
//   [user_uuid: 16]
//   [device_count: u8]
//     each device: [uuid:16][alias: u8+bytes][grade:u8][sg_rank:u8]
//                  [host_count:u8][each host: u8+bytes]
//       [app_count: u8]
//         each approved app: [id: u16 BE][alias: u8+bytes]

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
            buf.extend_from_slice(&a.id);
            push_str(&mut buf, &a.alias);
        }
    }
    buf
}

struct ContactData {
    user_uuid: Uuid,
    devices:   Vec<(Device, Vec<(Uuid, String)>)>, // (device, vec of (app_id, app_alias))
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
            let id: Uuid = read_arr(data, &mut pos)?;
            let alias    = read_str(data, &mut pos)?;
            apps.push((id, alias));
        }
        devices.push((device, apps));
    }
    Some(ContactData { user_uuid, devices })
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

const CHANGE_KIND_ADD_APPLICATION:        u8 = 0x01;
const CHANGE_KIND_REMOVE_APPLICATION:     u8 = 0x02;
const CHANGE_KIND_ADD_DEVICE:             u8 = 0x03;
const CHANGE_KIND_UPDATE_APPLICATION_ALIAS: u8 = 0x04;
const CHANGE_KIND_UPSERT_CONTACT:         u8 = 0x05;

/// Public snapshot of one of a contact's devices, carried inside
/// `Change::UpsertContact`. Mirrors a device's public fields plus its app
/// `(id, alias)` pairs — the only contact data visible at public scope. A
/// dedicated comparable type (rather than `Device`, which isn't `Clone`/`Eq`)
/// so `Change` stays `Clone + Eq` and the merge can diff contacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactDeviceCard {
    pub uuid:    Uuid,
    pub alias:   String,
    pub grade:   DeviceGrade,
    pub sg_rank: Option<u32>,
    pub hosts:   Vec<String>,
    pub apps:    Vec<(Uuid, String)>,
}

/// State mutations that flow through the writer SG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Public-scope: add an app entry (id + alias) to the device identified
    /// by `device_uuid` in the user's device list. The originating DG keeps
    /// the private fields (token, host, protocol) locally — they are not
    /// shared with the writer SG or peers. `app_id` is a 16-byte UUID
    /// (see Application.id docs).
    AddApplication {
        device_uuid: Uuid,
        app_id:      Uuid,
        app_alias:   String,
    },
    /// Public-scope: remove the app identified by `(device_uuid, app_id)`
    /// from the user's device list. Idempotent — a remove for an app id
    /// that's already absent is a no-op (no version bump).
    RemoveApplication {
        device_uuid: Uuid,
        app_id:      Uuid,
    },
    /// Public-scope: add a device (no apps) to the user's device list.
    /// Issued by the SG that accepts a new device via the invitation flow.
    /// Idempotent on `uuid`. Apps arrive later via `AddApplication`.
    AddDevice {
        uuid:    Uuid,
        alias:   String,
        grade:   DeviceGrade,
        sg_rank: Option<u32>,
        hosts:   Vec<String>,
    },
    /// Public-scope: rename app `app_id` on `device_uuid`. No-op if the
    /// alias already matches or the app doesn't exist.
    UpdateApplicationAlias {
        device_uuid: Uuid,
        app_id:      Uuid,
        new_alias:   String,
    },
    /// Public-scope: insert or replace a contact's cached public state
    /// (identity + the public snapshot of its devices/apps). Issued by the
    /// writer SG when a contact is added (contact handshake) or when its
    /// cached state is refreshed via a cross-user pull. Routing it through the
    /// write log is what lets non-writer own SGs reconcile the contact list —
    /// SG↔SG public sync is merge-only, so a direct mutation would never reach
    /// them (Gap #2). Idempotent: an upsert identical to the cached snapshot is
    /// a no-op (no version bump). Carries the full snapshot, so the merge
    /// resolves conflicts by last-writer-wins on the whole contact.
    UpsertContact {
        uuid:       Uuid,
        alias:      String,
        public_key: PublicKey,
        devices:    Vec<ContactDeviceCard>,
    },
}

/// Returns the scope(s) a given change is expected to bump on accept. Used
/// by `apply_change_locally` and by the notify fan-out to know which
/// `UpdateAvailable` notifications to emit.
fn change_scopes(c: &Change) -> &'static [Scope] {
    match c {
        // Only the public fields (id+alias) are recorded at the writer; the
        // originating DG's private fields stay local.
        Change::AddApplication { .. }          => &[Scope::Public],
        Change::RemoveApplication { .. }       => &[Scope::Public],
        Change::AddDevice { .. }               => &[Scope::Public],
        Change::UpdateApplicationAlias { .. }  => &[Scope::Public],
        Change::UpsertContact { .. }           => &[Scope::Public],
    }
}

fn serialize_change(c: &Change) -> Vec<u8> {
    let mut buf = Vec::new();
    match c {
        Change::AddApplication { device_uuid, app_id, app_alias } => {
            buf.push(CHANGE_KIND_ADD_APPLICATION);
            buf.extend_from_slice(device_uuid);
            buf.extend_from_slice(app_id);
            push_str(&mut buf, app_alias);
        }
        Change::RemoveApplication { device_uuid, app_id } => {
            buf.push(CHANGE_KIND_REMOVE_APPLICATION);
            buf.extend_from_slice(device_uuid);
            buf.extend_from_slice(app_id);
        }
        Change::AddDevice { uuid, alias, grade, sg_rank, hosts } => {
            buf.push(CHANGE_KIND_ADD_DEVICE);
            // Reuse push_device's layout by constructing a temporary Device.
            // `applications` is empty by design — apps arrive via AddApplication.
            let temp = Device {
                uuid:         *uuid,
                alias:        alias.clone(),
                grade:        *grade,
                sg_rank:      *sg_rank,
                hosts:        hosts.clone(),
                applications: Vec::new(),
            };
            push_device(&mut buf, &temp);
        }
        Change::UpdateApplicationAlias { device_uuid, app_id, new_alias } => {
            buf.push(CHANGE_KIND_UPDATE_APPLICATION_ALIAS);
            buf.extend_from_slice(device_uuid);
            buf.extend_from_slice(app_id);
            push_str(&mut buf, new_alias);
        }
        Change::UpsertContact { uuid, alias, public_key, devices } => {
            buf.push(CHANGE_KIND_UPSERT_CONTACT);
            buf.extend_from_slice(uuid);
            push_str(&mut buf, alias);
            buf.extend_from_slice(public_key);
            buf.push(devices.len().min(u8::MAX as usize) as u8);
            for card in devices.iter().take(u8::MAX as usize) {
                // Reuse push_device's layout via a temp Device (apps follow).
                let temp = Device {
                    uuid:         card.uuid,
                    alias:        card.alias.clone(),
                    grade:        card.grade,
                    sg_rank:      card.sg_rank,
                    hosts:        card.hosts.clone(),
                    applications: Vec::new(),
                };
                push_device(&mut buf, &temp);
                buf.push(card.apps.len().min(u8::MAX as usize) as u8);
                for (id, app_alias) in card.apps.iter().take(u8::MAX as usize) {
                    buf.extend_from_slice(id);
                    push_str(&mut buf, app_alias);
                }
            }
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
            let app_id:      Uuid = read_arr(data, &mut pos)?;
            let app_alias         = read_str(data, &mut pos)?;
            Some(Change::AddApplication { device_uuid, app_id, app_alias })
        }
        CHANGE_KIND_REMOVE_APPLICATION => {
            let device_uuid: Uuid = read_arr(data, &mut pos)?;
            let app_id:      Uuid = read_arr(data, &mut pos)?;
            Some(Change::RemoveApplication { device_uuid, app_id })
        }
        CHANGE_KIND_ADD_DEVICE => {
            let d = read_device(data, &mut pos)?;
            Some(Change::AddDevice {
                uuid:    d.uuid,
                alias:   d.alias,
                grade:   d.grade,
                sg_rank: d.sg_rank,
                hosts:   d.hosts,
            })
        }
        CHANGE_KIND_UPDATE_APPLICATION_ALIAS => {
            let device_uuid: Uuid = read_arr(data, &mut pos)?;
            let app_id:      Uuid = read_arr(data, &mut pos)?;
            let new_alias         = read_str(data, &mut pos)?;
            Some(Change::UpdateApplicationAlias { device_uuid, app_id, new_alias })
        }
        CHANGE_KIND_UPSERT_CONTACT => {
            let uuid:       Uuid      = read_arr(data, &mut pos)?;
            let alias                 = read_str(data, &mut pos)?;
            let public_key: PublicKey = read_arr(data, &mut pos)?;
            let dev_count = *data.get(pos)? as usize; pos += 1;
            let mut devices = Vec::with_capacity(dev_count);
            for _ in 0..dev_count {
                let d = read_device(data, &mut pos)?;
                let app_count = *data.get(pos)? as usize; pos += 1;
                let mut apps = Vec::with_capacity(app_count);
                for _ in 0..app_count {
                    let id: Uuid = read_arr(data, &mut pos)?;
                    let a        = read_str(data, &mut pos)?;
                    apps.push((id, a));
                }
                devices.push(ContactDeviceCard {
                    uuid: d.uuid, alias: d.alias, grade: d.grade,
                    sg_rank: d.sg_rank, hosts: d.hosts, apps,
                });
            }
            Some(Change::UpsertContact { uuid, alias, public_key, devices })
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
/// Mutate `owner` per `change`. Returns `Ok(true)` if state changed, `Ok(false)`
/// for an idempotent no-op (Add of an existing id, Remove of an absent id,
/// Update to the current alias). Validation errors fire when a Change
/// references a missing device. Pure state mutation — no version bump, no log
/// append; callers stitch those on as appropriate.
fn apply_change_to_owner(owner: &mut Owner, change: &Change) -> Result<bool, WriteError> {
    let applied = match change {
        Change::AddApplication { device_uuid, app_id, app_alias } => {
            let dev = owner.user.devices.iter_mut()
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
        Change::RemoveApplication { device_uuid, app_id } => {
            let dev = owner.user.devices.iter_mut()
                .find(|d| d.uuid == *device_uuid)
                .ok_or_else(|| WriteError::Validation(format!(
                    "unknown device_uuid {device_uuid:?}"
                )))?;
            let before = dev.applications.len();
            dev.applications.retain(|a| a.id != *app_id);
            before != dev.applications.len()
        }
        Change::AddDevice { uuid, alias, grade, sg_rank, hosts } => {
            if owner.user.devices.iter().any(|d| d.uuid == *uuid) {
                false
            } else {
                owner.user.devices.push(Device {
                    uuid:         *uuid,
                    alias:        alias.clone(),
                    grade:        *grade,
                    sg_rank:      *sg_rank,
                    hosts:        hosts.clone(),
                    applications: Vec::new(),
                });
                true
            }
        }
        Change::UpdateApplicationAlias { device_uuid, app_id, new_alias } => {
            let dev = owner.user.devices.iter_mut()
                .find(|d| d.uuid == *device_uuid)
                .ok_or_else(|| WriteError::Validation(format!(
                    "unknown device_uuid {device_uuid:?}"
                )))?;
            match dev.applications.iter_mut().find(|a| a.id == *app_id) {
                Some(app) if app.alias != *new_alias => {
                    app.alias = new_alias.clone();
                    true
                }
                _ => false,
            }
        }
        Change::UpsertContact { uuid, alias, public_key, devices } => {
            let incoming = normalize_cards(devices);
            match owner.contact_users.iter_mut().find(|c| c.user.uuid == *uuid) {
                Some(existing) => {
                    let unchanged = existing.user.alias == *alias
                        && existing.public_key == *public_key
                        && contact_cards(existing) == incoming;
                    if unchanged {
                        false
                    } else {
                        existing.user.alias   = alias.clone();
                        existing.public_key   = *public_key;
                        existing.user.devices = cards_to_devices(devices);
                        true
                    }
                }
                None => {
                    owner.contact_users.push(Contact {
                        user: User {
                            alias:   alias.clone(),
                            uuid:    *uuid,
                            devices: cards_to_devices(devices),
                        },
                        public_key: *public_key,
                        last_seen_public_version: SyncVersion::default(),
                    });
                    true
                }
            }
        }
    };
    Ok(applied)
}

/// Build `Application` stubs (public fields only — private fields zeroed) from
/// a card's `(app_id, alias)` pairs. Contact apps never carry private fields.
fn card_apps_to_applications(apps: &[(Uuid, String)]) -> Vec<Application> {
    apps.iter().map(|(id, alias)| Application {
        id:            *id,
        alias:         alias.clone(),
        protocol:      String::new(),
        host:          "0.0.0.0:0".parse().unwrap(),
        user_approved: true,
        token:         [0u8; 16],
    }).collect()
}

/// Convert contact device cards into stored `Device`s.
fn cards_to_devices(cards: &[ContactDeviceCard]) -> Vec<Device> {
    cards.iter().map(|c| Device {
        uuid:         c.uuid,
        alias:        c.alias.clone(),
        grade:        c.grade,
        sg_rank:      c.sg_rank,
        hosts:        c.hosts.clone(),
        applications: card_apps_to_applications(&c.apps),
    }).collect()
}

/// Cards for a set of stored devices, in a deterministic order (devices by
/// uuid, apps by id) so card equality is order-independent.
fn devices_to_cards(devices: &[Device]) -> Vec<ContactDeviceCard> {
    let mut cards: Vec<ContactDeviceCard> = devices.iter().map(|d| {
        let mut apps: Vec<(Uuid, String)> = d.applications.iter()
            .map(|a| (a.id, a.alias.clone())).collect();
        apps.sort();
        ContactDeviceCard {
            uuid: d.uuid, alias: d.alias.clone(), grade: d.grade,
            sg_rank: d.sg_rank, hosts: d.hosts.clone(), apps,
        }
    }).collect();
    cards.sort_by_key(|c| c.uuid);
    cards
}

/// Normalized cards for a stored contact (see `devices_to_cards`).
fn contact_cards(contact: &Contact) -> Vec<ContactDeviceCard> {
    devices_to_cards(&contact.user.devices)
}

/// Re-sort incoming cards into the same canonical order as `contact_cards`.
fn normalize_cards(cards: &[ContactDeviceCard]) -> Vec<ContactDeviceCard> {
    let mut out: Vec<ContactDeviceCard> = cards.iter().map(|c| {
        let mut apps = c.apps.clone();
        apps.sort();
        ContactDeviceCard {
            uuid: c.uuid, alias: c.alias.clone(), grade: c.grade,
            sg_rank: c.sg_rank, hosts: c.hosts.clone(), apps,
        }
    }).collect();
    out.sort_by_key(|c| c.uuid);
    out
}

fn apply_change_locally(
    change: &Change,
    writer_uuid: Uuid,
    ctx: &WorkerContext,
) -> Result<(SyncVersion, SyncVersion), WriteError> {
    let mut node = ctx.node.write().unwrap();
    let applied = apply_change_to_owner(&mut node.owner, change)?;
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

/// `find_writer_sg` with an on-demand failover probe on the `Unreachable`
/// path. The periodic `poll_sg` (every `POLL_SG_INTERVAL`, currently 30s) is
/// what marks a partitioned higher-rank writer down so a lower-rank SG can
/// elect itself. Between partition onset and the next poll tick, a rank-N SG's
/// write would hit `Unreachable` and be lost (terminal — no retry/queue). To
/// close that window, re-poll synchronously the moment a write can't find a
/// writer and re-evaluate: a real partition → the writer's ping times out
/// (~`SG_PING_TIMEOUT`) → it's marked down → we self-elect; a transient blip
/// where the writer is actually up → its pong arrives → we route remotely and
/// avoid a spurious split-brain. The probe fires only on `Unreachable`, so the
/// healthy `Local`/`Remote` write paths pay no extra cost.
fn find_writer_sg_probing(ctx: &WorkerContext) -> WriterTarget {
    let first = {
        let node = ctx.node.read().unwrap();
        find_writer_sg(&node)
    };
    if !matches!(first, WriterTarget::Unreachable) {
        return first;
    }
    poll_sg(ctx);
    let node = ctx.node.read().unwrap();
    find_writer_sg(&node)
}

/// Drive a state change through the writer-SG model. Used by any node that
/// wants to mutate state (UI, app-approval flow in phase 7, etc.):
///
/// - `WriterTarget::Local`  — apply locally; returns `Ok(())` after persist.
/// - `WriterTarget::Remote` — send a SyncWriteRequest to the elected writer
///   and return `Ok(())` immediately. The matching ack arrives later via
///   `sync_write_ack`. Phase 5 will turn the ack into "trigger a pull to
///   refresh local state and clear pending UI."
/// - `WriterTarget::Unreachable` — return `Err(Unreachable)`. An on-demand
///   poll (`find_writer_sg_probing`) is attempted first so a partitioned
///   rank-N SG can fail over without waiting for the periodic poll tick.
pub fn request_change(change: Change, ctx: &WorkerContext) -> Result<(), WriteError> {
    request_change_inner(change, ctx, /*force_bump_on_noop*/ true)
}

/// Like `request_change`, but on the `Local` path it only bumps + logs + fans
/// out when `apply_change_locally` actually changed state. Use for originators
/// that DON'T pre-mutate the local record and instead rely on the Change to do
/// the mutation — currently the contact-upsert sites (Gap #2). With these
/// semantics a duplicate `UpsertContact` (re-add, or an unchanged periodic
/// cross-user pull) is a true no-op: no redundant write-log entry, no spurious
/// version bump, no contact-notify storm.
pub fn request_change_idempotent(change: Change, ctx: &WorkerContext) -> Result<(), WriteError> {
    request_change_inner(change, ctx, /*force_bump_on_noop*/ false)
}

fn request_change_inner(
    change: Change,
    ctx: &WorkerContext,
    force_bump_on_noop: bool,
) -> Result<(), WriteError> {
    let target = find_writer_sg_probing(ctx);
    match target {
        WriterTarget::Local => apply_local_change(change, ctx, force_bump_on_noop),
        WriterTarget::Remote(writer_uuid) => {
            send_sync_write_request(&change, writer_uuid, ctx);
            Ok(())
        }
        WriterTarget::Unreachable => Err(WriteError::Unreachable),
    }
}

/// Commit a Change on the elected-local writer: apply it, bump the touched
/// scope versions, append one write-log entry per bumped scope, and notify own
/// peers (+ contacts on a public bump).
///
/// `force_bump_on_noop` selects the originator contract:
/// - `true`  — advance the version even when `apply_change_locally` was a
///   data-level no-op. The common path when the originator pre-mutated the
///   local record (e.g. `app_register` adds the app with token+host, then
///   publishes id+alias — the apply sees it already present but the state did
///   change). All non-contact callers use this.
/// - `false` — bump + log + notify ONLY for scopes that actually changed
///   (mirrors the receiver path `sync_write_request`). For originators that
///   route the real mutation through the Change itself, so an idempotent re-run
///   stays a true no-op.
fn apply_local_change(
    change: Change,
    ctx: &WorkerContext,
    force_bump_on_noop: bool,
) -> Result<(), WriteError> {
    let local_uuid = ctx.node.read().unwrap().device_uuid;
    let (pre_priv, pre_pub) = {
        let node = ctx.node.read().unwrap();
        (node.owner.private_version, node.owner.public_version)
    };
    // Applies + bumps only the scopes that actually changed (no-op leaves
    // versions untouched).
    apply_change_locally(&change, local_uuid, ctx)?;

    let bumped: Vec<Scope> = if force_bump_on_noop {
        // Originator pre-mutation contract: advance every touched scope
        // unconditionally (preserved verbatim — this is in addition to any bump
        // apply_change_locally already did on an actual change).
        let scopes_to_bump = change_scopes(&change);
        let mut node = ctx.node.write().unwrap();
        for &scope in scopes_to_bump {
            node.owner.bump_version(scope, local_uuid);
        }
        scopes_to_bump.iter().copied().collect()
    } else {
        // Strict contract: only the scopes apply_change_locally actually moved.
        let node = ctx.node.read().unwrap();
        bumped_scopes(pre_priv, pre_pub, node.owner.private_version, node.owner.public_version)
    };

    // True no-op under the strict contract — nothing to persist, log, or notify.
    if bumped.is_empty() {
        return Ok(());
    }

    let (post_priv, post_pub) = {
        let node = ctx.node.read().unwrap();
        (node.owner.private_version, node.owner.public_version)
    };
    ctx.save_node();
    // One write-log entry per accepted Change, recorded under the post-bump
    // version for each touched scope (current variants all touch a single
    // scope; revisit if a multi-scope variant lands).
    for &scope in &bumped {
        let v = match scope { Scope::Private => post_priv, Scope::Public => post_pub };
        append_to_write_log(&change, scope, v, ctx);
    }
    ctx.save_node();
    notify_own_peers(&bumped, post_priv, post_pub, ctx);
    if bumped.contains(&Scope::Public) {
        notify_contacts(post_pub, ctx);
    }
    Ok(())
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

/// Cross-user fan-out: send a `CrossUserUpdateAvailable(public, version)` to
/// the top-ranked reachable SG of every contact. Called from the writer-SG
/// path after a public-scope bump so contacts' SGs can pull the refreshed
/// Append an accepted Change to the writer SG's write log and prune entries
/// older than `WRITE_LOG_RETENTION`. Called from every code path that
/// commits a Change (i.e. that bumps a scope version on behalf of a Change),
/// so the log captures exactly the events sync v2 needs to replay during
/// partition reconciliation.
///
/// `version` is the post-bump version assigned to this Change for `scope`.
fn append_to_write_log(change: &Change, scope: Scope, version: SyncVersion, ctx: &WorkerContext) {
    let payload = serialize_change(change);
    let now = SystemTime::now();
    let cutoff = now.checked_sub(WRITE_LOG_RETENTION);
    let mut node = ctx.node.write().unwrap();
    node.owner.write_log.push(WriteLogEntry {
        version,
        scope,
        change_payload: payload,
        committed_at: now,
    });
    if let Some(cutoff) = cutoff {
        node.owner.write_log.retain(|e| e.committed_at >= cutoff);
    }
}

/// public state. Silently skips contacts with no active connection — they
/// will catch up on their next periodic pull.
fn notify_contacts(public: SyncVersion, ctx: &WorkerContext) {
    let packets: Vec<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        let mut out = Vec::new();
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

            let mut body = Vec::with_capacity(1 + SYNC_VERSION_WIRE_LEN);
            write_scope(&mut body, Scope::Public);
            write_sync_version(&mut body, &public);
            let pkt = build_encrypted_packet(CROSS_USER_UPDATE_AVAILABLE_OP, conn, &body);
            out.push((pkt, conn.peer_addr));
        }
        out
    };
    for (pkt, dest) in packets {
        send(ctx, dest, &pkt);
    }
}

/// True if `peer_uuid` names an SG-grade device in the local user's own
/// device list. Used to gate sync v2 partition reconciliation: probe + merge
/// only flow between own-user SGs, not between SG↔DG or SG↔contact pairs.
fn is_own_user_sg(owner: &Owner, peer_uuid: Uuid) -> bool {
    owner.user.devices.iter()
        .any(|d| d.uuid == peer_uuid && matches!(d.grade, DeviceGrade::SG))
}

/// True if the *local* device is an SG. Partition reconciliation is strictly an
/// SG↔SG protocol, so both endpoints must be own-user SGs — `is_own_user_sg`
/// covers the peer, this covers us. Without it a DG that connects to its own SG
/// would kick off the merge handshake and the SG would reject every proposal as
/// `malformed`, once per reconcile tick, forever.
fn local_is_sg(node: &super::data_models::Node) -> bool {
    let uuid = node.device_uuid;
    node.owner.user.devices.iter()
        .any(|d| d.uuid == uuid && matches!(d.grade, DeviceGrade::SG))
}

/// Periodic merge tick. Fires the partition-reconcile kickoff against every
/// active connection to an own-user SG, so reconciliation makes progress even
/// when the underlying `active_connection` survives a transient partition
/// (i.e. no fresh `connect_ack` to seed it). An empty merge — both sides
/// already in sync — is one watermark round-trip and one empty proposal pair;
/// the cost scales with own-user SG fan-out, which is small in practice.
pub fn partition_reconcile_tick(ctx: &WorkerContext) {
    let conn_ids: Vec<u16> = {
        let node = ctx.node.read().unwrap();
        // Reconciliation is SG↔SG only; a DG never initiates.
        if !local_is_sg(&node) { return; }
        node.owner.active_connections.iter()
            .filter(|(_, c)| is_own_user_sg(&node.owner, c.device_uuid))
            .map(|(id, _)| *id)
            .collect()
    };
    for id in conn_ids {
        partition_reconcile_on_reconnect(id, ctx);
    }
}

/// On-reconnect partition reconciliation kickoff. When a fresh active
/// connection lands between two own-user SGs, this side sends a
/// `WatermarkProbeRequest(Public)`. The responder will reply via
/// `watermark_probe_response`, which both stores the per-peer watermark *and*
/// fires the matching `MergeProposal` back. No-op for any peer that isn't an
/// own-user SG.
fn partition_reconcile_on_reconnect(conn_id: u16, ctx: &WorkerContext) {
    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        // Reconciliation is SG↔SG only: both ends must be own-user SGs.
        if !local_is_sg(&node) { return; }
        let Some(conn) = node.owner.active_connections.get(&conn_id) else { return };
        let peer_uuid = conn.device_uuid;
        if !is_own_user_sg(&node.owner, peer_uuid) { return; }
        let mut body = Vec::with_capacity(1);
        write_scope(&mut body, Scope::Public);
        Some((
            build_encrypted_packet(WATERMARK_PROBE_REQUEST_OP, conn, &body),
            conn.peer_addr,
        ))
    };
    if let Some((pkt, addr)) = pkt_and_addr {
        send(ctx, addr, &pkt);
    }
}

/// On-reconnect cross-user pull. Called from `connect_ack` immediately after a
/// fresh active connection lands. If the peer device on this connection
/// belongs to a contact, send a `CrossUserPullRequest(public, last_seen)` so
/// we catch up on any updates published by that contact while disconnected.
/// No-op if the peer isn't a contact device.
fn cross_user_pull_on_reconnect(conn_id: u16, ctx: &WorkerContext) {
    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        let Some(conn) = node.owner.active_connections.get(&conn_id) else { return };
        let peer_uuid = conn.device_uuid;
        let Some(contact) = node.owner.contact_users.iter()
            .find(|c| c.user.devices.iter().any(|d| d.uuid == peer_uuid))
        else { return };
        let mut body = Vec::with_capacity(1 + SYNC_VERSION_WIRE_LEN);
        write_scope(&mut body, Scope::Public);
        write_sync_version(&mut body, &contact.last_seen_public_version);
        Some((
            build_encrypted_packet(CROSS_USER_PULL_REQUEST_OP, conn, &body),
            conn.peer_addr,
        ))
    };
    if let Some((pkt, addr)) = pkt_and_addr {
        send(ctx, addr, &pkt);
    }
}

/// Fire a cross-user pull for a freshly-added contact over any active
/// connection we already hold to one of its devices. Closes the ordering race
/// where the SG↔SG connection's `connect_ack` (which normally drives the pull)
/// fired *before* the contact was registered — in that case the connect_ack
/// pull no-ops and nothing else retries. Called from the contact handlers.
fn cross_user_pull_for_contact(contact_uuid: Uuid, ctx: &WorkerContext) {
    let conn_ids: Vec<u16> = {
        let node = ctx.node.read().unwrap();
        let Some(contact) = node.owner.contact_users.iter()
            .find(|c| c.user.uuid == contact_uuid)
        else { return };
        let dev_uuids: Vec<Uuid> = contact.user.devices.iter().map(|d| d.uuid).collect();
        node.owner.active_connections.values()
            .filter(|c| dev_uuids.contains(&c.device_uuid))
            .map(|c| c.id)
            .collect()
    };
    for cid in conn_ids {
        cross_user_pull_on_reconnect(cid, ctx);
    }
}

/// Periodic / on-reconnect pull entry point. Called by the scheduler on its
/// `SYNC_PULL_INTERVAL` tick and by `connect_ack` immediately after a fresh
/// active connection lands. Sends one `SyncPullRequest` per scope to the best
/// reachable own SG (which carries the writer's state for us either directly
/// or via its own prior pull); no-op if this node is itself that source
/// (`Local`) or has no reachable own SG (`Unreachable`). Uses the permissive
/// `find_pull_source` rather than `find_writer_sg` so a fresh node with
/// `writer_sg_uuid == [0;16]` can still bootstrap its writer metadata.
pub fn sync_pull(ctx: &WorkerContext) {
    let (target, last_priv, last_pub) = {
        let node = ctx.node.read().unwrap();
        (find_pull_source(&node), node.owner.private_version, node.owner.public_version)
    };
    let writer_uuid = match target {
        WriterTarget::Local       => return,
        WriterTarget::Unreachable => {
            println!("[sync_pull] no reachable own SG — skipping");
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
        eprintln!("[sync_pull] pull source {writer_uuid:?} has no active connection");
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
            buf.extend_from_slice(&a.id);
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
                buf.extend_from_slice(&a.id);
                push_str(&mut buf, &a.alias);
            }
        }
    }
    buf
}

/// Parse a Public-state blob and apply it to the node:
///
/// - Own user `alias`/`uuid`: replace.
/// - Own devices, by `uuid`: existing entries get public fields refreshed
///   (alias/grade/sg_rank/hosts). App handling depends on whether the entry
///   is the **local** device (this node) or a peer device:
///   - **Local device**: apps are merged additively — incoming alias updates
///     matching ids, new ids are added, but apps in local state that aren't
///     in incoming are preserved. This protects in-flight `request_change`
///     pre-mutates (e.g., an app the local DG just registered or rejected
///     but whose write hasn't yet been acknowledged by the writer).
///   - **Peer device**: incoming is authoritative — apps absent from
///     incoming are removed from local state. This is how `RemoveApplication`
///     propagates from the writer's view to peers.
///   In both cases, an app entry that already exists locally keeps its
///   private fields (`token`/`host`/`protocol`/`user_approved`); only the
///   public `alias` is overwritten from incoming.
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
        apps:   Vec<(Uuid, String)>,
    }
    let mut devices: Vec<ParsedDevice> = Vec::with_capacity(dev_count as usize);
    for _ in 0..dev_count {
        let Some(d) = read_device(state, &mut pos) else { return false; };
        let Some(&app_count) = state.get(pos) else { return false; };
        pos += 1;
        let mut apps = Vec::with_capacity(app_count as usize);
        for _ in 0..app_count {
            let Some(id)    = read_arr::<16>(state, &mut pos) else { return false; };
            let Some(alias) = read_str(state, &mut pos)        else { return false; };
            apps.push((id, alias));
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
                let Some(id)    = read_arr::<16>(state, &mut pos) else { return false; };
                let Some(alias) = read_str(state, &mut pos)        else { return false; };
                apps.push((id, alias));
            }
            devs.push(ParsedDevice { device: d, apps });
        }
        contacts.push(ParsedContact { alias, uuid, public_key, devices: devs });
    }

    // Apply.
    let mut node = ctx.node.write().unwrap();
    let local_uuid = node.device_uuid;
    node.owner.user.alias = user_alias;
    node.owner.user.uuid  = user_uuid;

    for parsed in devices {
        let p = parsed.device;
        let apps = parsed.apps;
        let is_local = p.uuid == local_uuid;
        if let Some(existing) = node.owner.user.devices.iter_mut().find(|d| d.uuid == p.uuid) {
            existing.alias   = p.alias;
            existing.grade   = p.grade;
            existing.sg_rank = p.sg_rank;
            existing.hosts   = p.hosts;
            if is_local {
                // Local device: strictly additive. Only insert apps the peer
                // reports that we don't have yet; never overwrite an existing
                // local app's alias. The local node is the writer for its own
                // device under sync v2's multi-writer model, so a peer's view
                // of our apps may be stale and must not clobber ours. Any
                // legitimate cross-SG alias change reaches us via the sync v2
                // merge engine (apply_change_to_owner), not via this branch.
                let existing_ids: HashSet<Uuid> = existing.applications.iter()
                    .map(|a| a.id).collect();
                for (id, alias) in apps {
                    if existing_ids.contains(&id) { continue; }
                    existing.applications.push(Application {
                        id,
                        alias,
                        protocol:      String::new(),
                        host:          "0.0.0.0:0".parse().unwrap(),
                        user_approved: true,
                        token:         [0u8; 16],
                    });
                }
            } else {
                // Peer device: authoritative — drop apps the writer no longer
                // reports, so RemoveApplication propagates.
                let incoming_ids: HashSet<Uuid> = apps.iter().map(|(id, _)| *id).collect();
                existing.applications.retain(|a| incoming_ids.contains(&a.id));
                for (id, alias) in apps {
                    if let Some(local_app) = existing.applications.iter_mut().find(|a| a.id == id) {
                        local_app.alias = alias;
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
                last_seen_public_version: SyncVersion::default(),
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
        // One write-log entry per accepted Change. `bumped` is non-empty
        // exactly when apply_change_locally produced a real mutation.
        for &scope in &bumped {
            let v = match scope { Scope::Private => private_v, Scope::Public => public_v };
            append_to_write_log(&change, scope, v, ctx);
        }
        ctx.save_node();
        notify_own_peers(&bumped, private_v, public_v, ctx);
        if bumped.contains(&Scope::Public) {
            notify_contacts(public_v, ctx);
        }
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

    // Sync v2 (7c.6+) is the sole authority for Public-scope propagation
    // between two own-user SGs: the watermark probe + merge proposal
    // exchange handles cross-writer reconciliation deterministically by
    // rank. Sync v1's "cross-writer: pull and let the writer's state win"
    // rule corrupts the multi-writer model — a stale pull overwrites
    // `public_version` to the peer writer, the next bump flips the writer
    // forward, and two writes can end up with duplicate (writer,epoch,seq)
    // triples that block subsequent merge proposals. So: when *both* sides
    // are own-user SGs, ignore the notification. DGs still pull from their
    // writer SG; cross-user notifications still drive sync v1 as before.
    let suppress = {
        let node = ctx.node.read().unwrap();
        let local_is_sg = node.owner.user.devices.iter()
            .find(|d| d.uuid == node.device_uuid)
            .map(|d| matches!(d.grade, DeviceGrade::SG))
            .unwrap_or(false);
        let peer_is_own_sg = node.owner.active_connections.get(&conn_id)
            .map(|conn| is_own_user_sg(&node.owner, conn.device_uuid))
            .unwrap_or(false);
        local_is_sg && peer_is_own_sg
    };
    if suppress { return; }

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

// ── Cross-user sync v1 (ops 0x75 / 0x76 / 0x77) ──────────────────────────────
//
// Carries public-scope state across user boundaries. The writer SG for user A
// notifies each contact's top-ranked reachable SG when A's public_version
// bumps; the contact's SG pulls A's public state and caches it as the
// matching entry in `contact_users`. The receiver, if it is the local
// user's writer SG, also bumps its own public_version so the user's own DGs
// pull the refreshed contact list via `apply_public_state`.
//
// Encrypted body layouts:
//   0x75 CrossUserUpdateAvailable: [scope:1=public][version:28]
//   0x76 CrossUserPullRequest:     [scope:1=public][last_seen_version:28]
//   0x77 CrossUserPullResponse:    [scope:1=public][result:1][version:28][state:var]
//
// `state` (FullState only) is the sender's public payload — same shape as
// `serialize_contact_data`: user_uuid, devices+approved apps. The sender
// is identified by the active connection's contact mapping, so the payload
// is parsed without trusting the embedded user_uuid for routing.

pub fn cross_user_update_available(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[cross_user_update_available] header too short from {src}");
        return;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[cross_user_update_available] decryption failed from {src}");
                return;
            }
        }
    };

    let mut pos = 0usize;
    let Some(scope) = read_scope(&plaintext, &mut pos) else {
        eprintln!("[cross_user_update_available] bad scope from {src}");
        return;
    };
    if !matches!(scope, Scope::Public) {
        eprintln!("[cross_user_update_available] non-public scope ignored from {src}");
        return;
    }
    let Some(announced) = read_sync_version(&plaintext, &mut pos) else {
        eprintln!("[cross_user_update_available] truncated version from {src}");
        return;
    };

    let (last_seen, conn_present) = {
        let node = ctx.node.read().unwrap();
        let Some(conn) = node.owner.active_connections.get(&conn_id) else {
            return;
        };
        let peer_uuid = conn.device_uuid;
        let contact = node.owner.contact_users.iter()
            .find(|c| c.user.devices.iter().any(|d| d.uuid == peer_uuid));
        match contact {
            Some(c) => (c.last_seen_public_version, true),
            None    => (SyncVersion::zero(), false),
        }
    };
    if !conn_present {
        eprintln!("[cross_user_update_available] no contact owns conn {conn_id} from {src}");
        return;
    }

    use std::cmp::Ordering;
    let needs_pull = match announced.cmp_same_writer(&last_seen) {
        Some(Ordering::Greater) => true,
        Some(_)                 => false,
        None                    => true, // cross-writer: pull and adopt peer's state
    };
    if needs_pull {
        let mut body = Vec::with_capacity(1 + SYNC_VERSION_WIRE_LEN);
        write_scope(&mut body, scope);
        write_sync_version(&mut body, &last_seen);

        let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
            let node = ctx.node.read().unwrap();
            node.owner.active_connections.get(&conn_id)
                .map(|conn| (
                    build_encrypted_packet(CROSS_USER_PULL_REQUEST_OP, conn, &body),
                    conn.peer_addr,
                ))
        };
        let Some((pkt, addr)) = pkt_and_addr else { return };
        send(ctx, addr, &pkt);
    }
}

pub fn cross_user_pull_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[cross_user_pull_request] header too short from {src}");
        return;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[cross_user_pull_request] decryption failed from {src}");
                return;
            }
        }
    };

    let mut pos = 0usize;
    let Some(scope) = read_scope(&plaintext, &mut pos) else {
        eprintln!("[cross_user_pull_request] bad scope from {src}");
        return;
    };
    if !matches!(scope, Scope::Public) {
        eprintln!("[cross_user_pull_request] non-public scope ignored from {src}");
        return;
    }
    let Some(last_seen) = read_sync_version(&plaintext, &mut pos) else {
        eprintln!("[cross_user_pull_request] truncated version from {src}");
        return;
    };

    let (current_v, state_blob) = {
        let node = ctx.node.read().unwrap();
        (node.owner.public_version, serialize_contact_data(&node))
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
    }

    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.get(&conn_id)
            .map(|conn| (
                build_encrypted_packet(CROSS_USER_PULL_RESPONSE_OP, conn, &body),
                conn.peer_addr,
            ))
    };
    let Some((pkt, addr)) = pkt_and_addr else {
        eprintln!("[cross_user_pull_request] no connection {conn_id} from {src}");
        return;
    };
    send(ctx, addr, &pkt);
}

pub fn cross_user_pull_response(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[cross_user_pull_response] header too short from {src}");
        return;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[cross_user_pull_response] decryption failed from {src}");
                return;
            }
        }
    };

    let mut pos = 0usize;
    let Some(scope) = read_scope(&plaintext, &mut pos) else {
        eprintln!("[cross_user_pull_response] bad scope from {src}");
        return;
    };
    if !matches!(scope, Scope::Public) {
        eprintln!("[cross_user_pull_response] non-public scope ignored from {src}");
        return;
    }
    let Some(&result) = plaintext.get(pos) else {
        eprintln!("[cross_user_pull_response] missing result from {src}");
        return;
    };
    pos += 1;
    let Some(new_version) = read_sync_version(&plaintext, &mut pos) else {
        eprintln!("[cross_user_pull_response] truncated version from {src}");
        return;
    };

    let contact_user_uuid = {
        let node = ctx.node.read().unwrap();
        let Some(conn) = node.owner.active_connections.get(&conn_id) else {
            eprintln!("[cross_user_pull_response] no connection {conn_id} from {src}");
            return;
        };
        let peer_uuid = conn.device_uuid;
        match node.owner.contact_users.iter()
            .find(|c| c.user.devices.iter().any(|d| d.uuid == peer_uuid))
        {
            Some(c) => c.user.uuid,
            None    => {
                eprintln!("[cross_user_pull_response] conn {conn_id} not a contact from {src}");
                return;
            }
        }
    };

    match result {
        PULL_RESULT_NO_UPDATES => {
            let mut node = ctx.node.write().unwrap();
            if let Some(c) = node.owner.contact_users.iter_mut()
                .find(|c| c.user.uuid == contact_user_uuid)
            {
                c.last_seen_public_version = new_version;
            }
            drop(node);
            ctx.save_node();
        }
        PULL_RESULT_FULL_STATE => {
            let state_blob = &plaintext[pos..];
            let Some(data) = deserialize_contact_data(state_blob) else {
                eprintln!("[cross_user_pull_response] failed to parse state from {src}");
                return;
            };
            // Carry the contact's existing identity (alias + public_key); a
            // cross-user pull only refreshes the device/app snapshot.
            let identity = {
                let node = ctx.node.read().unwrap();
                node.owner.contact_users.iter()
                    .find(|c| c.user.uuid == data.user_uuid)
                    .map(|c| (c.user.alias.clone(), c.public_key))
            };
            if let Some((alias, public_key)) = identity {
                let cards: Vec<ContactDeviceCard> = data.devices.iter().map(|(d, apps)| {
                    ContactDeviceCard {
                        uuid: d.uuid, alias: d.alias.clone(), grade: d.grade,
                        sg_rank: d.sg_rank, hosts: d.hosts.clone(), apps: apps.clone(),
                    }
                }).collect();
                // Route the refreshed snapshot through the write log (Gap #2):
                // the writer logs it and merges it to non-writer own SGs.
                // Idempotent — an unchanged snapshot is a no-op, so periodic
                // pulls don't bump the version or spam the log.
                if let Err(WriteError::Unreachable) = request_change_idempotent(Change::UpsertContact {
                    uuid: data.user_uuid, alias, public_key, devices: cards,
                }, ctx) {
                    eprintln!("[cross_user_pull_response] no reachable writer SG; refreshed \
                               snapshot for {:?} not logged this round", data.user_uuid);
                }
            } else {
                eprintln!("[cross_user_pull_response] data for unknown contact {:?}",
                    data.user_uuid);
            }
            // Pin the cross-user pull baseline regardless of whether the
            // snapshot changed.
            {
                let mut node = ctx.node.write().unwrap();
                if let Some(c) = node.owner.contact_users.iter_mut()
                    .find(|c| c.user.uuid == contact_user_uuid)
                {
                    c.last_seen_public_version = new_version;
                }
            }
            ctx.save_node();
        }
        other => {
            eprintln!("[cross_user_pull_response] unknown result {other} from {src}");
        }
    }
}

// ── Sync v2 watermark exchange (ops 0x7A / 0x7B) ──────────────────────────────
//
// Sent SG↔SG between own-user SGs after a fresh active connection lands, to
// find the per-writer agreed reconciliation point before any merge proposal
// (0x78/0x79, landing in 7c.4). One round trip:
//
//   0x7A WatermarkProbeRequest:  [scope:1]
//   0x7B WatermarkProbeResponse: [scope:1][entry_count:u16]
//                                [(writer_sg_uuid:16, epoch:u32 BE, seq:u64 BE) × entry_count]
//
// The response body advertises the highest (epoch, seq) the sender has in
// its write log for each writer_sg_uuid that appears there for `scope`.
// After both sides exchange, each side takes the per-writer min of (our
// log, peer report) — that pair is the watermark from which the merge log
// replay would resume. v2-prerequisite only: this phase only stores the
// result; nothing consumes it yet.

/// Build the local writer-uuid → max version map for `scope` from the
/// write log. Returns one entry per distinct writer_sg_uuid present.
fn build_local_watermark_map(
    node: &super::data_models::Node,
    scope: Scope,
) -> Vec<(Uuid, SyncVersion)> {
    let mut out: Vec<(Uuid, SyncVersion)> = Vec::new();
    for entry in &node.owner.write_log {
        if entry.scope != scope { continue; }
        let writer = entry.version.writer_sg_uuid;
        match out.iter_mut().find(|(w, _)| *w == writer) {
            Some((_, v)) => {
                if (entry.version.epoch, entry.version.seq) > (v.epoch, v.seq) {
                    *v = entry.version;
                }
            }
            None => out.push((writer, entry.version)),
        }
    }
    out
}

fn serialize_watermark_map(scope: Scope, map: &[(Uuid, SyncVersion)]) -> Vec<u8> {
    let count = map.len().min(u16::MAX as usize) as u16;
    let mut buf = Vec::with_capacity(1 + 2 + (count as usize) * (16 + 4 + 8));
    write_scope(&mut buf, scope);
    buf.extend_from_slice(&count.to_be_bytes());
    for (writer, v) in map.iter().take(count as usize) {
        buf.extend_from_slice(writer);
        buf.extend_from_slice(&v.epoch.to_be_bytes());
        buf.extend_from_slice(&v.seq.to_be_bytes());
    }
    buf
}

fn parse_watermark_map(data: &[u8]) -> Option<(Scope, Vec<(Uuid, SyncVersion)>)> {
    let mut pos = 0usize;
    let scope = read_scope(data, &mut pos)?;
    let cnt_bytes: [u8; 2] = read_arr(data, &mut pos)?;
    let cnt = u16::from_be_bytes(cnt_bytes) as usize;
    let mut out = Vec::with_capacity(cnt);
    for _ in 0..cnt {
        let writer: Uuid = read_arr(data, &mut pos)?;
        let e_bytes: [u8; 4] = read_arr(data, &mut pos)?;
        let s_bytes: [u8; 8] = read_arr(data, &mut pos)?;
        out.push((writer, SyncVersion {
            writer_sg_uuid: writer,
            epoch: u32::from_be_bytes(e_bytes),
            seq:   u64::from_be_bytes(s_bytes),
        }));
    }
    Some((scope, out))
}

pub fn watermark_probe_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[watermark_probe_request] header too short from {src}");
        return;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[watermark_probe_request] decryption failed from {src}");
                return;
            }
        }
    };

    let mut pos = 0usize;
    let Some(scope) = read_scope(&plaintext, &mut pos) else {
        eprintln!("[watermark_probe_request] bad scope from {src}");
        return;
    };

    // SG↔SG only: ignore a probe unless we're an SG and the sender is an
    // own-user SG. Keeps an SG from engaging a stray probe (e.g. a DG running
    // an older build during a rollout).
    {
        let node = ctx.node.read().unwrap();
        let peer_is_own_sg = node.owner.active_connections.get(&conn_id)
            .map(|c| is_own_user_sg(&node.owner, c.device_uuid))
            .unwrap_or(false);
        if !local_is_sg(&node) || !peer_is_own_sg { return; }
    }

    let body = {
        let node = ctx.node.read().unwrap();
        let map = build_local_watermark_map(&node, scope);
        serialize_watermark_map(scope, &map)
    };

    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.get(&conn_id)
            .map(|conn| (
                build_encrypted_packet(WATERMARK_PROBE_RESPONSE_OP, conn, &body),
                conn.peer_addr,
            ))
    };
    let Some((pkt, addr)) = pkt_and_addr else {
        eprintln!("[watermark_probe_request] no connection {conn_id} to reply from {src}");
        return;
    };
    send(ctx, addr, &pkt);
}

pub fn watermark_probe_response(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[watermark_probe_response] header too short from {src}");
        return;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[watermark_probe_response] decryption failed from {src}");
                return;
            }
        }
    };

    let Some((scope, peer_map)) = parse_watermark_map(&plaintext) else {
        eprintln!("[watermark_probe_response] malformed body from {src}");
        return;
    };

    // Identify which peer device sent this so we can store the per-peer result.
    let peer_uuid = {
        let node = ctx.node.read().unwrap();
        match node.owner.active_connections.get(&conn_id) {
            Some(conn) => conn.device_uuid,
            None => {
                eprintln!("[watermark_probe_response] no connection {conn_id} from {src}");
                return;
            }
        }
    };

    // Compute per-writer min(our_log, peer_report) per descriptions/data sync.md
    // §"Watermark discovery". A writer absent from one side has an implicit
    // value of (0, 0) on that side, so the min is (0, 0) — meaning the agreed
    // reconciliation point is "before everything", and the side that *does*
    // have entries ships them all in the subsequent merge proposal.
    let our_map = {
        let node = ctx.node.read().unwrap();
        build_local_watermark_map(&node, scope)
    };
    let peer_writers: HashSet<Uuid> = peer_map.iter().map(|(w, _)| *w).collect();
    let our_writers:  HashSet<Uuid> = our_map.iter().map(|(w, _)| *w).collect();
    let mut merged: HashMap<Uuid, SyncVersion> = HashMap::new();
    for writer in our_writers.iter().chain(peer_writers.iter()).copied().collect::<HashSet<_>>() {
        let our_v  = our_map.iter().find(|(w, _)| *w == writer).map(|(_, v)| *v);
        let peer_v = peer_map.iter().find(|(w, _)| *w == writer).map(|(_, v)| *v);
        let merged_v = match (our_v, peer_v) {
            (Some(o), Some(p)) => {
                if (o.epoch, o.seq) <= (p.epoch, p.seq) { o } else { p }
            }
            _ => SyncVersion { writer_sg_uuid: writer, epoch: 0, seq: 0 },
        };
        merged.insert(writer, merged_v);
    }

    {
        let mut node = ctx.node.write().unwrap();
        node.owner.last_watermarks.insert(peer_uuid, merged);
    }

    // Sync v2: partition reconciliation is SG↔SG only — both this node and the
    // peer must be own-user SGs. A DG should never have probed (so never get
    // here), but guard so it never emits a proposal a peer would reject.
    let send_proposal = {
        let node = ctx.node.read().unwrap();
        local_is_sg(&node) && is_own_user_sg(&node.owner, peer_uuid)
    };
    if !send_proposal { return; }

    let (sender_version, entries) =
        build_merge_proposal_for_peer(peer_uuid, scope, ctx);
    let body = build_merge_proposal_body(scope, sender_version, &entries);
    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.get(&conn_id).map(|conn| (
            build_encrypted_packet(MERGE_PROPOSAL_OP, conn, &body),
            conn.peer_addr,
        ))
    };
    if let Some((pkt, addr)) = pkt_and_addr {
        send(ctx, addr, &pkt);
    }
}

// ── Sync v2 merge proposal exchange (ops 0x78 / 0x79) ────────────────────────
//
// After watermark discovery (0x7A/0x7B) settles the per-writer agreed point,
// each SG ships the slice of its write log above that point so the peer can
// merge. 7c.4 wires the receive-and-store path only — the actual merge
// engine and the ack-driven state mutation land in 7c.5 / 7c.6.
//
//   0x78 MergeProposal: [scope:1][sender_version:28][entry_count:u16]
//                       [entries...]
//     each entry: [version:28][payload_len:u16][change_payload:var]
//                 [committed_at_secs:u64 BE]
//   0x79 MergeAck:      [scope:1][new_watermark:28][result:1]
//     result: 0=applied, 1=retention-exhausted-fallback, 2=malformed
//
// `sender_version` in the proposal is the proposer's own post-bump version
// at proposal time — a sanity stamp so the receiver can detect divergence
// even before parsing entries. Per-writer filtering is done at the sender
// using `Owner.last_watermarks[peer_uuid]` from 7c.3, so the body need not
// re-ship a full watermark map.

fn build_merge_proposal_body(
    scope: Scope,
    sender_version: SyncVersion,
    entries: &[WriteLogEntry],
) -> Vec<u8> {
    let count = entries.len().min(u16::MAX as usize) as u16;
    let mut buf = Vec::with_capacity(1 + SYNC_VERSION_WIRE_LEN + 2);
    write_scope(&mut buf, scope);
    write_sync_version(&mut buf, &sender_version);
    buf.extend_from_slice(&count.to_be_bytes());
    for e in entries.iter().take(count as usize) {
        write_sync_version(&mut buf, &e.version);
        let p_len = e.change_payload.len().min(u16::MAX as usize) as u16;
        buf.extend_from_slice(&p_len.to_be_bytes());
        buf.extend_from_slice(&e.change_payload[..p_len as usize]);
        let secs = e.committed_at
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        buf.extend_from_slice(&secs.to_be_bytes());
    }
    buf
}

fn parse_merge_proposal_body(
    data: &[u8],
) -> Option<(Scope, SyncVersion, Vec<WriteLogEntry>)> {
    let mut pos = 0usize;
    let scope = read_scope(data, &mut pos)?;
    let sender_version = read_sync_version(data, &mut pos)?;
    let cnt_bytes: [u8; 2] = read_arr(data, &mut pos)?;
    let cnt = u16::from_be_bytes(cnt_bytes) as usize;
    let mut entries = Vec::with_capacity(cnt);
    for _ in 0..cnt {
        let version = read_sync_version(data, &mut pos)?;
        let p_len_bytes: [u8; 2] = read_arr(data, &mut pos)?;
        let p_len = u16::from_be_bytes(p_len_bytes) as usize;
        let payload_slice = data.get(pos..pos + p_len)?;
        let change_payload = payload_slice.to_vec();
        pos += p_len;
        let secs_bytes: [u8; 8] = read_arr(data, &mut pos)?;
        let secs = u64::from_be_bytes(secs_bytes);
        let committed_at = std::time::UNIX_EPOCH + Duration::from_secs(secs);
        entries.push(WriteLogEntry {
            version,
            scope,
            change_payload,
            committed_at,
        });
    }
    Some((scope, sender_version, entries))
}

fn build_merge_ack_body(scope: Scope, new_watermark: SyncVersion, result: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + SYNC_VERSION_WIRE_LEN + 1);
    write_scope(&mut buf, scope);
    write_sync_version(&mut buf, &new_watermark);
    buf.push(result);
    buf
}

fn parse_merge_ack_body(data: &[u8]) -> Option<(Scope, SyncVersion, u8)> {
    let mut pos = 0usize;
    let scope = read_scope(data, &mut pos)?;
    let v     = read_sync_version(data, &mut pos)?;
    let r     = *data.get(pos)?;
    Some((scope, v, r))
}

/// Build the entries this node would ship to `peer_uuid` for `scope`: the
/// log entries whose `(epoch, seq)` strictly exceeds the per-writer watermark
/// established by the most recent WatermarkProbe exchange. Writers the peer
/// reported but we don't have in `last_watermarks` are treated as "we know
/// nothing about their slice for the peer," and we ship every entry of ours
/// under those writers.
fn build_merge_proposal_for_peer(
    peer_uuid: Uuid,
    scope: Scope,
    ctx: &WorkerContext,
) -> (SyncVersion, Vec<WriteLogEntry>) {
    let node = ctx.node.read().unwrap();
    let watermark_for = |writer: &Uuid| -> Option<SyncVersion> {
        node.owner.last_watermarks
            .get(&peer_uuid)
            .and_then(|m| m.get(writer))
            .copied()
    };
    let entries: Vec<WriteLogEntry> = node.owner.write_log.iter()
        .filter(|e| e.scope == scope)
        .filter(|e| match watermark_for(&e.version.writer_sg_uuid) {
            Some(w) => (e.version.epoch, e.version.seq) > (w.epoch, w.seq),
            None    => true,
        })
        .cloned()
        .collect();
    let sender_version = match scope {
        Scope::Public  => node.owner.public_version,
        Scope::Private => node.owner.private_version,
    };
    (sender_version, entries)
}

pub fn merge_proposal(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[merge_proposal] header too short from {src}");
        return;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[merge_proposal] decryption failed from {src}");
                return;
            }
        }
    };

    let Some((scope, sender_version, entries)) = parse_merge_proposal_body(&plaintext) else {
        eprintln!("[merge_proposal] malformed body from {src}");
        return;
    };

    let peer_uuid = {
        let node = ctx.node.read().unwrap();
        match node.owner.active_connections.get(&conn_id) {
            Some(conn) => conn.device_uuid,
            None => {
                eprintln!("[merge_proposal] no connection {conn_id} from {src}");
                return;
            }
        }
    };

    println!(
        "[merge_proposal] {} entries from peer {:02x?} (scope={scope:?}, sender_version epoch={}, seq={})",
        entries.len(),
        &peer_uuid[..4],
        sender_version.epoch,
        sender_version.seq,
    );

    // 7c.6: actually run the merge. Receiving a proposal from a non-own-user
    // SG is a protocol violation — store nothing, ack malformed.
    let is_own_sg = {
        let node = ctx.node.read().unwrap();
        is_own_user_sg(&node.owner, peer_uuid)
    };
    if !is_own_sg {
        eprintln!("[merge_proposal] from non-own-user-SG peer {:02x?}; replying malformed",
                  &peer_uuid[..4]);
        send_merge_ack(conn_id, scope, SyncVersion::zero(),
                       MERGE_ACK_RESULT_MALFORMED, ctx);
        return;
    }

    // Cache the raw proposal for diagnostics; replaced on each round.
    {
        let mut node = ctx.node.write().unwrap();
        node.owner.received_merge_proposals.insert(peer_uuid, entries.clone());
    }

    // Snapshot inputs for the pure merge function, drop the read lock before
    // mutating.
    let (local_log, writer_ranks, local_uuid) = {
        let node = ctx.node.read().unwrap();
        let local_log: Vec<WriteLogEntry> = node.owner.write_log.iter()
            .filter(|e| e.scope == scope)
            .cloned()
            .collect();
        let writer_ranks: HashMap<Uuid, u32> = node.owner.user.devices.iter()
            .filter(|d| matches!(d.grade, DeviceGrade::SG))
            .filter_map(|d| d.sg_rank.map(|r| (d.uuid, r)))
            .collect();
        (local_log, writer_ranks, node.device_uuid)
    };

    let merged = merge_logs(&local_log, &entries, &writer_ranks);

    let mut any_state_change = false;
    let new_version: SyncVersion = {
        let mut node = ctx.node.write().unwrap();

        // Append peer entries verbatim so onward propagation preserves their
        // original (writer_uuid, epoch, seq) attribution.
        for e in &merged.new_entries {
            node.owner.write_log.push(e.clone());
        }
        // Prune retention on every append-batch.
        if let Some(cutoff) = SystemTime::now().checked_sub(WRITE_LOG_RETENTION) {
            node.owner.write_log.retain(|e| e.committed_at >= cutoff);
        }

        // Apply each merged Change directly to local state. `diff_states`
        // emits AddDevice before AddApplication so device-existence checks
        // pass; an idempotent Add or a Remove against a missing target is a
        // no-op rather than an error.
        for change in &merged.changes_to_apply {
            match apply_change_to_owner(&mut node.owner, change) {
                Ok(true)  => any_state_change = true,
                Ok(false) => {}
                Err(e) => eprintln!("[merge_proposal] applying {change:?} failed: {e:?}"),
            }
        }

        // One bump per merge, not per Change — the merge IS the write that
        // produced the new state, so DGs and own peers see a fresh version and
        // pull. Stamp it under the deterministically-elected writer (the
        // highest-rank reachable own SG, via the rank walk — NOT the
        // known-writer fast path, which may still carry a self-elected uuid
        // from the partition) rather than `local_uuid`. Otherwise both sides of
        // a bilateral heal stamp themselves, leaving the cluster with two SGs
        // each claiming to be the writer; routing then disagrees until the next
        // poll re-elects. Electing rank-1 here makes both survivors converge on
        // the same writer_sg_uuid and repairs this node's fast path in one step.
        if any_state_change {
            let writer_uuid = match find_pull_source(&node) {
                WriterTarget::Local       => local_uuid,
                WriterTarget::Remote(u)   => u,
                WriterTarget::Unreachable => local_uuid,
            };
            node.owner.bump_version(scope, writer_uuid);
        }

        match scope {
            Scope::Public  => node.owner.public_version,
            Scope::Private => node.owner.private_version,
        }
    };

    if !merged.new_entries.is_empty() || any_state_change {
        ctx.save_node();
    }

    // Notify own peers + contacts so they pull the merged state. notify_own_peers
    // is keyed on bumped scopes; only fire when state actually changed.
    if any_state_change {
        let (priv_v, pub_v) = {
            let node = ctx.node.read().unwrap();
            (node.owner.private_version, node.owner.public_version)
        };
        notify_own_peers(&[scope], priv_v, pub_v, ctx);
        if matches!(scope, Scope::Public) {
            notify_contacts(pub_v, ctx);
        }
    }

    send_merge_ack(conn_id, scope, new_version, MERGE_ACK_RESULT_APPLIED, ctx);
}

fn send_merge_ack(
    conn_id: u16,
    scope:   Scope,
    new_watermark: SyncVersion,
    result:  u8,
    ctx:     &WorkerContext,
) {
    let body = build_merge_ack_body(scope, new_watermark, result);
    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.get(&conn_id).map(|conn| (
            build_encrypted_packet(MERGE_ACK_OP, conn, &body),
            conn.peer_addr,
        ))
    };
    if let Some((pkt, addr)) = pkt_and_addr {
        send(ctx, addr, &pkt);
    }
}

pub fn merge_ack(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[merge_ack] header too short from {src}");
        return;
    }
    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[merge_ack] decryption failed from {src}");
                return;
            }
        }
    };
    let Some((scope, new_watermark, result)) = parse_merge_ack_body(&plaintext) else {
        eprintln!("[merge_ack] malformed body from {src}");
        return;
    };
    let result_str = match result {
        MERGE_ACK_RESULT_APPLIED            => "applied",
        MERGE_ACK_RESULT_RETENTION_EXHAUSTED => "retention_exhausted",
        MERGE_ACK_RESULT_MALFORMED          => "malformed",
        _ => "unknown",
    };
    println!(
        "[merge_ack] result={result_str} scope={scope:?} new_watermark=(epoch={}, seq={})",
        new_watermark.epoch, new_watermark.seq,
    );
}

// ── Sync v2 merge engine (7c.5) ──────────────────────────────────────────────
//
// Pure function over two `Vec<WriteLogEntry>` lists. Produces:
//   * `new_entries`     — peer entries we don't already have (append verbatim
//                         to our `write_log` so their original writer/version
//                         attribution survives onward propagation).
//   * `changes_to_apply` — minimal `Change` sequence that, when each is run
//                         through `apply_change_locally`, transforms current
//                         local state into the merged target state.
//
// Conflict-resolution rules (from `descriptions/data sync.md` §"v2: merge
// engine"):
//   * Add (AddApplication, AddDevice): union by uuid. Idempotent.
//   * Tombstone (RemoveApplication): wins globally for the (device, app_id)
//     pair regardless of any conflicting Add's `(epoch, seq)`. UUIDs make
//     re-add-after-remove safe because the new entity carries a fresh id.
//   * Scalar update (UpdateApplicationAlias): highest writer-rank wins;
//     tiebreaker `(epoch, seq)` then `writer_uuid`.
//
// 7c.6 wires this into `connect_ack`. Until then the engine has no callers —
// it's exercised purely by the unit tests below.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeOutput {
    /// Peer entries whose `(writer_sg_uuid, epoch, seq)` triple is absent
    /// from `local_log`. Caller appends these to `Owner.write_log` so future
    /// merge proposals can replay the peer's history under its original
    /// attribution.
    pub new_entries: Vec<WriteLogEntry>,
    /// Changes the caller should drive through `apply_change_locally` to
    /// bring local state in line with the merged target. Ordered so device
    /// creations precede their app entries.
    pub changes_to_apply: Vec<Change>,
}

/// Pure merge of `local_log` and `peer_log`. `writer_ranks` maps each known
/// writer SG to its `sg_rank` (lower = higher priority); writers absent from
/// the map are treated as lowest priority for tiebreaking scalar updates.
pub fn merge_logs(
    local_log: &[WriteLogEntry],
    peer_log:  &[WriteLogEntry],
    writer_ranks: &HashMap<Uuid, u32>,
) -> MergeOutput {
    let local_keys: HashSet<(Uuid, u32, u64)> = local_log.iter()
        .map(|e| (e.version.writer_sg_uuid, e.version.epoch, e.version.seq))
        .collect();

    let new_entries: Vec<WriteLogEntry> = peer_log.iter()
        .filter(|e| !local_keys.contains(&(
            e.version.writer_sg_uuid, e.version.epoch, e.version.seq,
        )))
        .cloned()
        .collect();

    if new_entries.is_empty() {
        return MergeOutput { new_entries, changes_to_apply: Vec::new() };
    }

    let current = compute_state(local_log.iter(), writer_ranks);
    let target  = compute_state(
        local_log.iter().chain(new_entries.iter()),
        writer_ranks,
    );

    let changes_to_apply = diff_states(&current, &target);

    MergeOutput { new_entries, changes_to_apply }
}

struct MergedState {
    /// (device_uuid, app_id) → resolved app.
    apps:    HashMap<(Uuid, Uuid), MergedApp>,
    devices: HashMap<Uuid, MergedDevice>,
    tombstones: HashSet<(Uuid, Uuid)>,
    /// contact_uuid → resolved contact snapshot. Whole-contact last-writer-wins
    /// (each `UpsertContact` carries the full snapshot, so the highest-priority
    /// entry's snapshot wins outright).
    contacts: HashMap<Uuid, MergedContact>,
}

/// Per-contact accumulator: the winning snapshot plus the priority of the
/// entry that set it.
struct MergedContact {
    alias:      String,
    public_key: PublicKey,
    devices:    Vec<ContactDeviceCard>,
    priority:   EntryPriority,
}

/// Per-app accumulator during the walk. `existed` becomes true once any
/// non-tombstoned `AddApplication` is seen — the entity is only present in
/// the final state when `existed`. `alias_from_update` tracks whether the
/// resolved alias came from an explicit `UpdateApplicationAlias`. An Update
/// always overrides an Add's incidental alias (regardless of writer rank);
/// among Updates the standard rank-priority decides, and among Adds (when
/// no Update has been seen) the same rank-priority decides. This split is
/// what makes bilateral partition recovery work: a later Update from a
/// lower-rank writer must beat an earlier Add from a higher-rank writer
/// when the Update is the explicit intent for that app's alias.
struct MergedApp {
    existed: bool,
    alias:   String,
    alias_priority: EntryPriority,
    alias_from_update: bool,
}

#[derive(Clone)]
struct MergedDevice {
    alias:   String,
    grade:   DeviceGrade,
    sg_rank: Option<u32>,
    hosts:   Vec<String>,
}

/// Comparison key for "who wins" on a scalar update. Tuple ordering gives
/// higher writer-rank (smaller `sg_rank`) the win first, then later
/// `(epoch, seq)`, then larger `writer_uuid` lexicographically.
type EntryPriority = (std::cmp::Reverse<u32>, u32, u64, Uuid);

fn entry_priority(version: &SyncVersion, ranks: &HashMap<Uuid, u32>) -> EntryPriority {
    let rank = ranks.get(&version.writer_sg_uuid).copied().unwrap_or(u32::MAX);
    (std::cmp::Reverse(rank), version.epoch, version.seq, version.writer_sg_uuid)
}

fn compute_state<'a, I: Iterator<Item = &'a WriteLogEntry>>(
    log: I,
    ranks: &HashMap<Uuid, u32>,
) -> MergedState {
    // Materialize so we can iterate twice (tombstones, then Add/Update).
    let mut entries: Vec<&WriteLogEntry> = log.collect();
    entries.sort_by_key(|e| (
        e.version.epoch,
        e.version.seq,
        e.version.writer_sg_uuid,
    ));

    let mut state = MergedState {
        apps: HashMap::new(),
        devices: HashMap::new(),
        tombstones: HashSet::new(),
        contacts: HashMap::new(),
    };

    // First pass: collect tombstones. Tombstone wins globally for its target,
    // regardless of `(epoch, seq)` of any conflicting Add.
    for e in &entries {
        if let Some(Change::RemoveApplication { device_uuid, app_id }) =
            deserialize_change(&e.change_payload)
        {
            state.tombstones.insert((device_uuid, app_id));
        }
    }

    // Second pass: walk Adds, Updates, and AddDevice. AddApplication and
    // UpdateApplicationAlias compete equally on alias priority — the winner
    // doesn't depend on whether the Update arrived before or after the Add in
    // `(epoch, seq)` order.
    for e in &entries {
        let Some(change) = deserialize_change(&e.change_payload) else { continue };
        let prio = entry_priority(&e.version, ranks);
        match change {
            Change::RemoveApplication { .. } => { /* recorded above */ }
            Change::AddApplication { device_uuid, app_id, app_alias } => {
                if state.tombstones.contains(&(device_uuid, app_id)) { continue; }
                upsert_alias(&mut state.apps, (device_uuid, app_id),
                             app_alias, prio, true);
            }
            Change::UpdateApplicationAlias { device_uuid, app_id, new_alias } => {
                if state.tombstones.contains(&(device_uuid, app_id)) { continue; }
                upsert_alias(&mut state.apps, (device_uuid, app_id),
                             new_alias, prio, false);
            }
            Change::AddDevice { uuid, alias, grade, sg_rank, hosts } => {
                state.devices.entry(uuid).or_insert(MergedDevice {
                    alias, grade, sg_rank, hosts,
                });
            }
            Change::UpsertContact { uuid, alias, public_key, devices } => {
                // Whole-contact last-writer-wins: the highest-priority upsert's
                // snapshot replaces any lower-priority one outright.
                let win = match state.contacts.get(&uuid) {
                    Some(existing) => prio > existing.priority,
                    None           => true,
                };
                if win {
                    state.contacts.insert(uuid, MergedContact {
                        alias,
                        public_key,
                        devices: normalize_cards(&devices),
                        priority: prio,
                    });
                }
            }
        }
    }

    // Drop apps that only ever appeared via an Update (no Add to establish
    // their existence). This shouldn't happen with correct watermark
    // filtering, but the guard keeps the diff sound.
    state.apps.retain(|_, a| a.existed);

    state
}

fn upsert_alias(
    apps: &mut HashMap<(Uuid, Uuid), MergedApp>,
    key:  (Uuid, Uuid),
    alias: String,
    prio:  EntryPriority,
    sets_existence: bool,   // true = Add, false = Update
) {
    let is_update = !sets_existence;
    match apps.get_mut(&key) {
        Some(slot) => {
            if sets_existence { slot.existed = true; }
            // Updates always beat Adds for the alias slot, regardless of
            // writer rank. Among same-kind entries, rank-priority decides.
            let should_overwrite = match (is_update, slot.alias_from_update) {
                (true,  false) => true,                     // Update over Add
                (false, true)  => false,                    // Add can't override Update
                _              => prio > slot.alias_priority,
            };
            if should_overwrite {
                slot.alias = alias;
                slot.alias_priority = prio;
                slot.alias_from_update = is_update || slot.alias_from_update;
            }
        }
        None => {
            apps.insert(key, MergedApp {
                existed: sets_existence,
                alias,
                alias_priority: prio,
                alias_from_update: is_update,
            });
        }
    }
}

fn diff_states(current: &MergedState, target: &MergedState) -> Vec<Change> {
    let mut out: Vec<Change> = Vec::new();

    // Devices first — AddApplication validates the device exists.
    let mut new_devices: Vec<(&Uuid, &MergedDevice)> = target.devices.iter()
        .filter(|(u, _)| !current.devices.contains_key(*u))
        .collect();
    new_devices.sort_by_key(|(u, _)| **u);
    for (uuid, dev) in new_devices {
        out.push(Change::AddDevice {
            uuid:    *uuid,
            alias:   dev.alias.clone(),
            grade:   dev.grade,
            sg_rank: dev.sg_rank,
            hosts:   dev.hosts.clone(),
        });
    }

    // Apps in target: Add if missing locally, Update if alias differs.
    let mut target_apps: Vec<(&(Uuid, Uuid), &MergedApp)> = target.apps.iter().collect();
    target_apps.sort_by_key(|(k, _)| **k);
    for ((d, id), app) in target_apps {
        match current.apps.get(&(*d, *id)) {
            None => out.push(Change::AddApplication {
                device_uuid: *d,
                app_id:      *id,
                app_alias:   app.alias.clone(),
            }),
            Some(cur) if cur.alias != app.alias => {
                out.push(Change::UpdateApplicationAlias {
                    device_uuid: *d,
                    app_id:      *id,
                    new_alias:   app.alias.clone(),
                });
            }
            _ => {}
        }
    }

    // Apps in current but absent from target: emit Remove. Driven either by
    // an explicit peer tombstone or by the peer adopting a remove we didn't
    // record (shouldn't happen, but the diff is symmetric).
    let mut removed: Vec<(Uuid, Uuid)> = current.apps.keys()
        .filter(|k| !target.apps.contains_key(k))
        .copied()
        .collect();
    removed.sort();
    for (d, id) in removed {
        out.push(Change::RemoveApplication { device_uuid: d, app_id: id });
    }

    // Contacts: emit an UpsertContact for any target contact that's new or
    // whose snapshot differs from current. No contact removal Change exists
    // yet, so contacts are never diffed out.
    let mut target_contacts: Vec<(&Uuid, &MergedContact)> = target.contacts.iter().collect();
    target_contacts.sort_by_key(|(u, _)| **u);
    for (uuid, c) in target_contacts {
        let differs = match current.contacts.get(uuid) {
            None      => true,
            Some(cur) => cur.alias != c.alias
                || cur.public_key != c.public_key
                || cur.devices != c.devices,
        };
        if differs {
            out.push(Change::UpsertContact {
                uuid:       *uuid,
                alias:      c.alias.clone(),
                public_key: c.public_key,
                devices:    c.devices.clone(),
            });
        }
    }

    out
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
        if plaintext.len() < 48 {
            eprintln!("[relay_packet] plaintext too short from {src}");
            return;
        }
        let dest_device_uuid: Uuid = plaintext[0..16].try_into().unwrap();
        let dest_app_id:      Uuid = plaintext[16..32].try_into().unwrap();
        let sender_app_id:    Uuid = plaintext[32..48].try_into().unwrap();
        let payload                = plaintext[48..].to_vec();

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

        if plaintext.len() < 32 {
            eprintln!("[app_packet] plaintext too short from {src}");
            return;
        }
        let dest_app_id:   Uuid = plaintext[0..16].try_into().unwrap();
        let sender_app_id: Uuid = plaintext[16..32].try_into().unwrap();
        let payload             = &plaintext[32..];

        // Find the destination app on this node.
        let device_uuid = node.device_uuid;
        let Some(app_host) = node.owner.user.devices.iter()
            .find(|d| d.uuid == device_uuid)
            .and_then(|d| d.applications.iter()
                .find(|a| a.id == dest_app_id && a.user_approved))
            .map(|a| a.host)
        else {
            eprintln!("[app_packet] no approved app with id {}", uuid_hex(&dest_app_id));
            return;
        };

        // Build push packet: [0x04][sender_app_id: 16][payload]
        let mut push = Vec::with_capacity(17 + payload.len());
        push.push(APP_PUSH_OP);
        push.extend_from_slice(&sender_app_id);
        push.extend_from_slice(payload);

        (push, app_host)
    };

    send(ctx, SocketAddr::V4(app_host), &push_pkt);
}

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
        ctx.scheduler_tx.send(super::action_queue::ScheduleRequest {
            action: super::action_queue::Action::MaintainConnections,
            delay:  PENDING_CONNECTION_TIMEOUT + Duration::from_millis(500),
        }).ok();
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
        if plaintext.len() < 32 {
            eprintln!("[tunnel_delivery] plaintext too short for tunnel {tunnel_id}");
            return;
        }

        let dest_app_id:   Uuid = plaintext[0..16].try_into().unwrap();
        let sender_app_id: Uuid = plaintext[16..32].try_into().unwrap();
        let payload             = &plaintext[32..];

        let device_uuid = node.device_uuid;
        let Some(app_host) = node.owner.user.devices.iter()
            .find(|d| d.uuid == device_uuid)
            .and_then(|d| d.applications.iter().find(|a| a.id == dest_app_id))
            .map(|a| a.host)
        else {
            eprintln!("[tunnel_delivery] no app {} for tunnel {tunnel_id}", uuid_hex(&dest_app_id));
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
        ("GET",  "/pending-apps")         => respond_html(&stream, 200, &render_pending_apps(ctx, &query)),
        ("POST", "/pending-apps/approve") => {
            let target = redirect_with_error("/pending-apps", approve_app(&body, ctx));
            respond_redirect(&stream, &target);
        }
        ("POST", "/pending-apps/reject")  => {
            let target = redirect_with_error("/pending-apps", reject_app(&body, ctx));
            respond_redirect(&stream, &target);
        }
        ("GET",  "/applications")  => respond_html(&stream, 200, &render_applications(ctx, &query)),
        ("POST", "/applications/delete") => {
            let target = redirect_with_error("/applications", reject_app(&body, ctx));
            respond_redirect(&stream, &target);
        }
        ("POST", "/applications/rename") => {
            let target = redirect_with_error("/applications", rename_app(&body, ctx));
            respond_redirect(&stream, &target);
        }
        ("GET",  "/contacts")      => respond_html(&stream, 200, &render_contacts(ctx)),
        ("GET",  "/devices")       => respond_html(&stream, 200, &render_devices(ctx)),
        ("POST", "/devices/sync")  => {
            // Manual refresh: pull the latest public/private state from the
            // writer SG. No-op when this node is the writer or has no
            // reachable own SG.
            sync_pull(ctx);
            respond_redirect(&stream, "/devices");
        }
        ("GET",  "/diagnostics")   => respond_html(&stream, 200, &render_diagnostics(ctx)),
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
        _ => respond_html(&stream, 404, &layout(ctx, "Not Found", "<h1>404 — Not Found</h1>")),
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

/// Helper for POST routes: redirect to `base` on success, or to
/// `base?error=<code>` when the action returned a UI error code.
fn redirect_with_error(base: &str, err: Option<&'static str>) -> String {
    match err {
        Some(code) => format!("{base}?error={code}"),
        None       => base.to_string(),
    }
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
    layout(ctx, "Dashboard", &body)
}

/// Render a red banner for the UI error codes emitted by approve_app /
/// reject_app. Returns an empty string when there's no error to show.
fn ui_error_banner(query: &str) -> String {
    match query_param(query, "error") {
        Some(code) if code == UI_ERR_PUBLISH_FAILED =>
            "<div class='card' style='background:#fee;color:#900;border:1px solid #c66'>\
                <strong>Could not publish change:</strong> no reachable writer SG. \
                The local change has been rolled back; retry when an SG is online.\
            </div>".to_string(),
        _ => String::new(),
    }
}

fn render_pending_apps(ctx: &WorkerContext, query: &str) -> String {
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
                    uuid_hex(&a.id),
                    uuid_hex(&a.id),
                ))
                .collect()
        })
        .unwrap_or_default();

    let error_banner = ui_error_banner(query);
    let table = if rows.is_empty() {
        "<p class='empty'>No pending applications.</p>".to_string()
    } else {
        format!(
            "<table>\
               <tr><th>Alias</th><th>Protocol</th><th>Host</th><th>Actions</th></tr>\
               {rows}\
             </table>"
        )
    };
    let body = format!("<h1>Pending Apps</h1>{error_banner}{table}");
    layout(ctx, "Pending Apps", &body)
}

fn render_applications(ctx: &WorkerContext, query: &str) -> String {
    let node        = ctx.node.read().unwrap();
    let device_uuid = node.device_uuid;
    let device      = node.owner.user.devices.iter().find(|d| d.uuid == device_uuid);

    let rows: String = device
        .map(|d| {
            d.applications.iter()
                .filter(|a| a.user_approved)
                .map(|a| format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td>\
                     <td><form method='post' action='/applications/rename' style='margin:0;display:flex;gap:.25rem'>\
                       <input type='hidden' name='id' value='{id_hex}'>\
                       <input type='text' name='alias' value='{alias}' required>\
                       <button type='submit'>Rename</button>\
                     </form></td>\
                     <td><form method='post' action='/applications/delete' style='margin:0'>\
                       <input type='hidden' name='id' value='{id_hex}'>\
                       <button type='submit'>Delete</button>\
                     </form></td></tr>",
                    html_escape(&a.alias),
                    html_escape(&a.protocol),
                    html_escape(&a.host.to_string()),
                    id_hex = uuid_hex(&a.id),
                    alias  = html_escape(&a.alias),
                ))
                .collect()
        })
        .unwrap_or_default();

    let error_banner = ui_error_banner(query);
    let table = if rows.is_empty() {
        "<p class='empty'>No approved applications.</p>".to_string()
    } else {
        format!(
            "<table>\
               <tr><th>Alias</th><th>Protocol</th><th>Host</th><th>Rename</th><th></th></tr>\
               {rows}\
             </table>"
        )
    };
    let body = format!("<h1>Applications</h1>{error_banner}{table}");
    layout(ctx, "Applications", &body)
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
    layout(ctx, "Contacts", &body)
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
    layout(ctx, "Devices", &body)
}

// ── Sync v2 diagnostics ───────────────────────────────────────────────────────

/// Render `/diagnostics` — surfaces the ephemeral state that drives sync v2
/// partition reconciliation: per-peer reachability, last exchanged watermarks,
/// and buffered inbound merge proposals. Read-only.
fn render_diagnostics(ctx: &WorkerContext) -> String {
    let node = ctx.node.read().unwrap();
    let local_uuid = node.device_uuid;
    let pv = node.owner.public_version;

    let local_section = format!(
        "<div class='card'>\
           <h2 style='margin-top:0'>Local node</h2>\
           <table>\
             <tr><th>Device UUID</th><td><code>{local}</code></td></tr>\
             <tr><th>Public version</th><td>writer=<code>{w}</code> epoch={e} seq={s}</td></tr>\
             <tr><th>Write log</th><td>{n} entries (retention {ret}d)</td></tr>\
           </table>\
         </div>",
        local = uuid_hex(&local_uuid),
        w     = uuid_hex(&pv.writer_sg_uuid),
        e     = pv.epoch,
        s     = pv.seq,
        n     = node.owner.write_log.len(),
        ret   = WRITE_LOG_RETENTION.as_secs() / 86_400,
    );

    // Build an alias lookup so peer-uuid keys in the ephemeral maps render
    // with human-readable names.
    let alias_of = |uuid: &Uuid| -> String {
        if uuid == &local_uuid { return "(this device)".to_string(); }
        for d in &node.owner.user.devices {
            if d.uuid == *uuid { return d.alias.clone(); }
        }
        for c in &node.owner.contact_users {
            for d in &c.user.devices {
                if d.uuid == *uuid { return format!("{}/{}", c.user.alias, d.alias); }
            }
        }
        "(unknown)".to_string()
    };

    // Own-user SG peers + reachability.
    let mut peer_rows = String::new();
    for d in &node.owner.user.devices {
        if !matches!(d.grade, DeviceGrade::SG) || d.uuid == local_uuid { continue; }
        let host_lines: String = d.hosts.iter().map(|h| {
            match node.sg_statuses.get(&(d.uuid, h.clone())) {
                Some(s) => {
                    let rtt = s.last_rtt.map(|r| format!("{}ms", r.as_millis()))
                        .unwrap_or_else(|| "—".to_string());
                    let status = if s.up { "<span style='color:#2d7a3b'>up</span>" }
                                 else    { "<span style='color:#c0392b'>down</span>" };
                    format!("<li><code>{}</code> — {status} (rtt {rtt})</li>", html_escape(h))
                }
                None => format!("<li><code>{}</code> — <span style='color:#888'>not yet polled</span></li>",
                                html_escape(h)),
            }
        }).collect();
        peer_rows.push_str(&format!(
            "<tr><td>{alias}<br><code style='font-size:.75rem;color:#888'>{uuid}</code></td>\
                 <td><ul style='margin:0;padding-left:1.2rem'>{host_lines}</ul></td></tr>",
            alias = html_escape(&d.alias),
            uuid  = uuid_hex(&d.uuid),
        ));
    }
    let peers_section = if peer_rows.is_empty() {
        "<div class='card'><h2 style='margin-top:0'>Own-user SG peers</h2>\
         <p class='empty'>No other own-user SG peers.</p></div>".to_string()
    } else {
        format!(
            "<div class='card'><h2 style='margin-top:0'>Own-user SG peers</h2>\
             <table><tr><th>Peer</th><th>Hosts</th></tr>{peer_rows}</table></div>"
        )
    };

    // Last watermarks: peer_uuid → writer_uuid → SyncVersion.
    let mut wm_rows = String::new();
    let mut peers_with_wm: Vec<&Uuid> = node.owner.last_watermarks.keys().collect();
    peers_with_wm.sort_by_key(|u| uuid_hex(u));
    for peer_uuid in peers_with_wm {
        let writers = &node.owner.last_watermarks[peer_uuid];
        let mut sub_rows: Vec<String> = writers.iter().map(|(wu, sv)| {
            format!(
                "<tr><td><code>{}</code><br><span style='font-size:.75rem;color:#888'>{}</span></td>\
                     <td>epoch={} seq={}</td></tr>",
                alias_of(wu), uuid_hex(wu), sv.epoch, sv.seq,
            )
        }).collect();
        sub_rows.sort();
        wm_rows.push_str(&format!(
            "<tr><td>{alias}<br><code style='font-size:.75rem;color:#888'>{uuid}</code></td>\
                 <td><table style='margin:0;box-shadow:none;background:transparent'>\
                       <tr><th>Writer</th><th>Version</th></tr>{}</table></td></tr>",
            sub_rows.concat(),
            alias = html_escape(&alias_of(peer_uuid)),
            uuid  = uuid_hex(peer_uuid),
        ));
    }
    let wm_section = if wm_rows.is_empty() {
        "<div class='card'><h2 style='margin-top:0'>Last watermarks</h2>\
         <p class='empty'>No watermark exchanges yet.</p></div>".to_string()
    } else {
        format!(
            "<div class='card'><h2 style='margin-top:0'>Last watermarks</h2>\
             <p style='font-size:.85rem;color:#666;margin-top:0'>Per-peer, per-writer agreed reconciliation point. \
                Rebuilt on every watermark-probe round-trip.</p>\
             <table><tr><th>Peer</th><th>Per-writer min</th></tr>{wm_rows}</table></div>"
        )
    };

    // Buffered inbound merge proposals.
    let mut pp_rows = String::new();
    let mut peers_with_pp: Vec<&Uuid> = node.owner.received_merge_proposals.keys().collect();
    peers_with_pp.sort_by_key(|u| uuid_hex(u));
    for peer_uuid in peers_with_pp {
        let entries = &node.owner.received_merge_proposals[peer_uuid];
        pp_rows.push_str(&format!(
            "<tr><td>{alias}<br><code style='font-size:.75rem;color:#888'>{uuid}</code></td>\
                 <td>{n} entr{plural}</td></tr>",
            alias  = html_escape(&alias_of(peer_uuid)),
            uuid   = uuid_hex(peer_uuid),
            n      = entries.len(),
            plural = if entries.len() == 1 { "y" } else { "ies" },
        ));
    }
    let pp_section = if pp_rows.is_empty() {
        "<div class='card'><h2 style='margin-top:0'>Buffered merge proposals</h2>\
         <p class='empty'>No inbound merge proposals buffered.</p></div>".to_string()
    } else {
        format!(
            "<div class='card'><h2 style='margin-top:0'>Buffered merge proposals</h2>\
             <p style='font-size:.85rem;color:#666;margin-top:0'>Entries received from peers and waiting to be \
                merged into the local log.</p>\
             <table><tr><th>Peer</th><th>Buffered</th></tr>{pp_rows}</table></div>"
        )
    };

    drop(node);

    let body = format!(
        "<h1>Diagnostics</h1>{local_section}{peers_section}{wm_section}{pp_section}"
    );
    layout(ctx, "Diagnostics", &body)
}

// ── App approval / rejection ──────────────────────────────────────────────────

/// Error code surfaced to the UI via `?error=` when a UI-driven mutation
/// reaches the sync v1 layer but cannot be published. The handler has
/// already rolled the local mutation back, so the UI state matches reality.
const UI_ERR_PUBLISH_FAILED: &str = "publish_failed";

/// Returns `Some(UI_ERR_*)` if the change could not be published (and the
/// local mutation was rolled back); `None` on success or for the silent
/// no-op cases (bad form, unknown id).
fn approve_app(body: &[u8], ctx: &WorkerContext) -> Option<&'static str> {
    let id_str = form_field(body, "id")?;
    let id = uuid_from_hex(id_str)?;
    let (was_approved, app_alias) = {
        let mut node    = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid)?;
        let app = device.applications.iter_mut().find(|a| a.id == id)?;
        let was_approved = app.user_approved;
        app.user_approved = true;
        (was_approved, app.alias.clone())
    };
    ctx.save_node();

    let device_uuid = ctx.node.read().unwrap().device_uuid;
    if let Err(e) = request_change(Change::AddApplication {
        device_uuid,
        app_id: id,
        app_alias,
    }, ctx) {
        // Roll back the approval — but only if we actually flipped it.
        // Re-approving an already-approved app is a no-op on Err.
        if !was_approved {
            let mut node = ctx.node.write().unwrap();
            if let Some(device) = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == device_uuid)
            {
                if let Some(app) = device.applications.iter_mut().find(|a| a.id == id) {
                    app.user_approved = false;
                }
            }
            drop(node);
            ctx.save_node();
        }
        eprintln!("[approve_app] publish failed for app {}: {e:?}", uuid_hex(&id));
        return Some(UI_ERR_PUBLISH_FAILED);
    }
    None
}

/// Admin UI alias rename. Mirrors `app_update`'s alias path but driven from the
/// admin UI (no app token). App ids are globally unique UUIDs (7c.0), so we
/// look the app up across every own-user device — any own-user SG can publish
/// a rename of any own-user app per the v2 reconciliation design. Same
/// pre-mutate + sync v1 publish + rollback-on-Err shape as `approve_app` /
/// `reject_app`.
fn rename_app(body: &[u8], ctx: &WorkerContext) -> Option<&'static str> {
    let id_str    = form_field(body, "id")?;
    let id        = uuid_from_hex(id_str)?;
    let new_alias = form_field(body, "alias").map(url_decode)?;
    if new_alias.is_empty() { return None; }

    let (device_uuid, prior_alias) = {
        let mut node = ctx.node.write().unwrap();
        let mut found = None;
        for device in node.owner.user.devices.iter_mut() {
            if let Some(app) = device.applications.iter_mut().find(|a| a.id == id) {
                if app.alias == new_alias { return None; }   // no-op
                let prior = std::mem::replace(&mut app.alias, new_alias.clone());
                found = Some((device.uuid, prior));
                break;
            }
        }
        found?
    };
    ctx.save_node();

    if let Err(e) = request_change(Change::UpdateApplicationAlias {
        device_uuid,
        app_id: id,
        new_alias,
    }, ctx) {
        {
            let mut node = ctx.node.write().unwrap();
            if let Some(dev) = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == device_uuid)
            {
                if let Some(app) = dev.applications.iter_mut().find(|a| a.id == id) {
                    app.alias = prior_alias;
                }
            }
        }
        ctx.save_node();
        eprintln!("[rename_app] publish failed for app {}: {e:?}", uuid_hex(&id));
        return Some(UI_ERR_PUBLISH_FAILED);
    }
    None
}

fn reject_app(body: &[u8], ctx: &WorkerContext) -> Option<&'static str> {
    let id_str = form_field(body, "id")?;
    let id = uuid_from_hex(id_str)?;
    let (device_uuid, removed) = {
        let mut node    = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let device = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid)?;
        let removed = device.applications.iter().position(|a| a.id == id)
            .map(|pos| device.applications.remove(pos));
        (device_uuid, removed)
    };
    let removed = removed?;       // unknown id → silent no-op
    ctx.save_node();

    if let Err(e) = request_change(Change::RemoveApplication {
        device_uuid,
        app_id: id,
    }, ctx) {
        // Roll back the removal — re-insert the cloned application.
        {
            let mut node = ctx.node.write().unwrap();
            if let Some(device) = node.owner.user.devices.iter_mut()
                .find(|d| d.uuid == device_uuid)
            {
                device.applications.push(removed);
            }
        }
        ctx.save_node();
        eprintln!("[reject_app] publish failed for app {}: {e:?}", uuid_hex(&id));
        return Some(UI_ERR_PUBLISH_FAILED);
    }
    None
}

// ── Invitation generation and bootstrap initiation ───────────────────────────

/// The local device's advertised `hosts`, embedded in codes minted here.
fn local_device_hosts(node: &super::data_models::Node) -> Vec<String> {
    let uuid = node.device_uuid;
    node.owner.user.devices.iter()
        .find(|d| d.uuid == uuid)
        .map(|d| d.hosts.clone())
        .unwrap_or_default()
}

/// The highest-ranked SG (lowest `sg_rank`) that can currently mint an outbound
/// invitation: either the local node itself (when it is an SG with hosts) or an
/// SG we hold an active connection to. Invitations are device-local and the code
/// embeds the minting SG's hosts, so the chosen SG must be reachable right now.
///
/// Iterating in rank order means even a higher-ranked *local* SG defers to a
/// lower-`sg_rank` (i.e. more preferred) SG when that peer is connected — only
/// the top-ranked online SG mints locally. If no more-preferred SG is reachable,
/// a local SG falls back to minting for itself. Returns the chosen SG's device
/// UUID, or `None` when no SG qualifies (e.g. a DG with no connected SG).
fn top_online_sg(node: &super::data_models::Node) -> Option<Uuid> {
    let local_uuid = node.device_uuid;
    let mut sgs: Vec<&Device> = node.owner.user.devices.iter()
        .filter(|d| matches!(d.grade, DeviceGrade::SG) && !d.hosts.is_empty())
        .collect();
    sgs.sort_by_key(|d| d.sg_rank.unwrap_or(u32::MAX));
    sgs.into_iter()
        .find(|d| d.uuid == local_uuid
            || node.owner.active_connections.values().any(|c| c.device_uuid == d.uuid))
        .map(|d| d.uuid)
}

/// Mint a fresh invitation and store it in the local device/contact vec
/// according to `kind`. Returns `(id, public_key)` for embedding in the code.
/// Caller is responsible for `ctx.save_node()`.
fn store_new_invitation(kind: u8, ctx: &WorkerContext) -> (Uuid, PublicKey) {
    let mut node = ctx.node.write().unwrap();
    let kp = generate_x25519_keypair();
    let pk = kp.public_key;
    let id = generate_uuid();
    let inv = Invitation {
        id,
        key_pair:   kp,
        expires_at: SystemTime::now() + Duration::from_secs(24 * 3600),
    };
    if kind == INVITE_TYPE_CONTACT {
        node.owner.contact_invitations.push(inv);
    } else {
        node.owner.device_invitations.push(inv);
    }
    (id, pk)
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

/// Generate a device invitation for the UI. See `generate_invitation`.
fn generate_device_invitation(ctx: &WorkerContext) -> Option<String> {
    generate_invitation(INVITE_TYPE_DEVICE, ctx)
}

/// Produce a shareable invitation code of `kind` (device or contact).
///
/// Invitations are device-local (never synced), so the code can only point to
/// the SG that actually stores it. The minting SG is always the top-ranked
/// online SG (`top_online_sg`). If that is the local node, it mints the
/// invitation itself and embeds its own hosts. Otherwise — whether the local
/// node is a DG or a lower-ranked SG — it asks that SG to mint and return the
/// code, guaranteeing the invitation is present on the SG the code points to
/// before the code exists.
///
/// Returns `None` on any terminal failure (no reachable SG, no hosts, or — for
/// the delegated path — the SG not replying within the timeout). Consistent
/// with the sync design rule that such failures are terminal, not retried.
fn generate_invitation(kind: u8, ctx: &WorkerContext) -> Option<String> {
    let (target, local_uuid, hosts) = {
        let node = ctx.node.read().unwrap();
        (top_online_sg(&node), node.device_uuid, local_device_hosts(&node))
    };

    let Some(target) = target else {
        eprintln!("[generate_invitation] no reachable SG to mint invitation");
        return None;
    };

    if target == local_uuid {
        // We are the top-ranked online SG: mint locally. `top_online_sg` only
        // returns the local node when it is an SG with hosts, so `hosts` is
        // non-empty here.
        let (inv_id, inv_pk) = store_new_invitation(kind, ctx);
        ctx.save_node();
        Some(encode_invitation_code(&inv_id, &inv_pk, &hosts))
    } else {
        request_invitation_from_sg(kind, target, ctx)
    }
}

/// Delegated path: ask `sg_uuid` (the top-ranked online SG) to mint an
/// invitation, block until it replies (op 0x36) or a short timeout elapses,
/// then return the encoded code. Used by DGs and by lower-ranked SGs.
///
/// The parked worker thread is woken by `generate_invitation_response` running
/// on another worker. With `WORKER_COUNT > 1` this can't self-deadlock for a
/// single request; only the pathological case of every worker parked at once
/// would stall, and the timeout breaks even that.
fn request_invitation_from_sg(kind: u8, sg_uuid: Uuid, ctx: &WorkerContext) -> Option<String> {
    let token = generate_uuid();

    // Build the 0x35 request to the chosen SG over its active connection.
    // Body: [kind:1][token:16].
    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.values()
            .find(|c| c.device_uuid == sg_uuid)
            .map(|conn| {
                let mut body = Vec::with_capacity(1 + 16);
                body.push(kind);
                body.extend_from_slice(&token);
                (build_encrypted_packet(GENERATE_INVITATION_REQUEST_OP, conn, &body), conn.peer_addr)
            })
    };
    let Some((pkt, addr)) = pkt_and_addr else {
        eprintln!("[request_invitation_from_sg] no reachable SG to mint invitation");
        return None;
    };

    // Register the rendezvous slot BEFORE sending so a fast reply can't race us.
    {
        let mut slots = ctx.pending_invites.slots.lock().unwrap();
        slots.insert(token, None);
    }
    send(ctx, addr, &pkt);

    // Park until the slot is filled (Some(_)) or the timeout fires.
    let timeout = Duration::from_secs(5);
    let outcome = {
        let slots = ctx.pending_invites.slots.lock().unwrap();
        let (mut slots, _) = ctx.pending_invites.cv
            .wait_timeout_while(slots, timeout, |s| matches!(s.get(&token), Some(None)))
            .unwrap();
        slots.remove(&token).flatten()
    };

    match outcome {
        Some(Ok(code)) => Some(code),
        Some(Err(())) => { eprintln!("[request_invitation_from_sg] SG reported mint failure"); None }
        None => { eprintln!("[request_invitation_from_sg] timed out waiting for SG reply"); None }
    }
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

/// Generate a contact invitation code for the UI. See `generate_invitation`.
fn generate_contact_invitation(ctx: &WorkerContext) -> Option<String> {
    generate_invitation(INVITE_TYPE_CONTACT, ctx)
}

/// SG side of the DG→SG invitation request (op 0x35). Mints an invitation,
/// stores it locally, and replies (op 0x36) with the encoded code embedding
/// this SG's own hosts. Request body: `[kind:1][token:16]`. Response body:
/// `[token:16][result:1][code_utf8...]`.
pub fn generate_invitation_request(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 2 {
        eprintln!("[generate_invitation_request] header too short from {src}");
        return;
    }
    let conn_id = u16::from_be_bytes([buf[0], buf[1]]);

    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[generate_invitation_request] decryption failed from {src}");
                return;
            }
        }
    };
    if plaintext.len() < 1 + 16 {
        eprintln!("[generate_invitation_request] body too short from {src}");
        return;
    }
    let kind = plaintext[0];
    let token: Uuid = plaintext[1..17].try_into().unwrap();

    // Any SG can mint: invitations are device-local, so the requesting DG's
    // code points here and this node will receive the BootstrapRequest.
    let hosts = {
        let node = ctx.node.read().unwrap();
        local_device_hosts(&node)
    };
    let (result_byte, code) = if hosts.is_empty() {
        eprintln!("[generate_invitation_request] this SG has no hosts configured — cannot mint");
        (INVITE_RESULT_ERROR, String::new())
    } else {
        let (inv_id, inv_pk) = store_new_invitation(kind, ctx);
        ctx.save_node();
        (INVITE_RESULT_OK, encode_invitation_code(&inv_id, &inv_pk, &hosts))
    };

    let mut body = Vec::with_capacity(16 + 1 + code.len());
    body.extend_from_slice(&token);
    body.push(result_byte);
    body.extend_from_slice(code.as_bytes());

    let pkt_and_addr: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();
        node.owner.active_connections.get(&conn_id)
            .map(|conn| (
                build_encrypted_packet(GENERATE_INVITATION_RESPONSE_OP, conn, &body),
                conn.peer_addr,
            ))
    };
    let Some((pkt, addr)) = pkt_and_addr else {
        eprintln!("[generate_invitation_request] no connection {conn_id} to reply from {src}");
        return;
    };
    send(ctx, addr, &pkt);
}

/// DG side of the invitation reply (op 0x36). Fills the rendezvous slot keyed
/// by the echoed token and wakes the parked `request_invitation_from_sg` thread.
pub fn generate_invitation_response(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let plaintext = {
        let node = ctx.node.read().unwrap();
        match decrypt_packet_body(&node, &buf) {
            Some(pt) => pt,
            None => {
                eprintln!("[generate_invitation_response] decryption failed from {src}");
                return;
            }
        }
    };
    if plaintext.len() < 17 {
        eprintln!("[generate_invitation_response] body too short from {src}");
        return;
    }
    let token: Uuid = plaintext[0..16].try_into().unwrap();
    let outcome: Result<String, ()> = if plaintext[16] == INVITE_RESULT_OK {
        match std::str::from_utf8(&plaintext[17..]) {
            Ok(code) => Ok(code.to_string()),
            Err(_) => {
                eprintln!("[generate_invitation_response] non-utf8 code from {src}");
                Err(())
            }
        }
    } else {
        Err(())
    };

    let mut slots = ctx.pending_invites.slots.lock().unwrap();
    if let Some(entry) = slots.get_mut(&token) {
        *entry = Some(outcome);
        ctx.pending_invites.cv.notify_all();
    } else {
        eprintln!("[generate_invitation_response] no waiter for token (late/duplicate reply) from {src}");
    }
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
    layout(ctx, "Invitations", &body)
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

fn layout(ctx: &WorkerContext, title: &str, body: &str) -> String {
    let banner = partition_banner(ctx);
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
    html.push_str("  <a href=\"/diagnostics\">Diagnostics</a>\n");
    html.push_str("</nav>\n<main>\n");
    html.push_str(&banner);
    html.push_str(body);
    html.push_str("\n</main>\n</body>\n</html>");
    html
}

/// Yellow banner shown on every admin page whenever any own-user SG peer is
/// currently marked down by poll_sg. Surfaces partition state so a user
/// looking at any tab knows convergence may be paused. Empty string when all
/// own-user SG peers (if any) are reachable.
fn partition_banner(ctx: &WorkerContext) -> String {
    let node = ctx.node.read().unwrap();
    let local_uuid = node.device_uuid;

    let own_sg_uuids: Vec<(Uuid, &str)> = node.owner.user.devices.iter()
        .filter(|d| matches!(d.grade, DeviceGrade::SG) && d.uuid != local_uuid)
        .map(|d| (d.uuid, d.alias.as_str()))
        .collect();
    if own_sg_uuids.is_empty() { return String::new(); }

    // A device is "down" iff *every* polled (uuid, host) entry for it is
    // down. An unpolled device contributes no entries — treat as up so we
    // don't falsely flag a freshly added peer before poll_sg's first round.
    let mut down: Vec<&str> = Vec::new();
    for (uuid, alias) in &own_sg_uuids {
        let polled: Vec<bool> = node.sg_statuses.iter()
            .filter(|((u, _), _)| u == uuid)
            .map(|(_, s)| s.up)
            .collect();
        if !polled.is_empty() && polled.iter().all(|up| !*up) {
            down.push(alias);
        }
    }
    if down.is_empty() { return String::new(); }

    let aliases = down.iter().map(|a| html_escape(a)).collect::<Vec<_>>().join(", ");
    format!(
        "<div class='card' style='background:#fff4d6;color:#7a5a00;border:1px solid #e0c060'>\
            <strong>Partition detected:</strong> own-user SG peer(s) currently unreachable: {aliases}. \
            Sync v2 will reconcile automatically when the peer comes back. \
            See <a href='/diagnostics'>Diagnostics</a> for watermarks and pending proposals.\
        </div>"
    )
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

            let ctx = WorkerContext { node, udp_socket: pnet_socket, writer_tx, scheduler_tx, pending_invites: Default::default() };
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
                peer_public_key: generate_key_bytes(),
                peer_active_connection_id: 10,
                device_uuid: own_sg_uuid,
                peer_addr: own_sg_sock.local_addr().unwrap(),
            });
            node.owner.active_connections.insert(2, ActiveConnection {
                id: 2,
                timeout: SystemTime::now() + Duration::from_secs(3600),
                key_pair: generate_x25519_keypair(),
                peer_public_key: generate_key_bytes(),
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
    fn add_specific_contact(t: &TestCtx, peer_dev: Uuid, peer_lt_pub: PublicKey) {
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
                peer_public_key:           generate_key_bytes(),
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
                last_seen_public_version: SyncVersion::default(),
            });
        }

        // Build a RelayPacket as if sent by the sender DG.
        // Shared secret for SG conn #1 = x25519_shared(dg_sender_sk, sg_from_dg_pk)
        //                               = x25519_shared(sg_from_dg_sk, dg_sender_pk) — same
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
                peer_public_key: generate_key_bytes(),
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
        let contact_pk    = [0x77; 32];
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
