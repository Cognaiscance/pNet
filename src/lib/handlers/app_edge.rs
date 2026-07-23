//! Local app edge: register / update / get-data / send, and inbound app packet push.
//!
//! These are the UDP control/data APIs apps use against a running node. Peer
//! fabric routing helpers and sync publish stay in the parent `handlers` module.

use std::net::{SocketAddr, SocketAddrV4};
use std::time::SystemTime;

use super::super::action_queue::WorkerContext;
use super::super::crypto::{
    aead_domain, aead_key_from_dh, build_encrypted_packet, decrypt_packet_body, xchacha20_encrypt,
};
use super::super::data_models::{Application, Uuid, generate_uuid};
use super::super::wire::*;
use super::{
    best_sg_connection, ipv4_from, local_approved_app_host, push_device, request_change, send,
    send_error, sg_candidates_for_dest, top_ranked_sg_for_device, Change,
};


/// Op 0 — Application registration.
///
/// Request body (after op byte):
///   [alias_len: u8][alias: alias_len bytes][port: u16 be]
///   [protocol_len: u8][protocol: protocol_len bytes]
///
/// Reply on success:  [OK][token: 16 bytes]
/// Reply on error:    [STATUS_ERR][error_code] — see `wire` ERR_* constants
pub fn app_register(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if !ctx
        .app_rate_limits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .allow_register(src)
    {
        eprintln!("[app_register] rate limited from {src}");
        return send_error(ctx, src, ERR_RATE_LIMITED);
    }

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
/// Reply on success:  [OK]
/// Reply on error:    [STATUS_ERR][error_code] — see `wire` ERR_* constants
pub fn app_update(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    // Parse header.
    if buf.len() < 17 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let Some(token) = slice_arr::<16>(&buf, 0) else {
        return send_error(ctx, src, ERR_BAD_PACKET);
    };
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
/// # Secrecy invariants
///
/// - The requesting app receives **its own** token only (echo of the auth
///   token). Other apps' tokens are never included.
/// - No identity private keys, X25519 private keys, or contact long-term
///   public keys appear in this reply (directory is identity-free for apps).
/// - Contact devices list **user-approved** apps only (`id` + `alias`); no
///   host/port/token for foreign apps.
///
/// Response format:
///   [OK: 1]
///   -- Requesting app's own data (full Application struct) --
///   [app_id: 16][app_alias: u8+bytes][app_host_ip: 4][app_host_port: 2 BE]
///   [app_user_approved: u8][app_token: 16][device_uuid: 16]
///   -- Owner data tree (no crypto keys) --
///   [owner_alias: u8+bytes][owner_uuid: 16]
///   [device_count: u8]
///     each device:
///       [uuid: 16][alias: u8+bytes][grade: u8][sg_rank: u8]
///       [host_count: u8][each host: u8+bytes]
///       [app_count: u8]
///         each app: [id: 16][alias: u8+bytes][ip: 4][port: 2 BE][user_approved: u8]
///                   (no token)
///   [contact_count: u8]
///     each contact:
///       [alias: u8+bytes][uuid: 16]
///       [device_count: u8]
///         each device:
///           [uuid: 16][alias: u8+bytes][grade: u8][sg_rank: u8]
///           [host_count: u8][each host: u8+bytes]
///           [app_count: u8]
///             each approved app: [id: 16][alias: u8+bytes]
pub fn app_get_data(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    if buf.len() < 16 {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }
    let Some(token) = slice_arr::<16>(&buf, 0) else {
        return send_error(ctx, src, ERR_BAD_PACKET);
    };

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
///   [token: 16][dest_device_uuid: 16][dest_app_id: 16][payload: rest]
///
/// Looks up the sending app by token (must be approved), then delivers via
/// DG↔DG tunnel if one is active, a direct `AppPacket` if this node already
/// has a session to the dest device, or a `RelayPacket` (op 0x40) through the
/// best reachable SG for that destination.
///
/// # Replies
///
/// - **Success:** no reply (fire-and-forget; acceptance ≠ end-to-end delivery).
/// - **Error:** `[STATUS_ERR=0x01][error_code]` with one of:
///   - `ERR_BAD_PACKET` (0x01) — body shorter than 48 bytes
///   - `ERR_TOKEN_UNKNOWN` (0x02) — token not registered on this device
///   - `ERR_NOT_APPROVED` (0x04) — token valid but app not user-approved
///   - `ERR_NO_ROUTE` (0x05) — no session to dest and no reachable SG to relay
///   - `ERR_PAYLOAD_TOO_LARGE` (0x06) — payload longer than `MAX_APP_PAYLOAD`
///   - `ERR_RATE_LIMITED` (0x07) — per-IP / per-token send rate exceeded
pub fn app_send_packet(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    const MIN_LEN: usize = 16 + 16 + 16;
    if buf.len() < MIN_LEN {
        return send_error(ctx, src, ERR_BAD_PACKET);
    }

    let Some(token) = slice_arr::<16>(&buf, 0) else {
        return send_error(ctx, src, ERR_BAD_PACKET);
    };
    let Some(dest_device_uuid) = slice_arr::<16>(&buf, 16) else {
        return send_error(ctx, src, ERR_BAD_PACKET);
    };
    let Some(dest_app_id) = slice_arr::<16>(&buf, 32) else {
        return send_error(ctx, src, ERR_BAD_PACKET);
    };
    let payload = &buf[48..];

    if !ctx
        .app_rate_limits
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .allow_send(src, Some(token))
    {
        eprintln!("[app_send_packet] rate limited from {src}");
        return send_error(ctx, src, ERR_RATE_LIMITED);
    }

    if payload.len() > MAX_APP_PAYLOAD {
        return send_error(ctx, src, ERR_PAYLOAD_TOO_LARGE);
    }

    // Build packet and look up the SG address under a single read lock.
    let out: Option<(Vec<u8>, SocketAddr)> = {
        let node = ctx.node.read().unwrap();

        // Find the sending app by token; distinguish unknown vs not approved.
        let device_uuid = node.device_uuid;
        let Some(local_device) = node.owner.user.devices.iter()
            .find(|d| d.uuid == device_uuid)
        else {
            return send_error(ctx, src, ERR_TOKEN_UNKNOWN);
        };
        let Some(sender_app) = local_device.applications.iter()
            .find(|a| a.token == token)
        else {
            return send_error(ctx, src, ERR_TOKEN_UNKNOWN);
        };
        if !sender_app.user_approved {
            return send_error(ctx, src, ERR_NOT_APPROVED);
        }
        let sender_app_id = sender_app.id;

        // ── Tunnel path (optional) ────────────────────────────────────────────
        // Prefer an active DG↔DG tunnel when present. If the tunnel session is
        // gone, incomplete, or no SG can carry TUNNEL_FORWARD, fall through to
        // direct/relay so teardown never black-holes delivery (§6.4).
        let tunnel_info: Option<(u16, u16)> = node
            .owner
            .dg_tunnel_map
            .iter()
            .find(|(_tid, conn_id)| {
                node.owner
                    .active_connections
                    .get(*conn_id)
                    .map(|c| c.device_uuid == dest_device_uuid)
                    .unwrap_or(false)
            })
            .map(|(tid, cid)| (*tid, *cid));

        let tunnel_pkt: Option<(Vec<u8>, SocketAddr)> =
            if let Some((tunnel_id, dg_dg_conn_id)) = tunnel_info {
                (|| {
                    let dg_dg_conn = node.owner.active_connections.get(&dg_dg_conn_id)?;
                    let aead_key = aead_key_from_dh(
                        &dg_dg_conn.key_pair.private_key,
                        &dg_dg_conn.peer_public_key,
                        aead_domain::TUNNEL,
                    );
                    let mut plaintext = Vec::with_capacity(32 + payload.len());
                    plaintext.extend_from_slice(&dest_app_id);
                    plaintext.extend_from_slice(&sender_app_id);
                    plaintext.extend_from_slice(payload);
                    let (ciphertext, nonce) = xchacha20_encrypt(&aead_key, &plaintext);
                    let sg_conn = top_ranked_sg_for_device(&node, &dest_device_uuid).or_else(|| {
                        let candidates = sg_candidates_for_dest(&node, &dest_device_uuid);
                        best_sg_connection(&node, &candidates)
                    })?;
                    let sender_sg_conn_id = sg_conn.peer_active_connection_id;
                    let mut pkt = Vec::with_capacity(4 + 24 + ciphertext.len());
                    pkt.push(TUNNEL_FORWARD_OP);
                    pkt.extend_from_slice(&sender_sg_conn_id.to_be_bytes());
                    pkt.extend_from_slice(&tunnel_id.to_be_bytes());
                    pkt.extend_from_slice(&nonce);
                    pkt.extend_from_slice(&ciphertext);
                    Some((pkt, sg_conn.peer_addr))
                })()
            } else {
                None
            };

        let now = SystemTime::now();
        if let Some(out) = tunnel_pkt {
            Some(out)
        } else if let Some(dest_conn) = node.owner.active_connections.values().find(|c| {
            // Never AppPacket on a tunnel leg (session AEAD domain ≠ tunnel).
            // Skip expired sessions (cleanup may leave the conn until renew).
            c.device_uuid == dest_device_uuid
                && c.timeout > now
                && !node.owner.dg_tunnel_map.values().any(|cid| *cid == c.id)
        }) {
            // ── Direct path (session to dest that is not the tunnel leg) ─────
            let mut app_body = Vec::with_capacity(32 + payload.len());
            app_body.extend_from_slice(&dest_app_id);
            app_body.extend_from_slice(&sender_app_id);
            app_body.extend_from_slice(payload);
            let pkt = build_encrypted_packet(APP_PACKET_OP, dest_conn, &app_body);
            Some((pkt, dest_conn.peer_addr))
        } else {
            // ── Standard relay path (also the fallback after tunnel teardown) ─
            let sg_conn = top_ranked_sg_for_device(&node, &dest_device_uuid).or_else(|| {
                let candidates = sg_candidates_for_dest(&node, &dest_device_uuid);
                best_sg_connection(&node, &candidates)
            });
            let Some(sg_conn) = sg_conn else {
                eprintln!("[app_send_packet] no reachable SG for dest {:?}", dest_device_uuid);
                return send_error(ctx, src, ERR_NO_ROUTE);
            };
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

/// Op 0x41 — App packet (SG → destination node).
///
/// The destination node decrypts the body, finds the local app by dest_app_id,
/// and pushes the payload to the app via UDP.
///
/// Encrypted body: [dest_app_id: 16][sender_app_id: 16][payload]
/// Push to app:    [0x04][sender_app_id: 16][payload]
///
/// `payload` must be ≤ [`MAX_APP_PAYLOAD`]; oversized packets are dropped.
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
        let Some(dest_app_id) = slice_arr::<16>(&plaintext, 0) else { return; };
        let Some(sender_app_id) = slice_arr::<16>(&plaintext, 16) else { return; };
        let payload             = &plaintext[32..];
        if payload.len() > MAX_APP_PAYLOAD {
            eprintln!(
                "[app_packet] app payload too large ({} > {MAX_APP_PAYLOAD}) from {src}",
                payload.len()
            );
            return;
        }

        // Unapproved apps must never receive pushes.
        let Some(app_host) = local_approved_app_host(&node, dest_app_id) else {
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
