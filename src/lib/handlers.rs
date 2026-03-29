use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

use super::action_queue::WorkerContext;
use super::data_models::{
    ActiveConnection, Application, Contact, Device, DeviceGrade, Invitation, KeyPair,
    PendingBootstrap, PendingConnection, PendingDeviceAcceptance, PublicKey,
    SgStatus, User, Uuid, CONNECTION_LIFETIME, RENEW_THRESHOLD, generate_key_bytes, generate_uuid,
};

// ── Reply status bytes ────────────────────────────────────────────────────────
const OK:                u8 = 0x00;
const ERR_BAD_PACKET:    u8 = 0x01;
const ERR_TOKEN_UNKNOWN: u8 = 0x02;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn send(ctx: &WorkerContext, dest: SocketAddr, data: &[u8]) {
    ctx.udp_socket.send_to(data, dest).ok();
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

    // Update node.
    let token = {
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
            user_approved: false,
            token,
        });
        token
        // write lock released here
    };

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
/// Authenticates the app and returns its view of the node data tree.
/// Serialization format TBD — returns a stub OK for now.
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

    let app_exists = device.applications.iter().any(|a| a.token == token);
    drop(node);

    if app_exists {
        // TODO: serialize and send the data tree
        send(ctx, src, &[OK]);
    } else {
        send_error(ctx, src, ERR_TOKEN_UNKNOWN);
    }
}

/// Op 3 — Application send packet.
///
/// Request body (after op byte):
///   [token: 16 bytes][target_device_uuid: 16 bytes][target_app_id: u16 be][payload: ...]
///
/// Looks up the active connection for the target device, encrypts the payload,
/// and forwards the packet to the peer pnet node.
/// Not yet implemented — requires ephemeral key exchange to be established first.
pub fn app_send_packet(src: SocketAddr, buf: Vec<u8>, ctx: &WorkerContext) {
    let _ = (src, buf, ctx); // TODO
}

// ── Peer pNet node handlers ───────────────────────────────────────────────────

const SG_PING_OP:          u8 = 0x10;
const SG_PONG_OP:          u8 = 0x11;
const DG_KEEPALIVE_OP:     u8 = 0x12;
const CONNECT_REQUEST_OP:  u8 = 0x20;
const CONNECT_ACK_OP:      u8 = 0x21;
const BOOTSTRAP_REQUEST_OP:  u8 = 0x30;
const BOOTSTRAP_RESPONSE_OP: u8 = 0x31;
const DEVICE_REGISTER_OP:    u8 = 0x32;

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
    // buf[82..146] = signature — TODO: verify with Ed25519

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
    let (our_conn_id, our_ephemeral_pk) = {
        let mut node = ctx.node.write().unwrap();
        let conn_id  = allocate_conn_id(&node);
        let key_pair = KeyPair { public_key: generate_key_bytes(), private_key: generate_key_bytes() };
        let pk_copy  = key_pair.public_key;
        node.owner.active_connections.insert(conn_id, ActiveConnection {
            id:                        conn_id,
            timeout:                   SystemTime::now() + CONNECTION_LIFETIME,
            key_pair,
            peer_public_key:           initiator_ephemeral_pk,
            peer_active_connection_id: initiator_conn_id,
            device_uuid:               initiator_device_uuid,
        });
        (conn_id, pk_copy)
    };

    // Reply with ConnectAck:
    //   [op=0x21][our_conn_id: u16][initiator_conn_id: u16][our_ephemeral_pk: 32][sig: 64]
    let mut pkt = [0u8; 101];
    pkt[0]       = CONNECT_ACK_OP;
    pkt[1..3].copy_from_slice(&our_conn_id.to_be_bytes());
    pkt[3..5].copy_from_slice(&initiator_conn_id.to_be_bytes());
    pkt[5..37].copy_from_slice(&our_ephemeral_pk);
    // pkt[37..101] = signature, zeros (TODO: Ed25519 signing)
    send(ctx, src, &pkt);
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
    // buf[36..100] = signature — TODO: verify with Ed25519 using pending.peer_longterm_pk

    let mut node = ctx.node.write().unwrap();
    let Some(pending) = node.owner.pending_connections.remove(&our_conn_id) else {
        eprintln!("[connect_ack] no pending connection for id {our_conn_id} from {src}");
        return;
    };

    node.owner.active_connections.insert(our_conn_id, ActiveConnection {
        id:                        our_conn_id,
        timeout:                   SystemTime::now() + CONNECTION_LIFETIME,
        key_pair:                  pending.our_key_pair,
        peer_public_key:           responder_ephemeral_pk,
        peer_active_connection_id: responder_conn_id,
        device_uuid:               pending.peer_device_uuid,
    });
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

// ── Bootstrap payload serialization ──────────────────────────────────────────
//
// Format of the bootstrap payload (user data, encrypted in BootstrapResponse):
//   [alias: u8 len + bytes]
//   [uuid: 16]
//   [long_term_pk: 32]
//   [long_term_sk: 32]
//   [device_count: u8]
//     each device: [uuid:16][alias: u8+bytes][grade:u8 (0=DG,1=SG)][ip:4][port:2 BE]
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
    buf.extend_from_slice(&d.host.ip().octets());
    buf.extend_from_slice(&d.host.port().to_be_bytes());
}

fn read_device(data: &[u8], pos: &mut usize) -> Option<Device> {
    let uuid: Uuid   = read_arr(data, pos)?;
    let alias        = read_str(data, pos)?;
    let grade_byte   = *data.get(*pos)?; *pos += 1;
    let grade        = if grade_byte == 1 { DeviceGrade::SG } else { DeviceGrade::DG };
    let ip: [u8; 4]  = read_arr(data, pos)?;
    let port_bytes: [u8; 2] = read_arr(data, pos)?;
    let port         = u16::from_be_bytes(port_bytes);
    Some(Device {
        uuid,
        alias,
        grade,
        host:         SocketAddrV4::new(Ipv4Addr::from(ip), port),
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
    let (shared_secret, invitation_id, sg_addr) = {
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
        (ss, pb.invitation_id, pb.sg_addr)
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
            eprintln!("[device_registration] new device '{}' registered from {src}", device.alias);
            node.owner.user.devices.push(device);
        }
    }
    ctx.save_node();
}

// ── Scheduled action handlers ─────────────────────────────────────────────────

const SG_PING_TIMEOUT: Duration = Duration::from_secs(1);

/// Ping every candidate SG, record RTT, and mark each one up or down.
///
/// Candidate pool: all SG-grade devices owned by the local user (excluding the
/// local device itself) plus all SG-grade devices of every contact user.
pub fn poll_sg(ctx: &WorkerContext) {
    // Collect (device_uuid, host) for every candidate SG.
    let candidates: Vec<(Uuid, SocketAddrV4)> = {
        let node = ctx.node.read().unwrap();
        let local_uuid = node.device_uuid;
        let mut v: Vec<(Uuid, SocketAddrV4)> = Vec::new();
        for d in &node.owner.user.devices {
            if matches!(d.grade, DeviceGrade::SG) && d.uuid != local_uuid {
                v.push((d.uuid, d.host));
            }
        }
        for contact in &node.owner.contact_users {
            for d in &contact.user.devices {
                if matches!(d.grade, DeviceGrade::SG) {
                    v.push((d.uuid, d.host));
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

    for (uuid, host) in candidates {
        let nonce = generate_uuid();
        let mut packet = [0u8; 17];
        packet[0] = SG_PING_OP;
        packet[1..17].copy_from_slice(&nonce);

        let start = Instant::now();
        if ping_socket.send_to(&packet, std::net::SocketAddr::V4(host)).is_err() {
            record_sg_status(ctx, uuid, None);
            continue;
        }

        let mut buf = [0u8; 32];
        let up = match ping_socket.recv_from(&mut buf) {
            Ok((len, _)) if len >= 17 && buf[0] == SG_PONG_OP && buf[1..17] == nonce => {
                Some(start.elapsed())
            }
            _ => None,
        };
        record_sg_status(ctx, uuid, up);
    }
}

fn record_sg_status(ctx: &WorkerContext, uuid: Uuid, rtt: Option<Duration>) {
    let mut node = ctx.node.write().unwrap();
    node.sg_statuses.insert(uuid, SgStatus {
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
    let (need_conn, our_longterm_pk, our_device_uuid) = {
        let node = ctx.node.read().unwrap();
        let our_device_uuid = node.device_uuid;
        let our_longterm_pk = node.owner.key_pair.public_key;

        let is_sg = node.owner.user.devices.iter()
            .find(|d| d.uuid == our_device_uuid)
            .map(|d| matches!(d.grade, DeviceGrade::SG))
            .unwrap_or(false);

        // Desired peers: own devices (all if SG, SGs-only if DG) + contact devices (same rule).
        let mut desired: Vec<(Uuid, SocketAddrV4, PublicKey)> = Vec::new();
        for d in &node.owner.user.devices {
            if d.uuid == our_device_uuid { continue; }
            if is_sg || matches!(d.grade, DeviceGrade::SG) {
                desired.push((d.uuid, d.host, our_longterm_pk));
            }
        }
        for contact in &node.owner.contact_users {
            for d in &contact.user.devices {
                if is_sg || matches!(d.grade, DeviceGrade::SG) {
                    desired.push((d.uuid, d.host, contact.public_key));
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

        (need_conn, our_longterm_pk, our_device_uuid)
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
                let key_pair = KeyPair { public_key: generate_key_bytes(), private_key: generate_key_bytes() };
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
        // pkt[83..147] = signature, zeros (TODO: Ed25519 signing)

        send(ctx, SocketAddr::V4(peer_host), &pkt);
    }
}

/// Retry an unacknowledged outbound message.
pub fn retry_message(message_id: u64, ctx: &WorkerContext) {
    let _ = (message_id, ctx); // TODO
}

/// Scheduled every 20 seconds on DG devices.
///
/// Sends a 1-byte packet (op `0x12`) to every SG with an active connection,
/// keeping the DG's NAT mapping alive so the SG can push packets back.
pub fn keepalive_dg(ctx: &WorkerContext) {
    let sg_hosts: Vec<SocketAddrV4> = {
        let node       = ctx.node.read().unwrap();
        let local_uuid = node.device_uuid;

        // Only DGs need to send keepalives.
        let is_dg = node.owner.user.devices.iter()
            .find(|d| d.uuid == local_uuid)
            .map(|d| matches!(d.grade, DeviceGrade::DG))
            .unwrap_or(false);
        if !is_dg { return; }

        // UUIDs of devices we currently have an active connection with.
        let connected: HashSet<Uuid> = node.owner.active_connections.values()
            .map(|c| c.device_uuid)
            .collect();

        // Collect the host address of every connected SG (own + contacts').
        let mut hosts = Vec::new();
        for d in &node.owner.user.devices {
            if matches!(d.grade, DeviceGrade::SG) && connected.contains(&d.uuid) {
                hosts.push(d.host);
            }
        }
        for contact in &node.owner.contact_users {
            for d in &contact.user.devices {
                if matches!(d.grade, DeviceGrade::SG) && connected.contains(&d.uuid) {
                    hosts.push(d.host);
                }
            }
        }
        hosts
    };

    for host in sg_hosts {
        send(ctx, SocketAddr::V4(host), &[DG_KEEPALIVE_OP]);
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
    match (method.as_str(), path.as_str()) {
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
        ("GET",  "/contacts")      => respond_html(&stream, 200, &render_contacts(ctx)),
        ("GET",  "/devices")       => respond_html(&stream, 200, &render_devices(ctx)),
        ("GET",  "/invitations")   => respond_html(&stream, 200, &render_invitations(ctx, &query)),
        ("POST", "/invitations/device") => {
            let code = generate_device_invitation(ctx).unwrap_or_default();
            respond_redirect(&stream, &format!("/invitations?code={code}"));
        }
        ("POST", "/invitations/enter") => {
            initiate_bootstrap(&body, ctx);
            respond_redirect(&stream, "/invitations");
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
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    html_escape(&a.alias),
                    html_escape(&a.protocol),
                    html_escape(&a.host.to_string()),
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
               <tr><th>Alias</th><th>Protocol</th><th>Host</th></tr>\
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
        .map(|c| format!(
            "<tr><td>{}</td><td>{}</td></tr>",
            html_escape(&c.user.alias),
            c.user.devices.len(),
        ))
        .collect();

    let body = if rows.is_empty() {
        "<h1>Contacts</h1><p class='empty'>No contacts yet.</p>".to_string()
    } else {
        format!(
            "<h1>Contacts</h1>\
             <table>\
               <tr><th>Alias</th><th>Devices</th></tr>\
               {rows}\
             </table>"
        )
    };
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
                html_escape(&d.host.to_string()),
                d.applications.len(),
            )
        })
        .collect();

    let body = if rows.is_empty() {
        "<h1>Devices</h1><p class='empty'>No devices.</p>".to_string()
    } else {
        format!(
            "<h1>Devices</h1>\
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
    {
        let mut node    = ctx.node.write().unwrap();
        let device_uuid = node.device_uuid;
        let Some(device) = node.owner.user.devices.iter_mut().find(|d| d.uuid == device_uuid) else { return };
        if let Some(app) = device.applications.iter_mut().find(|a| a.id == id) {
            app.user_approved = true;
        }
    }
    ctx.save_node();
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
}

// ── Invitation generation and bootstrap initiation ───────────────────────────

/// Generate a device invitation on the UI.  Picks the best SG (self if SG, else
/// lowest-RTT up SG), creates an invitation, and returns the base64-encoded code.
fn generate_device_invitation(ctx: &WorkerContext) -> Option<String> {
    use base64::Engine;

    let sg_host: SocketAddrV4 = {
        let node = ctx.node.read().unwrap();
        let local_uuid   = node.device_uuid;
        let local_device = node.owner.user.devices.iter().find(|d| d.uuid == local_uuid)?;

        if matches!(local_device.grade, DeviceGrade::SG) {
            local_device.host
        } else {
            // Find the lowest-RTT up SG among own devices.
            let mut best: Option<(Duration, SocketAddrV4)> = None;
            for d in &node.owner.user.devices {
                if !matches!(d.grade, DeviceGrade::SG) { continue; }
                if let Some(s) = node.sg_statuses.get(&d.uuid) {
                    if s.up {
                        let rtt = s.last_rtt.unwrap_or(Duration::MAX);
                        if best.map_or(true, |(br, _)| rtt < br) {
                            best = Some((rtt, d.host));
                        }
                    }
                }
            }
            best.map(|(_, h)| h)?
        }
    };

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

    // Encode: invitation_id (16) || invitation_pk (32) || sg_host ip (4) || port (2) = 54 bytes
    let mut raw = [0u8; 54];
    raw[0..16].copy_from_slice(&inv_id);
    raw[16..48].copy_from_slice(&inv_pk);
    raw[48..52].copy_from_slice(&sg_host.ip().octets());
    raw[52..54].copy_from_slice(&sg_host.port().to_be_bytes());
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

/// Parse an invitation code entered via the UI and send a BootstrapRequest to the SG.
fn initiate_bootstrap(body: &[u8], ctx: &WorkerContext) {
    use base64::Engine;

    let Some(code_str) = form_field(body, "code") else { return };
    let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(code_str.trim()) else {
        eprintln!("[initiate_bootstrap] invalid base64");
        return;
    };
    if raw.len() != 54 {
        eprintln!("[initiate_bootstrap] wrong code length ({})", raw.len());
        return;
    }

    let invitation_id: Uuid      = raw[0..16].try_into().unwrap();
    let invitation_pk: PublicKey = raw[16..48].try_into().unwrap();
    let ip_bytes: [u8; 4]        = raw[48..52].try_into().unwrap();
    let port = u16::from_be_bytes([raw[52], raw[53]]);
    let sg_addr = SocketAddrV4::new(Ipv4Addr::from(ip_bytes), port);

    // Generate our ephemeral key pair and store PendingBootstrap.
    let ephem_kp = generate_x25519_keypair();
    let ephem_pk = ephem_kp.public_key;
    {
        let mut node = ctx.node.write().unwrap();
        node.owner.pending_bootstrap = Some(PendingBootstrap {
            invitation_id,
            our_ephem_key_pair: ephem_kp,
            invitation_pk,
            sg_addr,
        });
    }

    // Send BootstrapRequest: [op=0x30][invitation_id:16][our_ephem_pk:32]
    let mut pkt = [0u8; 49];
    pkt[0]      = BOOTSTRAP_REQUEST_OP;
    pkt[1..17].copy_from_slice(&invitation_id);
    pkt[17..49].copy_from_slice(&ephem_pk);
    send(ctx, SocketAddr::V4(sg_addr), &pkt);
}

fn render_invitations(ctx: &WorkerContext, query: &str) -> String {
    let node = ctx.node.read().unwrap();

    // Show a generated code if one was passed back via the redirect query string.
    let code_param = query.split('&')
        .find_map(|p| p.strip_prefix("code="))
        .unwrap_or("");

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

    let inv_rows: String = node.owner.device_invitations.iter()
        .map(|inv| {
            let id_hex: String = inv.id.iter().map(|b| format!("{b:02x}")).collect();
            format!("<tr><td style='font-family:monospace'>{}</td></tr>", &id_hex[..16])
        })
        .collect();

    let inv_table = if inv_rows.is_empty() {
        "<p class='empty'>No pending device invitations.</p>".to_string()
    } else {
        format!("<table><tr><th>Invitation ID (first 8 bytes)</th></tr>{inv_rows}</table>")
    };

    drop(node);

    let body = format!(
        "<h1>Invitations</h1>\
         {code_section}\
         <div class='card'>\
           <h2 style='margin-top:0;font-size:1rem'>Add a Device</h2>\
           <p style='color:#666;font-size:.9rem;margin-top:0'>Generate a one-time code, then enter it on the new device.</p>\
           {inv_table}\
           <form method='post' action='/invitations/device' style='margin-top:1rem'>\
             <button type='submit'>Generate Device Invitation</button>\
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
            let mut buf = [0u8; 64];
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
    fn app_get_data_valid_token_returns_ok() {
        let t = TestCtx::new();
        let token = register_and_get_token(&t, "myapp", 9001);

        app_get_data(t.app_addr(), token.to_vec(), &t.ctx);
        let reply = t.recv_reply();
        assert_eq!(reply[0], OK);
    }

    #[test]
    fn app_get_data_unknown_token_returns_error() {
        let t = TestCtx::new();
        app_get_data(t.app_addr(), vec![0xFFu8; 16], &t.ctx);

        let reply = t.recv_reply();
        assert_eq!(reply[0], 0x01);
        assert_eq!(reply[1], ERR_TOKEN_UNKNOWN);
    }
}
