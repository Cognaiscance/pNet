//! Bootstrap, device registration, contact exchange, and invitation minting.
//!
//! Device join (0x30–0x32), contact card exchange (0x33–0x34), and invitation
//! codes (0x35–0x36 + UI mint/redeem helpers). Cross-user contact *directory*
//! sync blobs stay in the parent module with sync.

use std::net::{SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime};

use super::super::action_queue::{Action, ScheduleRequest, WorkerContext};
use super::super::crypto::{
    aead_domain, aead_key_from_dh, build_encrypted_packet, decrypt_packet_body,
    generate_x25519_keypair, xchacha20_decrypt, xchacha20_encrypt,
};
use super::super::data_models::{
    Contact, Device, DeviceGrade, Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey,
    Invitation, Node, PendingBootstrap, PendingContactExchange, PendingDeviceAcceptance,
    SyncVersion, User, Uuid, X25519PublicKey,
    generate_uuid,
};
use super::super::wire::*;
use super::{
    cross_user_pull_for_contact, devices_to_cards, fabric_event, form_field, parse_pnet_hosts,
    push_device, read_device, request_change, request_change_idempotent, resolve_hosts, send,
    url_decode, uuid_hex, Change, WriteError,
};

/// How long the SG keeps a PendingDeviceAcceptance waiting for DeviceRegistration.
const PENDING_ACCEPTANCE_TTL: Duration = Duration::from_secs(5 * 60);

fn serialize_bootstrap_payload(node: &Node) -> Vec<u8> {
    let mut buf = Vec::new();
    let owner = &node.owner;
    let user  = &owner.user;
    push_str(&mut buf, &user.alias);
    buf.extend_from_slice(&user.uuid);
    buf.extend_from_slice(owner.key_pair.public_key.as_bytes());
    buf.extend_from_slice(owner.key_pair.private_key.as_bytes());
    buf.push(user.devices.len() as u8);
    for d in &user.devices { push_device(&mut buf, d); }
    buf.push(owner.contact_users.len() as u8);
    for c in &owner.contact_users {
        buf.extend_from_slice(&c.user.uuid);
        push_str(&mut buf, &c.user.alias);
        buf.extend_from_slice(c.public_key.as_bytes());
        buf.push(c.user.devices.len() as u8);
        for d in &c.user.devices { push_device(&mut buf, d); }
    }
    buf
}

struct BootstrapPayload {
    user_alias: String,
    user_uuid:  Uuid,
    key_pair:   Ed25519KeyPair,
    devices:    Vec<Device>,
    contacts:   Vec<Contact>,
}

fn deserialize_bootstrap_payload(data: &[u8]) -> Option<BootstrapPayload> {
    let mut pos = 0usize;
    let user_alias  = read_str(data, &mut pos)?;
    let user_uuid:  Uuid      = read_arr(data, &mut pos)?;
    let pk: [u8; 32] = read_arr(data, &mut pos)?;
    let sk: [u8; 32] = read_arr(data, &mut pos)?;
    let key_pair = Ed25519KeyPair {
        public_key:  Ed25519PublicKey(pk),
        private_key: Ed25519SecretKey(sk),
    };
    let device_count = *data.get(pos)? as usize; pos += 1;
    let mut devices = Vec::new();
    for _ in 0..device_count { devices.push(read_device(data, &mut pos)?); }
    let contact_count = *data.get(pos)? as usize; pos += 1;
    let mut contacts = Vec::new();
    for _ in 0..contact_count {
        let c_uuid: Uuid = read_arr(data, &mut pos)?;
        let c_alias = read_str(data, &mut pos)?;
        let c_pk = Ed25519PublicKey(read_arr(data, &mut pos)?);
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
    let new_dev_ephem_pk = X25519PublicKey(buf[16..48].try_into().unwrap());

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

        let inv: Invitation = node.owner.device_invitations.remove(pos);
        // AEAD key (HKDF bootstrap domain over X25519), not the raw DH output.
        let shared_secret: [u8; 32] = aead_key_from_dh(
            &inv.key_pair.private_key,
            &new_dev_ephem_pk,
            aead_domain::BOOTSTRAP,
        );
        let payload: Vec<u8> = serialize_bootstrap_payload(&node);

        // Remember the AEAD key so we can decrypt the incoming DeviceRegistration.
        node.owner.pending_device_acceptances.insert(invitation_id, PendingDeviceAcceptance {
            shared_secret,
            expires_at: now + PENDING_ACCEPTANCE_TTL,
        });

        (shared_secret, payload)
        // write lock released here
    };

    fabric_event(
        "invite_consumed",
        &[
            ("kind", "device"),
            ("invitation_id", &uuid_hex(&invitation_id)),
            ("addr", &src.to_string()),
        ],
    );
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
        let ss = aead_key_from_dh(
            &pb.our_ephem_key_pair.private_key,
            &pb.invitation_pk,
            aead_domain::BOOTSTRAP,
        );
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
    ctx.scheduler_tx.send(ScheduleRequest {
        action: Action::MaintainConnections,
        delay:  Duration::from_millis(500),
    }).ok();
}

/// Op 0x32 — Device registration (new device → SG).
///
/// Payload (after op byte):
///   [invitation_id: 16][nonce: 24][encrypted device info]
///
/// The SG decrypts using the bootstrap AEAD key it stored for this invitation,
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

pub(crate) fn serialize_contact_payload(node: &Node) -> Vec<u8> {
    let mut buf = Vec::new();
    let user = &node.owner.user;
    push_str(&mut buf, &user.alias);
    buf.extend_from_slice(&user.uuid);
    buf.extend_from_slice(node.owner.key_pair.public_key.as_bytes());
    buf.push(user.devices.len() as u8);
    for d in &user.devices { push_device(&mut buf, d); }
    buf
}

struct ContactPayload {
    alias:      String,
    uuid:       Uuid,
    public_key: Ed25519PublicKey,
    devices:    Vec<Device>,
}

fn deserialize_contact_payload(data: &[u8]) -> Option<ContactPayload> {
    let mut pos = 0usize;
    let alias       = read_str(data, &mut pos)?;
    let uuid: Uuid  = read_arr(data, &mut pos)?;
    let pk = Ed25519PublicKey(read_arr(data, &mut pos)?);
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
    let requester_ephem_pk = X25519PublicKey(buf[16..48].try_into().unwrap());
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
        let shared_secret: [u8; 32] = aead_key_from_dh(
            &inv.key_pair.private_key,
            &requester_ephem_pk,
            aead_domain::BOOTSTRAP,
        );

        let Some(plaintext) = xchacha20_decrypt(&shared_secret, &nonce, ciphertext) else {
            eprintln!("[contact_request] decryption failed from {src}");
            return;
        };
        let Some(data) = deserialize_contact_payload(&plaintext) else {
            eprintln!("[contact_request] deserialization failed from {src}");
            return;
        };

        fabric_event(
            "invite_consumed",
            &[
                ("kind", "contact"),
                ("invitation_id", &uuid_hex(&invitation_id)),
                ("contact", &data.alias),
                ("addr", &src.to_string()),
            ],
        );

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
    ctx.scheduler_tx.send(ScheduleRequest {
        action: Action::MaintainConnections,
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
        aead_key_from_dh(
            &pce.our_ephem_key_pair.private_key,
            &pce.invitation_pk,
            aead_domain::BOOTSTRAP,
        )
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
    ctx.scheduler_tx.send(ScheduleRequest {
        action: Action::MaintainConnections,
        delay:  Duration::ZERO,
    }).ok();
}


// ── Invitation generation and bootstrap initiation ───────────────────────────

/// The local device's advertised `hosts`, embedded in codes minted here.
fn local_device_hosts(node: &Node) -> Vec<String> {
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
pub(crate) fn top_online_sg(node: &Node) -> Option<Uuid> {
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
fn store_new_invitation(kind: u8, ctx: &WorkerContext) -> (Uuid, X25519PublicKey) {
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
pub(crate) fn encode_invitation_code(inv_id: &Uuid, inv_pk: &X25519PublicKey, hosts: &[String]) -> String {
    use base64::Engine;
    let host_count = hosts.len().min(u8::MAX as usize);
    let mut raw = Vec::with_capacity(16 + 32 + 1 + host_count * 32);
    raw.extend_from_slice(inv_id);
    raw.extend_from_slice(inv_pk.as_bytes());
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
pub(crate) fn decode_invitation_code(code_str: &str) -> Option<(Uuid, X25519PublicKey, Vec<String>)> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(code_str.trim()).ok()?;
    if raw.len() < 49 { return None; }
    let inv_id:    Uuid      = raw[0..16].try_into().ok()?;
    let inv_pk = X25519PublicKey(raw[16..48].try_into().ok()?);
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

/// Outcome of starting an invitation mint on a worker (no long wait).
///
/// Local mint returns [`InvitationMint::Ready`] immediately. Delegated mint
/// sends 0x35 and returns [`InvitationMint::Pending`]; the admin UI must call
/// [`super::super::action_queue::PendingInvites::wait_result`] on an **off-pool**
/// thread so a worker is not pinned for the RTT (§5.2).
#[derive(Debug)]
pub(crate) enum InvitationMint {
    /// Encoded code available now (this node is the top online SG).
    Ready(String),
    /// 0x35 sent; wait for op 0x36 on `token` outside the worker pool.
    Pending { token: Uuid },
    /// No reachable SG / no connection / other terminal failure before wait.
    Failed,
}

/// Generate a device invitation for the UI. See `generate_invitation`.
pub(crate) fn generate_device_invitation(ctx: &WorkerContext) -> InvitationMint {
    generate_invitation(INVITE_TYPE_DEVICE, ctx)
}

/// Produce a shareable invitation code of `kind` (device or contact).
///
/// Invitations are device-local (never synced), so the code can only point to
/// the SG that actually stores it. The minting SG is always the top-ranked
/// online SG (`top_online_sg`). If that is the local node, it mints the
/// invitation itself and embeds its own hosts. Otherwise — whether the local
/// node is a DG or a lower-ranked SG — it asks that SG to mint and returns
/// [`InvitationMint::Pending`] so the caller can wait **off the pool**.
fn generate_invitation(kind: u8, ctx: &WorkerContext) -> InvitationMint {
    let (target, local_uuid, hosts) = {
        let node = ctx.node.read().unwrap();
        (top_online_sg(&node), node.device_uuid, local_device_hosts(&node))
    };

    let Some(target) = target else {
        eprintln!("[generate_invitation] no reachable SG to mint invitation");
        return InvitationMint::Failed;
    };

    if target == local_uuid {
        // We are the top-ranked online SG: mint locally. `top_online_sg` only
        // returns the local node when it is an SG with hosts, so `hosts` is
        // non-empty here.
        let (inv_id, inv_pk) = store_new_invitation(kind, ctx);
        ctx.save_node();
        InvitationMint::Ready(encode_invitation_code(&inv_id, &inv_pk, &hosts))
    } else {
        start_invitation_from_sg(kind, target, ctx)
    }
}

/// Delegated path (worker-side, non-blocking): ask `sg_uuid` to mint, register
/// a rendezvous token, send op 0x35, return immediately with that token.
///
/// The admin UI waits via [`PendingInvites::wait_result`] on a dedicated
/// thread (not a pool worker). `generate_invitation_response` fills the slot.
fn start_invitation_from_sg(kind: u8, sg_uuid: Uuid, ctx: &WorkerContext) -> InvitationMint {
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
        eprintln!("[start_invitation_from_sg] no reachable SG to mint invitation");
        return InvitationMint::Failed;
    };

    // Register the rendezvous slot BEFORE sending so a fast reply can't race us.
    {
        let mut slots = ctx.pending_invites.slots.lock().unwrap();
        slots.insert(token, None);
    }
    send(ctx, addr, &pkt);
    InvitationMint::Pending { token }
}

/// Parse an invitation code entered via the UI and send a BootstrapRequest to the SG.
pub(crate) fn initiate_bootstrap(body: &[u8], ctx: &WorkerContext) {
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

    let Some((picked_host, sg_addr)) = ({
        let mut cache = ctx.dns_cache.lock().unwrap();
        resolve_hosts(&mut cache, &hosts).into_iter().next()
    }) else {
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
    pkt[17..49].copy_from_slice(ephem_pk.as_bytes());
    println!("[start_bootstrap] sending bootstrap request to {sg_addr} (picked {picked_host} from {hosts:?})");
    send(ctx, SocketAddr::V4(sg_addr), &pkt);
    Ok(())
}

/// Generate a contact invitation code for the UI. See `generate_invitation`.
pub(crate) fn generate_contact_invitation(ctx: &WorkerContext) -> InvitationMint {
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
/// by the echoed token and wakes any off-pool waiter on [`PendingInvites`].
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
pub(crate) fn initiate_contact_exchange(body: &[u8], ctx: &WorkerContext) {
    let Some(code_str) = form_field(body, "code") else { return };
    let Some((invitation_id, invitation_pk, hosts)) = decode_invitation_code(code_str) else {
        eprintln!("[initiate_contact_exchange] invalid invitation code");
        return;
    };

    let Some((picked_host, sg_addr)) = ({
        let mut cache = ctx.dns_cache.lock().unwrap();
        resolve_hosts(&mut cache, &hosts).into_iter().next()
    }) else {
        eprintln!("[initiate_contact_exchange] no host in invitation code resolved: {hosts:?}");
        return;
    };
    println!("[initiate_contact_exchange] sending contact request to {sg_addr} (picked {picked_host} from {hosts:?})");

    let ephem_kp = generate_x25519_keypair();
    let ephem_pk = ephem_kp.public_key;
    let aead_key = aead_key_from_dh(
        &ephem_kp.private_key,
        &invitation_pk,
        aead_domain::BOOTSTRAP,
    );

    // Serialize and encrypt our contact card.
    let payload = {
        let node = ctx.node.read().unwrap();
        serialize_contact_payload(&node)
    };
    let (ciphertext, nonce) = xchacha20_encrypt(&aead_key, &payload);

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
    pkt.extend_from_slice(ephem_pk.as_bytes());
    pkt.extend_from_slice(&nonce);
    pkt.extend_from_slice(&ciphertext);
    send(ctx, SocketAddr::V4(sg_addr), &pkt);
}

