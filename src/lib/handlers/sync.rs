//! Sync: writer changes, pull, cross-user public sync, watermarks, merge.
//!
//! Ops 0x70–0x7B plus the pure merge engine. App edge / bootstrap call
//! `request_change`; sessions call `sync_pull` and reconnect pull helpers.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::super::action_queue::WorkerContext;
use super::super::crypto::{build_encrypted_packet, decrypt_packet_body};
use super::super::data_models::{
    AppGrant, AppInvitation, Application, Settlement, Contact, Device, DeviceGrade,
    Ed25519KeyPair, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, Charge, Node, Owner,
    PaymentReserve, PendingAccept, Purse, RunLimit,
    Scope, SyncVersion, User, Uuid, WriteLogEntry, X25519PublicKey, WRITE_LOG_RETENTION,
    unix_time_ms, utc_month_period, RESERVE_TTL_MS,
};
use super::super::payment::{
    body_from_line, body_from_pending, claim_exceeds_run, settlement_ok, decode_accept_at,
    decode_settlement_at, decode_confirm_at, encode_accept, encode_settlement, encode_confirm,
    line_covers, line_from, line_same_payment, offer_body_ok, pending_covers, pending_from,
};
use super::super::wire::*;
use super::{
    fabric_event, find_pull_source, find_writer_sg, find_writer_sg_probing, push_device, read_device,
    send, uuid_hex, WriterTarget,
};

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
//         each approved app: [id:16][alias lp][signing_pk:32][cert_sig:64]
//                            [issued_at:u64 le][cert_alias lp]

/// Public app identity carried in directory snapshots and contact cards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactAppCard {
    pub id: Uuid,
    pub alias: String,
    pub signing_pk: Ed25519PublicKey,
    pub cert_sig: Ed25519Signature,
    pub cert_issued_at: u64,
    pub cert_alias: String,
}

fn push_public_app(buf: &mut Vec<u8>, app: &ContactAppCard) {
    buf.extend_from_slice(&app.id);
    push_str(buf, &app.alias);
    buf.extend_from_slice(app.signing_pk.as_bytes());
    buf.extend_from_slice(&app.cert_sig.0);
    buf.extend_from_slice(&app.cert_issued_at.to_le_bytes());
    push_str(buf, &app.cert_alias);
}

fn push_public_app_from(buf: &mut Vec<u8>, app: &Application) {
    push_public_app(buf, &ContactAppCard {
        id: app.id,
        alias: app.alias.clone(),
        signing_pk: app.identity.public_key,
        cert_sig: app.cert_sig,
        cert_issued_at: app.cert_issued_at,
        cert_alias: app.cert_alias.clone(),
    });
}

fn read_public_app(data: &[u8], pos: &mut usize) -> Option<ContactAppCard> {
    let id: Uuid = read_arr(data, pos)?;
    let alias = read_str(data, pos)?;
    let signing_pk = Ed25519PublicKey(read_arr(data, pos)?);
    let cert_sig = Ed25519Signature(read_arr(data, pos)?);
    let issued: [u8; 8] = read_arr(data, pos)?;
    let cert_alias = read_str(data, pos)?;
    Some(ContactAppCard {
        id,
        alias,
        signing_pk,
        cert_sig,
        cert_issued_at: u64::from_le_bytes(issued),
        cert_alias,
    })
}

fn application_from_public(app: &ContactAppCard) -> Application {
    Application {
        id: app.id,
        alias: app.alias.clone(),
        protocol: String::new(),
        host: "0.0.0.0:0".parse().unwrap(),
        user_approved: true,
        token: [0u8; 16],
        identity: Ed25519KeyPair {
            public_key: app.signing_pk,
            private_key: Ed25519SecretKey::ZERO,
            private_key_sealed: String::new(),
        },
        cert_sig: app.cert_sig,
        cert_issued_at: app.cert_issued_at,
        cert_alias: app.cert_alias.clone(),
    }
}

/// Keep a locally held identity secret when the public key still matches.
fn merge_app_public(local: &mut Application, incoming: &ContactAppCard, fill_alias: bool) {
    if fill_alias {
        local.alias = incoming.alias.clone();
    }
    let same_key = local.identity.public_key == incoming.signing_pk;
    if !same_key && incoming.signing_pk != Ed25519PublicKey::ZERO {
        local.identity.public_key = incoming.signing_pk;
        local.identity.private_key = Ed25519SecretKey::ZERO;
        local.identity.private_key_sealed.clear();
    }
    let prefer_incoming = incoming.cert_sig != Ed25519Signature::ZERO
        && (local.cert_sig == Ed25519Signature::ZERO || !same_key);
    if prefer_incoming {
        local.cert_sig = incoming.cert_sig;
        local.cert_issued_at = incoming.cert_issued_at;
        local.cert_alias = incoming.cert_alias.clone();
    }
}

/// Marker before the per-contact allow list and invitations. Older peers stop
/// at the device list and ignore these trailing bytes.
const POLICY_MARKER: u8 = 0xA1;

pub(crate) fn serialize_contact_data(node: &Node) -> Vec<u8> {
    serialize_contact_directory(node, None)
}

/// Directory we publish to one contact. Approved apps are included only when
/// that contact has a grant for the app alias. The trailer lists every granted
/// alias, including aliases with no installed app, and any open invitation.
pub(crate) fn serialize_contact_data_for(node: &Node, contact_uuid: Uuid) -> Vec<u8> {
    serialize_contact_directory(node, Some(contact_uuid))
}

fn serialize_contact_directory(node: &Node, contact_uuid: Option<Uuid>) -> Vec<u8> {
    let mut buf = Vec::new();
    let user = &node.owner.user;
    buf.extend_from_slice(&user.uuid);
    buf.push(user.devices.len() as u8);
    let granted: Vec<&str> = match contact_uuid {
        Some(id) => node
            .owner
            .app_grants
            .iter()
            .filter(|g| g.contact_uuid == id)
            .map(|g| g.app_alias.as_str())
            .collect(),
        None => Vec::new(),
    };
    for d in &user.devices {
        push_device(&mut buf, d);
        let approved: Vec<&Application> = d
            .applications
            .iter()
            .filter(|a| a.user_approved)
            .filter(|a| contact_uuid.is_none() || granted.iter().any(|g| *g == a.alias))
            .collect();
        buf.push(approved.len() as u8);
        for a in approved {
            push_public_app_from(&mut buf, a);
        }
    }
    if let Some(id) = contact_uuid {
        buf.push(POLICY_MARKER);
        let mut aliases: Vec<&str> = granted;
        aliases.sort();
        aliases.dedup();
        buf.push(aliases.len().min(u8::MAX as usize) as u8);
        for alias in aliases.iter().take(u8::MAX as usize) {
            push_str(&mut buf, alias);
        }
        let invites: Vec<&AppInvitation> = node
            .owner
            .outbound_app_invitations
            .iter()
            .filter(|i| i.contact_uuid == id)
            .collect();
        buf.push(invites.len().min(u8::MAX as usize) as u8);
        for invite in invites.iter().take(u8::MAX as usize) {
            buf.extend_from_slice(&invite.id);
            push_str(&mut buf, &invite.app_alias);
        }
    }
    buf
}

pub(crate) struct ContactData {
    pub(crate) user_uuid: Uuid,
    pub(crate) devices:   Vec<(Device, Vec<ContactAppCard>)>,
    /// `None` when the peer is an older node that published every approved app.
    pub(crate) accepted_aliases: Option<Vec<String>>,
    pub(crate) invitations: Vec<(Uuid, String)>,
}

pub(crate) fn deserialize_contact_data(data: &[u8]) -> Option<ContactData> {
    let mut pos = 0usize;
    let user_uuid: Uuid    = read_arr(data, &mut pos)?;
    let device_count = *data.get(pos)? as usize; pos += 1;
    let mut devices = Vec::new();
    for _ in 0..device_count {
        let device = read_device(data, &mut pos)?;
        let app_count = *data.get(pos)? as usize; pos += 1;
        let mut apps = Vec::new();
        for _ in 0..app_count {
            apps.push(read_public_app(data, &mut pos)?);
        }
        devices.push((device, apps));
    }
    if pos >= data.len() || data[pos] != POLICY_MARKER {
        return Some(ContactData {
            user_uuid,
            devices,
            accepted_aliases: None,
            invitations: Vec::new(),
        });
    }
    pos += 1;
    let alias_count = *data.get(pos)? as usize;
    pos += 1;
    let mut accepted_aliases = Vec::with_capacity(alias_count);
    for _ in 0..alias_count {
        accepted_aliases.push(read_str(data, &mut pos)?);
    }
    let invite_count = *data.get(pos)? as usize;
    pos += 1;
    let mut invitations = Vec::with_capacity(invite_count);
    for _ in 0..invite_count {
        let id: Uuid = read_arr(data, &mut pos)?;
        let alias = read_str(data, &mut pos)?;
        invitations.push((id, alias));
    }
    Some(ContactData {
        user_uuid,
        devices,
        accepted_aliases: Some(accepted_aliases),
        invitations,
    })
}

/// True if `data` is a well-formed cross-user contact directory blob. §8.2 fuzz.
pub(crate) fn contact_data_well_formed(data: &[u8]) -> bool {
    deserialize_contact_data(data).is_some()
}

/// True if `data` is a well-formed write-log `Change` payload. §8.2 fuzz.
pub(crate) fn change_payload_well_formed(data: &[u8]) -> bool {
    deserialize_change(data).is_some()
}

/// True if `state` is a well-formed public directory snapshot (parse only, no apply).
/// Layout matches [`serialize_public_state`] / [`apply_public_state`]. §8.2 fuzz.
pub(crate) fn public_state_well_formed(state: &[u8]) -> bool {
    fn walk(state: &[u8]) -> Option<()> {
        let mut pos = 0usize;
        let _ = read_str(state, &mut pos)?;
        let _: [u8; 16] = read_arr(state, &mut pos)?;
        let dev_count = *state.get(pos)? as usize;
        pos += 1;
        for _ in 0..dev_count {
            let _ = read_device(state, &mut pos)?;
            let app_count = *state.get(pos)? as usize;
            pos += 1;
            for _ in 0..app_count {
                let _ = read_public_app(state, &mut pos)?;
            }
        }
        let contact_count = *state.get(pos)? as usize;
        pos += 1;
        for _ in 0..contact_count {
            let _ = read_str(state, &mut pos)?;
            let _: [u8; 16] = read_arr(state, &mut pos)?;
            let _: [u8; 32] = read_arr(state, &mut pos)?;
            let dc = *state.get(pos)? as usize;
            pos += 1;
            for _ in 0..dc {
                let _ = read_device(state, &mut pos)?;
                let ac = *state.get(pos)? as usize;
                pos += 1;
                for _ in 0..ac {
                    let _ = read_public_app(state, &mut pos)?;
                }
            }
        }
        if pos < state.len() && state[pos] == POLICY_MARKER {
            read_policy_snapshot(state, &mut pos)?;
        }
        let _ = pos;
        Some(())
    }
    walk(state).is_some()
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

// Scope / SyncVersion wire codecs and change-kind bytes: `wire`.

// ── Change types ──────────────────────────────────────────────────────────────
//
// A `Change` is the unit of state mutation the writer SG accepts. Each variant
// declares which scope(s) it touches via `change_scopes`, so the writer bumps
// the right counter(s) on accept. Wire `change_kind` is a single byte — the
// payload after it is variant-specific.

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
    pub apps:    Vec<ContactAppCard>,
    pub signing_pk: Ed25519PublicKey,
    pub dh_pk: X25519PublicKey,
    pub cert_sig: Ed25519Signature,
    pub cert_issued_at: u64,
    pub cert_alias: String,
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
        signing_pk: Ed25519PublicKey,
        cert_sig: Ed25519Signature,
        cert_issued_at: u64,
        cert_alias: String,
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
        signing_pk: Ed25519PublicKey,
        dh_pk: X25519PublicKey,
        cert_sig: Ed25519Signature,
        cert_issued_at: u64,
        cert_alias: String,
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
        public_key: Ed25519PublicKey,
        devices:    Vec<ContactDeviceCard>,
    },
    /// Public-scope: remove own-user device by uuid (and all its apps).
    /// Tombstone for merge: concurrent AddDevice of the same uuid loses.
    RemoveDevice { uuid: Uuid },
    /// Public-scope: remove a contact user by uuid (and all their devices).
    /// Tombstone for merge: concurrent UpsertContact of the same uuid loses.
    RemoveContact { uuid: Uuid },
    /// Public-scope: allow or revoke one app alias for one contact.
    SetAppGrant {
        contact_uuid: Uuid,
        app_alias: String,
        allowed: bool,
    },
    /// Public-scope: record an inbound app invitation we have not answered.
    PutAppInvitation {
        id: Uuid,
        contact_uuid: Uuid,
        app_alias: String,
    },
    /// Public-scope: drop an inbound invitation and remember its id.
    ForgetAppInvitation { id: Uuid },
    /// Public-scope: publish an invitation asking that contact to accept us.
    PutOutboundAppInvitation {
        id: Uuid,
        contact_uuid: Uuid,
        app_alias: String,
    },
    /// Public-scope: stop publishing an outbound invitation.
    ForgetOutboundAppInvitation { id: Uuid },
    /// Public-scope: replace the alias list this contact has accepted from us.
    SetContactTheyAccept {
        contact_uuid: Uuid,
        aliases: Vec<String>,
    },
    /// Private-scope: insert or replace one purse. The record is the whole
    /// purse, so a later upsert of the same id replaces the earlier one.
    /// Own devices learn it from a private pull. Contacts do not.
    UpsertPurse { purse: Purse },
    /// Private-scope: hold `amount_nanodollars` of one purse for `payment_id`.
    /// A repeat of the same hold does not reduce the available amount again.
    ReservePayment { reserve: PaymentReserve },
    /// Private-scope: return a hold to its purse. A missing id is a no-op.
    /// A payment that already became a charges line is not refunded.
    ReleaseReserve { payment_id: Uuid },
    /// Private-scope: store one confirmed payment. On the payer this consumes
    /// the matching hold without putting the amount back. On the payee it
    /// requires the staged accept.
    RecordCharge { line: Charge },
    /// Private-scope: remember a signed accept so it counts against the ceiling.
    StageAccept { pending: PendingAccept },
    /// Private-scope: forget a staged accept. This does not touch a purse.
    DropAccept { payment_id: Uuid },
    /// Private-scope: store one dual-signed settlement. The same signed bytes are
    /// one record. A different body of the same id is kept. This does not
    /// change a purse, and it does not require the named lines to be present yet.
    RecordSettlement { record: Settlement },
    /// Private-scope: set one payer's receive ceiling. The same payer and amount
    /// is a no-op. A different amount replaces that payer's row. This does not
    /// change a purse, a reserve, or the net. Contacts are not told the number.
    SetRunLimit { payer: Uuid, max_nanodollars: i64 },
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
        Change::RemoveDevice { .. }            => &[Scope::Public],
        Change::RemoveContact { .. }           => &[Scope::Public],
        Change::SetAppGrant { .. }             => &[Scope::Public],
        Change::PutAppInvitation { .. }        => &[Scope::Public],
        Change::ForgetAppInvitation { .. }     => &[Scope::Public],
        Change::PutOutboundAppInvitation { .. } => &[Scope::Public],
        Change::ForgetOutboundAppInvitation { .. } => &[Scope::Public],
        Change::SetContactTheyAccept { .. }    => &[Scope::Public],
        Change::UpsertPurse { .. }             => &[Scope::Private],
        Change::ReservePayment { .. }          => &[Scope::Private],
        Change::ReleaseReserve { .. }          => &[Scope::Private],
        Change::RecordCharge { .. }            => &[Scope::Private],
        Change::StageAccept { .. }             => &[Scope::Private],
        Change::DropAccept { .. }              => &[Scope::Private],
        Change::RecordSettlement { .. }          => &[Scope::Private],
        Change::SetRunLimit { .. }       => &[Scope::Private],
    }
}

pub(crate) fn serialize_change(c: &Change) -> Vec<u8> {
    let mut buf = Vec::new();
    match c {
        Change::AddApplication { device_uuid, app_id, app_alias, signing_pk, cert_sig, cert_issued_at, cert_alias } => {
            buf.push(CHANGE_KIND_ADD_APPLICATION);
            buf.extend_from_slice(device_uuid);
            buf.extend_from_slice(app_id);
            push_str(&mut buf, app_alias);
            buf.extend_from_slice(signing_pk.as_bytes());
            buf.extend_from_slice(&cert_sig.0);
            buf.extend_from_slice(&cert_issued_at.to_le_bytes());
            push_str(&mut buf, cert_alias);
        }
        Change::RemoveApplication { device_uuid, app_id } => {
            buf.push(CHANGE_KIND_REMOVE_APPLICATION);
            buf.extend_from_slice(device_uuid);
            buf.extend_from_slice(app_id);
        }
        Change::AddDevice { uuid, alias, grade, sg_rank, hosts, signing_pk, dh_pk, cert_sig, cert_issued_at, cert_alias } => {
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
                signing_pk:   *signing_pk,
                dh_pk:        *dh_pk,
                cert_sig:     *cert_sig,
                cert_issued_at: *cert_issued_at,
                cert_alias:   cert_alias.clone(),
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
            buf.extend_from_slice(public_key.as_bytes());
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
                    signing_pk:   card.signing_pk,
                    dh_pk:        card.dh_pk,
                    cert_sig:     card.cert_sig,
                    cert_issued_at: card.cert_issued_at,
                    cert_alias:   card.cert_alias.clone(),
                };
                push_device(&mut buf, &temp);
                buf.push(card.apps.len().min(u8::MAX as usize) as u8);
                for app in card.apps.iter().take(u8::MAX as usize) {
                    push_public_app(&mut buf, app);
                }
            }
        }
        Change::RemoveDevice { uuid } => {
            buf.push(CHANGE_KIND_REMOVE_DEVICE);
            buf.extend_from_slice(uuid);
        }
        Change::RemoveContact { uuid } => {
            buf.push(CHANGE_KIND_REMOVE_CONTACT);
            buf.extend_from_slice(uuid);
        }
        Change::SetAppGrant { contact_uuid, app_alias, allowed } => {
            buf.push(CHANGE_KIND_SET_APP_GRANT);
            buf.extend_from_slice(contact_uuid);
            buf.push(u8::from(*allowed));
            push_str(&mut buf, app_alias);
        }
        Change::PutAppInvitation { id, contact_uuid, app_alias } => {
            buf.push(CHANGE_KIND_PUT_APP_INVITATION);
            buf.extend_from_slice(id);
            buf.extend_from_slice(contact_uuid);
            push_str(&mut buf, app_alias);
        }
        Change::ForgetAppInvitation { id } => {
            buf.push(CHANGE_KIND_FORGET_APP_INVITATION);
            buf.extend_from_slice(id);
        }
        Change::PutOutboundAppInvitation { id, contact_uuid, app_alias } => {
            buf.push(CHANGE_KIND_PUT_OUTBOUND_APP_INVITATION);
            buf.extend_from_slice(id);
            buf.extend_from_slice(contact_uuid);
            push_str(&mut buf, app_alias);
        }
        Change::ForgetOutboundAppInvitation { id } => {
            buf.push(CHANGE_KIND_FORGET_OUTBOUND_APP_INVITATION);
            buf.extend_from_slice(id);
        }
        Change::SetContactTheyAccept { contact_uuid, aliases } => {
            buf.push(CHANGE_KIND_SET_CONTACT_THEY_ACCEPT);
            buf.extend_from_slice(contact_uuid);
            buf.push(aliases.len().min(u8::MAX as usize) as u8);
            for alias in aliases.iter().take(u8::MAX as usize) {
                push_str(&mut buf, alias);
            }
        }
        Change::UpsertPurse { purse } => {
            buf.push(CHANGE_KIND_UPSERT_PURSE);
            let mut purse = purse.normalized();
            if purse.kind == PURSE_KIND_FIXED {
                purse.period = 0;
            }
            push_purse(&mut buf, &purse);
            buf.push(purse.kind);
            buf.extend_from_slice(&purse.period.to_be_bytes());
        }
        Change::ReservePayment { reserve } => {
            buf.push(CHANGE_KIND_RESERVE_PAYMENT);
            push_reserve(&mut buf, reserve);
            buf.extend_from_slice(&reserve.period.to_be_bytes());
        }
        Change::ReleaseReserve { payment_id } => {
            buf.push(CHANGE_KIND_RELEASE_RESERVE);
            buf.extend_from_slice(payment_id);
        }
        Change::RecordCharge { line } => {
            buf.push(CHANGE_KIND_RECORD_CHARGE);
            push_line(&mut buf, line);
        }
        Change::StageAccept { pending } => {
            buf.push(CHANGE_KIND_STAGE_ACCEPT);
            push_pending(&mut buf, pending);
        }
        Change::DropAccept { payment_id } => {
            buf.push(CHANGE_KIND_DROP_ACCEPT);
            buf.extend_from_slice(payment_id);
        }
        Change::RecordSettlement { record } => {
            buf.push(CHANGE_KIND_RECORD_SETTLEMENT);
            push_settlement(&mut buf, record);
        }
        Change::SetRunLimit { payer, max_nanodollars } => {
            buf.push(CHANGE_KIND_SET_RUN_LIMIT);
            buf.extend_from_slice(payer);
            push_i64(&mut buf, *max_nanodollars);
        }
    }
    buf
}

pub(crate) fn deserialize_change(data: &[u8]) -> Option<Change> {
    let mut pos = 0usize;
    let kind = *data.get(pos)?;
    pos += 1;
    match kind {
        CHANGE_KIND_ADD_APPLICATION => {
            let device_uuid: Uuid = read_arr(data, &mut pos)?;
            let app_id:      Uuid = read_arr(data, &mut pos)?;
            let app_alias         = read_str(data, &mut pos)?;
            let signing_pk = Ed25519PublicKey(read_arr(data, &mut pos)?);
            let cert_sig = Ed25519Signature(read_arr(data, &mut pos)?);
            let issued_bytes: [u8; 8] = read_arr(data, &mut pos)?;
            let cert_issued_at = u64::from_le_bytes(issued_bytes);
            let cert_alias = read_str(data, &mut pos)?;
            Some(Change::AddApplication {
                device_uuid, app_id, app_alias, signing_pk, cert_sig, cert_issued_at, cert_alias,
            })
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
                signing_pk: d.signing_pk,
                dh_pk: d.dh_pk,
                cert_sig: d.cert_sig,
                cert_issued_at: d.cert_issued_at,
                cert_alias: d.cert_alias,
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
            let public_key = Ed25519PublicKey(read_arr(data, &mut pos)?);
            let dev_count = *data.get(pos)? as usize; pos += 1;
            let mut devices = Vec::with_capacity(dev_count);
            for _ in 0..dev_count {
                let d = read_device(data, &mut pos)?;
                let app_count = *data.get(pos)? as usize; pos += 1;
                let mut apps = Vec::with_capacity(app_count);
                for _ in 0..app_count {
                    apps.push(read_public_app(data, &mut pos)?);
                }
                devices.push(ContactDeviceCard {
                    uuid: d.uuid, alias: d.alias, grade: d.grade,
                    sg_rank: d.sg_rank, hosts: d.hosts, apps,
                    signing_pk: d.signing_pk,
                    dh_pk: d.dh_pk,
                    cert_sig: d.cert_sig,
                    cert_issued_at: d.cert_issued_at,
                    cert_alias: d.cert_alias,
                });
            }
            Some(Change::UpsertContact { uuid, alias, public_key, devices })
        }
        CHANGE_KIND_REMOVE_DEVICE => {
            let uuid: Uuid = read_arr(data, &mut pos)?;
            Some(Change::RemoveDevice { uuid })
        }
        CHANGE_KIND_REMOVE_CONTACT => {
            let uuid: Uuid = read_arr(data, &mut pos)?;
            Some(Change::RemoveContact { uuid })
        }
        CHANGE_KIND_SET_APP_GRANT => {
            let contact_uuid: Uuid = read_arr(data, &mut pos)?;
            let allowed = *data.get(pos)? != 0;
            pos += 1;
            let app_alias = read_str(data, &mut pos)?;
            Some(Change::SetAppGrant { contact_uuid, app_alias, allowed })
        }
        CHANGE_KIND_PUT_APP_INVITATION => {
            let id: Uuid = read_arr(data, &mut pos)?;
            let contact_uuid: Uuid = read_arr(data, &mut pos)?;
            let app_alias = read_str(data, &mut pos)?;
            Some(Change::PutAppInvitation { id, contact_uuid, app_alias })
        }
        CHANGE_KIND_FORGET_APP_INVITATION => {
            let id: Uuid = read_arr(data, &mut pos)?;
            Some(Change::ForgetAppInvitation { id })
        }
        CHANGE_KIND_PUT_OUTBOUND_APP_INVITATION => {
            let id: Uuid = read_arr(data, &mut pos)?;
            let contact_uuid: Uuid = read_arr(data, &mut pos)?;
            let app_alias = read_str(data, &mut pos)?;
            Some(Change::PutOutboundAppInvitation { id, contact_uuid, app_alias })
        }
        CHANGE_KIND_FORGET_OUTBOUND_APP_INVITATION => {
            let id: Uuid = read_arr(data, &mut pos)?;
            Some(Change::ForgetOutboundAppInvitation { id })
        }
        CHANGE_KIND_SET_CONTACT_THEY_ACCEPT => {
            let contact_uuid: Uuid = read_arr(data, &mut pos)?;
            let count = *data.get(pos)? as usize;
            pos += 1;
            let mut aliases = Vec::with_capacity(count);
            for _ in 0..count {
                aliases.push(read_str(data, &mut pos)?);
            }
            Some(Change::SetContactTheyAccept { contact_uuid, aliases })
        }
        CHANGE_KIND_UPSERT_PURSE => {
            let purse = read_purse_change(data, &mut pos)?;
            Some(Change::UpsertPurse { purse })
        }
        CHANGE_KIND_RESERVE_PAYMENT => {
            let reserve = read_reserve_change(data, &mut pos)?;
            Some(Change::ReservePayment { reserve })
        }
        CHANGE_KIND_RELEASE_RESERVE => {
            let payment_id: Uuid = read_arr(data, &mut pos)?;
            Some(Change::ReleaseReserve { payment_id })
        }
        CHANGE_KIND_RECORD_CHARGE => {
            let line = read_line(data, &mut pos)?;
            Some(Change::RecordCharge { line })
        }
        CHANGE_KIND_STAGE_ACCEPT => {
            let pending = read_pending(data, &mut pos)?;
            Some(Change::StageAccept { pending })
        }
        CHANGE_KIND_DROP_ACCEPT => {
            let payment_id: Uuid = read_arr(data, &mut pos)?;
            Some(Change::DropAccept { payment_id })
        }
        CHANGE_KIND_RECORD_SETTLEMENT => {
            let record = read_settlement(data, &mut pos)?;
            Some(Change::RecordSettlement { record })
        }
        CHANGE_KIND_SET_RUN_LIMIT => {
            let payer: Uuid = read_arr(data, &mut pos)?;
            let max_nanodollars = read_i64(data, &mut pos)?;
            Some(Change::SetRunLimit { payer, max_nanodollars })
        }
        _ => None,
    }
}

/// Why the writer refused a reserve without changing the purse.
#[derive(Debug, PartialEq, Eq)]
pub enum ReserveReject {
    /// The purse is missing, or the paying alias is not a member.
    NotMember,
    /// The amount is above what that purse still has available.
    OverPurse,
    /// This payment id is already on hold with a different body.
    Mismatch,
}

/// Why the writer refused a signed payment step without changing the books.
#[derive(Debug, PartialEq, Eq)]
pub enum PaymentReject {
    /// The new claim would pass the ceiling stored for that payer.
    OverCeiling,
    /// This payment id is already in use with a different body.
    Mismatch,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteError {
    /// No reachable own SG. Caller should report the error to the requesting app.
    Unreachable,
    /// Change refers to state the writer doesn't have (e.g., unknown device_uuid).
    Validation(String),
    /// A reserve was refused. The purse and the other holds are unchanged.
    ReserveRejected(ReserveReject),
    /// A signed payment step was refused. Existing lines and holds stay as they were.
    PaymentRejected(PaymentReject),
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
        Change::AddApplication {
            device_uuid, app_id, app_alias, signing_pk, cert_sig, cert_issued_at, cert_alias,
        } => {
            let dev = owner.user.devices.iter_mut()
                .find(|d| d.uuid == *device_uuid)
                .ok_or_else(|| WriteError::Validation(format!(
                    "unknown device_uuid {device_uuid:?}"
                )))?;
            let incoming = ContactAppCard {
                id: *app_id,
                alias: app_alias.clone(),
                signing_pk: *signing_pk,
                cert_sig: *cert_sig,
                cert_issued_at: *cert_issued_at,
                cert_alias: cert_alias.clone(),
            };
            if let Some(existing) = dev.applications.iter_mut().find(|a| a.id == *app_id) {
                let before = (existing.cert_sig, existing.identity.public_key);
                merge_app_public(existing, &incoming, false);
                before != (existing.cert_sig, existing.identity.public_key)
            } else {
                // Private-scope fields stay zero on the writer SG — the
                // originating DG holds the real token/host locally.
                dev.applications.push(application_from_public(&incoming));
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
        Change::AddDevice {
            uuid, alias, grade, sg_rank, hosts, signing_pk, dh_pk, cert_sig, cert_issued_at, cert_alias,
        } => {
            if let Some(existing) = owner.user.devices.iter_mut().find(|d| d.uuid == *uuid) {
                if existing.cert_sig == Ed25519Signature::ZERO && *cert_sig != Ed25519Signature::ZERO {
                    existing.signing_pk = *signing_pk;
                    existing.dh_pk = *dh_pk;
                    existing.cert_sig = *cert_sig;
                    existing.cert_issued_at = *cert_issued_at;
                    existing.cert_alias = cert_alias.clone();
                    true
                } else {
                    false
                }
            } else {
                owner.user.devices.push(Device {
                    uuid:         *uuid,
                    alias:        alias.clone(),
                    grade:        *grade,
                    sg_rank:      *sg_rank,
                    hosts:        hosts.clone(),
                    applications: Vec::new(),
                    signing_pk:   *signing_pk,
                    dh_pk:        *dh_pk,
                    cert_sig:     *cert_sig,
                    cert_issued_at: *cert_issued_at,
                    cert_alias:   cert_alias.clone(),
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
                        they_accept: Vec::new(),
                        last_seen_public_version: SyncVersion::default(),
                    });
                    true
                }
            }
        }
        Change::RemoveDevice { uuid } => {
            let before = owner.user.devices.len();
            owner.user.devices.retain(|d| d.uuid != *uuid);
            before != owner.user.devices.len()
        }
        Change::RemoveContact { uuid } => {
            let before = owner.contact_users.len()
                + owner.app_grants.len()
                + owner.app_invitations.len()
                + owner.outbound_app_invitations.len();
            owner.contact_users.retain(|c| c.user.uuid != *uuid);
            clear_contact_policy(owner, *uuid);
            let after = owner.contact_users.len()
                + owner.app_grants.len()
                + owner.app_invitations.len()
                + owner.outbound_app_invitations.len();
            before != after
        }
        Change::SetAppGrant { contact_uuid, app_alias, allowed } => {
            set_app_grant(owner, *contact_uuid, app_alias, *allowed)
        }
        Change::PutAppInvitation { id, contact_uuid, app_alias } => {
            put_invitation(&mut owner.app_invitations, &owner.seen_app_invitation_ids, *id, *contact_uuid, app_alias)
        }
        Change::ForgetAppInvitation { id } => forget_invitation(owner, *id),
        Change::PutOutboundAppInvitation { id, contact_uuid, app_alias } => {
            put_invitation(&mut owner.outbound_app_invitations, &[], *id, *contact_uuid, app_alias)
        }
        Change::ForgetOutboundAppInvitation { id } => {
            let before = owner.outbound_app_invitations.len();
            owner.outbound_app_invitations.retain(|i| i.id != *id);
            before != owner.outbound_app_invitations.len()
        }
        Change::SetContactTheyAccept { contact_uuid, aliases } => {
            let Some(contact) = owner.contact_users.iter_mut().find(|c| c.user.uuid == *contact_uuid) else {
                return Ok(false);
            };
            let mut next = aliases.clone();
            next.sort();
            next.dedup();
            if contact.they_accept == next {
                false
            } else {
                contact.they_accept = next;
                true
            }
        }
        Change::UpsertPurse { purse } => upsert_purse(owner, purse),
        Change::ReservePayment { reserve } => apply_reserve(owner, reserve)?,
        Change::ReleaseReserve { payment_id } => apply_release(owner, *payment_id),
        Change::RecordCharge { line } => apply_charge(owner, line)?,
        Change::StageAccept { pending } => apply_stage(owner, pending)?,
        Change::DropAccept { payment_id } => apply_drop(owner, *payment_id),
        Change::RecordSettlement { record } => apply_settlement(owner, record)?,
        Change::SetRunLimit { payer, max_nanodollars } => {
            set_run_limit(owner, *payer, *max_nanodollars)
        }
    };
    Ok(applied)
}

fn apply_reserve(owner: &mut Owner, reserve: &PaymentReserve) -> Result<bool, WriteError> {
    if reserve.amount_nanodollars <= 0
        || reserve.note.len() > 255
        || !alias_ok(&reserve.destination_alias)
        || !alias_ok(&reserve.paying_alias)
    {
        return Err(WriteError::Validation("reserve fields".into()));
    }
    if let Some(line) = owner.charges.iter().find(|line| line.payment_id == reserve.payment_id) {
        if line_same_payment(line, reserve, owner.user.uuid) {
            return Ok(false);
        }
        return Err(WriteError::ReserveRejected(ReserveReject::Mismatch));
    }
    if let Some(existing) = owner.reserves.iter().find(|r| r.payment_id == reserve.payment_id) {
        if existing.same_hold(reserve) {
            return Ok(false);
        }
        return Err(WriteError::ReserveRejected(ReserveReject::Mismatch));
    }
    let Some(purse) = owner.purses.iter_mut().find(|p| p.id == reserve.purse_id) else {
        return Err(WriteError::ReserveRejected(ReserveReject::NotMember));
    };
    if !purse.aliases.iter().any(|alias| alias == &reserve.paying_alias) {
        return Err(WriteError::ReserveRejected(ReserveReject::NotMember));
    }
    if reserve.amount_nanodollars > purse.available_nanodollars {
        return Err(WriteError::ReserveRejected(ReserveReject::OverPurse));
    }
    purse.available_nanodollars -= reserve.amount_nanodollars;
    owner.reserves.push(reserve.clone());
    Ok(true)
}

fn apply_release(owner: &mut Owner, payment_id: Uuid) -> bool {
    if owner.charges.iter().any(|line| line.payment_id == payment_id) {
        let before = owner.reserves.len();
        owner.reserves.retain(|reserve| reserve.payment_id != payment_id);
        return before != owner.reserves.len();
    }
    let Some(index) = owner.reserves.iter().position(|r| r.payment_id == payment_id) else {
        return false;
    };
    let reserve = owner.reserves.remove(index);
    if let Some(purse) = owner.purses.iter_mut().find(|p| p.id == reserve.purse_id) {
        if reserve_refunds(purse, &reserve) {
            purse.available_nanodollars = purse
                .available_nanodollars
                .saturating_add(reserve.amount_nanodollars);
        }
    }
    true
}

/// A fixed purse returns a released hold. So does a hold taken while the
/// purse was fixed (`period` 0), even after the purse becomes monthly. A
/// monthly hold is returned only while it still belongs to the purse's
/// current month. A hold from an earlier month was left behind when the
/// allotment was restored.
fn reserve_refunds(purse: &Purse, reserve: &PaymentReserve) -> bool {
    purse.kind != PURSE_KIND_MONTHLY || reserve.period == 0 || reserve.period == purse.period
}

fn apply_charge(owner: &mut Owner, line: &Charge) -> Result<bool, WriteError> {
    if !offer_body_ok(&body_from_line(line)) {
        return Err(WriteError::Validation("charge fields".into()));
    }
    // The same signed bytes are the same payment. A different body is kept.
    // The purse is charged only for the first body, and only when this record
    // names one purse that lists the paying alias and no matching hold remains.
    if owner.charges.iter().any(|stored| same_charge(stored, line)) {
        let removed_reserve = take_matching_reserve(owner, line);
        let removed_pending = take_matching_pending(owner, line);
        return Ok(removed_reserve || removed_pending);
    }
    if owner.charges.iter().any(|stored| stored.payment_id == line.payment_id) {
        take_matching_pending(owner, line);
        let mut stored = line.clone();
        stored.purse_id = [0u8; 16];
        owner.charges.push(stored);
        return Ok(true);
    }
    let reserve_purse = owner.reserves.iter().find_map(|reserve| {
        (reserve.payment_id == line.payment_id && line_same_payment(line, reserve, line.payer))
            .then_some(reserve.purse_id)
    });
    take_matching_pending(owner, line);
    if let Some(purse_id) = reserve_purse {
        take_reserve_no_refund(owner, line.payment_id);
        let mut stored = line.clone();
        stored.purse_id = purse_id;
        owner.charges.push(stored);
        return Ok(true);
    }
    let mut stored = line.clone();
    if stored.purse_id != [0u8; 16] {
        if let Some(purse) = owner.purses.iter_mut().find(|purse| purse.id == stored.purse_id) {
            if purse.aliases.iter().any(|alias| alias == &stored.paying_alias) {
                purse.available_nanodollars = purse
                    .available_nanodollars
                    .saturating_sub(stored.amount_nanodollars);
                owner.charges.push(stored);
                return Ok(true);
            }
        }
    }
    stored.purse_id = [0u8; 16];
    owner.charges.push(stored);
    Ok(true)
}

fn apply_stage(owner: &mut Owner, pending: &PendingAccept) -> Result<bool, WriteError> {
    if !offer_body_ok(&body_from_pending(pending)) {
        return Err(WriteError::Validation("accept fields".into()));
    }
    let body = body_from_pending(pending);
    if let Some(line) = owner.charges.iter().find(|line| line.payment_id == pending.payment_id) {
        if line_covers(line, &body, &pending.payer_sig) {
            return Ok(false);
        }
        return Err(WriteError::PaymentRejected(PaymentReject::Mismatch));
    }
    if let Some(existing) = owner.pending_accepts.iter().find(|stored| stored.payment_id == pending.payment_id) {
        if pending_covers(existing, &body, &pending.payer_sig) {
            return Ok(false);
        }
        return Err(WriteError::PaymentRejected(PaymentReject::Mismatch));
    }
    if claim_exceeds_run(owner, pending.payer, pending.amount_nanodollars, Some(pending.payment_id)) {
        return Err(WriteError::PaymentRejected(PaymentReject::OverCeiling));
    }
    owner.pending_accepts.push(pending.clone());
    Ok(true)
}

fn apply_drop(owner: &mut Owner, payment_id: Uuid) -> bool {
    take_pending(owner, payment_id)
}

fn apply_settlement(owner: &mut Owner, record: &Settlement) -> Result<bool, WriteError> {
    if !settlement_ok(record) {
        return Err(WriteError::Validation("settlement fields".into()));
    }
    if owner.settlements.iter().any(|stored| stored == record) {
        return Ok(false);
    }
    owner.settlements.push(record.clone());
    Ok(true)
}

fn same_charge(left: &Charge, right: &Charge) -> bool {
    body_from_line(left) == body_from_line(right)
        && left.payer_sig == right.payer_sig
        && left.payee_sig == right.payee_sig
        && left.confirm_sig == right.confirm_sig
}

fn take_reserve_no_refund(owner: &mut Owner, payment_id: Uuid) -> bool {
    let before = owner.reserves.len();
    owner.reserves.retain(|reserve| reserve.payment_id != payment_id);
    before != owner.reserves.len()
}

fn take_matching_reserve(owner: &mut Owner, line: &Charge) -> bool {
    let matches = owner.reserves.iter().any(|reserve| {
        reserve.payment_id == line.payment_id && line_same_payment(line, reserve, line.payer)
    });
    if !matches {
        return false;
    }
    take_reserve_no_refund(owner, line.payment_id)
}

fn take_matching_pending(owner: &mut Owner, line: &Charge) -> bool {
    let body = body_from_line(line);
    let matches = owner.pending_accepts.iter().any(|pending| {
        pending.payment_id == line.payment_id
            && pending_covers(pending, &body, &line.payer_sig)
            && pending.payee_sig == line.payee_sig
    });
    if !matches {
        return false;
    }
    take_pending(owner, line.payment_id)
}

fn take_pending(owner: &mut Owner, payment_id: Uuid) -> bool {
    let before = owner.pending_accepts.len();
    owner.pending_accepts.retain(|pending| pending.payment_id != payment_id);
    before != owner.pending_accepts.len()
}

fn alias_ok(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= 255
        && alias.trim() == alias
        && !alias.chars().any(|c| c.is_control())
}

/// Give back every hold whose expiry is at or before `now_ms`.
///
/// Only the writer does this. Another device leaves the holds for the writer
/// and learns the restored amount from the private pull.
pub fn release_expired_reserves(ctx: &WorkerContext) {
    release_expired_reserves_at(ctx, unix_time_ms());
}

pub(crate) fn release_expired_reserves_at(ctx: &WorkerContext, now_ms: u64) {
    let local = {
        let node = ctx.node.read().unwrap();
        matches!(find_writer_sg(&node), WriterTarget::Local)
    };
    if !local {
        return;
    }
    roll_monthly_purses_at(ctx, now_ms);
    let ids: Vec<Uuid> = {
        let node = ctx.node.read().unwrap();
        node.owner
            .reserves
            .iter()
            .filter(|reserve| reserve.expires_at_ms <= now_ms)
            .map(|reserve| reserve.payment_id)
            .collect()
    };
    for payment_id in ids {
        if let Err(err) = request_change_idempotent(Change::ReleaseReserve { payment_id }, ctx) {
            eprintln!("[release_expired_reserves] {payment_id:?}: {err:?}");
        }
    }
    let pending_ids: Vec<Uuid> = {
        let node = ctx.node.read().unwrap();
        node.owner
            .pending_accepts
            .iter()
            .filter(|pending| pending.expires_at_ms <= now_ms)
            .map(|pending| pending.payment_id)
            .collect()
    };
    for payment_id in pending_ids {
        if let Err(err) = request_change_idempotent(Change::DropAccept { payment_id }, ctx) {
            eprintln!("[release_expired_reserves] accept {payment_id:?}: {err:?}");
        }
    }
}

/// Keep one row for `payer`. A repeat of the same amount is a no-op.
/// A different amount replaces that row. Extra rows for the same payer are
/// dropped, because the offer path reads the first match.
fn set_run_limit(owner: &mut Owner, payer: Uuid, max_nanodollars: i64) -> bool {
    if max_nanodollars < 0 {
        return false;
    }
    let mut kept = false;
    let mut changed = false;
    owner.run_limits.retain(|row| {
        if row.payer != payer {
            return true;
        }
        if kept {
            changed = true;
            return false;
        }
        kept = true;
        if row.max_nanodollars != max_nanodollars {
            changed = true;
        }
        true
    });
    if let Some(row) = owner.run_limits.iter_mut().find(|row| row.payer == payer) {
        row.max_nanodollars = max_nanodollars;
        return changed;
    }
    owner.run_limits.push(RunLimit { payer, max_nanodollars });
    true
}

/// Start a new UTC month on each monthly purse whose stored period is behind
/// `now_ms`. The available amount becomes the allotment. Unspent amount does
/// not carry, and an open hold is not added back. Only the writer calls this.
fn roll_monthly_purses_at(ctx: &WorkerContext, now_ms: u64) {
    let period = utc_month_period(now_ms);
    let due: Vec<Purse> = {
        let node = ctx.node.read().unwrap();
        node.owner
            .purses
            .iter()
            .filter(|purse| purse.kind == PURSE_KIND_MONTHLY && purse.period != period)
            .cloned()
            .collect()
    };
    for mut purse in due {
        purse.period = period;
        purse.available_nanodollars = purse.allotment_nanodollars;
        if let Err(err) = request_change_idempotent(Change::UpsertPurse { purse }, ctx) {
            eprintln!("[roll_monthly_purses] {err:?}");
        }
    }
}

fn upsert_purse(owner: &mut Owner, purse: &Purse) -> bool {
    if purse.allotment_nanodollars < 0
        || purse.name.trim().is_empty()
        || purse.name.len() > 255
        || (purse.kind != PURSE_KIND_FIXED && purse.kind != PURSE_KIND_MONTHLY)
    {
        return false;
    }
    let mut purse = purse.normalized();
    if purse.kind == PURSE_KIND_FIXED {
        purse.period = 0;
    }
    if purse.name.is_empty() {
        return false;
    }
    if let Some(existing) = owner.purses.iter_mut().find(|p| p.id == purse.id) {
        if existing == &purse {
            false
        } else {
            *existing = purse;
            true
        }
    } else {
        owner.purses.push(purse);
        true
    }
}

fn clear_contact_policy(owner: &mut Owner, contact_uuid: Uuid) {
    owner.app_grants.retain(|g| g.contact_uuid != contact_uuid);
    owner.app_invitations.retain(|i| i.contact_uuid != contact_uuid);
    owner.outbound_app_invitations.retain(|i| i.contact_uuid != contact_uuid);
}

fn set_app_grant(owner: &mut Owner, contact_uuid: Uuid, app_alias: &str, allowed: bool) -> bool {
    let exists = owner.app_grants.iter().any(|g| {
        g.contact_uuid == contact_uuid && g.app_alias == app_alias
    });
    if allowed {
        if exists {
            false
        } else {
            owner.app_grants.push(AppGrant {
                contact_uuid,
                app_alias: app_alias.to_string(),
            });
            true
        }
    } else if exists {
        owner.app_grants.retain(|g| {
            !(g.contact_uuid == contact_uuid && g.app_alias == app_alias)
        });
        true
    } else {
        false
    }
}

fn invitation_seen(seen: &[String], id: Uuid) -> bool {
    let hex = uuid_hex(&id);
    seen.iter().any(|s| s == &hex)
}

fn put_invitation(
    list: &mut Vec<AppInvitation>,
    seen: &[String],
    id: Uuid,
    contact_uuid: Uuid,
    app_alias: &str,
) -> bool {
    if invitation_seen(seen, id) || list.iter().any(|i| i.id == id) {
        return false;
    }
    list.push(AppInvitation {
        id,
        contact_uuid,
        app_alias: app_alias.to_string(),
    });
    true
}

fn forget_invitation(owner: &mut Owner, id: Uuid) -> bool {
    let before = owner.app_invitations.len();
    owner.app_invitations.retain(|i| i.id != id);
    let hex = uuid_hex(&id);
    let newly = !owner.seen_app_invitation_ids.iter().any(|s| s == &hex);
    if newly {
        owner.seen_app_invitation_ids.push(hex);
    }
    before != owner.app_invitations.len() || newly
}

/// After a successful RemoveDevice / RemoveContact, drop fabric state that
/// referenced the removed identity (§7.2): sessions, tunnels, pending maps.
pub(crate) fn cascade_remove_fabric_state(ctx: &WorkerContext, change: &Change) {
    let device_uuids: Vec<Uuid> = match change {
        Change::RemoveDevice { uuid } => vec![*uuid],
        Change::RemoveContact { uuid } => {
            // Contact already removed from directory; drop sessions to any
            // device uuid we still have connections for that matched the
            // contact. Collect from active_connections that no longer map to
            // a known own device or remaining contact device.
            let node = ctx.node.read().unwrap();
            let known: HashSet<Uuid> = node
                .owner
                .user
                .devices
                .iter()
                .map(|d| d.uuid)
                .chain(
                    node.owner
                        .contact_users
                        .iter()
                        .flat_map(|c| c.user.devices.iter().map(|d| d.uuid)),
                )
                .collect();
            let _ = uuid; // contact user uuid — connections use device uuids
            node.owner
                .active_connections
                .values()
                .filter(|c| !known.contains(&c.device_uuid) && c.device_uuid != node.device_uuid)
                .map(|c| c.device_uuid)
                .collect()
        }
        _ => return,
    };
    if device_uuids.is_empty() && !matches!(change, Change::RemoveContact { .. }) {
        return;
    }

    let mut node = ctx.node.write().unwrap();
    match change {
        Change::RemoveDevice { uuid } => {
            drop_sessions_and_tunnels_for_device(&mut node, *uuid);
            fabric_event(
                "identity_removed",
                &[("kind", "device"), ("uuid", &uuid_hex(uuid))],
            );
        }
        Change::RemoveContact { uuid } => {
            // Drop any connection to devices no longer in the directory.
            let known: HashSet<Uuid> = node
                .owner
                .user
                .devices
                .iter()
                .map(|d| d.uuid)
                .chain(
                    node.owner
                        .contact_users
                        .iter()
                        .flat_map(|c| c.user.devices.iter().map(|d| d.uuid)),
                )
                .collect();
            let orphaned: Vec<Uuid> = node
                .owner
                .active_connections
                .values()
                .map(|c| c.device_uuid)
                .filter(|u| *u != node.device_uuid && !known.contains(u))
                .collect();
            for u in &orphaned {
                drop_sessions_and_tunnels_for_device(&mut node, *u);
            }
            // Also clear SG status rows for those devices.
            let local = node.device_uuid;
            node.sg_statuses
                .retain(|(u, _), _| known.contains(u) || *u == local);
            fabric_event(
                "identity_removed",
                &[
                    ("kind", "contact"),
                    ("uuid", &uuid_hex(uuid)),
                    ("sessions_dropped", &orphaned.len().to_string()),
                ],
            );
        }
        _ => {}
    }
}

fn drop_sessions_and_tunnels_for_device(node: &mut Node, device_uuid: Uuid) {
    node.owner
        .active_connections
        .retain(|_, c| c.device_uuid != device_uuid);
    node.owner
        .pending_connections
        .retain(|_, p| p.peer_device_uuid != device_uuid);

    // SG tunnel maps that reference those connection ids.
    let dead_conn_ids: HashSet<u16> = node
        .owner
        .active_connections
        .keys()
        .copied()
        .collect();
    // Recompute: connections already retained — remove tunnels whose legs are gone.
    let dead_tunnels: Vec<u16> = node
        .owner
        .active_tunnels
        .iter()
        .filter(|(_, t)| {
            !node.owner.active_connections.contains_key(&t.connection_a_id)
                || !node.owner.active_connections.contains_key(&t.connection_b_id)
        })
        .map(|(&id, _)| id)
        .collect();
    for id in dead_tunnels {
        node.owner.active_tunnels.remove(&id);
    }
    node.owner.pending_tunnels.retain(|_, p| {
        p.sender_device_uuid != device_uuid && p.dest_device_uuid != device_uuid
    });
    // DG tunnel map: drop entries whose conn was for this device (already gone).
    let map_dead: Vec<u16> = node
        .owner
        .dg_tunnel_map
        .iter()
        .filter(|(_, cid)| !dead_conn_ids.contains(cid))
        .map(|(&tid, _)| tid)
        .collect();
    for tid in map_dead {
        node.owner.dg_tunnel_map.remove(&tid);
        node.owner.pending_tunnel_connections.remove(&tid);
    }
    node.sg_statuses.retain(|(u, _), _| *u != device_uuid);
    let _ = dead_conn_ids;
}

/// Build `Application` stubs (public fields only — private fields zeroed) from
/// a card's public app records. Contact apps never carry private fields.
fn card_apps_to_applications(apps: &[ContactAppCard]) -> Vec<Application> {
    apps.iter().map(application_from_public).collect()
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
        signing_pk:   c.signing_pk,
        dh_pk:        c.dh_pk,
        cert_sig:     c.cert_sig,
        cert_issued_at: c.cert_issued_at,
        cert_alias:   c.cert_alias.clone(),
    }).collect()
}

fn app_to_card(app: &Application) -> ContactAppCard {
    ContactAppCard {
        id: app.id,
        alias: app.alias.clone(),
        signing_pk: app.identity.public_key,
        cert_sig: app.cert_sig,
        cert_issued_at: app.cert_issued_at,
        cert_alias: app.cert_alias.clone(),
    }
}

/// Cards for a set of stored devices, in a deterministic order (devices by
/// uuid, apps by id) so card equality is order-independent.
pub(crate) fn devices_to_cards(devices: &[Device]) -> Vec<ContactDeviceCard> {
    let mut cards: Vec<ContactDeviceCard> = devices.iter().map(|d| {
        let mut apps: Vec<ContactAppCard> = d.applications.iter().map(app_to_card).collect();
        apps.sort_by(|a, b| a.id.cmp(&b.id).then(a.alias.cmp(&b.alias)));
        ContactDeviceCard {
            uuid: d.uuid, alias: d.alias.clone(), grade: d.grade,
            sg_rank: d.sg_rank, hosts: d.hosts.clone(), apps,
            signing_pk: d.signing_pk,
            dh_pk: d.dh_pk,
            cert_sig: d.cert_sig,
            cert_issued_at: d.cert_issued_at,
            cert_alias: d.cert_alias.clone(),
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
        apps.sort_by(|a, b| a.id.cmp(&b.id).then(a.alias.cmp(&b.alias)));
        ContactDeviceCard {
            uuid: c.uuid, alias: c.alias.clone(), grade: c.grade,
            sg_rank: c.sg_rank, hosts: c.hosts.clone(), apps,
            signing_pk: c.signing_pk,
            dh_pk: c.dh_pk,
            cert_sig: c.cert_sig,
            cert_issued_at: c.cert_issued_at,
            cert_alias: c.cert_alias.clone(),
        }
    }).collect();
    out.sort_by_key(|c| c.uuid);
    out
}

pub(crate) fn apply_change_locally(
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
        WriterTarget::Local => {
            let result = apply_local_change(change.clone(), ctx, force_bump_on_noop);
            if result.is_ok() {
                cascade_remove_fabric_state(ctx, &change);
            }
            result
        }
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

    // §6.2: version writer_sg_uuid change (epoch rollover / new elected writer stamp).
    for (scope_name, pre, post) in [
        ("private", pre_priv, post_priv),
        ("public", pre_pub, post_pub),
    ] {
        if pre.writer_sg_uuid != post.writer_sg_uuid {
            fabric_event(
                "writer_change",
                &[
                    ("scope", scope_name),
                    ("from", &uuid_hex(&pre.writer_sg_uuid)),
                    ("to", &uuid_hex(&post.writer_sg_uuid)),
                    ("epoch", &post.epoch.to_string()),
                ],
            );
        }
    }
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
pub(crate) fn bumped_scopes(
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
pub(crate) fn notify_contacts(public: SyncVersion, ctx: &WorkerContext) {
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
fn local_is_sg(node: &Node) -> bool {
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
pub(crate) fn partition_reconcile_on_reconnect(conn_id: u16, ctx: &WorkerContext) {
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
pub(crate) fn cross_user_pull_on_reconnect(conn_id: u16, ctx: &WorkerContext) {
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
pub(crate) fn cross_user_pull_for_contact(contact_uuid: Uuid, ctx: &WorkerContext) {
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
//       [app_count: u8] each public app record (id, alias, signing key, cert)
//   [contact_count: u8]
//     each contact:
//       [user_alias: u8+bytes][user_uuid:16][public_key:32]
//       [device_count: u8] each device (same shape as own devices, apps included)
//
// Apps in the Public-scope blob carry id, alias, the app signing key, and
// the device-signed certificate. The originating device's private fields
// (`token`, `host`, `protocol`, app secret) stay local and are merged in
// by `apply_public_state` rather than overwritten.
//
// The Private-scope state blob is a purse snapshot:
//   [marker: 0xB7][count: u16][purse…]
//   then reserves, ceilings, lines, staged accepts, and settlements.
//   then each purse's kind and UTC month, and each reserve's month.
// An empty blob is a legacy writer and does not clear the puller's purses.
// A blob that ends before the settlement count has no settlements.
// A blob that ends at the settlements has fixed purses and reserve month 0.

pub(crate) fn serialize_public_state(node: &Node) -> Vec<u8> {
    let mut buf = Vec::new();
    let user = &node.owner.user;
    push_str(&mut buf, &user.alias);
    buf.extend_from_slice(&user.uuid);

    buf.push(user.devices.len().min(u8::MAX as usize) as u8);
    for d in user.devices.iter().take(u8::MAX as usize) {
        push_device(&mut buf, d);
        buf.push(d.applications.len().min(u8::MAX as usize) as u8);
        for a in d.applications.iter().take(u8::MAX as usize) {
            push_public_app_from(&mut buf, a);
        }
    }

    buf.push(node.owner.contact_users.len().min(u8::MAX as usize) as u8);
    for contact in node.owner.contact_users.iter().take(u8::MAX as usize) {
        push_str(&mut buf, &contact.user.alias);
        buf.extend_from_slice(&contact.user.uuid);
        buf.extend_from_slice(contact.public_key.as_bytes());
        buf.push(contact.user.devices.len().min(u8::MAX as usize) as u8);
        for d in contact.user.devices.iter().take(u8::MAX as usize) {
            push_device(&mut buf, d);
            buf.push(d.applications.len().min(u8::MAX as usize) as u8);
            for a in d.applications.iter().take(u8::MAX as usize) {
                push_public_app_from(&mut buf, a);
            }
        }
    }
    push_policy_snapshot(&mut buf, node);
    buf
}

fn push_u16(buf: &mut Vec<u8>, n: u16) {
    buf.extend_from_slice(&n.to_be_bytes());
}

fn push_i64(buf: &mut Vec<u8>, n: i64) {
    buf.extend_from_slice(&n.to_be_bytes());
}

fn read_i64(data: &[u8], pos: &mut usize) -> Option<i64> {
    let bytes: [u8; 8] = read_arr(data, pos)?;
    Some(i64::from_be_bytes(bytes))
}

/// First byte of a private-scope purse snapshot. An empty blob is a legacy
/// writer that has no purse record and must not wipe purses on the puller.
const PURSE_SNAPSHOT_MARKER: u8 = 0xB7;

fn push_purse(buf: &mut Vec<u8>, purse: &Purse) {
    let purse = purse.normalized();
    buf.extend_from_slice(&purse.id);
    push_str(buf, &purse.name);
    push_i64(buf, purse.allotment_nanodollars);
    push_i64(buf, purse.available_nanodollars);
    buf.push(purse.aliases.len().min(u8::MAX as usize) as u8);
    for alias in purse.aliases.iter().take(u8::MAX as usize) {
        push_str(buf, alias);
    }
}

fn read_purse(data: &[u8], pos: &mut usize) -> Option<Purse> {
    let id: Uuid = read_arr(data, pos)?;
    let name = read_str(data, pos)?;
    let allotment_nanodollars = read_i64(data, pos)?;
    let available_nanodollars = read_i64(data, pos)?;
    let count = *data.get(*pos)? as usize;
    *pos += 1;
    let mut aliases = Vec::with_capacity(count);
    for _ in 0..count {
        aliases.push(read_str(data, pos)?);
    }
    Some(Purse {
        id,
        name,
        allotment_nanodollars,
        available_nanodollars,
        aliases,
        kind: PURSE_KIND_FIXED,
        period: 0,
    }.normalized())
}

/// Kind and period follow the purse bytes. A change from before monthly
/// purses ends at the alias list and loads as fixed.
fn read_purse_change(data: &[u8], pos: &mut usize) -> Option<Purse> {
    let mut purse = read_purse(data, pos)?;
    if *pos == data.len() {
        return Some(purse);
    }
    if data.len() - *pos != 5 {
        return None;
    }
    purse.kind = *data.get(*pos)?;
    *pos += 1;
    let period_bytes: [u8; 4] = read_arr(data, pos)?;
    purse.period = u32::from_be_bytes(period_bytes);
    Some(purse)
}

fn push_reserve(buf: &mut Vec<u8>, reserve: &PaymentReserve) {
    buf.extend_from_slice(&reserve.payment_id);
    buf.extend_from_slice(&reserve.purse_id);
    push_i64(buf, reserve.amount_nanodollars);
    buf.extend_from_slice(&reserve.contact_uuid);
    push_str(buf, &reserve.destination_alias);
    push_str(buf, &reserve.note);
    push_str(buf, &reserve.paying_alias);
    buf.extend_from_slice(&reserve.expires_at_ms.to_be_bytes());
}

fn push_run_limit(buf: &mut Vec<u8>, ceiling: &RunLimit) {
    buf.extend_from_slice(&ceiling.payer);
    push_i64(buf, ceiling.max_nanodollars);
}

fn read_run_limit(data: &[u8], pos: &mut usize) -> Option<RunLimit> {
    let payer: Uuid = read_arr(data, pos)?;
    let max_nanodollars = read_i64(data, pos)?;
    Some(RunLimit { payer, max_nanodollars })
}

fn push_line(buf: &mut Vec<u8>, line: &Charge) {
    let body = body_from_line(line);
    buf.extend(encode_confirm(&body, &line.payer_sig, &line.payee_sig, &line.confirm_sig));
    buf.extend_from_slice(&line.purse_id);
}

fn read_line(data: &[u8], pos: &mut usize) -> Option<Charge> {
    let (body, payer_sig, payee_sig, confirm_sig) = decode_confirm_at(data, pos)?;
    let purse_id: Uuid = read_arr(data, pos)?;
    Some(line_from(&body, purse_id, payer_sig, payee_sig, confirm_sig))
}

fn push_pending(buf: &mut Vec<u8>, pending: &PendingAccept) {
    let body = body_from_pending(pending);
    buf.extend(encode_accept(&body, &pending.payer_sig, &pending.payee_sig));
}

fn read_pending(data: &[u8], pos: &mut usize) -> Option<PendingAccept> {
    let (body, payer_sig, payee_sig) = decode_accept_at(data, pos)?;
    Some(pending_from(&body, payer_sig, payee_sig))
}

fn push_settlement(buf: &mut Vec<u8>, record: &Settlement) {
    buf.extend(encode_settlement(record));
}

fn read_settlement(data: &[u8], pos: &mut usize) -> Option<Settlement> {
    decode_settlement_at(data, pos)
}

fn read_reserve(data: &[u8], pos: &mut usize) -> Option<PaymentReserve> {
    let payment_id: Uuid = read_arr(data, pos)?;
    let purse_id: Uuid = read_arr(data, pos)?;
    let amount_nanodollars = read_i64(data, pos)?;
    let contact_uuid: Uuid = read_arr(data, pos)?;
    let destination_alias = read_str(data, pos)?;
    let note = read_str(data, pos)?;
    let paying_alias = read_str(data, pos)?;
    let expires_bytes: [u8; 8] = read_arr(data, pos)?;
    Some(PaymentReserve {
        payment_id,
        purse_id,
        amount_nanodollars,
        contact_uuid,
        destination_alias,
        note,
        paying_alias,
        expires_at_ms: u64::from_be_bytes(expires_bytes),
        period: 0,
    })
}

/// The month follows the reserve bytes. An older change ends at the expiry
/// and loads as month 0.
fn read_reserve_change(data: &[u8], pos: &mut usize) -> Option<PaymentReserve> {
    let mut reserve = read_reserve(data, pos)?;
    if *pos == data.len() {
        return Some(reserve);
    }
    if data.len() - *pos != 4 {
        return None;
    }
    let period_bytes: [u8; 4] = read_arr(data, pos)?;
    reserve.period = u32::from_be_bytes(period_bytes);
    Some(reserve)
}

#[derive(Debug)]
enum PrivateSnapshot {
    /// Writer predates purses. Leave the puller's purse list alone.
    LegacyEmpty,
    /// Purses, holds, ceilings, confirmed lines, staged accepts, and settlements.
    /// A blob that ends after the purses has no holds. A blob that ends after
    /// the holds has no ceilings, lines, or staged accepts. A blob that ends
    /// after the staged accepts has no settlements.
    Purses {
        purses: Vec<Purse>,
        reserves: Vec<PaymentReserve>,
        ceilings: Vec<RunLimit>,
        charges: Vec<Charge>,
        pending: Vec<PendingAccept>,
        settlements: Vec<Settlement>,
    },
}

fn serialize_private_state(node: &Node) -> Vec<u8> {
    let mut purses = node.owner.purses.clone();
    purses.sort_by_key(|purse| purse.id);
    let mut reserves = node.owner.reserves.clone();
    reserves.sort_by_key(|reserve| reserve.payment_id);
    let mut ceilings = node.owner.run_limits.clone();
    ceilings.sort_by_key(|ceiling| ceiling.payer);
    let mut charges = node.owner.charges.clone();
    charges.sort_by_key(|line| line.payment_id);
    let mut pending = node.owner.pending_accepts.clone();
    pending.sort_by_key(|accept| accept.payment_id);
    let mut settlements = node.owner.settlements.clone();
    settlements.sort_by(|left, right| {
        left.settlement_id.cmp(&right.settlement_id).then(left.sig_lo.0.cmp(&right.sig_lo.0))
    });
    let mut buf = Vec::new();
    buf.push(PURSE_SNAPSHOT_MARKER);
    push_u16(&mut buf, purses.len().min(u16::MAX as usize) as u16);
    for purse in purses.iter().take(u16::MAX as usize) {
        push_purse(&mut buf, purse);
    }
    push_u16(&mut buf, reserves.len().min(u16::MAX as usize) as u16);
    for reserve in reserves.iter().take(u16::MAX as usize) {
        push_reserve(&mut buf, reserve);
    }
    push_u16(&mut buf, ceilings.len().min(u16::MAX as usize) as u16);
    for ceiling in ceilings.iter().take(u16::MAX as usize) {
        push_run_limit(&mut buf, ceiling);
    }
    push_u16(&mut buf, charges.len().min(u16::MAX as usize) as u16);
    for line in charges.iter().take(u16::MAX as usize) {
        push_line(&mut buf, line);
    }
    push_u16(&mut buf, pending.len().min(u16::MAX as usize) as u16);
    for accept in pending.iter().take(u16::MAX as usize) {
        push_pending(&mut buf, accept);
    }
    push_u16(&mut buf, settlements.len().min(u16::MAX as usize) as u16);
    for record in settlements.iter().take(u16::MAX as usize) {
        push_settlement(&mut buf, record);
    }
    push_u16(&mut buf, purses.len().min(u16::MAX as usize) as u16);
    for purse in purses.iter().take(u16::MAX as usize) {
        buf.extend_from_slice(&purse.id);
        buf.push(purse.kind);
        buf.extend_from_slice(&purse.period.to_be_bytes());
    }
    push_u16(&mut buf, reserves.len().min(u16::MAX as usize) as u16);
    for reserve in reserves.iter().take(u16::MAX as usize) {
        buf.extend_from_slice(&reserve.payment_id);
        buf.extend_from_slice(&reserve.period.to_be_bytes());
    }
    buf
}

fn read_private_snapshot(data: &[u8]) -> Option<PrivateSnapshot> {
    if data.is_empty() {
        return Some(PrivateSnapshot::LegacyEmpty);
    }
    if data[0] != PURSE_SNAPSHOT_MARKER {
        return None;
    }
    let mut pos = 1usize;
    let count = read_u16(data, &mut pos)? as usize;
    let mut purses = Vec::with_capacity(count);
    for _ in 0..count {
        purses.push(read_purse(data, &mut pos)?);
    }
    if pos == data.len() {
        return Some(PrivateSnapshot::Purses {
            purses,
            reserves: Vec::new(),
            ceilings: Vec::new(),
            charges: Vec::new(),
            pending: Vec::new(),
            settlements: Vec::new(),
        });
    }
    let reserve_count = read_u16(data, &mut pos)? as usize;
    let mut reserves = Vec::with_capacity(reserve_count);
    for _ in 0..reserve_count {
        reserves.push(read_reserve(data, &mut pos)?);
    }
    if pos == data.len() {
        return Some(PrivateSnapshot::Purses {
            purses,
            reserves,
            ceilings: Vec::new(),
            charges: Vec::new(),
            pending: Vec::new(),
            settlements: Vec::new(),
        });
    }
    let ceiling_count = read_u16(data, &mut pos)? as usize;
    let mut ceilings = Vec::with_capacity(ceiling_count);
    for _ in 0..ceiling_count {
        ceilings.push(read_run_limit(data, &mut pos)?);
    }
    let line_count = read_u16(data, &mut pos)? as usize;
    let mut charges = Vec::with_capacity(line_count);
    for _ in 0..line_count {
        charges.push(read_line(data, &mut pos)?);
    }
    let pending_count = read_u16(data, &mut pos)? as usize;
    let mut pending = Vec::with_capacity(pending_count);
    for _ in 0..pending_count {
        pending.push(read_pending(data, &mut pos)?);
    }
    if pos == data.len() {
        return Some(PrivateSnapshot::Purses {
            purses,
            reserves,
            ceilings,
            charges,
            pending,
            settlements: Vec::new(),
        });
    }
    let settlement_count = read_u16(data, &mut pos)? as usize;
    let mut settlements = Vec::with_capacity(settlement_count);
    for _ in 0..settlement_count {
        settlements.push(read_settlement(data, &mut pos)?);
    }
    read_month_tail(data, &mut pos, &mut purses, &mut reserves)?;
    Some(PrivateSnapshot::Purses { purses, reserves, ceilings, charges, pending, settlements })
}

/// Kind and month for each purse, then the month of each reserve. Missing
/// tail means fixed purses and reserve month 0. A purse id that is not in
/// the snapshot is skipped.
fn read_month_tail(
    data: &[u8],
    pos: &mut usize,
    purses: &mut [Purse],
    reserves: &mut [PaymentReserve],
) -> Option<()> {
    if *pos == data.len() {
        return Some(());
    }
    let purse_count = read_u16(data, pos)? as usize;
    for _ in 0..purse_count {
        let id: Uuid = read_arr(data, pos)?;
        let kind = *data.get(*pos)?;
        *pos += 1;
        let period_bytes: [u8; 4] = read_arr(data, pos)?;
        let period = u32::from_be_bytes(period_bytes);
        if let Some(purse) = purses.iter_mut().find(|purse| purse.id == id) {
            purse.kind = kind;
            purse.period = period;
        }
    }
    if *pos == data.len() {
        return Some(());
    }
    let reserve_count = read_u16(data, pos)? as usize;
    for _ in 0..reserve_count {
        let id: Uuid = read_arr(data, pos)?;
        let period_bytes: [u8; 4] = read_arr(data, pos)?;
        let period = u32::from_be_bytes(period_bytes);
        if let Some(reserve) = reserves.iter_mut().find(|reserve| reserve.payment_id == id) {
            reserve.period = period;
        }
    }
    if *pos != data.len() {
        return None;
    }
    Some(())
}

fn apply_private_state(blob: &[u8], ctx: &WorkerContext) -> bool {
    let Some(snapshot) = read_private_snapshot(blob) else {
        return false;
    };
    if let PrivateSnapshot::Purses { purses, reserves, ceilings, charges, pending, settlements } = snapshot {
        let mut node = ctx.node.write().unwrap();
        node.owner.purses = purses;
        node.owner.reserves = reserves;
        node.owner.run_limits = ceilings;
        node.owner.charges = charges;
        node.owner.pending_accepts = pending;
        node.owner.settlements = settlements;
    }
    true
}

fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    let bytes: [u8; 2] = read_arr(data, pos)?;
    Some(u16::from_be_bytes(bytes))
}

struct PolicySnapshot {
    grants: Vec<AppGrant>,
    they_accept: Vec<(Uuid, Vec<String>)>,
    inbound: Vec<AppInvitation>,
    seen: Vec<String>,
    outbound: Vec<AppInvitation>,
}

fn push_policy_snapshot(buf: &mut Vec<u8>, node: &Node) {
    buf.push(POLICY_MARKER);
    push_u16(buf, node.owner.app_grants.len().min(u16::MAX as usize) as u16);
    for grant in node.owner.app_grants.iter().take(u16::MAX as usize) {
        buf.extend_from_slice(&grant.contact_uuid);
        push_str(buf, &grant.app_alias);
    }
    let with_accept: Vec<&Contact> = node
        .owner
        .contact_users
        .iter()
        .filter(|c| !c.they_accept.is_empty())
        .collect();
    push_u16(buf, with_accept.len().min(u16::MAX as usize) as u16);
    for contact in with_accept.iter().take(u16::MAX as usize) {
        buf.extend_from_slice(&contact.user.uuid);
        buf.push(contact.they_accept.len().min(u8::MAX as usize) as u8);
        for alias in contact.they_accept.iter().take(u8::MAX as usize) {
            push_str(buf, alias);
        }
    }
    push_invite_list(buf, &node.owner.app_invitations);
    push_u16(buf, node.owner.seen_app_invitation_ids.len().min(u16::MAX as usize) as u16);
    for hex_id in node.owner.seen_app_invitation_ids.iter().take(u16::MAX as usize) {
        if let Some(id) = uuid_from_hex(hex_id) {
            buf.extend_from_slice(&id);
        } else {
            buf.extend_from_slice(&[0u8; 16]);
        }
    }
    push_invite_list(buf, &node.owner.outbound_app_invitations);
}

fn push_invite_list(buf: &mut Vec<u8>, invites: &[AppInvitation]) {
    push_u16(buf, invites.len().min(u16::MAX as usize) as u16);
    for invite in invites.iter().take(u16::MAX as usize) {
        buf.extend_from_slice(&invite.id);
        buf.extend_from_slice(&invite.contact_uuid);
        push_str(buf, &invite.app_alias);
    }
}

fn read_policy_snapshot(data: &[u8], pos: &mut usize) -> Option<PolicySnapshot> {
    if *pos >= data.len() || data[*pos] != POLICY_MARKER {
        return None;
    }
    *pos += 1;
    let grant_count = read_u16(data, pos)? as usize;
    let mut grants = Vec::with_capacity(grant_count);
    for _ in 0..grant_count {
        let contact_uuid: Uuid = read_arr(data, pos)?;
        grants.push(AppGrant { contact_uuid, app_alias: read_str(data, pos)? });
    }
    let they_count = read_u16(data, pos)? as usize;
    let mut they_accept = Vec::with_capacity(they_count);
    for _ in 0..they_count {
        let contact_uuid: Uuid = read_arr(data, pos)?;
        let n = *data.get(*pos)? as usize;
        *pos += 1;
        let mut aliases = Vec::with_capacity(n);
        for _ in 0..n {
            aliases.push(read_str(data, pos)?);
        }
        they_accept.push((contact_uuid, aliases));
    }
    let inbound = read_invite_list(data, pos)?;
    let seen_count = read_u16(data, pos)? as usize;
    let mut seen = Vec::with_capacity(seen_count);
    for _ in 0..seen_count {
        let id: Uuid = read_arr(data, pos)?;
        seen.push(uuid_hex(&id));
    }
    let outbound = read_invite_list(data, pos)?;
    Some(PolicySnapshot { grants, they_accept, inbound, seen, outbound })
}

fn read_invite_list(data: &[u8], pos: &mut usize) -> Option<Vec<AppInvitation>> {
    let count = read_u16(data, pos)? as usize;
    let mut invites = Vec::with_capacity(count);
    for _ in 0..count {
        let id: Uuid = read_arr(data, pos)?;
        let contact_uuid: Uuid = read_arr(data, pos)?;
        invites.push(AppInvitation {
            id,
            contact_uuid,
            app_alias: read_str(data, pos)?,
        });
    }
    Some(invites)
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
pub(crate) fn apply_public_state(state: &[u8], ctx: &WorkerContext) -> bool {
    let mut pos = 0usize;

    let Some(user_alias) = read_str(state, &mut pos) else { return false; };
    let Some(user_uuid)  = read_arr::<16>(state, &mut pos) else { return false; };

    let Some(&dev_count) = state.get(pos) else { return false; };
    pos += 1;

    // Parse all devices into a temp vec first so a malformed blob can't
    // half-apply.
    struct ParsedDevice {
        device: Device,
        apps:   Vec<ContactAppCard>,
    }
    let mut devices: Vec<ParsedDevice> = Vec::with_capacity(dev_count as usize);
    for _ in 0..dev_count {
        let Some(d) = read_device(state, &mut pos) else { return false; };
        let Some(&app_count) = state.get(pos) else { return false; };
        pos += 1;
        let mut apps = Vec::with_capacity(app_count as usize);
        for _ in 0..app_count {
            let Some(app) = read_public_app(state, &mut pos) else { return false; };
            apps.push(app);
        }
        devices.push(ParsedDevice { device: d, apps });
    }

    let Some(&contact_count) = state.get(pos) else { return false; };
    pos += 1;

    struct ParsedContact {
        alias:      String,
        uuid:       Uuid,
        public_key: Ed25519PublicKey,
        devices:    Vec<ParsedDevice>,
    }
    let mut contacts: Vec<ParsedContact> = Vec::with_capacity(contact_count as usize);
    for _ in 0..contact_count {
        let Some(alias)      = read_str(state, &mut pos) else { return false; };
        let Some(uuid)       = read_arr::<16>(state, &mut pos) else { return false; };
        let Some(pk_bytes) = read_arr::<32>(state, &mut pos) else { return false; };
        let public_key = Ed25519PublicKey(pk_bytes);
        let Some(&dc) = state.get(pos) else { return false; };
        pos += 1;
        let mut devs = Vec::with_capacity(dc as usize);
        for _ in 0..dc {
            let Some(d) = read_device(state, &mut pos) else { return false; };
            let Some(&ac) = state.get(pos) else { return false; };
            pos += 1;
            let mut apps = Vec::with_capacity(ac as usize);
            for _ in 0..ac {
                let Some(app) = read_public_app(state, &mut pos) else { return false; };
                apps.push(app);
            }
            devs.push(ParsedDevice { device: d, apps });
        }
        contacts.push(ParsedContact { alias, uuid, public_key, devices: devs });
    }

    let policy = if pos < state.len() && state[pos] == POLICY_MARKER {
        let Some(parsed) = read_policy_snapshot(state, &mut pos) else { return false; };
        Some(parsed)
    } else {
        None
    };

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
            existing.alias   = p.alias.clone();
            existing.grade   = p.grade;
            existing.sg_rank = p.sg_rank;
            existing.hosts   = p.hosts.clone();
            if existing.cert_sig == Ed25519Signature::ZERO && p.cert_sig != Ed25519Signature::ZERO {
                existing.signing_pk = p.signing_pk;
                existing.dh_pk = p.dh_pk;
                existing.cert_sig = p.cert_sig;
                existing.cert_issued_at = p.cert_issued_at;
                existing.cert_alias = p.cert_alias.clone();
            }
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
                for app in apps {
                    if existing_ids.contains(&app.id) { continue; }
                    existing.applications.push(application_from_public(&app));
                }
            } else {
                // Peer device: authoritative — drop apps the writer no longer
                // reports, so RemoveApplication propagates.
                let incoming_ids: HashSet<Uuid> = apps.iter().map(|a| a.id).collect();
                existing.applications.retain(|a| incoming_ids.contains(&a.id));
                for app in apps {
                    if let Some(local_app) = existing.applications.iter_mut().find(|a| a.id == app.id) {
                        merge_app_public(local_app, &app, true);
                    } else {
                        existing.applications.push(application_from_public(&app));
                    }
                }
            }
        } else {
            let mut new_dev = p;
            for app in apps {
                new_dev.applications.push(application_from_public(&app));
            }
            node.owner.user.devices.push(new_dev);
        }
    }

    for c in contacts {
        let devs_from = |parsed: Vec<ParsedDevice>| -> Vec<Device> {
            parsed.into_iter().map(|p| {
                let mut dev = p.device;
                for app in p.apps {
                    dev.applications.push(application_from_public(&app));
                }
                dev
            }).collect()
        };
        if let Some(existing) = node.owner.contact_users.iter_mut().find(|x| x.user.uuid == c.uuid) {
            existing.user.alias = c.alias;
            existing.public_key = c.public_key;
            // Replace the contact's device list — we don't have local
            // private fields to preserve for contact-owned apps.
            existing.user.devices = devs_from(c.devices);
        } else {
            node.owner.contact_users.push(Contact {
                public_key: c.public_key,
                user: User { alias: c.alias, uuid: c.uuid, devices: devs_from(c.devices) },
                they_accept: Vec::new(),
                last_seen_public_version: SyncVersion::default(),
            });
        }
    }

    if let Some(policy) = policy {
        node.owner.app_grants = policy.grants;
        node.owner.app_invitations = policy.inbound;
        node.owner.seen_app_invitation_ids = policy.seen;
        node.owner.outbound_app_invitations = policy.outbound;
        for contact in &mut node.owner.contact_users {
            contact.they_accept.clear();
        }
        for (uuid, aliases) in policy.they_accept {
            if let Some(contact) = node.owner.contact_users.iter_mut().find(|c| c.user.uuid == uuid) {
                contact.they_accept = aliases;
            }
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

    let Some(mut change) = deserialize_change(&plaintext) else {
        eprintln!("[sync_write_request] unparseable change from {src}");
        return;
    };
    let reserve_payment = match &change {
        Change::ReservePayment { reserve } => Some(reserve.payment_id),
        _ => None,
    };

    let (target, local_uuid) = {
        let node = ctx.node.read().unwrap();
        (find_writer_sg(&node), node.device_uuid)
    };

    let (result, private_v, public_v, bumped, failure_code) = match target {
        WriterTarget::Local => {
            if let Change::ReservePayment { reserve } = &mut change {
                // The sender's clock is not the hold. Stamp it here, after the
                // month roll, so a forwarded reserve uses this writer's time.
                release_expired_reserves(ctx);
                reserve.expires_at_ms = unix_time_ms().saturating_add(RESERVE_TTL_MS);
                let purse_id = reserve.purse_id;
                reserve.period = {
                    let node = ctx.node.read().unwrap();
                    node.owner.purses.iter().find(|purse| purse.id == purse_id).map(|purse| {
                        if purse.kind == PURSE_KIND_MONTHLY { purse.period } else { 0 }
                    }).unwrap_or(0)
                };
            }
            let (pre_priv, pre_pub) = {
                let node = ctx.node.read().unwrap();
                (node.owner.private_version, node.owner.public_version)
            };
            match apply_change_locally(&change, local_uuid, ctx) {
                Ok((priv_v, pub_v)) => {
                    let bumped = bumped_scopes(pre_priv, pre_pub, priv_v, pub_v);
                    (WRITE_ACK_OK, priv_v, pub_v, bumped, None)
                }
                Err(WriteError::Validation(msg)) => {
                    eprintln!("[sync_write_request] validation error from {src}: {msg}");
                    let node = ctx.node.read().unwrap();
                    (WRITE_ACK_VALIDATION_ERROR, node.owner.private_version, node.owner.public_version, Vec::new(), Some(ERR_BAD_PACKET))
                }
                Err(WriteError::ReserveRejected(reason)) => {
                    eprintln!("[sync_write_request] reserve rejected from {src}: {reason:?}");
                    let code = match reason {
                        ReserveReject::NotMember => ERR_NOT_IN_PURSE,
                        ReserveReject::OverPurse => ERR_OVER_PURSE,
                        ReserveReject::Mismatch => ERR_PAYMENT_MISMATCH,
                    };
                    let node = ctx.node.read().unwrap();
                    (WRITE_ACK_VALIDATION_ERROR, node.owner.private_version, node.owner.public_version, Vec::new(), Some(code))
                }
                Err(WriteError::PaymentRejected(reason)) => {
                    eprintln!("[sync_write_request] payment rejected from {src}: {reason:?}");
                    let node = ctx.node.read().unwrap();
                    (WRITE_ACK_VALIDATION_ERROR, node.owner.private_version, node.owner.public_version, Vec::new(), Some(ERR_PAYMENT_MISMATCH))
                }
                Err(WriteError::Unreachable) => {
                    // Cannot occur in the Local branch — defensive only.
                    let node = ctx.node.read().unwrap();
                    (WRITE_ACK_VALIDATION_ERROR, node.owner.private_version, node.owner.public_version, Vec::new(), Some(ERR_NO_WRITER))
                }
            }
        }
        WriterTarget::Remote(_) | WriterTarget::Unreachable => {
            let node = ctx.node.read().unwrap();
            (WRITE_ACK_NOT_WRITER, node.owner.private_version, node.owner.public_version, Vec::new(), Some(ERR_NO_WRITER))
        }
    };

    let mut body = build_write_ack_body(result, private_v, public_v);
    if let Some(payment_id) = reserve_payment {
        let (code, available, expires_at_ms) = if result == WRITE_ACK_OK {
            stored_reserve_reply(ctx, payment_id)
                .map(|(available, expires_at_ms)| (0, available, expires_at_ms))
                .unwrap_or((ERR_PAYMENT_MISMATCH, 0, 0))
        } else {
            (failure_code.unwrap_or(ERR_BAD_PACKET), 0, 0)
        };
        body.extend_from_slice(&payment_id);
        body.push(code);
        body.extend_from_slice(&available.to_be_bytes());
        body.extend_from_slice(&expires_at_ms.to_be_bytes());
    }
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
    if result == WRITE_ACK_OK {
        if let Some(payment_id) = reserve_payment {
            super::payment::deliver_payment(ctx, payment_id);
        }
    }

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
    // A forwarded reserve continues past the versions: payment id, app code,
    // available, expiry. An older ack ends here and is not a reserve result.
    let Some(payment_id) = slice_arr::<16>(&plaintext, pos) else { return };
    let Some(code) = plaintext.get(pos + 16).copied() else { return };
    let Some(available) = slice_arr::<8>(&plaintext, pos + 17) else { return };
    let Some(expires_at_ms) = slice_arr::<8>(&plaintext, pos + 25) else { return };
    super::finish_forwarded_reserve(
        ctx,
        payment_id,
        code,
        i64::from_be_bytes(available),
        u64::from_be_bytes(expires_at_ms),
    );
}

fn stored_reserve_reply(ctx: &WorkerContext, payment_id: Uuid) -> Option<(i64, u64)> {
    let node = ctx.node.read().unwrap();
    if let Some(hold) = node.owner.reserves.iter().find(|hold| hold.payment_id == payment_id) {
        let purse = node.owner.purses.iter().find(|purse| purse.id == hold.purse_id)?;
        return Some((purse.available_nanodollars, hold.expires_at_ms));
    }
    let line = node.owner.charges.iter().find(|line| line.payment_id == payment_id)?;
    let purse = node.owner.purses.iter().find(|purse| purse.id == line.purse_id)?;
    Some((purse.available_nanodollars, line.expires_at_ms))
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
/// Private-scope pulls return the purse snapshot. Contacts are not offered
/// this scope; cross-user sync stays on the public blob.
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
            Scope::Private => serialize_private_state(&node),
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
                Scope::Private => apply_private_state(state_blob, ctx),
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
        let contact_uuid = node.owner.active_connections.get(&conn_id).and_then(|conn| {
            let peer = conn.device_uuid;
            node.owner.contact_users.iter()
                .find(|c| c.user.devices.iter().any(|d| d.uuid == peer))
                .map(|c| c.user.uuid)
        });
        // An unknown peer gets an empty allow list, so no apps and no invitations.
        let blob = serialize_contact_data_for(&node, contact_uuid.unwrap_or([0u8; 16]));
        (node.owner.public_version, blob)
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
                        signing_pk: d.signing_pk,
                        dh_pk: d.dh_pk,
                        cert_sig: d.cert_sig,
                        cert_issued_at: d.cert_issued_at,
                        cert_alias: d.cert_alias.clone(),
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
                let accepted = match &data.accepted_aliases {
                    Some(list) => list.clone(),
                    None => data.devices.iter()
                        .flat_map(|(_, apps)| apps.iter().map(|a| a.alias.clone()))
                        .collect(),
                };
                let _ = request_change_idempotent(Change::SetContactTheyAccept {
                    contact_uuid: data.user_uuid,
                    aliases: accepted,
                }, ctx);
                let seen = {
                    let node = ctx.node.read().unwrap();
                    node.owner.seen_app_invitation_ids.clone()
                };
                let pending = {
                    let node = ctx.node.read().unwrap();
                    node.owner.app_invitations.iter().map(|i| i.id).collect::<Vec<_>>()
                };
                for (id, app_alias) in &data.invitations {
                    if invitation_seen(&seen, *id) || pending.contains(id) {
                        continue;
                    }
                    let _ = request_change_idempotent(Change::PutAppInvitation {
                        id: *id,
                        contact_uuid: data.user_uuid,
                        app_alias: app_alias.clone(),
                    }, ctx);
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
    node: &Node,
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

pub(crate) fn serialize_watermark_map(scope: Scope, map: &[(Uuid, SyncVersion)]) -> Vec<u8> {
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

pub(crate) fn parse_watermark_map(data: &[u8]) -> Option<(Scope, Vec<(Uuid, SyncVersion)>)> {
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

    // §7.1: never ship an incomplete log slice past a pruned watermark —
    // signal retention-exhausted so the peer adopts full state with visibility.
    let gap_writer = {
        let node = ctx.node.read().unwrap();
        retention_gap_for_peer(&node, peer_uuid, scope)
    };
    let (sender_version, body) = if let Some(writer) = gap_writer {
        let detail = format!(
            "peer={} writer={} scope={scope:?}",
            uuid_hex(&peer_uuid),
            uuid_hex(&writer)
        );
        {
            let mut node = ctx.node.write().unwrap();
            node.owner.retention_fallback_active = true;
            node.owner.retention_fallback_detail = detail.clone();
        }
        fabric_event(
            "retention_fallback",
            &[
                ("role", "proposer"),
                ("peer", &uuid_hex(&peer_uuid)),
                ("writer", &uuid_hex(&writer)),
                ("scope", &format!("{scope:?}")),
            ],
        );
        let sender_version = {
            let node = ctx.node.read().unwrap();
            match scope {
                Scope::Public => node.owner.public_version,
                Scope::Private => node.owner.private_version,
            }
        };
        (
            sender_version,
            build_retention_exhausted_proposal_body(scope, sender_version),
        )
    } else {
        let (sender_version, entries) =
            build_merge_proposal_for_peer(peer_uuid, scope, ctx);
        (
            sender_version,
            build_merge_proposal_body(scope, sender_version, &entries),
        )
    };
    let _ = sender_version;
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

pub(crate) fn build_merge_proposal_body(
    scope: Scope,
    sender_version: SyncVersion,
    entries: &[WriteLogEntry],
) -> Vec<u8> {
    let count = entries.len().min((MERGE_PROPOSAL_RETENTION_SENTINEL - 1) as usize) as u16;
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

/// Merge proposal body with retention-exhausted sentinel (no entries).
pub(crate) fn build_retention_exhausted_proposal_body(
    scope: Scope,
    sender_version: SyncVersion,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + SYNC_VERSION_WIRE_LEN + 2);
    write_scope(&mut buf, scope);
    write_sync_version(&mut buf, &sender_version);
    buf.extend_from_slice(&MERGE_PROPOSAL_RETENTION_SENTINEL.to_be_bytes());
    buf
}

/// Parsed merge proposal: normal entry list, or peer signaled retention gap.
#[derive(Debug)]
pub(crate) enum ParsedMergeProposal {
    Entries {
        scope: Scope,
        sender_version: SyncVersion,
        entries: Vec<WriteLogEntry>,
    },
    /// Peer's log cannot fill the gap to our watermark — full-state fallback.
    RetentionExhausted {
        scope: Scope,
        sender_version: SyncVersion,
    },
}

pub(crate) fn parse_merge_proposal_body(data: &[u8]) -> Option<ParsedMergeProposal> {
    let mut pos = 0usize;
    let scope = read_scope(data, &mut pos)?;
    let sender_version = read_sync_version(data, &mut pos)?;
    let cnt_bytes: [u8; 2] = read_arr(data, &mut pos)?;
    let cnt_u16 = u16::from_be_bytes(cnt_bytes);
    if cnt_u16 == MERGE_PROPOSAL_RETENTION_SENTINEL {
        return Some(ParsedMergeProposal::RetentionExhausted {
            scope,
            sender_version,
        });
    }
    let cnt = cnt_u16 as usize;
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
    Some(ParsedMergeProposal::Entries {
        scope,
        sender_version,
        entries,
    })
}

/// True when peer's agreed watermark for some writer sits **below** the oldest
/// retained log entry for that writer — we pruned history the peer still needs.
pub(crate) fn retention_gap_for_peer(
    node: &Node,
    peer_uuid: Uuid,
    scope: Scope,
) -> Option<Uuid> {
    let wms = node.owner.last_watermarks.get(&peer_uuid)?;
    for (writer, peer_v) in wms {
        if peer_v.is_initial() {
            continue;
        }
        let mut oldest: Option<&WriteLogEntry> = None;
        for e in &node.owner.write_log {
            if e.scope != scope || e.version.writer_sg_uuid != *writer {
                continue;
            }
            let older = oldest
                .map(|o| {
                    (e.version.epoch, e.version.seq) < (o.version.epoch, o.version.seq)
                })
                .unwrap_or(true);
            if older {
                oldest = Some(e);
            }
        }
        let Some(oldest) = oldest else {
            continue;
        };
        // Peer watermark behind our oldest retained entry for this writer.
        if (peer_v.epoch, peer_v.seq) < (oldest.version.epoch, oldest.version.seq) {
            let peer_exact = node.owner.write_log.iter().any(|e| {
                e.scope == scope
                    && e.version.writer_sg_uuid == *writer
                    && e.version.epoch == peer_v.epoch
                    && e.version.seq == peer_v.seq
            });
            if !peer_exact {
                return Some(*writer);
            }
        }
    }
    None
}

pub(crate) fn build_merge_ack_body(scope: Scope, new_watermark: SyncVersion, result: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + SYNC_VERSION_WIRE_LEN + 1);
    write_scope(&mut buf, scope);
    write_sync_version(&mut buf, &new_watermark);
    buf.push(result);
    buf
}

pub(crate) fn parse_merge_ack_body(data: &[u8]) -> Option<(Scope, SyncVersion, u8)> {
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
pub(crate) fn build_merge_proposal_for_peer(
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

    let Some(parsed) = parse_merge_proposal_body(&plaintext) else {
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

    let is_own_sg = {
        let node = ctx.node.read().unwrap();
        is_own_user_sg(&node.owner, peer_uuid)
    };

    // §7.1 retention-exhausted signal from peer: adopt full state via pull;
    // never silently discard local-only concurrent writes without visibility.
    if let ParsedMergeProposal::RetentionExhausted {
        scope,
        sender_version,
    } = &parsed
    {
        if !is_own_sg {
            send_merge_ack(
                conn_id,
                *scope,
                SyncVersion::zero(),
                MERGE_ACK_RESULT_MALFORMED,
                ctx,
            );
            return;
        }
        {
            let mut node = ctx.node.write().unwrap();
            node.owner.retention_fallback_active = true;
            node.owner.retention_fallback_detail = format!(
                "peer signaled retention-exhausted scope={scope:?} \
                 peer_version=(epoch={},seq={})",
                sender_version.epoch, sender_version.seq
            );
        }
        fabric_event(
            "retention_fallback",
            &[
                ("role", "receiver"),
                ("peer", &uuid_hex(&peer_uuid)),
                ("scope", &format!("{scope:?}")),
                ("action", "full_state_pull"),
            ],
        );
        let local_v = {
            let node = ctx.node.read().unwrap();
            node.owner.version(*scope)
        };
        send_pull_request(*scope, local_v, conn_id, ctx);
        send_merge_ack(
            conn_id,
            *scope,
            local_v,
            MERGE_ACK_RESULT_RETENTION_EXHAUSTED,
            ctx,
        );
        return;
    }

    let ParsedMergeProposal::Entries {
        scope,
        sender_version,
        entries,
    } = parsed
    else {
        return;
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

    // §7.2: drop sessions/tunnels after directory removes (needs Node lock).
    for change in &merged.changes_to_apply {
        if matches!(
            change,
            Change::RemoveDevice { .. } | Change::RemoveContact { .. }
        ) {
            cascade_remove_fabric_state(ctx, change);
        }
    }

    if !merged.new_entries.is_empty() || any_state_change {
        ctx.save_node();
    }

    // Successful log merge clears any prior retention-fallback warning.
    if !merged.new_entries.is_empty() || any_state_change {
        {
            let mut node = ctx.node.write().unwrap();
            if node.owner.retention_fallback_active {
                node.owner.retention_fallback_active = false;
                node.owner.retention_fallback_detail.clear();
            }
        }
        fabric_event(
            "merge_applied",
            &[
                ("peer", &uuid_hex(&peer_uuid)),
                ("scope", &format!("{scope:?}")),
                ("new_entries", &merged.new_entries.len().to_string()),
                ("changes", &merged.changes_to_apply.len().to_string()),
            ],
        );
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
    fabric_event(
        "merge_ack",
        &[
            ("result", result_str),
            ("scope", &format!("{scope:?}")),
            ("epoch", &new_watermark.epoch.to_string()),
            ("seq", &new_watermark.seq.to_string()),
        ],
    );
    if result == MERGE_ACK_RESULT_RETENTION_EXHAUSTED {
        let mut node = ctx.node.write().unwrap();
        node.owner.retention_fallback_active = true;
        if node.owner.retention_fallback_detail.is_empty() {
            node.owner.retention_fallback_detail =
                "peer reported retention-exhausted on our merge proposal".into();
        }
    }
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
    /// (contact, alias) → (allowed, priority of the winning write).
    grants: HashMap<(Uuid, String), (bool, EntryPriority)>,
    inbound: HashMap<Uuid, (Uuid, String)>,
    inbound_tomb: HashSet<Uuid>,
    outbound: HashMap<Uuid, (Uuid, String)>,
    outbound_tomb: HashSet<Uuid>,
    they_accept: HashMap<Uuid, (Vec<String>, EntryPriority)>,
    /// purse id → winning whole-purse snapshot.
    purses: HashMap<Uuid, (Purse, EntryPriority)>,
    /// payment id → hold still outstanding after the log is replayed in order.
    reserves: HashMap<Uuid, PaymentReserve>,
    /// payment id → confirmed lines, in the order they were recorded.
    /// Two signed bodies of one id are both kept.
    charges: HashMap<Uuid, Vec<Charge>>,
    /// payment id → staged accept that is not yet a line.
    pending: HashMap<Uuid, PendingAccept>,
    /// settlement id → dual-signed records. Two bodies of one id are both kept.
    settlements: HashMap<Uuid, Vec<Settlement>>,
    /// payer → (ceiling, priority of the write that set it).
    ceilings: HashMap<Uuid, (i64, EntryPriority)>,
}

/// Per-contact accumulator: the winning snapshot plus the priority of the
/// entry that set it.
struct MergedContact {
    alias:      String,
    public_key: Ed25519PublicKey,
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
    signing_pk: Ed25519PublicKey,
    cert_sig: Ed25519Signature,
    cert_issued_at: u64,
    cert_alias: String,
}

#[derive(Clone)]
struct MergedDevice {
    alias:   String,
    grade:   DeviceGrade,
    sg_rank: Option<u32>,
    hosts:   Vec<String>,
    signing_pk: Ed25519PublicKey,
    dh_pk: X25519PublicKey,
    cert_sig: Ed25519Signature,
    cert_issued_at: u64,
    cert_alias: String,
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
        grants: HashMap::new(),
        inbound: HashMap::new(),
        inbound_tomb: HashSet::new(),
        outbound: HashMap::new(),
        outbound_tomb: HashSet::new(),
        they_accept: HashMap::new(),
        purses: HashMap::new(),
        reserves: HashMap::new(),
        charges: HashMap::new(),
        pending: HashMap::new(),
        settlements: HashMap::new(),
        ceilings: HashMap::new(),
    };

    // First pass: collect tombstones. Tombstone wins globally for its target,
    // regardless of `(epoch, seq)` of any conflicting Add/Upsert.
    let mut device_tombstones: HashSet<Uuid> = HashSet::new();
    let mut contact_tombstones: HashSet<Uuid> = HashSet::new();
    for e in &entries {
        match deserialize_change(&e.change_payload) {
            Some(Change::RemoveApplication { device_uuid, app_id }) => {
                state.tombstones.insert((device_uuid, app_id));
            }
            Some(Change::RemoveDevice { uuid }) => {
                device_tombstones.insert(uuid);
            }
            Some(Change::RemoveContact { uuid }) => {
                contact_tombstones.insert(uuid);
            }
            Some(Change::ForgetAppInvitation { id }) => {
                state.inbound_tomb.insert(id);
            }
            Some(Change::ForgetOutboundAppInvitation { id }) => {
                state.outbound_tomb.insert(id);
            }
            _ => {}
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
            Change::AddApplication {
                device_uuid, app_id, app_alias, signing_pk, cert_sig, cert_issued_at, cert_alias,
            } => {
                if state.tombstones.contains(&(device_uuid, app_id)) { continue; }
                upsert_alias(
                    &mut state.apps, (device_uuid, app_id), app_alias, prio, true,
                    signing_pk, cert_sig, cert_issued_at, cert_alias,
                );
            }
            Change::UpdateApplicationAlias { device_uuid, app_id, new_alias } => {
                if state.tombstones.contains(&(device_uuid, app_id)) { continue; }
                upsert_alias(
                    &mut state.apps, (device_uuid, app_id), new_alias, prio, false,
                    Ed25519PublicKey::ZERO, Ed25519Signature::ZERO, 0, String::new(),
                );
            }
            Change::AddDevice {
                uuid, alias, grade, sg_rank, hosts, signing_pk, dh_pk, cert_sig, cert_issued_at, cert_alias,
            } => {
                if device_tombstones.contains(&uuid) {
                    continue;
                }
                match state.devices.get_mut(&uuid) {
                    Some(existing) if existing.cert_sig == Ed25519Signature::ZERO
                        && cert_sig != Ed25519Signature::ZERO =>
                    {
                        existing.signing_pk = signing_pk;
                        existing.dh_pk = dh_pk;
                        existing.cert_sig = cert_sig;
                        existing.cert_issued_at = cert_issued_at;
                        existing.cert_alias = cert_alias;
                    }
                    Some(_) => {}
                    None => {
                        state.devices.insert(uuid, MergedDevice {
                            alias, grade, sg_rank, hosts,
                            signing_pk, dh_pk, cert_sig, cert_issued_at, cert_alias,
                        });
                    }
                }
            }
            Change::UpsertContact { uuid, alias, public_key, devices } => {
                if contact_tombstones.contains(&uuid) {
                    continue;
                }
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
            Change::RemoveDevice { .. } | Change::RemoveContact { .. } => {}
            Change::SetAppGrant { contact_uuid, app_alias, allowed } => {
                if contact_tombstones.contains(&contact_uuid) {
                    continue;
                }
                let key = (contact_uuid, app_alias);
                match state.grants.get(&key) {
                    Some((_, prev)) if *prev >= prio => {}
                    _ => { state.grants.insert(key, (allowed, prio)); }
                }
            }
            Change::PutAppInvitation { id, contact_uuid, app_alias } => {
                if state.inbound_tomb.contains(&id) || contact_tombstones.contains(&contact_uuid) {
                    continue;
                }
                state.inbound.entry(id).or_insert((contact_uuid, app_alias));
            }
            Change::PutOutboundAppInvitation { id, contact_uuid, app_alias } => {
                if state.outbound_tomb.contains(&id) || contact_tombstones.contains(&contact_uuid) {
                    continue;
                }
                state.outbound.entry(id).or_insert((contact_uuid, app_alias));
            }
            Change::ForgetAppInvitation { .. } | Change::ForgetOutboundAppInvitation { .. } => {}
            Change::SetContactTheyAccept { contact_uuid, aliases } => {
                if contact_tombstones.contains(&contact_uuid) {
                    continue;
                }
                let win = match state.they_accept.get(&contact_uuid) {
                    Some((_, prev)) => prio > *prev,
                    None => true,
                };
                if win {
                    let mut next = aliases;
                    next.sort();
                    next.dedup();
                    state.they_accept.insert(contact_uuid, (next, prio));
                }
            }
            Change::UpsertPurse { purse } => {
                if purse.allotment_nanodollars < 0
                    || purse.name.trim().is_empty()
                    || (purse.kind != PURSE_KIND_FIXED && purse.kind != PURSE_KIND_MONTHLY)
                {
                    continue;
                }
                let mut purse = purse.normalized();
                if purse.kind == PURSE_KIND_FIXED {
                    purse.period = 0;
                }
                let win = match state.purses.get(&purse.id) {
                    Some((_, prev)) => prio > *prev,
                    None => true,
                };
                if win {
                    state.purses.insert(purse.id, (purse, prio));
                }
            }
            Change::ReservePayment { reserve } => {
                replay_reserve(&mut state, reserve);
            }
            Change::ReleaseReserve { payment_id } => {
                replay_release(&mut state, payment_id);
            }
            Change::RecordCharge { line } => {
                replay_record(&mut state, line);
            }
            Change::StageAccept { pending } => {
                replay_stage(&mut state, pending);
            }
            Change::DropAccept { payment_id } => {
                state.pending.remove(&payment_id);
            }
            Change::RecordSettlement { record } => {
                replay_settlement(&mut state, record);
            }
            Change::SetRunLimit { payer, max_nanodollars } => {
                if max_nanodollars < 0 {
                    continue;
                }
                let win = match state.ceilings.get(&payer) {
                    Some((_, prev)) => prio > *prev,
                    None => true,
                };
                if win {
                    state.ceilings.insert(payer, (max_nanodollars, prio));
                }
            }
        }
    }

    // Devices tombstoned must not appear even if only Adds were seen first.
    for u in &device_tombstones {
        state.devices.remove(u);
        state.apps.retain(|(d, _), _| d != u);
    }
    for u in &contact_tombstones {
        state.contacts.remove(u);
        state.grants.retain(|(contact, _), _| contact != u);
        state.inbound.retain(|_, (contact, _)| contact != u);
        state.outbound.retain(|_, (contact, _)| contact != u);
        state.they_accept.remove(u);
    }
    state.inbound.retain(|id, _| !state.inbound_tomb.contains(id));
    state.outbound.retain(|id, _| !state.outbound_tomb.contains(id));

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
    signing_pk: Ed25519PublicKey,
    cert_sig: Ed25519Signature,
    cert_issued_at: u64,
    cert_alias: String,
) {
    let is_update = !sets_existence;
    match apps.get_mut(&key) {
        Some(slot) => {
            if sets_existence { slot.existed = true; }
            let prev_prio = slot.alias_priority;
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
            if sets_existence
                && cert_sig != Ed25519Signature::ZERO
                && (slot.cert_sig == Ed25519Signature::ZERO || prio > prev_prio)
            {
                slot.signing_pk = signing_pk;
                slot.cert_sig = cert_sig;
                slot.cert_issued_at = cert_issued_at;
                slot.cert_alias = cert_alias;
            }
        }
        None => {
            apps.insert(key, MergedApp {
                existed: sets_existence,
                alias,
                alias_priority: prio,
                alias_from_update: is_update,
                signing_pk,
                cert_sig,
                cert_issued_at,
                cert_alias,
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
            signing_pk: dev.signing_pk,
            dh_pk: dev.dh_pk,
            cert_sig: dev.cert_sig,
            cert_issued_at: dev.cert_issued_at,
            cert_alias: dev.cert_alias.clone(),
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
                signing_pk:  app.signing_pk,
                cert_sig:    app.cert_sig,
                cert_issued_at: app.cert_issued_at,
                cert_alias:  app.cert_alias.clone(),
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

    // Devices present locally but absent in target (RemoveDevice tombstone).
    let mut removed_devs: Vec<Uuid> = current
        .devices
        .keys()
        .filter(|u| !target.devices.contains_key(*u))
        .copied()
        .collect();
    removed_devs.sort();
    for uuid in removed_devs {
        out.push(Change::RemoveDevice { uuid });
    }

    // Contacts: upsert new/changed; remove those tombstoned away.
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

    let mut removed_contacts: Vec<Uuid> = current
        .contacts
        .keys()
        .filter(|u| !target.contacts.contains_key(*u))
        .copied()
        .collect();
    removed_contacts.sort();
    for uuid in removed_contacts {
        out.push(Change::RemoveContact { uuid });
    }

    let grant_allowed = |map: &HashMap<(Uuid, String), (bool, EntryPriority)>, key: &(Uuid, String)| {
        map.get(key).is_some_and(|(allowed, _)| *allowed)
    };
    let mut grant_keys: Vec<(Uuid, String)> = current.grants.keys()
        .chain(target.grants.keys())
        .cloned()
        .collect();
    grant_keys.sort();
    grant_keys.dedup();
    for key in grant_keys {
        let now = grant_allowed(&current.grants, &key);
        let want = grant_allowed(&target.grants, &key);
        if now != want {
            out.push(Change::SetAppGrant {
                contact_uuid: key.0,
                app_alias: key.1,
                allowed: want,
            });
        }
    }

    let mut inbound_ids: Vec<Uuid> = current.inbound.keys()
        .chain(target.inbound.keys())
        .copied()
        .collect();
    inbound_ids.sort();
    inbound_ids.dedup();
    for id in inbound_ids {
        match (current.inbound.get(&id), target.inbound.get(&id)) {
            (_, Some((contact, alias))) if current.inbound.get(&id).is_none() => {
                out.push(Change::PutAppInvitation {
                    id,
                    contact_uuid: *contact,
                    app_alias: alias.clone(),
                });
            }
            (Some(_), None) => out.push(Change::ForgetAppInvitation { id }),
            _ => {}
        }
    }

    let mut outbound_ids: Vec<Uuid> = current.outbound.keys()
        .chain(target.outbound.keys())
        .copied()
        .collect();
    outbound_ids.sort();
    outbound_ids.dedup();
    for id in outbound_ids {
        match (current.outbound.get(&id), target.outbound.get(&id)) {
            (_, Some((contact, alias))) if current.outbound.get(&id).is_none() => {
                out.push(Change::PutOutboundAppInvitation {
                    id,
                    contact_uuid: *contact,
                    app_alias: alias.clone(),
                });
            }
            (Some(_), None) => out.push(Change::ForgetOutboundAppInvitation { id }),
            _ => {}
        }
    }

    let mut accept_ids: Vec<Uuid> = current.they_accept.keys()
        .chain(target.they_accept.keys())
        .copied()
        .filter(|id| target.contacts.contains_key(id) || current.contacts.contains_key(id))
        .collect();
    accept_ids.sort();
    accept_ids.dedup();
    for id in accept_ids {
        if !target.contacts.contains_key(&id) {
            continue;
        }
        let want = target.they_accept.get(&id).map(|(a, _)| a.clone()).unwrap_or_default();
        let now = current.they_accept.get(&id).map(|(a, _)| a.clone()).unwrap_or_default();
        if want != now {
            out.push(Change::SetContactTheyAccept { contact_uuid: id, aliases: want });
        }
    }

    let mut purse_ids: Vec<Uuid> = current.purses.keys()
        .chain(target.purses.keys())
        .copied()
        .collect();
    purse_ids.sort();
    purse_ids.dedup();
    for id in purse_ids {
        let Some((want, _)) = target.purses.get(&id) else { continue };
        let added = reserve_delta(current, target, id).saturating_add(charge_delta(current, target, id));
        let removed = release_delta(current, target, id).saturating_add(charge_delta(target, current, id));
        match current.purses.get(&id) {
            None => {
                let mut purse = want.clone();
                purse.available_nanodollars = net_before_reserve_diff(want.available_nanodollars, added, removed);
                out.push(Change::UpsertPurse { purse });
            }
            Some((now, _)) => {
                let definition_differs = now.name != want.name
                    || now.allotment_nanodollars != want.allotment_nanodollars
                    || now.aliases != want.aliases
                    || now.kind != want.kind
                    || now.period != want.period;
                let predicted = now.available_nanodollars.saturating_sub(added).saturating_add(removed);
                // A hold explains an available-amount change by itself. An
                // upsert is only needed when the definition differs, or when
                // the amount moved for some other reason.
                if definition_differs || predicted != want.available_nanodollars {
                    let mut purse = want.clone();
                    purse.available_nanodollars = net_before_reserve_diff(want.available_nanodollars, added, removed);
                    out.push(Change::UpsertPurse { purse });
                }
            }
        }
    }

    let mut reserve_ids: Vec<Uuid> = current.reserves.keys()
        .chain(target.reserves.keys())
        .copied()
        .collect();
    reserve_ids.sort();
    reserve_ids.dedup();
    for id in reserve_ids {
        match (current.reserves.get(&id), target.reserves.get(&id)) {
            (None, Some(reserve)) => {
                out.push(Change::ReservePayment { reserve: reserve.clone() });
            }
            (Some(_), None) if !target.charges.contains_key(&id) => {
                out.push(Change::ReleaseReserve { payment_id: id });
            }
            _ => {}
        }
    }

    let mut line_ids: Vec<Uuid> = current.charges.keys()
        .chain(target.charges.keys())
        .copied()
        .collect();
    line_ids.sort();
    line_ids.dedup();
    for id in line_ids {
        let current_lines = current.charges.get(&id).map(Vec::as_slice).unwrap_or(&[]);
        let Some(target_lines) = target.charges.get(&id) else { continue };
        // Target order is replay order, so the body that charged is applied first.
        for line in target_lines {
            if current_lines.iter().any(|stored| same_charge(stored, line)) {
                continue;
            }
            out.push(Change::RecordCharge { line: line.clone() });
        }
    }

    let mut pending_ids: Vec<Uuid> = current.pending.keys()
        .chain(target.pending.keys())
        .copied()
        .collect();
    pending_ids.sort();
    pending_ids.dedup();
    for id in pending_ids {
        match (current.pending.get(&id), target.pending.get(&id)) {
            (None, Some(pending)) if !target.charges.contains_key(&id) => {
                out.push(Change::StageAccept { pending: pending.clone() });
            }
            (Some(_), None) if !target.charges.contains_key(&id) => {
                out.push(Change::DropAccept { payment_id: id });
            }
            _ => {}
        }
    }

    let mut settlement_ids: Vec<Uuid> = current.settlements.keys()
        .chain(target.settlements.keys())
        .copied()
        .collect();
    settlement_ids.sort();
    settlement_ids.dedup();
    for id in settlement_ids {
        let current_rows = current.settlements.get(&id).map(Vec::as_slice).unwrap_or(&[]);
        let Some(target_rows) = target.settlements.get(&id) else { continue };
        for record in target_rows {
            if current_rows.iter().any(|stored| stored == record) {
                continue;
            }
            out.push(Change::RecordSettlement { record: record.clone() });
        }
    }

    let mut payers: Vec<Uuid> = current.ceilings.keys()
        .chain(target.ceilings.keys())
        .copied()
        .collect();
    payers.sort();
    payers.dedup();
    for payer in payers {
        let Some((want, _)) = target.ceilings.get(&payer) else { continue };
        match current.ceilings.get(&payer) {
            Some((now, _)) if now == want => {}
            _ => out.push(Change::SetRunLimit { payer, max_nanodollars: *want }),
        }
    }

    out
}

/// Sum of holds on `purse_id` that `current` still has and `target` does not,
/// counting only a release that adds the amount back.
fn release_delta(current: &MergedState, target: &MergedState, purse_id: Uuid) -> i64 {
    let Some((purse, _)) = target.purses.get(&purse_id) else {
        return 0;
    };
    current.reserves.values()
        .filter(|reserve| {
            reserve.purse_id == purse_id
                && !target.reserves.contains_key(&reserve.payment_id)
                && !target.charges.contains_key(&reserve.payment_id)
                && reserve_refunds(purse, reserve)
        })
        .map(|reserve| reserve.amount_nanodollars)
        .fold(0i64, i64::saturating_add)
}

/// Sum of holds on `purse_id` that are in `extra` and not in `base`.
fn reserve_delta(base: &MergedState, extra: &MergedState, purse_id: Uuid) -> i64 {
    extra.reserves.values()
        .filter(|reserve| {
            reserve.purse_id == purse_id
                && !base.reserves.contains_key(&reserve.payment_id)
                && !base.charges.contains_key(&reserve.payment_id)
        })
        .map(|reserve| reserve.amount_nanodollars)
        .fold(0i64, i64::saturating_add)
}

/// `available` before the reserve diff is applied on top of it.
fn net_before_reserve_diff(available: i64, added: i64, removed: i64) -> i64 {
    available.saturating_add(added).saturating_sub(removed)
}

/// Sum of first-body charges on `purse_id` that are in `extra` and not in `base`.
///
/// A copied debt with no hold reduces the purse once. A second body of an id
/// `base` already stores does not. A hold `base` still has explains the amount,
/// so that id is left out and the record consumes the hold instead.
fn charge_delta(base: &MergedState, extra: &MergedState, purse_id: Uuid) -> i64 {
    let Some((purse, _)) = extra.purses.get(&purse_id) else {
        return 0;
    };
    extra.charges.iter().filter_map(|(id, lines)| {
        let first = lines.first()?;
        if first.purse_id != purse_id || base.charges.contains_key(id) || base.reserves.contains_key(id) {
            return None;
        }
        if !purse.aliases.iter().any(|alias| alias == &first.paying_alias) {
            return None;
        }
        Some(first.amount_nanodollars)
    }).fold(0i64, i64::saturating_add)
}

fn replay_reserve(state: &mut MergedState, reserve: PaymentReserve) {
    if reserve.amount_nanodollars <= 0 {
        return;
    }
    if state.reserves.contains_key(&reserve.payment_id) || state.charges.contains_key(&reserve.payment_id) {
        return;
    }
    let Some((purse, _)) = state.purses.get_mut(&reserve.purse_id) else {
        return;
    };
    if !purse.aliases.iter().any(|alias| alias == &reserve.paying_alias) {
        return;
    }
    if reserve.amount_nanodollars > purse.available_nanodollars {
        return;
    }
    purse.available_nanodollars -= reserve.amount_nanodollars;
    state.reserves.insert(reserve.payment_id, reserve);
}

fn replay_release(state: &mut MergedState, payment_id: Uuid) {
    if state.charges.contains_key(&payment_id) {
        state.reserves.remove(&payment_id);
        return;
    }
    let Some(reserve) = state.reserves.remove(&payment_id) else { return };
    if let Some((purse, _)) = state.purses.get_mut(&reserve.purse_id) {
        if reserve_refunds(purse, &reserve) {
            purse.available_nanodollars = purse.available_nanodollars.saturating_add(reserve.amount_nanodollars);
        }
    }
}

fn matching_reserve_purse(state: &MergedState, line: &Charge) -> Option<Uuid> {
    let reserve = state.reserves.get(&line.payment_id)?;
    line_same_payment(line, reserve, line.payer).then_some(reserve.purse_id)
}

fn take_matching_pending_state(state: &mut MergedState, line: &Charge) {
    let body = body_from_line(line);
    let matches = state.pending.get(&line.payment_id).is_some_and(|pending| {
        pending_covers(pending, &body, &line.payer_sig) && pending.payee_sig == line.payee_sig
    });
    if matches {
        state.pending.remove(&line.payment_id);
    }
}

fn replay_settlement(state: &mut MergedState, record: Settlement) {
    if !settlement_ok(&record) {
        return;
    }
    let rows = state.settlements.entry(record.settlement_id).or_default();
    if rows.iter().any(|stored| stored == &record) {
        return;
    }
    rows.push(record);
}

fn replay_record(state: &mut MergedState, line: Charge) {
    if !offer_body_ok(&body_from_line(&line)) {
        return;
    }
    let same = state.charges.get(&line.payment_id).is_some_and(|lines| {
        lines.iter().any(|stored| same_charge(stored, &line))
    });
    if same {
        if matching_reserve_purse(state, &line).is_some() {
            state.reserves.remove(&line.payment_id);
        }
        take_matching_pending_state(state, &line);
        return;
    }
    if state.charges.contains_key(&line.payment_id) {
        take_matching_pending_state(state, &line);
        let mut stored = line;
        stored.purse_id = [0u8; 16];
        state.charges.get_mut(&stored.payment_id).expect("charge list").push(stored);
        return;
    }
    take_matching_pending_state(state, &line);
    if let Some(purse_id) = matching_reserve_purse(state, &line) {
        state.reserves.remove(&line.payment_id);
        let mut stored = line;
        stored.purse_id = purse_id;
        state.charges.insert(stored.payment_id, vec![stored]);
        return;
    }
    let mut stored = line;
    if stored.purse_id != [0u8; 16] {
        if let Some((purse, _)) = state.purses.get_mut(&stored.purse_id) {
            if purse.aliases.iter().any(|alias| alias == &stored.paying_alias) {
                purse.available_nanodollars = purse
                    .available_nanodollars
                    .saturating_sub(stored.amount_nanodollars);
                state.charges.insert(stored.payment_id, vec![stored]);
                return;
            }
        }
    }
    stored.purse_id = [0u8; 16];
    state.charges.insert(stored.payment_id, vec![stored]);
}

fn replay_stage(state: &mut MergedState, pending: PendingAccept) {
    if state.charges.contains_key(&pending.payment_id) || state.pending.contains_key(&pending.payment_id) {
        return;
    }
    if !offer_body_ok(&body_from_pending(&pending)) {
        return;
    }
    state.pending.insert(pending.payment_id, pending);
}

#[cfg(test)]
mod policy_tests {
    use super::{
        deserialize_change, deserialize_contact_data, forget_invitation, put_invitation,
        serialize_change, serialize_contact_data_for, Change,
    };
    use super::super::sender_may_deliver;
    use crate::data_models::{
        AppGrant, AppInvitation, Application, Contact, Device, DeviceGrade, Ed25519KeyPair,
        Ed25519PublicKey, Ed25519Signature, Node, SyncVersion, User, X25519PublicKey,
    };

    fn app(id: u8, alias: &str, approved: bool) -> Application {
        Application {
            id: [id; 16],
            alias: alias.into(),
            protocol: String::new(),
            host: "127.0.0.1:9".parse().unwrap(),
            user_approved: approved,
            token: [id; 16],
            identity: Ed25519KeyPair::ZERO,
            cert_sig: Ed25519Signature::ZERO,
            cert_issued_at: 0,
            cert_alias: String::new(),
        }
    }

    #[test]
    fn contact_directory_lists_only_granted_apps() {
        let mut node = Node::new();
        node.owner.user.devices[0].applications.push(app(7, "chat", true));
        node.owner.user.devices[0].applications.push(app(8, "files", true));
        let contact = [0x11u8; 16];
        node.owner.app_grants.push(AppGrant {
            contact_uuid: contact,
            app_alias: "chat".into(),
        });
        node.owner.app_grants.push(AppGrant {
            contact_uuid: contact,
            app_alias: "missing".into(),
        });
        node.owner.outbound_app_invitations.push(AppInvitation {
            id: [0x55; 16],
            contact_uuid: contact,
            app_alias: "files".into(),
        });

        let data = deserialize_contact_data(&serialize_contact_data_for(&node, contact)).unwrap();
        assert_eq!(data.devices[0].1.len(), 1);
        assert_eq!(data.devices[0].1[0].alias, "chat");
        let accepted = data.accepted_aliases.expect("new peers send the allow list");
        assert!(accepted.iter().any(|a| a == "chat"));
        assert!(accepted.iter().any(|a| a == "missing"));
        assert!(!accepted.iter().any(|a| a == "files"));
        assert_eq!(data.invitations, vec![([0x55; 16], "files".into())]);
    }

    #[test]
    fn relay_policy_allows_a_granted_contact_and_our_own_device() {
        let mut node = Node::new();
        let dest = node.device_uuid;
        node.owner.user.devices[0].applications.push(app(7, "chat", true));
        let sender_dev = [0x42u8; 16];
        node.owner.contact_users.push(Contact {
            user: User {
                alias: "ada".into(),
                uuid: [0x11; 16],
                devices: vec![Device {
                    alias: "phone".into(),
                    uuid: sender_dev,
                    grade: DeviceGrade::DG,
                    sg_rank: None,
                    hosts: Vec::new(),
                    applications: Vec::new(),
                    signing_pk: Ed25519PublicKey::ZERO,
                    dh_pk: X25519PublicKey::ZERO,
                    cert_sig: Ed25519Signature::ZERO,
                    cert_issued_at: 0,
                    cert_alias: String::new(),
                }],
            },
            public_key: Ed25519PublicKey::ZERO,
            they_accept: Vec::new(),
            last_seen_public_version: SyncVersion::default(),
        });

        assert!(!sender_may_deliver(&node, Some(sender_dev), [9; 16], dest, [7; 16]));
        node.owner.app_grants.push(AppGrant {
            contact_uuid: [0x11; 16],
            app_alias: "chat".into(),
        });
        assert!(sender_may_deliver(&node, Some(sender_dev), [9; 16], dest, [7; 16]));
        assert!(sender_may_deliver(&node, Some(dest), [9; 16], dest, [7; 16]));
    }

    #[test]
    fn a_rejected_invitation_does_not_return() {
        let mut owner = Node::new().owner;
        assert!(put_invitation(
            &mut owner.app_invitations,
            &owner.seen_app_invitation_ids,
            [1; 16],
            [2; 16],
            "chat",
        ));
        assert!(forget_invitation(&mut owner, [1; 16]));
        assert!(!put_invitation(
            &mut owner.app_invitations,
            &owner.seen_app_invitation_ids,
            [1; 16],
            [2; 16],
            "chat",
        ));
        assert!(owner.app_invitations.is_empty());
    }

    #[test]
    fn app_grant_change_roundtrips() {
        let change = Change::SetAppGrant {
            contact_uuid: [3; 16],
            app_alias: "chat".into(),
            allowed: true,
        };
        assert_eq!(deserialize_change(&serialize_change(&change)).unwrap(), change);
    }
}

#[cfg(test)]
mod purse_sync_tests {
    use std::time::SystemTime;

    use super::{
        apply_change_to_owner, deserialize_change, merge_logs, read_private_snapshot,
        serialize_change, serialize_private_state, Change, PrivateSnapshot, ReserveReject, WriteError,
    };
    use crate::data_models::{
        Settlement, Ed25519Signature, Charge, Node, PaymentReserve, PendingAccept, Purse,
        RunLimit,
        Scope, SyncVersion, WriteLogEntry, utc_month_period,
    };
    use crate::wire::{PURSE_KIND_FIXED, PURSE_KIND_MONTHLY};

    fn media() -> Purse {
        Purse {
            id: [0x11; 16],
            name: "media".into(),
            allotment_nanodollars: 5_000_000,
            available_nanodollars: 5_000_000,
            aliases: vec!["discordium".into()],
            kind: PURSE_KIND_FIXED,
            period: 0,
        }
    }

    #[test]
    fn purse_change_roundtrips_and_a_repeat_is_a_no_op() {
        let change = Change::UpsertPurse { purse: media() };
        assert_eq!(deserialize_change(&serialize_change(&change)).unwrap(), change);
        let mut node = Node::new();
        assert!(apply_change_to_owner(&mut node.owner, &change).unwrap());
        assert!(!apply_change_to_owner(&mut node.owner, &change).unwrap());
        assert_eq!(node.owner.purses, vec![media()]);
    }

    #[test]
    fn private_snapshot_lists_purses_and_an_empty_blob_is_legacy() {
        let mut node = Node::new();
        node.owner.purses.push(media());
        let blob = serialize_private_state(&node);
        match read_private_snapshot(&blob) {
            Some(PrivateSnapshot::Purses { purses, reserves, ceilings, charges, pending, settlements }) => {
                assert_eq!(purses, vec![media()]);
                assert!(reserves.is_empty());
                assert!(ceilings.is_empty());
                assert!(charges.is_empty());
                assert!(pending.is_empty());
                assert!(settlements.is_empty());
            }
            other => panic!("expected purse snapshot, got {other:?}"),
        }
        // One purse and no reserves: purse-count, id, kind, period, reserve-count.
        let month_tail = 2 + 16 + 1 + 4 + 2;
        // A writer from step 7 ends at the settlements, before the month tail.
        let step7 = &blob[..blob.len() - month_tail];
        match read_private_snapshot(step7) {
            Some(PrivateSnapshot::Purses { purses, reserves, ceilings, charges, pending, settlements }) => {
                assert_eq!(purses, vec![media()]);
                assert!(reserves.is_empty());
                assert!(ceilings.is_empty());
                assert!(charges.is_empty());
                assert!(pending.is_empty());
                assert!(settlements.is_empty());
            }
            other => panic!("expected a step-7 snapshot, got {other:?}"),
        }
        // A writer from step 6 ends after the pending count.
        let step6 = &blob[..blob.len() - 2 - month_tail];
        match read_private_snapshot(step6) {
            Some(PrivateSnapshot::Purses { purses, reserves, ceilings, charges, pending, settlements }) => {
                assert_eq!(purses, vec![media()]);
                assert!(reserves.is_empty());
                assert!(ceilings.is_empty());
                assert!(charges.is_empty());
                assert!(pending.is_empty());
                assert!(settlements.is_empty());
            }
            other => panic!("expected a step-6 snapshot, got {other:?}"),
        }
        // A writer from step 3 ends after the reserve count.
        let step3 = &blob[..blob.len() - 8 - month_tail];
        match read_private_snapshot(step3) {
            Some(PrivateSnapshot::Purses { purses, reserves, ceilings, charges, pending, settlements }) => {
                assert_eq!(purses, vec![media()]);
                assert!(reserves.is_empty());
                assert!(ceilings.is_empty());
                assert!(charges.is_empty());
                assert!(pending.is_empty());
                assert!(settlements.is_empty());
            }
            other => panic!("expected a step-3 snapshot, got {other:?}"),
        }
        // A writer from before holds omits the reserve count too.
        let legacy = &blob[..blob.len() - 10 - month_tail];
        match read_private_snapshot(legacy) {
            Some(PrivateSnapshot::Purses { purses, reserves, ceilings, charges, pending, settlements }) => {
                assert_eq!(purses, vec![media()]);
                assert!(reserves.is_empty());
                assert!(ceilings.is_empty());
                assert!(charges.is_empty());
                assert!(pending.is_empty());
                assert!(settlements.is_empty());
            }
            other => panic!("expected a pre-hold snapshot, got {other:?}"),
        }
        assert!(matches!(read_private_snapshot(&[]), Some(PrivateSnapshot::LegacyEmpty)));
    }

    #[test]
    fn merge_copies_a_purse_from_the_other_writer() {
        let entry = |writer: [u8; 16], purse: Purse| WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: writer, epoch: 1, seq: 1 },
            scope: Scope::Private,
            change_payload: serialize_change(&Change::UpsertPurse { purse }),
            committed_at: SystemTime::UNIX_EPOCH,
        };
        let local = vec![entry([0xA1; 16], Purse { id: [0x01; 16], name: "local".into(), aliases: vec![], ..media() })];
        let peer = vec![entry([0xB2; 16], media())];
        let out = merge_logs(&local, &peer, &std::collections::HashMap::new());
        assert_eq!(out.changes_to_apply.len(), 1);
        match &out.changes_to_apply[0] {
            Change::UpsertPurse { purse } => assert_eq!(purse.name, "media"),
            other => panic!("expected purse upsert, got {other:?}"),
        }
    }

    fn hold(payment_id: u8, amount: i64, expires_at_ms: u64) -> PaymentReserve {
        PaymentReserve {
            payment_id: [payment_id; 16],
            purse_id: [0x11; 16],
            amount_nanodollars: amount,
            contact_uuid: [0x22; 16],
            destination_alias: "player".into(),
            note: "clip-1".into(),
            paying_alias: "discordium".into(),
            expires_at_ms,
            period: 0,
        }
    }

    #[test]
    fn reserve_reduces_once_and_a_different_body_is_refused() {
        let mut owner = Node::new().owner;
        assert!(apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: media() }).unwrap());
        let reserve = hold(1, 1_000_000, 50);
        let change = Change::ReservePayment { reserve: reserve.clone() };
        assert_eq!(deserialize_change(&serialize_change(&change)).unwrap(), change);
        assert!(apply_change_to_owner(&mut owner, &change).unwrap());
        assert!(!apply_change_to_owner(&mut owner, &change).unwrap());
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        assert_eq!(owner.reserves, vec![reserve.clone()]);

        let mut other = reserve.clone();
        other.note = "clip-2".into();
        let err = apply_change_to_owner(&mut owner, &Change::ReservePayment { reserve: other }).unwrap_err();
        assert_eq!(err, WriteError::ReserveRejected(ReserveReject::Mismatch));
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        assert_eq!(owner.reserves.len(), 1);

        let over = hold(2, 4_000_001, 50);
        let err = apply_change_to_owner(&mut owner, &Change::ReservePayment { reserve: over }).unwrap_err();
        assert_eq!(err, WriteError::ReserveRejected(ReserveReject::OverPurse));
        assert_eq!(owner.reserves.len(), 1);

        let outsider = PaymentReserve { paying_alias: "other".into(), ..hold(3, 1, 50) };
        let err = apply_change_to_owner(&mut owner, &Change::ReservePayment { reserve: outsider }).unwrap_err();
        assert_eq!(err, WriteError::ReserveRejected(ReserveReject::NotMember));
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
    }

    #[test]
    fn release_restores_the_available_amount() {
        let mut owner = Node::new().owner;
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: media() }).unwrap();
        apply_change_to_owner(&mut owner, &Change::ReservePayment { reserve: hold(1, 5_000_000, 50) }).unwrap();
        assert_eq!(owner.purses[0].available_nanodollars, 0);
        assert!(apply_change_to_owner(&mut owner, &Change::ReleaseReserve { payment_id: [1; 16] }).unwrap());
        assert!(!apply_change_to_owner(&mut owner, &Change::ReleaseReserve { payment_id: [1; 16] }).unwrap());
        assert_eq!(owner.purses[0].available_nanodollars, 5_000_000);
        assert!(owner.reserves.is_empty());
    }

    fn monthly(period: u32, available: i64) -> Purse {
        Purse {
            kind: PURSE_KIND_MONTHLY,
            period,
            available_nanodollars: available,
            ..media()
        }
    }

    fn log_entry(seq: u64, change: Change) -> WriteLogEntry {
        WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: [0xA1; 16], epoch: 1, seq },
            scope: Scope::Private,
            change_payload: serialize_change(&change),
            committed_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn a_reserve_from_the_previous_month_does_not_raise_the_new_one() {
        let oct = utc_month_period(1_790_812_800_000);
        let nov = utc_month_period(1_793_491_200_000);
        assert_ne!(oct, nov);
        let mut owner = Node::new().owner;
        let purse = monthly(oct, 5_000_000);
        let stored = serialize_change(&Change::UpsertPurse { purse: purse.clone() });
        assert_eq!(deserialize_change(&stored).unwrap(), Change::UpsertPurse { purse: purse.clone() });
        let older = deserialize_change(&stored[..stored.len() - 5]).unwrap();
        match older {
            Change::UpsertPurse { purse } => {
                assert_eq!(purse.kind, PURSE_KIND_FIXED);
                assert_eq!(purse.period, 0);
            }
            other => panic!("expected an older purse upsert, got {other:?}"),
        }
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse }).unwrap();
        let mut reserve = hold(1, 1_000_000, 50);
        reserve.period = oct;
        let reserve_bytes = serialize_change(&Change::ReservePayment { reserve: reserve.clone() });
        assert_eq!(
            deserialize_change(&reserve_bytes).unwrap(),
            Change::ReservePayment { reserve: reserve.clone() }
        );
        match deserialize_change(&reserve_bytes[..reserve_bytes.len() - 4]).unwrap() {
            Change::ReservePayment { reserve } => assert_eq!(reserve.period, 0),
            other => panic!("expected an older reserve, got {other:?}"),
        }
        apply_change_to_owner(&mut owner, &Change::ReservePayment { reserve: reserve.clone() }).unwrap();
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);

        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: monthly(nov, 5_000_000) }).unwrap();
        assert_eq!(owner.reserves.len(), 1);
        assert!(apply_change_to_owner(&mut owner, &Change::ReleaseReserve { payment_id: [1; 16] }).unwrap());
        assert_eq!(owner.purses[0].available_nanodollars, 5_000_000);
        assert_eq!(owner.purses[0].period, nov);
        assert!(owner.reserves.is_empty());

        let mut same_month = hold(2, 1_000_000, 50);
        same_month.period = nov;
        apply_change_to_owner(&mut owner, &Change::ReservePayment { reserve: same_month }).unwrap();
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        apply_change_to_owner(&mut owner, &Change::ReleaseReserve { payment_id: [2; 16] }).unwrap();
        assert_eq!(owner.purses[0].available_nanodollars, 5_000_000);

        let mut bad = monthly(nov, 5_000_000);
        bad.kind = 9;
        assert!(!apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: bad }).unwrap());
        assert_eq!(owner.purses[0].kind, PURSE_KIND_MONTHLY);
    }

    #[test]
    fn a_fixed_hold_still_refunds_after_the_purse_becomes_monthly() {
        let nov = utc_month_period(1_793_491_200_000);
        let mut owner = Node::new().owner;
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: media() }).unwrap();
        apply_change_to_owner(&mut owner, &Change::ReservePayment { reserve: hold(1, 1_000_000, 50) }).unwrap();
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: monthly(nov, 4_000_000) }).unwrap();
        assert_eq!(owner.purses[0].kind, PURSE_KIND_MONTHLY);
        assert!(apply_change_to_owner(&mut owner, &Change::ReleaseReserve { payment_id: [1; 16] }).unwrap());
        assert_eq!(owner.purses[0].available_nanodollars, 5_000_000);
        assert!(owner.reserves.is_empty());
    }

    #[test]
    fn merge_does_not_refund_a_hold_from_the_previous_month() {
        let oct = utc_month_period(1_790_812_800_000);
        let nov = utc_month_period(1_793_491_200_000);
        let mut reserve = hold(1, 1_000_000, 50);
        reserve.period = oct;
        let local = vec![
            log_entry(1, Change::UpsertPurse { purse: monthly(oct, 5_000_000) }),
            log_entry(2, Change::ReservePayment { reserve: reserve.clone() }),
        ];
        let peer = vec![
            log_entry(3, Change::UpsertPurse { purse: monthly(nov, 5_000_000) }),
            log_entry(4, Change::ReleaseReserve { payment_id: [1; 16] }),
        ];
        let out = merge_logs(&local, &peer, &std::collections::HashMap::new());
        let mut owner = Node::new().owner;
        for entry in &local {
            apply_change_to_owner(&mut owner, &deserialize_change(&entry.change_payload).unwrap()).unwrap();
        }
        for change in &out.changes_to_apply {
            apply_change_to_owner(&mut owner, change).unwrap();
        }
        assert_eq!(owner.purses[0].available_nanodollars, 5_000_000);
        assert_eq!(owner.purses[0].period, nov);
        assert!(owner.reserves.is_empty());
        assert!(out.changes_to_apply.iter().any(|change| matches!(
            change,
            Change::UpsertPurse { purse } if purse.available_nanodollars == 5_000_000 && purse.period == nov
        )));

        let same_month = vec![log_entry(3, Change::ReleaseReserve { payment_id: [1; 16] })];
        let refunded = merge_logs(&local, &same_month, &std::collections::HashMap::new());
        let mut owner = Node::new().owner;
        for entry in &local {
            apply_change_to_owner(&mut owner, &deserialize_change(&entry.change_payload).unwrap()).unwrap();
        }
        for change in &refunded.changes_to_apply {
            apply_change_to_owner(&mut owner, change).unwrap();
        }
        assert_eq!(owner.purses[0].available_nanodollars, 5_000_000);
        assert!(owner.reserves.is_empty());
        assert!(refunded.changes_to_apply.iter().all(|change| !matches!(change, Change::UpsertPurse { .. })));
    }

    #[test]
    fn monthly_snapshot_roundtrips_and_an_older_tail_stays_fixed() {
        let mut node = Node::new();
        let purse = monthly(2026 * 12 + 9, 4_000_000);
        node.owner.purses.push(purse.clone());
        let mut reserve = hold(4, 1_000_000, 99);
        reserve.period = 2026 * 12 + 9;
        node.owner.reserves.push(reserve.clone());
        let blob = serialize_private_state(&node);
        match read_private_snapshot(&blob) {
            Some(PrivateSnapshot::Purses { purses, reserves, .. }) => {
                assert_eq!(purses, vec![purse]);
                assert_eq!(reserves, vec![reserve]);
            }
            other => panic!("expected a monthly snapshot, got {other:?}"),
        }
        // Drop the reserve-month count and its one row. The purse month remains.
        let purse_only = &blob[..blob.len() - (2 + 16 + 4)];
        match read_private_snapshot(purse_only) {
            Some(PrivateSnapshot::Purses { purses, reserves, .. }) => {
                assert_eq!(purses[0].kind, PURSE_KIND_MONTHLY);
                assert_eq!(purses[0].period, 2026 * 12 + 9);
                assert_eq!(reserves[0].period, 0);
            }
            other => panic!("expected a purse-month tail, got {other:?}"),
        }
    }

    #[test]
    fn private_snapshot_roundtrips_a_reserve() {
        let mut node = Node::new();
        node.owner.purses.push(media());
        node.owner.reserves.push(hold(4, 10, 99));
        let blob = serialize_private_state(&node);
        match read_private_snapshot(&blob) {
            Some(PrivateSnapshot::Purses { purses, reserves, ceilings, charges, pending, settlements }) => {
                assert_eq!(purses, vec![media()]);
                assert_eq!(reserves, vec![hold(4, 10, 99)]);
                assert!(ceilings.is_empty());
                assert!(charges.is_empty());
                assert!(pending.is_empty());
                assert!(settlements.is_empty());
            }
            other => panic!("expected purse and reserve snapshot, got {other:?}"),
        }
    }

    #[test]
    fn merge_applies_a_reserve_without_subtracting_twice() {
        let created = WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: [0xA1; 16], epoch: 1, seq: 1 },
            scope: Scope::Private,
            change_payload: serialize_change(&Change::UpsertPurse { purse: media() }),
            committed_at: SystemTime::UNIX_EPOCH,
        };
        let reserved = WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: [0xA1; 16], epoch: 1, seq: 2 },
            scope: Scope::Private,
            change_payload: serialize_change(&Change::ReservePayment { reserve: hold(7, 1_000_000, 80) }),
            committed_at: SystemTime::UNIX_EPOCH,
        };
        let out = merge_logs(&[created.clone()], &[reserved], &std::collections::HashMap::new());
        assert_eq!(out.changes_to_apply.len(), 1, "{:?}", out.changes_to_apply);
        assert!(matches!(out.changes_to_apply[0], Change::ReservePayment { .. }));

        let mut owner = Node::new().owner;
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: media() }).unwrap();
        for change in &out.changes_to_apply {
            apply_change_to_owner(&mut owner, change).unwrap();
        }
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        assert_eq!(owner.reserves.len(), 1);
    }

    fn confirmed_line(payer: [u8; 16], reserve: &PaymentReserve) -> Charge {
        Charge {
            payment_id: reserve.payment_id,
            amount_nanodollars: reserve.amount_nanodollars,
            payer,
            payee: reserve.contact_uuid,
            paying_alias: reserve.paying_alias.clone(),
            destination_alias: reserve.destination_alias.clone(),
            note: reserve.note.clone(),
            expires_at_ms: reserve.expires_at_ms,
            purse_id: reserve.purse_id,
            payer_sig: Ed25519Signature::ZERO,
            payee_sig: Ed25519Signature::ZERO,
            confirm_sig: Ed25519Signature::ZERO,
        }
    }

    #[test]
    fn record_consumes_a_reserve_once_without_refunding() {
        let mut owner = Node::new().owner;
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: media() }).unwrap();
        let reserve = hold(7, 1_000_000, 80);
        apply_change_to_owner(&mut owner, &Change::ReservePayment { reserve: reserve.clone() }).unwrap();
        let line = confirmed_line(owner.user.uuid, &reserve);
        let change = Change::RecordCharge { line: line.clone() };
        assert_eq!(deserialize_change(&serialize_change(&change)).unwrap(), change);
        assert!(apply_change_to_owner(&mut owner, &change).unwrap());
        assert!(!apply_change_to_owner(&mut owner, &change).unwrap());
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        assert!(owner.reserves.is_empty());
        assert_eq!(owner.charges, vec![line]);
    }

    #[test]
    fn private_snapshot_roundtrips_a_run_limit_a_charge_and_a_pending_accept() {
        let mut node = Node::new();
        node.owner.purses.push(media());
        let reserve = hold(4, 10, 99);
        node.owner.reserves.push(reserve.clone());
        let ceiling = RunLimit { payer: [3; 16], max_nanodollars: 10 };
        node.owner.run_limits.push(ceiling.clone());
        let line = confirmed_line(node.owner.user.uuid, &hold(5, 10, 99));
        node.owner.charges.push(line.clone());
        let pending = PendingAccept {
            payment_id: [6; 16],
            amount_nanodollars: 10,
            payer: [3; 16],
            payee: node.owner.user.uuid,
            paying_alias: "discordium".into(),
            destination_alias: "player".into(),
            note: "clip-1".into(),
            expires_at_ms: 99,
            payer_sig: Ed25519Signature::ZERO,
            payee_sig: Ed25519Signature::ZERO,
        };
        node.owner.pending_accepts.push(pending.clone());
        match read_private_snapshot(&serialize_private_state(&node)) {
            Some(PrivateSnapshot::Purses { purses, reserves, ceilings, charges, pending: staged, settlements }) => {
                assert_eq!(purses, vec![media()]);
                assert_eq!(reserves, vec![reserve]);
                assert_eq!(ceilings, vec![ceiling]);
                assert_eq!(charges, vec![line]);
                assert_eq!(staged, vec![pending]);
                assert!(settlements.is_empty());
            }
            other => panic!("expected the extra private lists, got {other:?}"),
        }
    }

    #[test]
    fn merge_of_a_confirmation_records_the_line_without_refunding() {
        let reserve = hold(7, 1_000_000, 80);
        let line = confirmed_line([0x44; 16], &reserve);
        let entry = |seq: u64, change: Change| WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: [0xA1; 16], epoch: 1, seq },
            scope: Scope::Private,
            change_payload: serialize_change(&change),
            committed_at: SystemTime::UNIX_EPOCH,
        };
        let created = entry(1, Change::UpsertPurse { purse: media() });
        let reserved = entry(2, Change::ReservePayment { reserve: reserve.clone() });
        let recorded = entry(3, Change::RecordCharge { line: line.clone() });
        let out = merge_logs(
            &[created.clone(), reserved.clone()],
            &[created, reserved, recorded],
            &std::collections::HashMap::new(),
        );
        assert_eq!(out.changes_to_apply.len(), 1, "{:?}", out.changes_to_apply);
        assert!(matches!(out.changes_to_apply[0], Change::RecordCharge { .. }));

        let mut owner = Node::new().owner;
        owner.user.uuid = [0x44; 16];
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: media() }).unwrap();
        apply_change_to_owner(&mut owner, &Change::ReservePayment { reserve }).unwrap();
        for change in &out.changes_to_apply {
            apply_change_to_owner(&mut owner, change).unwrap();
        }
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        assert!(owner.reserves.is_empty());
        assert_eq!(owner.charges, vec![line]);
    }

    #[test]
    fn private_snapshot_roundtrips_two_lines_for_one_payment() {
        let mut node = Node::new();
        let first = confirmed_line(node.owner.user.uuid, &hold(5, 10, 99));
        let mut second = first.clone();
        second.note = "other".into();
        second.purse_id = [0u8; 16];
        second.confirm_sig = Ed25519Signature([2; 64]);
        node.owner.charges.push(first.clone());
        node.owner.charges.push(second.clone());
        match read_private_snapshot(&serialize_private_state(&node)) {
            Some(PrivateSnapshot::Purses { charges, .. }) => {
                assert_eq!(charges.len(), 2);
                assert!(charges.iter().any(|line| line.note == first.note && line.confirm_sig == first.confirm_sig));
                assert!(charges.iter().any(|line| line.note == "other" && line.purse_id == [0u8; 16]));
            }
            other => panic!("expected both lines, got {other:?}"),
        }
    }

    #[test]
    fn an_unreserved_record_overruns_one_purse_and_keeps_a_second_body() {
        let mut owner = Node::new().owner;
        owner.user.uuid = [0x44; 16];
        let mut purse = media();
        purse.available_nanodollars = 0;
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse }).unwrap();
        let line = confirmed_line([0x44; 16], &hold(7, 1_000_000, 80));
        assert!(apply_change_to_owner(&mut owner, &Change::RecordCharge { line: line.clone() }).unwrap());
        assert_eq!(owner.purses[0].available_nanodollars, -1_000_000);
        let mut other = line.clone();
        other.note = "other".into();
        other.purse_id = [0x11; 16];
        other.confirm_sig = Ed25519Signature([4; 64]);
        assert!(apply_change_to_owner(&mut owner, &Change::RecordCharge { line: other }).unwrap());
        assert!(!apply_change_to_owner(&mut owner, &Change::RecordCharge { line }).unwrap());
        assert_eq!(owner.purses[0].available_nanodollars, -1_000_000);
        assert_eq!(owner.charges.len(), 2);
        assert_eq!(owner.charges[1].purse_id, [0u8; 16]);
    }

    #[test]
    fn merge_of_an_unreserved_line_charges_once() {
        let line = confirmed_line([0x44; 16], &hold(7, 1_000_000, 80));
        let entry = |seq: u64, change: Change| WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: [0xA1; 16], epoch: 1, seq },
            scope: Scope::Private,
            change_payload: serialize_change(&change),
            committed_at: SystemTime::UNIX_EPOCH,
        };
        let created = entry(1, Change::UpsertPurse { purse: media() });
        let recorded = entry(2, Change::RecordCharge { line: line.clone() });
        let out = merge_logs(
            &[created.clone()],
            &[created.clone(), recorded.clone()],
            &std::collections::HashMap::new(),
        );
        assert_eq!(out.changes_to_apply.len(), 1, "{:?}", out.changes_to_apply);
        assert!(matches!(out.changes_to_apply[0], Change::RecordCharge { .. }));

        let mut owner = Node::new().owner;
        owner.user.uuid = [0x44; 16];
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: media() }).unwrap();
        for change in &out.changes_to_apply {
            apply_change_to_owner(&mut owner, change).unwrap();
        }
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        assert_eq!(owner.charges.len(), 1);

        let again = merge_logs(
            &[created.clone(), recorded.clone()],
            &[created, recorded],
            &std::collections::HashMap::new(),
        );
        assert!(again.changes_to_apply.is_empty());
    }

    #[test]
    fn merge_of_a_second_body_does_not_charge_again() {
        let first = confirmed_line([0x44; 16], &hold(7, 1_000_000, 80));
        let mut second = first.clone();
        second.note = "other".into();
        second.purse_id = [0u8; 16];
        second.confirm_sig = Ed25519Signature([9; 64]);
        let entry = |seq: u64, change: Change| WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: [0xA1; 16], epoch: 1, seq },
            scope: Scope::Private,
            change_payload: serialize_change(&change),
            committed_at: SystemTime::UNIX_EPOCH,
        };
        let created = entry(1, Change::UpsertPurse { purse: media() });
        let recorded = entry(2, Change::RecordCharge { line: first });
        let extra = entry(3, Change::RecordCharge { line: second });
        let out = merge_logs(
            &[created.clone(), recorded.clone()],
            &[created, recorded, extra],
            &std::collections::HashMap::new(),
        );
        assert_eq!(out.changes_to_apply.len(), 1, "{:?}", out.changes_to_apply);
        assert!(matches!(out.changes_to_apply[0], Change::RecordCharge { .. }));

        let mut owner = Node::new().owner;
        owner.user.uuid = [0x44; 16];
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: media() }).unwrap();
        let first = confirmed_line([0x44; 16], &hold(7, 1_000_000, 80));
        apply_change_to_owner(&mut owner, &Change::RecordCharge { line: first }).unwrap();
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        apply_change_to_owner(&mut owner, &out.changes_to_apply[0]).unwrap();
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        assert_eq!(owner.charges.len(), 2);
        assert_eq!(owner.charges[1].purse_id, [0u8; 16]);
    }

    fn sample_settlement(settlement_id: [u8; 16], payment_id: [u8; 16]) -> Settlement {
        Settlement {
            settlement_id,
            user_lo: [0x01; 16],
            user_hi: [0x02; 16],
            payment_ids: vec![payment_id],
            sig_lo: Ed25519Signature([1; 64]),
            sig_hi: Ed25519Signature([2; 64]),
        }
    }

    #[test]
    fn private_snapshot_roundtrips_a_settlement_and_an_older_blob_has_none() {
        let mut node = Node::new();
        let record = sample_settlement([0xC1; 16], [0x10; 16]);
        node.owner.settlements.push(record.clone());
        let blob = serialize_private_state(&node);
        match read_private_snapshot(&blob) {
            Some(PrivateSnapshot::Purses { settlements, .. }) => assert_eq!(settlements, vec![record]),
            other => panic!("expected the settlement, got {other:?}"),
        }
        // No purses and no reserves: the month tail is two counts.
        let month_tail = 2 + 2;
        let step6 = &blob[..blob.len() - month_tail - 2 - encode_len_of_one_settlement()];
        match read_private_snapshot(step6) {
            Some(PrivateSnapshot::Purses { settlements, charges, pending, .. }) => {
                assert!(settlements.is_empty());
                assert!(charges.is_empty());
                assert!(pending.is_empty());
            }
            other => panic!("expected a snapshot with no settlement section, got {other:?}"),
        }
    }

    fn encode_len_of_one_settlement() -> usize {
        let record = sample_settlement([0xC1; 16], [0x10; 16]);
        serialize_change(&Change::RecordSettlement { record }).len() - 1
    }

    #[test]
    fn merge_applies_a_settlement_without_moving_the_purse() {
        let reserve = hold(7, 1_000_000, 80);
        let line = confirmed_line([0x44; 16], &reserve);
        let record = sample_settlement([0xC2; 16], reserve.payment_id);
        let entry = |seq: u64, change: Change| WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: [0xA1; 16], epoch: 1, seq },
            scope: Scope::Private,
            change_payload: serialize_change(&change),
            committed_at: SystemTime::UNIX_EPOCH,
        };
        let change = Change::RecordSettlement { record: record.clone() };
        assert_eq!(deserialize_change(&serialize_change(&change)).unwrap(), change);
        let created = entry(1, Change::UpsertPurse { purse: media() });
        let recorded = entry(2, Change::RecordCharge { line: line.clone() });
        let cleared = entry(3, change);
        let out = merge_logs(
            &[created.clone(), recorded.clone()],
            &[created, recorded, cleared],
            &std::collections::HashMap::new(),
        );
        assert_eq!(out.changes_to_apply.len(), 1, "{:?}", out.changes_to_apply);
        assert!(matches!(out.changes_to_apply[0], Change::RecordSettlement { .. }));

        let mut owner = Node::new().owner;
        owner.user.uuid = [0x44; 16];
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: media() }).unwrap();
        apply_change_to_owner(&mut owner, &Change::RecordCharge { line }).unwrap();
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        assert!(apply_change_to_owner(&mut owner, &out.changes_to_apply[0]).unwrap());
        assert!(!apply_change_to_owner(&mut owner, &out.changes_to_apply[0]).unwrap());
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        assert_eq!(owner.settlements.len(), 1);
        assert_eq!(owner.charges.len(), 1);
    }

    #[test]
    fn a_second_settlement_body_is_kept_and_the_tab_is_the_union() {
        let mut owner = Node::new().owner;
        owner.user.uuid = [0x11; 16];
        let contact = [0x22; 16];
        let first_line = confirmed_line(owner.user.uuid, &hold(1, 1_000_000, 80));
        let mut second_reserve = hold(2, 250_000, 80);
        second_reserve.payment_id = [2; 16];
        let second_line = confirmed_line(owner.user.uuid, &second_reserve);
        owner.charges.push(first_line);
        owner.charges.push(second_line);
        let mut first = sample_settlement([0xC3; 16], [1; 16]);
        first.user_lo = owner.user.uuid;
        first.user_hi = contact;
        let mut second = sample_settlement([0xC3; 16], [2; 16]);
        second.user_lo = owner.user.uuid;
        second.user_hi = contact;
        second.sig_lo = Ed25519Signature([3; 64]);
        assert!(apply_change_to_owner(&mut owner, &Change::RecordSettlement { record: first }).unwrap());
        assert_eq!(crate::payment::tab_nanodollars(&owner, contact), -250_000);
        assert!(apply_change_to_owner(&mut owner, &Change::RecordSettlement { record: second }).unwrap());
        assert_eq!(owner.settlements.len(), 2);
        assert_eq!(crate::payment::tab_nanodollars(&owner, contact), 0);
        assert!(owner.purses.is_empty());
    }

    #[test]
    fn merge_applies_a_run_limit_without_moving_the_purse() {
        let payer = [0x31; 16];
        let change = Change::SetRunLimit { payer, max_nanodollars: 5_000_000 };
        assert_eq!(deserialize_change(&serialize_change(&change)).unwrap(), change);
        let entry = |seq: u64, change: Change| WriteLogEntry {
            version: SyncVersion { writer_sg_uuid: [0xA1; 16], epoch: 1, seq },
            scope: Scope::Private,
            change_payload: serialize_change(&change),
            committed_at: SystemTime::UNIX_EPOCH,
        };
        let created = entry(1, Change::UpsertPurse { purse: media() });
        let ceiling = entry(2, change);
        let out = merge_logs(
            &[created.clone()],
            &[created, ceiling],
            &std::collections::HashMap::new(),
        );
        assert_eq!(out.changes_to_apply.len(), 1, "{:?}", out.changes_to_apply);
        assert!(matches!(
            out.changes_to_apply[0],
            Change::SetRunLimit { max_nanodollars: 5_000_000, .. }
        ));

        let mut owner = Node::new().owner;
        apply_change_to_owner(&mut owner, &Change::UpsertPurse { purse: media() }).unwrap();
        owner.purses[0].available_nanodollars = 4_000_000;
        owner.run_limits.push(RunLimit { payer, max_nanodollars: 1 });
        owner.run_limits.push(RunLimit { payer, max_nanodollars: 9 });
        assert!(apply_change_to_owner(&mut owner, &out.changes_to_apply[0]).unwrap());
        assert!(!apply_change_to_owner(&mut owner, &out.changes_to_apply[0]).unwrap());
        assert_eq!(owner.run_limits.len(), 1);
        assert_eq!(owner.run_limits[0].payer, payer);
        assert_eq!(owner.run_limits[0].max_nanodollars, 5_000_000);
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
        assert!(owner.reserves.is_empty());
        assert!(owner.charges.is_empty());

        let replaced = Change::SetRunLimit { payer, max_nanodollars: 0 };
        assert!(apply_change_to_owner(&mut owner, &replaced).unwrap());
        assert_eq!(owner.run_limits.len(), 1);
        assert_eq!(owner.run_limits[0].max_nanodollars, 0);
        assert!(!apply_change_to_owner(&mut owner, &Change::SetRunLimit {
            payer,
            max_nanodollars: -1,
        }).unwrap());
        assert_eq!(owner.run_limits[0].max_nanodollars, 0);
        assert_eq!(owner.purses[0].available_nanodollars, 4_000_000);
    }
}
