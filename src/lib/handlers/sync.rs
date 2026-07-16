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
    Application, Contact, Device, DeviceGrade, Node, Owner, PublicKey, Scope, SyncVersion,
    User, Uuid, WriteLogEntry, WRITE_LOG_RETENTION,
};
use super::super::wire::*;
use super::{
    find_pull_source, find_writer_sg, find_writer_sg_probing, push_device, read_device, send,
    WriterTarget,
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
//         each approved app: [id: 16][alias: u8+bytes]

pub(crate) fn serialize_contact_data(node: &Node) -> Vec<u8> {
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

pub(crate) struct ContactData {
    pub(crate) user_uuid: Uuid,
    pub(crate) devices:   Vec<(Device, Vec<(Uuid, String)>)>, // (device, vec of (app_id, app_alias))
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

pub(crate) fn serialize_change(c: &Change) -> Vec<u8> {
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

pub(crate) fn deserialize_change(data: &[u8]) -> Option<Change> {
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
pub(crate) fn devices_to_cards(devices: &[Device]) -> Vec<ContactDeviceCard> {
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
//       [app_count: u8] each [id: 16][alias: u8+bytes]
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

pub(crate) fn build_merge_proposal_body(
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

pub(crate) fn parse_merge_proposal_body(
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
