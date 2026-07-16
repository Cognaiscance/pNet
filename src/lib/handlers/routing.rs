//! Routing: host resolve, writer election, SG selection, pull source.
//!
//! Pure (mostly) selection helpers used by app edge, sessions, bootstrap, and
//! sync. `find_writer_sg_probing` is the only path that may call `poll_sg`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::super::action_queue::WorkerContext;
use super::super::data_models::{ActiveConnection, Device, DeviceGrade, Node, Uuid};
use super::poll_sg;

pub(crate) fn ipv4_from(addr: SocketAddr) -> Option<Ipv4Addr> {
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
pub(crate) fn resolve_host_entry(entry: &str) -> Option<SocketAddrV4> {
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
pub(crate) fn resolve_hosts(hosts: &[String]) -> Vec<(String, SocketAddrV4)> {
    hosts.iter()
        .filter_map(|h| resolve_host_entry(h).map(|a| (h.clone(), a)))
        .collect()
}

// ── Packet routing helpers ────────────────────────────────────────────────────
// Crypto primitives (x25519 / ed25519 / AEAD / seal-open) live in `crypto`.

/// Pick the best address for reaching `device_uuid`: the up entry with the
/// lowest recorded RTT in `sg_statuses`. Falls back to the first resolvable
/// entry in the device's host list when no poll data exists yet.
///
/// Cold-boot note: the first ConnectRequest after startup may land on a dead
/// address if the happy-eyeballs data isn't populated yet; the next `poll_sg`
/// cycle (≤30s) corrects that.
pub(crate) fn best_address_for_device(
    node: &Node,
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
pub(crate) fn sg_candidates_for_dest(node: &Node, dest_device_uuid: &Uuid) -> Vec<Uuid> {
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
pub fn find_writer_sg(node: &Node) -> WriterTarget {
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
pub(crate) fn remote_if_reachable(node: &Node, uuid: &Uuid) -> Option<WriterTarget> {
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
pub(crate) fn is_polled_down(node: &Node, uuid: &Uuid) -> bool {
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
pub(crate) fn find_pull_source(node: &Node) -> WriterTarget {
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
pub(crate) fn top_ranked_sg_for_device<'a>(
    node: &'a Node,
    dest_device_uuid: &Uuid,
) -> Option<&'a ActiveConnection> {
    // Find the user (own or contact) who owns dest_device_uuid.
    let dest_user_devices: Option<&Vec<Device>> =
        if node.owner.user.devices.iter().any(|d| d.uuid == *dest_device_uuid) {
            Some(&node.owner.user.devices)
        } else {
            node.owner.contact_users.iter()
                .find(|c| c.user.devices.iter().any(|d| d.uuid == *dest_device_uuid))
                .map(|c| &c.user.devices)
        };

    let devices = dest_user_devices?;

    // Collect SGs with active connections, sorted by rank ascending (None last).
    let mut sgs: Vec<&Device> = devices.iter()
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
pub(crate) fn best_sg_connection<'a>(
    node: &'a Node,
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


pub(crate) fn find_writer_sg_probing(ctx: &WorkerContext) -> WriterTarget {
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
