use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant, SystemTime};

pub const TUNNEL_THRESHOLD:      u32      = 10;
pub const TUNNEL_COUNTER_WINDOW: Duration = Duration::from_secs(5 * 60);

use serde::{Deserialize, Serialize};

pub type Uuid = [u8; 16];

// ── Distinct key types (Ed25519 identity vs X25519 DH) ────────────────────────
//
// Both are 32-byte Curve25519-family keys on the wire/disk, but they must not be
// mixed at the type level: long-term identity keys are Ed25519 (sign/verify);
// session, invitation, and tunnel ephemerals are X25519 (DH only).

/// Long-term identity public key (Ed25519 verifying key).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Ed25519PublicKey(pub [u8; 32]);

/// Long-term identity secret key (Ed25519 seed / signing key).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Ed25519SecretKey(pub [u8; 32]);

/// X25519 Diffie–Hellman public key (ephemeral / invitation).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct X25519PublicKey(pub [u8; 32]);

/// X25519 Diffie–Hellman secret key (ephemeral / invitation).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct X25519SecretKey(pub [u8; 32]);

impl Ed25519PublicKey {
    pub const ZERO: Self = Self([0u8; 32]);
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Ed25519SecretKey {
    pub const ZERO: Self = Self([0u8; 32]);
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl AsRef<[u8]> for Ed25519SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl X25519PublicKey {
    pub const ZERO: Self = Self([0u8; 32]);
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl X25519SecretKey {
    pub const ZERO: Self = Self([0u8; 32]);
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl AsRef<[u8]> for X25519SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Ed25519PublicKey {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}
impl From<[u8; 32]> for Ed25519SecretKey {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}
impl From<[u8; 32]> for X25519PublicKey {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}
impl From<[u8; 32]> for X25519SecretKey {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

macro_rules! impl_key_serde {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                serde_bytes_32::serialize(&self.0, s)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                serde_bytes_32::deserialize(d).map(Self)
            }
        }
    };
}
impl_key_serde!(Ed25519PublicKey);
impl_key_serde!(Ed25519SecretKey);
impl_key_serde!(X25519PublicKey);
impl_key_serde!(X25519SecretKey);

/// Long-term user identity key pair (Ed25519). Used for Connect signatures and
/// contact cards. Never used for X25519 DH.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Ed25519KeyPair {
    pub public_key:  Ed25519PublicKey,
    pub private_key: Ed25519SecretKey,
}

impl Ed25519KeyPair {
    pub const ZERO: Self = Self {
        public_key:  Ed25519PublicKey::ZERO,
        private_key: Ed25519SecretKey::ZERO,
    };
}

/// X25519 key pair for DH (sessions, invitations, tunnels). Never used for
/// Ed25519 sign/verify.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct X25519KeyPair {
    pub public_key:  X25519PublicKey,
    pub private_key: X25519SecretKey,
}

impl X25519KeyPair {
    pub const ZERO: Self = Self {
        public_key:  X25519PublicKey::ZERO,
        private_key: X25519SecretKey::ZERO,
    };
}

/// Active connections are renewed when less than this much time remains.
/// Must exceed MAINTAIN_CONNECTIONS_INTERVAL so a connection never lapses between checks.
pub const RENEW_THRESHOLD:    Duration = Duration::from_secs(2 * 3600);  // 2 hours
pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(24 * 3600); // 24 hours

/// A PendingConnection whose ConnectAck hasn't arrived in this window is
/// treated as failed and dropped, so `maintain_connections` can re-issue.
/// Covers silent SG-side rejections (e.g. a connect_request that lost the
/// race with its own device_registration) and other lost-packet scenarios.
pub const PENDING_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Fill `buf` from the OS CSPRNG (`getrandom`). Prefer this over opening
/// `/dev/urandom` so paths work portably and do not thrash file descriptors.
///
/// Returns `Err` only if the OS entropy source fails (extremely rare). Available
/// for callers that can skip work without panicking; encrypt currently uses
/// [`fill_random`] because a zero/reused AEAD nonce is worse than aborting.
pub fn try_fill_random(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::getrandom(buf)
}

/// Fill `buf` from the OS CSPRNG. Panics if entropy is unavailable.
///
/// Used for id/key generation and AEAD nonces. A failed CSPRNG is treated as
/// fatal rather than emitting predictable randomness.
pub fn fill_random(buf: &mut [u8]) {
    try_fill_random(buf).expect("OS CSPRNG (getrandom) failed");
}

/// 16 cryptographically random bytes (app/device/token ids, session salts).
pub fn generate_uuid() -> Uuid {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    bytes
}

/// 32 cryptographically random bytes (ephemeral key seeds, AEAD test keys).
pub fn generate_key_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    bytes
}

// ── Serde helpers ─────────────────────────────────────────────────────────────

/// Serialize/deserialize a [u8; 32] as a 64-character lowercase hex string.
pub mod serde_bytes_32 {
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        unhex_32(&s).map_err(D::Error::custom)
    }

    pub fn hex(bytes: &[u8]) -> String {
        const H: &[u8] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 0xf) as usize] as char);
        }
        s
    }

    fn unhex_32(s: &str) -> Result<[u8; 32], &'static str> {
        if s.len() != 64 { return Err("expected 64 hex chars for 32-byte field"); }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            out[i] = nibble(chunk[0])? << 4 | nibble(chunk[1])?;
        }
        Ok(out)
    }

    fn nibble(b: u8) -> Result<u8, &'static str> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("invalid hex character"),
        }
    }
}

/// Serialize/deserialize a [u8; 16] as a 32-character lowercase hex string.
mod serde_bytes_16 {
    use serde::{de::Error, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = v.iter().flat_map(|&b| {
            const H: &[u8] = b"0123456789abcdef";
            [H[(b >> 4) as usize] as char, H[(b & 0xf) as usize] as char]
        }).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        if s.len() != 32 { return Err(D::Error::custom("expected 32 hex chars for 16-byte field")); }
        let mut out = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            out[i] = nibble(chunk[0]).map_err(D::Error::custom)? << 4
                   | nibble(chunk[1]).map_err(D::Error::custom)?;
        }
        Ok(out)
    }

    fn nibble(b: u8) -> Result<u8, &'static str> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("invalid hex character"),
        }
    }
}

/// Serialize/deserialize a SocketAddrV4 as an "ip:port" string.
mod serde_socket_addr_v4 {
    use serde::{de::Error as _, Deserializer, Serializer};
    use std::net::SocketAddrV4;
    use std::str::FromStr;

    pub fn serialize<S: Serializer>(v: &SocketAddrV4, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SocketAddrV4, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        SocketAddrV4::from_str(&s).map_err(D::Error::custom)
    }
}

/// Serialize/deserialize a SystemTime as seconds since UNIX_EPOCH (i64).
mod serde_system_time {
    use serde::{Deserializer, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn serialize<S: Serializer>(v: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        let secs = v.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs() as i64;
        s.serialize_i64(secs)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let secs: i64 = serde::Deserialize::deserialize(d)?;
        Ok(UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64))
    }
}

// ── Data model structs ────────────────────────────────────────────────────────

/// Identifies a scope of synchronized state. Each scope has its own version
/// counter on `Owner` so changes in one don't bump the other (e.g. rotating an
/// app token mutates Private without bumping Public, sparing contacts a pull).
///
/// **Private** — visible only to the user's own devices. Application
/// `host`/`token`, invitations, the long-term keypair, and anything else that
/// must never leave the user's device set.
///
/// **Public** — also visible to the user's contacts. User `alias`/`uuid`,
/// device `uuid`/`grade`/`sg_rank`/`hosts`, and application `id`/`alias`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    Private,
    Public,
}

/// Version metadata for a synchronized scope.
///
/// `writer_sg_uuid` identifies which SG accepted the most recent write.
/// `(epoch, seq)` is a total order *within* a single writer. When a different
/// SG takes over as writer (failover, or a partition during which both sides
/// accepted writes), the new writer increments `epoch` and resets `seq` so its
/// stream is distinguishable from the prior writer's.
///
/// The zero value (`writer_sg_uuid == [0; 16]`, `epoch == 0`, `seq == 0`)
/// is the sentinel for "no version yet" — used at first boot before any
/// write has been accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncVersion {
    #[serde(with = "serde_bytes_16", default)]
    pub writer_sg_uuid: Uuid,
    #[serde(default)]
    pub epoch: u32,
    #[serde(default)]
    pub seq:   u64,
}

impl SyncVersion {
    /// Sentinel "no version yet" — used at first boot.
    pub const fn zero() -> Self {
        Self { writer_sg_uuid: [0u8; 16], epoch: 0, seq: 0 }
    }

    pub fn is_initial(&self) -> bool {
        self.writer_sg_uuid == [0u8; 16]
    }

    /// Advance the version for a write accepted by `writer_uuid`. If the
    /// writer differs from the current `writer_sg_uuid`, this is a writer
    /// transition: increment `epoch` and reset `seq` to 1. Otherwise just
    /// increment `seq`.
    pub fn bump(&mut self, writer_uuid: Uuid) {
        if self.writer_sg_uuid != writer_uuid {
            self.writer_sg_uuid = writer_uuid;
            self.epoch = self.epoch.saturating_add(1);
            self.seq   = 1;
        } else {
            self.seq = self.seq.saturating_add(1);
        }
    }

    /// Total order *within a single writer*. Returns `None` when the two
    /// versions came from different writers — that's the partition case,
    /// resolved by the reconciliation rules in `descriptions/data sync.md`
    /// rather than by simple comparison.
    pub fn cmp_same_writer(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self.writer_sg_uuid != other.writer_sg_uuid { return None; }
        Some((self.epoch, self.seq).cmp(&(other.epoch, other.seq)))
    }
}

/// One entry in the writer SG's append-only log of accepted state changes
/// (Add/Remove/Update of devices, apps, etc.). Persisted on `Owner.write_log`
/// and exchanged with peer SGs during sync v2 partition reconciliation, so
/// each side can replay the other side's changes since the last shared
/// watermark.
///
/// The Change is stored as opaque serialized bytes (the output of
/// `handlers::serialize_change`) so this module doesn't have to import the
/// `Change` enum. Decode at read time via `handlers::deserialize_change`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteLogEntry {
    pub version: SyncVersion,
    pub scope:   Scope,
    #[serde(default)]
    pub change_payload: Vec<u8>,
    #[serde(with = "serde_system_time")]
    pub committed_at: SystemTime,
}

/// Hard cap on how long the writer SG retains write-log entries for
/// reconciliation. An SG that has been offline longer than this can no
/// longer be merged at the change-replay level — it must adopt the other
/// side's full state via the existing `SyncPullResponse(FullState)` path.
pub const WRITE_LOG_RETENTION: std::time::Duration =
    std::time::Duration::from_secs(30 * 24 * 3600);

pub struct ActiveConnection {
    pub id:                        u16,
    pub timeout:                   SystemTime,
    /// Local X25519 ephemeral for this session.
    pub key_pair:                  X25519KeyPair,
    /// Peer's X25519 ephemeral public key.
    pub peer_public_key:           X25519PublicKey,
    pub peer_active_connection_id: u16,
    pub device_uuid:               Uuid,
    /// The actual source address of the peer's last connection packet.
    /// Used for direct sends (e.g. SG → DG AppPacket) instead of the
    /// potentially-stale `d.host` stored at device-registration time.
    pub peer_addr:                 std::net::SocketAddr,
}

/// A half-open connection: we sent a ConnectRequest and are waiting for a ConnectAck.
/// Keyed by our local connection ID in `Owner::pending_connections`.
pub struct PendingConnection {
    pub our_conn_id:      u16,
    pub our_key_pair:     X25519KeyPair,
    pub peer_device_uuid: Uuid,
    /// Long-term Ed25519 public key of the peer's user — used to verify the ConnectAck signature.
    pub peer_longterm_pk: Ed25519PublicKey,
    /// When this PendingConnection was created. Used by `maintain_connections`
    /// to evict entries whose ConnectAck never arrived.
    pub created_at:       SystemTime,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Application {
    /// 16-byte UUID. Wide enough that two writers accepting AddApplication
    /// during a network partition cannot collide on the same id, so v2's
    /// partition reconciliation can union Adds without reassignment.
    #[serde(with = "serde_bytes_16")]
    pub id:            Uuid,
    pub alias:         String,
    pub protocol:      String,
    #[serde(with = "serde_socket_addr_v4")]
    pub host:          SocketAddrV4,
    pub user_approved: bool,
    #[serde(with = "serde_bytes_16")]
    pub token:         Uuid,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceGrade {
    /// Server Grade — static IP or domain, acts as relay for the user's DGs.
    SG,
    /// Device Grade — laptop, phone, or any device behind arbitrary NAT.
    DG,
}

#[derive(Serialize, Deserialize)]
pub struct Device {
    pub alias:        String,
    #[serde(with = "serde_bytes_16")]
    pub uuid:         Uuid,
    pub grade:        DeviceGrade,
    /// Relay priority for SG-grade devices. Lower value = higher priority (1 = top).
    /// `None` for DG-grade devices (they do not act as relays).
    pub sg_rank:          Option<u32>,
    /// Advertised addresses for reaching this device, as hostnames or IPs with
    /// optional ":port" suffix (default 7777). Resolved at connection time — a
    /// name that only resolves inside one network simply fails to resolve
    /// elsewhere and is skipped. Empty for DG-grade devices.
    pub hosts:            Vec<String>,
    pub applications:     Vec<Application>,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub alias:   String,
    #[serde(with = "serde_bytes_16")]
    pub uuid:    Uuid,
    pub devices: Vec<Device>,
}

#[derive(Serialize, Deserialize)]
pub struct Invitation {
    #[serde(with = "serde_bytes_16")]
    pub id:         Uuid,
    /// One-time X25519 pair for the invitation DH (not an identity key).
    pub key_pair:   X25519KeyPair,
    #[serde(with = "serde_system_time")]
    pub expires_at: SystemTime,
}

/// State held by a node while waiting for a ContactResponse from the target's SG.
pub struct PendingContactExchange {
    /// Our one-time X25519 ephemeral key pair for this exchange.
    pub our_ephem_key_pair: X25519KeyPair,
    /// The invitation's X25519 public key (from the code).
    pub invitation_pk:      X25519PublicKey,
    /// Where the ContactResponse will come from.
    pub sg_addr:            SocketAddrV4,
}

/// State held by a new device while waiting for a BootstrapResponse from the SG.
pub struct PendingBootstrap {
    /// From the invitation code — needed to include in DeviceRegistration so the SG
    /// can look up the shared secret.
    pub invitation_id:      Uuid,
    /// Our one-time X25519 ephemeral key pair for this exchange.
    pub our_ephem_key_pair: X25519KeyPair,
    /// The invitation's X25519 public key (from the code).
    pub invitation_pk:      X25519PublicKey,
    /// Where to send DeviceRegistration once the response is received.
    pub sg_addr:            SocketAddrV4,
    /// Device alias entered by the user during setup — applied once bootstrap completes.
    pub device_alias:       String,
    /// Grade to assign to the local device once bootstrap completes.
    pub desired_grade:      DeviceGrade,
    /// SG rank to assign to the local device — `Some` only when `desired_grade == SG`.
    pub desired_sg_rank:    Option<u32>,
}

/// State held by an SG after sending a BootstrapResponse, while waiting for
/// the new device to send a DeviceRegistration.  Keyed by invitation ID.
pub struct PendingDeviceAcceptance {
    /// Bootstrap AEAD key (`aead_domain::BOOTSTRAP` over the X25519 DH output),
    /// not the raw shared secret. Used to decrypt DeviceRegistration.
    pub shared_secret: [u8; 32],
    pub expires_at:    SystemTime,
}

/// The local owner of this node. Extends User with contacts and a long-term key pair.
#[derive(Serialize, Deserialize)]
pub struct Owner {
    pub user:                User,
    pub contact_users:       Vec<Contact>,
    /// Long-term Ed25519 identity for this user (sign Connect*, contact card).
    pub key_pair:            Ed25519KeyPair,
    pub contact_invitations: Vec<Invitation>,
    pub device_invitations:  Vec<Invitation>,

    /// Latest version of the user's **private** state held by this node.
    /// On the writer SG this is authoritative; on other nodes it's the
    /// last version successfully pulled. See `Scope` for what's in scope.
    #[serde(default)]
    pub private_version: SyncVersion,
    /// Latest version of the user's **public** state held by this node.
    /// Bumped independently of `private_version` so contact-visible changes
    /// don't force a private-scope re-pull and vice versa.
    #[serde(default)]
    pub public_version:  SyncVersion,
    /// Append-only log of accepted `Change` events on this node, retained
    /// for `WRITE_LOG_RETENTION` so v2 partition reconciliation can replay
    /// the writer's history to a returning peer SG. Empty on non-writer
    /// nodes (they receive `WriteLogEntry`s during merge but don't persist
    /// their own log).
    ///
    /// **Persistence (§7.3):** not written into `node.toml` (directory snapshot).
    /// Stored separately as `write_log.toml` so the snapshot stays small as the
    /// log grows. Still deserialized from legacy `node.toml` if present.
    #[serde(default, skip_serializing)]
    pub write_log: Vec<WriteLogEntry>,
    /// Ephemeral — not persisted; rebuilt as connections are established.
    #[serde(skip)]
    pub active_connections:  HashMap<u16, ActiveConnection>,
    /// Ephemeral — sync v2 per-peer-SG watermarks from the latest
    /// `WatermarkProbe` exchange. Outer key: peer device uuid. Inner key:
    /// writer_sg_uuid. Inner value: the version that's the min of (our log,
    /// peer log) for that writer — the agreed reconciliation point.
    /// Rebuilt on each probe round-trip.
    #[serde(skip)]
    pub last_watermarks: HashMap<Uuid, HashMap<Uuid, SyncVersion>>,
    /// Ephemeral — sync v2 inbound merge proposals from peer SGs awaiting
    /// the actual merge step (7c.5/7c.6). Key: peer device uuid. Value:
    /// the entries the peer reported as missing on our side.
    #[serde(skip)]
    pub received_merge_proposals: HashMap<Uuid, Vec<WriteLogEntry>>,
    /// Ephemeral — true after a retention-exhausted merge path (write log
    /// pruned past a peer's watermark). Operator-visible data-loss signal
    /// (§7.1); cleared when a normal merge applies cleanly.
    #[serde(skip)]
    pub retention_fallback_active: bool,
    /// Ephemeral — short human detail for diagnostics (peer / writer uuids).
    #[serde(skip)]
    pub retention_fallback_detail: String,
    /// Ephemeral — not persisted; cleared when ConnectAck arrives.
    #[serde(skip)]
    pub pending_connections: HashMap<u16, PendingConnection>,
    /// Ephemeral — not persisted; set while waiting for ContactResponse.
    #[serde(skip)]
    pub pending_contact_exchange: Option<PendingContactExchange>,
    /// Ephemeral — not persisted; set while waiting for BootstrapResponse.
    #[serde(skip)]
    pub pending_bootstrap:   Option<PendingBootstrap>,
    /// Ephemeral — not persisted; set when this SG is awaiting DeviceRegistration.
    #[serde(skip)]
    pub pending_device_acceptances: HashMap<Uuid, PendingDeviceAcceptance>,

    // ── Tunnel state (all ephemeral, not persisted) ───────────────────────────

    /// SG side: fully established tunnels keyed by tunnel_id.
    #[serde(skip)]
    pub active_tunnels: HashMap<u16, ActiveTunnel>,
    /// SG side: tunnels mid-key-exchange, keyed by tunnel_id.
    #[serde(skip)]
    pub pending_tunnels: HashMap<u16, PendingTunnel>,
    /// SG side: rolling relay-packet counts per (sender_uuid, dest_uuid) pair.
    #[serde(skip)]
    pub tunnel_counters: HashMap<(Uuid, Uuid), TunnelCounter>,
    /// DG side: maps tunnel_id → ActiveConnection.id for the DG-to-DG connection.
    #[serde(skip)]
    pub dg_tunnel_map: HashMap<u16, u16>,
    /// DG sender side: ephemeral key exchange state, keyed by tunnel_id.
    #[serde(skip)]
    pub pending_tunnel_connections: HashMap<u16, PendingTunnelConnection>,
}

/// A known contact. Extends User with their long-term Ed25519 identity.
#[derive(Serialize, Deserialize)]
pub struct Contact {
    pub user:       User,
    /// Contact's long-term Ed25519 public key (identity verification).
    pub public_key: Ed25519PublicKey,
    /// Highest public-scope version we have applied for this contact via
    /// cross-user sync v1. Used as the `last_seen` baseline on outbound
    /// CrossUserPullRequest so the reply is `NoUpdates` when caught up.
    #[serde(default)]
    pub last_seen_public_version: SyncVersion,
}

/// SG side: maps a tunnel_id to the two active connection IDs on this relay SG.
/// Created once both legs of the DG-to-DG key exchange are complete.
pub struct ActiveTunnel {
    pub id:              u16,
    pub connection_a_id: u16,  // sender DG's connection to this SG
    pub connection_b_id: u16,  // dest DG's connection to this SG
    pub last_used_at:    Instant,
}

/// SG side: ephemeral state held while the DG-to-DG key exchange is in progress.
/// Keyed by tunnel_id in `Owner::pending_tunnels`.
pub struct PendingTunnel {
    pub tunnel_id:          u16,
    pub sender_device_uuid: Uuid,
    pub dest_device_uuid:   Uuid,
    pub sender_ephem_pk:    Option<X25519PublicKey>,
}

/// SG side: rolling packet count between a (sender, dest) DG pair.
/// Resets to (1, now) when the window expires before the threshold is reached.
pub struct TunnelCounter {
    pub count:        u32,
    pub window_start: Instant,
}

/// DG side: ephemeral state on DG_sender while waiting for the tunnel key
/// exchange to complete.  Keyed by tunnel_id in `Owner::pending_tunnel_connections`.
pub struct PendingTunnelConnection {
    pub tunnel_id:        u16,
    pub our_conn_id:      u16,
    pub our_key_pair:     X25519KeyPair,
    pub dest_device_uuid: Uuid,
}

/// Runtime SG health telemetry for a single (device, advertised-host) pair.
/// Keyed by `(device_uuid, host_string)` in `Node::sg_statuses` so we track
/// latency to every address a device advertises independently.
pub struct SgStatus {
    pub last_rtt:    Option<Duration>,
    pub up:          bool,
    pub last_polled: Instant,
}

#[derive(Serialize, Deserialize)]
pub struct Node {
    pub owner:       Owner,
    #[serde(with = "serde_bytes_16")]
    pub device_uuid: Uuid,
    /// Local admin UI password hash (`v1$salt$hash`). Never synced to peers —
    /// each device has its own admin password. Empty / `None` means no password
    /// set yet (first-run or pre-auth upgrade); the UI forces set-password.
    #[serde(default)]
    pub admin_password_hash: Option<String>,
    /// Ephemeral — not persisted; refreshed by PollSG on each run.
    /// Keyed by `(device_uuid, host_string)` — the host_string matches an
    /// entry in that device's `hosts` list.
    #[serde(skip)]
    pub sg_statuses: HashMap<(Uuid, String), SgStatus>,
    /// Ephemeral — last computed "own-user SG peer(s) all-down" flag, used to
    /// emit structured `partition_detect` / `partition_clear` logs on change
    /// (§6.2) and for diagnostics. Not persisted.
    #[serde(skip)]
    pub partition_flag: bool,
    /// Ephemeral — true while the preferred (lowest `sg_rank`) own SG is
    /// polled-down and writer/traffic has moved to a lower-rank SG or local
    /// (§6.3). Used to log `rank_failover` / `rank_recovery` on transition.
    #[serde(skip)]
    pub rank1_failover_active: bool,
}

impl Owner {
    /// Bump the version counter for the given scope, recording `writer_uuid`
    /// as the SG that accepted the write. Called by the writer SG immediately
    /// after persisting an accepted write request.
    pub fn bump_version(&mut self, scope: Scope, writer_uuid: Uuid) {
        match scope {
            Scope::Private => self.private_version.bump(writer_uuid),
            Scope::Public  => self.public_version.bump(writer_uuid),
        }
    }

    pub fn version(&self, scope: Scope) -> SyncVersion {
        match scope {
            Scope::Private => self.private_version,
            Scope::Public  => self.public_version,
        }
    }
}

impl Node {
    /// Create a brand-new node with no contacts, no apps, and placeholder keys.
    /// Used on first run before the user has completed setup.
    /// Returns true once the node has completed first-run setup (keys are non-zero).
    pub fn is_initialized(&self) -> bool {
        self.owner.key_pair.public_key != Ed25519PublicKey::ZERO
    }

    pub fn new() -> Self {
        let owner_uuid  = generate_uuid();
        let device_uuid = generate_uuid();

        let device = Device {
            alias:        "This Device".to_string(),
            uuid:         device_uuid,
            grade:        DeviceGrade::DG,
            sg_rank:      None,
            hosts:        Vec::new(),
            applications: Vec::new(),
        };

        Node {
            device_uuid,
            admin_password_hash: None,
            sg_statuses: HashMap::new(),
            partition_flag: false,
            rank1_failover_active: false,
            owner: Owner {
                user: User {
                    alias:   "Owner".to_string(),
                    uuid:    owner_uuid,
                    devices: vec![device],
                },
                contact_users:       Vec::new(),
                key_pair:            Ed25519KeyPair::ZERO,
                contact_invitations:        Vec::new(),
                device_invitations:         Vec::new(),
                private_version:            SyncVersion::zero(),
                public_version:             SyncVersion::zero(),
                write_log:                  Vec::new(),
                active_connections:         HashMap::new(),
                last_watermarks:            HashMap::new(),
                received_merge_proposals:   HashMap::new(),
                retention_fallback_active:  false,
                retention_fallback_detail:  String::new(),
                pending_connections:        HashMap::new(),
                pending_contact_exchange:   None,
                pending_bootstrap:          None,
                pending_device_acceptances: HashMap::new(),
                active_tunnels:             HashMap::new(),
                pending_tunnels:            HashMap::new(),
                tunnel_counters:            HashMap::new(),
                dg_tunnel_map:              HashMap::new(),
                pending_tunnel_connections: HashMap::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer_a() -> Uuid { [0xAA; 16] }
    fn writer_b() -> Uuid { [0xBB; 16] }

    #[test]
    fn try_fill_random_fills_buffer() {
        let mut buf = [0u8; 32];
        try_fill_random(&mut buf).expect("getrandom");
        // CSPRNG output should not be all-zero with overwhelming probability.
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn generate_uuid_and_key_bytes_are_nonzero_and_vary() {
        let a = generate_uuid();
        let b = generate_uuid();
        assert_ne!(a, [0u8; 16]);
        assert_ne!(a, b);
        let k1 = generate_key_bytes();
        let k2 = generate_key_bytes();
        assert_ne!(k1, [0u8; 32]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn zero_is_initial_and_default_matches() {
        let z = SyncVersion::zero();
        assert!(z.is_initial());
        assert_eq!(z, SyncVersion::default());
    }

    #[test]
    fn bump_same_writer_increments_seq() {
        let mut v = SyncVersion::zero();
        v.bump(writer_a());
        assert_eq!(v.writer_sg_uuid, writer_a());
        assert_eq!(v.epoch, 1);
        assert_eq!(v.seq,   1);
        v.bump(writer_a());
        assert_eq!(v.epoch, 1);
        assert_eq!(v.seq,   2);
    }

    #[test]
    fn bump_different_writer_increments_epoch_and_resets_seq() {
        let mut v = SyncVersion::zero();
        v.bump(writer_a()); // epoch 1, seq 1
        v.bump(writer_a()); // epoch 1, seq 2
        v.bump(writer_b()); // writer change → epoch 2, seq 1
        assert_eq!(v.writer_sg_uuid, writer_b());
        assert_eq!(v.epoch, 2);
        assert_eq!(v.seq,   1);
    }

    #[test]
    fn cmp_same_writer_orders_by_epoch_then_seq() {
        use std::cmp::Ordering;
        let a = SyncVersion { writer_sg_uuid: writer_a(), epoch: 1, seq: 5  };
        let b = SyncVersion { writer_sg_uuid: writer_a(), epoch: 1, seq: 10 };
        let c = SyncVersion { writer_sg_uuid: writer_a(), epoch: 2, seq: 1  };
        assert_eq!(a.cmp_same_writer(&b), Some(Ordering::Less));
        assert_eq!(b.cmp_same_writer(&a), Some(Ordering::Greater));
        assert_eq!(b.cmp_same_writer(&c), Some(Ordering::Less));
        assert_eq!(a.cmp_same_writer(&a), Some(Ordering::Equal));
    }

    #[test]
    fn cmp_different_writer_returns_none() {
        let a = SyncVersion { writer_sg_uuid: writer_a(), epoch: 1, seq: 5 };
        let b = SyncVersion { writer_sg_uuid: writer_b(), epoch: 1, seq: 5 };
        assert_eq!(a.cmp_same_writer(&b), None);
    }

    #[test]
    fn owner_bump_routes_by_scope() {
        let mut node = Node::new();
        let w = writer_a();
        node.owner.bump_version(Scope::Private, w);
        assert_eq!(node.owner.private_version.seq, 1);
        assert_eq!(node.owner.public_version.seq,  0); // untouched
        node.owner.bump_version(Scope::Public, w);
        assert_eq!(node.owner.private_version.seq, 1);
        assert_eq!(node.owner.public_version.seq,  1);
    }

    #[test]
    fn versions_roundtrip_through_toml() {
        let mut node = Node::new();
        node.owner.bump_version(Scope::Private, writer_a());
        node.owner.bump_version(Scope::Public,  writer_a());
        node.owner.bump_version(Scope::Public,  writer_a());

        let s = toml::to_string(&node).expect("serialize");
        let restored: Node = toml::from_str(&s).expect("deserialize");

        assert_eq!(restored.owner.private_version.writer_sg_uuid, writer_a());
        assert_eq!(restored.owner.private_version.epoch, 1);
        assert_eq!(restored.owner.private_version.seq,   1);
        assert_eq!(restored.owner.public_version.epoch,  1);
        assert_eq!(restored.owner.public_version.seq,    2);
    }

    #[test]
    fn missing_version_fields_default_to_zero() {
        // Older node.toml files written before SyncVersion existed will lack
        // the `private_version` and `public_version` tables. They must
        // deserialize cleanly with the zero sentinel.
        let legacy = r#"
device_uuid = "00112233445566778899aabbccddeeff"

[owner]
contact_users       = []
contact_invitations = []
device_invitations  = []

[owner.user]
alias   = "Legacy"
uuid    = "00112233445566778899aabbccddeeff"
devices = []

[owner.key_pair]
public_key  = "0000000000000000000000000000000000000000000000000000000000000000"
private_key = "0000000000000000000000000000000000000000000000000000000000000000"
"#;
        let restored: Node = toml::from_str(legacy).expect("deserialize legacy");
        assert!(restored.owner.private_version.is_initial());
        assert!(restored.owner.public_version.is_initial());
    }
}
