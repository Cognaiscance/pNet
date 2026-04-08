use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant, SystemTime};

pub const TUNNEL_THRESHOLD:      u32      = 10;
pub const TUNNEL_COUNTER_WINDOW: Duration = Duration::from_secs(5 * 60);

use serde::{Deserialize, Serialize};

// Curve25519 keys (32 bytes), compatible with NaCl/libsodium (rbnacl on the Rails side).
// Use X25519 for key exchange (EphemeralKeyExchange) and Ed25519 for signing (KeyPair).
pub type PublicKey  = [u8; 32];
pub type PrivateKey = [u8; 32];
pub type Uuid       = [u8; 16];

/// Active connections are renewed when less than this much time remains.
/// Must exceed MAINTAIN_CONNECTIONS_INTERVAL so a connection never lapses between checks.
pub const RENEW_THRESHOLD:    Duration = Duration::from_secs(2 * 3600);  // 2 hours
pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(24 * 3600); // 24 hours

/// Read 16 cryptographically random bytes from the OS.
pub fn generate_uuid() -> Uuid {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("failed to read /dev/urandom");
    bytes
}

/// Read 32 cryptographically random bytes from the OS (for ephemeral key generation).
pub fn generate_key_bytes() -> [u8; 32] {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("failed to read /dev/urandom");
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

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    #[serde(with = "serde_bytes_32")]
    pub public_key:  PublicKey,
    #[serde(with = "serde_bytes_32")]
    pub private_key: PrivateKey,
}

pub struct ActiveConnection {
    pub id:                        u16,
    pub timeout:                   SystemTime,
    pub key_pair:                  KeyPair,
    pub peer_public_key:           PublicKey,
    pub peer_active_connection_id: u16,
    pub device_uuid:               Uuid,
}

/// A half-open connection: we sent a ConnectRequest and are waiting for a ConnectAck.
/// Keyed by our local connection ID in `Owner::pending_connections`.
pub struct PendingConnection {
    pub our_conn_id:      u16,
    pub our_key_pair:     KeyPair,
    pub peer_device_uuid: Uuid,
    /// Long-term public key of the peer's user — used to verify the ConnectAck signature.
    pub peer_longterm_pk: PublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Application {
    pub id:            u16,
    pub alias:         String,
    pub protocol:      String,
    #[serde(with = "serde_socket_addr_v4")]
    pub host:          SocketAddrV4,
    pub user_approved: bool,
    #[serde(with = "serde_bytes_16")]
    pub token:         Uuid,
}

#[derive(Serialize, Deserialize)]
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
    pub sg_rank:      Option<u32>,
    #[serde(with = "serde_socket_addr_v4")]
    pub host:         SocketAddrV4,
    pub applications: Vec<Application>,
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
    pub key_pair:   KeyPair,
    #[serde(with = "serde_system_time")]
    pub expires_at: SystemTime,
}

/// State held by a node while waiting for a ContactResponse from the target's SG.
pub struct PendingContactExchange {
    /// Our one-time X25519 ephemeral key pair for this exchange.
    pub our_ephem_key_pair: KeyPair,
    /// The invitation's public key (from the code) — combined with our ephemeral
    /// private key to derive the shared secret.
    pub invitation_pk:      PublicKey,
    /// Where the ContactResponse will come from.
    pub sg_addr:            SocketAddrV4,
}

/// State held by a new device while waiting for a BootstrapResponse from the SG.
pub struct PendingBootstrap {
    /// From the invitation code — needed to include in DeviceRegistration so the SG
    /// can look up the shared secret.
    pub invitation_id:      Uuid,
    /// Our one-time X25519 ephemeral key pair for this exchange.
    pub our_ephem_key_pair: KeyPair,
    /// The invitation's public key (from the code) — combined with our ephemeral
    /// private key to derive the shared secret.
    pub invitation_pk:      PublicKey,
    /// Where to send DeviceRegistration once the response is received.
    pub sg_addr:            SocketAddrV4,
}

/// State held by an SG after sending a BootstrapResponse, while waiting for
/// the new device to send a DeviceRegistration.  Keyed by invitation ID.
pub struct PendingDeviceAcceptance {
    /// X25519 shared secret derived during the bootstrap exchange.
    pub shared_secret: [u8; 32],
    pub expires_at:    SystemTime,
}

/// The local owner of this node. Extends User with contacts and a long-term key pair.
#[derive(Serialize, Deserialize)]
pub struct Owner {
    pub user:                User,
    pub contact_users:       Vec<Contact>,
    pub key_pair:            KeyPair,
    pub contact_invitations: Vec<Invitation>,
    pub device_invitations:  Vec<Invitation>,
    /// Ephemeral — not persisted; rebuilt as connections are established.
    #[serde(skip)]
    pub active_connections:  HashMap<u16, ActiveConnection>,
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

/// A known contact. Extends User with an active ephemeral key exchange.
#[derive(Serialize, Deserialize)]
pub struct Contact {
    pub user:       User,
    #[serde(with = "serde_bytes_32")]
    pub public_key: PublicKey,
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
    pub sender_ephem_pk:    Option<PublicKey>,
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
    pub our_key_pair:     KeyPair,
    pub dest_device_uuid: Uuid,
}

/// Runtime SG health telemetry for a single candidate SG device.
/// Keyed by device UUID in `Node::sg_statuses`.
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
    /// Ephemeral — not persisted; refreshed by PollSG on each run.
    #[serde(skip)]
    pub sg_statuses: HashMap<Uuid, SgStatus>,
}

impl Node {
    /// Create a brand-new node with no contacts, no apps, and placeholder keys.
    /// Used on first run before the user has completed setup.
    /// Returns true once the node has completed first-run setup (keys are non-zero).
    pub fn is_initialized(&self) -> bool {
        self.owner.key_pair.public_key != [0u8; 32]
    }

    pub fn new() -> Self {
        let owner_uuid  = generate_uuid();
        let device_uuid = generate_uuid();

        let device = Device {
            alias:        "This Device".to_string(),
            uuid:         device_uuid,
            grade:        DeviceGrade::DG,
            sg_rank:      None,
            host:         "0.0.0.0:0".parse().unwrap(),
            applications: Vec::new(),
        };

        Node {
            device_uuid,
            sg_statuses: HashMap::new(),
            owner: Owner {
                user: User {
                    alias:   "Owner".to_string(),
                    uuid:    owner_uuid,
                    devices: vec![device],
                },
                contact_users:       Vec::new(),
                key_pair:            KeyPair { public_key: [0; 32], private_key: [0; 32] }, // TODO: generate real Curve25519 keys
                contact_invitations:        Vec::new(),
                device_invitations:         Vec::new(),
                active_connections:         HashMap::new(),
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
