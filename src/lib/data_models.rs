use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant, SystemTime};

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

#[derive(Clone)]
pub struct KeyPair {
    pub public_key:  PublicKey,
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

pub struct Application {
    pub id:            u16,
    pub alias:         String,
    pub protocol:      String,
    pub host:          SocketAddrV4,
    pub user_approved: bool,
    pub token:         Uuid,
}

pub enum DeviceGrade {
    /// Server Grade — static IP or domain, acts as relay for the user's DGs.
    SG,
    /// Device Grade — laptop, phone, or any device behind arbitrary NAT.
    DG,
}

pub struct Device {
    pub alias:        String,
    pub uuid:         Uuid,
    pub grade:        DeviceGrade,
    pub host:         SocketAddrV4,
    pub applications: Vec<Application>,
}

pub struct User {
    pub alias:   String,
    pub uuid:    Uuid,
    pub devices: Vec<Device>,
}

pub struct Invitation {
    pub id:         Uuid,
    pub key_pair:   KeyPair,
    pub expires_at: SystemTime,
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
pub struct Owner {
    pub user:                User,
    pub contact_users:       Vec<Contact>,
    pub key_pair:            KeyPair,
    pub contact_invitations: Vec<Invitation>,
    pub device_invitations:  Vec<Invitation>,
    /// Fully established sessions, keyed by our local connection ID.
    pub active_connections:  HashMap<u16, ActiveConnection>,
    /// Half-open sessions awaiting ConnectAck, keyed by our local connection ID.
    pub pending_connections: HashMap<u16, PendingConnection>,
    /// Set when this device has sent a BootstrapRequest and is awaiting the response.
    pub pending_bootstrap:   Option<PendingBootstrap>,
    /// Keyed by invitation ID. Set when this SG has sent a BootstrapResponse and is
    /// awaiting the new device's DeviceRegistration.
    pub pending_device_acceptances: HashMap<Uuid, PendingDeviceAcceptance>,
}

/// A known contact. Extends User with an active ephemeral key exchange.
pub struct Contact {
    pub user:       User,
    pub public_key: PublicKey,
}

/// Runtime SG health telemetry for a single candidate SG device.
/// Keyed by device UUID in `Node::sg_statuses`.
pub struct SgStatus {
    pub last_rtt:    Option<Duration>,
    pub up:          bool,
    pub last_polled: Instant,
}

pub struct Node {
    pub owner:        Owner,
    pub device_uuid:  Uuid,
    /// RTT and up/down status for every candidate SG, refreshed by PollSG.
    pub sg_statuses:  HashMap<Uuid, SgStatus>,
}

impl Node {
    /// Create a brand-new node with no contacts, no apps, and placeholder keys.
    /// Used on first run before the user has completed setup.
    pub fn new() -> Self {
        let owner_uuid  = generate_uuid();
        let device_uuid = generate_uuid();

        let device = Device {
            alias:        "This Device".to_string(),
            uuid:         device_uuid,
            grade:        DeviceGrade::DG,
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
                pending_bootstrap:          None,
                pending_device_acceptances: HashMap::new(),
            },
        }
    }
}
