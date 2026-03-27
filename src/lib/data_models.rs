use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::SystemTime;

// Curve25519 keys (32 bytes), compatible with NaCl/libsodium (rbnacl on the Rails side).
// Use X25519 for key exchange (EphemeralKeyExchange) and Ed25519 for signing (KeyPair).
pub type PublicKey  = [u8; 32];
pub type PrivateKey = [u8; 32];
pub type Uuid       = [u8; 16];

/// Read 16 cryptographically random bytes from the OS.
pub fn generate_uuid() -> Uuid {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("failed to read /dev/urandom");
    bytes
}

pub struct KeyPair {
    pub public_key:  PublicKey,
    pub private_key: PrivateKey,
}

pub struct ActiveConnection {
    pub id:                       u16,
    pub timeout:                  SystemTime,
    pub key_pair:                 KeyPair,
    pub peer_public_key:          PublicKey,
    pub peer_active_connection_id: u16,
    pub device_uuid:              Uuid,
}

pub struct Application {
    pub id:            u16,
    pub alias:         String,
    pub protocol:      String,
    pub host:          SocketAddrV4,
    pub user_approved: bool,
    pub token:         Uuid,
}

pub struct Device {
    pub alias:        String,
    pub uuid:         Uuid,
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

/// The local owner of this node. Extends User with contacts and a long-term key pair.
pub struct Owner {
    pub user:                User,
    pub contact_users:       Vec<Contact>,
    pub key_pair:            KeyPair,
    pub contact_invitations: Vec<Invitation>,
    pub device_invitations:  Vec<Invitation>,
    pub active_connections:  HashMap<u16, ActiveConnection>,
}

/// A known contact. Extends User with an active ephemeral key exchange.
pub struct Contact {
    pub user:       User,
    pub public_key: PublicKey,
}

pub struct Node {
    pub owner:       Owner,
    pub device_uuid: Uuid,
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
            host:         "0.0.0.0:0".parse().unwrap(),
            applications: Vec::new(),
        };

        Node {
            device_uuid,
            owner: Owner {
                user: User {
                    alias:   "Owner".to_string(),
                    uuid:    owner_uuid,
                    devices: vec![device],
                },
                contact_users:       Vec::new(),
                key_pair:            KeyPair { public_key: [0; 32], private_key: [0; 32] }, // TODO: generate real Curve25519 keys
                contact_invitations: Vec::new(),
                device_invitations:  Vec::new(),
                active_connections:  HashMap::new(),
            },
        }
    }
}
