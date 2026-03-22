use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::SystemTime;

// Curve25519 keys (32 bytes), compatible with NaCl/libsodium (rbnacl on the Rails side).
// Use X25519 for key exchange (EphemeralKeyExchange) and Ed25519 for signing (KeyPair).
pub type PublicKey = [u8; 32];
pub type PrivateKey = [u8; 32];
pub type Uuid = [u8; 16];

pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

pub struct ActiveConnection {
    pub id: u16,
    pub timeout: SystemTime,
    pub key_pair: KeyPair,
    pub peer_public_key: PublicKey,
    pub peer_active_connection_id: u16,
    pub device_uuid: Uuid,
}

pub enum ApplicationStatus {
    Accepted,
    Pending,
}

pub struct Application {
    pub uuid: Uuid,
    pub alias: String,
    pub host: SocketAddrV4,
    pub status: ApplicationStatus,
    pub token: Uuid,
}

pub struct Device {
    pub alias: String,
    pub uuid: Uuid,
    pub host: SocketAddrV4,
    pub applications: Vec<Application>,
}

pub struct User {
    pub alias: String,
    pub uuid: Uuid,
    pub devices: Vec<Device>,
}

pub struct Invitation {
    pub id: Uuid,
    pub key_pair: KeyPair,
    pub expires_at: SystemTime,
}

/// The local owner of this node. Extends User with contacts and a long-term key pair.
pub struct Owner {
    pub user: User,
    pub contact_users: Vec<Contact>,
    pub key_pair: KeyPair,
    pub contact_invitations: Vec<Invitation>,
    pub device_invitations: Vec<Invitation>,
    pub active_connections: HashMap<u16, ActiveConnection>,
}

/// A known contact. Extends User with an active ephemeral key exchange.
pub struct Contact {
    pub user: User,
    pub public_key: PublicKey,
}

pub struct Node {
    pub owner: Owner,
    pub device_uuid: Uuid,
}
