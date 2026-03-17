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

pub struct EphemeralKeyExchange {
    pub id: Uuid,
    pub timeout: SystemTime,
    pub key_pair: KeyPair,
    /// The remote peer's public key for this exchange.
    pub peer_public_key: PublicKey,
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
    pub api_key: String,
    pub ephemeral_key_exchange: EphemeralKeyExchange,
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
}

/// A known contact. Extends User with an active ephemeral key exchange.
pub struct Contact {
    pub user: User,
    pub public_key: PublicKey,
    pub ephemeral_key_exchange: EphemeralKeyExchange,
}

pub struct Node {
    pub owner: Owner,
    pub device_uuid: Uuid,
}
