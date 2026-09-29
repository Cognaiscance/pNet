# Node
description: holds information owned by the primary user of this pnet node
* owner
* device_uuid
	* uuid of the device this node is running on.

# Owner
description: the local owner of this node; extends User with contacts and a long-term key pair
* user
* contact_users
	* a list of Contact structs
* keypair
	* User Ed25519 identity. The public key is the user. The private seed signs device certificates and is sealed at rest. It is present on the node that created the user and on servers whose invitation released it. See `descriptions/identity-and-keys.md`.
* user_cert_sig / user_cert_issued_at
	* Self-signature on the user certificate (alias, public key, dates). No UUID in the signed payload.
* contact_invitations
	* a list of Invitation structs
* device_invitations
	* a list of Invitation structs
* active_connections
	* a list of ActiveConnection structs
* private_version
	* SyncVersion. Latest version of the user's **private** scope held by this node.
	  See `descriptions/data sync.md` for the writer-SG model and scope split.
* public_version
	* SyncVersion. Latest version of the user's **public** scope (visible to contacts).

# SyncVersion
description: per-scope version metadata used by the sync v1 protocol; total order within a single writer
* writer_sg_uuid
	* UUID of the SG that accepted the most recent write for this scope. Zero on a fresh node.
* epoch
	* u32. Increments on writer-SG transitions (failover or partition recovery).
* seq
	* u64. Monotonic counter inside an epoch; resets to 0 on epoch change.

# User
description: holds information unique to a user
* alias
* uuid
* devices
	* a list of devices owned by the user

# Contact
description: a known contact; extends User with an active ephemeral key exchange
* user
* public_key
	* the contact's long-term public key

# Invitation
description: an invitation token used to add a contact or device
* id
* key_pair
* expires_at
* releases_user_key
	* When true, bootstrap copies the user private key to the joiner. Default false. Set from the admin checkbox "this device is a server and may enroll other devices", and only honored when this node holds the user seed. A device-grade peer cannot set it by asking over op 0x35.

# Device
description: holds information specific to a device (laptop, server, phone)
* alias
* uuid
* grade
	* SG (Server Grade) or DG (Device Grade)
* sg_rank
	* Option<u32>. Relay priority for SG-grade devices, lower = higher priority. None for DG.
* hosts
	* Vec<String>. Advertised addresses for reaching this device, as hostnames or IPs
	  with optional ":port" suffix (default 7777). Resolved at connection time — a
	  name that only resolves inside one network simply fails to resolve elsewhere
	  and is skipped. Empty for DG-grade devices (DG peer_addr is learned from the
	  source address of incoming packets). On SG devices the list is populated at
	  startup from the `PNET_HOSTS` environment variable.
* applications
* signing_pk, dh_pk, cert_sig, cert_issued_at, cert_alias
	* Device certificate signed by the user key. `cert_alias` is the alias covered by the signature; the display alias may change later. Connect presents `signing_pk`, not the user key.

# Application
description: data required to handle communication with apps through the app api
* id: Uuid (16 bytes)
	* unique application id (partition-safe; union-by-id in sync v2 merge)
* alias
* host
	* a SocketAddrV4 (ipv4 address with port number)
* user_approved
	* true | false
* token
	* a UUID used to identify the application on subsequent local app-API requests
* identity
	* App Ed25519 key. The private seed is sealed at rest when this device generated it. An app may supply only the public key and keep the seed itself.
* cert_sig, cert_issued_at, cert_alias
	* Device signature over the app certificate. Issued when the owner approves the app (or when `PNET_AUTO_APPROVE_APPS` is set), not at mere registration.

# Ed25519KeyPair / Ed25519PublicKey / Ed25519SecretKey
description: long-term **identity** keys (Ed25519). The user key signs device certificates. Each device key signs app certificates and ConnectRequest/ConnectAck. Never used for Diffie–Hellman.
* public_key — 32-byte Ed25519 verifying key
* private_key — 32-byte Ed25519 seed, memory only
* private_key_sealed — Argon2id + XChaCha20-Poly1305 envelope written instead of the raw seed. A legacy plaintext `private_key` field still loads.

# X25519KeyPair / X25519PublicKey / X25519SecretKey
description: **ephemeral / invitation** keys (X25519). Used only for DH (sessions, bootstrap/contact invitations, tunnels). Never used for Ed25519 sign/verify.
* public_key — 32-byte X25519 public key
* private_key — 32-byte X25519 secret scalar

These are distinct Rust types so identity and DH material cannot be mixed at compile time. Public keys are 32-byte hex fields in TOML. Ed25519 private keys are sealed; invitation and session X25519 secrets remain on the device that created them.

# ActiveConnection
description: represents an active encrypted session with a peer device. Stored in a HashMap<u16, ActiveConnection> on Owner. Incoming packets include the receiver's id in the header, enabling O(1) key lookup for decryption without sending a full UUID.
* id: u16
	* local identifier; also the HashMap key
* timeout
* key_pair — local X25519 ephemeral (`X25519KeyPair`)
* peer_public_key — peer's X25519 ephemeral (`X25519PublicKey`)
* peer_active_connection_id: u16
	* the id the peer uses on their end; included in outbound packet headers
* device_uuid
	* identifies which device this connection is with
