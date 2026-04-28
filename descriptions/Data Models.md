# Node
description: holds information owned by the primary user of this pnet node
* owner
* device_uuid
	* uuid of the device this node is running on.
* sg_statuses
	* ephemeral, not persisted. `HashMap<(device_uuid, host_string), SgStatus>` — one entry per advertised host on every candidate SG, refreshed by the `PollSG` background task.

# Owner
description: the local owner of this node; extends User with contacts, a long-term key pair, module state, and ephemeral connection bookkeeping
* user
* contact_users
	* a list of Contact structs
* key_pair
	* long-term Curve25519 key pair used by the user when establishing ephemeral key connections
* contact_invitations
	* a list of Invitation structs
* device_invitations
	* a list of Invitation structs
* module_state
	* `HashMap<ModuleId, Vec<u8>>`. Each enabled module's private blob, persisted with the node and synced to the user's other devices via the device-data path. Opaque to pnet — each module serializes/deserializes its own state.
* active_connections
	* ephemeral. `HashMap<u16, ActiveConnection>` — fully established sessions keyed by our local connection id.
* pending_connections
	* ephemeral. half-open sessions awaiting `ConnectAck`.
* pending_contact_exchange / pending_bootstrap / pending_device_acceptances
	* ephemeral. state for the in-flight contact, bootstrap, and device-registration exchanges.
* active_tunnels / pending_tunnels / tunnel_counters / dg_tunnel_map / pending_tunnel_connections
	* ephemeral. SG-side and DG-side state for lazy DG-to-DG tunnels (see *Data transport diagram*).

# User
description: holds information unique to a user
* alias
* uuid
* devices
	* a list of devices owned by the user
* enabled_modules
	* `Vec<u16>`. The module ids this user has turned on. Active across all of the user's devices; synced to own devices via op 0x62/0x63 and to contacts via op 0x60/0x61 so contacts know which modules to address packets at.

# Contact
description: a known contact; extends User with a long-term public key
* user
* public_key
	* the contact's long-term public key

# Invitation
description: an invitation token used to add a contact or device
* id
* key_pair
* expires_at

# Device
description: holds information specific to a device (laptop, server, phone)
* alias
* uuid
* grade
	* SG (Server Grade) or DG (Device Grade)
* sg_rank
	* `Option<u32>`. Relay priority for SG-grade devices, lower = higher priority. None for DG.
* hosts
	* `Vec<String>`. Advertised addresses for reaching this device, as hostnames or IPs
	  with optional ":port" suffix (default 7777). Resolved at connection time — a
	  name that only resolves inside one network simply fails to resolve elsewhere
	  and is skipped. Empty for DG-grade devices (DG peer_addr is learned from the
	  source address of incoming packets). On SG devices the list is populated at
	  startup from the `PNET_HOSTS` environment variable.

> **Note**: there is no per-device app list. Apps are in-process modules; whether
> a module is on for the user is recorded at the User level via `enabled_modules`.

# KeyPair
description: a pair of Curve25519 encryption keys; Ed25519 for signing, X25519 for key exchange
* public_key
	* 32-byte Ed25519/X25519 public key
* private_key
	* 32-byte Ed25519/X25519 private key

# ActiveConnection
description: represents an active encrypted session with a peer device. Stored in a `HashMap<u16, ActiveConnection>` on Owner. Incoming packets include the receiver's id in the header, enabling O(1) key lookup for decryption without sending a full UUID.
* id: u16
	* local identifier; also the HashMap key
* timeout
* key_pair (ephemeral)
* peer_public_key (ephemeral)
* peer_active_connection_id: u16
	* the id the peer uses on their end; included in outbound packet headers
* device_uuid
	* identifies which device this connection is with
* peer_addr
	* the actual source address of the peer's last packet on this connection. Used for direct sends instead of the potentially-stale `Device.hosts`.

# SgStatus
description: runtime SG health telemetry for a single (device, advertised-host) pair, refreshed by `PollSG`. Ephemeral.
* last_rtt: `Option<Duration>`
* up: `bool`
* last_polled: `Instant`
