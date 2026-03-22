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
	* a more secure long term key used by the user when  establishing ephemeral key connections
* contact_invitations
	* a list of Invitation structs
* device_invitations
	* a list of Invitation structs
* active_connections
	* a list of ActiveConnection structs

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

# Device
description: holds information specific to a device (laptop, server, phone)
* alias
* uuid
* host
	* a SocketAddrV4 (ipv4 address with port number)
* applications

# Application
description: data required to handle communication with apps through the app api
* id: u16
	* unique per device; used in packet headers to save space
* alias
* host
	* a SocketAddrV4 (ipv4 address with port number)
* status
	* Accepted | Pending
* token
	* a UUID used to identify the application on subsequent requests

# KeyPair
description: a pair of Curve25519 encryption keys; Ed25519 for signing, X25519 for key exchange
* public_key
	* 32-byte Ed25519/X25519 public key
* private_key
	* 32-byte Ed25519/X25519 private key

# ActiveConnection
description: represents an active encrypted session with a peer device. Stored in a HashMap<u16, ActiveConnection> on Owner. Incoming packets include the receiver's id in the header, enabling O(1) key lookup for decryption without sending a full UUID.
* id: u16
	* local identifier; also the HashMap key
* timeout
* key_pair (ephemeral)
* peer_public_key (ephemeral)
* peer_active_connection_id: u16
	* the id the peer uses on their end; included in outbound packet headers
* device_uuid
	* identifies which device this connection is with
