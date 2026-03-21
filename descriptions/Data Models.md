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
* key_pair
* contact_invitations
	* a list of Invitation structs
* device_invitations
	* a list of Invitation structs

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
* ephemeral_key_exchange

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
* uuid
* alias
* host
	* a SocketAddrV4 (ipv4 address with port number)
* status
	* Accepted | Pending
* api_key
* ephemeral_key_exchange

# KeyPair
description: a pair of Curve25519 encryption keys; Ed25519 for signing, X25519 for key exchange
* public_key
	* 32-byte Ed25519/X25519 public key
* private_key
	* 32-byte Ed25519/X25519 private key

# EphemeralKeyExchange
description: a short-lived key exchange session with a remote peer
* id
* timeout
* key_pair
* peer_public_key
	* the remote peer's public key for this exchange
