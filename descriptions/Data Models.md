# Node
description: holds information owned by the primary user of this pnet node
* owner
* device_uuid
	* uuid of the device this node is running on.

# User
description: holds information unique to a user
* alias
* uuid
* devices
	* a list of devices owned by the user

# Owner
* the same attributes as user
* contact_users
	* a list of users who are friends with this user
* key pair

# Contact
* the same attributes as a user
* ephemeral_key_exchange

# Device
description: holds information specific to a device (laptop, server, phone)
* alias
* uuid
* host_name
	* an ipv4 address with port number
* applications

# KeyPair
description: a pair of encryption keys, I could use advice as to which type of keys to generate
* public_key
* private_key

# EphemeralKeyExchange
description: a short key used for a short time period
* id
* timeout
* has one KeyPair
* has one public_key

# Application
description: data required to handle communication with apps through the app api
* uuid
* alias
* host_name
* status
	* accepted | pending
* api_key
* ephemeral_key_exchange