These models are my best thoughts about how to set this project up.  Of course I would like your feedback on how to make them work the best way for this project.

# Node
description: holds information pertinent only to this node
* id
	* there should only be one entry in this table
* has one user
	* represents the user who owns this node
* has one device
	* the device that represents this node

# User
description: holds information unique to a user
* id
	* used by the database
* uuid
	* unique generated ID represents this user to other pNet nodes
	* an index for this table
* has many devices
	* used when this record belongs to the node
* has many users through contacts
	* used when this record belongs to the node
* alias
	* term used to represent this user to humans on the UI
* has many key_pairs
	* the most recent key_pair is the used for user level encryption
	* other key_pairs are kept for possible reasons:
		* reestablishing outdated connections
		* transitioning to a  new key_pair
		* analytics


# Contact
description: a link to users so that users can be owned by a user
* id
	* used by the database
* owner_id
	* the user who owns
* contact_id
	* the user who is owned


# Device
description: holds information specific to a device (laptop, server, phone)
* id
* uuid
* alias
	* term used to represent this device to humans
* has many connections
	* the most recent connection should be the one used for communication
	* older ones are kept for analytics
* has many apps

# Connection
description: everything necessary to establish and keep a reliable udp connection
* id
* timeout
* has many  ephemeral_keys
	* the most recent ephemeral_key is used for communication
	* older keys many be useful when
		* running analytics
		* establishing a new ephemeral_key
		* triggering ephemeral_key updates
* host_name
	* usually an ip address and port number  such as '192.168.1.114:7777'
	* the network location where the udp packets will be sent

# KeyPair
description: a pair of encryption keys
* id
* public_key
* private_key

# EphemeralKeyExchange
description: a short key used for a short time period
* id
* timeout
* has one KeyPair
* has one public_key

# App
description: data required to handle communication with apps through the app api
* id
* app_uuid
	* the id sent by the app to designate itself when starting the authentication process
	* this value can be a database index and must be unique
* app_name
	* the human readable name the app gives itself 
* has many connections
	* the most recent connection should be the one used for communication
	* older ones are kept for analytics