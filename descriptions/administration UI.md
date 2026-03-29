# Administration UI

The administration UI is a web interface accessible only to the owner of the pNet node. It is served over HTTP on localhost, port 8087.

## Access & Authentication

The UI is only accessible from localhost. On first access, the owner is prompted to set an admin password. On subsequent visits, a password prompt is shown before access is granted.

## Pages

### Setup (first run)
Shown only on first access, before the password is set.
* Set admin password
* Set owner alias
* Set device alias

### Dashboard
An overview of the node's current state.
* Node and device identity (alias, uuid)
* Number of contacts
* Number of registered applications
* Number of active connections
* Recent activity feed (abbreviated, links to full Activity Log)

### Pending Apps
A list of applications that have registered but not yet been approved.
* Shows each app's alias and host
* Owner can approve or reject each one

### Applications
A list of all approved applications registered on this node.
* Shows alias, host, and approval status for each app

### Contacts
The owner's address book.
* Lists each contact by alias
* Shows their devices and connection availability

### Devices
The owner's other devices running pNet.
* Shows alias, host, and connection health for each device
* Connection health indicated as online / idle / offline based on last contact
* Last seen timestamp shown for each device

### Activity Log
A high-level log of notable events on the node.
* App sent a packet to a contact's device
* App received a packet
* Contact added or removed
* Device came online or went offline
* App approved or rejected
* Invitation created or used
* Each entry includes a timestamp

### Invitations
Manage invitation tokens used to add new contacts or devices.
* Generate a new contact invitation
* Generate a new device invitation
* View pending invitations with expiry times
* Revoke an invitation

#### Device invitation detail

When the owner generates a device invitation, the node:
1. Selects the target SG — itself if this device is an SG, otherwise the lowest-RTT up SG from `sg_statuses`.
2. Creates an `Invitation` with a fresh ephemeral key pair and an expiry time.
3. Stores it in `owner.device_invitations`. If this device is a DG, the invitation will be synced to the target SG by the future device-sync system before the new device tries to use it.
4. Displays a shareable code: base64 of `invitation_id (16) || invitation_public_key (32) || sg_host (6)` — 72 characters, suitable for copy-paste or QR code.

On the new, unconfigured device, the owner enters the invitation code. The node parses out the invitation ID, public key, and SG host, then begins the bootstrap exchange (see pnet to pnet communication.md — Device Bootstrap). After the exchange completes, the owner is prompted to set an alias and grade for the new device before it registers with the SG.
