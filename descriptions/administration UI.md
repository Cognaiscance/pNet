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

SG-grade devices advertise their reachable addresses via the `PNET_HOSTS` environment variable rather than through the setup form — `PNET_HOSTS` is read at every startup and overwrites the local device's `hosts` list when set. DG-grade devices leave `hosts` empty; their peer address is learned from the source of incoming packets.

### Dashboard
An overview of the node's current state.
* Node and device identity (alias, uuid)
* Number of contacts
* Number of enabled modules (`User.enabled_modules.len()`)
* Number of active connections
* Recent activity feed (abbreviated, links to full Activity Log)

### Apps
A list of every module compiled into this binary. Each row shows the module's name, slug, and current state, with an Enable/Disable toggle.

* Toggling a module mutates `User.enabled_modules`, calls `Module::on_enable` or `on_disable`, and propagates the change to the user's other devices (op 0x62/0x63) and to contacts (op 0x60/0x61).
* A module's own UI, if any, is mounted under `/apps/<slug>/...` once it is enabled. Requests beneath that prefix are routed to the module's `on_http` handler with the prefix stripped — so `/apps/debug/inbox` arrives at the module as `/inbox`. Disabled or unknown modules return a 404. See *Apps and modules* for the trait surface.
* The bundled **debug** module (slug `debug`) renders the node state, an inbox of received packets, and a send form — useful for verifying routing end-to-end.

### Contacts
The owner's address book.
* Lists each contact by alias
* Shows their devices and connection availability

### Devices
The owner's other devices running pNet.
* Shows alias, advertised hosts list, and connection health for each device
* Connection health indicated as online / idle / offline based on last contact
* Last seen timestamp shown for each device

### Activity Log
A high-level log of notable events on the node.
* Module sent a packet to a contact's device
* Module received a packet
* Contact added or removed
* Device came online or went offline
* Module enabled or disabled
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
4. Displays a shareable code: base64 of `invitation_id (16) || invitation_public_key (32) || host_len (1) || host_bytes (host_len) || port (2)`, where `host_bytes` is the first entry from the target SG's `hosts` list (hostname or IP, no port suffix). Variable-length, suitable for copy-paste or QR code.

On the new, unconfigured device, the owner enters the invitation code. The node parses out the invitation ID, public key, and SG host, then begins the bootstrap exchange (see pnet to pnet communication.md — Device Bootstrap). After the exchange completes, the owner is prompted to set an alias and grade for the new device before it registers with the SG.
