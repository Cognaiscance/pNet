# Administration UI

The administration UI is a web interface accessible only to the owner of the pNet node. It is served over HTTP on localhost, port 8087.

## Access & Authentication

On first-run setup (new user or join), the owner sets an **admin password** for this node. The password is stored as a salted hash on the local node only (`admin_password_hash` in `node.toml`) and is never synced to peers.

After setup, every admin page requires a login session:

* `POST /login` with the admin password issues an HttpOnly `pnet_session` cookie (24h, in-memory sessions).
* Unauthenticated requests redirect to `/login`.
* `POST /logout` clears the session.
* Nodes upgraded from a pre-password build (initialized but no hash) are forced through `/set-password` once.

Headless deploys may set `PNET_ADMIN_PASSWORD` at startup to store a hash when none exists yet.

HTTP bind policy (loopback vs all interfaces) is separate — see control-plane checklist item 1.2.

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
* Shows alias, advertised hosts list, and connection health for each device
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
1. Selects the target SG — always the **top-ranked online SG**: the lowest-`sg_rank` SG (with hosts) that is either this device itself or one it holds an active connection to. A more-preferred connected SG always wins, so even a lower-ranked SG defers to it; a device only targets itself when it is the top-ranked online SG (or no more-preferred SG is reachable). A DG with no connected SG has no target and the generation fails.
2. Creates an `Invitation` with a fresh ephemeral key pair and an expiry time **on the target SG**, not necessarily on the generating device. If this device *is* the target SG, it mints the invitation locally. Otherwise — whether this device is a DG or a lower-ranked SG — it sends a `GenerateInvitationRequest` (op 0x35) to the target SG over the encrypted own-device channel; the SG mints + stores the invitation and returns the encoded code in a `GenerateInvitationResponse` (op 0x36). The generating device's UI thread blocks (≤5 s) on this round-trip. This guarantees the invitation already exists on the SG the code points to — the code cannot exist until the SG has stored it.
3. Stores the invitation in `owner.device_invitations` on that SG. Invitations are device-local (never synced); having the top-ranked SG mint it is what closes the lookup gap when the new device bootstraps.
4. Displays a shareable code: base64 of `invitation_id (16) || invitation_public_key (32) || host_len (1) || host_bytes (host_len) || port (2)`, where `host_bytes` is the first entry from the target SG's `hosts` list (hostname or IP, no port suffix). Variable-length, suitable for copy-paste or QR code.

On the new, unconfigured device, the owner enters the invitation code. The node parses out the invitation ID, public key, and SG host, then begins the bootstrap exchange (see pnet to pnet communication.md — Device Bootstrap). After the exchange completes, the owner is prompted to set an alias and grade for the new device before it registers with the SG.
