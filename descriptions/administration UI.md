# Administration UI (Config) and owner portal

The owner-facing website is the **Config** control plane plus a portal
**Home** page (see `descriptions/app-web-surfaces.md`). It is served over
HTTP on port **8777** by default (`PNET_HTTP_PORT` overrides).

**Only a server-grade (SG) node binds this port.** A device-grade (DG) node
does not host the website at all — not on port 80, and not on 8777. Phones,
laptops, and other DG nodes reach the portal by opening it on one of their
SG devices. `PNET_HTTP_BIND` is ignored on a DG.

| Path | Role |
|------|------|
| `/` | Portal home — app page links (when registered) + Config |
| `/config` | Config hub — overview stats and links to control sections |
| `/apps/<slug>/…` | Reverse-proxy to a local app HTTP port (owner session required) |
| `/api/app-web/register` | **Loopback only** — app process registers `slug` + `port` (+ optional `title`) |
| `/api/app-web/unregister` | **Loopback only** — remove a mount by `slug` |
| `/devices`, `/invitations`, … | Config section pages (same capabilities as the classic admin UI) |
| `/security` | Password change and optional authenticator 2FA |
| `/login/2fa` | Second login step when TOTP is enrolled |
| `/reauth` | Step-up prompt before invite mint (when elevation expired) |
| `/dashboard` | Redirects to `/` (legacy) |

Owner portal pages require sign-in (admin password session today). Mount
registration is authenticated by **loopback source address** (local apps), not
by the owner cookie. Proxied `/apps/<slug>/…` POST bodies may be up to **4 MiB**
(Config/login stay at 64 KiB) so filesync uploads fit through the portal.

Example (manual register after an app listens on port 9080):

```bash
curl -sS -X POST http://127.0.0.1:8777/api/app-web/register \
  --data 'slug=hello&port=9080&title=Hello'
# Then open /apps/hello/ while signed in to the portal.
```

Sample apps live in sibling repos under `~/code/pNet_project/` (not in this
crate). From that directory:

```bash
cargo run --manifest-path pnet_web_hello/Cargo.toml     # /apps/hello/
cargo run --manifest-path pnet_filesync/Cargo.toml      # /apps/filesync/
cargo run --manifest-path pnet_installer/Cargo.toml     # /apps/installer/
# Empty machine: pnet_installer bootstrap --from DIR --prefix ~/.pnet
```

## Access & Authentication

On first-run setup of an **SG** (new user or join), the installer or `PNET_ADMIN_PASSWORD` sets an **admin password** for this node's portal. The password is stored as a salted hash on the local node only (`admin_password_hash` in `node.toml`) and is never synced to peers. A DG has no portal, so it does not ask for one.

After setup, every admin page requires a login session:

* `POST /login` with the admin password issues an HttpOnly `pnet_session` cookie (24h, in-memory sessions).
* If authenticator 2FA is enrolled, login continues at `GET|POST /login/2fa` (TOTP or a one-time recovery code) before the session can browse.
* Unauthenticated requests redirect to `/login`.
* `POST /logout` clears the session.
* Nodes upgraded from a pre-password build (initialized but no hash) are forced through `/set-password` once.

**Optional TOTP 2FA** (RFC 6238, HMAC-SHA1, 30s, 6 digits) is enrolled per node on **Config → Security** (`/security`). The TOTP secret, recovery-code hashes, and last used time-step are node-local (`admin_totp_secret`, `admin_totp_recovery_hashes`, `admin_totp_last_step` in `node.toml`) and are never synced. Compatible with Google Authenticator, Aegis, 1Password, and other `otpauth://totp` apps.

If you lose the authenticator **and** the recovery codes, remove those three fields from `node.toml` on that device (with the node stopped) to fall back to password-only.

**Step-up:** browsing Home, app mounts, and Config GETs uses the signed-in session. Minting a device or contact invitation requires a **recent re-auth** (password, plus TOTP if enrolled) within the last 10 minutes. Fresh login starts elevated. Password change and 2FA enroll/disable ask for the current password (and TOTP when enabled) on the form itself.

Login attempts are rate-limited per client IP (burst of 8, then about one try every 5 seconds).

Headless deploys may set `PNET_ADMIN_PASSWORD` at startup to store a hash when none exists yet. That does **not** enroll TOTP.

**v1 session model:** one owner session cookie (not a separate “app browsing” cookie). Passkeys / WebAuthn are not implemented yet.

## CSRF / session cookie policy

Admin session cookies are always issued as:

`HttpOnly; SameSite=Strict; Path=/`

**Primary CSRF defence:** `SameSite=Strict` means modern browsers do **not** attach `pnet_session` to cross-site requests (including cross-site form POSTs). A malicious page cannot drive state-changing admin actions while you are logged in.

**Secondary check:** if a POST includes an `Origin` or `Referer` header, the host must match the request `Host` header; otherwise the server responds `403`. Clients that omit both headers (typical `curl` / scripts) are allowed, but still need a valid session when auth is required.

Prefer loopback bind (`127.0.0.1`) whenever possible. Remote admin (`PNET_HTTP_BIND=0.0.0.0`) relies on this SameSite policy plus password auth — do not disable cookies or proxy in ways that strip `SameSite`.

## Fabric address family (v1)

The pNet **UDP fabric is IPv4-only** in v1 (device hosts, peer sessions, DNS
resolve). Admin HTTP also binds IPv4 addresses only (`PNET_HTTP_BIND`). See
`descriptions/wire-versioning.md` and `pnet to pnet communication.md`.

## HTTP bind policy

When the portal runs (SG only), it binds to **loopback only** by default (`127.0.0.1`). That keeps the control plane off the LAN/WAN unless the operator opts in. A DG never binds, so there is no DG website to expose.

To expose an SG portal beyond the host (Docker port publish, remote admin, etc.), set:

```
PNET_HTTP_BIND=0.0.0.0
```

Any IPv4 address is accepted (e.g. a specific LAN interface). Invalid values fall back to loopback. Legacy `PNET_HTTP_BIND_ALL=1` is still accepted as an alias for `0.0.0.0` when `PNET_HTTP_BIND` is unset; prefer `PNET_HTTP_BIND`.

Password auth alone is not a full substitute for network exposure controls — bind loopback when you can, and treat non-loopback binds as intentional remote admin.

## Pages

### Setup (first run)

The website does not collect first-run setup. `pnet_installer bootstrap` asks
in a terminal dialog, then starts `pnet` with the parameters below. If those
parameters are already on the command line, the dialog is skipped.

| Grade | Dialog / flags | Variables passed to `pnet` |
|-------|----------------|----------------------------|
| DG | device name, connection code | `PNET_GRADE=dg`, `PNET_DEVICE_ALIAS`, `PNET_INVITATION_CODE` |
| SG, new user | name, device name, rank, reachable addresses, portal password | `PNET_GRADE=sg`, `PNET_USER_ALIAS`, `PNET_DEVICE_ALIAS`, `PNET_SG_RANK`, `PNET_HOSTS`, `PNET_ADMIN_PASSWORD` |
| SG, join | device name, connection code, rank, reachable addresses, portal password | same as new, with `PNET_INVITATION_CODE` instead of `PNET_USER_ALIAS` |

Headless installs set the same variables directly (no dialog). They are
ignored once the node is initialized, except `PNET_HOSTS`, which stays
authoritative for the local SG device on every startup. DG devices leave
`hosts` empty; their peer address is learned from the source of incoming
packets.

A DG has no portal password to type. An SG stores `PNET_ADMIN_PASSWORD` as
the portal hash when none exists yet. After an SG join is accepted, the
portal (already listening because `PNET_GRADE=sg`) shows a short waiting
page and then the normal sign-in. There is no `/setup` form.

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

**Code delivery (no query-string secrets):** after `POST /invitations/device` or `POST /invitations/contact`, the server responds `302 Location: /invitations` and:

* Sets a **one-shot session flash** so the next `GET /invitations` shows the code once in the page body (not in the URL, browser history, or Referer).
* Also returns `X-Pnet-Invitation-Code: <code>` on the 302 for automation/harnesses (scripts should read this header; do not scrape query strings).

Redeem paths use POST body fields (`code=…`), not long-lived query parameters.

### Diagnostics (`GET /diagnostics`)

Fabric health snapshot (§6.2):

* **Writer SG** — result of `find_writer_sg` (Local / Remote / Unreachable)
* **Public and private** sync versions (writer uuid, epoch, seq)
* **Partition flag** — own-user SG peer(s) unanimously polled-down
* **Retention fallback** — write-log pruned past a peer watermark; concurrent writes may have been discarded for full-state adopt (§7.1 data-loss path)
* **Active sessions** — peer alias/uuid, conn id, `peer_addr`, session remaining, refresh-age proxy (lifetime − remaining; approximates time since last connect/keepalive refresh)
* **Own-user SG peers** — hosts with up/down, last RTT, poll age
* Sync v2: last watermarks, buffered merge proposals

Banners on every page: yellow for **partition**; red for **retention fallback**.

Structured process logs (stdout) for operators/grep:

`[fabric] event=<name> key=value …`

Events: `session_up`, `session_down`, `writer_change`, `partition_detect` / `partition_clear`, `invite_consumed`, `rank_failover` / `rank_recovery`, `tunnel_teardown`, `merge_applied`, `merge_ack`, `retention_fallback` (proposer or receiver; never silent discard).

#### Device invitation detail

When the owner generates a device invitation, the node:
1. Selects the target SG — always the **top-ranked online SG**: the lowest-`sg_rank` SG (with hosts) that is either this device itself or one it holds an active connection to. A more-preferred connected SG always wins, so even a lower-ranked SG defers to it; a device only targets itself when it is the top-ranked online SG (or no more-preferred SG is reachable). A DG with no connected SG has no target and the generation fails.
2. Creates an `Invitation` with a fresh ephemeral key pair and an expiry time **on the target SG**, not necessarily on the generating device. If this device *is* the target SG, it mints the invitation locally. Otherwise — whether this device is a DG or a lower-ranked SG — it sends a `GenerateInvitationRequest` (op 0x35) to the target SG over the encrypted own-device channel; the SG mints + stores the invitation and returns the encoded code in a `GenerateInvitationResponse` (op 0x36). The generating device's UI thread blocks (≤5 s) on this round-trip. This guarantees the invitation already exists on the SG the code points to — the code cannot exist until the SG has stored it.
3. Stores the invitation in `owner.device_invitations` on that SG. Invitations are device-local (never synced); having the top-ranked SG mint it is what closes the lookup gap when the new device bootstraps.
4. Displays a shareable code (once, via flash / response header): base64 of `invitation_id (16) || invitation_public_key (32) || host_len (1) || host_bytes (host_len) || port (2)`, where `host_bytes` is the first entry from the target SG's `hosts` list (hostname or IP, no port suffix). Variable-length, suitable for copy-paste or QR code.

On the new device, `pnet_installer bootstrap` (or the command-line variables above) supplies the device alias, grade, and connection code before `pnet` starts. The node parses the invitation ID, public key, and SG host out of that code, then begins the bootstrap exchange (see pnet to pnet communication.md — Device Bootstrap). The new device does not show a setup page. A DG never serves the portal; an SG serves it after the parameters say it is server grade.
