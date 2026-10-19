# Processing of communications

Apps talk to a local pNet node over UDP (default pNet data port; the app
chooses its own listen port and registers it). Peer-to-peer fabric ops
(connect, sync, relay, etc.) are separate — see `pnet to pnet communication.md`.

Byte 0 of every **app → node** request is the operation type below.

## Local app ops (0–7)

### Reply framing (control ops 0–2 and 5–7)

| Status | Layout |
|--------|--------|
| Success | `[0x00]` or `[0x00][payload…]` |
| Error | `[0x01][error_code: u8]` |

### Error codes (`error_code`)

Defined in `src/lib/wire.rs` (stable for apps):

| Code | Name | Meaning |
|------|------|---------|
| `0x01` | `ERR_BAD_PACKET` | Malformed body (too short, bad fields) |
| `0x02` | `ERR_TOKEN_UNKNOWN` | Token not registered on this device |
| `0x03` | `ERR_NO_WRITER` | Public-scope change needs a writer SG; none reachable |
| `0x04` | `ERR_NOT_APPROVED` | Token valid but app not user-approved |
| `0x05` | `ERR_NO_ROUTE` | No path to dest (no session / no reachable SG) |
| `0x06` | `ERR_PAYLOAD_TOO_LARGE` | Payload longer than `MAX_APP_PAYLOAD` (4096) |
| `0x07` | `ERR_RATE_LIMITED` | Register/send token-bucket rate limit exceeded |

Handlers live in `src/lib/handlers/app_edge.rs`.

### Exposure policy (who may call ops 0–3 and 5–7)

The data plane UDP socket (`0.0.0.0:7777`) also carries **peer fabric**
ops. Local app control/data is a different trust model: the token is only
as strong as “anyone who can reach this UDP port.”

**Default:** ops `0x00`–`0x03` and `0x05`–`0x07` are accepted **only from
loopback** (`127.0.0.1` / `::1`). Non-loopback sources are dropped at the
UDP listener (no error reply). Op `0x04` is a push the node sends.

**Opt-in remote apps** (Docker sidecar on another container IP, multi-user
host, etc.):

```
PNET_APP_API_REMOTE=1
```

**Risk when remote is enabled:** any host that can send UDP to the node can
attempt `register` / `get_data` / `send` / the purse reads for any token
it learns. Prefer loopback when the app shares the host. Stage/live
compose sets remote for sidecar probes.

**Rate limits** (in-process token buckets, see `src/lib/app_api.rs`):

| Op | Key | Default capacity / refill |
|----|-----|---------------------------|
| register | source IP | 10 / 2 per second |
| send | source IP **and** app token | 200 / 100 per second each |

Exceeded limits reply `[0x01][ERR_RATE_LIMITED]`.

### Fabric constant: `MAX_APP_PAYLOAD`

**`MAX_APP_PAYLOAD = 4096`** (defined once in `src/lib/wire.rs`) is the fabric
ceiling for the **opaque app bytes** on every path that carries them:

| Path | Enforcement |
|------|-------------|
| Local op 3 `app_send_packet` | Reject with `ERR_PAYLOAD_TOO_LARGE` |
| Peer `RelayPacket` (0x40) | Drop (no forward / no local push). Also drop when the destination device is ours and the sender contact has no grant for that app alias |
| Peer `AppPacket` (0x41) | Drop (no local push) |
| Tunnel delivery (0x54) | Drop (no local push) |
| Tunnel forward (0x51) | Cap on opaque `nonce‖ciphertext` (`MAX_TUNNEL_FORWARD_BLOB`) |

This is not a path-MTU guarantee: stay ≈1 KiB or less if you want to avoid IP
fragmentation on typical WANs. Larger app messages must be chunked by the app.

A relay SG decrypts op 0x40, so it can drop a packet to one of its own devices
when the sender's contact has not been accepted for that app alias. Tunnel
forward (0x51) does not show the app id, so the destination device drops the
packet when it decrypts the delivery.

### 0 — application registration

- Request (after op): `[alias_len:u8][alias][port:u16 be][protocol_len:u8][protocol]`
- Success: `[0x00][token: 16]`
- Errors: `ERR_BAD_PACKET`, `ERR_NO_WRITER` (auto-approve path only)

### 1 — application update

- Request: `[token:16][flags:u8]` then optional alias/port fields
- Success: `[0x00]`
- Errors: `ERR_BAD_PACKET`, `ERR_TOKEN_UNKNOWN`, `ERR_NO_WRITER`

### 2 — application get data

- Request: `[token:16]`
- Success: `[0x00]` + directory tree the app may see (no private keys)
- Errors: `ERR_BAD_PACKET`, `ERR_TOKEN_UNKNOWN`
- Purpose: discovery of contacts/devices/apps for op 3 destinations

### 3 — application send packet

- Request: `[token:16][dest_device_uuid:16][dest_app_id:16][payload…]`
- **Success: no reply** (fire-and-forget; local acceptance ≠ end-to-end delivery)
- **Error: `[0x01][error_code]`** with codes from the table above, including
  `ERR_TOKEN_UNKNOWN`, `ERR_NOT_APPROVED`, `ERR_NO_ROUTE`, `ERR_PAYLOAD_TOO_LARGE`
- Payload max: see **Fabric constant: `MAX_APP_PAYLOAD`** above (same limit on
  relay / AppPacket / tunnel delivery).
- Node routes via active DG↔DG tunnel, direct session, or SG relay as available.

### 4 — push to app (node → app)

- Node delivers inbound app data: `[0x04][sender_app_id:16][payload…]`
- Only **user-approved** local apps receive pushes. Shared helper
  `local_approved_app_host` gates **all** inbound paths: local relay delivery,
  `AppPacket` (0x41), and tunnel delivery (0x54). Unapproved apps are silent
  drops.

### 5 — list purses

- Request: `[token:16]` exactly. Extra bytes are `ERR_BAD_PACKET`.
- The token must belong to an approved app on this device.
- Success: `[0x00][count:u16 be]` then, ordered by name then id, each purse
  the caller's alias belongs to:
  `[id:16][name][kind:u8][allotment:i64 be][available:i64 be]`
- `kind` is 0 (fixed). Amounts are nanodollars. Another alias's purses are
  absent. Count 0 is success. The read does not change a purse.
- Errors: `ERR_BAD_PACKET`, `ERR_TOKEN_UNKNOWN`, `ERR_NOT_APPROVED`

### 6 — list incoming payments

- Request: `[token:16]` exactly. Same approval check as op 5.
- Success: `[0x00][count:u16 be]` with count 0 until a payment is stored.
- These lines will be payments sent to this user for this app alias.

### 7 — list sent payments

- Same request, same approval check, and the same empty success as op 6.
- These lines will be payments this app sent.

### get-data secrecy (op 2)

- Echoes **only the requesting app's own token** (never sibling or contact tokens).
- Own-device apps list id/alias/host/approved **without tokens**.
- Contact apps: **approved only**, id + alias only (no host/token).
- No identity/ephemeral private keys and no contact long-term keys in the reply.

---

Fabric administration (connect, bootstrap, sync, tunnels) uses other op
ranges and is documented elsewhere (`pnet to pnet communication.md`,
`data sync.md`).

