# Processing of communications

Apps talk to a local pNet node over UDP (default pNet data port; the app
chooses its own listen port and registers it). Peer-to-peer fabric ops
(connect, sync, relay, etc.) are separate — see `pnet to pnet communication.md`.

Byte 0 of every **app → node** request is the operation type below.

## Local app ops (0–8)

### Reply framing (control ops 0–2 and 5–8)

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
| `0x08` | `ERR_NOT_IN_PURSE` | Purse missing, or the caller's alias is not a member |
| `0x09` | `ERR_OVER_PURSE` | Amount is above the purse's available amount |
| `0x0A` | `ERR_PAYMENT_MISMATCH` | Payment id is already reserved with a different body |

Handlers live in `src/lib/handlers/app_edge.rs`.

### Exposure policy (who may call ops 0–3 and 5–8)

The data plane UDP socket (`0.0.0.0:7777`) also carries **peer fabric**
ops. Local app control/data is a different trust model: the token is only
as strong as “anyone who can reach this UDP port.”

**Default:** ops `0x00`–`0x03` and `0x05`–`0x08` are accepted **only from
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
- `kind` is 0 (fixed) or 1 (monthly). Amounts are nanodollars. Another alias's
  purses are absent. Count 0 is success. The read does not change a purse.
  A monthly purse refills to its allotment at the UTC month on the writer's
  clock. Unspent amount does not carry over.
- Errors: `ERR_BAD_PACKET`, `ERR_TOKEN_UNKNOWN`, `ERR_NOT_APPROVED`

### 6 — list incoming payments

- Request: `[token:16]` exactly. Same approval check as op 5.
- Success: `[0x00][count:u16 be]` then each confirmed line whose payee is this user and whose destination alias is the caller's alias, ordered by payment id and then the payer's confirmation signature:
  `[payment id:16][amount:i64 be][payer uuid:16][payee uuid:16][paying alias][destination alias][note]`
- Amounts are nanodollars. Strings are a length byte and then UTF-8, the same as a purse name. The purse id, the expiry, and the signatures are absent. A hold that is not confirmed is absent. A line for another alias is absent. Two signed bodies of one id are both listed. Count 0 is success. The read does not change a purse or the tab.
- Errors: `ERR_BAD_PACKET`, `ERR_TOKEN_UNKNOWN`, `ERR_NOT_APPROVED`

### 7 — list sent payments

- Same request, same approval check, and the same line layout as op 6.
- A line is included when this user is the payer and the paying alias is the caller's alias.

### 8 — reserve

- Request: `[token:16][purse id:16][amount:i64 be][contact uuid:16][destination alias][note][payment id:16]`
- Amount is nanodollars and must be greater than zero. The destination alias is trimmed. The note is opaque UTF-8, at most 255 bytes, and may be empty. No bytes follow the payment id.
- The caller must be an approved app, and a member of that purse. This node applies the reserve only when it is the writer.
- Success: `[0x00][available:i64 be][expires_at_ms:u64 be]`. `available` is what the purse still has. The hold lasts 24 hours from the writer's clock. The same payment id and the same body return this result again and do not reduce the available amount a second time. After a confirmation, the same id returns the purse's current available amount and the line's expiry, and does not reserve again.
- A node that is not the writer sends the reserve to the writer and waits. It does not change its own purse. The writer stamps the expiry from its own clock. The answer is the available amount, or the same error the writer would return. No reachable writer, or no answer, is `ERR_NO_WRITER`. When this node is the writer and holds the user key, it signs an offer and sends op `0x60` to the contact. A device that is not the writer does not sign the offer. The offer does not name the purse. A missing session leaves the hold until a retry, a refusal, or expiry.
- Errors: `ERR_BAD_PACKET`, `ERR_TOKEN_UNKNOWN`, `ERR_NOT_APPROVED`, `ERR_NO_WRITER`, `ERR_NOT_IN_PURSE`, `ERR_OVER_PURSE`, `ERR_PAYMENT_MISMATCH`.
- When the hold expires without a confirmation, the writer adds the amount back. A later reserve with a new payment id can use it. A confirmed payment is not added back. A hold taken in an earlier UTC month on a monthly purse is not added back. The new month starts at the allotment.

### 0x60 — payment offer

Session-sealed. The payer's writer sends this to the payee's writer. The plaintext is the offer body and the payer's user-key signature. The body is `[payment id:16][amount:i64 be][payer user uuid:16][payee user uuid:16][paying alias][destination alias][note][expires_at_ms:u64 be]`. The purse id is absent. The signature domain is `pnet-payment-offer-v1`.

The payee's writer drops a packet it cannot open, a bad signature, an offer for another user, or a packet that arrives on a node that is not the writer. An offer past `expires_at_ms` gets a signed refusal with reason `0x02`. An offer whose new claim would pass the run stored for that payer gets reason `0x01`. A missing run is zero. An amount equal to the run is accepted. A different body for a payment id already staged or stored gets reason `0x03`.

### 0x61 — payment accept

Session-sealed. The payee's writer sends this after it has signed the offer. The plaintext is the offer body, the payer signature, and the payee signature. The accept domain is `pnet-payment-accept-v1` over the body and the payer signature.

The payer's writer checks both signatures against the held offer. It then signs the confirmation and stores the charge, removing the hold without adding the amount back. It sends op `0x63`. A repeat of an accept that is already a line resends that confirmation.

### 0x62 — payment refuse

Session-sealed. The plaintext is the offer body, the payer signature, one reason byte, and the payee signature. The refuse domain is `pnet-payment-refuse-v1` over the body, the payer signature, and the reason byte. Reasons are `0x01` over the run, `0x02` expired, and `0x03` a different body for that payment id.

A signed refusal that matches the held offer releases it. A refusal after the line exists is ignored. A refusal that does not match the hold is ignored.

### 0x63 — payment confirm

Session-sealed. The plaintext is the accept plus the payer's second signature. The confirm domain is `pnet-payment-confirm-v1` over the body, the payer signature, and the payee signature.

The payee's writer stores the line when the three signatures verify. The purse id on that copy is 16 zero bytes. A repeat of the same confirmation is ignored. A second body for an id that already has a line is ignored on this op. Expiry drops a staged accept and does not by itself create a line. A confirmation that arrives after that still stores the line.

### 0x64 — payment index

Session-sealed. A writer sends this when a session to one of a contact's devices comes up. It is not sent to an own device. The plaintext is `[flags:u8][count:u16 be]` and then `count` entries of `[payment id:16][confirm signature:64]`. Flag `0x01` starts a list and replaces one in progress. Flag `0x02` ends the list. One packet can set both. A long list uses more than one packet, and the receiver unions them before comparing.

When the list ends, the receiver sends op `0x65` for each confirmed line of this pair whose payment id and confirmation signature are absent. It does not answer with another index. A node that is not the writer drops the packet.

### 0x65 — payment record

Session-sealed. The plaintext is the confirmation from op `0x63` and does not name a purse. The receiver stores it when the three signatures verify and the two users are this node and the contact that owns the session. A bad signature is dropped, and nothing is released or changed.

The same signed bytes are not stored twice. A different signed body is stored beside the first and does not reduce a purse again. The payee's copy uses an empty purse id. A payer with a matching hold consumes that hold and does not subtract again. A payer with no matching hold reduces the one purse that lists the paying alias, which can leave a negative available amount. If none or several do, the line is stored and no purse is chosen.

### 0x66 — settlement proposal

Session-sealed. One owner sends this to the other. An app does not. The plaintext is the body and the sender's user-key signature. The body is `[settlement id:16][user lo:16][user hi:16][count:u16 be][payment id:16…]`. The user ids are in byte order. The payment ids are strictly increasing, at least one and at most 64. The signature domain is `pnet-payment-clearing-v1` over the body. Both users sign those same bytes.

The receiver signs only when every named id is already a charge between this pair. An id that belongs to some other pair does not count. A missing id gets no reply. A bad signature is dropped. There is no refusal op. A node that is not the writer drops the packet.

### 0x67 — settlement ack

Session-sealed. The plaintext is the body plus the lower user's signature and then the higher user's signature. This is also the stored record. The same body is stored once and does not change a purse. A different body for the same settlement id is kept beside the first. The tab excludes every payment id named by any stored settlement for the pair. The lines stay on the tab and on ops `0x06` and `0x07`.

A repeat of a proposal the receiver has already signed sends this ack again and does not store a second row. If the sender already holds that exact record, a later proposal is this ack instead of a new `0x66`.

### 0x68 — settlement index

Session-sealed. A writer sends this when a session to one of a contact's devices comes up, after the payment index. It is not sent to an own device. The plaintext has the same shape as op `0x64`: `[flags:u8][count:u16 be]` and then `count` entries of `[settlement id:16][lower-user signature:64]`. Flag `0x01` starts a list. Flag `0x02` ends it. The lower user's signature distinguishes two bodies of one settlement id.

When the list ends, the receiver sends op `0x69` for each settlement of this pair whose id and lower-user signature are absent. It does not answer with another index. A node that is not the writer drops the packet.

### 0x69 — settlement record

Session-sealed. The plaintext is the ack from op `0x67`. The receiver stores it when both signatures verify and the two users are this node and the contact that owns the session. A missing payment line does not block the copy. Once that line is stored, the id no longer counts toward the tab or toward that payer's what you'll run. The purse's available amount does not change. A bad signature is dropped.

### get-data secrecy (op 2)

- Echoes **only the requesting app's own token** (never sibling or contact tokens).
- Own-device apps list id/alias/host/approved **without tokens**.
- Contact apps: **approved only**, id + alias only (no host/token).
- No identity/ephemeral private keys and no contact long-term keys in the reply.

---

Fabric administration (connect, bootstrap, sync, tunnels) uses other op
ranges and is documented elsewhere (`pnet to pnet communication.md`,
`data sync.md`).

