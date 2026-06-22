# pNet to pNet Communication

This document describes how two pNet nodes communicate with each other directly — distinct from how apps communicate with their local pNet node.

## Active Connections

Before two pNet nodes can exchange encrypted messages, they must establish an ActiveConnection. Each side holds an `ActiveConnection` struct containing a locally assigned `u16` ID, an ephemeral key pair, the peer's ephemeral public key, and the peer's corresponding `u16` ID.

When a packet is sent from one pNet node to another, the sender places the receiver's `peer_active_connection_id` in the packet header. This allows the receiving node to look up the correct decryption key in O(1) time without transmitting full UUIDs.

## Packet Structure

Unencrypted header:
```
┌───────────────────────────┬───────┐
│           Field           │ Bytes │
├───────────────────────────┼───────┤
│ Operation type            │ 1     │
├───────────────────────────┼───────┤
│ Receiver active conn. ID  │ 2     │
├───────────────────────────┼───────┤
│ Nonce                     │ 24    │
└───────────────────────────┴───────┘
```

The remainder of the packet is encrypted using the ephemeral keys from the active connection. The encrypted body varies by operation type.

## Connection Handshake

Before two nodes can exchange encrypted packets they must establish an `ActiveConnection` via a two-message handshake. This is driven by the `MaintainConnections` background task (see background systems.md).

### DgKeepalive — op `0x12`

Sent by a DG to each SG it has an active connection with, every 20 seconds.

```
┌──────────────────────────────┬───────┐
│ Field                        │ Bytes │
├──────────────────────────────┼───────┤
│ Operation type (0x12)        │ 1     │
└──────────────────────────────┴───────┘
```
Total: 1 byte.

No response is sent. The packet's only purpose is to refresh the DG's NAT mapping so the SG can continue to push packets back to the DG. See background systems.md — DG Keepalive.

---

### ConnectRequest — op `0x20`

Sent by the initiator (always a DG when connecting to an SG; lower-UUID node when SG-to-SG).

```
┌──────────────────────────────┬───────┐
│ Field                        │ Bytes │
├──────────────────────────────┼───────┤
│ Operation type (0x20)        │ 1     │
│ Initiator connection ID      │ 2     │
│ Initiator device UUID        │ 16    │
│ Initiator ephemeral PK       │ 32    │   X25519
│ Initiator long-term PK       │ 32    │   Ed25519 identity key
│ Signature                    │ 64    │   Ed25519 over all preceding fields (TODO)
└──────────────────────────────┴───────┘
```
Total: 147 bytes.

The responder validates the long-term public key against its known devices and contacts. If accepted, it allocates its own connection ID, stores an `ActiveConnection`, and replies with a ConnectAck.

### ConnectAck — op `0x21`

Sent by the responder.

```
┌──────────────────────────────┬───────┐
│ Field                        │ Bytes │
├──────────────────────────────┼───────┤
│ Operation type (0x21)        │ 1     │
│ Responder connection ID      │ 2     │
│ Initiator connection ID      │ 2     │   echoed for correlation
│ Responder ephemeral PK       │ 32    │   X25519
│ Signature                    │ 64    │   Ed25519 over all preceding fields (TODO)
└──────────────────────────────┴───────┘
```
Total: 101 bytes.

On receipt, the initiator finds the matching `PendingConnection` by the echoed connection ID, verifies the signature, and promotes it to an `ActiveConnection`.

---

## Device Bootstrap

Before a new device can participate in the network it must receive a copy of the user's full data (identity, long-term key pair, known devices, and contacts). This is done once via a three-message exchange between the new device and an SG.

### Prerequisites

- The user has at least one configured device and at least one SG.
- An invitation was generated on any configured device (see Administration UI — Invitations). The invitation contains a short-lived ephemeral key pair and the address of a target SG.
- The invitation's `id`, `public_key`, and a resolvable SG address are shared with the new device out-of-band (copy-paste or QR code). The device-invitation code encodes `invitation_id (16) || invitation_public_key (32) || host_len (1) || host_bytes (host_len) || port (2)` — variable length, where `host_bytes` is the first entry from the SG's `hosts` list (hostname or IP, no port suffix). The contact-invitation code uses the fixed-length form `invitation_id (16) || invitation_public_key (32) || ipv4 (4) || port (2)` — 54 bytes / 72 base64 characters; the full hostname list arrives later via ContactDataPush.
- The invitation is always minted *on* the top-ranked online SG, never synced after the fact. Unless the generating device is itself that SG, it sends a `GenerateInvitationRequest` (op `0x35`) to it — this applies to DGs and to lower-ranked SGs alike — and the target SG creates and stores the `Invitation` locally, returning the encoded code via `GenerateInvitationResponse` (op `0x36`). The code therefore always points to an SG that already holds the matching invitation. Invitations are device-local state and are never replicated between SGs.

### BootstrapRequest — op `0x30`

Sent by the new device to the SG whose address was in the invitation code.

```
┌──────────────────────────────┬───────┐
│ Field                        │ Bytes │
├──────────────────────────────┼───────┤
│ Operation type (0x30)        │ 1     │
│ Invitation ID                │ 16    │
│ New device ephemeral PK      │ 32    │   X25519; used to encrypt the response
└──────────────────────────────┴───────┘
```
Total: 49 bytes.

The new device generates a one-time ephemeral key pair for this exchange. The SG uses the invitation's private key and this public key to derive a shared secret (X25519).

### BootstrapResponse — op `0x31`

Sent by the SG back to the new device if the invitation is valid and not expired.

```
┌──────────────────────────────┬───────┐
│ Field                        │ Bytes │
├──────────────────────────────┼───────┤
│ Operation type (0x31)        │ 1     │
│ Nonce                        │ 24    │   ChaCha20-Poly1305
│ Encrypted payload            │ var   │
└──────────────────────────────┴───────┘
```

The encrypted payload contains the full user data needed to configure the new device:
- User alias and UUID
- User long-term key pair (public and private, 32 bytes each)
- All of the user's known devices (alias, UUID, grade, sg_rank, hosts list). Each device encodes its address list as `[host_count:u8]` followed by `host_count` length-prefixed hostname strings.
- All of the user's contacts (alias, UUID, public key, devices)

After sending the response the SG removes the invitation — it is single-use.

The new device derives the same shared secret (X25519 using its ephemeral private key and the invitation's public key from the code) and decrypts the payload.

### DeviceRegistration — op `0x32`

Sent by the new device to the SG after successfully decrypting the bootstrap payload.

```
┌──────────────────────────────┬───────┐
│ Field                        │ Bytes │
├──────────────────────────────┼───────┤
│ Operation type (0x32)        │ 1     │
│ Nonce                        │ 24    │   same shared secret as above
│ Encrypted payload            │ var   │
└──────────────────────────────┴───────┘
```

Encrypted payload:
- New device UUID (generated fresh on the new device)
- Device alias
- Device grade (SG or DG)
- Device host (IP + port)

The SG decrypts using the same shared secret, adds the new device to `owner.user.devices`, and the new device is now a full participant. Future changes are propagated via the device-sync system (not yet defined).

### GenerateInvitationRequest / Response — ops `0x35` / `0x36`

Used whenever the generating device is **not** the top-ranked online SG — i.e.
a DG, or a lower-ranked SG. The device asks the top-ranked online SG to mint the
invitation so the code points to an SG that already holds it (invitations are
device-local and never synced). Both messages travel over an established
own-device `ActiveConnection` and use the standard encrypted framing
(`[op][peer_active_conn_id:2][nonce:24][ciphertext]`).

Request (`0x35`, DG → SG) plaintext body:
- Invitation kind: 1 byte (`0x00` device, `0x01` contact)
- Request token: 16 bytes (random; echoed in the response so the parked DG UI thread can match it)

Response (`0x36`, SG → DG) plaintext body:
- Request token: 16 bytes (echoed)
- Result: 1 byte (`0x00` ok, `0x01` mint failed — e.g. the SG has no `hosts`)
- Encoded invitation code: variable (UTF-8; same base64 form the UI displays)

On `0x35` the SG mints an `Invitation`, stores it in its own
`device_invitations`/`contact_invitations`, encodes the code with its own
`hosts`, and replies. The DG's UI thread blocks (≤5 s) waiting for `0x36`; a
missing or failed reply is a terminal error (no retry/queue), surfaced as a UI
error. If the generating device is itself the top-ranked online SG, it mints
locally and these messages are not sent.

---

## Administration Operations

The following operations are used to manage the state of the network and are not yet fully defined:

* **Connection establishment** — handled by ConnectRequest/ConnectAck above; driven automatically by `MaintainConnections`
* **Updating contact or device details** — propagating changes such as a new host address
* **Synchronizing user data** — keeping pNet nodes owned by the same user consistent with each other. This should be handled automatically by a background task. Implementation not yet defined.
