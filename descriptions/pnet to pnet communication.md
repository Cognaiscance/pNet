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
- The invitation's `id`, `public_key`, and `sg_host` are shared with the new device out-of-band (copy-paste or QR code). The shareable code is the base64 encoding of `invitation_id (16) || invitation_public_key (32) || sg_host (6)` — 54 raw bytes / 72 base64 characters.
- If the invitation was generated on a DG, it is synced to the SG before use (handled by the future device-sync system).

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
- All of the user's known devices (alias, UUID, grade, host)
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

---

## Administration Operations

The following operations are used to manage the state of the network and are not yet fully defined:

* **Connection establishment** — handled by ConnectRequest/ConnectAck above; driven automatically by `MaintainConnections`
* **Updating contact or device details** — propagating changes such as a new host address
* **Synchronizing user data** — keeping pNet nodes owned by the same user consistent with each other. This should be handled automatically by a background task. Implementation not yet defined.
