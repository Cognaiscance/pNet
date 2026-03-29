# pNet to pNet Communication

This document describes how two pNet nodes communicate with each other directly — distinct from how apps communicate with their local pNet node.

## Constraints

All pNet-to-pNet UDP packets must fit within 512 bytes, the safe limit for internet UDP transmission.

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

## Administration Operations

The following operations are used to manage the state of the network. They are yet to be fully defined:

* **Connection establishment** — handled by ConnectRequest/ConnectAck above; driven automatically by `MaintainConnections`
* **Updating contact or device details** — propagating changes such as a new host address
* **Synchronizing user data** — keeping pNet nodes owned by the same user consistent with each other. This should be handled automatically by a background task. Implementation not yet defined.
