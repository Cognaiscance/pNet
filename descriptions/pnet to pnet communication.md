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

## Administration Operations

The following operations are used to manage the state of the network. They are yet to be fully defined:

* **Initializing a contact or device** — establishing a new active connection with a newly added contact or device
* **Ephemeral key update** — refreshing the ephemeral key in an existing active connection
* **Generating a new ephemeral key** — initiating a fresh key exchange
  * Key rotation is handled automatically by a time-based background task on a fixed schedule, independent of any network activity. See background systems.md.
* **Updating contact or device details** — propagating changes such as a new host address
* **Synchronizing user data** — keeping pNet nodes owned by the same user consistent with each other. This should be handled automatically by a background task. Implementation not yet defined.
