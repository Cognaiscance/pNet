# Wire protocol

Peers and the local node share one IPv4 UDP socket (default port 7777). The first byte selects the handler. An unknown byte is logged and dropped. App ops `0x00`–`0x03` are the local API in [api.md](api.md) and are filtered by source address. Every other op below is accepted from any source. There is no separate peer port.

Integers are big-endian unless marked LE. Strings are `u8` length plus UTF-8. UUIDs are 16 bytes. The device layout used inside several payloads is the one in the app API's get-data section.

## Session seal

After the handshake, most peer payloads use one framing:

```text
op (u8) || receiver's connection id (u16) || nonce (24) || XChaCha20-Poly1305 ciphertext
```

The key is HKDF-SHA256 of the X25519 shared secret of the two session ephemerals, info string `pnet-aead-v1-session`. The connection id is the id the receiver stored, which the sender learned as `peer_active_connection_id`. A bad id or a bad tag drops the datagram. No error is sent.

Three HKDF labels exist, and they are not interchangeable:

| Label | Used for |
| --- | --- |
| `pnet-aead-v1-session` | Relay, direct app packet, sync, keepalive, invitation mint |
| `pnet-aead-v1-bootstrap` | Device join and contact-card exchange |
| `pnet-aead-v1-tunnel` | DG-to-DG payload inside a tunnel |

The opaque app payload maximum is 4096 bytes on relay, direct app packet, and tunnel delivery. A larger inbound fabric payload is dropped with no reply. Tunnel-forward blobs are capped at 24 + 16 + 32 + 4096 bytes (nonce, tag, the two app ids, and the payload).

## Op bytes

| Op | Name | Seal |
| --- | --- | --- |
| `0x10` | SG ping | cleartext |
| `0x11` | SG pong | cleartext |
| `0x12` | DG keepalive | session |
| `0x13` | connection reset | cleartext, op only |
| `0x20` | connect request | cleartext, Ed25519 |
| `0x21` | connect ack | cleartext, Ed25519 |
| `0x30` | bootstrap request | cleartext plus a signature |
| `0x31` | bootstrap response | bootstrap AEAD |
| `0x32` | device registration | bootstrap AEAD |
| `0x33` | contact request | bootstrap AEAD |
| `0x34` | contact response | bootstrap AEAD |
| `0x35` | generate-invitation request | session |
| `0x36` | generate-invitation response | session |
| `0x40` | relay packet | session |
| `0x41` | app packet | session |
| `0x50` | tunnel init | cleartext |
| `0x51` | tunnel forward | opaque to the SG |
| `0x52` | tunnel connect request | cleartext |
| `0x53` | tunnel connect ack | cleartext |
| `0x54` | tunnel delivery | tunnel AEAD inside |
| `0x70` | sync write request | session |
| `0x71` | sync write ack | session |
| `0x72` | sync update available | session |
| `0x73` | sync pull request | session |
| `0x74` | sync pull response | session |
| `0x75` | cross-user update available | session |
| `0x76` | cross-user pull request | session |
| `0x77` | cross-user pull response | session |
| `0x78` | merge proposal | session |
| `0x79` | merge ack | session |
| `0x7A` | watermark probe request | session |
| `0x7B` | watermark probe response | session |

## Reachability

**SG ping (`0x10`).** Body: 16-byte nonce. Shorter datagrams are dropped.

**SG pong (`0x11`).** Body: the same nonce. Poll uses a separate socket so the pong does not enter the main listener. The poll waits 1 second.

**DG keepalive (`0x12`).** Session-sealed empty plaintext. A DG sends one per connected SG every 20 seconds. On success the SG refreshes that session's peer address and sets the lifetime to 24 hours from now. If the seal fails, the SG replies with connection reset.

**Connection reset (`0x13`).** No body. The DG drops every session whose peer IPv4 matches the source and runs connection maintenance immediately.

## Connect handshake

The signature key is the device Ed25519 signing key, not the user key.

**Connect request (`0x20`).** 146 bytes after the op byte:

```text
initiator connection id (u16)
|| initiator device uuid (16)
|| initiator ephemeral X25519 public key (32)
|| initiator device signing public key (32)
|| Ed25519 signature (64)
```

The signature covers `0x20` concatenated with the 82 bytes before the signature. The receiver accepts it only when the signing key equals the directory entry for that device UUID and that device's certificate verifies under the user public key (the owner key, or the contact's key). It then drops any older session to that device, stores a session (24-hour lifetime), and replies.

**Connect ack (`0x21`).** 100 bytes after the op byte:

```text
responder connection id (u16)
|| initiator connection id (u16)
|| responder ephemeral X25519 public key (32)
|| Ed25519 signature (64)
```

The signature covers `0x21` plus the 36 bytes before it, under the device signing key the initiator expected. A valid ack promotes the pending session. The initiator then pulls from the writer if this peer is the writer, pulls the contact's public directory if this peer belongs to a contact, and, when both sides are own-user SGs, starts a watermark probe.

A pending request with no ack is discarded after 5 seconds.

## Device join

The invitation code (see the API page) identifies a one-time X25519 key pair stored on the minting SG, plus that SG's hosts. The invitation is removed when the request is accepted. Expired invitations (24 hours) are removed and ignored. The AEAD key is HKDF of X25519(invitation secret, joiner ephemeral), label `pnet-aead-v1-bootstrap`.

**Bootstrap request (`0x30`).**

```text
invitation id (16) || joiner ephemeral X25519 public key (32)
|| device signing public key (32) || device X25519 public key (32)
|| device alias || Ed25519 signature (64)
```

The signature is over `0x30` plus every byte before the signature, verified with the device signing public key in the body. The alias must be non-empty. The SG must hold the user private key. It signs a device certificate for the presented keys and alias, remembers the bootstrap key for 5 minutes, and replies. The user private key is copied into the payload only when that invitation was minted with `releases_user_key` and this SG still holds the seed.

**Bootstrap response (`0x31`).**

```text
invitation id (16) || nonce (24) || ciphertext
```

Plaintext:

```text
user alias || user uuid (16) || user public key (32)
|| user certificate signature (64) || user cert issued-at (u64 LE)
|| user-key flag (u8, 1 = present) || user private key (32) if the flag is 1
|| issued device signing public key (32) || issued device X25519 public key (32)
|| issued certificate signature (64) || issued-at (u64 LE) || cert alias
|| device count (u8) || repeated device
|| contact count (u8) || repeated contact
```

A contact inside this payload is:

```text
user uuid (16) || alias || user public key (32)
|| device count (u8) || repeated device
```

The joiner verifies the user certificate and the issued device certificate before it installs them. It then sends device registration.

**Device registration (`0x32`).**

```text
invitation id (16) || nonce (24) || ciphertext
```

The plaintext is one device record (the same device layout), encrypted with the bootstrap key. The SG checks that the signing key matches the key from the bootstrap request and that the certificate verifies under the user public key, then adds the device and publishes `AddDevice`. The pending acceptance is single-use.

## Contact exchange

**Contact request (`0x33`).**

```text
invitation id (16) || requester ephemeral X25519 public key (32)
|| nonce (24) || ciphertext
```

Plaintext is the requester's contact card:

```text
alias || user uuid (16) || user public key (32)
|| device count (u8) || repeated device
```

The SG consumes a contact invitation, stores the requester as a contact, publishes `UpsertContact`, and replies.

**Contact response (`0x34`).** Same outer shape as the request's encrypted tail: nonce and ciphertext of this user's contact card, under the same bootstrap key. The requester stores that card and publishes `UpsertContact` through its own writer.

## Invitation mint between nodes

A node that is not the top-ranked online SG asks that SG to mint.

**Generate-invitation request (`0x35`).** Session plaintext:

```text
kind (u8) || token (16) || optional flags (u8)
```

`kind` is `0` for a device invitation and `1` for a contact invitation. Bit 0 of `flags`, when the byte is present, asks to release the user private key. The minting SG honors that bit only when the requester is an own SG and this node holds the user seed. A contact invitation never copies the key. A missing flags byte means do not release it.

**Generate-invitation response (`0x36`).** Session plaintext:

```text
token (16) || result (u8) || code
```

`result` `0` is success and the rest is the ASCII invitation code. `result` `1` is failure. The waiting UI matches `token`.

## Application delivery

**Relay (`0x40`).** Session plaintext:

```text
destination device uuid (16) || destination app id (16)
|| sender app id (16) || payload
```

The SG opens the session seal, finds a session to the destination device, and sends an app packet. It counts relays per pair. At 10 inside a 5-minute window it sends tunnel init. Payload longer than 4096 bytes is dropped.

**App packet (`0x41`).** Session plaintext:

```text
destination app id (16) || sender app id (16) || payload
```

The destination looks up an approved local app with that id and pushes `0x04 || sender app id || payload` to the app's registered UDP host.

## Tunnels

Tunnel setup messages are cleartext. The SG never sees the app plaintext.

**Tunnel init (`0x50`).** SG to the sending DG: `tunnel id (u16) || destination device uuid (16)`.

**Tunnel connect request (`0x52`).**

- DG to SG, 34 bytes after the op: `tunnel id (u16) || sender ephemeral X25519 public key (32)`.
- SG to destination DG, 50 bytes after the op: the same, plus `sender device uuid (16)`.

The destination creates a session keyed with the tunnel label, maps the tunnel id to that session, and replies.

**Tunnel connect ack (`0x53`).** `tunnel id (u16) || ephemeral X25519 public key (32)`. The SG records the tunnel against the two device sessions and forwards the ack to the sender. The sender stores its half the same way.

**Tunnel forward (`0x51`).** DG to SG:

```text
sender's SG connection id (u16) || tunnel id (u16) || nonce (24) || ciphertext
```

The ciphertext is the tunnel-sealed body. The SG checks the connection id is one leg of that tunnel and forwards the nonce and ciphertext as delivery. It does not decrypt.

**Tunnel delivery (`0x54`).** SG to DG: `tunnel id (u16) || nonce (24) || ciphertext`.

Tunnel plaintext, before the AEAD:

```text
destination app id (16) || sender app id (16) || payload
```

The DG opens it with the tunnel key and pushes to the approved app. Oversized payloads are dropped.

If the sender has a tunnel id but the session or the carrying SG is gone, it does not use the tunnel. It sends a direct app packet or a relay instead.

## Sync

A sync version is 28 bytes:

```text
writer SG uuid (16) || epoch (u32) || sequence (u64)
```

All zeros means "no version yet". A bump on the same writer increments the sequence. A bump under a different writer increments the epoch and sets the sequence to 1. Comparison of epoch and sequence is defined only when the writer UUID matches.

Scope is one byte: `0` private, `1` public. Every change the process can build is public. Private pulls return an empty snapshot.

**Write request (`0x70`).** Session plaintext is one change (below). The receiver accepts it only when this node is the writer. Otherwise it acks "not writer". It does not forward the write.

**Write ack (`0x71`).** Session plaintext:

```text
result (u8) || private version (28) || public version (28)
```

| Result | Meaning |
| --- | --- |
| `0` | Accepted. |
| `1` | This node is not the writer. |
| `2` | The change did not parse as a valid mutation. |

**Update available (`0x72`).** Session plaintext: `scope || version (28)`. If the version is newer from the same writer, or from a different writer, the receiver sends a pull request.

**Pull request (`0x73`).** Session plaintext: `scope || last-seen version (28)`.

**Pull response (`0x74`).** Session plaintext:

```text
scope || result (u8) || version (28) || snapshot, only when result is 1
```

`result` `0` means no updates (versions equal, same writer). `result` `1` means a full snapshot. A different writer also produces a full snapshot so the puller adopts that writer's public directory.

Public snapshot:

```text
user alias || user uuid (16)
|| device count (u8) || repeated (device || app count (u8) || repeated public app)
|| contact count (u8) || repeated (
     alias || user uuid (16) || user public key (32)
     || device count (u8) || repeated (device || app count || repeated public app)
   )
```

A public app is:

```text
app id (16) || alias || app signing public key (32)
|| certificate signature (64) || issued-at (u64 LE) || cert alias
```

**Cross-user update available (`0x75`).** Same body shape as update available, for one contact's public version.

**Cross-user pull request (`0x76`).** `scope || last-seen version`. Sent to a contact's device after the session comes up, and when a contact is first stored. The receiver answers only when the scope is public. Any other scope is ignored.

**Cross-user pull response (`0x77`).** Same result byte and version as a normal pull response. The snapshot, when present, is that node's own devices and its approved apps, not the full public directory:

```text
user uuid (16) || device count (u8)
|| repeated (device || app count (u8) || repeated public app)
```

### Change bytes

The first byte of a write-request plaintext is the kind.

| Kind | Body |
| --- | --- |
| `0x01` add application | device uuid, app id, alias, app signing public key (32), cert signature (64), issued-at (`u64` LE), cert alias |
| `0x02` remove application | device uuid, app id |
| `0x03` add device | one device record |
| `0x04` update alias | device uuid, app id, new alias |
| `0x05` upsert contact | user uuid, alias, user public key (32), device count, then each device followed by app count and that many public apps |
| `0x06` remove device | device uuid |
| `0x07` remove contact | user uuid |

Removes are tombstones in the SG merge. An add of an id that was removed does not bring it back. A new app uses a new id.

### SG reconciliation

**Watermark probe request (`0x7A`).** Session plaintext: `scope`. An SG sends public scope to each connected own-user SG on session-up and every 60 seconds.

**Watermark probe response (`0x7B`).** Session plaintext:

```text
scope || count (u16) || repeated (writer uuid (16) || epoch (u32) || sequence (u64))
```

The writer UUID is also the version's writer. Receiving the map causes a merge proposal.

**Merge proposal (`0x78`).** Session plaintext:

```text
scope || sender version (28) || entry count (u16) || repeated entry
```

Each entry is `version (28) || payload length (u16) || change bytes || committed-at unix seconds (u64)`. Entry count `0xFFFF` means the sender's log has been pruned past the peer's watermark (30-day retention) and no entries follow. On that sentinel the receiver sets the in-memory retention-fallback flag, pulls a full snapshot for that scope, and acks result `1`.

**Merge ack (`0x79`).** Session plaintext: `scope || new version (28) || result (u8)`.

| Result | Meaning |
| --- | --- |
| `0` | Applied. |
| `1` | Retention fallback. |
| `2` | Malformed, or the sender is not an own SG. |

When the proposal is a real entry list from an own SG, the receiver runs the merge: union adds by id, tombstone wins over an add of the same id, alias chosen by lower `sg_rank`, then higher epoch and sequence, then writer UUID bytes. New log entries are appended with their original writer attribution, the resulting changes are applied, and one version bump is stamped under the rank-walk writer.
