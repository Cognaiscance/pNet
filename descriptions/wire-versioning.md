# Wire versioning (v1 → next break)

**Status:** design note for §8.3 of the core rewrite checklist. No runtime
negotiation is implemented yet; this records how a **breaking** wire change
will be introduced without silent misparse.

## Current wire (v1)

- Transport: **UDP / IPv4 only** (see *IPv4 contract* below and
  `pnet to pnet communication.md`).
- Framing: first byte is the **operation code** (`wire.rs`).
- Session packets after connect: `[op:1][receiver_conn_id:u16][nonce:24][AEAD ciphertext…]`.
- Handshake / bootstrap ops use their own fixed layouts (documented per op).
- No global protocol version field on the wire today.

Op ranges in use (hex):

| Range | Role |
|-------|------|
| `0x00–0x0F` | Local app API (loopback) |
| `0x10–0x1F` | Control (ping, keepalive, conn-reset) |
| `0x20–0x2F` | Session handshake |
| `0x30–0x3F` | Bootstrap / invitations |
| `0x40–0x4F` | Relay / app packet |
| `0x50–0x5F` | Tunnels |
| `0x70–0x7F` | Sync v1/v2 |
| unassigned | Reserved for future ops |

## How the next **breaking** change will be signaled

When a change cannot be made backward-compatible (layout change of an existing
op, AEAD domain/KDF break, etc.):

1. **Prefer new op codes** in a free range over redefining existing ops.
   Old nodes ignore unknown ops (UDP listener logs and continues).
2. If an existing op must change shape, introduce a **capability / version
   byte** negotiated during the connection handshake:
   - Extend `ConnectRequest` / `ConnectAck` with an optional trailing
     `capabilities: u32` bitmask (or `proto_version: u8`) after the signature
     fields **only when** a high bit of a reserved flag is set, **or**
   - Add sibling ops `ConnectRequestV2` / `ConnectAckV2` (`0x22` / `0x23`) and
     deprecate `0x20` / `0x21` after dual-stack migration.
3. Nodes that do not understand the peer's version **must not** attempt to
   parse the new body as the old format. Drop or reply with conn-reset.
4. Domain-separated crypto labels already use `pnet-aead-v1-…` (`crypto.rs`);
   a crypto break bumps to `v2` labels and new session types — never reuse
   v1 domains with a different KDF.

Non-breaking extensions (new optional ops, new app payload conventions)
require no version bump — only documentation and unused op codes.

## Rollout expectation

- Dual-run period: both op/layout families accepted.
- Admin diagnostics / structured logs note peer capability when present.
- After all deployments upgrade, old ops may be rejected with a clear log.

---

## IPv4 contract (v1)

**pNet fabric v1 is IPv4-only.**

- Peer addressing, `Device.hosts`, DNS resolve, connect/relay/tunnel, and
  admin bind helpers all use `SocketAddrV4` / `Ipv4Addr`.
- IPv6 addresses are not accepted on the fabric wire path. Host resolve
  filters to IPv4 results only (`dns_cache` / `resolve_host_uncached`).
- Dual-stack (IPv6) is **not** scheduled for v1; it would be a separate
  design pass (address encoding, dual sockets, happy-eyeballs policy).

Admin HTTP may bind any IPv4 interface (`PNET_HTTP_BIND`); that is orthogonal
to the fabric IP family.
