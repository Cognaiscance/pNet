# Background Systems

pNet has two independent background systems that run on a schedule. They have different purposes and are intentionally kept separate so that changes to one do not affect the other.

---

## Connection Maintenance

Every pNet node must hold active encrypted sessions with a set of peer nodes before it can route or receive application packets. The `MaintainConnections` background task keeps this set current and prevents sessions from lapsing unnoticed.

- **Trigger**: enqueued immediately at startup, then by the scheduler every 5 minutes
- **Interval rationale**: RENEW_THRESHOLD (2 hours) >> 5-minute interval, so a session is always renewed well before it expires
- **No dependency on**: network activity, SG health polling, or message retry

### Desired connection set

The set of peers a node should be connected to depends on its device grade:

| Local grade | Connects to |
|-------------|-------------|
| DG | All SG-grade devices: own user's SGs + every contact's SGs |
| SG | All devices: own user's SGs + DGs + every contact's SGs + DGs |

An SG connects to DGs as well as other SGs because it can originate application packets directly, not only relay them.

### What it does each run

1. Reads the current desired peer set from the node's known devices and contacts.
2. Builds a set of devices that already have a healthy `ActiveConnection` (more than `RENEW_THRESHOLD` remaining) or an in-flight `PendingConnection`.
3. For every remaining desired peer, generates an ephemeral key pair, stores a `PendingConnection`, and sends a `ConnectRequest` UDP packet.

### Handshake

Connection establishment is a two-message exchange:

1. **ConnectRequest** (op `0x20`) — sent by the initiator. Contains the initiator's ephemeral public key, device UUID, and long-term public key (Ed25519, for identity verification).
2. **ConnectAck** (op `0x21`) — sent by the responder. Contains the responder's ephemeral public key and echoes the initiator's connection ID so the initiator can correlate it to the pending entry.

After the ack, both sides hold an `ActiveConnection` with the peer's ephemeral public key and a matched pair of connection IDs. The X25519 shared secret is derived from the ephemeral keys on demand during encryption/decryption.

**Initiation rule**: a DG always initiates to an SG (NAT — the DG must punch outward). For SG-to-SG connections, the node whose device UUID sorts lower initiates, preventing simultaneous handshake collisions.

### Key fields involved

- `Owner::active_connections: HashMap<u16, ActiveConnection>` — fully established sessions, keyed by our local connection ID
- `Owner::pending_connections: HashMap<u16, PendingConnection>` — half-open sessions awaiting ConnectAck, keyed by our local connection ID
- `ActiveConnection::timeout` / `CONNECTION_LIFETIME` (24 h) — session lifetime
- `RENEW_THRESHOLD` (2 h) — renew if less than this much time remains

---

## SG Health Polling

Each pNet node maintains a ranked list of candidate SGs for routing decisions. This list is kept fresh by periodically pinging each candidate SG and recording the round-trip time (RTT).

- **Trigger**: scheduler enqueues a `PollSG` action at a regular interval
- **No dependency on**: key rotation or packet send activity
- **Purpose**: two goals served by one mechanism:
  1. **SG availability** — if an SG does not respond it is marked down and excluded from routing until it recovers
  2. **Network distance** — RTT replaces geographic lat/long as the proximity metric, giving an accurate measure of actual network latency rather than physical distance

**Candidate pool**: for any send operation between user A and user B, the candidate pool is all SGs owned by either user A or user B. The DG selects the candidate with the lowest RTT that is currently marked up.

**Ranking**: candidates are sorted by RTT ascending. The top responsive candidate is used for routing. If it goes down, the next in the list is used automatically.

**Frequency tradeoff**: polling too rarely risks acting on stale RTT data; polling too frequently adds unnecessary background traffic, which matters on mobile connections. An adaptive strategy — polling more aggressively during active send periods and backing off during idle periods — is worth considering.

---

## What was removed: Heartbeat

An earlier design included a `Heartbeat` action to ping peers and keep NAT pinholes open. This has been removed. The SG/DG architecture eliminates the need for NAT hole-punching since DGs always communicate via SGs, which have stable reachable addresses. SG health polling covers the liveness-checking concern that the heartbeat previously served.
