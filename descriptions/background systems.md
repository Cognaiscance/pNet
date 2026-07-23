# Background Systems

pNet has two independent background systems that run on a schedule. They have different purposes and are intentionally kept separate so that changes to one do not affect the other.

---

## Connection Maintenance

Every pNet node must hold active encrypted sessions with a set of peer nodes before it can route or receive application packets. The `MaintainConnections` background task keeps this set current and prevents sessions from lapsing unnoticed.

- **Trigger**: enqueued immediately at startup, then by the scheduler every 5 minutes; also **immediately** after a DG receives conn-reset (op `0x13`) so reconnect does not wait for the next 5‑minute tick (§6.1)
- **Interval rationale**: RENEW_THRESHOLD (2 hours) >> 5-minute interval, so a session is always renewed well before it expires
- **Also after connect work**: if maintain just issued ConnectRequests, a one-shot follow-up is scheduled ~5.5s later to retry silent failures
- **No dependency on**: SG health polling or message retry for the periodic path

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

After the ack, both sides hold an `ActiveConnection` with the peer's ephemeral public key and a matched pair of connection IDs. Encryption uses an AEAD key derived on demand: X25519 DH of the ephemeral keys, then **HKDF-SHA256** with info label `pnet-aead-v1-session` (raw DH output is never used as the AEAD key).

**Initiation rule**: a DG always initiates to an SG (NAT — the DG must punch outward). For SG-to-SG connections, the node whose device UUID sorts lower initiates, preventing simultaneous handshake collisions.

### Key fields involved

- `Owner::active_connections: HashMap<u16, ActiveConnection>` — fully established sessions, keyed by our local connection ID
- `Owner::pending_connections: HashMap<u16, PendingConnection>` — half-open sessions awaiting ConnectAck, keyed by our local connection ID
- `ActiveConnection::timeout` / `CONNECTION_LIFETIME` (24 h) — session lifetime
- `RENEW_THRESHOLD` (2 h) — renew if less than this much time remains

---

## SG Health Polling

Each pNet node maintains a ranked list of candidate SGs for routing decisions. This list is kept fresh by periodically pinging each candidate SG and recording the round-trip time (RTT).

- **Trigger**: scheduler enqueues a `PollSG` action at a regular interval; also **at startup** (before the first `MaintainConnections`) so cold-boot connect can see RTT when poll finishes first (§6.3)
- **No dependency on**: key rotation or packet send activity
- **Purpose**: two goals served by one mechanism:
  1. **SG availability** — if an SG does not respond it is marked down and excluded from routing until it recovers
  2. **Network distance** — RTT replaces geographic lat/long as the proximity metric, giving an accurate measure of actual network latency rather than physical distance

**Candidate pool**: for any send operation between user A and user B, the candidate pool is all SGs owned by either user A or user B. The DG selects the candidate with the lowest RTT that is currently marked up.

**Ranking**: candidates are sorted by RTT ascending. The top responsive candidate is used for routing. If it goes down, the next in the list is used automatically.

**Writer rank failover (§6.3):** preferred own SG is the lowest `sg_rank` (rank 1). When poll marks that SG unanimously down, `find_writer_sg` skips it and elects the next reachable own SG (or Local). On that transition the process logs  
`[fabric] event=rank_failover skipped=… skipped_rank=… reason=polled_down writer_kind=… writer=…`  
and `rank_recovery` when preferred SG is no longer skipped.

**Cold-boot:** until the first successful poll populates `sg_statuses`, address selection falls back to the first resolvable `Device.hosts` entry (not necessarily lowest RTT). Startup order is PollSG then MaintainConnections to reduce that window.

**Frequency tradeoff**: polling too rarely risks acting on stale RTT data; polling too frequently adds unnecessary background traffic, which matters on mobile connections. An adaptive strategy — polling more aggressively during active send periods and backing off during idle periods — is worth considering.

---

## DG Keepalive

NAT routers typically expire idle UDP mappings after 30–120 seconds. For an SG to push an incoming application packet to a DG, there must be an active NAT mapping established by a recent outbound packet from that DG. If the DG has been idle, the mapping may have expired and the SG's packet is silently dropped by the DG's router.

`KeepAliveDG` prevents this by sending a minimal 1-byte UDP packet (op `0x12`) from the DG to each SG it holds an `ActiveConnection` with, on an interval safely under the typical 30-second NAT timeout.

- **Runs on**: DG-grade devices only — SGs have stable public addresses and do not need this
- **Interval**: every 20 seconds
- **No response expected**: the SG silently discards the packet; the sole purpose is to produce outbound UDP traffic so the DG's router keeps the mapping alive
- **Sends to**: every SG (own user's and contacts') for which an `ActiveConnection` currently exists

---

## What was removed: Heartbeat

An earlier design included a `Heartbeat` action to ping all peers and keep NAT pinholes open between arbitrary nodes. This was removed when the SG/DG architecture was introduced: DGs no longer communicate directly with other DGs, so the hole-punching concern between arbitrary pairs of nodes no longer applies.

`KeepAliveDG` is the targeted replacement. It addresses the one remaining NAT concern — keeping the DG→SG mapping alive so the SG can push packets back to the DG — without the broader scope of the original Heartbeat.
