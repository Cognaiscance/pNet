# Background Systems

pNet has two independent background systems that run on a schedule. They have different purposes and are intentionally kept separate so that changes to one do not affect the other.

---

## Key Rotation

Ephemeral keys used for encrypted communication are rotated on a fixed time-based schedule. The rotation fires regardless of whether any packets are being sent or received — it is driven purely by a timer.

- **Trigger**: scheduler enqueues a `KeyRotation` action at a fixed interval
- **No dependency on**: network activity, SG availability, or any other system
- **Purpose**: limit the window of exposure if an ephemeral key is ever compromised

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
