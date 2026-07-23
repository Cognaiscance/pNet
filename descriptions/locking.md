# Node locking (§5.4 audit)

## Model

All fabric state lives under one `Arc<RwLock<Node>>` on `WorkerContext`, shared by
the fixed worker pool (default **4** threads). Separate locks already exist for:

| Resource | Lock |
|----------|------|
| Action queue | `Mutex<ActionQueue>` + Condvar |
| DNS cache | `Mutex<DnsCache>` |
| Admin sessions | interior mutex in `SessionStore` |
| App API rate limits | `Mutex<AppRateLimiter>` |
| Pending invite waiters | `Mutex` + Condvar on `PendingInvites` |
| Writer / scheduler | channels (not the node lock) |

## Code audit (2026-07-23)

**Scale of use:** on the order of ~100 write and ~200 read acquire *sites* in
handlers (many short scopes). Sync and session paths dominate.

**What holds the write lock:** in-memory mutations — session promote/evict,
app register/update, sync merge apply, invitation store, tunnel map updates.
Typical hold is allocate + insert/remove, not network RTT.

**What holds the read lock:** routing lookups, packet build (copy session keys
and peer addrs), UI page render, `save_node` serialization snapshot.

**I/O relative to the lock:** UDP `send` is almost always **outside** the node
lock after state is copied. DNS (§5.3) uses `dns_cache`, not `Node`. Invite mint
wait is off-pool (§5.2). So the main lock is not a network wait point by design.

**Contention risk today:**

1. **Writer count is small (4).** At most three workers can block behind one
   writer; unlikely to thrash under normal mesh traffic.
2. **Read-heavy routing** can run concurrently under `RwLock` (multiple readers).
3. **`save_node`** takes a read lock for full TOML serialize — can stall writers
   briefly on large directories; frequency is mutation-driven, not per packet.
4. **Long write scopes** that still exist (large sync apply under write) can
   delay session setup; that is **hold duration**, not map-structure contention.

**Split of `active_connections` / `sg_statuses` (checklist option):** would let
session keepalive and poll updates avoid contending with directory/sync writes.
Cost: almost every interesting path needs *both* session maps and directory
(identity, devices, contacts) — dual locks create ordering hazards and large
refactors without a measured win.

## Decision

**Do not split the global `Node` lock now.** No production or load-test
measurements show map-level contention; the architecture already keeps RTT and
DNS off this lock. Revisit if:

- Diagnostics or tracing show workers stalled on `node.write` under load, or
- `save_node` / large merge holds are proven to delay connect/keepalive, or
- Worker count is raised substantially.

If revisited: prefer **shorter critical sections** and snapshot-for-serialize
before a full map split; then consider separate `SessionPlane` /
`DirectoryPlane` locks with a documented order (e.g. directory → sessions).

## Operator note

`/diagnostics` states that fabric state uses a single `RwLock<Node>` and that
session/directory split is deferred. There is no live contention counter yet;
add tracing if this becomes an operational question.
