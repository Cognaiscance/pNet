# Data Sync

This document describes how state changes propagate across pNet nodes — the user's own devices and their contacts' devices. It supersedes the ad-hoc per-change sync messages used during early development.

## Goals

- One definitive copy of state at any moment, not many copies that have to be merged on every change.
- Adding/removing apps, devices, contacts, or invitations is a single explicit operation, not a side effect of gossip.
- Missed packets are recoverable: if a node was offline or a notification was lost, it catches up on its next pull.
- A clear answer for "where do api keys go" vs "what does my contact see".

## Concepts

### Writer SG

At any moment exactly one SG acts as the **writer** for the user's data. All state-changing requests originate at a DG or SG and are sent to the writer SG. The writer assigns ordering metadata to the change, persists it, and notifies the rest of the network that an update is available.

Writer election rule:

- A DG sends writes to the **highest-rank SG it can currently reach**.
- An SG that receives a write first forwards it to the highest-rank SG *it* can reach. Only when no higher-rank SG is reachable does it accept the write itself.
- If no SG is reachable from a DG, the DG returns an error to the calling app. DGs do not buffer writes locally.

Under normal conditions this collapses to "rank 1 SG is the writer." During a rank-1 outage, rank 2 takes over. During a network partition, each side has its own writer; reconciliation rules (below) handle the rejoin.

### Sync scopes

State is split into two scopes with independent version counters:

| Scope | Visible to | Includes |
|---|---|---|
| **Private** | The user's own devices only | Application `token`/`api_key`, application `host`/port, invitations, long-term keypair, active connections, anything else that must never leave the user's device set. |
| **Public** | The user's own devices and the user's contacts | User `alias` and `uuid`, devices' `uuid`/`grade`/`sg_rank`/`hosts`, application `id` and `alias`. |

Splitting the scopes means a contact pull never touches private fields, an api-key rotation does not bump the contacts' counters, and a sync bug cannot accidentally leak a token.

### Version metadata

Every accepted write carries `(writer_sg_uuid, epoch, seq)`:

- `epoch: u32` — increments on the writer SG whenever its view of "am I the highest-rank reachable SG?" changes. A fresh boot starts at the last persisted epoch + 1.
- `seq: u64` — monotonic counter inside an epoch. Resets to 0 on epoch change.

The pair `(epoch, seq)` is a total order within a single SG's writes. Across SGs, the `writer_sg_uuid` distinguishes concurrent epochs (which only happen during a partition).

A scope's current version on a node is the highest `(writer_sg_uuid, epoch, seq)` it has applied.

## Write path

```mermaid
sequenceDiagram
    participant App
    participant DG
    participant SG2 as SG (rank 2)
    participant SG1 as SG (rank 1, writer)

    App->>DG: AddApplication(alias)
    DG->>DG: assign api_key locally
    DG->>SG1: WriteRequest(AddApp, ...)
    Note over SG1: assigns (epoch, seq), persists
    SG1-->>DG: WriteAck(epoch, seq)
    par notify
        SG1->>SG2: UpdateAvailable(scope, epoch, seq)
        SG1->>DG: UpdateAvailable(scope, epoch, seq)
        SG1->>Contacts: UpdateAvailable(scope=public, epoch, seq)
    end
    DG->>SG1: PullRequest(scope, last_seen=...)
    SG1-->>DG: PullResponse(new state, version)
    Note over DG: app now officially recorded
```

Until the originating DG completes its own pull, it may show the change locally as "pending" so the UI is not gated on the round trip — but the authoritative record is the one returned by the pull.

## Notify-then-pull

The writer SG sends a small `UpdateAvailable` notification to every interested node when a write commits. The notification carries only the scope and the new version — not the change itself. Recipients respond by issuing a `PullRequest` with the highest version they have already applied.

Pull semantics:

- `PullRequest(scope, last_seen_version)` → either a state delta with a new version, or `NoUpdates`.
- Pulls are idempotent. A duplicate pull returns the same response.
- Notifications are best-effort. A lost notification is corrected by the next periodic pull, so correctness never depends on notification delivery.

## Periodic and on-reconnect pull

Every node issues a pull on its own schedule independent of notifications:

- On reconnect to an SG (after coming online or after a connection refresh).
- On a periodic timer while online — initial value: every few hours.

This makes the system self-healing: a node that misses every notification for a day will still converge on its next periodic pull.

## Visibility split in practice

- **User's own devices** pull both scopes from the writer SG.
- **Contacts' devices** pull only the public scope, and only via their own writer SG. A contact's SG fetches the public scope from the user's writer SG on the contact's behalf, so contacts do not connect directly to the user's writer for sync.
- The contact-side writer SG caches the public scope locally and serves its own DGs from that cache.

## Failover and writer handoff

When the rank-1 SG goes down:

1. DGs detect the outage via their existing `poll_sg` results and start sending writes to rank 2.
2. Rank 2 observes that no higher-rank SG is reachable, increments its `epoch`, and accepts writes.
3. While serving as writer, rank 2 also notifies the user's other devices and the user's contacts, exactly as rank 1 did.
4. When rank 1 comes back online, it and rank 2 reconcile (next section). After reconciliation, rank 1 resumes as writer and rank 2 returns to forwarding.

If **all** SGs are unreachable from a DG, the DG returns an error to the requesting app. No local queueing.

## Reconciliation on rejoin

When two SGs that have both been writers reconnect, they exchange their write logs since the last shared `(writer_sg_uuid, epoch, seq)` watermark.

Two cases:

1. **Sequential** — only one side accepted writes during the split (e.g., rank 1 was simply down). The returning SG fetches the other side's writes and applies them in order. No conflicts.
2. **Concurrent** — both sides accepted writes (a true partition). Apply each side's writes in `(epoch, seq)` order, resolving any per-field conflict using the rules below.

After reconciliation the SGs share a common watermark and the higher-rank SG resumes as writer.

## Field-level merge rules

These rules apply only when concurrent writes touch the same field during a partition.

| Change kind | Rule |
|---|---|
| Add (application, device, contact, invitation) | **Union.** All adds from both sides are kept. Identity is by UUID (app ids are 16-byte UUIDs — pure union by id; no reassignment). |
| Remove (any of the above) | **Tombstone wins.** A remove on either side overrides a concurrent add or modification of the same record. Removes are recorded as tombstones in the write log so a late-arriving add from the partitioned side cannot resurrect the record. |
| Scalar update (`alias`, `sg_rank`, `hosts`, etc.) | **Highest writer-rank wins.** Tie broken by `(epoch, seq)`. |

These rules are deliberately small. Most users on a small home pNet will never trigger them; they exist so the system has a defined answer when they do.

## Implementation phasing

- **v1**: writer election, version metadata, notify-then-pull, periodic pull, scope split, sequential rejoin (rank 1 was simply down). Concurrent-partition reconciliation is *not* yet implemented; on detection of a cross-writer version the current code adopts the locally-reachable writer's state and silently discards the other side's writes. This is less safe than the documented v1 intent ("log and refuse"); v2 supersedes it.
- **v2**: implement the field-level merge rules and tombstone log so true partitions heal automatically. Detailed below.

## v2: partition reconciliation

### Prerequisite — UUID app ids (done, 7c.0)

`Application.id` is a 16-byte `Uuid` everywhere — `Application`, every `Change` variant carrying the id, app-facing ops (`app_register`, `app_get_data`, `app_send_packet`, push), and persisted state. Add collisions cannot happen; the merge engine for Adds is a pure union by id.

### Write log

Each SG records every accepted `Change` and every accepted removal as an entry in a chronological log persisted on `Owner`:

```rust
pub struct WriteLogEntry {
    pub version:      SyncVersion,    // (writer_sg_uuid, epoch, seq)
    pub scope:        Scope,           // Public initially; Private deferred
    pub kind:         WriteLogKind,
    pub committed_at: SystemTime,      // for retention pruning
}

pub enum WriteLogKind {
    Change(Change),                                // existing Change enum
    Tombstone { target: TombstoneTarget },         // removal marker
}

pub enum TombstoneTarget {
    Application { device_uuid: Uuid, app_id: Uuid },
    Device      { uuid: Uuid },
    // Contact lands when Change::AddContact does.
}
```

`#[serde(default)]` keeps existing snapshots loadable; new fields start empty. The log is appended at the same point versions are bumped (`apply_change_locally` + `sync_write_request`).

### Watermark discovery

When two SGs of the same user reconnect (detected in `connect_ack`), they exchange a per-writer map: `{writer_uuid → highest_seq_we_have}` for every writer that appears in either log. The per-writer watermark is the `min` of the two values; the overall reconciliation point is the resulting `(writer_sg_uuid, epoch, seq)` per writer.

One round trip, payload size linear in the number of distinct writers (small — usually 1-2).

Op `0x7A WatermarkProbe`:  request carries `[scope:1]`, response carries `[scope:1][entry_count:u16][(writer_uuid:16, epoch:4, seq:8) × entry_count]`.

### Merge proposal exchange

After watermark discovery, each side sends a `MergeProposal` (op `0x78`) containing every log entry whose version exceeds the watermark for its writer:

```
[scope:1][last_known_watermark:28][entry_count:u16][WriteLogEntry × entry_count]
```

The receiver runs the merge engine and replies with `MergeAck` (op `0x79`):
```
[scope:1][new_watermark:28][result:1]
```
where `result` is `0` (applied), `1` (retention-exhausted, falling back to full state transfer per the policy below), or `2` (malformed).

### Merge engine

Given two `Vec<WriteLogEntry>` lists, sort by `(epoch, seq, writer_uuid)`, walk in order:

- **Add (`AddApplication`, `AddDevice`)**: union by id (UUID). Idempotent.
- **Tombstone (`TombstoneTarget`)**: removes the matching record from the merged state and suppresses any later Change whose `(epoch, seq)` ≤ the tombstone's. Tombstone wins regardless of which side has the higher epoch.
- **Scalar update (`UpdateApplicationAlias`, future device/contact field updates)**: highest writer-rank wins; tiebreaker `(epoch, seq)`.

Pure function — given inputs in, merged state + bumped watermark out. Heavy unit-test target.

### Retention and full-state fallback

Write log entries older than **30 days** (hard bound for v2; configurable later if telemetry warrants it) are pruned during merge. A returning SG whose `last_watermark` lies in another SG's pruned range cannot reliably merge — the other side has no record of the writes between watermarks.

Policy on exhaustion: **the returning SG accepts the other side's full public state via `SyncPullResponse(FullState)` and discards its local-only writes**. This is a known data-loss path reserved for the degenerate case of an SG offline for more than a month while the rest of the cluster has stayed active. No operator intervention required; surfaced via the `partition_detected` flag on `Owner` and a banner in the admin UI for visibility.

### Sub-phase breakdown

| Phase | Scope |
|---|---|
| 7c.0 | Widen `Application.id` from u16 to UUID across the codebase + snapshot migration. **Done.** |
| 7c.1 | This design doc (you are here). |
| 7c.2 | `WriteLogEntry` / `WriteLogKind` / `TombstoneTarget`, persistence, append in `apply_change_locally` + `sync_write_request`, retention pruning. |
| 7c.3 | Watermark discovery — `0x7A WatermarkProbe` request + reply, store result. |
| 7c.4 | Merge proposal exchange — `0x78` / `0x79` ops + payload serialization; receive but do not apply. |
| 7c.5 | Merge engine — pure function with rule tests. |
| 7c.6 | Wire merge engine into `connect_ack` between own-user SGs; apply merged state, bump version, `notify_own_peers`, clear `partition_detected`. First end-to-end run. |
| 7c.7 | Stage C harness — docker-compose with two own SGs, partition/heal via network manipulation, assertion suite covering union / tombstone / scalar-conflict cases. |
| 7c.8 | (Optional) `partition_detected` banner in admin UI + diagnostics page surfacing the watermark and any unmerged proposals. |

7c.0 must precede 7c.2. 7c.2 and 7c.3 are independent. 7c.5 depends on 7c.2. 7c.6 depends on 7c.4 + 7c.5. Cross-user reconciliation deferred indefinitely.

## Open questions (remaining)

- Periodic pull interval — start with every few hours, tune from telemetry.
- Wire format for `WriteRequest`/`WriteAck`/`UpdateAvailable`/`PullRequest`/`PullResponse` — defined inline with the existing op codes in `pnet to pnet communication.md`; cross-reference rather than duplicating here.
