# pNet core fabric rewrite checklist

Working plan for the **pNet core fabric only** (not sample apps).  
Branch: `grok-rewrite`.

## How to use this

1. Open this repo in Grok and ask **“what’s next on our list?”**
2. Do **one** unchecked item (or a clearly scoped sub-bullet) in a session.
3. When an item is done: mark it `[x]`, add a short **Done** note (date + commit if useful), and stop.
4. Next session: same thing. Do not skip ahead unless a dependency forces it.

**Convention**

- `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked (note why)
- Prefer small, reviewable commits on `grok-rewrite`.
- Keep sample apps working when the fabric edge changes (or note breakage under Done).

**Sources** — this list is the actionable form of the core-fabric review (control plane, structure, app edge, crypto, workers, sync, persistence, IPv4).

---

## Status snapshot

| Field | Value |
|-------|--------|
| Current focus | *(none — next is §9.1)* |
| Last completed | 8.3 Wire versioning note (2026-07-23) |
| Branch | `grok-rewrite` |

Update this table when you finish a session.

---

## Phase 1 — Control plane safety

Highest risk relative to data-plane quality. Finish this phase before treating the node as safe on a real network.

### 1.1 Admin authentication
- [x] Implement admin password (set on first setup; stored hashed, not plaintext)
- [x] Session after login (cookie or equivalent); unauthenticated requests redirected to login
- [x] Setup routes remain available only while uninitialized; post-setup always require auth

**Done:** 2026-07-14 — `admin_auth` module (salted SHA-256 stretch hash, in-memory sessions, HttpOnly cookie). Password on new-user + join setup; `/login` + `/logout`; upgrade path `/set-password` when initialized without hash; `PNET_ADMIN_PASSWORD` for headless. See `descriptions/administration UI.md`.

### 1.2 Safe HTTP bind defaults
- [x] Default bind is loopback for all grades unless explicitly opted in
- [x] Opt-in remote admin via clear env (e.g. `PNET_HTTP_BIND=0.0.0.0`); document it
- [x] Align `main.rs` DG/SG bind logic with the above (invert “SG open by default”)

**Done:** 2026-07-15 — `http_bind_ip()` / `parse_http_bind()` in `http_server.rs`; default `127.0.0.1` for all grades; opt-in `PNET_HTTP_BIND` (legacy `PNET_HTTP_BIND_ALL` alias kept). Docker compose + live harness set `PNET_HTTP_BIND=0.0.0.0` where admin ports are published. Docs: `descriptions/administration UI.md`.

### 1.3 State-changing POSTs
- [x] CSRF protection (or same-site session policy documented) for admin POSTs when bind is non-loopback
- [x] Avoid putting invitation codes only in long-lived query strings when easy to fix (prefer POST body + display once)

**Done:** 2026-07-16 — Documented `SameSite=Strict` session cookie CSRF policy; Origin/Referer host must match `Host` when present (403 otherwise). Invitation codes no longer in redirect query strings: one-shot session flash for UI + `X-Pnet-Invitation-Code` header for harnesses. Stage/live helpers log in with `PNET_ADMIN_PASSWORD` / `stagetest1`. Docs: `descriptions/administration UI.md`.

### 1.4 Data directory permissions
- [x] Ensure data dir is `0700` on create/load
- [x] Confirm writer keeps files at `0600` (already intended; verify all write paths)

**Done:** 2026-07-16 — `persistence::ensure_data_dir` creates/secures `~/.pnet/data` at `0700` (parent `.pnet` too), tightens existing `node.toml`/`apps.toml` to `0600`. Public `writer::write_atomic` used by writer + main `PNET_HOSTS` path (no bare `fs::write`); post-rename `0600`. Unit tests for modes. Docs: `descriptions/data persistence.md`.

---

## Phase 2 — Code structure and honesty

Make the core navigable and stop lying comments/docs from causing wire bugs.

### 2.1 Split `handlers.rs` (thin dispatch stays)
Do one module at a time; keep tests compiling after each move.

- [x] Extract crypto helpers (`x25519`, ed25519, aead, seal/open packet)
- [x] Extract wire constants / min lengths / shared parse helpers
- [x] Extract local app edge (`app_register`, `app_update`, `app_get_data`, `app_send_packet`, push path)
- [x] Extract sessions (`connect_*`, `maintain_connections`, keepalive, conn_reset, poll_sg)
- [x] Extract bootstrap + invitations (device/contact invite mint + exchange)
- [x] Extract routing (`find_writer_sg`, `find_pull_source`, best SG, host resolve)
- [x] Extract sync (write/pull/cross-user/watermarks/merge)
- [x] Extract tunnels
- [x] Extract admin UI handlers/pages
- [x] `Action::dispatch` remains a thin router into these modules

**Done:** 2026-07-16 — Full §2.1 split:
- Top-level: `crypto.rs`, `wire.rs`
- `handlers/{app_edge,sessions,bootstrap,routing,sync,tunnels,admin_ui}.rs` + thin `handlers/mod.rs` (shared helpers, re-exports, unit tests)
- `Action::dispatch` only matches → `handlers::*` (unchanged thin router)

### 2.2 Fix stale docs and comments in core
- [x] App id is UUID (16 bytes) everywhere in comments (`app_get_data`, `app_send_packet`, design notes if wrong)
- [x] Remove obsolete “TODO: verify Ed25519” where verification already runs
- [x] Remove duplicate / “not yet implemented” docblocks above live handlers
- [x] Align short notes in `descriptions/` only where they contradict code (core fabric docs, not apps)

**Done:** 2026-07-16 — Wire comments use 16-byte app ids (`app_edge`, `relay_packet`, contact/public-state comments). Connect docs note Ed25519 is verified (not TODO). Removed stale “not yet implemented” + duplicate `app_send_packet` docblock. Docs: `Data Models.md` Application.id → Uuid; `data sync.md` merge rules + 7c.0 marked done.

---

## Phase 3 — Local app edge contracts

The fabric API apps depend on. Opaque payloads stay; contracts get boring and explicit.

### 3.1 Structured errors to apps
- [x] Send path returns error reply codes for: bad token, not approved, no route, payload too large (extend existing `0x01` scheme)
- [x] Document codes next to app op handlers (or in `descriptions/communication methods.md`)

**Done:** 2026-07-21 — `app_send_packet` returns `[STATUS_ERR][code]` for bad packet, unknown token, not approved, no route, payload too large (`ERR_NOT_APPROVED`/`ERR_NO_ROUTE`/`ERR_PAYLOAD_TOO_LARGE` + `MAX_APP_PAYLOAD=4096` in `wire.rs`). Success remains silent. Docs: handler comment block + `descriptions/communication methods.md`. Unit tests for each rejection.

### 3.2 Payload size limits
- [x] Enforce max app payload size on `AppSendPacket` (and reject oversized relay bodies consistently)
- [x] Document the limit as a fabric constant

**Done:** 2026-07-21 — `MAX_APP_PAYLOAD=4096` enforced on send (already §3.1), `relay_packet`, `app_packet`, `tunnel_delivery`; tunnel forward caps opaque blob via `MAX_TUNNEL_FORWARD_BLOB`. Docs: `wire.rs`, `communication methods.md`, `pnet to pnet communication.md`. Unit tests for oversized relay + AppPacket drop.

### 3.3 App API exposure policy
- [x] Prefer accepting app control/data only from loopback (or document multi-user risk and gate via env)
- [x] Rate-limit register/send per token and/or source (simple token bucket is enough)

**Done:** 2026-07-21 — App ops 0x00–0x03 loopback-only by default (`app_api_source_allowed` in UDP listener); `PNET_APP_API_REMOTE=1` opt-in (compose/live set it for sidecars). Token buckets on register (per IP) and send (per IP + token); `ERR_RATE_LIMITED=0x07`. Module `app_api.rs`. Docs: `communication methods.md`.

### 3.4 Push and approval invariants
- [x] Confirm unapproved apps never receive pushes
- [x] get-data never leaks foreign tokens/private keys (spot-check + test)

**Done:** 2026-07-21 — Shared `local_approved_app_host` on relay local delivery, `app_packet`, `tunnel_delivery` (tunnel path previously lacked approval). get-data secrecy docs + tests for no sibling/contact tokens, no private keys, unapproved contact apps omitted.

---

## Phase 4 — Cryptography hygiene

Data plane is already real; tighten key use and typing.

### 4.1 KDF before AEAD
- [x] Derive AEAD keys via HKDF (or domain-separated KDF) from X25519 shared secrets
- [x] Separate domain labels for session / bootstrap / tunnel if all use the helper

**Done:** 2026-07-22 — HKDF-SHA256 (`hkdf` crate) in `crypto.rs`: `derive_aead_key` / `aead_key_from_dh` with `aead_domain::{SESSION,BOOTSTRAP,TUNNEL}` (`pnet-aead-v1-…`). Session seal/open, bootstrap + contact invitation AEAD, and tunnel encrypt/decrypt all use derived keys (raw DH never fed to XChaCha). `PendingDeviceAcceptance.shared_secret` stores the bootstrap AEAD key. Docs: background systems, pnet-to-pnet, transport diagram. 234 tests green.

### 4.2 Distinct key types
- [x] Split identity (Ed25519) vs ephemeral (X25519) types so they cannot be mixed at compile time
- [x] Update generation sites (`generate_ed25519_keypair`, `generate_x25519_keypair`)

**Done:** 2026-07-22 — Replaced flat `KeyPair`/`PublicKey` aliases with `Ed25519{KeyPair,PublicKey,SecretKey}` and `X25519{KeyPair,PublicKey,SecretKey}` in `data_models`. Generators and crypto helpers take/return the matching types (`ed25519_sign/verify` vs `x25519_shared`/`aead_key_from_dh`). Field types: Owner/Contact identity → Ed25519; ActiveConnection/Invitation/Pending*/tunnel ephemerals → X25519. TOML hex shape unchanged. Docs: `Data Models.md`. 235 tests green.

### 4.3 RNG
- [x] Replace ad-hoc `/dev/urandom` opens with `getrandom` (or one shared helper); avoid panic on hot paths where practical

**Done:** 2026-07-23 — Shared `try_fill_random` / `fill_random` via `getrandom` crate in `data_models`; `generate_uuid` / `generate_key_bytes` and AEAD nonce minting use it (no per-call `/dev/urandom` open). CSPRNG failure still panics rather than emitting a zero/reused nonce (Option-return API deferred). Unit tests for fill + nonce uniqueness. Phase 4 complete.
---

## Phase 5 — Workers, queue, and runtime hygiene

Keep the hand-rolled pool; remove stall and unbounded-growth risks.

### 5.1 Queue bounds
- [x] Cap queue depth; define drop policy (prefer drop low priority under pressure)
- [x] Log/metric when drops happen

**Done:** 2026-07-23 — `QUEUE_CAPACITY=1024`; `ActionQueue::push` returns bool; at cap, drop newest item from the lowest-priority bucket strictly worse than the admit, else drop incoming. Logs `[queue] drop existing|incoming …`. `Action::kind_name` for log labels. Unit tests for capacity, shed-low, refuse-equal. Docs: `main program loop.md`.
### 5.2 No long waits on worker threads
- [x] Invitation mint wait (≤5s) must not hold a pool worker for the whole RTT (wait outside pool or release worker)
- [x] Audit other blocking UI/sync waits on workers

**Done:** 2026-07-23 — Delegated mint: worker only sends 0x35 + registers token (`InvitationMint::Pending`); admin UI waits via `PendingInvites::wait_result` on `pnet-invite-wait-*` off-pool threads that own the TCP stream. Local mint still `Ready` on the worker. Audit: no other RTT parks on workers; DNS still blocking on maintain/bootstrap paths (deferred to §5.3); `writer_tx` SyncSender can block if full (unrelated). Tests: wait/timeout + local Ready. Docs: main program loop.
### 5.3 DNS off the hot path
- [x] Cache host resolutions with TTL
- [x] Resolve on maintain/poll paths; send/routing uses cache only

**Done:** 2026-07-23 — `dns_cache::DnsCache` on `WorkerContext` (positive TTL 60s, negative 15s). `lookup` for send/routing (`best_address_for_device` cache-only; IPv4 literals always parse). `resolve` / `refresh_dns_for_known_hosts` on maintain + poll; bootstrap/contact join warm via `resolve_hosts(&mut cache, …)`. Tests: cache hit/miss/negative + hostname routing without OS. Docs: main program loop.
### 5.4 Locking (only if needed)
- [x] Measure or note contention on global `RwLock<Node>`
- [x] If needed: split hot maps (`active_connections`, `sg_statuses`) from cold directory state

**Done:** 2026-07-23 — **No split.** Code audit: 4 workers; send/DNS/invite-wait already off the node lock; holds are mostly short in-memory updates. Splitting session maps would add dual-lock hazard on almost every path without measured contention. Documented in `descriptions/locking.md`; discipline note on `WorkerContext`; diagnostics line for operators. Revisit if load shows `node.write` stalls. Phase 5 complete.
---

## Phase 6 — Sessions, NAT, routing (fabric ops quality)

Core behavior is largely designed; make it observable and resilient.

### 6.1 Fast reconnect after conn-reset
- [x] DG that receives conn-reset re-enters connection maintenance promptly (not only on 5‑minute tick)

**Done:** 2026-07-23 — `conn_reset` evicts active sessions (and pending to those peers) by peer IP, then calls `maintain_connections` **inline** on the same worker (no scheduler 1s/5min delay). Logs eviction. Test: stale session cleared + fresh pending ConnectRequest. Docs: background systems.
### 6.2 Diagnostics for fabric health
- [x] Diagnostics show: writer SG, versions (public/private), peer list, last RTT, keepalive/peer_addr age, partition flag
- [x] Structured log lines for: session up/down, writer change, partition detect, invite consumed

**Done:** 2026-07-23 — `/diagnostics` fabric health: writer election, public+private versions, partition flag, active sessions (peer_addr, remaining, refresh-age proxy), SG peers with RTT+poll age; watermarks/proposals retained. `fabric_event` logs: `session_up`/`session_down`, `writer_change` (version stamp + probe elect), `partition_detect`/`partition_clear` after poll, `invite_consumed`. `Node.partition_flag` for transition tracking. Docs: administration UI.
### 6.3 Routing / failover visibility
- [x] Log clear event when rank-1 treated down and traffic/writer moves to next rank
- [x] Cold-boot note: first connect may use unresolved RTT until poll warms (document or improve order)

**Done:** 2026-07-23 — `rank1_failover_info` + `Node.rank1_failover_active`; after PollSG log `rank_failover` / `rank_recovery` with skipped preferred SG and new writer. Startup enqueues PollSG (normal prio) before MaintainConnections. Cold-boot documented on `best_address_for_device` + background systems. Tests for failover info active/inactive/local takeover.
### 6.4 Tunnel correctness invariant
- [x] Test or assert: tunnel teardown falls back to standard relay without losing the ability to deliver

**Done:** 2026-07-23 — `app_send_packet`: tunnel path is best-effort; on failure/teardown fall through to direct (non-tunnel sessions) or `RELAY_PACKET`. Never AppPacket on a tunnel leg; skip expired sessions. `cleanup_tunnels` drops expired `dg_tunnel_map` + pending, logs `tunnel_teardown`. Tests: live tunnel uses 0x51; after cleanup send uses 0x40; stale map → relay. Phase 6 complete.
---

## Phase 7 — Sync honesty and durability

### 7.1 Partition / merge path
- [x] v2 merge is the supported concurrent-writer path; no quiet “discard other side” without operator visibility
- [x] Pure merge engine covered by union / tombstone / scalar-rank tests (extend if gaps)
- [x] `partition_detected` and retention-fallback data-loss path visible in admin diagnostics

**Done:** 2026-07-23 — Retention gap detection (`retention_gap_for_peer`); MergeProposal `0xFFFF` sentinel instead of incomplete log slice; receiver full-state pull + `MERGE_ACK_RESULT_RETENTION_EXHAUSTED`; `Owner.retention_fallback_*` + red banner + diagnostics row; fabric events `retention_fallback` / `merge_applied` / `merge_ack`. Merge tests: contact LWW by rank + retention sentinel/gap unit tests. Existing union/tombstone/scalar-rank suite retained.
### 7.2 Contact/device remove cascade
- [x] Remove contact/device: tombstone sync, drop sessions, drop tunnels, stop accepting connect from that identity

**Done:** 2026-07-23 — `Change::RemoveDevice` / `RemoveContact` (wire 0x06/0x07); apply + merge tombstones; `cascade_remove_fabric_state` drops sessions, pending, tunnels, sg_statuses; connect rejects unknown identities (existing). Logs `identity_removed`. Tests: merge device tombstone + local remove drops sessions.
### 7.3 Persistence split (when write_log grows)
- [x] Append-only write log (or separate file) vs directory snapshot
- [x] Keep atomic rename + fsync discipline from current writer

**Done:** 2026-07-23 — `write_log` skipped in `node.toml` serialization; separate `write_log.toml` via `WriteRequest::WriteLog` + `save_write_log` / load merge. Legacy embedded log still loads; next save splits. Atomic write uses per-file `.{name}.tmp` + fsync + rename + 0600. `ensure_data_dir` covers write_log.toml. Docs: data persistence. Phase 7 complete.
---

## Phase 8 — Wire and platform contracts

### 8.1 IPv4 contract
- [x] Document “IPv4 only” as v1 fabric contract **or** schedule dual-stack work
- [x] If documenting only: one short section in a core description + admin note

**Done:** 2026-07-23 — Documented IPv4-only v1 (no dual-stack schedule): `wire-versioning.md`, `pnet to pnet communication.md`, admin UI note. Dual-stack deferred to a later design.

### 8.2 Parser robustness
- [x] Untrusted UDP paths return errors instead of `unwrap` on slice conversion where practical
- [ ] Optional: fuzz bootstrap / directory encode / change payloads

**Done:** 2026-07-23 — `wire::slice_arr` (no panic on short buffers); production parse sites in udp_listener, sessions, bootstrap, tunnels, app_edge, relay use `Option` early-return. Fuzz optional deferred. Unit test for `slice_arr`.

### 8.3 Wire versioning note
- [x] Short design note: how the next breaking wire change will be signaled (capability byte / op range)

**Done:** 2026-07-23 — `descriptions/wire-versioning.md`: prefer new ops; handshake capability / V2 connect ops; AEAD domain `v1` → `v2` labels. Phase 8 complete (fuzz optional left unchecked intentionally).
---

## Phase 9 — Core test harness hygiene

### 9.1 Fast in-process fabric tests
- [ ] Two-node loopback test: connect → relay/app packet → local push path (no Docker)
- [ ] Keep stage/live harnesses for NAT and partition only

**Done:**  

### 9.2 Golden vectors
- [ ] Golden encode/decode for bootstrap payload and app get-data tree (UUID app ids)

**Done:**  

---

## Out of scope (do not pull into this list)

- Sample app product work (`pnet_chat` rooms/media, deliverer UX, etc.)
- Turning core into a message store or app-level ACK bus (unless a later checklist revisits hop-ACK deliberately)
- Third-party hosted SG product packaging (optional later; not blocking phases 1–8)

## Deferred — after this checklist

**App web surfaces (hybrid native + web apps)** — rank-1 SG hosts optional
public HTTPS mounts for apps (`/filesync`, etc.); native agents on DGs; same
app identity. Design captured in `descriptions/app-web-surfaces.md`. **Start
only after phases above are done**; do not fold into rewrite PRs.

---

## Session log

Add a line per work session (newest at top).

| Date | Item(s) | Notes |
|------|---------|--------|
| 2026-07-23 | 8.1–8.3 Wire/platform contracts | IPv4 docs; slice_arr parse; wire-versioning.md. Phase 8 done. |
| 2026-07-23 | 7.3 Persistence split | write_log.toml vs node.toml; atomic fsync kept. Phase 7 done. |
| 2026-07-23 | 7.2 Remove cascade | RemoveDevice/Contact + fabric session/tunnel drop. |
| 2026-07-23 | 7.1 Partition / merge honesty | Retention sentinel + visibility; contact merge tests. |
| 2026-07-23 | 6.4 Tunnel teardown → relay | Fallback + cleanup; tests. Phase 6 done. |
| 2026-07-23 | 6.3 Rank failover visibility | rank_failover logs; PollSG before maintain at boot. |
| 2026-07-23 | 6.2 Fabric diagnostics + logs | Diagnostics page + `[fabric] event=` lines. |
| 2026-07-23 | 6.1 Fast reconnect after conn-reset | Inline maintain after eviction; test. |
| 2026-07-23 | 5.4 Locking | Audit only; keep global RwLock; split deferred. Phase 5 done. |
| 2026-07-23 | 5.3 DNS off hot path | DnsCache TTL; maintain/poll resolve; routing lookup-only. |
| 2026-07-23 | 5.2 No long waits on workers | Invite mint wait off-pool; audit note; tests. |
| 2026-07-23 | 5.1 Queue bounds | Cap 1024; drop low-prio first; log drops; tests. |
| 2026-07-23 | 4.3 RNG | `getrandom` + shared fill helpers; no `/dev/urandom` in core; tests. |
| 2026-07-22 | 4.2 Distinct key types | Ed25519 vs X25519 newtypes end-to-end; 235 tests. |
| 2026-07-22 | 4.1 KDF before AEAD | HKDF-SHA256 + domain labels session/bootstrap/tunnel; 234 tests. |
| 2026-07-21 | 3.4 push/approval invariants | Approval gate on all push paths; get-data leak tests. |
| 2026-07-21 | 3.3 app API exposure | Loopback-only app ops + PNET_APP_API_REMOTE; rate limits; compose/live updated. |
| 2026-07-21 | 3.2 payload size limits | Same MAX_APP_PAYLOAD on relay/app_packet/tunnel; docs + drop tests. |
| 2026-07-21 | 3.1 structured app send errors | Distinct ERR_* on send path; MAX_APP_PAYLOAD; docs + unit tests. |
| 2026-07-16 | 2.2 stale docs/comments | UUID app-id comments; Ed25519 TODOs fixed; data models + sync docs. |
| 2026-07-16 | 2.1 admin UI + finish split | `handlers/admin_ui.rs`; §2.1 complete; 217 tests green. |
| 2026-07-16 | 2.1 tunnels extract | `handlers/tunnels.rs` 0x50–0x54 + cleanup; 217 tests green. |
| 2026-07-16 | 2.1 sync extract | `handlers/sync.rs` write/pull/cross-user/merge; 217 tests green. |
| 2026-07-16 | 2.1 routing extract | `handlers/routing.rs` writer election + host resolve; 217 tests green. |
| 2026-07-16 | 2.1 bootstrap + invitations | `handlers/bootstrap.rs`; 217 tests green. |
| 2026-07-16 | 2.1 sessions extract | `handlers/sessions.rs` connect/poll/maintain/keepalive; 217 tests green. |
| 2026-07-16 | 2.1 local app edge extract | `handlers/app_edge.rs`; handlers → directory; 217 tests green. |
| 2026-07-16 | 2.1 wire constants extract | New `wire.rs`; udp_listener uses named ops; 217 tests green. |
| 2026-07-16 | 2.1 crypto helpers extract | New `crypto.rs`; handlers uses it; 214 tests green. |
| 2026-07-16 | 1.4 Data directory permissions | ensure_data_dir 0700; write_atomic 0600 + main hosts path; mode tests. |
| 2026-07-16 | 1.3 State-changing POSTs | SameSite CSRF policy + Origin check; invite flash + X-Pnet-Invitation-Code; harness auth. |
| 2026-07-15 | 1.2 Safe HTTP bind defaults | Loopback default; `PNET_HTTP_BIND` opt-in; compose/live updated. |
| 2026-07-14 | 1.1 Admin authentication | Password hash + session cookie + route gates; tests green (198). |
| | | |

---

## What’s next?

The next work item is the **first unchecked `[ ]` in phase order** (Phase 1 → 9).  
If something is `[~]`, finish that before starting another.  
If something is `[!]`, either unblock it or mark a dependency and skip only with an explicit note in the session log.
