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
| Current focus | *(none — next is §1.2)* |
| Last completed | 1.1 Admin authentication (2026-07-14) |
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
- [ ] Default bind is loopback for all grades unless explicitly opted in
- [ ] Opt-in remote admin via clear env (e.g. `PNET_HTTP_BIND=0.0.0.0`); document it
- [ ] Align `main.rs` DG/SG bind logic with the above (invert “SG open by default”)

**Done:**  

### 1.3 State-changing POSTs
- [ ] CSRF protection (or same-site session policy documented) for admin POSTs when bind is non-loopback
- [ ] Avoid putting invitation codes only in long-lived query strings when easy to fix (prefer POST body + display once)

**Done:**  

### 1.4 Data directory permissions
- [ ] Ensure data dir is `0700` on create/load
- [ ] Confirm writer keeps files at `0600` (already intended; verify all write paths)

**Done:**  

---

## Phase 2 — Code structure and honesty

Make the core navigable and stop lying comments/docs from causing wire bugs.

### 2.1 Split `handlers.rs` (thin dispatch stays)
Do one module at a time; keep tests compiling after each move.

- [ ] Extract crypto helpers (`x25519`, ed25519, aead, seal/open packet)
- [ ] Extract wire constants / min lengths / shared parse helpers
- [ ] Extract local app edge (`app_register`, `app_update`, `app_get_data`, `app_send_packet`, push path)
- [ ] Extract sessions (`connect_*`, `maintain_connections`, keepalive, conn_reset, poll_sg)
- [ ] Extract bootstrap + invitations (device/contact invite mint + exchange)
- [ ] Extract routing (`find_writer_sg`, `find_pull_source`, best SG, host resolve)
- [ ] Extract sync (write/pull/cross-user/watermarks/merge)
- [ ] Extract tunnels
- [ ] Extract admin UI handlers/pages
- [ ] `Action::dispatch` remains a thin router into these modules

**Done:**  

### 2.2 Fix stale docs and comments in core
- [ ] App id is UUID (16 bytes) everywhere in comments (`app_get_data`, `app_send_packet`, design notes if wrong)
- [ ] Remove obsolete “TODO: verify Ed25519” where verification already runs
- [ ] Remove duplicate / “not yet implemented” docblocks above live handlers
- [ ] Align short notes in `descriptions/` only where they contradict code (core fabric docs, not apps)

**Done:**  

---

## Phase 3 — Local app edge contracts

The fabric API apps depend on. Opaque payloads stay; contracts get boring and explicit.

### 3.1 Structured errors to apps
- [ ] Send path returns error reply codes for: bad token, not approved, no route, payload too large (extend existing `0x01` scheme)
- [ ] Document codes next to app op handlers (or in `descriptions/communication methods.md`)

**Done:**  

### 3.2 Payload size limits
- [ ] Enforce max app payload size on `AppSendPacket` (and reject oversized relay bodies consistently)
- [ ] Document the limit as a fabric constant

**Done:**  

### 3.3 App API exposure policy
- [ ] Prefer accepting app control/data only from loopback (or document multi-user risk and gate via env)
- [ ] Rate-limit register/send per token and/or source (simple token bucket is enough)

**Done:**  

### 3.4 Push and approval invariants
- [ ] Confirm unapproved apps never receive pushes
- [ ] get-data never leaks foreign tokens/private keys (spot-check + test)

**Done:**  

---

## Phase 4 — Cryptography hygiene

Data plane is already real; tighten key use and typing.

### 4.1 KDF before AEAD
- [ ] Derive AEAD keys via HKDF (or domain-separated KDF) from X25519 shared secrets
- [ ] Separate domain labels for session / bootstrap / tunnel if all use the helper

**Done:**  

### 4.2 Distinct key types
- [ ] Split identity (Ed25519) vs ephemeral (X25519) types so they cannot be mixed at compile time
- [ ] Update generation sites (`generate_ed25519_keypair`, `generate_x25519_keypair`)

**Done:**  

### 4.3 RNG
- [ ] Replace ad-hoc `/dev/urandom` opens with `getrandom` (or one shared helper); avoid panic on hot paths where practical

**Done:**  

---

## Phase 5 — Workers, queue, and runtime hygiene

Keep the hand-rolled pool; remove stall and unbounded-growth risks.

### 5.1 Queue bounds
- [ ] Cap queue depth; define drop policy (prefer drop low priority under pressure)
- [ ] Log/metric when drops happen

**Done:**  

### 5.2 No long waits on worker threads
- [ ] Invitation mint wait (≤5s) must not hold a pool worker for the whole RTT (wait outside pool or release worker)
- [ ] Audit other blocking UI/sync waits on workers

**Done:**  

### 5.3 DNS off the hot path
- [ ] Cache host resolutions with TTL
- [ ] Resolve on maintain/poll paths; send/routing uses cache only

**Done:**  

### 5.4 Locking (only if needed)
- [ ] Measure or note contention on global `RwLock<Node>`
- [ ] If needed: split hot maps (`active_connections`, `sg_statuses`) from cold directory state

**Done:**  

---

## Phase 6 — Sessions, NAT, routing (fabric ops quality)

Core behavior is largely designed; make it observable and resilient.

### 6.1 Fast reconnect after conn-reset
- [ ] DG that receives conn-reset re-enters connection maintenance promptly (not only on 5‑minute tick)

**Done:**  

### 6.2 Diagnostics for fabric health
- [ ] Diagnostics show: writer SG, versions (public/private), peer list, last RTT, keepalive/peer_addr age, partition flag
- [ ] Structured log lines for: session up/down, writer change, partition detect, invite consumed

**Done:**  

### 6.3 Routing / failover visibility
- [ ] Log clear event when rank-1 treated down and traffic/writer moves to next rank
- [ ] Cold-boot note: first connect may use unresolved RTT until poll warms (document or improve order)

**Done:**  

### 6.4 Tunnel correctness invariant
- [ ] Test or assert: tunnel teardown falls back to standard relay without losing the ability to deliver

**Done:**  

---

## Phase 7 — Sync honesty and durability

### 7.1 Partition / merge path
- [ ] v2 merge is the supported concurrent-writer path; no quiet “discard other side” without operator visibility
- [ ] Pure merge engine covered by union / tombstone / scalar-rank tests (extend if gaps)
- [ ] `partition_detected` and retention-fallback data-loss path visible in admin diagnostics

**Done:**  

### 7.2 Contact/device remove cascade
- [ ] Remove contact/device: tombstone sync, drop sessions, drop tunnels, stop accepting connect from that identity

**Done:**  

### 7.3 Persistence split (when write_log grows)
- [ ] Append-only write log (or separate file) vs directory snapshot
- [ ] Keep atomic rename + fsync discipline from current writer

**Done:**  

---

## Phase 8 — Wire and platform contracts

### 8.1 IPv4 contract
- [ ] Document “IPv4 only” as v1 fabric contract **or** schedule dual-stack work
- [ ] If documenting only: one short section in a core description + admin note

**Done:**  

### 8.2 Parser robustness
- [ ] Untrusted UDP paths return errors instead of `unwrap` on slice conversion where practical
- [ ] Optional: fuzz bootstrap / directory encode / change payloads

**Done:**  

### 8.3 Wire versioning note
- [ ] Short design note: how the next breaking wire change will be signaled (capability byte / op range)

**Done:**  

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

---

## Session log

Add a line per work session (newest at top).

| Date | Item(s) | Notes |
|------|---------|--------|
| 2026-07-14 | 1.1 Admin authentication | Password hash + session cookie + route gates; tests green (198). |
| | | |

---

## What’s next?

The next work item is the **first unchecked `[ ]` in phase order** (Phase 1 → 9).  
If something is `[~]`, finish that before starting another.  
If something is `[!]`, either unblock it or mark a dependency and skip only with an explicit note in the session log.
