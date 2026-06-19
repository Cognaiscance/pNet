# Live multi-machine test harness

Stands pNet up on **real hardware over SSH** (not Docker) to validate sync v1
(cross-user) and sync v2 (partition reconciliation) on the wire — real NAT, real
WAN latency, public DNS, genuine link drops. Complements `tests/stage-{a,b,c}/`.

## Topology

| User | SG | Host | UDP | HTTP | Reach |
|------|----|------|-----|------|-------|
| alice | rank1 | n64 | 7777 | 8777 | public (`pnet.thehomegarage.com`) + LAN |
| alice | rank2 | golden | 7777 | 8777 | LAN |
| bob | rank1 | n64 | 7778 | 8778 | public + LAN |
| bob | rank2 | zeus | 7777 | 8777 | LAN |
| bob | rank3 | stealth-bomber | 7777 | 8777 | **WAN/office** (NAT, reaches others only via n64's public name) |

One probe per SG (the registered app + `/status` oracle). `alice ↔ bob` are
contacts. Per-host UDP/HTTP ports + per-node `$HOME` let n64 host both users'
rank-1 SGs (needs the `PNET_HTTP_PORT` env var added alongside this harness).

## Files

- `hosts.env` — host table + node/probe roster (edit here to retarget hardware).
- `lib.sh` — SSH launch (`setsid`+`nohup`, data isolated per node `$HOME`),
  admin-UI helpers (invitations/contacts/rename), probe `/status` oracles, waits,
  teardown. Mirrors the stage-c assertion logic.
- `deploy.sh` — build hosts: `cargo build --release` under `~/pnet-src` on **n64**
  (x86_64) and **golden** (aarch64), then this distributes binaries to every
  host's `~/pnet-live/bin/` (aarch64 golden→{zeus,stealth}).
- `up.sh` — P2 bring-up + per-user convergence.
- `down.sh [--wipe]` — stop everything (`--wipe` also clears per-node data).
- `partition.sh cut|heal|show` — real nft UDP drop for P5.

## Prerequisites

1. Source tree present at `~/pnet-src` on n64 + golden, built `--release`
   (`pnet`, `pnet_test_probe`, `pnet_deliverer`). golden needs `build-essential`
   + a rustup toolchain.
2. SSH aliases `n64 golden zeus stealth-bomber` resolve (see `~/.ssh/config`).
3. Dev box can curl each host's admin/probe ports (it routes to all hosts).
4. `curl`, `jq` on the dev box.

## Run

```bash
cd tests/live
bash deploy.sh          # distribute binaries
bash up.sh              # P2: bring up + converge
# P3 cross-user sync, P4 WAN DG join, P5 partition — driven on top of a live up.sh
bash down.sh --wipe     # teardown
```

## Scenarios

- **P3 cross-user sync** — mint a contact invitation on alice, redeem on bob;
  assert each user's probes see the other's apps; delete one side, assert
  propagation.
- **P4 WAN DG join** — an alice DG joins from stealth over `pnet.thehomegarage.com`;
  assert register/approve + receipt of alice's Public state over real WAN/NAT.
- **P5 partition reconciliation** — `partition.sh cut` (LAN: golden⊥n64; WAN:
  stealth⊥n64), mutate both sides (`rename_app`), `heal`, watch the 60s merge
  tick converge (union / rank conflict / tombstone).

## Notes

- WAN heal depends on the isolated SG **re-initiating** to the anchor (NAT gives
  no inbound path). Watch that the keepalive/poll/reconcile cadence keeps the NAT
  mapping warm (`scheduler.rs`: poll 30s, reconcile 60s, keepalive 20s).
- Throwaway harness: processes are plain detached binaries, killed by `pkill -f`
  patterns in `down.sh`; no systemd units installed.
