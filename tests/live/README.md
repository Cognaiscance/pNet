# Live multi-machine test harness

Stands pNet up on **real hardware over SSH** (not Docker) to validate fabric
behavior across sites — real NAT, real WAN latency, public DNS. Complements
`tests/stage-{a,b,c}/`.

## Roles

| Machine | Network | Role |
|---------|---------|------|
| **sanosuke** (dev box) | office LAN + VPN to house | **Orchestration only**: ssh, curl admin/probe HTTP, rsync, deploy |
| **n64** | house LAN + **public** `pnet.thehomegarage.com` | Rank-1 **SG** (only public UDP anchor) |
| **tealface** | office LAN | **DG** for the same user; dials SG over the public name |
| **zeus** | house LAN | receives aarch64 bins (optional future LAN peer; not required for P2) |

### Hard rule: no data-plane cheating

- **Do not** put VPN addresses (`10.8.0.*`) or Tailscale (`100.*`) in `PNET_HOSTS`.
- Cross-site pNet traffic must use **`pnet.thehomegarage.com`** (port forwards on the house router → n64).
- sanosuke’s VPN is fine for **SSH and HTTP oracles**; nodes must not depend on it.

## Current topology (WAN DG join)

| User | Device | Host | Grade | UDP/HTTP | Advertised hosts |
|------|--------|------|-------|----------|------------------|
| alice | alice-n64 | n64 | SG rank1 | 7777 / 8777 | `pnet.thehomegarage.com:7777` |
| alice | alice-tealface | tealface | DG | 7777 / 8777 | *(none — joiner)* |

Probes: `alice-n64-app` on n64, `alice-tealface-app` on tealface.

This is the live analogue of **P4 (WAN DG join)**: office DG bootstraps and
syncs through the public SG without a private path to the house LAN.

## Files

- `hosts.env` — host table + node/probe roster (edit here to retarget hardware).
- `lib.sh` — SSH launch, admin-UI helpers, probe oracles, waits, teardown.
- `deploy.sh` — n64 x86_64 (built on n64); **aarch64 cross-built on sanosuke**
  (native gcc or podman) and pushed to tealface + zeus.
- `up.sh` — bring-up + convergence (matches current `hosts.env`).
- `down.sh [--wipe]` — stop everything (`--wipe` also clears per-node data).
- `partition.sh cut|heal|show` — real nft UDP drop (LAN/WAN partition experiments).

## Prerequisites

1. SSH aliases `n64`, `tealface`, `zeus` in `~/.ssh/config`.
2. Source tree at `~/pnet-src` on **n64** (x86_64 native build). aarch64 is
   built on **sanosuke** — either:
   - `gcc-aarch64-linux-gnu` + `rustup target add aarch64-unknown-linux-gnu`, or
   - **podman** (used automatically; pulls `rust:1-bookworm`, no root install).
3. House router: UDP **7777** (and 7778 if you add a second public SG) → n64.
4. sanosuke can curl n64 admin/probe (via VPN) and tealface admin/probe (office LAN).
5. `curl`, `jq` on sanosuke.

## Run

```bash
cd tests/live

# After code changes: sync x86 tree to n64, then deploy (local arm cross-build)
rsync -az --delete --exclude target --exclude .git --exclude 'tests/stage-*' \
  ../../ n64:~/pnet-src/
bash deploy.sh
#   → cargo --release on n64 if needed
#   → aarch64 cross-build on sanosuke (podman or native linker)
#   → push aarch64 bins to tealface + zeus

bash up.sh              # P2: public SG + office DG converge
# … P3 contact / P5 partition later as needed …
bash down.sh --wipe
```

Reuse an existing aarch64 build: `SKIP_AARCH64_BUILD=1 bash deploy.sh`.

## Scenarios

- **P2 / P4 WAN DG join** — `up.sh` (this topology). Assert both probes
  registered and own-device graphs converge.
- **P3 cross-user sync** — needs a second user’s reachable SG (e.g. bob on
  n64:7778 public, if forwarded). Not in the default roster yet.
- **P5 partition** — nft drop between peers that already have a real path;
  office↔house partitions are “public path down,” not LAN nft on golden.

## Notes

- DG only **initiates** to the SG; responses return on the NAT binding. tealface
  does not need inbound port forwards.
- Throwaway harness: detached binaries under `$HOME/pnet-live/`, killed by
  `pkill` patterns in `down.sh`; no systemd units.
- Older LAN topology (golden + zeus, private `192.168.1.*` hosts) is retired
  while golden is offline; recover from git history if needed.
