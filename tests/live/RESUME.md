# Resume guide — live multi-machine testing

Updated: 2026-07-24 (tealface@office replaces golden; no Tailscale/VPN data plane).

## Topology in force

See `hosts.env` + `README.md`. Short version:

- **Orchestration:** sanosuke (office LAN + VPN to house) — ssh/curl only.
- **SG:** `alice_n64` on n64, `PNET_HOSTS=pnet.thehomegarage.com:7777` only.
- **DG:** `alice_tealface` on tealface (office) joins via device invitation; dials
  the **public** SG (real WAN/NAT). No private path to `192.168.1.*`.
- **Builds:** n64 builds its own x86_64 release; **sanosuke cross-builds
  aarch64** (podman or `gcc-aarch64-linux-gnu`) and `deploy.sh` pushes to
  tealface + zeus (no cargo on the Pis).
- **golden:** unplugged — removed from the active roster.

## Fast path

```bash
cd tests/live
# rebuild if needed (rsync + cargo on n64 + zeus), then:
bash deploy.sh
bash up.sh
bash down.sh --wipe
```

## Open work after P2 is green

1. Confirm public UDP 7777 still forwards to n64 from the internet (office
   tealface → `pnet.thehomegarage.com:7777`).
2. Rebuild from `grok-rewrite` (bins on hosts may still be May 2026-era).
3. P3 cross-user: second public SG (e.g. bob on n64:7778) if port-forwarded.
4. P5: partition tealface↔public IP, then heal and watch re-connect/merge.
5. Merge `grok-rewrite` → `develop` only after the live run you care about passes.

## Historical notes (still useful)

- Hairpin NAT: do not co-locate two users on n64 both advertising LAN+public in
  a way that forces hairpin; public-only for WAN peers is intentional here.
- pNet dials the first advertised host only — no LAN/public fallback.
- SIGTERM shutdown hang fixed 2026-06-21 (7c.14); writer-election partition
  fixes in 7c.11–7c.13 — re-validate under this WAN topology when you get to P5.
