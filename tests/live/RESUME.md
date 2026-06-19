# Resume guide — live multi-machine testing

Last session: 2026-05-29. Stopped after validating P2 (bring-up) + P3 (cross-user
sync) and a partial P5 (partition reconciliation). All live nodes are torn down;
the dev-box working tree has the fixes (uncommitted) and is clean (179 unit tests
pass). See memory `project_live_test_findings.md` for the full findings.

## Fast resume (everything is already in place)

Binaries are already built and deployed on every host at `~/pnet-live/bin/`
(x86_64 on n64; aarch64 on golden/zeus/stealth). Source is at `~/pnet-src` on
n64 + golden. SSH connection multiplexing is configured in `lib.sh`.

```bash
cd tests/live
bash up.sh          # brings up the LAN topology + waits for convergence
# ... run scenarios ...
bash down.sh --wipe # stop + clear data (binaries stay)
```

`hosts.env` is currently the **LAN cross-user topology** (validated for P3 + P5):
- alice: alice-n64 (rank1)
- bob:   bob-golden (rank1) + bob-zeus (rank2)
- all advertise LAN IPs only → no hairpin NAT.

NOTE: `up.sh` was written for the *original* full topology (alice n64+golden,
bob n64+zeus+stealth). After the P3 hairpin finding, `hosts.env` was switched to
the LAN topology and the P3/P5 bring-up was driven inline. Before re-running
`up.sh`, reconcile it with the current `hosts.env` node names (alice_n64,
bob_golden, bob_zeus) — or drive bring-up inline as last session did (wipe →
start_node alice_n64 / bob_golden → mint device invite → start_node bob_zeus →
start probes → wait_for_convergence). The original full/WAN topology is described
in README.md and recoverable from git history of hosts.env.

## After code changes — rebuild + redeploy

```bash
# sync source to build hosts, rebuild, then distribute
rsync -az --delete --exclude target --exclude .git --exclude 'tests/stage-*' \
  ../../ n64:~/pnet-src/ ; rsync ... golden:~/pnet-src/
ssh n64    'cd ~/pnet-src && ~/.cargo/bin/cargo build --release -p pnet -p pnet_test_probe -p pnet_deliverer'
ssh golden 'cd ~/pnet-src && ~/.cargo/bin/cargo build --release -p pnet -p pnet_test_probe -p pnet_deliverer'
bash deploy.sh      # n64=x86_64, golden→{zeus,stealth}=aarch64 (pipes via cat; stealth has no scp)
```
(rsync of the tree to the hosts needs a Bash permission the user authorized last
session — re-authorize if prompted.)

## Environment notes / gotchas
- golden + stealth ssh as **root**; n64 + zeus ssh as **william** (no sudo on n64).
- golden now has `nftables` installed (for `partition.sh`). Partition bob's SGs:
  `bash partition.sh cut golden 192.168.1.116 7777` / `... heal golden`.
- Kill nodes with the `[p]net-live/bin/pnet` bracket pattern (pkill self-match!).
- pnet hangs on SIGTERM — always SIGKILL (`down.sh` does).
- zeus has a pre-existing service on :3000 → its probe uses :3010.
- Only n64 has public UDP forwarding (7777/7778 → pnet.thehomegarage.com); the
  others are LAN-only. pNet dials only the first advertised host (no LAN/public
  fallback) — that's why mixed LAN+WAN can't share one node.

## Open work (next session)
1. ~~**P5 write-log bug**~~ — FIXED in code 2026-06-19 (commit 7c.11), pending
   live re-validation. Root cause was NOT a missing write-log append (that path
   was fine); it was **writer-election timing**: a rank-2 SG could only self-elect
   writer after the rank-1 was confirmed polled-down (up to POLL_SG_INTERVAL=30s),
   and during that window its write hit `Unreachable` and was rolled back (lost),
   so it had nothing to propose on heal. Fix: `find_writer_sg_probing` fires an
   on-demand `poll_sg` on the Unreachable write path and re-evaluates, collapsing
   the window to ~1 ping timeout. **Re-run the bilateral nft partition (golden
   rank1 + zeus rank2, both rename their own app during the cut) and confirm heal
   now converges BOTH directions.**
   - ~~Related latent issue: `merge_proposal` stamps `writer_sg_uuid=local_uuid`
     on heal, so both SGs claim writer post-heal.~~ FIXED 2026-06-19 (7c.12): the
     merge bump now stamps the elected rank-1 writer (`find_pull_source` rank
     walk) so both survivors converge on the same writer_sg_uuid. Test:
     `merge_bump_stamps_elected_rank1_writer_not_local`.
2. **Gap #2** — contact public-state not propagated to non-writer own SGs.
3. **SIGTERM hang** — graceful shutdown never completes.
4. **P4 WAN DG join** — not yet run (needs the n64 public anchor).
5. ~~Decide what to commit~~ — DONE: 4 fixes committed as 7c.9 (`07d6fb3`),
   `tests/live/` as 7c.10 (`fa50eb5`); both pushed to origin/develop.
