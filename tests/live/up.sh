#!/usr/bin/env bash
# P2 bring-up: stand up the live topology and wait for per-user convergence.
# Assumes deploy.sh has placed binaries on every host used by NODES/PROBES.
#
# Current hosts.env topology (WAN DG join):
#   alice_n64       SG-new rank1 @ n64, public PNET_HOSTS
#   alice_tealface  DG join      @ tealface (office → public SG)
#
# Usage:  cd tests/live && bash up.sh

cd "$(dirname "$0")"
source hosts.env
source lib.sh
require curl; require jq; require ssh

ADMIN_WAIT=40
REGISTER_WAIT=90
CONVERGE_WAIT=180

# Hosts that run nodes/probes in this topology (derived from rosters).
wipe_hosts_in_use() {
    local h name hosts=()
    for name in "${NODES[@]}"; do
        h=$(field "$(eval echo "\$NODE_${name}")" 1)
        hosts+=("$h")
    done
    for name in "${PROBES[@]}"; do
        h=$(field "$(eval echo "\$PROBE_${name}")" 1)
        hosts+=("$h")
    done
    # unique
    printf '%s\n' "${hosts[@]}" | sort -u
}

say "clean slate: stop + wipe hosts used by this topology"
while read -r h; do
    [[ -n "$h" ]] || continue
    wipe_host "$h"
done < <(wipe_hosts_in_use)
sleep 2

# ── rank-1 (SG-new) public anchor ──────────────────────────────────────────
start_node alice_n64

say "waiting for alice_n64 admin UI..."
wait_for_url "$(admin_url alice_n64)/" "$ADMIN_WAIT" \
    || die "alice_n64 admin UI never came up at $(admin_url alice_n64)"

# ── office DG over public DNS ──────────────────────────────────────────────
say "minting device invitation on alice_n64 + starting alice_tealface (DG)"
CODE_AT=$(mint_device_invitation alice_n64)
start_node alice_tealface "$CODE_AT"

say "waiting for alice_tealface admin UI (office LAN)..."
wait_for_url "$(admin_url alice_tealface)/" "$ADMIN_WAIT" \
    || warn "alice_tealface admin UI not up yet (bootstrap may still be in flight)"

# ── probes ─────────────────────────────────────────────────────────────────
say "starting probes"
for p in "${PROBES[@]}"; do start_probe "$p"; done

say "waiting up to ${REGISTER_WAIT}s for probes registered+approved..."
wait_for_probes "$REGISTER_WAIT" "${PROBES[@]}" \
    || die "not all probes registered/approved"

# ── per-user convergence (SG + office DG via public path / relay) ──────────
say "waiting up to ${CONVERGE_WAIT}s for alice SG+DG to converge..."
wait_for_convergence "$CONVERGE_WAIT" p_alice_n64 p_alice_tealface \
    || die "alice did not converge (check tealface can dial ${N64_PUBLIC}:7777 UDP)"

say "TOPOLOGY UP — alice SG (n64/public) + DG (tealface/office) converged."
printf '  alice admin: %s (n64) | %s (tealface)\n' \
    "$(admin_url alice_n64)" "$(admin_url alice_tealface)"
printf '  probes: '; for p in "${PROBES[@]}"; do printf '%s ' "$(probe_url "$p")"; done; echo
printf '  data plane: SG advertises %s (no VPN/Tailscale hosts)\n' "${N64_PUBLIC}:7777"
