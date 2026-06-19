#!/usr/bin/env bash
# P2 bring-up: stand up the full live topology and wait for per-user
# device-app convergence. Assumes deploy.sh has placed binaries on every host.
#
#   alice: alice_n64 (SG-new, rank1, public) + alice_golden (SG-join, rank2)
#   bob:   bob_n64   (SG-new, rank1, public) + bob_zeus (join,2) + bob_stealth (join,3,WAN)
#   one probe per SG.
#
# Usage:  cd tests/live && bash up.sh

cd "$(dirname "$0")"
source hosts.env
source lib.sh
require curl; require jq; require ssh

ADMIN_WAIT=40
REGISTER_WAIT=90
CONVERGE_WAIT=120

say "clean slate: stop + wipe all hosts"
for h in n64 golden zeus stealth-bomber; do wipe_host "$h"; done
sleep 2

# ── rank-1 (SG-new) anchors on n64 ─────────────────────────────────────────
start_node alice_n64
start_node bob_n64

say "waiting for n64 admin UIs (alice:8777, bob:8778)..."
wait_for_url "$(admin_url alice_n64)/" "$ADMIN_WAIT" || die "alice_n64 admin UI never came up"
wait_for_url "$(admin_url bob_n64)/"   "$ADMIN_WAIT" || die "bob_n64 admin UI never came up"

# ── joining SGs ─────────────────────────────────────────────────────────────
say "minting device invitations + starting joining SGs"
CODE_AG=$(mint_device_invitation alice_n64); start_node alice_golden "$CODE_AG"
CODE_BZ=$(mint_device_invitation bob_n64);   start_node bob_zeus     "$CODE_BZ"
CODE_BS=$(mint_device_invitation bob_n64);   start_node bob_stealth  "$CODE_BS"

say "waiting for joining SG admin UIs..."
wait_for_url "$(admin_url alice_golden)/" "$ADMIN_WAIT" || warn "alice_golden admin UI not up"
wait_for_url "$(admin_url bob_zeus)/"     "$ADMIN_WAIT" || warn "bob_zeus admin UI not up"
wait_for_url "$(admin_url bob_stealth)/"  "$ADMIN_WAIT" || warn "bob_stealth admin UI not up (WAN)"

# ── probes (the registered apps + oracles) ──────────────────────────────────
say "starting probes"
for p in "${PROBES[@]}"; do start_probe "$p"; done

say "waiting up to ${REGISTER_WAIT}s for probes registered+approved..."
wait_for_probes "$REGISTER_WAIT" "${PROBES[@]}" || die "not all probes registered/approved"

# ── per-user convergence ─────────────────────────────────────────────────────
say "waiting up to ${CONVERGE_WAIT}s for alice's 2 SGs to converge..."
wait_for_convergence "$CONVERGE_WAIT" p_alice_n64 p_alice_golden || die "alice did not converge"

say "waiting up to ${CONVERGE_WAIT}s for bob's 3 SGs (incl. WAN stealth) to converge..."
wait_for_convergence "$CONVERGE_WAIT" p_bob_n64 p_bob_zeus p_bob_stealth || die "bob did not converge"

say "TOPOLOGY UP — per-user device-app graphs converged."
printf '  alice admin: %s (n64) | %s (golden)\n' "$(admin_url alice_n64)" "$(admin_url alice_golden)"
printf '  bob   admin: %s (n64) | %s (zeus) | %s (stealth)\n' "$(admin_url bob_n64)" "$(admin_url bob_zeus)" "$(admin_url bob_stealth)"
printf '  probes: '; for p in "${PROBES[@]}"; do printf '%s ' "$(probe_url "$p")"; done; echo
