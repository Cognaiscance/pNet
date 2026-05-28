#!/usr/bin/env bash
# Stage C test suite — sync v2 partition reconciliation end-to-end.
#
# Partition mechanism: pause both proxy-sg-N sidecars. Pausing freezes the
# socat fork children but preserves their UDP socket bindings, so each SG's
# ActiveConnection.peer_addr (pointing at a socat child's ephemeral port)
# stays valid across the partition — convergence after unpause flows through
# the 7c.6.5 periodic merge tick rather than a fresh connect_ack.
#
# Scenarios (all reuse the same converged base topology, run in order):
#   A. Union (independent targets, no merge conflict) — both sides rename a
#      different app while partitioned; after heal both sides must see both
#      renames applied.
#   B. Scalar conflict (same target, rank decides) — both sides rename the
#      *same* app to different values while partitioned; after heal both
#      sides must see the rank-1 SG's value win (lower rank = higher
#      priority, per entry_priority's std::cmp::Reverse<rank>).
#   C. Tombstone (single-sided delete) — sg-alice-1 deletes an app while
#      partitioned; after heal sg-alice-2 must drop it too.
#
# Exits non-zero on any assertion failure. Requires: podman compose, curl, jq.

set -euo pipefail

cd "$(dirname "$0")/../.."

COMPOSE_FILE="docker-compose.stage-c.yml"
COMPOSE=(podman compose -f "$COMPOSE_FILE")

SG1_ADMIN="http://localhost:8821"
SG2_ADMIN="http://localhost:8822"
PROBE1_PORT=3821
PROBE2_PORT=3822

PROXY_SERVICES=(proxy-sg-1 proxy-sg-2)

# poll_sg fires every 30s. Each SG must mark the other down before it'll
# elect itself writer (sg-1 already is the known writer, so this only really
# gates sg-2's writes). 60s = two poll cycles for a comfortable margin.
WAIT_POLL_DOWN_SECS=60
# partition_reconcile_tick fires every 60s — give it 120s to definitely run
# at least once on each side after we unpause. Bilateral merges may need a
# second tick to converge if the first round only flowed one direction.
WAIT_CONVERGE_SECS=120
POLL_INTERVAL=2

say()  { printf '\n[stage-c-test] %s\n' "$*"; }
ok()   { printf '[stage-c-test][ok]   %s\n' "$*"; }
die()  { printf '\n[stage-c-test][FAIL] %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

probe_status() {
    local port="$1"
    curl -sSf "http://localhost:${port}/status" 2>/dev/null
}

# App count for a given device alias as visible from a probe.
device_app_count() {
    local port="$1" device_alias="$2" body
    body=$(probe_status "$port") || return 1
    jq -r --arg alias "$device_alias" '
        .own_devices[]
        | select(.alias == $alias)
        | (.apps // []) | length
    ' <<< "$body" | head -n1
}

# Alias of a given app on a given device, as seen via a probe.
device_app_alias() {
    local port="$1" device_alias="$2" app_id="$3" body
    body=$(probe_status "$port") || return 1
    jq -r --arg dev "$device_alias" --arg id "$app_id" '
        .own_devices[]
        | select(.alias == $dev)
        | .apps[]?
        | select(.id_hex == $id)
        | .alias
    ' <<< "$body" | head -n1
}

# probe-1's own app id, read from probe-1 itself.
probe1_app_id() {
    local body
    body=$(probe_status "$PROBE1_PORT") || return 1
    jq -r '
        .own_devices[]
        | select(.alias == "sg-alice-1")
        | .apps[]?
        | select(.alias == "probe")
        | .id_hex
    ' <<< "$body" | head -n1
}

# probe-2's own app id, read from probe-2 itself.
probe2_app_id() {
    local body
    body=$(probe_status "$PROBE2_PORT") || return 1
    jq -r '
        .own_devices[]
        | select(.alias == "sg-alice-2")
        | .apps[]?
        | select(.alias == "probe")
        | .id_hex
    ' <<< "$body" | head -n1
}

# Wait until a single probe's /status view shows `expected` for (device, app).
# Probes refresh every 5s, so pre-heal sanity checks need a brief poll to
# tolerate the refresh lag rather than a one-shot read.
wait_for_alias_on_probe() {
    local port="$1" device_alias="$2" app_id="$3" expected="$4" timeout="$5"
    local deadline=$(( $(date +%s) + timeout ))
    while :; do
        local got
        got=$(device_app_alias "$port" "$device_alias" "$app_id" || echo "?")
        if [[ "$got" == "$expected" ]]; then return 0; fi
        if [[ $(date +%s) -ge $deadline ]]; then
            say "expected alias '${expected}' on ${device_alias}'s app ${app_id} via port ${port}; got '${got}' after ${timeout}s"
            die "single-probe alias wait timeout"
        fi
        sleep "$POLL_INTERVAL"
    done
}

# Wait until both probes' /status views agree on the alias of (device, app).
# Errors on any non-303/302 publish failure surfaced via ?error=.
wait_for_alias_on_both_probes() {
    local device_alias="$1" app_id="$2" expected="$3" timeout="$4"
    local deadline=$(( $(date +%s) + timeout ))
    while :; do
        local a1 a2
        a1=$(device_app_alias "$PROBE1_PORT" "$device_alias" "$app_id" || echo "?")
        a2=$(device_app_alias "$PROBE2_PORT" "$device_alias" "$app_id" || echo "?")
        if [[ "$a1" == "$expected" && "$a2" == "$expected" ]]; then return 0; fi
        if [[ $(date +%s) -ge $deadline ]]; then
            say "expected alias '${expected}' on ${device_alias}'s app ${app_id} from both probes;"
            say "  got probe-1=${a1} probe-2=${a2} after ${timeout}s"
            die "alias-convergence timeout"
        fi
        sleep "$POLL_INTERVAL"
    done
}

wait_for_sg1_app_count_from_probe2() {
    local expected="$1" timeout="$2"
    local deadline=$(( $(date +%s) + timeout ))
    while :; do
        local got
        got=$(device_app_count "$PROBE2_PORT" "sg-alice-1" || echo "?")
        if [[ "$got" == "$expected" ]]; then return 0; fi
        if [[ $(date +%s) -ge $deadline ]]; then
            local body; body=$(probe_status "$PROBE2_PORT" || echo "{}")
            say "expected ${expected} apps on sg-alice-1 (per probe-2), got ${got}, after ${timeout}s. View:"
            jq -c '.own_devices' <<< "$body"
            die "tombstone convergence timeout"
        fi
        sleep "$POLL_INTERVAL"
    done
}

post_rename() {
    local admin="$1" id="$2" alias="$3" code
    code=$(curl -sS -o /dev/null -w '%{http_code}' \
        -X POST \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "id=${id}" \
        --data-urlencode "alias=${alias}" \
        "${admin}/applications/rename")
    [[ "$code" == "303" || "$code" == "302" ]] \
        || die "rename returned ${code}, expected 302/303 (admin=${admin} id=${id})"
}

require curl
require jq
require podman

# ── Bring up ──────────────────────────────────────────────────────────────

say "running tests/stage-c/run.sh..."
bash "$(dirname "$0")/run.sh"

APP1_ID=$(probe1_app_id)
APP2_ID=$(probe2_app_id)
[[ -n "$APP1_ID" ]] || die "could not read probe-1's app id"
[[ -n "$APP2_ID" ]] || die "could not read probe-2's app id"
say "probe-1's app id = $APP1_ID"
say "probe-2's app id = $APP2_ID"

# ── Scenario A: union (independent targets) ────────────────────────────────

say "scenario A: union — independent renames on each side during partition."

say "  pausing both UDP relays to simulate partition..."
"${COMPOSE[@]}" pause "${PROXY_SERVICES[@]}" >/dev/null

say "  waiting ${WAIT_POLL_DOWN_SECS}s for both sides' poll_sg to mark each other down..."
sleep "$WAIT_POLL_DOWN_SECS"

say "  renaming probe-1's app on sg-alice-1 → 'renamed-by-1'..."
post_rename "$SG1_ADMIN" "$APP1_ID" "renamed-by-1"

say "  renaming probe-2's app on sg-alice-2 → 'renamed-by-2'..."
post_rename "$SG2_ADMIN" "$APP2_ID" "renamed-by-2"

say "  unpausing relays..."
"${COMPOSE[@]}" unpause "${PROXY_SERVICES[@]}" >/dev/null

say "  waiting up to ${WAIT_CONVERGE_SECS}s for both sides to see both renames..."
wait_for_alias_on_both_probes "sg-alice-1" "$APP1_ID" "renamed-by-1" "$WAIT_CONVERGE_SECS"
wait_for_alias_on_both_probes "sg-alice-2" "$APP2_ID" "renamed-by-2" "$WAIT_CONVERGE_SECS"
ok "scenario A: independent renames from both sides converged after heal"

# ── Scenario B: scalar conflict (same target, lower rank wins) ─────────────

say "scenario B: scalar conflict — both sides rename probe-1's app; rank-1 SG wins."

say "  pausing both UDP relays..."
"${COMPOSE[@]}" pause "${PROXY_SERVICES[@]}" >/dev/null

say "  waiting ${WAIT_POLL_DOWN_SECS}s for both sides' poll_sg to mark each other down..."
sleep "$WAIT_POLL_DOWN_SECS"

say "  renaming probe-1's app on sg-alice-1 → 'rank1-wins'..."
post_rename "$SG1_ADMIN" "$APP1_ID" "rank1-wins"

say "  renaming probe-1's app on sg-alice-2 → 'rank2-loses' (must overwrite sg-2's local view)..."
post_rename "$SG2_ADMIN" "$APP1_ID" "rank2-loses"

# Sanity: each side committed locally before heal. Use a short poll to
# absorb the probe's 5s refresh cycle — the rename POST returns immediately
# but probe-N's /status reflects the value at its last fetch.
wait_for_alias_on_probe "$PROBE1_PORT" "sg-alice-1" "$APP1_ID" "rank1-wins" 15
wait_for_alias_on_probe "$PROBE2_PORT" "sg-alice-1" "$APP1_ID" "rank2-loses" 15
ok "  pre-heal: each side has its own divergent value (partition confirmed)"

say "  unpausing relays..."
"${COMPOSE[@]}" unpause "${PROXY_SERVICES[@]}" >/dev/null

say "  waiting up to ${WAIT_CONVERGE_SECS}s for merge engine to pick rank-1 winner on both sides..."
wait_for_alias_on_both_probes "sg-alice-1" "$APP1_ID" "rank1-wins" "$WAIT_CONVERGE_SECS"
ok "scenario B: lower-rank SG (rank 1) won the scalar conflict on both sides"

# ── Scenario C: tombstone (single-sided delete) ────────────────────────────

say "scenario C: tombstone — probe-1's app deleted on sg-alice-1, must vanish on sg-alice-2."

say "  pausing both UDP relays..."
"${COMPOSE[@]}" pause "${PROXY_SERVICES[@]}" >/dev/null

say "  waiting ${WAIT_POLL_DOWN_SECS}s for sg-alice-1's poll to mark sg-alice-2 down..."
sleep "$WAIT_POLL_DOWN_SECS"

say "  deleting probe-1's app via sg-alice-1's admin UI..."
DELETE_RESP=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "id=${APP1_ID}" \
    "${SG1_ADMIN}/applications/delete")
[[ "$DELETE_RESP" == "303" || "$DELETE_RESP" == "302" ]] \
    || die "delete returned ${DELETE_RESP}, expected 302/303"

say "  unpausing relays to heal partition..."
"${COMPOSE[@]}" unpause "${PROXY_SERVICES[@]}" >/dev/null

say "  waiting up to ${WAIT_CONVERGE_SECS}s for the merge tick to drop probe-1's app from sg-alice-2's view..."
wait_for_sg1_app_count_from_probe2 0 "$WAIT_CONVERGE_SECS"
ok "scenario C: tombstone propagated sg-1 → sg-2 via sync v2 merge after partition heal"

# probe-2's own app must survive the tombstone round-trip — nothing about it
# was touched and it carries 'renamed-by-2' from scenario A.
[[ "$(device_app_count "$PROBE2_PORT" "sg-alice-2")" == "1" ]] \
    || die "after-heal: probe-2's own app disappeared from sg-alice-2's view"
[[ "$(device_app_alias "$PROBE2_PORT" "sg-alice-2" "$APP2_ID")" == "renamed-by-2" ]] \
    || die "after-heal: probe-2's 'renamed-by-2' was lost"
ok "probe-2's app preserved on sg-alice-2 with its scenario-A alias intact"

say "Stage C tests passed: union + scalar conflict + tombstone all converged via sync v2 merge after partition heal."
