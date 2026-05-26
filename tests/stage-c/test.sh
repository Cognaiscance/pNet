#!/usr/bin/env bash
# Stage C test suite — sync v2 partition reconciliation end-to-end.
#
# 1. Bring up the Stage C topology via tests/stage-c/run.sh (2 own-user SGs
#    + probe per side, both sides converged on the device-app graph).
# 2. Tombstone scenario:
#      a. `podman pause` sg-alice-2 to simulate a partition. Pause preserves
#         the container's IP and the existing active_connection, so when we
#         unpause, no fresh connect_ack fires — convergence has to come from
#         the 7c.6.5 periodic merge tick.
#      b. Wait for sg-alice-1's poll_sg to mark sg-alice-2 down (~30s), so
#         sg-alice-1 considers itself the writer for the deletion.
#      c. Delete probe-1's app via sg-alice-1's admin UI → tombstone enters
#         sg-alice-1's write_log. (Probe-1 registers once at startup and
#         doesn't retry, so the deletion sticks.)
#      d. Unpause sg-alice-2.
#      e. Within the merge-tick window (~70-90s) sync v2 must converge both
#         sides: probe-1's app gone from both sg-alice-1 and sg-alice-2.
#
# Exits non-zero on any assertion failure. Requires: podman compose, curl, jq.

set -euo pipefail

cd "$(dirname "$0")/../.."

COMPOSE_FILE="docker-compose.stage-c.yml"
COMPOSE=(podman compose -f "$COMPOSE_FILE")

SG1_ADMIN="http://localhost:8821"
PROBE1_PORT=3821
PROBE2_PORT=3822

# poll_sg fires every 30s — give it 45s to definitely flip sg-2's status.
WAIT_POLL_DOWN_SECS=45
# partition_reconcile_tick fires every 60s — give it 90s to definitely run
# at least once after we unpause.
WAIT_CONVERGE_SECS=90
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

# App-count helper, scoped by device alias. Used via probe-2 to inspect
# both SGs' views (probe-1 itself can't be queried reliably post-delete:
# its token gets invalidated by the very deletion we're testing, so its
# fetch_data calls error out and /status freezes on stale data).
device_app_count() {
    local port="$1" device_alias="$2" body
    body=$(probe_status "$port") || return 1
    jq -r --arg alias "$device_alias" '
        .own_devices[]
        | select(.alias == $alias)
        | (.apps // []) | length
    ' <<< "$body" | head -n1
}

probe1_app_id_on_sg1() {
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

wait_for_sg1_app_count() {
    # Wait until probe-2 reports `expected` apps on sg-alice-1's device.
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
            die "convergence timeout"
        fi
        sleep "$POLL_INTERVAL"
    done
}

require curl
require jq
require podman

# ── Bring up ──────────────────────────────────────────────────────────────

say "running tests/stage-c/run.sh..."
bash "$(dirname "$0")/run.sh"

# ── Tombstone scenario ────────────────────────────────────────────────────

say "tombstone scenario: probe-1's app should disappear from sg-alice-2's view after partition + delete + heal."

# Sanity: probe-2 sees one app on each device before we start.
[[ "$(device_app_count "$PROBE2_PORT" "sg-alice-1")" == "1" ]] \
    || die "pre-test: probe-2 view should show 1 app on sg-alice-1"
[[ "$(device_app_count "$PROBE2_PORT" "sg-alice-2")" == "1" ]] \
    || die "pre-test: probe-2 view should show 1 app on sg-alice-2"
ok "pre-test: probe-2 sees 1 app on each SG device"

APP1_ID=$(probe1_app_id_on_sg1)
[[ -n "$APP1_ID" ]] || die "could not read probe-1's app id"
say "probe-1's app id = $APP1_ID"

say "pausing sg-alice-2 to simulate partition..."
podman pause pnet-sg-alice-2-1 >/dev/null

say "waiting up to ${WAIT_POLL_DOWN_SECS}s for sg-alice-1's poll to mark sg-alice-2 as down..."
# poll_sg fires every 30s and is the gate that lets sg-alice-1 elect itself
# writer for the deletion. We can't observe it from outside, so just sleep.
sleep "$WAIT_POLL_DOWN_SECS"

say "deleting probe-1's app via sg-alice-1's admin UI..."
DELETE_RESP=$(curl -sS -o /dev/null -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "id=${APP1_ID}" \
    "${SG1_ADMIN}/applications/delete")
[[ "$DELETE_RESP" == "303" || "$DELETE_RESP" == "302" ]] \
    || die "delete returned ${DELETE_RESP}, expected 302/303"

# sg-2 still paused — probe-2's view hasn't received the tombstone yet.
ok "deletion published on sg-alice-1 (sg-alice-2 still paused — by design)"

say "unpausing sg-alice-2 to heal the partition..."
podman unpause pnet-sg-alice-2-1 >/dev/null

say "waiting up to ${WAIT_CONVERGE_SECS}s for the merge tick to drop probe-1's app from sg-alice-2's view..."
wait_for_sg1_app_count 0 "$WAIT_CONVERGE_SECS"
ok "sg-alice-2 no longer sees probe-1's app (tombstone applied via sync v2 merge)"

# probe-2's own app must have survived the merge round-trip — it's on
# sg-alice-2, and nothing about it was touched.
[[ "$(device_app_count "$PROBE2_PORT" "sg-alice-2")" == "1" ]] \
    || die "after-heal: probe-2's own app disappeared from sg-alice-2's view"
ok "probe-2's own app preserved on sg-alice-2"

say "Stage C tests passed: tombstone propagated sg-alice-1 → sg-alice-2 via sync v2 merge after partition heal."
