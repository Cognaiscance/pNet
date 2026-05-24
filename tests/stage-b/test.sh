#!/usr/bin/env bash
# Stage B test suite.
#
# 1. Bring up the Stage B topology via tests/stage-b/run.sh (sets up two users
#    with a pre-established contact relationship).
# 2. Static assertion: each side's probes see the other user's devices and
#    probe apps under .contacts[].
# 3. Dynamic assertion: delete sg-bob's probe app via sg-bob's admin UI;
#    verify alice's probes lose it from their view of contacts[bob] within
#    PROPAGATE_WAIT_SECS, exercising sync v1 cross-user fan-out end-to-end.
#
# Exits non-zero on any assertion failure or the bring-up failing.
# Requires: podman compose, curl, jq.

set -euo pipefail

cd "$(dirname "$0")/../.."

COMPOSE_FILE="docker-compose.stage-b.yml"
COMPOSE=(podman compose -f "$COMPOSE_FILE")

ALICE_ADMIN="http://localhost:8811"
BOB_ADMIN="http://localhost:8812"

PROBE_SG_ALICE=3811
PROBE_DG_ALICE=3812
PROBE_SG_BOB=3813
PROBE_DG_BOB=3814

PROPAGATE_WAIT_SECS=30   # cross-user mutation should land well under this

# ── Helpers ────────────────────────────────────────────────────────────────

say()  { printf '\n[stage-b-test] %s\n' "$*"; }
ok()   { printf '[stage-b-test][ok]   %s\n' "$*"; }
warn() { printf '[stage-b-test][FAIL] %s\n' "$*" >&2; }
die()  { warn "$*"; exit 1; }

probe_status() {
    local port="$1"
    curl -sSf "http://localhost:${port}/status" 2>/dev/null
}

contact_devices() {
    # Print JSON of the named contact's devices array on the given probe.
    local port="$1" contact_alias="$2"
    local body; body=$(probe_status "$port") || { echo "[]"; return; }
    jq -c --arg a "$contact_alias" '
        .contacts | map(select(.alias == $a)) | first | .devices // []
    ' <<< "$body"
}

contact_has_device_with_app() {
    # 0 if /status on $port reports contact $alias having device $dev with app $app.
    local port="$1" alias="$2" dev="$3" app="$4"
    local devs; devs=$(contact_devices "$port" "$alias")
    [[ "$devs" == "null" || "$devs" == "[]" ]] && return 1
    local match
    match=$(jq --arg d "$dev" --arg a "$app" '
        map(select(.alias == $d)) | first
        | (.apps // []) | map(select(.alias == $a)) | length > 0
    ' <<< "$devs")
    [[ "$match" == "true" ]]
}

probe_app_id_for() {
    # Print the app_id of the (contact, device, app_alias) triple seen at $port.
    local port="$1" contact_alias="$2" dev_alias="$3" app_alias="$4"
    local body; body=$(probe_status "$port") || return 1
    jq -r --arg c "$contact_alias" --arg d "$dev_alias" --arg a "$app_alias" '
        .contacts | map(select(.alias == $c)) | first
        | .devices | map(select(.alias == $d)) | first
        | .apps | map(select(.alias == $a)) | first
        | .id // empty
    ' <<< "$body"
}

own_app_id_for() {
    # Print the app_id of (device_alias, app_alias) under own_devices at $port.
    local port="$1" dev_alias="$2" app_alias="$3"
    local body; body=$(probe_status "$port") || return 1
    jq -r --arg d "$dev_alias" --arg a "$app_alias" '
        .own_devices | map(select(.alias == $d)) | first
        | .apps | map(select(.alias == $a)) | first
        | .id // empty
    ' <<< "$body"
}

wait_until_not() {
    # Repeatedly run $1 (a function name + args) until it returns non-zero,
    # or die after $2 seconds.
    local timeout="$1"; shift
    local deadline=$(( $(date +%s) + timeout ))
    until ! "$@" >/dev/null 2>&1; do
        if [[ $(date +%s) -ge $deadline ]]; then
            die "condition still true after ${timeout}s: $*"
        fi
        sleep 1
    done
}

# ── Bring-up ───────────────────────────────────────────────────────────────

say "running tests/stage-b/run.sh..."
bash "$(dirname "$0")/run.sh"

# ── Static assertions ─────────────────────────────────────────────────────

say "asserting cross-user visibility on alice's side..."
for port in "$PROBE_SG_ALICE" "$PROBE_DG_ALICE"; do
    contact_has_device_with_app "$port" "bob" "sg-bob"  "probe" \
        || die "port $port: alice should see bob/sg-bob/probe under contacts"
    contact_has_device_with_app "$port" "bob" "dg-bob"  "probe" \
        || die "port $port: alice should see bob/dg-bob/probe under contacts"
    ok "alice probe @$port sees bob/{sg,dg}-bob/probe"
done

say "asserting cross-user visibility on bob's side..."
for port in "$PROBE_SG_BOB" "$PROBE_DG_BOB"; do
    contact_has_device_with_app "$port" "alice" "sg-alice" "probe" \
        || die "port $port: bob should see alice/sg-alice/probe under contacts"
    contact_has_device_with_app "$port" "alice" "dg-alice" "probe" \
        || die "port $port: bob should see alice/dg-alice/probe under contacts"
    ok "bob probe @$port sees alice/{sg,dg}-alice/probe"
done

# ── Dynamic assertion: delete sg-bob's probe app, watch it disappear on alice ─

say "looking up sg-bob's probe app_id..."
SG_BOB_PROBE_APP_ID=$(own_app_id_for "$PROBE_SG_BOB" "sg-bob" "probe")
[[ -z "$SG_BOB_PROBE_APP_ID" ]] && die "could not resolve sg-bob/probe app_id"
ok "sg-bob/probe app_id = $SG_BOB_PROBE_APP_ID"

say "deleting sg-bob's probe app via admin UI..."
curl -sSf -o /dev/null -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "id=${SG_BOB_PROBE_APP_ID}" \
    "${BOB_ADMIN}/applications/delete" \
    || die "POST ${BOB_ADMIN}/applications/delete failed"

say "waiting up to ${PROPAGATE_WAIT_SECS}s for the removal to reach alice's probes..."
for port in "$PROBE_SG_ALICE" "$PROBE_DG_ALICE"; do
    wait_until_not "$PROPAGATE_WAIT_SECS" \
        contact_has_device_with_app "$port" "bob" "sg-bob" "probe"
    ok "alice probe @$port no longer sees bob/sg-bob/probe"
done

# ── Done ──────────────────────────────────────────────────────────────────

say "Stage B tests passed: cross-user visibility + dynamic mutation propagation."
