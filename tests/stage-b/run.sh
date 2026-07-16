#!/usr/bin/env bash
# Stage B bring-up harness.
#
# Brings up docker-compose.stage-b.yml from a clean slate:
#   1. tear down any prior stack (down -v wipes named volumes)
#   2. build images
#   3. start sg-alice + sg-bob + their probes
#   4. wait for both admin HTTPs (8811 alice, 8812 bob)
#   5. mint one device-invitation per user, start the DGs and remaining probes
#   6. wait for all 4 probes to report registered + approved
#   7. wait for the device-app graph to converge on each side (intra-user)
#   8. mint a contact invitation on sg-alice and redeem on sg-bob
#   9. wait for both sides' probes to report the other as a contact
#
# Pure orchestration, no test assertions — those land in test.sh.
# Requires: podman compose, curl, jq.

set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root

# ── Config ────────────────────────────────────────────────────────────────

COMPOSE_FILE="docker-compose.stage-b.yml"
COMPOSE=(podman compose -f "$COMPOSE_FILE")

ALICE_ADMIN="http://localhost:8811"
BOB_ADMIN="http://localhost:8812"

# probe-name : host-port pairs
PROBES=(
    "probe-sg-alice:3811"
    "probe-dg-alice:3812"
    "probe-sg-bob:3813"
    "probe-dg-bob:3814"
)

ADMIN_WAIT_SECS=30      # both SG admin HTTPs up
REGISTER_WAIT_SECS=60   # all 4 probes registered + approved
CONVERGE_WAIT_SECS=90   # intra-user device-app graph converged per side
CONTACT_WAIT_SECS=60    # contact relationship visible on both sides
POLL_INTERVAL=1

# ── Helpers ───────────────────────────────────────────────────────────────

say()  { printf '\n[stage-b] %s\n' "$*"; }
die()  { printf '\n[stage-b][FAIL] %s\n' "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

wait_for_url() {
    local url="$1" timeout="$2"
    local deadline=$(( $(date +%s) + timeout ))
    until curl -sSf "$url" >/dev/null 2>&1; do
        [[ $(date +%s) -ge $deadline ]] && die "timeout waiting for $url"
        sleep "$POLL_INTERVAL"
    done
}

# Shared with stage compose: PNET_ADMIN_PASSWORD on seed SG(s).
ADMIN_PASSWORD="${PNET_TEST_ADMIN_PASSWORD:-stagetest1}"

admin_cookie_jar() {
    local admin="$1"
    local jar
    jar=$(mktemp)
    curl -sS -c "$jar" -b "$jar" -o /dev/null -X POST \
        --data-urlencode "password=${ADMIN_PASSWORD}" \
        "${admin}/login" \
        || { rm -f "$jar"; die "POST ${admin}/login failed"; }
    grep -q 'pnet_session' "$jar" \
        || { rm -f "$jar"; die "no pnet_session cookie from ${admin}/login"; }
    printf '%s' "$jar"
}

mint_device_invitation() {
    # POST /invitations/device (authed) → 302 + X-Pnet-Invitation-Code
    local admin="$1"
    local jar resp location code
    jar=$(admin_cookie_jar "$admin")
    resp=$(curl -sS -i -b "$jar" -X POST "${admin}/invitations/device") \
        || { rm -f "$jar"; die "POST ${admin}/invitations/device failed"; }
    rm -f "$jar"
    location=$(printf '%s' "$resp" | awk 'BEGIN{IGNORECASE=1}/^Location:/{print $2; exit}' | tr -d '\r')
    [[ -z "$location" ]] && die "no Location header from ${admin}/invitations/device"
    if [[ "$location" == *"error="* ]]; then
        die "device invitation generation reported error from ${admin}: $location"
    fi
    code=$(printf '%s' "$resp" | awk 'BEGIN{IGNORECASE=1}/^X-Pnet-Invitation-Code:/{print $2; exit}' | tr -d '\r')
    [[ -z "$code" ]] && die "no X-Pnet-Invitation-Code from ${admin}/invitations/device"
    printf '%s' "$code"
}

mint_contact_invitation() {
    # POST /invitations/contact (authed) → 302 + X-Pnet-Invitation-Code
    local admin="$1"
    local jar resp location code
    jar=$(admin_cookie_jar "$admin")
    resp=$(curl -sS -i -b "$jar" -X POST "${admin}/invitations/contact") \
        || { rm -f "$jar"; die "POST ${admin}/invitations/contact failed"; }
    rm -f "$jar"
    location=$(printf '%s' "$resp" | awk 'BEGIN{IGNORECASE=1}/^Location:/{print $2; exit}' | tr -d '\r')
    [[ -z "$location" ]] && die "no Location header from ${admin}/invitations/contact"
    if [[ "$location" == *"error="* ]]; then
        die "contact invitation generation reported error from ${admin}: $location"
    fi
    code=$(printf '%s' "$resp" | awk 'BEGIN{IGNORECASE=1}/^X-Pnet-Invitation-Code:/{print $2; exit}' | tr -d '\r')
    [[ -z "$code" ]] && die "no X-Pnet-Invitation-Code from ${admin}/invitations/contact"
    printf '%s' "$code"
}

redeem_contact_code() {
    # POST /contacts/enter with form field code=<base64>. Returns nothing useful;
    # we verify the outcome by polling the contacts list afterwards.
    local admin="$1" code="$2"
    local jar
    jar=$(admin_cookie_jar "$admin")
    curl -sS -o /dev/null -b "$jar" -X POST \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "code=${code}" \
        "${admin}/contacts/enter" \
        || { rm -f "$jar"; die "POST ${admin}/contacts/enter failed"; }
    rm -f "$jar"
}

probe_status() {
    local port="$1"
    curl -sSf "http://localhost:${port}/status" 2>/dev/null
}

probe_ready() {
    local port="${1#*:}"
    local body
    body=$(probe_status "$port") || return 1
    [[ "$(jq -r '.registered' <<< "$body")" == "true" ]] || return 1
    [[ "$(jq -r '.approved'   <<< "$body")" == "true" ]] || return 1
}

wait_for_probes() {
    local timeout="$1"
    local deadline=$(( $(date +%s) + timeout ))
    while :; do
        local all=1 not_ready=()
        for p in "${PROBES[@]}"; do
            if probe_ready "$p"; then :; else all=0; not_ready+=("${p%%:*}"); fi
        done
        if [[ $all -eq 1 ]]; then return 0; fi
        if [[ $(date +%s) -ge $deadline ]]; then
            die "timeout waiting for probes to register/approve. Not ready: ${not_ready[*]}"
        fi
        sleep "$POLL_INTERVAL"
    done
}

# Per-user signature: own_devices array of {alias, sorted app aliases}.
# Two probes within the same user are converged when their signatures match
# AND no own device has an empty app list.
probe_own_signature() {
    local port="$1" body
    body=$(probe_status "$port") || return 1
    jq -S -c '
        .own_devices
        | map({alias, apps: ([.apps[].alias] | sort)})
        | sort_by(.alias)
    ' <<< "$body"
}

wait_for_intra_user_convergence() {
    local timeout="$1"; shift
    local ports=("$@")
    local deadline=$(( $(date +%s) + timeout ))
    while :; do
        local sigs=() fetched=1
        for p in "${ports[@]}"; do
            local sig
            sig=$(probe_own_signature "$p") || { fetched=0; break; }
            sigs+=("$sig")
        done
        if [[ $fetched -eq 1 ]]; then
            local first="${sigs[0]}"
            local agreed=1
            for s in "${sigs[@]:1}"; do
                [[ "$s" != "$first" ]] && { agreed=0; break; }
            done
            if [[ $agreed -eq 1 ]]; then
                local empty
                empty=$(jq 'map(select(.apps == [])) | length' <<< "$first")
                [[ "$empty" == "0" ]] && return 0
            fi
        fi
        if [[ $(date +%s) -ge $deadline ]]; then
            say "intra-user convergence timeout — last signatures:"
            for i in "${!ports[@]}"; do
                printf '  port %s: %s\n' "${ports[$i]}" "${sigs[$i]:-<no-fetch>}"
            done
            die "intra-user graph did not converge within ${timeout}s"
        fi
        sleep "$POLL_INTERVAL"
    done
}

# Returns 0 if /status reports a contact with alias $2 whose devices all have
# at least one app. Used to detect that cross-user sync v1 has fully landed.
probe_sees_contact_with_apps() {
    local port="$1" expected_contact_alias="$2"
    local body
    body=$(probe_status "$port") || return 1
    local match
    match=$(jq -c --arg alias "$expected_contact_alias" '
        .contacts
        | map(select(.alias == $alias))
        | first
    ' <<< "$body")
    [[ "$match" == "null" || -z "$match" ]] && return 1
    local dev_count empty_apps
    dev_count=$(jq '.devices | length' <<< "$match")
    [[ "$dev_count" -gt 0 ]] || return 1
    empty_apps=$(jq '.devices | map(select(.apps == [])) | length' <<< "$match")
    [[ "$empty_apps" -eq 0 ]]
}

wait_for_cross_user_visibility() {
    local timeout="$1"
    local deadline=$(( $(date +%s) + timeout ))
    while :; do
        local alice_ok=1 bob_ok=1
        # Alice's probes should see bob as a contact with non-empty app lists.
        for p in 3811 3812; do
            if probe_sees_contact_with_apps "$p" "bob"; then :; else alice_ok=0; fi
        done
        # Bob's probes should see alice as a contact with non-empty app lists.
        for p in 3813 3814; do
            if probe_sees_contact_with_apps "$p" "alice"; then :; else bob_ok=0; fi
        done
        if [[ $alice_ok -eq 1 && $bob_ok -eq 1 ]]; then return 0; fi
        if [[ $(date +%s) -ge $deadline ]]; then
            say "cross-user visibility timeout — current contact views:"
            for p in 3811 3812 3813 3814; do
                local b; b=$(probe_status "$p" || echo "{}")
                printf '  port %s contacts: %s\n' "$p" "$(jq -c '.contacts | map({alias, devs: (.devices | length), app_counts: ([.devices[].apps | length])})' <<< "$b")"
            done
            die "cross-user sync v1 did not converge within ${timeout}s"
        fi
        sleep "$POLL_INTERVAL"
    done
}

# ── Main ──────────────────────────────────────────────────────────────────

require curl
require jq
require podman

say "tearing down any prior stack..."
"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true

say "building images..."
"${COMPOSE[@]}" build

say "starting sg-alice + sg-bob + their probes..."
"${COMPOSE[@]}" up -d sg-alice sg-bob probe-sg-alice probe-sg-bob

say "waiting up to ${ADMIN_WAIT_SECS}s for both SG admin HTTPs..."
wait_for_url "${ALICE_ADMIN}/" "$ADMIN_WAIT_SECS"
wait_for_url "${BOB_ADMIN}/"   "$ADMIN_WAIT_SECS"

say "minting device invitations on each SG..."
INV_DG_ALICE=$(mint_device_invitation "$ALICE_ADMIN")
INV_DG_BOB=$(mint_device_invitation "$BOB_ADMIN")
say "  INV_DG_ALICE = ${INV_DG_ALICE:0:32}..."
say "  INV_DG_BOB   = ${INV_DG_BOB:0:32}..."

say "starting DGs and their probes..."
INV_DG_ALICE="$INV_DG_ALICE" INV_DG_BOB="$INV_DG_BOB" \
    "${COMPOSE[@]}" up -d dg-alice dg-bob probe-dg-alice probe-dg-bob

say "waiting up to ${REGISTER_WAIT_SECS}s for all 4 probes registered+approved..."
wait_for_probes "$REGISTER_WAIT_SECS"

say "waiting up to ${CONVERGE_WAIT_SECS}s for intra-user device-app graph (alice side)..."
wait_for_intra_user_convergence "$CONVERGE_WAIT_SECS" 3811 3812
say "waiting up to ${CONVERGE_WAIT_SECS}s for intra-user device-app graph (bob side)..."
wait_for_intra_user_convergence "$CONVERGE_WAIT_SECS" 3813 3814

say "minting contact invitation on sg-alice and redeeming on sg-bob..."
CONTACT_CODE=$(mint_contact_invitation "$ALICE_ADMIN")
say "  CONTACT_CODE = ${CONTACT_CODE:0:32}..."
redeem_contact_code "$BOB_ADMIN" "$CONTACT_CODE"

say "waiting up to ${CONTACT_WAIT_SECS}s for cross-user visibility on both sides..."
wait_for_cross_user_visibility "$CONTACT_WAIT_SECS"

say "Stage B topology up — 8 services running, contact relationship established."
say "  probe-sg-alice: http://localhost:3811/status"
say "  probe-dg-alice: http://localhost:3812/status"
say "  probe-sg-bob:   http://localhost:3813/status"
say "  probe-dg-bob:   http://localhost:3814/status"
say "  sg-alice admin: http://localhost:8811/"
say "  sg-bob admin:   http://localhost:8812/"
