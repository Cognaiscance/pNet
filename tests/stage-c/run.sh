#!/usr/bin/env bash
# Stage C bring-up harness.
#
# Brings up docker-compose.stage-c.yml from a clean slate:
#   1. tear down any prior stack (down -v wipes named volumes)
#   2. build images
#   3. start sg-alice-1 + probe-1
#   4. wait for sg-alice-1 admin HTTP
#   5. mint a device invitation, start sg-alice-2 + probe-2
#   6. wait for both probes registered+approved
#   7. wait for the device-app graph to converge on both sides (both probes
#      visible on both SGs' .own_devices)
#
# Pure orchestration; assertions in test.sh. Requires: podman compose, curl, jq.

set -euo pipefail

cd "$(dirname "$0")/../.."

COMPOSE_FILE="docker-compose.stage-c.yml"
COMPOSE=(podman compose -f "$COMPOSE_FILE")

SG1_ADMIN="http://localhost:8821"
SG2_ADMIN="http://localhost:8822"

PROBES=(
    "probe-1:3821"
    "probe-2:3822"
)

ADMIN_WAIT_SECS=30
REGISTER_WAIT_SECS=60
CONVERGE_WAIT_SECS=90
POLL_INTERVAL=1

say()  { printf '\n[stage-c] %s\n' "$*"; }
die()  { printf '\n[stage-c][FAIL] %s\n' "$*" >&2; exit 1; }

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

mint_device_invitation() {
    local admin="$1"
    local resp location
    resp=$(curl -sS -i -X POST "${admin}/invitations/device") \
        || die "POST ${admin}/invitations/device failed"
    location=$(printf '%s' "$resp" | awk '/^[Ll]ocation:/{print $2}' | tr -d '\r' | head -n1)
    [[ -z "$location" ]] && die "no Location header from ${admin}/invitations/device"
    if [[ "$location" == *"error="* ]]; then
        die "device invitation generation reported error from ${admin}: $location"
    fi
    local code="${location#*code=}"
    code="${code%%&*}"
    [[ -z "$code" ]] && die "could not parse code from Location: $location"
    printf '%s' "$code"
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

# Signature: sorted list of {device alias → sorted app aliases}.
probe_own_signature() {
    local port="$1" body
    body=$(probe_status "$port") || return 1
    jq -S -c '
        .own_devices
        | map({alias, apps: ([.apps[].alias] | sort)})
        | sort_by(.alias)
    ' <<< "$body"
}

wait_for_convergence() {
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
            say "convergence timeout — last signatures:"
            for i in "${!ports[@]}"; do
                printf '  port %s: %s\n' "${ports[$i]}" "${sigs[$i]:-<no-fetch>}"
            done
            die "device-app graph did not converge within ${timeout}s"
        fi
        sleep "$POLL_INTERVAL"
    done
}

require curl
require jq
require podman

say "tearing down any prior stack..."
# A previous test.sh that died between pause and unpause leaves the proxies
# (or, from the pre-7c.8c topology, sg-alice-2) paused; `compose down`
# refuses to clean a paused container, so undo first.
"${COMPOSE[@]}" unpause proxy-sg-1 proxy-sg-2 sg-alice-2 >/dev/null 2>&1 || true
"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true

say "building images..."
"${COMPOSE[@]}" build

say "starting UDP relays..."
"${COMPOSE[@]}" up -d --no-recreate proxy-sg-1 proxy-sg-2

say "starting sg-alice-1 + probe-1..."
"${COMPOSE[@]}" up -d --no-recreate sg-alice-1 probe-1

say "waiting up to ${ADMIN_WAIT_SECS}s for sg-alice-1 admin HTTP..."
wait_for_url "${SG1_ADMIN}/" "$ADMIN_WAIT_SECS"

say "minting device invitation for sg-alice-2..."
INV_SG2=$(mint_device_invitation "$SG1_ADMIN")
say "  INV_SG2 = ${INV_SG2:0:32}..."

say "starting sg-alice-2 + probe-2..."
INV_SG2="$INV_SG2" "${COMPOSE[@]}" up -d --no-recreate sg-alice-2 probe-2

say "waiting up to ${ADMIN_WAIT_SECS}s for sg-alice-2 admin HTTP..."
wait_for_url "${SG2_ADMIN}/" "$ADMIN_WAIT_SECS"

say "waiting up to ${REGISTER_WAIT_SECS}s for both probes registered+approved..."
wait_for_probes "$REGISTER_WAIT_SECS"

say "waiting up to ${CONVERGE_WAIT_SECS}s for both sides to see both apps..."
wait_for_convergence "$CONVERGE_WAIT_SECS" 3821 3822

say "Stage C topology up — both SGs converged on the device-app graph."
say "  probe-1:       http://localhost:3821/status"
say "  probe-2:       http://localhost:3822/status"
say "  sg-alice-1 admin: http://localhost:8821/"
say "  sg-alice-2 admin: http://localhost:8822/"
