#!/usr/bin/env bash
# Stage A bring-up harness.
#
# Brings the docker-compose.stage-a.yml topology up from a clean slate:
#   1. tear down any prior stack (down -v wipes named volumes)
#   2. build images
#   3. start sg-william-1 + probe-sg-1
#   4. wait for sg-william-1 admin HTTP at :8801
#   5. mint 3 device-invitation codes via POST /invitations/device
#   6. start the joining services (sg-william-2, dg-william-{a,b}) with the
#      codes in env vars, plus the remaining probes
#   7. poll all 4 probes until they all report registered=true && approved=true
#
# Pure orchestration, no test assertions yet — those land in test.sh.
# Requires: podman compose, curl, jq.

set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root

# ── Config ────────────────────────────────────────────────────────────────

COMPOSE_FILE="docker-compose.stage-a.yml"
COMPOSE=(podman compose -f "$COMPOSE_FILE")

SG1_ADMIN="http://localhost:8801"

# probe-name : host-port pairs
PROBES=(
    "probe-sg-1:3001"
    "probe-sg-2:3002"
    "probe-dg-a:3003"
    "probe-dg-b:3004"
)

ADMIN_WAIT_SECS=30      # sg-william-1 admin HTTP up
REGISTER_WAIT_SECS=60   # all 4 probes registered + approved
CONVERGE_WAIT_SECS=90   # all 4 probes agree on the device-app graph
POLL_INTERVAL=1

# ── Helpers ───────────────────────────────────────────────────────────────

say()  { printf '\n[stage-a] %s\n' "$*"; }
die()  { printf '\n[stage-a][FAIL] %s\n' "$*" >&2; exit 1; }

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

mint_invitation() {
    # POST /invitations/device → 302 Location: /invitations?code=<base64>
    # Returns the code on stdout. Dies on error.
    local resp location
    resp=$(curl -sS -i -X POST "${SG1_ADMIN}/invitations/device") \
        || die "POST /invitations/device failed"
    location=$(printf '%s' "$resp" | awk '/^[Ll]ocation:/{print $2}' | tr -d '\r' | head -n1)
    [[ -z "$location" ]] && die "no Location header from /invitations/device (resp: ${resp:0:200})"
    if [[ "$location" == *"error="* ]]; then
        die "invitation generation reported error: $location"
    fi
    local code="${location#*code=}"
    code="${code%%&*}"
    [[ -z "$code" ]] && die "could not parse code from Location: $location"
    printf '%s' "$code"
}

probe_status() {
    # Returns 0 and prints status JSON on success.
    local port="$1"
    curl -sSf "http://localhost:${port}/status" 2>/dev/null
}

probe_ready() {
    # arg: name:port. 0 iff /status reports registered && approved.
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

# Normalized signature of a probe's view: a sorted JSON array of
# {alias, apps:[sorted aliases]} per device. Two probes have converged
# when their signatures are byte-identical.
probe_signature() {
    local port="$1"
    local body
    body=$(probe_status "$port") || return 1
    jq -S -c '
        .own_devices
        | map({alias, apps: ([.apps[].alias] | sort)})
        | sort_by(.alias)
    ' <<< "$body"
}

# For Stage A every pnet has a probe sidecar, so every device must report
# at least one app. Treats a converged-but-empty graph as "still syncing."
wait_for_convergence() {
    local timeout="$1"
    local deadline=$(( $(date +%s) + timeout ))
    while :; do
        local sigs=() fetched=1
        for p in "${PROBES[@]}"; do
            local sig
            sig=$(probe_signature "${p#*:}") || { fetched=0; break; }
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
            say "convergence timeout — last signatures per probe:"
            for i in "${!PROBES[@]}"; do
                printf '  %s: %s\n' "${PROBES[$i]%%:*}" "${sigs[$i]:-<no-fetch>}"
            done
            die "topology did not converge within ${timeout}s"
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

say "starting sg-william-1 and probe-sg-1..."
"${COMPOSE[@]}" up -d sg-william-1 probe-sg-1

say "waiting up to ${ADMIN_WAIT_SECS}s for sg-william-1 admin HTTP at ${SG1_ADMIN}..."
wait_for_url "${SG1_ADMIN}/" "$ADMIN_WAIT_SECS"

say "minting 3 device-invitation codes..."
INV_SG2=$(mint_invitation)
INV_DGA=$(mint_invitation)
INV_DGB=$(mint_invitation)
say "  INV_SG2 = ${INV_SG2:0:32}..."
say "  INV_DGA = ${INV_DGA:0:32}..."
say "  INV_DGB = ${INV_DGB:0:32}..."

say "starting joining services (sg-william-2, dg-william-a, dg-william-b) and remaining probes..."
INV_SG2="$INV_SG2" INV_DGA="$INV_DGA" INV_DGB="$INV_DGB" \
    "${COMPOSE[@]}" up -d \
        sg-william-2 dg-william-a dg-william-b \
        probe-sg-2 probe-dg-a probe-dg-b

say "waiting up to ${REGISTER_WAIT_SECS}s for all 4 probes to report registered + approved..."
wait_for_probes "$REGISTER_WAIT_SECS"

say "waiting up to ${CONVERGE_WAIT_SECS}s for all 4 probes to agree on the device-app graph..."
wait_for_convergence "$CONVERGE_WAIT_SECS"

say "Stage A topology up — 8 services running, device-app graph converged."
say "  probe-sg-1: http://localhost:3001/status"
say "  probe-sg-2: http://localhost:3002/status"
say "  probe-dg-a: http://localhost:3003/status"
say "  probe-dg-b: http://localhost:3004/status"
say "  sg-william-1 admin: http://localhost:8801/"
