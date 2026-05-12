#!/usr/bin/env bash
# Stage A test matrix.
#
# 1. Bring up the Stage A topology via tests/stage-a/run.sh.
# 2. For every ordered pair (sender, receiver) of the 4 pnets, send a unique
#    payload from sender's probe to receiver's probe and verify it lands.
# 3. Failover sanity: stop sg-william-1, then verify the pairs not involving
#    sg-william-1 still reach each other (eventually) via sg-william-2.
# 4. Restart sg-william-1 to leave the stack in roughly the original state.
#
# Exits non-zero on any pair failure or the bring-up failing.
# Requires: podman compose, curl, jq.

set -euo pipefail

cd "$(dirname "$0")/../.."

COMPOSE_FILE="docker-compose.stage-a.yml"
COMPOSE=(podman compose -f "$COMPOSE_FILE")

# Probe alias → host-port map.
declare -A PROBE_PORT=(
    [sg-william-1]=3001
    [sg-william-2]=3002
    [dg-william-a]=3003
    [dg-william-b]=3004
)
ALIASES=(sg-william-1 sg-william-2 dg-william-a dg-william-b)

PER_PAIR_TIMEOUT=5         # seconds per pair in the steady-state matrix
FAILOVER_PAIR_TIMEOUT=60   # seconds per pair after sg-1 is down
FAILOVER_SETTLE_SECS=5     # grace period after stopping sg-1 before testing
SEND_RETRY_INTERVAL=5      # how often to re-fire the send while waiting

# ── Helpers ────────────────────────────────────────────────────────────────

say()  { printf '\n[stage-a-test] %s\n' "$*"; }
ok()   { printf '[stage-a-test][ok]   %s\n' "$*"; }
warn() { printf '[stage-a-test][FAIL] %s\n' "$*" >&2; }
die()  { warn "$*"; exit 1; }

# Fire a single /send POST. Returns 0 if the probe accepted the request,
# 1 otherwise (with a warning printed once per pair).
fire_send() {
    local sport="$1" receiver="$2" payload="$3"
    local body
    body=$(curl -sS -X POST "http://localhost:${sport}/send" \
        -H 'content-type: application/json' \
        -d "$(jq -n --arg da "$receiver" --arg aa probe --arg pt "$payload" \
             '{device_alias:$da, app_alias:$aa, payload_text:$pt}')") \
        || return 1
    [[ "$(jq -r '.ok' <<< "$body")" == "true" ]]
}

# Send a packet from $sender → $receiver. Return 0 if a push_received event
# with the unique payload appears on the receiver within $timeout seconds.
# Re-fires the send every SEND_RETRY_INTERVAL seconds while waiting, so the
# test reflects how a real client app would behave (UDP is fire-and-forget,
# and pNet's daemon may take up to POLL_SG_INTERVAL=30s to detect a downed
# SG and stop using it as a relay).
send_and_verify() {
    local sender="$1" receiver="$2" timeout="$3"
    local sport="${PROBE_PORT[$sender]}"
    local rport="${PROBE_PORT[$receiver]}"
    local nonce="$(date +%s%N)"
    local payload="msg ${sender}->${receiver} ${nonce}"

    curl -sSf -X POST "http://localhost:${rport}/reset-events" >/dev/null \
        || { warn "${sender} → ${receiver}: could not reset events on ${receiver}"; return 1; }

    if ! fire_send "$sport" "$receiver" "$payload"; then
        warn "${sender} → ${receiver}: probe rejected initial send"
        return 1
    fi
    local last_send=$(date +%s)
    local deadline=$(( last_send + timeout ))

    while :; do
        local events
        events=$(curl -sSf "http://localhost:${rport}/events" 2>/dev/null) || events="[]"
        if jq -e --arg pt "$payload" '
            map(select(.kind=="push_received" and .payload_text==$pt)) | length > 0
        ' <<< "$events" >/dev/null; then
            return 0
        fi
        local now=$(date +%s)
        if [[ $now -ge $deadline ]]; then
            warn "${sender} → ${receiver}: payload not received within ${timeout}s"
            return 1
        fi
        if (( now - last_send >= SEND_RETRY_INTERVAL )); then
            fire_send "$sport" "$receiver" "$payload" || true
            last_send=$now
        fi
        sleep 1
    done
}

# ── Phase 1: bring up topology ─────────────────────────────────────────────

say "running tests/stage-a/run.sh to bring up topology..."
bash tests/stage-a/run.sh

# ── Phase 2: full 12-pair messaging matrix ─────────────────────────────────

say "running 12-pair messaging matrix (timeout ${PER_PAIR_TIMEOUT}s/pair)..."
PASS=0; FAIL=0; FAIL_PAIRS=()
for s in "${ALIASES[@]}"; do
    for r in "${ALIASES[@]}"; do
        [[ "$s" == "$r" ]] && continue
        if send_and_verify "$s" "$r" "$PER_PAIR_TIMEOUT"; then
            ok "${s} → ${r}"
            PASS=$((PASS+1))
        else
            FAIL=$((FAIL+1))
            FAIL_PAIRS+=("${s}->${r}")
        fi
    done
done
say "matrix: ${PASS} pass, ${FAIL} fail"
[[ $FAIL -gt 0 ]] && die "matrix failures: ${FAIL_PAIRS[*]}"

# ── Phase 3: SG-1 failover ─────────────────────────────────────────────────

say "stopping sg-william-1 to test rank-2 failover..."
"${COMPOSE[@]}" stop sg-william-1 >/dev/null
sleep "$FAILOVER_SETTLE_SECS"

# Pairs that should still work via sg-2: anything not involving sg-william-1.
FAILOVER_PAIRS=(
    "sg-william-2 dg-william-a"
    "sg-william-2 dg-william-b"
    "dg-william-a sg-william-2"
    "dg-william-a dg-william-b"
    "dg-william-b sg-william-2"
    "dg-william-b dg-william-a"
)

say "exercising ${#FAILOVER_PAIRS[@]} pairs via sg-william-2 (timeout ${FAILOVER_PAIR_TIMEOUT}s/pair)..."
FPASS=0; FFAIL=0; FFAIL_PAIRS=()
for pair in "${FAILOVER_PAIRS[@]}"; do
    s="${pair% *}"
    r="${pair#* }"
    if send_and_verify "$s" "$r" "$FAILOVER_PAIR_TIMEOUT"; then
        ok "(failover) ${s} → ${r}"
        FPASS=$((FPASS+1))
    else
        FFAIL=$((FFAIL+1))
        FFAIL_PAIRS+=("${s}->${r}")
    fi
done

say "restarting sg-william-1 to leave the stack restored..."
"${COMPOSE[@]}" start sg-william-1 >/dev/null

say "failover: ${FPASS} pass, ${FFAIL} fail"
[[ $FFAIL -gt 0 ]] && die "failover failures: ${FFAIL_PAIRS[*]}"

say "Stage A tests passed: ${PASS} matrix + ${FPASS} failover"
