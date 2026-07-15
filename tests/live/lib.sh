#!/usr/bin/env bash
# Shared helpers for the live multi-machine harness. Source after hosts.env:
#   cd tests/live && source hosts.env && source lib.sh
#
# Nodes/probes are launched on remote hosts over SSH, detached via setsid+nohup,
# data isolated per node under $HOME/<REMOTE_DIR>/<name> (PNET data = .pnet/data
# under that). Binaries live at $HOME/<REMOTE_DIR>/bin/ on each host.
#
# Observation is from the dev box: it routes to every host's admin/probe ports
# (see ADMIN_* / PROBE_URL_* in hosts.env). Pure curl + jq, mirroring stage-c.

set -uo pipefail

POLL_INTERVAL=2
# Connection multiplexing: one persistent master per host, reused by every
# subsequent call. Avoids re-auth on each ssh (faster, and sidesteps agent /
# connection-rate flakiness when firing many calls in a loop).
SSH_OPTS=(-o ConnectTimeout=8 -o BatchMode=yes
          -o ControlMaster=auto -o ControlPersist=600
          -o ControlPath=/tmp/pnet-live-ssh-%r@%h:%p)

say()  { printf '\n[live] %s\n' "$*"; }
warn() { printf '\n[live][warn] %s\n' "$*" >&2; }
die()  { printf '\n[live][FAIL] %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

# field <PIPE_STRING> <1-based index>
field() { awk -F'|' -v i="$2" '{print $i}' <<< "$1"; }

# Resolve the absolute HOME used to isolate a node's data on its host.
remote_home() {  # <ssh_host> <name>
    local host="$1" name="$2" base
    base=$(ssh "${SSH_OPTS[@]}" "$host" 'echo $HOME') || die "cannot resolve HOME on $host"
    printf '%s/%s/%s' "$base" "$REMOTE_DIR" "$name"
}

remote_bin() {   # <ssh_host>
    local host="$1" base
    base=$(ssh "${SSH_OPTS[@]}" "$host" 'echo $HOME') || die "cannot resolve HOME on $host"
    printf '%s/%s/bin' "$base" "$REMOTE_DIR"
}

# ── Launch ───────────────────────────────────────────────────────────────
# start_node <name> [invitation_code]
start_node() {
    local name="$1" code="${2:-}"
    local spec; spec="$(eval echo "\$NODE_${name}")"
    local host grade ualias dalias rank udp http hosts role
    host=$(field "$spec" 1);  grade=$(field "$spec" 2); ualias=$(field "$spec" 3)
    dalias=$(field "$spec" 4); rank=$(field "$spec" 5); udp=$(field "$spec" 6)
    http=$(field "$spec" 7);  hosts=$(field "$spec" 8); role=$(field "$spec" 9)

    local home bin
    home=$(remote_home "$host" "$name"); bin=$(remote_bin "$host")

    local env="HOME='$home' PNET_GRADE='$grade' PNET_DEVICE_ALIAS='$dalias'"
    env+=" PNET_SG_RANK='$rank' PNET_UDP_PORT='$udp' PNET_HTTP_PORT='$http'"
    env+=" PNET_HTTP_BIND=0.0.0.0 PNET_AUTO_APPROVE_APPS=1"
    [[ -n "$hosts" ]] && env+=" PNET_HOSTS='$hosts'"
    if [[ "$role" == "new" ]]; then
        env+=" PNET_USER_ALIAS='$ualias'"
    else
        [[ -z "$code" ]] && die "start_node $name: join role needs an invitation code"
        env+=" PNET_INVITATION_CODE='$code'"
    fi

    say "starting node $name on $host (grade=$grade rank=$rank udp=$udp http=$http)"
    # The ( … & ) subshell exits immediately, orphaning the node so ssh returns
    # rather than waiting on the detached process's channel.
    ssh "${SSH_OPTS[@]}" "$host" \
        "mkdir -p '$home' && cd '$home' && \
         ( $env setsid '$bin/pnet' > '$home/node.log' 2>&1 < /dev/null & ) ; \
         echo launched" \
        || die "failed to launch node $name on $host"
}

# start_probe <pname>
start_probe() {
    local pname="$1"
    local spec; spec="$(eval echo "\$PROBE_${pname}")"
    local host addr alias bind push ctrl
    host=$(field "$spec" 1); addr=$(field "$spec" 2)
    alias=$(field "$spec" 3); bind=$(field "$spec" 4)
    push=$(field "$spec" 5); ctrl=$(field "$spec" 6)
    local home bin
    home=$(remote_home "$host" "$pname"); bin=$(remote_bin "$host")
    say "starting probe $pname on $host (addr=$addr alias=$alias bind=$bind push=$push ctrl=$ctrl)"
    ssh "${SSH_OPTS[@]}" "$host" \
        "mkdir -p '$home' && \
         ( HOME='$home' PNET_ADDR='$addr' PNET_PROBE_ALIAS='$alias' PNET_PROBE_HTTP_BIND='$bind' \
           PNET_PROBE_PUSH_PORT='$push' PNET_PROBE_CTRL_PORT='$ctrl' \
           setsid '$bin/pnet_test_probe' > '$home/probe.log' 2>&1 < /dev/null & ) ; \
         echo launched" \
        || die "failed to launch probe $pname on $host"
}

# ── Invitations / contacts (admin UI over HTTP from the dev box) ───────────
admin_url() { eval echo "\$ADMIN_${1}"; }       # <node name>
probe_url() { eval echo "\$PROBE_URL_${1}"; }    # <probe name>

mint_device_invitation() {  # <node name> -> prints code
    local admin; admin="$(admin_url "$1")"
    local resp loc code
    resp=$(curl -sS -i -X POST "${admin}/invitations/device") || die "POST $admin/invitations/device failed"
    loc=$(awk '/^[Ll]ocation:/{print $2}' <<< "$resp" | tr -d '\r' | head -n1)
    [[ "$loc" == *"error="* || -z "$loc" ]] && die "device invitation error from $admin: ${loc:-<none>}"
    code="${loc#*code=}"; code="${code%%&*}"
    [[ -z "$code" ]] && die "could not parse device code from: $loc"
    printf '%s' "$code"
}

mint_contact_invitation() {  # <node name> -> prints contact_code
    local admin; admin="$(admin_url "$1")"
    local resp loc code
    resp=$(curl -sS -i -X POST "${admin}/invitations/contact") || die "POST $admin/invitations/contact failed"
    loc=$(awk '/^[Ll]ocation:/{print $2}' <<< "$resp" | tr -d '\r' | head -n1)
    [[ "$loc" == *"error="* || -z "$loc" ]] && die "contact invitation error from $admin: ${loc:-<none>}"
    code="${loc#*contact_code=}"; code="${code%%&*}"
    [[ -z "$code" ]] && die "could not parse contact code from: $loc"
    printf '%s' "$code"
}

redeem_contact() {  # <node name> <contact_code>
    local admin; admin="$(admin_url "$1")"
    curl -sS -o /dev/null --data-urlencode "code=$2" "${admin}/contacts/enter" \
        || die "POST $admin/contacts/enter failed"
}

# rename_app <node name> <app_id_hex> <new_alias>
rename_app() {
    local admin; admin="$(admin_url "$1")"
    curl -sS -o /dev/null --data-urlencode "id=$2" --data-urlencode "alias=$3" \
        "${admin}/applications/rename" || die "POST $admin/applications/rename failed"
}

# ── Waits / oracles (probe /status JSON) ───────────────────────────────────
wait_for_url() {  # <url> <timeout>
    local url="$1" deadline=$(( $(date +%s) + $2 ))
    until curl -sSf "$url" >/dev/null 2>&1; do
        [[ $(date +%s) -ge $deadline ]] && return 1
        sleep "$POLL_INTERVAL"
    done
}

probe_status() { curl -sSf "$(probe_url "$1")/status" 2>/dev/null; }

probe_ready() {  # <probe name>
    local b; b=$(probe_status "$1") || return 1
    [[ "$(jq -r '.registered' <<< "$b")" == "true" ]] || return 1
    [[ "$(jq -r '.approved'   <<< "$b")" == "true" ]] || return 1
}

wait_for_probes() {  # <timeout> <probe names...>
    local timeout="$1"; shift
    local deadline=$(( $(date +%s) + timeout ))
    while :; do
        local all=1 pending=()
        for p in "$@"; do probe_ready "$p" || { all=0; pending+=("$p"); }; done
        [[ $all -eq 1 ]] && return 0
        [[ $(date +%s) -ge $deadline ]] && { warn "probes not ready: ${pending[*]}"; return 1; }
        sleep "$POLL_INTERVAL"
    done
}

# Signature of a probe's own-user device-app graph (device alias -> sorted apps).
probe_own_signature() {  # <probe name>
    local b; b=$(probe_status "$1") || return 1
    jq -S -c '.own_devices | map({alias, apps:([.apps[].alias]|sort)}) | sort_by(.alias)' <<< "$b"
}

# wait_for_convergence <timeout> <probe names...> : all agree + no empty app lists
wait_for_convergence() {
    local timeout="$1"; shift
    local deadline=$(( $(date +%s) + timeout ))
    while :; do
        local sigs=() ok=1 first=""
        for p in "$@"; do
            local s; s=$(probe_own_signature "$p") || { ok=0; break; }
            sigs+=("$s")
        done
        if [[ $ok -eq 1 ]]; then
            first="${sigs[0]}"; local agreed=1
            for s in "${sigs[@]:1}"; do [[ "$s" != "$first" ]] && agreed=0; done
            if [[ $agreed -eq 1 && "$(jq 'map(select(.apps==[]))|length' <<< "$first")" == "0" ]]; then
                return 0
            fi
        fi
        if [[ $(date +%s) -ge $deadline ]]; then
            warn "convergence timeout; signatures:"
            local i=0; for p in "$@"; do printf '  %s: %s\n' "$p" "${sigs[$i]:-<none>}"; i=$((i+1)); done
            return 1
        fi
        sleep "$POLL_INTERVAL"
    done
}

# ── Teardown ───────────────────────────────────────────────────────────────
# stop_host <ssh_host> : kill any live node/probe/deliverer processes from this
# harness. The `[p]` bracket prevents pkill from matching its own shell (whose
# argv contains the pattern) — that self-match SIGKILLs the ssh command and
# yields a spurious rc=255. The single prefix matches pnet, pnet_test_probe,
# and pnet_deliverer.
stop_host() {
    ssh "${SSH_OPTS[@]}" "$1" "pkill -9 -f '[p]net-live/bin/pnet' 2>/dev/null; true"
}

# wipe_host <ssh_host> : stop + delete all per-node data dirs (keeps bin/)
wipe_host() {
    stop_host "$1"
    ssh "${SSH_OPTS[@]}" "$1" "find \$HOME/$REMOTE_DIR -mindepth 1 -maxdepth 1 ! -name bin -exec rm -rf {} + 2>/dev/null; true"
}
