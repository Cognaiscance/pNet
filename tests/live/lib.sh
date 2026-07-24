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
    env+=" PNET_HTTP_BIND=0.0.0.0 PNET_AUTO_APPROVE_APPS=1 PNET_APP_API_REMOTE=1"
    # Match harness default; mint/rename helpers log in with this password.
    env+=" PNET_ADMIN_PASSWORD='${PNET_TEST_ADMIN_PASSWORD:-stagetest1}'"
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

# Live nodes must set PNET_ADMIN_PASSWORD (default matches stage harnesses).
ADMIN_PASSWORD="${PNET_TEST_ADMIN_PASSWORD:-stagetest1}"

admin_cookie_jar() {  # <admin base url> -> prints cookie jar path
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

mint_device_invitation() {  # <node name> -> prints code
    local admin; admin="$(admin_url "$1")"
    local jar resp loc code
    jar=$(admin_cookie_jar "$admin")
    resp=$(curl -sS -i -b "$jar" -X POST "${admin}/invitations/device") \
        || { rm -f "$jar"; die "POST $admin/invitations/device failed"; }
    rm -f "$jar"
    loc=$(awk 'BEGIN{IGNORECASE=1}/^Location:/{print $2; exit}' <<< "$resp" | tr -d '\r')
    [[ "$loc" == *"error="* || -z "$loc" ]] && die "device invitation error from $admin: ${loc:-<none>}"
    code=$(awk 'BEGIN{IGNORECASE=1}/^X-Pnet-Invitation-Code:/{print $2; exit}' <<< "$resp" | tr -d '\r')
    [[ -z "$code" ]] && die "no X-Pnet-Invitation-Code from $admin"
    printf '%s' "$code"
}

mint_contact_invitation() {  # <node name> -> prints contact_code
    local admin; admin="$(admin_url "$1")"
    local jar resp loc code
    jar=$(admin_cookie_jar "$admin")
    resp=$(curl -sS -i -b "$jar" -X POST "${admin}/invitations/contact") \
        || { rm -f "$jar"; die "POST $admin/invitations/contact failed"; }
    rm -f "$jar"
    loc=$(awk 'BEGIN{IGNORECASE=1}/^Location:/{print $2; exit}' <<< "$resp" | tr -d '\r')
    [[ "$loc" == *"error="* || -z "$loc" ]] && die "contact invitation error from $admin: ${loc:-<none>}"
    code=$(awk 'BEGIN{IGNORECASE=1}/^X-Pnet-Invitation-Code:/{print $2; exit}' <<< "$resp" | tr -d '\r')
    [[ -z "$code" ]] && die "no X-Pnet-Invitation-Code from $admin"
    printf '%s' "$code"
}

redeem_contact() {  # <node name> <contact_code>
    local admin; admin="$(admin_url "$1")"
    local jar
    jar=$(admin_cookie_jar "$admin")
    curl -sS -o /dev/null -b "$jar" --data-urlencode "code=$2" "${admin}/contacts/enter" \
        || { rm -f "$jar"; die "POST $admin/contacts/enter failed"; }
    rm -f "$jar"
}

# rename_app <node name> <app_id_hex> <new_alias>
rename_app() {
    local admin; admin="$(admin_url "$1")"
    local jar
    jar=$(admin_cookie_jar "$admin")
    curl -sS -o /dev/null -b "$jar" --data-urlencode "id=$2" --data-urlencode "alias=$3" \
        "${admin}/applications/rename" || { rm -f "$jar"; die "POST $admin/applications/rename failed"; }
    rm -f "$jar"
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
# yields a spurious rc=255. Match the full bin path prefix so pnet,
# pnet_test_probe, and pnet_deliverer all die; also fuser kill by common ports.
stop_host() {
    local host="$1"
    ssh "${SSH_OPTS[@]}" "$host" "
        pkill -9 -f '[p]net-live/bin/pnet' 2>/dev/null || true
        # DietPi / busy hosts: belt-and-suspenders if pkill pattern misses.
        for p in 7777 7778 8777 8778 3000 3010 3100 8888 8889; do
          fuser -k \${p}/tcp \${p}/udp 2>/dev/null || true
        done
        sleep 0.5
        true
    " || warn "stop_host ssh failed on $host"
}

# wipe_host <ssh_host> : stop + delete all per-node data dirs (keeps bin/)
wipe_host() {
    local host="$1"
    stop_host "$host"
    ssh "${SSH_OPTS[@]}" "$host" "
        set -e
        base=\"\$HOME/$REMOTE_DIR\"
        if [ -d \"\$base\" ]; then
          find \"\$base\" -mindepth 1 -maxdepth 1 ! -name bin -exec rm -rf {} +
        fi
        # Verify no leftover node.toml (stale identity breaks WAN re-join).
        if find \"\$base\" -name node.toml 2>/dev/null | grep -q .; then
          echo \"[wipe] still have node.toml under \$base\" >&2
          find \"\$base\" -name node.toml
          exit 1
        fi
        echo \"[wipe] \$base clean (bin kept)\"
    " || die "wipe_host failed on $host"
}
