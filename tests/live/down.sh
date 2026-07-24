#!/usr/bin/env bash
# Teardown: stop all live nodes/probes on hosts used by this topology.
# Pass --wipe to also delete per-node data dirs (fresh-slate next bring-up);
# bin/ is kept.
#
# Usage:  cd tests/live && bash down.sh [--wipe]

cd "$(dirname "$0")"
source hosts.env
source lib.sh

# Prefer roster-derived hosts so we do not depend on a hard-coded golden list.
hosts_in_use() {
    local h name
    for name in "${NODES[@]:-}"; do
        h=$(field "$(eval echo "\$NODE_${name}")" 1)
        printf '%s\n' "$h"
    done
    for name in "${PROBES[@]:-}"; do
        h=$(field "$(eval echo "\$PROBE_${name}")" 1)
        printf '%s\n' "$h"
    done
}

mapfile -t HOSTS < <(hosts_in_use | sort -u)
# Fallback if roster empty.
if [[ ${#HOSTS[@]} -eq 0 ]]; then
    HOSTS=(n64 tealface)
fi

if [[ "${1:-}" == "--wipe" ]]; then
    for h in "${HOSTS[@]}"; do say "wiping $h"; wipe_host "$h"; done
else
    for h in "${HOSTS[@]}"; do say "stopping $h"; stop_host "$h"; done
fi
say "teardown complete."
