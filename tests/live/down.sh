#!/usr/bin/env bash
# Teardown: stop all live nodes/probes on every host. Pass --wipe to also delete
# per-node data dirs (fresh-slate next bring-up); bin/ is kept.
#
# Usage:  cd tests/live && bash down.sh [--wipe]

cd "$(dirname "$0")"
source hosts.env
source lib.sh

HOSTS=(n64 golden zeus stealth-bomber)
if [[ "${1:-}" == "--wipe" ]]; then
    for h in "${HOSTS[@]}"; do say "wiping $h"; wipe_host "$h"; done
else
    for h in "${HOSTS[@]}"; do say "stopping $h"; stop_host "$h"; done
fi
say "teardown complete."
