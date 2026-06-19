#!/usr/bin/env bash
# Distribute pre-built pNet binaries to every host's $HOME/<REMOTE_DIR>/bin/.
#
# Build hosts (must already have `cargo build --release` output under ~/pnet-src):
#   n64    -> x86_64  binaries (also runs alice@7777 + bob@7778)
#   golden -> aarch64 binaries (runs alice-golden; source for zeus + stealth)
#
# aarch64 binaries are pulled from golden to the dev box, then pushed to zeus
# and stealth (all three are aarch64 Debian 13). x86_64 stays on n64.
#
# Usage:  cd tests/live && source hosts.env && source lib.sh && bash deploy.sh

cd "$(dirname "$0")"
source hosts.env
source lib.sh

require ssh; require scp

BINS=(pnet pnet_test_probe pnet_deliverer)
STAGE="/tmp/pnet-live-aarch64"

place_local_build() {  # <ssh_host> : copy that host's own ~/pnet-src build into bin/
    local host="$1"
    say "placing local build on $host -> \$HOME/$REMOTE_DIR/bin"
    ssh "${SSH_OPTS[@]}" "$host" \
        "set -e; src=\$HOME/pnet-src/target/release; dst=\$HOME/$REMOTE_DIR/bin; \
         mkdir -p \$dst; cp -f \$src/pnet \$src/pnet_test_probe \$src/pnet_deliverer \$dst/; \
         chmod +x \$dst/*; ls -la \$dst" \
        || die "place_local_build failed on $host"
}

push_aarch64() {  # <ssh_host> : push staged aarch64 binaries to bin/
    local host="$1" bin; bin=$(remote_bin "$host")
    say "pushing aarch64 binaries to $host -> $bin"
    ssh "${SSH_OPTS[@]}" "$host" "mkdir -p '$bin'" || die "mkdir bin on $host"
    # Pipe over ssh+cat rather than scp: some hosts (e.g. stealth) have neither
    # sftp-server nor scp. cat is universally present.
    for b in "${BINS[@]}"; do
        ssh "${SSH_OPTS[@]}" "$host" "cat > '$bin/$b'" < "$STAGE/$b" || die "copy $b -> $host failed"
    done
    ssh "${SSH_OPTS[@]}" "$host" "chmod +x '$bin'/*; ls -la '$bin' | grep pnet"
}

say "n64: place x86_64 build"
place_local_build n64

say "golden: place aarch64 build"
place_local_build golden

say "staging aarch64 binaries from golden -> $STAGE"
mkdir -p "$STAGE"
gbin=$(remote_bin golden)
for b in "${BINS[@]}"; do
    scp "${SSH_OPTS[@]}" "golden:$gbin/$b" "$STAGE/$b" || die "pull $b from golden failed"
done

push_aarch64 zeus
push_aarch64 stealth-bomber

say "deploy complete."
