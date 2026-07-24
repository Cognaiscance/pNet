#!/usr/bin/env bash
# Distribute pNet release binaries to live hosts' $HOME/<REMOTE_DIR>/bin/.
#
# Builds:
#   n64     x86_64  — built on n64 (native), then placed into pnet-live/bin
#   aarch64 — cross-built on *this machine* (sanosuke), then pushed to
#             tealface and zeus (no cargo required on the Pis)
#
# Cross-build methods (first available):
#   1. Native: rustup target aarch64-unknown-linux-gnu + aarch64-linux-gnu-gcc
#   2. Podman: rust image + gcc-aarch64-linux-gnu (no root on host)
#
# Usage:  cd tests/live && bash deploy.sh
#
# Optional env:
#   SKIP_AARCH64_BUILD=1   reuse existing target/aarch64-.../release bins
#   SKIP_N64_BUILD=1       assume n64 already has ~/pnet-src release build
#   AARCH64_PUSH_HOSTS     space-separated ssh hosts (default: "tealface zeus")

cd "$(dirname "$0")"
source hosts.env
source lib.sh

require ssh

REPO="$(cd ../.. && pwd)"
BINS=(pnet pnet_test_probe pnet_deliverer)
STAGE="/tmp/pnet-live-aarch64"
AARCH64_TRIPLE="aarch64-unknown-linux-gnu"
AARCH64_OUT="$REPO/target/${AARCH64_TRIPLE}/release"
# Runtime hosts that need the aarch64 image (build farm + office DG).
AARCH64_PUSH_HOSTS="${AARCH64_PUSH_HOSTS:-tealface zeus}"

place_local_build() {  # <ssh_host> : copy that host's own ~/pnet-src build into bin/
    local host="$1"
    say "placing local build on $host -> \$HOME/$REMOTE_DIR/bin"
    ssh "${SSH_OPTS[@]}" "$host" \
        "set -e; src=\$HOME/pnet-src/target/release; dst=\$HOME/$REMOTE_DIR/bin; \
         mkdir -p \$dst; \
         for b in pnet pnet_test_probe pnet_deliverer; do \
           test -x \$src/\$b || { echo missing \$src/\$b; exit 1; }; \
           cp -f \$src/\$b \$dst/\$b; \
         done; \
         chmod +x \$dst/*; ls -la \$dst" \
        || die "place_local_build failed on $host"
}

push_staged_aarch64() {  # <ssh_host>
    local host="$1" bin; bin=$(remote_bin "$host")
    say "pushing aarch64 binaries to $host -> $bin"
    ssh "${SSH_OPTS[@]}" "$host" "mkdir -p '$bin'" || die "mkdir bin on $host"
    for b in "${BINS[@]}"; do
        ssh "${SSH_OPTS[@]}" "$host" "cat > '$bin/$b'" < "$STAGE/$b" \
            || die "copy $b -> $host failed"
    done
    ssh "${SSH_OPTS[@]}" "$host" "chmod +x '$bin'/*; ls -la '$bin' | grep pnet"
}

have_native_aarch64_linker() {
    command -v aarch64-linux-gnu-gcc >/dev/null 2>&1
}

build_aarch64_native() {
    say "cross-building aarch64 natively on $(hostname) ($AARCH64_TRIPLE)"
    require rustup; require cargo
    rustup target add "$AARCH64_TRIPLE" >/dev/null
    (
        cd "$REPO"
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
        cargo build --release --target "$AARCH64_TRIPLE" \
            -p pnet --bin pnet
        cargo build --release --target "$AARCH64_TRIPLE" \
            -p pnet_test_probe -p pnet_deliverer
    ) || die "native aarch64 cargo build failed"
}

build_aarch64_podman() {
    require podman
    say "cross-building aarch64 via podman (rust image + gcc-aarch64-linux-gnu)"
    # Official rust image puts cargo/rustup under /usr/local/cargo/bin; bash -lc
    # may drop image ENV PATH, so set it explicitly. :z for Fedora SELinux.
    podman run --rm \
        -v "$REPO:/src:z" \
        -w /src \
        -e PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        -e CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        docker.io/library/rust:1-bookworm \
        bash -lc '
            set -euo pipefail
            export PATH=/usr/local/cargo/bin:$PATH
            export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
            rustup target add aarch64-unknown-linux-gnu
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq gcc-aarch64-linux-gnu >/dev/null
            # Only the live runtime bins (skip pnet_fuzz_wire).
            # --bin filters the whole invocation, so build pnet bin separately
            # from the probe/deliverer packages.
            cargo build --release --target aarch64-unknown-linux-gnu \
                -p pnet --bin pnet
            cargo build --release --target aarch64-unknown-linux-gnu \
                -p pnet_test_probe -p pnet_deliverer
        ' || die "podman aarch64 build failed"
}

stage_aarch64_bins() {
    mkdir -p "$STAGE"
    for b in "${BINS[@]}"; do
        local src="$AARCH64_OUT/$b"
        [[ -x "$src" ]] || die "missing aarch64 binary: $src (build failed?)"
        cp -f "$src" "$STAGE/$b"
        chmod +x "$STAGE/$b"
        # Sanity: ELF aarch64
        file "$STAGE/$b" | grep -qi 'aarch64\|ARM aarch64' \
            || warn "file(1) did not report aarch64 for $b: $(file "$STAGE/$b")"
    done
    say "staged aarch64 bins in $STAGE"
    ls -la "$STAGE"
}

# ── x86_64 → n64 ───────────────────────────────────────────────────────────
if [[ "${SKIP_N64_BUILD:-0}" != "1" ]]; then
    say "n64: cargo build --release on n64:~/pnet-src (always rebuild after rsync)"
    # FORCE_N64_BUILD=0 keeps old bins if present (default: always rebuild).
    if [[ "${FORCE_N64_BUILD:-1}" == "1" ]] || ! ssh "${SSH_OPTS[@]}" n64 \
        'test -x $HOME/pnet-src/target/release/pnet \
          && test -x $HOME/pnet-src/target/release/pnet_test_probe \
          && test -x $HOME/pnet-src/target/release/pnet_deliverer'; then
        # Non-interactive ssh often omits ~/.cargo/bin.
        ssh "${SSH_OPTS[@]}" n64 \
            'export PATH="$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH"
             cd "$HOME/pnet-src" && cargo build --release -p pnet -p pnet_test_probe -p pnet_deliverer' \
            || die "n64 remote build failed (rsync grok-rewrite tree to ~/pnet-src first)"
    fi
    place_local_build n64
else
    say "SKIP_N64_BUILD=1 — placing whatever is already on n64"
    place_local_build n64
fi

# ── aarch64 on sanosuke → tealface + zeus ──────────────────────────────────
if [[ "${SKIP_AARCH64_BUILD:-0}" != "1" ]]; then
    if have_native_aarch64_linker; then
        build_aarch64_native
    elif command -v podman >/dev/null 2>&1; then
        build_aarch64_podman
    else
        die "no aarch64 cross toolchain: install gcc-aarch64-linux-gnu, or podman"
    fi
else
    say "SKIP_AARCH64_BUILD=1 — reusing $AARCH64_OUT"
fi

stage_aarch64_bins

for h in $AARCH64_PUSH_HOSTS; do
    push_staged_aarch64 "$h"
done

say "deploy complete."
printf '  x86_64  -> n64:~/pnet-live/bin\n'
printf '  aarch64 -> %s (built on sanosuke)\n' "$AARCH64_PUSH_HOSTS"
