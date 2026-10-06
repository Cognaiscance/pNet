#!/bin/bash
# Build the release archives the installer downloads.
#
# One gzip archive per target. The archive contains a single file, pnet.
# A sibling .sha256 is the GNU sha256sum line for that archive. index.json
# lists version, target, URL, and the same sha256. See
# descriptions/release-assets.md.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

out_dir() {
    printf '%s\n' "${DIST:-dist}"
}

die() {
    echo "release-assets: $*" >&2
    exit 1
}

package_version() {
    awk '
        $0 == "[package]" { in_pkg = 1; next }
        in_pkg && /^\[/ { exit }
        in_pkg && /^version[[:space:]]*=/ {
            gsub(/"/, "", $3)
            print $3
            exit
        }
    ' Cargo.toml
}

require_version() {
    local version
    version="$(package_version)"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Cargo.toml version is not major.minor.patch: ${version:-<missing>}"
    printf '%s\n' "$version"
}

require_target() {
    case "$1" in
        x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu) ;;
        *) die "unsupported target: $1" ;;
    esac
}

archive_name() {
    printf 'pnet-%s-%s.tar.gz\n' "$1" "$2"
}

cmd_version() {
    require_version
}

cmd_pack() {
    local target="${1:-}" binary="${2:-}"
    [[ -n "$target" && -n "$binary" ]] || die "pack needs <target> <binary>"
    require_target "$target"
    [[ -f "$binary" ]] || die "not a file: $binary"
    local version name stage out
    version="$(require_version)"
    name="$(archive_name "$version" "$target")"
    out="$(out_dir)"
    mkdir -p "$out"
    stage="$(mktemp -d)"
    cp "$binary" "$stage/pnet"
    chmod 0755 "$stage/pnet"
    tar -C "$stage" -czf "$out/$name" pnet
    rm -rf "$stage"
    (
        cd "$out"
        sha256sum "$name" >"$name.sha256"
    )
    echo "$out/$name"
}

cmd_build() {
    local target="${1:-}"
    [[ -n "$target" ]] || die "build needs <target>"
    require_target "$target"
    local version
    version="$(require_version)"
    if [[ -n "${RELEASE_TAG:-}" && "$RELEASE_TAG" != "v$version" ]]; then
        die "RELEASE_TAG $RELEASE_TAG does not match Cargo.toml $version"
    fi
    if [[ "$target" == aarch64-unknown-linux-gnu ]]; then
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
        command -v "$CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER" >/dev/null \
            || die "missing linker $CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER"
    fi
    rustup target add "$target"
    cargo build --locked --release --target "$target" -p pnet --bin pnet
    cmd_pack "$target" "target/$target/release/pnet"
}

cmd_index() {
    local repo="${GITHUB_REPOSITORY:-}"
    [[ -n "$repo" ]] || die "set GITHUB_REPOSITORY to owner/name"
    local version
    version="$(require_version)"
    local tag="v$version" out
    out="$(out_dir)"
    python3 - "$out" "$version" "$tag" "$repo" <<'PY'
import hashlib, json, pathlib, sys
dist, version, tag, repo = sys.argv[1:]
root = pathlib.Path(dist)
rows = []
for sidecar in sorted(root.glob("pnet-*.tar.gz.sha256")):
    text = sidecar.read_text().strip().split()
    if len(text) != 2:
        raise SystemExit(f"release-assets: bad checksum line in {sidecar}")
    digest, name = text
    archive = root / name
    if not archive.is_file():
        raise SystemExit(f"release-assets: missing archive {archive}")
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != digest:
        raise SystemExit(f"release-assets: {name} sha256 is {actual}, sidecar says {digest}")
    prefix = f"pnet-{version}-"
    suffix = ".tar.gz"
    if not (name.startswith(prefix) and name.endswith(suffix)):
        raise SystemExit(f"release-assets: unexpected archive name {name}")
    target = name[len(prefix):-len(suffix)]
    rows.append({
        "target": target,
        "name": name,
        "url": f"https://github.com/{repo}/releases/download/{tag}/{name}",
        "sha256": digest,
    })
if not rows:
    raise SystemExit(f"release-assets: no archives in {root}")
doc = {"version": version, "tag": tag, "assets": rows}
(root / "index.json").write_text(json.dumps(doc, indent=2) + "\n")
print(root / "index.json")
PY
}

cmd_self_test() {
    local work version name
    work="$(mktemp -d)"
    DIST="$work" cmd_version >/dev/null
    version="$(require_version)"
    printf '#!/bin/sh\necho pnet %s\n' "$version" >"$work/fake-pnet"
    chmod 0755 "$work/fake-pnet"
    DIST="$work" cmd_pack x86_64-unknown-linux-gnu "$work/fake-pnet"
    DIST="$work" cmd_pack aarch64-unknown-linux-gnu "$work/fake-pnet"
    GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-Cognaiscance/pNet}" DIST="$work" cmd_index
    for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
        name="$(archive_name "$version" "$target")"
        (cd "$work" && sha256sum -c "$name.sha256")
        [[ "$(tar -tzf "$work/$name")" == "pnet" ]] || die "archive $name is not a single pnet file"
        local body
        body="$(tar -xOf "$work/$name" pnet)"
        [[ "$body" == *"pnet $version"* ]] || die "archive $name has the wrong binary"
    done
    python3 - "$work/index.json" "$version" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
version = sys.argv[2]
assert doc["version"] == version
assert doc["tag"] == "v" + version
assert len(doc["assets"]) == 2
targets = {row["target"] for row in doc["assets"]}
assert targets == {"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"}
for row in doc["assets"]:
    assert row["sha256"] and len(row["sha256"]) == 64
    assert row["url"].endswith("/" + row["name"])
    assert f"/releases/download/v{version}/" in row["url"]
print("self-test ok")
PY
    # A sidecar that does not match the archive must fail the index.
    name="$(archive_name "$version" "x86_64-unknown-linux-gnu")"
    printf '0000000000000000000000000000000000000000000000000000000000000000  %s\n' "$name" >"$work/$name.sha256"
    if GITHUB_REPOSITORY=Cognaiscance/pNet DIST="$work" cmd_index >"$work/index-out" 2>"$work/index-err"; then
        die "index accepted a bad sha256"
    fi
    grep -q "sha256 is" "$work/index-err" || die "index failed for the wrong reason: $(cat "$work/index-err")"
    rm -rf "$work"
}

usage() {
    cat <<'EOF'
usage: scripts/release-assets.sh <command>

  version                 print the pnet package version
  pack <target> <binary>  archive that file as pnet inside dist/
  build <target>          cargo build --release and pack it
  index                   write dist/index.json (needs GITHUB_REPOSITORY)
  self-test               pack stand-in binaries and check the index
EOF
}

cmd="${1:-}"
shift || true
case "$cmd" in
    version) cmd_version ;;
    pack) cmd_pack "$@" ;;
    build) cmd_build "$@" ;;
    index) cmd_index ;;
    self-test) cmd_self_test ;;
    -h | --help | help | "") usage ;;
    *) die "unknown command: $cmd" ;;
esac
