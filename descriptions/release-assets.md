# Release assets

**Status:** the workflow and the script are in the tree. No tag has been
published. Pushing `vX.Y.Z` is what creates the GitHub Release. The tag must
match `version` in the root `Cargo.toml` (`v0.1.0` for `0.1.0`). `develop`
is not a version.

The installer fetches `index.json` from that release. It does not fetch
`develop`.

## What a release contains

Built by [scripts/release-assets.sh](../scripts/release-assets.sh) and
uploaded by [.github/workflows/release.yml](../.github/workflows/release.yml).

| File | Contents |
|------|----------|
| `pnet-<version>-<target>.tar.gz` | One file, named `pnet`, mode `0755`. |
| `pnet-<version>-<target>.tar.gz.sha256` | `sha256sum` line for that archive. |
| `index.json` | The version, the tag, and one row per archive. |

Targets in the workflow:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

Both are glibc builds. A musl archive and a Windows archive are not built
here.

`index.json`:

```json
{
  "version": "0.1.0",
  "tag": "v0.1.0",
  "assets": [
    {
      "target": "x86_64-unknown-linux-gnu",
      "name": "pnet-0.1.0-x86_64-unknown-linux-gnu.tar.gz",
      "url": "https://github.com/Cognaiscance/pNet/releases/download/v0.1.0/pnet-0.1.0-x86_64-unknown-linux-gnu.tar.gz",
      "sha256": "<sha256 of the tar.gz, lowercase hex>"
    }
  ]
}
```

`sha256` is the hash of the archive bytes, the same value as in the
`.sha256` file. The URL is
`https://github.com/<owner>/<repo>/releases/download/<tag>/<name>`.

The newest release's index is
`https://github.com/Cognaiscance/pNet/releases/latest/download/index.json`.

## Commands

From the repo root:

```bash
scripts/release-assets.sh self-test
scripts/release-assets.sh build x86_64-unknown-linux-gnu
scripts/release-assets.sh build aarch64-unknown-linux-gnu
GITHUB_REPOSITORY=Cognaiscance/pNet scripts/release-assets.sh index
```

`build` uses `cargo build --locked --release --target <triple> -p pnet --bin pnet`.
The aarch64 build needs `aarch64-linux-gnu-gcc` on `PATH` (or
`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER`). Archives land in `dist/`,
which is gitignored.

`RELEASE_TAG`, when set, must be `v` plus the `Cargo.toml` version or `build`
stops. The workflow sets it from the tag that started the run.

## Cutting a release

1. Set the root `Cargo.toml` `version` to the number you are shipping.
2. In `descriptions/wire-versioning.md`, record that tag, the
   `format_version` it writes, and which older tags it still speaks to.
3. Merge that to `develop`.
4. Tag the merge commit `vX.Y.Z` and push the tag. The workflow checks the
   tag against `Cargo.toml`, builds both archives, and creates the GitHub
   Release. It does not run on a branch push.
