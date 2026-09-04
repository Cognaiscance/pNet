# pNet Filesync (hybrid)

Folder replica on each device that runs the agent, plus a web viewport on the
owner portal (`/apps/filesync/`). **pNet stays a dumb pipe** — this app owns
paths, hashes, chunks, retries, and conflict policy.

**v1 target:** owner’s own devices (intra-user). Phone-without-app uses the
portal on the rank-1 SG after sign-in. Not contact sharing, not public links.

## Roles

| Process | Where | What it does |
|---------|--------|----------------|
| **Agent** | Each DG/SG you want in the set | Watches a folder; full replica; talks fabric |
| **Web UI** | Same process, loopback HTTP | Browse / download / upload / delete; portal reverse-proxies it |

Run the agent on the SG as well so the web UI still has files when laptops are
off (index + replica on the SG).

## Local model

- Folder: `PNET_FILESYNC_DIR` (default `~/pnet-filesync`)
- State: `PNET_FILESYNC_STATE` (default `~/.pnet/filesync/`) — replica id + index
- Recursive files only (no empty dirs, no symlinks, no hidden `.*` names)
- Content hash: SHA-256; cap **32 MiB** per file (portal upload **4 MiB**)

**Conflicts:** last-write-wins by `mtime`, then hash. Same mtime: a delete
beats a file. No merge, no `.conflict` copies.

**Deletes:** disappearing files become tombstones and propagate.

## Fabric protocol (app payload)

Opaque datagrams, `MAX_APP_PAYLOAD` 4096. We keep packets ≤ 3500 bytes.
Reliability is **ACK + retry** in the app (pNet does not retransmit).

| Type | Meaning |
|------|---------|
| HELLO | replica id + index generation |
| INDEX | path / size / mtime / hash / deleted (split across packets) |
| WANT | request blob by SHA-256 |
| CHUNK | 2 KiB slice of a blob |
| ACK | confirms a message id |

Peers are **own-user apps** whose alias is `filesync` (from `get_data`).
Contact apps are ignored in v1.

Chunking exists so bulk traffic can promote a **lazy tunnel** after the usual
relay threshold; the app does not speak tunnel opcodes.

## Web

Loopback HTTP (default `:9090`) registered as portal slug `filesync`.
Auth is the **owner portal session** (the app does not implement a second
login). Relative links so `/apps/filesync/` works.

## Run

```bash
# Node (approve the app in Config, or PNET_AUTO_APPROVE_APPS=1 for tests)
PNET_HTTP_BIND=127.0.0.1 cargo run -p pnet

# Agent on the same host
PNET_FILESYNC_DIR=$HOME/pnet-filesync cargo run -p pnet_filesync
```

Sign in → Home → **Filesync**. Put files in the folder or upload in the page;
other approved `filesync` agents on your devices converge.

| Variable | Default |
|----------|---------|
| `PNET_FILESYNC_DIR` | `~/pnet-filesync` |
| `PNET_FILESYNC_STATE` | `~/.pnet/filesync` |
| `PNET_FILESYNC_WEB_PORT` | `9090` |
| `PNET_FILESYNC_SLUG` | `filesync` |
| `PNET_PORTAL` | `http://127.0.0.1:8777` |
| `PNET_ADDR` | `127.0.0.1:7777` |
| `PNET_SKIP_FABRIC=1` | local folder + web only |
| `PNET_FILESYNC_NO_WEB=1` | agent without HTTP |

## Non-goals (v1)

- Contact- or link-shared folders
- Partial/sparse replicas
- Windows/macOS agents (Linux first; paths are `/`-separated)
- Passkeys, app-store install of this binary
