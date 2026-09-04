# pNet Installer (phase 2)

Installer **agent** as a pNet app: catalog, **desired** apps/devices, and
**status**. **Notify only** — this process never downloads, verifies, or starts
packages (that is phase 4).

pNet stays a dumb pipe. Desire and status are installer↔installer app payloads.

## What it does

1. Registers as fabric alias `installer` and portal slug `/apps/installer/`.
2. Shows the verified catalog (same apps as portal `/store`, plus itself).
3. On the **rank-1 SG** (lowest `sg_rank` among own-user SGs): you enable an app
   and pick devices. That **desire** syncs to other installer agents.
4. Each agent looks at local `get_data`: if the target alias is registered and
   approved → **installed**; if desired but missing → **pending** with the
   copy-install command. It does **not** run `cargo` or unpack a tarball.

Solo node (no SG in the directory) may write desire locally.

## Run

```bash
PNET_AUTO_APPROVE_APPS=1 cargo run -p pnet
cargo run -p pnet_installer
```

Sign in → Home → **Installer** (or **Store** until the agent is up).

| Variable | Default |
|----------|---------|
| `PNET_INSTALLER_WEB_PORT` | `9091` |
| `PNET_INSTALLER_SLUG` | `installer` |
| `PNET_INSTALLER_STATE` | `~/.pnet/installer` |
| `PNET_PORTAL` | `http://127.0.0.1:8777` |
| `PNET_ADDR` | `127.0.0.1:7777` |
| `PNET_SKIP_FABRIC=1` | UI only, no directory sync |

## Non-goals (this phase)

- Signed package fetch / exec / systemd
- Bootstrap install of pNet
- Contact-shared or public catalogs
- Auto-approve of target apps

See `descriptions/app-store-installer.md`.
