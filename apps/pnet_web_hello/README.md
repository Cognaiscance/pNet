# pnet_web_hello

Sample **hybrid** app for the owner portal (`descriptions/app-web-surfaces.md`).

- Serves a tiny HTML page on **loopback** (`127.0.0.1:9080` by default).
- Registers a portal mount: `/apps/hello/` → that port (via
  `POST /api/app-web/register`, loopback-only on the node).
- Optionally registers with the fabric as app alias `web-hello`.

## Run (same host as pNet)

```bash
# Terminal 1 — pNet SG with portal open on loopback or LAN
PNET_HTTP_BIND=127.0.0.1 cargo run -p pnet
# (or your usual compose / live env)

# Terminal 2
cargo run -p pnet_web_hello
```

Then sign in to the portal (`http://127.0.0.1:8777/`), open **Home**, and click
**Hello** (or go to `/apps/hello/`).

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `PNET_WEB_PORT` | `9080` | Loopback HTTP port for the page |
| `PNET_WEB_SLUG` | `hello` | Portal path `/apps/<slug>/` |
| `PNET_WEB_TITLE` | `Hello` | Display title |
| `PNET_PORTAL` | `http://127.0.0.1:8777` | Portal base URL for register |
| `PNET_ADDR` | `127.0.0.1:7777` | Fabric UDP for app register |
| `PNET_WEB_ALIAS` | `web-hello` | Fabric app alias |
| `PNET_SKIP_FABRIC` | unset | Set `1` to skip fabric register |

Ctrl+C unregisters the portal mount.
