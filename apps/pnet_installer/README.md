# pnet_installer

Installer agent (desire + status) and **bootstrap** (install pNet + agent from
local binaries). See [description.md](description.md).

```bash
# Empty machine (binaries in the same folder as this program):
./pnet_installer bootstrap

# Agent only, pNet already running:
PNET_AUTO_APPROVE_APPS=1 cargo run -p pnet
cargo run -p pnet_installer
```

Portal: sign in → Home → **Installer** (`/apps/installer/`).
