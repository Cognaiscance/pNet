# App store and installer agent

**Status:** design intent. **Phase 2:**
`pnet_installer` agent — desire + status, notify only. **Phase 3 landed:**
`pnet_installer bootstrap` installs pNet + agent from a **local** binary
directory (no network fetch). **Phase 3b landed (current code):** catalog is a
directory of GitHub URL lists (`app_sources/`); the store shows summaries
fetched from those repos (cached) on `/apps/installer/` only. Core has no
`/store` route. **Phase 4 decisions locked** (signed GitHub Release tarball +
`systemd --user`; Save desire installs official apps; installer attests fabric
approve) — not implemented yet. Extra org lists stay notify-only until phase 5.

**Related:** `descriptions/app-web-surfaces.md` (owner portal, app web mounts).
Apps and the installer live in sibling repos under `pNet_project/` (not in the
pNet crate).  
**Out of scope for early portal PRs:** do not fold catalog install into core
fabric opcodes or into the first `/apps/` reverse-proxy work beyond optional
manual mounts.

---

## Problem

Users should discover **verified** apps and run them across their devices.
pNet already knows how to:

- Run a **node** (SG/DG)
- Let **processes register** as apps (loopback app API)
- **Route and sync** app-related directory state

pNet does **not** today:

- Fetch packages, verify signatures, install binaries, or manage OS services

So “install from an app store on every DG” needs an explicit lifecycle outside
the dumb pipe, while still using pNet for identity, connectivity, and
preference sync.

---

## Goals

1. **App store UX** in the owner portal: browse verified apps, choose which
   devices should run them, see install status.
2. **Installer agent** as a **pNet app** (not core): package trust, download,
   install/start/stop, report status.
3. **Bootstrap path:** one download that installs pNet (if needed), then the
   installer agent, then registers the agent with pNet.
4. **Agent shipped with normal pNet install** so every device has a reconciler
   by default.
5. **Desired install state** syncs **installer↔installer** (app data path), not
   as “executable blobs” in core directory sync.
6. **Target apps self-register** with local pNet after install (existing edge).

## Non-goals (v1 / near term)

- Core node downloading or exec’ing packages on sync
- Multi-publisher fully decentralized store (start with a small trusted catalog)
- Silent install of unsigned software
- Forcing every app onto every device
- Full Windows/macOS matrix on day one (call out per-OS support in catalog)
- App store as a multi-tenant commercial marketplace

---

## Product shape

### Three pieces

| Piece | Role |
|--------|------|
| **Bootstrap installer** | First-run / recovery: install pNet + agent; help create/join user |
| **Installer agent (app)** | Long-running; store UI (on SG), desire sync, local reconcile |
| **Target apps** | Normal pNet apps (filesync, chat host, …); register themselves |

Same codebase can serve bootstrap and agent modes.

### Portal integration

```text
Portal Home  (core)
  ├── Config           → fabric / node control plane
  └── Installer        → /apps/installer/  (agent web UI = app store)
         ├── Catalog (verified apps)
         ├── Enable app → select devices / labels
         └── Status per device (Installed / Pending / Failed / …)
```

- **Config** stays fabric admin (invites, devices, approvals, diagnostics).
- **App store** is the installer app’s page, not a core HTML module that
  understands packages.

### Happy path (user mental model)

1. Install pNet (+ agent) via bootstrap package or existing install path.
2. Open portal → **Installer**.
3. Pick a verified app → choose machines (e.g. rank-1 SG + this laptop).
4. Installer agents on those machines fetch the signed GitHub Release, verify
   it, unpack, and start a `systemd --user` unit (Save desire is consent).
5. Each target app registers with its local node; the installer attests fabric
   approval for what it just started (manual `cargo run` still uses Config).
6. Optional: app mounts a web UI on the SG (`/apps/<slug>/`).

---

## Architecture

```text
                    Internet (signed catalog / packages)
                              │
                              ▼
┌──────────────────────────────────────────────────────────┐
│  Rank-1 SG                                               │
│  pNet core ── portal ── /apps/installer/ ──► installer   │
│       │                         │              agent     │
│       │                         │                 │      │
│       │ fabric register         │ desire sync     │ HTTPS│
│       │ (target apps)           │ (app payloads)  │      │
└───────┼─────────────────────────┼─────────────────┼──────┘
        │                         │                 │
        │                         ▼                 │
        │              installer agent (DG) ────────┘
        │                     │
        │                     ▼ install / start
        │              target app process
        └──────────────────── register ──► local pNet
```

### Layer split

| Layer | Content | Transport |
|--------|---------|-----------|
| **Desire / policy** | Which apps, versions, which devices, enabled | Installer↔installer over pNet (private app messages / app-level sync) |
| **Packages** | Bytes + version + signature + OS/arch | HTTPS GitHub Releases on the catalog repo (airgap import later) |
| **Runtime** | Process up, register, portal mount | Local agent + existing app API |
| **Directory** | Who is running what for routing | Existing pNet register + directory sync |

**Critical rule:** desired state is **data**. Packages are **not** synced as
untrusted fabric payloads as the primary install path.

---

## Catalog sources (`app_sources/`)

The store listing is **not** a hardcoded table in pNet. After the installer is
on a machine, it owns:

```text
~/.pnet/installer/app_sources/     # 0700
  pnet.list                        # managed official GitHub URLs
  acme.list                        # org/user extra lists; never overwritten
```

Same idea as apt `sources.list.d`: each **regular file** is a list of GitHub
repo URLs. The store is the **union** of every file (`pnet.list` first, then
other files in filename order). Duplicate URLs keep the first occurrence
(so extra files only add).

### Managed default

`pnet.list` is written by the installer (bootstrap and agent start). It is
**managed**: if missing, or if its `# managed-revision: N` does not match this
installer, it is rewritten to the current official set. Do not edit it — add
another file instead. Extra files are never created or overwritten by us.

Official v1 set (Cognaiscance):

- `https://github.com/Cognaiscance/pnet_filesync`
- `https://github.com/Cognaiscance/pnet_web_hello`
- `https://github.com/Cognaiscance/pnet_chat`
- `https://github.com/Cognaiscance/pnet_installer`

### File format

```text
# comments and blank lines ignored
https://github.com/acme/pnet-timesheets
https://github.com/acme/pnet-badge
```

- One `https://github.com/owner/repo` URL per line (optional `.git` / trailing slash)
- Bad lines are skipped and logged; they do not blank the store
- Dotfiles, `*.bak` / `*.tmp` / `*.swp` / `*~` are ignored
- Files `0600`, directory `0700` (writing a file here is “add a software source”)

An organization adds apps by dropping `acme.list` into `app_sources/` (image,
bootstrap, or copy). No installer rebuild.

### Store cards (listing only — no auto-install)

The **installer agent** (rank-1 SG UI at `/apps/installer/`) reads the source
files and builds cards:

1. Prefer `pnet-app.json` at `HEAD` in the repo (id, name, summary, placement,
   fabric alias, web slug).
2. Else GitHub repo API `description` / name.
3. Else last on-disk cache (`~/.pnet/installer/catalog-cache/`).
4. Else a baked fallback for official URLs, or a minimal card from the repo name.

Cache so GitHub being down does not empty the page. Refresh on agent start and
about every six hours. pNet core does **not** fetch GitHub and has no `/store`
route. The catalog lives only on the installer mount (`/apps/installer/`).
Until that agent is running, Home lists no installer page.

`app_sources` is **local config**, not fabric-synced. Desire still syncs
“enable this catalog id on these devices” and now also carries `github_url` /
`fabric_alias` so a DG can report pending without a copy of `acme.list`. To
**see** extra apps on a laptop’s own store UI, copy the extra file there too.

Auto-install from those GitHub URLs is **not** phase 3b. Phase 4 installs
**signed GitHub Release tarballs** for official `pnet.list` apps only (see
below). Extra `app_sources/` files stay notify-only until phase 5.

### `pnet-app.json` (in each app repo)

```json
{
  "id": "filesync",
  "name": "Filesync",
  "summary": "Folder replica plus portal web viewport.",
  "placement": "Desktops you want in the set; also the rank-1 SG for always-on web.",
  "os": "Linux (v1)",
  "fabric_alias": "filesync",
  "web_slug": "filesync",
  "notes": "Store install (phase 4): installer attests fabric approve. Manual cargo run: Config → Pending Apps."
}
```

---

## Installer as a pNet app

### Why

- Evolves without core releases
- Uses existing connectivity, identity, and (later) tunnels for agent traffic
- Web UI mounts via existing portal reverse-proxy (`app-web-surfaces.md`)
- Clear security boundary: agent holds package keys and install privileges;
  core does not

### Responsibilities

- Serve store UI (especially on rank-1 SG)
- Maintain **desired state** document(s)
- Sync desire to peer installer agents for the same user
- On each device: reconcile local reality to desire (install/update/remove)
- Verify package signatures before install
- Report **status** back into shared installer state
- Never require core to understand packages or systemd

### What it does *not* do

- Replace Config / admin for invites and ranks
- Become a general remote shell
- Auto-approve **arbitrary** local apps. Phase 4: it attests fabric approval
  only for aliases **it just installed** (loopback, installer app token).
  Manual `cargo run` still uses Config → Pending Apps.
  `PNET_AUTO_APPROVE_APPS` remains test-only.

---

## Bootstrap installer

### Goals

1. Install **pNet** if missing or outdated (user-consented).
2. Install/start **installer agent**.
3. Help **create user or join** (invite), or hand off to portal Config.
4. Register agent with local pNet; on SG, register portal mount for store UI.

### Relationship to normal install

- Full pNet packages **include** the agent (enabled by default).
- Bootstrap binary is the “empty machine” entry; upgrades can reuse the same
  agent with a different subcommand (`bootstrap` vs `run`).

### Security note

The bootstrap binary is a **high-trust** artifact (same class as installing an
OS agent). Distribute over HTTPS, ideally signed; document checksums.

---

## Desired state (sync between installer agents)

### Conceptual schema (illustrative)

```text
DesiredApp {
  catalog_id: string,          // e.g. "filesync"
  version: string,             // pin preferred; "latest" optional/discouraged
  enabled: bool,
  placement: Placement,        // see below
  updated_at: timestamp,
  updated_by_device: uuid,
}

Placement =
  | DeviceUuids([uuid, ...])
  | Labels([string, ...])      // e.g. "desktop", "sg-rank1"
  | AllOwnedDevices            // use sparingly; avoid as default
```

```text
InstallStatus {               // per device, reported by local agent
  catalog_id, version,
  device_uuid,
  state: Pending | Downloading | Installed | Failed | Unsupported | Removed,
  detail: string,             // error message, no secrets
  reported_at: timestamp,
}
```

### Source of truth

- **Rank-1 SG installer** (lowest `sg_rank` among own-user SGs) is
  authoritative for the desire list. Solo node (no SG) may write locally.
- Other agents **pull / accept** desire and **push** local status.
- Avoid dual-writer CRDTs until there is a real need for offline multi-edit.

### Transport

- Prefer **installer app protocol** over pNet `send` / app-level sync blobs
  (versioned, encrypted by fabric as any app payload).
- Do **not** overload core `Application` directory rows to mean “please install
  binary X.” Directory remains “running app endpoints.”

---

## Placement policy

Installing “on all DGs” is usually wrong.

Examples:

| App | Typical placement |
|-----|-------------------|
| Chat room host | Rank-1 SG only |
| File sync agent | Desktop DGs + optional SG index |
| Web guestbook | Rank-1 SG only |
| Installer agent | Every device that runs pNet |

Store UI must make placement explicit. Labels (desktop / always-on / phone)
beat raw UUID lists for UX, with UUID override for power users.

---

## Package trust and install mechanics

### Catalog listing vs packages

- **Listing (3b):** GitHub URL lists in `app_sources/`; cards from
  `pnet-app.json` / API / cache. Not a hardcoded table in core.
- **Packages (phase 4):** GitHub **Releases** on that same repo. Assets are a
  signed tarball for the local OS/arch plus a detached signature. Docker is
  not the v1 install path.
- Agent ships **pinned public keys**. Unsigned, wrong key, or extra-list
  apps: **no exec** (extra lists stay notify-only until phase 5).

### Install pipeline (per device, phase 4)

1. See desire: enabled for **this** device (Save desire on the rank-1 SG is
   consent; no per-device confirm). New devices are not included until their
   UUID is added to the desire list.
2. Skip if already at requested version and healthy.
3. Fetch the GitHub Release tarball + signature for **local OS/arch**.
   Official `pnet.list` only.
4. Verify signature against the pinned project key (fail closed).
5. Unpack under `~/.pnet/apps/<id>/` (versioned). Write a systemd **user**
   unit and start it. Headless SGs need linger so the unit survives logout.
6. Wait for fabric **register**. Installer attests approve for that local
   alias (loopback, installer app token). Core does not learn about packages.
7. Publish `InstallStatus`: Pending → Downloading → Installed / Failed.

### Uninstall / disable

1. Desire `enabled: false` or removed for this device.  
2. Stop the user unit; unregister fabric app / portal mount if applicable.  
3. Optionally remove package files; **prompt or policy** for user data dirs.  
4. Status → `Removed`.

---

## Security considerations

| Risk | Mitigation |
|------|------------|
| Malicious “install this” desire | Signed packages only; agent ignores unsigned and extra-list apps |
| Compromised SG pushes malware | Same: signature + pin keys. Save desire is fleet consent; extra lists cannot exec |
| Over-broad placement | Explicit device/label selection; safe defaults |
| Agent as root | Prefer non-root; clear escalation if required |
| Secrets in desire sync | Never put tokens/passwords in desire; local config only |
| Confused deputy (core as installer) | Core never runs packages |
| Supply chain | Version pins; checksum + sig; document update channel |

**Installer agent is powerful.** Treat it like a package manager: same care as
shipping `apt` or Docker to the home server.

---

## Phased delivery (when scheduled)

| Phase | Deliverable | Installs code? |
|-------|-------------|----------------|
| **0** | Manual app run + portal mount register (`pnet_web_hello`) | No |
| **1** | Catalog UI + “copy install command” (was portal `/store`; removed — catalog is installer-only) | No |
| **2** | Installer agent app + desire schema + status; **notify only** (`pnet_installer`, `/apps/installer/`) | No auto |
| **3** | Bootstrap installer installs pNet + agent (`pnet_installer bootstrap`, local binaries only) | Yes (bootstrap) |
| **3b** (current) | `app_sources/` GitHub URL lists + store cards from `pnet-app.json` / API / cache | No auto |
| **4** | Agent auto-installs **signed GitHub Release tarballs** via `systemd --user` for matching placement (official `pnet.list` only) | Yes |
| **5** | Updates, uninstall polish, multi-arch, optional multi-publisher | Yes |

Phase 1’s portal `/store` fallback was removed; catalog requires the installer agent.  
Phase 4 is the first “true” multi-device app store install. Decisions below are
locked; code is still phase 3b.

---

## Phase 4 decisions (locked 2026-09-16)

Not implemented yet. Current agent is still notify-only (phase 3b).

| Topic | Decision |
|--------|----------|
| **Package format** | Signed tarball + `systemd --user` unit. Not Docker. Headless SGs need linger so the unit survives logout. Unpack under `~/.pnet/apps/<id>/`. |
| **Registry** | GitHub Releases on the same repo URL as `app_sources/`. Assets: tarball + signature. Verify against the pinned project public key (fail closed). |
| **Who auto-installs** | Official `pnet.list` apps only, when the signature matches. Extra org lists (`acme.list`) stay **notify-only** until phase 5 (multi-publisher keys). |
| **Consent** | Save desire on the rank-1 SG (enable + device list) is enough. Matching agents fetch, verify, unpack, and start. No per-device confirm. New devices are not included until their UUID is added. |
| **Fabric approval** | After the started process registers, the installer auto-approves that local alias (loopback-only attest with the installer app token). Core stays dumb: no package knowledge. `cargo run` and anything not started by the installer still need Config → Pending Apps. `PNET_AUTO_APPROVE_APPS` remains test-only. |
| **Desire writer** | Rank-1 SG (lowest `sg_rank` among own-user SGs). Solo node may write. Already in 3b. |
| **Web slug** | `installer` (`/apps/installer/`). Already in 3b. |

---

## Relationship to existing design

| Doc / system | Relationship |
|--------------|--------------|
| **Dumb pipe / app API** | Unchanged; target apps still register/send/push |
| **App web surfaces** | Store UI is an app mount; portal Home lists it |
| **Config / admin UI** | Fabric control plane (invites, ranks, manual app approve); not the package manager |
| **Directory / sync** | Running apps only; desire stays in installer app |
| **Lazy tunnels** | Optional for large package mirrors later; not required for GitHub Releases |

---

## Summary

- Users get **verified apps** from a store UI; apps **register with pNet** after
  they run.  
- An **installer agent** (itself a pNet app) owns catalog, placement, signed
  install, and status.  
- A **bootstrap installer** installs pNet then the agent; the agent is also
  part of normal pNet install.  
- **Desire** syncs installer→installer; **packages** come from GitHub
  Releases on the catalog repo (signed tarball + `systemd --user`);
  **directory** still reflects only running apps.  

This keeps pNet a dumb pipe while making multi-device app install a deliberate,
securable product surface.

---

## Document history

| Date | Note |
|------|------|
| 2026-07-24 | Initial design from product discussion (portal + agent + bootstrap + desire sync). |
| 2026-09-04 | Phase 1: portal `/store` catalog + copy-install; still no agent. |
| 2026-09-04 | Phase 2: `pnet_installer` desire/status, notify only; rank-1 SG writes desire. |
| 2026-09-04 | Phase 3: `bootstrap` copies local `pnet` + agent into `~/.pnet`, writes `start.sh`. |
| 2026-09-04 | Split apps/installer into sibling repos under `pNet_project/` for independent versioning. |
| 2026-09-14 | Phase 3b: `app_sources/` GitHub URL lists; store cards from repo manifest/API/cache. |
| 2026-09-14 | Removed portal `/store`. Catalog is only `/apps/installer/` (installer agent). |
| 2026-09-16 | Phase 4 decisions locked: signed tarball + systemd user unit; GitHub Releases; Save desire installs official apps; installer attests fabric approve; extra lists notify-only until phase 5. |
