# App store and installer agent

**Status:** design intent. **Phase 1** portal `/store` copy-install. **Phase 2:**
`pnet_installer` agent — desire + status, notify only. **Phase 3 landed:**
`pnet_installer bootstrap` installs pNet + agent from a **local** binary
directory (no network fetch). Phase 4 (signed catalog packages) remains later.

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
4. Installer agents on those machines install the signed package and start it.
5. Each target app registers with its local node; routing/approval work as today.
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
| **Packages** | Bytes + version + signature + OS/arch | HTTPS (or later airgap import) from trusted registry |
| **Runtime** | Process up, register, portal mount | Local agent + existing app API |
| **Directory** | Who is running what for routing | Existing pNet register + directory sync |

**Critical rule:** desired state is **data**. Packages are **not** synced as
untrusted fabric payloads as the primary install path.

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
- Never require core to understand Docker/apt/systemd details

### What it does *not* do

- Replace Config / admin for invites and ranks
- Become a general remote shell
- Auto-approve fabric apps unless product policy says so (still use approval
  or `PNET_AUTO_APPROVE_APPS` only in test)

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

### Source of truth (v1 recommendation)

- **Rank-1 SG installer** (or single elected “policy writer”) is authoritative
  for the desire list.
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

### Catalog

- List of verified apps: id, name, description, versions, supported OS/arch,
  default placement hints, package URLs, **signatures**.
- Hosted by the project (or user-configured registry URL in agent config).
- Agent ships **pinned public keys** for catalog/package verification.

### Install pipeline (per device)

1. See desire: enabled for **this** device.  
2. Skip if already at requested version and healthy.  
3. Fetch package for **local OS/arch**.  
4. Verify signature (fail closed).  
5. Install via **one** v1 mechanism (choose at implementation time), e.g.:
   - signed tarball + systemd **user** unit, or  
   - Docker image + compose fragment  
6. Start process; wait for fabric **register** (or document if agent registers
   a stub).  
7. Publish `InstallStatus`.

### Uninstall / disable

1. Desire `enabled: false` or removed for this device.  
2. Stop process; unregister fabric app / portal mount if applicable.  
3. Optionally remove package files; **prompt or policy** for user data dirs.  
4. Status → `Removed`.

---

## Security considerations

| Risk | Mitigation |
|------|------------|
| Malicious “install this” desire | Signed packages only; agent ignores unsigned |
| Compromised SG pushes malware | Same: signature + pin keys; optional user confirm on first install |
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
| **1** | Catalog UI + “copy install command” / docs only (`GET /store`) | No |
| **2** | Installer agent app + desire schema + status; **notify only** (`pnet_installer`, `/apps/installer/`) | No auto |
| **3** (current) | Bootstrap installer installs pNet + agent (`pnet_installer bootstrap`, local binaries only) | Yes (bootstrap) |
| **4** | Agent auto-installs **signed** packages for matching placement | Yes |
| **5** | Updates, uninstall polish, multi-arch, optional multi-publisher | Yes |

Phase 1 can live mostly in portal/docs without a fleet agent.  
Phase 4 is the first “true” multi-device app store install.

---

## Open decisions (resolve at implementation)

1. **Package format v1:** tarball+systemd vs Docker-first.  
2. **Desire writer:** rank-1 SG only vs any device with conflict rules.  
3. **First-install UX:** fully automatic after enable vs confirm per device.  
4. **Catalog hosting:** static signed JSON on project CDN vs self-hosted only.  
5. **Relation to fabric app approval:** auto-approve store-installed apps on
   the installing user’s devices?  
6. **Agent web slug:** e.g. `installer` or `store`.

---

## Relationship to existing design

| Doc / system | Relationship |
|--------------|--------------|
| **Dumb pipe / app API** | Unchanged; target apps still register/send/push |
| **App web surfaces** | Store UI is an app mount; portal Home lists it |
| **Config / admin UI** | Fabric control plane; not the package manager |
| **Directory / sync** | Running apps only; desire stays in installer app |
| **Lazy tunnels** | Optional for large package mirrors later; not required for HTTPS registry |

---

## Summary

- Users get **verified apps** from a store UI; apps **register with pNet** after
  they run.  
- An **installer agent** (itself a pNet app) owns catalog, placement, signed
  install, and status.  
- A **bootstrap installer** installs pNet then the agent; the agent is also
  part of normal pNet install.  
- **Desire** syncs installer→installer; **packages** come from a trusted
  registry; **directory** still reflects only running apps.  

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
