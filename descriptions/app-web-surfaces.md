# App web surfaces (hybrid native + web)

**Status:** design intent / future architecture. **Do not implement until the
current rewrite checklist in `GROK_REWRITE.md` is finished.** This document
captures product and architecture decisions so the work can resume without
re-deriving the motivation.

## Motivation

pNet already requires an always-on **SG** for reachability (DG keepalives,
relay, writer, invite minting, always-on app hosts such as a chat room host).
An alternative product shape is “one home/server box + browser access only.”
pNet is stronger when **devices remain first-class peers** (local apps, multi-
device mesh, hostile-NAT baseline). A hybrid keeps that strength and adds the
convenience of the alternative:

> **pNet apps can run on your devices, on your gateway as a website, or both —
> same network, same identity. Install when you want a real agent; open the
> browser when you just need access.**

The rank-1 SG becomes not only a relay but an optional **public app portal**
for apps that opt in.

## Three app modes

| Mode | Where it runs | How it uses pNet | Best for |
|------|---------------|------------------|----------|
| **Native** | Process on DG and/or SG | Local app API (`register` / `get_data` / `send` / push) | Sync agents, voice, background work, filesystem, always-on hosts |
| **Web** | Pages/API served from the owner's rank-1 SG | Same fabric, via a **bridge process on the SG** that holds the app identity | Guest devices, phones without install, “grab a file and go” |
| **Hybrid** | Both, shared identity and data model | Native does heavy lifting; web is viewport + download/upload path | File sync, chat history, photo library, notes |

Apps choose the mix. Voice might stay native-only; a simple guestbook might be
web-only; file sync is the flagship hybrid.

## Flagship example: file sync

**Native (desktops / always-on agents):**

- A `filesync` agent registers on each machine the user wants to keep in sync.
- Watches a folder; chunks and versions are app-owned (pNet stays a dumb pipe).
- Replicates over pNet to the user's other devices (intra-user via rank-1 hub;
  lazy tunnels for bulk).
- Optionally runs on the SG as well so an always-on replica/index exists.

**Web (phone or any browser without the agent):**

- User opens something like `https://will.example/filesync` (exact URL scheme
  is product detail; see *URL identity* below).
- Authenticates as the **owner** of that SG (not necessarily full admin).
- Browses the tree, downloads; optional upload lands in the same app store and
  propagates to native agents.

**Same user, same app protocol, two front ends.**

For “open the site while my laptop is off” to work, the app should keep at
least an **index** (and ideally a hot file cache) on the SG. Agents on DGs hold
full working sets; the SG holds the always-available subset that backs the web
UI.

## Architecture sketch

```text
                    Internet
                        │
                        ▼
              ┌─────────────────┐
              │  Rank-1 SG      │
              │  HTTPS gateway  │
              │  /filesync  ──► filesync web + API
              │  /chat      ──► optional chat web
              │       │         (HTTP → local app process)
              │       ▼
              │  app agent on SG (pNet app token)
              │       │ local app API / fabric
              └───────┼─────────────────┘
                      │ encrypted pNet
         ┌────────────┼────────────┐
         ▼            ▼            ▼
      DG laptop    DG phone     peer SGs…
   native agent   native or
                  browser only
```

**Critical boundary:** the browser is **not** a fabric peer. It talks HTTP(S)
to an app (or reverse-proxied port) on the SG. That SG-local process is the
pNet app: it uses the existing loopback app API and fabric. This preserves
default app-API exposure policy (loopback-only unless opted in) and avoids
exposing the UDP fabric to the open web.

## What pNet core owns vs what apps own

### Keep out of core (dumb pipe stays dumb)

- Folder/file semantics, conflict policy, media codecs, room models
- App-specific UI and routes (`/filesync` content)
- A general multi-tenant CMS for arbitrary websites

### Platform hooks (reusable, app-agnostic)

1. **Public HTTP on SG, opt-in** — separate from the **admin UI** (admin remains
   owner control plane; default loopback bind; see `administration UI.md`).
2. **App web mounts** — reverse-proxy or static+API under a stable namespace
   (e.g. `/apps/<slug>/…` or `/a/<app_id>/…`) for apps the owner enabled on
   that SG.
3. **Bridge convention** — web traffic hits a **local app process on the SG**
   that already holds a pNet app token; browsers never speak raw fabric UDP.
4. **Owner (or scoped) web auth** — session/passkey for app surfaces, with
   least privilege: “can download my files” must not imply “can mint invites /
   change SG rank / full admin.”
5. **Discovery** — publish a web base URL (or mount slug) in app/device
   metadata so other devices (and later contacts) can open the right place
   without hardcoding.

Optional later (already noted as out of scope for the rewrite): third-party
hosted SG packaging so users get `https://me.pnet.host/filesync` without
running hardware at home.

## Comparison: pure models vs hybrid

| Pure SG + browser only | Pure DG apps only | **Hybrid** |
|------------------------|-------------------|------------|
| Easy access, weak agents | Strong agents, weak guest access | Both |
| Server is the product | Mesh is the product | **Mesh + portal** |
| Session-shaped clients | Device peers | Device peers **and** optional web viewport |

pNet’s enduring strengths vs “just browse my home server”:

- Devices remain peers (local apps, multi-device, multi-app fabric).
- Hostile NAT is baseline (keepalive + rank failover), not a VPN add-on.
- One identity/routing substrate for many apps; web is an access path, not the
  only product surface.
- High-volume paths can stay native/tunnel-oriented; web is not forced to carry
  every workload.

## Design choices (decide at implementation time)

### URL identity

Examples (product choice, not core semantics):

- Path on a shared host: `https://sg.example/u/will/filesync`
- Per-user domain: `https://will.pnet.example/filesync`
- Per-SG raw: `https://203.0.113.5:8443/apps/filesync`

Core only needs: **an SG can serve app mounts the owner enabled.**

### TLS termination

Caddy/nginx (or similar) in front of pNet is fine for v1. Core learning HTTPS
is optional later.

### Where web app code lives

Prefer: each app ships a binary (or static UI + API process) that runs on the
SG as a normal pNet app and listens on localhost; pNet (or an external reverse
proxy) mounts that port under the public path. Apps own all HTML/API.

### Security surface

- **Admin UI ≠ app web.** Different bind policy, auth, CSRF rules.
- Compromise of a web app session must not equal full node admin.
- Object access: authorize every download; no “secret URL = capability” unless
  that is an explicit, time-limited feature.
- Public bind for app surfaces is opt-in and SG-oriented; do not open DG app
  web by default.

### Data placement for web

Decide per app the always-on minimum:

- Metadata/index only on SG
- Hot cache of recent/popular objects
- On-demand pull from a live DG (harder, fails when agents are offline)

File sync should document its choice; platform need not prescribe one policy.

### Cross-user and non-user access

**v1 target:** owner accessing **their own** app surfaces on **their** rank-1
SG (the phone-without-app case).

**Later, separate features:**

- Capability links for friends without pNet
- Contact-gated shared folders
- Time-limited public drop links

Do not conflate those with the owner web portal.

## Suggested implementation phases (when unblocked)

1. **Convention only** — app on SG opens its own HTTP port; reverse proxy by
   hand; prove UX (e.g. filesync browse/download).
2. **Platform** — SG app mounts + owner web login + proxy to registered local
   ports; keep admin UI separate.
3. **Discovery** — publish web base URL / mount in app or device metadata.
4. **Polish** — domains, TLS automation, hosted-SG product, capability links.

None of these phases require pNet core to understand files, rooms, or messages.

## Relationship to existing design

- **Dumb pipe** (`apps/pnet_chat/description.md` and app API docs): unchanged;
  web is another client of the *app*, not a new fabric opcode family for
  “websites.”
- **SG roles** (`Data transport diagram.md`): add “optional public app web
  host” alongside keepalive hub, relay, writer, invite minting, always-on app
  hosts.
- **Admin UI** (`administration UI.md`): remains owner control plane; must stay
  distinct from app web auth and exposure.
- **Chat room host on top SG**: same always-on placement pattern; web surfaces
  generalize “something useful lives on rank-1” with an HTTP face.

## Scheduling

| When | What |
|------|------|
| **Now** | Finish `GROK_REWRITE.md` phases (security defaults, modularity, app edge, live harness, etc.). |
| **After rewrite checklist** | Implement this architecture (app web surfaces / hybrid apps), starting from phase 1 above. |

This file is the standing reference for that follow-on work.
