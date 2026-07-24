# App web surfaces (hybrid native + web)

**Status:** design intent / **in progress** (branch `app-web-surfaces`).  
Rewrite checklist in `GROK_REWRITE.md` is complete; this document is the
standing product + architecture reference for the owner-facing web portal.

## Product shape (owner web portal)

The primary browser experience is a **pNet-hosted dashboard** on the rank-1 SG
(opt-in public HTTP(S), not the default loopback admin bind alone).

```text
  https://<your-sg>/                  ←  Dashboard (pNet core)
       │
       ├── links to app pages         ←  /apps/<slug>/…  (proxied to local apps)
       ├── link to Config             ←  node / fabric control (see below)
       └── (later) App store          ←  FUTURE — do not implement now
```

### Dashboard (pNet core)

- Home page after owner login (owner web session; see *Auth*).
- **Catalog of available app web surfaces** — each entry is a link to an app
  page the owner has enabled / that has registered a mount on this SG.
- **Link to Config** — open the pNet configuration UI (devices, invites, apps
  approval, diagnostics, etc.), same *kind* of control plane as today’s
  administration UI (`descriptions/administration UI.md`).
- Does **not** embed app-specific UI (no file trees, chat rooms, etc. in core
  HTML). Apps own their pages.

### App pages

- Served under a stable namespace (v1 recommendation: `/apps/<slug>/…`).
- Reverse-proxied (or equivalent) to a **local process on the SG** that holds
  a normal pNet app token and talks fabric via the loopback app API.
- The browser is **never** a fabric peer (no raw UDP fabric from the web).

### Config page (on the web, authenticated)

Config is a **first-class part of the owner web portal**, not a localhost-only
side door. Once the portal is published, the owner can open Config from a phone
or remote browser the same way they open the dashboard—**after authenticating**.

- **Same product surface as the portal:** dashboard links to Config under the
  same origin (e.g. `/config/…`). Responsibilities match today’s administration
  UI: password, devices, invitations, pending apps, diagnostics, etc.
  (`descriptions/administration UI.md`).
- **Must require sign-in** (or stronger). Unauthenticated clients never receive
  config pages or state-changing APIs.
  - **v1 baseline:** owner password → HttpOnly session cookie (`SameSite=Strict`,
    CSRF host checks as today).
  - **Stronger (plan for next, not optional forever):** passkeys / WebAuthn;
    optional TOTP / second factor especially for remote Config; step-up re-auth
    for invite mint, rank change, password change if app browsing uses a lighter
    session.
- **Public by design when the portal is public:** opt-in portal bind exposes
  dashboard, app mounts, **and** Config. Security is **auth + TLS + CSRF**, not
  “config stays on loopback forever.” Listener default remains loopback until
  the operator opts into public bind; production still wants reverse TLS.
- **Least privilege still allowed:** typed sessions or step-up so “signed in for
  filesync” need not equal every dangerous config action—document the v1 choice
  (single full owner session vs split scopes).

Plumbing (implementation detail):

1. **Preferred:** one portal origin — `/`, `/config/…`, `/apps/<slug>/…` with a
   shared login gate; evolve today’s admin UI into `/config`.
2. **Interim:** serve config via the same public host only if auth/TLS match;
   avoid a second open port without the same sign-in story.

### Auth (v1)

- **One owner portal login** gates dashboard, app pages (as needed), and
  **Config on the web**.
- Password session is the minimum; design for **passkeys / 2FA** next so remote
  Config is not “password only forever.”
- Optional later: typed sessions or step-up so day-to-day app use is weaker
  than invite/rank/password changes.
- Public portal bind is opt-in; with it, Config is intentionally reachable
  remotely **only after sign-in** (plus TLS in production).

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

The rank-1 SG becomes not only a relay but an optional **owner web portal**:
dashboard + config + app pages.

## Three app modes

| Mode | Where it runs | How it uses pNet | Best for |
|------|---------------|------------------|----------|
| **Native** | Process on DG and/or SG | Local app API (`register` / `get_data` / `send` / push) | Sync agents, voice, background work, filesystem, always-on hosts |
| **Web** | Pages/API under the portal (`/apps/<slug>`) | Bridge process on the SG holds the app identity | Guest devices, phones without install, “grab a file and go” |
| **Hybrid** | Both, shared identity and data model | Native does heavy lifting; web is viewport + download/upload | File sync, chat history, photo library, notes |

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

- User opens the **dashboard**, then the **filesync** app link (e.g.
  `/apps/filesync`), or a bookmark to that path.
- Authenticates as the **owner** of that SG portal.
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
              ┌─────────────────────────────────────┐
              │  Rank-1 SG                          │
              │  HTTPS (often external) → portal    │
              │                                     │
              │  /              Dashboard (core)    │
              │  /config/…      Config UI (core)    │
              │  /apps/filesync ──► filesync process│
              │  /apps/chat     ──► optional chat   │
              │       │         (HTTP → localhost)  │
              │       ▼                             │
              │  app agent on SG (pNet app token)   │
              │       │ local app API / fabric      │
              └───────┼─────────────────────────────┘
                      │ encrypted pNet
         ┌────────────┼────────────┐
         ▼            ▼            ▼
      DG laptop    DG phone     peer SGs…
   native agent   native or
                  browser only
```

**Critical boundary:** the browser is **not** a fabric peer. It talks HTTP(S)
to the portal; app pages are reverse-proxied to a local app process that uses
the existing loopback app API and fabric. This preserves default app-API
exposure policy (loopback-only unless opted in) and avoids exposing the UDP
fabric to the open web.

## What pNet core owns vs what apps own

### Keep out of core (dumb pipe stays dumb)

- Folder/file semantics, conflict policy, media codecs, room models
- App-specific UI and routes under `/apps/<slug>/…` **content**
- A general multi-tenant CMS for arbitrary websites
- **App store catalog / install-across-devices** (see *Future: App store*)

### Platform hooks (reusable, app-agnostic)

1. **Owner portal HTTP on SG, opt-in** — dashboard + routing; default loopback;
   public bind is explicit and documented separately from admin-only history.
2. **Dashboard** — lists registered app web mounts + link to Config.
3. **Config UI** — node/fabric control plane (same domain as today’s
   administration UI; see `administration UI.md`).
4. **App web mounts** — reverse-proxy under `/apps/<slug>/…` for apps that
   registered a local upstream on this SG.
5. **Bridge convention** — web traffic hits a **local app process on the SG**
   that already holds a pNet app token; browsers never speak raw fabric UDP.
6. **Owner (or scoped) web auth** — portal session with least privilege for
   day-to-day app use; config/admin privileges gated appropriately.
7. **Discovery** — publish a web base URL (or mount slug) in app/device
   metadata so other devices can open the right place without hardcoding.

Optional later: third-party hosted SG packaging so users get
`https://me.pnet.host/` without running hardware at home.

## Future: App store (do not implement now)

**Status: future project — note only; out of scope for the current branch’s
implementation phases.**

Longer-term, the dashboard should grow a surface like an **app store** where
the owner can:

- Discover pNet apps (catalog / listings)
- Install or enable them **across their pNet devices** (push agents or install
  instructions to DGs/SGs they own)
- See which devices run which apps

That work is product + distribution + possibly packaging/signing. It must not
block:

- Dashboard shell
- Config link / UI
- App mounts and reverse proxy
- A few real hybrid apps (e.g. filesync)

When the app store is scheduled, give it its own design doc and branch; do not
fold catalog/install orchestration into early portal PRs.

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

**v1 recommendation:** one portal origin, path-based:

| Path | Owner |
|------|--------|
| `/` | Dashboard (core) |
| `/config/…` or legacy admin entry | Config (core) |
| `/apps/<slug>/…` | App process (proxied) |

Other product skins (per-user domain, raw IP:port) are fine if they map to the
same trees.

### TLS termination

Caddy/nginx (or similar) in front of pNet is fine for v1. Core learning HTTPS
is optional later. Production public portal = **opt-in bind + reverse TLS**,
not “admin password alone on cleartext HTTP.”

### Where web app code lives

Prefer: each app ships a binary (or static UI + API process) that runs on the
SG as a normal pNet app and listens on localhost; pNet mounts that port under
`/apps/<slug>`. Apps own all HTML/API under their slug.

### Security surface

- **Config is on the web when the portal is**—always behind sign-in (and
  stronger factors as they land). Never unauthenticated remote config.
- **Portal app use may still be weaker than full config** via step-up or typed
  sessions (optional product choice); if v1 uses one owner session for both,
  say so and rely on password/passkey quality + TLS.
- Object access: authorize every download; no “secret URL = capability” unless
  that is an explicit, time-limited feature.
- Public bind for the portal is opt-in and **SG-oriented**; do not open DG
  public portals by default.

### Data placement for web

Decide per app the always-on minimum:

- Metadata/index only on SG
- Hot cache of recent/popular objects
- On-demand pull from a live DG (harder, fails when agents are offline)

File sync should document its choice; platform need not prescribe one policy.

### Cross-user and non-user access

**v1 target:** owner accessing **their own** portal on **their** rank-1 SG
(the phone-without-app case).

**Later, separate features:**

- Capability links for friends without pNet
- Contact-gated shared folders
- Time-limited public drop links
- App store / multi-device install (see above)

Do not conflate those with the owner dashboard + config + app links.

## Suggested implementation phases

1. **Portal shell** — **done:** `GET /` home, `GET /config` hub, nav
   Home/Config, login → `/`, legacy `/dashboard` → `/`.
2. **Mounts + reverse proxy** — **started:** in-memory registry;
   `POST /api/app-web/register` / `unregister` (loopback only);
   `GET|POST /apps/<slug>/…` reverse-proxies to `127.0.0.1:<port>`; Home lists
   mounts.
3. **Owner portal auth hardening** — password session already gates the
   portal; next: passkeys/2FA and optional step-up for dangerous config.
4. **Sample / flagship app page** — **started:** `apps/pnet_web_hello` serves
   loopback HTML and auto-registers `/apps/hello/` with the portal.
5. **Discovery** — publish slug / base URL hints in metadata.
6. **Polish** — domains, TLS automation, hosted-SG product, capability links.
7. **(Future project)** App store — discover + install across devices.

None of the near-term phases require pNet core to understand files, rooms, or
messages. Phase 7 is explicitly deferred.

## Relationship to existing design

- **Dumb pipe** (`apps/pnet_chat/description.md` and app API docs): unchanged;
  web is another client of the *app*, not a new fabric opcode family for
  “websites.”
- **SG roles** (`Data transport diagram.md`): add “optional owner web portal”
  (dashboard + config entry + app mounts) alongside keepalive hub, relay,
  writer, invite minting, always-on app hosts.
- **Admin UI** (`administration UI.md`): becomes the **Config** surface linked
  from the dashboard; keep security defaults (loopback default, password,
  CSRF). Product navigation: dashboard first, config second.
- **Chat room host on top SG**: same always-on placement pattern; portal
  generalizes “something useful lives on rank-1” with an HTTP face.

## Ops note (success criterion)

Public portal access needs:

1. Opt-in bind for the portal listener (dashboard + **Config** + app mounts).
2. Reverse TLS in real deployments (especially because Config is remote).
3. Owner **sign-in** before Config (and before sensitive portal use); plan for
   passkeys/2FA rather than password-forever.
4. Optional: step-up for the most dangerous config actions.

Stage/live harnesses may bind `0.0.0.0` for tests; that is not a production
recipe by itself.

## Scheduling

| When | What |
|------|------|
| **Now (`app-web-surfaces` branch)** | Portal shell, mounts, auth, config link, sample app pages |
| **Later (own design + branch)** | App store / catalog / install-across-devices |
| **Later** | Capability links, hosted SG product, automated TLS in core |

This file is the standing reference for owner web portal work.
