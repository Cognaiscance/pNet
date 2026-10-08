# API

Two interfaces face programs and people on this machine.

- The **owner HTTP site** is how a person sets up the node, signs in, and edits the directory. Most responses are HTML. Two routes are plain text and exist for a local app to register a web mount.
- The **UDP app API** is how a co-located application registers and sends payloads. It shares the fabric socket (default `127.0.0.1:7777`). Ops `0x00`–`0x03` are accepted from loopback only, unless `PNET_APP_API_REMOTE` is `1`, `true`, or `yes`.

Peer-to-peer datagrams are in [wire.md](wire.md). How the process is put together is in [README.md](README.md).

Integers are big-endian unless a field says LE. A length-prefixed string is `u8` length plus that many UTF-8 bytes (maximum 255). A UUID is 16 raw bytes. The portal prints UUIDs as 32 lowercase hex characters.

## Owner HTTP

Default bind is `127.0.0.1:8777`. The server reads one HTTP/1.1 request per connection: request line, headers, then a body capped at 64 KiB. It keeps `Content-Length`, `Cookie`, `Host`, `Origin`, and `Referer`. There is no TLS.

POST bodies are `application/x-www-form-urlencoded`. A field is the text between `name=` and the next `&`. `+` is a space. `%HH` is a byte. Missing fields make the handler no-op or redirect with an error, depending on the route.

### Authentication

The admin password is per node. It is not the key passphrase and it is not synced.

Until the node has keys, only `/setup`, `/setup/create`, and `/setup/join` are served. Everything else redirects to `/setup`.

After initialization, if no password hash is stored, only `/set-password` is served.

After a password exists:

- `GET` and `POST /login` are public.
- `POST /api/app-web/register` and `POST /api/app-web/unregister` are public to **loopback** clients and do not use the session cookie. Any other source is redirected to `/login` before the handler runs.
- Every other route requires a session.

The session cookie is `pnet_session=<32 hex chars>; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`. It lives in process memory for 24 hours. Logout clears it. Restart drops every session.

A POST that is not the loopback app-web API is rejected with HTML **403** when `Origin` or `Referer` is present and its host does not match `Host`. A client that sends neither (curl, a script) is allowed and still needs the cookie when the route requires one.

Successful mutations answer **302**. The invitation code is not put in the redirect URL. The browser shows it once from a session flash. The same response also sets `X-Pnet-Invitation-Code` for a harness. Failures redirect to the same page with `?error=<code>`.

| `error` | Meaning |
| --- | --- |
| `bad` | Login password did not match. |
| `password_short` | Password shorter than 8 characters. |
| `password_mismatch` | Password and confirmation differ. |
| `passphrase` | Key passphrase missing or shorter than 8 characters. |
| `fields` | Required alias empty. |
| `publish_failed` | No writer could accept the directory change. The local edit was reverted. |
| `remove_self` | The device serving the page cannot remove itself. |
| `no_host` | No reachable SG could mint an invitation. |

### Routes

| Method and path | Auth | Behavior |
| --- | --- | --- |
| `GET /setup` | uninitialized | Setup wizard. Query `grade=sg\|dg`, `role=new\|join`, `waiting=1`, `error`. |
| `POST /setup/create` | uninitialized | Create a user on this machine. On success, set the session cookie and redirect to `/`. |
| `POST /setup/join` | uninitialized | Store the password, send `BootstrapRequest`, set the cookie, redirect to `/setup?waiting=1`. |
| `GET /login` | public | Login form. |
| `POST /login` | public | Fields: `password`. Success redirects to `/`. Failure redirects to `/login?error=bad`. |
| `GET /set-password` | no hash yet | Form for the first password. |
| `POST /set-password` | no hash yet | Fields: `password`, `password_confirm`. |
| `POST /logout` | session | Revoke the session and clear the cookie. |
| `GET /` | session | Home: owner alias, device alias, grade, links to mounted apps, link to Config. |
| `GET /dashboard` | session | Redirect to `/`. |
| `GET /config` | session | Counts and links: devices, invitations, applications, contacts, diagnostics. |
| `POST /api/app-web/register` | loopback | Register a portal mount. Plain text. |
| `POST /api/app-web/unregister` | loopback | Remove a portal mount. Plain text. |
| `GET /apps/<slug>/…` | session | Reverse-proxy to the registered loopback port. |
| `GET /pending-apps` | session | Apps on this device with `user_approved` false. |
| `POST /pending-apps/approve` | session | Field `id` (hex). Sign an app certificate and publish it. |
| `POST /pending-apps/reject` | session | Field `id`. Remove the app and publish the removal. |
| `GET /applications` | session | Apps on this device. |
| `POST /applications/rename` | session | Fields `id`, `alias`. Publishes the alias. Empty alias is a no-op. |
| `POST /applications/delete` | session | Field `id`. Same removal as reject. |
| `GET /contacts` | session | Contact list and a form to enter a contact code. |
| `POST /contacts/enter` | session | Field `code`. Starts a contact exchange. |
| `GET /devices` | session | Own devices, sessions, hosts. |
| `POST /devices/sync` | session | Pull from the writer, then redirect to `/devices`. |
| `POST /devices/remove` | session | Field `id` (device UUID hex). Publishes `RemoveDevice`. |
| `GET /diagnostics` | session | Writer, public and private versions, partition flag, retention-fallback flag, write-log size, live sessions, and per-host SG poll state. |
| `GET /invitations` | session | Mint forms, and the one-shot code flash. |
| `POST /invitations/device` | session | Mint a device invitation. Optional checkbox `releases_user_key`. |
| `POST /invitations/contact` | session | Mint a contact invitation. Never copies the user private key. |
| `POST /invitations/enter` | session | Field `code`. Sends `BootstrapRequest` from an already configured node. |
| anything else | session | HTML 404. |

`POST /setup/create` fields: `alias` (user), `device_alias`, `grade` (`sg`), `sg_rank`, `password`, `password_confirm`, `key_passphrase`.

`POST /setup/join` fields: `grade` (`sg` or `dg`), `device_alias`, `code`, `password`, `password_confirm`, `key_passphrase`. An SG join also sends `sg_rank` when the form includes it. The headless path reads rank from `PNET_SG_RANK` instead.

The device-invitation checkbox asks the minting SG to put the user private key in the bootstrap payload so the joiner can enroll further devices. The handler forces the flag off when **this** process does not hold that key, and it logs that it did so. Contact invitations never set the flag. Codes expire 24 hours after mint. The code itself is base64url (no padding) of:

```text
invitation id (16) || invitation X25519 public key (32) || host count (u8)
  || repeated (length u8 || host bytes)
```

Hosts are the minting SG's advertised addresses, each already allowed to carry `:port`.

A mint on the top-ranked online SG is local and immediate. A DG, or a lower-ranked SG, sends the mint to that SG and the HTTP worker waits up to 5 seconds off the pool for the code. Timeout or no SG redirects with `error=no_host`.

### App web mounts

`POST /api/app-web/register` from a loopback peer, form fields:

| Field | Required | Rule |
| --- | --- | --- |
| `slug` | yes | 1–32 characters, `[a-z0-9]`, single internal hyphens, no leading or trailing hyphen. |
| `port` | yes | TCP port on `127.0.0.1`, not 0. |
| `title` | no | Display string on the home page. |

Responses are `text/plain`:

| Status | Body |
| --- | --- |
| 200 | `ok slug=<slug> port=<port>\n` |
| 400 | `error: slug_len\n`, `error: slug_hyphen\n`, `error: slug_chars\n`, or `error: port\n` |
| 403 | `forbidden: loopback only\n` |

`POST /api/app-web/unregister` takes `slug`. **200** `ok\n` when removed, **404** `error: not_found\n` when absent, **400** `error: slug\n` when empty, **403** from a non-loopback peer.

The table is memory only. It is empty after restart. The home page lists mounts. `GET` or `POST /apps/<slug>` and `/apps/<slug>/<rest>` require a session and are proxied to `http://127.0.0.1:<port>/<rest>` with the original query string. An unknown slug is HTML 404. A refused connection is HTML 502.

## UDP app API

Send a datagram to the node's UDP port. The first byte is the operation. The rest is the body below. Replies come back to the source address.

Ops `0x00`–`0x03` from a non-loopback address are dropped with a log line when remote access is off. Op `0x04` is not a request. The node sends it to the app.

| Byte | Name | Who sends it |
| --- | --- | --- |
| `0x00` | register | app → node |
| `0x01` | update | app → node |
| `0x02` | get data | app → node |
| `0x03` | send packet | app → node |
| `0x04` | push | node → app |

Success replies start with `0x00`. Errors are `0x01` followed by one code. Send (`0x03`) sends nothing on success.

| Code | Name | When |
| --- | --- | --- |
| `0x01` | bad packet | Truncated, bad UTF-8, empty string, port 0, or a source that is not IPv4. |
| `0x02` | token unknown | Token is not on this device. |
| `0x03` | no writer | Auto-approve, or an alias change, could not be published. |
| `0x04` | not approved | Token is valid and `user_approved` is false. Used by send. |
| `0x05` | no route | No session to the destination and no SG to relay through. |
| `0x06` | payload too large | More than 4096 bytes of app payload. |
| `0x07` | rate limited | Register or send bucket is empty. |

Register is limited per source IP: capacity 10, refill 2 tokens per second. Send is limited per source IP and per token: capacity 200, refill 100 per second. Idle buckets are dropped about once a minute.

### Register (`0x00`)

```text
alias length (u8) || alias || port (u16) || protocol length (u8) || protocol
  || optional app signing public key (32)
```

Alias and protocol must be non-empty UTF-8. Port must be non-zero. The body is either exact (no key) or exactly 32 extra bytes. Anything else is `bad packet`.

The node records the app on the local device:

- `id` and `token` are fresh UUIDs.
- `host` is the source IPv4 address plus the given port. That is where pushes are sent.
- `user_approved` is false, unless `PNET_AUTO_APPROVE_APPS` is set, in which case the node mints an app key if the caller did not supply a public key, signs an app certificate with the device key, and publishes `AddApplication`. If that publish fails, the new app is deleted and the reply is `no writer`.

The same alias and the same host (address and port) reuse the existing id and token. A repeat registration does not create a second app.

Success reply, 17 bytes: `0x00 || token (16)`.

### Update (`0x01`)

```text
token (16) || flags (u8)
  || if flags bit 0: alias length (u8) || alias
  || if flags bit 1: port (u16)
```

Bit 0 changes the alias. Bit 1 changes the port. The IP is always taken from the source address. Other flag bits are ignored. A port update is stored locally and is not published. An alias that actually changes is published as `UpdateApplicationAlias`. If that publish fails, the alias is restored and the reply is `no writer`.

Success reply: a single `0x00`.

### Get data (`0x02`)

Body: `token (16)`.

The reply is the caller's view of the directory. It includes the caller's own token and no other app's token. It includes no private keys. Contact devices list approved apps only, and those entries have id and alias, not host or port.

```text
0x00
|| app id (16) || alias || IPv4 (4) || port (u16) || user_approved (u8)
|| token (16) || local device uuid (16)
|| owner alias || owner user uuid (16)
|| device count (u8)
||   repeated device
||     || app count (u8)
||     ||   repeated: app id (16) || alias || IPv4 (4) || port (u16) || user_approved (u8)
|| contact count (u8)
||   repeated: alias || user uuid (16) || device count (u8)
||     || repeated device
||          || approved-app count (u8)
||          ||   repeated: app id (16) || alias
```

A device, everywhere this API and the fabric share the layout, is:

```text
uuid (16) || alias || grade (u8, 0 = DG, 1 = SG) || sg_rank (u8, 0 = none)
|| host count (u8) || repeated host string
|| device signing public key (32) || device X25519 public key (32)
|| device certificate signature (64) || cert issued-at (u64 LE) || cert alias
```

`sg_rank` on the wire is clamped to 255. Host lists and device lists longer than 255 are truncated to 255 on output.

### Send packet (`0x03`)

```text
token (16) || destination device uuid (16) || destination app id (16) || payload
```

The token must belong to an approved app on this device. The payload maximum is 4096 bytes. On success there is no reply. The node then delivers as described in the README: tunnel, else direct session, else relay. The payload bytes are opaque to the node.

### Push (`0x04`)

The node sends this to `host` of an approved local app:

```text
0x04 || sender app id (16) || payload
```

Unapproved apps are not pushed to. The sender app id is the fabric app id, not a token. The node does not wait for the app to answer.
