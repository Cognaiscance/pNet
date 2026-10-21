# API

Two interfaces face programs and people on this machine.

- The **owner HTTP site** is how a person sets up the node, signs in, and edits the directory. Most responses are HTML. Two routes are plain text and exist for a local app to register a web mount.
- The **UDP app API** is how a co-located application registers, reads its purses, reserves funds, and sends payloads. It shares the fabric socket (default `127.0.0.1:7777`). Request ops `0x00`–`0x03` and `0x05`–`0x08` are accepted from loopback only, unless `PNET_APP_API_REMOTE` is `1`, `true`, or `yes`.

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
| `GET /config` | session | Counts and links: devices, invitations, applications, purses, contacts, diagnostics. |
| `POST /api/app-web/register` | loopback | Register a portal mount. Plain text. |
| `POST /api/app-web/unregister` | loopback | Remove a portal mount. Plain text. |
| `GET /apps/<slug>/…` | session | Reverse-proxy to the registered loopback port. |
| `GET /pending-apps` | session | Apps on this device with `user_approved` false. |
| `POST /pending-apps/approve` | session | Field `id` (hex). Sign an app certificate and publish it. |
| `POST /pending-apps/reject` | session | Field `id`. Remove the app and publish the removal. |
| `GET /purses` | session | Fixed spending purses: name, allotment, available amount, member aliases. |
| `POST /purses/create` | session | Fields `name`, `amount` (dollars, up to 9 decimal places). Publishes a new purse. |
| `POST /purses/add-alias` | session | Fields `purse` (hex id), `alias`. Adds that app alias to the purse. |
| `POST /purses/remove-alias` | session | Fields `purse` (hex id), `alias`. Removes that alias. |
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

Request ops `0x00`–`0x03` and `0x05`–`0x08` from a non-loopback address are dropped with a log line when remote access is off. Op `0x04` is not a request. The node sends it to the app.

| Byte | Name | Who sends it |
| --- | --- | --- |
| `0x00` | register | app → node |
| `0x01` | update | app → node |
| `0x02` | get data | app → node |
| `0x03` | send packet | app → node |
| `0x04` | push | node → app |
| `0x05` | list purses | app → node |
| `0x06` | list incoming | app → node |
| `0x07` | list sent | app → node |
| `0x08` | reserve | app → node |

Success replies start with `0x00`. Errors are `0x01` followed by one code. Send (`0x03`) sends nothing on success.

| Code | Name | When |
| --- | --- | --- |
| `0x01` | bad packet | Truncated, bad UTF-8, empty string, port 0, or a source that is not IPv4. |
| `0x02` | token unknown | Token is not on this device. |
| `0x03` | no writer | Auto-approve, or an alias change, could not be published. |
| `0x04` | not approved | Token is valid and `user_approved` is false. Used by send, the purse and payment reads, and reserve. |
| `0x05` | no route | No session to the destination and no SG to relay through. |
| `0x06` | payload too large | More than 4096 bytes of app payload. |
| `0x07` | rate limited | Register or send bucket is empty. |
| `0x08` | not in purse | The purse is missing, or this app's alias is not a member. |
| `0x09` | over purse | The amount is greater than the available amount. |
| `0x0A` | payment mismatch | This payment id is already reserved with a different body. |

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

### List purses (`0x05`)

Body: `token (16)`, exactly 16 bytes. A shorter or longer body is `bad packet`.

The token must belong to an approved app on this device. The reply lists only purses whose member aliases include that app's alias. Order is name, then id. A purse that belongs to another alias is absent, including its name and amounts. An app with no purse gets a count of zero, which is success.

```text
0x00
|| count (u16)
||   repeated purse
||     id (16) || name || kind (u8, 0 = fixed) || allotment (i64) || available (i64)
```

Amounts are nanodollars, big-endian. Kind is 0. Monthly purses are not stored. The count is a `u16` so a later payment list can pass 255 lines without a new header. This read does not change the available amount. Available is signed: a debt copied back after the purse was spent again can make it negative.

Errors: `bad packet`, `token unknown`, `not approved`.

### List incoming (`0x06`)

Body: `token (16)`, exactly 16 bytes. Same approval check as list purses.

The reply lists confirmed lines whose payee is this user and whose destination alias is the caller's alias. A hold that is not confirmed is absent. A line for another alias is absent, including its note. Order is payment id, then the payer's confirmation signature. Two different signed bodies of one payment id are both listed. Count 0 is success. The read does not change a purse or the ledger.

```text
0x00
|| count (u16)
||   repeated line
||     payment id (16) || amount (i64) || payer (16) || payee (16)
||     paying alias || destination alias || note
```

Amounts are nanodollars, big-endian. Strings are a length byte and then UTF-8, the same as a purse name. The purse id, the expiry, and the signatures are absent.

Errors: `bad packet`, `token unknown`, `not approved`.

### List sent (`0x07`)

Same request and same approval check. The lines are confirmed payments whose payer is this user and whose paying alias is the caller's alias. Each line uses the same layout as list incoming.

### Reserve (`0x08`)

```text
token (16) || purse id (16) || amount (i64) || contact uuid (16)
|| destination alias || note || payment id (16)
```

The token must belong to an approved app on this device, and that app's alias must be a member of the purse. The amount is nanodollars and must be greater than zero. The destination alias is trimmed. The note is opaque UTF-8, at most 255 bytes, and may be empty. Nothing follows the payment id.

This node applies the reserve only when it is the writer. Any other node replies `no writer` and leaves the purse as it is. When the writer holds the user key and has a session to that contact, it signs an offer and sends it. The offer does not name the purse. The app reply is the same either way. A missing session leaves the hold until a retry, a refusal, or expiry. The reply does not change when the contact later accepts or refuses. The next purse read shows the restored available amount after a refusal or an expiry.

Success:

```text
0x00 || available (i64) || expires at (u64, unix milliseconds)
```

`available` is what that purse still has after the hold. The hold lasts 24 hours from the writer's clock. The same payment id with the same body returns this result again and does not reduce the available amount a second time. After the payer has confirmed the line, the same id returns the current available amount and that line's expiry, and does not reserve again. A different body for an id that is still held, or for an id already confirmed with a different body, is `payment mismatch`. When an unconfirmed hold expires, the writer adds the amount back. The check runs about once a minute, and also at the start of the next reserve. A confirmed payment is not added back.

Errors: `bad packet`, `token unknown`, `not approved`, `no writer`, `not in purse`, `over purse`, `payment mismatch`. An amount equal to the available amount succeeds and leaves zero.
