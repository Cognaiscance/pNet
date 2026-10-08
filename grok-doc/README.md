# pNet

These pages describe the `pnet` 0.1.0 process in this checkout. Each statement comes from the Rust under `src/`. The notes in `descriptions/` are a separate set of documents and are not the source of these pages.

`pnet` is one long-running process. It keeps a local directory of a user, that user's devices, and the user's contacts, and it moves opaque application payloads between those devices. A co-located app talks to the process over UDP. The person who runs the node uses a small HTTP site. Peer nodes talk to each other over the same UDP socket the apps use, distinguished by the first byte of each datagram.

## What a node is

A node is one machine's copy of one user. On first run it has no keys. Setup either creates a new user on this machine or joins an existing user with an invitation code.

Two grades exist:

- **SG** (server grade). The device has a list of advertised hostnames or IP addresses (`hosts`). It accepts connections from other nodes, relays application payloads, and can be the writer for the user's directory.
- **DG** (device grade). The device has no advertised hosts. It opens sessions toward SG peers and keeps those NAT mappings warm. It does not accept a connection that an SG initiates toward it.

`sg_rank` is a `u32` on SG devices. A lower number is preferred. Rank 1 is the first choice for writer and for relay. DG devices store `None`.

UUIDs (16 raw bytes) are local indexes: user, device, application, invitation, and connection correlation. They travel in directory records and in cleartext on `ConnectRequest`. They are not inside certificate payloads. The cryptographic identity is an Ed25519 public key.

## Process layout

`src/main.rs` starts the process and stops it on SIGINT or SIGTERM.

| Piece | Role |
| --- | --- |
| UDP listener | Binds `0.0.0.0` on `PNET_UDP_PORT` (default **7777**). One datagram becomes one queued action. |
| HTTP server | Binds an IPv4 address (default `127.0.0.1`) on `PNET_HTTP_PORT` (default **8777**). Parses one HTTP/1.1 request and queues it. |
| Scheduler | Wakes about once a second and enqueues periodic work. |
| Four workers | Share one priority queue (capacity 1024). UDP is high priority, HTTP is normal, scheduled work is low. Under pressure the queue drops the lower priority first. |
| Writer thread | Writes `node.toml` and `write_log.toml` by temp file, fsync, and rename. Files end up mode `0600` on Unix. |

`pnet --version` and `pnet -V` print `pnet 0.1.0` and exit before creating `~/.pnet`.

Data lives in `$HOME/.pnet/data`. The directory is created mode `0700`, and `~/.pnet` is tightened to `0700` when that is the parent. `node.toml` holds the directory. `write_log.toml` holds the writer's append-only change log. Sessions, tunnels, SG poll results, and the admin cookie map are memory only and disappear on restart.

A file that exists and cannot be parsed, or whose `format_version` is outside 1, makes the process exit without rewriting the files. This build writes `format_version = 1`. A missing `node.toml` starts a fresh node.

## Startup

1. Install a key passphrase from `PNET_KEY_PASSPHRASE` (at least 8 characters) or, if that is unset, from the controlling terminal. A short value is ignored.
2. Load `node.toml` and `write_log.toml`, then open sealed private keys.
3. If the node is already initialized and a sealed key does not open, or a private key is in memory and no passphrase is installed, the process exits.
4. If `PNET_HOSTS` is set and this device is SG, replace this device's `hosts` with that comma-separated list and save.
5. Start the writer, scheduler, UDP listener, and workers.
6. If the node is not initialized and `PNET_GRADE` is set, run headless setup (below).
7. If `PNET_ADMIN_PASSWORD` is set, the node has no admin hash yet, and the password is at least 8 characters, store the hash.
8. If this process holds the user private key and the local device has no verifying certificate, mint a device key, sign a device certificate, and publish `AddDevice`.
9. Enqueue an SG poll, then connection maintenance.
10. Start HTTP.

Headless setup runs only when the node is not yet initialized:

| Variable | Effect |
| --- | --- |
| `PNET_GRADE` | `sg` or `dg`. Unset skips headless setup. |
| `PNET_DEVICE_ALIAS` | Required. |
| `PNET_USER_ALIAS` | Required for a new SG user (no invitation code). |
| `PNET_SG_RANK` | SG only. Defaults to 1. Values below 1 become 1. |
| `PNET_INVITATION_CODE` | Required for DG and for an SG that is joining. Absent means "create a new user", which only SG may do. |
| `PNET_HOSTS` | Advertised addresses for an SG. `host` or `host:port`. The port defaults to 7777 at resolve time. |

A join sends `BootstrapRequest` and returns. The asynchronous `BootstrapResponse` finishes initialization.

## Other environment variables

| Variable | Default | Effect |
| --- | --- | --- |
| `PNET_UDP_PORT` | `7777` | UDP bind port. |
| `PNET_HTTP_PORT` | `8777` | Portal port. |
| `PNET_HTTP_BIND` | `127.0.0.1` | IPv4 bind address. `localhost` is loopback. An unparseable value falls back to loopback. |
| `PNET_HTTP_BIND_ALL` | unset | `1` or `true` binds `0.0.0.0` when `PNET_HTTP_BIND` is unset. |
| `PNET_APP_API_REMOTE` | unset | `1`, `true`, or `yes` lets non-loopback hosts use app ops `0x00`–`0x03`. |
| `PNET_AUTO_APPROVE_APPS` | unset | `1` or `true` marks a new registration approved, signs an app certificate, and publishes it. |
| `PNET_ADMIN_PASSWORD` | unset | First admin password, if none is stored yet. |
| `PNET_KEY_PASSPHRASE` | unset | Passphrase that seals private keys. Minimum 8 characters. |

## Scheduled work

| Action | Interval | What it does |
| --- | --- | --- |
| Poll SG | 30 s | UDP ping/pong to every advertised host of every known SG (own and contacts). Records RTT and up/down. Unresolvable hosts are down. |
| Maintain connections | 5 min | Opens missing sessions. Also runs once at startup and 5.5 s after a connect attempt that got no ack. |
| DG keepalive | 20 s | Each DG sends an empty encrypted datagram on every live SG session. |
| Sync pull | 30 min | Pull public and private versions from the current writer. |
| Partition reconcile | 60 s | Each SG sends a public watermark probe to every connected own-user SG. |
| Tunnel cleanup | 5 min | Drops idle tunnels. |

A session lives 24 hours from the last successful handshake or DG keepalive. Maintenance renews a session when less than 2 hours remain. A `ConnectRequest` that gets no ack is forgotten after 5 seconds.

Who opens the session:

- A DG opens sessions to SG devices (own and contacts).
- An SG opens a session to another SG only when its own device UUID is numerically smaller.
- An SG does not open a session to a DG. The DG's session is the one both sides use.

Address choice uses a DNS cache. Poll and maintenance may resolve. Send and routing only read the cache, plus IPv4 literals. Among polled-up addresses, the lowest RTT wins. With no poll data, the first resolvable host is used.

## Identity, as this process implements it

Three Ed25519 layers, all algorithm Ed25519:

1. **User key.** Created at new-user setup. It self-signs a user certificate (alias, user public key, issued-at, expiry field). The expiry field in the signed bytes is always 0, and verification rebuilds the payload with 0, so certificates do not expire by time.
2. **Device key.** An Ed25519 signing key plus a separate X25519 static key. The user key signs a device certificate over the device alias, both public keys, and the user public key. Connect signatures are made with the device signing key. A peer accepts the signature only when that key equals the directory entry for the claimed device UUID and the device certificate verifies under the user public key already stored for that user (owner or contact).
3. **App key.** Minted when the app is approved (or at registration when auto-approve is on). The device signing key signs an app certificate over the app alias and the app public key.

Renames of the display alias do not rewrite `cert_alias`, so the signature stays valid.

The user private key is present on the node that created the user, and on a joiner whose invitation was minted with the user-key checkbox. An ordinary device invitation carries the user public certificate and a freshly signed device certificate, and does not carry the user seed. A node whose user private key is all zeros cannot sign device certificates. The portal checkbox is ignored when this process does not hold that key. On a delegated mint the receiving SG also ignores the release bit unless the requester is an own SG. A DG cannot obtain the user seed by setting the bit.

Keys at rest:

- User seed, each app identity seed, and the local device bundle (signing seed, signing public key, X25519 secret, X25519 public key) are sealed before they hit disk.
- The seal is base64 of version `1`, 16-byte salt, Argon2id parameters (m, t, p as `u32` little-endian), 24-byte nonce, and XChaCha20-Poly1305 ciphertext. Production parameters are 64 MiB, 3 iterations, parallelism 1. The passphrase is the Argon2id password.
- A legacy `node.toml` that still has a plaintext user seed loads. The next save wraps it.
- Invitation X25519 private keys are stored in `node.toml` inside the invitation record. They are not sealed by this module.
- The admin password hash is a separate secret: `v1$<salt hex>$<hash hex>`, SHA-256 stretched 100,000 times with a 16-byte salt and the label `pnet-admin-v1`. It is node-local and is not synced.

## Directory and writer

One own SG is the writer. Selection:

1. If `public_version.writer_sg_uuid` is already set and that device is this node, or is reachable, that device is the writer.
2. Otherwise walk own SG devices by ascending `sg_rank`. Reaching this node means this node is the writer. A higher-rank peer that has been polled and is entirely down is skipped. A higher-rank peer that is not reachable and is not polled-down stops the walk: the result is unreachable, and a lower rank is not used yet.
3. A write that finds no writer runs one synchronous SG poll and tries again, so a dead preferred SG can fail over without waiting for the 30-second poll.

Reachable means an active session exists and poll data is missing or at least one host is up.

Every implemented directory change is public scope. The private version is still carried on sync messages. A private-scope pull returns an empty snapshot. Public changes are:

| Change | Effect |
| --- | --- |
| Add application | Publish app id, alias, and app certificate for a device. Host, token, and protocol stay on the registering node. |
| Remove application | Drop that app id. |
| Add device | Publish a device with no apps. |
| Update application alias | Rename. |
| Upsert contact | Replace one contact's cached public card. |
| Remove device | Drop a device and its apps. |
| Remove contact | Drop a contact. |

The writer appends each accepted change to `write_log` and keeps entries for 30 days. Peers hear `UpdateAvailable` and pull a full public snapshot. On a pull of this node's own device, apps already stored locally are left alone and new ids are added. On a peer device, the incoming app list replaces the stored one. Apps created from a snapshot get `user_approved = true`, an empty protocol, host `0.0.0.0:0`, and a zero token. The registering device keeps the real host, token, and protocol.

Own SGs also reconcile with each other. On session-up and every 60 seconds an SG sends a public watermark probe to each connected own SG. The reply leads to a merge proposal. The merge unions adds by id, lets a remove tombstone win over an add of the same id, and picks an alias by writer rank (lower `sg_rank` first), then epoch and sequence, then writer UUID. If the log no longer covers the peer's watermark, the proposal carries a retention sentinel, the receiver adopts a full public snapshot, and the diagnostics page can show a retention-fallback flag.

Removing a device from the portal publishes `RemoveDevice`, drops it from the directory, and drops live sessions to it. The device that is serving the page cannot remove itself. A later add of that same UUID loses to the tombstone. The removed install no longer matches a directory entry, so its connect signature is rejected. Rejoining means a new invitation and a new device UUID.

Approving an app signs its certificate and publishes `AddApplication`. Rejecting or deleting it publishes `RemoveApplication`. There is one session per device, so unapproving an app does not close a session. A peer that has not yet pulled still has the old directory entry.

`request_change` toward a remote writer sends `SyncWriteRequest` and returns success to the caller without waiting for `SyncWriteAck`. The portal rolls a local edit back only when that call returns an error (no writer). A lost datagram is not rolled back by the HTTP handler.

## Application traffic

A local app registers, and after a person approves it (or auto-approve is set) it may send an opaque payload of at most 4096 bytes to another device's app id. Delivery order on the sender:

1. An active DG-to-DG tunnel for that destination, if the tunnel session and an SG to carry it both exist.
2. Otherwise a direct session to that device, if one exists and it is not the tunnel leg.
3. Otherwise an encrypted relay through the best reachable SG for that destination.

The SG decrypts a relay, re-encrypts toward the destination, and after 10 relays between the same pair inside a 5-minute window it starts a tunnel setup. The tunnel's inner payload is encrypted with the two DGs' ephemeral keys. The SG forwards that ciphertext without decrypting it. If the tunnel cannot be used, the sender falls back to direct or relay.

The destination pushes the payload to the approved app's registered UDP host. Success of a local send is silent. Failure is a two-byte error. Acceptance is not an end-to-end delivery receipt.

## Cryptography on the wire

- X25519 for session, invitation, and tunnel secrets. The raw Diffie-Hellman output is never the cipher key.
- HKDF-SHA256 with an empty salt and one of three info strings: `pnet-aead-v1-session`, `pnet-aead-v1-bootstrap`, `pnet-aead-v1-tunnel`.
- XChaCha20-Poly1305 for those keys.
- Ed25519 for certificates and for the connect handshake.

Session packets are `[op][peer's connection id u16][nonce 24][ciphertext]`. The connection id is the receiver's id.

## Sample apps in this workspace

These are separate binaries in `apps/`. The daemon does not require them.

| Binary | What it does |
| --- | --- |
| `pnet_web_hello` | Serves HTML on `127.0.0.1` (default port 9080) and registers the portal mount `POST /api/app-web/register`. Optionally also registers as a fabric app. |
| `pnet_deliverer` | Registers alias `deliverer`, persists its token to `pnet_token.bin`, and exposes a small HTTP UI on port 3000 for sending text payloads. Push port 8888, control port 8889. |
| `pnet_test_probe` | Headless harness app. Registers, fetches the directory, accepts pushes, and can send. Emits JSON events on stdout and `GET /events`. Default HTTP `0.0.0.0:3000`. Does not persist a token. |
| `pnet_chat` | Registers alias `pnet-chat` and can send a framed test payload `[version][msg_type][room id 16][body]`. HTTP default port 3100. The later chat message-type constants are declared in that crate and are not handled. |

`pnet_fuzz_wire` is a mutational fuzzer for the wire parsers (`cargo run --bin pnet_fuzz_wire -- --iters N`).

## Pages

- [API](api.md) — owner HTTP site and the local UDP app API.
- [Wire protocol](wire.md) — peer datagrams, from the first byte through sync and tunnels.
