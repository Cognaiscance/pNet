# Apps and modules

Apps are not separate processes. Each app is an in-process **module** compiled into the pnet binary. Once compiled in, a module can be turned on or off by the user; an enabled module is active on every device that user owns, kept in sync via the existing device-data path.

## The Module trait

Every module implements `Module` (see `src/lib/modules/mod.rs`):

```rust
pub trait Module: Send + Sync {
    fn id(&self)    -> ModuleId;        // u16, registry-allocated, stable across releases
    fn slug(&self)  -> &'static str;    // URL-safe slug used as the HTTP mount prefix
    fn alias(&self) -> &'static str;    // human-readable name shown in the toggle UI

    fn on_receive(&self, from: PacketSource, payload: &[u8], ctx: &ModuleCtx);
    fn on_http(&self, req: &HttpRequest, ctx: &ModuleCtx) -> Option<HttpResponse> { None }
    fn on_enable(&self,  ctx: &ModuleCtx) {}
    fn on_disable(&self, ctx: &ModuleCtx) {}
}
```

`PacketSource` and `PacketTarget` both address by `(user, device, module)`. Modules are first-party trusted code; the context exposes the full node tree under a read lock so apps can pick targets without a curated view.

## Registry

`modules::all()` returns the boxed list of every module compiled into the binary. The registry is constructed at startup, stored on `WorkerContext.modules`, and is the same on every node. Module ids must be unique and stable — once allocated, never renumbered, since the id is carried on the wire.

## Enable / disable

A user enables modules from the **Apps** page in the admin UI. The toggle:

1. Mutates `User.enabled_modules: Vec<u16>` (the set of module ids the user has on).
2. Calls `Module::on_enable` or `on_disable`.
3. Persists, then triggers `sync_devices` and `push_data_to_contacts` so other own devices and every contact learn the new state. See *pnet to pnet communication* for how `enabled_modules` rides on ops 0x60–0x63.

## Sending

A module addresses a packet by `(user, device, module)`:

```rust
ctx.send(PacketTarget { user, device, module: self.id() }, payload)
```

pnet picks a route in this order:
1. **Local short-circuit** — if `device == this device`, deliver in-process by calling the destination module's `on_receive` directly.
2. **DG-to-DG tunnel** if one is active for that destination (op 0x51 wraps an end-to-end-encrypted payload).
3. **Direct active connection** if this node already has one to the destination device (op 0x41 AppPacket).
4. **SG relay** through the destination's top-ranked SG, falling back to the lowest-RTT up SG (op 0x40 RelayPacket).

`send` is fire-and-forget. It returns `Err(SendError::NoPath)` only when pnet knows up front it cannot route — no acks, no retries, no buffering. Reliability semantics, retention, and ordering are app-level concerns. Apps are expected to make wise targeting decisions: a messaging-shaped app sends to the recipient's top-ranked SG so its module instance there can persist; a live-tunnel app sends to a specific online DG.

## Receiving

When an inbound packet's destination module id matches a registered module *and* the receiving user has that module enabled, pnet calls `Module::on_receive(from, payload, ctx)`. Otherwise the packet is dropped with a log line. Three handlers feed this dispatch:

- `app_packet` (op 0x41) — direct delivery from a peer node
- `tunnel_delivery` (op 0x54) — delivery via an end-to-end DG tunnel
- `relay_packet` (op 0x40), local-recipient branch — when the SG happens to also be the destination

## On-wire format

`AppPacket` (op 0x41) and `RelayPacket` (op 0x40) bodies are unchanged from the external-app era; the two `u16` fields are now interpreted as module ids:

```
Encrypted body:
┌─────────────────────────┬───────┐
│ Receiver module id      │ 2     │
│ Sender module id        │ 2     │
│ Payload                 │ var   │
└─────────────────────────┴───────┘
```

`RelayPacket` prepends a 16-byte destination device UUID; `TunnelDelivery` (op 0x54) wraps the same 4-byte module-id pair plus payload using the DG-to-DG shared secret.

## HTTP UI

Modules can serve their own UI under `/apps/<slug>/...` on the localhost admin server. The router strips the `/apps/<slug>` prefix and calls `Module::on_http` with the suffix path. `on_http` returns `Some(HttpResponse { status, content_type, body })` to handle the request, or `None` to fall through to the standard 404. The mount is gated on the user having the module enabled.

The included **debug** module (id `1`, slug `debug`) is a working reference: it dumps the owner, devices, contacts, active connections, and SG status; logs an in-memory inbox of received packets; and offers a send form that fires arbitrary text payloads at any known device.
