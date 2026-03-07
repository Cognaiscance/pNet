# pNet Full Project Overview Plan

## Context
Building a secure peer-to-peer networking daemon in Ruby on Rails. pNet acts as a routing layer: apps on a device communicate with their local pNet node via HTTPS, and pNet nodes communicate with each other via encrypted UDP. The design docs specify the Rails interactor pattern for complex multi-step processes.

---

## Tech Stack
- **Ruby on Rails** (dual-mode: API for the App API, full-stack for the localhost UI)
- **SQLite** (or PostgreSQL) for persistence
- **`interactor` gem** for the organizer/interactor pattern
- **Custom UDP server** running as a background thread/process (Rake task or `lib/tasks`)
- **Self-signed TLS cert** for localhost HTTPS

---

## Data Models

### Clarifications & Additions

**Node** — Singleton enforced at the model level (`before_create` check). Has one `User` (owner), has one `Device` (this machine).

**User** — `uuid` indexed. `alias` for display. Has many `key_pairs` (most recent = active), has many `devices` (when owner), has many contacts (through `Contact` join).

**Contact** — Join table: `owner_id` → `user_id`, `contact_id` → `user_id`. Enables `user.contacts` to return other users.

**Device** — `uuid` indexed. `alias`. Has many `connections` (most recent = active). Has many `apps`.

**Connection** — `host_name` (e.g. `192.168.1.x:7777`), `timeout`. Has many `ephemeral_key_exchanges`. Polymorphic `belongs_to :connectable` (Device and App both "has many connections" — same model, polymorphic owner).

**KeyPair** — `public_key`, `private_key` (encrypted at rest). Polymorphic `belongs_to :owner` (User or App).

**EphemeralKeyExchange** — `timeout`, belongs_to `Connection`. Has one `key_pair` (local side). Has one `peer_public_key` (string — the remote party's public key, completing the DH exchange).

**App** — `app_uuid` (unique index), `app_name`, `status` (enum: `pending`/`accepted`/`rejected`), `api_key` (generated on acceptance, stored hashed), `app_api_key` (the key the app sends so pNet can authenticate when pushing to it — optional). Has many `connections` (via polymorphic Connection). Belongs_to `device`.

---

## File Structure

```
app/
  models/
    node.rb
    user.rb
    contact.rb
    device.rb
    connection.rb          # polymorphic: Device and App
    key_pair.rb            # polymorphic: User and App
    ephemeral_key_exchange.rb
    app.rb
  interactors/
    send_udp_packet/
      organizer.rb         # calls steps in order
      find_destination.rb  # resolve user+device → Connection
      verify_keys.rb       # check ephemeral key freshness
      request_ephemeral_keys.rb  # negotiate new keys if expired
      encrypt_payload.rb
      send_packet.rb
      notify_app.rb        # POST to app's API confirming delivery
    receive_udp_packet/
      organizer.rb
      authenticate_sender.rb
      decrypt_payload.rb
      find_target_app.rb
      forward_to_app.rb
    app_registration/
      organizer.rb
      validate_registration.rb
      create_app_record.rb
      notify_pending.rb    # surface in UI for user to accept/reject
    app_acceptance/
      organizer.rb
      generate_api_key.rb
      deliver_api_key.rb   # POST to app's /receive_key endpoint
  controllers/
    api/
      node_controller.rb   # App-facing API (HTTPS)
    ui/
      dashboard_controller.rb
      pending_apps_controller.rb  # accept/reject app registrations
      contacts_controller.rb      # view/add/delete contacts
      devices_controller.rb
  views/ui/                # ERB for the localhost UI
lib/
  udp_server.rb            # background UDP listener
  tasks/
    udp.rake               # rake pnet:start to launch UDP server
db/
  migrations/
    ...
```

---

## App API (HTTPS, localhost)

### `POST /api/register` — No API key required
App sends: `app_uuid`, `app_name`, `host` (its IP:port), optionally its `public_key`.
pNet creates an `App` record with `status: pending` and surfaces it in the UI.
Response: `202 Accepted` — app polls or waits for pNet to call its `/receive_key`.

### `GET /api/node` — Requires API key
Returns node info (user, devices, contacts). Excludes `key_pairs`, `ephemeral_key_exchanges`, `connections`.

### `POST /api/send` — Requires API key
Body: `{ to_user_uuid, to_device_uuid, payload }`.
Triggers `SendUdpPacket::Organizer`.

---

## App Expectations (Standard for App Implementors)

Apps must expose:
- `POST /receive_key` — pNet delivers the api_key after user accepts
- `POST /receive_message` — pNet forwards incoming payloads here

---

## Authentication: App ↔ pNet

Recommendation: **HTTPS + Bearer token (api_key)**
- The api_key is a securely random token (e.g. `SecureRandom.hex(32)`) generated on acceptance.
- Stored hashed in the DB; sent to app once via `POST /receive_key`.
- App sends it as `Authorization: Bearer <token>` on all subsequent requests.
- For UDP layer encryption, the `KeyPair` / `EphemeralKeyExchange` models handle DH-based encryption separately.

This keeps the app API simple while the heavy crypto lives in the UDP transport layer.

---

## Interactor Pattern

Use the [`interactor` gem](https://github.com/collectiveidea/interactor). Each organizer `include Interactor::Organizer` and calls steps via `organize`. Each step `include Interactor` and implements `#call`. Context object (`context.key`) is shared across steps.

Example organizer:
```ruby
# app/interactors/send_udp_packet/organizer.rb
class SendUdpPacket::Organizer
  include Interactor::Organizer
  organize SendUdpPacket::FindDestination,
           SendUdpPacket::VerifyKeys,
           SendUdpPacket::RequestEphemeralKeys,
           SendUdpPacket::EncryptPayload,
           SendUdpPacket::SendPacket,
           SendUdpPacket::NotifyApp
end
```

---

## UDP Transport

- Packets include: sender `user_uuid`, sender `device_uuid`, target `app_uuid`, encrypted payload.
- Encryption: DH-negotiated ephemeral shared secret (e.g. X25519 via `rbnacl` gem).
- `lib/udp_server.rb` listens on configured port, passes raw packets to `ReceiveUdpPacket::Organizer`.

---

## Localhost UI

Accessible only on `127.0.0.1`. Views for:
- **Pending Apps** — accept/reject registration requests
- **Address Book** — contacts (other users) and their devices; add/remove
- **My Devices** — devices owned by this node's user
- **Node Info** — current keys, connection status

---

## Open Questions / Suggestions

1. **App model and Connection polymorphism** — App's `connections` tracks the app's callback IP:port (for HTTPS pushes). This reuses the `Connection` model polymorphically but the semantics differ slightly from Device connections (HTTPS vs UDP). Worth discussing whether to split or annotate with a `protocol` field.

2. **UDP key negotiation** — The flow for initiating an ephemeral key exchange (when none exists yet) needs a defined handshake protocol. This would be its own interactor organizer.

3. **Initial setup** — First-run UX: the Node/User/Device records need to be seeded. A setup controller or seed task is needed.

---

## Verification

1. Run `rails db:migrate` — all tables created correctly
2. Boot pNet: `rails server` (HTTPS on localhost) + `rake pnet:start` (UDP listener)
3. Simulate app registration: `curl -X POST https://localhost:3000/api/register ...` → see pending in UI
4. Accept in UI → app receives API key at its `/receive_key` endpoint
5. Send a message via `POST /api/send` → verify it arrives at target app's `/receive_message`
6. Check interactor call chain with unit tests per organizer step
