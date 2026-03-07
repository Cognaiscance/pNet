# pNet

A peer-to-peer encrypted messaging node built with Rails 8.

## Requirements

- Ruby 3.4.8
- SQLite3

## Setup

```bash
bundle install
rails db:create db:migrate
```

Then visit `http://localhost:3000/ui/setup` to configure your node (user, device, key pair).

## Running

Start the Rails server (HTTP API + UI):

```bash
rails server
```

Start the UDP listener (in a separate terminal):

```bash
rake pnet:start
```

The UDP server listens on port `7777` by default. Override with:

```bash
PNET_UDP_PORT=8888 rake pnet:start
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `PNET_UDP_PORT` | UDP listener port | `7777` |
| `PNET_HOST` | Your LAN IP, used when generating connection codes | *(none)* |

Set `PNET_HOST` to your LAN IP before generating a connection code so other nodes can reach you:

```bash
PNET_HOST=192.168.1.x rails server
```

## UI

The web UI is accessible from localhost only at `http://localhost:3000/ui`.

- `/ui` — dashboard
- `/ui/pending_apps` — accept/reject app registrations
- `/ui/contacts` — address book
- `/ui/connection_code` — generate or import a connection code to pair with another node
- `/ui/devices` — device list
- `/ui/setup` — first-run setup

## Pairing Two Nodes

1. On Machine A: set `PNET_HOST=<LAN IP>`, start Rails + UDP listener
2. Visit `http://localhost:3000/ui/connection_code`, copy the generated code
3. Share the code out-of-band (chat, text, etc.) to Machine B's user
4. On Machine B: visit `http://localhost:3000/ui/connection_code`, paste the code, submit
5. Repeat in reverse so Machine A also has Machine B as a contact

Connection codes expire after 15 minutes.
