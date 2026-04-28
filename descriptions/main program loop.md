# Main Program Loop

The core of pnet is a simple, hand-rolled work queue with a fixed thread pool. No external async runtimes or job frameworks — the loop is meant to be readable and self-contained.

## Queue

The queue has priority buckets. When a worker thread is ready, it checks the highest-priority bucket first and works its way down. Items within a bucket are FIFO.

Priority levels (high → low):
- **high** — inbound UDP packets (time-sensitive, peer may be waiting)
- **normal** — UI/API requests
- **low** — scheduled/maintenance tasks (retries, key rotation, SG polling, etc.)

Each item in the queue is a variant of the `Action` enum — one variant per action type. This keeps all action types centralized and avoids heap allocation per item.

Known action variants:

**From local apps:**
- *(none — apps are in-process modules, not separate processes. They call into pnet directly via `ModuleCtx::send` rather than enqueueing actions. See *Apps and modules*.)*

**From peer pnet nodes (via UDP):**
- `SgPing` (0x10) / `DgKeepalive` (0x12) / `ConnReset` (0x13)
- `ConnectRequest` (0x20) / `ConnectAck` (0x21)
- `BootstrapRequest` (0x30) / `BootstrapResponse` (0x31) / `DeviceRegistration` (0x32)
- `ContactRequest` (0x33) / `ContactResponse` (0x34)
- `RelayPacket` (0x40) / `AppPacket` (0x41)
- `TunnelInit` (0x50) / `TunnelForward` (0x51) / `TunnelConnectRequest` (0x52) / `TunnelConnectAck` (0x53) / `TunnelDelivery` (0x54)
- `ContactDataPush` (0x60) / `ContactDataPullRequest` (0x61) / `DeviceDataPush` (0x62) / `DeviceDataPullRequest` (0x63)

**From the HTTP UI:**
- `UiRequest` — wraps the parsed method/path/query/body and the open TCP stream

**Scheduled:**
- `MaintainConnections` — top up the `ActiveConnection` set; runs every 5 minutes (see background systems.md)
- `PollSG` — ping candidate SGs to measure RTT and detect downtime (see background systems.md)
- `KeepAliveDG` — DG-only; refresh NAT mappings to each connected SG every 20 seconds
- `CleanupTunnels` — expire idle DG-to-DG tunnels and stale relay counters
- `SyncContacts` / `SyncDevices` — daily push or pull of the user's data (see *pnet to pnet communication*)
- `SetupTunnel` — one-shot, scheduled by an SG when a sender/destination pair crosses the relay-traffic threshold

## Producers

Things that put items into the queue:

- **UDP listener** — receives a raw packet, reads the op byte to determine the action type, wraps the sender's socket address and raw bytes into the appropriate `Action` variant, and enqueues it. Parsing and processing happen in the worker.
- **HTTP handlers** (API + UI) — on request, wrap the work as a normal-priority action and enqueue it; the handler waits for the result to send a response
- **Scheduler** — a lightweight loop that wakes up periodically and enqueues low-priority actions whose time has come (retries, key rotation, SG polling, etc.)

## Workers

A fixed number of worker threads (configurable, e.g. 4) pull actions from the queue and execute them one at a time per thread. Workers do not spawn their own threads; all concurrency comes from the pool size.

## Scheduler

A single scheduler thread sleeps for a short interval (e.g. 1 second), wakes up, checks a list of scheduled jobs, and enqueues any that are due. Jobs can be one-shot or recurring.

## Startup / Shutdown

On startup, the program:
1. Loads all data from disk into memory
2. Starts the queue
3. Starts the worker threads
4. Starts the writer thread (disk persistence channel)
5. Starts the scheduler thread
6. Starts the UDP listener
7. Starts the HTTP server

On shutdown (SIGTERM/SIGINT), threads are stopped in reverse startup order:

1. **Stop producers** — the UDP listener, HTTP server, and scheduler are signaled to stop. They finish any in-flight operation and go quiet. The queue may still have items.
2. **Drain the queue** — worker threads keep running until the queue is empty.
3. **Stop worker threads** — workers are signaled to exit. Each finishes its current action, checks the signal on its next iteration, and exits. Main thread joins all worker threads.
4. **Stop the writer thread** — the channel sender is closed. The writer processes any remaining queued writes, then exits when the channel is empty and closed. Main thread joins the writer thread.
5. **Exit**

The stop signal for most threads is a shared `Arc<AtomicBool>` flag — main thread sets it to false, threads check it on each loop iteration. The writer thread uses channel closure as its natural stop signal.
