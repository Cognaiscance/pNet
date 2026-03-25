# Main Program Loop

The core of pnet is a simple, hand-rolled work queue with a fixed thread pool. No external async runtimes or job frameworks — the loop is meant to be readable and self-contained.

## Queue

The queue has priority buckets. When a worker thread is ready, it checks the highest-priority bucket first and works its way down. Items within a bucket are FIFO.

Priority levels (high → low):
- **high** — inbound UDP packets (time-sensitive, peer may be waiting)
- **normal** — UI/API requests
- **low** — scheduled/maintenance tasks (retries, heartbeats, key rotation, etc.)

Each item in the queue is a variant of the `Action` enum — one variant per action type. This keeps all action types centralized and avoids heap allocation per item.

Known action variants:

**From local apps (via UDP op byte):**
- `AppRegister` — op 0, app sends alias + port, pnet replies with token
- `AppUpdate` — op 1, app sends token + fields to change
- `AppGetData` — op 2, app requests the data tree
- `AppSendPacket` — op 3, app sends token + delivery path + payload

**From peer pnet nodes (via UDP):**
- *(to be defined — see communication methods.md)*

**From the HTTP UI:**
- *(to be defined)*

**Scheduled:**
- `Heartbeat` — ping peers
- `KeyRotation` — renegotiate expiring ephemeral keys
- `RetryMessage` — retry an unACKed outbound message

## Producers

Things that put items into the queue:

- **UDP listener** — receives a raw packet, reads the op byte to determine the action type, wraps the sender's socket address and raw bytes into the appropriate `Action` variant, and enqueues it. Parsing and processing happen in the worker.
- **HTTP handlers** (API + UI) — on request, wrap the work as a normal-priority action and enqueue it; the handler waits for the result to send a response
- **Scheduler** — a lightweight loop that wakes up periodically and enqueues low-priority actions whose time has come (retries, heartbeats, EKE rotation, etc.)

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
