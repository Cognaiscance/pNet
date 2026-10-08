# Data Persistence

## In-memory

All data model structs are loaded into memory at startup and kept there for the lifetime of the process. All reads during normal operation hit memory, not disk.

## On-disk format

Data is stored in human-readable files on disk. Changes are written through to disk whenever a model is created or updated.

## File layout and permissions

Data files live in a dedicated directory (e.g. `~/.pnet/data/`). The directory and all files within it are owned by the user running pnet, with permissions set to `700` (directory) and `600` (files) so that only that user (and root) can read or write them. The pnet process, running as that user, has full access.

**Enforced on create/load (Unix):** at startup `ensure_data_dir` creates `~/.pnet/data` if needed, sets the data directory (and parent `.pnet` when present) to mode `0700`, and sets existing `node.toml` / `apps.toml` / `write_log.toml` to `0600` if they exist. The writer thread (and any other durable write of node state) uses atomic temp + rename (per-file temp name + fsync) and always sets file mode `0600`. Wrong ownership or an unwritable path still fails as a normal I/O error — the process does not ask the user to run `chmod` for mode-only drift.

## Decisions

- **File format** — TOML
- **File layout** — split by growth rate (§7.3):
  - `node.toml` — directory snapshot (identity, devices, contacts, versions; **no** write log)
  - `write_log.toml` — sync v2 write-log entries (`entries = [...]`)
  - `apps.toml` — reserved / app-side data
- **Write strategy** — write on every change. To avoid corrupt files on crash, write to a temp file first (`.{filename}.tmp`), fsync, then rename into place (on Linux, rename is atomic). `save_node` enqueues **both** directory and write-log flushes.
- **Migration** — older builds embedded `write_log` inside `node.toml`. Load still accepts that; the next save writes the split layout. `node.toml` carries `format_version` (currently 2). A file that omits the field loads as version 1. Version 1 has no per-contact app grants; load keeps every existing contact allowed to reach every app that was already approved, then the in-memory node is version 2. The file itself is not rewritten until the next save. A number this build does not understand, or a `node.toml` that exists and does not parse, makes `pnet` exit before it writes `node.toml`, `write_log.toml`, or `apps.toml`. Load does not replace that file with a fresh node.
- **Private keys** — Ed25519 seeds are not written as plaintext. `node.toml` stores `private_key_sealed` (base64 envelope: version, Argon2id salt and parameters, XChaCha20-Poly1305 nonce and ciphertext). The device signing seed and static X25519 secret share one sealed blob, `device_secrets_sealed`. A legacy file that still has a plaintext `private_key` loads, and the next save wraps it. The process passphrase comes from `PNET_KEY_PASSPHRASE` or a terminal prompt; it is not the admin password. Invitation X25519 secrets stay on the device that minted them and are still stored with the invitation. See `descriptions/identity-and-keys.md`.

## Thread safety and disk writes

A dedicated writer thread owns all disk I/O. Worker threads never write to disk directly. When a worker updates in-memory data, it clones the updated state and sends it down a channel to the writer thread, then continues immediately without waiting.

The writer thread processes the channel sequentially — one write at a time — so there is no file contention and no locking needed on the files themselves. If multiple writes arrive in quick succession they queue up in the channel and are flushed in order.

The in-memory data still needs a brief lock (e.g. `RwLock`) so that worker threads can read and update it safely, but that lock is held only for the in-memory operation — never for the duration of a disk write. This keeps blocking time very short.
