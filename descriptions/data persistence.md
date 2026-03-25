# Data Persistence

## In-memory

All data model structs are loaded into memory at startup and kept there for the lifetime of the process. All reads during normal operation hit memory, not disk.

## On-disk format

Data is stored in human-readable files on disk. Changes are written through to disk whenever a model is created or updated.

## File layout and permissions

Data files live in a dedicated directory (e.g. `~/.pnet/data/`). The directory and all files within it are owned by the user running pnet, with permissions set to `700` (directory) and `600` (files) so that only that user (and root) can read or write them. The pnet process, running as that user, has full access.

## Decisions

- **File format** — TOML
- **File layout** — one file per model type (e.g. `nodes.toml`, `apps.toml`)
- **Write strategy** — write on every change. To avoid corrupt files on crash, write to a temp file first then rename it into place (on Linux, rename is atomic).

## Thread safety and disk writes

A dedicated writer thread owns all disk I/O. Worker threads never write to disk directly. When a worker updates in-memory data, it clones the updated state and sends it down a channel to the writer thread, then continues immediately without waiting.

The writer thread processes the channel sequentially — one write at a time — so there is no file contention and no locking needed on the files themselves. If multiple writes arrive in quick succession they queue up in the channel and are flushed in order.

The in-memory data still needs a brief lock (e.g. `RwLock`) so that worker threads can read and update it safely, but that lock is held only for the in-memory operation — never for the duration of a disk write. This keeps blocking time very short.
