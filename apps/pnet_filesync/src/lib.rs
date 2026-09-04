//! Hybrid filesync app: folder replica + portal web UI.
//!
//! pNet is a dumb pipe. All file semantics, chunking, and conflict policy
//! live here. See `description.md`.

pub mod fabric;
pub mod paths;
pub mod proto;
pub mod store;
pub mod sync;
pub mod web;
