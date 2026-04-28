//! In-process app modules.
//!
//! Each module is a piece of code that the user can turn on or off. Once on,
//! the module is active on every device the user owns, kept in sync via the
//! existing device-data path (op 0x62/0x63). Modules talk to one another by
//! addressing a (user, device, module) triple — pnet routes the bytes and
//! takes no opinions about reliability, retention, or ordering. Apps make
//! their own targeting decisions: a messaging-shaped app sends to the
//! recipient's top-ranked SG so its module instance there can persist; a
//! live-tunnel app sends to a specific online DG; etc.
//!
//! Modules are first-party trusted code. The context exposes the full node
//! tree under a read lock so apps can pick targets without a curated view.

pub mod debug;

use std::sync::Arc;

use super::action_queue::WorkerContext;
use super::data_models::{Node, Uuid};

/// Stable, registry-allocated identifier for a module. Carried on the wire
/// in AppPacket bodies and stored in the user's enabled-modules list, so it
/// must not change between releases once allocated.
pub type ModuleId = u16;

#[derive(Debug, Clone, Copy)]
pub struct PacketSource {
    pub user:   Uuid,
    pub device: Uuid,
    pub module: ModuleId,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketTarget {
    pub user:   Uuid,
    pub device: Uuid,
    pub module: ModuleId,
}

#[derive(Debug)]
pub enum SendError {
    /// pnet has no known route to the target right now (no SG up, no direct
    /// connection). The app may retry, pick another device, or drop.
    NoPath,
}

pub trait Module: Send + Sync {
    fn id(&self) -> ModuleId;
    fn slug(&self) -> &'static str;
    fn alias(&self) -> &'static str;

    fn on_receive(&self, from: PacketSource, payload: &[u8], ctx: &ModuleCtx);

    fn on_http(&self, _req: &HttpRequest, _ctx: &ModuleCtx) -> Option<HttpResponse> {
        None
    }

    fn on_enable(&self, _ctx: &ModuleCtx)  {}
    fn on_disable(&self, _ctx: &ModuleCtx) {}
}

pub struct ModuleCtx<'a> {
    pub(crate) inner:  &'a WorkerContext,
    pub(crate) module: ModuleId,
}

impl ModuleCtx<'_> {
    /// Fire-and-forget. Returns Err only when pnet knows up-front it cannot
    /// route — the app then decides what to do.
    pub fn send(&self, target: PacketTarget, payload: &[u8]) -> Result<(), SendError> {
        super::handlers::route_app_send(self.inner, self.module, target, payload)
    }

    /// Run a closure under a read lock on the full node. Modules are trusted.
    pub fn read<R>(&self, f: impl FnOnce(&Node) -> R) -> R {
        f(&self.inner.node.read().unwrap())
    }

    pub fn load_state(&self) -> Option<Vec<u8>> {
        self.inner
            .node
            .read()
            .unwrap()
            .owner
            .module_state
            .get(&self.module)
            .cloned()
    }

    pub fn save_state(&self, blob: Vec<u8>) {
        {
            let mut node = self.inner.node.write().unwrap();
            node.owner.module_state.insert(self.module, blob);
        }
        self.inner.save_node();
    }
}

pub struct HttpRequest {
    pub method: String,
    pub path:   String,
    pub query:  String,
    pub body:   Vec<u8>,
}

pub struct HttpResponse {
    pub status:       u16,
    pub content_type: &'static str,
    pub body:         Vec<u8>,
}

/// Every module compiled into this binary. Edit this list to add or remove
/// apps. Module ids must be unique and stable.
pub fn all() -> Vec<Arc<dyn Module>> {
    vec![Arc::new(debug::Debug::new())]
}
