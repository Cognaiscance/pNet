use std::net::{SocketAddr, UdpSocket};
use std::sync::{mpsc, Arc, RwLock};
use std::time::Duration;

use super::data_models::Node;
use super::writer::WriteRequest;

pub const PRIORITY_HIGH:   u8 = 0;
pub const PRIORITY_NORMAL: u8 = 1;
pub const PRIORITY_LOW:    u8 = 2;

pub enum Action {
    // From local apps (op byte in first byte of UDP packet)
    AppRegister   { src: SocketAddr, buf: Vec<u8> },
    AppUpdate     { src: SocketAddr, buf: Vec<u8> },
    AppGetData    { src: SocketAddr, buf: Vec<u8> },
    AppSendPacket { src: SocketAddr, buf: Vec<u8> },

    // Scheduled
    Heartbeat,
    KeyRotation,
    RetryMessage { message_id: u64 },
}

/// Sent by an action handler to schedule future work.
pub struct ScheduleRequest {
    pub action: Action,
    pub delay:  Duration,
}

/// Shared context passed to every action handler.
pub struct WorkerContext {
    pub node:         Arc<RwLock<Node>>,
    pub udp_socket:   Arc<UdpSocket>,
    pub writer_tx:    mpsc::SyncSender<WriteRequest>,
    pub scheduler_tx: mpsc::Sender<ScheduleRequest>,
}

impl Action {
    pub fn dispatch(self, ctx: &WorkerContext) {
        use super::handlers;
        match self {
            Action::AppRegister   { src, buf } => handlers::app_register(src, buf, ctx),
            Action::AppUpdate     { src, buf } => handlers::app_update(src, buf, ctx),
            Action::AppGetData    { src, buf } => handlers::app_get_data(src, buf, ctx),
            Action::AppSendPacket { src, buf } => handlers::app_send_packet(src, buf, ctx),
            Action::Heartbeat                  => handlers::heartbeat(ctx),
            Action::KeyRotation                => handlers::key_rotation(ctx),
            Action::RetryMessage { message_id } => handlers::retry_message(message_id, ctx),
        }
    }
}

pub struct ActionQueue {
    buckets: [Vec<Action>; 8],
}

impl ActionQueue {
    pub fn new() -> Self {
        ActionQueue {
            buckets: std::array::from_fn(|_| Vec::new()),
        }
    }

    pub fn push(&mut self, priority: u8, action: Action) {
        assert!(priority <= 7, "priority must be 0–7");
        self.buckets[priority as usize].push(action);
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|b| b.is_empty())
    }

    pub fn pop(&mut self) -> Option<Action> {
        for bucket in &mut self.buckets {
            if !bucket.is_empty() {
                return Some(bucket.remove(0));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000)
    }

    fn reg() -> Action { Action::AppRegister { src: addr(), buf: vec![] } }
    fn upd() -> Action { Action::AppUpdate   { src: addr(), buf: vec![] } }

    #[test]
    fn pop_empty_returns_none() {
        let mut q = ActionQueue::new();
        assert!(q.pop().is_none());
    }

    #[test]
    fn push_and_pop_single() {
        let mut q = ActionQueue::new();
        q.push(0, reg());
        assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
        assert!(q.pop().is_none());
    }

    #[test]
    fn lower_priority_popped_first() {
        let mut q = ActionQueue::new();
        q.push(3, Action::Heartbeat);
        q.push(0, reg());
        assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
        assert!(matches!(q.pop().unwrap(), Action::Heartbeat));
    }

    #[test]
    fn fifo_within_same_priority() {
        let mut q = ActionQueue::new();
        q.push(1, reg());
        q.push(1, upd());
        assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
        assert!(matches!(q.pop().unwrap(), Action::AppUpdate   { .. }));
    }

    #[test]
    fn drains_bucket_before_next() {
        let mut q = ActionQueue::new();
        q.push(0, reg());
        q.push(0, upd());
        q.push(1, Action::Heartbeat);
        assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
        assert!(matches!(q.pop().unwrap(), Action::AppUpdate   { .. }));
        assert!(matches!(q.pop().unwrap(), Action::Heartbeat));
    }

    #[test]
    #[should_panic]
    fn push_invalid_priority_panics() {
        let mut q = ActionQueue::new();
        q.push(8, reg());
    }
}
