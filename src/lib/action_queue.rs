use std::net::{SocketAddr, TcpStream, UdpSocket};
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

    // From HTTP UI
    UiRequest { stream: TcpStream, method: String, path: String, query: String, body: Vec<u8> },

    // From peer pNet nodes
    SgPing             { src: SocketAddr, nonce: [u8; 16] },
    ConnectRequest     { src: SocketAddr, buf: Vec<u8> },
    ConnectAck         { src: SocketAddr, buf: Vec<u8> },
    BootstrapRequest   { src: SocketAddr, buf: Vec<u8> },
    BootstrapResponse  { src: SocketAddr, buf: Vec<u8> },
    DeviceRegistration { src: SocketAddr, buf: Vec<u8> },

    // Scheduled
    PollSG,
    MaintainConnections,
    KeepAliveDG,
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
            Action::UiRequest { stream, method, path, query, body } => {
                handlers::ui_request(stream, method, path, query, body, ctx)
            }
            Action::SgPing             { src, nonce } => handlers::sg_ping(src, nonce, ctx),
            Action::ConnectRequest     { src, buf }   => handlers::connect_request(src, buf, ctx),
            Action::ConnectAck         { src, buf }   => handlers::connect_ack(src, buf, ctx),
            Action::BootstrapRequest   { src, buf }   => handlers::bootstrap_request(src, buf, ctx),
            Action::BootstrapResponse  { src, buf }   => handlers::bootstrap_response(src, buf, ctx),
            Action::DeviceRegistration { src, buf }   => handlers::device_registration(src, buf, ctx),
            Action::PollSG                          => handlers::poll_sg(ctx),
            Action::MaintainConnections             => handlers::maintain_connections(ctx),
            Action::KeepAliveDG                     => handlers::keepalive_dg(ctx),
            Action::RetryMessage { message_id }     => handlers::retry_message(message_id, ctx),
        }
    }
}

/// After this many consecutive bucket-0 pops, the next pop yields to the
/// highest-priority non-zero bucket that has work, preventing starvation.
const STARVATION_THRESHOLD: usize = 20;

pub struct ActionQueue {
    buckets:     [Vec<Action>; 8],
    high_streak: usize,
}

impl ActionQueue {
    pub fn new() -> Self {
        ActionQueue {
            buckets:     std::array::from_fn(|_| Vec::new()),
            high_streak: 0,
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
        // Starvation guard: after STARVATION_THRESHOLD consecutive bucket-0
        // pops, yield to the next non-empty lower-priority bucket.
        if self.high_streak >= STARVATION_THRESHOLD {
            for bucket in &mut self.buckets[1..] {
                if !bucket.is_empty() {
                    self.high_streak = 0;
                    return Some(bucket.remove(0));
                }
            }
            // Nothing in lower buckets; fall through to normal priority order.
        }

        for (i, bucket) in self.buckets.iter_mut().enumerate() {
            if !bucket.is_empty() {
                if i == 0 {
                    self.high_streak += 1;
                } else {
                    self.high_streak = 0;
                }
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
        q.push(3, Action::MaintainConnections);
        q.push(0, reg());
        assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
        assert!(matches!(q.pop().unwrap(), Action::MaintainConnections));
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
        q.push(1, Action::MaintainConnections);
        assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
        assert!(matches!(q.pop().unwrap(), Action::AppUpdate   { .. }));
        assert!(matches!(q.pop().unwrap(), Action::MaintainConnections));
    }

    #[test]
    #[should_panic]
    fn push_invalid_priority_panics() {
        let mut q = ActionQueue::new();
        q.push(8, reg());
    }

    // ── Starvation prevention ─────────────────────────────────────────────────

    #[test]
    fn starvation_guard_yields_to_lower_priority_after_threshold() {
        let mut q = ActionQueue::new();

        // Fill bucket 0 beyond the threshold and add one low-priority item.
        for _ in 0..STARVATION_THRESHOLD {
            q.push(0, reg());
        }
        q.push(1, Action::MaintainConnections); // the item that must not starve

        // First STARVATION_THRESHOLD pops should all be bucket-0 items.
        for _ in 0..STARVATION_THRESHOLD {
            assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
        }

        // The very next pop must yield the lower-priority item.
        assert!(matches!(q.pop().unwrap(), Action::MaintainConnections));
    }

    #[test]
    fn starvation_streak_resets_after_lower_priority_pop() {
        let mut q = ActionQueue::new();

        // Burn through the threshold.
        for _ in 0..STARVATION_THRESHOLD {
            q.push(0, reg());
        }
        q.push(1, Action::MaintainConnections);
        for _ in 0..STARVATION_THRESHOLD {
            q.pop();
        }
        q.pop(); // yields Heartbeat, streak resets to 0

        // Queue is empty; add fewer than STARVATION_THRESHOLD high-priority
        // items — they should all pop normally without triggering the guard.
        for _ in 0..STARVATION_THRESHOLD - 1 {
            q.push(0, reg());
        }
        q.push(1, Action::MaintainConnections);
        for _ in 0..STARVATION_THRESHOLD - 1 {
            assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
        }
        // KeyRotation should still be in the queue (streak hasn't hit threshold yet).
        assert!(matches!(q.pop().unwrap(), Action::MaintainConnections));
    }

    #[test]
    fn starvation_guard_falls_through_when_no_lower_priority_work() {
        let mut q = ActionQueue::new();

        // Only bucket-0 items; guard should not block them even after threshold.
        for _ in 0..=STARVATION_THRESHOLD {
            q.push(0, reg());
        }
        for _ in 0..=STARVATION_THRESHOLD {
            assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
        }
        assert!(q.pop().is_none());
    }
}
