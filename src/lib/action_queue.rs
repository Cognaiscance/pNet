use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::{mpsc, Arc, Condvar, Mutex, RwLock};
use std::time::Duration;

use super::data_models::{Node, Uuid};
use super::writer::WriteRequest;

/// Rendezvous slots for DG→SG invitation mint (op 0x35 / 0x36).
///
/// The worker that *sends* 0x35 only registers a token and must **not** park
/// here — that would pin a pool thread for up to the mint RTT (§5.2). The UI
/// path waits via [`PendingInvites::wait_result`] on a short-lived off-pool
/// thread that owns the HTTP response. `generate_invitation_response` (0x36)
/// fills the slot and notifies `cv`.
///
/// Slot values: `None` = still waiting; `Some(Ok(code))` = success;
/// `Some(Err(()))` = SG-side failure. Missing after timeout = no reply.
#[derive(Default)]
pub struct PendingInvites {
    pub slots: Mutex<HashMap<Uuid, Option<Result<String, ()>>>>,
    pub cv:    Condvar,
}

/// Max time a non-pool waiter blocks for an SG mint reply (op 0x36).
pub const INVITATION_MINT_TIMEOUT: Duration = Duration::from_secs(5);

impl PendingInvites {
    /// Block until the slot for `token` is filled or `timeout` elapses.
    ///
    /// Removes the slot either way. Call from **off-pool** threads only
    /// (e.g. the invite-mint waiter spawned by the admin UI).
    pub fn wait_result(
        &self,
        token: Uuid,
        timeout: Duration,
    ) -> Option<Result<String, ()>> {
        let slots = self.slots.lock().unwrap();
        let (mut slots, _) = self
            .cv
            .wait_timeout_while(slots, timeout, |s| matches!(s.get(&token), Some(None)))
            .unwrap();
        slots.remove(&token).flatten()
    }
}

pub const PRIORITY_HIGH:   u8 = 0;
pub const PRIORITY_NORMAL: u8 = 1;
pub const PRIORITY_LOW:    u8 = 2;

/// Max actions waiting across all priority buckets.
///
/// UDP (high), admin HTTP (normal), and the scheduler (low) share this budget.
/// Under pressure, [`ActionQueue::push`] drops lower-priority work first so
/// session/crypto packets keep flowing.
pub const QUEUE_CAPACITY: usize = 1024;

pub enum Action {
    // From local apps (op byte in first byte of UDP packet)
    AppRegister   { src: SocketAddr, buf: Vec<u8> },
    AppUpdate     { src: SocketAddr, buf: Vec<u8> },
    AppGetData    { src: SocketAddr, buf: Vec<u8> },
    AppSendPacket { src: SocketAddr, buf: Vec<u8> },

    // From HTTP UI
    UiRequest {
        stream: TcpStream,
        method: String,
        path: String,
        query: String,
        /// Raw `Cookie` header value (may be empty).
        cookie: String,
        /// Raw `Host` header (for CSRF Origin/Referer checks).
        host: String,
        /// Raw `Origin` header (may be empty).
        origin: String,
        /// Raw `Referer` header (may be empty).
        referer: String,
        body: Vec<u8>,
    },

    // From peer pNet nodes
    SgPing             { src: SocketAddr, nonce: [u8; 16] },
    DgKeepalive        { src: SocketAddr, buf: Vec<u8> },
    ConnReset          { src: SocketAddr },
    ConnectRequest     { src: SocketAddr, buf: Vec<u8> },
    ConnectAck         { src: SocketAddr, buf: Vec<u8> },
    BootstrapRequest   { src: SocketAddr, buf: Vec<u8> },
    BootstrapResponse  { src: SocketAddr, buf: Vec<u8> },
    DeviceRegistration { src: SocketAddr, buf: Vec<u8> },
    ContactRequest        { src: SocketAddr, buf: Vec<u8> },
    ContactResponse       { src: SocketAddr, buf: Vec<u8> },
    // 0x35/0x36 — DG asks an SG to mint an invitation; SG replies with the code.
    GenerateInvitationRequest  { src: SocketAddr, buf: Vec<u8> },
    GenerateInvitationResponse { src: SocketAddr, buf: Vec<u8> },
    // Sync v1 (descriptions/data sync.md). Replaces the push-everywhere
    // ContactDataPush/DeviceDataPush flow once phases 3–7 land.
    SyncWriteRequest      { src: SocketAddr, buf: Vec<u8> },
    SyncWriteAck          { src: SocketAddr, buf: Vec<u8> },
    SyncUpdateAvailable   { src: SocketAddr, buf: Vec<u8> },
    SyncPullRequest       { src: SocketAddr, buf: Vec<u8> },
    SyncPullResponse      { src: SocketAddr, buf: Vec<u8> },
    CrossUserUpdateAvailable { src: SocketAddr, buf: Vec<u8> },
    CrossUserPullRequest     { src: SocketAddr, buf: Vec<u8> },
    CrossUserPullResponse    { src: SocketAddr, buf: Vec<u8> },
    WatermarkProbeRequest    { src: SocketAddr, buf: Vec<u8> },
    WatermarkProbeResponse   { src: SocketAddr, buf: Vec<u8> },
    MergeProposal            { src: SocketAddr, buf: Vec<u8> },
    MergeAck                 { src: SocketAddr, buf: Vec<u8> },
    RelayPacket        { src: SocketAddr, buf: Vec<u8> },
    AppPacket          { src: SocketAddr, buf: Vec<u8> },

    // Tunnel
    TunnelInit           { src: SocketAddr, buf: Vec<u8> },
    TunnelForward        { src: SocketAddr, buf: Vec<u8> },
    TunnelDelivery       { src: SocketAddr, buf: Vec<u8> },
    TunnelConnectRequest { src: SocketAddr, buf: Vec<u8> },
    TunnelConnectAck     { src: SocketAddr, buf: Vec<u8> },

    // Scheduled
    PollSG,
    MaintainConnections,
    KeepAliveDG,
    CleanupTunnels,
    /// Periodic pull from the elected writer SG for both scopes. Also fired
    /// as a one-shot when an active connection to the writer SG is established.
    SyncPull,
    /// Sync v2 periodic merge tick. Fires `partition_reconcile_on_reconnect`
    /// for every active connection to an own-user SG so partition reconciliation
    /// progresses even when the underlying connection survives the partition
    /// (i.e. no fresh `connect_ack` to trigger it).
    PartitionReconcile,
    SetupTunnel   { sender_uuid: super::data_models::Uuid, dest_uuid: super::data_models::Uuid },
}

/// Sent by an action handler to schedule future work.
pub struct ScheduleRequest {
    pub action: Action,
    pub delay:  Duration,
}

/// Shared context passed to every action handler.
///
/// **Locking (§5.4):** `node` is a single global `RwLock`. Prefer short critical
/// sections: copy what you need under the lock, then `send` / DNS / disk outside
/// it. Do not hold `node` across network RTT. Session maps and directory state
/// stay together for now — see `descriptions/locking.md`.
pub struct WorkerContext {
    pub node:         Arc<RwLock<Node>>,
    pub udp_socket:   Arc<UdpSocket>,
    pub writer_tx:    mpsc::SyncSender<WriteRequest>,
    pub scheduler_tx: mpsc::Sender<ScheduleRequest>,
    /// Rendezvous for DG→SG invitation requests (op 0x35/0x36).
    pub pending_invites: Arc<PendingInvites>,
    /// In-memory admin UI sessions (cookie → expiry). Not persisted.
    pub sessions: Arc<super::admin_auth::SessionStore>,
    /// Local app API rate limits (register/send token buckets).
    pub app_rate_limits: Arc<std::sync::Mutex<super::app_api::AppRateLimiter>>,
    /// Host resolve cache (§5.3). Maintain/poll refresh; send/routing look up only.
    pub dns_cache: Arc<std::sync::Mutex<super::dns_cache::DnsCache>>,
}

impl WorkerContext {
    /// Serialize the current node state and queue it for writing to disk.
    /// Call this after any mutation that affects persistent data.
    pub fn save_node(&self) {
        let toml_str = super::persistence::save(&*self.node.read().unwrap());
        let _ = self.writer_tx.send(WriteRequest::NodeData(toml_str));
    }
}

impl Action {
    /// Short stable name for logs/metrics (not for wire).
    pub fn kind_name(&self) -> &'static str {
        match self {
            Action::AppRegister { .. } => "AppRegister",
            Action::AppUpdate { .. } => "AppUpdate",
            Action::AppGetData { .. } => "AppGetData",
            Action::AppSendPacket { .. } => "AppSendPacket",
            Action::UiRequest { .. } => "UiRequest",
            Action::SgPing { .. } => "SgPing",
            Action::DgKeepalive { .. } => "DgKeepalive",
            Action::ConnReset { .. } => "ConnReset",
            Action::ConnectRequest { .. } => "ConnectRequest",
            Action::ConnectAck { .. } => "ConnectAck",
            Action::BootstrapRequest { .. } => "BootstrapRequest",
            Action::BootstrapResponse { .. } => "BootstrapResponse",
            Action::DeviceRegistration { .. } => "DeviceRegistration",
            Action::ContactRequest { .. } => "ContactRequest",
            Action::ContactResponse { .. } => "ContactResponse",
            Action::GenerateInvitationRequest { .. } => "GenerateInvitationRequest",
            Action::GenerateInvitationResponse { .. } => "GenerateInvitationResponse",
            Action::SyncWriteRequest { .. } => "SyncWriteRequest",
            Action::SyncWriteAck { .. } => "SyncWriteAck",
            Action::SyncUpdateAvailable { .. } => "SyncUpdateAvailable",
            Action::SyncPullRequest { .. } => "SyncPullRequest",
            Action::SyncPullResponse { .. } => "SyncPullResponse",
            Action::CrossUserUpdateAvailable { .. } => "CrossUserUpdateAvailable",
            Action::CrossUserPullRequest { .. } => "CrossUserPullRequest",
            Action::CrossUserPullResponse { .. } => "CrossUserPullResponse",
            Action::WatermarkProbeRequest { .. } => "WatermarkProbeRequest",
            Action::WatermarkProbeResponse { .. } => "WatermarkProbeResponse",
            Action::MergeProposal { .. } => "MergeProposal",
            Action::MergeAck { .. } => "MergeAck",
            Action::RelayPacket { .. } => "RelayPacket",
            Action::AppPacket { .. } => "AppPacket",
            Action::TunnelInit { .. } => "TunnelInit",
            Action::TunnelForward { .. } => "TunnelForward",
            Action::TunnelDelivery { .. } => "TunnelDelivery",
            Action::TunnelConnectRequest { .. } => "TunnelConnectRequest",
            Action::TunnelConnectAck { .. } => "TunnelConnectAck",
            Action::PollSG => "PollSG",
            Action::MaintainConnections => "MaintainConnections",
            Action::KeepAliveDG => "KeepAliveDG",
            Action::CleanupTunnels => "CleanupTunnels",
            Action::SyncPull => "SyncPull",
            Action::PartitionReconcile => "PartitionReconcile",
            Action::SetupTunnel { .. } => "SetupTunnel",
        }
    }

    pub fn dispatch(self, ctx: &WorkerContext) {
        use super::handlers;
        match self {
            Action::AppRegister   { src, buf } => handlers::app_register(src, buf, ctx),
            Action::AppUpdate     { src, buf } => handlers::app_update(src, buf, ctx),
            Action::AppGetData    { src, buf } => handlers::app_get_data(src, buf, ctx),
            Action::AppSendPacket { src, buf } => handlers::app_send_packet(src, buf, ctx),
            Action::UiRequest {
                stream, method, path, query, cookie, host, origin, referer, body,
            } => {
                handlers::ui_request(
                    stream, method, path, query, cookie, host, origin, referer, body, ctx,
                )
            }
            Action::SgPing             { src, nonce } => handlers::sg_ping(src, nonce, ctx),
            Action::DgKeepalive        { src, buf }   => handlers::dg_keepalive_receive(src, buf, ctx),
            Action::ConnReset          { src }        => handlers::conn_reset(src, ctx),
            Action::ConnectRequest     { src, buf }   => handlers::connect_request(src, buf, ctx),
            Action::ConnectAck         { src, buf }   => handlers::connect_ack(src, buf, ctx),
            Action::BootstrapRequest   { src, buf }   => handlers::bootstrap_request(src, buf, ctx),
            Action::BootstrapResponse  { src, buf }   => handlers::bootstrap_response(src, buf, ctx),
            Action::DeviceRegistration { src, buf }   => handlers::device_registration(src, buf, ctx),
            Action::ContactRequest         { src, buf } => handlers::contact_request(src, buf, ctx),
            Action::ContactResponse        { src, buf } => handlers::contact_response(src, buf, ctx),
            Action::GenerateInvitationRequest  { src, buf } => handlers::generate_invitation_request(src, buf, ctx),
            Action::GenerateInvitationResponse { src, buf } => handlers::generate_invitation_response(src, buf, ctx),
            Action::SyncWriteRequest       { src, buf } => handlers::sync_write_request(src, buf, ctx),
            Action::SyncWriteAck           { src, buf } => handlers::sync_write_ack(src, buf, ctx),
            Action::SyncUpdateAvailable    { src, buf } => handlers::sync_update_available(src, buf, ctx),
            Action::SyncPullRequest        { src, buf } => handlers::sync_pull_request(src, buf, ctx),
            Action::SyncPullResponse       { src, buf } => handlers::sync_pull_response(src, buf, ctx),
            Action::CrossUserUpdateAvailable { src, buf } => handlers::cross_user_update_available(src, buf, ctx),
            Action::CrossUserPullRequest     { src, buf } => handlers::cross_user_pull_request(src, buf, ctx),
            Action::CrossUserPullResponse    { src, buf } => handlers::cross_user_pull_response(src, buf, ctx),
            Action::WatermarkProbeRequest    { src, buf } => handlers::watermark_probe_request(src, buf, ctx),
            Action::WatermarkProbeResponse   { src, buf } => handlers::watermark_probe_response(src, buf, ctx),
            Action::MergeProposal            { src, buf } => handlers::merge_proposal(src, buf, ctx),
            Action::MergeAck                 { src, buf } => handlers::merge_ack(src, buf, ctx),
            Action::RelayPacket        { src, buf }   => handlers::relay_packet(src, buf, ctx),
            Action::AppPacket          { src, buf }   => handlers::app_packet(src, buf, ctx),
            Action::TunnelInit           { src, buf } => handlers::tunnel_init(src, buf, ctx),
            Action::TunnelForward        { src, buf } => handlers::tunnel_forward(src, buf, ctx),
            Action::TunnelDelivery       { src, buf } => handlers::tunnel_delivery(src, buf, ctx),
            Action::TunnelConnectRequest { src, buf } => handlers::tunnel_connect_request(src, buf, ctx),
            Action::TunnelConnectAck     { src, buf } => handlers::tunnel_connect_ack(src, buf, ctx),
            Action::PollSG                           => handlers::poll_sg(ctx),
            Action::MaintainConnections              => handlers::maintain_connections(ctx),
            Action::KeepAliveDG                      => handlers::keepalive_dg(ctx),
            Action::CleanupTunnels                   => handlers::cleanup_tunnels(ctx),
            Action::SyncPull                         => handlers::sync_pull(ctx),
            Action::PartitionReconcile               => handlers::partition_reconcile_tick(ctx),
            Action::SetupTunnel { sender_uuid, dest_uuid } => handlers::setup_tunnel(sender_uuid, dest_uuid, ctx),
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

    /// Total actions waiting across all priority buckets.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Enqueue `action` at `priority` (0 = highest).
    ///
    /// Returns `true` if the action is waiting in the queue, `false` if it was
    /// dropped. When at [`QUEUE_CAPACITY`], lower-priority (higher index)
    /// work is discarded first to make room; if nothing lower-priority exists,
    /// the **incoming** action is dropped. Every drop is logged.
    pub fn push(&mut self, priority: u8, action: Action) -> bool {
        assert!(priority <= 7, "priority must be 0–7");

        if self.len() < QUEUE_CAPACITY {
            self.buckets[priority as usize].push(action);
            return true;
        }

        // At capacity: sacrifice lower-priority work (scan from lowest prio up).
        if let Some(drop_prio) = self.lowest_priority_strictly_below(priority) {
            let dropped = self.buckets[drop_prio]
                .pop()
                .expect("bucket non-empty after lowest_priority_strictly_below");
            eprintln!(
                "[queue] drop existing kind={} prio={} to admit kind={} prio={} depth={}/{}",
                dropped.kind_name(),
                drop_prio,
                action.kind_name(),
                priority,
                self.len() + 1, // still full; about to push
                QUEUE_CAPACITY,
            );
            self.buckets[priority as usize].push(action);
            return true;
        }

        eprintln!(
            "[queue] drop incoming kind={} prio={} depth={}/{} (no lower-priority work to shed)",
            action.kind_name(),
            priority,
            self.len(),
            QUEUE_CAPACITY,
        );
        false
    }

    /// Highest bucket index (lowest priority) that is non-empty and strictly
    /// worse than `priority` (numerically greater).
    fn lowest_priority_strictly_below(&self, priority: u8) -> Option<usize> {
        let start = (priority as usize) + 1;
        (start..self.buckets.len())
            .rev()
            .find(|&i| !self.buckets[i].is_empty())
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

    // ── Capacity / drop policy ────────────────────────────────────────────────

    /// Build a full queue using a temporary smaller capacity by filling until
    /// `len() == QUEUE_CAPACITY` would be expensive in tests — instead exercise
    /// the policy with a helper that forces the full path via direct bucket
    /// fills when testing logic unit-style.
    ///
    /// We test against real [`QUEUE_CAPACITY`] but only fill it once in a
    /// dedicated test; smaller synthetic tests use the public API after
    /// pre-filling via many pushes.

    #[test]
    fn push_accepts_until_capacity() {
        let mut q = ActionQueue::new();
        for i in 0..QUEUE_CAPACITY {
            assert!(
                q.push(PRIORITY_LOW, Action::MaintainConnections),
                "push {i} should succeed under capacity"
            );
        }
        assert_eq!(q.len(), QUEUE_CAPACITY);
    }

    #[test]
    fn at_capacity_drop_incoming_when_nothing_lower() {
        let mut q = ActionQueue::new();
        for _ in 0..QUEUE_CAPACITY {
            assert!(q.push(PRIORITY_HIGH, reg()));
        }
        // Queue is all high priority; another high must be dropped.
        assert!(!q.push(PRIORITY_HIGH, upd()));
        assert_eq!(q.len(), QUEUE_CAPACITY);
        // Still only AppRegister items (the dropped Update never entered).
        assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
    }

    #[test]
    fn at_capacity_drop_lower_priority_to_admit_higher() {
        let mut q = ActionQueue::new();
        // Fill with low-priority work.
        for _ in 0..QUEUE_CAPACITY {
            assert!(q.push(PRIORITY_LOW, Action::MaintainConnections));
        }
        // High-priority work must displace a low-priority item.
        assert!(q.push(PRIORITY_HIGH, reg()));
        assert_eq!(q.len(), QUEUE_CAPACITY);

        // First pop is the high-priority admit.
        assert!(matches!(q.pop().unwrap(), Action::AppRegister { .. }));
        // Remaining are still MaintainConnections (one fewer than capacity).
        assert_eq!(q.len(), QUEUE_CAPACITY - 1);
        assert!(matches!(q.pop().unwrap(), Action::MaintainConnections));
    }

    #[test]
    fn at_capacity_prefer_dropping_lowest_of_several_low_buckets() {
        let mut q = ActionQueue::new();
        // Fill: mostly priority 1, one priority 2 at the end of the low end.
        for _ in 0..(QUEUE_CAPACITY - 1) {
            assert!(q.push(PRIORITY_NORMAL, reg()));
        }
        assert!(q.push(2, Action::PollSG));
        assert_eq!(q.len(), QUEUE_CAPACITY);

        // Admit another NORMAL: should shed the priority-2 PollSG, not a NORMAL.
        assert!(q.push(PRIORITY_NORMAL, upd()));
        assert_eq!(q.len(), QUEUE_CAPACITY);

        // Drain all NORMAL-register, then should see Update, never PollSG.
        let mut saw_update = false;
        let mut saw_poll = false;
        while let Some(a) = q.pop() {
            match a {
                Action::AppUpdate { .. } => saw_update = true,
                Action::PollSG => saw_poll = true,
                Action::AppRegister { .. } => {}
                other => panic!("unexpected {:?}", other.kind_name()),
            }
        }
        assert!(saw_update);
        assert!(!saw_poll);
    }

    #[test]
    fn len_tracks_push_and_pop() {
        let mut q = ActionQueue::new();
        assert_eq!(q.len(), 0);
        q.push(0, reg());
        q.push(1, upd());
        assert_eq!(q.len(), 2);
        q.pop();
        assert_eq!(q.len(), 1);
        q.pop();
        assert_eq!(q.len(), 0);
    }
}
