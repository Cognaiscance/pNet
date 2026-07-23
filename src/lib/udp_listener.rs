use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::action_queue::{Action, PRIORITY_HIGH};
use super::app_api::app_api_source_allowed;
use super::thread_pool::SharedQueue;
use super::wire::{
    slice_arr, APP_GET_DATA_OP, APP_PACKET_OP, APP_REGISTER_OP, APP_SEND_PACKET_OP, APP_UPDATE_OP,
    BOOTSTRAP_REQUEST_OP, BOOTSTRAP_RESPONSE_OP, CONNECT_ACK_OP, CONNECT_REQUEST_OP,
    CONTACT_REQUEST_OP, CONTACT_RESPONSE_OP, CONN_RESET_OP, CROSS_USER_PULL_REQUEST_OP,
    CROSS_USER_PULL_RESPONSE_OP, CROSS_USER_UPDATE_AVAILABLE_OP, DEVICE_REGISTER_OP,
    DG_KEEPALIVE_OP, GENERATE_INVITATION_REQUEST_OP, GENERATE_INVITATION_RESPONSE_OP,
    MERGE_ACK_OP, MERGE_PROPOSAL_OP, RELAY_PACKET_OP, SG_PING_OP, SYNC_PULL_REQUEST_OP,
    SYNC_PULL_RESPONSE_OP, SYNC_UPDATE_AVAILABLE_OP, SYNC_WRITE_ACK_OP, SYNC_WRITE_REQUEST_OP,
    TUNNEL_CONNECT_ACK_OP, TUNNEL_CONNECT_REQUEST_OP, TUNNEL_DELIVERY_OP, TUNNEL_FORWARD_OP,
    TUNNEL_INIT_OP, WATERMARK_PROBE_REQUEST_OP, WATERMARK_PROBE_RESPONSE_OP,
};

const READ_TIMEOUT: Duration = Duration::from_millis(100);
const DEFAULT_PORT: u16 = 7777;

pub struct UdpListener {
    /// The address the socket is actually bound to. Useful when port 0 was
    /// requested and the OS assigned an ephemeral port.
    pub local_addr: SocketAddr,
    /// Shared with workers so they can send replies on the same socket.
    pub socket: Arc<UdpSocket>,
    handle: thread::JoinHandle<()>,
}

impl UdpListener {
    pub fn start(port: u16, queue: SharedQueue, stop: Arc<AtomicBool>) -> UdpListener {
        // Bind before spawning so `local_addr` and `socket` are available immediately.
        let addr = format!("0.0.0.0:{port}");
        let socket = Arc::new(
            UdpSocket::bind(&addr)
                .unwrap_or_else(|e| panic!("UDP bind on {addr} failed: {e}")),
        );
        socket
            .set_read_timeout(Some(READ_TIMEOUT))
            .expect("set_read_timeout failed");
        let local_addr = socket.local_addr().unwrap();

        let socket_for_thread = Arc::clone(&socket);
        let handle = thread::spawn(move || {
            let (lock, cvar) = &*queue;
            let mut buf = [0u8; 65535];

            while !stop.load(Ordering::Acquire) {
                let (len, src) = match socket_for_thread.recv_from(&mut buf) {
                    Ok(r) => r,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(e) => {
                        eprintln!("[udp] recv error: {e}");
                        continue;
                    }
                };

                if len == 0 {
                    continue;
                }

                let op = buf[0];
                let payload = buf[1..len].to_vec();

                // Local app control plane (ops 0x00–0x03): loopback-only by
                // default. Peer fabric ops stay open on the public UDP socket.
                // Opt in with PNET_APP_API_REMOTE=1 (e.g. Docker sidecar apps).
                let is_app_api = matches!(
                    op,
                    APP_REGISTER_OP | APP_UPDATE_OP | APP_GET_DATA_OP | APP_SEND_PACKET_OP
                );
                if is_app_api && !app_api_source_allowed(src) {
                    eprintln!(
                        "[udp] drop app op {op:#04x} from non-loopback {src} \
                         (set PNET_APP_API_REMOTE=1 to allow)"
                    );
                    continue;
                }

                let action = match op {
                    APP_REGISTER_OP => Action::AppRegister { src, buf: payload },
                    APP_UPDATE_OP => Action::AppUpdate { src, buf: payload },
                    APP_GET_DATA_OP => Action::AppGetData { src, buf: payload },
                    APP_SEND_PACKET_OP => Action::AppSendPacket { src, buf: payload },
                    SG_PING_OP => {
                        let Some(nonce) = slice_arr::<16>(&payload, 0) else {
                            eprintln!("[udp] sg_ping too short from {src}");
                            continue;
                        };
                        Action::SgPing { src, nonce }
                    }
                    // DG encrypted keepalive: SG verifies the connection is still
                    // live and sends a conn-reset if it isn't.
                    DG_KEEPALIVE_OP => Action::DgKeepalive { src, buf: payload },
                    // SG conn-reset: tells the DG its connection is gone so it
                    // can reconnect immediately.
                    CONN_RESET_OP => Action::ConnReset { src },
                    CONNECT_REQUEST_OP => Action::ConnectRequest { src, buf: payload },
                    CONNECT_ACK_OP => Action::ConnectAck { src, buf: payload },
                    BOOTSTRAP_REQUEST_OP => Action::BootstrapRequest { src, buf: payload },
                    BOOTSTRAP_RESPONSE_OP => Action::BootstrapResponse { src, buf: payload },
                    DEVICE_REGISTER_OP => Action::DeviceRegistration { src, buf: payload },
                    CONTACT_REQUEST_OP => Action::ContactRequest { src, buf: payload },
                    CONTACT_RESPONSE_OP => Action::ContactResponse { src, buf: payload },
                    GENERATE_INVITATION_REQUEST_OP => {
                        Action::GenerateInvitationRequest { src, buf: payload }
                    }
                    GENERATE_INVITATION_RESPONSE_OP => {
                        Action::GenerateInvitationResponse { src, buf: payload }
                    }
                    SYNC_WRITE_REQUEST_OP => Action::SyncWriteRequest { src, buf: payload },
                    SYNC_WRITE_ACK_OP => Action::SyncWriteAck { src, buf: payload },
                    SYNC_UPDATE_AVAILABLE_OP => Action::SyncUpdateAvailable { src, buf: payload },
                    SYNC_PULL_REQUEST_OP => Action::SyncPullRequest { src, buf: payload },
                    SYNC_PULL_RESPONSE_OP => Action::SyncPullResponse { src, buf: payload },
                    CROSS_USER_UPDATE_AVAILABLE_OP => {
                        Action::CrossUserUpdateAvailable { src, buf: payload }
                    }
                    CROSS_USER_PULL_REQUEST_OP => {
                        Action::CrossUserPullRequest { src, buf: payload }
                    }
                    CROSS_USER_PULL_RESPONSE_OP => {
                        Action::CrossUserPullResponse { src, buf: payload }
                    }
                    MERGE_PROPOSAL_OP => Action::MergeProposal { src, buf: payload },
                    MERGE_ACK_OP => Action::MergeAck { src, buf: payload },
                    WATERMARK_PROBE_REQUEST_OP => {
                        Action::WatermarkProbeRequest { src, buf: payload }
                    }
                    WATERMARK_PROBE_RESPONSE_OP => {
                        Action::WatermarkProbeResponse { src, buf: payload }
                    }
                    RELAY_PACKET_OP => Action::RelayPacket { src, buf: payload },
                    APP_PACKET_OP => Action::AppPacket { src, buf: payload },
                    TUNNEL_INIT_OP => Action::TunnelInit { src, buf: payload },
                    TUNNEL_FORWARD_OP => Action::TunnelForward { src, buf: payload },
                    TUNNEL_CONNECT_REQUEST_OP => {
                        Action::TunnelConnectRequest { src, buf: payload }
                    }
                    TUNNEL_CONNECT_ACK_OP => Action::TunnelConnectAck { src, buf: payload },
                    TUNNEL_DELIVERY_OP => Action::TunnelDelivery { src, buf: payload },
                    _ => {
                        eprintln!("[udp] unknown op byte {op} from {src}");
                        continue;
                    }
                };

                let mut guard = lock.lock().unwrap();
                guard.push(PRIORITY_HIGH, action);
                cvar.notify_one();
            }
        });

        UdpListener { local_addr, socket, handle }
    }

    pub fn join(self) {
        self.handle.join().expect("UDP listener thread panicked");
    }
}

pub fn udp_port() -> u16 {
    std::env::var("PNET_UDP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Condvar, Mutex};
    use super::super::action_queue::{Action, ActionQueue};

    fn make_queue() -> SharedQueue {
        Arc::new((Mutex::new(ActionQueue::new()), Condvar::new()))
    }

    fn send_packet(dest: SocketAddr, bytes: &[u8]) {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(bytes, dest).unwrap();
    }

    #[test]
    fn op_bytes_map_to_correct_action_variants() {
        let cases: &[(u8, fn(&Action) -> bool)] = &[
            (0x00, |a| matches!(a, Action::AppRegister      { .. })),
            (0x01, |a| matches!(a, Action::AppUpdate        { .. })),
            (0x02, |a| matches!(a, Action::AppGetData       { .. })),
            (0x03, |a| matches!(a, Action::AppSendPacket    { .. })),
            (0x10, |a| matches!(a, Action::SgPing           { .. })),
            (0x20, |a| matches!(a, Action::ConnectRequest   { .. })),
            (0x21, |a| matches!(a, Action::ConnectAck       { .. })),
            (0x30, |a| matches!(a, Action::BootstrapRequest   { .. })),
            (0x31, |a| matches!(a, Action::BootstrapResponse  { .. })),
            (0x32, |a| matches!(a, Action::DeviceRegistration { .. })),
            (0x35, |a| matches!(a, Action::GenerateInvitationRequest  { .. })),
            (0x36, |a| matches!(a, Action::GenerateInvitationResponse { .. })),
            (0x70, |a| matches!(a, Action::SyncWriteRequest      { .. })),
            (0x71, |a| matches!(a, Action::SyncWriteAck          { .. })),
            (0x72, |a| matches!(a, Action::SyncUpdateAvailable   { .. })),
            (0x73, |a| matches!(a, Action::SyncPullRequest       { .. })),
            (0x74, |a| matches!(a, Action::SyncPullResponse      { .. })),
        ];

        for (op, check) in cases {
            let queue = make_queue();
            let stop = Arc::new(AtomicBool::new(false));
            let udp = UdpListener::start(0, Arc::clone(&queue), Arc::clone(&stop));

            // SgPing requires op + 16-byte nonce; other ops are fine with a short payload.
            let packet: Vec<u8> = if *op == 0x10 {
                let mut p = vec![*op];
                p.extend_from_slice(&[0u8; 16]);
                p
            } else {
                vec![*op, 0xAA, 0xBB]
            };
            send_packet(udp.local_addr, &packet);

            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            loop {
                {
                    let (lock, _) = &*queue;
                    let mut guard = lock.lock().unwrap();
                    if let Some(action) = guard.pop() {
                        assert!(check(&action), "wrong variant for op {op}");
                        break;
                    }
                }
                assert!(std::time::Instant::now() < deadline, "timed out for op {op}");
                std::thread::sleep(Duration::from_millis(10));
            }

            stop.store(true, Ordering::SeqCst);
            udp.join();
        }
    }

    #[test]
    fn unknown_op_byte_is_ignored() {
        let queue = make_queue();
        let stop = Arc::new(AtomicBool::new(false));
        let udp = UdpListener::start(0, Arc::clone(&queue), Arc::clone(&stop));

        send_packet(udp.local_addr, &[0xFF, 0x01]);
        std::thread::sleep(Duration::from_millis(150));

        let (lock, _) = &*queue;
        assert!(lock.lock().unwrap().is_empty(), "unknown op should be dropped");

        stop.store(true, Ordering::SeqCst);
        udp.join();
    }

    #[test]
    fn stop_signal_exits_cleanly() {
        let queue = make_queue();
        let stop = Arc::new(AtomicBool::new(false));
        let udp = UdpListener::start(0, Arc::clone(&queue), Arc::clone(&stop));

        stop.store(true, Ordering::SeqCst);
        udp.join();
    }
}
