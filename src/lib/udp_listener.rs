use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::action_queue::{Action, PRIORITY_HIGH};
use super::thread_pool::SharedQueue;

const READ_TIMEOUT: Duration = Duration::from_millis(100);
const DEFAULT_PORT: u16 = 7777;

pub struct UdpListener {
    /// The address the socket is actually bound to. Useful when port 0 was
    /// requested and the OS assigned an ephemeral port.
    pub local_addr: SocketAddr,
    handle: thread::JoinHandle<()>,
}

impl UdpListener {
    pub fn start(port: u16, queue: SharedQueue, stop: Arc<AtomicBool>) -> UdpListener {
        // Bind before spawning so callers can read `local_addr` immediately.
        let addr = format!("0.0.0.0:{port}");
        let socket = UdpSocket::bind(&addr)
            .unwrap_or_else(|e| panic!("UDP bind on {addr} failed: {e}"));
        socket
            .set_read_timeout(Some(READ_TIMEOUT))
            .expect("set_read_timeout failed");
        let local_addr = socket.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (lock, cvar) = &*queue;
            let mut buf = [0u8; 512];

            while !stop.load(Ordering::Acquire) {
                let (len, src) = match socket.recv_from(&mut buf) {
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

                let action = match op {
                    0 => Action::AppRegister   { src, buf: payload },
                    1 => Action::AppUpdate     { src, buf: payload },
                    2 => Action::AppGetData    { src, buf: payload },
                    3 => Action::AppSendPacket { src, buf: payload },
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

        UdpListener { local_addr, handle }
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
            (0, |a| matches!(a, Action::AppRegister   { .. })),
            (1, |a| matches!(a, Action::AppUpdate     { .. })),
            (2, |a| matches!(a, Action::AppGetData    { .. })),
            (3, |a| matches!(a, Action::AppSendPacket { .. })),
        ];

        for (op, check) in cases {
            let queue = make_queue();
            let stop = Arc::new(AtomicBool::new(false));
            let udp = UdpListener::start(0, Arc::clone(&queue), Arc::clone(&stop));

            send_packet(udp.local_addr, &[*op, 0xAA, 0xBB]);

            // Poll until the action appears (up to 500 ms).
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
        std::thread::sleep(Duration::from_millis(150)); // one read-timeout cycle

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
        udp.join(); // must return without deadlocking
    }
}
