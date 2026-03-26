use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::action_queue::{Action, PRIORITY_HIGH};
use super::thread_pool::SharedQueue;

const READ_TIMEOUT: Duration = Duration::from_millis(100);
const DEFAULT_PORT: u16 = 7777;

pub struct UdpListener {
    handle: thread::JoinHandle<()>,
}

impl UdpListener {
    pub fn start(port: u16, queue: SharedQueue, stop: Arc<AtomicBool>) -> UdpListener {
        let handle = thread::spawn(move || {
            let addr = format!("0.0.0.0:{port}");
            let socket = UdpSocket::bind(&addr)
                .unwrap_or_else(|e| panic!("UDP bind on {addr} failed: {e}"));
            socket
                .set_read_timeout(Some(READ_TIMEOUT))
                .expect("set_read_timeout failed");

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

        UdpListener { handle }
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
