use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::thread_pool::SharedQueue;

const HTTP_ADDR: &str = "127.0.0.1:8080";

pub struct HttpServer {
    handle: thread::JoinHandle<()>,
}

impl HttpServer {
    pub fn start(queue: SharedQueue, stop: Arc<AtomicBool>) -> HttpServer {
        let handle = thread::spawn(move || {
            let listener = TcpListener::bind(HTTP_ADDR)
                .unwrap_or_else(|e| panic!("HTTP bind on {HTTP_ADDR} failed: {e}"));
            listener
                .set_nonblocking(true)
                .expect("set_nonblocking failed");

            let _ = queue; // TODO: enqueue PRIORITY_NORMAL actions for each request

            while !stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((_stream, _addr)) => {
                        // TODO: parse HTTP request and enqueue as Action at PRIORITY_NORMAL
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        eprintln!("[http] accept error: {e}");
                    }
                }
            }
        });

        HttpServer { handle }
    }

    pub fn join(self) {
        self.handle.join().expect("HTTP server thread panicked");
    }
}
