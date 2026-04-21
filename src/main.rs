mod lib;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};

use lib::action_queue::{Action, ActionQueue, WorkerContext, PRIORITY_LOW};
use lib::data_models::DeviceGrade;
use lib::http_server::HttpServer;
use lib::persistence;
use lib::scheduler::SchedulerThread;
use lib::thread_pool::{SharedQueue, ThreadPool};
use lib::udp_listener::{udp_port, UdpListener};
use lib::writer::WriterThread;

const WORKER_COUNT: usize = 4;

fn data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".pnet").join("data")
}

/// Parse the `PNET_HOSTS` env var into an advertised-hostname list.
/// Comma-separated entries with optional `:port` suffix (default 7777).
/// Returns empty vec if unset or contains only whitespace.
fn parse_pnet_hosts() -> Vec<String> {
    std::env::var("PNET_HOSTS")
        .ok()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Overwrite the local device's `hosts` list with the parsed `PNET_HOSTS`
/// entries, if the node is already set up and the local device is SG-grade.
/// Called on every startup — `PNET_HOSTS` is authoritative when set.
fn apply_pnet_hosts(node: &Arc<RwLock<lib::data_models::Node>>, hosts: &[String]) {
    if hosts.is_empty() { return; }
    let mut n = node.write().unwrap();
    if !n.is_initialized() { return; }
    let local_uuid = n.device_uuid;
    let Some(dev) = n.owner.user.devices.iter_mut().find(|d| d.uuid == local_uuid) else { return };
    if !matches!(dev.grade, DeviceGrade::SG) { return; }
    dev.hosts = hosts.to_vec();
}

fn main() {
    // ── 1. Load data from disk ───────────────────────────────────────────────
    let dir = data_dir();
    std::fs::create_dir_all(&dir).expect("could not create data directory");
    let node = Arc::new(RwLock::new(persistence::load(&dir)));

    // ── 1a. Apply PNET_HOSTS (authoritative for the local SG device) ─────────
    let pnet_hosts = parse_pnet_hosts();
    apply_pnet_hosts(&node, &pnet_hosts);
    if !pnet_hosts.is_empty() {
        let toml = persistence::save(&node.read().unwrap());
        std::fs::write(dir.join("node.toml"), &toml)
            .expect("could not persist PNET_HOSTS update");
        println!("[main] PNET_HOSTS applied: {pnet_hosts:?}");
    }

    // ── 2. Start the shared queue ────────────────────────────────────────────
    let queue: SharedQueue = Arc::new((Mutex::new(ActionQueue::new()), Condvar::new()));

    // Stop flag shared by all threads.
    let stop = Arc::new(AtomicBool::new(false));

    // ── 3. Start writer thread ───────────────────────────────────────────────
    let mut writer = WriterThread::start(dir);

    // ── 4. Start scheduler ───────────────────────────────────────────────────
    let (scheduler, scheduler_tx) = SchedulerThread::start(
        Arc::clone(&queue),
        Arc::clone(&stop),
        std::time::Duration::from_secs(1),
    );

    // ── 5. Start UDP listener ────────────────────────────────────────────────
    // Must start before building WorkerContext so workers share the same socket.
    let port = udp_port();
    let udp = UdpListener::start(port, Arc::clone(&queue), Arc::clone(&stop));
    println!("[main] UDP listening on port {}", udp.local_addr.port());

    // ── 6. Build WorkerContext and start worker threads ──────────────────────
    let ctx = Arc::new(WorkerContext {
        node:         Arc::clone(&node),
        udp_socket:   Arc::clone(&udp.socket),
        writer_tx:    writer.sender(),
        scheduler_tx,
    });
    let mut pool = ThreadPool::new(WORKER_COUNT, Arc::clone(&queue), Arc::clone(&stop), ctx);

    // ── 7. Kick off initial connection maintenance ───────────────────────────
    {
        let (lock, cvar) = &*queue;
        lock.lock().unwrap().push(PRIORITY_LOW, Action::MaintainConnections);
        cvar.notify_one();
    }

    // ── 8. Start HTTP server ─────────────────────────────────────────────────
    // SG devices (and uninitialized nodes awaiting setup) bind on all interfaces
    // so the admin UI is reachable. DG devices bind on loopback only.
    let http_bind = {
        let n = node.read().unwrap();
        let is_dg = n.is_initialized() && {
            let device_uuid = n.device_uuid;
            n.owner.user.devices.iter()
                .find(|d| d.uuid == device_uuid)
                .map_or(false, |d| matches!(d.grade, DeviceGrade::DG))
        };
        if is_dg { std::net::Ipv4Addr::LOCALHOST } else { std::net::Ipv4Addr::UNSPECIFIED }
    };
    let http = HttpServer::start(http_bind, 8777, Arc::clone(&queue), Arc::clone(&stop));

    println!("[main] running. HTTP on {http_bind}:8777");

    // ── Wait for SIGINT / SIGTERM ─────────────────────────────────────────────
    ctrlc::set_handler({
        let stop = Arc::clone(&stop);
        move || {
            println!("\n[main] shutdown signal received");
            stop.store(true, Ordering::SeqCst);
        }
    })
    .expect("could not set signal handler");

    while !stop.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // ── Shutdown (reverse startup order) ─────────────────────────────────────

    {
        let (_, cvar) = &*queue;
        cvar.notify_all();
    }

    println!("[main] stopping producers...");
    udp.join();
    http.join();
    scheduler.join();

    println!("[main] draining queue and stopping workers...");
    pool.join();

    println!("[main] stopping writer...");
    writer.join();

    println!("[main] clean shutdown complete.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lib::data_models::Node;
    use std::time::Duration;

    #[test]
    fn full_startup_and_shutdown() {
        let queue: SharedQueue = Arc::new((Mutex::new(ActionQueue::new()), Condvar::new()));
        let stop  = Arc::new(AtomicBool::new(false));
        let node  = Arc::new(RwLock::new(Node::new()));

        let dir = std::env::temp_dir().join("pnet_integration_test");
        std::fs::create_dir_all(&dir).unwrap();
        let mut writer = WriterThread::start(dir);

        let (scheduler, scheduler_tx) = SchedulerThread::start(
            Arc::clone(&queue),
            Arc::clone(&stop),
            Duration::from_millis(10),
        );

        let udp = UdpListener::start(0, Arc::clone(&queue), Arc::clone(&stop));

        let ctx = Arc::new(WorkerContext {
            node,
            udp_socket:   Arc::clone(&udp.socket),
            writer_tx:    writer.sender(),
            scheduler_tx,
        });
        let mut pool = ThreadPool::new(2, Arc::clone(&queue), Arc::clone(&stop), ctx);

        let http = HttpServer::start(std::net::Ipv4Addr::LOCALHOST, 0, Arc::clone(&queue), Arc::clone(&stop));

        stop.store(true, Ordering::SeqCst);
        {
            let (_, cvar) = &*queue;
            cvar.notify_all();
        }

        udp.join();
        http.join();
        scheduler.join();
        pool.join();
        writer.join();
    }
}
