mod lib;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use lib::action_queue::{ActionQueue, WorkerContext};
use lib::http_server::HttpServer;
use lib::scheduler::SchedulerThread;
use lib::thread_pool::{SharedQueue, ThreadPool};
use lib::udp_listener::{udp_port, UdpListener};
use lib::writer::WriterThread;

const WORKER_COUNT: usize = 4;

fn data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".pnet").join("data")
}

fn main() {
    // ── 1. Load data from disk ───────────────────────────────────────────────
    // TODO: deserialize TOML files from data_dir() into data_models::Node,
    //       wrap in Arc<RwLock<Node>>, and pass into WorkerContext.
    println!("[main] loading data...");

    // ── 2. Start the shared queue ────────────────────────────────────────────
    let queue: SharedQueue = Arc::new((Mutex::new(ActionQueue::new()), Condvar::new()));

    // Stop flag shared by all threads.
    let stop = Arc::new(AtomicBool::new(false));

    // ── 3. Start writer thread ───────────────────────────────────────────────
    let dir = data_dir();
    std::fs::create_dir_all(&dir).expect("could not create data directory");
    let mut writer = WriterThread::start(dir);

    // ── 4. Start scheduler — gives us the sender for WorkerContext ───────────
    let (scheduler, scheduler_tx) = SchedulerThread::start(
        Arc::clone(&queue),
        Arc::clone(&stop),
        std::time::Duration::from_secs(1),
    );

    // ── 5. Build worker context, then start worker threads ───────────────────
    let ctx = Arc::new(WorkerContext { scheduler_tx });
    let mut pool = ThreadPool::new(WORKER_COUNT, Arc::clone(&queue), Arc::clone(&stop), ctx);

    // ── 6. Start UDP listener ────────────────────────────────────────────────
    let port = udp_port();
    let udp = UdpListener::start(port, Arc::clone(&queue), Arc::clone(&stop));

    // ── 7. Start HTTP server ─────────────────────────────────────────────────
    let http = HttpServer::start(8080, Arc::clone(&queue), Arc::clone(&stop));

    println!("[main] running. UDP port {port}, HTTP on 127.0.0.1:8080");

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

    // Wake all workers sleeping on an empty queue so they see stop=true and exit.
    {
        let (_, cvar) = &*queue;
        cvar.notify_all();
    }

    // Stop producers: UDP listener, HTTP server, scheduler.
    println!("[main] stopping producers...");
    udp.join();
    http.join();
    scheduler.join();

    // Workers drain the queue then exit (stop=true AND queue empty).
    println!("[main] draining queue and stopping workers...");
    pool.join();

    // Drop the writer sender; writer drains remaining writes and exits.
    println!("[main] stopping writer...");
    writer.join();

    println!("[main] clean shutdown complete.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Smoke test: bring up all components and shut them down cleanly.
    /// Verifies there are no deadlocks or panics in the startup/shutdown sequence.
    #[test]
    fn full_startup_and_shutdown() {
        let queue: SharedQueue = Arc::new((Mutex::new(ActionQueue::new()), Condvar::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let dir = std::env::temp_dir().join("pnet_integration_test");
        std::fs::create_dir_all(&dir).unwrap();
        let mut writer = WriterThread::start(dir);

        let (scheduler, scheduler_tx) = SchedulerThread::start(
            Arc::clone(&queue),
            Arc::clone(&stop),
            Duration::from_millis(10),
        );

        let ctx = Arc::new(WorkerContext { scheduler_tx });
        let mut pool = ThreadPool::new(2, Arc::clone(&queue), Arc::clone(&stop), ctx);

        // Use port 0 so the OS assigns ephemeral ports — no conflicts.
        let udp  = UdpListener::start(0, Arc::clone(&queue), Arc::clone(&stop));
        let http = HttpServer::start(0, Arc::clone(&queue), Arc::clone(&stop));

        // Signal stop immediately.
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
