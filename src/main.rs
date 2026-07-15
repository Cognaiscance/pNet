mod lib;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};

use lib::action_queue::{Action, ActionQueue, WorkerContext, PRIORITY_LOW};
use lib::data_models::DeviceGrade;
use lib::handlers::{apply_new_user_setup, parse_pnet_hosts, start_bootstrap};
use lib::http_server::{http_bind_ip, http_port, HttpServer};
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

/// Overwrite the local device's `hosts` list with the parsed `PNET_HOSTS`
/// entries, if the node is already set up and the local device is SG-grade.
/// Called on every startup — `PNET_HOSTS` is authoritative when set.
/// On fresh containers, `complete_setup` re-applies after initialization.
fn apply_pnet_hosts(node: &Arc<RwLock<lib::data_models::Node>>, hosts: &[String]) {
    if hosts.is_empty() { return; }
    let mut n = node.write().unwrap();
    if !n.is_initialized() { return; }
    let local_uuid = n.device_uuid;
    let Some(dev) = n.owner.user.devices.iter_mut().find(|d| d.uuid == local_uuid) else { return };
    if !matches!(dev.grade, DeviceGrade::SG) { return; }
    dev.hosts = hosts.to_vec();
}

/// Drive first-run setup from environment variables when the container is
/// started headless (no admin UI access). Reads:
///
///   PNET_GRADE             "sg" | "dg" — selects SG-new vs join path
///   PNET_DEVICE_ALIAS      Always required.
///   PNET_USER_ALIAS        SG-new only (no PNET_INVITATION_CODE).
///   PNET_SG_RANK           SG only — defaults to 1.
///   PNET_INVITATION_CODE   Required for SG-join and DG; absent for SG-new.
///   PNET_HOSTS             Required for SG-new and SG-join.
///
/// No-op if the node is already initialized or `PNET_GRADE` is unset. For the
/// join path, sends the BootstrapRequest immediately and lets the existing
/// async response handler complete initialization.
fn apply_env_setup(ctx: &WorkerContext) {
    if ctx.node.read().unwrap().is_initialized() { return; }
    let Ok(grade_str) = std::env::var("PNET_GRADE") else { return };

    let grade = match grade_str.to_ascii_lowercase().as_str() {
        "sg" => DeviceGrade::SG,
        "dg" => DeviceGrade::DG,
        other => {
            eprintln!("[apply_env_setup] PNET_GRADE={other:?} not recognized; expected 'sg' or 'dg'");
            return;
        }
    };

    let device_alias = std::env::var("PNET_DEVICE_ALIAS").unwrap_or_default();
    if device_alias.trim().is_empty() {
        eprintln!("[apply_env_setup] PNET_DEVICE_ALIAS is required");
        return;
    }

    let sg_rank = if matches!(grade, DeviceGrade::SG) {
        Some(std::env::var("PNET_SG_RANK")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(1)
            .max(1))
    } else {
        None
    };

    let invitation_code = std::env::var("PNET_INVITATION_CODE").ok();
    match invitation_code {
        Some(code) if !code.trim().is_empty() => {
            // SG-join or DG-join path.
            if let Err(e) = start_bootstrap(device_alias.trim(), code.trim(), grade, sg_rank, ctx) {
                eprintln!("[apply_env_setup] bootstrap failed: {e}");
                return;
            }
            println!("[apply_env_setup] bootstrap request sent; waiting for SG acceptance");
        }
        _ => {
            // SG-new path — must be SG, must have user alias.
            if !matches!(grade, DeviceGrade::SG) {
                eprintln!("[apply_env_setup] PNET_GRADE=dg requires PNET_INVITATION_CODE");
                return;
            }
            let user_alias = std::env::var("PNET_USER_ALIAS").unwrap_or_default();
            if user_alias.trim().is_empty() {
                eprintln!("[apply_env_setup] PNET_USER_ALIAS is required for SG-new setup");
                return;
            }
            if let Some(err) = apply_new_user_setup(
                user_alias.trim(),
                device_alias.trim(),
                grade,
                sg_rank,
                ctx,
            ) {
                eprintln!("[apply_env_setup] new-user setup failed: {err}");
                return;
            }
            println!("[apply_env_setup] new-user SG setup complete");
        }
    }
}

/// If `PNET_ADMIN_PASSWORD` is set and the node has no admin hash yet, store it.
/// Used by headless deploys so the UI is not left passwordless after env setup.
fn apply_env_admin_password(ctx: &WorkerContext) {
    let Ok(password) = std::env::var("PNET_ADMIN_PASSWORD") else { return };
    if password.is_empty() { return; }
    {
        let node = ctx.node.read().unwrap();
        if node.admin_password_hash.is_some() { return; }
    }
    if password.len() < lib::admin_auth::MIN_PASSWORD_LEN {
        eprintln!(
            "[apply_env_admin_password] PNET_ADMIN_PASSWORD shorter than {} chars; ignored",
            lib::admin_auth::MIN_PASSWORD_LEN
        );
        return;
    }
    let hash = lib::admin_auth::hash_password(&password);
    ctx.node.write().unwrap().admin_password_hash = Some(hash);
    ctx.save_node();
    println!("[apply_env_admin_password] admin password hash stored from env");
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
        pending_invites: Default::default(),
        sessions:     Arc::new(lib::admin_auth::SessionStore::new()),
    });

    // ── 6a. Headless env-driven first-run setup, if requested ────────────────
    apply_env_setup(&ctx);
    // Optional admin password for headless / first boot (also used when the
    // node was already initialized without a hash — sets it if still missing).
    apply_env_admin_password(&ctx);

    let mut pool = ThreadPool::new(WORKER_COUNT, Arc::clone(&queue), Arc::clone(&stop), Arc::clone(&ctx));

    // ── 7. Kick off initial connection maintenance ───────────────────────────
    {
        let (lock, cvar) = &*queue;
        lock.lock().unwrap().push(PRIORITY_LOW, Action::MaintainConnections);
        cvar.notify_one();
    }

    // ── 8. Start HTTP server ─────────────────────────────────────────────────
    // Default bind is loopback for all grades (SG and DG). Opt into remote admin
    // with PNET_HTTP_BIND=0.0.0.0 (or another IPv4). Docker / live harnesses that
    // publish the admin port must set this explicitly.
    let http_bind = http_bind_ip();
    let hport = http_port();
    let http = HttpServer::start(http_bind, hport, Arc::clone(&queue), Arc::clone(&stop));

    println!("[main] running. HTTP on {http_bind}:{hport}");

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

    // Drop the last `WorkerContext` Arc before joining the writer. The writer
    // thread exits only when every `writer_tx` clone is dropped (its recv()
    // returns Err on channel close). `WorkerContext` holds one such clone; the
    // workers' Arc clones are gone once `pool.join()` returns, but `main` still
    // holds the original `ctx` here — so without this drop, `writer.join()`
    // blocks forever and SIGTERM never completes a clean shutdown.
    drop(ctx);

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
            pending_invites: Default::default(),
            sessions:     Arc::new(crate::lib::admin_auth::SessionStore::new()),
        });
        // Retain `ctx` in this scope via Arc::clone, exactly as `main` does.
        // This is what makes the test faithful: the lingering `WorkerContext`
        // holds a `writer_tx` clone, so the shutdown sequence MUST drop `ctx`
        // before `writer.join()` or the writer channel never closes and the
        // join hangs (the SIGTERM hang). Moving `ctx` into the pool would hide
        // the bug.
        let mut pool = ThreadPool::new(2, Arc::clone(&queue), Arc::clone(&stop), Arc::clone(&ctx));

        let http = HttpServer::start(std::net::Ipv4Addr::LOCALHOST, 0, Arc::clone(&queue), Arc::clone(&stop));

        stop.store(true, Ordering::SeqCst);
        {
            let (_, cvar) = &*queue;
            cvar.notify_all();
        }

        // Run shutdown in a watched thread: a regression here would otherwise
        // hang the whole test binary, so bound it with a timeout and fail loudly.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let shutdown = std::thread::spawn(move || {
            udp.join();
            http.join();
            scheduler.join();
            pool.join();
            drop(ctx); // release the last WorkerContext → closes the writer_tx clone
            writer.join();
            done_tx.send(()).unwrap();
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("shutdown hung — writer.join blocked on a live writer_tx clone");
        shutdown.join().unwrap();
    }
}
