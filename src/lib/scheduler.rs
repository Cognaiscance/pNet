use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::action_queue::{Action, ScheduleRequest, PRIORITY_LOW};
use super::thread_pool::SharedQueue;

const POLL_SG_INTERVAL:              Duration = Duration::from_secs(30);
const MAINTAIN_CONNECTIONS_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Must be safely under the typical 30-second UDP NAT mapping timeout.
const KEEPALIVE_DG_INTERVAL:         Duration = Duration::from_secs(20);
const CLEANUP_TUNNELS_INTERVAL:      Duration = Duration::from_secs(5 * 60);
const SYNC_CONTACTS_INTERVAL:        Duration = Duration::from_secs(24 * 3600);

pub struct SchedulerThread {
    handle: thread::JoinHandle<()>,
}

impl SchedulerThread {
    /// Start the scheduler thread. Returns the thread handle and a sender that
    /// action handlers can use to schedule one-shot future work.
    ///
    /// `tick` controls how often the scheduler wakes to check for due jobs.
    /// Pass `Duration::from_secs(1)` in production and a short duration in tests.
    pub fn start(
        queue: SharedQueue,
        stop: Arc<AtomicBool>,
        tick: Duration,
    ) -> (SchedulerThread, mpsc::Sender<ScheduleRequest>) {
        let (tx, rx) = mpsc::channel::<ScheduleRequest>();

        let handle = thread::spawn(move || {
            let (lock, cvar) = &*queue;

            let mut last_poll_sg         = Instant::now();
            let mut last_maintain        = Instant::now();
            let mut last_keepalive       = Instant::now();
            let mut last_cleanup_tunnels = Instant::now();
            let mut last_sync_contacts   = Instant::now();
            let mut pending: Vec<(Instant, Action)> = Vec::new();

            while !stop.load(Ordering::Acquire) {
                thread::sleep(tick);

                let now = Instant::now();

                // Pick up any new one-shot requests from action handlers.
                while let Ok(req) = rx.try_recv() {
                    pending.push((now + req.delay, req.action));
                }

                let mut to_enqueue: Vec<Action> = Vec::new();

                // Recurring jobs.
                if now.duration_since(last_poll_sg) >= POLL_SG_INTERVAL {
                    to_enqueue.push(Action::PollSG);
                    last_poll_sg = now;
                }
                if now.duration_since(last_maintain) >= MAINTAIN_CONNECTIONS_INTERVAL {
                    to_enqueue.push(Action::MaintainConnections);
                    last_maintain = now;
                }
                if now.duration_since(last_keepalive) >= KEEPALIVE_DG_INTERVAL {
                    to_enqueue.push(Action::KeepAliveDG);
                    last_keepalive = now;
                }
                if now.duration_since(last_cleanup_tunnels) >= CLEANUP_TUNNELS_INTERVAL {
                    to_enqueue.push(Action::CleanupTunnels);
                    last_cleanup_tunnels = now;
                }
                if now.duration_since(last_sync_contacts) >= SYNC_CONTACTS_INTERVAL {
                    to_enqueue.push(Action::SyncContacts);
                    last_sync_contacts = now;
                }

                // One-shot pending jobs — drain those that are due.
                let mut remaining = Vec::new();
                for (due_at, action) in pending.drain(..) {
                    if now >= due_at {
                        to_enqueue.push(action);
                    } else {
                        remaining.push((due_at, action));
                    }
                }
                pending = remaining;

                if !to_enqueue.is_empty() {
                    let mut guard = lock.lock().unwrap();
                    for action in to_enqueue {
                        guard.push(PRIORITY_LOW, action);
                    }
                    cvar.notify_all();
                }
            }
        });

        (SchedulerThread { handle }, tx)
    }

    pub fn join(self) {
        self.handle.join().expect("scheduler thread panicked");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Condvar, Mutex};
    use super::super::action_queue::{Action, ActionQueue, ScheduleRequest};

    fn make_queue() -> SharedQueue {
        Arc::new((Mutex::new(ActionQueue::new()), Condvar::new()))
    }

    #[test]
    fn one_shot_request_fires_after_delay() {
        let queue = make_queue();
        let stop = Arc::new(AtomicBool::new(false));
        let (scheduler, tx) = SchedulerThread::start(
            Arc::clone(&queue),
            Arc::clone(&stop),
            Duration::from_millis(10),
        );

        tx.send(ScheduleRequest {
            action: Action::MaintainConnections,
            delay:  Duration::from_millis(20),
        })
        .unwrap();

        // Wait long enough for at least one tick after the delay elapses.
        std::thread::sleep(Duration::from_millis(100));

        let (lock, _) = &*queue;
        let guard = lock.lock().unwrap();
        assert!(!guard.is_empty(), "action should have been enqueued by now");

        stop.store(true, Ordering::SeqCst);
        drop(guard);
        scheduler.join();
    }

    #[test]
    fn stop_signal_exits_cleanly() {
        let queue = make_queue();
        let stop = Arc::new(AtomicBool::new(false));
        let (scheduler, _tx) = SchedulerThread::start(
            Arc::clone(&queue),
            Arc::clone(&stop),
            Duration::from_millis(10),
        );

        stop.store(true, Ordering::SeqCst);
        scheduler.join(); // must return without deadlocking
    }
}
