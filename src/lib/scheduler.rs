use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::action_queue::{Action, PRIORITY_LOW};
use super::thread_pool::SharedQueue;

const TICK:                  Duration = Duration::from_secs(1);
const HEARTBEAT_INTERVAL:    Duration = Duration::from_secs(60);
const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(30);

pub struct SchedulerThread {
    handle: thread::JoinHandle<()>,
}

impl SchedulerThread {
    pub fn start(queue: SharedQueue, stop: Arc<AtomicBool>) -> SchedulerThread {
        let handle = thread::spawn(move || {
            let (lock, cvar) = &*queue;

            let mut last_heartbeat    = Instant::now();
            let mut last_key_rotation = Instant::now();

            while !stop.load(Ordering::Acquire) {
                thread::sleep(TICK);

                let now = Instant::now();
                let mut due: Vec<Action> = Vec::new();

                if now.duration_since(last_heartbeat) >= HEARTBEAT_INTERVAL {
                    due.push(Action::Heartbeat);
                    last_heartbeat = now;
                }
                if now.duration_since(last_key_rotation) >= KEY_ROTATION_INTERVAL {
                    due.push(Action::KeyRotation);
                    last_key_rotation = now;
                }

                if !due.is_empty() {
                    let mut guard = lock.lock().unwrap();
                    for action in due {
                        guard.push(PRIORITY_LOW, action);
                    }
                    cvar.notify_all();
                }
            }
        });

        SchedulerThread { handle }
    }

    pub fn join(self) {
        self.handle.join().expect("scheduler thread panicked");
    }
}
