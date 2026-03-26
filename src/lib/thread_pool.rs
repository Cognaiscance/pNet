use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use super::action_queue::{ActionQueue, WorkerContext};

pub type SharedQueue = Arc<(Mutex<ActionQueue>, Condvar)>;

pub struct ThreadPool {
    workers: Vec<Worker>,
}

impl ThreadPool {
    pub fn new(
        size: usize,
        queue: SharedQueue,
        stop: Arc<AtomicBool>,
        ctx: Arc<WorkerContext>,
    ) -> ThreadPool {
        assert!(size > 0);
        let mut workers = Vec::with_capacity(size);
        for id in 0..size {
            workers.push(Worker::new(
                id,
                Arc::clone(&queue),
                Arc::clone(&stop),
                Arc::clone(&ctx),
            ));
        }
        ThreadPool { workers }
    }

    /// Wait for all workers to drain the queue and exit.
    /// Caller must have already set the stop flag and called `cvar.notify_all()`.
    pub fn join(&mut self) {
        for worker in self.workers.drain(..) {
            worker.thread.join().expect("worker thread panicked");
        }
    }
}

struct Worker {
    id: usize,
    thread: thread::JoinHandle<()>,
}

impl Worker {
    fn new(
        id: usize,
        queue: SharedQueue,
        stop: Arc<AtomicBool>,
        ctx: Arc<WorkerContext>,
    ) -> Worker {
        let thread = thread::spawn(move || {
            let (lock, cvar) = &*queue;
            let mut guard = lock.lock().unwrap();

            loop {
                // Sleep while queue is empty and stop hasn't been signalled.
                while guard.is_empty() && !stop.load(Ordering::Acquire) {
                    guard = cvar.wait(guard).unwrap();
                }

                // Exit when stopped and nothing left to process.
                if guard.is_empty() {
                    return;
                }

                let action = guard.pop().unwrap();
                drop(guard);

                action.dispatch(&ctx);

                guard = lock.lock().unwrap();
            }
        });

        Worker { id, thread }
    }
}
