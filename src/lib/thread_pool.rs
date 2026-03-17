use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use super::action_queue::ActionQueue;

pub type SharedQueue = Arc<(Mutex<ActionQueue>, Condvar)>;

pub struct ThreadPool {
    workers: Vec<Worker>,
}

impl ThreadPool {
    pub fn new(size: usize, queue: SharedQueue) -> ThreadPool {
        assert!(size > 0);

        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&queue)));
        }

        ThreadPool { workers }
    }
}

struct Worker {
    id: usize,
    thread: thread::JoinHandle<()>,
}

impl Worker {
    fn new(id: usize, queue: SharedQueue) -> Worker {
        let thread = thread::spawn(move || {
            let (lock, cvar) = &*queue;
            let mut guard = lock.lock().unwrap();

            loop {
                while guard.is_empty() {
                    guard = cvar.wait(guard).unwrap();
                }

                let action = guard.pop().unwrap();
                drop(guard);

                (action.handler)();

                guard = lock.lock().unwrap();
            }
        });

        Worker { id, thread }
    }
}
