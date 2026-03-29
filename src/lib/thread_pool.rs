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

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::action_queue::{Action, ActionQueue, WorkerContext};

    fn make_queue() -> SharedQueue {
        Arc::new((Mutex::new(ActionQueue::new()), Condvar::new()))
    }

    fn make_ctx() -> Arc<WorkerContext> {
        use std::net::UdpSocket;
        use std::sync::RwLock;
        use super::super::data_models::Node;
        use super::super::writer::WriteRequest;

        let (scheduler_tx, _sched_rx) = std::sync::mpsc::channel();
        let (writer_tx, _writer_rx)   = std::sync::mpsc::sync_channel::<WriteRequest>(16);
        Arc::new(WorkerContext {
            node:         Arc::new(RwLock::new(Node::new())),
            udp_socket:   Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap()),
            writer_tx,
            scheduler_tx,
        })
    }

    fn stop_and_wake(stop: &Arc<AtomicBool>, queue: &SharedQueue) {
        stop.store(true, Ordering::SeqCst);
        let (_, cvar) = &**queue;
        cvar.notify_all();
    }

    #[test]
    fn workers_drain_queue_before_stopping() {
        let queue = make_queue();
        let stop = Arc::new(AtomicBool::new(false));
        let mut pool = ThreadPool::new(2, Arc::clone(&queue), Arc::clone(&stop), make_ctx());

        {
            let (lock, cvar) = &*queue;
            let mut guard = lock.lock().unwrap();
            for _ in 0..20 {
                guard.push(0, Action::MaintainConnections);
            }
            cvar.notify_all();
        }

        stop_and_wake(&stop, &queue);
        pool.join();

        let (lock, _) = &*queue;
        assert!(lock.lock().unwrap().is_empty());
    }

    #[test]
    fn workers_exit_on_empty_queue_with_stop_signal() {
        let queue = make_queue();
        let stop = Arc::new(AtomicBool::new(false));
        let mut pool = ThreadPool::new(2, Arc::clone(&queue), Arc::clone(&stop), make_ctx());

        stop_and_wake(&stop, &queue);
        pool.join(); // must return without deadlocking
    }
}
