pub struct Action {
    pub name: String,
    pub id: String,
    pub handler: Box<dyn FnOnce() + Send + 'static>,
}

pub struct ActionQueue {
    buckets: [Vec<Action>; 8],
}

impl ActionQueue {
    pub fn new() -> Self {
        ActionQueue {
            buckets: Default::default(),
        }
    }

    pub fn push(&mut self, priority: u8, action: Action) {
        assert!(priority <= 7, "priority must be 0–7");
        self.buckets[priority as usize].push(action);
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|b| b.is_empty())
    }

    pub fn pop(&mut self) -> Option<Action> {
        for bucket in &mut self.buckets {
            if !bucket.is_empty() {
                return Some(bucket.remove(0));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(name: &str) -> Action {
        Action { name: name.to_string(), id: name.to_string(), handler: Box::new(|| {}) }
    }

    #[test]
    fn pop_empty_returns_none() {
        let mut q = ActionQueue::new();
        assert!(q.pop().is_none());
    }

    #[test]
    fn push_and_pop_single() {
        let mut q = ActionQueue::new();
        q.push(0, action("a"));
        assert_eq!(q.pop().unwrap().name, "a");
        assert!(q.pop().is_none());
    }

    #[test]
    fn lower_priority_popped_first() {
        let mut q = ActionQueue::new();
        q.push(3, action("low"));
        q.push(0, action("high"));
        assert_eq!(q.pop().unwrap().name, "high");
        assert_eq!(q.pop().unwrap().name, "low");
    }

    #[test]
    fn fifo_within_same_priority() {
        let mut q = ActionQueue::new();
        q.push(1, action("first"));
        q.push(1, action("second"));
        assert_eq!(q.pop().unwrap().name, "first");
        assert_eq!(q.pop().unwrap().name, "second");
    }

    #[test]
    fn drains_bucket_before_next() {
        let mut q = ActionQueue::new();
        q.push(0, action("a0"));
        q.push(0, action("b0"));
        q.push(1, action("a1"));
        assert_eq!(q.pop().unwrap().name, "a0");
        assert_eq!(q.pop().unwrap().name, "b0");
        assert_eq!(q.pop().unwrap().name, "a1");
    }

    #[test]
    #[should_panic]
    fn push_invalid_priority_panics() {
        let mut q = ActionQueue::new();
        q.push(8, action("bad"));
    }
}
