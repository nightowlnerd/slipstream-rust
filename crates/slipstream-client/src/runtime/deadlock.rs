pub(crate) struct AcceptorSaturationTracker {
    saturated_since: u64,
    saturated_max: usize,
    saturated_bytes: u64,
    timeout_us: u64,
}

#[cfg(test)]
mod tests {
    use super::AcceptorSaturationTracker;

    #[test]
    fn does_not_trigger_before_timeout() {
        let mut tracker = AcceptorSaturationTracker::new(30);
        assert!(!tracker.update(10, 10, 10, 100));
        assert!(!tracker.update(35, 10, 10, 100));
    }

    #[test]
    fn triggers_after_timeout_with_no_progress() {
        let mut tracker = AcceptorSaturationTracker::new(30);
        assert!(!tracker.update(10, 10, 10, 100));
        assert!(tracker.update(40, 10, 10, 100));
    }

    #[test]
    fn resets_when_progress_changes() {
        let mut tracker = AcceptorSaturationTracker::new(30);
        assert!(!tracker.update(10, 10, 10, 100));
        assert!(!tracker.update(25, 10, 10, 200));
        assert!(!tracker.update(40, 10, 10, 200));
        assert!(tracker.update(56, 10, 10, 200));
    }

    #[test]
    fn clears_when_no_longer_saturated() {
        let mut tracker = AcceptorSaturationTracker::new(30);
        assert!(!tracker.update(10, 10, 10, 100));
        assert!(!tracker.update(20, 5, 10, 100));
        assert!(!tracker.update(40, 10, 10, 100));
    }
}

impl AcceptorSaturationTracker {
    pub(crate) fn new(timeout_us: u64) -> Self {
        Self {
            saturated_since: 0,
            saturated_max: 0,
            saturated_bytes: 0,
            timeout_us,
        }
    }

    pub(crate) fn timeout_us(&self) -> u64 {
        self.timeout_us
    }

    pub(crate) fn update(&mut self, now: u64, used: usize, max: usize, total_bytes: u64) -> bool {
        if max == 0 || used < max {
            self.saturated_since = 0;
            return false;
        }

        if self.saturated_since == 0
            || max != self.saturated_max
            || total_bytes != self.saturated_bytes
        {
            self.saturated_since = now;
            self.saturated_max = max;
            self.saturated_bytes = total_bytes;
            return false;
        }

        now.saturating_sub(self.saturated_since) >= self.timeout_us
    }
}
