use std::time::Duration;

pub(crate) struct LoopSleepPolicy {
    pub(crate) has_work: bool,
    pub(crate) timeout: Duration,
}

pub(crate) fn compute_loop_sleep_policy(
    delay_us: u64,
    has_work: bool,
    min_poll_interval_us: u64,
    dns_poll_slice_us: u64,
) -> LoopSleepPolicy {
    let timeout_us = if has_work {
        delay_us.clamp(min_poll_interval_us, dns_poll_slice_us)
    } else {
        delay_us.max(min_poll_interval_us)
    };

    LoopSleepPolicy {
        has_work,
        timeout: Duration::from_micros(timeout_us),
    }
}

#[cfg(test)]
mod tests {
    use super::compute_loop_sleep_policy;

    #[test]
    fn clamps_active_timeout_to_slice() {
        let policy = compute_loop_sleep_policy(30_000, true, 100, 5_000);
        assert_eq!(policy.timeout.as_micros(), 5_000);
    }

    #[test]
    fn enforces_min_timeout_when_active() {
        let policy = compute_loop_sleep_policy(10, true, 100, 5_000);
        assert_eq!(policy.timeout.as_micros(), 100);
    }

    #[test]
    fn uses_full_delay_when_idle() {
        let policy = compute_loop_sleep_policy(30_000, false, 100, 5_000);
        assert_eq!(policy.timeout.as_micros(), 30_000);
    }

    #[test]
    fn enforces_min_timeout_when_idle() {
        let policy = compute_loop_sleep_policy(10, false, 100, 5_000);
        assert_eq!(policy.timeout.as_micros(), 100);
    }
}
