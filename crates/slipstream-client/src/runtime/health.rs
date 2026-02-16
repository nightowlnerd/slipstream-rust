pub(crate) fn should_log_flow_blocked(
    streams_len: usize,
    has_ready_stream: bool,
    flow_blocked: bool,
    now: u64,
    last_log_at: u64,
    interval_us: u64,
) -> bool {
    streams_len > 0
        && has_ready_stream
        && flow_blocked
        && now.saturating_sub(last_log_at) >= interval_us
}

pub(crate) fn compute_last_enqueue_ms(now: u64, last_enqueue_at: u64) -> u64 {
    if last_enqueue_at == 0 {
        0
    } else {
        now.saturating_sub(last_enqueue_at) / 1_000
    }
}

pub(crate) fn should_reconnect_for_resolver_stall(
    ready: bool,
    streams_len: usize,
    current_time: u64,
    last_recv_at: u64,
    timeout_us: u64,
) -> Option<u64> {
    if !ready || last_recv_at == 0 || streams_len == 0 {
        return None;
    }

    let stall_us = current_time.saturating_sub(last_recv_at);
    if stall_us >= timeout_us {
        return Some(stall_us);
    }

    None
}

pub(crate) fn should_reconnect_for_handshake_stall(
    ready: bool,
    current_time: u64,
    connect_started_at: u64,
    timeout_us: u64,
) -> Option<u64> {
    if ready || connect_started_at == 0 {
        return None;
    }

    let stall_us = current_time.saturating_sub(connect_started_at);
    if stall_us >= timeout_us {
        return Some(stall_us);
    }

    None
}

pub(crate) fn should_log_health(
    ready: bool,
    report_time: u64,
    last_health_log_at: u64,
    interval_us: u64,
) -> bool {
    ready && report_time.saturating_sub(last_health_log_at) >= interval_us
}

#[cfg(test)]
mod tests {
    use super::{
        compute_last_enqueue_ms, should_log_flow_blocked, should_log_health,
        should_reconnect_for_handshake_stall, should_reconnect_for_resolver_stall,
    };

    #[test]
    fn flow_blocked_log_requires_all_gates() {
        assert!(should_log_flow_blocked(1, true, true, 10_000, 0, 1_000));
        assert!(!should_log_flow_blocked(0, true, true, 10_000, 0, 1_000));
        assert!(!should_log_flow_blocked(1, false, true, 10_000, 0, 1_000));
        assert!(!should_log_flow_blocked(1, true, false, 10_000, 0, 1_000));
        assert!(!should_log_flow_blocked(1, true, true, 1_500, 1_000, 1_000));
    }

    #[test]
    fn enqueue_ms_handles_zero_timestamp() {
        assert_eq!(compute_last_enqueue_ms(1_000_000, 0), 0);
        assert_eq!(compute_last_enqueue_ms(2_000_000, 1_000_000), 1_000);
    }

    #[test]
    fn resolver_stall_requires_ready_and_streams() {
        assert_eq!(
            should_reconnect_for_resolver_stall(true, 1, 20_000, 1_000, 10_000),
            Some(19_000)
        );
        assert_eq!(
            should_reconnect_for_resolver_stall(false, 1, 20_000, 1_000, 10_000),
            None
        );
        assert_eq!(
            should_reconnect_for_resolver_stall(true, 0, 20_000, 1_000, 10_000),
            None
        );
        assert_eq!(
            should_reconnect_for_resolver_stall(true, 1, 5_000, 1_000, 10_000),
            None
        );
    }

    #[test]
    fn handshake_stall_requires_not_ready_and_timeout() {
        assert_eq!(
            should_reconnect_for_handshake_stall(false, 20_000, 1_000, 10_000),
            Some(19_000)
        );
        assert_eq!(
            should_reconnect_for_handshake_stall(true, 20_000, 1_000, 10_000),
            None
        );
        assert_eq!(
            should_reconnect_for_handshake_stall(false, 5_000, 1_000, 10_000),
            None
        );
        assert_eq!(
            should_reconnect_for_handshake_stall(false, 20_000, 0, 10_000),
            None
        );
    }

    #[test]
    fn health_log_gate_requires_ready_and_interval() {
        assert!(should_log_health(true, 20_000, 1_000, 10_000));
        assert!(!should_log_health(false, 20_000, 1_000, 10_000));
        assert!(!should_log_health(true, 5_000, 1_000, 10_000));
    }
}
