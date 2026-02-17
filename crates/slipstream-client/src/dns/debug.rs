use crate::pacing::PacingBudgetSnapshot;
use tracing::{debug, info};

use super::resolver::ResolverState;

const DEBUG_REPORT_INTERVAL_US: u64 = 1_000_000;

pub(crate) struct DebugMetrics {
    pub(crate) enabled: bool,
    pub(crate) last_report_at: u64,
    pub(crate) dns_responses: u64,
    pub(crate) zero_send_loops: u64,
    pub(crate) zero_send_with_streams: u64,
    pub(crate) data_ready_skips: u64,
    pub(crate) enqueued_bytes: u64,
    pub(crate) send_packets: u64,
    pub(crate) send_bytes: u64,
    pub(crate) polls_sent: u64,
    pub(crate) last_enqueue_at: u64,
    pub(crate) last_report_dns: u64,
    pub(crate) last_report_zero: u64,
    pub(crate) last_report_zero_streams: u64,
    pub(crate) last_report_data_ready_skips: u64,
    pub(crate) last_report_enqueued: u64,
    pub(crate) last_report_send_packets: u64,
    pub(crate) last_report_send_bytes: u64,
    pub(crate) last_report_polls: u64,
    pub(crate) inflight_poll_timeouts: u64,
    pub(crate) path_probe_successes: u64,
    pub(crate) path_probe_failures: u64,
    pub(crate) path_rtt_us: u64,
    pub(crate) path_cwnd: u64,
    pub(crate) path_bytes_in_transit: u64,
    pub(crate) path_pacing_rate: u64,
    pub(crate) switch_to_count: u64,
    pub(crate) switch_from_count: u64,
}

impl DebugMetrics {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            last_report_at: 0,
            dns_responses: 0,
            zero_send_loops: 0,
            zero_send_with_streams: 0,
            data_ready_skips: 0,
            enqueued_bytes: 0,
            send_packets: 0,
            send_bytes: 0,
            polls_sent: 0,
            last_enqueue_at: 0,
            last_report_dns: 0,
            last_report_zero: 0,
            last_report_zero_streams: 0,
            last_report_data_ready_skips: 0,
            last_report_enqueued: 0,
            last_report_send_packets: 0,
            last_report_send_bytes: 0,
            last_report_polls: 0,
            inflight_poll_timeouts: 0,
            path_probe_successes: 0,
            path_probe_failures: 0,
            path_rtt_us: 0,
            path_cwnd: 0,
            path_bytes_in_transit: 0,
            path_pacing_rate: 0,
            switch_to_count: 0,
            switch_from_count: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolverSwitchReason {
    StartupPrimary,
    ManualOverride,
    ProbeRecovery,
    TimeoutStreakExceeded,
    HandshakeStall,
    LossSpike,
    LatencyRegression,
    PathUnavailable,
    CooldownExpired,
}

pub(crate) fn resolver_switch_reason_catalog() -> &'static [ResolverSwitchReason] {
    static REASONS: [ResolverSwitchReason; 9] = [
        ResolverSwitchReason::StartupPrimary,
        ResolverSwitchReason::ManualOverride,
        ResolverSwitchReason::ProbeRecovery,
        ResolverSwitchReason::TimeoutStreakExceeded,
        ResolverSwitchReason::HandshakeStall,
        ResolverSwitchReason::LossSpike,
        ResolverSwitchReason::LatencyRegression,
        ResolverSwitchReason::PathUnavailable,
        ResolverSwitchReason::CooldownExpired,
    ];
    &REASONS
}

impl ResolverSwitchReason {
    fn as_str(self) -> &'static str {
        match self {
            ResolverSwitchReason::StartupPrimary => "startup_primary",
            ResolverSwitchReason::ManualOverride => "manual_override",
            ResolverSwitchReason::ProbeRecovery => "probe_recovery",
            ResolverSwitchReason::TimeoutStreakExceeded => "timeout_streak_exceeded",
            ResolverSwitchReason::HandshakeStall => "handshake_stall",
            ResolverSwitchReason::LossSpike => "loss_spike",
            ResolverSwitchReason::LatencyRegression => "latency_regression",
            ResolverSwitchReason::PathUnavailable => "path_unavailable",
            ResolverSwitchReason::CooldownExpired => "cooldown_expired",
        }
    }
}

pub(crate) fn record_resolver_switch(
    resolvers: &mut [ResolverState],
    from_index: Option<usize>,
    to_index: usize,
    reason: ResolverSwitchReason,
) {
    if to_index >= resolvers.len() {
        return;
    }

    let to_addr = resolvers[to_index].addr;
    resolvers[to_index].debug.switch_to_count =
        resolvers[to_index].debug.switch_to_count.saturating_add(1);

    let from_addr = if let Some(index) = from_index {
        if index < resolvers.len() {
            resolvers[index].debug.switch_from_count =
                resolvers[index].debug.switch_from_count.saturating_add(1);
            Some(resolvers[index].addr)
        } else {
            None
        }
    } else {
        None
    };

    info!(
        "resolver switch: from={} to={} reason={}",
        from_addr
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "none".to_string()),
        to_addr,
        reason.as_str()
    );
}

pub(crate) fn maybe_report_debug(
    resolver: &mut ResolverState,
    now: u64,
    streams_len: usize,
    pending_polls: usize,
    inflight_polls: usize,
    pacing_snapshot: Option<PacingBudgetSnapshot>,
) {
    let label = resolver.label();
    let metrics = &mut resolver.debug;
    if !metrics.enabled {
        return;
    }
    if metrics.last_report_at == 0 {
        metrics.last_report_at = now;
        return;
    }
    let elapsed = now.saturating_sub(metrics.last_report_at);
    if elapsed < DEBUG_REPORT_INTERVAL_US {
        return;
    }
    let dns_delta = metrics
        .dns_responses
        .saturating_sub(metrics.last_report_dns);
    let zero_delta = metrics
        .zero_send_loops
        .saturating_sub(metrics.last_report_zero);
    let zero_stream_delta = metrics
        .zero_send_with_streams
        .saturating_sub(metrics.last_report_zero_streams);
    let data_ready_delta = metrics
        .data_ready_skips
        .saturating_sub(metrics.last_report_data_ready_skips);
    let enq_delta = metrics
        .enqueued_bytes
        .saturating_sub(metrics.last_report_enqueued);
    let send_pkt_delta = metrics
        .send_packets
        .saturating_sub(metrics.last_report_send_packets);
    let send_bytes_delta = metrics
        .send_bytes
        .saturating_sub(metrics.last_report_send_bytes);
    let polls_delta = metrics.polls_sent.saturating_sub(metrics.last_report_polls);
    let enqueue_ms = if metrics.last_enqueue_at == 0 {
        0
    } else {
        now.saturating_sub(metrics.last_enqueue_at) / 1_000
    };
    let pacing_summary = if let Some(snapshot) = pacing_snapshot {
        format!(
            " pacing_rate={} qps_target={:.2} target_inflight={} gain={:.2}",
            snapshot.pacing_rate, snapshot.qps, snapshot.target_inflight, snapshot.gain
        )
    } else {
        String::new()
    };
    debug!(
        "debug: {} dns+={} send_pkts+={} send_bytes+={} polls+={} zero_send+={} zero_send_streams+={} data_ready_skips+={} streams={} enqueued+={} last_enqueue_ms={} pending_polls={} inflight_polls={} poll_timeouts={} probe_ok={} probe_fail={} path_rtt_us={} path_cwnd={} path_in_transit={} path_pacing_rate={} switches_to={} switches_from={}{}",
        label,
        dns_delta,
        send_pkt_delta,
        send_bytes_delta,
        polls_delta,
        zero_delta,
        zero_stream_delta,
        data_ready_delta,
        streams_len,
        enq_delta,
        enqueue_ms,
        pending_polls,
        inflight_polls,
        metrics.inflight_poll_timeouts,
        metrics.path_probe_successes,
        metrics.path_probe_failures,
        metrics.path_rtt_us,
        metrics.path_cwnd,
        metrics.path_bytes_in_transit,
        metrics.path_pacing_rate,
        metrics.switch_to_count,
        metrics.switch_from_count,
        pacing_summary
    );
    metrics.last_report_at = now;
    metrics.last_report_dns = metrics.dns_responses;
    metrics.last_report_zero = metrics.zero_send_loops;
    metrics.last_report_zero_streams = metrics.zero_send_with_streams;
    metrics.last_report_data_ready_skips = metrics.data_ready_skips;
    metrics.last_report_enqueued = metrics.enqueued_bytes;
    metrics.last_report_send_packets = metrics.send_packets;
    metrics.last_report_send_bytes = metrics.send_bytes;
    metrics.last_report_polls = metrics.polls_sent;
}

#[cfg(test)]
mod tests {
    use super::ResolverSwitchReason;

    #[test]
    fn resolver_switch_reasons_are_stable_tokens() {
        assert_eq!(
            ResolverSwitchReason::StartupPrimary.as_str(),
            "startup_primary"
        );
        assert_eq!(
            ResolverSwitchReason::ManualOverride.as_str(),
            "manual_override"
        );
        assert_eq!(
            ResolverSwitchReason::ProbeRecovery.as_str(),
            "probe_recovery"
        );
        assert_eq!(
            ResolverSwitchReason::TimeoutStreakExceeded.as_str(),
            "timeout_streak_exceeded"
        );
        assert_eq!(
            ResolverSwitchReason::HandshakeStall.as_str(),
            "handshake_stall"
        );
        assert_eq!(ResolverSwitchReason::LossSpike.as_str(), "loss_spike");
        assert_eq!(
            ResolverSwitchReason::LatencyRegression.as_str(),
            "latency_regression"
        );
        assert_eq!(
            ResolverSwitchReason::PathUnavailable.as_str(),
            "path_unavailable"
        );
        assert_eq!(
            ResolverSwitchReason::CooldownExpired.as_str(),
            "cooldown_expired"
        );
    }
}
