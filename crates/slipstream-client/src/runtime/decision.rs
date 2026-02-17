use super::deadlock::AcceptorSaturationTracker;
use super::path::maybe_switch_active_resolver;
use crate::dns::ResolverManager;
use crate::streams::ClientState;
use slipstream_ffi::picoquic::picoquic_current_time;
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReconnectReason {
    ActivePathLoss {
        streams_len: usize,
    },
    AcceptorDeadlock {
        used: usize,
        max: usize,
        total_bytes: u64,
        timeout_us: u64,
    },
}

pub(crate) fn decide_active_path_loss_reconnect(
    streams_len: usize,
    active_path_ready: bool,
    threshold: usize,
) -> Option<ReconnectReason> {
    if streams_len >= threshold && !active_path_ready {
        return Some(ReconnectReason::ActivePathLoss { streams_len });
    }
    None
}

pub(crate) fn decide_acceptor_deadlock_reconnect(
    deadlock_detected: bool,
    used: usize,
    max: usize,
    total_bytes: u64,
    timeout_us: u64,
) -> Option<ReconnectReason> {
    if deadlock_detected {
        return Some(ReconnectReason::AcceptorDeadlock {
            used,
            max,
            total_bytes,
            timeout_us,
        });
    }
    None
}

pub(crate) fn reconnect_due_to_active_path_loss(
    resolver_manager: &mut ResolverManager,
    current_time: u64,
    preferred_startup_resolver_index: &mut usize,
    state_ptr: *mut ClientState,
    threshold: usize,
) -> bool {
    maybe_switch_active_resolver(
        resolver_manager,
        current_time,
        preferred_startup_resolver_index,
    );

    let streams_len = unsafe { (*state_ptr).streams_len() };
    let active_path_ready = resolver_manager.active().added;
    if let Some(reason) =
        decide_active_path_loss_reconnect(streams_len, active_path_ready, threshold)
    {
        log_reconnect_reason(reason);
        return true;
    }
    false
}

pub(crate) fn reconnect_due_to_acceptor_deadlock(
    state_ptr: *mut ClientState,
    acceptor_saturation: &mut AcceptorSaturationTracker,
) -> bool {
    let (used, max) = unsafe { (*state_ptr).acceptor_metrics() };
    let total_bytes = unsafe { (*state_ptr).total_stream_bytes() };
    let now = unsafe { picoquic_current_time() };
    let deadlock_detected = acceptor_saturation.update(now, used, max, total_bytes);
    if let Some(reason) = decide_acceptor_deadlock_reconnect(
        deadlock_detected,
        used,
        max,
        total_bytes,
        acceptor_saturation.timeout_us(),
    ) {
        log_reconnect_reason(reason);
        return true;
    }
    false
}

fn log_reconnect_reason(reason: ReconnectReason) {
    match reason {
        ReconnectReason::ActivePathLoss { streams_len } => {
            warn!(
                "active resolver path deleted with {} streams and no standby path ready; reconnecting to limit reset storm",
                streams_len,
            );
        }
        ReconnectReason::AcceptorDeadlock {
            used,
            max,
            total_bytes,
            timeout_us,
        } => {
            warn!(
                "acceptor deadlock for {}s ({}/{}, bytes={}, no progress), forcing reconnect",
                timeout_us / 1_000_000,
                used,
                max,
                total_bytes
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decide_acceptor_deadlock_reconnect, decide_active_path_loss_reconnect, ReconnectReason,
    };

    #[test]
    fn active_path_loss_requires_threshold_and_no_ready_path() {
        assert_eq!(
            decide_active_path_loss_reconnect(32, false, 32),
            Some(ReconnectReason::ActivePathLoss { streams_len: 32 })
        );
        assert_eq!(decide_active_path_loss_reconnect(31, false, 32), None);
        assert_eq!(decide_active_path_loss_reconnect(64, true, 32), None);
    }

    #[test]
    fn acceptor_deadlock_decision_requires_detected_flag() {
        assert_eq!(
            decide_acceptor_deadlock_reconnect(true, 512, 512, 2048, 30_000_000),
            Some(ReconnectReason::AcceptorDeadlock {
                used: 512,
                max: 512,
                total_bytes: 2048,
                timeout_us: 30_000_000,
            })
        );
        assert_eq!(
            decide_acceptor_deadlock_reconnect(false, 512, 512, 2048, 30_000_000),
            None
        );
    }
}
