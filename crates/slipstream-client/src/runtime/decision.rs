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
