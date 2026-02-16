use crate::error::ClientError;
use crate::pacing::{PacingBudgetSnapshot, PacingPollBudget};
use slipstream_core::state_machine::ResolverRole;
use slipstream_core::{normalize_dual_stack_addr, resolve_host_port};
use slipstream_ffi::{socket_addr_to_storage, ResolverMode, ResolverSpec};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::warn;

use super::debug::DebugMetrics;
use super::debug::ResolverSwitchReason;

const SELECTOR_COOLDOWN_US: u64 = 10_000_000;
const SELECTOR_PROMOTION_THRESHOLD_PERCENT: u64 = 15;
const SELECTOR_REQUIRED_CONSECUTIVE_WINS: u8 = 3;
const SCORE_UNAVAILABLE_PENALTY: u64 = 2_000_000;
const SCORE_TIMEOUT_PENALTY: u64 = 50_000;
const SCORE_PROBE_FAILURE_PENALTY: u64 = 20_000;
const SCORE_STICKINESS_BIAS: u64 = 10_000;

pub(crate) struct ResolverManager {
    resolvers: Vec<ResolverState>,
    active_index: usize,
    last_switch_at: u64,
    candidate_index: Option<usize>,
    candidate_wins: u8,
}

pub(crate) struct ResolverState {
    pub(crate) addr: SocketAddr,
    pub(crate) storage: libc::sockaddr_storage,
    pub(crate) local_addr_storage: Option<libc::sockaddr_storage>,
    pub(crate) mode: ResolverMode,
    pub(crate) role: ResolverRole,
    pub(crate) added: bool,
    pub(crate) path_id: libc::c_int,
    pub(crate) unique_path_id: Option<u64>,
    pub(crate) probe_attempts: u32,
    pub(crate) next_probe_at: u64,
    pub(crate) pending_polls: usize,
    pub(crate) inflight_poll_ids: HashMap<u16, u64>,
    pub(crate) pacing_budget: Option<PacingPollBudget>,
    pub(crate) last_pacing_snapshot: Option<PacingBudgetSnapshot>,
    pub(crate) debug: DebugMetrics,
}

impl ResolverState {
    pub(crate) fn label(&self) -> String {
        format!(
            "path_id={} unique_id={:?} resolver={} mode={:?} role={:?}",
            self.path_id, self.unique_path_id, self.addr, self.mode, self.role
        )
    }

    pub(crate) fn is_active(&self) -> bool {
        self.role == ResolverRole::Active
    }
}

impl ResolverManager {
    pub(crate) fn from_specs(
        resolvers: &[ResolverSpec],
        mtu: u32,
        debug_poll: bool,
    ) -> Result<Self, ClientError> {
        let resolved = resolve_resolvers(resolvers, mtu, debug_poll)?;
        Self::new(resolved)
    }

    fn new(mut resolvers: Vec<ResolverState>) -> Result<Self, ClientError> {
        if resolvers.is_empty() {
            return Err(ClientError::new("At least one resolver is required"));
        }

        let active_index = resolvers
            .iter()
            .position(|resolver| resolver.role == ResolverRole::Active)
            .unwrap_or(0);
        for (index, resolver) in resolvers.iter_mut().enumerate() {
            resolver.role = if index == active_index {
                ResolverRole::Active
            } else {
                ResolverRole::Standby
            };
        }

        Ok(Self {
            resolvers,
            active_index,
            last_switch_at: 0,
            candidate_index: None,
            candidate_wins: 0,
        })
    }

    pub(crate) fn active_index(&self) -> usize {
        self.active_index
    }

    pub(crate) fn set_startup_active_index(&mut self, index: usize) {
        if index >= self.resolvers.len() || index == self.active_index {
            return;
        }

        self.active_index = index;
        for (resolver_index, resolver) in self.resolvers.iter_mut().enumerate() {
            resolver.role = if resolver_index == index {
                ResolverRole::Active
            } else {
                ResolverRole::Standby
            };
            resolver.added = resolver_index == index;
            resolver.path_id = if resolver_index == index { 0 } else { -1 };
            resolver.unique_path_id = if resolver_index == index {
                Some(0)
            } else {
                None
            };
            resolver.local_addr_storage = None;
            resolver.pending_polls = 0;
            resolver.inflight_poll_ids.clear();
            resolver.last_pacing_snapshot = None;
            resolver.probe_attempts = 0;
            resolver.next_probe_at = 0;
        }
    }

    pub(crate) fn active_mut(&mut self) -> &mut ResolverState {
        &mut self.resolvers[self.active_index]
    }

    pub(crate) fn active(&self) -> &ResolverState {
        &self.resolvers[self.active_index]
    }

    pub(crate) fn as_slice(&self) -> &[ResolverState] {
        &self.resolvers
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [ResolverState] {
        &mut self.resolvers
    }

    pub(crate) fn maybe_select_active(
        &mut self,
        now_us: u64,
    ) -> Option<(usize, usize, ResolverSwitchReason)> {
        if self.resolvers.len() <= 1 {
            return None;
        }

        let from = self.active_index;
        if !self.resolvers[from].added {
            if let Some(to) = self.best_available_index() {
                if to != from {
                    self.set_active(to, now_us);
                    return Some((from, to, ResolverSwitchReason::PathUnavailable));
                }
            }
            return None;
        }

        let to = self.best_available_index()?;
        if to == from {
            self.candidate_index = None;
            self.candidate_wins = 0;
            return None;
        }

        let current_score = self.score(from);
        let candidate_score = self.score(to);
        let required_improvement =
            current_score.saturating_mul(SELECTOR_PROMOTION_THRESHOLD_PERCENT) / 100;
        let actual_improvement = current_score.saturating_sub(candidate_score);
        if actual_improvement < required_improvement {
            self.candidate_index = None;
            self.candidate_wins = 0;
            return None;
        }

        if self.candidate_index == Some(to) {
            self.candidate_wins = self.candidate_wins.saturating_add(1);
        } else {
            self.candidate_index = Some(to);
            self.candidate_wins = 1;
        }
        if self.candidate_wins < SELECTOR_REQUIRED_CONSECUTIVE_WINS {
            return None;
        }
        if self.last_switch_at > 0
            && now_us.saturating_sub(self.last_switch_at) < SELECTOR_COOLDOWN_US
        {
            return None;
        }

        self.set_active(to, now_us);
        Some((from, to, ResolverSwitchReason::LatencyRegression))
    }

    fn set_active(&mut self, active_index: usize, now_us: u64) {
        self.active_index = active_index;
        for (index, resolver) in self.resolvers.iter_mut().enumerate() {
            resolver.role = if index == active_index {
                ResolverRole::Active
            } else {
                ResolverRole::Standby
            };
        }
        self.last_switch_at = now_us;
        self.candidate_index = None;
        self.candidate_wins = 0;
    }

    fn best_available_index(&self) -> Option<usize> {
        let mut best_index = None;
        let mut best_score = u64::MAX;
        for (index, resolver) in self.resolvers.iter().enumerate() {
            if !resolver.added {
                continue;
            }
            let score = self.score(index);
            if score < best_score {
                best_score = score;
                best_index = Some(index);
            }
        }
        best_index
    }

    fn score(&self, index: usize) -> u64 {
        let resolver = &self.resolvers[index];
        let mut score = resolver.debug.path_rtt_us.max(100_000);
        score = score.saturating_add(
            resolver
                .debug
                .inflight_poll_timeouts
                .saturating_mul(SCORE_TIMEOUT_PENALTY),
        );
        score = score.saturating_add(
            resolver
                .debug
                .path_probe_failures
                .saturating_mul(SCORE_PROBE_FAILURE_PENALTY),
        );
        score = score.saturating_add(resolver.debug.path_bytes_in_transit / 8);
        if !resolver.added {
            score = score.saturating_add(SCORE_UNAVAILABLE_PENALTY);
        }
        if resolver.role == ResolverRole::Active {
            score = score.saturating_sub(SCORE_STICKINESS_BIAS);
        }
        score
    }
}

pub(crate) fn resolve_resolvers(
    resolvers: &[ResolverSpec],
    mtu: u32,
    debug_poll: bool,
) -> Result<Vec<ResolverState>, ClientError> {
    let mut resolved = Vec::with_capacity(resolvers.len());
    let mut seen = HashMap::new();
    for (idx, resolver) in resolvers.iter().enumerate() {
        let addr = resolve_host_port(&resolver.resolver)
            .map_err(|err| ClientError::new(err.to_string()))?;
        let addr = normalize_dual_stack_addr(addr);
        if let Some(existing_mode) = seen.get(&addr) {
            return Err(ClientError::new(format!(
                "Duplicate resolver address {} (modes: {:?} and {:?})",
                addr, existing_mode, resolver.mode
            )));
        }
        seen.insert(addr, resolver.mode);
        let is_primary = idx == 0;
        resolved.push(ResolverState {
            addr,
            storage: socket_addr_to_storage(addr),
            local_addr_storage: None,
            mode: resolver.mode,
            role: if is_primary {
                ResolverRole::Active
            } else {
                ResolverRole::Standby
            },
            added: is_primary,
            path_id: if is_primary { 0 } else { -1 },
            unique_path_id: if is_primary { Some(0) } else { None },
            probe_attempts: 0,
            next_probe_at: 0,
            pending_polls: 0,
            inflight_poll_ids: HashMap::new(),
            pacing_budget: match resolver.mode {
                ResolverMode::Authoritative => Some(PacingPollBudget::new(mtu)),
                ResolverMode::Recursive => None,
            },
            last_pacing_snapshot: None,
            debug: DebugMetrics::new(debug_poll),
        });
    }
    Ok(resolved)
}

pub(crate) fn reset_resolver_path(resolver: &mut ResolverState) {
    warn!(
        "Path for resolver {} became unavailable; resetting state",
        resolver.addr
    );
    resolver.added = false;
    resolver.path_id = -1;
    resolver.unique_path_id = None;
    resolver.local_addr_storage = None;
    resolver.pending_polls = 0;
    resolver.inflight_poll_ids.clear();
    resolver.last_pacing_snapshot = None;
    resolver.probe_attempts = 0;
    resolver.next_probe_at = 0;
}

pub(crate) fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
) -> Result<SocketAddr, ClientError> {
    slipstream_ffi::sockaddr_storage_to_socket_addr(storage).map_err(ClientError::new)
}

#[cfg(test)]
mod tests {
    use super::{resolve_resolvers, ResolverManager};
    use slipstream_core::state_machine::ResolverRole;
    use slipstream_core::{AddressFamily, HostPort};
    use slipstream_ffi::{ResolverMode, ResolverSpec};

    #[test]
    fn rejects_duplicate_resolver_addr() {
        let resolvers = vec![
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Authoritative,
            },
        ];

        match resolve_resolvers(&resolvers, 900, false) {
            Ok(_) => panic!("expected duplicate resolver error"),
            Err(err) => assert!(err.to_string().contains("Duplicate resolver address")),
        }
    }

    #[test]
    fn manager_tracks_single_active_resolver() {
        let resolvers = vec![
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.2".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Authoritative,
            },
        ];

        let manager = ResolverManager::from_specs(&resolvers, 900, false)
            .expect("resolver manager should initialize");

        assert_eq!(manager.active_index(), 0);
        assert_eq!(manager.as_slice()[0].role, ResolverRole::Active);
        assert_eq!(manager.as_slice()[1].role, ResolverRole::Standby);
    }

    #[test]
    fn manager_switches_active_when_candidate_consistently_better() {
        let resolvers = vec![
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.2".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
        ];

        let mut manager = ResolverManager::from_specs(&resolvers, 900, false)
            .expect("resolver manager should initialize");
        manager.as_mut_slice()[0].added = true;
        manager.as_mut_slice()[1].added = true;
        manager.as_mut_slice()[0].debug.path_rtt_us = 300_000;
        manager.as_mut_slice()[1].debug.path_rtt_us = 50_000;

        assert!(manager.maybe_select_active(1_000_000).is_none());
        assert!(manager.maybe_select_active(2_000_000).is_none());
        let switch = manager
            .maybe_select_active(11_000_000)
            .expect("third consecutive win should switch");
        assert_eq!(switch.0, 0);
        assert_eq!(switch.1, 1);
        assert_eq!(manager.active_index(), 1);
        assert_eq!(manager.active().role, ResolverRole::Active);
    }

    #[test]
    fn manager_can_set_startup_active_index() {
        let resolvers = vec![
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.2".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
        ];

        let mut manager = ResolverManager::from_specs(&resolvers, 900, false)
            .expect("resolver manager should initialize");
        manager.set_startup_active_index(1);

        assert_eq!(manager.active_index(), 1);
        assert!(manager.as_slice()[1].added);
        assert_eq!(manager.as_slice()[1].path_id, 0);
        assert_eq!(manager.as_slice()[1].unique_path_id, Some(0));
        assert!(!manager.as_slice()[0].added);
        assert_eq!(manager.as_slice()[0].path_id, -1);
        assert_eq!(manager.as_slice()[0].unique_path_id, None);
    }
}
