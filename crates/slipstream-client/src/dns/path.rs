use crate::error::ClientError;
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_current_time, picoquic_get_path_addr, picoquic_probe_new_path_ex,
    slipstream_find_path_id_by_addr, slipstream_get_path_id_from_unique,
    slipstream_set_default_path_mode,
};
use slipstream_ffi::ResolverMode;
use tracing::{info, warn};

use super::resolver::{
    clear_active_path_suspect, note_active_refresh_failure, reset_resolver_path,
    should_failover_active_path, ResolverState,
};

const PATH_PROBE_INITIAL_DELAY_US: u64 = 250_000;
const PATH_PROBE_MAX_DELAY_US: u64 = 10_000_000;
const PROBE_FAILURE_LOG_INTERVAL_US: u64 = 10_000_000;

pub(crate) fn refresh_resolver_path(
    cnx: *mut picoquic_cnx_t,
    resolver: &mut ResolverState,
) -> bool {
    if let Some(unique_path_id) = resolver.unique_path_id {
        let path_id = unsafe { slipstream_get_path_id_from_unique(cnx, unique_path_id) };
        if path_id >= 0 {
            resolver.added = true;
            if resolver.path_id != path_id {
                resolver.path_id = path_id;
            }
            resolver.last_path_unavailable_log_at = 0;
            clear_active_path_suspect(resolver);
            return true;
        }
        resolver.unique_path_id = None;
    }
    let peer = &resolver.storage as *const _ as *const libc::sockaddr;
    let path_id = unsafe { slipstream_find_path_id_by_addr(cnx, peer) };
    if path_id < 0 {
        if resolver.is_active() {
            let now = unsafe { picoquic_current_time() };
            note_active_refresh_failure(resolver, now);
            if should_failover_active_path(resolver, now) {
                reset_resolver_path(resolver);
            }
        } else if resolver.added || resolver.path_id >= 0 {
            reset_resolver_path(resolver);
        }
        return false;
    }

    resolver.added = true;
    if resolver.path_id != path_id {
        resolver.path_id = path_id;
    }
    resolver.last_path_unavailable_log_at = 0;
    clear_active_path_suspect(resolver);
    true
}

pub(crate) fn add_paths(
    cnx: *mut picoquic_cnx_t,
    resolvers: &mut [ResolverState],
) -> Result<(), ClientError> {
    if resolvers.len() <= 1 {
        return Ok(());
    }

    let mut local_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let ret = unsafe { picoquic_get_path_addr(cnx, 0, 1, &mut local_storage) };
    if ret != 0 {
        return Ok(());
    }
    let now = unsafe { picoquic_current_time() };
    let primary_mode = resolvers[0].mode;
    let mut default_mode = primary_mode;

    for resolver in resolvers.iter_mut().skip(1) {
        if resolver.added {
            continue;
        }
        if resolver.next_probe_at > now {
            continue;
        }
        if resolver.mode != default_mode {
            unsafe { slipstream_set_default_path_mode(resolver_mode_to_c(resolver.mode)) };
            default_mode = resolver.mode;
        }
        let mut path_id: libc::c_int = -1;
        let ret = unsafe {
            picoquic_probe_new_path_ex(
                cnx,
                &resolver.storage as *const _ as *const libc::sockaddr,
                &local_storage as *const _ as *const libc::sockaddr,
                0,
                now,
                0,
                &mut path_id,
            )
        };
        if ret == 0 && path_id >= 0 {
            resolver.added = true;
            resolver.path_id = path_id;
            resolver.last_probe_failure_log_at = 0;
            resolver.debug.path_probe_successes =
                resolver.debug.path_probe_successes.saturating_add(1);
            info!("Added path {}", resolver.addr);
            continue;
        }
        resolver.debug.path_probe_failures = resolver.debug.path_probe_failures.saturating_add(1);
        resolver.probe_attempts = resolver.probe_attempts.saturating_add(1);
        let delay = path_probe_backoff(resolver.probe_attempts);
        resolver.next_probe_at = now.saturating_add(delay);
        let should_log = resolver.probe_attempts == 1
            || resolver.probe_attempts.is_power_of_two()
            || resolver.last_probe_failure_log_at == 0
            || now.saturating_sub(resolver.last_probe_failure_log_at)
                >= PROBE_FAILURE_LOG_INTERVAL_US;
        if should_log {
            resolver.last_probe_failure_log_at = now;
            warn!(
                "Failed adding path {} (attempt {}), retrying in {}ms",
                resolver.addr,
                resolver.probe_attempts,
                delay / 1000
            );
        }
    }

    if default_mode != primary_mode {
        unsafe { slipstream_set_default_path_mode(resolver_mode_to_c(primary_mode)) };
    }

    Ok(())
}

pub(crate) fn resolver_mode_to_c(mode: ResolverMode) -> libc::c_int {
    match mode {
        ResolverMode::Recursive => 1,
        ResolverMode::Authoritative => 2,
    }
}

fn path_probe_backoff(attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(6);
    let delay = PATH_PROBE_INITIAL_DELAY_US.saturating_mul(1u64 << shift);
    delay.min(PATH_PROBE_MAX_DELAY_US)
}
