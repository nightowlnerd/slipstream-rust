mod path;
mod setup;

use self::path::{
    apply_path_mode, drain_path_events, fetch_path_quality, find_resolver_by_addr_mut,
    loop_burst_total, maybe_switch_active_resolver, path_poll_burst_max,
};
use self::setup::{bind_tcp_listener, bind_udp_socket, compute_mtu, map_io};
use crate::dns::{
    add_paths, expire_inflight_polls, handle_dns_response, maybe_report_debug,
    record_resolver_switch, refresh_resolver_path, resolver_mode_to_c,
    resolver_switch_reason_catalog, send_poll_queries, sockaddr_storage_to_socket_addr,
    DnsResponseContext, ResolverManager, ResolverSwitchReason,
};
use crate::error::ClientError;
use crate::pacing::{cwnd_target_polls, inflight_packet_estimate};
use crate::pinning::configure_pinned_certificate;
use crate::streams::{
    acceptor::ClientAcceptor, client_callback, drain_commands, drain_stream_data, handle_command,
    ClientState, Command,
};
use slipstream_core::{net::is_transient_udp_error, normalize_dual_stack_addr};
use slipstream_dns::{build_qname, encode_query, QueryParams, CLASS_IN, RR_TXT};
use slipstream_ffi::{
    configure_quic_with_custom,
    picoquic::{
        picoquic_close, picoquic_cnx_t, picoquic_connection_id_t, picoquic_create,
        picoquic_create_client_cnx, picoquic_current_time, picoquic_disable_keep_alive,
        picoquic_enable_keep_alive, picoquic_enable_path_callbacks,
        picoquic_enable_path_callbacks_default, picoquic_get_cnx_state,
        picoquic_get_next_wake_delay, picoquic_prepare_next_packet_ex, picoquic_set_callback,
        picoquic_set_default_multipath_option, picoquic_state_enum, slipstream_has_ready_stream,
        slipstream_is_flow_blocked, slipstream_mixed_cc_algorithm, slipstream_set_cc_override,
        slipstream_set_cid_limit, slipstream_set_default_path_mode,
        PICOQUIC_CONNECTION_ID_MAX_SIZE, PICOQUIC_MAX_PACKET_SIZE, PICOQUIC_PACKET_LOOP_RECV_MAX,
        PICOQUIC_PACKET_LOOP_SEND_MAX,
    },
    socket_addr_to_storage, take_crypto_errors, ClientConfig, QuicGuard, ResolverMode,
};
use std::ffi::CString;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

// Protocol defaults; see docs/config.md for details.
const SLIPSTREAM_ALPN: &str = "picoquic_sample";
const SLIPSTREAM_SNI: &str = "test.example.com";
const DNS_WAKE_DELAY_MAX_US: i64 = 10_000_000;
const DNS_POLL_SLICE_US: u64 = 50_000;
const RECONNECT_SLEEP_MIN_MS: u64 = 250;
const RECONNECT_SLEEP_MAX_MS: u64 = 5_000;
const FLOW_BLOCKED_LOG_INTERVAL_US: u64 = 1_000_000;
const MIN_POLL_INTERVAL_US: u64 = 100;
/// Force a reconnect if no DNS responses arrive within this window while the
/// connection is active.  This catches cases where the recursive resolver
/// silently stops forwarding queries (rate-limit, anti-tunnel heuristic, etc.).
const RESOLVER_STALL_TIMEOUT_US: u64 = 60_000_000;
/// Force reconnect if the connection never reaches ready state within this
/// startup window. With multiple recursive resolvers, rotate the startup
/// resolver index on each stall to avoid sticking on a blocked resolver.
const HANDSHAKE_STALL_TIMEOUT_US: u64 = 30_000_000;
/// If a stream is half-closed by the remote side and local upload stays open
/// without forward progress for too long, abort the local reader to avoid
/// zombie streams exhausting MAX_STREAMS credit.
const HALF_CLOSE_IDLE_TIMEOUT_US: u64 = 60_000_000;
/// Force a reconnect if the MAX_STREAMS budget has been fully consumed for
/// this long.  When flow control deadlocks prevent streams from completing,
/// picoquic cannot extend MAX_STREAMS and the tunnel is effectively dead.
const ACCEPTOR_SATURATED_TIMEOUT_US: u64 = 30_000_000;
/// Periodic health heartbeat log interval (5 minutes).  Emits connection
/// state at INFO level so we can diagnose silent tunnel deaths.
const HEALTH_LOG_INTERVAL_US: u64 = 300_000_000;
const WATCHDOG_STALE_SECS: u64 = 15;
const WATCHDOG_CHECK_INTERVAL: Duration = Duration::from_secs(3);
const WATCHDOG_ABORT_STRIKES: u32 = 3;
const WATCHDOG_SELECT_RECONNECT_SECS: u64 = 30;
const WATCHDOG_SELECT_ABORT_SECS: u64 = 180;
const ACTIVE_PATH_LOSS_RECONNECT_STREAMS: usize = 32;

/// Watchdog that runs on a separate OS thread (not tokio) to detect when the
/// single-threaded tokio runtime freezes (e.g. a picoquic C FFI call hangs).
/// If the main loop hasn't updated the heartbeat for WATCHDOG_STALE_SECS,
/// the watchdog emits warnings and only aborts in non-select phases.
///
/// `PHASE_SELECT` may legitimately appear stale under host scheduler jitter,
/// so we first request reconnect; abort is only a last-resort cap.
struct Watchdog {
    heartbeat: Arc<AtomicU64>,
    phase: Arc<AtomicU32>,
    alive: Arc<AtomicBool>,
    select_reconnect_requested: Arc<AtomicBool>,
    _handle: std::thread::JoinHandle<()>,
}

const PHASE_DRAIN_COMMANDS: u32 = 1;
const PHASE_DRAIN_STREAM_DATA: u32 = 2;
const PHASE_CNX_STATE_CHECK: u32 = 3;
const PHASE_WAKE_DELAY: u32 = 4;
const PHASE_SELECT: u32 = 5;
const PHASE_POST_DRAIN: u32 = 6;
const PHASE_PREPARE_PACKET: u32 = 7;
const PHASE_SEND_DNS: u32 = 8;
const PHASE_POLL_QUERIES: u32 = 9;
const PHASE_HEALTH_LOG: u32 = 10;

fn phase_name(phase: u32) -> &'static str {
    match phase {
        PHASE_DRAIN_COMMANDS => "drain_commands",
        PHASE_DRAIN_STREAM_DATA => "drain_stream_data",
        PHASE_CNX_STATE_CHECK => "cnx_state_check",
        PHASE_WAKE_DELAY => "wake_delay",
        PHASE_SELECT => "select/sleep",
        PHASE_POST_DRAIN => "post_select_drain",
        PHASE_PREPARE_PACKET => "prepare_next_packet_ex",
        PHASE_SEND_DNS => "send_dns_query",
        PHASE_POLL_QUERIES => "send_poll_queries",
        PHASE_HEALTH_LOG => "health_log",
        _ => "unknown",
    }
}

impl Watchdog {
    fn spawn() -> Self {
        let heartbeat = Arc::new(AtomicU64::new(0));
        let phase = Arc::new(AtomicU32::new(0));
        let alive = Arc::new(AtomicBool::new(true));
        let select_reconnect_requested = Arc::new(AtomicBool::new(false));
        let hb = Arc::clone(&heartbeat);
        let ph = Arc::clone(&phase);
        let al = Arc::clone(&alive);
        let reconnect_flag = Arc::clone(&select_reconnect_requested);
        let handle = std::thread::Builder::new()
            .name("watchdog".into())
            .spawn(move || {
                let mut last_check = Instant::now();
                let mut stale_strikes = 0u32;
                while al.load(Ordering::Relaxed) {
                    std::thread::sleep(WATCHDOG_CHECK_INTERVAL);
                    if !al.load(Ordering::Relaxed) {
                        break;
                    }
                    let now_instant = Instant::now();
                    let ts = hb.load(Ordering::Relaxed);
                    if ts == 0 {
                        stale_strikes = 0;
                        last_check = now_instant;
                        continue;
                    }
                    let now_pico = unsafe { picoquic_current_time() };
                    let stale_us = now_pico.saturating_sub(ts);
                    let own_sleep = now_instant.duration_since(last_check);
                    let own_sleep_us = own_sleep.as_micros() as u64;
                    last_check = now_instant;
                    let expected_sleep_us =
                        WATCHDOG_CHECK_INTERVAL.as_micros() as u64;
                    if stale_us > WATCHDOG_STALE_SECS * 1_000_000
                        && own_sleep_us > expected_sleep_us * 3
                    {
                        stale_strikes = 0;
                        let stuck_phase = ph.load(Ordering::Relaxed);
                        eprintln!(
                            "WATCHDOG: VPS suspend detected ({:.1}s gap, own sleep {:.1}s), \
                             phase {} ({}), NOT aborting — petting heartbeat",
                            stale_us as f64 / 1_000_000.0,
                            own_sleep_us as f64 / 1_000_000.0,
                            stuck_phase,
                            phase_name(stuck_phase),
                        );
                        hb.store(now_pico, Ordering::Relaxed);
                        continue;
                    }
                    if stale_us > WATCHDOG_STALE_SECS * 1_000_000 {
                        stale_strikes = stale_strikes.saturating_add(1);
                        let stuck_phase = ph.load(Ordering::Relaxed);
                        let phase_name = phase_name(stuck_phase);
                        if stuck_phase == PHASE_SELECT {
                            if stale_us >= WATCHDOG_SELECT_RECONNECT_SECS * 1_000_000 {
                                let first_request = !reconnect_flag.swap(true, Ordering::Relaxed);
                                if first_request {
                                    eprintln!(
                                        "WATCHDOG: select phase stale for {:.1}s; requesting reconnect",
                                        stale_us as f64 / 1_000_000.0,
                                    );
                                }
                            }
                            if stale_us >= WATCHDOG_SELECT_ABORT_SECS * 1_000_000 {
                                eprintln!(
                                    "WATCHDOG: select phase stalled for {:.1}s (phase {} / {}), aborting as last resort",
                                    stale_us as f64 / 1_000_000.0,
                                    stuck_phase,
                                    phase_name,
                                );
                                std::process::abort();
                            }
                            eprintln!(
                                "WATCHDOG: stale heartbeat {:.1}s at phase {} ({}), strikes={}, waiting (select phase uses reconnect-first policy)",
                                stale_us as f64 / 1_000_000.0,
                                stuck_phase,
                                phase_name,
                                stale_strikes,
                            );
                            continue;
                        }
                        if stale_strikes >= WATCHDOG_ABORT_STRIKES {
                            eprintln!(
                                "WATCHDOG: main loop stalled for {:.1}s at phase {} ({}), strikes={}, aborting process",
                                stale_us as f64 / 1_000_000.0,
                                stuck_phase,
                                phase_name,
                                stale_strikes,
                            );
                            std::process::abort();
                        }
                        eprintln!(
                            "WATCHDOG: stale heartbeat {:.1}s at phase {} ({}), strikes={}, waiting",
                            stale_us as f64 / 1_000_000.0,
                            stuck_phase,
                            phase_name,
                            stale_strikes,
                        );
                    } else {
                        stale_strikes = 0;
                    }
                }
            })
            .expect("failed to spawn watchdog thread");
        Self {
            heartbeat,
            phase,
            alive,
            select_reconnect_requested,
            _handle: handle,
        }
    }

    fn pet(&self) {
        let now = unsafe { picoquic_current_time() };
        self.heartbeat.store(now, Ordering::Relaxed);
    }

    fn set_phase(&self, p: u32) {
        self.phase.store(p, Ordering::Relaxed);
    }

    fn take_select_reconnect_requested(&self) -> bool {
        self.select_reconnect_requested
            .swap(false, Ordering::Relaxed)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Relaxed);
    }
}

fn is_ipv6_unspecified(host: &str) -> bool {
    host.parse::<Ipv6Addr>()
        .map(|addr| addr.is_unspecified())
        .unwrap_or(false)
}

fn drain_disconnected_commands(command_rx: &mut mpsc::UnboundedReceiver<Command>) -> usize {
    let mut dropped = 0usize;
    while let Ok(command) = command_rx.try_recv() {
        dropped += 1;
        if let Command::NewStream { stream, .. } = command {
            drop(stream);
        }
    }
    dropped
}

fn should_reconnect_for_handshake_stall(
    ready: bool,
    current_time: u64,
    connect_started_at: u64,
    timeout_us: u64,
) -> Option<u64> {
    if ready || connect_started_at == 0 {
        return None;
    }
    let elapsed = current_time.saturating_sub(connect_started_at);
    if elapsed >= timeout_us {
        Some(elapsed)
    } else {
        None
    }
}

pub async fn run_client(config: &ClientConfig<'_>) -> Result<i32, ClientError> {
    let _ = resolver_switch_reason_catalog();
    let domain_len = config.domain.len();
    let mtu = compute_mtu(domain_len)?;
    let udp = bind_udp_socket().await?;

    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let data_notify = Arc::new(Notify::new());
    let data_ready = Arc::new(AtomicBool::new(false));
    let acceptor = ClientAcceptor::new();
    let debug_streams = config.debug_streams;
    let tcp_host = config.tcp_listen_host;
    let tcp_port = config.tcp_listen_port;
    let mut bound_host = tcp_host.to_string();
    let listener = match bind_tcp_listener(tcp_host, tcp_port).await {
        Ok(listener) => listener,
        Err(err) => {
            if is_ipv6_unspecified(tcp_host) {
                warn!(
                    "Failed to bind TCP listener on {}:{} ({}); falling back to 0.0.0.0",
                    tcp_host, tcp_port, err
                );
                match bind_tcp_listener("0.0.0.0", tcp_port).await {
                    Ok(listener) => {
                        bound_host = "0.0.0.0".to_string();
                        listener
                    }
                    Err(fallback_err) => {
                        return Err(ClientError::new(format!(
                            "Failed to bind TCP listener on {}:{} ({}) or 0.0.0.0:{} ({})",
                            tcp_host, tcp_port, err, tcp_port, fallback_err
                        )));
                    }
                }
            } else {
                return Err(err);
            }
        }
    };
    acceptor.spawn(listener, command_tx.clone());
    info!("Listening on TCP port {} (host {})", tcp_port, bound_host);

    let alpn = CString::new(SLIPSTREAM_ALPN)
        .map_err(|_| ClientError::new("ALPN contains an unexpected null byte"))?;
    let sni = CString::new(SLIPSTREAM_SNI)
        .map_err(|_| ClientError::new("SNI contains an unexpected null byte"))?;
    let cc_override = match config.congestion_control {
        Some(value) => Some(CString::new(value).map_err(|_| {
            ClientError::new("Congestion control contains an unexpected null byte")
        })?),
        None => None,
    };

    let mut state = Box::new(ClientState::new(
        command_tx,
        data_notify.clone(),
        data_ready.clone(),
        debug_streams,
        acceptor,
    ));
    let state_ptr: *mut ClientState = &mut *state;
    let _state = state;

    let mut reconnect_delay = Duration::from_millis(RECONNECT_SLEEP_MIN_MS);
    let mut preferred_startup_resolver_index = 0usize;

    loop {
        let mut resolver_manager =
            ResolverManager::from_specs(config.resolvers, mtu, config.debug_poll)?;
        resolver_manager.set_startup_active_index(preferred_startup_resolver_index);
        let active_index = resolver_manager.active_index();
        record_resolver_switch(
            resolver_manager.as_mut_slice(),
            None,
            active_index,
            ResolverSwitchReason::StartupPrimary,
        );

        let mut local_addr_storage = socket_addr_to_storage(udp.local_addr().map_err(map_io)?);

        let current_time = unsafe { picoquic_current_time() };
        let connect_started_at = current_time;
        let quic = unsafe {
            picoquic_create(
                8,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                alpn.as_ptr(),
                Some(client_callback),
                state_ptr as *mut _,
                None,
                std::ptr::null_mut(),
                std::ptr::null(),
                current_time,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        if quic.is_null() {
            let crypto_errors = take_crypto_errors();
            if crypto_errors.is_empty() {
                return Err(ClientError::new("Could not create QUIC context"));
            }
            return Err(ClientError::new(format!(
                "Could not create QUIC context (TLS errors: {})",
                crypto_errors.join("; ")
            )));
        }
        let _quic_guard = QuicGuard::new(quic);
        let mixed_cc = unsafe { slipstream_mixed_cc_algorithm };
        if mixed_cc.is_null() {
            return Err(ClientError::new("Could not load mixed congestion control"));
        }
        unsafe {
            configure_quic_with_custom(quic, mixed_cc, mtu);
            // Multipath is only useful with multiple resolvers; leave it off
            // (picoquic default) for single-resolver to avoid CID exhaustion.
            if resolver_manager.as_slice().len() > 1 {
                picoquic_set_default_multipath_option(quic, 1);
                // Multipath provisions 8 CIDs per path; the default limit of 8
                // is too low with 2+ paths.  32 accommodates ~7 paths.
                slipstream_set_cid_limit(quic, 32);
            }
            picoquic_enable_path_callbacks_default(quic, 1);
            let override_ptr = cc_override
                .as_ref()
                .map(|value| value.as_ptr())
                .unwrap_or(std::ptr::null());
            slipstream_set_cc_override(override_ptr);
        }
        unsafe {
            slipstream_set_default_path_mode(resolver_mode_to_c(
                resolver_manager.active_mut().mode,
            ));
        }
        if let Some(cert) = config.cert {
            configure_pinned_certificate(quic, cert).map_err(ClientError::new)?;
        }
        let mut server_storage = resolver_manager.active_mut().storage;
        // picoquic_create_client_cnx calls picoquic_start_client_cnx internally (see picoquic/quicctx.c).
        let cnx = unsafe {
            picoquic_create_client_cnx(
                quic,
                &mut server_storage as *mut _ as *mut libc::sockaddr,
                current_time,
                0,
                sni.as_ptr(),
                alpn.as_ptr(),
                Some(client_callback),
                state_ptr as *mut _,
            )
        };
        if cnx.is_null() {
            return Err(ClientError::new("Could not create QUIC connection"));
        }

        apply_path_mode(cnx, resolver_manager.active_mut())?;

        unsafe {
            picoquic_set_callback(cnx, Some(client_callback), state_ptr as *mut _);
            picoquic_enable_path_callbacks(cnx, 1);
            if config.keep_alive_interval > 0 {
                // picoquic expects microseconds; config value is in seconds.
                picoquic_enable_keep_alive(cnx, config.keep_alive_interval as u64 * 1_000_000);
            } else {
                picoquic_disable_keep_alive(cnx);
            }
        }

        if config.gso {
            warn!("GSO is not implemented in the Rust client loop yet.");
        }

        let mut dns_id = 1u16;
        let mut recv_buf = vec![0u8; 4096];
        let mut send_buf = vec![0u8; PICOQUIC_MAX_PACKET_SIZE];
        let packet_loop_send_max =
            loop_burst_total(resolver_manager.as_slice(), PICOQUIC_PACKET_LOOP_SEND_MAX);
        let packet_loop_recv_max =
            loop_burst_total(resolver_manager.as_slice(), PICOQUIC_PACKET_LOOP_RECV_MAX);
        let mut zero_send_loops = 0u64;
        let mut zero_send_with_streams = 0u64;
        let mut data_ready_skips = 0u64;
        let mut last_flow_block_log_at = 0u64;
        let mut last_recv_at = 0u64;
        let mut last_health_log_at = 0u64;
        let mut acceptor_saturated_since: u64 = 0;
        let mut acceptor_saturated_max: usize = 0;
        let mut acceptor_saturated_bytes: u64 = 0;
        let watchdog = Watchdog::spawn();

        // Clear closing flag that picoquic_free (QuicGuard::drop) may have
        // set via the close callback at the end of the previous iteration.
        unsafe {
            (*state_ptr).clear_closing();
        }

        loop {
            watchdog.pet();
            watchdog.set_phase(PHASE_DRAIN_COMMANDS);
            let current_time = unsafe { picoquic_current_time() };
            if watchdog.take_select_reconnect_requested() {
                warn!(
                    "watchdog requested reconnect after select-phase stall; recycling connection"
                );
                break;
            }
            // Only process application commands after the QUIC handshake
            // completes.  During reconnect the acceptor may queue NewStream
            // commands while the connection is still in initial state;
            // processing them before ready triggers picoquic errors (0xc).
            if unsafe { (*state_ptr).is_ready() } {
                drain_commands(cnx, state_ptr, &mut command_rx);
            } else {
                let _ = drain_disconnected_commands(&mut command_rx);
            }
            watchdog.set_phase(PHASE_DRAIN_STREAM_DATA);
            drain_stream_data(cnx, state_ptr);
            watchdog.set_phase(PHASE_CNX_STATE_CHECK);
            let closing = unsafe { (*state_ptr).is_closing() };
            if closing {
                break;
            }

            // Detect broken QUIC connection state that the callback missed.
            let cnx_state = unsafe { picoquic_get_cnx_state(cnx) };
            if cnx_state as u32 >= picoquic_state_enum::picoquic_state_disconnecting as u32 {
                warn!(
                    "QUIC connection unhealthy: state={:?}, forcing reconnect",
                    cnx_state
                );
                break;
            }

            let ready = unsafe { (*state_ptr).is_ready() };
            if let Some(stall_us) = should_reconnect_for_handshake_stall(
                ready,
                current_time,
                connect_started_at,
                HANDSHAKE_STALL_TIMEOUT_US,
            ) {
                let resolver_count = resolver_manager.as_slice().len();
                if resolver_count > 1 {
                    let from_index = resolver_manager.active_index();
                    let to_index = (from_index + 1) % resolver_count;
                    let from_addr = resolver_manager.as_slice()[from_index].addr;
                    let to_addr = resolver_manager.as_slice()[to_index].addr;
                    record_resolver_switch(
                        resolver_manager.as_mut_slice(),
                        Some(from_index),
                        to_index,
                        ResolverSwitchReason::HandshakeStall,
                    );
                    preferred_startup_resolver_index = to_index;
                    warn!(
                        "handshake stall for {:.1}s on startup resolver {}; rotating startup resolver to {} and reconnecting",
                        stall_us as f64 / 1_000_000.0,
                        from_addr,
                        to_addr,
                    );
                } else {
                    warn!(
                        "handshake stall for {:.1}s on single resolver; reconnecting",
                        stall_us as f64 / 1_000_000.0
                    );
                }
                break;
            }
            if ready {
                if last_recv_at == 0 {
                    last_recv_at = current_time;
                }
                unsafe {
                    (*state_ptr).update_acceptor_limit(cnx);
                }
                if reconnect_delay != Duration::from_millis(RECONNECT_SLEEP_MIN_MS) {
                    reconnect_delay = Duration::from_millis(RECONNECT_SLEEP_MIN_MS);
                }
                add_paths(cnx, resolver_manager.as_mut_slice())?;
                for resolver in resolver_manager.as_mut_slice().iter_mut() {
                    if resolver.added {
                        apply_path_mode(cnx, resolver)?;
                    }
                }
            }
            let active_path_deleted =
                drain_path_events(cnx, resolver_manager.as_mut_slice(), state_ptr);
            if active_path_deleted {
                maybe_switch_active_resolver(
                    &mut resolver_manager,
                    current_time,
                    &mut preferred_startup_resolver_index,
                );
                let streams_len = unsafe { (*state_ptr).streams_len() };
                let active_path_ready = resolver_manager.active().added;
                if streams_len >= ACTIVE_PATH_LOSS_RECONNECT_STREAMS && !active_path_ready {
                    warn!(
                        "active resolver path deleted with {} streams and no standby path ready; reconnecting to limit reset storm",
                        streams_len,
                    );
                    break;
                }
            }

            for resolver in resolver_manager.as_mut_slice().iter_mut() {
                if resolver.mode == ResolverMode::Authoritative {
                    let expired =
                        expire_inflight_polls(&mut resolver.inflight_poll_ids, current_time);
                    if expired > 0 {
                        resolver.debug.inflight_poll_timeouts = resolver
                            .debug
                            .inflight_poll_timeouts
                            .saturating_add(expired as u64);
                    }
                }
            }

            watchdog.set_phase(PHASE_WAKE_DELAY);
            let delay_us =
                unsafe { picoquic_get_next_wake_delay(quic, current_time, DNS_WAKE_DELAY_MAX_US) };
            let delay_us = if delay_us < 0 { 0 } else { delay_us as u64 };
            let streams_len_for_sleep = unsafe { (*state_ptr).streams_len() };
            let mut has_work = streams_len_for_sleep > 0;
            for resolver in resolver_manager.as_mut_slice().iter_mut() {
                if !refresh_resolver_path(cnx, resolver) {
                    continue;
                }
                if !resolver.is_active() && resolver.mode == ResolverMode::Recursive {
                    continue;
                }
                let pending_for_sleep = match resolver.mode {
                    ResolverMode::Authoritative => {
                        let quality = fetch_path_quality(cnx, resolver);
                        resolver.debug.path_rtt_us = quality.rtt;
                        resolver.debug.path_cwnd = quality.cwin;
                        resolver.debug.path_bytes_in_transit = quality.bytes_in_transit;
                        resolver.debug.path_pacing_rate = quality.pacing_rate;
                        let snapshot = resolver
                            .pacing_budget
                            .as_mut()
                            .map(|budget| budget.target_inflight(&quality, delay_us.max(1)));
                        resolver.last_pacing_snapshot = snapshot;
                        let target = snapshot
                            .map(|snapshot| snapshot.target_inflight)
                            .unwrap_or_else(|| cwnd_target_polls(quality.cwin, mtu));
                        let inflight_packets =
                            inflight_packet_estimate(quality.bytes_in_transit, mtu);
                        target.saturating_sub(inflight_packets)
                    }
                    ResolverMode::Recursive => resolver.pending_polls,
                };
                if pending_for_sleep > 0 {
                    has_work = true;
                }
                if resolver.mode == ResolverMode::Authoritative
                    && !resolver.inflight_poll_ids.is_empty()
                {
                    has_work = true;
                }
            }
            // Avoid a tight poll loop when idle, but keep the short slice during active transfers.
            let timeout_us = if has_work {
                delay_us.clamp(MIN_POLL_INTERVAL_US, DNS_POLL_SLICE_US)
            } else {
                delay_us.max(MIN_POLL_INTERVAL_US)
            };
            let timeout = Duration::from_micros(timeout_us);

            watchdog.set_phase(PHASE_SELECT);
            let pre_select = Instant::now();
            if data_ready.swap(false, Ordering::Acquire) {
                data_ready_skips = data_ready_skips.saturating_add(1);
            } else {
                let notified = data_notify.notified();
                tokio::pin!(notified);
                tokio::select! {
                    command = command_rx.recv() => {
                        if let Some(command) = command {
                            if unsafe { (*state_ptr).is_ready() } {
                                handle_command(cnx, state_ptr, command);
                            } else if let Command::NewStream { stream, .. } = command {
                                drop(stream);
                            }
                        }
                    }
                    _ = &mut notified => {
                        data_ready.swap(false, Ordering::Acquire);
                    }
                    recv = udp.recv_from(&mut recv_buf) => {
                        match recv {
                            Ok((size, peer)) => {
                                last_recv_at = unsafe { picoquic_current_time() };
                                let mut response_ctx = DnsResponseContext {
                                    quic,
                                    local_addr_storage: &local_addr_storage,
                                    resolvers: resolver_manager.as_mut_slice(),
                                };
                                handle_dns_response(&recv_buf[..size], peer, &mut response_ctx)?;
                                for _ in 1..packet_loop_recv_max {
                                    match udp.try_recv_from(&mut recv_buf) {
                                        Ok((size, peer)) => {
                                            handle_dns_response(&recv_buf[..size], peer, &mut response_ctx)?;
                                        }
                                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                                        Err(err) => {
                                            if is_transient_udp_error(&err) {
                                                break;
                                            }
                                            return Err(map_io(err));
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                if !is_transient_udp_error(&err) {
                                    return Err(map_io(err));
                                }
                            }
                        }
                    }
                    _ = sleep(timeout) => {}
                }
            }
            let select_elapsed = pre_select.elapsed();
            if select_elapsed > Duration::from_secs(10) {
                warn!(
                    "select overslept: {:.1}s (timeout was {:.1}s, has_work={})",
                    select_elapsed.as_secs_f64(),
                    timeout.as_secs_f64(),
                    has_work,
                );
            }
            watchdog.pet();
            if watchdog.take_select_reconnect_requested() {
                warn!(
                    "watchdog requested reconnect after select-phase stall; recycling connection"
                );
                break;
            }

            watchdog.set_phase(PHASE_POST_DRAIN);
            if unsafe { (*state_ptr).is_ready() } {
                drain_commands(cnx, state_ptr, &mut command_rx);
            } else {
                let _ = drain_disconnected_commands(&mut command_rx);
            }
            drain_stream_data(cnx, state_ptr);
            let active_path_deleted =
                drain_path_events(cnx, resolver_manager.as_mut_slice(), state_ptr);
            if active_path_deleted {
                maybe_switch_active_resolver(
                    &mut resolver_manager,
                    current_time,
                    &mut preferred_startup_resolver_index,
                );
                let streams_len = unsafe { (*state_ptr).streams_len() };
                let active_path_ready = resolver_manager.active().added;
                if streams_len >= ACTIVE_PATH_LOSS_RECONNECT_STREAMS && !active_path_ready {
                    warn!(
                        "active resolver path deleted with {} streams and no standby path ready; reconnecting to limit reset storm",
                        streams_len,
                    );
                    break;
                }
            }
            let reaped_half_closed = unsafe {
                let now = picoquic_current_time();
                (*state_ptr).reap_stale_half_closed_streams(now, HALF_CLOSE_IDLE_TIMEOUT_US)
            };
            if reaped_half_closed > 0 {
                warn!(
                    "reaped {} stale half-closed stream(s) after {}s idle timeout",
                    reaped_half_closed,
                    HALF_CLOSE_IDLE_TIMEOUT_US / 1_000_000
                );
            }

            // Circuit breaker: force reconnect when MAX_STREAMS is fully
            // consumed and no progress is being made (flow control deadlock).
            //
            // Three gates prevent false-triggering on healthy saturated connections:
            //   1. `used >= max` — acceptor budget fully consumed
            //   2. `max` unchanged — peer hasn't extended MAX_STREAMS
            //   3. total stream bytes unchanged — no data flowing (true deadlock)
            //
            // Any gate resetting (MAX_STREAMS extended, or bytes increasing)
            // restarts the 30s timer.
            {
                let (used, max) = unsafe { (*state_ptr).acceptor_metrics() };
                let total_bytes = unsafe { (*state_ptr).total_stream_bytes() };
                if max > 0 && used >= max {
                    let now = unsafe { picoquic_current_time() };
                    if acceptor_saturated_since == 0
                        || max != acceptor_saturated_max
                        || total_bytes != acceptor_saturated_bytes
                    {
                        // First saturation, limit extended, or bytes moved — (re)start.
                        acceptor_saturated_since = now;
                        acceptor_saturated_max = max;
                        acceptor_saturated_bytes = total_bytes;
                    } else if now.saturating_sub(acceptor_saturated_since)
                        >= ACCEPTOR_SATURATED_TIMEOUT_US
                    {
                        warn!(
                            "acceptor deadlock for {}s ({}/{}, bytes={}, no progress), forcing reconnect",
                            ACCEPTOR_SATURATED_TIMEOUT_US / 1_000_000,
                            used,
                            max,
                            total_bytes
                        );
                        break;
                    }
                } else {
                    acceptor_saturated_since = 0;
                }
            }

            let mut sent_quic_data = false;
            for _ in 0..packet_loop_send_max {
                watchdog.set_phase(PHASE_PREPARE_PACKET);
                let current_time = unsafe { picoquic_current_time() };
                let mut send_length: libc::size_t = 0;
                let mut addr_to: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let mut addr_from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let mut if_index: libc::c_int = 0;
                let mut log_cid = picoquic_connection_id_t {
                    id: [0; PICOQUIC_CONNECTION_ID_MAX_SIZE],
                    id_len: 0,
                };
                let mut last_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();

                let ret = unsafe {
                    picoquic_prepare_next_packet_ex(
                        quic,
                        current_time,
                        send_buf.as_mut_ptr(),
                        send_buf.len(),
                        &mut send_length,
                        &mut addr_to,
                        &mut addr_from,
                        &mut if_index,
                        &mut log_cid,
                        &mut last_cnx,
                        std::ptr::null_mut(),
                    )
                };
                if ret < 0 {
                    return Err(ClientError::new("Failed preparing outbound QUIC packet"));
                }
                if send_length == 0 {
                    zero_send_loops = zero_send_loops.saturating_add(1);
                    let streams_len = unsafe { (*state_ptr).streams_len() };
                    if streams_len > 0 {
                        zero_send_with_streams = zero_send_with_streams.saturating_add(1);
                        // Ensure recursive resolvers keep polling even when the
                        // congestion window is full (not just flow control).
                        // The server can only send ACKs inside DNS responses,
                        // so we must keep querying to unblock the CWND.
                        for resolver in resolver_manager.as_mut_slice().iter_mut() {
                            if resolver.is_active()
                                && resolver.mode == ResolverMode::Recursive
                                && resolver.added
                            {
                                resolver.pending_polls = resolver.pending_polls.max(1);
                            }
                        }
                    }
                    break;
                }

                if addr_to.ss_family == 0 {
                    break;
                }
                sent_quic_data = true;
                if let Ok(dest) = sockaddr_storage_to_socket_addr(&addr_to) {
                    let dest = normalize_dual_stack_addr(dest);
                    if let Some(resolver) =
                        find_resolver_by_addr_mut(resolver_manager.as_mut_slice(), dest)
                    {
                        resolver.local_addr_storage = Some(unsafe { std::ptr::read(&addr_from) });
                        resolver.debug.send_packets = resolver.debug.send_packets.saturating_add(1);
                        resolver.debug.send_bytes =
                            resolver.debug.send_bytes.saturating_add(send_length as u64);
                    }
                }

                watchdog.set_phase(PHASE_SEND_DNS);
                let qname = build_qname(&send_buf[..send_length], config.domain)
                    .map_err(|err| ClientError::new(err.to_string()))?;
                let params = QueryParams {
                    id: dns_id,
                    qname: &qname,
                    qtype: RR_TXT,
                    qclass: CLASS_IN,
                    rd: true,
                    cd: false,
                    qdcount: 1,
                    is_query: true,
                };
                dns_id = dns_id.wrapping_add(1);
                let packet =
                    encode_query(&params).map_err(|err| ClientError::new(err.to_string()))?;

                let dest = sockaddr_storage_to_socket_addr(&addr_to)?;
                let dest = normalize_dual_stack_addr(dest);
                local_addr_storage = addr_from;
                if let Err(err) = udp.send_to(&packet, dest).await {
                    if !is_transient_udp_error(&err) {
                        return Err(map_io(err));
                    }
                }
            }

            maybe_switch_active_resolver(
                &mut resolver_manager,
                current_time,
                &mut preferred_startup_resolver_index,
            );

            let has_ready_stream = unsafe { slipstream_has_ready_stream(cnx) != 0 };
            let flow_blocked = unsafe { slipstream_is_flow_blocked(cnx) != 0 };
            let streams_len = unsafe { (*state_ptr).streams_len() };
            if streams_len > 0 && has_ready_stream && flow_blocked {
                let now = unsafe { picoquic_current_time() };
                if now.saturating_sub(last_flow_block_log_at) >= FLOW_BLOCKED_LOG_INTERVAL_US {
                    let metrics = unsafe { (*state_ptr).stream_debug_metrics() };
                    let backlog = unsafe { (*state_ptr).stream_backlog_summaries(8) };
                    let (enqueued_bytes, last_enqueue_at) =
                        unsafe { (*state_ptr).debug_snapshot() };
                    let last_enqueue_ms = if last_enqueue_at == 0 {
                        0
                    } else {
                        now.saturating_sub(last_enqueue_at) / 1_000
                    };
                    error!(
                        "connection flow blocked: streams={} streams_with_rx_queued={} queued_bytes_total={} streams_with_recv_fin={} streams_with_send_fin={} streams_discarding={} streams_with_unconsumed_rx={} enqueued_bytes={} last_enqueue_ms={} zero_send_with_streams={} zero_send_loops={} data_ready_skips={} flow_blocked={} has_ready_stream={} backlog={:?}",
                        streams_len,
                        metrics.streams_with_rx_queued,
                        metrics.queued_bytes_total,
                        metrics.streams_with_recv_fin,
                        metrics.streams_with_send_fin,
                        metrics.streams_discarding,
                        metrics.streams_with_unconsumed_rx,
                        enqueued_bytes,
                        last_enqueue_ms,
                        zero_send_with_streams,
                        zero_send_loops,
                        data_ready_skips,
                        flow_blocked,
                        has_ready_stream,
                        backlog
                    );
                    last_flow_block_log_at = now;
                }
            }
            watchdog.set_phase(PHASE_POLL_QUERIES);
            for resolver in resolver_manager.as_mut_slice().iter_mut() {
                if !resolver.is_active() && resolver.mode == ResolverMode::Recursive {
                    continue;
                }
                if !refresh_resolver_path(cnx, resolver) {
                    continue;
                }
                match resolver.mode {
                    ResolverMode::Authoritative => {
                        let quality = fetch_path_quality(cnx, resolver);
                        resolver.debug.path_rtt_us = quality.rtt;
                        resolver.debug.path_cwnd = quality.cwin;
                        resolver.debug.path_bytes_in_transit = quality.bytes_in_transit;
                        resolver.debug.path_pacing_rate = quality.pacing_rate;
                        let snapshot = resolver.last_pacing_snapshot;
                        let pacing_target = snapshot
                            .map(|snapshot| snapshot.target_inflight)
                            .unwrap_or_else(|| cwnd_target_polls(quality.cwin, mtu));
                        let inflight_packets =
                            inflight_packet_estimate(quality.bytes_in_transit, mtu);
                        let mut poll_deficit = pacing_target.saturating_sub(inflight_packets);
                        // Only suppress polls when the send loop actually produced
                        // QUIC packets (which act as implicit polls). When CWND is
                        // full, prepare_next_packet_ex returns nothing—but the server
                        // can only send ACKs inside DNS responses, so we must keep
                        // polling to unblock the congestion window.
                        if has_ready_stream && !flow_blocked && sent_quic_data {
                            poll_deficit = 0;
                        }
                        if poll_deficit > 0 && resolver.debug.enabled {
                            debug!(
                                "cc_state: {} cwnd={} in_transit={} rtt_us={} flow_blocked={} deficit={}",
                                resolver.label(),
                                quality.cwin,
                                quality.bytes_in_transit,
                                quality.rtt,
                                flow_blocked,
                                poll_deficit
                            );
                        }
                        if poll_deficit > 0 {
                            let burst_max = path_poll_burst_max(resolver);
                            let mut to_send = poll_deficit.min(burst_max);
                            send_poll_queries(
                                cnx,
                                &udp,
                                config,
                                &mut local_addr_storage,
                                &mut dns_id,
                                resolver,
                                &mut to_send,
                                &mut send_buf,
                            )
                            .await?;
                        }
                    }
                    ResolverMode::Recursive => {
                        resolver.last_pacing_snapshot = None;
                        if resolver.pending_polls > 0 {
                            let burst_max = path_poll_burst_max(resolver);
                            if resolver.pending_polls > burst_max {
                                let mut to_send = burst_max;
                                send_poll_queries(
                                    cnx,
                                    &udp,
                                    config,
                                    &mut local_addr_storage,
                                    &mut dns_id,
                                    resolver,
                                    &mut to_send,
                                    &mut send_buf,
                                )
                                .await?;
                                resolver.pending_polls = resolver
                                    .pending_polls
                                    .saturating_sub(burst_max)
                                    .saturating_add(to_send);
                            } else {
                                let mut pending = resolver.pending_polls;
                                send_poll_queries(
                                    cnx,
                                    &udp,
                                    config,
                                    &mut local_addr_storage,
                                    &mut dns_id,
                                    resolver,
                                    &mut pending,
                                    &mut send_buf,
                                )
                                .await?;
                                resolver.pending_polls = pending;
                            }
                        }
                    }
                }
            }

            // Detect resolver stall: if we've been sending polls but getting
            // no DNS responses for RESOLVER_STALL_TIMEOUT_US, the recursive
            // resolver likely stopped forwarding.  Force a reconnect so the
            // new QUIC handshake resets resolver state.
            // Only check when streams are active — idle connections legitimately
            // receive no responses and should not trigger a reconnect.
            if last_recv_at > 0 && ready {
                let streams_len = unsafe { (*state_ptr).streams_len() };
                let stall_us = current_time.saturating_sub(last_recv_at);
                if streams_len > 0 && stall_us >= RESOLVER_STALL_TIMEOUT_US {
                    warn!(
                        "resolver stall detected: no DNS responses for {:.1}s, streams={}, forcing reconnect",
                        stall_us as f64 / 1_000_000.0,
                        streams_len,
                    );
                    // Don't close here — the post-loop picoquic_close handles it.
                    break;
                }
            }

            watchdog.set_phase(PHASE_HEALTH_LOG);
            let report_time = unsafe { picoquic_current_time() };
            let (enqueued_bytes, last_enqueue_at) = unsafe { (*state_ptr).debug_snapshot() };
            let streams_len = unsafe { (*state_ptr).streams_len() };
            for resolver in resolver_manager.as_mut_slice().iter_mut() {
                resolver.debug.enqueued_bytes = enqueued_bytes;
                resolver.debug.last_enqueue_at = last_enqueue_at;
                resolver.debug.zero_send_loops = zero_send_loops;
                resolver.debug.zero_send_with_streams = zero_send_with_streams;
                resolver.debug.data_ready_skips = data_ready_skips;
                if !refresh_resolver_path(cnx, resolver) {
                    continue;
                }
                let inflight_polls = resolver.inflight_poll_ids.len();
                let pending_for_debug = match resolver.mode {
                    ResolverMode::Authoritative => {
                        let quality = fetch_path_quality(cnx, resolver);
                        resolver.debug.path_rtt_us = quality.rtt;
                        resolver.debug.path_cwnd = quality.cwin;
                        resolver.debug.path_bytes_in_transit = quality.bytes_in_transit;
                        resolver.debug.path_pacing_rate = quality.pacing_rate;
                        let inflight_packets =
                            inflight_packet_estimate(quality.bytes_in_transit, mtu);
                        resolver
                            .last_pacing_snapshot
                            .map(|snapshot| {
                                snapshot.target_inflight.saturating_sub(inflight_packets)
                            })
                            .unwrap_or(0)
                    }
                    ResolverMode::Recursive => resolver.pending_polls,
                };
                maybe_report_debug(
                    resolver,
                    report_time,
                    streams_len,
                    pending_for_debug,
                    inflight_polls,
                    resolver.last_pacing_snapshot,
                );
            }

            // Periodic health heartbeat: log key metrics at INFO level so we
            // can diagnose silent tunnel deaths from production logs.
            if ready && report_time.saturating_sub(last_health_log_at) >= HEALTH_LOG_INTERVAL_US {
                last_health_log_at = report_time;
                let (acceptor_used, acceptor_max) = unsafe { (*state_ptr).acceptor_metrics() };
                let recv_age_s = if last_recv_at > 0 {
                    report_time.saturating_sub(last_recv_at) / 1_000_000
                } else {
                    0
                };
                info!(
                    "health: streams={} cnx_state={:?} recv_age={}s acceptor={}/{} zero_send_with_streams={} data_ready_skips={}",
                    streams_len,
                    cnx_state,
                    recv_age_s,
                    acceptor_used,
                    acceptor_max,
                    zero_send_with_streams,
                    data_ready_skips,
                );
            }
        }

        unsafe {
            picoquic_close(cnx, 0);
        }

        unsafe {
            (*state_ptr).reset_for_reconnect();
        }
        let dropped = drain_disconnected_commands(&mut command_rx);
        if dropped > 0 {
            warn!("Dropped {} queued commands while reconnecting", dropped);
        }
        warn!(
            "Connection closed; reconnecting in {}ms",
            reconnect_delay.as_millis()
        );
        // Sleep in small chunks and drop commands that arrive while disconnected.
        let mut remaining_sleep = reconnect_delay;
        while remaining_sleep > Duration::ZERO {
            let chunk = remaining_sleep.min(Duration::from_millis(100));
            sleep(chunk).await;
            remaining_sleep -= chunk;
            let _ = drain_disconnected_commands(&mut command_rx);
        }
        reconnect_delay = (reconnect_delay * 2).min(Duration::from_millis(RECONNECT_SLEEP_MAX_MS));
    }
}
