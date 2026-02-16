use crate::dns::{send_poll_queries, ResolverState};
use crate::error::ClientError;
use crate::pacing::{cwnd_target_polls, inflight_packet_estimate};
use slipstream_ffi::picoquic::picoquic_cnx_t;
use slipstream_ffi::{ClientConfig, ResolverMode};
use tokio::net::UdpSocket as TokioUdpSocket;
use tracing::debug;

use super::path::{fetch_path_quality, path_poll_burst_max};

pub(crate) struct PollDispatch<'a, 'cfg> {
    pub(crate) udp: &'a TokioUdpSocket,
    pub(crate) config: &'a ClientConfig<'cfg>,
    pub(crate) local_addr_storage: &'a mut libc::sockaddr_storage,
    pub(crate) dns_id: &'a mut u16,
    pub(crate) send_buf: &'a mut [u8],
}

pub(crate) async fn poll_authoritative_resolver(
    cnx: *mut picoquic_cnx_t,
    dispatch: &mut PollDispatch<'_, '_>,
    resolver: &mut ResolverState,
    mtu: u32,
    has_ready_stream: bool,
    flow_blocked: bool,
    sent_quic_data: bool,
) -> Result<(), ClientError> {
    let quality = fetch_path_quality(cnx, resolver);
    resolver.debug.path_rtt_us = quality.rtt;
    resolver.debug.path_cwnd = quality.cwin;
    resolver.debug.path_bytes_in_transit = quality.bytes_in_transit;
    resolver.debug.path_pacing_rate = quality.pacing_rate;

    let snapshot = resolver.last_pacing_snapshot;
    let pacing_target = snapshot
        .map(|snapshot| snapshot.target_inflight)
        .unwrap_or_else(|| cwnd_target_polls(quality.cwin, mtu));
    let inflight_packets = inflight_packet_estimate(quality.bytes_in_transit, mtu);
    let mut poll_deficit = pacing_target.saturating_sub(inflight_packets);

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
            dispatch.udp,
            dispatch.config,
            dispatch.local_addr_storage,
            dispatch.dns_id,
            resolver,
            &mut to_send,
            dispatch.send_buf,
        )
        .await?;
    }

    Ok(())
}

pub(crate) async fn poll_recursive_resolver(
    cnx: *mut picoquic_cnx_t,
    dispatch: &mut PollDispatch<'_, '_>,
    resolver: &mut ResolverState,
) -> Result<(), ClientError> {
    if resolver.mode != ResolverMode::Recursive {
        return Ok(());
    }

    resolver.last_pacing_snapshot = None;
    if resolver.pending_polls == 0 {
        return Ok(());
    }

    let burst_max = path_poll_burst_max(resolver);
    if resolver.pending_polls > burst_max {
        let mut to_send = burst_max;
        send_poll_queries(
            cnx,
            dispatch.udp,
            dispatch.config,
            dispatch.local_addr_storage,
            dispatch.dns_id,
            resolver,
            &mut to_send,
            dispatch.send_buf,
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
            dispatch.udp,
            dispatch.config,
            dispatch.local_addr_storage,
            dispatch.dns_id,
            resolver,
            &mut pending,
            dispatch.send_buf,
        )
        .await?;
        resolver.pending_polls = pending;
    }

    Ok(())
}
