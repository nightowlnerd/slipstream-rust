use crate::error::ClientError;
use slipstream_dns::max_payload_len_for_domain;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use tokio::net::{lookup_host, TcpListener as TokioTcpListener, UdpSocket as TokioUdpSocket};
use tracing::warn;

pub(crate) fn compute_mtu(domain: &str) -> Result<u32, ClientError> {
    let mtu =
        max_payload_len_for_domain(domain).map_err(|err| ClientError::new(err.to_string()))?;
    if mtu == 0 {
        return Err(ClientError::new(
            "MTU computed to zero; check domain length",
        ));
    }
    u32::try_from(mtu).map_err(|_| ClientError::new("MTU conversion overflow"))
}

pub(crate) async fn bind_udp_socket() -> Result<TokioUdpSocket, ClientError> {
    let bind_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
    bind_udp_socket_addr(bind_addr)
}

pub(crate) async fn bind_tcp_listener(
    host: &str,
    port: u16,
) -> Result<TokioTcpListener, ClientError> {
    let addrs: Vec<SocketAddr> = lookup_host((host, port)).await.map_err(map_io)?.collect();
    if addrs.is_empty() {
        return Err(ClientError::new(format!(
            "No addresses resolved for {}:{}",
            host, port
        )));
    }
    let mut last_err = None;
    for addr in addrs {
        match bind_tcp_listener_addr(addr) {
            Ok(listener) => return Ok(listener),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        ClientError::new(format!("Failed to bind TCP listener on {}:{}", host, port))
    }))
}

fn bind_tcp_listener_addr(addr: SocketAddr) -> Result<TokioTcpListener, ClientError> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(map_io)?;
    #[cfg(not(windows))]
    if let Err(err) = socket.set_reuse_address(true) {
        warn!("Failed to enable SO_REUSEADDR on {}: {}", addr, err);
    }
    if let SocketAddr::V6(_) = addr {
        if let Err(err) = socket.set_only_v6(false) {
            warn!(
                "Failed to enable dual-stack TCP listener on {}: {}",
                addr, err
            );
        }
    }
    let sock_addr = SockAddr::from(addr);
    socket.bind(&sock_addr).map_err(map_io)?;
    socket.listen(1024).map_err(map_io)?;
    socket.set_nonblocking(true).map_err(map_io)?;
    let std_listener: std::net::TcpListener = socket.into();
    TokioTcpListener::from_std(std_listener).map_err(map_io)
}

fn bind_udp_socket_addr(addr: SocketAddr) -> Result<TokioUdpSocket, ClientError> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(map_io)?;
    if let SocketAddr::V6(_) = addr {
        if let Err(err) = socket.set_only_v6(false) {
            warn!(
                "Failed to enable dual-stack UDP socket on {}: {}",
                addr, err
            );
        }
    }
    let sock_addr = SockAddr::from(addr);
    socket.bind(&sock_addr).map_err(map_io)?;
    socket.set_nonblocking(true).map_err(map_io)?;
    let std_socket: std::net::UdpSocket = socket.into();
    TokioUdpSocket::from_std(std_socket).map_err(map_io)
}

pub(crate) fn map_io(err: std::io::Error) -> ClientError {
    ClientError::new(err.to_string())
}
