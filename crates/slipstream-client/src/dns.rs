mod debug;
mod path;
mod poll;
mod resolver;
mod response;

pub(crate) use debug::{
    maybe_report_debug, record_resolver_switch, resolver_switch_reason_catalog,
    ResolverSwitchReason,
};
pub(crate) use path::{add_paths, refresh_resolver_path, resolver_mode_to_c};
pub(crate) use poll::{expire_inflight_polls, send_poll_queries};
pub(crate) use resolver::{
    note_active_path_delete_signal, reset_resolver_path, should_failover_active_path,
    sockaddr_storage_to_socket_addr, ResolverManager, ResolverState,
};
pub(crate) use response::{handle_dns_response, DnsResponseContext};
