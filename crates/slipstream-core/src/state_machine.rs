use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Init,
    Handshaking,
    Active,
    Degraded,
    Recovering,
    Draining,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnEvent {
    StartHandshake,
    HandshakeReady,
    HandshakeFailed,
    Degrade,
    Recover,
    Drain,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverHealthState {
    Unknown,
    Probing,
    Healthy,
    Degraded,
    Cooling,
    Dead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverRole {
    Active,
    Standby,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverEvent {
    ProbeStarted,
    ProbeSucceeded,
    ProbeFailed,
    MarkDegraded,
    StartCooldown,
    CooldownExpired,
    MarkDead,
    Revive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    Open,
    FinLocal,
    FinRemote,
    Closed,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEvent {
    Open,
    LocalFin,
    RemoteFin,
    AckClose,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineKind {
    Connection,
    Resolver,
    Stream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionError {
    pub machine: MachineKind,
    pub state: &'static str,
    pub event: &'static str,
}

impl TransitionError {
    fn new(machine: MachineKind, state: &'static str, event: &'static str) -> Self {
        Self {
            machine,
            state,
            event,
        }
    }
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {:?} transition: state={} event={}",
            self.machine, self.state, self.event
        )
    }
}

impl std::error::Error for TransitionError {}

pub fn validate_conn_transition(
    state: ConnState,
    event: ConnEvent,
) -> Result<ConnState, TransitionError> {
    if event == ConnEvent::Close {
        return match state {
            ConnState::Closed => Err(TransitionError::new(
                MachineKind::Connection,
                conn_state_name(state),
                conn_event_name(event),
            )),
            _ => Ok(ConnState::Closed),
        };
    }

    let next = match (state, event) {
        (ConnState::Init, ConnEvent::StartHandshake) => ConnState::Handshaking,
        (ConnState::Handshaking, ConnEvent::HandshakeReady) => ConnState::Active,
        (ConnState::Handshaking, ConnEvent::HandshakeFailed) => ConnState::Recovering,
        (ConnState::Active, ConnEvent::Degrade) => ConnState::Degraded,
        (ConnState::Active, ConnEvent::Drain) => ConnState::Draining,
        (ConnState::Degraded, ConnEvent::Recover) => ConnState::Active,
        (ConnState::Degraded, ConnEvent::Drain) => ConnState::Draining,
        (ConnState::Recovering, ConnEvent::StartHandshake) => ConnState::Handshaking,
        (ConnState::Recovering, ConnEvent::Drain) => ConnState::Draining,
        (ConnState::Draining, ConnEvent::Drain) => ConnState::Draining,
        _ => {
            return Err(TransitionError::new(
                MachineKind::Connection,
                conn_state_name(state),
                conn_event_name(event),
            ));
        }
    };

    Ok(next)
}

pub fn validate_resolver_transition(
    state: ResolverHealthState,
    event: ResolverEvent,
) -> Result<ResolverHealthState, TransitionError> {
    let next = match (state, event) {
        (ResolverHealthState::Unknown, ResolverEvent::ProbeStarted) => ResolverHealthState::Probing,
        (ResolverHealthState::Probing, ResolverEvent::ProbeSucceeded) => {
            ResolverHealthState::Healthy
        }
        (ResolverHealthState::Probing, ResolverEvent::ProbeFailed) => ResolverHealthState::Degraded,
        (ResolverHealthState::Healthy, ResolverEvent::MarkDegraded) => {
            ResolverHealthState::Degraded
        }
        (ResolverHealthState::Healthy, ResolverEvent::MarkDead) => ResolverHealthState::Dead,
        (ResolverHealthState::Degraded, ResolverEvent::ProbeSucceeded) => {
            ResolverHealthState::Healthy
        }
        (ResolverHealthState::Degraded, ResolverEvent::StartCooldown) => {
            ResolverHealthState::Cooling
        }
        (ResolverHealthState::Degraded, ResolverEvent::MarkDead) => ResolverHealthState::Dead,
        (ResolverHealthState::Cooling, ResolverEvent::CooldownExpired) => {
            ResolverHealthState::Probing
        }
        (ResolverHealthState::Cooling, ResolverEvent::MarkDead) => ResolverHealthState::Dead,
        (ResolverHealthState::Dead, ResolverEvent::Revive) => ResolverHealthState::Probing,
        _ => {
            return Err(TransitionError::new(
                MachineKind::Resolver,
                resolver_state_name(state),
                resolver_event_name(event),
            ));
        }
    };

    Ok(next)
}

pub fn validate_stream_transition(
    state: StreamState,
    event: StreamEvent,
) -> Result<StreamState, TransitionError> {
    let next = match (state, event) {
        (StreamState::Idle, StreamEvent::Open) => StreamState::Open,
        (StreamState::Open, StreamEvent::LocalFin) => StreamState::FinLocal,
        (StreamState::Open, StreamEvent::RemoteFin) => StreamState::FinRemote,
        (StreamState::Open, StreamEvent::Reset) => StreamState::Reset,
        (StreamState::FinLocal, StreamEvent::RemoteFin) => StreamState::Closed,
        (StreamState::FinLocal, StreamEvent::AckClose) => StreamState::Closed,
        (StreamState::FinLocal, StreamEvent::Reset) => StreamState::Reset,
        (StreamState::FinRemote, StreamEvent::LocalFin) => StreamState::Closed,
        (StreamState::FinRemote, StreamEvent::AckClose) => StreamState::Closed,
        (StreamState::FinRemote, StreamEvent::Reset) => StreamState::Reset,
        (StreamState::Reset, StreamEvent::AckClose) => StreamState::Closed,
        _ => {
            return Err(TransitionError::new(
                MachineKind::Stream,
                stream_state_name(state),
                stream_event_name(event),
            ));
        }
    };

    Ok(next)
}

fn conn_state_name(state: ConnState) -> &'static str {
    match state {
        ConnState::Init => "Init",
        ConnState::Handshaking => "Handshaking",
        ConnState::Active => "Active",
        ConnState::Degraded => "Degraded",
        ConnState::Recovering => "Recovering",
        ConnState::Draining => "Draining",
        ConnState::Closed => "Closed",
    }
}

fn conn_event_name(event: ConnEvent) -> &'static str {
    match event {
        ConnEvent::StartHandshake => "StartHandshake",
        ConnEvent::HandshakeReady => "HandshakeReady",
        ConnEvent::HandshakeFailed => "HandshakeFailed",
        ConnEvent::Degrade => "Degrade",
        ConnEvent::Recover => "Recover",
        ConnEvent::Drain => "Drain",
        ConnEvent::Close => "Close",
    }
}

fn resolver_state_name(state: ResolverHealthState) -> &'static str {
    match state {
        ResolverHealthState::Unknown => "Unknown",
        ResolverHealthState::Probing => "Probing",
        ResolverHealthState::Healthy => "Healthy",
        ResolverHealthState::Degraded => "Degraded",
        ResolverHealthState::Cooling => "Cooling",
        ResolverHealthState::Dead => "Dead",
    }
}

fn resolver_event_name(event: ResolverEvent) -> &'static str {
    match event {
        ResolverEvent::ProbeStarted => "ProbeStarted",
        ResolverEvent::ProbeSucceeded => "ProbeSucceeded",
        ResolverEvent::ProbeFailed => "ProbeFailed",
        ResolverEvent::MarkDegraded => "MarkDegraded",
        ResolverEvent::StartCooldown => "StartCooldown",
        ResolverEvent::CooldownExpired => "CooldownExpired",
        ResolverEvent::MarkDead => "MarkDead",
        ResolverEvent::Revive => "Revive",
    }
}

fn stream_state_name(state: StreamState) -> &'static str {
    match state {
        StreamState::Idle => "Idle",
        StreamState::Open => "Open",
        StreamState::FinLocal => "FinLocal",
        StreamState::FinRemote => "FinRemote",
        StreamState::Closed => "Closed",
        StreamState::Reset => "Reset",
    }
}

fn stream_event_name(event: StreamEvent) -> &'static str {
    match event {
        StreamEvent::Open => "Open",
        StreamEvent::LocalFin => "LocalFin",
        StreamEvent::RemoteFin => "RemoteFin",
        StreamEvent::AckClose => "AckClose",
        StreamEvent::Reset => "Reset",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        validate_conn_transition, validate_resolver_transition, validate_stream_transition,
        ConnEvent, ConnState, MachineKind, ResolverEvent, ResolverHealthState, StreamEvent,
        StreamState,
    };

    #[test]
    fn connection_transition_happy_path() {
        let state = validate_conn_transition(ConnState::Init, ConnEvent::StartHandshake)
            .expect("start handshake should succeed");
        let state = validate_conn_transition(state, ConnEvent::HandshakeReady)
            .expect("handshake ready should succeed");
        let state =
            validate_conn_transition(state, ConnEvent::Degrade).expect("degrade should succeed");
        let state =
            validate_conn_transition(state, ConnEvent::Recover).expect("recover should succeed");
        let state =
            validate_conn_transition(state, ConnEvent::Drain).expect("drain should succeed");
        let state =
            validate_conn_transition(state, ConnEvent::Close).expect("close should succeed");
        assert_eq!(state, ConnState::Closed);
    }

    #[test]
    fn rejects_connection_invalid_transition_with_context() {
        let err = validate_conn_transition(ConnState::Init, ConnEvent::Recover)
            .expect_err("recover from init should fail");
        assert_eq!(err.machine, MachineKind::Connection);
        assert_eq!(err.state, "Init");
        assert_eq!(err.event, "Recover");
    }

    #[test]
    fn resolver_transition_happy_path() {
        let state =
            validate_resolver_transition(ResolverHealthState::Unknown, ResolverEvent::ProbeStarted)
                .expect("probe start should succeed");
        let state = validate_resolver_transition(state, ResolverEvent::ProbeSucceeded)
            .expect("probe success should succeed");
        let state = validate_resolver_transition(state, ResolverEvent::MarkDegraded)
            .expect("degrade should succeed");
        let state = validate_resolver_transition(state, ResolverEvent::StartCooldown)
            .expect("start cooldown should succeed");
        let state = validate_resolver_transition(state, ResolverEvent::CooldownExpired)
            .expect("cooldown expiry should succeed");
        assert_eq!(state, ResolverHealthState::Probing);
    }

    #[test]
    fn resolver_dead_can_revive_to_probing() {
        let state = validate_resolver_transition(ResolverHealthState::Dead, ResolverEvent::Revive)
            .expect("revive should succeed");
        assert_eq!(state, ResolverHealthState::Probing);
    }

    #[test]
    fn stream_transition_happy_path() {
        let state = validate_stream_transition(StreamState::Idle, StreamEvent::Open)
            .expect("open should succeed");
        let state = validate_stream_transition(state, StreamEvent::LocalFin)
            .expect("local fin should succeed");
        let state = validate_stream_transition(state, StreamEvent::RemoteFin)
            .expect("remote fin should succeed");
        assert_eq!(state, StreamState::Closed);
    }

    #[test]
    fn stream_invalid_transition_reports_context() {
        let err = validate_stream_transition(StreamState::Idle, StreamEvent::RemoteFin)
            .expect_err("remote fin from idle should fail");
        assert_eq!(err.machine, MachineKind::Stream);
        assert_eq!(err.state, "Idle");
        assert_eq!(err.event, "RemoteFin");
    }
}
