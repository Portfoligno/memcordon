//! Directional relay outcomes; closed input never establishes target retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    Stdin,
    Stdout,
    Stderr,
}
impl Lane {
    pub fn label(self) -> &'static str {
        match self {
            Self::Stdin => "stdin",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endpoint {
    Source,
    Destination,
}
impl Endpoint {
    pub fn label(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteFailure {
    Retry,
    CloseInput,
    Fatal,
}
pub fn retryable(errno: Option<i32>) -> bool {
    matches!(errno, Some(libc::EAGAIN | libc::EINTR))
}
pub fn write_failure(lane: Lane, errno: Option<i32>) -> WriteFailure {
    if retryable(errno) {
        WriteFailure::Retry
    } else if lane == Lane::Stdin && errno == Some(libc::EPIPE) {
        WriteFailure::CloseInput
    } else {
        WriteFailure::Fatal
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollAction {
    Continue,
    CloseInput,
    InvalidDescriptor,
    FatalEndpoint,
}
pub fn poll_action(lane: Lane, endpoint: Endpoint, events: i16) -> PollAction {
    if events & libc::POLLNVAL != 0 {
        PollAction::InvalidDescriptor
    } else if events & libc::POLLERR == 0 {
        PollAction::Continue
    } else if lane == Lane::Stdin && endpoint == Endpoint::Destination {
        PollAction::CloseInput
    } else {
        PollAction::FatalEndpoint
    }
}
