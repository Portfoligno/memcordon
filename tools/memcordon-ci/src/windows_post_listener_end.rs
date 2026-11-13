//! Bounded frontend settlement after a private root's observed native failure.
use super::descriptor::controller_start::Binding;
use crate::windows_listener_wait::{ApplicationEnd, Identity, Owner};
use memcordon_platform::windows_private_fixture_binding::PrivateFixtureBinding;
use std::{fmt, io, time::Instant};

#[derive(Clone, Copy, Debug)]
pub enum Stage {
    BeforeOwnerCheck,
    AfterOwnerCheck,
    BeforePeerAdmission,
}
impl Stage {
    fn primary(self) -> &'static str {
        match self {
            Self::BeforeOwnerCheck => "native listener root is not held live",
            Self::AfterOwnerCheck => "native listener owner retired during observation",
            Self::BeforePeerAdmission => "private root retired before peer admission",
        }
    }
    pub fn abort(self, secondary: impl fmt::Display) -> io::Error {
        io::Error::other(format!(
            "{}; post-listener settlement evidence: {secondary}",
            self.primary()
        ))
    }
    pub fn original(self) -> io::Error {
        io::Error::other(self.primary())
    }
}

#[derive(Debug)]
pub struct Failure {
    pub ended: ApplicationEnd,
    pub stage: Stage,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; pid={}; birth={}; native-exit-status={}",
            self.stage.primary(),
            self.ended.identity.pid,
            self.ended.identity.birth,
            self.ended.status
        )
    }
}
impl std::error::Error for Failure {}

pub struct Evidence<'a> {
    pub expected_root: Identity,
    pub owner: Owner,
    pub start: Option<&'a Binding>,
    pub descriptor_sha256: [u8; 32],
    pub challenge: &'a [u8],
    pub port: u16,
    pub observed_guardian: Identity,
    pub held_guardians: &'a [Identity],
    pub declared_private: Option<&'a PrivateFixtureBinding>,
    pub retained_private: Option<&'a PrivateFixtureBinding>,
}

/// This permits only the existing bounded frontend wait. It does not establish
/// descendant absence, recipient retirement or release of any private input.
pub fn qualify(
    evidence: Evidence<'_>,
    stage: Stage,
    now: Instant,
    cutoff: Instant,
) -> Option<Failure> {
    let start = evidence.start?;
    let declared = evidence.declared_private?;
    let retained = evidence.retained_private?;
    let status = evidence.owner.exit_status?;
    (now < cutoff
        && status != 0
        && evidence.expected_root.pid != 0
        && evidence.expected_root.birth != 0
        && evidence.owner.identity == evidence.expected_root
        && start.pid == evidence.expected_root.pid
        && u128::from(start.birth) == evidence.expected_root.birth
        && start.descriptor_sha256 == evidence.descriptor_sha256
        && !evidence.challenge.is_empty()
        && start.challenge == evidence.challenge
        && evidence.port != 0
        && evidence.observed_guardian.pid != 0
        && evidence.observed_guardian.birth != 0
        && evidence.held_guardians == [evidence.observed_guardian]
        && retained == declared)
        .then_some(Failure {
            ended: ApplicationEnd {
                identity: evidence.expected_root,
                status,
            },
            stage,
        })
}
