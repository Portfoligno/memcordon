//! Static context around existing operations; the original error stays owned.
use std::{fmt, io};

#[derive(Clone, Copy, Debug)]
pub enum Operation {
    ListenerLocalAddress,
    CompetingBind,
    TranscriptConflictingBind,
    TranscriptListenerOwned,
    ChallengeWrite,
    PeerStdoutCreate,
    PeerStdoutDuplicate,
    PeerStdoutValidate,
    CurrentExecutable,
    PeerCommandSpawn,
    TranscriptSpawnIntent,
    PendingPeerIdentity,
    TranscriptPendingAdmission,
    PeerRecipientAdmission,
    RegistryMetadataHandoff,
    PeerIdentity,
    TranscriptPeerCreated,
}

impl Operation {
    pub fn label(self) -> &'static str {
        match self {
            Self::ListenerLocalAddress => "listener-local-address",
            Self::CompetingBind => "competing-bind-expected-WSAEADDRINUSE",
            Self::TranscriptConflictingBind => "transcript-conflicting-bind",
            Self::TranscriptListenerOwned => "transcript-listener-owned",
            Self::ChallengeWrite => "tcp-challenge-write",
            Self::PeerStdoutCreate => "peer-stdout-create-owned-file",
            Self::PeerStdoutDuplicate => "peer-stdout-duplicate-held-file",
            Self::PeerStdoutValidate => "peer-stdout-validate-after-retirement",
            Self::CurrentExecutable => "current-executable-lookup",
            Self::PeerCommandSpawn => "peer-command-spawn",
            Self::TranscriptSpawnIntent => "transcript-peer-spawn-intent",
            Self::PendingPeerIdentity => "pending-peer-identity",
            Self::TranscriptPendingAdmission => "transcript-peer-pending-admission",
            Self::PeerRecipientAdmission => "peer-recipient-admission",
            Self::RegistryMetadataHandoff => "peer-registry-metadata-handoff",
            Self::PeerIdentity => "peer-created-identity",
            Self::TranscriptPeerCreated => "transcript-peer-created",
        }
    }
}

#[derive(Debug)]
pub struct Failure {
    operation: Operation,
    original: io::Error,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [original_native_code={:?}]: {}",
            self.operation.label(),
            self.original.raw_os_error(),
            self.original
        )
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}

pub fn context<T>(operation: Operation, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|original| {
        io::Error::new(
            original.kind(),
            Failure {
                operation,
                original,
            },
        )
    })
}
