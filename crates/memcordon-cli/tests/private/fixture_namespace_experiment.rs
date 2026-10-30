//! Outcomes of the synthetic fresh-primary experiment, never installed readiness.
use super::protocol::{self, Cell, Phase, Request, Response};
use serde::Serialize;
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum OriginalOutcome {
    HeldAwaitingIdentity,
    OriginalEventAccessDenied,
    NamespaceRejected,
    NegativeEventAccessDenied,
}
#[derive(Clone, Copy, Debug)]
pub struct Binding {
    pub initial_identity: (u32, u64),
    pub current_identity: (u32, u64),
    /// Set only after mandatory native source/token readback succeeds.
    pub token_matches: bool,
    /// Set only after mandatory native source/default-ACL readback succeeds.
    pub default_acl_matches: bool,
}
pub fn classify_original(
    request: &Request,
    response: &Response,
    binding: Binding,
) -> io::Result<OriginalOutcome> {
    protocol::encode_request(request)?;
    protocol::encode_response(response)?;
    response.diagnostics.validate_correspondence(request)?;
    if request.nonce != response.nonce
        || binding.initial_identity.0 == 0
        || binding.initial_identity.1 == 0
        || binding.current_identity != binding.initial_identity
        || !binding.token_matches
        || !binding.default_acl_matches
    {
        return Err(io::Error::other(
            "experiment original response/source binding failed",
        ));
    }
    if response.phase == Phase::Held {
        if !matches!(request.cell, Cell::Local | Cell::Private)
            || !response.success
            || response.modify_denied != Some(true)
        {
            return Err(io::Error::other("experiment unexpected held result"));
        }
        return Ok(OriginalOutcome::HeldAwaitingIdentity);
    }
    if response.success
        || response.event_handle.is_some()
        || response.modify_denied.is_some()
        || response.raw_error == Some(0)
    {
        return Err(io::Error::other("experiment malformed negative result"));
    }
    match (request.cell, response.phase, response.raw_error) {
        (Cell::Local | Cell::Private, Phase::Event, Some(5)) => {
            Ok(OriginalOutcome::OriginalEventAccessDenied)
        }
        (Cell::NamespaceDenied, Phase::Namespace, Some(5))
        | (Cell::WrongBoundary, Phase::Namespace, Some(_)) => {
            Ok(OriginalOutcome::NamespaceRejected)
        }
        (Cell::EventDenied, Phase::Event, Some(5)) => {
            Ok(OriginalOutcome::NegativeEventAccessDenied)
        }
        _ => Err(io::Error::other(
            "experiment unexpected original API phase/error",
        )),
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Settlement {
    pub process_settled: bool,
    pub exit_zero: bool,
    pub identity_stable: bool,
    pub token_and_acl_stable: bool,
    pub event_sd_stable: bool,
    pub thread_stable: bool,
    pub resources_released: bool,
    pub held_identity_and_release_verified: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum FinalOutcome {
    HeldAndIdentityVerified,
    OriginalEventAccessDenied,
    NamespaceRejected,
    NegativeEventAccessDenied,
}
impl FinalOutcome {
    pub fn scenario_success(self) -> bool {
        self == Self::HeldAndIdentityVerified
    }
}
pub fn complete_cell(
    outcome: OriginalOutcome,
    settlement: &Settlement,
) -> io::Result<FinalOutcome> {
    if ![
        settlement.process_settled,
        settlement.exit_zero,
        settlement.identity_stable,
        settlement.token_and_acl_stable,
        settlement.event_sd_stable,
        settlement.thread_stable,
        settlement.resources_released,
    ]
    .into_iter()
    .all(|fact| fact)
    {
        return Err(io::Error::other(
            "experiment harness settlement/invariance failed",
        ));
    }
    if (outcome == OriginalOutcome::HeldAwaitingIdentity)
        != settlement.held_identity_and_release_verified
    {
        return Err(io::Error::other(
            "experiment live identity/release proof missing or falsely claimed",
        ));
    }
    Ok(match outcome {
        OriginalOutcome::HeldAwaitingIdentity => FinalOutcome::HeldAndIdentityVerified,
        OriginalOutcome::OriginalEventAccessDenied => FinalOutcome::OriginalEventAccessDenied,
        OriginalOutcome::NamespaceRejected => FinalOutcome::NamespaceRejected,
        OriginalOutcome::NegativeEventAccessDenied => FinalOutcome::NegativeEventAccessDenied,
    })
}
