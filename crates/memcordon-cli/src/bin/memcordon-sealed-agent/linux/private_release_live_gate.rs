//! Protected, phase-separated sampling barriers. These transport target identities
//! and exact output; they do not attest to the observer's subsequent measurements.

use super::private_attempt::ProcessIdentityV4;

pub(crate) fn wait_pre_for_candidate<J: super::private_lifecycle::PrivateNativeJournal>(
    case: &super::private_release_run::ReleaseCandidateRunAuthorityV1,
    owner: &mut super::private_lifecycle::PrivateAttemptOwner<J>,
    target: &ProcessIdentityV4,
) -> Result<(), String> {
    wait_for_sample(
        case.protected_case_directory()?,
        case.selector(),
        case.protected_result_key()?,
        &case.challenge_bytes(),
        target,
        false,
        &[],
        case.deadline(),
        || owner.require_live_target_identity(target),
    )
}
use super::private_release_child_gate::{persist_atomic, protected_directory, read_leaf};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::Serialize;
use std::fs::File;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

/// Independently reopen the committed native record before any GO or fault
/// transport send. This barrier cannot itself assert durability or readback.
pub(crate) fn wait_release_intent_for_candidate(
    case: &super::private_release_run::ReleaseCandidateRunAuthorityV1,
    owner: &mut super::private_lifecycle::PrivateAttemptOwner<
        super::private_release_attempt::DurableReleaseCandidateAttemptV1,
    >,
    role: Option<super::private_release_dual_attempt::DualAttemptRoleV1>,
) -> Result<(), String> {
    use super::private_release_dual_attempt::DualAttemptRoleV1;
    let (phase, pending, gate, ack) = match role {
        None => (
            "release-intent-gated",
            "candidate-live-release-intent-v1.pending",
            "candidate-live-release-intent-v1.json",
            "candidate-live-release-intent-v1.ack",
        ),
        Some(DualAttemptRoleV1::First) => (
            "first-release-intent-gated",
            "candidate-first-release-intent-v1.pending",
            "candidate-first-release-intent-v1.json",
            "candidate-first-release-intent-v1.ack",
        ),
        Some(DualAttemptRoleV1::Second) => (
            "second-release-intent-gated",
            "candidate-second-release-intent-v1.pending",
            "candidate-second-release-intent-v1.json",
            "candidate-second-release-intent-v1.ack",
        ),
    };
    let target = owner.observe_unsent_checkpoint_gate()?;
    let directory = case.protected_case_directory()?;
    protected_directory(directory)?;
    let bytes = serde_json::to_vec(&LiveGateV1 {
        schema_version: 1,
        selector: case.selector(),
        result_key: case.protected_result_key()?,
        challenge_sha256: hash_bytes(&case.challenge_bytes()),
        phase,
        target: &target,
        raw_response: &[],
    })
    .map_err(|error| error.to_string())?;
    persist_atomic(directory, pending, gate, &bytes)?;
    let expected = hash_bytes(&bytes);
    loop {
        if owner.observe_unsent_checkpoint_gate()? != target {
            return Err("release-intent gated target changed".into());
        }
        if let Some(bytes) = read_leaf(directory, ack, true)? {
            if bytes.as_slice() != expected.bytes() {
                return Err("release-intent sampler ACK differs".into());
            }
            return Ok(());
        }
        if Instant::now() >= case.deadline() {
            return Err("release-intent sampler deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Consume only the fixed pre-operation frame, leaving all later fixture
/// output untouched. Relay pumping remains owned by the actual lifecycle.
pub(crate) fn wait_baseline_for_candidate(
    case: &super::private_release_run::ReleaseCandidateRunAuthorityV1,
    owner: &mut super::private_lifecycle::PrivateAttemptOwner<
        super::private_release_attempt::DurableReleaseCandidateAttemptV1,
    >,
    output: BorrowedFd<'_>,
    input: BorrowedFd<'_>,
    role: Option<u8>,
) -> Result<(), String> {
    let target = owner.observe_live_terminal_join_target()?;
    let mut frame = [0_u8; 48];
    let mut offset = 0;
    while offset < frame.len() {
        owner.require_live_target_identity(&target)?;
        owner.tick_relay_for_unix_observer()?;
        let mut descriptor = libc::pollfd {
            fd: output.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows one retained endpoint; read writes only the
        // unfilled suffix of a fixed live buffer and cannot eat later output.
        let ready = unsafe { libc::poll(&raw mut descriptor, 1, 0) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if ready > 0 {
            let count = unsafe {
                libc::read(
                    output.as_raw_fd(),
                    frame[offset..].as_mut_ptr().cast(),
                    frame.len() - offset,
                )
            };
            if count > 0 {
                offset += count as usize;
            } else if count == 0 {
                return Err("candidate baseline pipe closed".into());
            } else if !matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        if Instant::now() >= case.deadline() {
            return Err("candidate baseline deadline".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if &frame[..8] != b"MCBL\x01\0\0\0"
        || frame[8..40] != case.challenge_bytes()
        || frame[40..44] != 3_i32.to_le_bytes()
        || frame[44..] != 0_u32.to_le_bytes()
    {
        return Err("candidate actual baseline frame differs".into());
    }
    let (phase, pending, gate, ack) = match role {
        None => (
            "post-exec-baseline",
            "candidate-live-baseline-v1.pending",
            "candidate-live-baseline-v1.json",
            "candidate-live-baseline-v1.ack",
        ),
        Some(0) => (
            "first-post-exec-baseline",
            "candidate-first-baseline-v1.pending",
            "candidate-first-baseline-v1.json",
            "candidate-first-baseline-v1.ack",
        ),
        Some(1) => (
            "second-post-exec-baseline",
            "candidate-second-baseline-v1.pending",
            "candidate-second-baseline-v1.json",
            "candidate-second-baseline-v1.ack",
        ),
        _ => return Err("candidate baseline role differs".into()),
    };
    let directory = case.protected_case_directory()?;
    protected_directory(directory)?;
    let bytes = serde_json::to_vec(&LiveGateV1 {
        schema_version: 1,
        selector: case.selector(),
        result_key: case.protected_result_key()?,
        challenge_sha256: hash_bytes(&case.challenge_bytes()),
        phase,
        target: &target,
        raw_response: &frame,
    })
    .map_err(|error| error.to_string())?;
    persist_atomic(directory, pending, gate, &bytes)?;
    let expected = hash_bytes(&bytes);
    loop {
        owner.require_live_target_identity(&target)?;
        if let Some(ackbytes) = read_leaf(directory, ack, true)? {
            if ackbytes.as_slice() != expected.bytes() {
                return Err("candidate baseline root ACK differs".into());
            }
            break;
        }
        if Instant::now() >= case.deadline() {
            return Err("candidate baseline root sampler deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut ack_input = b"memcordon/private-fixture-baseline-ack/v1\0".to_vec();
    ack_input.extend_from_slice(&frame);
    let digest = hash_bytes(&ack_input);
    // SAFETY: the retained pipe/control endpoint receives one fixed scalar
    // protocol frame. Short writes are errors, never silently acknowledged.
    if unsafe {
        libc::write(
            input.as_raw_fd(),
            digest.bytes().as_ptr().cast(),
            digest.bytes().len(),
        )
    } != digest.bytes().len() as isize
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[derive(Serialize)]
struct LiveGateV1<'a> {
    schema_version: u8,
    selector: &'a str,
    result_key: &'a DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    phase: &'a str,
    target: &'a ProcessIdentityV4,
    raw_response: &'a [u8],
}

pub(crate) fn wait_for_sample(
    directory: &File,
    selector: &str,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    target: &ProcessIdentityV4,
    post_exec: bool,
    raw_response: &[u8],
    deadline: Instant,
    mut require_live: impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    wait_for_sample_with_role(
        directory,
        selector,
        result_key,
        challenge,
        target,
        post_exec,
        raw_response,
        deadline,
        require_live,
        None,
    )
}

pub(crate) fn wait_for_sample_with_role(
    directory: &File,
    selector: &str,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    target: &ProcessIdentityV4,
    post_exec: bool,
    raw_response: &[u8],
    deadline: Instant,
    mut require_live: impl FnMut() -> Result<(), String>,
    role: Option<u8>,
) -> Result<(), String> {
    protected_directory(directory)?;
    let (phase, pending, gate, ack) = if let Some(role) = role {
        if post_exec {
            if role != 1 {
                return Err("role-specific post retirement gate differs".into());
            }
            (
                "second-after-first-retired",
                "candidate-second-post-retirement-v1.pending",
                "candidate-second-post-retirement-v1.json",
                "candidate-second-post-retirement-v1.ack",
            )
        } else {
            match role {
                0 => (
                    "first-pre-exec-gated",
                    "candidate-first-pre-v1.pending",
                    "candidate-first-pre-v1.json",
                    "candidate-first-pre-v1.ack",
                ),
                1 => (
                    "second-pre-exec-gated",
                    "candidate-second-pre-v1.pending",
                    "candidate-second-pre-v1.json",
                    "candidate-second-pre-v1.ack",
                ),
                _ => return Err("role-specific pre gate differs".into()),
            }
        }
    } else if post_exec {
        (
            "post-exec-held",
            "candidate-live-post-v1.pending",
            "candidate-live-post-v1.json",
            "candidate-live-post-v1.ack",
        )
    } else {
        (
            "pre-exec-gated",
            "candidate-live-pre-v1.pending",
            "candidate-live-pre-v1.json",
            "candidate-live-pre-v1.ack",
        )
    };
    if raw_response.len() > 64 * 1024 || (!post_exec && !raw_response.is_empty()) {
        return Err("MCSEALED-PRIVATE-RELEASE: live gate response budget or phase differs".into());
    }
    require_live()?;
    let bytes = serde_json::to_vec(&LiveGateV1 {
        schema_version: 1,
        selector,
        result_key,
        challenge_sha256: hash_bytes(challenge),
        phase,
        target,
        raw_response,
    })
    .map_err(|error| error.to_string())?;
    persist_atomic(directory, pending, gate, &bytes)?;
    let expected = hash_bytes(&bytes);
    loop {
        require_live()?;
        if let Some(bytes) = read_leaf(directory, ack, true)? {
            if bytes.as_slice() != expected.bytes() {
                return Err("MCSEALED-PRIVATE-RELEASE: phase-specific sampler ACK differs".into());
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("MCSEALED-PRIVATE-RELEASE: phase-specific sampler ACK timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
