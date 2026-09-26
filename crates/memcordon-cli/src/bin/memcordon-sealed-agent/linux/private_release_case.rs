//! Separate release-matrix admission. The installed eight-case host canary is
//! not a release qualification, and no case may be inferred from its result.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use sha2::{Digest, Sha256};

pub(crate) use memcordon_core::private_release_case_v1::{
    PRIVATE_RELEASE_RESULT_ROOT_V1 as RESULT_ROOT,
    REQUIRED_PRIVATE_RELEASE_SELECTORS_V1 as REQUIRED_SELECTORS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReleaseStageV1 {
    CandidateCapability,
    FinalPublic,
}

impl ReleaseStageV1 {
    fn parse(value: &OsStr) -> Result<Self, String> {
        match value.to_str() {
            Some("candidate-capability") => Ok(Self::CandidateCapability),
            Some("final-public") => Ok(Self::FinalPublic),
            _ => Err("MCSEALED-PRIVATE-RELEASE: stage differs from fixed catalogue".into()),
        }
    }

    fn core_stage(self) -> PrivateReleaseStageV1 {
        match self {
            Self::CandidateCapability => PrivateReleaseStageV1::CandidateCapability,
            Self::FinalPublic => PrivateReleaseStageV1::FinalPublic,
        }
    }
}

pub(crate) struct ReleaseCaseRequestV1 {
    pub(crate) stage: ReleaseStageV1,
    pub(crate) selector: &'static str,
    pub(crate) challenge: [u8; 32],
}

impl ReleaseCaseRequestV1 {
    pub(crate) fn parse(
        stage: &OsStr,
        selector: &OsStr,
        challenge: &OsStr,
    ) -> Result<Self, String> {
        let stage = ReleaseStageV1::parse(stage)?;
        let selector = selector
            .to_str()
            .and_then(|value| REQUIRED_SELECTORS.into_iter().find(|fixed| *fixed == value))
            .ok_or("MCSEALED-PRIVATE-RELEASE: selector differs from fixed catalogue")?;
        let text = challenge
            .to_str()
            .ok_or("MCSEALED-PRIVATE-RELEASE: challenge is not UTF-8")?;
        let mut decoded = [0_u8; 32];
        if text.len() != decoded.len() * 2
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("MCSEALED-PRIVATE-RELEASE: challenge syntax differs".into());
        }
        for (index, byte) in decoded.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&text[offset..offset + 2], 16)
                .map_err(|_| "MCSEALED-PRIVATE-RELEASE: challenge syntax differs")?;
        }
        if decoded == [0; 32] {
            return Err("MCSEALED-PRIVATE-RELEASE: zero challenge rejected".into());
        }
        Ok(Self {
            stage,
            selector,
            challenge: decoded,
        })
    }

    pub(crate) fn result_key(&self) -> DiagnosticSha256 {
        private_release_case_key_v1(self.stage.core_stage(), self.selector, &self.challenge)
            .expect("parsed fixed release-case identity remains valid")
    }

    pub(crate) fn result_path(&self) -> PathBuf {
        let key: String = self.result_key().into();
        Path::new(RESULT_ROOT).join(format!("{key}.json"))
    }
}

/// The release-matrix command is deliberately distinct from the installed H1
/// canary. Only physically implemented candidate selectors can acquire a
/// protected result after detached service-owned readback; that result is not Q.
pub(crate) fn run(request: ReleaseCaseRequestV1) -> Result<(), String> {
    run_candidate_transport(request, false)
}

pub(crate) fn run_caller_spoof(request: ReleaseCaseRequestV1) -> Result<(), String> {
    super::private_release_run::IndependentCallerProbeV2::prepare(request)?.run()
}

pub(crate) fn run_facility_controls(
    request: ReleaseCaseRequestV1,
    revision: &DiagnosticSha256,
) -> Result<(), String> {
    super::private_release_run::IndependentFacilityProbeV1::prepare(request, revision)?.run()
}

pub(crate) fn run_reuse_source(
    request: ReleaseCaseRequestV1,
    revision: &DiagnosticSha256,
    phase: memcordon_core::private_reuse_source_v1::ReuseSourcePhaseV1,
) -> Result<(), String> {
    super::private_release_run::IndependentReuseSourceV1::prepare(request, revision, phase)?.run()
}

pub(crate) fn run_abi_raw(request: ReleaseCaseRequestV1) -> Result<(), String> {
    if request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != super::private_release_alt_abi::SELECTOR
    {
        return Err(
            "MCSEALED-PRIVATE-RELEASE: ABI raw verb accepts only fixed candidate selector".into(),
        );
    }
    run_candidate_transport(request, true)
}

fn run_candidate_transport(
    request: ReleaseCaseRequestV1,
    abi_raw_only: bool,
) -> Result<(), String> {
    // SAFETY: geteuid has no pointer arguments and returns the kernel identity.
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: root supervisor required".into());
    }
    match request.stage {
        ReleaseStageV1::CandidateCapability => {
            let current = std::fs::metadata(
                std::env::current_exe().map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let installed = std::fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent")
                .map_err(|error| error.to_string())?;
            use std::os::unix::fs::MetadataExt;
            if !installed.is_file()
                || current.dev() != installed.dev()
                || current.ino() != installed.ino()
            {
                return Err("MCSEALED-PRIVATE-RELEASE: invoke installed agent image".into());
            }
            let status = std::process::Command::new("systemctl")
                .arg("start")
                .arg("memcordon-sealed-network-launcher.socket")
                .status()
                .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: start socket: {error}"))?;
            if !status.success() {
                return Err(format!(
                    "MCSEALED-PRIVATE-RELEASE: start socket exited {status}"
                ));
            }
            if abi_raw_only {
                super::service::request_release_candidate_abi_raw(&request)
            } else if request.selector == "private_tcp::wrong_grant_profile_and_port_rejected" {
                super::private_policy_decision_peer::run_root_supervised(&request)
            } else {
                super::service::request_release_candidate_case(&request)
            }
        }
        ReleaseStageV1::FinalPublic => Err(
            "MCSEALED-PRIVATE-RELEASE: final public V2 lease and native case owner unavailable; no result written"
                .into(),
        ),
    }
}

pub(crate) fn run_policy_branch_raw(base_challenge: &OsStr, branch: &OsStr) -> Result<(), String> {
    let mut request = ReleaseCaseRequestV1::parse(
        OsStr::new("candidate-capability"),
        OsStr::new("private_tcp::wrong_grant_profile_and_port_rejected"),
        base_challenge,
    )?;
    let branch = branch
        .to_str()
        .and_then(|value| {
            memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::ALL
                .into_iter()
                .find(|branch| branch.as_str() == value)
        })
        .ok_or("MCSEALED-PRIVATE-RELEASE: policy branch differs from fixed catalogue")?;
    request.challenge = memcordon_core::private_release_branch_v1::policy_branch_challenge_v1(
        &request.challenge,
        branch,
    )
    .map_err(str::to_owned)?;
    run(request)
}

/// Fixed target fixtures emit challenge-bound raw observations, never native
/// case results or qualification authority.
pub(crate) fn run_candidate_fixture(selector: &OsStr) -> Result<(), String> {
    run_fixture(selector, None, None)
}

/// Fixed unprivileged target entry; argv carries only catalogue selector and
/// challenge. Faults and allocation authority remain supervisor-owned.
pub(crate) fn run_public_fixture(selector: &OsStr, challenge_hex: &OsStr) -> Result<(), String> {
    run_public_fixture_with_port(selector, challenge_hex, None)
}

pub(crate) fn run_public_fixture_with_port(
    selector: &OsStr,
    challenge_hex: &OsStr,
    port: Option<&OsStr>,
) -> Result<(), String> {
    let text = challenge_hex
        .to_str()
        .ok_or("public fixture challenge is not UTF-8")?;
    let mut challenge = [0_u8; 32];
    if text.len() != challenge.len() * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("public fixture challenge syntax differs".into());
    }
    for (output, pair) in challenge.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or("challenge digit invalid")?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or("challenge digit invalid")?;
        *output = ((high << 4) | low) as u8;
    }
    if challenge == [0; 32] {
        return Err("public fixture challenge is zero".into());
    }
    let port = port
        .map(|value| {
            value
                .to_str()
                .ok_or("public port UTF-8")?
                .parse::<u16>()
                .map_err(|_| "public port syntax differs")
        })
        .transpose()?;
    if port == Some(0) {
        return Err("public port zero".into());
    }
    run_fixture(selector, Some(challenge), port)
}

fn run_fixture(
    selector: &OsStr,
    supplied_challenge: Option<[u8; 32]>,
    public_port: Option<u16>,
) -> Result<(), String> {
    let selector = selector
        .to_str()
        .ok_or("MCSEALED-PRIVATE-RELEASE-FIXTURE: selector is not UTF-8")?;
    if !candidate_executable_fixture_supported(selector)
        && !(supplied_challenge.is_some()
            && selector == super::private_release_unix_intent::SELECTOR)
    {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: selector unavailable".into());
    }
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    // SAFETY: each call writes only three live scalar output slots.
    if unsafe { libc::getresuid(&raw mut real_uid, &raw mut effective_uid, &raw mut saved_uid) }
        != 0
        || unsafe { libc::getresgid(&raw mut real_gid, &raw mut effective_gid, &raw mut saved_gid) }
            != 0
        || real_uid == 0
        || real_gid == 0
        || real_uid != effective_uid
        || real_uid != saved_uid
        || real_gid != effective_gid
        || real_gid != saved_gid
        // SAFETY: a null getgroups buffer with size zero queries only count.
        || unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: target credentials differ".into());
    }
    let mut challenge = supplied_challenge.unwrap_or([0; 32]);
    if supplied_challenge.is_none() {
        std::io::stdin()
            .read_exact(&mut challenge)
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: challenge: {error}"))?;
    }
    hold_post_exec_baseline(&challenge)?;
    run_fixture_operations(selector, supplied_challenge, public_port, challenge)
}

pub(crate) fn hold_post_exec_baseline(challenge: &[u8; 32]) -> Result<(), String> {
    // Retain the actual scalar syscall return in the independent observer.
    // The target never sets securebits here; a failed query is not a value.
    let securebits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
    if securebits != 3 {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: actual securebits differ".into());
    }
    // The first post-exec observation precedes sockets, children, namespace
    // probes, descriptor projection, and other selector operations. It does
    // not claim clean entry: the root observer samples that independently.
    let mut baseline = b"MCBL\x01\0\0\0".to_vec();
    baseline.extend_from_slice(challenge);
    baseline.extend_from_slice(&securebits.to_le_bytes());
    baseline.extend_from_slice(&0_u32.to_le_bytes());
    std::io::stdout()
        .write_all(&baseline)
        .and_then(|()| std::io::stdout().flush())
        .map_err(|error| error.to_string())?;
    let mut baseline_ack = [0_u8; 32];
    std::io::stdin()
        .read_exact(&mut baseline_ack)
        .map_err(|error| format!("fixture baseline ACK: {error}"))?;
    let mut ack_input = b"memcordon/private-fixture-baseline-ack/v1\0".to_vec();
    ack_input.extend_from_slice(&baseline);
    if baseline_ack != *memcordon_core::workload_codec::hash_bytes(&ack_input).bytes() {
        return Err("fixture baseline ACK differs".into());
    }
    Ok(())
}

fn run_fixture_operations(
    selector: &str,
    supplied_challenge: Option<[u8; 32]>,
    public_port: Option<u16>,
    challenge: [u8; 32],
) -> Result<(), String> {
    if supplied_challenge.is_some() {
        if matches!(
            selector,
            super::private_release_unix_intent::SELECTOR
                | super::private_release_children::SELECTOR
                | super::private_release_terminal_join::SELECTOR
        ) {
            // This public-only versioned target emission supplies the exec
            // response independently of the following operation transcript.
            // The original special operation frames and ACKs are unchanged.
            let response =
                memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
                    selector, &challenge, 0,
                )?;
            if response.len() != challenge.len() {
                return Err("public exec response width differs".into());
            }
            std::io::stdout()
                .write_all(b"MCEX\x01\0\0\0")
                .and_then(|()| std::io::stdout().write_all(&response))
                .and_then(|()| std::io::stdout().flush())
                .map_err(|error| format!("public exec response emission: {error}"))?;
        }
        if selector == super::private_release_unix_intent::SELECTOR {
            let bytes = super::private_release_unix_intent::observe_target_denials(&challenge)?;
            return write_public_held_fixture(&bytes, &challenge);
        }
        if selector == super::private_release_socket_launder::SELECTOR {
            let port = public_port
                .ok_or("public SCM clean-entry fixture requires exact request --port")?;
            let projection = super::private_release_descriptors::observe_target_projection()?;
            if projection != super::private_release_socket_launder::expected_target_suffix() {
                return Err("public SCM clean-entry socket projection differs".into());
            }
            super::private_qualification::tcp_listener_client_competitor_held(
                &challenge,
                Some(port),
                |_| {
                    let mut output = candidate_fixture_response(selector, &challenge).to_vec();
                    output.extend_from_slice(&projection);
                    write_public_held_fixture(&output, &challenge)
                },
            )?;
            return Ok(());
        }
        if matches!(
            selector,
            TOPOLOGY_SELECTOR | super::private_release_denial::NAMESPACE_SELECTOR
        ) {
            let port =
                public_port.ok_or("public topology fixture requires exact request --port")?;
            super::private_public_release_case::run_final_public_topology_fixture(
                selector,
                challenge,
                port,
                |observed| {
                    let bytes = serde_json::to_vec(observed).map_err(|error| error.to_string())?;
                    write_public_held_fixture(&bytes, &challenge)
                },
            )?;
            return Ok(());
        }
        if matches!(
            selector,
            "private_tcp::native_tcp_bind_listen_connect"
                | "private_tcp::frontend_loss_retired"
                | "private_tcp::guardian_loss_retired"
                | "private_tcp::dual_attempt_namespace_isolation"
        ) {
            let port = public_port.ok_or("public TCP fixture requires exact request --port")?;
            super::private_public_release_case::run_final_public_tcp_fixture(
                challenge,
                port,
                selector == "private_tcp::dual_attempt_namespace_isolation",
                |observed| {
                    let bytes = serde_json::to_vec(observed).map_err(|error| error.to_string())?;
                    write_public_held_fixture(&bytes, &challenge)
                },
            )?;
            return Ok(());
        }
        if selector == super::private_release_denial::PORT_COLLISION_SELECTOR {
            let port =
                public_port.ok_or("public collision fixture requires exact request --port")?;
            super::private_public_release_case::run_final_public_port_collision_fixture(
                challenge,
                port,
                |observed| {
                    let bytes = serde_json::to_vec(observed).map_err(|error| error.to_string())?;
                    write_public_held_fixture(&bytes, &challenge)
                },
            )?;
            return Ok(());
        }
    }
    if selector == super::private_release_guardian_loss::SELECTOR {
        return super::private_release_guardian_loss::run_target(&challenge);
    }
    if selector == super::private_release_frontend_loss::SELECTOR {
        return super::private_release_frontend_loss::run_target(&challenge);
    }
    if selector == super::private_release_children::SELECTOR {
        return super::private_release_children::run_target(&challenge);
    }
    if selector == super::private_release_terminal_join::SELECTOR {
        return super::private_release_terminal_join::run_target(&challenge);
    }
    if selector == super::private_release_dual_attempt::SELECTOR {
        return super::private_release_dual_attempt::run_target(&challenge);
    }
    if supplied_challenge.is_none()
        && matches!(
            selector,
            "private_tcp::native_tcp_bind_listen_connect"
                | super::private_release_denial::PORT_COLLISION_SELECTOR
                | super::private_release_socket_launder::SELECTOR
                | TOPOLOGY_SELECTOR
        )
    {
        let socket_projection = if selector == super::private_release_socket_launder::SELECTOR {
            let projection = super::private_release_descriptors::observe_target_projection()?;
            if projection != super::private_release_socket_launder::expected_target_suffix() {
                return Err("candidate exceptional socket survived exec".into());
            }
            Some(projection)
        } else {
            None
        };
        return super::private_qualification::tcp_listener_client_competitor_held(
            &challenge,
            Some(memcordon_core::private_release_case_v1::candidate_fixture_port_v1(&challenge)),
            |errno| {
                let mut output = candidate_fixture_response(selector, &challenge).to_vec();
                if selector == super::private_release_denial::PORT_COLLISION_SELECTOR {
                    output.extend_from_slice(&errno.to_le_bytes());
                }
                if selector == TOPOLOGY_SELECTOR {
                    use std::os::unix::fs::MetadataExt;
                    output.extend_from_slice(
                        &std::fs::metadata("/proc/self/ns/net")
                            .map_err(|error| error.to_string())?
                            .ino()
                            .to_le_bytes(),
                    );
                }
                if let Some(projection) = socket_projection {
                    output.extend_from_slice(&projection);
                }
                write_candidate_held_response(&output, &challenge)
            },
        )
        .map(|_| ());
    }
    let mut output = candidate_fixture_response(selector, &challenge).to_vec();
    match selector {
        "private_tcp::native_tcp_bind_listen_connect"
        | super::private_release_caller::SELECTOR
        | super::private_release_alt_abi::SELECTOR
        | RETIREMENT_FAULT_SELECTOR
        | CHECKPOINT_GATE_SELECTOR => {
            super::private_qualification::tcp_listener_client_competitor(&challenge)?;
        }
        super::private_release_denial::SELECTOR => {
            output.extend_from_slice(&super::private_release_denial::observe_target_denials()?);
        }
        super::private_release_denial::IMPORT_SELECTOR => {
            output.extend_from_slice(&super::private_release_denial::observe_import_denials()?);
        }
        super::private_release_denial::NAMESPACE_SELECTOR => {
            output.extend_from_slice(&super::private_release_denial::observe_namespace_denials()?);
        }
        super::private_release_denial::PORT_COLLISION_SELECTOR => {
            output.extend_from_slice(&super::private_release_denial::observe_port_collision(
                &challenge,
            )?);
        }
        super::private_release_identity::SELECTOR => {
            output
                .extend_from_slice(&super::private_release_identity::observe_target_projection()?);
        }
        super::private_release_filter::SELECTOR => {
            output.extend_from_slice(&super::private_release_filter::observe_target_projection()?);
        }
        super::private_release_descriptors::SELECTOR => {
            output.extend_from_slice(
                &super::private_release_descriptors::observe_target_projection()?,
            );
        }
        super::private_release_socket_launder::SELECTOR => {
            output.extend_from_slice(&super::private_release_socket_launder::run_target(
                &challenge,
            )?);
        }
        super::private_release_host_state::SELECTOR => {
            output.extend_from_slice(
                &super::private_release_host_state::observe_target_private_projection()?,
            );
        }
        super::private_release_exec::SELECTOR => {
            output.extend_from_slice(&super::private_release_exec::observe_target_projection()?);
        }
        super::private_release_ancestor::SELECTOR => {
            output.extend_from_slice(&super::private_release_exec::observe_target_projection()?);
        }
        TOPOLOGY_SELECTOR => {
            use std::os::unix::fs::MetadataExt;
            let inode = std::fs::metadata("/proc/self/ns/net")
                .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: netns: {error}"))?
                .ino();
            if inode == 0 {
                return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: netns inode is zero".into());
            }
            output.extend_from_slice(&inode.to_le_bytes());
        }
        _ => return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: selector unavailable".into()),
    }
    if supplied_challenge.is_some() {
        return write_public_held_fixture(&output, &challenge);
    }
    if selector == RETIREMENT_FAULT_SELECTOR {
        std::io::stdout()
            .write_all(&output)
            .and_then(|()| std::io::stdout().flush())
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    write_candidate_held_response(&output, &challenge)
}

fn write_candidate_held_response(output: &[u8], challenge: &[u8; 32]) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&output)
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: response: {error}"))?;
    let mut waiting = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: fixed stdin is the reviewed one-shot observer ACK channel.
    if unsafe { libc::poll(&raw mut waiting, 1, 45_000) } != 1
        || waiting.revents & libc::POLLIN == 0
        || waiting.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0
    {
        return Err("candidate fixture observer ACK timed out".into());
    }
    let mut ack = [0_u8; 32];
    std::io::stdin().read_exact(&mut ack).map_err(|error| {
        format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: candidate observer ACK: {error}")
    })?;
    if ack != *super::private_release_unix_intent::observer_ack_digest(&challenge).bytes() {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: candidate observer ACK differs".into());
    }
    Ok(())
}

fn write_public_held_fixture(bytes: &[u8], challenge: &[u8; 32]) -> Result<(), String> {
    let size = u32::try_from(bytes.len()).map_err(|_| "public fixture response size overflow")?;
    let mut frame = b"MCPH\x01\0\0\0".to_vec();
    frame.extend_from_slice(&size.to_le_bytes());
    frame.extend_from_slice(bytes);
    std::io::stdout()
        .write_all(&frame)
        .and_then(|()| std::io::stdout().flush())
        .map_err(|error| error.to_string())?;
    let mut ack = [0_u8; 32];
    std::io::stdin()
        .read_exact(&mut ack)
        .map_err(|error| format!("public observer ACK: {error}"))?;
    if ack != *super::private_release_unix_intent::observer_ack_digest(challenge).bytes() {
        return Err("public observer ACK differs".into());
    }
    Ok(())
}

pub(crate) fn candidate_fixture_supported(selector: &str) -> bool {
    selector == "private_tcp::native_tcp_bind_listen_connect"
        || selector == super::private_release_caller::SELECTOR
        || selector == super::private_release_alt_abi::SELECTOR
        || selector == super::private_release_denial::SELECTOR
        || selector == super::private_release_denial::IMPORT_SELECTOR
        || selector == super::private_release_denial::NAMESPACE_SELECTOR
        || selector == super::private_release_denial::PORT_COLLISION_SELECTOR
        || selector == super::private_release_identity::SELECTOR
        || selector == super::private_release_filter::SELECTOR
        || selector == super::private_release_descriptors::SELECTOR
        || selector == super::private_release_host_state::SELECTOR
        || selector == super::private_release_exec::SELECTOR
        || selector == super::private_release_ancestor::SELECTOR
        || selector == TOPOLOGY_SELECTOR
}

/// Fault selectors use the same fixed gated ELF setup, but only the durable
/// retirement fault executes a target fixture. Neither may enter the normal
/// TargetCompleted result constructor.
pub(crate) fn candidate_physical_selector_supported(selector: &str) -> bool {
    candidate_executable_fixture_supported(selector)
        || selector == AUTHORIZATION_UNCERTAIN_SELECTOR
        || selector == super::private_release_unix_intent::SELECTOR
}

pub(crate) fn candidate_executable_fixture_supported(selector: &str) -> bool {
    candidate_fixture_supported(selector)
        || selector == RETIREMENT_FAULT_SELECTOR
        || selector == CHECKPOINT_GATE_SELECTOR
        || selector == super::private_release_guardian_loss::SELECTOR
        || selector == super::private_release_frontend_loss::SELECTOR
        || selector == super::private_release_children::SELECTOR
        || selector == super::private_release_socket_launder::SELECTOR
        || selector == super::private_release_terminal_join::SELECTOR
        || selector == super::private_release_dual_attempt::SELECTOR
}

pub(crate) const TOPOLOGY_SELECTOR: &str = "private_tcp::private_namespace_topology_exact";
pub(crate) const AUTHORIZATION_UNCERTAIN_SELECTOR: &str =
    "private_tcp::authorization_uncertainty_retired";
pub(crate) const RETIREMENT_FAULT_SELECTOR: &str = "private_tcp::retirement_failure_blocks_reuse";
pub(crate) const CHECKPOINT_GATE_SELECTOR: &str =
    "private_tcp::checkpoint_persisted_before_release";

/// The dynamic suffix must come from gated kernel readback, never from target
/// stdout. The target separately reads its own nsfs inode and must match it.
pub(crate) fn candidate_fixture_output_with_native(
    selector: &str,
    challenge: &[u8; 32],
    gated_namespace_inode: u64,
    pinned_image_identity: (u64, u64),
) -> Result<Vec<u8>, String> {
    if !candidate_executable_fixture_supported(selector) || gated_namespace_inode == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: gated namespace identity unavailable".into());
    }
    memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1(
        super::runtime_manifest::target()?,
        selector,
        challenge,
        Some(gated_namespace_inode),
        Some(pinned_image_identity),
    )
    .map_err(str::to_owned)
}

pub(crate) fn candidate_fixture_output(selector: &str, challenge: &[u8; 32]) -> Vec<u8> {
    assert_ne!(
        selector, TOPOLOGY_SELECTOR,
        "dynamic namespace evidence required"
    );
    assert!(
        selector != super::private_release_exec::SELECTOR
            && selector != super::private_release_ancestor::SELECTOR,
        "pinned executable identity required"
    );
    memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1(
        super::runtime_manifest::target().expect("reviewed native candidate target"),
        selector,
        challenge,
        None,
        None,
    )
    .expect("fixed executable fixture uses the reviewed non-dynamic codec")
}

pub(crate) fn candidate_fixture_response(selector: &str, challenge: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-candidate-fixture-v1\0");
    digest.update(selector.as_bytes());
    digest.update([0]);
    digest.update(challenge);
    digest.finalize().into()
}
