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
            super::service::request_release_candidate_case(&request)
        }
        ReleaseStageV1::FinalPublic => Err(
            "MCSEALED-PRIVATE-RELEASE: final public V2 lease and native case owner unavailable; no result written"
                .into(),
        ),
    }
}

/// Fixed target fixtures emit challenge-bound raw observations, never native
/// case results or qualification authority.
pub(crate) fn run_candidate_fixture(selector: &OsStr) -> Result<(), String> {
    let selector = selector
        .to_str()
        .ok_or("MCSEALED-PRIVATE-RELEASE-FIXTURE: selector is not UTF-8")?;
    if !candidate_executable_fixture_supported(selector) {
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
    let mut challenge = [0_u8; 32];
    std::io::stdin()
        .read_exact(&mut challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: challenge: {error}"))?;
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
    let mut output = candidate_fixture_response(selector, &challenge).to_vec();
    match selector {
        "private_tcp::native_tcp_bind_listen_connect"
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
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&output)
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: response: {error}"))
}

pub(crate) fn candidate_fixture_supported(selector: &str) -> bool {
    selector == "private_tcp::native_tcp_bind_listen_connect"
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
    if selector == TOPOLOGY_SELECTOR {
        let mut output = candidate_fixture_response(selector, challenge).to_vec();
        output.extend_from_slice(&gated_namespace_inode.to_le_bytes());
        Ok(output)
    } else if selector == super::private_release_exec::SELECTOR
        || selector == super::private_release_ancestor::SELECTOR
    {
        let mut output = candidate_fixture_response(selector, challenge).to_vec();
        output.extend_from_slice(&super::private_release_exec::expected_projection(
            pinned_image_identity.0,
            pinned_image_identity.1,
        )?);
        Ok(output)
    } else {
        Ok(candidate_fixture_output(selector, challenge))
    }
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
    let mut output = candidate_fixture_response(selector, challenge).to_vec();
    if selector == super::private_release_denial::SELECTOR {
        output.extend_from_slice(&super::private_release_denial::expected_errno_bytes());
    } else if selector == super::private_release_denial::IMPORT_SELECTOR {
        output.extend_from_slice(&super::private_release_denial::expected_import_errno_bytes());
    } else if selector == super::private_release_denial::NAMESPACE_SELECTOR {
        output.extend_from_slice(&super::private_release_denial::expected_namespace_errno_bytes());
    } else if selector == super::private_release_denial::PORT_COLLISION_SELECTOR {
        output.extend_from_slice(
            &super::private_release_denial::expected_port_collision_errno_bytes(),
        );
    } else if selector == super::private_release_identity::SELECTOR {
        output.extend_from_slice(&super::private_release_identity::expected_projection());
    } else if selector == super::private_release_filter::SELECTOR {
        output.extend_from_slice(&super::private_release_filter::expected_projection());
    } else if selector == super::private_release_descriptors::SELECTOR {
        output.extend_from_slice(&super::private_release_descriptors::expected_projection());
    } else if selector == super::private_release_socket_launder::SELECTOR {
        output.extend_from_slice(&super::private_release_socket_launder::expected_target_suffix());
    } else if selector == super::private_release_host_state::SELECTOR {
        output.extend_from_slice(&super::private_release_host_state::expected_private_projection());
    }
    output
}

pub(crate) fn candidate_fixture_response(selector: &str, challenge: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-candidate-fixture-v1\0");
    digest.update(selector.as_bytes());
    digest.update([0]);
    digest.update(challenge);
    digest.finalize().into()
}
