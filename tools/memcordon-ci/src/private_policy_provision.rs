//! Root-protected, workflow-digest-pinned policy experiment provisioning.
//! This is independent release intent, not claimant or native-result authority.

use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_branch_v1::{
    PrivatePolicyObserverIntentV1, PrivatePolicyReleaseIntentV1,
};
use memcordon_core::workload_codec::{contract_digest_v2, hash_bytes};
use memcordon_core::workload_contract::{
    ContractVersionTwo, Nonce128, PolicyEpoch, reject_duplicate_json_keys,
};
use memcordon_core::workload_registry::CallerSelector;
use memcordon_core::workload_registry_v2::{
    CandidatePolicyDecisionV2, PolicyRegistryV2, ProfileKindV2, evaluate_candidate_policy_v2,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

const INTENT: &str = "/var/lib/memcordon/sealed/private-release-policy-intent-v1.json";
const FIXTURE: &str = "/var/lib/memcordon/sealed/private-release-policy-v1.json";
const ACTIVATION: &str = "/var/lib/memcordon/policy/policy-activation.json";
const LOCK: &str = "/var/lib/memcordon/policy/policy.lock";
const MAX_INTENT_BYTES: usize = 256 * 1024;

/// Reviewed recipes contain explicit empty dynamic slots. Only independently
/// observed H0/epoch and a controller-derived challenge may fill those slots.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticCandidatePolicyIntentV2 {
    pub schema_version: u8,
    pub recipe: PrivatePolicyReleaseIntentV1,
}

impl StaticCandidatePolicyIntentV2 {
    pub(crate) fn prepare_from_actual_h0(
        &self,
        live: &PolicyLiveExpectationV1,
        epoch: &PolicyEpoch,
        challenge: [u8; 32],
    ) -> Result<PrivatePolicyReleaseIntentV1> {
        let r = &self.recipe;
        if self.schema_version != 2
            || r.schema_version != 1
            || r.installed_inspection_sha256.bytes() != &[0; 32]
            || r.installation_epoch_sha256.bytes() != &[0; 32]
            || r.base_challenge != [0; 32]
            || challenge == [0; 32]
            || r.target != live.target
            || r.candidate_build_sha256 != live.candidate_build_sha256
            || r.observer.agent_sha256 != live.agent_sha256
            || [&r.accepted, &r.changed_port, &r.committed_tamper]
                .iter()
                .any(|c| {
                    c.expected_epoch.service_instance.0 != [0; 16]
                        || c.expected_epoch.revision.get() != 1
                })
            || epoch.service_instance.0 == [0; 16]
            || live.installed_inspection_sha256.bytes() == &[0; 32]
            || live.installation_epoch_sha256.bytes() == &[0; 32]
        {
            return Err(fail(
                "static policy recipe or actual H0/epoch/challenge differs",
            ));
        }
        let mut prepared = r.clone();
        prepared.installed_inspection_sha256 = live.installed_inspection_sha256.clone();
        prepared.installation_epoch_sha256 = live.installation_epoch_sha256.clone();
        prepared.base_challenge = challenge;
        for contract in [
            &mut prepared.accepted,
            &mut prepared.changed_port,
            &mut prepared.committed_tamper,
        ] {
            contract.expected_epoch = epoch.clone();
        }
        prepared.validate().map_err(CiError::Message)?;
        Ok(prepared)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyLiveExpectationV1 {
    pub(crate) target: String,
    pub(crate) candidate_build_sha256: DiagnosticSha256,
    pub(crate) agent_sha256: DiagnosticSha256,
    pub(crate) installed_inspection_sha256: DiagnosticSha256,
    pub(crate) installation_epoch_sha256: DiagnosticSha256,
}

pub(crate) struct ProvisionedPolicyFixtureV1 {
    intent_sha256: DiagnosticSha256,
    fixture_sha256: DiagnosticSha256,
    reviewed_topology_sha256: DiagnosticSha256,
    registry_sha256: DiagnosticSha256,
    authenticated_caller_uid: u32,
    authenticated_caller_sha256: DiagnosticSha256,
    accepted_request_sha256: DiagnosticSha256,
    changed_request_sha256: DiagnosticSha256,
    committed_tamper_request_sha256: DiagnosticSha256,
    base_challenge: [u8; 32],
    observer: PrivatePolicyObserverIntentV1,
}

impl ProvisionedPolicyFixtureV1 {
    pub(crate) fn intent_sha256(&self) -> &DiagnosticSha256 {
        &self.intent_sha256
    }
    pub(crate) fn fixture_sha256(&self) -> &DiagnosticSha256 {
        &self.fixture_sha256
    }
    pub(crate) fn reviewed_topology_sha256(&self) -> &DiagnosticSha256 {
        &self.reviewed_topology_sha256
    }
    pub(crate) fn registry_sha256(&self) -> &DiagnosticSha256 {
        &self.registry_sha256
    }
    pub(crate) fn authenticated_caller_sha256(&self) -> &DiagnosticSha256 {
        &self.authenticated_caller_sha256
    }
    pub(crate) fn authenticated_caller_uid(&self) -> u32 {
        self.authenticated_caller_uid
    }
    pub(crate) fn accepted_request_sha256(&self) -> &DiagnosticSha256 {
        &self.accepted_request_sha256
    }
    pub(crate) fn changed_request_sha256(&self) -> &DiagnosticSha256 {
        &self.changed_request_sha256
    }
    pub(crate) fn committed_tamper_request_sha256(&self) -> &DiagnosticSha256 {
        &self.committed_tamper_request_sha256
    }
    pub(crate) fn base_challenge(&self) -> &[u8; 32] {
        &self.base_challenge
    }
    pub(crate) fn observer(&self) -> &PrivatePolicyObserverIntentV1 {
        &self.observer
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LiveActivationV2 {
    schema_version: ContractVersionTwo,
    registry: PolicyRegistryV2,
    registry_digest: DiagnosticSha256,
    epoch: PolicyEpoch,
    revoked_admissions: Vec<Nonce128>,
}

fn fail(message: &'static str) -> CiError {
    CiError::Message(message.into())
}

/// `expected_digest` is a digest-only workflow input independently pinned in
/// the administrator-protected downstream collector intent. The caller must
/// provide B/H0/epoch from its own installed-package admission lease.
#[cfg(target_os = "linux")]
pub(crate) fn provision_policy_fixture(
    expected_digest: &DiagnosticSha256,
    live: &PolicyLiveExpectationV1,
) -> Result<ProvisionedPolicyFixtureV1> {
    provision_policy_fixture_inner(expected_digest, live, None)
}

#[cfg(target_os = "linux")]
pub(crate) fn provision_static_policy_fixture(
    expected_digest: &DiagnosticSha256,
    live: &PolicyLiveExpectationV1,
    controller_challenge: [u8; 32],
) -> Result<ProvisionedPolicyFixtureV1> {
    provision_policy_fixture_inner(expected_digest, live, Some(controller_challenge))
}

#[cfg(target_os = "linux")]
fn provision_policy_fixture_inner(
    expected_digest: &DiagnosticSha256,
    live: &PolicyLiveExpectationV1,
    controller_challenge: Option<[u8; 32]>,
) -> Result<ProvisionedPolicyFixtureV1> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::time::{Duration, Instant};

    if !rustix::process::geteuid().is_root() || expected_digest.bytes() == &[0; 32] {
        return Err(fail(
            "policy provisioning requires root and reviewed digest",
        ));
    }
    let bytes = crate::private_protected_readback::read_protected_raw_case_file(Path::new(INTENT))?;
    if bytes.len() > MAX_INTENT_BYTES || hash_bytes(&bytes) != *expected_digest {
        return Err(fail("policy release intent differs from workflow digest"));
    }
    reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let intent: PrivatePolicyReleaseIntentV1 = if let Some(challenge) = controller_challenge {
        let reviewed: StaticCandidatePolicyIntentV2 = serde_json::from_slice(&bytes)?;
        if serde_json::to_vec(&reviewed)? != bytes {
            return Err(fail("static policy intent is not canonical"));
        }
        let activation_raw =
            crate::private_protected_readback::read_protected_raw_case_file(Path::new(ACTIVATION))?;
        let activation: LiveActivationV2 =
            crate::private_observer_session::strict_json(&activation_raw, MAX_INTENT_BYTES)?;
        reviewed.prepare_from_actual_h0(live, &activation.epoch, challenge)?
    } else {
        let legacy: PrivatePolicyReleaseIntentV1 = serde_json::from_slice(&bytes)?;
        if serde_json::to_vec(&legacy)? != bytes {
            return Err(fail("legacy policy intent is not canonical"));
        }
        legacy
    };
    intent.validate().map_err(CiError::Message)?;
    if intent.target != live.target
        || intent.candidate_build_sha256 != live.candidate_build_sha256
        || intent.installed_inspection_sha256 != live.installed_inspection_sha256
        || intent.installation_epoch_sha256 != live.installation_epoch_sha256
        || intent.reviewed_topology_sha256
            != hash_bytes(include_bytes!(
                "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/fixtures/private_policy_branches_v1.json"
            ))
        || intent.observer.agent_sha256 != live.agent_sha256
        || intent.observer.bpf_source_sha256
            != hash_bytes(include_bytes!("../probes/private_kernel_v1.bpf.c"))
        || intent.observer.loader_source_sha256
            != hash_bytes(include_bytes!("../probes/private_kernel_v1_loader.c"))
    {
        return Err(fail("policy intent B/H0/epoch/topology differs"));
    }
    let caller = CallerSelector::Linux {
        uid: intent.authenticated_caller_uid,
    };
    let caller_sha256 = hash_bytes(&serde_json::to_vec(&caller)?);
    if intent.authenticated_caller_uid == 0 || intent.authenticated_caller_sha256 != caller_sha256 {
        return Err(fail("policy intent authenticated caller differs"));
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(LOCK)?;
    let lock_meta = lock.metadata()?;
    if lock_meta.uid() != 0
        || !lock_meta.is_file()
        || lock_meta.nlink() != 1
        || lock_meta.mode() & 0o7777 != 0o600
    {
        return Err(fail("policy activation lease differs"));
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => break,
            Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return Err(fail("policy activation lease unavailable")),
        }
    }
    let activation_bytes =
        crate::private_protected_readback::read_protected_raw_case_file(Path::new(ACTIVATION))?;
    reject_duplicate_json_keys(&activation_bytes).map_err(CiError::Message)?;
    let activation: LiveActivationV2 = serde_json::from_slice(&activation_bytes)?;
    activation
        .registry
        .baseline_v1_projection()
        .map_err(CiError::Message)?;
    let canonical_activation = activation_bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| fail("policy activation newline absent"))?;
    if serde_json::to_vec(&activation)? != canonical_activation
        || activation.revoked_admissions.len() > 256
        || activation
            .revoked_admissions
            .iter()
            .enumerate()
            .any(|(index, nonce)| activation.revoked_admissions[..index].contains(nonce))
        || activation
            .registry
            .canonical_digest()
            .map_err(CiError::Message)?
            != activation.registry_digest
        || activation.registry_digest != intent.registry_sha256
        || activation.epoch != intent.accepted.expected_epoch
        || !matches!(
            evaluate_candidate_policy_v2(
                &activation.registry,
                &activation.epoch,
                &intent.accepted,
                &caller,
                ProfileKindV2::LinuxTcp4PrivateV1,
                &live.installed_inspection_sha256,
            ),
            CandidatePolicyDecisionV2::Accepted
        )
    {
        return Err(fail(
            "policy live activation/admission differs from reviewed intent",
        ));
    }
    let fixture_bytes = intent
        .canonical_agent_fixture_bytes()
        .map_err(CiError::Message)?;
    let fixture_path = Path::new(FIXTURE);
    let parent = fixture_path
        .parent()
        .ok_or_else(|| fail("policy fixture parent absent"))?;
    let parent_meta = std::fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir()
        || parent_meta.uid() != 0
        || parent_meta.permissions().mode() & 0o7777 != 0o700
    {
        return Err(fail("policy fixture parent protection differs"));
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(fixture_path)
    {
        Ok(mut file) => {
            file.write_all(&fixture_bytes)?;
            file.sync_all()?;
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(parent)?
                .sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing =
                crate::private_protected_readback::read_protected_raw_case_file(fixture_path)?;
            if existing != fixture_bytes {
                return Err(fail("existing policy fixture differs"));
            }
        }
        Err(error) => return Err(CiError::Message(error.to_string())),
    }
    // Keep the registry lease through fixture commit. The agent reacquires
    // the same lease and repeats live admission for each branch.
    Ok(ProvisionedPolicyFixtureV1 {
        intent_sha256: expected_digest.clone(),
        fixture_sha256: hash_bytes(&fixture_bytes),
        reviewed_topology_sha256: intent.reviewed_topology_sha256,
        registry_sha256: intent.registry_sha256,
        authenticated_caller_uid: intent.authenticated_caller_uid,
        authenticated_caller_sha256: intent.authenticated_caller_sha256,
        accepted_request_sha256: contract_digest_v2(&intent.accepted).map_err(CiError::Message)?,
        changed_request_sha256: contract_digest_v2(&intent.changed_port)
            .map_err(CiError::Message)?,
        committed_tamper_request_sha256: contract_digest_v2(&intent.committed_tamper)
            .map_err(CiError::Message)?,
        base_challenge: intent.base_challenge,
        observer: intent.observer,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn provision_static_policy_fixture(
    _expected_digest: &DiagnosticSha256,
    _live: &PolicyLiveExpectationV1,
    _controller_challenge: [u8; 32],
) -> Result<ProvisionedPolicyFixtureV1> {
    Err(fail("policy provisioning requires native Linux"))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn provision_policy_fixture(
    _expected_digest: &DiagnosticSha256,
    _live: &PolicyLiveExpectationV1,
) -> Result<ProvisionedPolicyFixtureV1> {
    Err(fail("policy provisioning requires native Linux"))
}
