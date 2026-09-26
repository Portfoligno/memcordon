//! Immutable public inputs are prepared only from an authenticated actual
//! generation and independently protected static approval. No policy, grant,
//! enrollment, service, key, or release is activated here.
use crate::private_public_plan::{PreparedPublicGenerationV1, StaticPublicSuiteIntentV1};
use crate::{CiError, Result};
use memcordon_core::private_public_preparation_v2::{
    ApprovedPublicPreparationPolicyV2, PreparedPublicDispatchRecordV2, PublicPreparedRoleV2,
};
use memcordon_core::workload_contract::{PolicyEpoch, WorkloadContractV2};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};

pub(crate) struct PreparedPublicContractInputsV2 {
    pub(crate) record: PreparedPublicDispatchRecordV2,
    pub(crate) contract_bytes: Vec<u8>,
    pub(crate) admission_bytes: Vec<u8>,
    pub(crate) directory: std::path::PathBuf,
}

pub fn validate_public_preparation_approval(
    suite: &StaticPublicSuiteIntentV1,
    approved: &ApprovedPublicPreparationPolicyV2,
) -> Result<()> {
    suite.validate()?;
    approved.validate().map_err(CiError::Message)?;
    if approved.static_suite_sha256 != suite.identity_sha256()?
        || approved.source_commit != suite.observer_subject.source_commit
        || approved.target != suite.observer_subject.target
        || approved.manifest_sha256 != suite.manifest_sha256
        || approved.qualification_sha256 != suite.qualification_sha256
        || approved.public_cli_sha256 != suite.public_cli_sha256
        || approved.public_uid != suite.public_uid
        || approved.public_gid != suite.public_gid
        || approved.historical_spoof_uid != suite.historical_spoof_uid
        || approved.historical_spoof_gid != suite.historical_spoof_gid
        || hex::encode(approved.historical_spoof_challenge_seed)
            != suite.historical_spoof_challenge_seed
        || approved.policy_registry_sha256 != suite.policy_recipe.registry_sha256
        || approved.policy_fixture_template_sha256 != suite.policy_recipe.fixture_template_sha256
        || approved.cases.iter().zip(&suite.scenarios).any(|(a, b)| {
            a.selector != b.selector
                || hex::encode(a.challenge_seed) != b.challenge
                || a.fixture_sha256 != b.fixture_sha256
                || a.contract_template_sha256 != b.contract_template_sha256
                || a.fixture_argv_template != b.recipe.fixture_argv
                || a.facility_source_sha256 != b.recipe.facility_source_sha256
        })
        || approved
            .policy_branches
            .iter()
            .zip(&suite.policy_recipe.branches)
            .any(|(a, b)| {
                a.branch != b.branch || a.contract_template_sha256 != b.contract_template_sha256
            })
    {
        return fail(
            "administrator preparation approval differs from exact protected static public suite",
        );
    }
    Ok(())
}

/// Fill only the actual epoch slot. Routing is independently revalidated by
/// the native admission reader; it is never an origin/signing capability.
pub(crate) fn prepare_public_contract_inputs(
    suite: &StaticPublicSuiteIntentV1,
    generation: &PreparedPublicGenerationV1,
    approved: &ApprovedPublicPreparationPolicyV2,
    selector: &str,
    role: PublicPreparedRoleV2,
    template_bytes: &[u8],
    actual_policy_epoch: &PolicyEpoch,
    make_routing: impl FnOnce(&PreparedPublicDispatchRecordV2) -> Result<Vec<u8>>,
) -> Result<PreparedPublicContractInputsV2> {
    validate_public_preparation_approval(suite, approved)?;
    if generation.subject() != &suite.observer_subject
        || generation.static_intent_sha256() != &approved.static_suite_sha256
        || generation.generation().installed_manifest_sha256 != suite.manifest_sha256
        || actual_policy_epoch.service_instance.0 == [0; 16]
    {
        return fail("public input preparation lacks authenticated actual H1/epoch");
    }
    let mut contract = WorkloadContractV2::parse(template_bytes).map_err(CiError::Message)?;
    if contract.expected_epoch.service_instance.0 != [0; 16]
        || contract.expected_epoch.revision.get() != 1
    {
        return fail("static public contract template predicts a future epoch");
    }
    contract.expected_epoch = actual_policy_epoch.clone();
    let nonce = hex::decode(generation.session_nonce())
        .map_err(|_| CiError::Message("prepared controller nonce differs".into()))?
        .try_into()
        .map_err(|_| CiError::Message("prepared nonce size differs".into()))?;
    let challenge = approved
        .challenge(nonce, generation.generation().generation, selector, role)
        .map_err(CiError::Message)?;
    let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
        memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
        selector,
        &challenge,
    )
    .map_err(CiError::Message)?;
    let directory = std::path::Path::new("/run/memcordon-final-public/prepared-v2")
        .join(String::from(key.clone()));
    let contract_path = directory.join("contract.json");
    let contract_bytes = crate::private_observer_session::canonical_bytes(&contract)?;
    let mut record = PreparedPublicDispatchRecordV2 {
        schema_version: 2,
        static_suite_sha256: approved.static_suite_sha256.clone(),
        session_nonce: nonce,
        generation: generation.generation().generation,
        selector: selector.into(),
        role,
        challenge,
        result_key: key,
        installation_epoch: generation.generation().installation_epoch.clone(),
        active_h1_receipt_sha256: generation.generation().installed_receipt_sha256.clone(),
        policy_epoch: actual_policy_epoch.clone(),
        contract_path: contract_path.to_string_lossy().into_owned(),
        contract_file_sha256: hash_bytes(&contract_bytes),
        dispatch_bytes: Vec::new(),
    };
    record.dispatch_bytes = make_routing(&record)?;
    record
        .validate(approved, &contract)
        .map_err(CiError::Message)?;
    let admission_bytes = crate::private_observer_session::canonical_bytes(&record)?;
    Ok(PreparedPublicContractInputsV2 {
        record,
        contract_bytes,
        admission_bytes,
        directory,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn persist_prepared_public_inputs(
    inputs: &PreparedPublicContractInputsV2,
) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    if !rustix::process::geteuid().is_root() {
        return fail("public input writer requires enrolled root supervisor");
    }
    // Never create or enable administrator approval. The fixed runtime root
    // is a separate deployment prerequisite; every case child is exclusive.
    let root = std::path::Path::new("/run/memcordon-final-public/prepared-v2");
    for path in [
        std::path::Path::new("/run"),
        std::path::Path::new("/run/memcordon-final-public"),
        root,
    ] {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return fail("public prepared runtime root is not independently protected");
        }
    }
    if inputs.directory.parent() != Some(root)
        || std::fs::symlink_metadata(&inputs.directory).is_ok()
    {
        return fail("public prepared case directory is not fresh/exact");
    }
    std::fs::create_dir(&inputs.directory)?;
    std::fs::set_permissions(&inputs.directory, std::fs::Permissions::from_mode(0o755))?;
    for (name, bytes, mode) in [
        ("contract.json", &inputs.contract_bytes, 0o644),
        ("admission.json", &inputs.admission_bytes, 0o600),
    ] {
        let path = inputs.directory.join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if crate::private_protected_readback::read_protected_raw_case_file(&path)? != *bytes {
            return fail("prepared public immutable input readback differs");
        }
    }
    std::fs::File::open(&inputs.directory)?.sync_all()?;
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn persist_prepared_public_inputs(
    _inputs: &PreparedPublicContractInputsV2,
) -> Result<()> {
    fail("public protected input preparation requires native Linux")
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
