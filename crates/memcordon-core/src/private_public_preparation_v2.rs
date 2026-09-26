//! Explicit static approval and actual-generation preparation. These wire
//! carriers never authenticate observer origin or grant a signing role.
use crate::DiagnosticSha256;
use crate::private_release_branch_v1::{PolicyOperationBranchV1, policy_branch_challenge_v1};
use crate::private_release_case_v1::{
    PrivateReleaseStageV1, REQUIRED_PRIVATE_RELEASE_SELECTORS_V1, private_release_case_key_v1,
};
use crate::workload_codec::hash_bytes;
use crate::workload_contract::{Nonce128, PolicyEpoch, WorkloadContractV2};
use serde::{Deserialize, Serialize};

/// Reviewed entrypoint grammar. ABI uses its real filtered-target producer;
/// no ordinary selector may substitute that specialized argv.
pub fn approved_public_fixture_argv_shape_v2(selector: &str, argv: &[String]) -> bool {
    let entry = argv
        .first()
        .is_some_and(|path| std::path::Path::new(path).is_absolute());
    let shape = if selector == crate::private_public_abi_composite_v1::PUBLIC_ABI_SELECTOR_V1 {
        argv.len() == 4
            && argv.get(1).map(String::as_str) == Some("public-abi-filtered-target")
            && argv.get(2).map(String::as_str) == Some("--challenge")
    } else {
        argv.len() >= 5
            && argv.get(1).map(String::as_str) == Some("public-release-fixture")
            && argv.get(2).map(String::as_str) == Some(selector)
            && argv.get(3).map(String::as_str) == Some("--challenge")
    };
    entry
        && shape
        && argv.iter().all(|argument| !argument.contains('\0'))
        && argv
            .iter()
            .filter(|argument| argument.as_str() == "--challenge")
            .count()
            == 1
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedPublicCaseTemplateV2 {
    pub selector: String,
    pub challenge_seed: [u8; 32],
    pub contract_template_sha256: DiagnosticSha256,
    pub fixture_sha256: DiagnosticSha256,
    #[serde(default)]
    pub facility_source_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    pub fixture_argv_template: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedPublicPolicyBranchTemplateV2 {
    pub branch: PolicyOperationBranchV1,
    pub contract_template_sha256: DiagnosticSha256,
}
/// Installed independently by an administrator. Code neither creates this
/// policy nor enables its explicit approval. The preparer is an enrolled TCB
/// image, not an uploaded key or a receipt accepted as origin authority.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedPublicPreparationPolicyV2 {
    pub schema_version: u8,
    pub stage_semantics_version: u8,
    pub preparation_approved: bool,
    pub static_suite_sha256: DiagnosticSha256,
    pub preparer_image_sha256: DiagnosticSha256,
    pub source_commit: String,
    pub target: String,
    pub manifest_sha256: DiagnosticSha256,
    pub qualification_sha256: DiagnosticSha256,
    pub public_cli_sha256: DiagnosticSha256,
    pub public_uid: u32,
    pub public_gid: u32,
    pub historical_spoof_uid: u32,
    pub historical_spoof_gid: u32,
    pub historical_spoof_challenge_seed: [u8; 32],
    pub policy_registry_sha256: DiagnosticSha256,
    pub policy_fixture_template_sha256: DiagnosticSha256,
    pub cases: Vec<ApprovedPublicCaseTemplateV2>,
    pub policy_branches: Vec<ApprovedPublicPolicyBranchTemplateV2>,
}
impl ApprovedPublicPreparationPolicyV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 2
            || self.stage_semantics_version != 3
            || !self.preparation_approved
            || !matches!(
                self.target.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
            || self.source_commit.len() != 40
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.public_uid == 0
            || self.public_gid == 0
            || self.historical_spoof_uid == 0
            || self.historical_spoof_gid == 0
            || self.historical_spoof_uid == self.public_uid
            || self.historical_spoof_gid == self.public_gid
            || self.historical_spoof_challenge_seed == [0; 32]
            || [
                &self.static_suite_sha256,
                &self.preparer_image_sha256,
                &self.manifest_sha256,
                &self.qualification_sha256,
                &self.public_cli_sha256,
                &self.policy_registry_sha256,
                &self.policy_fixture_template_sha256,
            ]
            .iter()
            .any(|hash| hash.bytes() == &[0; 32])
            || self.cases.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
            || self
                .cases
                .iter()
                .zip(REQUIRED_PRIVATE_RELEASE_SELECTORS_V1)
                .any(|(case, selector)| {
                    case.selector != selector
                        || case.challenge_seed == [0; 32]
                        || case.challenge_seed == self.historical_spoof_challenge_seed
                        || case.contract_template_sha256.bytes() == &[0; 32]
                        || case.fixture_sha256.bytes() == &[0; 32]
                        || case.facility_source_sha256.as_ref().is_some_and(|digest|
                            digest != &crate::private_facility_source_v1::facility_source_revision_sha256())
                        || !approved_public_fixture_argv_shape_v2(&case.selector,&case.fixture_argv_template)
                        || !case.fixture_argv_template.windows(2).any(|pair|pair[0]=="--challenge"
                            && pair[1]==String::from(DiagnosticSha256::from_bytes(case.challenge_seed)))
                })
            || self.policy_branches.len() != PolicyOperationBranchV1::ALL.len()
            || self
                .policy_branches
                .iter()
                .zip(PolicyOperationBranchV1::ALL)
                .any(|(recipe, branch)| {
                    recipe.branch != branch || recipe.contract_template_sha256.bytes() == &[0; 32]
                })
        {
            return Err(
                "public preparation requires exact independently approved V2 static policy".into(),
            );
        }
        let seeds = self
            .cases
            .iter()
            .map(|case| case.challenge_seed)
            .collect::<std::collections::BTreeSet<_>>();
        if seeds.len() != self.cases.len() {
            return Err("public preparation challenge seeds are duplicated".into());
        }
        Ok(())
    }
    pub fn challenge(
        &self,
        nonce: [u8; 32],
        generation: u32,
        selector: &str,
        role: PublicPreparedRoleV2,
    ) -> Result<[u8; 32], String> {
        self.validate()?;
        if nonce == [0; 32] {
            return Err("public preparation controller nonce is empty".into());
        }
        let case = self
            .cases
            .iter()
            .find(|case| case.selector == selector)
            .ok_or("public preparation selector absent")?;
        let mut bytes = if role == PublicPreparedRoleV2::CallerSpoof {
            if selector != "private_tcp::caller_identity_and_epoch_bound" || generation == 0 {
                return Err("public spoof preparation role/generation differs".into());
            }
            b"memcordon/prepared-public-caller-spoof/v1\0".to_vec()
        } else {
            b"memcordon/prepared-public-case-challenge/v1\0".to_vec()
        };
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&generation.to_be_bytes());
        if role == PublicPreparedRoleV2::CallerSpoof {
            bytes.extend_from_slice(&self.historical_spoof_challenge_seed);
        } else {
            bytes.extend_from_slice(&case.challenge_seed);
            bytes.extend_from_slice(selector.as_bytes());
        }
        let challenge = *hash_bytes(&bytes).bytes();
        if let PublicPreparedRoleV2::Policy { branch } = role {
            if selector != "private_tcp::wrong_grant_profile_and_port_rejected" {
                return Err("public policy preparation selector differs".into());
            }
            policy_branch_challenge_v1(&challenge, branch).map_err(str::to_owned)
        } else {
            Ok(challenge)
        }
    }

    /// Exact target argv from independent static approval. Only dual attempts
    /// have an ordinal-dependent challenge transformation; the contract and
    /// plan remain unchanged and every other argv byte stays pinned.
    pub fn fixture_argv(
        &self,
        nonce: [u8; 32],
        generation: u32,
        selector: &str,
        role: PublicPreparedRoleV2,
        ordinal: u8,
    ) -> Result<Vec<String>, String> {
        self.validate()?;
        let case = self
            .cases
            .iter()
            .find(|case| case.selector == selector)
            .ok_or("prepared fixture argv selector absent")?;
        let parent = self.challenge(nonce, generation, selector, role)?;
        let challenge = if selector == "private_tcp::dual_attempt_namespace_isolation" {
            if role != PublicPreparedRoleV2::Ordinary || ordinal > 1 {
                return Err("prepared dual argv role/ordinal is not approved".into());
            }
            crate::private_release_case_v1::public_dual_challenge_v1(&parent, ordinal)
                .map_err(str::to_owned)?
        } else {
            parent
        };
        let mut argv = case.fixture_argv_template.clone();
        let index = argv
            .iter()
            .position(|argument| argument == "--challenge")
            .ok_or("prepared fixture challenge slot absent")?;
        argv[index + 1] = String::from(DiagnosticSha256::from_bytes(challenge));
        Ok(argv)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PublicPreparedRoleV2 {
    Ordinary,
    HistoricalE0,
    CallerSpoof,
    Policy { branch: PolicyOperationBranchV1 },
}
/// Immutable protected preparation written by the enrolled live supervisor.
/// Legacy routing bytes are diagnostic; policy and actual H1 authorize the
/// selected exact contract, never arbitrary contents of that routing carrier.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedPublicDispatchRecordV2 {
    pub schema_version: u8,
    pub static_suite_sha256: DiagnosticSha256,
    pub session_nonce: [u8; 32],
    pub generation: u32,
    pub selector: String,
    pub role: PublicPreparedRoleV2,
    pub challenge: [u8; 32],
    pub result_key: DiagnosticSha256,
    pub installation_epoch: DiagnosticSha256,
    pub active_h1_receipt_sha256: DiagnosticSha256,
    pub policy_epoch: PolicyEpoch,
    pub contract_path: String,
    pub contract_file_sha256: DiagnosticSha256,
    pub dispatch_bytes: Vec<u8>,
}
impl PreparedPublicDispatchRecordV2 {
    pub fn validate(
        &self,
        approved: &ApprovedPublicPreparationPolicyV2,
        contract: &WorkloadContractV2,
    ) -> Result<(), String> {
        approved.validate()?;
        let expected = approved.challenge(
            self.session_nonce,
            self.generation,
            &self.selector,
            self.role,
        )?;
        let template = if let PublicPreparedRoleV2::Policy { branch } = self.role {
            approved
                .policy_branches
                .iter()
                .find(|recipe| recipe.branch == branch)
                .ok_or("public branch template absent")?
                .contract_template_sha256
                .clone()
        } else {
            approved
                .cases
                .iter()
                .find(|case| case.selector == self.selector)
                .ok_or("public case template absent")?
                .contract_template_sha256
                .clone()
        };
        if self.schema_version != 2
            || self.static_suite_sha256 != approved.static_suite_sha256
            || self.challenge != expected
            || self.result_key
                != private_release_case_key_v1(
                    PrivateReleaseStageV1::FinalPublic,
                    &self.selector,
                    &expected,
                )?
            || self.installation_epoch.bytes() == &[0; 32]
            || self.active_h1_receipt_sha256.bytes() == &[0; 32]
            || self.policy_epoch.service_instance.0 == [0; 16]
            || self.policy_epoch != contract.expected_epoch
            || self.role == PublicPreparedRoleV2::HistoricalE0
                && (self.generation != 0
                    || self.selector != "private_tcp::caller_identity_and_epoch_bound")
            || public_contract_template_sha256_v2(contract)? != template
            || !std::path::Path::new(&self.contract_path)
                .starts_with("/run/memcordon-final-public/prepared-v2")
            || std::path::Path::new(&self.contract_path)
                .components()
                .any(|component| {
                    !matches!(
                        component,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                })
            || self.contract_file_sha256.bytes() == &[0; 32]
            || self.dispatch_bytes.is_empty()
            || self.dispatch_bytes.len() > 128 * 1024
        {
            return Err("public prepared actual generation/recipe/contract differs".into());
        }
        Ok(())
    }
}
pub fn public_contract_template_sha256_v2(
    contract: &WorkloadContractV2,
) -> Result<DiagnosticSha256, String> {
    let mut template = contract.clone();
    template.expected_epoch = PolicyEpoch {
        service_instance: Nonce128([0; 16]),
        revision: std::num::NonZeroU64::MIN,
    };
    let mut bytes = b"memcordon/public-contract-template/v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&template).map_err(|error| error.to_string())?);
    bytes.push(b'\n');
    Ok(hash_bytes(&bytes))
}
