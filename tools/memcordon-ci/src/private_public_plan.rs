//! Public input preparation separates static release pins from host facts
//! observed only after installation and H1 activation.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use crate::private_observer_session::{
    AuthenticatedLiveObserverLeaseV1, AuthenticatedObserverSessionV1, ObservedGenerationV1,
    ObserverStageV1, ObserverSubjectV1,
};
use crate::{CiError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicStageSemanticsPolicyV1 {
    pub schema_version: u8,
    /// V3 deliberately changes descriptor-sensitive final-stage claims to
    /// clean entry AND a same-filter valid-context auxiliary.
    pub final_stage_semantics_version: u8,
    pub approved_semantics_sha256: DiagnosticSha256,
    pub auxiliary_conjunction_approved: bool,
}

impl PublicStageSemanticsPolicyV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.final_stage_semantics_version != 3
            || !self.auxiliary_conjunction_approved
            || self.approved_semantics_sha256
                != crate::private_case_semantics::semantics_revision_sha256()
        {
            return Err(CiError::Message("public V3 requires administrator approval of the exact versioned clean-entry/valid-context auxiliary semantics".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticPublicScenarioV1 {
    pub selector: String,
    pub challenge: String,
    pub fixture_sha256: DiagnosticSha256,
    pub contract_template_sha256: DiagnosticSha256,
    pub recipe: ReviewedPublicCaseRecipeV1,
}

/// Independently protected static fixture operands. No runtime sample,
/// generation, terminal, or pass bit can appear in this recipe.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedPublicCaseRecipeV1 {
    pub filter_sha256: DiagnosticSha256,
    #[serde(default)]
    pub filter_install_source_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    pub facility_source_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    pub host_preservation_source_sha256: Option<DiagnosticSha256>,
    pub fixture_argv: Vec<String>,
    pub target_uid: u32,
    pub target_gid: u32,
    pub supplementary_groups: Vec<u32>,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedPublicPolicyBranchV1 {
    pub branch: memcordon_core::private_release_branch_v1::PolicyOperationBranchV1,
    pub contract_template_sha256: DiagnosticSha256,
}
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedPublicPolicyRecipeV1 {
    pub registry_sha256: DiagnosticSha256,
    pub fixture_template_sha256: DiagnosticSha256,
    pub branches: Vec<ReviewedPublicPolicyBranchV1>,
}

fn static_epoch() -> memcordon_core::workload_contract::PolicyEpoch {
    memcordon_core::workload_contract::PolicyEpoch {
        service_instance: memcordon_core::workload_contract::Nonce128([0; 16]),
        revision: std::num::NonZeroU64::MIN,
    }
}
/// The only dynamic contract slot is the independently observed service
/// epoch. Grant, identity, requirements, endpoints, ports and plan labels
/// remain committed; changing one is not "preparation".
pub fn public_contract_template_sha256(
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
) -> Result<DiagnosticSha256> {
    memcordon_core::private_public_preparation_v2::public_contract_template_sha256_v2(contract)
        .map_err(CiError::Message)
}
pub fn public_policy_fixture_template_sha256(
    fixture: &memcordon_core::private_release_branch_v1::PrivatePolicyAgentFixtureV1,
) -> Result<DiagnosticSha256> {
    let mut template = fixture.clone();
    template.base_challenge = [0; 32];
    for contract in [
        &mut template.accepted,
        &mut template.changed_port,
        &mut template.committed_tamper,
    ] {
        contract.expected_epoch = static_epoch();
    }
    let mut bytes = b"memcordon/public-policy-fixture-template/v1\0".to_vec();
    bytes.extend_from_slice(&crate::private_observer_session::canonical_bytes(
        &template,
    )?);
    Ok(hash_bytes(&bytes))
}

/// The static challenge is a reviewed seed, never the future session's actual
/// challenge. Bind every executed recipe to the custodian nonce and generation.
pub fn prepared_public_case_recipe_v1(
    intent: &StaticPublicSuiteIntentV1,
    session_nonce: &str,
    generation: u32,
    selector: &str,
) -> Result<([u8; 32], Vec<String>)> {
    let scenario = intent
        .scenarios
        .iter()
        .find(|scenario| scenario.selector == selector)
        .ok_or_else(|| CiError::Message("prepared public selector recipe absent".into()))?;
    let nonce = hex::decode(session_nonce)
        .map_err(|_| CiError::Message("public controller nonce differs".into()))?;
    let seed = hex::decode(&scenario.challenge)
        .map_err(|_| CiError::Message("public static challenge seed differs".into()))?;
    if nonce.len() != 32
        || hex::encode(&nonce) != session_nonce
        || nonce.iter().all(|byte| *byte == 0)
        || seed.len() != 32
    {
        return Err(CiError::Message(
            "public controller nonce/static seed size differs".into(),
        ));
    }
    let mut bytes = b"memcordon/prepared-public-case-challenge/v1\0".to_vec();
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&seed);
    bytes.extend_from_slice(selector.as_bytes());
    let challenge = *hash_bytes(&bytes).bytes();
    let mut argv = scenario.recipe.fixture_argv.clone();
    let indexes = argv
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| (arg == "--challenge").then_some(index))
        .collect::<Vec<_>>();
    if indexes.len() != 1 || argv.get(indexes[0] + 1) != Some(&scenario.challenge) {
        return Err(CiError::Message(
            "reviewed public challenge argv slot differs".into(),
        ));
    }
    argv[indexes[0] + 1] = hex::encode(challenge);
    Ok((challenge, argv))
}

/// The generic exec-image witness is the first actual dual branch, while its
/// enrolled interval and prepared contract keep the parent logical challenge.
pub(crate) fn public_first_observed_fixture_recipe_v1(
    selector: &str,
    parent: [u8; 32],
    parent_argv: &[String],
) -> Result<([u8; 32], Vec<String>)> {
    if selector != "private_tcp::dual_attempt_namespace_isolation" {
        return Ok((parent, parent_argv.to_vec()));
    }
    let challenge = memcordon_core::private_release_case_v1::public_dual_challenge_v1(&parent, 0)
        .map_err(|error| CiError::Message(error.into()))?;
    let mut argv = parent_argv.to_vec();
    let slots = argv
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| (arg == "--challenge").then_some(index))
        .collect::<Vec<_>>();
    if slots.len() != 1 || argv.get(slots[0] + 1) != Some(&hex::encode(parent)) {
        return Err(CiError::Message(
            "public parent fixture challenge slot differs".into(),
        ));
    }
    argv[slots[0] + 1] = hex::encode(challenge);
    Ok((challenge, argv))
}

pub fn prepared_public_spoof_challenge_v1(
    intent: &StaticPublicSuiteIntentV1,
    session_nonce: &str,
    generation: u32,
) -> Result<[u8; 32]> {
    let nonce = hex::decode(session_nonce)
        .map_err(|_| CiError::Message("spoof controller nonce differs".into()))?;
    let seed = hex::decode(&intent.historical_spoof_challenge_seed)
        .map_err(|_| CiError::Message("spoof approved seed differs".into()))?;
    if nonce.len() != 32
        || hex::encode(&nonce) != session_nonce
        || nonce.iter().all(|byte| *byte == 0)
        || seed.len() != 32
        || hex::encode(&seed) != intent.historical_spoof_challenge_seed
    {
        return Err(CiError::Message("spoof nonce/seed encoding differs".into()));
    }
    let mut bytes = b"memcordon/prepared-public-caller-spoof/v1\0".to_vec();
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&seed);
    Ok(*hash_bytes(&bytes).bytes())
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticPublicSuiteIntentV1 {
    pub schema_version: u8,
    pub observer_subject: ObserverSubjectV1,
    pub archive_sha256: DiagnosticSha256,
    pub archive_size: u64,
    pub manifest_sha256: DiagnosticSha256,
    pub qualification_sha256: DiagnosticSha256,
    pub qualification_certificate_file_sha256: DiagnosticSha256,
    pub qualification_certificate_payload_sha256: DiagnosticSha256,
    pub public_cli_sha256: DiagnosticSha256,
    pub public_uid: u32,
    pub public_gid: u32,
    /// Independently approved historical caller-spoof control identity.
    /// Presented receipts cannot choose the expected unauthorized actor.
    pub historical_spoof_uid: u32,
    pub historical_spoof_gid: u32,
    pub historical_spoof_challenge_seed: String,
    pub policy_recipe: ReviewedPublicPolicyRecipeV1,
    pub semantics_policy: PublicStageSemanticsPolicyV1,
    pub scenarios: Vec<StaticPublicScenarioV1>,
}

impl StaticPublicSuiteIntentV1 {
    /// Domain-separated admission identity excludes only its own subject
    /// reference. All recipe operands and challenges remain committed.
    pub fn identity_sha256(&self) -> Result<DiagnosticSha256> {
        let mut canonical = self.clone();
        canonical.observer_subject.intent_sha256 = DiagnosticSha256::from_bytes([0; 32]);
        let mut bytes = b"memcordon/static-public-suite-intent/v1\0".to_vec();
        bytes.extend_from_slice(&crate::private_observer_session::canonical_bytes(
            &canonical,
        )?);
        Ok(hash_bytes(&bytes))
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let intent: Self = crate::private_observer_session::strict_json(bytes, 128 * 1024)?;
        intent.validate()?;
        Ok(intent)
    }
    pub fn validate(&self) -> Result<()> {
        self.observer_subject.validate()?;
        self.semantics_policy.validate()?;
        let spoof_seed = hex::decode(&self.historical_spoof_challenge_seed)
            .map_err(|_| CiError::Message("static spoof seed differs".into()))?;
        if spoof_seed.len() != 32
            || spoof_seed.iter().all(|byte| *byte == 0)
            || hex::encode(&spoof_seed) != self.historical_spoof_challenge_seed
            || self
                .scenarios
                .iter()
                .any(|case| case.challenge == self.historical_spoof_challenge_seed)
        {
            return Err(CiError::Message(
                "static spoof challenge seed must be independent canonical 32 bytes".into(),
            ));
        }
        let policy_branches =
            memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::ALL;
        if self.policy_recipe.registry_sha256.bytes() == &[0; 32]
            || self.policy_recipe.fixture_template_sha256.bytes() == &[0; 32]
            || self.policy_recipe.branches.len() != policy_branches.len()
            || self
                .policy_recipe
                .branches
                .iter()
                .zip(policy_branches)
                .any(|(recipe, branch)| {
                    recipe.branch != branch || recipe.contract_template_sha256.bytes() == &[0; 32]
                })
        {
            return Err(CiError::Message(
                "static public policy registry/fixture/exact five branch templates differ".into(),
            ));
        }
        if self.schema_version != 1
            || self.observer_subject.stage != ObserverStageV1::Public
            || self.archive_size == 0
            || self.public_uid == 0
            || self.public_gid == 0
            || self.historical_spoof_uid == 0
            || self.historical_spoof_gid == 0
            || self.historical_spoof_uid == self.public_uid
            || self.historical_spoof_gid == self.public_gid
            || [
                &self.archive_sha256,
                &self.manifest_sha256,
                &self.qualification_sha256,
                &self.qualification_certificate_file_sha256,
                &self.qualification_certificate_payload_sha256,
                &self.public_cli_sha256,
            ]
            .into_iter()
            .any(|digest| digest.bytes() == &[0; 32])
            || self.scenarios.len() != REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len()
            || self.identity_sha256()? != self.observer_subject.intent_sha256
        {
            return Err(CiError::Message(
                "static public release subject differs".into(),
            ));
        }
        let mut challenges = std::collections::BTreeSet::new();
        for (scenario, selector) in self
            .scenarios
            .iter()
            .zip(REQUIRED_PRIVATE_RELEASE_SELECTORS_V1)
        {
            let challenge = hex::decode(&scenario.challenge)
                .map_err(|_| CiError::Message("public challenge is not hex".into()))?;
            if scenario.selector != selector
                || challenge.len() != 32
                || hex::encode(&challenge) != scenario.challenge
                || challenge.iter().all(|byte| *byte == 0)
                || !challenges.insert(&scenario.challenge)
                || scenario.fixture_sha256.bytes() == &[0; 32]
                || scenario.contract_template_sha256.bytes() == &[0; 32]
            {
                return Err(CiError::Message(
                    "static public scenario order/challenge/fixture differs".into(),
                ));
            }
            crate::private_case_semantics::closed_case_spec(
                selector,
                &self.observer_subject.target,
            )?;
            if scenario.recipe.filter_sha256.bytes() == &[0; 32]
                || scenario
                    .recipe
                    .filter_install_source_sha256
                    .as_ref()
                    .is_some_and(|digest| digest.bytes() == &[0; 32])
                || !memcordon_core::private_public_preparation_v2::approved_public_fixture_argv_shape_v2(selector,&scenario.recipe.fixture_argv)
                || scenario.recipe.target_uid == 0
                || scenario.recipe.target_gid == 0
                || scenario.recipe.port == 0
                || scenario
                    .recipe
                    .supplementary_groups
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(CiError::Message(
                    "protected public fixture recipe is incomplete or ambiguous".into(),
                ));
            }
            if scenario.recipe.filter_install_source_sha256.as_ref().is_some_and(|digest|
                digest != &crate::private_candidate_filter_facility_facts::filter_install_source_revision_sha256()) {
                return Err(CiError::Message("public installed-filter source requires exact reviewed opt-in".into()));
            }
            if scenario.recipe.facility_source_sha256.as_ref().is_some_and(|digest|
                digest != &memcordon_core::private_facility_source_v1::facility_source_revision_sha256()) {
                return Err(CiError::Message("public Facility sources require exact reviewed opt-in".into()));
            }
            if scenario.recipe.host_preservation_source_sha256.as_ref().is_some_and(|digest|
                digest != &crate::private_candidate_host_facts::host_preservation_source_revision_sha256()) {
                return Err(CiError::Message("public host-preservation sources require exact reviewed opt-in".into()));
            }
            let slots = scenario
                .recipe
                .fixture_argv
                .iter()
                .enumerate()
                .filter_map(|(index, arg)| (arg == "--challenge").then_some(index))
                .collect::<Vec<_>>();
            if slots.len() != 1
                || scenario.recipe.fixture_argv.get(slots[0] + 1) != Some(&scenario.challenge)
            {
                return Err(CiError::Message(
                    "static public challenge seed argv slot differs".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Live prepared state is neither serializable nor completed P authority.
pub struct PreparedPublicGenerationV1 {
    static_intent_sha256: DiagnosticSha256,
    subject: ObserverSubjectV1,
    session_nonce: String,
    boot_id: String,
    generation: ObservedGenerationV1,
}

impl PreparedPublicGenerationV1 {
    pub fn generation(&self) -> &ObservedGenerationV1 {
        &self.generation
    }
    pub fn session_nonce(&self) -> &str {
        &self.session_nonce
    }
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }
    pub fn subject(&self) -> &ObserverSubjectV1 {
        &self.subject
    }
    pub fn static_intent_sha256(&self) -> &DiagnosticSha256 {
        &self.static_intent_sha256
    }
}

pub fn prepare_public_generation(
    intent: &StaticPublicSuiteIntentV1,
    lease: &AuthenticatedLiveObserverLeaseV1,
    generation: u32,
) -> Result<PreparedPublicGenerationV1> {
    intent.validate()?;
    let descriptor = lease.descriptor();
    descriptor.validate()?;
    if descriptor.subject != intent.observer_subject {
        return Err(CiError::Message(
            "live public lease differs from static protected release intent".into(),
        ));
    }
    let observed = descriptor
        .generations
        .get(generation as usize)
        .ok_or_else(|| {
            CiError::Message("public generation has not been independently activated".into())
        })?;
    if observed.generation != generation
        || observed.installed_manifest_sha256 != intent.manifest_sha256
        || observed.installed_receipt_sha256.bytes() == &[0; 32]
    {
        return Err(CiError::Message(
            "prepared public generation lacks exact installed M1/H1".into(),
        ));
    }
    Ok(PreparedPublicGenerationV1 {
        static_intent_sha256: intent.identity_sha256()?,
        subject: descriptor.subject.clone(),
        session_nonce: descriptor.session_nonce.clone(),
        boot_id: descriptor.boot_id.clone(),
        generation: observed.clone(),
    })
}

/// Historical timeline capability is reconstructed from custody, never from
/// collector-local /proc, installation receipts or current H1.
pub struct VerifiedInstalledPublicTimelineV1 {
    generations: Vec<ObservedGenerationV1>,
    digest: DiagnosticSha256,
    boot_id: String,
}

impl VerifiedInstalledPublicTimelineV1 {
    pub fn generations(&self) -> &[ObservedGenerationV1] {
        &self.generations
    }
    pub fn digest(&self) -> &DiagnosticSha256 {
        &self.digest
    }
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }
    pub fn final_generation(&self) -> &ObservedGenerationV1 {
        self.generations
            .last()
            .expect("verified timeline cannot be empty")
    }
}

pub fn verify_installed_public_timeline(
    intent: &StaticPublicSuiteIntentV1,
    origin: &AuthenticatedObserverSessionV1,
) -> Result<VerifiedInstalledPublicTimelineV1> {
    verify_public_timeline_origin(intent, origin)
}
pub(crate) fn verify_public_timeline_origin(
    intent: &StaticPublicSuiteIntentV1,
    origin: &impl crate::private_observer_session::ObserverEvidenceV1,
) -> Result<VerifiedInstalledPublicTimelineV1> {
    intent.validate()?;
    let descriptor = origin.descriptor();
    descriptor.validate()?;
    if descriptor.subject != intent.observer_subject || descriptor.generations.len() < 2 {
        return Err(CiError::Message(
            "public origin lacks E0/E1 installed chronology".into(),
        ));
    }
    for (ordinal, generation) in descriptor.generations.iter().enumerate() {
        if generation.generation as usize != ordinal
            || generation.installed_manifest_sha256 != intent.manifest_sha256
            || ordinal > 0
                && (generation.installed_receipt_sha256
                    == descriptor.generations[ordinal - 1].installed_receipt_sha256
                    || generation.installation_epoch
                        == descriptor.generations[ordinal - 1].installation_epoch
                    || generation.service_identity_sha256
                        == descriptor.generations[ordinal - 1].service_identity_sha256)
        {
            return Err(CiError::Message(
                "public H1/epoch/service transition differs".into(),
            ));
        }
        let root = std::path::Path::new("installed/generations").join(ordinal.to_string());
        for (leaf, digest) in [
            ("h1.json", &generation.installed_receipt_sha256),
            ("transaction.json", &generation.transaction_sha256),
        ] {
            let path = root.join(leaf).to_string_lossy().into_owned();
            if hash_bytes(origin.leaf(&path)?) != *digest {
                return Err(CiError::Message(
                    "public installed timeline exact bytes differ".into(),
                ));
            }
        }
        origin.leaf(&root.join("activation.json").to_string_lossy())?;
    }
    for (path, digest) in [
        (
            "installed/build.json",
            &intent.observer_subject.build_sha256,
        ),
        ("installed/manifest.json", &intent.manifest_sha256),
        ("installed/qualification.json", &intent.qualification_sha256),
        (
            "installed/native-certificate.json",
            &intent.qualification_certificate_file_sha256,
        ),
    ] {
        if hash_bytes(origin.leaf(path)?) != *digest {
            return Err(CiError::Message(
                "public installed B/M1/Q/CQ bytes differ".into(),
            ));
        }
    }
    let signed = memcordon_core::release_trust::SignedNativeQualificationCertificateV1::parse(
        origin.leaf("installed/native-certificate.json")?,
    )
    .map_err(CiError::Message)?;
    if hash_bytes(&signed.payload.canonical_bytes().map_err(CiError::Message)?)
        != intent.qualification_certificate_payload_sha256
    {
        return Err(CiError::Message(
            "public CQ file digest was substituted for canonical payload digest".into(),
        ));
    }
    let digest = hash_bytes(&crate::private_observer_session::canonical_bytes(
        &descriptor.generations,
    )?);
    if &digest != origin.generation_timeline_sha256() {
        return Err(CiError::Message(
            "public timeline origin commitment differs".into(),
        ));
    }
    Ok(VerifiedInstalledPublicTimelineV1 {
        generations: descriptor.generations.clone(),
        digest,
        boot_id: descriptor.boot_id.clone(),
    })
}
