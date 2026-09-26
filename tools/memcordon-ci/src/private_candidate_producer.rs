//! Static candidate planning and live observer orchestration. The controller
//! chooses the fresh session nonce; installed generations are supplied only
//! after independent live observation, never predicted in the static plan.

use crate::private_kernel_replay::{IntervalIdV1, IntervalPurposeV1, parse_capture_v2};
use crate::private_observer_session::*;
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "argument",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum ReviewedFixtureArgumentV1 {
    Literal(String),
    FreshChallengeHex,
    RequestedPort,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedCandidateRecipeV1 {
    pub selector: String,
    pub fixture_sha256: DiagnosticSha256,
    pub argv: Vec<ReviewedFixtureArgumentV1>,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub port: u16,
    #[serde(default)]
    pub port_recipe: CandidatePortRecipeV1,
    pub auxiliary_semantics_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    pub filter_install_source_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    pub facility_source_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    pub host_preservation_source_sha256: Option<DiagnosticSha256>,
    #[serde(default)]
    pub reuse_source_sha256: Option<DiagnosticSha256>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidatePortRecipeV1 {
    #[default]
    Fixed,
    ChallengeBoundPrivateV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticCandidateProducerIntentV1 {
    pub schema_version: u8,
    pub subject: ObserverSubjectV1,
    pub custody_policy: PathBuf,
    pub enrolled_host: String,
    pub recipes: Vec<ReviewedCandidateRecipeV1>,
    pub observer: memcordon_core::private_release_branch_v1::PrivatePolicyObserverIntentV1,
}

impl StaticCandidateProducerIntentV1 {
    pub fn identity_sha256(&self) -> Result<DiagnosticSha256> {
        let mut canonical = self.clone();
        canonical.subject.intent_sha256 = DiagnosticSha256::from_bytes([0; 32]);
        let mut bytes = b"memcordon/static-candidate-producer-intent/v1\0".to_vec();
        bytes.extend_from_slice(&canonical_bytes(&canonical)?);
        Ok(hash_bytes(&bytes))
    }
    pub fn validate(&self) -> Result<()> {
        self.subject.validate()?;
        self.observer.validate().map_err(CiError::Message)?;
        if self.schema_version!=1 || self.subject.stage!=ObserverStageV1::Candidate
            || self.identity_sha256()?!=self.subject.intent_sha256
            || !self.custody_policy.is_absolute() || self.enrolled_host.is_empty()
            || self.recipes.len()!=crate::private_suite::REQUIRED_CASES.len()
            || self.recipes.iter().zip(crate::private_suite::REQUIRED_CASES).any(|(recipe,selector)|
                recipe.selector!=selector || recipe.fixture_sha256.bytes()==&[0;32] || recipe.argv.is_empty()
                || recipe.filter_install_source_sha256.as_ref().is_some_and(|revision|revision!=&crate::private_candidate_filter_facility_facts::filter_install_source_revision_sha256())
                || recipe.facility_source_sha256.as_ref().is_some_and(|revision|revision!=&memcordon_core::private_facility_source_v1::facility_source_revision_sha256())
                || recipe.host_preservation_source_sha256.as_ref().is_some_and(|revision|revision!=&crate::private_candidate_host_facts::host_preservation_source_revision_sha256())
                || recipe.reuse_source_sha256.as_ref().is_some_and(|revision|recipe.selector!=memcordon_core::private_reuse_source_v1::REUSE_SELECTOR_V1 || revision!=&memcordon_core::private_reuse_source_v1::reuse_source_revision_sha256())
                || recipe.argv.len()>128 || recipe.uid==0 || recipe.gid==0
                || match recipe.port_recipe {
                    CandidatePortRecipeV1::Fixed => recipe.port == 0,
                    CandidatePortRecipeV1::ChallengeBoundPrivateV1 => recipe.port != 0,
                }
                || recipe.argv.iter().any(|argument|matches!(argument,ReviewedFixtureArgumentV1::Literal(value) if value.is_empty() || value.len()>4096 || value.contains('\0')))) {
            return fail("static candidate producer plan differs from closed subject/recipe catalogue");
        }
        Ok(())
    }
    pub fn read_protected(path: &Path) -> Result<Self> {
        let intent: Self = strict_json(
            &crate::private_protected_readback::read_protected_raw_case_file(path)?,
            128 * 1024,
        )?;
        intent.validate()?;
        Ok(intent)
    }
}

/// This carrier can exist only after a fresh enrolled live lease. It contains
/// no claim that an attempt was allocated, executed, retired or uploaded.
pub(crate) struct PreparedCandidateCaseV1 {
    pub(crate) selector: String,
    pub(crate) challenge: [u8; 32],
    pub(crate) key: DiagnosticSha256,
    pub(crate) argv: Vec<String>,
    pub(crate) port: u16,
    pub(crate) recipe: ReviewedCandidateRecipeV1,
    pub(crate) interval_id: IntervalIdV1,
}

/// Actual immutable pre-request native carrier and independently held caller.
/// This is source data only; no rejection or epoch capability is returned.
#[derive(Default)]
pub(crate) struct CandidateCallerSourcesV1 {
    pub(crate) admission: Option<Vec<u8>>,
    pub(crate) ready: Option<Vec<u8>>,
    pub(crate) sample: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
}

#[cfg(target_os = "linux")]
pub(crate) fn sample_candidate_caller_if_ready(
    directory: &Path,
    parent: &PreparedCandidateCaseV1,
    expected_image: &DiagnosticSha256,
    state: &mut CandidateCallerSourcesV1,
) -> Result<bool> {
    use crate::private_candidate_caller_frames::{
        IndependentCallerAdmissionV2, IndependentCallerReadyV1,
    };
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if state.sample.is_some() {
        return Ok(false);
    }
    let ready_path = directory.join("caller-ready-v1.json");
    if matches!(std::fs::symlink_metadata(&ready_path),Err(error) if error.kind()==std::io::ErrorKind::NotFound)
    {
        return Ok(false);
    }
    let ready_bytes = crate::private_protected_readback::read_protected_raw_case_file(&ready_path)?;
    let admission_bytes = crate::private_protected_readback::read_protected_raw_case_file(
        &directory.join("request.json"),
    )?;
    let ready: IndependentCallerReadyV1 = strict_json(&ready_bytes, 16 * 1024)?;
    let admission: IndependentCallerAdmissionV2 = strict_json(&admission_bytes, 16 * 1024)?;
    if ready.schema_version != 1
        || ready.protocol != "candidate-independent-caller-ready-v1"
        || admission.schema_version != 2
        || admission.protocol != "candidate-independent-caller-probe-v2"
        || ready.parent_result_key != parent.key
        || admission.parent_result_key != parent.key
        || admission.challenge != parent.challenge
        || ready.admission_sha256 != hash_bytes(&admission_bytes)
        || admission.spoof_challenge
            != crate::private_candidate_caller_frames::caller_spoof_challenge_v1(&parent.challenge)
        || ready.caller_uid != parent.recipe.uid
        || ready.caller_gid != parent.recipe.gid
        || admission.caller_uid != parent.recipe.uid
        || admission.caller_gid != parent.recipe.gid
        || ready.caller.pid == 0
        || ready.caller.start_time == 0
        || ready.control_group_gid == 0
        || admission.admission_monotonic_ns == 0
        || ready.ready_monotonic_ns < admission.admission_monotonic_ns
    {
        return fail("independent caller actual admission/ready recipe differs");
    }
    let sample = crate::private_public_live::sample_held_target_raw(
        ready.caller.pid,
        ready.caller.start_time,
        expected_image,
    )?;
    let status = std::str::from_utf8(
        sample
            .leaves
            .get("status.raw")
            .ok_or_else(|| CiError::Message("actual caller status absent".into()))?,
    )
    .map_err(|_| CiError::Message("actual caller status is not text".into()))?;
    for (field, expected) in [("Uid:", ready.caller_uid), ("Gid:", ready.caller_gid)] {
        let values = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .ok_or_else(|| CiError::Message("actual held caller credentials absent".into()))?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| CiError::Message("actual held caller credentials invalid".into()))?;
        if values != vec![expected; 4] {
            return fail("actual held caller credentials differ");
        }
    }
    if sample.begin_monotonic_ns < ready.ready_monotonic_ns
        || crate::private_protected_readback::read_protected_raw_case_file(&ready_path)?
            != ready_bytes
        || crate::private_protected_readback::read_protected_raw_case_file(
            &directory.join("request.json"),
        )? != admission_bytes
    {
        return fail("actual caller admission/ready changed while independently held");
    }
    let ack = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"gate_sha256":hash_bytes(&ready_bytes)}),
    )?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("caller-ready-v1.ack"))?;
    file.write_all(&ack)?;
    file.sync_all()?;
    std::fs::File::open(directory)?.sync_all()?;
    state.admission = Some(admission_bytes);
    state.ready = Some(ready_bytes);
    state.sample = Some(sample);
    Ok(true)
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn sample_candidate_caller_if_ready(
    _directory: &Path,
    _parent: &PreparedCandidateCaseV1,
    _expected_image: &DiagnosticSha256,
    _state: &mut CandidateCallerSourcesV1,
) -> Result<bool> {
    fail("independent caller sampling requires Linux")
}

/// Pure preparation shared by live execution and completed replay. Static
/// admission never predicts the controller nonce or an installed generation.
pub(crate) fn prepared_candidate_case_recipe_v1(
    intent: &StaticCandidateProducerIntentV1,
    session_nonce: &str,
    generation: u32,
    selector: &str,
    purpose: IntervalPurposeV1,
    ordinal: u32,
) -> Result<PreparedCandidateCaseV1> {
    let recipe = intent
        .recipes
        .iter()
        .find(|recipe| recipe.selector == selector)
        .ok_or_else(|| CiError::Message("candidate selector has no reviewed recipe".into()))?
        .clone();
    let nonce: [u8; 32] = hex::decode(session_nonce)
        .map_err(|_| CiError::Message("live nonce encoding differs".into()))?
        .try_into()
        .map_err(|_| CiError::Message("live nonce length differs".into()))?;
    if nonce == [0; 32] || hex::encode(nonce) != session_nonce {
        return fail("controller nonce is not canonical or fresh");
    }
    let mut seed = b"memcordon/candidate-prepared-case/v1\0".to_vec();
    seed.extend_from_slice(&nonce);
    seed.extend_from_slice(&generation.to_be_bytes());
    seed.extend_from_slice(&ordinal.to_be_bytes());
    seed.push(purpose as u8);
    seed.extend_from_slice(&(selector.len() as u64).to_be_bytes());
    seed.extend_from_slice(selector.as_bytes());
    let challenge = *hash_bytes(&seed).bytes();
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        selector,
        &challenge,
    )
    .map_err(CiError::Message)?;
    let port = match recipe.port_recipe {
        CandidatePortRecipeV1::Fixed => recipe.port,
        CandidatePortRecipeV1::ChallengeBoundPrivateV1 => {
            memcordon_core::private_release_case_v1::candidate_fixture_port_v1(&challenge)
        }
    };
    let argv = recipe
        .argv
        .iter()
        .map(|argument| match argument {
            ReviewedFixtureArgumentV1::Literal(value) => value.clone(),
            ReviewedFixtureArgumentV1::FreshChallengeHex => hex::encode(challenge),
            ReviewedFixtureArgumentV1::RequestedPort => port.to_string(),
        })
        .collect();
    Ok(PreparedCandidateCaseV1 {
        selector: selector.into(),
        challenge,
        key: key.clone(),
        argv,
        port,
        recipe,
        interval_id: IntervalIdV1 {
            session_nonce: nonce,
            generation,
            logical_case_key: key,
            purpose,
            ordinal,
        },
    })
}

pub(crate) struct CandidateProducerJournalV1 {
    intent: StaticCandidateProducerIntentV1,
    transport: AuthenticatedCustodianTransportV1,
    lease: AuthenticatedLiveObserverLeaseV1,
    next_chunk: u64,
    chain: DiagnosticSha256,
    payload: BTreeMap<String, Vec<u8>>,
    generation: u32,
    open_interval: Option<DiagnosticSha256>,
    pending_generation_raw: BTreeMap<String, Vec<u8>>,
}

impl CandidateProducerJournalV1 {
    pub(crate) fn raw_payload(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.payload
    }
    pub(crate) fn descriptor(&self) -> &ObserverSessionDescriptorV1 {
        self.lease.descriptor()
    }
    pub(crate) fn begin(
        intent: StaticCandidateProducerIntentV1,
        boot_id: String,
        kernel_btf_sha256: DiagnosticSha256,
        observer_executable_sha256: DiagnosticSha256,
        first: ObservedGenerationV1,
    ) -> Result<Self> {
        intent.validate()?;
        if first.generation != 0 {
            return fail("candidate E0 must be the first observed generation");
        }
        let descriptor = ObserverSessionDescriptorV1 {
            schema_version: 1,
            session_nonce: String::new(),
            subject: intent.subject.clone(),
            enrolled_host: intent.enrolled_host.clone(),
            boot_id,
            kernel_btf_sha256,
            observer_executable_sha256,
            generations: vec![first],
            intervals: Vec::new(),
        };
        // No nonce is claimed by this enrollment request. BeginObserved
        // installs the controller's independently generated random nonce.
        let mut transport = AuthenticatedCustodianTransportV1::connect(&intent.custody_policy)?;
        let lease = transport.begin_live_observed(descriptor)?;
        let chain = hash_bytes(&canonical_bytes(lease.descriptor())?);
        Ok(Self {
            intent,
            transport,
            lease,
            next_chunk: 0,
            chain,
            payload: BTreeMap::new(),
            generation: 0,
            open_interval: None,
            pending_generation_raw: BTreeMap::new(),
        })
    }
    pub(crate) fn subject(&self) -> &ObserverSubjectV1 {
        &self.intent.subject
    }
    pub(crate) fn queue_generation_raw(&mut self, raw: BTreeMap<String, Vec<u8>>) -> Result<()> {
        if self.open_interval.is_some() || !self.pending_generation_raw.is_empty() {
            return fail("candidate generation raw overlaps armed/pending custody");
        }
        self.pending_generation_raw = raw;
        if self.generation == 0 {
            // This configuration witness is independently committed by the
            // enrolled subject.intent_sha256; it does not enroll itself.
            self.pending_generation_raw.insert(
                "candidate-c-v3/observer/static-intent.v1.json".into(),
                canonical_bytes(&self.intent)?,
            );
        }
        Ok(())
    }
    pub(crate) fn prepare_case(
        &self,
        selector: &str,
        purpose: IntervalPurposeV1,
        ordinal: u32,
    ) -> Result<PreparedCandidateCaseV1> {
        prepared_candidate_case_recipe_v1(
            &self.intent,
            &self.lease.descriptor().session_nonce,
            self.generation,
            selector,
            purpose,
            ordinal,
        )
    }
    pub(crate) fn arm_before_execution(&mut self, case: &PreparedCandidateCaseV1) -> Result<()> {
        if self.open_interval.is_some() || case.interval_id.generation != self.generation {
            return fail("candidate custody arm overlaps interval/generation");
        }
        let id = case.interval_id.storage_sha256();
        let reply = self.transport.begin_interval(&self.lease, id.clone())?;
        if reply.next_chunk != self.next_chunk || reply.last_chunk_sha256 != self.chain {
            return fail("candidate arm custody continuity differs");
        }
        self.open_interval = Some(id);
        for (path, bytes) in std::mem::take(&mut self.pending_generation_raw) {
            self.append_raw(path, bytes)?;
        }
        Ok(())
    }
    pub(crate) fn append_raw(&mut self, path: String, bytes: Vec<u8>) -> Result<()> {
        if self.open_interval.is_none() || self.payload.contains_key(&path) {
            return fail("candidate raw append outside arm or repeats path");
        }
        // This lane may not inherit the public stage's larger envelope.
        // Reserve the fixed I/K/R/W carriers before accepting literal bytes.
        const CANDIDATE_PAYLOAD_BUDGET: usize = 64 * 1024 * 1024 - 3 * 128 * 1024;
        let used = self
            .payload
            .values()
            .try_fold(0_usize, |total, raw| total.checked_add(raw.len()))
            .ok_or_else(|| CiError::Message("candidate payload byte count overflow".into()))?;
        if bytes.len() > 8 * 1024 * 1024
            || used
                .checked_add(bytes.len())
                .is_none_or(|total| total > CANDIDATE_PAYLOAD_BUDGET)
        {
            return fail("candidate raw custody exceeds reviewed member/suite budget");
        }
        let reply = self.transport.append(
            &self.lease,
            self.next_chunk,
            self.chain.clone(),
            path.clone(),
            bytes.clone(),
        )?;
        self.next_chunk = reply.next_chunk;
        self.chain = reply.last_chunk_sha256;
        self.payload.insert(path, bytes);
        Ok(())
    }
    pub(crate) fn retain_shared_image(&mut self, bytes: Vec<u8>) -> Result<String> {
        let path = Path::new("candidate-c-v3/observer/images")
            .join(format!("{}.raw", String::from(hash_bytes(&bytes))))
            .to_string_lossy()
            .into_owned();
        let expanded = crate::private_source_carrier::expand_source_payload(&self.payload)?;
        if let Some(previous) = expanded.get(&path) {
            if previous != &bytes {
                return fail("shared held ELF source changed for the same digest/path");
            }
        } else {
            self.append_raw(path.clone(), bytes)?;
        }
        Ok(path)
    }
    pub(crate) fn append_representation(&mut self, path: String, bytes: Vec<u8>) -> Result<()> {
        if self.open_interval.is_some() || self.payload.contains_key(&path) {
            return fail("candidate representation overlaps capture or repeats a literal leaf");
        }
        let used = self
            .payload
            .values()
            .try_fold(0_usize, |total, raw| total.checked_add(raw.len()))
            .ok_or_else(|| CiError::Message("candidate representation total overflow".into()))?;
        if bytes.len() > 8 * 1024 * 1024
            || used
                .checked_add(bytes.len())
                .is_none_or(|total| total > 64 * 1024 * 1024 - 3 * 128 * 1024)
        {
            return fail("candidate representation exceeds reviewed member/suite budget");
        }
        let reply = self.transport.append_representation(
            &self.lease,
            self.next_chunk,
            self.chain.clone(),
            path.clone(),
            bytes.clone(),
        )?;
        if reply.next_chunk
            != self.next_chunk.checked_add(1).ok_or_else(|| {
                CiError::Message("candidate representation sequence overflow".into())
            })?
        {
            return fail("candidate representation acknowledgement differs");
        }
        self.next_chunk = reply.next_chunk;
        self.chain = reply.last_chunk_sha256;
        self.payload.insert(path, bytes);
        Ok(())
    }
    pub(crate) fn close_after_detach(
        &mut self,
        case: &PreparedCandidateCaseV1,
        interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
        capture_path: String,
        controls_paths: Vec<String>,
        sample_paths: Vec<String>,
        arm_monotonic_ns: u64,
        detach_monotonic_ns: u64,
    ) -> Result<()> {
        if self.open_interval.as_ref() != Some(&case.interval_id.storage_sha256())
            || interval.physical_interval_id() != Some(&case.interval_id)
            || interval.result_key() != &case.key
        {
            return fail("candidate detach physical id differs from pre-execution arm");
        }
        let parsed = parse_capture_v2(interval.capture_bytes()?, &case.key)?;
        let timing = interval.observation_timing().ok_or_else(|| {
            CiError::Message("original measured candidate observer timing absent".into())
        })?;
        if arm_monotonic_ns > timing.operation_begin_monotonic_ns
            || detach_monotonic_ns < timing.operation_end_monotonic_ns
        {
            return fail("outer candidate interval does not contain measured operation");
        }
        let first = parsed
            .events()
            .first()
            .ok_or_else(|| CiError::Message("candidate capture is empty".into()))?;
        let last = parsed
            .events()
            .last()
            .ok_or_else(|| CiError::Message("candidate capture is empty".into()))?;
        let purpose = match case.interval_id.purpose {
            IntervalPurposeV1::KnownControls => "controls",
            IntervalPurposeV1::Ordinary => "ordinary",
            IntervalPurposeV1::Policy => "policy",
            IntervalPurposeV1::AbiOuter => "abi-outer",
            IntervalPurposeV1::AbiFiltered => "abi-filtered",
            IntervalPurposeV1::Historical => match case.interval_id.ordinal {
                0 => "historical-e0",
                1 => "historical-replay",
                2 => "historical-e1",
                _ => return fail("historical interval ordinal is not closed"),
            },
            IntervalPurposeV1::CallerSpoof => "caller-spoof",
            IntervalPurposeV1::ReuseFirst => "reuse-first",
            IntervalPurposeV1::ReuseBlocked => "reuse-blocked",
            IntervalPurposeV1::Recovery => {
                if case.selector == "private_tcp::retirement_failure_blocks_reuse" {
                    "reuse-recovery"
                } else {
                    "fault-recovery"
                }
            }
            IntervalPurposeV1::DualContinuous => "dual",
            IntervalPurposeV1::FacilityControls => "facility-controls",
        };
        let record = ObserverIntervalRecordV1 {
            interval_id: case.interval_id.storage_sha256(),
            logical_case_key: case.key.clone(),
            generation: self.generation,
            purpose: purpose.into(),
            ordinal: case.interval_id.ordinal,
            capture_path,
            capture_sha256: parsed.digest().clone(),
            controls_paths,
            sample_paths,
            arm_monotonic_ns: timing.armed_monotonic_ns,
            begin_monotonic_ns: timing.operation_begin_monotonic_ns,
            end_monotonic_ns: timing.operation_end_monotonic_ns,
            detach_monotonic_ns: timing.detached_monotonic_ns,
            loss_count: 0,
            first_sequence: first.sequence,
            last_sequence: last.sequence,
        };
        let reply = self.transport.close_interval(&self.lease, record)?;
        self.lease = self.transport.begin_live(&self.intent.subject)?;
        if reply.next_chunk != self.next_chunk || reply.last_chunk_sha256 != self.chain {
            return fail("candidate detached custody continuity differs");
        }
        self.open_interval = None;
        Ok(())
    }
    pub(crate) fn observe_upgrade(&mut self, next: ObservedGenerationV1) -> Result<()> {
        if self.open_interval.is_some() || self.generation.checked_add(1) != Some(next.generation) {
            return fail("candidate upgrade crosses active interval or skips generation");
        }
        let generation = next.generation;
        self.transport.observe_generation(&self.lease, next)?;
        self.lease = self.transport.begin_live(&self.intent.subject)?;
        self.generation = generation;
        Ok(())
    }
    pub(crate) fn seal(
        self,
        cleanup_sha256: DiagnosticSha256,
        monotonic_ns: u64,
    ) -> Result<(
        AuthenticatedSealedLiveObserverSessionV1,
        CustodianReadbackV1,
    )> {
        if self.open_interval.is_some() {
            return fail("candidate seal while interval remains armed");
        }
        let mut transport = self.transport;
        transport.seal_and_authenticate(self.lease, self.payload, cleanup_sha256, monotonic_ns)
    }
    pub(crate) fn repack_sources(&mut self, path: String, sources: Vec<String>) -> Result<Vec<u8>> {
        if self.open_interval.is_some() {
            return fail("candidate source packing while capture remains armed");
        }
        let mut raw = BTreeMap::new();
        for source in &sources {
            raw.insert(
                source.clone(),
                self.payload
                    .get(source)
                    .ok_or_else(|| CiError::Message("candidate pack source absent".into()))?
                    .clone(),
            );
        }
        let packed = crate::private_source_carrier::encode_source_carrier(&raw)?;
        let reply = self.transport.repack_sources(
            &self.lease,
            self.next_chunk,
            self.chain.clone(),
            path.clone(),
            sources.clone(),
        )?;
        if reply.next_chunk
            != self
                .next_chunk
                .checked_add(1)
                .ok_or_else(|| CiError::Message("candidate pack sequence overflow".into()))?
        {
            return fail("candidate packing acknowledgment differs");
        }
        for source in sources {
            self.payload.remove(&source);
        }
        self.payload.insert(path, packed.clone());
        self.next_chunk = reply.next_chunk;
        self.chain = reply.last_chunk_sha256;
        Ok(packed)
    }
}

/// Samples an installed generation using held argv-free observer inputs. A
/// pending package transaction or any epoch change invalidates the sample.
/// The resulting record is raw custody input, not an installed qualification.
#[cfg(target_os = "linux")]
pub(crate) fn observe_candidate_generation(
    intent: &StaticCandidateProducerIntentV1,
    generation: u32,
    manifest: DiagnosticSha256,
    receipt: DiagnosticSha256,
    receipt_bytes: &[u8],
    epoch: DiagnosticSha256,
) -> Result<(
    ObservedGenerationV1,
    BTreeMap<String, Vec<u8>>,
    DiagnosticSha256,
)> {
    use crate::private_kernel_observer::{
        InstalledObserverRoleV1, activate_installed_network_broker_for_observation,
        observe_installed_observer_subject,
    };
    let begin = memcordon_platform::test_support::private_observer_monotonic_ns()?;
    if crate::private_installed_h0::read_fixed_installation_epoch()? != epoch
        || hash_bytes(receipt_bytes) != receipt
    {
        return fail("observed candidate generation initial H0/epoch differs");
    }
    let epoch_raw = crate::private_protected_readback::read_protected_raw_case_file(Path::new(
        "/usr/libexec/.memcordon-installation-epoch.json",
    ))?;
    if crate::private_installed_h0::validate_installation_epoch_bytes(&epoch_raw)? != epoch {
        return fail("candidate original epoch bytes differ");
    }
    let manifest_raw = crate::private_protected_readback::read_protected_raw_case_file(Path::new(
        "/usr/libexec/memcordon-runtime-manifest.json",
    ))?;
    if hash_bytes(&manifest_raw) != manifest {
        return fail("candidate original manifest bytes differ");
    }
    let service = observe_installed_observer_subject(InstalledObserverRoleV1::SealedService)?;
    let broker = activate_installed_network_broker_for_observation()?;
    let service_raw = canonical_bytes(
        &serde_json::json!({"schema_version":1,"pid":service.pid,"start_time_ticks":service.start_ticks,"cgroup_inode":service.cgroup_inode}),
    )?;
    let broker_raw = canonical_bytes(
        &serde_json::json!({"schema_version":1,"pid":broker.pid,"start_time_ticks":broker.start_ticks,"cgroup_inode":broker.cgroup_inode}),
    )?;
    // `read_fixed_installation_epoch` independently rejects the actual fixed
    // package-journal path. This carrier records that sampled absence, not an
    // invented successful transaction or an authorization to upgrade.
    let transaction_raw = canonical_bytes(
        &serde_json::json!({"schema_version":1,"pending_journal":false,"installation_epoch":epoch,"observed_monotonic_ns":begin}),
    )?;
    let p = &intent.observer;
    let probe = crate::private_probe_bundle::verify_probe_bundle(
        crate::private_probe_bundle::ExpectedProbeBundleV1 {
            bpf_source_sha256: p.bpf_source_sha256.clone(),
            loader_source_sha256: p.loader_source_sha256.clone(),
            object_sha256: p.object_sha256.clone(),
            loader_sha256: p.loader_sha256.clone(),
            agent_sha256: p.agent_sha256.clone(),
            agent_build_id: p.agent_build_id.clone(),
            request_entry_offset: p.request_entry_offset,
            request_exit_offset: p.request_exit_offset,
            allocation_entry_offset: p.allocation_entry_offset,
        },
    )?;
    let observer_raw = canonical_bytes(
        &serde_json::json!({"schema_version":1,"reviewed":intent.observer,"probe_attestation_sha256":probe.attestation_digest()}),
    )?;
    let btf = crate::private_observer_session::read_bounded_file(
        Path::new("/sys/kernel/btf/vmlinux"),
        64 * 1024 * 1024,
    )?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    if boot.trim() != p.boot_id || hash_bytes(&btf) != p.btf_sha256 {
        return fail("candidate live boot/BTF differs from enrolled profile");
    }
    if crate::private_installed_h0::read_fixed_installation_epoch()? != epoch {
        return fail("candidate generation rotated while observed");
    }
    let end = memcordon_platform::test_support::private_observer_monotonic_ns()?;
    let record = ObservedGenerationV1 {
        generation,
        installation_epoch: epoch,
        installed_manifest_sha256: manifest,
        installed_receipt_sha256: receipt,
        service_identity_sha256: hash_bytes(&service_raw),
        broker_identity_sha256: hash_bytes(&broker_raw),
        transaction_sha256: hash_bytes(&transaction_raw),
        observer_bundle_sha256: hash_bytes(&observer_raw),
        begin_monotonic_ns: begin,
        end_monotonic_ns: end,
    };
    let prefix = Path::new("candidate-c-v3/observer/generations").join(generation.to_string());
    let raw = [
        ("installation-epoch.json", epoch_raw),
        ("manifest.json", manifest_raw),
        ("installed-receipt.json", receipt_bytes.to_vec()),
        ("service.json", service_raw),
        ("broker.json", broker_raw),
        ("transaction.json", transaction_raw),
        ("observer-map.json", observer_raw),
    ]
    .into_iter()
    .map(|(leaf, bytes)| (prefix.join(leaf).to_string_lossy().into_owned(), bytes))
    .collect();
    let executable = std::env::current_exe()?.canonicalize()?;
    let executable_sha256 = hash_bytes(&crate::private_observer_session::read_bounded_file(
        &executable,
        64 * 1024 * 1024,
    )?);
    Ok((record, raw, executable_sha256))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn observe_candidate_generation(
    _intent: &StaticCandidateProducerIntentV1,
    _generation: u32,
    _manifest: DiagnosticSha256,
    _receipt: DiagnosticSha256,
    _receipt_bytes: &[u8],
    _epoch: DiagnosticSha256,
) -> Result<(
    ObservedGenerationV1,
    BTreeMap<String, Vec<u8>>,
    DiagnosticSha256,
)> {
    fail("candidate installed generation observation requires native Linux")
}

fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateHeldIdentityV1 {
    pid: u32,
    start_time: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateLiveGateV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    phase: String,
    target: CandidateHeldIdentityV1,
    raw_response: Vec<u8>,
}

/// Phase-separated raw observations. These are collected while the native
/// target is held; neither the worker's gate nor the ACK is a semantic token.
#[derive(Default)]
pub(crate) struct CandidateLivePhasesV1 {
    pub(crate) pre: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
    pub(crate) second_pre: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
    pub(crate) release_intent: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
    pub(crate) second_release_intent: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
    pub(crate) baseline: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
    pub(crate) second_baseline: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
    pub(crate) first_ready: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
    pub(crate) second_ready: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
    pub(crate) second_after_retirement:
        Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
    pub(crate) post: Option<crate::private_public_live::HeldPublicTargetSamplesV1>,
    pub(crate) gates: BTreeMap<String, Vec<u8>>,
    /// Exact native journal snapshots and independently reopened metadata.
    /// These are custody sources, not projections of a completed result.
    pub(crate) source_leaves: BTreeMap<String, Vec<u8>>,
    pub(crate) held_roles: BTreeMap<String, crate::private_public_live::HeldPublicTargetSamplesV1>,
    namespace_handles: Vec<crate::private_public_live::HeldPublicNamespaceCustodyV1>,
    pub(crate) namespace_closes: Vec<crate::private_public_live::PublicNamespaceCloseV1>,
}

impl CandidateLivePhasesV1 {
    pub(crate) fn retain_held_role(
        &mut self,
        role: String,
        sample: crate::private_public_live::HeldPublicTargetSamplesV1,
    ) -> Result<()> {
        if self.held_roles.contains_key(&role) {
            return fail("candidate held source role duplicated");
        }
        self.namespace_handles
            .push(crate::private_public_live::hold_sampled_public_namespaces(
                &sample,
            )?);
        self.held_roles.insert(role, sample);
        Ok(())
    }
    pub(crate) fn close_observer_namespaces(&mut self) -> Result<()> {
        for handles in std::mem::take(&mut self.namespace_handles) {
            self.namespace_closes.extend(handles.close()?);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn sample_candidate_phases_if_ready(
    directory: &Path,
    selector: &str,
    target: &str,
    challenge: &[u8; 32],
    expected_pre_image: &DiagnosticSha256,
    recipe: &ReviewedCandidateRecipeV1,
    argv: &[String],
    state: &mut CandidateLivePhasesV1,
) -> Result<bool> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        selector,
        challenge,
    )
    .map_err(CiError::Message)?;
    let meta = std::fs::symlink_metadata(directory)?;
    if !rustix::process::geteuid().is_root()
        || !meta.is_dir()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
    {
        return fail("candidate sampling directory is not protected root custody");
    }
    let dual = selector == "private_tcp::dual_attempt_namespace_isolation";
    retain_candidate_journal_snapshots(directory, dual, state)?;
    let mut phases = vec![if dual {
        (
            "first-pre-exec-gated",
            "candidate-first-pre-v1.json",
            "candidate-first-pre-v1.ack",
            0,
        )
    } else {
        (
            "pre-exec-gated",
            "candidate-live-pre-v1.json",
            "candidate-live-pre-v1.ack",
            0,
        )
    }];
    if dual {
        phases.extend([
            (
                "first-release-intent-gated",
                "candidate-first-release-intent-v1.json",
                "candidate-first-release-intent-v1.ack",
                6,
            ),
            (
                "first-post-exec-baseline",
                "candidate-first-baseline-v1.json",
                "candidate-first-baseline-v1.ack",
                1,
            ),
            (
                "second-pre-exec-gated",
                "candidate-second-pre-v1.json",
                "candidate-second-pre-v1.ack",
                4,
            ),
            (
                "second-release-intent-gated",
                "candidate-second-release-intent-v1.json",
                "candidate-second-release-intent-v1.ack",
                7,
            ),
            (
                "second-post-exec-baseline",
                "candidate-second-baseline-v1.json",
                "candidate-second-baseline-v1.ack",
                2,
            ),
        ]);
        phases.push((
            "second-after-first-retired",
            "candidate-second-post-retirement-v1.json",
            "candidate-second-post-retirement-v1.ack",
            5,
        ));
    } else {
        phases.push((
            "release-intent-gated",
            "candidate-live-release-intent-v1.json",
            "candidate-live-release-intent-v1.ack",
            6,
        ));
        phases.push((
            "post-exec-baseline",
            "candidate-live-baseline-v1.json",
            "candidate-live-baseline-v1.ack",
            1,
        ));
    }
    phases.push((
        "post-exec-held",
        "candidate-live-post-v1.json",
        "candidate-live-post-v1.ack",
        3,
    ));
    for (phase, leaf, ack, slot) in phases {
        if match slot {
            0 => state.pre.is_some(),
            1 => state.baseline.is_some(),
            2 => state.second_baseline.is_some(),
            3 => state.post.is_some(),
            4 => state.second_pre.is_some(),
            5 => state.second_after_retirement.is_some(),
            6 => state.release_intent.is_some(),
            7 => state.second_release_intent.is_some(),
            _ => unreachable!(),
        } {
            continue;
        }
        let path = directory.join(leaf);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let bytes = crate::private_protected_readback::read_protected_raw_case_file(&path)?;
        let gate: CandidateLiveGateV1 = strict_json(&bytes, 128 * 1024)?;
        if gate.schema_version != 1
            || gate.selector != selector
            || gate.result_key != key
            || gate.challenge_sha256 != hash_bytes(challenge)
            || gate.phase != phase
            || gate.target.pid == 0
            || gate.target.start_time == 0
            || gate.raw_response.len() > 64 * 1024
            || (matches!(slot, 0 | 4 | 6 | 7) && !gate.raw_response.is_empty())
            || serde_json::to_vec(&gate)? != bytes
        {
            return fail("candidate phase gate exact identity/phase/challenge differs");
        }
        if matches!(slot, 1 | 2)
            && (gate.raw_response.len() != 48
                || gate.raw_response.get(..8) != Some(b"MCBL\x01\0\0\0".as_slice())
                || gate.raw_response.get(8..40) != Some(challenge.as_slice())
                || gate.raw_response.get(40..44) != Some(3_i32.to_le_bytes().as_slice())
                || gate.raw_response.get(44..) != Some(0_u32.to_le_bytes().as_slice()))
        {
            return fail("candidate exact pre-operation baseline frame differs");
        }
        if slot == 5
            && (gate.raw_response.len() != 82
                || gate.raw_response.get(..8) != Some(b"MCDR\x01\0\0\0".as_slice())
                || gate.raw_response.get(8..40) != Some(challenge.as_slice()))
        {
            return fail("candidate actual post-retirement second exchange frame differs");
        }
        let mut sample = if !matches!(slot, 0 | 4 | 6 | 7) {
            let pre = if matches!(slot, 2 | 5) {
                &state.second_pre
            } else {
                &state.pre
            };
            if pre.as_ref().is_none_or(|pre| {
                pre.pid != gate.target.pid || pre.start_time_ticks != gate.target.start_time
            }) {
                return fail(
                    "candidate post-exec gate is not the same independently sampled pre-exec target",
                );
            }
            crate::private_public_live::sample_held_public_target(
                gate.target.pid,
                gate.target.start_time,
                recipe.uid,
                recipe.gid,
                &recipe.fixture_sha256,
                argv,
            )?
        } else {
            if matches!(slot, 6 | 7) {
                let pre = if slot == 7 {
                    &state.second_pre
                } else {
                    &state.pre
                };
                if pre.as_ref().is_none_or(|sample| {
                    sample.pid != gate.target.pid
                        || sample.start_time_ticks != gate.target.start_time
                }) {
                    return fail("release-intent gate replaced the independently held target");
                }
                let branch = if dual {
                    if slot == 6 {
                        "dual-first"
                    } else {
                        "dual-second"
                    }
                } else {
                    ""
                };
                let source = Path::new(branch)
                    .join("release-intent-v1.json")
                    .to_string_lossy()
                    .into_owned();
                if !state.source_leaves.contains_key(&source)
                    || !state
                        .source_leaves
                        .contains_key(&format!("{source}.metadata.json"))
                {
                    return fail("pre-GO release-intent gate lacks exact reopened native snapshot");
                }
            }
            crate::private_public_live::sample_held_target_raw(
                gate.target.pid,
                gate.target.start_time,
                expected_pre_image,
            )?
        };
        if matches!(slot, 3 | 5)
            && crate::private_case_semantics::closed_candidate_case_spec(selector, target)?
                .facts
                .iter()
                .any(|kind| {
                    matches!(
                        kind,
                        crate::private_case_semantics::CaseFactKindV1::Tcp
                            | crate::private_case_semantics::CaseFactKindV1::Collision
                            | crate::private_case_semantics::CaseFactKindV1::Topology
                    )
                })
        {
            crate::private_public_live::sample_held_network_source(&mut sample)?;
        }
        if matches!(slot, 0 | 1 | 2 | 4) {
            if matches!(slot, 1 | 2) {
                state.namespace_handles.push(
                    crate::private_public_live::hold_sampled_public_namespaces(&sample)?,
                );
            }
            let branch = if dual {
                if matches!(slot, 0 | 1) {
                    "dual-first"
                } else {
                    "dual-second"
                }
            } else {
                ""
            };
            let pre_roles = matches!(slot, 0 | 4);
            let snapshot = Path::new(branch).join(if pre_roles {
                "pre-exec-attempt.json"
            } else {
                "execution-observed-v1.json"
            });
            let snapshot = snapshot.to_string_lossy().into_owned();
            if pre_roles {
                let actual = directory.join(branch).join("attempt.json");
                let bytes =
                    crate::private_protected_readback::read_protected_raw_case_file(&actual)?;
                if crate::private_protected_readback::read_protected_raw_case_file(&actual)?
                    != bytes
                {
                    return fail("actual gated role journal changed while sampled");
                }
                state.source_leaves.insert(snapshot.clone(), bytes);
            }
            let bytes = state.source_leaves.get(&snapshot).ok_or_else(|| {
                CiError::Message("actual immutable journal snapshot absent at sampling gate".into())
            })?;
            let attempt: crate::private_protected_readback::ProtectedCandidateAttemptV1 =
                strict_json(bytes, 16 * 1024)?;
            if attempt.canonical_digest()? != *attempt.terminal_record_digest()
                || serde_json::to_vec(&attempt)? != *bytes
            {
                return fail("actual held-role journal snapshot digest differs");
            }
            let identities = attempt.terminal_processes().ok_or_else(|| {
                CiError::Message("actual execution journal process roles absent".into())
            })?;
            if identities[2].pid != sample.pid
                || identities[2].start_time != sample.start_time_ticks
            {
                return fail("actual execution journal target differs from baseline sample");
            }
            for (role, identity) in ["guardian", "namespace-init"].into_iter().zip(&identities) {
                let role = Path::new(branch).join(role).to_string_lossy().into_owned();
                if state.held_roles.contains_key(&role) {
                    continue;
                }
                let held = crate::private_public_live::sample_held_target_raw(
                    identity.pid,
                    identity.start_time,
                    expected_pre_image,
                )?;
                state.namespace_handles.push(
                    crate::private_public_live::hold_sampled_public_namespaces(&held)?,
                );
                state.held_roles.insert(role, held);
            }
            if let Some(frontend) = attempt.frontend_identity() {
                if !state.held_roles.contains_key("frontend") {
                    let held = crate::private_public_live::sample_held_target_raw(
                        frontend.pid,
                        frontend.start_time,
                        expected_pre_image,
                    )?;
                    state.held_roles.insert("frontend".into(), held);
                }
            }
        }
        // Re-read the immutable owner carrier and the live process after all
        // bounded samples. No ACK is published before these checks complete.
        if crate::private_protected_readback::read_protected_raw_case_file(&path)? != bytes {
            return fail("candidate gate changed while independently sampled");
        }
        let stat = std::fs::read_to_string(
            Path::new("/proc")
                .join(gate.target.pid.to_string())
                .join("stat"),
        )?;
        if crate::private_supervisor::parse_linux_child_stat(&stat, gate.target.pid)?
            .start_time_ticks
            != gate.target.start_time
        {
            return fail("candidate target was replaced while sampled");
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(ack))?;
        file.write_all(hash_bytes(&bytes).bytes())?;
        file.sync_all()?;
        std::fs::File::open(directory)?.sync_all()?;
        state.gates.insert(leaf.into(), bytes);
        match slot {
            0 => state.pre = Some(sample),
            4 => state.second_pre = Some(sample),
            5 => state.second_after_retirement = Some(sample),
            6 => state.release_intent = Some(sample),
            7 => state.second_release_intent = Some(sample),
            1 => state.baseline = Some(sample),
            2 => state.second_baseline = Some(sample),
            3 => state.post = Some(sample),
            _ => unreachable!(),
        }
    }
    Ok(state.pre.is_some() && state.post.is_some())
}

#[cfg(target_os = "linux")]
fn retain_candidate_journal_snapshots(
    directory: &Path,
    dual: bool,
    state: &mut CandidateLivePhasesV1,
) -> Result<()> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    #[derive(serde::Serialize)]
    struct ReopenedCheckpointMetadataV1 {
        schema_version: u8,
        file_dev: u64,
        file_inode: u64,
        directory_dev: u64,
        directory_inode: u64,
        observed_monotonic_ns: u64,
        bytes_sha256: DiagnosticSha256,
    }
    let branches: &[&str] = if dual {
        &["dual-first", "dual-second"]
    } else {
        &[""]
    };
    for branch in branches {
        let mut snapshot_leaves = vec![
            "checkpoint-committed-v1.json",
            "release-intent-v1.json",
            "execution-observed-v1.json",
        ];
        if branch.is_empty() {
            snapshot_leaves.extend([
                "terminal-join-midflight.json",
                "dual-first-midflight.json",
                "dual-second-midflight.json",
                "dual-second-post-retirement.json",
            ]);
        }
        for leaf in snapshot_leaves {
            let relative = Path::new(branch).join(leaf).to_string_lossy().into_owned();
            let path = directory.join(&relative);
            if state.source_leaves.contains_key(&relative) {
                if crate::private_protected_readback::read_protected_raw_case_file(&path)?
                    != state.source_leaves[&relative]
                {
                    return fail("immutable candidate journal snapshot changed");
                }
                continue;
            }
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            let parent = path
                .parent()
                .ok_or_else(|| CiError::Message("snapshot parent absent".into()))?;
            let held_parent = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
                .open(parent)?;
            let parent_meta = held_parent.metadata()?;
            if parent_meta.uid() != 0 || parent_meta.mode() & 0o077 != 0 {
                return fail("snapshot directory is not protected root custody");
            }
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            let before = file.metadata()?;
            if !before.is_file()
                || before.uid() != 0
                || before.mode() & 0o077 != 0
                || before.nlink() != 1
                || before.len() == 0
                || before.len() > 16 * 1024
            {
                return fail("snapshot file is not a bounded immutable root source");
            }
            let mut bytes = Vec::new();
            (&mut file).take(16 * 1024 + 1).read_to_end(&mut bytes)?;
            let after = file.metadata()?;
            let observed = memcordon_platform::test_support::private_observer_monotonic_ns()?;
            let reopened = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            let reopened_meta = reopened.metadata()?;
            let current_parent = std::fs::symlink_metadata(parent)?;
            if before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.len() != after.len()
                || before.len() != bytes.len() as u64
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.dev() != reopened_meta.dev()
                || before.ino() != reopened_meta.ino()
                || parent_meta.dev() != current_parent.dev()
                || parent_meta.ino() != current_parent.ino()
                || crate::private_protected_readback::read_protected_raw_case_file(&path)? != bytes
            {
                return fail("candidate journal source changed across held read/reopen");
            }
            let metadata = canonical_bytes(&ReopenedCheckpointMetadataV1 {
                schema_version: 1,
                file_dev: before.dev(),
                file_inode: before.ino(),
                directory_dev: parent_meta.dev(),
                directory_inode: parent_meta.ino(),
                observed_monotonic_ns: observed,
                bytes_sha256: hash_bytes(&bytes),
            })?;
            state.source_leaves.insert(relative.clone(), bytes);
            state
                .source_leaves
                .insert(format!("{relative}.metadata.json"), metadata);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn sample_candidate_phases_if_ready(
    _directory: &Path,
    _selector: &str,
    _target: &str,
    _challenge: &[u8; 32],
    _expected_pre_image: &DiagnosticSha256,
    _recipe: &ReviewedCandidateRecipeV1,
    _argv: &[String],
    _state: &mut CandidateLivePhasesV1,
) -> Result<bool> {
    fail("candidate phase sampling requires native Linux")
}
