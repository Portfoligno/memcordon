//! Append-only public observer production. The producer exports raw transport
//! bytes after authenticated sealing, never completed P or signing authority.
use crate::private_observer_session::{
    AuthenticatedCustodianTransportV1, AuthenticatedLiveObserverLeaseV1,
    AuthenticatedSealedLiveObserverSessionV1, ObservedGenerationV1, ObserverIntervalRecordV1,
    ObserverSessionDescriptorV1, ObserverStageV1,
};
use crate::private_public_plan::{
    PreparedPublicGenerationV1, StaticPublicSuiteIntentV1, prepare_public_generation,
};
use crate::private_public_raw::{
    ORIGIN_COMMITMENT, ORIGIN_RECEIPT, PAYLOAD_INDEX, PublicLeafKindV1, RawPublicEvidenceIndexV1,
    canonical_json, make_transport_index, validate_relative_evidence_path, write_public_archive,
};
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use std::collections::BTreeMap;
use std::io::{Seek, Write};

pub(crate) struct PublicObserverProducerV1 {
    transport: AuthenticatedCustodianTransportV1,
    lease: AuthenticatedLiveObserverLeaseV1,
    intent: StaticPublicSuiteIntentV1,
    next_chunk: u64,
    last_chunk: DiagnosticSha256,
    payload: BTreeMap<String, (PublicLeafKindV1, Vec<u8>)>,
    open_interval: Option<DiagnosticSha256>,
}

pub(crate) struct SealedPublicRawV1 {
    pub(crate) origin: AuthenticatedSealedLiveObserverSessionV1,
    index: RawPublicEvidenceIndexV1,
    leaves: BTreeMap<String, Vec<u8>>,
}

pub(crate) struct PreparedPublicCaseV1 {
    pub(crate) selector: String,
    pub(crate) challenge: [u8; 32],
    pub(crate) argv: Vec<String>,
    pub(crate) key: DiagnosticSha256,
    pub(crate) interval_id: crate::private_kernel_replay::IntervalIdV1,
    pub(crate) filter_sha256: DiagnosticSha256,
    pub(crate) filter_install_source_sha256: Option<DiagnosticSha256>,
    pub(crate) facility_source_sha256: Option<DiagnosticSha256>,
    pub(crate) host_preservation_source_sha256: Option<DiagnosticSha256>,
}
pub(crate) struct DetachedPublicIntervalV1 {
    pub(crate) interval: crate::private_kernel_observer::VerifiedKernelIntervalV1,
    pub(crate) controls_path: String,
    pub(crate) arm_monotonic_ns: u64,
    pub(crate) detach_monotonic_ns: u64,
    pub(crate) host_sources: Option<Vec<u8>>,
}

/// Enroll before either controls or product execution. Control output,
/// original clock and original physical capture close durably before GO for
/// the product interval. The returned interval remains open in custody until
/// its actual case sources are appended and `retain_interval` closes it.
#[cfg(unix)]
pub(crate) fn run_public_journal_interval<T>(
    journal: &mut PublicObserverProducerV1,
    probe: &crate::private_probe_bundle::VerifiedProbeBundleV1,
    case: &PreparedPublicCaseV1,
    mut control_expected: crate::private_kernel_observer::ExpectedKernelAdapterV1,
    mut product_expected: crate::private_kernel_observer::ExpectedKernelAdapterV1,
    operation: impl FnOnce(&mut PublicObserverProducerV1) -> Result<T>,
) -> Result<(T, DetachedPublicIntervalV1)> {
    let mut control_id = case.interval_id.clone();
    control_id.purpose = crate::private_kernel_replay::IntervalPurposeV1::KnownControls;
    let control = PreparedPublicCaseV1 {
        selector: case.selector.clone(),
        challenge: case.challenge,
        argv: case.argv.clone(),
        key: case.key.clone(),
        interval_id: control_id,
        filter_sha256: case.filter_sha256.clone(),
        filter_install_source_sha256: case.filter_install_source_sha256.clone(),
        facility_source_sha256: case.facility_source_sha256.clone(),
        host_preservation_source_sha256: case.host_preservation_source_sha256.clone(),
    };
    control_expected.result_key = control.key.clone();
    product_expected.result_key = case.key.clone();
    journal.begin_interval(control.interval_id.storage_sha256())?;
    let controls = crate::private_probe_controls::run_fixed_known_action_controls_with_stage(
        probe,
        control_expected,
        control.interval_id.clone(),
        crate::private_kernel_replay::CaptureStageV2::FinalPublic,
    )?;
    let prefix = std::path::Path::new("observer")
        .join("intervals")
        .join(String::from(control.interval_id.storage_sha256()));
    let output_path = prefix
        .join("control-output.stream")
        .to_string_lossy()
        .into_owned();
    let mut output = (controls.command_output().len() as u64)
        .to_be_bytes()
        .to_vec();
    output.extend_from_slice(controls.command_output());
    journal.append(output_path.clone(), PublicLeafKindV1::Control, output)?;
    let control_path = prefix.join("capture.bin").to_string_lossy().into_owned();
    let timing = controls
        .interval()
        .observation_timing()
        .ok_or_else(|| CiError::Message("public controls original timing absent".into()))?;
    journal.retain_interval(
        &control,
        controls.interval(),
        vec![control_path.clone()],
        vec![output_path],
        timing.armed_monotonic_ns,
        timing.operation_end_monotonic_ns,
        timing.detached_monotonic_ns,
    )?;
    journal.begin_interval(case.interval_id.storage_sha256())?;
    let filter_sources = journal
        .intent
        .scenarios
        .iter()
        .find(|scenario| scenario.selector == case.selector)
        .is_some_and(|scenario| {
            scenario.recipe.filter_install_source_sha256.is_some()
                || scenario.recipe.facility_source_sha256.is_some()
        });
    let mut observed = None;
    let host_watch = if let Some(revision) = &case.host_preservation_source_sha256 {
        if revision
            != &crate::private_candidate_host_facts::host_preservation_source_revision_sha256()
        {
            return Err(CiError::Message(
                "public host continuity source revision not approved".into(),
            ));
        }
        Some(memcordon_platform::test_support::HostNetworkWatchV1::start()?)
    } else {
        None
    };
    let invoke = || {
        observed = Some(operation(journal)?);
        Ok(())
    };
    let interval = if let Some(watch) = &host_watch {
        crate::private_kernel_observer::run_probe_interval_raw_with_host_sources(
            probe,
            product_expected,
            controls.controls(),
            case.interval_id.clone(),
            crate::private_kernel_replay::CaptureStageV2::FinalPublic,
            filter_sources,
            watch.object_pins(),
            invoke,
        )?
    } else if filter_sources {
        crate::private_kernel_observer::run_probe_interval_raw_with_filter_sources(
            probe,
            product_expected,
            controls.controls(),
            case.interval_id.clone(),
            crate::private_kernel_replay::CaptureStageV2::FinalPublic,
            invoke,
        )?
    } else if matches!(
        case.interval_id.purpose,
        crate::private_kernel_replay::IntervalPurposeV1::DualContinuous
            | crate::private_kernel_replay::IntervalPurposeV1::ReuseFirst
            | crate::private_kernel_replay::IntervalPurposeV1::ReuseBlocked
            | crate::private_kernel_replay::IntervalPurposeV1::Recovery
    ) {
        crate::private_kernel_observer::run_probe_interval_raw_with_stage(
            probe,
            product_expected,
            controls.controls(),
            case.interval_id.clone(),
            crate::private_kernel_replay::CaptureStageV2::FinalPublic,
            invoke,
        )?
    } else {
        crate::private_kernel_observer::run_probe_interval_with_stage(
            probe,
            product_expected,
            Some(controls.controls()),
            case.interval_id.clone(),
            crate::private_kernel_replay::CaptureStageV2::FinalPublic,
            invoke,
        )?
    };
    let timing = interval
        .observation_timing()
        .ok_or_else(|| CiError::Message("public product original timing absent".into()))?;
    let arm_monotonic_ns = timing.armed_monotonic_ns;
    let detach_monotonic_ns = timing.detached_monotonic_ns;
    let observed = observed
        .ok_or_else(|| CiError::Message("public enrolled operation was not invoked".into()))?;
    let host_sources = host_watch
        .map(|watch| -> Result<Vec<u8>> {
            Ok(crate::private_source_carrier::encode_source_carrier(
                &watch.finish()?,
            )?)
        })
        .transpose()?;
    Ok((
        observed,
        DetachedPublicIntervalV1 {
            interval,
            controls_path: control_path,
            arm_monotonic_ns,
            detach_monotonic_ns,
            host_sources,
        },
    ))
}
impl SealedPublicRawV1 {
    pub(crate) fn export<W: Write + Seek>(&self, writer: W) -> Result<W> {
        write_public_archive(writer, &self.index, &self.leaves)
    }
    /// Upload the literal leaves, not a nested ZIP. The platform's immutable
    /// artifact ZIP is the W archive verified by the completed collector.
    #[cfg(target_os = "linux")]
    pub(crate) fn export_files(&self, directory: &std::path::Path) -> Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if std::fs::symlink_metadata(directory).is_ok() {
            return Err(CiError::Message(
                "public export directory already exists".into(),
            ));
        }
        let transport = self.index.canonical_bytes()?;
        let declared = self
            .index
            .leaves
            .iter()
            .map(|leaf| leaf.path.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if self
            .leaves
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != declared
            || self.index.leaves.iter().any(|leaf| {
                self.leaves.get(&leaf.path).is_none_or(|bytes| {
                    bytes.len() as u64 != leaf.size || hash_bytes(bytes) != leaf.sha256
                })
            })
        {
            return Err(CiError::Message(
                "public literal export inventory or original bytes differ".into(),
            ));
        }
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))?;
        for (path, bytes) in self
            .leaves
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
            .chain(std::iter::once((
                crate::private_public_raw::TRANSPORT_INDEX,
                transport.as_slice(),
            )))
        {
            validate_relative_evidence_path(path)?;
            let output = directory.join(path);
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&output)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        std::fs::File::open(directory)?.sync_all()?;
        Ok(())
    }
}

impl PublicObserverProducerV1 {
    pub(crate) fn begin(
        intent: StaticPublicSuiteIntentV1,
        descriptor: ObserverSessionDescriptorV1,
        mut transport: AuthenticatedCustodianTransportV1,
    ) -> Result<Self> {
        intent.validate()?;
        if descriptor.subject != intent.observer_subject
            || descriptor.subject.stage != ObserverStageV1::Public
            || descriptor.generations.len() != 1
            || descriptor.generations[0].generation != 0
            || descriptor.generations[0].installed_manifest_sha256 != intent.manifest_sha256
            || !descriptor.intervals.is_empty()
        {
            return Err(CiError::Message(
                "public producer initial live descriptor differs from static admission".into(),
            ));
        }
        let lease = transport.begin_live_observed(descriptor)?;
        let last_chunk = hash_bytes(&crate::private_observer_session::canonical_bytes(
            lease.descriptor(),
        )?);
        Ok(Self {
            transport,
            lease,
            intent,
            next_chunk: 0,
            last_chunk,
            payload: BTreeMap::new(),
            open_interval: None,
        })
    }
    pub(crate) fn observe_generation(
        &mut self,
        generation: ObservedGenerationV1,
    ) -> Result<PreparedPublicGenerationV1> {
        if self.open_interval.is_some()
            || generation.installed_manifest_sha256 != self.intent.manifest_sha256
        {
            return Err(CiError::Message(
                "public generation changed A/M1 or crosses a live interval".into(),
            ));
        }
        let number = generation.generation;
        let readback = self.transport.observe_generation(&self.lease, generation)?;
        if readback.next_chunk != self.next_chunk
            || readback.last_chunk_sha256 != self.last_chunk
            || readback.descriptor.subject != self.intent.observer_subject
        {
            return Err(CiError::Message(
                "custodian generation ack changed payload continuity".into(),
            ));
        }
        self.lease = self.transport.begin_live(&self.intent.observer_subject)?;
        prepare_public_generation(&self.intent, &self.lease, number)
    }
    pub(crate) fn descriptor(&self) -> &ObserverSessionDescriptorV1 {
        self.lease.descriptor()
    }
    pub(crate) fn current_generation(&self) -> Result<PreparedPublicGenerationV1> {
        let number = self
            .descriptor()
            .generations
            .last()
            .ok_or_else(|| CiError::Message("public actual H1 generation absent".into()))?
            .generation;
        prepare_public_generation(&self.intent, &self.lease, number)
    }
    pub(crate) fn prepare_case(
        &self,
        selector: &str,
        purpose: crate::private_kernel_replay::IntervalPurposeV1,
        ordinal: u32,
    ) -> Result<PreparedPublicCaseV1> {
        let generation = self.descriptor().generations.last().ok_or_else(|| {
            CiError::Message("public prepare requires observed H1 generation".into())
        })?;
        let (mut challenge, mut argv) = crate::private_public_plan::prepared_public_case_recipe_v1(
            &self.intent,
            &self.descriptor().session_nonce,
            generation.generation,
            selector,
        )?;
        if purpose == crate::private_kernel_replay::IntervalPurposeV1::Policy {
            if selector
                != memcordon_core::private_public_policy_composite_v1::PUBLIC_POLICY_SELECTOR_V1
            {
                return Err(CiError::Message(
                    "public policy physical selector differs".into(),
                ));
            }
            let branch = memcordon_core::private_release_branch_v1::PolicyOperationBranchV1::ALL
                .get(ordinal as usize)
                .ok_or_else(|| CiError::Message("public policy branch ordinal differs".into()))?;
            let old = hex::encode(challenge);
            challenge = memcordon_core::private_release_branch_v1::policy_branch_challenge_v1(
                &challenge, *branch,
            )
            .map_err(|error| CiError::Message(error.into()))?;
            let slot = argv
                .iter()
                .position(|arg| arg == "--challenge")
                .ok_or_else(|| CiError::Message("public policy argv challenge absent".into()))?;
            if argv.get(slot + 1) != Some(&old) {
                return Err(CiError::Message("public policy parent argv differs".into()));
            }
            argv[slot + 1] = hex::encode(challenge);
        } else if purpose == crate::private_kernel_replay::IntervalPurposeV1::CallerSpoof {
            if selector != "private_tcp::caller_identity_and_epoch_bound" {
                return Err(CiError::Message(
                    "public spoof physical selector differs".into(),
                ));
            }
            let old = hex::encode(challenge);
            challenge = crate::private_public_plan::prepared_public_spoof_challenge_v1(
                &self.intent,
                &self.descriptor().session_nonce,
                generation.generation,
            )?;
            let slots = argv
                .iter()
                .enumerate()
                .filter_map(|(index, arg)| (arg == "--challenge").then_some(index))
                .collect::<Vec<_>>();
            let [slot] = slots.as_slice() else {
                return Err(CiError::Message(
                    "public spoof exact argv slot differs".into(),
                ));
            };
            if argv.get(slot + 1) != Some(&old) {
                return Err(CiError::Message(
                    "public spoof parent argv recipe differs".into(),
                ));
            }
            argv[slot + 1] = hex::encode(challenge);
        }
        let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
            memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
            selector,
            &challenge,
        )
        .map_err(CiError::Message)?;
        let session_nonce = hex::decode(&self.descriptor().session_nonce)
            .map_err(|_| CiError::Message("public custodian nonce differs".into()))?
            .try_into()
            .map_err(|_| CiError::Message("public custodian nonce size differs".into()))?;
        Ok(PreparedPublicCaseV1 {
            selector: selector.into(),
            challenge,
            argv,
            key: key.clone(),
            filter_sha256: self
                .intent
                .scenarios
                .iter()
                .find(|scenario| scenario.selector == selector)
                .expect("validated prepared selector")
                .recipe
                .filter_sha256
                .clone(),
            filter_install_source_sha256: self
                .intent
                .scenarios
                .iter()
                .find(|scenario| scenario.selector == selector)
                .expect("validated prepared selector")
                .recipe
                .filter_install_source_sha256
                .clone(),
            facility_source_sha256: self
                .intent
                .scenarios
                .iter()
                .find(|scenario| scenario.selector == selector)
                .expect("validated prepared selector")
                .recipe
                .facility_source_sha256
                .clone(),
            host_preservation_source_sha256: self
                .intent
                .scenarios
                .iter()
                .find(|scenario| scenario.selector == selector)
                .expect("validated prepared selector")
                .recipe
                .host_preservation_source_sha256
                .clone(),
            interval_id: crate::private_kernel_replay::IntervalIdV1 {
                session_nonce,
                generation: generation.generation,
                logical_case_key: key,
                purpose,
                ordinal,
            },
        })
    }

    pub(crate) fn retain_interval(
        &mut self,
        case: &PreparedPublicCaseV1,
        interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
        controls_paths: Vec<String>,
        sample_paths: Vec<String>,
        arm_ns: u64,
        observation_end_ns: u64,
        detach_ns: u64,
    ) -> Result<()> {
        self.retain_interval_with_record(
            case,
            interval,
            controls_paths,
            sample_paths,
            arm_ns,
            observation_end_ns,
            detach_ns,
            None,
        )
    }
    pub(crate) fn retain_interval_with_record(
        &mut self,
        case: &PreparedPublicCaseV1,
        interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
        controls_paths: Vec<String>,
        mut sample_paths: Vec<String>,
        arm_ns: u64,
        observation_end_ns: u64,
        detach_ns: u64,
        record_path: Option<String>,
    ) -> Result<()> {
        let id = case.interval_id.storage_sha256();
        if interval.physical_interval_id() != Some(&case.interval_id)
            || interval.result_key() != &case.key
        {
            return Err(CiError::Message(
                "public native capture was not armed with the admitted physical interval".into(),
            ));
        }
        let capture = interval.capture_bytes()?;
        let parsed = crate::private_kernel_replay::parse_capture_v2_with_budget(
            capture,
            &case.key,
            crate::private_kernel_replay::CaptureStageV2::FinalPublic,
        )?;
        let first = parsed
            .events()
            .first()
            .ok_or_else(|| CiError::Message("public native capture has no first event".into()))?;
        let last = parsed
            .events()
            .last()
            .ok_or_else(|| CiError::Message("public native capture has no last event".into()))?;
        let timing = interval.observation_timing().ok_or_else(|| {
            CiError::Message("public native original observation timing absent".into())
        })?;
        if arm_ns != timing.armed_monotonic_ns
            || observation_end_ns != timing.operation_end_monotonic_ns
            || detach_ns != timing.detached_monotonic_ns
        {
            return Err(CiError::Message(
                "public supplied interval timing differs from actual native endpoints".into(),
            ));
        }
        let prefix = std::path::Path::new("observer")
            .join("intervals")
            .join(String::from(id.clone()));
        let path = |name: &str| prefix.join(name).to_string_lossy().into_owned();
        let capture_path = path("capture.bin");
        let clock_path = path("clock.json");
        self.append(
            capture_path.clone(),
            PublicLeafKindV1::Capture,
            capture.to_vec(),
        )?;
        self.append(
            clock_path.clone(),
            PublicLeafKindV1::LiveSample,
            crate::private_observer_session::canonical_bytes(interval.clock_inputs().ok_or_else(
                || CiError::Message("public native capture original clock inputs absent".into()),
            )?)?,
        )?;
        sample_paths.push(clock_path);
        let metadata_path = path("kernel-metadata.json");
        self.append(
            metadata_path.clone(),
            PublicLeafKindV1::LiveSample,
            crate::private_observer_session::canonical_bytes(&interval.replay_metadata())?,
        )?;
        sample_paths.push(metadata_path);
        if let Some(stderr) = interval.loader_stderr() {
            let mut bytes = (stderr.len() as u64).to_be_bytes().to_vec();
            bytes.extend_from_slice(stderr);
            let stderr_path = path("loader-stderr.stream");
            self.append(stderr_path.clone(), PublicLeafKindV1::Stdio, bytes)?;
            sample_paths.push(stderr_path);
        }
        sample_paths.sort();
        sample_paths.dedup();
        let purpose = match case.interval_id.purpose {
            crate::private_kernel_replay::IntervalPurposeV1::KnownControls => "known-controls",
            crate::private_kernel_replay::IntervalPurposeV1::Ordinary => "ordinary",
            crate::private_kernel_replay::IntervalPurposeV1::AbiOuter => "abi-outer",
            crate::private_kernel_replay::IntervalPurposeV1::AbiFiltered => "abi-filtered",
            crate::private_kernel_replay::IntervalPurposeV1::Historical => "historical",
            crate::private_kernel_replay::IntervalPurposeV1::CallerSpoof => "caller-spoof",
            crate::private_kernel_replay::IntervalPurposeV1::Policy => "policy",
            crate::private_kernel_replay::IntervalPurposeV1::ReuseFirst => "reuse-first",
            crate::private_kernel_replay::IntervalPurposeV1::ReuseBlocked => "reuse-blocked",
            crate::private_kernel_replay::IntervalPurposeV1::Recovery => "recovery",
            crate::private_kernel_replay::IntervalPurposeV1::DualContinuous => "dual-continuous",
            crate::private_kernel_replay::IntervalPurposeV1::FacilityControls => {
                "facility-controls"
            }
        };
        let record = ObserverIntervalRecordV1 {
            interval_id: id,
            logical_case_key: case.key.clone(),
            generation: case.interval_id.generation,
            purpose: purpose.into(),
            ordinal: case.interval_id.ordinal,
            capture_path,
            capture_sha256: parsed.digest().clone(),
            controls_paths,
            sample_paths,
            arm_monotonic_ns: arm_ns,
            begin_monotonic_ns: timing.operation_begin_monotonic_ns,
            end_monotonic_ns: observation_end_ns,
            detach_monotonic_ns: detach_ns,
            loss_count: 0,
            first_sequence: first.sequence,
            last_sequence: last.sequence,
        };
        if let Some(path) = record_path {
            self.append(
                path,
                PublicLeafKindV1::LiveSample,
                crate::private_observer_session::canonical_bytes(&record)?,
            )?;
        }
        self.close_interval(record)
    }
    pub(crate) fn begin_interval(&mut self, id: DiagnosticSha256) -> Result<()> {
        if self.open_interval.is_some() {
            return Err(CiError::Message("public custody intervals overlap".into()));
        }
        let readback = self.transport.begin_interval(&self.lease, id.clone())?;
        if readback.next_chunk != self.next_chunk || readback.last_chunk_sha256 != self.last_chunk {
            return Err(CiError::Message(
                "public interval ack changed payload continuity".into(),
            ));
        }
        self.open_interval = Some(id);
        Ok(())
    }
    pub(crate) fn append(
        &mut self,
        path: String,
        kind: PublicLeafKindV1,
        bytes: Vec<u8>,
    ) -> Result<()> {
        self.append_phase(path, kind, bytes, false)
    }
    /// Derived transport representations cannot add a physical interval or
    /// confer origin authority. The controller admits a closed path inventory
    /// only after the genuine source intervals have been durably closed.
    pub(crate) fn append_representation(
        &mut self,
        path: String,
        kind: PublicLeafKindV1,
        bytes: Vec<u8>,
    ) -> Result<()> {
        self.append_phase(path, kind, bytes, true)
    }
    pub(crate) fn acknowledged_leaf(&self, path: &str) -> Result<&[u8]> {
        self.payload
            .get(path)
            .map(|(_, bytes)| bytes.as_slice())
            .ok_or_else(|| CiError::Message("public acknowledged source leaf absent".into()))
    }
    pub(crate) fn observed_cleanup_inventory(&self) -> Result<DiagnosticSha256> {
        let sources = self
            .payload
            .iter()
            .filter(|(path, _)| {
                path.ends_with("/cgroup-retirement-v1.json")
                    || path.ends_with("/namespace-closes.json")
                    || path.ends_with("/cleanup.bin")
            })
            .map(|(path, (_, bytes))| (path.clone(), hash_bytes(bytes)))
            .collect::<BTreeMap<_, _>>();
        if sources.is_empty() {
            return Err(CiError::Message(
                "public observed cleanup source inventory absent".into(),
            ));
        }
        Ok(hash_bytes(
            &crate::private_observer_session::canonical_bytes(&sources)?,
        ))
    }
    fn append_phase(
        &mut self,
        path: String,
        kind: PublicLeafKindV1,
        bytes: Vec<u8>,
        representation: bool,
    ) -> Result<()> {
        validate_relative_evidence_path(&path)?;
        if self.open_interval.is_none() != representation
            || self.payload.contains_key(&path)
            || bytes.is_empty()
                && !matches!(path.rsplit('/').next(), Some("stdout.raw" | "stderr.raw"))
        {
            return Err(CiError::Message(
                "public raw append is outside its physical interval or duplicated".into(),
            ));
        }
        let readback = if representation {
            self.transport.append_representation(
                &self.lease,
                self.next_chunk,
                self.last_chunk.clone(),
                path.clone(),
                bytes.clone(),
            )?
        } else {
            self.transport.append(
                &self.lease,
                self.next_chunk,
                self.last_chunk.clone(),
                path.clone(),
                bytes.clone(),
            )?
        };
        let mut record = b"memcordon/observer-append/v1\0".to_vec();
        record.extend_from_slice(self.last_chunk.bytes());
        record.extend_from_slice(&self.next_chunk.to_be_bytes());
        record.extend_from_slice(&(path.len() as u64).to_be_bytes());
        record.extend_from_slice(path.as_bytes());
        record.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        record.extend_from_slice(hash_bytes(&bytes).bytes());
        let next = self
            .next_chunk
            .checked_add(1)
            .ok_or_else(|| CiError::Message("public append ordinal overflow".into()))?;
        let chain = hash_bytes(&record);
        if readback.next_chunk != next
            || readback.last_chunk_sha256 != chain
            || readback.descriptor.subject != self.intent.observer_subject
        {
            return Err(CiError::Message(
                "custodian durable append acknowledgment differs".into(),
            ));
        }
        self.payload.insert(path, (kind, bytes));
        self.next_chunk = next;
        self.last_chunk = chain;
        Ok(())
    }
    pub(crate) fn close_interval(&mut self, record: ObserverIntervalRecordV1) -> Result<()> {
        if self.open_interval.as_ref() != Some(&record.interval_id) {
            return Err(CiError::Message(
                "public physical interval close identity differs".into(),
            ));
        }
        let readback = self.transport.close_interval(&self.lease, record)?;
        if readback.next_chunk != self.next_chunk || readback.last_chunk_sha256 != self.last_chunk {
            return Err(CiError::Message(
                "public interval close changed durable append continuity".into(),
            ));
        }
        self.open_interval = None;
        self.lease = self.transport.begin_live(&self.intent.observer_subject)?;
        Ok(())
    }
    pub(crate) fn seal(
        self,
        cleanup_inventory_sha256: DiagnosticSha256,
        sealed_ns: u64,
    ) -> Result<SealedPublicRawV1> {
        if self.open_interval.is_some() {
            return Err(CiError::Message(
                "public export has an unclosed physical interval".into(),
            ));
        }
        let mut transport = self.transport;
        let payload = self
            .payload
            .iter()
            .map(|(path, (_, bytes))| (path.clone(), bytes.clone()))
            .collect();
        let (origin, readback) = transport.seal_and_authenticate(
            self.lease,
            payload,
            cleanup_inventory_sha256,
            sealed_ns,
        )?;
        let index: crate::private_observer_session::ObserverPayloadIndexV1 =
            crate::private_observer_session::strict_json(
                &readback.payload_index,
                16 * 1024 * 1024,
            )?;
        let transport_index = make_transport_index(
            &index,
            &self.payload,
            &readback.payload_index,
            &readback.origin_commitment,
            &readback.origin_receipt,
        )?;
        let mut leaves = self
            .payload
            .into_iter()
            .map(|(path, (_, bytes))| (path, bytes))
            .collect::<BTreeMap<_, _>>();
        leaves.insert(PAYLOAD_INDEX.into(), readback.payload_index);
        leaves.insert(ORIGIN_COMMITMENT.into(), readback.origin_commitment);
        leaves.insert(ORIGIN_RECEIPT.into(), readback.origin_receipt);
        // The W writer regenerates exact canonical bytes and rejects any
        // undeclared extra file, including a circular P/CP inside origin I.
        canonical_json(&transport_index)?;
        Ok(SealedPublicRawV1 {
            origin,
            index: transport_index,
            leaves,
        })
    }
}
