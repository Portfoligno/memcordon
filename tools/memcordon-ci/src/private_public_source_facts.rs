//! Source-only public fixture decoding. No parser in this module grants
//! observer origin or a completed semantic capability.
use crate::{CiError, Result};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::Deserialize;

pub use crate::private_public_fault_dual_replay::validate_public_checkpoint_capture;

const HELD_MAGIC: &[u8] = b"MCPH\x01\0\0\0";
const MAX_HELD_BYTES: usize = 64 * 1024;
const EXEC_MAGIC: &[u8] = b"MCEX\x01\0\0\0";

/// Compare stable process credentials/filter predicates while retaining each
/// original status byte stream. Scheduling and memory counters may change
/// during an authentic held observation and are not identity predicates.
pub fn validate_public_facility_status_join(gate: &[u8], held: &[u8]) -> Result<()> {
    crate::private_candidate_facility_replay::validate_facility_status_join(gate, held)?;
    let values = |raw: &[u8], field: &str, radix: u32| -> Result<Vec<u64>> {
        let text = std::str::from_utf8(raw)
            .map_err(|_| CiError::Message("Facility original status is not UTF-8".into()))?;
        let rows = text
            .lines()
            .filter_map(|line| line.strip_prefix(field))
            .collect::<Vec<_>>();
        let [row] = rows.as_slice() else {
            return fail("Facility original status predicate absent or duplicated");
        };
        row.split_whitespace()
            .map(|value| {
                u64::from_str_radix(value, radix).map_err(|_| {
                    CiError::Message("Facility original status predicate differs".into())
                })
            })
            .collect()
    };
    for (field, width, radix) in [
        ("Pid:", 1, 10),
        ("Tgid:", 1, 10),
        ("Uid:", 4, 10),
        ("Gid:", 4, 10),
        ("NoNewPrivs:", 1, 10),
        ("Seccomp:", 1, 10),
        ("Seccomp_filters:", 1, 10),
        ("CapInh:", 1, 16),
        ("CapPrm:", 1, 16),
        ("CapEff:", 1, 16),
        ("CapBnd:", 1, 16),
        ("CapAmb:", 1, 16),
    ] {
        let gate_values = values(gate, field, radix)?;
        let held_values = values(held, field, radix)?;
        if gate_values.len() != width || gate_values != held_values {
            return fail("Facility held original credentials/filter identity changed");
        }
    }
    if values(gate, "Groups:", 10)? != values(held, "Groups:", 10)? {
        return fail("Facility held original supplementary groups changed");
    }
    Ok(())
}

pub fn uses_public_exec_response_frame(selector: &str) -> bool {
    matches!(
        selector,
        "private_tcp::af_unix_abstract_and_pathname_denied"
            | "private_tcp::child_runtime_and_threads_retired"
            | "private_tcp::release_checkpoint_terminal_joined"
    )
}

/// A live snapshot may be incomplete. Once complete, retain the target's
/// emitted response bytes separately from its unchanged operation protocol.
pub fn decode_public_exec_response_frame<'a>(
    selector: &str,
    challenge: &[u8; 32],
    bytes: &'a [u8],
) -> Result<Option<(&'a [u8], &'a [u8])>> {
    if !uses_public_exec_response_frame(selector) {
        return fail("public exec response frame selector differs");
    }
    if bytes.len() < EXEC_MAGIC.len() {
        return Ok(None);
    }
    let raw = bytes
        .strip_prefix(EXEC_MAGIC)
        .ok_or_else(|| CiError::Message("public emitted exec response magic differs".into()))?;
    let expected = memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
        selector, challenge, 0,
    )
    .map_err(|error| CiError::Message(error.into()))?;
    let Some(response) = raw.get(..expected.len()) else {
        return Ok(None);
    };
    if response != expected {
        return fail("public emitted exec response recipe differs");
    }
    Ok(Some((response, &raw[expected.len()..])))
}

/// Decode exactly one complete fixture frame, not a prefix of a live stream.
pub fn decode_public_held_payload(bytes: &[u8]) -> Result<&[u8]> {
    let raw = bytes
        .strip_prefix(HELD_MAGIC)
        .ok_or_else(|| CiError::Message("public source held fixture magic differs".into()))?;
    let width = std::mem::size_of::<u32>();
    let length = u32::from_le_bytes(
        raw.get(..width)
            .ok_or_else(|| CiError::Message("public source held length truncated".into()))?
            .try_into()
            .expect("bounded u32"),
    ) as usize;
    let payload = &raw[width..];
    if length == 0 || length > MAX_HELD_BYTES || payload.len() != length {
        return fail("public source held frame is incomplete, concatenated or oversized");
    }
    Ok(payload)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TcpResponseSourceV2 {
    schema_version: u8,
    network_namespace_inode: u64,
    listener_port: u16,
    client_port: u16,
    challenge_sha256: DiagnosticSha256,
    response_sha256: DiagnosticSha256,
    observed_response_bytes: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TopologyResponseSourceV3 {
    schema_version: u8,
    tcp: TcpResponseSourceV2,
    namespace_reentry_errno: Option<i32>,
    namespace_creation_errno: Option<i32>,
    namespace_operand: Option<NamespaceOperandSourceV3>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceOperandSourceV3 {
    descriptor: i32,
    device: u64,
    inode: u64,
}

fn topology_response(selector: &str, payload: &[u8]) -> Result<TopologyResponseSourceV3> {
    let source: TopologyResponseSourceV3 =
        crate::private_observer_session::strict_json(payload, MAX_HELD_BYTES)?;
    let reentry = selector == "private_tcp::namespace_reentry_denied";
    if source.schema_version != 3
        || !matches!(
            selector,
            "private_tcp::namespace_reentry_denied"
                | "private_tcp::private_namespace_topology_exact"
        )
        || if reentry {
            source.namespace_reentry_errno != Some(1)
                || source.namespace_creation_errno != Some(1)
                || source.namespace_operand.as_ref().is_none_or(|operand| {
                    operand.descriptor <= 2 || operand.device == 0 || operand.inode == 0
                })
        } else {
            source.namespace_reentry_errno.is_some()
                || source.namespace_creation_errno.is_some()
                || source.namespace_operand.is_some()
        }
    {
        return fail("public topology actual response source role/operands differ");
    }
    Ok(source)
}

fn validate_tcp_response(
    source: &TcpResponseSourceV2,
    challenge: &[u8; 32],
    port: u16,
) -> Result<()> {
    if source.schema_version != 2
        || source.network_namespace_inode == 0
        || source.listener_port != port
        || port == 0
        || source.client_port == 0
        || source.client_port == port
        || source.challenge_sha256 != hash_bytes(challenge)
        || source.response_sha256.bytes() != &source.observed_response_bytes
    {
        return fail("public TCP actual-read source recipe differs");
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CollisionResponseSourceV2 {
    schema_version: u8,
    network_namespace_inode: u64,
    bound_port: u16,
    challenge_sha256: DiagnosticSha256,
    collision_os_code: i32,
    observed_response_bytes: [u8; 32],
}

/// Retain only bytes actually emitted in the fixture payload. In particular
/// schema-1 TCP summaries contain no raw response and cannot be upgraded by
/// copying a challenge or computing the expected response in the collector.
pub fn extract_public_fixture_response(
    selector: &str,
    challenge: &[u8; 32],
    port: u16,
    frame: &[u8],
) -> Result<[u8; 32]> {
    if uses_public_exec_response_frame(selector) {
        let (response, operations) = decode_public_exec_response_frame(selector, challenge, frame)?
            .ok_or_else(|| CiError::Message("public emitted exec response incomplete".into()))?;
        if operations.is_empty() {
            return fail("public emitted exec response lacks original operation protocol");
        }
        return Ok(response.try_into().expect("bounded response"));
    }
    let payload = decode_public_held_payload(frame)?;
    let expected = memcordon_core::private_release_case_v1::public_fixture_expected_response_v1(
        selector, challenge, port,
    )
    .map_err(|error| CiError::Message(error.into()))?;
    let observed = match selector {
        "private_tcp::namespace_reentry_denied"
        | "private_tcp::private_namespace_topology_exact" => {
            let source = topology_response(selector, payload)?;
            validate_tcp_response(&source.tcp, challenge, port)?;
            source.tcp.observed_response_bytes
        }
        "private_tcp::native_tcp_bind_listen_connect"
        | "private_tcp::dual_attempt_namespace_isolation"
        | "private_tcp::frontend_loss_retired"
        | "private_tcp::guardian_loss_retired" => {
            let source: TcpResponseSourceV2 =
                crate::private_observer_session::strict_json(payload, MAX_HELD_BYTES)?;
            validate_tcp_response(&source, challenge, port)?;
            source.observed_response_bytes
        }
        "private_tcp::port_collision_same_namespace" => {
            let source: CollisionResponseSourceV2 =
                crate::private_observer_session::strict_json(payload, MAX_HELD_BYTES)?;
            if source.schema_version != 2
                || source.network_namespace_inode == 0
                || source.bound_port != port
                || port == 0
                || source.challenge_sha256 != hash_bytes(challenge)
                || source.collision_os_code != 98
            {
                return fail("public collision actual-read source recipe differs");
            }
            source.observed_response_bytes
        }
        _ => payload
            .get(..expected.len())
            .ok_or_else(|| CiError::Message("public source emitted response truncated".into()))?
            .try_into()
            .expect("bounded response"),
    };
    if observed != expected {
        return fail("public source emitted response differs from independent fixture recipe");
    }
    Ok(observed)
}

pub(crate) fn record_public_common_sources(
    intent: &crate::private_public_plan::StaticPublicSuiteIntentV1,
    descriptor: &crate::private_observer_session::ObserverSessionDescriptorV1,
    prepared_admission: &[u8],
    case: &crate::private_public_producer::PreparedPublicCaseV1,
    prefix: &std::path::Path,
    target: &str,
    port: u16,
    observed: &crate::private_public_dispatch::ObservedInstalledPublicCaseV3,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
    provider_record: &[u8],
    provider_leaves: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<Vec<(String, crate::private_public_raw::PublicLeafKindV1, Vec<u8>)>> {
    if case.selector == "private_tcp::authorization_uncertainty_retired" {
        return record_public_pre_exec_fault_sources(
            case,
            prefix,
            observed,
            interval,
            provider_record,
            provider_leaves,
        );
    }
    use crate::private_public_raw::PublicLeafKindV1 as Kind;
    let samples_prefix = prefix.join("samples");
    let sample = |name: &str| -> Result<crate::private_public_live::HeldPublicTargetSamplesV1> {
        let bytes = observed
            .live_samples
            .get(name)
            .ok_or_else(|| CiError::Message("public common actual held source absent".into()))?;
        crate::private_source_carrier::decode_held_source(bytes, |origin_path| {
            let suffix = std::path::Path::new(origin_path)
                .strip_prefix(&samples_prefix)
                .map_err(|_| {
                    CiError::Message("public held image maps outside case origin".into())
                })?;
            observed
                .live_samples
                .get(suffix.to_string_lossy().as_ref())
                .cloned()
                .ok_or_else(|| {
                    CiError::Message("public held image original raw bytes absent".into())
                })
        })
    };
    let dual = case.selector == "private_tcp::dual_attempt_namespace_isolation";
    let baseline_name = if dual {
        "dual-first-baseline/target-live-sample-v1.json"
    } else {
        "baseline/target-live-sample-v1.json"
    };
    let baseline_root = if dual {
        "dual-first-baseline/target-live"
    } else {
        "baseline/target-live"
    };
    let before = sample("pre-exec/target-live-sample-v1.json")?;
    let baseline = sample(baseline_name)?;
    let frame = observed
        .live_samples
        .get(if dual {
            "dual-first-overlap/target-response-at-held-gate.bin"
        } else {
            "target-response-at-held-gate.bin"
        })
        .ok_or_else(|| CiError::Message("public actual fixture held response absent".into()))?;
    let branch_challenge = if dual {
        memcordon_core::private_release_case_v1::public_dual_challenge_v1(&case.challenge, 0)
            .map_err(|error| CiError::Message(error.into()))?
    } else {
        case.challenge
    };
    let response = extract_public_fixture_response(&case.selector, &branch_challenge, port, frame)?;
    let response_path = prefix.join("response.raw").to_string_lossy().into_owned();
    let clock = interval
        .clock_inputs()
        .ok_or_else(|| CiError::Message("public source original process clock absent".into()))?;
    let clock_bytes = crate::private_observer_session::canonical_bytes(clock)?;
    let mut source = crate::private_live_fact_recording::record_common_source_facts(
        interval.capture_bytes()?,
        &case.key,
        crate::private_kernel_replay::CaptureStageV2::FinalPublic,
        target,
        &clock_bytes,
        &before,
        &baseline,
        response_path.clone(),
    )?;
    source
        .facts
        .push(crate::private_live_fact_recording::record_elf_source_fact(
            &baseline,
            samples_prefix
                .join(baseline_root)
                .join("image.raw")
                .to_string_lossy()
                .into_owned(),
            samples_prefix
                .join(baseline_root)
                .join("ancestors-before.json")
                .to_string_lossy()
                .into_owned(),
            samples_prefix
                .join(baseline_root)
                .join("ancestors-after.json")
                .to_string_lossy()
                .into_owned(),
        )?);
    let provider = crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
        provider_record,
        provider_leaves,
    )?;
    if provider.attempts.len() != if dual { 2 } else { 1 } {
        return fail("public source actual settled attempt count differs");
    }
    let attempt = &provider.attempts[0];
    let cgroups = provider
        .attempts
        .iter()
        .map(|attempt| {
            attempt
                .phase_leaves
                .get("cgroup-retirement-v1.json")
                .cloned()
                .ok_or_else(|| {
                    CiError::Message("public original cgroup removal source absent".into())
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let close = observed
        .live_samples
        .get("supervisor/namespace-close-v1.json")
        .ok_or_else(|| {
            CiError::Message("public original namespace holder close source absent".into())
        })?;
    let mut held = vec![(
        "target",
        sample(if dual {
            "dual-first-pre-retirement/target-live-sample-v1.json"
        } else {
            "target-live-sample-v1.json"
        })?,
    )];
    if case.selector == "private_tcp::child_runtime_and_threads_retired" {
        held.push(("child", sample("children/child/sample-v1.json")?));
    }
    if dual {
        held.push((
            "target",
            sample("dual-second-after-first-retirement/target-live-sample-v1.json")?,
        ));
    }
    for (role, leaf) in [
        ("guardian", "pre-exec/guardian/sample-v1.json"),
        ("namespace-init", "pre-exec/namespace_init/sample-v1.json"),
    ] {
        if observed.live_samples.contains_key(leaf) {
            held.push((role, sample(leaf)?));
        }
    }
    if dual {
        for (role, leaf) in [
            ("guardian", "dual-second/pre-exec/guardian/sample-v1.json"),
            (
                "namespace-init",
                "dual-second/pre-exec/namespace_init/sample-v1.json",
            ),
        ] {
            held.push((role, sample(leaf)?));
        }
    }
    let parsed = crate::private_kernel_replay::parse_capture_v2_with_budget(
        interval.capture_bytes()?,
        &case.key,
        crate::private_kernel_replay::CaptureStageV2::FinalPublic,
    )?;
    if matches!(
        case.selector.as_str(),
        "private_tcp::namespace_reentry_denied" | "private_tcp::private_namespace_topology_exact"
    ) {
        let init = held
            .iter()
            .find(|(role, _)| *role == "namespace-init")
            .map(|(_, sample)| sample)
            .ok_or_else(|| {
                CiError::Message("public topology independently held namespace init absent".into())
            })?;
        let expected_init = crate::private_public_fault::public_topology_checkpoint_init(
            &provider,
            &case.selector,
            &case.key,
            &descriptor.boot_id,
            &case.filter_sha256,
        )?;
        crate::private_candidate_network_facts::validate_held_topology_sources(
            &held[0].1,
            &source.target,
            parsed.events(),
            clock,
            &before,
            init,
            &expected_init,
        )?;
        validate_public_topology_response_sources(
            &case.selector,
            &case.challenge,
            port,
            frame,
            &held[0].1,
            &source.target,
            parsed.events(),
            target,
        )?;
        source.facts.push(
            crate::private_candidate_replay::CaseFactV1::PublicTopologyV1 {
                case_prefix: prefix.to_string_lossy().into_owned(),
            },
        );
    }
    if case.selector == "private_tcp::child_runtime_and_threads_retired" {
        source.facts.push(record_public_descendants_source(
            &source.target,
            &held[0].1,
            &held[1].1,
            frame,
            &case.challenge,
            parsed.events(),
            interval.original_clock().ok_or_else(|| {
                CiError::Message("public descendant original calibration absent".into())
            })?,
        )?);
    }
    if matches!(
        case.selector.as_str(),
        "private_tcp::checkpoint_persisted_before_release"
            | "private_tcp::release_checkpoint_terminal_joined"
    ) {
        let original = observed
            .live_samples
            .get("release-intent/release-intent-v4.bin")
            .ok_or_else(|| {
                CiError::Message("public checkpoint original durable read absent".into())
            })?;
        let metadata = observed
            .live_samples
            .get("release-intent/release-intent-v4.bin.metadata.json")
            .ok_or_else(|| {
                CiError::Message("public checkpoint original reopen metadata absent".into())
            })?;
        if attempt.phase_leaves.get("release-intent-v4.bin") != Some(original) {
            return fail("public checkpoint reopened file differs from provider durable inventory");
        }
        source.facts.push(record_public_checkpoint_source(
            interval.capture_bytes()?,
            &case.key,
            &source.target,
            original,
            metadata,
            samples_prefix
                .join("release-intent")
                .join("release-intent-v4.bin")
                .to_string_lossy()
                .into_owned(),
        )?);
    }
    if case.selector == "private_tcp::release_checkpoint_terminal_joined" {
        let get = |path: &str| {
            observed.live_samples.get(path).ok_or_else(|| {
                CiError::Message("public terminal original source leaf absent".into())
            })
        };
        let role = crate::private_public_fault::PublicRetirementRoleSourceV3 {
            schema_version: 3,
            provider_record: provider_record.to_vec(),
            provider_leaves: provider_leaves.clone(),
        };
        let role_bytes = crate::private_observer_session::canonical_bytes(&role)?;
        let clock = interval.clock_inputs().ok_or_else(|| {
            CiError::Message("public terminal original reader clock absent".into())
        })?;
        validate_public_terminal_source(
            get("release-intent/release-intent-v4.bin")?,
            get("terminal-midpoint/execution-observed-v4.bin")?,
            get("terminal-midpoint/execution-observed-v4.bin.metadata.json")?,
            &role_bytes,
            &held[0].1,
            frame,
            &case.key,
            &source.target,
            &case.challenge,
            &descriptor.boot_id,
            parsed.events(),
            clock,
        )?;
        let origin = |path: &str| samples_prefix.join(path).to_string_lossy().into_owned();
        source.facts.push(
            crate::private_candidate_replay::CaseFactV1::PublicTerminalV1 {
                checkpoint_path: origin("release-intent/release-intent-v4.bin"),
                midpoint_path: origin("terminal-midpoint/execution-observed-v4.bin"),
                midpoint_metadata_path: origin(
                    "terminal-midpoint/execution-observed-v4.bin.metadata.json",
                ),
                terminal_source_path: prefix
                    .join("retirement-role-source.v3.json")
                    .to_string_lossy()
                    .into_owned(),
                held_path: origin("target-live-sample-v1.json"),
                frame_path: origin("target-response-at-held-gate.bin"),
            },
        );
    }
    if dual {
        let (listener, _) = crate::private_candidate_network_facts::validate_held_tcp_endpoints(
            &held[0].1,
            &source.target,
            parsed.events(),
            target,
            port,
        )?;
        source.facts.push(record_public_collision_source(
            &held[0].1,
            &source.target,
            parsed.events(),
            target,
            &listener,
            &response_path,
        )?);
        source.facts.push(
            crate::private_candidate_replay::CaseFactV1::PublicFaultDualV1 {
                family: crate::private_case_semantics::CaseFactKindV1::Dual,
                case_prefix: prefix.to_string_lossy().into_owned(),
            },
        );
    }
    let mut request_source = None;
    let mut filter_source = None;
    if memcordon_core::private_facility_source_v1::facility_operations_v1(&case.selector).is_ok() {
        use crate::private_candidate_facility_replay::NativeFacilitySourcesV1;
        let scenario = intent
            .scenarios
            .iter()
            .find(|scenario| scenario.selector == case.selector)
            .ok_or_else(|| CiError::Message("public Facility independent recipe absent".into()))?;
        if case.facility_source_sha256.as_ref()
            != Some(&memcordon_core::private_facility_source_v1::facility_source_revision_sha256())
        {
            return fail("public Facility conjunction requires protected exact source opt-in");
        }
        let interval_prefix = std::path::Path::new("observer/intervals")
            .join(String::from(case.interval_id.storage_sha256()));
        let source_path = |name: &str| {
            samples_prefix
                .join("facility")
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        let pidfd = case.selector == "private_tcp::io_uring_and_pidfd_import_denied";
        let sources = NativeFacilitySourcesV1 {
            product_request_path: None,
            schema_version: 1,
            capture_path: interval_prefix
                .join("capture.bin")
                .to_string_lossy()
                .into_owned(),
            clock_path: interval_prefix
                .join("clock.json")
                .to_string_lossy()
                .into_owned(),
            admission_path: prefix
                .join("prepared-admission.json")
                .to_string_lossy()
                .into_owned(),
            report_path: source_path("facility-source-v1.json"),
            outer_gate_path: source_path("outer/gate.json"),
            outer_ack_path: source_path("outer/ack.bin"),
            outer_held_path: source_path("outer/sample-v1.json"),
            private_gate_path: source_path("private/gate.json"),
            private_ack_path: source_path("private/ack.bin"),
            private_held_path: source_path("private/sample-v1.json"),
            source_outer_held_path: pidfd.then(|| source_path("outer/source/sample-v1.json")),
            source_private_held_path: pidfd.then(|| source_path("private/source/sample-v1.json")),
        };
        let mut raw = observed
            .live_samples
            .iter()
            .map(|(name, bytes)| {
                (
                    samples_prefix.join(name).to_string_lossy().into_owned(),
                    bytes.clone(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        raw.insert(sources.clock_path.clone(), clock_bytes.clone());
        raw.insert(sources.admission_path.clone(), prepared_admission.to_vec());
        let (_, argv) = crate::private_public_plan::prepared_public_case_recipe_v1(
            intent,
            &descriptor.session_nonce,
            case.interval_id.generation,
            &case.selector,
        )?;
        let expected = crate::private_candidate_replay::ExpectedCaseSubjectV1 {
            selector: &case.selector,
            result_key: &case.key,
            fixture_sha256: &scenario.fixture_sha256,
            filter_sha256: &case.filter_sha256,
            filter_install_source_sha256: case.filter_install_source_sha256.as_ref(),
            facility_source_sha256: case.facility_source_sha256.as_ref(),
            host_preservation_source_sha256: case.host_preservation_source_sha256.as_ref(),
            reuse_source_sha256: None,
            fixture_argv: &argv,
            uid: scenario.recipe.target_uid,
            gid: scenario.recipe.target_gid,
            groups: &scenario.recipe.supplementary_groups,
            port,
            challenge: &case.challenge,
            auxiliary_semantics_sha256: Some(&intent.semantics_policy.approved_semantics_sha256),
            exact_response: &response,
        };
        // Source construction has no origin capability. It uses measured
        // detached endpoints; the later controller close and completed replay
        // must authenticate this exact physical record and all mapped bytes.
        let mut source_descriptor = descriptor.clone();
        if !source_descriptor
            .intervals
            .iter()
            .any(|record| record.interval_id == case.interval_id.storage_sha256())
        {
            let timing = interval
                .observation_timing()
                .ok_or_else(|| CiError::Message("public Facility measured timing absent".into()))?;
            source_descriptor.intervals.push(
                crate::private_observer_session::ObserverIntervalRecordV1 {
                    interval_id: case.interval_id.storage_sha256(),
                    logical_case_key: case.key.clone(),
                    generation: case.interval_id.generation,
                    purpose: "ordinary".into(),
                    ordinal: case.interval_id.ordinal,
                    capture_path: sources.capture_path.clone(),
                    capture_sha256: parsed.digest().clone(),
                    controls_paths: Vec::new(),
                    sample_paths: raw.keys().cloned().collect(),
                    arm_monotonic_ns: timing.armed_monotonic_ns,
                    begin_monotonic_ns: timing.operation_begin_monotonic_ns,
                    end_monotonic_ns: timing.operation_end_monotonic_ns,
                    detach_monotonic_ns: timing.detached_monotonic_ns,
                    loss_count: 0,
                    first_sequence: parsed
                        .events()
                        .first()
                        .ok_or_else(|| CiError::Message("public Facility capture empty".into()))?
                        .sequence,
                    last_sequence: parsed.events().last().expect("nonempty capture").sequence,
                },
            );
        }
        source.facts.extend(
            crate::private_candidate_facility_replay::record_facility_source_facts(
                &source_descriptor,
                &expected,
                &source.target,
                &sources.capture_path.clone(),
                case.interval_id.generation,
                sources,
                parsed.events(),
                |path| {
                    raw.get(path).cloned().ok_or_else(|| {
                        CiError::Message("public Facility original source leaf absent".into())
                    })
                },
            )?,
        );
    }
    if case.selector == "private_tcp::host_namespace_and_sysctl_unchanged" {
        if case.host_preservation_source_sha256.as_ref()
            != Some(
                &crate::private_candidate_host_facts::host_preservation_source_revision_sha256(),
            )
        {
            return fail(
                "public host continuity proof lacks independently approved source feature",
            );
        }
        let raw = observed
            .live_samples
            .get("host-continuity.v1.bin")
            .ok_or_else(|| CiError::Message("public continuous host raw source absent".into()))?;
        let map = crate::private_source_carrier::parse_source_carrier(raw)?;
        let timing = interval.observation_timing().ok_or_else(|| {
            CiError::Message("public host original interval timing absent".into())
        })?;
        crate::private_candidate_host_facts::verify_host_sources(
            &map,
            parsed.events(),
            timing.armed_monotonic_ns,
            timing.detached_monotonic_ns,
        )?;
        crate::private_candidate_host_facts::verify_host_reader_clock(
            &map,
            parsed.events(),
            clock,
        )?;
        source
            .facts
            .push(crate::private_candidate_replay::CaseFactV1::PublicHostV1 {
                sources: crate::private_candidate_host_facts::NativeHostSourcesV1 {
                    schema_version: 1,
                    source_path: samples_prefix
                        .join("host-continuity.v1.bin")
                        .to_string_lossy()
                        .into_owned(),
                },
            });
    }
    if case.selector == "private_tcp::native_filter_digest_and_abi_bound" {
        if case.filter_install_source_sha256.as_ref()!=Some(
            &crate::private_candidate_filter_facility_facts::filter_install_source_revision_sha256()) {
            return fail("public installed-kernel filter proof requires independently approved feature opt-in");
        }
        let sources = crate::private_candidate_filter_facility_facts::NativeFilterSourcesV1 {
            schema_version: 1,
            pre_path: samples_prefix
                .join("pre-exec/target-live-sample-v1.json")
                .to_string_lossy()
                .into_owned(),
            baseline_path: samples_prefix
                .join("baseline/target-live-sample-v1.json")
                .to_string_lossy()
                .into_owned(),
            instruction_path: prefix
                .join("installed-filter-instructions.v1.bin")
                .to_string_lossy()
                .into_owned(),
        };
        let (measured, dump) =
            crate::private_candidate_filter_facility_facts::record_filter_source_facts(
                parsed.events(),
                clock,
                &source.target,
                &before,
                &baseline,
                sources,
                &case.filter_sha256,
            )?;
        let [crate::private_candidate_replay::CaseFactV1::NativeFilterV1 { sources }] =
            measured.as_slice()
        else {
            return fail("public installed-filter source constructor family differs");
        };
        source.facts.push(
            crate::private_candidate_replay::CaseFactV1::PublicFilterV1 {
                sources: sources.clone(),
            },
        );
        filter_source = Some((sources.instruction_path.clone(), Kind::Case, dump));
    }
    if case.selector == "private_tcp::af_unix_abstract_and_pathname_denied" {
        crate::private_candidate_unix_facts::verify_held_unix_sources(
            &held[0].1,
            parsed.events(),
            clock,
            &source.target,
            target,
            &case.challenge,
        )?;
        source
            .facts
            .push(crate::private_candidate_replay::CaseFactV1::PublicUnixV1 {
                held_sample_path: samples_prefix
                    .join("target-live-sample-v1.json")
                    .to_string_lossy()
                    .into_owned(),
            });
    }
    if matches!(
        case.selector.as_str(),
        "private_tcp::native_tcp_bind_listen_connect"
            | "private_tcp::port_collision_same_namespace"
            | "private_tcp::scm_rights_and_precreated_socket_denied"
            | "private_tcp::namespace_reentry_denied"
            | "private_tcp::private_namespace_topology_exact"
    ) {
        let late = &held[0].1;
        let (listener, connector) =
            crate::private_candidate_network_facts::validate_held_tcp_endpoints(
                late,
                &source.target,
                parsed.events(),
                target,
                port,
            )?;
        if matches!(
            case.selector.as_str(),
            "private_tcp::native_tcp_bind_listen_connect"
                | "private_tcp::namespace_reentry_denied"
                | "private_tcp::private_namespace_topology_exact"
        ) {
            let observation = if case.selector == "private_tcp::native_tcp_bind_listen_connect" {
                crate::private_observer_session::strict_json::<TcpResponseSourceV2>(
                    decode_public_held_payload(frame)?,
                    MAX_HELD_BYTES,
                )?
            } else {
                topology_response(&case.selector, decode_public_held_payload(frame)?)?.tcp
            };
            let rows = crate::private_candidate_network_facts::parse_held_tcp_table(
                late.leaves.get("net-tcp.raw").ok_or_else(|| {
                    CiError::Message("public original held TCP table absent".into())
                })?,
            )?;
            if observation.network_namespace_inode != listener.netns_inode
                || !rows.iter().any(|row| {
                    row.inode == connector.socket_inode && row.local_port == observation.client_port
                })
            {
                return fail(
                    "public actual-read response namespace/client differs from held endpoints",
                );
            }
        }
        let argv = baseline
            .leaves
            .get("cmdline.raw")
            .ok_or_else(|| CiError::Message("public original target argv absent".into()))?;
        let mut arguments = argv.split(|byte| *byte == 0);
        let mut challenges = Vec::new();
        while let Some(argument) = arguments.next() {
            if argument == b"--challenge" {
                let bytes = arguments.next().ok_or_else(|| {
                    CiError::Message("public observed challenge argv absent".into())
                })?;
                challenges.push(hex::decode(bytes).map_err(|_| {
                    CiError::Message("public observed challenge argv malformed".into())
                })?);
            }
        }
        let [actual] = challenges.as_slice() else {
            return fail("public observed challenge argv is ambiguous");
        };
        if actual != &case.challenge {
            return fail("public observed challenge argv differs");
        }
        if case.selector == "private_tcp::port_collision_same_namespace" {
            source.facts.push(record_public_collision_source(
                late,
                &source.target,
                parsed.events(),
                target,
                &listener,
                &response_path,
            )?);
        }
        let request_path = prefix
            .join("request-challenge.raw")
            .to_string_lossy()
            .into_owned();
        request_source = Some((request_path.clone(), Kind::Request, actual.clone()));
        source
            .facts
            .push(crate::private_candidate_replay::CaseFactV1::Tcp {
                listener,
                connector,
                response_path: response_path.clone(),
                request_path,
            });
    }
    let role_path = prefix
        .join("retirement-role-source.v3.json")
        .to_string_lossy()
        .into_owned();
    if attempt.terminal_bytes.is_none() && attempt.fault.is_none() {
        return fail("public common retirement original terminal source absent");
    }
    let retirement = crate::private_live_fact_recording::record_retirement_source_fact(
        parsed.events(),
        clock,
        &held
            .iter()
            .map(|(role, sample)| (*role, sample))
            .collect::<Vec<_>>(),
        &cgroups,
        close,
        role_path.clone(),
    )?;
    source.facts.push(retirement);
    if matches!(
        case.selector.as_str(),
        "private_tcp::frontend_loss_retired" | "private_tcp::guardian_loss_retired"
    ) {
        use crate::private_case_semantics::CaseFactKindV1 as F;
        let family = if case.selector == "private_tcp::frontend_loss_retired" {
            F::FrontendLoss
        } else {
            F::GuardianLoss
        };
        for family in [family, F::Checkpoint] {
            source.facts.push(
                crate::private_candidate_replay::CaseFactV1::PublicFaultDualV1 {
                    family,
                    case_prefix: prefix.to_string_lossy().into_owned(),
                },
            );
        }
    }
    // This is explicitly an intermediate source representation, not the
    // completed facts.json accepted by independent all25 replay. Missing
    // selector families must be assembled before that constructor is called.
    let facts = crate::private_candidate_replay::CaseReplayFactsV1 {
        schema_version: 1,
        selector: case.selector.clone(),
        result_key: case.key.clone(),
        generation: case.interval_id.generation,
        interval_id: case.interval_id.storage_sha256(),
        target: source.target,
        facts: source.facts,
        clock_path: std::path::Path::new("observer/intervals")
            .join(String::from(case.interval_id.storage_sha256()))
            .join("clock.json")
            .to_string_lossy()
            .into_owned(),
        held_sample_paths: vec![
            samples_prefix
                .join(baseline_name)
                .to_string_lossy()
                .into_owned(),
        ],
    };
    let role = crate::private_public_fault::PublicRetirementRoleSourceV3 {
        schema_version: 3,
        provider_record: provider_record.to_vec(),
        provider_leaves: provider_leaves.clone(),
    };
    let mut leaves = vec![
        (response_path, Kind::Response, response.to_vec()),
        (
            role_path,
            Kind::Case,
            crate::private_observer_session::canonical_bytes(&role)?,
        ),
        (
            prefix
                .join("common-facts-source.json")
                .to_string_lossy()
                .into_owned(),
            Kind::Case,
            crate::private_observer_session::canonical_bytes(&facts)?,
        ),
    ];
    if let Some(request) = request_source {
        leaves.push(request);
    }
    if let Some(filter) = filter_source {
        leaves.push(filter);
    }
    let spec = crate::private_case_semantics::closed_case_spec(&case.selector, target)?;
    let mut selected = Vec::new();
    for kind in &spec.facts {
        let matching = facts
            .facts
            .iter()
            .filter(|fact| fact.kind() == *kind)
            .collect::<Vec<_>>();
        match matching.as_slice() {
            [fact] => selected.push((*fact).clone()),
            [] => return Ok(leaves), // Explicit intermediate source, not final facts.
            _ => return fail("public actual source family duplicated"),
        }
    }
    let mut assembled = facts;
    assembled.facts = selected;
    leaves.push((
        prefix.join("facts.json").to_string_lossy().into_owned(),
        Kind::Case,
        crate::private_observer_session::canonical_bytes(&assembled)?,
    ));
    Ok(leaves)
}

fn record_public_collision_source(
    sample: &crate::private_public_live::HeldPublicTargetSamplesV1,
    task: &crate::private_candidate_replay::ReplayTaskV1,
    events: &[crate::private_kernel_replay::KernelEventRecordV2],
    triple: &str,
    listener: &crate::private_candidate_replay::SocketV1,
    response_path: &str,
) -> Result<crate::private_candidate_replay::CaseFactV1> {
    use crate::private_candidate_network_facts::{
        checked_loopback_operand, matches, parse_held_tcp_table, returned, socket_fds,
        validate_socket_lifetime,
    };
    let nr = crate::private_case_semantics::native_syscall_number(
        triple,
        crate::private_case_semantics::NativeOperationV1::Bind,
    )?;
    let fds = socket_fds(sample)?;
    let listener_fd = fds.get(&listener.socket_inode).ok_or_else(|| {
        CiError::Message("public collision original listener descriptor absent".into())
    })?;
    let denied = events
        .iter()
        .filter(|event| {
            event.kind == 4
                && matches(task, event)
                && event.syscall_nr == nr
                && event.seccomp_action == 0x7fff0000
                && event.monotonic_ns < sample.begin_monotonic_ns
                && checked_loopback_operand(event, listener.port)
                && event.args[0] != u64::from(*listener_fd)
                && returned(events, event).is_ok_and(|ret| ret.syscall_result == -98)
        })
        .collect::<Vec<_>>();
    let [denied] = denied.as_slice() else {
        return fail("public collision occupied-port bind is absent/ambiguous");
    };
    let denied_return = returned(events, denied)?;
    validate_socket_lifetime(events, task, denied, denied_return.monotonic_ns)?;
    let free = events
        .iter()
        .filter(|event| {
            event.kind == 4
                && matches(task, event)
                && event.syscall_nr == nr
                && event.seccomp_action == 0x7fff0000
                && event.sequence > denied.sequence
                && event.monotonic_ns < sample.begin_monotonic_ns
                && event.args[0] != u64::from(*listener_fd)
                && checked_loopback_operand(event, 0)
                && returned(events, event).is_ok_and(|ret| ret.syscall_result == 0)
        })
        .collect::<Vec<_>>();
    let [free] = free.as_slice() else {
        return fail("public collision separate free-port bind is absent/ambiguous");
    };
    validate_socket_lifetime(events, task, free, sample.end_monotonic_ns)?;
    // Rust closes the failed bind socket, so its numerical FD may legitimately
    // be reused. Prove the close and new socket occurrence, not FD inequality.
    if free.args[0] == denied.args[0] {
        let creation = events
            .iter()
            .filter(|event| {
                event.kind == 4
                    && matches(task, event)
                    && matches!(
                        (event.syscall_arch, event.syscall_nr),
                        (0xc000003e, 41) | (0xc00000b7, 198)
                    )
                    && event.sequence > denied_return.sequence
                    && event.sequence < free.sequence
                    && returned(events, event)
                        .is_ok_and(|ret| ret.syscall_result == free.args[0] as i64)
            })
            .collect::<Vec<_>>();
        let [creation] = creation.as_slice() else {
            return fail("public collision reused FD lacks a unique fresh socket");
        };
        let closed = events
            .iter()
            .filter(|event| {
                matches!(event.kind, 4 | 11)
                    && matches(task, event)
                    && matches!(
                        (event.syscall_arch, event.syscall_nr),
                        (0xc000003e, 3) | (0xc00000b7, 57)
                    )
                    && event.args[0] == denied.args[0]
                    && event.sequence > denied_return.sequence
                    && event.sequence < creation.sequence
                    && returned(events, event).is_ok_and(|ret| {
                        ret.syscall_result == 0 && ret.sequence < creation.sequence
                    })
            })
            .count();
        if closed != 1 {
            return fail("public collision reused FD lacks its exact failed-socket close");
        }
    }
    let rows = parse_held_tcp_table(sample.leaves.get("net-tcp.raw").ok_or_else(|| {
        CiError::Message("public collision original held TCP table absent".into())
    })?)?;
    if !rows.iter().any(|row| {
        row.state == 10
            && row.local_address == 0x0100007f
            && row.local_port != 0
            && row.local_port != listener.port
            && fds
                .get(&row.inode)
                .is_some_and(|fd| u64::from(*fd) == free.args[0])
    }) {
        return fail("public collision actual free-bound socket is absent");
    }
    Ok(crate::private_candidate_replay::CaseFactV1::Collision {
        listener: listener.clone(),
        competitor: task.clone(),
        bind_occurrence: denied.syscall_occurrence,
        free_bind_occurrence: free.syscall_occurrence,
        response_path: response_path.into(),
    })
}

fn record_public_checkpoint_source(
    capture: &[u8],
    key: &DiagnosticSha256,
    target: &crate::private_candidate_replay::ReplayTaskV1,
    original: &[u8],
    metadata: &[u8],
    checkpoint_path: String,
) -> Result<crate::private_candidate_replay::CaseFactV1> {
    validate_public_checkpoint_capture(capture, key, target, original, metadata, false)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reopen {
        schema_version: u8,
        file_dev: u64,
        file_inode: u64,
        directory_dev: u64,
        directory_inode: u64,
        bytes_sha256: DiagnosticSha256,
        observed_monotonic_ns: u64,
    }
    let reopened: Reopen = crate::private_observer_session::strict_json(metadata, 4096)?;
    if reopened.schema_version != 1 || reopened.bytes_sha256 != hash_bytes(original) {
        return fail("public checkpoint source metadata differs");
    }
    let parsed = crate::private_kernel_replay::parse_capture_v2_with_budget(
        capture,
        key,
        crate::private_kernel_replay::CaptureStageV2::FinalPublic,
    )?;
    let events = parsed.events();
    let entry = |ret: &crate::private_kernel_replay::KernelEventRecordV2| {
        events.iter().find(|event| {
            event.kind == 11
                && event.task == ret.task
                && event.syscall_occurrence == ret.syscall_occurrence
                && event.syscall_arch == ret.syscall_arch
                && event.syscall_nr == ret.syscall_nr
                && event.args == ret.args
                && event.sequence < ret.sequence
        })
    };
    let file = events
        .iter()
        .filter(|event| {
            event.kind == 5
                && event.syscall_result == 0
                && matches!(
                    (event.syscall_arch, event.syscall_nr),
                    (0xc000003e, 74) | (0xc00000b7, 82)
                )
                && event.monotonic_ns < reopened.observed_monotonic_ns
                && entry(event).is_some_and(|e| {
                    e.image_dev == reopened.file_dev && e.image_inode == reopened.file_inode
                })
        })
        .collect::<Vec<_>>();
    let [file] = file.as_slice() else {
        return fail("public checkpoint exact file sync ambiguous");
    };
    let directory = events
        .iter()
        .filter(|event| {
            event.kind == 5
                && event.task == file.task
                && event.syscall_nr == file.syscall_nr
                && event.syscall_result == 0
                && event.sequence > file.sequence
                && event.monotonic_ns < reopened.observed_monotonic_ns
                && entry(event).is_some_and(|e| {
                    e.image_dev == reopened.directory_dev
                        && e.image_inode == reopened.directory_inode
                })
        })
        .collect::<Vec<_>>();
    let [directory] = directory.as_slice() else {
        return fail("public checkpoint exact directory sync ambiguous");
    };
    let exec = events
        .iter()
        .find(|event| {
            event.kind == 6 && crate::private_candidate_network_facts::matches(target, event)
        })
        .ok_or_else(|| CiError::Message("public checkpoint target exec absent".into()))?;
    let release = events
        .iter()
        .filter(|event| {
            event.kind == 5
                && event.task == file.task
                && matches!(
                    (event.syscall_arch, event.syscall_nr),
                    (0xc000003e, 1) | (0xc00000b7, 64)
                )
                && event.args[2] == 1
                && event.syscall_result == 1
                && event.monotonic_ns > reopened.observed_monotonic_ns
                && event.sequence < exec.sequence
        })
        .collect::<Vec<_>>();
    let [release] = release.as_slice() else {
        return fail("public checkpoint exact GO ambiguous");
    };
    let task = &file.task;
    Ok(crate::private_candidate_replay::CaseFactV1::Checkpoint {
        checkpoint_path,
        file_dev: reopened.file_dev,
        file_inode: reopened.file_inode,
        owner: crate::private_candidate_replay::ReplayTaskV1 {
            tid: task.tid,
            tgid: task.tgid,
            start_boottime_ns: task.start_boottime_ns,
            cgroup_inode: task.cgroup_inode,
            time_ns_inode: task.time_ns_inode,
        },
        fd: u32::try_from(file.args[0])
            .map_err(|_| CiError::Message("public checkpoint fd overflow".into()))?,
        directory_fd: u32::try_from(directory.args[0])
            .map_err(|_| CiError::Message("public checkpoint directory fd overflow".into()))?,
        file_sync_sequence: file.sequence,
        directory_sync_sequence: directory.sequence,
        release_sequence: release.sequence,
    })
}

fn record_public_pre_exec_fault_sources(
    case: &crate::private_public_producer::PreparedPublicCaseV1,
    prefix: &std::path::Path,
    observed: &crate::private_public_dispatch::ObservedInstalledPublicCaseV3,
    interval: &crate::private_kernel_observer::VerifiedKernelIntervalV1,
    provider_record: &[u8],
    provider_leaves: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<Vec<(String, crate::private_public_raw::PublicLeafKindV1, Vec<u8>)>> {
    use crate::private_candidate_replay::{CaseFactV1, CaseReplayFactsV1};
    use crate::private_public_raw::PublicLeafKindV1 as Kind;
    let provider = crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
        provider_record,
        provider_leaves,
    )?;
    let [attempt] = provider.attempts.as_slice() else {
        return fail("public preexec fault attempt inventory differs");
    };
    let fault = attempt
        .fault
        .as_ref()
        .ok_or_else(|| CiError::Message("public preexec actual fault absent".into()))?;
    if fault.outcome!=memcordon_core::private_release_case_v1::PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain {
        return fail("public preexec fault actual outcome differs");
    }
    let samples = prefix.join("samples");
    let sample = |name: &str| -> Result<crate::private_public_live::HeldPublicTargetSamplesV1> {
        crate::private_source_carrier::decode_held_source(
            observed.live_samples.get(name).ok_or_else(|| {
                CiError::Message("public preexec held original source absent".into())
            })?,
            |path| {
                let relative = std::path::Path::new(path)
                    .strip_prefix(&samples)
                    .map_err(|_| {
                        CiError::Message("public preexec image outside original source case".into())
                    })?;
                observed
                    .live_samples
                    .get(relative.to_string_lossy().as_ref())
                    .cloned()
                    .ok_or_else(|| {
                        CiError::Message("public preexec held original image absent".into())
                    })
            },
        )
    };
    let mut held = vec![("target", sample("pre-exec/target-live-sample-v1.json")?)];
    for (role, path) in [
        ("guardian", "pre-exec/guardian/sample-v1.json"),
        ("namespace-init", "pre-exec/namespace_init/sample-v1.json"),
    ] {
        if observed.live_samples.contains_key(path) {
            held.push((role, sample(path)?));
        }
    }
    let clock = interval
        .original_clock()
        .ok_or_else(|| CiError::Message("public preexec original clock absent".into()))?;
    let parsed = crate::private_kernel_replay::parse_capture_v2_with_budget(
        interval.capture_bytes()?,
        &case.key,
        crate::private_kernel_replay::CaptureStageV2::FinalPublic,
    )?;
    let target = crate::private_public_fault_dual_replay::task(
        parsed.events(),
        clock,
        held[0].1.pid,
        held[0].1.start_time_ticks,
    )?;
    let cgroup = attempt
        .phase_leaves
        .get("cgroup-retirement-v1.json")
        .ok_or_else(|| {
            CiError::Message("public preexec actual removed cgroup source absent".into())
        })?;
    let close = observed
        .live_samples
        .get("supervisor/namespace-close-v1.json")
        .ok_or_else(|| {
            CiError::Message("public preexec actual namespace holder closes absent".into())
        })?;
    let role_path = prefix
        .join("retirement-role-source.v3.json")
        .to_string_lossy()
        .into_owned();
    let retirement = crate::private_live_fact_recording::record_retirement_source_fact(
        parsed.events(),
        clock
            .inputs()
            .ok_or_else(|| CiError::Message("public preexec archived clock input absent".into()))?,
        &held
            .iter()
            .map(|(role, sample)| (*role, sample))
            .collect::<Vec<_>>(),
        &[cgroup.clone()],
        close,
        role_path.clone(),
    )?;
    let facts = CaseReplayFactsV1 {
        schema_version: 1,
        selector: case.selector.clone(),
        result_key: case.key.clone(),
        generation: case.interval_id.generation,
        interval_id: case.interval_id.storage_sha256(),
        target,
        facts: vec![
            retirement,
            CaseFactV1::PublicFaultDualV1 {
                family: crate::private_case_semantics::CaseFactKindV1::AuthorizationLoss,
                case_prefix: prefix.to_string_lossy().into_owned(),
            },
            CaseFactV1::PublicUncertainCheckpointV1 {
                case_prefix: prefix.to_string_lossy().into_owned(),
            },
        ],
        clock_path: std::path::Path::new("observer/intervals")
            .join(String::from(case.interval_id.storage_sha256()))
            .join("clock.json")
            .to_string_lossy()
            .into_owned(),
        // No post-exec sample exists: this versioned source proves actual
        // pre-exec EOF/rejection and retains pre-exec raw in its own carrier.
        held_sample_paths: Vec::new(),
    };
    let role = crate::private_public_fault::PublicRetirementRoleSourceV3 {
        schema_version: 3,
        provider_record: provider_record.to_vec(),
        provider_leaves: provider_leaves.clone(),
    };
    Ok(vec![
        (
            role_path,
            Kind::Case,
            crate::private_observer_session::canonical_bytes(&role)?,
        ),
        (
            prefix.join("facts.json").to_string_lossy().into_owned(),
            Kind::Case,
            crate::private_observer_session::canonical_bytes(&facts)?,
        ),
    ])
}

/// Diagnostic raw mapping only: no process lifetime or release capability is
/// established until the original capture and retirement facts also replay.
pub fn validate_public_descendant_samples(
    parent_sample: &crate::private_public_live::HeldPublicTargetSamplesV1,
    child_sample: &crate::private_public_live::HeldPublicTargetSamplesV1,
    operations: &[u8],
    challenge: &[u8; 32],
) -> Result<u32> {
    let width = std::mem::size_of::<u32>();
    let magic = b"MCRCHLD1";
    if operations.len() != magic.len() + 3 * width + challenge.len()
        || !operations.starts_with(magic)
        || operations[operations.len() - challenge.len()..] != *hash_bytes(challenge).bytes()
    {
        return fail("public child operation frame differs");
    }
    let nsids = (0..3)
        .map(|index| {
            u32::from_le_bytes(
                operations[magic.len() + index * width..magic.len() + (index + 1) * width]
                    .try_into()
                    .expect("fixed child field"),
            )
        })
        .collect::<Vec<_>>();
    let nspid = |bytes: &[u8]| -> Result<u32> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CiError::Message("public descendant status is not UTF-8".into()))?;
        let rows = text
            .lines()
            .filter_map(|line| line.strip_prefix("NSpid:"))
            .collect::<Vec<_>>();
        let [row] = rows.as_slice() else {
            return fail("public descendant namespace PID ambiguous");
        };
        row.split_whitespace()
            .last()
            .ok_or_else(|| CiError::Message("public descendant namespace PID absent".into()))?
            .parse()
            .map_err(|_| CiError::Message("public descendant namespace PID differs".into()))
    };
    if nspid(
        parent_sample
            .leaves
            .get("status.raw")
            .ok_or_else(|| CiError::Message("public parent raw status absent".into()))?,
    )? != nsids[0]
        || nspid(
            child_sample
                .leaves
                .get("status.raw")
                .ok_or_else(|| CiError::Message("public child raw status absent".into()))?,
        )? != nsids[1]
        || child_sample.pid == parent_sample.pid
        || parent_sample.tasks.len() != 2
        || child_sample.tasks.len() != 1
    {
        return fail("public descendant actual host/namespace inventory differs");
    }
    let scalar = |bytes: &[u8], field: &str| -> Result<u32> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CiError::Message("public descendant status is not UTF-8".into()))?;
        let rows = text
            .lines()
            .filter_map(|line| line.strip_prefix(field))
            .collect::<Vec<_>>();
        let [row] = rows.as_slice() else {
            return fail("public descendant status identity ambiguous");
        };
        let values = row.split_whitespace().collect::<Vec<_>>();
        let [value] = values.as_slice() else {
            return fail("public descendant status scalar differs");
        };
        value
            .parse()
            .map_err(|_| CiError::Message("public descendant status identity differs".into()))
    };
    let child_status = child_sample
        .leaves
        .get("status.raw")
        .ok_or_else(|| CiError::Message("public child status absent".into()))?;
    if scalar(child_status, "PPid:")? != parent_sample.pid
        || scalar(child_status, "Tgid:")? != child_sample.pid
    {
        return fail("public child original parent/group differs");
    }
    let children = std::str::from_utf8(
        child_sample
            .leaves
            .get("parent-children.raw")
            .ok_or_else(|| {
                CiError::Message("public original parent children list absent".into())
            })?,
    )
    .map_err(|_| CiError::Message("public original parent children list is not UTF-8".into()))?
    .split_whitespace()
    .map(str::parse::<u32>)
    .collect::<std::result::Result<Vec<_>, _>>()
    .map_err(|_| CiError::Message("public original parent children list differs".into()))?;
    if children
        .iter()
        .filter(|pid| **pid == child_sample.pid)
        .count()
        != 1
    {
        return fail("public child absent or aliased in original parent children list");
    }
    let parent_tasks = parent_sample
        .tasks
        .iter()
        .filter(|task| task.tid == parent_sample.pid && task.tgid == parent_sample.pid)
        .collect::<Vec<_>>();
    let [parent_task] = parent_tasks.as_slice() else {
        return fail("public original parent task differs");
    };
    let [child_task] = child_sample.tasks.as_slice() else {
        return fail("public child task inventory differs");
    };
    if child_task.tid != child_sample.pid || child_task.tgid != child_sample.pid {
        return fail("public original child task differs");
    }
    let thread_samples = parent_sample
        .tasks
        .iter()
        .filter(|task| task.tid != parent_sample.pid && task.tgid == parent_sample.pid)
        .collect::<Vec<_>>();
    let [thread_sample] = thread_samples.as_slice() else {
        return fail("public thread raw inventory ambiguous");
    };
    if nspid(
        parent_sample
            .leaves
            .get(
                std::path::Path::new("tasks")
                    .join(thread_sample.tid.to_string())
                    .join("status.raw")
                    .to_string_lossy()
                    .as_ref(),
            )
            .ok_or_else(|| CiError::Message("public thread raw status absent".into()))?,
    )? != nsids[2]
    {
        return fail("public actual thread namespace TID differs");
    }
    for role in ["pid", "net", "mnt"] {
        let inode = parent_task
            .namespace_inodes
            .get(role)
            .filter(|inode| **inode != 0)
            .ok_or_else(|| CiError::Message("public parent private namespace absent".into()))?;
        if child_task.namespace_inodes.get(role) != Some(inode)
            || thread_sample.namespace_inodes.get(role) != Some(inode)
        {
            return fail("public descendant private namespace differs");
        }
    }
    Ok(thread_sample.tid)
}

fn record_public_descendants_source(
    parent: &crate::private_candidate_replay::ReplayTaskV1,
    parent_sample: &crate::private_public_live::HeldPublicTargetSamplesV1,
    child_sample: &crate::private_public_live::HeldPublicTargetSamplesV1,
    frame: &[u8],
    challenge: &[u8; 32],
    events: &[crate::private_kernel_replay::KernelEventRecordV2],
    clock: &crate::private_process_clock::VerifiedProcClockCalibrationV1,
) -> Result<crate::private_candidate_replay::CaseFactV1> {
    let (_, operations) = decode_public_exec_response_frame(
        "private_tcp::child_runtime_and_threads_retired",
        challenge,
        frame,
    )?
    .ok_or_else(|| CiError::Message("public children original MCEX frame incomplete".into()))?;
    let thread_tid =
        validate_public_descendant_samples(parent_sample, child_sample, operations, challenge)?;
    if parent_sample.pid != parent.tid {
        return fail("public descendant source parent differs");
    }
    let thread_sample = parent_sample
        .tasks
        .iter()
        .find(|task| task.tid == thread_tid)
        .expect("validated original thread");
    let child = crate::private_public_fault_dual_replay::task(
        events,
        clock,
        child_sample.pid,
        child_sample.start_time_ticks,
    )?;
    let thread = crate::private_public_fault_dual_replay::task(
        events,
        clock,
        thread_sample.tid,
        thread_sample.start_time_ticks,
    )?;
    let simultaneous = parent_sample
        .end_monotonic_ns
        .max(child_sample.end_monotonic_ns);
    for task in [&child, &thread] {
        let forks = events
            .iter()
            .filter(|event| {
                event.kind == 7
                    && event.task.tid == parent.tid
                    && event.task.start_boottime_ns == parent.start_boottime_ns
                    && event.other_tid == task.tid
            })
            .collect::<Vec<_>>();
        let [fork] = forks.as_slice() else {
            return fail("public descendant actual fork absent or ambiguous");
        };
        if u64::try_from(fork.syscall_result).ok() != Some(task.start_boottime_ns)
            || fork.monotonic_ns >= simultaneous
            || task.cgroup_inode != parent.cgroup_inode
            || child.tgid == parent.tgid
            || thread.tgid != parent.tgid
            || events
                .iter()
                .filter(|event| {
                    event.kind == 8
                        && event.task.tid == task.tid
                        && event.task.start_boottime_ns == task.start_boottime_ns
                })
                .any(|event| event.monotonic_ns <= simultaneous)
        {
            return fail("public descendant held causal identity/lifetime differs");
        }
    }
    Ok(crate::private_candidate_replay::CaseFactV1::Descendants {
        parent: parent.clone(),
        child,
        thread,
        simultaneously_live_monotonic_ns: simultaneous,
    })
}

pub(crate) fn validate_public_terminal_source(
    checkpoint: &[u8],
    midpoint: &[u8],
    metadata: &[u8],
    terminal_source: &[u8],
    held: &crate::private_public_live::HeldPublicTargetSamplesV1,
    frame: &[u8],
    key: &DiagnosticSha256,
    target: &crate::private_candidate_replay::ReplayTaskV1,
    challenge: &[u8; 32],
    boot: &str,
    events: &[crate::private_kernel_replay::KernelEventRecordV2],
    clock: &crate::private_process_clock::ProcClockInputsV1,
) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reopened {
        schema_version: u8,
        file_dev: u64,
        file_inode: u64,
        directory_dev: u64,
        directory_inode: u64,
        bytes_sha256: DiagnosticSha256,
        observed_monotonic_ns: u64,
    }
    let reopened: Reopened = crate::private_observer_session::strict_json(metadata, 4096)?;
    let original_clock = crate::private_process_clock::ParsedProcClockCalibrationV1::parse(clock)?;
    let namespace_pid = decode_public_terminal_midpoint_frame(frame, challenge)?;
    let status = std::str::from_utf8(
        held.leaves
            .get("status.raw")
            .ok_or_else(|| CiError::Message("public terminal raw status absent".into()))?,
    )
    .map_err(|_| CiError::Message("public terminal raw status is not UTF-8".into()))?;
    let nspids = status
        .lines()
        .filter_map(|line| line.strip_prefix("NSpid:"))
        .collect::<Vec<_>>();
    let [nspids] = nspids.as_slice() else {
        return fail("public terminal original namespace PID ambiguous");
    };
    if namespace_pid == 0
        || nspids
            .split_whitespace()
            .last()
            .and_then(|pid| pid.parse::<u32>().ok())
            != Some(namespace_pid)
        || held.pid != target.tid
        || held.tasks.len() != 1
        || held.tasks[0].tid != target.tid
        || held.tasks[0].tgid != target.tgid
        || reopened.schema_version != 1
        || reopened.file_dev == 0
        || reopened.file_inode == 0
        || reopened.directory_dev == 0
        || reopened.directory_inode == 0
        || reopened.bytes_sha256 != hash_bytes(midpoint)
        || reopened.observed_monotonic_ns < held.end_monotonic_ns
        || held.begin_monotonic_ns == 0
        || held.begin_monotonic_ns > held.end_monotonic_ns
    {
        return fail("public original terminal midpoint object/held identity differs");
    }
    let matches = |event: &&crate::private_kernel_replay::KernelEventRecordV2| {
        crate::private_candidate_network_facts::matches(target, event)
    };
    let execs = events
        .iter()
        .filter(|event| event.kind == 6)
        .filter(matches)
        .collect::<Vec<_>>();
    let exits = events
        .iter()
        .filter(|event| event.kind == 8)
        .filter(matches)
        .collect::<Vec<_>>();
    let [exec] = execs.as_slice() else {
        return fail("public terminal exact exec ambiguous");
    };
    let [exit] = exits.as_slice() else {
        return fail("public terminal exact exit ambiguous");
    };
    let reaps = events
        .iter()
        .filter(|event| {
            event.kind == 9
                && event.other_tid == target.tid
                && u64::try_from(event.syscall_result).ok() == Some(target.start_boottime_ns)
                && event.sequence > exit.sequence
        })
        .collect::<Vec<_>>();
    if reaps.len() != 1
        || exec.monotonic_ns >= held.begin_monotonic_ns
        || reopened.observed_monotonic_ns >= exit.monotonic_ns
        || !original_clock.matches(
            crate::private_kernel_observer::KernelTaskIdentityV1 {
                pid: target.tid,
                start_time: target.start_boottime_ns,
                cgroup_inode: target.cgroup_inode,
                time_ns_inode: exec.task.time_ns_inode,
            },
            held.start_time_ticks,
        )
    {
        return fail("public terminal held midpoint/exec/retirement causal order differs");
    }
    crate::private_public_fault::validate_public_terminal_states(
        checkpoint,
        midpoint,
        terminal_source,
        key,
        &crate::private_public_fault::FaultProcessV1 {
            pid: target.tid,
            start_time: held.start_time_ticks,
        },
        boot,
    )
}

/// Extract only the actual target's namespace PID from its emitted midpoint
/// protocol. This diagnostic parser does not establish execution or custody.
pub fn decode_public_terminal_midpoint_frame(frame: &[u8], challenge: &[u8; 32]) -> Result<u32> {
    let (_, operations) = decode_public_exec_response_frame(
        "private_tcp::release_checkpoint_terminal_joined",
        challenge,
        frame,
    )?
    .ok_or_else(|| CiError::Message("public terminal original emitted response absent".into()))?;
    let magic = b"MCRJOIN1";
    let pid_end = magic.len() + std::mem::size_of::<u32>();
    if operations.len() != pid_end + challenge.len()
        || !operations.starts_with(magic)
        || operations[pid_end..] != *hash_bytes(challenge).bytes()
    {
        return fail("public terminal original held frame differs");
    }
    let namespace_pid = u32::from_le_bytes(
        operations[magic.len()..pid_end]
            .try_into()
            .expect("fixed terminal PID"),
    );
    if namespace_pid == 0 {
        return fail("public terminal original namespace PID absent");
    }
    Ok(namespace_pid)
}

fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

pub(crate) fn verify_public_topology_source(
    origin: &impl crate::private_observer_session::ObserverEvidenceV1,
    expected: &crate::private_candidate_replay::ExpectedCaseSubjectV1,
    facts: &crate::private_candidate_replay::CaseReplayFactsV1,
    case_prefix: &str,
) -> Result<()> {
    use crate::private_kernel_replay::CaptureStageV2;
    let ordinal = memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
        .iter()
        .position(|selector| *selector == expected.selector)
        .ok_or_else(|| CiError::Message("public topology selector outside catalogue".into()))?;
    if std::path::Path::new(case_prefix) != std::path::Path::new("cases").join(ordinal.to_string())
    {
        return fail("public topology original case prefix differs from closed catalogue");
    }
    let path = |name: &str| {
        std::path::Path::new(case_prefix)
            .join(name)
            .to_string_lossy()
            .into_owned()
    };
    let provider = crate::private_public_specialist_replay::provider(origin, &path("provider"))?;
    let expected_init = crate::private_public_fault::public_topology_checkpoint_init(
        &provider,
        expected.selector,
        expected.result_key,
        &origin.descriptor().boot_id,
        expected.filter_sha256,
    )?;
    let record: crate::private_observer_session::ObserverIntervalRecordV1 =
        crate::private_observer_session::strict_json(
            origin.leaf(&path("interval.json"))?,
            64 * 1024,
        )?;
    if record.interval_id != facts.interval_id
        || record.generation != facts.generation
        || record.logical_case_key != *expected.result_key
        || !origin
            .descriptor()
            .intervals
            .iter()
            .any(|enrolled| *enrolled == record)
    {
        return fail("public topology physical source enrollment differs");
    }
    let held = |name: &str| -> Result<crate::private_public_live::HeldPublicTargetSamplesV1> {
        let source = path(name);
        if !record.sample_paths.contains(&source) {
            return fail("public topology original held sample not enrolled");
        }
        crate::private_source_carrier::decode_held_source(origin.leaf(&source)?, |image| {
            origin.leaf(image).map(ToOwned::to_owned)
        })
    };
    let target = held("samples/target-live-sample-v1.json")?;
    let host = held("samples/pre-exec/target-live-sample-v1.json")?;
    let init = held("samples/pre-exec/namespace_init/sample-v1.json")?;
    let clock: crate::private_process_clock::ProcClockInputsV1 =
        crate::private_observer_session::strict_json(origin.leaf(&facts.clock_path)?, 128 * 1024)?;
    let capture = crate::private_kernel_replay::parse_capture_v2_with_budget(
        origin.leaf(&record.capture_path)?,
        expected.result_key,
        CaptureStageV2::FinalPublic,
    )?;
    crate::private_candidate_network_facts::validate_held_topology_sources(
        &target,
        &facts.target,
        capture.events(),
        &clock,
        &host,
        &init,
        &expected_init,
    )?;
    let challenge: &[u8; 32] = expected
        .challenge
        .try_into()
        .map_err(|_| CiError::Message("public topology challenge width differs".into()))?;
    validate_public_topology_response_sources(
        expected.selector,
        challenge,
        expected.port,
        origin.leaf(&path("samples/target-response-at-held-gate.bin"))?,
        &target,
        &facts.target,
        capture.events(),
        &origin.descriptor().subject.target,
    )
}

fn validate_public_topology_response_sources(
    selector: &str,
    challenge: &[u8; 32],
    port: u16,
    frame: &[u8],
    sample: &crate::private_public_live::HeldPublicTargetSamplesV1,
    task: &crate::private_candidate_replay::ReplayTaskV1,
    events: &[crate::private_kernel_replay::KernelEventRecordV2],
    triple: &str,
) -> Result<()> {
    let source = topology_response(selector, decode_public_held_payload(frame)?)?;
    extract_public_fixture_response(selector, challenge, port, frame)?;
    let (listener, connector) =
        crate::private_candidate_network_facts::validate_held_tcp_endpoints(
            sample, task, events, triple, port,
        )?;
    let rows = crate::private_candidate_network_facts::parse_held_tcp_table(
        sample
            .leaves
            .get("net-tcp.raw")
            .ok_or_else(|| CiError::Message("public topology original TCP table absent".into()))?,
    )?;
    if source.tcp.network_namespace_inode != listener.netns_inode
        || !rows.iter().any(|row| {
            row.inode == connector.socket_inode && row.local_port == source.tcp.client_port
        })
    {
        return fail(
            "public topology actual TCP response namespace/client differs from original held endpoints",
        );
    }
    if selector == "private_tcp::namespace_reentry_denied" {
        let operand = source
            .namespace_operand
            .as_ref()
            .ok_or_else(|| CiError::Message("public reentry held NSFS descriptor absent".into()))?;
        let fd = u32::try_from(operand.descriptor)
            .map_err(|_| CiError::Message("public reentry descriptor is negative".into()))?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Descriptor {
            fd: u32,
            link: String,
            device: u64,
            inode: u64,
            mode: u32,
        }
        let name = std::path::Path::new("tasks")
            .join(task.tid.to_string())
            .join("fds")
            .join(fd.to_string())
            .join("identity.json");
        let raw = sample
            .leaves
            .get(name.to_string_lossy().as_ref())
            .ok_or_else(|| {
                CiError::Message("public reentry independently held NSFS identity absent".into())
            })?;
        let held: Descriptor = crate::private_observer_session::strict_json(raw, 4096)?;
        if held.fd != fd
            || held.device != operand.device
            || held.inode != operand.inode
            || held.inode != listener.netns_inode
            || held.link != format!("net:[{}]", held.inode)
            || held.mode & 0o170000 != 0o100000
        {
            return fail("public reentry actual same-network NSFS object differs");
        }
        for (operation, args) in [
            (
                crate::private_case_semantics::NativeOperationV1::Setns,
                [u64::from(fd), 0x40000000],
            ),
            (
                crate::private_case_semantics::NativeOperationV1::Unshare,
                [0x40000000, 0],
            ),
        ] {
            let nr = crate::private_case_semantics::native_syscall_number(triple, operation)?;
            let entries = events
                .iter()
                .filter(|event| {
                    event.kind == 4
                        && crate::private_candidate_network_facts::matches(task, event)
                        && event.syscall_nr == nr
                        && event.args[0] == args[0]
                        && (operation != crate::private_case_semantics::NativeOperationV1::Setns
                            || event.args[1] == args[1])
                })
                .collect::<Vec<_>>();
            let [entry] = entries.as_slice() else {
                return fail("public reentry exact target operation absent/ambiguous");
            };
            if entry.seccomp_action != 0x50000
                || entry.syscall_result != 1
                || crate::private_candidate_network_facts::returned(events, entry)?.syscall_result
                    != -1
            {
                return fail("public reentry actual denied operation differs");
            }
        }
    }
    Ok(())
}
