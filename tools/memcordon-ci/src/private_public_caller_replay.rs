//! Public-only caller source conjunction. A policy rejection or a held peer
//! receipt alone cannot establish the caller lifecycle or non-allocation.
use crate::private_kernel_replay::KernelEventRecordV2;
use crate::private_observer_session::{ObserverIntervalRecordV1, ObserverSessionDescriptorV1};
use crate::private_public_plan::StaticPublicSuiteIntentV1;
use crate::{CiError, Result};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallerIdentityV1 {
    pid: u32,
    start_time_ticks: u64,
    uid: u32,
    gid: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicCallerGateV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    prepared_admission_sha256: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    runtime_manifest_sha256: DiagnosticSha256,
    installed_qualification_sha256: DiagnosticSha256,
    request_sha256: DiagnosticSha256,
    caller: CallerIdentityV1,
    observed_monotonic_ns: u64,
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

pub(crate) fn validate_public_caller_sources(
    intent: &StaticPublicSuiteIntentV1,
    descriptor: &ObserverSessionDescriptorV1,
    record: &ObserverIntervalRecordV1,
    events: &[KernelEventRecordV2],
    clock: &crate::private_process_clock::ProcClockInputsV1,
    leaf: impl Fn(&str) -> Result<Vec<u8>>,
) -> Result<()> {
    use memcordon_core::private_public_preparation_v2::{
        PreparedPublicDispatchRecordV2, PublicPreparedRoleV2,
    };
    let selector = "private_tcp::caller_identity_and_epoch_bound";
    if descriptor.subject.stage != crate::private_observer_session::ObserverStageV1::Public
        || descriptor.subject != intent.observer_subject
        || record.purpose != "caller-spoof"
        || record.ordinal != 0
        || record.loss_count != 0
    {
        return fail("public caller source subject or physical role differs");
    }
    let generation = descriptor
        .generations
        .iter()
        .find(|generation| generation.generation == record.generation)
        .ok_or_else(|| CiError::Message("public caller installed generation absent".into()))?;
    let admission_bytes = leaf("historical/spoof/prepared-admission.json")?;
    let admission: PreparedPublicDispatchRecordV2 =
        crate::private_observer_session::strict_json(&admission_bytes, 1024 * 1024)?;
    let challenge = crate::private_public_plan::prepared_public_spoof_challenge_v1(
        intent,
        &descriptor.session_nonce,
        record.generation,
    )?;
    let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
        memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
        selector,
        &challenge,
    )
    .map_err(CiError::Message)?;
    let gate_path = "historical/spoof/samples/caller-spoof/gate.json";
    let held_path = "historical/spoof/samples/caller-spoof/sample-v1.json";
    let ack_path = "historical/spoof/samples/caller-spoof/ack.bin";
    for path in [
        gate_path,
        held_path,
        ack_path,
        "historical/spoof/prepared-admission.json",
    ] {
        if !record.sample_paths.iter().any(|sample| sample == path) {
            return fail("public caller original physical sample not enrolled");
        }
    }
    let gate_bytes = leaf(gate_path)?;
    let gate: PublicCallerGateV1 =
        crate::private_observer_session::strict_json(&gate_bytes, 16 * 1024)?;
    let request = leaf("historical/spoof/request.bin")?;
    let sample = crate::private_source_carrier::decode_held_source(&leaf(held_path)?, &leaf)?;
    if admission.schema_version != 2
        || admission.role != PublicPreparedRoleV2::CallerSpoof
        || admission.static_suite_sha256 != intent.identity_sha256()?
        || admission.selector != selector
        || hex::encode(admission.session_nonce) != descriptor.session_nonce
        || admission.generation != record.generation
        || admission.result_key != key
        || admission.challenge != challenge
        || record.logical_case_key != key
        || admission.installation_epoch != generation.installation_epoch
        || admission.active_h1_receipt_sha256 != generation.installed_receipt_sha256
        || admission.contract_file_sha256 != hash_bytes(&request)
        || gate.schema_version != 1
        || gate.selector != selector
        || gate.result_key != key
        || gate.prepared_admission_sha256 != hash_bytes(&admission_bytes)
        || gate.installation_epoch != generation.installation_epoch
        || gate.active_h1_receipt_sha256 != generation.installed_receipt_sha256
        || gate.runtime_manifest_sha256 != intent.manifest_sha256
        || gate.installed_qualification_sha256 != intent.qualification_sha256
        || gate.request_sha256 != hash_bytes(&request)
        || leaf(ack_path)? != hash_bytes(&gate_bytes).bytes()
        || gate.caller.pid != sample.pid
        || gate.caller.start_time_ticks != sample.start_time_ticks
        || gate.caller.uid != intent.historical_spoof_uid
        || gate.caller.gid != intent.historical_spoof_gid
        || sample.schema_version != 1
        || sample.executable_sha256 != intent.public_cli_sha256
        || sample
            .leaves
            .get("image.raw")
            .map(|image| hash_bytes(image))
            != Some(intent.public_cli_sha256.clone())
        || sample.pid == 0
        || sample.start_time_ticks == 0
        || sample.executable_device == 0
        || sample.executable_inode == 0
        || gate.observed_monotonic_ns < record.begin_monotonic_ns
        || gate.observed_monotonic_ns > sample.begin_monotonic_ns
        || sample.begin_monotonic_ns > sample.end_monotonic_ns
        || sample.end_monotonic_ns > record.end_monotonic_ns
    {
        return fail("public caller original admission/peer/image/gate/timing differs");
    }
    let raw = |name: &str| -> Result<&[u8]> {
        sample
            .leaves
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| CiError::Message("public caller original proc leaf absent".into()))
    };
    for name in ["stat-before.raw", "stat-after.raw"] {
        let stat = std::str::from_utf8(raw(name)?)
            .map_err(|_| CiError::Message("public caller stat not text".into()))?;
        let end = stat
            .rfind(')')
            .ok_or_else(|| CiError::Message("public caller stat command absent".into()))?;
        if stat
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            != Some(sample.pid)
            || stat[end + 1..]
                .split_whitespace()
                .nth(19)
                .and_then(|value| value.parse::<u64>().ok())
                != Some(sample.start_time_ticks)
        {
            return fail("public caller independently sampled PID/start aliases");
        }
    }
    let status = std::str::from_utf8(raw("status.raw")?)
        .map_err(|_| CiError::Message("public caller status not text".into()))?;
    for (field, expected) in [
        ("Pid:", vec![sample.pid]),
        ("Tgid:", vec![sample.pid]),
        ("Uid:", vec![intent.historical_spoof_uid; 4]),
        ("Gid:", vec![intent.historical_spoof_gid; 4]),
        ("Groups:", Vec::new()),
    ] {
        let values = status
            .lines()
            .filter_map(|line| line.strip_prefix(field))
            .collect::<Vec<_>>();
        let [value] = values.as_slice() else {
            return fail("public caller held credential field absent/duplicated");
        };
        let actual = value
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| CiError::Message("public caller raw credential invalid".into()))?;
        if actual != expected {
            return fail("public caller independently sampled credentials differ");
        }
    }
    let argv_raw = raw("cmdline.raw")?;
    let argv = argv_raw
        .strip_suffix(&[0])
        .ok_or_else(|| CiError::Message("public caller argv lacks final NUL".into()))?
        .split(|byte| *byte == 0)
        .map(std::str::from_utf8)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| CiError::Message("public caller argv not UTF-8".into()))?;
    let [
        cli,
        sealed,
        contract_flag,
        contract_path,
        report_flag,
        report_path,
        boundary,
        fixture,
        verb,
        actual_selector,
        challenge_flag,
        actual_challenge,
    ] = argv.as_slice()
    else {
        return fail("public caller exact argv shape differs");
    };
    if *cli != "/usr/bin/memcordon"
        || *sealed != "--sealed"
        || *contract_flag != "--workload-contract"
        || *contract_path != admission.contract_path
        || *report_flag != "--report"
        || *boundary != "--"
        || *fixture != "/usr/libexec/memcordon-sealed-agent"
        || *verb != "public-release-fixture"
        || *actual_selector != selector
        || *challenge_flag != "--challenge"
        || *actual_challenge != hex::encode(challenge)
        || !std::path::Path::new(report_path).is_absolute()
        || std::path::Path::new(report_path)
            .file_stem()
            .and_then(|value| value.to_str())
            != Some(String::from(key.clone()).as_str())
    {
        return fail("public caller measured installed argv differs from approved request role");
    }
    let calibration = crate::private_process_clock::ParsedProcClockCalibrationV1::parse(clock)?;
    let matches = |event: &KernelEventRecordV2| {
        event.task.tid == sample.pid
            && event.task.tgid == sample.pid
            && calibration.matches(
                crate::private_kernel_observer::KernelTaskIdentityV1 {
                    pid: event.task.tid,
                    start_time: event.task.start_boottime_ns,
                    cgroup_inode: event.task.cgroup_inode,
                    time_ns_inode: event.task.time_ns_inode,
                },
                sample.start_time_ticks,
            )
    };
    let one = |kind| -> Result<&KernelEventRecordV2> {
        let matches = events
            .iter()
            .filter(|event| event.kind == kind && matches(event))
            .collect::<Vec<_>>();
        let [event] = matches.as_slice() else {
            return fail("public caller actual lifecycle event absent/ambiguous");
        };
        Ok(*event)
    };
    let exec = one(6)?;
    let exit = one(8)?;
    let supervisor = leaf("historical/spoof/cli/stdio.bin")?;
    let mut supervisor = supervisor
        .strip_prefix(b"memcordon/public-stdio/v1\0")
        .ok_or_else(|| CiError::Message("public caller supervisor stdio domain differs".into()))?;
    fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N]> {
        let value = bytes
            .get(..N)
            .ok_or_else(|| CiError::Message("public caller supervisor frame truncated".into()))?
            .try_into()
            .expect("bounded supervisor field");
        *bytes = &bytes[N..];
        Ok(value)
    }
    let supervised_pid = u32::from_le_bytes(take(&mut supervisor)?);
    let supervised_start = u64::from_le_bytes(take(&mut supervisor)?);
    let supervised_status = i32::from_le_bytes(take(&mut supervisor)?);
    let stdout_len = u32::from_le_bytes(take(&mut supervisor)?) as usize;
    if stdout_len > 1024 * 1024 || supervisor.len() < stdout_len {
        return fail("public caller supervisor stdout bound differs");
    }
    supervisor = &supervisor[stdout_len..];
    let stderr_len = u32::from_le_bytes(take(&mut supervisor)?) as usize;
    if stderr_len > 1024 * 1024
        || supervisor.len() != stderr_len
        || supervised_pid != sample.pid
        || supervised_start != sample.start_time_ticks
        || i64::from(supervised_status) != exit.syscall_result
    {
        return fail(
            "public caller actual supervisor identity/status differs from original kernel exit",
        );
    }
    let forks = events
        .iter()
        .filter(|event| event.kind == 7 && event.other_tid == sample.pid)
        .collect::<Vec<_>>();
    let [fork] = forks.as_slice() else {
        return fail("public caller owned fork absent/ambiguous");
    };
    let reaps = events
        .iter()
        .filter(|event| {
            event.kind == 9
                && event.other_tid == sample.pid
                && u64::try_from(event.syscall_result).ok() == Some(exit.task.start_boottime_ns)
        })
        .collect::<Vec<_>>();
    let [reap] = reaps.as_slice() else {
        return fail("public caller original reap absent/ambiguous");
    };
    let enters = events
        .iter()
        .filter(|event| event.kind == 1)
        .collect::<Vec<_>>();
    let ends = events
        .iter()
        .filter(|event| event.kind == 2)
        .collect::<Vec<_>>();
    let ([enter], [end]) = (enters.as_slice(), ends.as_slice()) else {
        return fail("public caller actual decision bracket absent/ambiguous");
    };
    let (reader_pid, reader_ticks) = calibration.reader_identity();
    let reader = |event: &KernelEventRecordV2| {
        event.task.tid == reader_pid
            && event.task.tgid == reader_pid
            && calibration.matches(
                crate::private_kernel_observer::KernelTaskIdentityV1 {
                    pid: event.task.tid,
                    start_time: event.task.start_boottime_ns,
                    cgroup_inode: event.task.cgroup_inode,
                    time_ns_inode: event.task.time_ns_inode,
                },
                reader_ticks,
            )
    };
    if !reader(fork)
        || !reader(reap)
        || fork.sequence >= exec.sequence
        || exec.sequence >= enter.sequence
        || exec.image_dev != sample.executable_device
        || exec.image_inode != sample.executable_inode
        || enter.monotonic_ns > gate.observed_monotonic_ns
        || end.monotonic_ns < sample.end_monotonic_ns
        || end.sequence >= exit.sequence
        || exit.sequence >= reap.sequence
        || reap.monotonic_ns > record.end_monotonic_ns
        || events.iter().any(|event| {
            event.kind == 3
                || matches!(event.kind, 6 | 7)
                    && event.sequence > enter.sequence
                    && event.sequence < end.sequence
        })
    {
        return fail(
            "public caller actual fork/installed exec/held decision/exit/reap/no-allocation chain differs",
        );
    }
    Ok(())
}

pub(crate) fn assemble_public_caller_facts(bytes: &[u8], target: &str) -> Result<Vec<u8>> {
    let mut facts: crate::private_candidate_replay::CaseReplayFactsV1 =
        crate::private_observer_session::strict_json(bytes, 1024 * 1024)?;
    if facts.selector != "private_tcp::caller_identity_and_epoch_bound" {
        return fail("public caller common representation selector differs");
    }
    facts.facts.push(
        crate::private_candidate_replay::CaseFactV1::PublicCallerEpochV1 {
            static_intent_path: "installed/static-suite-intent.json".into(),
        },
    );
    let spec = crate::private_case_semantics::closed_case_spec(&facts.selector, target)?;
    let mut selected = Vec::new();
    for kind in spec.facts {
        let matches = facts
            .facts
            .iter()
            .filter(|fact| fact.kind() == kind)
            .collect::<Vec<_>>();
        let [fact] = matches.as_slice() else {
            return fail("public caller exact complete source family absent/duplicated");
        };
        selected.push((*fact).clone());
    }
    facts.facts = selected;
    crate::private_observer_session::canonical_bytes(&facts)
}
