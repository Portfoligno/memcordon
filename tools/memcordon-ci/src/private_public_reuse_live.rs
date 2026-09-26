//! Actual held-namespace public reuse production. Three physically enrolled
//! intervals retain original durable/provider/CLI bytes; no Candidate marker
//! recovery or diagnostic projection creates public authority.
use crate::{CiError, Result};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use std::path::Path;

const SELECTOR: &str = "private_tcp::retirement_failure_blocks_reuse";
const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HolderFdSourceV1 {
    pid: u32,
    start_time_ticks: u64,
    descriptor: u32,
    device: u64,
    inode: u64,
    link: String,
    fdinfo: Vec<u8>,
    holder_open_sha256: DiagnosticSha256,
    observed_monotonic_ns: u64,
}
/// Diagnostic byte join only. Authority requires the original enrolled
/// holder sample/clock/capture and strong public three-interval compositor.
pub fn validate_holder_fd_source(
    transcript: &[u8],
    source: &[u8],
    holder_open: &[u8],
    pid: u32,
    start: u64,
) -> Result<()> {
    let original: serde_json::Value =
        crate::private_observer_session::strict_json(transcript, 16 * 1024)?;
    let open: serde_json::Value =
        crate::private_observer_session::strict_json(holder_open, 16 * 1024)?;
    let source: HolderFdSourceV1 = crate::private_observer_session::strict_json(source, 16 * 1024)?;
    let number =
        |value: &serde_json::Value, name: &str| value.get(name).and_then(serde_json::Value::as_u64);
    let expected_link = ["net:[", &source.inode.to_string(), "]"].concat();
    let fdinfo = std::str::from_utf8(&source.fdinfo)
        .map_err(|_| CiError::Message("reuse fdinfo not UTF8".into()))?;
    let inodes = fdinfo
        .lines()
        .filter_map(|line| line.strip_prefix("ino:").map(str::trim))
        .collect::<Vec<_>>();
    if source.pid != pid
        || source.start_time_ticks != start
        || source.descriptor <= 2
        || source.device == 0
        || source.inode == 0
        || source.link != expected_link
        || source.holder_open_sha256 != hash_bytes(holder_open)
        || source.observed_monotonic_ns == 0
        || inodes.len() != 1
        || inodes[0].parse::<u64>().ok() != Some(source.inode)
        || number(&original, "holder_pid") != Some(u64::from(pid))
        || number(&original, "holder_start_time") != Some(start)
        || number(&original, "held_fd") != Some(u64::from(source.descriptor))
        || number(&original, "namespace_inode") != Some(source.inode)
        || number(&open, "held_fd") != Some(u64::from(source.descriptor))
        || number(&open, "namespace_inode") != Some(source.inode)
        || open.get("holder").and_then(|value| number(value, "pid")) != Some(u64::from(pid))
        || open
            .get("holder")
            .and_then(|value| number(value, "start_time"))
            != Some(start)
    {
        return Err(CiError::Message(
            "reuse original independently held namespace fd differs".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn run_public_reuse_sources(
    root: &Path,
    target: &str,
    intent: &crate::private_public_driver::ProtectedPublicProducerIntentV2,
    approval: &memcordon_core::private_public_preparation_v2::ApprovedPublicPreparationPolicyV2,
    journal: &mut crate::private_public_producer::PublicObserverProducerV1,
    probe: &crate::private_probe_bundle::VerifiedProbeBundleV1,
    host: &crate::private_final_install::FinalHostReadbackV1,
    context: &crate::private_public_driver::ActualPublicPreparationContextV2,
    prepared_generation: &crate::private_public_plan::PreparedPublicGenerationV1,
    service: &crate::private_kernel_observer::LiveKernelSubjectV1,
    broker: &crate::private_kernel_observer::LiveKernelSubjectV1,
) -> Result<()> {
    use crate::private_kernel_replay::IntervalPurposeV1 as Purpose;
    use crate::private_public_producer::run_public_journal_interval;
    use crate::private_public_raw::PublicLeafKindV1 as Kind;
    use std::io::{Read, Write};
    use std::os::unix::{fs::MetadataExt, net::UnixStream};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    let scenario = intent
        .suite
        .scenarios
        .get(20)
        .ok_or_else(|| CiError::Message("public reuse static recipe absent".into()))?;
    let input = intent
        .cases
        .get(20)
        .ok_or_else(|| CiError::Message("public reuse static input absent".into()))?;
    if scenario.selector != SELECTOR
        || input.selector != SELECTOR
        || context.installation_epoch != *host.installation_epoch()
        || context.active_h1_receipt_sha256 != *host.active_h1_receipt_sha256()
    {
        return Err(CiError::Message(
            "public reuse current installed/static tuple differs".into(),
        ));
    }
    let first_case = journal.prepare_case(SELECTOR, Purpose::ReuseFirst, 0)?;
    let blocked_case = journal.prepare_case(SELECTOR, Purpose::ReuseBlocked, 1)?;
    let recovery_case = journal.prepare_case(SELECTOR, Purpose::Recovery, 2)?;
    if first_case.key != blocked_case.key || first_case.key != recovery_case.key {
        return Err(CiError::Message(
            "public reuse logical parent differs".into(),
        ));
    }
    let challenge = hex::encode(first_case.challenge);
    let key = String::from(first_case.key.clone());
    let template = crate::private_protected_readback::read_protected_raw_case_file(
        &input.contract_template_path,
    )?;
    let fixture = crate::private_public_driver::read_pinned_image(
        &input.fixture_path,
        &scenario.fixture_sha256,
    )?;
    let report_parent = std::fs::symlink_metadata(&input.report_directory)?;
    if !report_parent.is_dir()
        || report_parent.uid() != intent.suite.public_uid
        || report_parent.mode() & 0o7777 != 0o700
    {
        return Err(CiError::Message(
            "public reuse report directory protection differs".into(),
        ));
    }
    let report_path = input.report_directory.join(&key).with_extension("json");
    let inputs = crate::private_public_preparation::prepare_public_contract_inputs(
        &intent.suite,
        prepared_generation,
        approval,
        SELECTOR,
        memcordon_core::private_public_preparation_v2::PublicPreparedRoleV2::Ordinary,
        &template,
        &context.policy_epoch,
        |record| {
            crate::private_observer_session::canonical_bytes(&serde_json::json!({
                "schema_version":1,"source_commit":intent.suite.observer_subject.source_commit,
                "target":target,"manifest_sha256":intent.suite.manifest_sha256,
                "qualification_sha256":intent.suite.qualification_sha256,"public_cli_sha256":intent.suite.public_cli_sha256,
                "public_uid":intent.suite.public_uid,"public_gid":intent.suite.public_gid,
                "historical_e0":null,"historical_spoof":null,"policy":null,
                "cases":[{"selector":record.selector,"challenge":hex::encode(record.challenge),"contract_path":record.contract_path,"contract_sha256":record.contract_file_sha256}]
            }))
        },
    )?;
    if inputs.record.result_key != first_case.key || inputs.record.challenge != first_case.challenge
    {
        return Err(CiError::Message(
            "public reuse prepared admission differs".into(),
        ));
    }
    crate::private_public_preparation::persist_prepared_public_inputs(&inputs)?;
    let abi = match target {
        "x86_64-unknown-linux-gnu" => {
            memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::X86_64LinuxGnu
        }
        "aarch64-unknown-linux-gnu" => {
            memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::Aarch64LinuxGnu
        }
        _ => {
            return Err(CiError::Message(
                "public reuse target is not reviewed GNU ABI".into(),
            ));
        }
    };
    let expected_report = crate::private_public_v2::ExpectedPublicV2Readback {
        source_commit: &intent.suite.observer_subject.source_commit,
        native_abi: abi,
        archive_sha256: &intent.suite.archive_sha256,
        runtime_manifest_sha256: &intent.suite.manifest_sha256,
        qualification_sha256: &intent.suite.qualification_sha256,
        host_receipt_sha256: host.active_h1_receipt_sha256(),
        report_owner_uid: intent.suite.public_uid,
        outcome: crate::private_public_v2::ExpectedPublicV2Outcome::AllocatedUnverified,
    };
    let prefix = Path::new("composites/reuse");
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?
        .trim()
        .to_owned();
    let btf_sha256 = hash_bytes(&std::fs::read("/sys/kernel/btf/vmlinux")?);
    let probe_map_sha256 = probe.attestation_digest();
    let reader = crate::private_kernel_observer::observe_live_kernel_subject(std::process::id())?;
    let expected =
        |key: DiagnosticSha256,
         coordinator: &crate::private_kernel_observer::LiveKernelSubjectV1,
         secondary: &crate::private_kernel_observer::LiveKernelSubjectV1| {
            crate::private_kernel_observer::ExpectedKernelAdapterV1 {
                boot_id: host.boot_id().into(),
                kernel_release: kernel_release.clone(),
                btf_sha256: btf_sha256.clone(),
                probe_map_sha256: probe_map_sha256.clone(),
                result_key: key,
                coordinator_pid: coordinator.pid,
                coordinator_start_time: 0,
                coordinator_start_ticks: coordinator.start_ticks,
                cgroup_inode: coordinator.cgroup_inode,
                broker_pid: secondary.pid,
                broker_start_ticks: secondary.start_ticks,
                broker_cgroup_inode: secondary.cgroup_inode,
            }
        };
    let (mut supervisor_barrier, child_barrier) = UnixStream::pair()?;
    supervisor_barrier.set_read_timeout(Some(Duration::from_secs(150)))?;
    supervisor_barrier.set_write_timeout(Some(Duration::from_secs(30)))?;
    let holder_slot = Arc::new(Mutex::new(None::<OwnedChild>));
    let first_phase = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let first_phase_child = Arc::clone(&first_phase);
    let child_holder = Arc::clone(&holder_slot);
    let holder_challenge = challenge.clone();
    let holder_key = key.clone();
    let holder_root = root.to_path_buf();
    let (observed, first, blocked) = std::thread::scope(|scope| -> Result<_> {
        let mut child = None;
        let (_, first) = run_public_journal_interval(
            journal,
            probe,
            &first_case,
            expected(first_case.key.clone(), &reader, broker),
            expected(first_case.key.clone(), service, broker),
            |journal| {
                for (name, kind, bytes) in [
                    (
                        "prepared-admission.json",
                        Kind::Request,
                        inputs.admission_bytes.clone(),
                    ),
                    (
                        "contract.json",
                        Kind::Request,
                        inputs.contract_bytes.clone(),
                    ),
                    ("fixture.raw", Kind::Case, fixture.clone()),
                ] {
                    journal.append(
                        prefix.join(name).to_string_lossy().into_owned(),
                        kind,
                        bytes,
                    )?;
                }
                let actual_host =
                    crate::command::CommandSpec::new(AGENT, root, Duration::from_secs(30))
                        .remove_github_token()
                        .args(["package", "verify-private-host", "--json"])
                        .run()?;
                let checked_host =
                    crate::private_final_install::FinalHostReadbackV1::parse_bounded(&actual_host)?;
                if checked_host.installation_epoch() != host.installation_epoch()
                    || checked_host.active_h1_receipt_sha256() != host.active_h1_receipt_sha256()
                    || checked_host.agent_sha256() != host.agent_sha256()
                {
                    return Err(CiError::Message(
                        "reuse actual H1 changed before first launch".into(),
                    ));
                }
                journal.append(
                    "composites/reuse/host.json".into(),
                    Kind::Installed,
                    actual_host,
                )?;
                child = Some(scope.spawn(|| {
                    crate::private_public_dispatch::run_installed_public_reuse_source_case(
                        root,
                        &challenge,
                        &intent.suite.public_cli_sha256,
                        Path::new(&inputs.record.contract_path),
                        &report_path,
                        &input.fixture_path,
                        &input.report_directory,
                        intent.suite.public_uid,
                        intent.suite.public_gid,
                        &expected_report,
                        child_barrier,
                        Box::new(move || {
                            let process = std::process::Command::new(AGENT)
                                .args([
                                    "package",
                                    "public-reuse-hold",
                                    "--selector",
                                    SELECTOR,
                                    "--challenge",
                                    &holder_challenge,
                                    "--dispatch-key",
                                    &holder_key,
                                ])
                                .env_clear()
                                .current_dir(holder_root)
                                .stdin(std::process::Stdio::null())
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .spawn()?;
                            *child_holder.lock().map_err(|_| {
                                std::io::Error::other("reuse holder lock poisoned")
                            })? = Some(OwnedChild(process));
                            Ok(())
                        }),
                        prefix,
                        first_phase_child,
                    )
                }));
                let mut ready = [0];
                supervisor_barrier.read_exact(&mut ready)?;
                if ready != *b"R" {
                    return Err(CiError::Message(
                        "public reuse first settled barrier differs".into(),
                    ));
                }
                Ok(())
            },
        )?;
        let timing = first
            .interval
            .observation_timing()
            .ok_or_else(|| CiError::Message("public reuse first timing absent".into()))?;
        let mut first_samples = vec![
            prefix
                .join("prepared-admission.json")
                .to_string_lossy()
                .into_owned(),
        ];
        for (name, bytes) in first_phase
            .lock()
            .map_err(|_| CiError::Message("reuse first sources lock poisoned".into()))?
            .iter()
        {
            let path = prefix
                .join("samples")
                .join(name)
                .to_string_lossy()
                .into_owned();
            journal.append(path.clone(), Kind::LiveSample, bytes.clone())?;
            first_samples.push(path);
        }
        journal.retain_interval_with_record(
            &first_case,
            &first.interval,
            vec![first.controls_path.clone()],
            first_samples,
            timing.armed_monotonic_ns,
            timing.operation_end_monotonic_ns,
            timing.detached_monotonic_ns,
            Some(
                prefix
                    .join("first-interval.json")
                    .to_string_lossy()
                    .into_owned(),
            ),
        )?;
        let (observed, blocked) = run_public_journal_interval(
            journal,
            probe,
            &blocked_case,
            expected(blocked_case.key.clone(), &reader, broker),
            expected(blocked_case.key.clone(), service, broker),
            |_| {
                supervisor_barrier.write_all(b"G")?;
                child
                    .take()
                    .ok_or_else(|| CiError::Message("reuse CLI supervisor absent".into()))?
                    .join()
                    .map_err(|_| CiError::Message("reuse CLI supervisor panicked".into()))?
            },
        )?;
        let timing = blocked
            .interval
            .observation_timing()
            .ok_or_else(|| CiError::Message("public reuse blocked timing absent".into()))?;
        let mut samples = Vec::new();
        for (name, bytes) in &observed.live_samples {
            if let Some(original) = first_phase
                .lock()
                .map_err(|_| CiError::Message("reuse first sources lock poisoned".into()))?
                .get(name)
            {
                if original != bytes {
                    return Err(CiError::Message(
                        "reuse original held source changed after first close".into(),
                    ));
                }
                continue;
            }
            let path = prefix
                .join("samples")
                .join(name)
                .to_string_lossy()
                .into_owned();
            journal.append(path.clone(), Kind::LiveSample, bytes.clone())?;
            samples.push(path);
        }
        journal.retain_interval_with_record(
            &blocked_case,
            &blocked.interval,
            vec![blocked.controls_path.clone()],
            samples,
            timing.armed_monotonic_ns,
            timing.operation_end_monotonic_ns,
            timing.detached_monotonic_ns,
            Some(
                prefix
                    .join("blocked-interval.json")
                    .to_string_lossy()
                    .into_owned(),
            ),
        )?;
        Ok((observed, first, blocked))
    })?;
    let mut holder = holder_slot
        .lock()
        .map_err(|_| CiError::Message("reuse holder lock poisoned".into()))?
        .take()
        .ok_or_else(|| CiError::Message("reuse holder missing".into()))?;
    let holder_subject =
        crate::private_kernel_observer::observe_live_kernel_subject(holder.0.id())?;
    let journal_directory = Path::new("/var/lib/memcordon/sealed/private-public-reuse").join(&key);
    let read = |name: &str| {
        crate::private_protected_readback::read_protected_raw_case_file(
            &journal_directory.join(name),
        )
    };
    let holder_open = read("holder-open.json")?;
    let open: serde_json::Value =
        crate::private_observer_session::strict_json(&holder_open, 16 * 1024)?;
    let held_fd = open
        .get("held_fd")
        .and_then(serde_json::Value::as_u64)
        .and_then(|fd| u32::try_from(fd).ok())
        .ok_or_else(|| CiError::Message("reuse held fd absent".into()))?;
    let fdpath = Path::new("/proc")
        .join(holder_subject.pid.to_string())
        .join("fd")
        .join(held_fd.to_string());
    let mut recovery = OwnedChild(
        std::process::Command::new(AGENT)
            .args([
                "package",
                "public-reuse-release-and-recover",
                "--selector",
                SELECTOR,
                "--challenge",
                &challenge,
                "--dispatch-key",
                &key,
            ])
            .env_clear()
            .current_dir(root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?,
    );
    let (holder_clock, recovered) = run_public_journal_interval(
        journal,
        probe,
        &recovery_case,
        expected(recovery_case.key.clone(), &reader, broker),
        expected(recovery_case.key.clone(), &holder_subject, service),
        |journal| {
            let clock =
                crate::private_process_clock::VerifiedProcClockCalibrationV1::observe_live_reader(
                    holder_subject.pid,
                    holder_subject.start_ticks,
                )?;
            crate::private_process_clock::require_live_start_ticks(
                holder_subject.pid,
                holder_subject.start_ticks,
            )?;
            let fdmeta = std::fs::metadata(&fdpath)?;
            let fdinfo = std::fs::read(
                Path::new("/proc")
                    .join(holder_subject.pid.to_string())
                    .join("fdinfo")
                    .join(held_fd.to_string()),
            )?;
            let fdlink = std::fs::read_link(&fdpath)?;
            let held = crate::private_public_live::sample_held_target_raw(
                holder_subject.pid,
                holder_subject.start_ticks,
                host.agent_sha256(),
            )?;
            let after = std::fs::metadata(&fdpath)?;
            crate::private_process_clock::require_live_start_ticks(
                holder_subject.pid,
                holder_subject.start_ticks,
            )?;
            if (fdmeta.dev(), fdmeta.ino()) != (after.dev(), after.ino())
                || open
                    .get("namespace_inode")
                    .and_then(serde_json::Value::as_u64)
                    != Some(fdmeta.ino())
            {
                return Err(CiError::Message(
                    "reuse actual held namespace changed while sampled".into(),
                ));
            }
            let holder_image_path = "composites/reuse/holder-image.raw";
            journal.append(
                holder_image_path.into(),
                Kind::LiveSample,
                held.leaves
                    .get("image.raw")
                    .ok_or_else(|| {
                        CiError::Message("reuse actual holder image bytes absent".into())
                    })?
                    .clone(),
            )?;
            journal.append(
                "composites/reuse/holder-sample.bin".into(),
                Kind::LiveSample,
                crate::private_source_carrier::encode_held_source(&held, holder_image_path.into())?,
            )?;
            journal.append(
                prefix
                    .join("holder-clock.json")
                    .to_string_lossy()
                    .into_owned(),
                Kind::LiveSample,
                crate::private_observer_session::canonical_bytes(
                    clock
                        .inputs()
                        .ok_or_else(|| CiError::Message("reuse holder raw clock absent".into()))?,
                )?,
            )?;
            journal.append(prefix.join("holder-identity.json").to_string_lossy().into_owned(),Kind::LiveSample,crate::private_observer_session::canonical_bytes(&serde_json::json!({"pid":holder_subject.pid,"start_time_ticks":holder_subject.start_ticks,"cgroup_inode":holder_subject.cgroup_inode}))?)?;
            journal.append(prefix.join("holder-namespace-fd.bin").to_string_lossy().into_owned(),Kind::LiveSample,crate::private_observer_session::canonical_bytes(&serde_json::json!({"pid":holder_subject.pid,"start_time_ticks":holder_subject.start_ticks,"descriptor":held_fd,"device":fdmeta.dev(),"inode":fdmeta.ino(),"link":fdlink.to_string_lossy(),"fdinfo":fdinfo,"holder_open_sha256":hash_bytes(&holder_open),"observed_monotonic_ns":held.begin_monotonic_ns}))?)?;
            recovery
                .0
                .stdin
                .take()
                .ok_or_else(|| CiError::Message("reuse recovery gate absent".into()))?
                .write_all(b"G")?;
            wait_success(&mut recovery.0)?;
            wait_success(&mut holder.0)?;
            Ok(clock)
        },
    )?;
    let (provider_record, provider_leaves) =
        crate::private_public_dispatch::read_original_public_provider_sources(
            SELECTOR,
            &challenge,
            &first_case.key,
        )?;
    let provider = crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
        &provider_record,
        &provider_leaves,
    )?;
    let transcript = read("reuse.json")?;
    let incomplete = read("incomplete-v4.bin")?;
    let failure = read("first-failure.bin")?;
    let blocked_request = read("blocked-request.bin")?;
    let rejection = read("blocked-rejection.bin")?;
    let cleanup = read("recovered-cleanup.bin")?;
    let detached = crate::command::CommandSpec::new(AGENT, root, Duration::from_secs(30))
        .remove_github_token()
        .args([
            "package",
            "public-reuse-verify",
            "--selector",
            SELECTOR,
            "--challenge",
            &challenge,
            "--dispatch-key",
            &key,
        ])
        .run()?;
    let [first_attempt, blocked_attempt] = provider.attempts.as_slice() else {
        return Err(CiError::Message(
            "public reuse original ordered attempts differ".into(),
        ));
    };
    let first_clock = first
        .interval
        .original_clock()
        .ok_or_else(|| CiError::Message("reuse original first clock absent".into()))?;
    let joined = crate::private_public_reuse_join::join_public_reuse_v1(
        &crate::private_public_reuse_join::ExpectedPublicReuseLiveV1 {
            protected_record_bytes: &transcript,
            detached_stdout: &detached,
            detached: crate::private_public_reuse_join::ExpectedPublicReuseV1 {
                result_key: &first_case.key,
                boot_id: host.boot_id(),
                installation_epoch: host.installation_epoch(),
                active_h1_receipt_sha256: host.active_h1_receipt_sha256(),
                first_attempt_id: &first_attempt.attempt_id,
                second_attempt_id: &blocked_attempt.attempt_id,
                cleanup_failure_bytes: &failure,
                blocked_request_bytes: &blocked_request,
                blocked_rejection_bytes: &rejection,
                recovered_cleanup_bytes: &cleanup,
                expected_failure_code: "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE",
                expected_blocked_code: "MCSEALED-PRIVATE-REUSE-BLOCKED",
            },
            provider: &provider,
            first_clock,
            holder_clock: &holder_clock,
            first_interval: &first.interval,
            blocked_interval: &blocked.interval,
            recovery_interval: &recovered.interval,
        },
    )?;
    let child = observed
        .process
        .linux_child
        .ok_or_else(|| CiError::Message("reuse real CLI child absent".into()))?;
    let report = observed
        .report_bytes
        .as_ref()
        .ok_or_else(|| CiError::Message("reuse CLI raw report absent".into()))?;
    let composite = memcordon_core::private_public_reuse_composite_v1::PublicReuseCompositeCaseV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        challenge: first_case.challenge,
        source_commit: intent.suite.observer_subject.source_commit.clone(),
        release_version: memcordon_core::BoundedText::new(host.version())
            .map_err(|e| CiError::Message(e.into()))?,
        target: host.target().into(),
        native_machine: host.native_machine().into(),
        archive_sha256: intent.suite.archive_sha256.clone(),
        manifest_sha256: host.manifest_sha256().clone(),
        qualification_sha256: host.qualification_sha256().clone(),
        active_h1_receipt_sha256: host.active_h1_receipt_sha256().clone(),
        installation_epoch: host.installation_epoch().clone(),
        child: memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2 {
            pid: child.pid,
            start_time_ticks: child.start_time_ticks,
            boot_identity: memcordon_core::BoundedText::new(host.boot_id())
                .map_err(|e| CiError::Message(e.into()))?,
            uid: intent.suite.public_uid,
            gid: intent.suite.public_gid,
            supplementary_groups_empty: true,
            executable_sha256: observed.cli_sha256.clone(),
            argv_sha256: observed.argv_sha256.clone(),
            working_directory_sha256: observed.working_directory_sha256.clone(),
        },
        provider_sha256: hash_bytes(&provider_record),
        report_sha256: hash_bytes(report),
        stdio_sha256: hash_bytes(&observed.stdio_bytes),
        first_failure_sha256: joined.cleanup_failure_sha256().clone(),
        blocked_rejection_sha256: joined.blocked_rejection_sha256().clone(),
        recovered_cleanup_sha256: joined.recovered_cleanup_sha256().clone(),
        durable_incomplete_snapshot_sha256: hash_bytes(&incomplete),
        protected_reuse_transcript_sha256: hash_bytes(&transcript),
        semantic_join_sha256: joined.transcript_sha256().clone(),
        first_kernel_capture_sha256: first.interval.trace_sha256().clone(),
        blocked_kernel_capture_sha256: blocked.interval.trace_sha256().clone(),
        recovery_kernel_capture_sha256: recovered.interval.trace_sha256().clone(),
    };
    for (name, kind, bytes) in [
        ("provider/record.json", Kind::Provider, provider_record),
        ("cli/report.json", Kind::Report, report.clone()),
        ("cli/stdio.bin", Kind::Stdio, observed.stdio_bytes),
        ("reuse.json", Kind::Case, transcript),
        ("incomplete-v4.bin", Kind::Checkpoint, incomplete),
        ("first-failure.bin", Kind::Response, failure),
        ("blocked-request.bin", Kind::Request, blocked_request),
        ("blocked-rejection.bin", Kind::Response, rejection),
        ("recovered-cleanup.bin", Kind::Cleanup, cleanup),
        ("detached-readback.bin", Kind::Report, detached),
        ("holder-open.json", Kind::LiveSample, holder_open),
    ] {
        journal.append(
            prefix.join(name).to_string_lossy().into_owned(),
            kind,
            bytes,
        )?;
    }
    for (name, bytes) in provider_leaves {
        journal.append(
            prefix
                .join("provider/raw")
                .join(name)
                .to_string_lossy()
                .into_owned(),
            Kind::Provider,
            bytes,
        )?;
    }
    let timing = recovered
        .interval
        .observation_timing()
        .ok_or_else(|| CiError::Message("reuse recovery timing absent".into()))?;
    journal.retain_interval_with_record(
        &recovery_case,
        &recovered.interval,
        vec![recovered.controls_path],
        vec![
            "composites/reuse/holder-clock.json".into(),
            "composites/reuse/holder-identity.json".into(),
            "composites/reuse/holder-namespace-fd.bin".into(),
            "composites/reuse/holder-sample.bin".into(),
            "composites/reuse/holder-image.raw".into(),
        ],
        timing.armed_monotonic_ns,
        timing.operation_end_monotonic_ns,
        timing.detached_monotonic_ns,
        Some("composites/reuse/recovery-interval.json".into()),
    )?;
    let composite = serde_json::to_vec(&composite)?;
    memcordon_core::private_public_reuse_composite_v1::PublicReuseCompositeCaseV1::parse(
        &composite,
    )
    .map_err(CiError::Message)?;
    journal.append_representation(
        "composites/reuse/composite.json".into(),
        Kind::Case,
        composite,
    )
}

#[cfg(target_os = "linux")]
struct OwnedChild(std::process::Child);
#[cfg(target_os = "linux")]
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
#[cfg(target_os = "linux")]
fn wait_success(child: &mut std::process::Child) -> Result<()> {
    let begin = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(CiError::Message("public reuse owned helper failed".into()));
            }
            return Ok(());
        }
        if begin.elapsed() > std::time::Duration::from_secs(60) {
            child.kill()?;
            child.wait()?;
            return Err(CiError::Message("public reuse helper deadline".into()));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
