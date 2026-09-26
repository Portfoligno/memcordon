//! Distinct final-public ABI outer/filtered physical source orchestration.
//! Structural composites are independently replayed after completed Actions
//! provenance. No candidate proof or old dispatch intent is synthesized.
#[cfg(target_os = "linux")]
use crate::private_kernel_observer::{ExpectedKernelAdapterV1, LiveKernelSubjectV1};
#[cfg(target_os = "linux")]
use crate::private_public_driver::{
    ActualPublicPreparationContextV2, ProtectedPublicProducerIntentV2,
};
#[cfg(target_os = "linux")]
use crate::private_public_plan::PreparedPublicGenerationV1;
#[cfg(target_os = "linux")]
use crate::private_public_producer::{PublicObserverProducerV1, run_public_journal_interval};
#[cfg(target_os = "linux")]
use crate::private_public_raw::PublicLeafKindV1 as Kind;
#[cfg(target_os = "linux")]
use crate::{CiError, Result};
#[cfg(target_os = "linux")]
use memcordon_core::private_public_preparation_v2::{
    ApprovedPublicPreparationPolicyV2, PublicPreparedRoleV2,
};
#[cfg(target_os = "linux")]
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

#[cfg(target_os = "linux")]
pub(crate) fn run_public_abi_sources(
    root: &Path,
    target: &str,
    intent: &ProtectedPublicProducerIntentV2,
    approval: &ApprovedPublicPreparationPolicyV2,
    journal: &mut PublicObserverProducerV1,
    probe: &crate::private_probe_bundle::VerifiedProbeBundleV1,
    host: &crate::private_final_install::FinalHostReadbackV1,
    host_bytes: &[u8],
    context: &ActualPublicPreparationContextV2,
    prepared_generation: &PreparedPublicGenerationV1,
    service: &LiveKernelSubjectV1,
    broker: &LiveKernelSubjectV1,
) -> Result<()> {
    use crate::private_kernel_replay::IntervalPurposeV1;
    use crate::private_public_abi_filtered::*;
    use crate::private_public_abi_outer::*;
    use memcordon_core::private_public_abi_composite_v1::{
        PUBLIC_ABI_SELECTOR_V1, PublicAbiCompositeCaseV1,
    };
    use memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let original_host =
        crate::private_final_install::FinalHostReadbackV1::parse_bounded(host_bytes)?;
    if original_host.source_commit() != host.source_commit()
        || original_host.target() != host.target()
        || original_host.version() != host.version()
        || original_host.native_machine() != host.native_machine()
        || original_host.boot_id() != host.boot_id()
        || original_host.installation_epoch() != host.installation_epoch()
        || original_host.manifest_sha256() != host.manifest_sha256()
        || original_host.qualification_sha256() != host.qualification_sha256()
        || original_host.public_cli_sha256() != host.public_cli_sha256()
        || original_host.agent_sha256() != host.agent_sha256()
        || original_host.arm32_helper_sha256() != host.arm32_helper_sha256()
        || original_host.active_h1_receipt_sha256() != host.active_h1_receipt_sha256()
        || original_host.filter_sha256() != host.filter_sha256()
    {
        return fail("public ABI original host bytes differ from observed generation");
    }
    let input = intent
        .cases
        .iter()
        .find(|case| case.selector == PUBLIC_ABI_SELECTOR_V1)
        .ok_or_else(|| CiError::Message("public ABI static case inputs absent".into()))?;
    let scenario = intent
        .suite
        .scenarios
        .iter()
        .find(|case| case.selector == PUBLIC_ABI_SELECTOR_V1)
        .ok_or_else(|| CiError::Message("public ABI approved scenario absent".into()))?;
    if target != host.target()
        || target != intent.suite.observer_subject.target
        || prepared_generation.generation().generation != 1
        || host.installation_epoch() != &context.installation_epoch
        || host.active_h1_receipt_sha256() != &context.active_h1_receipt_sha256
        || scenario.fixture_sha256 != *host.agent_sha256()
        || scenario.recipe.filter_sha256 != *host.filter_sha256()
    {
        return fail("public ABI source is not the independently observed approved E1 fixture");
    }
    let template = crate::private_protected_readback::read_protected_raw_case_file(
        &input.contract_template_path,
    )?;
    if hash_bytes(&template) != scenario.contract_template_sha256 {
        return fail("public ABI template pin differs");
    }
    let fixture = crate::private_public_driver::read_pinned_image(
        &input.fixture_path,
        &scenario.fixture_sha256,
    )?;
    let parent = std::fs::symlink_metadata(&input.report_directory)?;
    if !parent.is_dir()
        || parent.uid() != intent.suite.public_uid
        || parent.gid() != intent.suite.public_gid
        || parent.mode() & 0o7777 != 0o700
    {
        return fail("public ABI report parent is not exact protected nonroot directory");
    }
    let case = journal.prepare_case(PUBLIC_ABI_SELECTOR_V1, IntervalPurposeV1::AbiFiltered, 0)?;
    let challenge = hex::encode(case.challenge);
    if case.argv
        != vec![
            input.fixture_path.to_string_lossy().into_owned(),
            "public-abi-filtered-target".into(),
            "--challenge".into(),
            challenge.clone(),
        ]
    {
        return fail("public ABI exact approved entrypoint argv differs");
    }
    let inputs = crate::private_public_preparation::prepare_public_contract_inputs(
        &intent.suite,
        prepared_generation,
        approval,
        PUBLIC_ABI_SELECTOR_V1,
        PublicPreparedRoleV2::Ordinary,
        &template,
        &context.policy_epoch,
        |record| {
            crate::private_observer_session::canonical_bytes(
                &serde_json::json!({"schema_version":1,"source_commit":intent.suite.observer_subject.source_commit,"target":target,"manifest_sha256":intent.suite.manifest_sha256,"qualification_sha256":intent.suite.qualification_sha256,"public_cli_sha256":intent.suite.public_cli_sha256,"public_uid":intent.suite.public_uid,"public_gid":intent.suite.public_gid,"historical_e0":null,"historical_spoof":null,"policy":null,"cases":[{"selector":record.selector,"challenge":hex::encode(record.challenge),"contract_path":record.contract_path,"contract_sha256":record.contract_file_sha256}]}),
            )
        },
    )?;
    if inputs.record.result_key != case.key || inputs.record.challenge != case.challenge {
        return fail("public ABI prepared input recipe differs from actual controller nonce");
    }
    crate::private_public_preparation::persist_prepared_public_inputs(&inputs)?;
    let reader = crate::private_kernel_observer::observe_live_kernel_subject(std::process::id())?;
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let btf_sha256 = journal.descriptor().kernel_btf_sha256.clone();
    let expected = |key: DiagnosticSha256, controls: bool| ExpectedKernelAdapterV1 {
        boot_id: host.boot_id().into(),
        kernel_release: release.trim().into(),
        btf_sha256: btf_sha256.clone(),
        probe_map_sha256: probe.attestation_digest(),
        result_key: key,
        coordinator_pid: if controls { reader.pid } else { service.pid },
        coordinator_start_time: 0,
        coordinator_start_ticks: if controls {
            reader.start_ticks
        } else {
            service.start_ticks
        },
        cgroup_inode: if controls {
            reader.cgroup_inode
        } else {
            service.cgroup_inode
        },
        broker_pid: broker.pid,
        broker_start_ticks: broker.start_ticks,
        broker_cgroup_inode: broker.cgroup_inode,
    };
    // Pin the actual ARM helper object across both intervals, not a producer
    // dev/inode claim or a helper from an unrelated installed generation.
    let held_helper = match (target, host.arm32_helper_sha256()) {
        ("x86_64-unknown-linux-gnu", None) => None,
        ("aarch64-unknown-linux-gnu", Some(sha)) => {
            let path = Path::new("/usr/libexec/memcordon-arm32-abi-helper");
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            let metadata = file.metadata()?;
            let mut bytes = Vec::new();
            (&file).take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.gid() != 0
                || metadata.mode() & 0o022 != 0
                || metadata.mode() & 0o111 == 0
                || metadata.nlink() != 1
                || bytes.len() > 8 * 1024 * 1024
                || hash_bytes(&bytes) != *sha
            {
                return fail("public ABI independently held ARM image differs from H1");
            }
            Some((file, metadata, bytes))
        }
        _ => return fail("public ABI H1 helper inventory differs from target"),
    };
    let mut material = b"memcordon-public-abi-outer-v1\0".to_vec();
    for value in [
        host.active_h1_receipt_sha256(),
        host.installation_epoch(),
        &case.key,
        &DiagnosticSha256::from_bytes(case.challenge),
    ] {
        material.extend_from_slice(value.bytes());
    }
    let auxiliary_key = hash_bytes(&material);
    let mut outer_case =
        journal.prepare_case(PUBLIC_ABI_SELECTOR_V1, IntervalPurposeV1::AbiOuter, 0)?;
    outer_case.key = auxiliary_key.clone();
    outer_case.interval_id.logical_case_key = auxiliary_key.clone();
    let outer_prefix = PathBuf::from("composites/abi/outer");
    let outer_control = expected(outer_case.key.clone(), true);
    let outer_product = expected(outer_case.key.clone(), false);
    let ((outer_request, outer_raw), outer_detached) = run_public_journal_interval(
        journal,
        probe,
        &outer_case,
        outer_control,
        outer_product,
        |journal| {
            let key = String::from(case.key.clone());
            let output = crate::command::CommandSpec::new(
                Path::new("/usr/libexec/memcordon-sealed-agent"),
                root,
                Duration::from_secs(60),
            )
            .remove_github_token()
            .args([
                "package",
                "public-abi-outer-control",
                "--selector",
                PUBLIC_ABI_SELECTOR_V1,
                "--challenge",
                challenge.as_str(),
                "--dispatch-key",
                key.as_str(),
            ])
            .run()?;
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Response {
                schema: u8,
                auxiliary_key: DiagnosticSha256,
                raw_sha256: DiagnosticSha256,
            }
            let response: Response = crate::private_observer_session::strict_json(
                output.strip_suffix(b"\n").ok_or_else(|| {
                    CiError::Message("actual public ABI outer stdout frame differs".into())
                })?,
                128 * 1024,
            )?;
            let directory = Path::new("/var/lib/memcordon/sealed/private-public-abi-controls")
                .join(String::from(auxiliary_key.clone()));
            let request = crate::private_protected_readback::read_protected_raw_case_file(
                &directory.join("request.json"),
            )?;
            let raw = crate::private_protected_readback::read_protected_raw_case_file(
                &directory.join("outer-control.raw.json"),
            )?;
            if response.schema != 1
                || response.auxiliary_key != auxiliary_key
                || response.raw_sha256 != hash_bytes(&raw)
            {
                return fail("public ABI outer stdout differs from original protected raw source");
            }
            journal.append(
                outer_prefix
                    .join("host.json")
                    .to_string_lossy()
                    .into_owned(),
                Kind::Installed,
                host_bytes.to_vec(),
            )?;
            journal.append(
                outer_prefix
                    .join("request.json")
                    .to_string_lossy()
                    .into_owned(),
                Kind::Request,
                request.clone(),
            )?;
            journal.append(
                outer_prefix
                    .join("outer-control.raw.json")
                    .to_string_lossy()
                    .into_owned(),
                Kind::Case,
                raw.clone(),
            )?;
            if let Some((_, metadata, bytes)) = &held_helper {
                journal.append(
                    outer_prefix
                        .join("helper-image.raw")
                        .to_string_lossy()
                        .into_owned(),
                    Kind::Case,
                    bytes.clone(),
                )?;
                journal.append(outer_prefix.join("helper-image.json").to_string_lossy().into_owned(),Kind::LiveSample,serde_json::to_vec(&serde_json::json!({"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode(),"nlink":metadata.nlink(),"size":metadata.len(),"sha256":hash_bytes(bytes)}))?)?;
            }
            // The native response is sent before the service worker exits.
            // Keep this physical interval armed through the parent's genuine
            // wait/reap, rather than interpreting response completion as R.
            let source = readback_public_abi_outer_v1(
                &request,
                &raw,
                &ExpectedPublicAbiOuterV1 {
                    target,
                    challenge: &case.challenge,
                    h1_sha256: host.active_h1_receipt_sha256(),
                    installation_epoch: host.installation_epoch(),
                    service_pid: service.pid,
                    service_start_ticks: service.start_ticks,
                    service_cgroup_inode: service.cgroup_inode,
                },
            )?;
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                match crate::private_process_clock::read_live_start_ticks(source.service_worker_pid)
                {
                    Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                        break;
                    }
                    Ok(ticks) if ticks != source.service_worker_start_ticks => break,
                    Ok(_) => {}
                    Err(error) => return Err(error),
                }
                if std::time::Instant::now() >= deadline {
                    return fail("public ABI actual outer worker remains live or unreaped");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok((request, raw))
        },
    )?;
    let outer_clock =
        crate::private_process_clock::VerifiedProcClockCalibrationV1::observe_live_reader(
            reader.pid,
            reader.start_ticks,
        )?;
    let outer = readback_public_abi_outer_v1(
        &outer_request,
        &outer_raw,
        &ExpectedPublicAbiOuterV1 {
            target,
            challenge: &case.challenge,
            h1_sha256: host.active_h1_receipt_sha256(),
            installation_epoch: host.installation_epoch(),
            service_pid: service.pid,
            service_start_ticks: service.start_ticks,
            service_cgroup_inode: service.cgroup_inode,
        },
    )?;
    let outer_join =
        join_public_abi_outer_kernel_v1(&outer, &outer_detached.interval, &outer_clock)?;
    if outer.dispatch_key != case.key || outer.auxiliary_key != auxiliary_key {
        return fail("public ABI outer request differs from prepared public parent");
    }
    let outer_timing = outer_detached
        .interval
        .observation_timing()
        .ok_or_else(|| CiError::Message("public ABI actual outer timing absent".into()))?;
    let mut outer_sources = vec![
        outer_prefix
            .join("host.json")
            .to_string_lossy()
            .into_owned(),
        outer_prefix
            .join("request.json")
            .to_string_lossy()
            .into_owned(),
        outer_prefix
            .join("outer-control.raw.json")
            .to_string_lossy()
            .into_owned(),
    ];
    if held_helper.is_some() {
        for name in ["helper-image.raw", "helper-image.json"] {
            outer_sources.push(outer_prefix.join(name).to_string_lossy().into_owned());
        }
    }
    journal.retain_interval_with_record(
        &outer_case,
        &outer_detached.interval,
        vec![outer_detached.controls_path],
        outer_sources,
        outer_timing.armed_monotonic_ns,
        outer_timing.operation_end_monotonic_ns,
        outer_timing.detached_monotonic_ns,
        Some(
            outer_prefix
                .join("interval.json")
                .to_string_lossy()
                .into_owned(),
        ),
    )?;
    let prefix = PathBuf::from("composites/abi/filtered");
    let report_path = input
        .report_directory
        .join(String::from(case.key.clone()))
        .with_extension("json");
    let abi = match target {
        "x86_64-unknown-linux-gnu" => {
            memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::X86_64LinuxGnu
        }
        "aarch64-unknown-linux-gnu" => {
            memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2::Aarch64LinuxGnu
        }
        _ => return fail("ABI GNU target differs"),
    };
    let readback = crate::private_public_v2::ExpectedPublicV2Readback {
        source_commit: &intent.suite.observer_subject.source_commit,
        native_abi: abi,
        archive_sha256: &intent.suite.archive_sha256,
        runtime_manifest_sha256: &intent.suite.manifest_sha256,
        qualification_sha256: &intent.suite.qualification_sha256,
        host_receipt_sha256: host.active_h1_receipt_sha256(),
        report_owner_uid: intent.suite.public_uid,
        outcome: crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0),
    };
    let filtered_control = expected(case.key.clone(), true);
    let filtered_product = expected(case.key.clone(), false);
    let (observed, filtered_detached) = run_public_journal_interval(
        journal,
        probe,
        &case,
        filtered_control,
        filtered_product,
        |journal| {
            journal.append(
                prefix.join("host.json").to_string_lossy().into_owned(),
                Kind::Installed,
                host_bytes.to_vec(),
            )?;
            journal.append(
                prefix
                    .join("prepared-admission.json")
                    .to_string_lossy()
                    .into_owned(),
                Kind::Request,
                inputs.admission_bytes.clone(),
            )?;
            journal.append(
                prefix.join("contract.json").to_string_lossy().into_owned(),
                Kind::Request,
                inputs.contract_bytes.clone(),
            )?;
            journal.append(
                prefix.join("fixture.raw").to_string_lossy().into_owned(),
                Kind::Case,
                fixture.clone(),
            )?;
            crate::private_public_dispatch::run_installed_public_abi_source_case(
                root,
                PUBLIC_ABI_SELECTOR_V1,
                &challenge,
                Path::new("/usr/bin/memcordon"),
                &intent.suite.public_cli_sha256,
                Path::new(&inputs.record.contract_path),
                &report_path,
                &input.fixture_path,
                &input.report_directory,
                intent.suite.public_uid,
                intent.suite.public_gid,
                &readback,
                &prefix,
            )
        },
    )?;
    let (provider_record, provider_leaves) =
        crate::private_public_dispatch::read_original_public_provider_sources(
            PUBLIC_ABI_SELECTOR_V1,
            &challenge,
            &case.key,
        )?;
    let provider = crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
        &provider_record,
        &provider_leaves,
    )?;
    let [attempt] = provider.attempts.as_slice() else {
        return fail("public ABI genuine filtered attempt count differs");
    };
    let target_identity = attempt.target_identity.as_ref().ok_or_else(|| {
        CiError::Message("public ABI actual protected target identity absent".into())
    })?;
    let filtered_clock =
        crate::private_process_clock::VerifiedProcClockCalibrationV1::observe_live_reader(
            reader.pid,
            reader.start_ticks,
        )?;
    let kernel_join = crate::private_public_kernel_join::join_public_case_kernel_targets(
        &filtered_detached.interval,
        &filtered_clock,
        &case.key,
        &[
            crate::private_public_kernel_join::ProtectedPublicTargetExpectationV1 {
                attempt_id: attempt.attempt_id.clone(),
                pid: target_identity.target.pid,
                start_ticks: target_identity.target.start_time,
                network_namespace_inode: target_identity.network_namespace_inode,
                entrypoint_sha256: target_identity.entrypoint_sha256.clone(),
                entrypoint_device: target_identity.entrypoint_device,
                entrypoint_inode: target_identity.entrypoint_inode,
                entrypoint_path: target_identity.entrypoint_path.clone(),
            },
        ],
    )?;
    let directory = Path::new("/var/lib/memcordon/sealed/private-public-abi-filtered")
        .join(String::from(case.key.clone()));
    let raw_report = crate::private_protected_readback::read_protected_raw_case_file(
        &directory.join("target-report.bin"),
    )?;
    let raw_protected = crate::private_protected_readback::read_protected_raw_case_file(
        &directory.join("filtered.json"),
    )?;
    let checkpoint_bytes = crate::private_protected_readback::read_protected_raw_case_file(
        &directory.join("checkpoint.json"),
    )?;
    let checkpoint: memcordon_core::workload_evidence_v2::PrivateTcpCheckpointV2 =
        crate::private_observer_session::strict_json(&checkpoint_bytes, 4096)?;
    let checkpoint_sha = checkpoint.canonical_digest().map_err(CiError::Message)?;
    let helper_identity = held_helper
        .as_ref()
        .map(|(_, metadata, _)| (metadata.dev(), metadata.ino()));
    let filtered = readback_public_abi_filtered_v1(
        &raw_report,
        &raw_protected,
        &checkpoint_bytes,
        &ExpectedPublicAbiFilteredV1 {
            target,
            challenge: &case.challenge,
            result_key: &case.key,
            boot_id: host.boot_id(),
            installation_epoch: host.installation_epoch(),
            active_h1_receipt_sha256: host.active_h1_receipt_sha256(),
            attempt_id: &attempt.attempt_id,
            target_pid: target_identity.target.pid,
            target_start_ticks: target_identity.target.start_time,
            target_uid: intent.suite.public_uid,
            target_gid: intent.suite.public_gid,
            checkpoint_sha256: &checkpoint_sha,
            filter_sha256: host.filter_sha256(),
            network_namespace_inode: target_identity.network_namespace_inode,
            helper_device: helper_identity.map(|pair| pair.0),
            helper_inode: helper_identity.map(|pair| pair.1),
        },
    )?;
    let filtered_join = join_public_abi_filtered_kernel_v1(
        &filtered,
        &filtered_detached.interval,
        &filtered_clock,
        target_identity.entrypoint_device,
        target_identity.entrypoint_inode,
    )?;
    if let Some((file, metadata, bytes)) = &held_helper {
        let after = file.metadata()?;
        let path = std::fs::symlink_metadata("/usr/libexec/memcordon-arm32-abi-helper")?;
        let mut same_file = file;
        same_file.seek(SeekFrom::Start(0))?;
        let mut reread = Vec::new();
        same_file
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut reread)?;
        if (
            after.dev(),
            after.ino(),
            after.uid(),
            after.gid(),
            after.mode(),
            after.nlink(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) != (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ) || (path.dev(), path.ino()) != (metadata.dev(), metadata.ino())
            || bytes.len() as u64 != after.len()
            || reread != *bytes
        {
            return fail("public ABI independently held helper changed across physical intervals");
        }
    }
    let child = observed
        .process
        .linux_child
        .ok_or_else(|| CiError::Message("public ABI actual held public CLI child absent".into()))?;
    let report = observed
        .report_bytes
        .as_ref()
        .ok_or_else(|| CiError::Message("public ABI original nonroot CLI report absent".into()))?;
    let terminal = attempt
        .terminal_bytes
        .as_ref()
        .ok_or_else(|| CiError::Message("public ABI original terminal absent".into()))?;
    let cleanup = attempt
        .cleanup_bytes
        .as_ref()
        .ok_or_else(|| CiError::Message("public ABI original cleanup absent".into()))?;
    let composite = PublicAbiCompositeCaseV1 {
        schema_version: 1,
        selector: PUBLIC_ABI_SELECTOR_V1.into(),
        challenge: case.challenge,
        source_commit: intent.suite.observer_subject.source_commit.clone(),
        release_version: memcordon_core::BoundedText::new(host.version())
            .map_err(|message| CiError::Message(message.into()))?,
        target: target.into(),
        native_machine: host.native_machine().into(),
        archive_sha256: intent.suite.archive_sha256.clone(),
        manifest_sha256: host.manifest_sha256().clone(),
        qualification_sha256: host.qualification_sha256().clone(),
        active_h1_receipt_sha256: host.active_h1_receipt_sha256().clone(),
        installation_epoch: host.installation_epoch().clone(),
        filtered_child: FinalPublicChildIdentityV2 {
            pid: child.pid,
            start_time_ticks: child.start_time_ticks,
            boot_identity: memcordon_core::BoundedText::new(host.boot_id())
                .map_err(|message| CiError::Message(message.into()))?,
            uid: intent.suite.public_uid,
            gid: intent.suite.public_gid,
            supplementary_groups_empty: true,
            executable_sha256: observed.cli_sha256.clone(),
            argv_sha256: observed.argv_sha256.clone(),
            working_directory_sha256: observed.working_directory_sha256.clone(),
        },
        filtered_provider_sha256: hash_bytes(&provider_record),
        filtered_report_sha256: hash_bytes(report),
        filtered_stdio_sha256: hash_bytes(&observed.stdio_bytes),
        filtered_terminal_sha256: hash_bytes(terminal),
        filtered_cleanup_sha256: hash_bytes(cleanup),
        filtered_target_report_sha256: filtered.report_sha256.clone(),
        filtered_service_journal_sha256: filtered.protected_sha256.clone(),
        filtered_checkpoint_file_sha256: filtered.checkpoint_file_sha256.clone(),
        filtered_kernel_capture_sha256: filtered_join.capture_sha256().clone(),
        outer_auxiliary_key: outer.auxiliary_key.clone(),
        outer_request_sha256: outer.request_sha256.clone(),
        outer_raw_sha256: outer.raw_sha256.clone(),
        outer_kernel_capture_sha256: outer_join.capture_sha256().clone(),
    };
    let bytes = serde_json::to_vec(&composite)?;
    PublicAbiCompositeCaseV1::parse(&bytes).map_err(CiError::Message)?;
    crate::private_public_verify::verify_public_abi_composite(
        &bytes,
        &observed,
        &provider,
        &outer,
        &outer_join,
        &filtered,
        &filtered_join,
        &filtered_detached.interval,
        &kernel_join,
    )?;
    // Structural derived bytes enter custody only alongside all genuine
    // source leaves. Completed specialist replay rechecks every physical join.
    journal.append("composites/abi/composite.json".into(), Kind::Case, bytes)?;
    journal.append(
        prefix
            .join("provider/record.json")
            .to_string_lossy()
            .into_owned(),
        Kind::Case,
        provider_record,
    )?;
    let provider_source_paths = provider_leaves
        .keys()
        .map(|name| {
            prefix
                .join("provider/raw")
                .join(name)
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    for (name, bytes) in provider_leaves {
        journal.append(
            prefix
                .join("provider/raw")
                .join(name)
                .to_string_lossy()
                .into_owned(),
            Kind::Case,
            bytes,
        )?;
    }
    let mut samples = vec![
        prefix.join("host.json").to_string_lossy().into_owned(),
        prefix
            .join("prepared-admission.json")
            .to_string_lossy()
            .into_owned(),
        prefix.join("contract.json").to_string_lossy().into_owned(),
        prefix.join("fixture.raw").to_string_lossy().into_owned(),
        prefix
            .join("provider/record.json")
            .to_string_lossy()
            .into_owned(),
    ];
    samples.extend(provider_source_paths);
    for (name, bytes) in observed.live_samples {
        let name = prefix
            .join("samples")
            .join(name)
            .to_string_lossy()
            .into_owned();
        journal.append(name.clone(), Kind::LiveSample, bytes)?;
        samples.push(name);
    }
    for (name, kind, bytes) in [
        ("target/report.json", Kind::Case, raw_report),
        ("target/protected.json", Kind::Case, raw_protected),
        (
            "target/checkpoint-file.bin",
            Kind::Checkpoint,
            checkpoint_bytes,
        ),
        ("cli/report.json", Kind::Report, report.clone()),
        ("cli/stdio.bin", Kind::Stdio, observed.stdio_bytes),
    ] {
        let name = prefix.join(name).to_string_lossy().into_owned();
        journal.append(name.clone(), kind, bytes)?;
        samples.push(name);
    }
    let timing = filtered_detached
        .interval
        .observation_timing()
        .ok_or_else(|| CiError::Message("public ABI actual filtered timing absent".into()))?;
    journal.retain_interval_with_record(
        &case,
        &filtered_detached.interval,
        vec![filtered_detached.controls_path],
        samples,
        timing.armed_monotonic_ns,
        timing.operation_end_monotonic_ns,
        timing.detached_monotonic_ns,
        Some(prefix.join("interval.json").to_string_lossy().into_owned()),
    )
}
