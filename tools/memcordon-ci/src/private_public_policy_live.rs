//! Five actual installed public requests under separate enrolled physical
//! intervals. Prepared comparison bytes never stand in for provider raw.
use crate::private_observer_session::canonical_bytes;
use crate::private_public_driver::{
    ActualPublicPreparationContextV2, ProtectedPublicProducerIntentV2,
};
use crate::private_public_producer::{PublicObserverProducerV1, run_public_journal_interval};
use crate::private_public_raw::PublicLeafKindV1 as Kind;
use crate::{CiError, Result};
use memcordon_core::private_public_policy_composite_v1::{
    PUBLIC_POLICY_SELECTOR_V1 as SELECTOR, PublicPolicyBranchEvidenceV1,
    PublicPolicyBranchOutcomeV1, PublicPolicyCompositeCaseV1,
};
use memcordon_core::private_release_branch_v1::{
    PolicyOperationBranchV1 as Branch, PrivatePolicyAgentFixtureV1,
};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

#[cfg(target_os = "linux")]
pub(crate) fn run_public_policy_sources(
    root: &Path,
    target: &str,
    intent: &ProtectedPublicProducerIntentV2,
    approval: &memcordon_core::private_public_preparation_v2::ApprovedPublicPreparationPolicyV2,
    journal: &mut PublicObserverProducerV1,
    probe: &crate::private_probe_bundle::VerifiedProbeBundleV1,
    host: &crate::private_final_install::FinalHostReadbackV1,
    context: &ActualPublicPreparationContextV2,
    generation: &crate::private_public_plan::PreparedPublicGenerationV1,
    service: &crate::private_kernel_observer::LiveKernelSubjectV1,
    broker: &crate::private_kernel_observer::LiveKernelSubjectV1,
) -> Result<()> {
    use memcordon_core::private_public_preparation_v2::PublicPreparedRoleV2;
    use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;
    use std::os::unix::fs::MetadataExt;
    let abi = match target {
        "x86_64-unknown-linux-gnu" => QualifiedNativeAbiV2::X86_64LinuxGnu,
        "aarch64-unknown-linux-gnu" => QualifiedNativeAbiV2::Aarch64LinuxGnu,
        _ => return fail("public policy native ABI differs"),
    };
    let (base, _) = crate::private_public_plan::prepared_public_case_recipe_v1(
        &intent.suite,
        &journal.descriptor().session_nonce,
        generation.generation().generation,
        SELECTOR,
    )?;
    let mut fixture: PrivatePolicyAgentFixtureV1 = crate::private_observer_session::strict_json(
        &crate::private_protected_readback::read_protected_raw_case_file(
            &intent.policy.fixture_template_path,
        )?,
        512 * 1024,
    )?;
    if fixture.base_challenge != [0; 32]
        || fixture.authenticated_caller_uid != intent.suite.public_uid
        || crate::private_public_plan::public_policy_fixture_template_sha256(&fixture)?
            != intent.suite.policy_recipe.fixture_template_sha256
        || [
            &fixture.accepted,
            &fixture.changed_port,
            &fixture.committed_tamper,
        ]
        .iter()
        .any(|contract| {
            contract.expected_epoch.service_instance.0 != [0; 16]
                || contract.expected_epoch.revision.get() != 1
        })
    {
        return fail(
            "public policy fixture template predicts runtime facts or differs from approval",
        );
    }
    fixture.base_challenge = base;
    for contract in [
        &mut fixture.accepted,
        &mut fixture.changed_port,
        &mut fixture.committed_tamper,
    ] {
        contract.expected_epoch = context.policy_epoch.clone();
    }
    fixture.validate().map_err(CiError::Message)?;
    let input = intent
        .cases
        .iter()
        .find(|case| case.selector == SELECTOR)
        .ok_or_else(|| CiError::Message("public policy fixture input absent".into()))?;
    let recipe = intent
        .suite
        .scenarios
        .iter()
        .find(|case| case.selector == SELECTOR)
        .ok_or_else(|| CiError::Message("public policy recipe absent".into()))?;
    let image = crate::private_public_driver::read_pinned_image(
        &input.fixture_path,
        &recipe.fixture_sha256,
    )?;
    let mut prepared = Vec::new();
    let names = [
        "accepted",
        "wrong-grant",
        "wrong-profile",
        "unapproved-port",
        "frozen-tamper",
    ];
    for ((branch_input, branch), name) in intent.policy.branches.iter().zip(Branch::ALL).zip(names)
    {
        if branch_input.branch != branch {
            return fail("public policy physical branch order differs");
        }
        let parent = std::fs::symlink_metadata(&branch_input.report_directory)?;
        if !parent.is_dir()
            || parent.uid() != intent.suite.public_uid
            || parent.mode() & 0o7777 != 0o700
        {
            return fail(
                "public policy report directory is not the approved private caller directory",
            );
        }
        let template = crate::private_protected_readback::read_protected_raw_case_file(
            &branch_input.contract_template_path,
        )?;
        let inputs = crate::private_public_preparation::prepare_public_contract_inputs(
            &intent.suite,
            generation,
            approval,
            SELECTOR,
            PublicPreparedRoleV2::Policy { branch },
            &template,
            &context.policy_epoch,
            |_| canonical_bytes(&serde_json::json!({"preparation_pending":true})),
        )?;
        let contract =
            memcordon_core::workload_contract::WorkloadContractV2::parse(&inputs.contract_bytes)
                .map_err(CiError::Message)?;
        if branch == Branch::AcceptedControl || branch == Branch::CommittedPortTamper {
            if contract != fixture.accepted {
                return fail(
                    "public accepted/frozen policy template differs from approved fixture",
                );
            }
        } else if branch == Branch::UnapprovedChangedPortPlan && contract != fixture.changed_port {
            return fail("public changed-port template differs from approved fixture");
        }
        let comparison = if matches!(
            branch,
            Branch::AcceptedControl | Branch::CommittedPortTamper
        ) {
            // This projection is only a typed caller comparison. The actual
            // provider plan receipt is separately retained and replayed.
            Some(canonical_bytes(
                &memcordon_core::workload_plan_v2::PrivatePlanReceiptV2 {
                    schema_version: 3,
                    contract_digest: memcordon_core::workload_codec::contract_digest_v2(&contract)
                        .map_err(CiError::Message)?,
                    registry_digest: intent.suite.policy_recipe.registry_sha256.clone(),
                    installed_qualification_sha256: intent.suite.qualification_sha256.clone(),
                    runtime_manifest_sha256: intent.suite.manifest_sha256.clone(),
                    generation_digest: host.installation_epoch().clone(),
                    caller_uid: intent.suite.public_uid,
                    policy_epoch: context.policy_epoch.clone(),
                    source_commit: intent.suite.observer_subject.source_commit.clone(),
                    native_abi: abi,
                },
            )?)
        } else {
            None
        };
        let report = branch_input
            .report_directory
            .join(String::from(inputs.record.result_key.clone()))
            .with_extension("json");
        prepared.push((branch, name, inputs, comparison, report));
    }
    let branches=prepared.iter().map(|(branch,_,inputs,comparison,report)|{
        let expected=comparison.as_ref().map(|bytes|hash_bytes(bytes));
        Ok(serde_json::json!({"selector":SELECTOR,"challenge":hex::encode(inputs.record.challenge),"contract_path":inputs.record.contract_path,"contract_sha256":inputs.record.contract_file_sha256,
            "policy_branch":branch,"fixture_path":input.fixture_path,"fixture_sha256":recipe.fixture_sha256,"report_path":report,
            "outcome":if *branch==Branch::AcceptedControl{"exited"}else{"rejected"},
            "expected_plan_path":comparison.as_ref().map(|_|inputs.directory.join("expected-plan-comparison.json")),"expected_plan_sha256":expected,
            "tampered_contract_path":(*branch==Branch::CommittedPortTamper).then(||inputs.directory.join("tampered-contract.json")),
            "tampered_contract_sha256":if *branch==Branch::CommittedPortTamper{Some(hash_bytes(&canonical_bytes(&fixture.committed_tamper)?))}else{None}}))
    }).collect::<Result<Vec<_>>>()?;
    let base_entry = serde_json::json!({"selector":SELECTOR,"challenge":hex::encode(base),"contract_path":prepared[0].2.record.contract_path,"contract_sha256":prepared[0].2.record.contract_file_sha256});
    let routing = canonical_bytes(
        &serde_json::json!({"schema_version":1,"source_commit":intent.suite.observer_subject.source_commit,"target":target,"manifest_sha256":intent.suite.manifest_sha256,"qualification_sha256":intent.suite.qualification_sha256,"public_cli_sha256":intent.suite.public_cli_sha256,"public_uid":intent.suite.public_uid,"public_gid":intent.suite.public_gid,"historical_e0":null,"historical_spoof":null,"cases":[base_entry],"policy":{"base_challenge":hex::encode(base),"branches":branches}}),
    )?;
    for (branch, _, inputs, comparison, _) in &mut prepared {
        inputs.record.dispatch_bytes = routing.clone();
        inputs.admission_bytes = canonical_bytes(&inputs.record)?;
        inputs
            .record
            .validate(
                approval,
                &memcordon_core::workload_contract::WorkloadContractV2::parse(
                    &inputs.contract_bytes,
                )
                .map_err(CiError::Message)?,
            )
            .map_err(CiError::Message)?;
        crate::private_public_preparation::persist_prepared_public_inputs(inputs)?;
        if let Some(bytes) = comparison {
            write_prepared_comparison(&inputs.directory, "expected-plan-comparison.json", bytes)?;
        }
        if *branch == Branch::CommittedPortTamper {
            write_prepared_comparison(
                &inputs.directory,
                "tampered-contract.json",
                &canonical_bytes(&fixture.committed_tamper)?,
            )?;
        }
    }
    let reader = crate::private_kernel_observer::observe_live_kernel_subject(std::process::id())?;
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let expected = |key: DiagnosticSha256, control: bool| {
        crate::private_kernel_observer::ExpectedKernelAdapterV1 {
            boot_id: host.boot_id().into(),
            kernel_release: release.trim().into(),
            btf_sha256: journal.descriptor().kernel_btf_sha256.clone(),
            probe_map_sha256: probe.attestation_digest(),
            result_key: key,
            coordinator_pid: if control { reader.pid } else { service.pid },
            coordinator_start_time: 0,
            coordinator_start_ticks: if control {
                reader.start_ticks
            } else {
                service.start_ticks
            },
            cgroup_inode: if control {
                reader.cgroup_inode
            } else {
                service.cgroup_inode
            },
            broker_pid: broker.pid,
            broker_start_ticks: broker.start_ticks,
            broker_cgroup_inode: broker.cgroup_inode,
        }
    };
    let expectations = prepared
        .iter()
        .map(|(_, _, inputs, _, _)| {
            (
                expected(inputs.record.result_key.clone(), true),
                expected(inputs.record.result_key.clone(), false),
            )
        })
        .collect::<Vec<_>>();
    let mut branch_evidence = Vec::new();
    let mut live = Vec::new();
    for (
        ordinal,
        ((branch, name, inputs, comparison, report_path), (control_expected, product_expected)),
    ) in prepared.into_iter().zip(expectations).enumerate()
    {
        let mut case = journal.prepare_case(
            SELECTOR,
            crate::private_kernel_replay::IntervalPurposeV1::Policy,
            ordinal as u32,
        )?;
        case.filter_install_source_sha256 = None;
        case.facility_source_sha256 = None;
        case.host_preservation_source_sha256 = None;
        if case.challenge != inputs.record.challenge || case.key != inputs.record.result_key {
            return fail("public policy controller recipe differs from prepared branch");
        }
        let prefix = Path::new("composites/policy").join(name);
        let challenge = hex::encode(case.challenge);
        let expected_report = crate::private_public_v2::ExpectedPublicV2Readback {
            source_commit: &intent.suite.observer_subject.source_commit,
            native_abi: abi,
            archive_sha256: &intent.suite.archive_sha256,
            runtime_manifest_sha256: &intent.suite.manifest_sha256,
            qualification_sha256: &intent.suite.qualification_sha256,
            host_receipt_sha256: host.active_h1_receipt_sha256(),
            report_owner_uid: intent.suite.public_uid,
            outcome: if branch == Branch::AcceptedControl {
                crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0)
            } else {
                crate::private_public_v2::ExpectedPublicV2Outcome::PreallocationRejected
            },
        };
        let (observed, detached) = run_public_journal_interval(
            journal,
            probe,
            &case,
            control_expected,
            product_expected,
            |journal| {
                if ordinal == 0 {
                    journal.append(
                        "composites/policy/fixture.json".into(),
                        Kind::Case,
                        canonical_bytes(&fixture)?,
                    )?;
                }
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
                    image.clone(),
                )?;
                crate::private_public_dispatch::run_installed_public_source_case(
                    root,
                    SELECTOR,
                    &challenge,
                    Path::new("/usr/bin/memcordon"),
                    &intent.suite.public_cli_sha256,
                    Path::new(&inputs.record.contract_path),
                    &report_path,
                    &input.fixture_path,
                    comparison
                        .as_ref()
                        .map(|_| inputs.directory.join("expected-plan-comparison.json"))
                        .as_deref(),
                    (branch == Branch::CommittedPortTamper)
                        .then(|| inputs.directory.join("tampered-contract.json"))
                        .as_deref(),
                    report_path.parent().ok_or_else(|| {
                        CiError::Message("public policy report parent absent".into())
                    })?,
                    intent.suite.public_uid,
                    intent.suite.public_gid,
                    Duration::from_secs(120),
                    &expected_report,
                    &prefix,
                )
            },
        )?;
        let (record, leaves) =
            crate::private_public_dispatch::read_original_public_provider_sources(
                SELECTOR, &challenge, &case.key,
            )?;
        let provider = crate::private_public_dispatch::parse_structural_provider_case_from_leaves(
            &record, &leaves,
        )?;
        let clock = detached
            .interval
            .original_clock()
            .ok_or_else(|| CiError::Message("public policy original clock absent".into()))?;
        let joined = crate::private_public_dispatch::join_public_provider_kernel(
            &provider,
            &detached.interval,
            clock,
        )?;
        let attachments = crate::private_public_dispatch::collect_public_raw_attachments(
            SELECTOR,
            &observed,
            &provider,
            &detached.interval,
        )?;
        let child = observed
            .process
            .linux_child
            .ok_or_else(|| CiError::Message("public policy supervised caller absent".into()))?;
        let report_bytes = observed
            .report_bytes
            .as_ref()
            .ok_or_else(|| CiError::Message("public policy original report absent".into()))?;
        let outcome = match branch {
            Branch::AcceptedControl => {
                let [attempt] = provider.attempts.as_slice() else {
                    return fail("public policy positive attempt count differs");
                };
                PublicPolicyBranchOutcomeV1::AcceptedControl {
                    attempt_id: attempt.attempt_id.clone(),
                    target_identity_sha256: hash_bytes(
                        attempt.target_identity_bytes.as_ref().ok_or_else(|| {
                            CiError::Message("public policy target raw absent".into())
                        })?,
                    ),
                    terminal_sha256: hash_bytes(attempt.terminal_bytes.as_ref().ok_or_else(
                        || CiError::Message("public policy terminal raw absent".into()),
                    )?),
                    cleanup_sha256: hash_bytes(attempt.cleanup_bytes.as_ref().ok_or_else(
                        || CiError::Message("public policy cleanup raw absent".into()),
                    )?),
                }
            }
            Branch::CommittedPortTamper => {
                let [attempt] = provider.attempts.as_slice() else {
                    return fail("public policy frozen attempt count differs");
                };
                PublicPolicyBranchOutcomeV1::FrozenPlanDenied {
                    rejection_sha256: hash_bytes(&attempt.response_bytes),
                }
            }
            negative => {
                let expected = match negative {
                    Branch::WrongGrant => {
                        memcordon_core::workload_registry_v2::AdmissionCodeV2::ProfileNotAuthorized
                    }
                    Branch::WrongProfile => {
                        memcordon_core::workload_registry_v2::AdmissionCodeV2::ProfileDigestMismatch
                    }
                    Branch::UnapprovedChangedPortPlan => {
                        memcordon_core::workload_registry_v2::AdmissionCodeV2::PlanNotApproved
                    }
                    _ => unreachable!(),
                };
                PublicPolicyBranchOutcomeV1::PlanDenied {
                    admission_code: expected,
                    rejection_sha256: hash_bytes(provider.terminal_bytes.as_ref().ok_or_else(
                        || CiError::Message("public policy exact plan rejection raw absent".into()),
                    )?),
                }
            }
        };
        let raw_inventory = serde_json::to_vec(
            &attachments
                .iter()
                .map(|item| (item.role, item.bytes.len() as u64, hash_bytes(&item.bytes)))
                .collect::<Vec<_>>(),
        )?;
        branch_evidence.push(PublicPolicyBranchEvidenceV1 {
            branch,
            challenge: case.challenge,
            result_key: case.key.clone(),
            child: memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2 {
                pid: child.pid,
                start_time_ticks: child.start_time_ticks,
                boot_identity: memcordon_core::BoundedText::new(host.boot_id())
                    .map_err(|error| CiError::Message(error.into()))?,
                uid: intent.suite.public_uid,
                gid: intent.suite.public_gid,
                supplementary_groups_empty: true,
                executable_sha256: observed.cli_sha256.clone(),
                argv_sha256: observed.argv_sha256.clone(),
                working_directory_sha256: observed.working_directory_sha256.clone(),
            },
            provider_record_sha256: hash_bytes(&provider.record_bytes),
            plan_response_sha256: hash_bytes(&provider.plan_response_bytes),
            grant_decision_sha256: hash_bytes(&provider.grant_decision_bytes),
            kernel_capture_sha256: detached.interval.trace_sha256().clone(),
            report_sha256: hash_bytes(report_bytes),
            stdio_sha256: hash_bytes(&observed.stdio_bytes),
            raw_inventory_sha256: hash_bytes(&raw_inventory),
            outcome,
        });
        let mut samples = vec![
            prefix
                .join("prepared-admission.json")
                .to_string_lossy()
                .into_owned(),
            prefix.join("contract.json").to_string_lossy().into_owned(),
            prefix.join("fixture.raw").to_string_lossy().into_owned(),
        ];
        if ordinal == 0 {
            samples.push("composites/policy/fixture.json".into());
        }
        let mut append = |path: PathBuf, kind, bytes: Vec<u8>| -> Result<()> {
            let path = path.to_string_lossy().into_owned();
            journal.append(path.clone(), kind, bytes)?;
            samples.push(path);
            Ok(())
        };
        append(prefix.join("provider/record.json"), Kind::Provider, record)?;
        for (name, bytes) in leaves {
            append(
                prefix.join("provider/raw").join(name),
                Kind::Provider,
                bytes,
            )?;
        }
        append(
            prefix.join("cli/stdio.bin"),
            Kind::Stdio,
            observed.stdio_bytes.clone(),
        )?;
        append(
            prefix.join("cli/report.json"),
            Kind::Report,
            report_bytes.clone(),
        )?;
        for (name, bytes) in &observed.live_samples {
            append(
                prefix.join("samples").join(name),
                Kind::LiveSample,
                bytes.clone(),
            )?;
        }
        let timing = detached
            .interval
            .observation_timing()
            .ok_or_else(|| CiError::Message("public policy actual timing absent".into()))?;
        journal.retain_interval_with_record(
            &case,
            &detached.interval,
            vec![detached.controls_path],
            samples,
            timing.armed_monotonic_ns,
            timing.operation_end_monotonic_ns,
            timing.detached_monotonic_ns,
            Some(prefix.join("interval.json").to_string_lossy().into_owned()),
        )?;
        live.push(crate::private_public_verify::PublicPolicyBranchLiveV1 {
            observed,
            provider,
            interval: detached.interval,
            joined,
            attachments,
        });
    }
    let case = PublicPolicyCompositeCaseV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        base_challenge: base,
        source_commit: intent.suite.observer_subject.source_commit.clone(),
        release_version: memcordon_core::BoundedText::new(host.version())
            .map_err(|error| CiError::Message(error.into()))?,
        target: target.into(),
        native_machine: host.native_machine().into(),
        archive_sha256: intent.suite.archive_sha256.clone(),
        manifest_sha256: host.manifest_sha256().clone(),
        qualification_sha256: host.qualification_sha256().clone(),
        active_h1_receipt_sha256: host.active_h1_receipt_sha256().clone(),
        installation_epoch: host.installation_epoch().clone(),
        build_context_sha256: intent.suite.observer_subject.build_sha256.clone(),
        release_catalogue_sha256: intent.suite.observer_subject.catalogue_sha256.clone(),
        provider_inventory_sha256: hash_bytes(&serde_json::to_vec(
            &branch_evidence
                .iter()
                .map(|branch| &branch.provider_record_sha256)
                .collect::<Vec<_>>(),
        )?),
        interval_inventory_sha256: hash_bytes(&serde_json::to_vec(
            &branch_evidence
                .iter()
                .map(|branch| &branch.kernel_capture_sha256)
                .collect::<Vec<_>>(),
        )?),
        branches: branch_evidence
            .try_into()
            .map_err(|_| CiError::Message("public policy exact five branches absent".into()))?,
    };
    let bytes = serde_json::to_vec(&case)?;
    let live = live
        .try_into()
        .map_err(|_| CiError::Message("public policy five original intervals absent".into()))?;
    crate::private_public_verify::verify_public_policy_composite(&bytes, &live)?;
    journal.append_representation("composites/policy/composite.json".into(), Kind::Case, bytes)
}

#[cfg(target_os = "linux")]
fn write_prepared_comparison(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !matches!(
        name,
        "expected-plan-comparison.json" | "tampered-contract.json"
    ) || !directory.starts_with("/run/memcordon-final-public/prepared-v2")
    {
        return fail("public comparison path is not closed");
    }
    let parent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)?;
    let before = parent.metadata()?;
    if before.uid() != 0 || before.mode() & 0o022 != 0 {
        return fail("public comparison parent mutable");
    }
    let path = directory.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    parent.sync_all()?;
    let after = parent.metadata()?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino())
        || crate::private_protected_readback::read_protected_raw_case_file(&path)? != bytes
    {
        return fail("public comparison immutable readback differs");
    }
    Ok(())
}
