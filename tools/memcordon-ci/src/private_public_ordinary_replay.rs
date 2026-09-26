//! Public caller/admission/report joins in addition to closed target facts.
//! Neither a public-stage origin label nor generic target execution is enough.
use crate::private_observer_session::{ObserverEvidenceV1, ObserverIntervalRecordV1, strict_json};
use crate::private_public_plan::{StaticPublicSuiteIntentV1, public_contract_template_sha256};
use crate::{CiError, Result};
use memcordon_core::private_public_case_v2::FinalPublicCaseEvidenceV3;
use memcordon_core::workload_registry_v2::{
    PolicyGrantV2, PolicyRegistryV2, ProfileKindV2, resolve_v2,
};
use memcordon_core::{
    DiagnosticSha256,
    workload_codec::{contract_digest_v2, hash_bytes},
};

fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum GrantOutcome {
    Granted {
        grant: PolicyGrantV2,
    },
    Rejected {
        rejection: memcordon_core::workload_registry_v2::AdmissionRejectionV2,
    },
}

#[cfg(unix)]
pub(crate) fn process(
    bytes: &[u8],
    child: &memcordon_core::private_public_case_v2::FinalPublicChildIdentityV2,
) -> Result<crate::private_supervisor::SupervisedProcessV2> {
    use std::os::unix::process::ExitStatusExt;
    let mut bytes = bytes
        .strip_prefix(b"memcordon/public-stdio/v1\0")
        .ok_or_else(|| CiError::Message("public supervisor stdio domain differs".into()))?;
    fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N]> {
        let value = bytes
            .get(..N)
            .ok_or_else(|| CiError::Message("public supervisor stdio truncated".into()))?
            .try_into()
            .expect("bounded array");
        *bytes = &bytes[N..];
        Ok(value)
    }
    let pid = u32::from_le_bytes(take(&mut bytes)?);
    let start = u64::from_le_bytes(take(&mut bytes)?);
    let status = i32::from_le_bytes(take(&mut bytes)?);
    let stdout_len = u32::from_le_bytes(take(&mut bytes)?) as usize;
    if stdout_len > 1024 * 1024 {
        return fail("public supervisor stdout exceeds fixed bound");
    }
    let stdout = bytes
        .get(..stdout_len)
        .ok_or_else(|| CiError::Message("public stdout truncated".into()))?
        .to_vec();
    bytes = &bytes[stdout_len..];
    let stderr_len = u32::from_le_bytes(take(&mut bytes)?) as usize;
    if stderr_len > 1024 * 1024
        || bytes.len() != stderr_len
        || pid != child.pid
        || start != child.start_time_ticks
    {
        return fail("public supervisor exact child/streams differ");
    }
    Ok(crate::private_supervisor::SupervisedProcessV2 {
        status: std::process::ExitStatus::from_raw(status),
        stdout,
        stderr: bytes.to_vec(),
        linux_child: Some(crate::private_supervisor::LinuxChildIdentityV1 {
            pid,
            start_time_ticks: start,
        }),
    })
}

#[cfg(unix)]
pub(crate) fn verify_public_case_inputs(
    intent: &StaticPublicSuiteIntentV1,
    origin: &impl ObserverEvidenceV1,
    ordinal: usize,
    interval: &ObserverIntervalRecordV1,
    challenge: &[u8; 32],
    key: &DiagnosticSha256,
) -> Result<()> {
    use crate::private_public_specialist_replay as replay;
    use memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2 as Report;
    use memcordon_core::private_release_case_v1::{
        PrivateReleaseAllocatedOutcomeV1 as Outcome, PrivateReleaseObservationV1 as Observation,
    };
    use memcordon_core::report_v11::{
        PrivatePublicOutcomeV11, PrivatePublicResultV11, PrivateTerminalOutcomeV11,
    };
    let prefix = std::path::Path::new("cases").join(ordinal.to_string());
    let path = |name: &str| prefix.join(name).to_string_lossy().into_owned();
    let scenario = &intent.scenarios[ordinal];
    let case = FinalPublicCaseEvidenceV3::parse(origin.leaf(&path("result.json"))?)
        .map_err(CiError::Message)?
        .0;
    let host = replay::host(origin, intent, &path("host.json"), interval.generation)?;
    let provider = replay::provider(origin, &path("provider"))?;
    replay::bind_provider(
        intent,
        origin,
        &provider,
        &scenario.selector,
        interval.generation,
    )?;
    // A derived role carrier cannot introduce a second provider history. Its
    // bytes must be the same original leaves used by this mandatory tuple join.
    let facts: crate::private_candidate_replay::CaseReplayFactsV1 =
        strict_json(origin.leaf(&path("facts.json"))?, 1024 * 1024)?;
    for fact in &facts.facts {
        if let crate::private_candidate_replay::CaseFactV1::Retirement {
            tasks,
            terminal_path,
            ..
        } = fact
        {
            if tasks
                .iter()
                .any(|task| matches!(task.role.as_str(), "guardian" | "frontend"))
            {
                let source: crate::private_public_fault::PublicRetirementRoleSourceV3 =
                    strict_json(origin.leaf(terminal_path)?, 16 * 1024 * 1024)?;
                let raw_prefix = path("provider/raw");
                let mut original = std::collections::BTreeMap::new();
                for name in crate::private_public_dispatch::public_provider_source_leaf_names(
                    &provider.record_bytes,
                )? {
                    let source_path = std::path::Path::new(&raw_prefix).join(&name);
                    original.insert(
                        name,
                        origin
                            .leaf(source_path.to_string_lossy().as_ref())?
                            .to_vec(),
                    );
                }
                if source.schema_version != 3
                    || source.provider_record != provider.record_bytes
                    || source.provider_leaves != original
                {
                    return fail(
                        "public retirement role carrier differs from original admitted provider history",
                    );
                }
            }
        }
    }
    let raw: serde_json::Value = strict_json(&provider.record_bytes, 128 * 1024)?;
    if case.selector != scenario.selector
        || case.challenge != *challenge
        || case.result_key().map_err(CiError::Message)? != *key
        || case.source_commit != intent.observer_subject.source_commit
        || case.release_version.as_str() != intent.observer_subject.release_version
        || case.target != intent.observer_subject.target
        || case.native_machine != host.native_machine()
        || case.build_context_sha256 != intent.observer_subject.build_sha256
        || case.release_catalogue_sha256 != intent.observer_subject.catalogue_sha256
        || case.installed.installation_epoch != *host.installation_epoch()
        || case.installed.archive_sha256 != intent.archive_sha256
        || case.installed.qualified_manifest_sha256 != intent.manifest_sha256
        || case.installed.release_qualification_sha256 != intent.qualification_sha256
        || case.installed.active_host_receipt_sha256 != *host.active_h1_receipt_sha256()
        || case.installed.component_sha256 != *host.component_sha256()
        || case.installed.unit_sha256 != *host.unit_sha256()
        || case.installed.filter_sha256 != *host.filter_sha256()
        || case.installed.filter_sha256 != scenario.recipe.filter_sha256
        || case.installed.public_plan_sha256 != hash_bytes(&provider.plan_response_bytes)
        || case.installed.public_grant_sha256 != hash_bytes(&provider.grant_decision_bytes)
        || case.child.uid != intent.public_uid
        || case.child.gid != intent.public_gid
        || !case.child.supplementary_groups_empty
        || case.child.executable_sha256 != intent.public_cli_sha256
        || case.child.boot_identity.as_str() != host.boot_id()
        || raw.get("peer_pid").and_then(serde_json::Value::as_u64)
            != Some(u64::from(case.child.pid))
        || raw
            .get("peer_start_time_ticks")
            .and_then(serde_json::Value::as_u64)
            != Some(case.child.start_time_ticks)
        || provider.policy_branch.is_some()
    {
        return fail("ordinary public case differs from actual installed/caller/provider inputs");
    }
    let contract =
        memcordon_core::workload_contract::WorkloadContractV2::parse(&provider.request_bytes)
            .map_err(CiError::Message)?;
    if public_contract_template_sha256(&contract)? != scenario.contract_template_sha256
        || origin.leaf(&path("provider/raw/plan-request.bin"))? != provider.request_bytes
    {
        return fail("public plan contract differs from independently approved static template");
    }
    let registry = PolicyRegistryV2::parse(
        provider
            .registry_bytes
            .as_deref()
            .ok_or_else(|| CiError::Message("public original registry absent".into()))?,
    )
    .map_err(CiError::Message)?;
    let registry_sha = registry.canonical_digest().map_err(CiError::Message)?;
    let decision: serde_json::Value = strict_json(&provider.grant_decision_bytes, 128 * 1024)?;
    let epoch: memcordon_core::workload_contract::PolicyEpoch = serde_json::from_value(
        decision
            .get("policy_epoch")
            .cloned()
            .ok_or_else(|| CiError::Message("public actual policy epoch absent".into()))?,
    )?;
    let outcome: GrantOutcome = serde_json::from_value(
        decision
            .get("outcome")
            .cloned()
            .ok_or_else(|| CiError::Message("public actual grant outcome absent".into()))?,
    )?;
    if registry_sha != intent.policy_recipe.registry_sha256 || contract.expected_epoch != epoch {
        return fail("public registry/epoch differs from independently protected policy");
    }
    match (
        outcome,
        resolve_v2(
            &registry,
            &epoch,
            &contract,
            &memcordon_core::workload_registry::CallerSelector::Linux {
                uid: intent.public_uid,
            },
            ProfileKindV2::LinuxTcp4PrivateV1,
            &intent.qualification_sha256,
        ),
    ) {
        (GrantOutcome::Granted { grant }, Ok(selected)) if &grant == selected => {}
        (GrantOutcome::Rejected { rejection }, Err(expected)) if rejection == expected => {
            return fail("ordinary allocated public case has an actual rejected grant");
        }
        _ => return fail("public grant differs from independent current V2 resolution"),
    }
    let receipt = memcordon_core::workload_plan_v2::PrivatePlanReceiptV2::parse_for_contract(
        &provider.plan_response_bytes,
        &contract,
    )
    .map_err(CiError::Message)?;
    if receipt.caller_uid != intent.public_uid
        || receipt.policy_epoch != epoch
        || receipt.registry_digest != registry_sha
        || receipt.runtime_manifest_sha256 != intent.manifest_sha256
        || receipt.installed_qualification_sha256 != intent.qualification_sha256
        || receipt.generation_digest != *host.installation_epoch()
        || receipt.source_commit != intent.observer_subject.source_commit
        || receipt.contract_digest != contract_digest_v2(&contract).map_err(CiError::Message)?
    {
        return fail("public plan receipt differs from actual contract/caller/H1");
    }
    let stdio = origin.leaf(&path("cli/stdio.bin"))?;
    let observed_process = process(stdio, &case.child)?;
    let (kernel, clock) = replay::interval(origin, &path("interval.json"), &interval.purpose)?;
    let report_bytes = match &case.report {
        Report::Present { size, sha256 } => {
            let bytes = origin.leaf(&path("cli/report.json"))?;
            if *size != bytes.len() as u64 || *sha256 != hash_bytes(bytes) {
                return fail("public actual report bytes differ");
            }
            Some(bytes)
        }
        Report::AbsentFrontendLoss {
            authenticated_terminal_sha256,
            supervised_transport_sha256,
            independent_recovery_sha256,
        } => {
            use std::os::unix::process::ExitStatusExt;
            let attempt = provider
                .attempts
                .first()
                .ok_or_else(|| CiError::Message("frontend actual attempt absent".into()))?;
            let fault = attempt
                .fault
                .as_ref()
                .ok_or_else(|| CiError::Message("frontend actual fault absent".into()))?;
            if fault.outcome != Outcome::FrontendLost
                || fault.victim.pid != case.child.pid
                || fault.victim.start_time != case.child.start_time_ticks
                || observed_process.status.signal() != Some(libc::SIGKILL)
                || attempt
                    .terminal_bytes
                    .as_ref()
                    .is_none_or(|bytes| hash_bytes(bytes) != *authenticated_terminal_sha256)
                || *supervised_transport_sha256 != hash_bytes(stdio)
                || *independent_recovery_sha256 != *kernel.trace_sha256()
            {
                return fail(
                    "frontend absent report lacks actual supervisor/fault/terminal replacement",
                );
            }
            None
        }
        Report::AbsentFrontendRejectedV3 {
            original_rejection_sha256,
            supervised_transport_sha256,
            supervisor_wait_sha256,
            independent_recovery_sha256,
        } => {
            use std::os::unix::process::ExitStatusExt;
            let [attempt] = provider.attempts.as_slice() else {
                return fail("nonterminal frontend exact attempt differs");
            };
            let fault = attempt.fault.as_ref().ok_or_else(|| {
                CiError::Message("nonterminal frontend actual fault absent".into())
            })?;
            let wait_bytes = origin.leaf(&path("samples/supervisor/wait-v1.json"))?;
            let wait: crate::private_public_live::PublicFrontendSupervisorWaitV1 =
                strict_json(wait_bytes, 4096)?;
            if fault.outcome != Outcome::FrontendLost
                || fault.response_kind != 106
                || attempt.terminal_bytes.is_some()
                || fault.victim.pid != case.child.pid
                || fault.victim.start_time != case.child.start_time_ticks
                || observed_process.status.signal() != Some(libc::SIGKILL)
                || *original_rejection_sha256 != hash_bytes(&attempt.response_bytes)
                || *supervised_transport_sha256 != hash_bytes(stdio)
                || *supervisor_wait_sha256 != hash_bytes(wait_bytes)
                || *independent_recovery_sha256 != *kernel.trace_sha256()
                || wait.schema_version != 1
                || wait.pid != case.child.pid
                || wait.start_time_ticks != case.child.start_time_ticks
                || wait.signal != libc::SIGKILL
                || wait.raw_wait_status != observed_process.status.into_raw()
                || wait.stdout_sha256 != hash_bytes(&observed_process.stdout)
                || wait.stderr_sha256 != hash_bytes(&observed_process.stderr)
                || wait.wait_observed_monotonic_ns < interval.begin_monotonic_ns
                || wait.wait_observed_monotonic_ns > interval.end_monotonic_ns
            {
                return fail(
                    "V3 frontend nonterminal replacement differs from actual rejection/wait/raw streams",
                );
            }
            None
        }
    };
    let is_dual = scenario.selector == "private_tcp::dual_attempt_namespace_isolation";
    let (report, dual_report) = if is_dual {
        let expected = crate::private_public_v2::ExpectedPublicV2Readback {
            source_commit: &intent.observer_subject.source_commit,
            native_abi: receipt.native_abi,
            archive_sha256: &intent.archive_sha256,
            runtime_manifest_sha256: &intent.manifest_sha256,
            qualification_sha256: &intent.qualification_sha256,
            host_receipt_sha256: host.active_h1_receipt_sha256(),
            report_owner_uid: intent.public_uid,
            outcome: crate::private_public_v2::ExpectedPublicV2Outcome::Exited(0),
        };
        let dual = crate::private_public_v2::validate_structural_public_dual_v12_readback(
            &observed_process,
            report_bytes.ok_or_else(|| CiError::Message("dual actual report absent".into()))?,
            &expected,
        )?;
        (None, Some(dual))
    } else if let Some(bytes) = report_bytes {
        let report: PrivatePublicResultV11 = strict_json(bytes, 1024 * 1024)?;
        report.validate_structure().map_err(CiError::Message)?;
        let [attempt] = provider.attempts.as_slice() else {
            return fail("ordinary actual attempt count differs");
        };
        let expected_outcome = match &report.result {
            PrivatePublicOutcomeV11::Complete {
                terminal,
                raw_response,
            } if raw_response == &attempt.response_bytes => {
                if attempt.fault.is_none()
                    && terminal.outcome != (PrivateTerminalOutcomeV11::Exited { code: 0 })
                {
                    return fail("ordinary completed public target did not actually exit zero");
                }
                match terminal.outcome {
                    PrivateTerminalOutcomeV11::Exited { code } => {
                        crate::private_public_v2::ExpectedPublicV2Outcome::Exited(code)
                    }
                    PrivateTerminalOutcomeV11::NativeFailure { .. } => {
                        crate::private_public_v2::ExpectedPublicV2Outcome::NativeFailure
                    }
                    PrivateTerminalOutcomeV11::Interrupted { .. } => {
                        crate::private_public_v2::ExpectedPublicV2Outcome::Interrupted
                    }
                }
            }
            PrivatePublicOutcomeV11::AllocatedUnverified { raw_response, .. }
                if raw_response == &attempt.response_bytes =>
            {
                crate::private_public_v2::ExpectedPublicV2Outcome::AllocatedUnverified
            }
            PrivatePublicOutcomeV11::Indeterminate { raw_response, .. }
                if raw_response == &attempt.response_bytes =>
            {
                crate::private_public_v2::ExpectedPublicV2Outcome::Indeterminate
            }
            _ => return fail("public result does not preserve exact original protected response"),
        };
        let expected = crate::private_public_v2::ExpectedPublicV2Readback {
            source_commit: &intent.observer_subject.source_commit,
            native_abi: receipt.native_abi,
            archive_sha256: &intent.archive_sha256,
            runtime_manifest_sha256: &intent.manifest_sha256,
            qualification_sha256: &intent.qualification_sha256,
            host_receipt_sha256: host.active_h1_receipt_sha256(),
            report_owner_uid: intent.public_uid,
            outcome: expected_outcome,
        };
        (
            Some(
                crate::private_public_v2::validate_structural_public_v2_readback(
                    &observed_process,
                    bytes,
                    &expected,
                )?,
            ),
            None,
        )
    } else {
        (None, None)
    };
    let samples_prefix = path("samples");
    let mut live_samples = std::collections::BTreeMap::new();
    for original_path in &interval.sample_paths {
        if let Some(relative) = original_path
            .strip_prefix(&samples_prefix)
            .and_then(|suffix| suffix.strip_prefix('/'))
        {
            live_samples.insert(relative.to_owned(), origin.leaf(original_path)?.to_vec());
        }
    }
    let observed = crate::private_public_dispatch::ObservedInstalledPublicCaseV3 {
        process: observed_process,
        report,
        dual_report,
        report_bytes: report_bytes.map(Vec::from),
        stdio_bytes: stdio.to_vec(),
        cli_sha256: intent.public_cli_sha256.clone(),
        argv_sha256: case.child.argv_sha256.clone(),
        working_directory_sha256: case.child.working_directory_sha256.clone(),
        live_samples,
    };
    if matches!(
        scenario.selector.as_str(),
        "private_tcp::descriptor_table_and_stdio_bound"
            | "private_tcp::caller_identity_and_epoch_bound"
            | "private_tcp::af_unix_abstract_and_pathname_denied"
            | "private_tcp::af_unix_socketpair_denied"
            | "private_tcp::io_uring_and_pidfd_import_denied"
            | "private_tcp::namespace_reentry_denied"
            | "private_tcp::private_namespace_topology_exact"
            | "private_tcp::scm_rights_and_precreated_socket_denied"
            | "private_tcp::child_runtime_and_threads_retired"
            | "private_tcp::release_checkpoint_terminal_joined"
            | "private_tcp::authorization_uncertainty_retired"
            | "private_tcp::checkpoint_persisted_before_release"
            | "private_tcp::elf_ancestor_and_identity_pinned"
            | "private_tcp::native_tcp_bind_listen_connect"
            | "private_tcp::port_collision_same_namespace"
            | "private_tcp::frontend_loss_retired"
            | "private_tcp::guardian_loss_retired"
            | "private_tcp::native_filter_digest_and_abi_bound"
            | "private_tcp::dual_attempt_namespace_isolation"
            | "private_tcp::host_namespace_and_sysctl_unchanged"
            | "private_tcp::target_credentials_and_capabilities_dropped"
            | "private_tcp::target_exec_and_fd_leak_observed"
    ) {
        let raw_prefix = path("provider/raw");
        let mut original = std::collections::BTreeMap::new();
        for name in crate::private_public_dispatch::public_provider_source_leaf_names(
            &provider.record_bytes,
        )? {
            let source_path = std::path::Path::new(&raw_prefix).join(&name);
            original.insert(
                name,
                origin
                    .leaf(source_path.to_string_lossy().as_ref())?
                    .to_vec(),
            );
        }
        let prepared = crate::private_public_producer::PreparedPublicCaseV1 {
            selector: scenario.selector.clone(),
            challenge: *challenge,
            argv: scenario.recipe.fixture_argv.clone(),
            key: key.clone(),
            filter_sha256: scenario.recipe.filter_sha256.clone(),
            filter_install_source_sha256: scenario.recipe.filter_install_source_sha256.clone(),
            facility_source_sha256: scenario.recipe.facility_source_sha256.clone(),
            host_preservation_source_sha256: scenario
                .recipe
                .host_preservation_source_sha256
                .clone(),
            interval_id: kernel.physical_interval_id().cloned().ok_or_else(|| {
                CiError::Message("public original physical interval ID absent".into())
            })?,
        };
        let reconstructed = crate::private_public_source_facts::record_public_common_sources(
            intent,
            origin.descriptor(),
            origin.leaf(&path("prepared-admission.json"))?,
            &prepared,
            &prefix,
            &intent.observer_subject.target,
            scenario.recipe.port,
            &observed,
            &kernel,
            &provider.record_bytes,
            &original,
        )?;
        let expected_path = path("facts.json");
        let bytes = if scenario.selector == "private_tcp::caller_identity_and_epoch_bound" {
            crate::private_public_specialist_replay::replay_public_history_origin(intent, origin)?;
            let common_path = path("common-facts-source.json");
            let (_, _, common) = reconstructed
                .iter()
                .find(|(path, _, _)| *path == common_path)
                .ok_or_else(|| {
                    CiError::Message("public caller original common facts absent".into())
                })?;
            if origin.leaf(&common_path)? != common {
                return fail(
                    "public caller intermediate source differs from original reconstruction",
                );
            }
            crate::private_public_caller_replay::assemble_public_caller_facts(
                common,
                &intent.observer_subject.target,
            )?
        } else {
            reconstructed
                .iter()
                .find(|(path, _, _)| *path == expected_path)
                .map(|(_, _, bytes)| bytes.clone())
                .ok_or_else(|| {
                    CiError::Message("public complete source family reconstruction absent".into())
                })?
        };
        if origin.leaf(&expected_path)? != bytes {
            return fail(
                "public typed facts differ from independent original raw-source reconstruction",
            );
        }
    }
    let attachments = crate::private_public_dispatch::collect_public_raw_attachments_v3(
        &scenario.selector,
        &observed,
        &provider,
        &kernel,
    )?;
    if attachments
        .iter()
        .zip(&case.attachments)
        .any(|(raw, index)| {
            raw.role != index.role
                || raw.bytes.len() as u64 != index.size
                || hash_bytes(&raw.bytes) != index.sha256
        })
        || attachments.len() != case.attachments.len()
    {
        return fail("public recomputed raw attachment inventory differs");
    }
    let fault = provider
        .attempts
        .first()
        .and_then(|attempt| attempt.fault.as_ref());
    if let Some(fault) = fault {
        let [attempt] = provider.attempts.as_slice() else {
            return fail("public fault exact attempt differs");
        };
        let exact = match &case.observation {
            Observation::AllocatedRetired {
                outcome,
                attempt_id,
                checkpoint_sha256,
                terminal_sha256,
                retirement_sha256,
                release_knowledge,
                exec,
                native_observer_sha256,
            } => {
                fault.response_kind == 105
                    && *outcome == fault.outcome
                    && attempt_id == &attempt.attempt_id
                    && attempt
                        .checkpoint_bytes
                        .as_ref()
                        .is_some_and(|bytes| hash_bytes(bytes) == *checkpoint_sha256)
                    && attempt
                        .terminal_bytes
                        .as_ref()
                        .is_some_and(|bytes| hash_bytes(bytes) == *terminal_sha256)
                    && *retirement_sha256 == fault.retirement_sha256
                    && *release_knowledge == fault.knowledge
                    && *exec == fault.exec
                    && native_observer_sha256 == kernel.trace_sha256()
            }
            Observation::PublicFaultRejectedRetiredV2 {
                outcome,
                attempt_id,
                checkpoint_file_sha256,
                original_rejection_sha256,
                fault_trigger_sha256,
                fault_failure_sha256,
                retirement_sha256,
                recovery_sha256,
                release_knowledge,
                exec,
                native_observer_sha256,
            } => {
                fault.response_kind == 106
                    && attempt.terminal_bytes.is_none()
                    && *outcome == fault.outcome
                    && attempt_id == &attempt.attempt_id
                    && attempt
                        .checkpoint_bytes
                        .as_ref()
                        .is_some_and(|bytes| hash_bytes(bytes) == *checkpoint_file_sha256)
                    && *original_rejection_sha256 == hash_bytes(&attempt.response_bytes)
                    && *fault_trigger_sha256 == fault.trigger_sha256
                    && *fault_failure_sha256 == fault.failure_sha256
                    && *retirement_sha256 == fault.retirement_sha256
                    && *recovery_sha256 == fault.recovery_sha256
                    && *release_knowledge == fault.knowledge
                    && *exec == fault.exec
                    && native_observer_sha256 == kernel.trace_sha256()
            }
            _ => false,
        };
        if !exact {
            return fail("public fault observation differs from actual protected causal outcome");
        }
    } else {
        let joined = replay::target_join(&provider, &kernel, &clock)?;
        let (observation, report, positive) =
            crate::private_public_dispatch::compose_public_case_observation(
                &scenario.selector,
                &provider,
                &observed,
                &kernel,
                &joined,
                None,
            )?;
        if observation != case.observation
            || report != case.report
            || positive != case.positive_control_terminal_sha256
        {
            return fail(
                "public observation differs from independently reconstructed provider/kernel/public report",
            );
        }
    }
    Ok(())
}
