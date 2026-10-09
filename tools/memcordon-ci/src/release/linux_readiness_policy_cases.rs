//! Owned installed-policy exercises. This module collects actual operations;
//! the separate readiness verifier decides whether their evidence is sufficient.
#![cfg(target_os = "linux")]

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use memcordon_core::PublicProviderBindingV1;
use memcordon_core::workload_contract::PolicyEpoch;
use memcordon_core::workload_contract_v3::WorkloadContractV3;
use memcordon_core::workload_registry_v3::RuntimePrivatePolicyRegistryV3;
use memcordon_readiness_verifier::ProductKey;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::linux_mixed_installed::{
    ActivatedMixedPolicy, InstalledMixedLaunch, InstalledMixedLaunchInput,
};
use crate::command::CommandSpec;
use crate::consumer_readiness_ledger::SourceIdentity;
use crate::{CiError, Result};

#[derive(Clone, Copy)]
pub struct PolicyCaseContext<'a> {
    pub identity: &'a SourceIdentity,
    pub cell: &'a ProductKey,
    pub lease_id: &'a str,
    pub provider: &'a PublicProviderBindingV1,
    pub activated: &'a ActivatedMixedPolicy,
    pub account: &'a crate::consumer_readiness_ledger::ExclusiveAccount,
    pub output: &'a Path,
    pub artifact_root: &'a Path,
    pub admin_root: &'a Path,
    /// The original work cutoff; it is never renewed between cases.
    pub deadline: Instant,
    /// The original reserved cleanup cutoff, also retained on failed restoration.
    pub cleanup_deadline: Instant,
}

#[derive(Serialize)]
pub struct PolicyCaseObservation {
    pub scenario: String,
    pub expected_admission_code: String,
    pub requested_contract: PathBuf,
    pub activation: Option<PathBuf>,
    pub restoration: Option<PathBuf>,
    pub invocation: Option<PathBuf>,
    pub result: Option<PathBuf>,
    pub stdout: Option<PathBuf>,
    pub stderr: Option<PathBuf>,
    pub native_exit: Option<i32>,
    pub error: Option<String>,
    pub transition_artifacts: Vec<PathBuf>,
}

pub struct PolicyCaseReport {
    pub completed: Vec<super::linux_mixed_installed::CompletedMixedCollection>,
    pub observations: Vec<PolicyCaseObservation>,
    /// Frontends and capture workers remain owned even when capture/recovery fails.
    pub launches: Vec<InstalledMixedLaunch>,
    pub baseline_registry: RuntimePrivatePolicyRegistryV3,
    pub baseline_epoch: PolicyEpoch,
    pub restoration_required: bool,
    pub failures: Vec<String>,
    pub privileged_policy_root: PathBuf,
    /// The selected privileged root and all policy staging directories stay open.
    pub directory_custody: Vec<File>,
    pub prepared_owners: Vec<crate::linux_consumer_readiness::PreparedLinuxObserver>,
    pub descendant_owners: Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    pub service_owners: Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    pub command_owners: Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    pub output_root: PathBuf,
    pub reserved_cleanup_deadline: Instant,
    pub cleanup_attempts: u64,
}

pub fn normalize_running(
    report: &mut PolicyCaseReport,
    images: &super::linux_mixed_installed::MixedImages,
    input: &super::linux_mixed_installed::InstalledMixedDriverInput<'_>,
) -> Result<
    Vec<(
        memcordon_readiness_verifier::CaseKey,
        super::linux_mixed_installed::CompletedMixedCollection,
    )>,
> {
    use memcordon_readiness_verifier::{
        Artifact, BehaviorArtifact, FixtureBehavior, FixtureInput, NativeArguments,
        OperationObservation, SemanticObservation,
    };
    let collections = std::mem::take(&mut report.completed);
    let mut completed = Vec::new();
    for mut collection in collections {
        let key = collection.persisted.key.clone();
        if key.family != "L-ID-03"
            || !["drain-running", "revoke-running", "restart-fresh-admission"]
                .contains(&key.scenario.as_str())
        {
            return Err(CiError::Message(
                "policy completed key outside exact executed three".into(),
            ));
        }
        let restart = key.scenario == "restart-fresh-admission";
        let prefix = format!(
            "{}/{}/policy-running/{}",
            input.cell.target, input.cell.channel, key.scenario
        );
        let directory = report.output_root.join(&key.scenario);
        let observation = report
            .observations
            .iter()
            .find(|row| row.scenario == key.scenario)
            .ok_or_else(|| CiError::Message("running policy lost actual observation".into()))?;
        if observation.error.is_some()
            || report.restoration_required
            || observation.restoration.is_none()
        {
            return Err(CiError::Message(
                "running policy mutation/restoration unsettled".into(),
            ));
        }
        let public = memcordon_core::mixed_runtime::MixedRuntimeRequest::parse(&read_named(
            &input
                .artifact_root
                .join(format!("{prefix}/provider-request.json")),
            4 * 1024 * 1024,
        )?)
        .map_err(CiError::Message)?;
        let admission = match &collection.result.runtime.outcome {
            memcordon_core::result_v2::MixedRuntimeOutcomeV2::Executed { admission, .. } => {
                admission
            }
            _ => {
                return Err(CiError::Message(
                    "running policy has no actual executed result".into(),
                ));
            }
        };
        let attempt = admission.attempt_id.as_str().to_owned();
        let (effective, environment) =
            super::linux_mixed_installed::reconstruct_effective_invocation(
                &public, images, admission,
            )?;
        let mut persist = |name: &str, bytes: &[u8]| -> Result<Artifact> {
            budget(input.cleanup_deadline, Duration::from_secs(1))?;
            let path = format!("{prefix}/{name}");
            retain(&input.artifact_root.join(&path), bytes)?;
            let artifact = Artifact {
                path,
                length: bytes.len() as u64,
                sha256: hex_digest(bytes),
            };
            collection.persisted.artifacts.push(artifact.clone());
            Ok(artifact)
        };
        collection.effective_invocation = Some(persist("effective-invocation.bin", &effective)?);
        collection.effective_environment = Some(persist(
            "effective-environment.json",
            &serde_json::to_vec(&environment)?,
        )?);
        let mut peers = Vec::new();
        let agent = persist(
            "policy-agent-image.bin",
            &read_named(
                Path::new("/usr/libexec/memcordon-sealed-agent"),
                512 * 1024 * 1024,
            )?,
        )?;
        peers.push(BehaviorArtifact {
            role: "policy-agent-image".into(),
            path: agent.path,
        });
        let owner = persist(
            "policy-owner.json",
            &read_named(&report.output_root.join("owner.json"), 16 * 1024 * 1024)?,
        )?;
        peers.push(BehaviorArtifact {
            role: "policy-owner".into(),
            path: owner.path,
        });
        for name in if restart {
            ["activation", "restoration"].as_slice()
        } else {
            ["activation", "revocation", "restoration"].as_slice()
        } {
            for extension in [
                "json",
                "policy.json",
                "invocation.json",
                "exit.json",
                "stderr.bin",
            ] {
                let path = directory.join(format!("{name}.{extension}"));
                let artifact = persist(
                    &format!("policy-{name}-{extension}"),
                    &read_named(&path, 16 * 1024 * 1024)?,
                )?;
                peers.push(BehaviorArtifact {
                    role: format!("policy-{name}-{extension}"),
                    path: artifact.path,
                });
            }
        }
        if !restart {
            for name in [
                "running-native-held.json",
                "prepared-family-retirement.json",
                "fresh-contract.json",
                "fresh-challenge.bin",
                "fresh-exit.json",
                "fresh-native-census.json",
            ] {
                let artifact = persist(
                    &format!("policy-{name}"),
                    &read_named(&directory.join(name), 16 * 1024 * 1024)?,
                )?;
                peers.push(BehaviorArtifact {
                    role: format!("policy-{name}"),
                    path: artifact.path,
                });
            }
            if key.scenario == "drain-running" {
                let artifact = persist(
                    "policy-running-after-revocation.json",
                    &read_named(
                        &directory.join("running-after-revocation.json"),
                        4 * 1024 * 1024,
                    )?,
                )?;
                peers.push(BehaviorArtifact {
                    role: "policy-running-after-revocation.json".into(),
                    path: artifact.path,
                });
            }
            for name in [
                "result.json",
                "stdout.bin",
                "stderr.bin",
                "frontend-invocation.json",
            ] {
                let artifact = persist(
                    &format!("policy-fresh-{name}"),
                    &read_named(
                        &directory.join("fresh-frontend").join(name),
                        16 * 1024 * 1024,
                    )?,
                )?;
                peers.push(BehaviorArtifact {
                    role: format!("policy-fresh-{name}"),
                    path: artifact.path,
                });
            }
            let fresh = report
                .launches
                .iter()
                .find(|launch| launch.result == directory.join("fresh-frontend/result.json"))
                .ok_or_else(|| {
                    CiError::Message("running policy fresh frontend owner absent".into())
                })?;
            let paths = std::fs::read_dir(&fresh.observation_directory)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?
                .into_iter()
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.ends_with(".provider-request.bin"))
                })
                .collect::<Vec<_>>();
            if paths.len() != 1 {
                return Err(CiError::Message(
                    "running policy fresh original provider request is not unique".into(),
                ));
            }
            let basename = paths[0]
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    CiError::Message("running policy fresh request native basename absent".into())
                })?;
            let attempt = basename
                .strip_suffix(".provider-request.bin")
                .filter(|name| {
                    name.len() == 32
                        && name
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or_else(|| {
                    CiError::Message("running policy fresh request original attempt invalid".into())
                })?;
            let artifact = persist(
                &format!("policy-fresh-{attempt}.provider-request.bin"),
                &read_named(&paths[0], 4 * 1024 * 1024)?,
            )?;
            peers.push(BehaviorArtifact {
                role: "policy-fresh-provider-request.json".into(),
                path: artifact.path,
            });
        } else {
            let tool = persist(
                "policy-control-tool-image.bin",
                &read_named(Path::new("/usr/bin/systemctl"), 512 * 1024 * 1024)?,
            )?;
            peers.push(BehaviorArtifact {
                role: "policy-control-tool-image".into(),
                path: tool.path,
            });
            for name in [
                "before.service-native.json",
                "after.service-native.json",
                "control-generation-settlement.json",
                "fresh-family-retirement.json",
            ] {
                let artifact = persist(
                    &format!("policy-{name}"),
                    &read_named(&directory.join(name), 16 * 1024 * 1024)?,
                )?;
                peers.push(BehaviorArtifact {
                    role: format!("policy-{name}"),
                    path: artifact.path,
                });
            }
            for stem in ["before-show", "restart", "after-show"] {
                for suffix in [
                    "command.json",
                    "command-exit.json",
                    "command.stdout.bin",
                    "command.stderr.bin",
                ] {
                    let name = format!("{stem}-{suffix}");
                    let artifact = persist(
                        &format!("policy-{name}"),
                        &read_named(&directory.join(&name), 16 * 1024 * 1024)?,
                    )?;
                    peers.push(BehaviorArtifact {
                        role: format!("policy-{name}"),
                        path: artifact.path,
                    });
                }
            }
        }
        let invocation: memcordon_readiness_verifier::NativeInvocation =
            serde_json::from_slice(&read_named(
                &input.artifact_root.join(&collection.public_invocation.path),
                4 * 1024 * 1024,
            )?)?;
        let NativeArguments::UnixBytes(arguments) = &invocation.arguments else {
            return Err(CiError::Message(
                "running policy actual native argv encoding differs".into(),
            ));
        };
        let challenge = read_named(
            &input.artifact_root.join(format!("{prefix}/challenge.bin")),
            32,
        )?;
        let descriptor = FixtureInput {
            format: "memcordon.consumer-readiness.input".into(),
            revision: 1,
            run_id: input.identity.run_id.clone(),
            key: key.clone(),
            challenge_sha256: hex_digest(&challenge),
            binary: Vec::new(),
            target_argv: NativeArguments::UnixBytes(arguments.iter().skip(1).cloned().collect()),
            deadline_millis: public.attempt_deadline_millis,
            memory_bytes: Some(256 * 1024 * 1024),
            toolchain_identity: None,
        };
        let descriptor_artifact =
            persist("policy-descriptor.json", &serde_json::to_vec(&descriptor)?)?;
        let semantic = SemanticObservation {
            format: "memcordon.consumer-readiness.semantic".into(),
            revision: 1,
            run_id: input.identity.run_id.clone(),
            key: key.clone(),
            challenge: format!("{prefix}/challenge.bin"),
            operations: vec![OperationObservation {
                operation: format!("policy-{}", key.scenario),
                observer: "owned-fixture-behavior".into(),
                attempt_id: Some(attempt),
                root_pid: collection.held_processes.first().map(|process| process.pid),
                native_receipt: format!("{prefix}/stdout.bin"),
            }],
            comparisons: Vec::new(),
            counters: Default::default(),
            negative_probe: None,
            component_test: None,
            component_actors: None,
            windows_capacity: None,
            windows_refusal: None,
            fixture_behavior: Some(FixtureBehavior {
                descriptor: descriptor_artifact.path,
                transcript: format!("{prefix}/stdout.bin"),
                expected_token: None,
                peer_artifacts: peers,
                native_binding: Some(collection.prepared_native_receipt.path.clone()),
            }),
        };
        let semantic_path = persist("semantic.json", &serde_json::to_vec(&semantic)?)?.path;
        let evidence = super::linux_mixed_installed::completed_case_base(
            &mut collection,
            images,
            input,
            descriptor,
            &prefix,
            &semantic_path,
        )?;
        let path = format!("{prefix}/case-evidence.json");
        let bytes = serde_json::to_vec(&evidence)?;
        retain(&input.artifact_root.join(&path), &bytes)?;
        collection.persisted.artifacts.push(Artifact {
            path,
            length: bytes.len() as u64,
            sha256: hex_digest(&bytes),
        });
        completed.push((key, collection));
    }
    Ok(completed)
}

const BINDING_CASES: [(&str, &str); 9] = [
    ("wrong-caller", "unauthorized-caller"),
    ("wrong-plan", "unauthorized-plan"),
    ("wrong-image", "unauthorized-image"),
    ("wrong-profile", "unauthorized-profile"),
    ("wrong-identity", "unauthorized-identity"),
    ("wrong-digest", "unauthorized-image"),
    ("wrong-epoch", "stale-epoch"),
    ("disabled-grant", "disabled-grant"),
    ("changed-grant", "wrong-grant-revision"),
];

/// One report owns the entire policy-case group, including native resources
/// retained on failure. Callers must keep it through provider recovery and the
/// original reserved cleanup cutoff, rather than dropping it on a row error.
pub fn run(context: PolicyCaseContext<'_>) -> Result<PolicyCaseReport> {
    let mut report = run_binding_cases(context)?;
    if !report.failures.is_empty() {
        return Ok(report);
    }
    let phases: [fn(&PolicyCaseContext<'_>, &mut PolicyCaseReport) -> Result<()>; 7] = [
        revoke_discovery,
        revoke_preparation,
        revoke_release,
        drain_running,
        revoke_running,
        restart_fresh_admission,
        v3_preserve_caller,
    ];
    for phase in phases {
        if Instant::now() >= context.deadline {
            report.failures.push(
                "original policy work cutoff exhausted; remaining cases were not executed".into(),
            );
            break;
        }
        if let Err(error) = phase(&context, &mut report) {
            report.failures.push(error.to_string());
            break;
        }
        if report.restoration_required {
            report.failures.push(
                "exact baseline restoration remains uncertain; subsequent policy cases withheld"
                    .into(),
            );
            break;
        }
    }
    Ok(report)
}

/// Settle every retained owner without turning a signal/capture failure into
/// permission to drop another owner. The caller keeps this report on error.
pub fn finalize_report(report: &mut PolicyCaseReport, cleanup_deadline: Instant) -> Result<()> {
    let deadline = cleanup_deadline.min(report.reserved_cleanup_deadline);
    let mut failures = Vec::new();
    // Signal all owned frontends first. One blocking capture must not delay
    // cancellation of another actual launch.
    for (index, launch) in report.launches.iter_mut().enumerate() {
        match launch.frontend.try_wait() {
            Ok(None) => {
                if Instant::now() >= deadline {
                    failures.push(format!(
                        "frontend {index} remains owned after cleanup cutoff"
                    ));
                } else if let Err(error) = launch.frontend.kill() {
                    failures.push(format!("frontend {index} cancellation failed: {error}"));
                }
            }
            Ok(Some(_)) => {}
            Err(error) => {
                failures.push(format!("frontend {index} wait observation failed: {error}"))
            }
        }
        launch.frontend.stdin.take();
    }
    for (index, launch) in report.launches.iter_mut().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if let Err(error) = launch.wait_and_capture(remaining) {
            failures.push(format!(
                "frontend {index} retirement/capture remains owned: {error}"
            ));
        }
    }
    for (index, owner) in report.command_owners.iter().enumerate() {
        match owner.exited() {
            Ok(true) => {}
            Ok(false) => failures.push(format!(
                "control command {index} remains owned after capture"
            )),
            Err(error) => failures.push(format!(
                "control command {index} retirement observation failed: {error}"
            )),
        }
    }
    report.cleanup_attempts = report
        .cleanup_attempts
        .checked_add(1)
        .ok_or_else(|| CiError::Message("policy cleanup retry counter overflow".into()))?;
    let name = format!("cleanup-{}", report.cleanup_attempts);
    let output = report.output_root.join(&name);
    let privileged = report.privileged_policy_root.join(&name);
    // Restoration is attempted even after a native cancellation/capture error.
    if report.restoration_required {
        let restored = (|| -> Result<(PolicyEpoch, PathBuf)> {
            budget(deadline, Duration::from_secs(60))?;
            std::fs::create_dir(&output)?;
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o755))?;
            std::fs::create_dir(&privileged)?;
            std::fs::set_permissions(&privileged, std::fs::Permissions::from_mode(0o700))?;
            report
                .directory_custody
                .push(hold_admin_directory(&privileged)?);
            apply_policy(
                &report.baseline_registry,
                &output,
                &privileged,
                "restoration",
                deadline,
            )
        })();
        match restored {
            Ok((epoch, _)) => {
                report.baseline_epoch = epoch;
                report.restoration_required = false;
            }
            Err(error) => failures.push(format!(
                "exact original registry restoration remains owned: {error}"
            )),
        }
    }
    loop {
        let mut pending = false;
        for (index, observer) in report.prepared_owners.iter().enumerate() {
            match observer.native_family_retired(&report.descendant_owners) {
                Ok(true) => {}
                Ok(false) => pending = true,
                Err(error) => {
                    failures.push(format!(
                        "prepared family {index} native retirement unknown: {error}"
                    ));
                    pending = true;
                }
            }
        }
        for child in &report.descendant_owners {
            match child.exited() {
                Ok(true) => {}
                Ok(false) => pending = true,
                Err(error) => {
                    failures.push(format!(
                        "held descendant {}:{} retirement unknown: {error}",
                        child.process_id, child.birth
                    ));
                    pending = true;
                }
            }
        }
        if !pending {
            break;
        }
        if Instant::now() >= deadline {
            failures.push("held target/init/guardian/descendant obligations remain at original cleanup cutoff".into());
            break;
        }
        // Avoid an unbounded repeated error log while still polling independent
        // native obligations after another observer failed.
        failures.sort();
        failures.dedup();
        std::thread::sleep(Duration::from_millis(10));
    }
    // A launch with no acquired native observer is safe to classify only from
    // its actual strict never-authorized, no-obligation refusal. Missing or
    // indeterminate products remain an explicit outer recovery obligation.
    for (index, launch) in report.launches.iter().enumerate() {
        let classified = (|| -> Result<()> {
            let result = memcordon_core::result_v2::ResultV2::parse(&read_named(
                &launch.result,
                4 * 1024 * 1024,
            )?)
            .map_err(CiError::Message)?;
            match &result.runtime.outcome {
                memcordon_core::result_v2::MixedRuntimeOutcomeV2::RejectedIngress{allocation,..}
                |memcordon_core::result_v2::MixedRuntimeOutcomeV2::RejectedBeforeAuthorization{allocation,..}
                    if allocation.authorization==memcordon_core::result_v2::MixedAuthorizationKnowledgeV2::NeverAuthorized
                        &&allocation.obligations.as_slice().is_empty()=>Ok(()),
                memcordon_core::result_v2::MixedRuntimeOutcomeV2::Executed{admission,..}
                    if report.prepared_owners.iter().any(|owner|owner.observation.admission.attempt_id==admission.attempt_id)=>Ok(()),
                _=>Err(CiError::Message("native attempt association/retirement cannot be reconstructed from this product".into())),
            }
        })();
        if let Err(error) = classified {
            failures.push(format!(
                "frontend {index} provider recovery remains uncertain: {error}"
            ));
        }
    }
    // Current control-service observation handles intentionally remain held;
    // the outer installed lifetime owns their later uninstall/retirement.
    failures.sort();
    failures.dedup();
    report.failures.extend(failures.iter().cloned());
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CiError::Message(failures.join("; ")))
    }
}

/// Exercise all representable V3 binding/grant refusals through the installed
/// public frontend. Malformed ingress and release-transition cases use distinct
/// native transport/barrier owners rather than pretending these are admissions.
pub fn run_binding_cases(context: PolicyCaseContext<'_>) -> Result<PolicyCaseReport> {
    context
        .activated
        .registry
        .validate()
        .map_err(CiError::Message)?;
    context
        .activated
        .contract
        .validate()
        .map_err(CiError::Message)?;
    let grants = context.activated.registry.grants.as_slice();
    if grants.len() != 1
        || grants[0].id.as_str() != "owned-readiness-grant"
        || grants[0].revision.get() != 1
        || !grants[0].enabled
        || context.activated.contract.authorization.grant_id != grants[0].id
        || context.activated.contract.authorization.grant_revision != grants[0].revision
        || context
            .activated
            .contract
            .authorization
            .approved_plan_digest
            != context.activated.contract.workload_plan_digest
    {
        return Err(CiError::Message("policy exercises require the exact owned baseline grant, not unrelated administrator policy".into()));
    }
    if context.lease_id.is_empty()
        || !context
            .lease_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || context.output.exists()
        || !context.output.is_absolute()
        || !context.output.starts_with(context.artifact_root)
        || !context.admin_root.is_absolute()
        || context.cleanup_deadline < context.deadline
    {
        return Err(CiError::Message(
            "policy case owner paths or lease differ".into(),
        ));
    }
    let admin = hold_admin_directory(context.admin_root)?;
    let admin_metadata = admin.metadata()?;
    let privileged_policy_root = context
        .admin_root
        .join(format!("policy-cases-{}", context.lease_id));
    std::fs::create_dir(&privileged_policy_root)?;
    std::fs::set_permissions(
        &privileged_policy_root,
        std::fs::Permissions::from_mode(0o700),
    )?;
    let staged = hold_admin_directory(&privileged_policy_root)?;
    std::fs::create_dir(context.output)?;
    std::fs::set_permissions(context.output, std::fs::Permissions::from_mode(0o755))?;
    let baseline = context.activated.registry.clone();
    let mut report = PolicyCaseReport {
        completed: Vec::new(),
        observations: Vec::new(),
        launches: Vec::new(),
        baseline_registry: baseline.clone(),
        baseline_epoch: context.activated.contract.expected_epoch.clone(),
        restoration_required: false,
        failures: Vec::new(),
        privileged_policy_root,
        directory_custody: vec![admin, staged],
        prepared_owners: Vec::new(),
        descendant_owners: Vec::new(),
        service_owners: Vec::new(),
        command_owners: Vec::new(),
        output_root: context.output.to_path_buf(),
        reserved_cleanup_deadline: context.cleanup_deadline,
        cleanup_attempts: 0,
    };
    retain(
        &context.output.join("owner.json"),
        &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-policy-case-owner", "revision":1,
            "run_id":context.identity.run_id,"source_commit":context.identity.source_commit,
            "source_tree_sha256":context.identity.source_tree_sha256,"cell":context.cell,
            "lease_id":context.lease_id,"provider":context.provider,
            "baseline_registry":baseline,"baseline_epoch":report.baseline_epoch,
            "admin_root":context.admin_root,"admin_root_device":admin_metadata.dev(),
            "admin_root_inode":admin_metadata.ino(),
            "privileged_policy_root":report.privileged_policy_root,
        }))?,
    )?;
    for (scenario, code) in BINDING_CASES {
        let directory = context.output.join(scenario);
        let outcome = execute_binding(&context, &mut report, &directory, scenario, code);
        if let Err(error) = outcome {
            report.failures.push(error.to_string());
            break;
        }
        if Instant::now() >= context.deadline {
            break;
        }
    }
    Ok(report)
}

/// Mutate the grant while the authenticated prepared target remains gated and
/// the independent observer has not published its ACK. The report retains the
/// native owners on every error; this is not the later leased-release facet.
pub fn revoke_preparation(
    context: &PolicyCaseContext<'_>,
    report: &mut PolicyCaseReport,
) -> Result<()> {
    execute_transition(context, report, "revoke-preparation")
}

pub fn drain_running(context: &PolicyCaseContext<'_>, report: &mut PolicyCaseReport) -> Result<()> {
    execute_transition(context, report, "drain-running")
}

pub fn revoke_running(
    context: &PolicyCaseContext<'_>,
    report: &mut PolicyCaseReport,
) -> Result<()> {
    execute_transition(context, report, "revoke-running")
}

pub fn revoke_release(
    context: &PolicyCaseContext<'_>,
    report: &mut PolicyCaseReport,
) -> Result<()> {
    execute_transition(context, report, "revoke-release")
}

pub fn revoke_discovery(
    context: &PolicyCaseContext<'_>,
    report: &mut PolicyCaseReport,
) -> Result<()> {
    execute_binding(
        context,
        report,
        &context.output.join("revoke-discovery"),
        "revoke-discovery",
        "stale-epoch",
    )
}

/// Send one deliberately malformed preserve-caller V3 request through the
/// installed native V4 transport. The base bytes came from this owner's actual
/// env-cleared fixture launch; no production request or credential is collected.
pub fn v3_preserve_caller(
    context: &PolicyCaseContext<'_>,
    report: &mut PolicyCaseReport,
) -> Result<()> {
    let mut candidates = Vec::new();
    let qualified = report
        .observations
        .iter()
        .find(|observation| {
            observation.scenario == "restart-fresh-admission"
                && observation.error.is_none()
                && observation.native_exit == Some(0)
        })
        .and_then(|observation| observation.result.as_ref())
        .ok_or_else(|| {
            CiError::Message("malformed ingress original qualified fresh admission absent".into())
        })?;
    for launch in report
        .launches
        .iter()
        .filter(|launch| &launch.result == qualified)
    {
        for entry in std::fs::read_dir(&launch.observation_directory)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".provider-request.bin"))
            {
                candidates.push(entry.path());
            }
        }
    }
    if candidates.len() != 1 {
        return Err(CiError::Message(
            "malformed ingress qualified original provider request absent/ambiguous".into(),
        ));
    }
    let base_path = candidates.first().ok_or_else(|| {
        CiError::Message("actual owned native request absent for malformed ingress exercise".into())
    })?;
    let base = read_named(
        base_path,
        memcordon_core::workload_limits::CONTRACT_ENVELOPE_BYTES as u64,
    )?;
    memcordon_core::mixed_runtime::MixedRuntimeRequest::parse(&base).map_err(CiError::Message)?;
    let directory = context.output.join("v3-preserve-caller");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
    retain(&directory.join("original-provider-request.bin"), &base)?;
    let mut malformed: serde_json::Value = serde_json::from_slice(&base)?;
    malformed["contract"]["execution_identity"] = serde_json::json!({"kind":"preserve-caller"});
    let bytes = serde_json::to_vec(&malformed)?;
    if memcordon_core::mixed_runtime::MixedRuntimeRequest::parse(&bytes).is_ok() {
        return Err(CiError::Message(
            "preserve-caller fixture unexpectedly became a valid combined contract".into(),
        ));
    }
    let request = directory.join("malformed-provider-request.bin");
    retain(&request, &bytes)?;
    let output_directory = directory.join("caller-observation");
    std::fs::create_dir(&output_directory)?;
    std::fs::set_permissions(&output_directory, std::fs::Permissions::from_mode(0o700))?;
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(&output_directory)?;
    rustix::fs::fchown(
        &held,
        Some(rustix::process::Uid::from_raw(65534)),
        Some(rustix::process::Gid::from_raw(65534)),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    held.sync_all()?;
    report.directory_custody.push(held);
    let receipt = output_directory.join("native-ingress.json");
    let executable = std::env::current_exe()?;
    let executable_bytes = read_named(&executable, 512 * 1024 * 1024)?;
    let executable_sha256 = hex_digest(&executable_bytes);
    let helper_image = directory.join("helper-image.bin");
    retain(&helper_image, &executable_bytes)?;
    let arguments = vec![
        OsString::from("--reuid"),
        OsString::from("65534"),
        OsString::from("--regid"),
        OsString::from("65534"),
        OsString::from("--clear-groups"),
        OsString::from("--"),
        executable.clone().into_os_string(),
        OsString::from("consumer-readiness-malformed-ingress"),
        OsString::from("--request"),
        request.clone().into_os_string(),
        OsString::from("--output"),
        receipt.clone().into_os_string(),
    ];
    use std::os::unix::ffi::OsStrExt;
    let invocation = directory.join("invocation.json");
    let command_budget = budget(context.deadline, Duration::from_secs(60))?;
    let original_lease = context
        .output
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| CiError::Message("malformed ingress original lease parent absent".into()))?
        .join("lease-owner.json");
    let lease: serde_json::Value =
        serde_json::from_slice(&read_named(&original_lease, 32 * 1024 * 1024)?)?;
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CiError::Message(error.to_string()))?
        .as_millis();
    let wall_remaining = lease["work_deadline_unix_millis"]
        .as_u64()
        .ok_or_else(|| CiError::Message("original malformed ingress wall cutoff absent".into()))?
        .checked_sub(u64::try_from(started).map_err(|error| CiError::Message(error.to_string()))?)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| CiError::Message("original malformed ingress work cutoff elapsed".into()))?;
    let command_budget = command_budget.min(Duration::from_millis(wall_remaining));
    retain(
        &invocation,
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.linux-malformed-ingress-invocation","revision":2,
        "program":b"/usr/bin/setpriv","arguments":arguments.iter().map(|argument|argument.as_os_str().as_bytes()).collect::<Vec<_>>(),
        "environment_cleared":true,"helper":executable,"helper_sha256":executable_sha256,"caller_uid":65534,"caller_gid":65534,
        "cwd":directory.as_os_str().as_bytes(),"budget_millis":command_budget.as_millis(),"started_unix_millis":started,
        "work_deadline_unix_millis":lease["work_deadline_unix_millis"],"cleanup_deadline_unix_millis":lease["cleanup_deadline_unix_millis"]}),
        )?,
    )?;
    let index = report.observations.len();
    report.observations.push(PolicyCaseObservation {
        scenario: "v3-preserve-caller".into(),
        expected_admission_code: "rejected-ingress".into(),
        requested_contract: request,
        activation: None,
        restoration: None,
        invocation: Some(invocation.clone()),
        result: Some(receipt.clone()),
        stdout: Some(directory.join("stdout.bin")),
        stderr: Some(directory.join("stderr.bin")),
        native_exit: None,
        error: None,
        transition_artifacts: vec![
            directory.join("original-provider-request.bin"),
            helper_image,
        ],
    });
    let mut creation = None;
    let command_owner_index = report.command_owners.len();
    let observed = crate::command::CommandSpec::new("/usr/bin/setpriv", &directory, command_budget)
        .args(arguments)
        .cleared_environment()
        .bounded_until(context.deadline)
        .output_quiet_with_creation(|child| {
            let birth = crate::linux_consumer_readiness::process_birth(child.id())
                .map_err(CiError::Message)?;
            let owner =
                crate::linux_consumer_readiness::HeldLinuxProcess::acquire(child.id(), birth)
                    .map_err(CiError::Message)?;
            creation = Some(owner.retirement_identity().map_err(CiError::Message)?);
            report.command_owners.push(owner);
            Ok(())
        })?;
    retain(&directory.join("stdout.bin"), &observed.stdout)?;
    retain(&directory.join("stderr.bin"), &observed.stderr)?;
    use std::os::unix::process::ExitStatusExt;
    let retired = report.command_owners[command_owner_index]
        .retirement_identity()
        .map_err(CiError::Message)?;
    if !retired.retirement_observed {
        return Err(CiError::Message(
            "malformed ingress original helper process remains owned after native wait".into(),
        ));
    }
    let exit = directory.join("native-exit.json");
    retain(
        &exit,
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.linux-malformed-ingress-exit","revision":1,
        "creation":creation.ok_or_else(||CiError::Message("malformed ingress actual creation identity absent".into()))?,
        "retirement":retired,"raw_wait_status":observed.status.into_raw(),"native_exit":observed.status.code(),"signal":observed.status.signal(),
        "invocation_sha256":hex_digest(&read_named(&invocation,65536)?),"stdout_sha256":hex_digest(&observed.stdout),"stderr_sha256":hex_digest(&observed.stderr)}),
        )?,
    )?;
    report.observations[index].transition_artifacts.push(exit);
    report.observations[index].native_exit = observed.status.code();
    if !observed.status.success() {
        return Err(CiError::Message(
            "actual malformed-ingress probe failed; raw outputs retained".into(),
        ));
    }
    let raw = read_named(&receipt, 4 * 1024 * 1024)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&raw).map_err(CiError::Message)?;
    let actual: serde_json::Value = serde_json::from_slice(&raw)?;
    if actual["format"] != "memcordon.linux-malformed-ingress-observation"
        || actual["revision"] != 2
        || actual["request"] != serde_json::to_value(&bytes)?
        || actual["provider"] != serde_json::to_value(context.provider)?
        || actual["caller_uid"] != 65534
        || actual["caller_gid"] != 65534
        || actual["caller_pid"] != retired.pid
        || actual["caller_birth"] != retired.birth
        || actual["native_image"]["sha256"] != executable_sha256
        || actual["native_image"]["length"].as_u64() != Some(executable_bytes.len() as u64)
    {
        return Err(CiError::Message(
            "actual malformed-ingress receipt differs from owned exact request/caller/provider"
                .into(),
        ));
    }
    let attempt: Vec<u8> = serde_json::from_value(actual["attempt"].clone())?;
    if attempt.len() != 16 {
        return Err(CiError::Message(
            "malformed ingress original transport attempt bound differs".into(),
        ));
    }
    let census = directory.join("native-census.json");
    super::linux_mixed_installed::persist_policy_refusal_census(
        context.account,
        context.provider,
        context.identity,
        context.cell,
        context.lease_id,
        "v3-preserve-caller",
        &hex::encode(attempt),
        &raw,
        &bytes,
        &census,
        context.deadline,
    )?;
    report.observations[index].transition_artifacts.push(census);
    retain(
        &directory.join("observation.json"),
        &serde_json::to_vec(&report.observations[index])?,
    )?;
    Ok(())
}

/// Restart only the installed control service after every previously retained
/// workload owner has retired, then obtain the actual new activation epoch and
/// perform a fresh public admission. A command's success is not epoch evidence.
pub fn restart_fresh_admission(
    context: &PolicyCaseContext<'_>,
    report: &mut PolicyCaseReport,
) -> Result<()> {
    if report.restoration_required {
        return Err(CiError::Message(
            "policy restoration remains owned before restart".into(),
        ));
    }
    for owner in &report.prepared_owners {
        if !owner
            .native_family_retired(&report.descendant_owners)
            .map_err(CiError::Message)?
        {
            return Err(CiError::Message(
                "prior native workload family remains live before restart".into(),
            ));
        }
    }
    let directory = context.output.join("restart-fresh-admission");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
    let privileged = report
        .privileged_policy_root
        .join("restart-fresh-admission");
    std::fs::create_dir(&privileged)?;
    std::fs::set_permissions(&privileged, std::fs::Permissions::from_mode(0o700))?;
    report
        .directory_custody
        .push(hold_admin_directory(&privileged)?);
    let index = report.observations.len();
    report.observations.push(PolicyCaseObservation {
        scenario: "restart-fresh-admission".into(),
        expected_admission_code: "executed".into(),
        requested_contract: directory.join("contract.json"),
        activation: None,
        restoration: None,
        invocation: None,
        result: None,
        stdout: None,
        stderr: None,
        native_exit: None,
        error: None,
        transition_artifacts: Vec::new(),
    });
    let old_index = observe_control_service(&directory, "before", context.deadline, report)?;
    let output = observe_systemctl(
        &directory,
        "restart",
        &["restart", "memcordon-sealed-agent.service"],
        context.deadline,
        report,
    )?;
    retain(&directory.join("restart.stdout.bin"), &output.stdout)?;
    retain(&directory.join("restart.stderr.bin"), &output.stderr)?;
    retain(
        &directory.join("restart.exit.json"),
        &serde_json::to_vec(&serde_json::json!({"native_exit":output.status.code()}))?,
    )?;
    if !output.status.success() {
        return Err(CiError::Message(
            "actual installed control restart failed; held owner retained".into(),
        ));
    }
    let current_index = observe_control_service(&directory, "after", context.deadline, report)?;
    if !report.service_owners[old_index]
        .exited()
        .map_err(CiError::Message)?
        || report.service_owners[current_index]
            .exited()
            .map_err(CiError::Message)?
        || (
            report.service_owners[old_index].process_id,
            report.service_owners[old_index].birth,
        ) == (
            report.service_owners[current_index].process_id,
            report.service_owners[current_index].birth,
        )
    {
        return Err(CiError::Message(
            "actual control generation did not change with retired predecessor".into(),
        ));
    }
    retain(
        &directory.join("control-generation-settlement.json"),
        &serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.linux-policy-control-generation-settlement","revision":1,
        "old":report.service_owners[old_index].retirement_identity().map_err(CiError::Message)?,
        "current":report.service_owners[current_index].retirement_identity().map_err(CiError::Message)?}))?,
    )?;
    report.restoration_required = true;
    retain(
        &directory.join("restoration-required.json"),
        &serde_json::to_vec(&report.baseline_registry)?,
    )?;
    let outcome = (|| -> Result<()> {
        let previous = report.baseline_epoch.clone();
        let (epoch, activation) = apply_policy(
            &report.baseline_registry,
            &directory,
            &privileged,
            "activation",
            context.deadline,
        )?;
        if epoch.service_instance == previous.service_instance {
            return Err(CiError::Message(
                "actual restarted activation retained old service instance".into(),
            ));
        }
        report.observations[index].activation = Some(activation);
        let mut contract = context.activated.contract.clone();
        contract.expected_epoch = epoch;
        let request = report.observations[index].requested_contract.clone();
        retain(&request, &serde_json::to_vec(&contract)?)?;
        let mut challenge = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut challenge)?;
        if challenge == [0; 32] {
            return Err(CiError::Message("zero restart challenge".into()));
        }
        retain(&directory.join("challenge.bin"), &challenge)?;
        let challenge: String = challenge.iter().map(|byte| format!("{byte:02x}")).collect();
        let args = [OsString::from("tcp-http"), OsString::from(&challenge)];
        let duration = OsString::from(format!(
            "+{}ms",
            budget(context.deadline, Duration::from_secs(60))?
                .as_millis()
                .max(1)
        ));
        let launch = InstalledMixedLaunch::start(InstalledMixedLaunchInput {
            directory: &directory.join("frontend"),
            contract: &request,
            caller_uid: 65534,
            caller_gid: 65534,
            target_arguments: &args,
            deadline: &duration,
            memory: OsStr::new("+256M"),
        })?;
        report.observations[index].invocation =
            Some(directory.join("frontend/frontend-invocation.json"));
        report.observations[index].result = Some(launch.result.clone());
        report.observations[index].stdout = Some(launch.stdout.clone());
        report.observations[index].stderr = Some(launch.stderr.clone());
        report.launches.push(launch);
        let launch_index = report.launches.len() - 1;
        let relative = directory
            .strip_prefix(context.artifact_root)
            .map_err(|_| CiError::Message("restart artifacts escaped root".into()))?
            .join("prepared.json")
            .to_str()
            .ok_or_else(|| CiError::Message("restart artifact path not UTF-8".into()))?
            .to_owned();
        let observer = report.launches[launch_index].acquire_prepared(
            context.provider,
            &contract,
            context.artifact_root,
            &relative,
            budget(context.deadline, Duration::from_secs(30))?,
        )?;
        report.prepared_owners.push(observer);
        let observer_index = report.prepared_owners.len() - 1;
        let native_relative = directory
            .strip_prefix(context.artifact_root)
            .map_err(|_| {
                CiError::Message("restart native receipt leaves original artifact root".into())
            })?
            .join("prepared-native.json")
            .to_str()
            .ok_or_else(|| CiError::Message("restart native receipt path not UTF8".into()))?
            .to_owned();
        report.prepared_owners[observer_index]
            .persist_native_receipt(
                &context.identity.run_id,
                context.artifact_root,
                &native_relative,
            )
            .map_err(CiError::Message)?;
        report.prepared_owners[observer_index]
            .acknowledge(&report.launches[launch_index].observation_directory)
            .map_err(CiError::Message)?;
        let status = report.launches[launch_index]
            .wait_and_capture(budget(context.deadline, Duration::from_secs(60))?)?;
        report.observations[index].native_exit = status.code();
        let retired = report.prepared_owners[observer_index]
            .native_family_retired(&[])
            .map_err(CiError::Message)?;
        let retirement = directory.join("fresh-family-retirement.json");
        retain(
            &retirement,
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.linux-policy-restarted-family-retirement","revision":1,
            "prepared":report.prepared_owners[observer_index].observation,"native_family_retired":retired,
            "target_retirement":report.prepared_owners[observer_index].target.retirement_identity().map_err(CiError::Message)?,
            "namespace_init_retirement":report.prepared_owners[observer_index].namespace_init.retirement_identity().map_err(CiError::Message)?,
            "guardian_retirement":report.prepared_owners[observer_index].guardian.retirement_identity().map_err(CiError::Message)?,
            "old_control_retired":report.service_owners[old_index].exited().map_err(CiError::Message)?,
            "new_control_live":!report.service_owners[current_index].exited().map_err(CiError::Message)?}),
            )?,
        )?;
        report.observations[index]
            .transition_artifacts
            .extend([context.artifact_root.join(relative), retirement]);
        memcordon_core::result_v2::ResultV2::parse(&read_named(
            &report.launches[launch_index].result,
            4 * 1024 * 1024,
        )?)
        .map_err(CiError::Message)?;
        if !retired {
            return Err(CiError::Message(
                "fresh restarted family remains owned after capture".into(),
            ));
        }
        let key = memcordon_readiness_verifier::CaseKey {
            target: context.cell.target.clone(),
            channel: Some(context.cell.channel.clone()),
            family: "L-ID-03".into(),
            scenario: "restart-fresh-admission".into(),
            evidence_class: memcordon_readiness_verifier::EvidenceClass::InstalledProduct,
        };
        let prefix = format!(
            "{}/{}/policy-running/restart-fresh-admission",
            context.cell.target, context.cell.channel
        );
        std::fs::create_dir_all(context.artifact_root.join(&prefix))?;
        let collected = report.launches[launch_index].collect_completed(
            &report.prepared_owners[observer_index],
            &[],
            (*context.identity).clone(),
            context.lease_id.into(),
            key,
            challenge,
            prefix,
            &request,
            context.artifact_root,
            budget(context.cleanup_deadline, Duration::from_secs(30))?,
        )?;
        report.completed.push(collected);
        Ok(())
    })();
    match apply_policy(
        &report.baseline_registry,
        &directory,
        &privileged,
        "restoration",
        context.cleanup_deadline,
    ) {
        Ok((epoch, path)) => {
            report.baseline_epoch = epoch;
            report.observations[index].restoration = Some(path);
            report.restoration_required = false;
        }
        Err(error) => report
            .failures
            .push(format!("restart policy restoration remains owned: {error}")),
    }
    if let Err(error) = &outcome {
        report.observations[index].error = Some(error.to_string());
        report.failures.push(error.to_string());
    }
    retain(
        &directory.join("observation.json"),
        &serde_json::to_vec(&report.observations[index])?,
    )?;
    outcome
}

fn observe_control_service(
    directory: &Path,
    stage: &str,
    deadline: Instant,
    report: &mut PolicyCaseReport,
) -> Result<usize> {
    let output = observe_systemctl(
        directory,
        &format!("{stage}-show"),
        &[
            "show",
            "--property=MainPID",
            "--value",
            "memcordon-sealed-agent.service",
        ],
        deadline,
        report,
    )?;
    retain(
        &directory.join(stage).with_extension("service.stdout.bin"),
        &output.stdout,
    )?;
    retain(
        &directory.join(stage).with_extension("service.stderr.bin"),
        &output.stderr,
    )?;
    if !output.status.success() {
        return Err(CiError::Message(
            "actual owned control unit observation failed".into(),
        ));
    }
    let pid = std::str::from_utf8(&output.stdout)
        .map_err(|_| CiError::Message("native unit PID bytes not UTF-8".into()))?
        .trim()
        .parse::<u32>()
        .map_err(|error| CiError::Message(error.to_string()))?;
    let proc = Path::new("/proc").join(pid.to_string());
    let stat = std::fs::read_to_string(proc.join("stat"))?;
    let birth = stat
        .rsplit_once(')')
        .ok_or_else(|| CiError::Message("native control stat malformed".into()))?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| CiError::Message("native control birth absent".into()))?
        .parse::<u64>()
        .map_err(|error| CiError::Message(error.to_string()))?;
    let owner = crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid, birth)
        .map_err(CiError::Message)?;
    report.service_owners.push(owner);
    let index = report.service_owners.len() - 1;
    let actual = std::fs::read_link(proc.join("exe"))?;
    if actual != Path::new("/usr/libexec/memcordon-sealed-agent")
        || report.service_owners[index]
            .exited()
            .map_err(CiError::Message)?
    {
        return Err(CiError::Message(
            "actual owned control process image differs or retired".into(),
        ));
    }
    let image = hex_digest(&read_named(&actual, 512 * 1024 * 1024)?);
    if report.service_owners[index]
        .exited()
        .map_err(CiError::Message)?
    {
        return Err(CiError::Message(
            "held control process retired during image readback".into(),
        ));
    }
    retain(
        &directory.join(stage).with_extension("service-native.json"),
        &serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.linux-policy-control-service-native","revision":1,"stage":stage,
        "unit":"memcordon-sealed-agent.service","process_id":pid,"birth":birth,"image":actual,"image_sha256":image,
        "held_live":true,"native_unit_exit":output.status.code()}))?,
    )?;
    Ok(index)
}

fn observe_systemctl(
    directory: &Path,
    stem: &str,
    arguments: &[&str],
    deadline: Instant,
    report: &mut PolicyCaseReport,
) -> Result<memcordon_testkit::ObservedOutput> {
    use std::os::unix::process::ExitStatusExt;
    let program = Path::new("/usr/bin/systemctl");
    let selected = std::fs::symlink_metadata(program)?;
    if !selected.is_file()
        || selected.uid() != 0
        || selected.mode() & 0o022 != 0
        || selected.nlink() != 1
    {
        return Err(CiError::Message(
            "restart systemctl selected native image is not protected".into(),
        ));
    }
    let bytes = read_named(program, 512 * 1024 * 1024)?;
    let available = budget(deadline, Duration::from_secs(60))?;
    let invocation = serde_json::to_vec(
        &serde_json::json!({"format":"memcordon.linux-policy-control-command","revision":1,
        "program":program.as_os_str().as_bytes(),"arguments":arguments.iter().map(|value|value.as_bytes()).collect::<Vec<_>>(),
        "cwd":directory.as_os_str().as_bytes(),"environment":Vec::<serde_json::Value>::new(),
        "program_sha256":hex_digest(&bytes),"program_device":selected.dev(),"program_inode":selected.ino(),"budget_millis":available.as_millis()}),
    )?;
    retain(&directory.join(format!("{stem}-command.json")), &invocation)?;
    let mut creation = None;
    let output = CommandSpec::new(program, directory, available)
        .cleared_environment()
        .bounded_until(deadline)
        .args(arguments.iter().copied())
        .output_quiet_with_creation(|child| {
            let birth = crate::linux_consumer_readiness::process_birth(child.id())
                .map_err(CiError::Message)?;
            let mut owner =
                crate::linux_consumer_readiness::HeldLinuxProcess::acquire(child.id(), birth)
                    .map_err(CiError::Message)?;
            let image = if owner.exited().map_err(CiError::Message)? {
                None
            } else {
                Some(
                    owner
                        .hold_executable_image(deadline)
                        .map_err(CiError::Message)?,
                )
            };
            if image.as_ref().is_some_and(|image| {
                image["sha256"] != hex_digest(&bytes)
                    || image["device"] != selected.dev()
                    || image["inode"] != selected.ino()
            }) {
                return Err(CiError::Message(
                    "restart control command actual image differs".into(),
                ));
            }
            creation = Some(serde_json::json!({"pid":child.id(),"birth":birth,"image":image}));
            report.command_owners.push(owner);
            Ok(())
        })?;
    let owner = report
        .command_owners
        .last()
        .ok_or_else(|| CiError::Message("restart control command native owner absent".into()))?;
    let current = std::fs::symlink_metadata(program)?;
    if (current.dev(), current.ino()) != (selected.dev(), selected.ino())
        || read_named(program, 512 * 1024 * 1024)? != bytes
        || !owner.exited().map_err(CiError::Message)?
    {
        return Err(CiError::Message(
            "restart control command source changed or native owner unsettled".into(),
        ));
    }
    retain(
        &directory.join(format!("{stem}-command.stdout.bin")),
        &output.stdout,
    )?;
    retain(
        &directory.join(format!("{stem}-command.stderr.bin")),
        &output.stderr,
    )?;
    retain(
        &directory.join(format!("{stem}-command-exit.json")),
        &serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.linux-policy-control-command-exit","revision":1,"creation":creation.ok_or_else(||CiError::Message("restart actual command creation absent".into()))?,
        "retirement":owner.retirement_identity().map_err(CiError::Message)?,"raw_wait_status":output.status.into_raw(),"native_exit":output.status.code(),"signal":output.status.signal(),
        "invocation_sha256":hex_digest(&invocation),"stdout_sha256":hex_digest(&output.stdout),"stderr_sha256":hex_digest(&output.stderr)}))?,
    )?;
    Ok(output)
}

fn execute_transition(
    context: &PolicyCaseContext<'_>,
    report: &mut PolicyCaseReport,
    scenario: &str,
) -> Result<()> {
    let running = matches!(scenario, "drain-running" | "revoke-running");
    let final_release = scenario == "revoke-release";
    let directory = context.output.join(scenario);
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
    let privileged = report.privileged_policy_root.join(scenario);
    std::fs::create_dir(&privileged)?;
    std::fs::set_permissions(&privileged, std::fs::Permissions::from_mode(0o700))?;
    report
        .directory_custody
        .push(hold_admin_directory(&privileged)?);
    let index = report.observations.len();
    report.observations.push(PolicyCaseObservation {
        scenario: scenario.into(),
        expected_admission_code: "stale-epoch".into(),
        requested_contract: directory.join("contract.json"),
        activation: None,
        restoration: None,
        invocation: None,
        result: None,
        stdout: None,
        stderr: None,
        native_exit: None,
        error: None,
        transition_artifacts: Vec::new(),
    });
    report.restoration_required = true;
    retain(
        &directory.join("restoration-required.json"),
        &serde_json::to_vec(&report.baseline_registry)?,
    )?;
    let mut outcome = (|| -> Result<()> {
        let (epoch, activation) = apply_policy(
            &report.baseline_registry,
            &directory,
            &privileged,
            "activation",
            context.deadline,
        )?;
        report.observations[index].activation = Some(activation);
        let mut contract = context.activated.contract.clone();
        contract.expected_epoch = epoch;
        let request = report.observations[index].requested_contract.clone();
        retain(&request, &serde_json::to_vec(&contract)?)?;
        let mut challenge = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut challenge)?;
        if challenge == [0; 32] {
            return Err(CiError::Message("zero preparation challenge".into()));
        }
        retain(&directory.join("challenge.bin"), &challenge)?;
        let text: String = challenge.iter().map(|byte| format!("{byte:02x}")).collect();
        let arguments = [
            OsString::from(if running { "cooperation" } else { "tcp-http" }),
            OsString::from(&text),
        ];
        let duration = OsString::from(format!(
            "+{}ms",
            budget(context.deadline, Duration::from_secs(30))?
                .as_millis()
                .max(1)
        ));
        let launch = InstalledMixedLaunch::start(InstalledMixedLaunchInput {
            directory: &directory.join("frontend"),
            contract: &request,
            caller_uid: 65534,
            caller_gid: 65534,
            target_arguments: &arguments,
            deadline: &duration,
            memory: OsStr::new("+256M"),
        })?;
        report.observations[index].invocation =
            Some(directory.join("frontend/frontend-invocation.json"));
        report.observations[index].result = Some(launch.result.clone());
        report.observations[index].stdout = Some(launch.stdout.clone());
        report.observations[index].stderr = Some(launch.stderr.clone());
        report.launches.push(launch);
        let launch_index = report.launches.len() - 1;
        let relative = directory
            .strip_prefix(context.artifact_root)
            .map_err(|_| CiError::Message("prepared artifact escaped root".into()))?
            .join("prepared.json")
            .to_str()
            .ok_or_else(|| CiError::Message("prepared artifact path not UTF-8".into()))?
            .to_owned();
        let observer = report.launches[launch_index].acquire_prepared(
            context.provider,
            &contract,
            context.artifact_root,
            &relative,
            budget(context.deadline, Duration::from_secs(30))?,
        )?;
        report.prepared_owners.push(observer);
        let observer_index = report.prepared_owners.len() - 1;
        let native_relative = directory
            .strip_prefix(context.artifact_root)
            .map_err(|_| CiError::Message("native prepared artifact escaped root".into()))?
            .join("prepared-native.json")
            .to_str()
            .ok_or_else(|| CiError::Message("native prepared path not UTF-8".into()))?
            .to_owned();
        report.prepared_owners[observer_index]
            .persist_native_receipt(
                &context.identity.run_id,
                context.artifact_root,
                &native_relative,
            )
            .map_err(CiError::Message)?;
        report.observations[index].transition_artifacts.extend([
            context.artifact_root.join(relative),
            context.artifact_root.join(native_relative),
        ]);
        let descendant_start = report.descendant_owners.len();
        if final_release {
            let observations = &report.launches[launch_index].observation_directory;
            let marker = observations.join("release-observer.json");
            publish_caller_observation(
                &marker,
                &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.mixed-release-observer","revision":2}))?,
                65534,
            )?;
            // Worker cannot send the second observation until the ordinary
            // prepared ACK passes its first native barrier.
            report.prepared_owners[observer_index]
                .acknowledge(observations)
                .map_err(CiError::Message)?;
            let attempt = report.prepared_owners[observer_index]
                .observation
                .admission
                .attempt_id
                .as_str();
            let path = observations
                .join(attempt)
                .with_extension("release-prepared.json");
            loop {
                if path.exists() {
                    break;
                }
                if report.prepared_owners[observer_index]
                    .target
                    .exited()
                    .map_err(CiError::Message)?
                {
                    return Err(CiError::Message(
                        "prepared target retired before final leased-release observation".into(),
                    ));
                }
                budget(context.deadline, Duration::from_secs(1))?;
                std::thread::sleep(Duration::from_millis(10));
            }
            let raw = read_named(&path, 1024 * 1024)?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&raw)
                .map_err(CiError::Message)?;
            let release: serde_json::Value = serde_json::from_slice(&raw)?;
            if release["format"] != "memcordon.mixed-release-observation"
                || release["revision"] != 2
                || release["authorizes_launch"] != false
                || release["prepared"]
                    != serde_json::to_value(&report.prepared_owners[observer_index].observation)?
            {
                return Err(CiError::Message("actual final release observation differs from original held native preparation".into()));
            }
            let retained = directory.join("release-prepared.json");
            retain(&retained, &raw)?;
            report.observations[index]
                .transition_artifacts
                .push(retained);
        }
        if running {
            report.prepared_owners[observer_index]
                .acknowledge(&report.launches[launch_index].observation_directory)
                .map_err(CiError::Message)?;
            let row = wait_cooperation(
                &report.launches[launch_index].stdout,
                &text,
                context.deadline,
                &report.prepared_owners[observer_index].target,
            )?;
            report.launches[launch_index].hold_fixture_tree_into(
                &report.prepared_owners[observer_index],
                &row.observation,
                &mut report.descendant_owners,
            )?;
            let identities = report.descendant_owners[descendant_start..]
                .iter()
                .map(|child| child.retirement_identity().map_err(CiError::Message))
                .collect::<Result<Vec<_>>>()?;
            let snapshots = report.descendant_owners[descendant_start..]
                .iter()
                .map(|child| child.live_snapshot().map_err(CiError::Message))
                .collect::<Result<Vec<_>>>()?;
            let held_path = directory.join("running-native-held.json");
            retain(
                &held_path,
                &serde_json::to_vec(
                    &serde_json::json!({"format":"memcordon.linux-policy-running-native-held","revision":1,
                "attempt_id":report.prepared_owners[observer_index].observation.admission.attempt_id,
                "target":report.prepared_owners[observer_index].observation.target,"challenge":text,
                "fixture_row":row,"held_descendants":identities,"native_descendants":snapshots }),
                )?,
            )?;
            report.observations[index]
                .transition_artifacts
                .push(held_path);
        }
        let mut revoked = serde_json::to_value(&report.baseline_registry)?;
        revoked["grants"][0]["enabled"] = false.into();
        revoked["active_attempt_disposition"] =
            serde_json::to_value(if scenario == "drain-running" {
                memcordon_core::workload_registry::GrantChangeDisposition::DrainExisting
            } else {
                memcordon_core::workload_registry::GrantChangeDisposition::RevokeActive
            })?;
        let revoked: RuntimePrivatePolicyRegistryV3 = serde_json::from_value(revoked)?;
        let (revoked_epoch, applied) = apply_policy(
            &revoked,
            &directory,
            &privileged,
            "revocation",
            context.deadline,
        )?;
        report.observations[index]
            .transition_artifacts
            .push(applied);
        if running {
            let mut fresh_request = contract.clone();
            fresh_request.expected_epoch = revoked_epoch;
            let fresh_path = directory.join("fresh-contract.json");
            retain(&fresh_path, &serde_json::to_vec(&fresh_request)?)?;
            let mut fresh_challenge = [0u8; 32];
            File::open("/dev/urandom")?.read_exact(&mut fresh_challenge)?;
            if fresh_challenge == [0; 32] || fresh_challenge == challenge {
                return Err(CiError::Message(
                    "fresh admission challenge was not independently fresh".into(),
                ));
            }
            let fresh_challenge_path = directory.join("fresh-challenge.bin");
            retain(&fresh_challenge_path, &fresh_challenge)?;
            let fresh_text: String = fresh_challenge
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let fresh_arguments = [OsString::from("tcp-http"), OsString::from(fresh_text)];
            let fresh_duration = OsString::from(format!(
                "+{}ms",
                budget(context.deadline, Duration::from_secs(10))?
                    .as_millis()
                    .max(1)
            ));
            let fresh_directory = directory.join("fresh-frontend");
            let fresh = InstalledMixedLaunch::start(InstalledMixedLaunchInput {
                directory: &fresh_directory,
                contract: &fresh_path,
                caller_uid: 65534,
                caller_gid: 65534,
                target_arguments: &fresh_arguments,
                deadline: &fresh_duration,
                memory: OsStr::new("+256M"),
            })?;
            let fresh_result = fresh.result.clone();
            let fresh_stdout = fresh.stdout.clone();
            let fresh_stderr = fresh.stderr.clone();
            report.launches.push(fresh);
            let fresh_index = report.launches.len() - 1;
            report.launches[fresh_index]
                .wait_and_capture(budget(context.deadline, Duration::from_secs(15))?)?;
            let fresh_exit = directory.join("fresh-exit.json");
            retain(
                &fresh_exit,
                &serde_json::to_vec(&report.launches[fresh_index].retained_frontend_wait()?)?,
            )?;
            memcordon_core::result_v2::ResultV2::parse(&read_named(
                &fresh_result,
                4 * 1024 * 1024,
            )?)
            .map_err(CiError::Message)?;
            report.observations[index].transition_artifacts.extend([
                fresh_path,
                fresh_challenge_path,
                fresh_result,
                fresh_stdout,
                fresh_stderr,
                fresh_directory.join("frontend-invocation.json"),
                fresh_exit,
            ]);
        }
        let acknowledgment = if final_release {
            let observations = &report.launches[launch_index].observation_directory;
            let attempt = report.prepared_owners[observer_index]
                .observation
                .admission
                .attempt_id
                .as_str();
            let original = observations
                .join(attempt)
                .with_extension("observer-ack.json");
            let mut ack: serde_json::Value =
                serde_json::from_slice(&read_named(&original, 64 * 1024)?)?;
            ack["format"] = "memcordon.mixed-release-observer-acknowledgment".into();
            let bytes = serde_json::to_vec(&ack)?;
            let retained = directory.join("release-observer-ack.json");
            retain(&retained, &bytes)?;
            report.observations[index]
                .transition_artifacts
                .push(retained);
            publish_caller_observation(
                &observations
                    .join(attempt)
                    .with_extension("release-observer-ack.json"),
                &bytes,
                65534,
            )
            .map_err(|error| error.to_string())
        } else if running {
            Ok(())
        } else {
            report.prepared_owners[observer_index]
                .acknowledge(&report.launches[launch_index].observation_directory)
        };
        let ack_path = directory.join("observer-ack-operation.json");
        retain(
            &ack_path,
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.linux-policy-observer-ack-operation","revision":1,
            "after_revocation":!running,"acknowledgment_published":acknowledgment.is_ok(),"error":acknowledgment.err()}),
            )?,
        )?;
        report.observations[index]
            .transition_artifacts
            .push(ack_path);
        if scenario == "drain-running" {
            if report.prepared_owners[observer_index]
                .target
                .exited()
                .map_err(CiError::Message)?
            {
                return Err(CiError::Message(
                    "drained existing target retired before owned fixture release".into(),
                ));
            }
            let after = serde_json::json!({"format":"memcordon.linux-policy-running-after-revocation","revision":1,
                "attempt_id":report.prepared_owners[observer_index].observation.admission.attempt_id,
                "target":report.prepared_owners[observer_index].target.retirement_identity().map_err(CiError::Message)?,
                "descendants":report.descendant_owners[descendant_start..].iter().map(|child|child.retirement_identity().map_err(CiError::Message)).collect::<Result<Vec<_>>>()?});
            retain(
                &directory.join("running-after-revocation.json"),
                &serde_json::to_vec(&after)?,
            )?;
            report.launches[launch_index].release_fixture_barrier()?;
        }
        let status = report.launches[launch_index]
            .wait_and_capture(budget(context.deadline, Duration::from_secs(60))?)?;
        report.observations[index].native_exit = status.code();
        let retirement = report.prepared_owners[observer_index]
            .native_family_retired(&report.descendant_owners[descendant_start..])
            .map_err(CiError::Message)?;
        let retired_path = directory.join("prepared-family-retirement.json");
        let actual = &report.prepared_owners[observer_index].observation;
        let target_retirement = report.prepared_owners[observer_index]
            .target
            .retirement_identity()
            .map_err(CiError::Message)?;
        let namespace_init_retirement = report.prepared_owners[observer_index]
            .namespace_init
            .retirement_identity()
            .map_err(CiError::Message)?;
        let guardian_retirement = report.prepared_owners[observer_index]
            .guardian
            .retirement_identity()
            .map_err(CiError::Message)?;
        let descendants = report.descendant_owners[descendant_start..]
            .iter()
            .map(|child| child.retirement_identity().map_err(CiError::Message))
            .collect::<Result<Vec<_>>>()?;
        retain(
            &retired_path,
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.linux-policy-prepared-family-retirement","revision":1,
            "attempt_id":actual.admission.attempt_id,"admission_nonce":actual.admission.admission_nonce,
            "target":actual.target,"namespace_init":actual.namespace_init,"guardian":actual.guardian,
            "target_retirement":target_retirement,"namespace_init_retirement":namespace_init_retirement,"guardian_retirement":guardian_retirement,
            "held_before_revocation":true,"native_family_retired":retirement,"held_descendants":descendants}),
            )?,
        )?;
        report.observations[index]
            .transition_artifacts
            .push(retired_path);
        let bytes = read_named(&report.launches[launch_index].result, 4 * 1024 * 1024)?;
        memcordon_core::result_v2::ResultV2::parse(&bytes).map_err(CiError::Message)?;
        if !retirement {
            return Err(CiError::Message(
                "prepared family retirement remains owned and uncertain".into(),
            ));
        }
        if running {
            let key = memcordon_readiness_verifier::CaseKey {
                target: context.cell.target.clone(),
                channel: Some(context.cell.channel.clone()),
                family: "L-ID-03".into(),
                scenario: scenario.into(),
                evidence_class: memcordon_readiness_verifier::EvidenceClass::InstalledProduct,
            };
            let prefix = format!(
                "{}/{}/policy-running/{scenario}",
                context.cell.target, context.cell.channel
            );
            std::fs::create_dir_all(context.artifact_root.join(&prefix))?;
            let collected = report.launches[launch_index].collect_completed(
                &report.prepared_owners[observer_index],
                &report.descendant_owners[descendant_start..],
                (*context.identity).clone(),
                context.lease_id.into(),
                key,
                text.clone(),
                prefix,
                &request,
                context.artifact_root,
                budget(context.cleanup_deadline, Duration::from_secs(30))?,
            )?;
            report.completed.push(collected);
        }
        Ok(())
    })();
    match apply_policy(
        &report.baseline_registry,
        &directory,
        &privileged,
        "restoration",
        context.cleanup_deadline,
    ) {
        Ok((epoch, path)) => {
            report.baseline_epoch = epoch;
            report.observations[index].restoration = Some(path);
            report.restoration_required = false;
        }
        Err(error) => report.failures.push(format!(
            "preparation policy restoration remains owned: {error}"
        )),
    }
    if outcome.is_ok() && !report.restoration_required {
        if let Err(error) = persist_transition_census(context, report, index, scenario) {
            outcome = Err(error);
        }
    }
    if let Err(error) = &outcome {
        report.observations[index].error = Some(error.to_string());
        report.failures.push(error.to_string());
    }
    retain(
        &directory.join("observation.json"),
        &serde_json::to_vec(&report.observations[index])?,
    )?;
    outcome
}

fn persist_transition_census(
    context: &PolicyCaseContext<'_>,
    report: &mut PolicyCaseReport,
    index: usize,
    scenario: &str,
) -> Result<()> {
    let result = report.observations[index]
        .result
        .as_ref()
        .ok_or_else(|| CiError::Message("transition actual result absent".into()))?;
    let launch = report
        .launches
        .iter()
        .find(|launch| launch.result == *result)
        .ok_or_else(|| CiError::Message("transition original frontend owner absent".into()))?;
    let mut requests = Vec::new();
    for (ordinal, entry) in std::fs::read_dir(&launch.observation_directory)?.enumerate() {
        if ordinal >= 128 {
            return Err(CiError::Message(
                "transition raw artifact count exceeds bound".into(),
            ));
        }
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".provider-request.bin"))
        {
            requests.push(path);
        }
    }
    if requests.len() != 1 {
        return Err(CiError::Message(
            "transition requires exact original provider request".into(),
        ));
    }
    let request = &requests[0];
    let attempt = request
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".provider-request.bin"))
        .filter(|name| {
            name.len() == 32
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| CiError::Message("transition original attempt filename differs".into()))?;
    let destination = result
        .parent()
        .ok_or_else(|| CiError::Message("transition result parent absent".into()))?
        .join("native-census.json");
    super::linux_mixed_installed::persist_policy_refusal_census(
        context.account,
        context.provider,
        context.identity,
        context.cell,
        context.lease_id,
        scenario,
        attempt,
        &read_named(result, 4 * 1024 * 1024)?,
        &read_named(request, 4 * 1024 * 1024)?,
        &destination,
        context.cleanup_deadline,
    )?;
    report.observations[index]
        .transition_artifacts
        .push(destination);
    if ["drain-running", "revoke-running"].contains(&scenario) {
        let directory = report.observations[index]
            .requested_contract
            .parent()
            .ok_or_else(|| CiError::Message("running policy original directory absent".into()))?;
        let result = directory.join("fresh-frontend/result.json");
        let launch = report
            .launches
            .iter()
            .find(|launch| launch.result == result)
            .ok_or_else(|| {
                CiError::Message("running policy fresh original frontend absent".into())
            })?;
        let paths = std::fs::read_dir(&launch.observation_directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".provider-request.bin"))
            })
            .collect::<Vec<_>>();
        if paths.len() != 1 {
            return Err(CiError::Message(
                "running policy fresh request is not unique".into(),
            ));
        }
        let attempt = paths[0]
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".provider-request.bin"))
            .ok_or_else(|| CiError::Message("fresh original native attempt absent".into()))?;
        let destination = directory.join("fresh-native-census.json");
        super::linux_mixed_installed::persist_policy_refusal_census(
            context.account,
            context.provider,
            context.identity,
            context.cell,
            context.lease_id,
            scenario,
            attempt,
            &read_named(&result, 4 * 1024 * 1024)?,
            &read_named(&paths[0], 4 * 1024 * 1024)?,
            &destination,
            context.cleanup_deadline,
        )?;
        report.observations[index]
            .transition_artifacts
            .push(destination);
    }
    Ok(())
}

fn execute_binding(
    context: &PolicyCaseContext<'_>,
    report: &mut PolicyCaseReport,
    directory: &Path,
    scenario: &str,
    code: &str,
) -> Result<()> {
    std::fs::create_dir(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))?;
    let observation = PolicyCaseObservation {
        scenario: scenario.into(),
        expected_admission_code: code.into(),
        requested_contract: directory.join("contract.json"),
        activation: None,
        restoration: None,
        invocation: None,
        result: None,
        stdout: None,
        stderr: None,
        native_exit: None,
        error: None,
        transition_artifacts: Vec::new(),
    };
    let index = report.observations.len();
    report.observations.push(observation);
    // Persist the restoration obligation before the first policy mutation.
    report.restoration_required = true;
    retain(
        &directory.join("restoration-required.json"),
        &serde_json::to_vec(&report.baseline_registry)?,
    )?;
    let mut result = (|| -> Result<()> {
        let privileged = report.privileged_policy_root.join(scenario);
        std::fs::create_dir(&privileged)?;
        std::fs::set_permissions(&privileged, std::fs::Permissions::from_mode(0o700))?;
        report
            .directory_custody
            .push(hold_admin_directory(&privileged)?);
        let mut policy = serde_json::to_value(&report.baseline_registry)?;
        if scenario == "disabled-grant" {
            policy["grants"][0]["enabled"] = false.into();
        }
        if scenario == "changed-grant" {
            policy["grants"][0]["revision"] = 2.into();
        }
        let policy: RuntimePrivatePolicyRegistryV3 = serde_json::from_value(policy)?;
        let (epoch, activation) = apply_policy(
            &policy,
            directory,
            &privileged,
            "activation",
            context.deadline,
        )?;
        report.observations[index].activation = Some(activation);
        let mut request = serde_json::to_value(&context.activated.contract)?;
        request["expected_epoch"] = serde_json::to_value(&epoch)?;
        let different_digest = hex_digest(scenario.as_bytes());
        match scenario {
            "wrong-plan" => {
                request["workload_plan_digest"] = different_digest.clone().into();
                request["authorization"]["approved_plan_digest"] = different_digest.into();
            }
            "wrong-image" => request["runtime_image"]["id"] = "owned-readiness-wrong-image".into(),
            "wrong-profile" => {
                request["authorized_profile"]["semantic_digest"] = different_digest.into()
            }
            "wrong-identity" => {
                request["execution_identity"]["identity"]["digest"] = different_digest.into()
            }
            "wrong-digest" => request["runtime_image"]["digest"] = different_digest.into(),
            "wrong-epoch" => {
                request["expected_epoch"] = serde_json::to_value(&report.baseline_epoch)?
            }
            "wrong-caller" | "disabled-grant" | "changed-grant" | "revoke-discovery" => {}
            _ => return Err(CiError::Message("unfrozen binding scenario".into())),
        }
        let contract: WorkloadContractV3 = serde_json::from_value(request)?;
        contract.validate().map_err(CiError::Message)?;
        if scenario == "revoke-discovery" {
            let discovery_contract = directory.join("discovery-contract.json");
            retain(&discovery_contract, &serde_json::to_vec(&contract)?)?;
            let arguments = vec![
                OsString::from("--reuid"),
                OsString::from("65534"),
                OsString::from("--regid"),
                OsString::from("65534"),
                OsString::from("--clear-groups"),
                OsString::from("--"),
                OsString::from("/usr/libexec/memcordon"),
                OsString::from("doctor"),
                OsString::from("--json"),
                OsString::from("--capability-format"),
                OsString::from("capabilities-v2"),
                OsString::from("--require"),
                OsString::from("sealed"),
                OsString::from("--workload-contract"),
                discovery_contract.clone().into_os_string(),
            ];
            let invocation = directory.join("discovery-invocation.json");
            use std::os::unix::ffi::OsStrExt;
            retain(
                &invocation,
                &serde_json::to_vec(
                    &serde_json::json!({"format":"memcordon.linux-policy-discovery-invocation","revision":1,
                "program":b"/usr/bin/setpriv","arguments":arguments.iter().map(|arg|arg.as_os_str().as_bytes()).collect::<Vec<_>>(),
                "caller_uid":65534,"caller_gid":65534,"environment_cleared":true,
                "cli_sha256":hex_digest(&read_named(Path::new("/usr/libexec/memcordon"),512*1024*1024)?) }),
                )?,
            )?;
            let output = CommandSpec::new(
                "/usr/bin/setpriv",
                directory,
                budget(context.deadline, Duration::from_secs(30))?,
            )
            .bounded_until(context.deadline)
            .args(arguments)
            .output_quiet()?;
            let discovery = directory.join("discovery.json");
            let stderr = directory.join("discovery.stderr.bin");
            let status = directory.join("discovery.exit.json");
            retain(&discovery, &output.stdout)?;
            retain(&stderr, &output.stderr)?;
            retain(
                &status,
                &serde_json::to_vec(&serde_json::json!({"native_exit":output.status.code(),
                    "stdout_sha256":hex_digest(&output.stdout),"stderr_sha256":hex_digest(&output.stderr)}))?,
            )?;
            report.observations[index].transition_artifacts.extend([
                discovery_contract,
                invocation,
                discovery,
                stderr,
                status,
            ]);
            if !output.status.success() {
                return Err(CiError::Message("actual pre-revocation discovery was unavailable; no advisory authority invented".into()));
            }
            memcordon_core::canonical_json::reject_duplicate_json_keys(&output.stdout)
                .map_err(CiError::Message)?;
            let _: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            let mut revoked = serde_json::to_value(&report.baseline_registry)?;
            revoked["grants"][0]["enabled"] = false.into();
            let revoked: RuntimePrivatePolicyRegistryV3 = serde_json::from_value(revoked)?;
            let (_, applied) = apply_policy(
                &revoked,
                directory,
                &privileged,
                "discovery-revocation",
                context.deadline,
            )?;
            report.observations[index]
                .transition_artifacts
                .push(applied);
            // Launch retains the discovered epoch. Advisory discovery cannot
            // substitute for the provider's current preparation decision.
        }
        let path = report.observations[index].requested_contract.clone();
        retain(&path, &serde_json::to_vec(&contract)?)?;
        let caller = if scenario == "wrong-caller" {
            65533
        } else {
            65534
        };
        let mut challenge = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut challenge)?;
        if challenge == [0; 32] {
            return Err(CiError::Message(
                "fresh policy challenge is all zero".into(),
            ));
        }
        retain(&directory.join("challenge.bin"), &challenge)?;
        let challenge_text: String = challenge.iter().map(|byte| format!("{byte:02x}")).collect();
        let target_arguments = [OsString::from("tcp-http"), OsString::from(challenge_text)];
        let native_deadline = OsString::from(format!(
            "+{}ms",
            budget(context.deadline, Duration::from_secs(30))?
                .as_millis()
                .max(1)
        ));
        let launch = InstalledMixedLaunch::start(InstalledMixedLaunchInput {
            directory: &directory.join("frontend"),
            contract: &path,
            caller_uid: caller,
            caller_gid: caller,
            target_arguments: &target_arguments,
            deadline: &native_deadline,
            memory: OsStr::new("+256M"),
        })?;
        report.observations[index].invocation =
            Some(directory.join("frontend/frontend-invocation.json"));
        report.observations[index].result = Some(launch.result.clone());
        report.observations[index].stdout = Some(launch.stdout.clone());
        report.observations[index].stderr = Some(launch.stderr.clone());
        report.launches.push(launch);
        let launch = report.launches.last_mut().expect("retained launch owner");
        let remaining = budget(context.deadline, Duration::from_secs(60))?;
        let status = launch.wait_and_capture(remaining)?;
        report.observations[index].native_exit = status.code();
        // Decode actual bytes for shape/custody only; no producer-side verdict.
        let bytes = read_named(&launch.result, 4 * 1024 * 1024)?;
        memcordon_core::result_v2::ResultV2::parse(&bytes).map_err(CiError::Message)?;
        Ok(())
    })();
    let restoration = apply_policy(
        &report.baseline_registry,
        directory,
        &report.privileged_policy_root.join(scenario),
        "restoration",
        context.cleanup_deadline,
    );
    match restoration {
        Ok((epoch, path)) => {
            report.baseline_epoch = epoch;
            report.observations[index].restoration = Some(path);
            report.restoration_required = false;
        }
        Err(error) => report
            .failures
            .push(format!("policy restoration remains owned: {error}")),
    }
    if result.is_ok() && report.restoration_required {
        result = Err(CiError::Message(
            "policy restoration remains unresolved before native census".into(),
        ));
    }
    if result.is_ok() && !report.restoration_required {
        let census = (|| -> Result<()> {
            let result_path = report.observations[index]
                .result
                .as_ref()
                .ok_or_else(|| CiError::Message("policy result path absent".into()))?;
            let launch = report
                .launches
                .iter()
                .find(|launch| &launch.result == result_path)
                .ok_or_else(|| {
                    CiError::Message("policy result has no retained frontend owner".into())
                })?;
            let mut requests = Vec::new();
            for (ordinal, entry) in std::fs::read_dir(&launch.observation_directory)?.enumerate() {
                if ordinal >= 128 {
                    return Err(CiError::Message(
                        "policy observation directory exceeds bound".into(),
                    ));
                }
                let path = entry?.path();
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".provider-request.bin"))
                {
                    requests.push(path);
                }
            }
            if requests.len() != 1 {
                return Err(CiError::Message(
                    "policy refusal requires one actual provider request".into(),
                ));
            }
            let request = &requests[0];
            let attempt = request
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".provider-request.bin"))
                .filter(|name| {
                    name.len() == 32
                        && name
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or_else(|| {
                    CiError::Message("policy request attempt basename differs".into())
                })?;
            let destination = result_path
                .parent()
                .ok_or_else(|| CiError::Message("policy result parent absent".into()))?
                .join("native-census.json");
            super::linux_mixed_installed::persist_policy_refusal_census(
                context.account,
                context.provider,
                context.identity,
                context.cell,
                context.lease_id,
                scenario,
                attempt,
                &read_named(result_path, 4 * 1024 * 1024)?,
                &read_named(request, 4 * 1024 * 1024)?,
                &destination,
                context.cleanup_deadline,
            )?;
            report.observations[index]
                .transition_artifacts
                .push(destination);
            Ok(())
        })();
        if let Err(error) = census {
            result = Err(error);
        }
    }
    if let Err(error) = &result {
        report.observations[index].error = Some(error.to_string());
    }
    retain(
        &directory.join("observation.json"),
        &serde_json::to_vec(&report.observations[index])?,
    )?;
    result
}

pub(super) fn apply_policy(
    registry: &RuntimePrivatePolicyRegistryV3,
    directory: &Path,
    privileged: &Path,
    stem: &str,
    deadline: Instant,
) -> Result<(PolicyEpoch, PathBuf)> {
    registry.validate().map_err(CiError::Message)?;
    let input = directory.join(stem).with_extension("policy.json");
    let bytes = serde_json::to_vec(registry)?;
    retain(&input, &bytes)?;
    let privileged_input = privileged.join(stem).with_extension("policy.json");
    retain(&privileged_input, &bytes)?;
    let policy_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&privileged_input)?;
    let selected = policy_file.metadata()?;
    if selected.uid() != 0
        || selected.mode() & 0o022 != 0
        || read_named(&privileged_input, bytes.len() as u64)? != bytes
    {
        return Err(CiError::Message(
            "privileged policy source custody differs".into(),
        ));
    }
    let agent_path = Path::new("/usr/libexec/memcordon-sealed-agent");
    let agent_ancestors = [Path::new("/"), Path::new("/usr"), Path::new("/usr/libexec")]
        .into_iter()
        .map(|path| hold_admin_directory(path).map(|held| (path, held)))
        .collect::<Result<Vec<_>>>()?;
    let agent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(agent_path)?;
    let agent_metadata = agent.metadata()?;
    if !agent_metadata.is_file() || agent_metadata.uid() != 0 || agent_metadata.mode() & 0o022 != 0
    {
        return Err(CiError::Message(
            "selected policy agent is not protected native file".into(),
        ));
    }
    let agent_bytes = read_named(agent_path, 512 * 1024 * 1024)?;
    let arguments = [
        OsString::from("package"),
        OsString::from("policy"),
        OsString::from("apply"),
        OsString::from("--file"),
        privileged_input.clone().into_os_string(),
    ];
    let invocation_path = directory.join(stem).with_extension("invocation.json");
    let available = budget(deadline, Duration::from_secs(60))?;
    let invocation = serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.linux-policy-activation-command","revision":1,
        "agent_sha256":hex::encode(Sha256::digest(&agent_bytes)),
        "program":agent_path.as_os_str().as_bytes(),
        "arguments":arguments.iter().map(|argument| argument.as_os_str().as_bytes()).collect::<Vec<_>>(),
        "cwd":directory.as_os_str().as_bytes(),
        "environment_cleared":true,"budget_millis":available.as_millis(),
        "policy_sha256":hex::encode(Sha256::digest(&bytes))
    }))?;
    retain(&invocation_path, &invocation)?;
    let mut command = CommandSpec::new(agent_path, directory, available)
        .bounded_until(deadline)
        .args(arguments)
        .materialize()?;
    command.env_clear();
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        budget(deadline, available)?,
        2 * 1024 * 1024,
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let agent_named = std::fs::symlink_metadata(agent_path)?;
    for (path, held) in &agent_ancestors {
        let current = held.metadata()?;
        let named = std::fs::symlink_metadata(path)?;
        if !named.is_dir()
            || current.uid() != 0
            || current.mode() & 0o022 != 0
            || (current.dev(), current.ino()) != (named.dev(), named.ino())
        {
            return Err(CiError::Message(
                "selected policy agent ancestry changed during actual apply".into(),
            ));
        }
    }
    if (agent_named.dev(), agent_named.ino()) != (agent_metadata.dev(), agent_metadata.ino())
        || read_named(agent_path, 512 * 1024 * 1024)? != agent_bytes
    {
        return Err(CiError::Message(
            "selected policy agent changed during native apply".into(),
        ));
    }
    let named = std::fs::symlink_metadata(&privileged_input)?;
    if (named.dev(), named.ino()) != (selected.dev(), selected.ino())
        || read_named(&privileged_input, bytes.len() as u64)? != bytes
    {
        return Err(CiError::Message(
            "privileged policy input changed during actual apply".into(),
        ));
    }
    retain(
        &directory.join(stem).with_extension("stderr.bin"),
        &output.stderr,
    )?;
    let path = directory.join(stem).with_extension("json");
    retain(&path, &output.stdout)?;
    retain(
        &directory.join(stem).with_extension("exit.json"),
        &serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.linux-policy-activation-exit","revision":1,
        "native_exit":output.status.code(),"success":output.status.success(),
        "invocation_sha256":hex::encode(Sha256::digest(&invocation)),
        "stdout_sha256":hex::encode(Sha256::digest(&output.stdout)),
        "stderr_sha256":hex::encode(Sha256::digest(&output.stderr))}))?,
    )?;
    if !output.status.success() {
        return Err(CiError::Message(
            "actual policy apply failed; raw products retained".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&output.stdout)
        .map_err(CiError::Message)?;
    let actual: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    if actual["format"] != "memcordon.local-private-activation"
        || actual["revision"] != 2
        || actual["registry"] != serde_json::to_value(registry)?
        || actual["registry_digest"]
            != serde_json::to_value(registry.canonical_digest().map_err(CiError::Message)?)?
    {
        return Err(CiError::Message(
            "actual activation differs from exact requested registry".into(),
        ));
    }
    Ok((serde_json::from_value(actual["epoch"].clone())?, path))
}

fn budget(deadline: Instant, cap: Duration) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now()).min(cap);
    if remaining.is_zero() {
        return Err(CiError::Message(
            "original policy operation deadline exhausted; owners retained".into(),
        ));
    }
    Ok(remaining)
}

fn wait_cooperation(
    path: &Path,
    challenge: &str,
    deadline: Instant,
    target: &crate::linux_consumer_readiness::HeldLinuxProcess,
) -> Result<crate::linux_consumer_readiness::LinuxTranscriptRow> {
    loop {
        if target.exited().map_err(CiError::Message)? {
            return Err(CiError::Message(
                "native running target retired before held barrier observation".into(),
            ));
        }
        if path.exists() {
            // Capture is an owned live writer. Only an incomplete final line
            // is tolerated; complete records retain strict JSON/stage checks.
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            let held = file.metadata()?;
            if !held.is_file() || held.nlink() != 1 || held.len() > 1024 * 1024 {
                return Err(CiError::Message(
                    "live cooperation capture exceeds finite bound".into(),
                ));
            }
            let mut bytes = Vec::new();
            std::io::Read::by_ref(&mut file)
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            let named = std::fs::symlink_metadata(path)?;
            if !named.is_file()
                || (named.dev(), named.ino()) != (held.dev(), held.ino())
                || bytes.len() > 1024 * 1024
            {
                return Err(CiError::Message(
                    "live cooperation named capture custody differs".into(),
                ));
            }
            if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
                let line = &bytes[..end];
                memcordon_core::canonical_json::reject_duplicate_json_keys(line)
                    .map_err(CiError::Message)?;
                let row: crate::linux_consumer_readiness::LinuxTranscriptRow =
                    serde_json::from_slice(line)?;
                if row.sequence != 1
                    || row.challenge != challenge
                    || row.operation != "same-attempt-cooperation-held"
                {
                    return Err(CiError::Message(
                        "actual running fixture challenge/stage differs".into(),
                    ));
                }
                if target.exited().map_err(CiError::Message)? {
                    return Err(CiError::Message(
                        "running barrier target ceased to be held live".into(),
                    ));
                }
                return Ok(row);
            }
        }
        if Instant::now() >= deadline {
            return Err(CiError::Message(
                "running fixture remains owned before observation cutoff".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn retain(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o644)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let held = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if held.nlink() != 1
        || !named.is_file()
        || (held.dev(), held.ino()) != (named.dev(), named.ino())
        || read_named(path, bytes.len() as u64)? != bytes
    {
        return Err(CiError::Message(
            "policy artifact named custody/readback differs".into(),
        ));
    }
    File::open(
        path.parent()
            .ok_or_else(|| CiError::Message("artifact parent absent".into()))?,
    )?
    .sync_all()?;
    Ok(())
}

fn read_named(path: &Path, bound: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.nlink() != 1 || before.len() > bound {
        return Err(CiError::Message(
            "policy evidence type/length differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(bound + 1)
        .read_to_end(&mut bytes)?;
    let named = std::fs::symlink_metadata(path)?;
    let after = file.metadata()?;
    if !named.is_file()
        || (named.dev(), named.ino()) != (before.dev(), before.ino())
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || bytes.len() as u64 != before.len()
    {
        return Err(CiError::Message(
            "policy evidence changed during native read".into(),
        ));
    }
    Ok(bytes)
}

fn hold_admin_directory(path: &Path) -> Result<File> {
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(path)?;
    let before = held.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if !before.is_dir()
        || before.uid() != 0
        || before.mode() & 0o022 != 0
        || !named.is_dir()
        || (before.dev(), before.ino()) != (named.dev(), named.ino())
    {
        return Err(CiError::Message(
            "selected privileged policy directory is not protected root-owned native custody"
                .into(),
        ));
    }
    Ok(held)
}

fn publish_caller_observation(path: &Path, bytes: &[u8], uid: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    rustix::fs::fchown(&file, Some(rustix::process::Uid::from_raw(uid)), None)
        .map_err(|error| CiError::Message(error.to_string()))?;
    file.sync_all()?;
    let held = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if held.uid() != uid
        || held.mode() & 0o077 != 0
        || held.nlink() != 1
        || !named.is_file()
        || (held.dev(), held.ino()) != (named.dev(), named.ino())
        || read_named(path, bytes.len() as u64)? != bytes
    {
        return Err(CiError::Message(
            "caller observation publication custody differs".into(),
        ));
    }
    File::open(
        path.parent()
            .ok_or_else(|| CiError::Message("caller observation parent absent".into()))?,
    )?
    .sync_all()?;
    Ok(())
}
