//! Actual installed frozen public commands, collected before any V3 mutation.
#![cfg(target_os = "linux")]
use crate::{CiError, Result, command::CommandSpec, linux_consumer_readiness::HeldLinuxProcess};
use memcordon_core::{
    workload_contract::{ExecutionIdentityRequestV2, WorkloadContractV2},
    workload_registry_v2::RuntimePrivatePolicyRegistry,
};
use sha2::{Digest, Sha256};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, PermissionsExt},
    process::ExitStatusExt,
};
use std::{
    ffi::OsString,
    fs,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const CLI: &str = "/usr/libexec/memcordon";
const FIXTURE: &str = "/usr/libexec/memcordon-installed-private-fixture";
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn json(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    save(path, &bytes)
}
fn image(path: &Path) -> Result<serde_json::Value> {
    let file = fs::File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.mode() & 0o022 != 0
        || before.len() > 512 * 1024 * 1024
    {
        return Err(CiError::Message(
            "frozen installed image custody differs".into(),
        ));
    }
    let bytes = fs::read(path)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.ctime(),
        after.ctime_nsec(),
    ) || named.file_type().is_symlink()
        || (named.dev(), named.ino()) != (before.dev(), before.ino())
    {
        return Err(CiError::Message(
            "frozen image changed during capture".into(),
        ));
    }
    Ok(
        serde_json::json!({"path":path.as_os_str().as_bytes(),"device":before.dev(),"inode":before.ino(),"length":bytes.len(),"sha256":hash(&bytes),"uid":before.uid(),"mode":before.mode()}),
    )
}
fn apply_registry(
    work: &Path,
    root: &Path,
    stem: &str,
    registry: &serde_json::Value,
    cutoff: u64,
) -> Result<serde_json::Value> {
    let path = root.join(format!("{stem}.policy.json"));
    json(&path, registry)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let started = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| CiError::Message(e.to_string()))?
            .as_millis(),
    )
    .map_err(|e| CiError::Message(e.to_string()))?;
    let budget = cutoff
        .checked_sub(started)
        .filter(|n| *n > 0)
        .ok_or_else(|| CiError::Message("frozen policy original cutoff exhausted".into()))?
        .min(60_000);
    let deadline = Instant::now() + Duration::from_millis(budget);
    let program = "/usr/libexec/memcordon-sealed-agent";
    let args = vec![
        OsString::from("package"),
        "policy".into(),
        "apply".into(),
        "--registry".into(),
        path.into_os_string(),
    ];
    let selected = image(Path::new(program))?;
    let invocation = serde_json::json!({"program":program.as_bytes(),"arguments":args.iter().map(|v|v.as_os_str().as_bytes()).collect::<Vec<_>>(),"cwd":work.as_os_str().as_bytes(),"environment":[],"started_unix_millis":started,"work_deadline_unix_millis":cutoff,"budget_millis":budget,"selected_image":selected});
    json(&root.join(format!("{stem}.invocation.json")), &invocation)?;
    let mut held = None;
    let observed=CommandSpec::new(program,work,Duration::from_millis(budget)).args(args).cleared_environment().bounded_until(deadline).output_limit(16*1024*1024).output_quiet_with_creation(|child|{
        let stat=fs::read_to_string(format!("/proc/{}/stat",child.id()))?;let birth=stat.rsplit_once(") ").and_then(|(_,tail)|tail.split_whitespace().nth(19)).and_then(|v|v.parse().ok()).ok_or_else(||CiError::Message("frozen policy original child birth absent".into()))?;
        let mut owner=HeldLinuxProcess::acquire(child.id(),birth).map_err(CiError::Message)?;let kernel=owner.hold_executable_image(deadline).map_err(CiError::Message)?;json(&root.join(format!("{stem}.creation.json")),&serde_json::json!({"identity":owner.retirement_identity().map_err(CiError::Message)?,"kernel_image":kernel,"stat":stat.as_bytes()}))?;held=Some(owner);Ok(())})?;
    let owner =
        held.ok_or_else(|| CiError::Message("frozen policy original child owner absent".into()))?;
    let retired = owner.retirement_identity().map_err(CiError::Message)?;
    save(&root.join(format!("{stem}.stdout.json")), &observed.stdout)?;
    save(&root.join(format!("{stem}.stderr.bin")), &observed.stderr)?;
    json(
        &root.join(format!("{stem}.exit.json")),
        &serde_json::json!({"identity":retired,"native_status":observed.status.into_raw(),"invocation_sha256":hash(&fs::read(root.join(format!("{stem}.invocation.json")))?),"stdout_sha256":hash(&observed.stdout),"stderr_sha256":hash(&observed.stderr)}),
    )?;
    if !observed.status.success() || !retired.retirement_observed {
        return Err(CiError::Message(
            "actual frozen policy apply failed or remains owned".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&observed.stdout)
        .map_err(CiError::Message)?;
    let activation: serde_json::Value = serde_json::from_slice(&observed.stdout)?;
    if activation["registry"] != *registry {
        return Err(CiError::Message(
            "actual frozen policy readback differs".into(),
        ));
    }
    Ok(activation)
}
pub fn capture(
    work: &Path,
    output: &Path,
    group: u32,
    registry: &RuntimePrivatePolicyRegistry,
    contracts: &[WorkloadContractV2],
) -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(CiError::Message(
            "frozen readiness commands require the actual root controller".into(),
        ));
    }
    let contract = contracts
        .iter()
        .find(|contract| {
            matches!(
                contract.execution_identity,
                ExecutionIdentityRequestV2::PreserveCaller
            )
        })
        .ok_or_else(|| CiError::Message("original preserved legacy contract absent".into()))?;
    let root = output.join("frozen-legacy");
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
    let lease: serde_json::Value = serde_json::from_slice(&fs::read(
        output
            .parent()
            .ok_or_else(|| CiError::Message("original installed parent absent".into()))?
            .join("lifetime/lease-owner.json"),
    )?)?;
    let work_cutoff = lease["work_deadline_unix_millis"]
        .as_u64()
        .ok_or_else(|| CiError::Message("original frozen work cutoff absent".into()))?;
    let cleanup_cutoff = lease["cleanup_deadline_unix_millis"]
        .as_u64()
        .ok_or_else(|| CiError::Message("original frozen cleanup cutoff absent".into()))?;
    let cli = image(Path::new(CLI))?;
    let fixture = image(Path::new(FIXTURE))?;
    let launcher = image(Path::new("/usr/bin/setpriv"))?;
    let host_network = fs::metadata("/proc/self/ns/net")?;
    save(&root.join("cli.bin"), &fs::read(CLI)?)?;
    save(&root.join("fixture.bin"), &fs::read(FIXTURE)?)?;
    save(&root.join("launcher.bin"), &fs::read("/usr/bin/setpriv")?)?;
    let mut current_contract = contract.clone();
    for version in [1, 2] {
        let mut actual_registry = serde_json::to_value(registry)?;
        let mut request = serde_json::to_value(&current_contract)?;
        if version == 1 {
            let profile = memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate;
            actual_registry = serde_json::json!({"format":"memcordon.local-policy","revision":1,"profiles":[{"profile":profile,"reference":profile.reference(),"enabled":true}],"grants":[{"id":"installed-preserved","revision":1,"profile":profile.reference(),"ceiling":profile.ceiling(),"enabled":true,"callers":[{"platform":"linux","uid":65534}],"approved_plans":[fixture["sha256"]]}],"active_attempt_disposition":"drain-existing"});
            memcordon_core::workload_registry::RuntimePolicyRegistry::parse(&serde_json::to_vec(
                &actual_registry,
            )?)
            .map_err(CiError::Message)?;
            let activation =
                apply_registry(work, &root, "v1-activation", &actual_registry, work_cutoff)?;
            request["schema_version"] = serde_json::json!(1);
            request["authorized_profile"] = serde_json::to_value(profile.reference())?;
            request["ceiling"] = serde_json::to_value(profile.ceiling())?;
            request["expected_epoch"] = activation["epoch"].clone();
            request
                .as_object_mut()
                .ok_or_else(|| CiError::Message("legacy contract object absent".into()))?
                .remove("execution_identity");
            memcordon_core::workload_contract::WorkloadContractV1::parse(&serde_json::to_vec(
                &request,
            )?)
            .map_err(CiError::Message)?;
        }
        let directory = root.join(format!("v{version}"));
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
        json(
            &directory.join("owner.json"),
            &serde_json::json!({"format":"memcordon.linux-frozen-legacy-owner","revision":1,"registry":actual_registry,"contract":request,"caller_uid":65534,"caller_gid":65534,"caller_group":group,"work":work,"output":output,"cli":cli,"fixture":fixture,"launcher":launcher,"host_network_namespace":{"device":host_network.dev(),"inode":host_network.ino()},"work_deadline_unix_millis":work_cutoff,"cleanup_deadline_unix_millis":cleanup_cutoff}),
        )?;
        let request_path = directory.join("request.json");
        json(&request_path, &request)?;
        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o644))?;
        let commands = (|| -> Result<()> {
            for action in if version == 1 {
                &["result", "plan", "capabilities"][..]
            } else {
                &["result"][..]
            } {
                let row = directory.join(action);
                fs::create_dir(&row)?;
                let report = work.join(format!("frozen-v{version}-{action}.json"));
                let mut args = vec![
                    OsString::from("--reuid=65534"),
                    "--regid=65534".into(),
                    format!("--groups={group}").into(),
                    "--bounding-set=-all".into(),
                    "--inh-caps=-all".into(),
                    "--ambient-caps=-all".into(),
                    "--no-new-privs".into(),
                    "--".into(),
                    CLI.into(),
                ];
                match *action {
                    "result" => args.extend([
                        "--sealed".into(),
                        "--workload-contract".into(),
                        request_path.as_os_str().to_owned(),
                        "--report-format".into(),
                        "result-v1".into(),
                        "--report".into(),
                        report.as_os_str().to_owned(),
                        "--".into(),
                        FIXTURE.into(),
                        "assert-private-runtime".into(),
                        "65534".into(),
                        "65534".into(),
                    ]),
                    "plan" => args.extend([
                        "plan".into(),
                        "--sealed".into(),
                        "--plan-format".into(),
                        "plan-v1".into(),
                        "--workload-contract".into(),
                        request_path.as_os_str().to_owned(),
                    ]),
                    "capabilities" => args.extend([
                        "doctor".into(),
                        "--require".into(),
                        "sealed".into(),
                        "--capability-format".into(),
                        "capabilities-v1".into(),
                        "--workload-contract".into(),
                        request_path.as_os_str().to_owned(),
                    ]),
                    _ => unreachable!(),
                }
                if version == 1 && *action == "result" {
                    args.truncate(args.len() - 3);
                    args.push("assert-frozen-baseline".into());
                }
                if version == 1 && *action == "result" {
                    let observations = row.join("observations");
                    fs::create_dir(&observations)?;
                    fs::set_permissions(&observations, fs::Permissions::from_mode(0o700))?;
                    let held = fs::File::open(&observations)?;
                    rustix::fs::fchown(
                        &held,
                        Some(rustix::process::Uid::from_raw(65534)),
                        Some(rustix::process::Gid::from_raw(65534)),
                    )
                    .map_err(|e| CiError::Message(e.to_string()))?;
                    let marker = args
                        .iter()
                        .position(|arg| arg == "--sealed")
                        .expect("original sealed argument");
                    args.splice(
                        marker..marker,
                        [
                            OsString::from("--mixed-observation-directory"),
                            observations.into_os_string(),
                        ],
                    );
                }
                let started = u64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|e| CiError::Message(e.to_string()))?
                        .as_millis(),
                )
                .map_err(|e| CiError::Message(e.to_string()))?;
                let budget = work_cutoff
                    .checked_sub(started)
                    .filter(|value| *value > 0)
                    .ok_or_else(|| {
                        CiError::Message("original frozen work cutoff exhausted".into())
                    })?
                    .min(60_000);
                let deadline = Instant::now() + Duration::from_millis(budget);
                let mut held = None;
                let invocation = serde_json::json!({"format":"memcordon.linux-frozen-legacy-invocation","revision":1,"program":b"/usr/bin/setpriv","arguments":args.iter().map(|arg|arg.as_os_str().as_bytes().to_vec()).collect::<Vec<_>>(),"cwd":work.as_os_str().as_bytes(),"environment":[],"started_unix_millis":started,"work_deadline_unix_millis":work_cutoff,"cleanup_deadline_unix_millis":cleanup_cutoff,"budget_millis":budget});
                json(&row.join("invocation.json"), &invocation)?;
                let observed=CommandSpec::new("/usr/bin/setpriv",work,Duration::from_millis(budget)).args(&args).cleared_environment().output_limit(16*1024*1024).bounded_until(deadline).output_quiet_with_creation(|child| {
                let stat=fs::read_to_string(format!("/proc/{}/stat",child.id()))?;let birth=stat.rsplit_once(") ").and_then(|(_,tail)|tail.split_whitespace().nth(19)).and_then(|value|value.parse().ok()).ok_or_else(||CiError::Message("original frozen child birth absent".into()))?;
                let mut owner=HeldLinuxProcess::acquire(child.id(),birth).map_err(CiError::Message)?;
                let kernel_image=owner.hold_executable_image(deadline).map_err(CiError::Message)?;
                json(&row.join("creation.json"),&serde_json::json!({"identity":owner.retirement_identity().map_err(CiError::Message)?,"kernel_image":kernel_image,"stat":stat.as_bytes()}))?;held=Some(owner);Ok(())
            })?;
                let held =
                    held.ok_or_else(|| CiError::Message("frozen native child hold absent".into()))?;
                let retired = held.retirement_identity().map_err(CiError::Message)?;
                if !retired.retirement_observed {
                    return Err(CiError::Message("frozen child has not retired".into()));
                }
                save(&row.join("stdout.bin"), &observed.stdout)?;
                save(&row.join("stderr.bin"), &observed.stderr)?;
                json(
                    &row.join("exit.json"),
                    &serde_json::json!({"identity":retired,"native_status":observed.status.into_raw(),"invocation_sha256":hash(&fs::read(row.join("invocation.json"))?),"stdout_sha256":hash(&observed.stdout),"stderr_sha256":hash(&observed.stderr),"cli":image(Path::new(CLI))?,"fixture":image(Path::new(FIXTURE))?,"launcher":image(Path::new("/usr/bin/setpriv"))?}),
                )?;
                if *action == "result" {
                    save(&row.join("result.json"), &fs::read(&report)?)?;
                }
                if !observed.status.success() {
                    return Err(CiError::Message(format!(
                        "actual frozen v{version} {action} command failed"
                    )));
                }
            }
            Ok(())
        })();
        if version == 1 {
            let restored = apply_registry(
                work,
                &root,
                "v2-restoration",
                &serde_json::to_value(registry)?,
                work_cutoff,
            )?;
            current_contract.expected_epoch = serde_json::from_value(restored["epoch"].clone())?;
        }
        commands?;
    }
    Ok(())
}
pub fn normalize(
    output: &Path,
    identity: &crate::consumer_readiness_ledger::SourceIdentity,
    cell: &memcordon_readiness_verifier::ProductKey,
    artifact_root: &Path,
) -> Result<(
    Vec<memcordon_readiness_verifier::CaseRecord>,
    Vec<memcordon_readiness_verifier::Artifact>,
)> {
    use memcordon_readiness_verifier::{
        Artifact, CaseKey, CaseRecord, CaseState, EvidenceClass, LinuxFrozenLegacyCommand,
        LinuxFrozenLegacyEvidence,
    };
    let root = output.join("frozen-legacy");
    let mut records = Vec::new();
    let mut artifacts = std::collections::BTreeMap::<String, Artifact>::new();
    let original_lease = output
        .parent()
        .ok_or_else(|| CiError::Message("frozen installed parent absent".into()))?
        .join("lifetime/lease-owner.json");
    let lease: serde_json::Value = serde_json::from_slice(&fs::read(&original_lease)?)?;
    let mut register = |path: &Path| -> Result<String> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.len() > 512 * 1024 * 1024
        {
            return Err(CiError::Message(
                "frozen original artifact native custody differs".into(),
            ));
        }
        let bytes = fs::read(path)?;
        let after = fs::symlink_metadata(path)?;
        if (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err(CiError::Message(
                "frozen artifact changed during custody capture".into(),
            ));
        }
        let relative = path
            .strip_prefix(artifact_root)
            .map_err(|e| CiError::Message(e.to_string()))?
            .to_str()
            .ok_or_else(|| CiError::Message("frozen archive path not UTF8".into()))?
            .to_owned();
        artifacts.insert(
            relative.clone(),
            Artifact {
                path: relative.clone(),
                length: bytes.len() as u64,
                sha256: hash(&bytes),
            },
        );
        Ok(relative)
    };
    for version in [1, 2] {
        let key = CaseKey {
            target: cell.target.clone(),
            channel: Some(cell.channel.clone()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: "L-ID-01".into(),
            scenario: format!("v{version}-preserve-caller"),
        };
        let normalized = (|| -> Result<String> {
            let owner = register(&root.join(format!("v{version}/owner.json")))?;
            let original_lease = register(&original_lease)?;
            let request = register(&root.join(format!("v{version}/request.json")))?;
            let cli = register(&root.join("cli.bin"))?;
            let fixture = register(&root.join("fixture.bin"))?;
            let launcher = register(&root.join("launcher.bin"))?;
            let stem = if version == 1 {
                "v1-activation"
            } else {
                "v2-restoration"
            };
            let mut activation = std::collections::BTreeMap::new();
            for leaf in [
                "policy.json",
                "invocation.json",
                "creation.json",
                "stdout.json",
                "stderr.bin",
                "exit.json",
            ] {
                activation.insert(
                    leaf.to_owned(),
                    register(&root.join(format!("{stem}.{leaf}")))?,
                );
            }
            let mut commands = Vec::new();
            for action in if version == 1 {
                &["result", "plan", "capabilities"][..]
            } else {
                &["result"][..]
            } {
                let row = root.join(format!("v{version}/{action}"));
                let mut provider_request = None;
                let mut provider_terminal = None;
                if version == 1 && *action == "result" {
                    for entry in fs::read_dir(row.join("observations"))? {
                        let path = entry?.path();
                        let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
                            CiError::Message("legacy observation leaf encoding differs".into())
                        })?;
                        let slot = if name.ends_with(".legacy-provider-request.bin") {
                            &mut provider_request
                        } else if name.ends_with(".legacy-provider-terminal.bin") {
                            &mut provider_terminal
                        } else {
                            return Err(CiError::Message(
                                "unexpected legacy observation member".into(),
                            ));
                        };
                        if slot.is_some() {
                            return Err(CiError::Message(
                                "ambiguous original legacy observation".into(),
                            ));
                        }
                        *slot = Some(register(&path)?);
                    }
                    if provider_request.is_none() || provider_terminal.is_none() {
                        return Err(CiError::Message(
                            "actual legacy native exchange absent".into(),
                        ));
                    }
                }
                commands.push(LinuxFrozenLegacyCommand {
                    action: (*action).into(),
                    invocation: register(&row.join("invocation.json"))?,
                    creation: register(&row.join("creation.json"))?,
                    exit: register(&row.join("exit.json"))?,
                    stdout: register(&row.join("stdout.bin"))?,
                    stderr: register(&row.join("stderr.bin"))?,
                    result: if *action == "result" {
                        Some(register(&row.join("result.json"))?)
                    } else {
                        None
                    },
                    provider_request,
                    provider_terminal,
                });
            }
            let e = LinuxFrozenLegacyEvidence {
                format: "memcordon.consumer-readiness.linux-frozen-legacy".into(),
                revision: 1,
                key: key.clone(),
                run_id: identity.run_id.clone(),
                source_commit: identity.source_commit.clone(),
                source_tree_sha256: identity.source_tree_sha256.clone(),
                lease_id: lease["lease_id"]
                    .as_str()
                    .ok_or_else(|| CiError::Message("frozen original lease absent".into()))?
                    .into(),
                owner,
                original_lease,
                request,
                cli,
                fixture,
                launcher,
                activation,
                commands,
            };
            let path = root.join(format!("v{version}/case-evidence.json"));
            json(&path, &serde_json::to_value(e)?)?;
            register(&path)
        })();
        match normalized {
            Ok(evidence) => records.push(CaseRecord {
                key,
                run_id: identity.run_id.clone(),
                state: CaseState::Passed,
                reason: None,
                evidence: Some(evidence),
            }),
            Err(error) => records.push(CaseRecord {
                key,
                run_id: identity.run_id.clone(),
                state: CaseState::Failed,
                reason: Some(error.to_string()),
                evidence: None,
            }),
        }
    }
    Ok((records, artifacts.into_values().collect()))
}
