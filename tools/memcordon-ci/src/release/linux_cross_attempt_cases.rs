//! Two actual admitted attempts; the retained report owns every partial phase.
use super::linux_mixed_installed::{
    ActivatedMixedPolicy, CompletedMixedCollection, ExclusiveAccount, InstalledMixedLaunch,
    InstalledMixedLaunchInput, MixedImages,
};
use crate::command::CommandSpec;
use crate::consumer_readiness_ledger::SourceIdentity;
use crate::linux_consumer_readiness::{HeldLinuxProcess, PreparedLinuxObserver};
use crate::{CiError, Result};
use memcordon_core::workload_contract::{LogicalId, PolicyEpoch};
use memcordon_core::workload_contract_v3::{
    BoundObjectRef, DeniedOperationV3, RequirementV3, WorkloadContractV3,
};
use memcordon_core::workload_registry_v3::RuntimePrivatePolicyRegistryV3;
use memcordon_readiness_verifier::{Artifact, CaseKey, EvidenceClass, ProductKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct CrossAttemptContext<'a> {
    pub identity: &'a SourceIdentity,
    pub cell: &'a ProductKey,
    pub lease_id: &'a str,
    pub provider: &'a memcordon_core::PublicProviderBindingV1,
    pub images: &'a MixedImages,
    pub baseline: &'a ActivatedMixedPolicy,
    pub primary_account: &'a ExclusiveAccount,
    pub output: &'a Path,
    pub protected_output: &'a Path,
    pub artifact_root: &'a Path,
    pub original_lease: &'a Path,
    pub original_acquisition: &'a Path,
    pub deadline: Instant,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline: Instant,
    pub cleanup_deadline_unix_millis: u64,
}

pub struct CrossAttemptOwner {
    pub launch: InstalledMixedLaunch,
    pub observer: Option<PreparedLinuxObserver>,
    pub frontend: Option<HeldLinuxProcess>,
    pub native_receipt: Option<Artifact>,
    pub prepared_target: Option<crate::linux_consumer_readiness::LinuxHeldSnapshot>,
    pub contract: WorkloadContractV3,
    pub contract_path: PathBuf,
    pub prefix: String,
    pub key: CaseKey,
}

pub struct CrossAttemptReport {
    pub identity: SourceIdentity,
    pub cell: ProductKey,
    pub output_root: PathBuf,
    pub protected_root: PathBuf,
    pub acquisition_output: PathBuf,
    pub peer_account: Option<ExclusiveAccount>,
    pub account_retired: bool,
    pub prior_registry: RuntimePrivatePolicyRegistryV3,
    pub restoration_required: bool,
    pub attempts: Vec<CrossAttemptOwner>,
    pub commands: Vec<HeldLinuxProcess>,
    pub directory_owners: Vec<File>,
    pub target: Option<CompletedMixedCollection>,
    pub peer: Option<CompletedMixedCollection>,
    pub canary: Option<Artifact>,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline: Instant,
    pub cleanup_deadline_unix_millis: u64,
    pub failures: Vec<String>,
    recovery_ordinal: u32,
}

fn error(text: &str) -> CiError {
    CiError::Message(text.into())
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(bytes)?)
}
fn bounded(deadline: Instant, cap: Duration) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(error("cross-attempt original cutoff exhausted"))
    } else {
        Ok(remaining.min(cap))
    }
}
fn id(value: &str) -> Result<LogicalId> {
    LogicalId::new(value.into()).map_err(CiError::Message)
}
fn retain(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| error("cross original parent absent"))?,
    )?
    .sync_all()?;
    Ok(())
}
fn read(path: &Path, bound: u64) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > bound || before.nlink() != 1 {
        return Err(error(
            "cross original native file not bounded regular single owner",
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(bound + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || (
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
        )
    {
        return Err(error("cross original native file changed during capture"));
    }
    Ok(bytes)
}
fn hold_directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(error("cross original directory is not administrator-owned"));
    }
    Ok(file)
}
fn relative(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .map_err(|error| CiError::Message(error.to_string()))?
        .to_str()
        .ok_or_else(|| error("cross original artifact path not UTF-8"))?
        .into())
}

pub fn initialize(context: &CrossAttemptContext<'_>) -> Result<CrossAttemptReport> {
    bounded(context.deadline, Duration::from_secs(1))?;
    std::fs::create_dir(context.output)?;
    std::fs::set_permissions(context.output, std::fs::Permissions::from_mode(0o755))?;
    let mut directories = vec![
        hold_directory(context.output)?,
        hold_directory(context.protected_output)?,
    ];
    let acquisition = context.output.join("account");
    std::fs::create_dir(&acquisition)?;
    std::fs::set_permissions(&acquisition, std::fs::Permissions::from_mode(0o700))?;
    directories.push(hold_directory(&acquisition)?);
    let prior = serde_json::to_vec(&context.baseline.registry)?;
    retain(&context.output.join("prior-registry.json"), &prior)?;
    let source = read(&context.baseline.activation_path, 4 * 1024 * 1024)?;
    let actual: Value = decode(&source)?;
    if actual["registry"] != serde_json::to_value(&context.baseline.registry)?
        || actual["epoch"] != serde_json::to_value(&context.baseline.contract.expected_epoch)?
    {
        return Err(error(
            "cross prior policy differs from original actual activation",
        ));
    }
    retain(&context.output.join("prior-activation.json"), &source)?;
    retain(
        &context.output.join("original-contract.json"),
        &serde_json::to_vec(&context.baseline.contract)?,
    )?;
    retain(
        &context.output.join("owner.json"),
        &serde_json::to_vec(
            &json!({"format":"memcordon.linux-cross-attempt-owner","revision":1,"identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"acquisition_output":acquisition,"protected_output":context.protected_output,"original_registry_sha256":hash(&prior),"primary_account":context.primary_account,"original_lease":context.original_lease,"original_acquisition":context.original_acquisition,"work_deadline_unix_millis":context.work_deadline_unix_millis,"cleanup_deadline_unix_millis":context.cleanup_deadline_unix_millis}),
        )?,
    )?;
    Ok(CrossAttemptReport {
        identity: context.identity.clone(),
        cell: context.cell.clone(),
        output_root: context.output.into(),
        protected_root: context.protected_output.into(),
        acquisition_output: acquisition,
        peer_account: None,
        account_retired: false,
        prior_registry: context.baseline.registry.clone(),
        restoration_required: false,
        attempts: Vec::new(),
        commands: Vec::new(),
        directory_owners: directories,
        target: None,
        peer: None,
        canary: None,
        work_deadline_unix_millis: context.work_deadline_unix_millis,
        cleanup_deadline: context.cleanup_deadline,
        cleanup_deadline_unix_millis: context.cleanup_deadline_unix_millis,
        failures: Vec::new(),
        recovery_ordinal: 0,
    })
}

fn apply(
    report: &mut CrossAttemptReport,
    registry: &RuntimePrivatePolicyRegistryV3,
    stem: &str,
    deadline: Instant,
) -> Result<PolicyEpoch> {
    registry.validate().map_err(CiError::Message)?;
    let policy = serde_json::to_vec(registry)?;
    let original = report.output_root.join(format!("{stem}.policy.json"));
    let protected = report.protected_root.join(format!("{stem}.policy.json"));
    retain(&original, &policy)?;
    retain(&protected, &policy)?;
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&protected)?;
    let identity = held.metadata()?;
    if identity.uid() != 0
        || identity.mode() & 0o022 != 0
        || read(&protected, policy.len() as u64)? != policy
    {
        return Err(error("cross actual native policy source changed"));
    }
    let program = Path::new("/usr/libexec/memcordon-sealed-agent");
    let mut image_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(program)?;
    let image_identity = image_file.metadata()?;
    let mut image = Vec::new();
    std::io::Read::by_ref(&mut image_file)
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut image)?;
    if image.len() as u64 != image_identity.len() || image.len() > 512 * 1024 * 1024 {
        return Err(error("cross selected native image exceeds original bound"));
    }
    if image_identity.uid() != 0 || image_identity.mode() & 0o022 != 0 {
        return Err(error(
            "cross selected actual native policy image not protected",
        ));
    }
    let started_unix_millis = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| CiError::Message(error.to_string()))?
            .as_millis(),
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    let deadline_unix_millis = if stem == "activation" {
        report.work_deadline_unix_millis
    } else {
        report.cleanup_deadline_unix_millis
    };
    let wall = deadline_unix_millis
        .checked_sub(started_unix_millis)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| error("cross native policy original wall cutoff exhausted"))?;
    let budget = bounded(deadline, Duration::from_secs(60))?.min(Duration::from_millis(wall));
    let args = [
        "package".into(),
        "policy".into(),
        "apply".into(),
        "--file".into(),
        protected.as_os_str().to_owned(),
    ];
    let command = serde_json::to_vec(
        &json!({"format":"memcordon.linux-cross-policy-command","revision":1,"program":program.as_os_str().as_bytes(),"arguments":args.iter().map(|value:&std::ffi::OsString|value.as_bytes()).collect::<Vec<_>>(),"cwd":report.output_root.as_os_str().as_bytes(),"environment_cleared":true,"started_unix_millis":started_unix_millis,"deadline_unix_millis":deadline_unix_millis,"budget_millis":budget.as_millis(),"program_sha256":hash(&image),"program_device":image_identity.dev(),"program_inode":image_identity.ino(),"policy_sha256":hash(&policy)}),
    )?;
    retain(
        &report.output_root.join(format!("{stem}.invocation.json")),
        &command,
    )?;
    let start = report.commands.len();
    let mut creation = None;
    let output = CommandSpec::new(program, &report.output_root, budget)
        .cleared_environment()
        .bounded_until(deadline)
        .args(args)
        .output_quiet_with_creation(|child| {
            let birth = crate::linux_consumer_readiness::process_birth(child.id())
                .map_err(CiError::Message)?;
            let mut owner =
                HeldLinuxProcess::acquire(child.id(), birth).map_err(CiError::Message)?;
            let executed = match owner.hold_executable_image(deadline) {
                Ok(value) => value,
                Err(message) => {
                    report.commands.push(owner);
                    return Err(CiError::Message(message));
                }
            };
            if executed["sha256"] != hash(&image)
                || executed["device"] != image_identity.dev()
                || executed["inode"] != image_identity.ino()
            {
                report.commands.push(owner);
                return Err(error("cross actual native command image differs"));
            }
            creation = Some(json!({"pid":child.id(),"birth":birth,"image":executed}));
            report.commands.push(owner);
            Ok(())
        })?;
    let owner = report
        .commands
        .get(start)
        .ok_or_else(|| error("cross original policy Child/PIDFD absent"))?;
    let named = std::fs::symlink_metadata(&protected)?;
    let after = held.metadata()?;
    if !owner.exited().map_err(CiError::Message)?
        || (named.dev(), named.ino(), after.dev(), after.ino())
            != (
                identity.dev(),
                identity.ino(),
                identity.dev(),
                identity.ino(),
            )
        || read(&protected, policy.len() as u64)? != policy
        || read(program, 512 * 1024 * 1024)? != image
    {
        return Err(error("cross policy command original source/wait changed"));
    }
    retain(
        &report.output_root.join(format!("{stem}.json")),
        &output.stdout,
    )?;
    retain(
        &report.output_root.join(format!("{stem}.stderr.bin")),
        &output.stderr,
    )?;
    retain(
        &report.output_root.join(format!("{stem}.exit.json")),
        &serde_json::to_vec(
            &json!({"format":"memcordon.linux-cross-policy-exit","revision":1,"creation":creation.ok_or_else(||error("cross native command creation missing"))?,"retirement":owner.retirement_identity().map_err(CiError::Message)?,"raw_wait_status":output.status.into_raw(),"native_exit":output.status.code(),"signal":output.status.signal(),"invocation_sha256":hash(&command),"stdout_sha256":hash(&output.stdout),"stderr_sha256":hash(&output.stderr)}),
        )?,
    )?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&output.stdout)
        .map_err(CiError::Message)?;
    let receipt: Value = decode(&output.stdout)?;
    if !output.status.success()
        || receipt["format"] != "memcordon.local-private-activation"
        || receipt["revision"] != 2
        || receipt["registry"] != serde_json::to_value(registry)?
        || receipt["registry_digest"]
            != serde_json::to_value(registry.canonical_digest().map_err(CiError::Message)?)?
    {
        return Err(error("cross native policy application/readback differs"));
    }
    Ok(serde_json::from_value(receipt["epoch"].clone())?)
}

fn contracts(
    context: &CrossAttemptContext<'_>,
    report: &mut CrossAttemptReport,
) -> Result<(
    RuntimePrivatePolicyRegistryV3,
    WorkloadContractV3,
    WorkloadContractV3,
)> {
    let account = report
        .peer_account
        .as_ref()
        .ok_or_else(|| error("cross peer account original acquisition absent"))?;
    if account.uid == context.primary_account.uid || account.gid == context.primary_account.gid {
        return Err(error(
            "cross real admitted identities alias one exclusive account",
        ));
    }
    let mut registry = context.baseline.registry.clone();
    let mut identity = registry
        .execution_identities
        .as_slice()
        .iter()
        .find(|identity| {
            identity.reference().ok().as_ref()
                == Some(&context.baseline.contract.execution_identity)
        })
        .ok_or_else(|| error("cross original primary execution definition absent"))?
        .clone();
    let declaration = serde_json::to_vec(
        &json!({"format":"memcordon.owned-readiness-exclusive-use-declaration","revision":1,"run_id":context.identity.run_id,"cell":context.cell,"account":account.name,"uid":account.uid,"gid":account.gid,"purpose":"exclusive original other-attempt abstract peer identity"}),
    )?;
    retain(
        &report.output_root.join("peer-exclusive-use-policy.json"),
        &declaration,
    )?;
    identity.identity_id = id("owned-cross-attempt-identity")?;
    identity.uid = NonZeroU32::new(account.uid).ok_or_else(|| error("cross peer UID zero"))?;
    identity.gid = NonZeroU32::new(account.gid).ok_or_else(|| error("cross peer GID zero"))?;
    identity.reservation_key = id("owned-cross-attempt-reservation")?;
    identity.exclusive_use_policy = BoundObjectRef {
        id: id("owned-cross-attempt-use")?,
        digest: memcordon_core::DiagnosticSha256::from_bytes(Sha256::digest(&declaration).into()),
    };
    let mut peer = context.baseline.contract.clone();
    peer.execution_identity = identity.reference().map_err(CiError::Message)?;
    peer.requirements = serde_json::from_value(json!([RequirementV3::UnixAbstractStream {
        id: id("peer-abstract")?
    }]))?;
    let mut target = context.baseline.contract.clone();
    target.requirements = serde_json::from_value(json!([
        RequirementV3::UnixAbstractStream {
            id: id("own-abstract")?
        },
        RequirementV3::ExpectedDenial {
            id: id("other-attempt-denial")?,
            operation: DeniedOperationV3::OtherAttempt
        }
    ]))?;
    for request in [&mut target, &mut peer] {
        let plan = serde_json::to_vec(&(
            &request.runtime_image,
            &request.input_image,
            &request.root_layout,
            &request.execution_identity,
            &request.requirements,
        ))?;
        request.workload_plan_digest =
            memcordon_core::DiagnosticSha256::from_bytes(Sha256::digest(&plan).into());
        request.authorization.approved_plan_digest = request.workload_plan_digest.clone();
    }
    let mut grants = registry.grants.as_slice().to_vec();
    let original = grants
        .iter_mut()
        .find(|grant| grant.id == target.authorization.grant_id)
        .ok_or_else(|| error("cross original primary grant absent"))?;
    let mut approved = original.approved_plans.as_slice().to_vec();
    if !approved.contains(&target.workload_plan_digest) {
        approved.push(target.workload_plan_digest.clone());
    }
    original.approved_plans = serde_json::from_value(json!(approved))?;
    let mut grant = original.clone();
    grant.id = id("owned-cross-attempt-grant")?;
    grant.execution_identity = peer.execution_identity.clone();
    grant.approved_plans = serde_json::from_value(json!([peer.workload_plan_digest]))?;
    peer.authorization.grant_id = grant.id.clone();
    peer.authorization.grant_revision = grant.revision;
    grants.push(grant);
    let mut identities = registry.execution_identities.as_slice().to_vec();
    identities.push(identity);
    registry.execution_identities = serde_json::from_value(json!(identities))?;
    registry.grants = serde_json::from_value(json!(grants))?;
    registry.validate().map_err(CiError::Message)?;
    target.validate().map_err(CiError::Message)?;
    peer.validate().map_err(CiError::Message)?;
    Ok((registry, target, peer))
}

fn start(
    context: &CrossAttemptContext<'_>,
    report: &mut CrossAttemptReport,
    contract: WorkloadContractV3,
    stem: &str,
    mode: &str,
    challenge: &str,
) -> Result<usize> {
    let directory = report.output_root.join(stem);
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
    report.directory_owners.push(hold_directory(&directory)?);
    let contract_path = directory.join("contract.json");
    retain(&contract_path, &serde_json::to_vec(&contract)?)?;
    let mut arguments = vec![std::ffi::OsString::from(mode), challenge.into()];
    if mode == "forbidden-abstract" {
        arguments.push(format!("memcordon-readiness-{challenge}").into());
    }
    let duration = format!(
        "+{}ms",
        bounded(context.deadline, Duration::from_secs(30))?
            .as_millis()
            .max(1)
    );
    let launch = InstalledMixedLaunch::start(InstalledMixedLaunchInput {
        directory: &directory,
        contract: &contract_path,
        caller_uid: 65534,
        caller_gid: 65534,
        target_arguments: &arguments,
        deadline: std::ffi::OsStr::new(&duration),
        memory: std::ffi::OsStr::new("+256M"),
    })?;
    let prefix = format!(
        "{}/{}/cross-attempt-abstract/{stem}",
        context.cell.target, context.cell.channel
    );
    let key = CaseKey {
        target: context.cell.target.clone(),
        channel: Some(context.cell.channel.clone()),
        evidence_class: EvidenceClass::InstalledProduct,
        family: "L-ISO-03".into(),
        scenario: if stem == "peer" {
            "own-abstract-positive"
        } else {
            "other-attempt-abstract"
        }
        .into(),
    };
    report.attempts.push(CrossAttemptOwner {
        launch,
        observer: None,
        frontend: None,
        native_receipt: None,
        prepared_target: None,
        contract,
        contract_path,
        prefix,
        key,
    });
    let index = report.attempts.len() - 1;
    report.attempts[index].frontend = Some(report.attempts[index].launch.hold_original_frontend()?);
    let prepared = report.attempts[index].launch.acquire_prepared(
        context.provider,
        &report.attempts[index].contract,
        context.artifact_root,
        &format!("{}/prepared.json", report.attempts[index].prefix),
        bounded(context.deadline, Duration::from_secs(30))?,
    )?;
    report.attempts[index].observer = Some(prepared);
    let owner = &mut report.attempts[index];
    let observer = owner
        .observer
        .as_ref()
        .expect("retained original prepared family");
    owner.prepared_target = Some(observer.target.live_snapshot().map_err(CiError::Message)?);
    owner.native_receipt = Some(
        observer
            .persist_native_receipt(
                &context.identity.run_id,
                context.artifact_root,
                &format!("{}/prepared-before-ack-native.json", owner.prefix),
            )
            .map_err(CiError::Message)?,
    );
    observer
        .acknowledge(&owner.launch.observation_directory)
        .map_err(CiError::Message)?;
    Ok(index)
}

fn wait_held(
    report: &CrossAttemptReport,
    index: usize,
    challenge: &str,
    deadline: Instant,
) -> Result<Value> {
    let owner = &report.attempts[index];
    loop {
        bounded(deadline, Duration::from_secs(1))?;
        let bytes = match read(&owner.launch.stdout, 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(_) => {
                if owner
                    .frontend
                    .as_ref()
                    .ok_or_else(|| error("cross original frontend PIDFD absent"))?
                    .exited()
                    .map_err(CiError::Message)?
                {
                    return Err(error(
                        "cross peer stdout unavailable after actual Child exit",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
        };
        if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
            let row: Value = decode(&bytes[..end])?;
            let observer = owner
                .observer
                .as_ref()
                .ok_or_else(|| error("cross native peer prepared owner absent"))?;
            let snapshot = observer.target.live_snapshot().map_err(CiError::Message)?;
            if row["format"] != "memcordon.linux-readiness-transcript"
                || row["revision"] != 1
                || row["sequence"] != 1
                || row["operation"] != "other-attempt-abstract-held"
                || row["challenge"] != challenge
                || row["root_birth"] != snapshot.birth
                || row["root_pid"]
                    != *snapshot
                        .namespace_pids
                        .last()
                        .ok_or_else(|| error("cross peer local native PID absent"))?
                || row["observation"]["network_namespace_inode"] != snapshot.network.inode
                || row["observation"]["name"]
                    != json!(format!("memcordon-readiness-{challenge}").as_bytes())
                || row["observation"]["baseline_client_connected"] != true
                || row["observation"]["baseline_server_accepted"] != true
                || row["observation"]["socket_inode"]
                    .as_u64()
                    .is_none_or(|inode| inode == 0)
                || row["observation"]["bytes"] != json!(b"abstract-unix-readiness".as_slice())
            {
                return Err(error("cross actual live peer listener/source row differs"));
            }
            return Ok(row);
        }
        if owner
            .frontend
            .as_ref()
            .ok_or_else(|| error("cross original frontend PIDFD absent"))?
            .exited()
            .map_err(CiError::Message)?
        {
            return Err(error("cross actual peer exited before listener barrier"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn collect(
    context: &CrossAttemptContext<'_>,
    report: &mut CrossAttemptReport,
    index: usize,
    challenge: &str,
) -> Result<CompletedMixedCollection> {
    let owner = &mut report.attempts[index];
    let observer = owner
        .observer
        .as_ref()
        .ok_or_else(|| error("cross completed original native observer absent"))?;
    let mut collection = owner.launch.collect_completed(
        observer,
        &[],
        context.identity.clone(),
        context.lease_id.into(),
        owner.key.clone(),
        challenge.into(),
        owner.prefix.clone(),
        &owner.contract_path,
        context.artifact_root,
        bounded(context.deadline, Duration::from_secs(30))?,
    )?;
    for (leaf, bytes) in [
        (
            "original-frontend-invocation.json",
            owner.launch.retained_frontend_invocation()?,
        ),
        (
            "original-frontend-exit.json",
            serde_json::to_vec(&owner.launch.retained_frontend_wait()?)?,
        ),
    ] {
        let path = format!("{}/{leaf}", owner.prefix);
        retain(&context.artifact_root.join(&path), &bytes)?;
        collection.persisted.artifacts.push(Artifact {
            path,
            length: bytes.len() as u64,
            sha256: hash(&bytes),
        });
    }
    let request = memcordon_core::mixed_runtime::MixedRuntimeRequest::parse(&read(
        &context
            .artifact_root
            .join(format!("{}/provider-request.json", owner.prefix)),
        4 * 1024 * 1024,
    )?)
    .map_err(CiError::Message)?;
    let memcordon_core::result_v2::MixedRuntimeOutcomeV2::Executed { admission, .. } =
        &collection.result.runtime.outcome
    else {
        return Err(error(
            "cross completed carrier is not actual admitted native execution",
        ));
    };
    let (effective, environment) = super::linux_mixed_installed::reconstruct_effective_invocation(
        &request,
        context.images,
        admission,
    )?;
    for (leaf, bytes) in [
        ("effective-invocation.bin", effective),
        (
            "effective-environment.json",
            serde_json::to_vec(&environment)?,
        ),
    ] {
        let path = format!("{}/{leaf}", owner.prefix);
        retain(&context.artifact_root.join(&path), &bytes)?;
        let artifact = Artifact {
            path,
            length: bytes.len() as u64,
            sha256: hash(&bytes),
        };
        if leaf.ends_with(".bin") {
            collection.effective_invocation = Some(artifact.clone());
        } else {
            collection.effective_environment = Some(artifact.clone());
        }
        collection.persisted.artifacts.push(artifact);
    }
    collection.prepared_native_receipt = owner
        .native_receipt
        .as_ref()
        .ok_or_else(|| error("cross original pre-ACK receipt absent"))?
        .clone();
    collection
        .persisted
        .artifacts
        .push(collection.prepared_native_receipt.clone());
    Ok(collection)
}

pub fn run(context: &CrossAttemptContext<'_>, report: &mut CrossAttemptReport) -> Result<()> {
    let result = (|| {
        report.peer_account = Some(
            super::linux_mixed_installed::provision_cross_attempt_account_until(
                context.identity,
                context.cell,
                &report.acquisition_output,
                context.deadline,
            )?,
        );
        let (registry, mut target, mut peer) = contracts(context, report)?;
        report.restoration_required = true;
        retain(
            &report.output_root.join("restoration-intent.json"),
            &serde_json::to_vec(
                &json!({"format":"memcordon.linux-cross-policy-restoration-intent","revision":1,"identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"prior_registry":report.prior_registry}),
            )?,
        )?;
        let epoch = apply(report, &registry, "activation", context.deadline)?;
        target.expected_epoch = epoch.clone();
        peer.expected_epoch = epoch;
        let mut challenge = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut challenge)?;
        if challenge == [0; 32] {
            return Err(error("cross original challenge is zero"));
        }
        let challenge = hex::encode(challenge);
        retain(
            &report.output_root.join("challenge.bin"),
            &hex::decode(&challenge).map_err(|error| CiError::Message(error.to_string()))?,
        )?;
        let peer_index = start(
            context,
            report,
            peer,
            "peer",
            "own-abstract-held",
            &challenge,
        )?;
        let listener = wait_held(report, peer_index, &challenge, context.deadline)?;
        let before = report.attempts[peer_index]
            .observer
            .as_ref()
            .expect("retained native peer")
            .target
            .live_snapshot()
            .map_err(CiError::Message)?;
        let target_index = start(
            context,
            report,
            target,
            "target",
            "forbidden-abstract",
            &challenge,
        )?;
        let target_native = report.attempts[target_index]
            .prepared_target
            .as_ref()
            .ok_or_else(|| error("cross original pre-ACK target snapshot absent"))?
            .clone();
        if (before.network.device, before.network.inode)
            == (target_native.network.device, target_native.network.inode)
            || before.process_id == target_native.process_id
        {
            return Err(error(
                "cross concurrent real attempts share a native target/network namespace",
            ));
        }
        let target = collect(context, report, target_index, &challenge)?;
        let after = report.attempts[peer_index]
            .observer
            .as_ref()
            .expect("retained peer native owner")
            .target
            .live_snapshot()
            .map_err(CiError::Message)?;
        if serde_json::to_value(&before)? != serde_json::to_value(&after)? {
            return Err(error(
                "cross original peer identity/namespace changed while target probed",
            ));
        }
        report.target = Some(target);
        report.attempts[peer_index]
            .launch
            .release_fixture_barrier()?;
        report.peer = Some(collect(context, report, peer_index, &challenge)?);
        let prior = report.prior_registry.clone();
        apply(report, &prior, "restoration", context.cleanup_deadline)?;
        report.restoration_required = false;
        let peer_prefix = &report.attempts[peer_index].prefix;
        let target_prefix = &report.attempts[target_index].prefix;
        let reference =
            |leaf: &str| relative(context.artifact_root, &report.output_root.join(leaf));
        let account = report
            .peer_account
            .as_ref()
            .expect("retained actual account");
        let mut canary_fields = serde_json::Map::new();
        for group in [
            json!({"format":"memcordon.linux-other-attempt-abstract-canary","revision":1,"run_id":context.identity.run_id,"lease_id":context.lease_id,"cell":context.cell,"challenge":challenge,"name":listener["observation"]["name"],"peer_account":account,"peer_account_intent":relative(context.artifact_root,&account.intent)?,"peer_account_passwd":relative(context.artifact_root,&account.native_readback)?,"peer_account_group":relative(context.artifact_root,&account.group_readback)?}),
            json!({"original_lease":relative(context.artifact_root,context.original_lease)?,"original_acquisition":relative(context.artifact_root,context.original_acquisition)?,"cross_owner":reference("owner.json")?,"prior_activation":reference("prior-activation.json")?,"original_contract":reference("original-contract.json")?,"prior_registry":reference("prior-registry.json")?,"activation":reference("activation.json")?,"activation_policy":reference("activation.policy.json")?,"activation_invocation":reference("activation.invocation.json")?,"activation_exit":reference("activation.exit.json")?,"activation_stderr":reference("activation.stderr.bin")?}),
            json!({"restoration":reference("restoration.json")?,"restoration_policy":reference("restoration.policy.json")?,"restoration_invocation":reference("restoration.invocation.json")?,"restoration_exit":reference("restoration.exit.json")?,"restoration_stderr":reference("restoration.stderr.bin")?,"peer_frontend_invocation":format!("{peer_prefix}/original-frontend-invocation.json"),"peer_frontend_exit":format!("{peer_prefix}/original-frontend-exit.json"),"peer_case":format!("{peer_prefix}/case-evidence.json"),"peer_account_retirement":reference("account-retired.json")?,"peer_account_creation":relative(context.artifact_root,&report.acquisition_output.join("exclusive-account-useradd-creation.json"))?}),
            json!({"peer_request":format!("{peer_prefix}/provider-request.json"),"peer_prepared":format!("{peer_prefix}/prepared.json"),"peer_native":report.attempts[peer_index].native_receipt.as_ref().expect("retained peer native receipt").path,"peer_result":format!("{peer_prefix}/result.json"),"peer_retirement":format!("{peer_prefix}/native-family-retirement.json"),"held_peer":before,"held_peer_after":after,"target_native":target_native,"listener":listener,"peer_collection_root":peer_prefix,"target_collection_root":target_prefix}),
        ] {
            for (field, value) in group
                .as_object()
                .ok_or_else(|| error("cross original canary group is not an object"))?
            {
                if canary_fields.insert(field.clone(), value.clone()).is_some() {
                    return Err(error("cross original canary duplicates field"));
                }
            }
        }
        let canary = Value::Object(canary_fields);
        let bytes = serde_json::to_vec(&canary)?;
        let path = reference("other-attempt-abstract-canary.json")?;
        retain(&context.artifact_root.join(&path), &bytes)?;
        report.canary = Some(Artifact {
            path,
            length: bytes.len() as u64,
            sha256: hash(&bytes),
        });
        Ok(())
    })();
    if let Err(error) = &result {
        report.failures.push(error.to_string());
    }
    result
}

fn measured_account_command(
    report: &mut CrossAttemptReport,
    program: &str,
    args: &[&str],
    stem: &str,
) -> Result<(memcordon_testkit::ObservedOutput, Value)> {
    let held_program = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(program)?;
    let metadata = held_program.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(error(
            "cross account command original image is not protected",
        ));
    }
    let image = read(Path::new(program), 64 * 1024 * 1024)?;
    let image_sha = hex::encode(Sha256::digest(&image));
    let leaf = |suffix: &str| format!("{stem}.{suffix}");
    retain(&report.output_root.join(leaf("image.bin")), &image)?;
    let started_unix_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CiError::Message(error.to_string()))?
        .as_millis();
    let wall_remaining = u128::from(report.cleanup_deadline_unix_millis)
        .checked_sub(started_unix_millis)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| error("cross account command exceeds original wall cutoff"))?;
    let budget =
        bounded(report.cleanup_deadline, Duration::from_secs(30))?.min(Duration::from_millis(
            u64::try_from(wall_remaining).map_err(|error| CiError::Message(error.to_string()))?,
        ));
    let invocation = serde_json::to_vec(
        &json!({"format":"memcordon.linux-cross-account-command","revision":1,"identity":report.identity,"cell":report.cell,"program":program,"program_sha256":image_sha,"arguments":args,"cwd":report.output_root,"started_unix_millis":started_unix_millis,"budget_millis":budget.as_millis(),"cleanup_deadline_unix_millis":report.cleanup_deadline_unix_millis}),
    )?;
    retain(
        &report.output_root.join(leaf("invocation.json")),
        &invocation,
    )?;
    let invocation_sha = hex::encode(Sha256::digest(&invocation));
    let mut owner_index = None;
    let output=CommandSpec::new(program,&report.output_root,budget).bounded_until(report.cleanup_deadline).args(args.iter().copied()).output_quiet_with_creation(|child|{
        let pid=child.id();let birth=crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)?;
        report.commands.push(HeldLinuxProcess::acquire(pid,birth).map_err(CiError::Message)?);let index=report.commands.len()-1;owner_index=Some(index);
        let kernel=report.commands[index].hold_executable_image(report.cleanup_deadline).map_err(CiError::Message)?;
        if kernel["device"]!=metadata.dev()||kernel["inode"]!=metadata.ino()||kernel["length"]!=metadata.len()||kernel["sha256"]!=image_sha{return Err(error("cross account command kernel image differs from held original"));}
        retain(&report.output_root.join(leaf("creation.json")),&serde_json::to_vec(&json!({"format":"memcordon.linux-cross-account-command-creation","revision":1,"process_id":pid,"birth":birth,"invocation_sha256":invocation_sha,"kernel_image":kernel}))?)
    })?;
    let held = report.commands
        [owner_index.ok_or_else(|| error("cross account command original Child absent"))?]
    .retirement_identity()
    .map_err(CiError::Message)?;
    if !held.retirement_observed {
        return Err(error(
            "cross account command original PIDFD remains live after wait",
        ));
    }
    retain(&report.output_root.join(leaf("stdout.bin")), &output.stdout)?;
    retain(&report.output_root.join(leaf("stderr.bin")), &output.stderr)?;
    retain(
        &report.output_root.join(leaf("exit.json")),
        &serde_json::to_vec(
            &json!({"format":"memcordon.linux-cross-account-command-exit","revision":1,"held":held,"raw_wait_status":output.status.into_raw(),"native_exit":output.status.code(),"signal":output.status.signal(),"invocation_sha256":invocation_sha,"stdout_sha256":hex::encode(Sha256::digest(&output.stdout)),"stderr_sha256":hex::encode(Sha256::digest(&output.stderr))}),
        )?,
    )?;
    Ok((
        output,
        json!({"invocation":leaf("invocation.json"),"image":leaf("image.bin"),"creation":leaf("creation.json"),"stdout":leaf("stdout.bin"),"stderr":leaf("stderr.bin"),"exit":leaf("exit.json")}),
    ))
}

fn retain_account_census(
    root: &Path,
    account: &ExclusiveAccount,
    deadline: Instant,
    ordinal: u32,
) -> Result<String> {
    let mut rows = Vec::new();
    for process in std::fs::read_dir("/proc")? {
        let process = process?;
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let tasks = match std::fs::read_dir(process.path().join("task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for task in tasks {
            if rows.len() >= 1_048_576 || Instant::now() >= deadline {
                return Err(error("cross original account census exceeds native bound"));
            }
            let task = task?;
            let tid = task
                .file_name()
                .to_str()
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or_else(|| error("cross native task id malformed"))?;
            let status = match std::fs::read(task.path().join("status")) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let text = std::str::from_utf8(&status)
                .map_err(|error| CiError::Message(error.to_string()))?;
            let mut credentials = Vec::new();
            for (prefix, expected) in [("Pid:", tid), ("Tgid:", pid)] {
                let actual = text
                    .lines()
                    .find(|line| line.starts_with(prefix))
                    .and_then(|line| line[prefix.len()..].trim().parse::<u32>().ok());
                if actual != Some(expected) {
                    return Err(error(
                        "cross native task raw PID/TGID differs from original sampled task",
                    ));
                }
            }
            for (prefix, owned, count) in [
                ("Uid:", account.uid, 4),
                ("Gid:", account.gid, 4),
                ("Groups:", account.gid, 0),
            ] {
                let line = text
                    .lines()
                    .find(|line| line.starts_with(prefix))
                    .ok_or_else(|| error("cross native task credential absent"))?;
                let values = line[prefix.len()..]
                    .split_whitespace()
                    .map(str::parse::<u32>)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|error| CiError::Message(error.to_string()))?;
                if (count != 0 && values.len() != count) || values.contains(&owned) {
                    return Err(error(
                        "cross original account remains in native task credentials",
                    ));
                }
                credentials.push(values);
            }
            rows.push(
                json!({"process_id":pid,"task_id":tid,"status":status,"credentials":credentials}),
            );
        }
    }
    if rows.is_empty() {
        return Err(error("cross native account task census empty"));
    }
    rows.sort_by_key(|row| (row["process_id"].as_u64(), row["task_id"].as_u64()));
    let leaf = format!("account-task-census-{ordinal}.json");
    retain(
        &root.join(&leaf),
        &serde_json::to_vec(
            &json!({"format":"memcordon.linux-cross-account-task-census","revision":1,"uid":account.uid,"gid":account.gid,"tasks":rows}),
        )?,
    )?;
    Ok(leaf)
}

impl CrossAttemptReport {
    /// The caller first settles the original native attempts; this method never
    /// replaces their process observations with reconstructed journal claims.
    pub fn recover_after_native_attempts(
        output: &Path,
        identity: &SourceIdentity,
        cell: &ProductKey,
        lease_id: &str,
        artifact_root: &Path,
        admin_root: &Path,
        work_wall: u64,
        cleanup_wall: u64,
        cleanup_deadline: Instant,
    ) -> Result<Option<Self>> {
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| CiError::Message(error.to_string()))?
                .as_millis(),
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let remaining = cleanup_wall
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| error("cross cold original wall cleanup cutoff exhausted"))?;
        let wall_deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or_else(|| error("cross cold original wall-to-monotonic cutoff overflow"))?;
        let cleanup_deadline = cleanup_deadline.min(wall_deadline);
        bounded(cleanup_deadline, Duration::from_secs(1))?;
        let owner_path = output.join("owner.json");
        let owner_bytes = match read(&owner_path, 4 * 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(CiError::Io(native_error))
                if native_error.kind() == std::io::ErrorKind::NotFound =>
            {
                if output
                    .join("account/exclusive-account-intent.json")
                    .exists()
                    || output.join("restoration-intent.json").exists()
                {
                    return Err(error(
                        "cross cold partial acquisition lacks original owner authority",
                    ));
                }
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let owner: Value = decode(&owner_bytes)?;
        let fields = [
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "acquisition_output",
            "protected_output",
            "original_registry_sha256",
            "primary_account",
            "original_lease",
            "original_acquisition",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ];
        if owner.as_object().is_none_or(|object| {
            object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
        }) || owner["format"] != "memcordon.linux-cross-attempt-owner"
            || owner["revision"] != 1
            || owner["identity"] != serde_json::to_value(identity)?
            || owner["cell"] != serde_json::to_value(cell)?
            || owner["lease_id"] != lease_id
            || owner["work_deadline_unix_millis"] != work_wall
            || owner["cleanup_deadline_unix_millis"] != cleanup_wall
            || work_wall == 0
            || cleanup_wall <= work_wall
        {
            return Err(error(
                "cross cold original owner/source/lease/cutoffs differ",
            ));
        }
        relative(artifact_root, output)?;
        let original_path = |field: &str| -> Result<PathBuf> {
            let path = PathBuf::from(
                owner[field]
                    .as_str()
                    .ok_or_else(|| error("cross cold original authority source absent"))?,
            );
            if !path.is_absolute()
                || path.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
            {
                return Err(error("cross cold original authority path unsafe"));
            }
            relative(artifact_root, &path)?;
            Ok(path)
        };
        let lease: Value = decode(&read(&original_path("original_lease")?, 4 * 1024 * 1024)?)?;
        let acquisition: Value = decode(&read(
            &original_path("original_acquisition")?,
            4 * 1024 * 1024,
        )?)?;
        if lease["format"] != "memcordon.consumer-readiness.linux-lease-owner"
            || lease["revision"] != 1
            || lease["identity"] != owner["identity"]
            || lease["cell"] != owner["cell"]
            || lease["lease_id"] != lease_id
            || lease["artifact_root"] != serde_json::to_value(artifact_root)?
            || lease["admin_root"] != serde_json::to_value(admin_root)?
            || lease["work_deadline_unix_millis"] != work_wall
            || lease["cleanup_deadline_unix_millis"] != cleanup_wall
            || acquisition["format"] != "memcordon.owned-readiness-resources"
            || acquisition["revision"] != 1
            || acquisition["identity"] != owner["identity"]
            || acquisition["cell"] != owner["cell"]
            || acquisition["admin_root"] != lease["admin_root"]
            || acquisition["device"] != lease["device"]
            || acquisition["inode"] != lease["inode"]
            || acquisition["account"] != owner["primary_account"]
        {
            return Err(error(
                "cross cold original primary acquisition/lease authority differs",
            ));
        }
        let admin = hold_directory(admin_root)?;
        let admin_metadata = admin.metadata()?;
        if lease["device"] != admin_metadata.dev() || lease["inode"] != admin_metadata.ino() {
            return Err(error(
                "cross cold administrator directory changed native identity",
            ));
        }
        let acquisition_output = output.join("account");
        if owner["acquisition_output"] != serde_json::to_value(&acquisition_output)? {
            return Err(error("cross cold secondary acquisition scope differs"));
        }
        let protected_root = PathBuf::from(
            owner["protected_output"]
                .as_str()
                .ok_or_else(|| error("cross cold original policy source absent"))?,
        );
        if !protected_root.is_absolute()
            || protected_root.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || protected_root.strip_prefix(admin_root).is_err()
        {
            return Err(error(
                "cross cold original protected policy directory escapes lease",
            ));
        }
        let directory_owners = vec![
            admin,
            hold_directory(output)?,
            hold_directory(&acquisition_output)?,
            hold_directory(&protected_root)?,
        ];
        let prior_bytes = read(&output.join("prior-registry.json"), 4 * 1024 * 1024)?;
        if owner["original_registry_sha256"] != hash(&prior_bytes) {
            return Err(error("cross cold original registry digest differs"));
        }
        let prior_registry: RuntimePrivatePolicyRegistryV3 = decode(&prior_bytes)?;
        prior_registry.validate().map_err(CiError::Message)?;
        if serde_json::to_value(&prior_registry)?["legacy"] != lease["legacy"]
            || acquisition["legacy"] != lease["legacy"]
        {
            return Err(error("cross cold original frozen legacy authority differs"));
        }
        let initial: Value = decode(&read(
            &output.join("prior-activation.json"),
            4 * 1024 * 1024,
        )?)?;
        let contract: WorkloadContractV3 = decode(&read(
            &output.join("original-contract.json"),
            4 * 1024 * 1024,
        )?)?;
        contract.validate().map_err(CiError::Message)?;
        if initial["format"] != "memcordon.local-private-activation"
            || initial["revision"] != 2
            || initial["registry"] != serde_json::to_value(&prior_registry)?
            || initial["registry_digest"]
                != serde_json::to_value(
                    prior_registry
                        .canonical_digest()
                        .map_err(CiError::Message)?,
                )?
            || initial["epoch"] != serde_json::to_value(&contract.expected_epoch)?
        {
            return Err(error(
                "cross cold original active registry/contract differs",
            ));
        }
        let mut restoration_required = false;
        match read(&output.join("restoration-intent.json"), 4 * 1024 * 1024) {
            Ok(bytes) => {
                let intent: Value = decode(&bytes)?;
                if intent["format"] != "memcordon.linux-cross-policy-restoration-intent"
                    || intent["revision"] != 1
                    || intent["identity"] != owner["identity"]
                    || intent["cell"] != owner["cell"]
                    || intent["lease_id"] != lease_id
                    || intent["prior_registry"] != serde_json::to_value(&prior_registry)?
                {
                    return Err(error("cross cold original restoration intent differs"));
                }
                restoration_required = true;
            }
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let peer_account = if acquisition_output
            .join("exclusive-account-intent.json")
            .exists()
        {
            super::linux_mixed_installed::recover_cross_attempt_account_until(
                identity,
                cell,
                &acquisition_output,
                cleanup_deadline,
            )?
        } else {
            None
        };
        let mut recovery_ordinal = 0u32;
        for entry in std::fs::read_dir(output)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| error("cross cold original archive filename nonUTF8"))?;
            if name.starts_with("account-") || name.starts_with("recovery-restoration-") {
                for part in name.split('-') {
                    let token = part.split('.').next().unwrap_or("");
                    if let Ok(ordinal) = token.parse::<u32>() {
                        recovery_ordinal = recovery_ordinal.max(ordinal);
                    }
                }
            }
        }
        if recovery_ordinal >= 128 {
            return Err(error(
                "cross original cold recovery native capture bound exhausted",
            ));
        }
        Ok(Some(Self {
            identity: identity.clone(),
            cell: cell.clone(),
            output_root: output.into(),
            protected_root,
            acquisition_output,
            peer_account,
            account_retired: false,
            prior_registry,
            restoration_required,
            attempts: Vec::new(),
            commands: Vec::new(),
            directory_owners,
            target: None,
            peer: None,
            canary: None,
            work_deadline_unix_millis: work_wall,
            cleanup_deadline,
            cleanup_deadline_unix_millis: cleanup_wall,
            failures: Vec::new(),
            recovery_ordinal,
        }))
    }
    pub fn native_owners_settled(&self) -> bool {
        !self.restoration_required
            && self.account_retired
            && self
                .commands
                .iter()
                .all(|owner| owner.exited().unwrap_or(false))
            && self.attempts.iter().all(|owner| {
                owner.launch.capture_owners_settled()
                    && owner.observer.as_ref().is_some_and(|observer| {
                        observer.native_family_retired(&[]).unwrap_or(false)
                    })
            })
    }
    pub fn finalize(&mut self) -> Result<()> {
        bounded(self.cleanup_deadline, Duration::from_secs(1))?;
        self.recovery_ordinal = self
            .recovery_ordinal
            .checked_add(1)
            .ok_or_else(|| error("cross bounded cleanup ordinal overflow"))?;
        for owner in &mut self.attempts {
            if !owner.launch.capture_owners_settled() {
                if let Some(frontend) = &owner.frontend {
                    if !frontend.exited().map_err(CiError::Message)? {
                        let signaled = frontend.signal_interrupt().map_err(CiError::Message)?;
                        if let Err(errno) = signaled {
                            return Err(CiError::Message(format!(
                                "cross original frontend interrupt failed errno {errno}"
                            )));
                        }
                    }
                }
                owner
                    .launch
                    .wait_and_capture(bounded(self.cleanup_deadline, Duration::from_secs(30))?)?;
            }
            if !owner
                .observer
                .as_ref()
                .is_some_and(|observer| observer.native_family_retired(&[]).unwrap_or(false))
            {
                return Err(error(
                    "cross original native family still owned; recovery remains required",
                ));
            }
        }
        if self.restoration_required {
            let prior = self.prior_registry.clone();
            let stem = format!("recovery-restoration-{}", self.recovery_ordinal);
            self.recovery_ordinal = self
                .recovery_ordinal
                .checked_add(1)
                .ok_or_else(|| error("cross bounded recovery ordinal overflow"))?;
            apply(self, &prior, &stem, self.cleanup_deadline)?;
            self.restoration_required = false;
        }
        if self.account_retired {
            return Ok(());
        }
        if self.peer_account.is_none()
            && self
                .acquisition_output
                .join("exclusive-account-intent.json")
                .exists()
        {
            self.peer_account = super::linux_mixed_installed::recover_cross_attempt_account_until(
                &self.identity,
                &self.cell,
                &self.acquisition_output,
                self.cleanup_deadline,
            )?;
        }
        let Some(account) = &self.peer_account else {
            self.account_retired = true;
            return Ok(());
        };
        let account = account.clone();
        let census = retain_account_census(
            &self.output_root,
            &account,
            self.cleanup_deadline,
            self.recovery_ordinal,
        )?;
        let mut identity_checks = Vec::new();
        let mut removals = Vec::new();
        let mut absence_checks = Vec::new();
        for (database, original) in [
            ("passwd", &account.native_readback),
            ("group", &account.group_readback),
        ] {
            let (lookup, proof) = measured_account_command(
                self,
                "/usr/bin/getent",
                &[database, &account.name],
                &format!("account-lookup-{database}-{}", self.recovery_ordinal),
            )?;
            identity_checks.push(proof);
            if lookup.status.code() == Some(2) && lookup.stdout.is_empty() {
                continue;
            }
            if !lookup.status.success() || lookup.stdout != read(original, 4096)? {
                return Err(error(
                    "cross original secondary account native identity changed before retirement",
                ));
            }
            let program = if database == "passwd" {
                "/usr/sbin/userdel"
            } else {
                "/usr/sbin/groupdel"
            };
            let (deleted, proof) = measured_account_command(
                self,
                program,
                &["--", &account.name],
                &format!("account-removal-{database}-{}", self.recovery_ordinal),
            )?;
            removals.push(proof);
            let destination = self.output_root.join(format!(
                "account-retirement-{database}-{}.json",
                self.recovery_ordinal
            ));
            retain(
                &destination,
                &serde_json::to_vec(
                    &json!({"format":"memcordon.linux-cross-account-retirement","revision":1,"account":account,"database":database,"program":program,"stdout":deleted.stdout,"stderr":deleted.stderr,"native_exit":deleted.status.code()}),
                )?,
            )?;
            if !deleted.status.success() {
                return Err(error(
                    "cross secondary account removal failed; original owner retained",
                ));
            }
        }
        for (ordinal, (database, key)) in [
            ("passwd", account.name.clone()),
            ("passwd", account.uid.to_string()),
            ("group", account.name.clone()),
            ("group", account.gid.to_string()),
        ]
        .into_iter()
        .enumerate()
        {
            let (absent, proof) = measured_account_command(
                self,
                "/usr/bin/getent",
                &[database, &key],
                &format!("account-absence-{}-{ordinal}", self.recovery_ordinal),
            )?;
            absence_checks.push(proof);
            if absent.status.code() != Some(2) || !absent.stdout.is_empty() {
                return Err(error(
                    "cross original secondary account/native group absence unresolved",
                ));
            }
        }
        let retirement_leaf = if self.output_root.join("account-retired.json").exists() {
            format!("account-recovery-retired-{}.json", self.recovery_ordinal)
        } else {
            "account-retired.json".into()
        };
        retain(
            &self.output_root.join(retirement_leaf),
            &serde_json::to_vec(
                &json!({"format":"memcordon.linux-cross-account-retired","revision":2,"account":account,"task_census":census,"identity_checks":identity_checks,"removals":removals,"absence_checks":absence_checks}),
            )?,
        )?;
        self.account_retired = true;
        Ok(())
    }
}
