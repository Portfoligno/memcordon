//! Materializes the owned native mixed workload inside an already installed
//! selected product lifetime. Installation and final uninstall belong to the
//! outer owner; this module retains every imported-image receipt for it.
#![cfg(target_os = "linux")]
use super::installed_consumer::MaterializedPayload;
use crate::{CiError, Result, command::CommandSpec, consumer_readiness_ledger::SourceIdentity};
use memcordon_core::{
    BoundedVec, DiagnosticSha256,
    workload_contract::LogicalId,
    workload_contract_v3::RootRelativePath,
    workload_registry_v3::{ImageEntryV1, ImageEntrypointV1, RuntimeImageDefinitionV1},
};
use memcordon_readiness_verifier::ProductKey;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureBarrierDecision {
    Continue,
    WithholdRelease,
}

/// An installed invocation retains its actual frontend and capture workers on
/// every error. The outer lifecycle owner must recover the provider attempt
/// before disposing of this value; a capture timeout is never retirement.
pub struct InstalledMixedLaunch {
    pub frontend: std::process::Child,
    stdout_worker: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    stderr_worker: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub result: PathBuf,
    pub observation_directory: PathBuf,
    pub frontend_status: Option<std::process::ExitStatus>,
    frontend_birth: Option<u64>,
    frontend_invocation_owner: File,
    frontend_invocation_bytes: Vec<u8>,
    capture_failures: Vec<String>,
    image_entrypoint_source: Option<serde_json::Value>,
    image_entrypoint_owner: Option<crate::linux_consumer_readiness::HeldLinuxProcess>,
    capture_gate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    capture_pipe_owners: Vec<File>,
    build_file_owners: Vec<File>,
    outside_canary: Option<super::linux_isolation_cases::HostOutsideFile>,
    host_socket_descriptor: Option<super::linux_isolation_cases::HostSocketDescriptor>,
}

pub struct InstalledMixedLaunchInput<'a> {
    pub directory: &'a Path,
    pub contract: &'a Path,
    pub caller_uid: u32,
    pub caller_gid: u32,
    pub target_arguments: &'a [std::ffi::OsString],
    pub deadline: &'a std::ffi::OsStr,
    pub memory: &'a std::ffi::OsStr,
}

pub struct CompletedMixedCollection {
    pub lease_id: String,
    pub persisted: crate::linux_consumer_readiness::LinuxCollectedEvidence,
    pub result: memcordon_core::result_v2::ResultV2,
    pub held_processes: Vec<memcordon_readiness_verifier::HeldProcessIdentity>,
    pub prepared_native_receipt: memcordon_readiness_verifier::Artifact,
    pub frontend_status: i32,
    pub effective_invocation: Option<memcordon_readiness_verifier::Artifact>,
    pub effective_environment: Option<memcordon_readiness_verifier::Artifact>,
    pub public_invocation: memcordon_readiness_verifier::Artifact,
    pub public_environment: memcordon_readiness_verifier::Artifact,
    pub export_receipt: memcordon_readiness_verifier::Artifact,
}

/// Reconstructs the effective native bytes from the actual pre-dispatch
/// request and the imported approved image definitions. The authenticated
/// admission digest must equal this reconstruction; CI never supplies it to
/// the provider or authorizes execution through it.
pub fn reconstruct_effective_invocation(
    public: &memcordon_core::mixed_runtime::MixedRuntimeRequest,
    images: &MixedImages,
    admission: &memcordon_core::workload_admission_v3::RuntimeMixedAdmissionSnapshot,
) -> Result<(Vec<u8>, memcordon_readiness_verifier::NativeEnvironment)> {
    use memcordon_readiness_verifier::{NativeEnvironment, UnixEnvironmentVariable};
    public.validate().map_err(CiError::Message)?;
    if public.contract != admission.request
        || images.runtime.reference().map_err(CiError::Message)? != public.contract.runtime_image
        || images.input.reference().map_err(CiError::Message)? != public.contract.input_image
    {
        return Err(CiError::Message(
            "effective invocation image/request differs from authenticated admission".into(),
        ));
    }
    fn u32_value(reader: &mut impl Read) -> Result<u32> {
        let mut bytes = [0u8; std::mem::size_of::<u32>()];
        reader.read_exact(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }
    fn value(reader: &mut impl Read) -> Result<Vec<u8>> {
        let length = u32_value(reader)?;
        if length > 64 * 1024 {
            return Err(CiError::Message(
                "native invocation value exceeds bound".into(),
            ));
        }
        let mut value = vec![0; length as usize];
        reader.read_exact(&mut value)?;
        Ok(value)
    }
    fn put(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
        output.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|error| CiError::Message(error.to_string()))?
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
        Ok(())
    }
    let mut reader = std::io::Cursor::new(&public.native_launch);
    let mut version = [0u8; std::mem::size_of::<u16>()];
    reader.read_exact(&mut version)?;
    if u16::from_be_bytes(version) != 3 {
        return Err(CiError::Message(
            "effective invocation native codec differs".into(),
        ));
    }
    let mut restart = [0u8; std::mem::size_of::<u64>()];
    reader.read_exact(&mut restart)?;
    if value(&mut reader)? != public.contract.launch.entrypoint.as_str().as_bytes() {
        return Err(CiError::Message(
            "actual public image selector differs".into(),
        ));
    }
    let count = u32_value(&mut reader)?;
    if count > 4096 {
        return Err(CiError::Message("actual native argv exceeds bound".into()));
    }
    let mut arguments = Vec::new();
    for _ in 0..count {
        arguments.push(value(&mut reader)?);
    }
    if u32_value(&mut reader)? != 0 {
        return Err(CiError::Message(
            "readiness public request inherited caller environment".into(),
        ));
    }
    let mut policy = Vec::new();
    reader.read_to_end(&mut policy)?;
    if policy.is_empty() {
        return Err(CiError::Message(
            "actual native launch policy absent".into(),
        ));
    }
    let entry = images
        .runtime
        .entrypoints
        .as_slice()
        .iter()
        .find(|entry| entry.id == public.contract.launch.entrypoint)
        .ok_or_else(|| CiError::Message("actual authorized image entrypoint absent".into()))?;
    let mut environment = BTreeMap::new();
    let mut directories = Vec::new();
    for image in [&images.runtime, &images.input] {
        for variable in image.startup_environment.as_slice() {
            if environment
                .insert(
                    variable.name.as_bytes().to_vec(),
                    variable.value.as_bytes().to_vec(),
                )
                .is_some()
            {
                return Err(CiError::Message(
                    "approved image environment overlaps".into(),
                ));
            }
        }
        for directory in image.library_directories.as_slice() {
            if !directories.contains(directory) {
                directories.push(directory.clone());
            }
        }
    }
    if !directories.is_empty() {
        environment.insert(
            b"LD_LIBRARY_PATH".to_vec(),
            directories
                .iter()
                .map(|directory| format!("/{}", directory.as_str()))
                .collect::<Vec<_>>()
                .join(":")
                .into_bytes(),
        );
    }
    let environment = environment
        .into_iter()
        .map(|(name, value)| UnixEnvironmentVariable { name, value })
        .collect::<Vec<_>>();
    let mut effective = Vec::new();
    effective.extend_from_slice(&version);
    effective.extend_from_slice(&restart);
    put(
        &mut effective,
        format!("/{}", entry.path.as_str()).as_bytes(),
    )?;
    effective.extend_from_slice(&count.to_be_bytes());
    for argument in arguments {
        put(&mut effective, &argument)?;
    }
    effective.extend_from_slice(
        &u32::try_from(environment.len())
            .map_err(|error| CiError::Message(error.to_string()))?
            .to_be_bytes(),
    );
    for variable in &environment {
        put(&mut effective, &variable.name)?;
        put(&mut effective, &variable.value)?;
    }
    effective.extend_from_slice(&policy);
    effective.extend_from_slice(public.contract.digest().map_err(CiError::Message)?.bytes());
    if memcordon_core::workload_codec::hash_bytes(&effective) != admission.invocation_sha256 {
        return Err(CiError::Message(
            "reconstructed approved invocation differs from actually admitted invocation digest"
                .into(),
        ));
    }
    Ok((effective, NativeEnvironment::UnixBytes(environment)))
}

/// Data from the outer selected installation lifetime. The root controller
/// observes native owners; the public frontend runs under the separate caller.
pub struct InstalledMixedDriverInput<'a> {
    pub recovery_harness: &'a super::linux_recovery_harness::HeldRecoveryHarness,
    pub lease_id: String,
    pub admin_root: &'a Path,
    pub payload: &'a MaterializedPayload,
    pub provider: &'a memcordon_core::PublicProviderBindingV1,
    pub legacy: memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry,
    pub workspace: &'a Path,
    pub output: &'a Path,
    pub artifact_root: &'a Path,
    pub identity: SourceIdentity,
    pub cell: ProductKey,
    pub deadline: std::time::Instant,
    pub cleanup_deadline: std::time::Instant,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
}

/// Explicit recipe inputs are application requests, not acceptance predicates.
/// Their keys remain in the outer finite manifest even if execution fails.
pub struct InstalledMixedRecipe {
    pub key: memcordon_readiness_verifier::CaseKey,
    pub mode: String,
    pub arguments: Vec<std::ffi::OsString>,
    pub requirements: Vec<memcordon_core::workload_contract_v3::RequirementV3>,
    pub output_files: Vec<RootRelativePath>,
    pub memory: std::ffi::OsString,
    pub product_deadline: std::ffi::OsString,
    pub observation_limit: Duration,
}

pub struct OwnedMixedRecipe {
    pub key: memcordon_readiness_verifier::CaseKey,
    pub launch: InstalledMixedLaunch,
    pub observer: Option<crate::linux_consumer_readiness::PreparedLinuxObserver>,
    pub held: Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    pub transcript: Vec<crate::linux_consumer_readiness::LinuxTranscriptRow>,
    pub prepared_native_receipt: Option<memcordon_readiness_verifier::Artifact>,
    pub host_tcp_canary: Option<std::net::TcpListener>,
    pub host_abstract_canary: Option<std::os::unix::net::UnixListener>,
    pub host_path_canary: Option<super::linux_isolation_cases::HostPathSocket>,
}

/// Retained by the outer cleanup owner on *every* return. Native attempts,
/// imports and account intents must be settled before this owner is discarded.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedResourceCheckpoint {
    format: String,
    revision: u32,
    identity: SourceIdentity,
    cell: ProductKey,
    admin_root: PathBuf,
    device: u64,
    inode: u64,
    legacy: memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry,
    images: Option<MixedImages>,
    account: Option<ExclusiveAccount>,
}

#[derive(Default)]
pub struct InstalledMixedDriver {
    isolation_account_contexts: Vec<AccountRefusalContext>,
    isolation_import_contexts: Vec<AccountRefusalContext>,
    cross_attempt_reports: Vec<super::linux_cross_attempt_cases::CrossAttemptReport>,
    pub isolation_import_reports: Vec<super::linux_isolation_cases::ImportRefusalReport>,
    pub isolation_account_reports: Vec<super::linux_isolation_cases::AccountRefusalReport>,
    pub lifecycle_reports: Vec<super::linux_readiness_lifecycle_cases::LifecycleReport>,
    pub limits_reports: Vec<super::linux_readiness_limits_cases::LimitsReport>,
    recovered_case_images: Vec<(RuntimeImageDefinitionV1, PathBuf)>,
    pub image_reports: Vec<super::linux_readiness_image_cases::ImageCaseReport>,
    image_attempts_settled: bool,
    pub policy_reports: Vec<super::linux_readiness_policy_cases::PolicyCaseReport>,
    policy_attempts_settled: bool,
    admin_retirement: Option<AdminSourceRetirement>,
    pub retired_images: BTreeSet<String>,
    pub legacy_restored: bool,
    pub account_retired: bool,
    retired_account: Option<ExclusiveAccount>,
    pub images: Option<MixedImages>,
    pub account: Option<ExclusiveAccount>,
    pub active: Vec<OwnedMixedRecipe>,
    pub completed: Vec<(
        memcordon_readiness_verifier::CaseKey,
        CompletedMixedCollection,
    )>,
    pub failures: Vec<(memcordon_readiness_verifier::CaseKey, String)>,
}

struct AccountRefusalContext {
    key: memcordon_readiness_verifier::CaseKey,
    owner: serde_json::Value,
    baseline_contract: PathBuf,
    original_lease: PathBuf,
    acquisition: PathBuf,
}

impl InstalledMixedDriver {
    /// Reconstruct only the finite image import intents from this installation.
    /// Called after native attempt recovery and before policy/image retirement.
    #[expect(
        clippy::too_many_arguments,
        reason = "Recovery binds original image intent, lease, acquisition, policy, account, and cutoff separately"
    )]
    pub fn recover_image_case_intents(
        &mut self,
        output: &Path,
        identity: &SourceIdentity,
        cell: &ProductKey,
        admin_root: &Path,
        lease_id: &str,
        work_deadline_unix_millis: u64,
        cleanup_deadline_unix_millis: u64,
        deadline: std::time::Instant,
        artifact_root: &Path,
    ) -> Result<()> {
        let scenarios = [
            "neighbor-import",
            "first-image",
            "interpreter",
            "shared-library",
            "writable-alias",
            "ld-injection",
            "loader-config",
            "rpath-injection",
        ];
        for scenario in scenarios {
            let path = output
                .join("image-cases")
                .join(scenario)
                .join("import-intent.json");
            let present = match std::fs::symlink_metadata(&path) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            };
            if !present {
                continue;
            }
            let intent =
                decode_owned_resource_json(&read_owned_resource(&path, 16 * 1024 * 1024)?)?;
            let fields = [
                "format",
                "revision",
                "identity",
                "cell",
                "lease_id",
                "scenario",
                "definition",
                "definition_sha256",
                "cleanup_definition",
                "cleanup_definition_sha256",
                "submitted_definition_valid",
                "reference",
                "source_root",
                "work_deadline_unix_millis",
                "cleanup_deadline_unix_millis",
            ];
            let root = admin_root.join("image-cases").join(lease_id).join(scenario);
            let definition = root.join("definition.json");
            if intent.as_object().is_none_or(|object| {
                object.len() != fields.len()
                    || object.keys().any(|key| !fields.contains(&key.as_str()))
            }) || intent["format"] != "memcordon.linux-readiness-image-import-intent"
                || intent["revision"] != 1
                || intent["identity"] != serde_json::to_value(identity)?
                || intent["cell"] != serde_json::to_value(cell)?
                || intent["lease_id"] != lease_id
                || intent["scenario"] != scenario
                || intent["definition"] != serde_json::to_value(&definition)?
                || work_deadline_unix_millis == 0
                || cleanup_deadline_unix_millis <= work_deadline_unix_millis
                || intent["work_deadline_unix_millis"] != work_deadline_unix_millis
                || intent["cleanup_deadline_unix_millis"] != cleanup_deadline_unix_millis
            {
                return Err(CiError::Message(
                    "image case recovery intent crosses original finite owner/cutoff".into(),
                ));
            }
            let bytes = read_owned_resource(&definition, 16 * 1024 * 1024)?;
            let image: RuntimeImageDefinitionV1 =
                serde_json::from_value(decode_owned_resource_json(&bytes)?)?;
            let cleanup_path = root.join("cleanup-definition.json");
            let cleanup_bytes = read_owned_resource(&cleanup_path, 16 * 1024 * 1024)?;
            let cleanup: RuntimeImageDefinitionV1 =
                serde_json::from_value(decode_owned_resource_json(&cleanup_bytes)?)?;
            let valid = image.reference().is_ok();
            if intent["source_root"] != serde_json::to_value(root.join("source"))?
                || intent["definition_sha256"] != hex::encode(Sha256::digest(&bytes))
                || image.target != cell.target
                || intent["cleanup_definition"] != serde_json::to_value(&cleanup_path)?
                || intent["cleanup_definition_sha256"]
                    != hex::encode(Sha256::digest(&cleanup_bytes))
                || intent["submitted_definition_valid"] != valid
                || (!valid && scenario != "ld-injection")
                || cleanup.image_id != image.image_id
                || cleanup.target != cell.target
                || (valid && serde_json::to_value(&cleanup)? != serde_json::to_value(&image)?)
                || intent["reference"]
                    != serde_json::to_value(cleanup.reference().map_err(CiError::Message)?)?
            {
                return Err(CiError::Message(
                    "image case recovery exact definition/reference differs".into(),
                ));
            }
            if let Some((existing, path)) = self
                .recovered_case_images
                .iter()
                .find(|(image, _)| image.image_id == cleanup.image_id)
            {
                if existing != &cleanup || path != &cleanup_path {
                    return Err(CiError::Message(
                        "recovered image cleanup identity was reassociated".into(),
                    ));
                }
            } else {
                self.recovered_case_images.push((cleanup, cleanup_path));
            }
        }
        for (image, path) in super::linux_isolation_recovery::recover_imports(
            output,
            identity,
            cell,
            admin_root,
            lease_id,
            work_deadline_unix_millis,
            cleanup_deadline_unix_millis,
            deadline,
        )? {
            if let Some((original, original_path)) = self
                .recovered_case_images
                .iter()
                .find(|(original, _)| original.image_id == image.image_id)
            {
                if original != &image || original_path != &path {
                    return Err(CiError::Message(
                        "cold isolation image intent changed original definition owner".into(),
                    ));
                }
            } else {
                self.recovered_case_images.push((image, path));
            }
        }
        for (ordinal, recipe) in owned_fixture_recipes(cell)?.into_iter().enumerate() {
            if recipe.key.family != "L-ISO-03" || recipe.key.scenario != "other-attempt-abstract" {
                continue;
            }
            let source = output
                .join(format!("recipe-{ordinal}"))
                .join("cross-attempt-source");
            if let Some(mut report) =
                super::linux_cross_attempt_cases::CrossAttemptReport::recover_after_native_attempts(
                    &source,
                    identity,
                    cell,
                    lease_id,
                    artifact_root,
                    admin_root,
                    work_deadline_unix_millis,
                    cleanup_deadline_unix_millis,
                    deadline,
                )?
            {
                report.finalize()?;
                self.cross_attempt_reports.push(report);
            }
        }
        Ok(())
    }
    /// Read-only convergence after administrative sources were already retired.
    /// This cannot reconstruct an execution owner or authorize any removal.
    #[expect(
        clippy::too_many_arguments,
        reason = "Retirement assessment retains independent native resource and original custody inputs"
    )]
    pub fn assess_retired_resources(
        output: &Path,
        identity: &SourceIdentity,
        cell: &ProductKey,
        admin_root: &Path,
        device: u64,
        inode: u64,
        workspace: &Path,
        deadline: std::time::Instant,
    ) -> Result<()> {
        let path = if output.join("owned-resources-acquired.json").is_file() {
            output.join("owned-resources-acquired.json")
        } else {
            output.join("owned-resources-images.json")
        };
        let bytes = read_owned_resource(&path, 32 * 1024 * 1024)?;
        let checkpoint: OwnedResourceCheckpoint =
            serde_json::from_value(decode_owned_resource_json(&bytes)?)?;
        if checkpoint.format != "memcordon.owned-readiness-resources"
            || checkpoint.revision != 1
            || serde_json::to_value(&checkpoint.identity)? != serde_json::to_value(identity)?
            || checkpoint.cell != *cell
            || checkpoint.admin_root != admin_root
            || (checkpoint.device, checkpoint.inode) != (device, inode)
        {
            return Err(CiError::Message(
                "already-retired resource checkpoint association differs".into(),
            ));
        }
        let receipt = decode_owned_resource_json(&read_owned_resource(
            &output.join("owned-resources-retired.json"),
            32 * 1024 * 1024,
        )?)?;
        let mut digests = BTreeSet::new();
        if let Some(images) = &checkpoint.images {
            for definition in [&images.runtime, &images.input] {
                digests.insert(String::from(
                    definition.reference().map_err(CiError::Message)?.digest,
                ));
            }
        }
        let fields = [
            "format",
            "revision",
            "identity",
            "cell",
            "admin_root",
            "device",
            "inode",
            "checkpoint_sha256",
            "legacy_restored",
            "retired_image_digests",
            "account_retired",
            "original_account",
        ];
        if receipt.as_object().is_none_or(|object| {
            object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
        }) || receipt["format"] != "memcordon.owned-readiness-resources-retired"
            || receipt["revision"] != 1
            || receipt["identity"] != serde_json::to_value(identity)?
            || receipt["cell"] != serde_json::to_value(cell)?
            || receipt["admin_root"] != serde_json::to_value(admin_root)?
            || receipt["device"] != device
            || receipt["inode"] != inode
            || receipt["checkpoint_sha256"] != hex::encode(Sha256::digest(&bytes))
            || receipt["legacy_restored"] != true
            || receipt["account_retired"] != true
            || receipt["retired_image_digests"] != serde_json::to_value(&digests)?
        {
            return Err(CiError::Message(
                "already-retired resources lack exact durable successful settlement".into(),
            ));
        }
        for digest in digests {
            for name in [
                digest.clone(),
                format!(".retiring-{digest}"),
                format!(".retirement-{digest}.json"),
                format!(".retirement-staging-{digest}.json"),
            ] {
                require_protected_absence(
                    &Path::new("/var/lib/memcordon/runtime-images").join(name),
                )?;
            }
        }
        let original_account: Option<ExclusiveAccount> =
            serde_json::from_value(receipt["original_account"].clone())?;
        if checkpoint.account.is_some()
            && serde_json::to_value(&checkpoint.account)?
                != serde_json::to_value(&original_account)?
        {
            return Err(CiError::Message(
                "settled account differs from acquired checkpoint".into(),
            ));
        }
        if original_account.is_none() && output.join("exclusive-account-intent.json").exists() {
            return Err(CiError::Message(
                "images-only checkpoint cannot omit attempted account creation".into(),
            ));
        }
        if let Some(account) = &original_account {
            validate_account_creation_paths(output, account).map_err(CiError::Message)?;
            let intent = decode_owned_resource_json(&read_owned_resource(&account.intent, 4096)?)?;
            let passwd = read_owned_resource(&account.native_readback, 4096)?;
            let passwd = std::str::from_utf8(&passwd)
                .map_err(|_| CiError::Message("original native passwd readback not UTF-8".into()))?
                .trim_end_matches('\n')
                .split(':')
                .collect::<Vec<_>>();
            if account.intent != output.join("exclusive-account-intent.json")
                || intent["run_id"] != identity.run_id
                || intent["cell"] != serde_json::to_value(cell)?
                || intent["account_name"] != account.name
                || passwd.len() != 7
                || passwd[0] != account.name
                || passwd[2] != account.uid.to_string()
                || passwd[3] != account.gid.to_string()
                || passwd[6] != "/usr/sbin/nologin"
                || read_owned_resource(&account.group_readback, 4096)?
                    != format!("{}:x:{}:\n", account.name, account.gid).as_bytes()
            {
                return Err(CiError::Message(
                    "settled original account creation custody differs".into(),
                ));
            }
            observe_account_quiescence(account.uid, account.gid, deadline)?;
            for (database, key) in [
                ("passwd", account.name.clone()),
                ("passwd", account.uid.to_string()),
                ("group", account.name.clone()),
                ("group", account.gid.to_string()),
            ] {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(CiError::Message("resource absence deadline expired".into()));
                }
                let observed = CommandSpec::new(
                    "/usr/bin/getent",
                    workspace,
                    remaining.min(Duration::from_secs(30)),
                )
                .bounded_until(deadline)
                .args([database, key.as_str()])
                .output()?;
                if observed.status.code() != Some(2) || !observed.stdout.is_empty() {
                    return Err(CiError::Message(
                        "already-retired account/group identity is present or unresolved".into(),
                    ));
                }
            }
        }
        Ok(())
    }
    /// Handles cancellation before the first complete image checkpoint. Import
    /// intents precede the native command; absence of both intents therefore
    /// proves this dispatcher never attempted an installed image mutation.
    pub fn recover_partial_acquisition(
        output: &Path,
        identity: &SourceIdentity,
        cell: &ProductKey,
        admin_root: &Path,
    ) -> Result<Self> {
        let materialized = admin_root.join("materialized");
        let runtime_intent = materialized.join("runtime.import-intent.json");
        let input_intent = materialized.join("input.import-intent.json");
        let present = |path: &Path| -> Result<bool> {
            match std::fs::symlink_metadata(path) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error.into()),
            }
        };
        let runtime_attempted = present(&runtime_intent)?;
        let input_attempted = present(&input_intent)?;
        if !runtime_attempted && !input_attempted {
            if present(&output.join("exclusive-account-intent.json"))? {
                return Err(CiError::Message(
                    "account intent without prior image acquisition checkpoint remains unresolved"
                        .into(),
                ));
            }
            return Ok(Self::default());
        }
        let runtime_definition = materialized.join("runtime-image.json");
        let input_definition = materialized.join("input-image.json");
        let runtime: RuntimeImageDefinitionV1 =
            serde_json::from_value(decode_owned_resource_json(&read_owned_resource(
                &runtime_definition,
                16 * 1024 * 1024,
            )?)?)?;
        let input: RuntimeImageDefinitionV1 = serde_json::from_value(decode_owned_resource_json(
            &read_owned_resource(&input_definition, 16 * 1024 * 1024)?,
        )?)?;
        if runtime.target != cell.target || input.target != cell.target {
            return Err(CiError::Message(
                "partial imported image native target differs".into(),
            ));
        }
        let runtime_source = materialized.join("runtime-source");
        let input_source = materialized.join("input-source");
        for (attempted, intent, definition, source, image) in [
            (
                runtime_attempted,
                &runtime_intent,
                &runtime_definition,
                &runtime_source,
                &runtime,
            ),
            (
                input_attempted,
                &input_intent,
                &input_definition,
                &input_source,
                &input,
            ),
        ] {
            if !attempted {
                continue;
            }
            let actual =
                decode_owned_resource_json(&read_owned_resource(intent, 16 * 1024 * 1024)?)?;
            let expected = serde_json::json!({"format":"memcordon.owned-readiness-image-import-intent","revision":1,
                "run_id":identity.run_id,"source_commit":identity.source_commit,"cell":cell,"definition":definition,"source_root":source,
                "image":image.reference().map_err(CiError::Message)?});
            if actual != expected {
                return Err(CiError::Message(
                    "partial image import original source/definition association differs".into(),
                ));
            }
        }
        let fixture_sha256 = runtime
            .entries
            .as_slice()
            .iter()
            .find_map(|entry| match entry {
                ImageEntryV1::Regular {
                    path,
                    sha256,
                    executable: true,
                    ..
                } if path.as_str() == "bin/owned-readiness" => Some(String::from(sha256.clone())),
                _ => None,
            })
            .ok_or_else(|| {
                CiError::Message(
                    "partial runtime definition lacks exact measured fixture entry".into(),
                )
            })?;
        let mut import_receipts = Vec::new();
        for path in [
            materialized.join("runtime.import.json"),
            materialized.join("input.import.json"),
        ] {
            if present(&path)? {
                read_owned_resource(&path, 16 * 1024 * 1024)?;
                import_receipts.push(path);
            }
        }
        Ok(Self {
            images: Some(MixedImages {
                runtime,
                input,
                runtime_definition,
                input_definition,
                runtime_source,
                input_source,
                fixture_sha256,
                native_linker: PathBuf::from("/usr/bin/cc"),
                import_receipts,
            }),
            ..Self::default()
        })
    }
    /// Persists resource identity only; this document never proves native
    /// attempt retirement. Recovery must settle the provider journal first.
    #[expect(
        clippy::too_many_arguments,
        reason = "Checkpoint binds actual native resources to independent original lease and acquisition custody"
    )]
    pub fn persist_resource_checkpoint(
        &self,
        path: &Path,
        admin_root: &Path,
        device: u64,
        inode: u64,
        identity: &SourceIdentity,
        cell: &ProductKey,
        legacy: &memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry,
    ) -> Result<()> {
        let checkpoint = OwnedResourceCheckpoint {
            format: "memcordon.owned-readiness-resources".into(),
            revision: 1,
            identity: identity.clone(),
            cell: cell.clone(),
            admin_root: admin_root.to_path_buf(),
            device,
            inode,
            legacy: legacy.clone(),
            images: self.images.clone(),
            account: self.account.clone(),
        };
        let parent = path
            .parent()
            .ok_or_else(|| CiError::Message("resource checkpoint parent absent".into()))?;
        let pending = path.with_extension("resource-pending");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&pending)?;
        file.write_all(&serde_json::to_vec(&checkpoint)?)?;
        file.sync_all()?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &pending,
            rustix::fs::CWD,
            path,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let named = std::fs::symlink_metadata(path)?;
        let held = file.metadata()?;
        if named.file_type().is_symlink()
            || (named.dev(), named.ino(), named.nlink()) != (held.dev(), held.ino(), 1)
        {
            return Err(CiError::Message(
                "published resource checkpoint named/native identity differs".into(),
            ));
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    }
    /// Reconstructs exact resource intents after independently completed native
    /// recovery. It does not recreate a Child, PIDFD, or an execution result.
    pub fn recover_owned_resources(
        path: &Path,
        identity: &SourceIdentity,
        cell: &ProductKey,
        admin_root: &Path,
        device: u64,
        inode: u64,
        legacy: &memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry,
    ) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let before = file.metadata()?;
        if !before.is_file()
            || before.nlink() != 1
            || before.len() > 16 * 1024 * 1024
            || before.uid() != 0
            || before.mode() & 0o022 != 0
        {
            return Err(CiError::Message(
                "resource checkpoint custody/type differs".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.try_clone()?
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        let document = decode_owned_resource_json(&bytes)?;
        let mut checkpoint: OwnedResourceCheckpoint = serde_json::from_value(document)?;
        if checkpoint.format != "memcordon.owned-readiness-resources"
            || checkpoint.revision != 1
            || serde_json::to_value(&checkpoint.identity)? != serde_json::to_value(identity)?
            || checkpoint.cell != *cell
            || checkpoint.admin_root != admin_root
            || (checkpoint.device, checkpoint.inode) != (device, inode)
            || serde_json::to_value(&checkpoint.legacy)? != serde_json::to_value(legacy)?
        {
            return Err(CiError::Message(
                "resource checkpoint original cell/admin/policy association differs".into(),
            ));
        }
        let named = std::fs::symlink_metadata(path)?;
        let after = file.metadata()?;
        if (named.dev(), named.ino(), named.len()) != (before.dev(), before.ino(), before.len())
            || named.file_type().is_symlink()
            || (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
            ) != (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
            )
        {
            return Err(CiError::Message(
                "resource checkpoint changed during readback".into(),
            ));
        }
        if let Some(images) = &checkpoint.images {
            for (definition, expected) in [
                (&images.runtime_definition, &images.runtime),
                (&images.input_definition, &images.input),
            ] {
                if !definition.starts_with(admin_root) {
                    return Err(CiError::Message(
                        "recovered image definition escapes owned admin source".into(),
                    ));
                }
                let held = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(definition)?;
                let metadata = held.metadata()?;
                if !metadata.is_file()
                    || metadata.nlink() != 1
                    || metadata.uid() != 0
                    || metadata.mode() & 0o022 != 0
                    || metadata.len() > 16 * 1024 * 1024
                {
                    return Err(CiError::Message(
                        "recovered image definition custody differs".into(),
                    ));
                }
                let mut actual = Vec::new();
                held.take(16 * 1024 * 1024 + 1).read_to_end(&mut actual)?;
                let decoded: RuntimeImageDefinitionV1 =
                    serde_json::from_value(decode_owned_resource_json(&actual)?)?;
                if serde_json::to_value(decoded)? != serde_json::to_value(expected)? {
                    return Err(CiError::Message(
                        "recovered image definition bytes differ".into(),
                    ));
                }
            }
        }
        if checkpoint.account.is_none() {
            let directory = path
                .parent()
                .ok_or_else(|| CiError::Message("resource checkpoint directory absent".into()))?;
            let intent_path = directory.join("exclusive-account-intent.json");
            match std::fs::symlink_metadata(&intent_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    let intent =
                        decode_owned_resource_json(&read_owned_resource(&intent_path, 4096)?)?;
                    if intent["format"] != "memcordon.owned-readiness-account-intent"
                        || intent["revision"] != 1
                        || intent["run_id"] != identity.run_id
                        || intent["cell"] != serde_json::to_value(cell)?
                        || intent["native_absence_verified"] != true
                        || intent["creation_attempted"] != true
                    {
                        return Err(CiError::Message(
                            "partial account intent differs from original source/cell".into(),
                        ));
                    }
                    let name = intent["account_name"]
                        .as_str()
                        .ok_or_else(|| CiError::Message("partial account name absent".into()))?
                        .to_owned();
                    let nonce = Sha256::digest(serde_json::to_vec(&(identity, cell))?);
                    let number = u64::from_le_bytes(nonce[..8].try_into().map_err(|_| {
                        CiError::Message("account discriminator width differs".into())
                    })?);
                    if name != format!("mc-ready-{number:x}") {
                        return Err(CiError::Message(
                            "partial account intent name differs from owned cell discriminator"
                                .into(),
                        ));
                    }
                    let native_readback = directory.join("exclusive-account-getent.bin");
                    let group_readback = directory.join("exclusive-group-getent.bin");
                    let passwd = read_owned_resource(&native_readback, 4096)?;
                    let text = std::str::from_utf8(&passwd)
                        .map_err(|error| CiError::Message(error.to_string()))?;
                    let rows = text.lines().collect::<Vec<_>>();
                    if rows.len() != 1 {
                        return Err(CiError::Message(
                            "partial account lacks exact creation readback".into(),
                        ));
                    }
                    let fields = rows[0].split(':').collect::<Vec<_>>();
                    if fields.len() != 7 || fields[0] != name || fields[6] != "/usr/sbin/nologin" {
                        return Err(CiError::Message(
                            "partial account native creation identity differs".into(),
                        ));
                    }
                    let uid = fields[2]
                        .parse::<u32>()
                        .map_err(|error| CiError::Message(error.to_string()))?;
                    let gid = fields[3]
                        .parse::<u32>()
                        .map_err(|error| CiError::Message(error.to_string()))?;
                    if [0, 65533, 65534].contains(&uid)
                        || [0, 65533, 65534].contains(&gid)
                        || read_owned_resource(&group_readback, 4096)?
                            != format!("{name}:x:{gid}:\n").as_bytes()
                    {
                        return Err(CiError::Message(
                            "partial account/group creation custody is incomplete; intent retained"
                                .into(),
                        ));
                    }
                    checkpoint.account = Some(ExclusiveAccount {
                        name,
                        uid,
                        gid,
                        intent: intent_path,
                        native_readback,
                        group_readback,
                    });
                }
            }
        }
        Ok(Self {
            images: checkpoint.images,
            account: checkpoint.account,
            ..Self::default()
        })
    }
    pub fn retire_admin_sources(
        &mut self,
        path: &Path,
        device: u64,
        inode: u64,
        deadline: std::time::Instant,
    ) -> Result<serde_json::Value> {
        use std::os::fd::AsFd;
        if !self.active.is_empty() || self.images.is_some() || self.account.is_some() {
            return Err(CiError::Message(
                "native/images/account must settle before owned admin sources".into(),
            ));
        }
        if self.admin_retirement.is_none() {
            self.admin_retirement = Some(AdminSourceRetirement::acquire(path, device, inode)?);
        }
        let owner = self
            .admin_retirement
            .as_mut()
            .expect("retained admin source owner");
        if owner.path != path || (owner.device, owner.inode) != (device, inode) {
            return Err(CiError::Message(
                "admin retirement retry changes original native owner".into(),
            ));
        }
        let mut entries = 0usize;
        if !owner.unlinked {
            retire_admin_children(&owner.root, device, deadline, 0, &mut entries)?;
            require_admin_named_inode(&owner.parent, &owner.name, &owner.root)?;
            rustix::fs::unlinkat(
                owner.parent.as_fd(),
                &owner.name,
                rustix::fs::AtFlags::REMOVEDIR,
            )
            .map_err(|e| CiError::Message(e.to_string()))?;
            owner.unlinked = true;
        }
        if owner.root.metadata()?.nlink() != 0 {
            return Err(CiError::Message(
                "retired admin root remains linked; owner retained".into(),
            ));
        }
        match rustix::fs::statat(
            owner.parent.as_fd(),
            &owner.name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => {
                return Err(CiError::Message(
                    "admin root pathname remains present after owned unlink".into(),
                ));
            }
        }
        owner.parent.sync_all()?;
        Ok(
            serde_json::json!({"format":"memcordon.owned-readiness-admin-retirement","revision":1,
            "path":path,"device":device,"inode":inode,"native_root_links":0,"named_absent":true,"parent_synced":true,"visited_entries":entries}),
        )
    }
    /// Settles definitions and the fresh account only after this owner has
    /// settled every retained native attempt. Retry state remains borrowed.
    pub fn finalize_owned_resources(
        &mut self,
        workspace: &Path,
        output: &Path,
        legacy: &memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry,
        deadline: std::time::Instant,
    ) -> Result<()> {
        if !self.active.is_empty()
            || self
                .cross_attempt_reports
                .iter()
                .any(|report| !report.native_owners_settled())
            || self
                .isolation_import_reports
                .iter()
                .any(|report| !report.native_owners_settled())
            || self
                .isolation_account_reports
                .iter()
                .any(|report| !report.native_owners_settled())
            || self
                .lifecycle_reports
                .iter()
                .any(|report| !report.native_owners_settled())
            || self
                .limits_reports
                .iter()
                .any(|report| !report.native_owners_settled())
            || (!self.policy_reports.is_empty() && !self.policy_attempts_settled)
            || (!self.image_reports.is_empty() && !self.image_attempts_settled)
        {
            return Err(CiError::Message(
                "owned mixed native attempts remain unresolved; resources retained".into(),
            ));
        }
        let original_account = if self.account.is_some() {
            self.account.clone()
        } else if self.retired_account.is_some() {
            self.retired_account.clone()
        } else if output.join("owned-resources-retired.json").is_file() {
            serde_json::from_value(
                decode_owned_resource_json(&read_owned_resource(
                    &output.join("owned-resources-retired.json"),
                    32 * 1024 * 1024,
                )?)?["original_account"]
                    .clone(),
            )?
        } else {
            None
        };
        let checkpoint = if output.join("owned-resources-acquired.json").is_file() {
            Some(output.join("owned-resources-acquired.json"))
        } else if output.join("owned-resources-images.json").is_file() {
            Some(output.join("owned-resources-images.json"))
        } else {
            None
        };
        let checkpoint_bytes = checkpoint
            .as_ref()
            .map(|path| read_owned_resource(path, 32 * 1024 * 1024))
            .transpose()?;
        if self.account.is_none()
            && !self.account_retired
            && output.join("exclusive-account-intent.json").exists()
        {
            return Err(CiError::Message("partial native account creation intent lacks completed identity custody; explicit recovery remains required".into()));
        }
        if let Some(account) = &self.account {
            observe_account_quiescence(account.uid, account.gid, deadline)?;
        }
        let timeout = || -> Result<Duration> {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                Err(CiError::Message(
                    "owned resource retirement deadline expired; intents retained".into(),
                ))
            } else {
                Ok(remaining.min(Duration::from_secs(120)))
            }
        };
        let retain_attempt = |label: &str, bytes: &[u8]| -> Result<()> {
            for ordinal in 0..128 {
                let path = output.join(format!("resource-retirement-{label}-{ordinal}.json"));
                match OpenOptions::new().write(true).create_new(true).open(path) {
                    Ok(mut file) => {
                        file.write_all(bytes)?;
                        file.write_all(b"\n")?;
                        file.sync_all()?;
                        File::open(output)?.sync_all()?;
                        return Ok(());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err(CiError::Message(
                "resource retirement retry receipts exceed finite bound".into(),
            ))
        };
        if !self.legacy_restored {
            let path = output.join("original-legacy-restore.policy.json");
            let bytes = serde_json::to_vec(legacy)?;
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    retain(&path, &bytes)?
                }
                Err(error) => return Err(error.into()),
                Ok(metadata) => {
                    if !metadata.is_file()
                        || metadata.file_type().is_symlink()
                        || metadata.nlink() != 1
                        || std::fs::read(&path)? != bytes
                    {
                        return Err(CiError::Message(
                            "original registry restoration intent differs".into(),
                        ));
                    }
                }
            }
            let reply =
                CommandSpec::new("/usr/libexec/memcordon-sealed-agent", workspace, timeout()?)
                    .bounded_until(deadline)
                    .args(["package", "policy", "apply", "--file"])
                    .arg(&path)
                    .output()?;
            retain_attempt(
                "policy",
                &serde_json::to_vec(
                    &serde_json::json!({"stdout":reply.stdout,"stderr":reply.stderr,"status":reply.status.code()}),
                )?,
            )?;
            if !reply.status.success() {
                return Err(CiError::Message(
                    "exact original registry restoration failed; resources retained".into(),
                ));
            }
            self.legacy_restored = true;
        }
        for report in &mut self.image_reports {
            super::linux_readiness_image_cases::finalize_retained_images(report, deadline)?;
        }
        for (image, path) in &self.recovered_case_images {
            let reference = image.reference().map_err(CiError::Message)?;
            let discriminator = String::from(reference.digest.clone());
            if self.retired_images.contains(&discriminator) {
                continue;
            }
            let reply =
                CommandSpec::new("/usr/libexec/memcordon-sealed-agent", workspace, timeout()?)
                    .bounded_until(deadline)
                    .args(["package", "policy", "image", "retire", "--definition"])
                    .arg(path)
                    .arg("--json")
                    .output()?;
            retain_attempt(
                "case-image",
                &serde_json::to_vec(
                    &serde_json::json!({"stdout":reply.stdout,"stderr":reply.stderr,"status":reply.status.code()}),
                )?,
            )?;
            let value = decode_owned_resource_json(&reply.stdout)?;
            if !reply.status.success()
                || value["format"] != "memcordon.runtime-image-retirement"
                || value["revision"] != 1
                || value["storage_absent"] != true
                || value["reference"] != serde_json::to_value(&reference)?
            {
                return Err(CiError::Message(
                    "recovered image case native retirement differs; exact intent retained".into(),
                ));
            }
            self.retired_images.insert(discriminator);
        }
        if let Some(images) = &self.images {
            for (definition, path) in [
                (&images.runtime, &images.runtime_definition),
                (&images.input, &images.input_definition),
            ] {
                let reference = definition.reference().map_err(CiError::Message)?;
                let discriminator = String::from(reference.digest.clone());
                if self.retired_images.contains(&discriminator) {
                    continue;
                }
                let reply =
                    CommandSpec::new("/usr/libexec/memcordon-sealed-agent", workspace, timeout()?)
                        .bounded_until(deadline)
                        .args(["package", "policy", "image", "retire", "--definition"])
                        .arg(path)
                        .arg("--json")
                        .output()?;
                retain_attempt(
                    "image",
                    &serde_json::to_vec(
                        &serde_json::json!({"stdout":reply.stdout,"stderr":reply.stderr,"status":reply.status.code()}),
                    )?,
                )?;
                if !reply.status.success() {
                    return Err(CiError::Message(
                        "native image retirement failed; exact definition retained".into(),
                    ));
                }
                let value = decode_owned_resource_json(&reply.stdout)?;
                if value["format"] != "memcordon.runtime-image-retirement"
                    || value["revision"] != 1
                    || value["storage_absent"] != true
                    || value["reference"] != serde_json::to_value(&reference)?
                {
                    return Err(CiError::Message(
                        "native image retirement receipt differs from retained reference".into(),
                    ));
                }
                self.retired_images.insert(discriminator);
            }
        }
        if let Some(account) = &self.account {
            let observed = CommandSpec::new("/usr/bin/getent", workspace, timeout()?)
                .bounded_until(deadline)
                .args(["passwd", &account.name])
                .output()?;
            if observed.status.code() == Some(2) && observed.stdout.is_empty() {
                // An absent account is retry convergence, only after original
                // native creation/readback custody remains available below.
                if !account.intent.is_file() || !account.native_readback.is_file() {
                    return Err(CiError::Message(
                        "absent account lacks original creation custody".into(),
                    ));
                }
            } else {
                if !observed.status.success()
                    || observed.stdout != std::fs::read(&account.native_readback)?
                {
                    return Err(CiError::Message(
                        "current account differs from exact owned creation readback".into(),
                    ));
                }
                for process in std::fs::read_dir("/proc")? {
                    let process = process?;
                    if !process
                        .file_name()
                        .as_encoded_bytes()
                        .iter()
                        .all(u8::is_ascii_digit)
                    {
                        continue;
                    }
                    let tasks = match std::fs::read_dir(process.path().join("task")) {
                        Ok(tasks) => tasks,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error.into()),
                    };
                    for task in tasks {
                        let status = match std::fs::read_to_string(task?.path().join("status")) {
                            Ok(status) => status,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(error) => return Err(error.into()),
                        };
                        for (prefix, owned) in [("Uid:", account.uid), ("Gid:", account.gid)] {
                            let line = status
                                .lines()
                                .find(|line| line.starts_with(prefix))
                                .ok_or_else(|| {
                                    CiError::Message("native task credential row absent".into())
                                })?;
                            let values = line[prefix.len()..]
                                .split_whitespace()
                                .map(str::parse::<u32>)
                                .collect::<std::result::Result<Vec<_>, _>>()
                                .map_err(|e| CiError::Message(e.to_string()))?;
                            if values.len() != 4 || values.contains(&owned) {
                                return Err(CiError::Message("owned account native task credentials remain live or unresolved".into()));
                            }
                        }
                    }
                }
                let deleted = CommandSpec::new("/usr/sbin/userdel", workspace, timeout()?)
                    .bounded_until(deadline)
                    .arg("--")
                    .arg(&account.name)
                    .output()?;
                retain_attempt(
                    "account",
                    &serde_json::to_vec(
                        &serde_json::json!({"stdout":deleted.stdout,"stderr":deleted.stderr,"status":deleted.status.code(),"name":account.name,"uid":account.uid,"gid":account.gid}),
                    )?,
                )?;
                if !deleted.status.success() {
                    return Err(CiError::Message(
                        "owned account deletion failed; original identity retained".into(),
                    ));
                }
                let absent = CommandSpec::new("/usr/bin/getent", workspace, timeout()?)
                    .bounded_until(deadline)
                    .args(["passwd", &account.name])
                    .output()?;
                if absent.status.code() != Some(2) || !absent.stdout.is_empty() {
                    return Err(CiError::Message(
                        "owned account remains present after deletion".into(),
                    ));
                }
            }
            let group = CommandSpec::new("/usr/bin/getent", workspace, timeout()?)
                .bounded_until(deadline)
                .args(["group", &account.name])
                .output()?;
            if group.status.code() != Some(2) || !group.stdout.is_empty() {
                if !group.status.success()
                    || group.stdout != std::fs::read(&account.group_readback)?
                {
                    return Err(CiError::Message(
                        "remaining native group differs from owned creation readback".into(),
                    ));
                }
                observe_account_quiescence(account.uid, account.gid, deadline)?;
                let removed = CommandSpec::new("/usr/sbin/groupdel", workspace, timeout()?)
                    .bounded_until(deadline)
                    .arg("--")
                    .arg(&account.name)
                    .output()?;
                retain_attempt(
                    "group",
                    &serde_json::to_vec(
                        &serde_json::json!({"stdout":removed.stdout,"stderr":removed.stderr,"status":removed.status.code(),"name":account.name,"gid":account.gid}),
                    )?,
                )?;
                if !removed.status.success() {
                    return Err(CiError::Message(
                        "owned group retirement failed; account/group identity retained".into(),
                    ));
                }
                let absent = CommandSpec::new("/usr/bin/getent", workspace, timeout()?)
                    .bounded_until(deadline)
                    .args(["group", &account.name])
                    .output()?;
                if absent.status.code() != Some(2) || !absent.stdout.is_empty() {
                    return Err(CiError::Message(
                        "owned group remains present after retirement".into(),
                    ));
                }
            }
            self.retired_account = self.account.clone();
            self.account = None;
            self.account_retired = true;
        }
        self.images = None;
        if let Some(bytes) = checkpoint_bytes {
            let checkpoint: OwnedResourceCheckpoint =
                serde_json::from_value(decode_owned_resource_json(&bytes)?)?;
            let receipt = serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.owned-readiness-resources-retired","revision":1,
                "identity":checkpoint.identity,"cell":checkpoint.cell,"admin_root":checkpoint.admin_root,"device":checkpoint.device,"inode":checkpoint.inode,
                "checkpoint_sha256":hex::encode(Sha256::digest(&bytes)),"legacy_restored":self.legacy_restored,
                "retired_image_digests":self.retired_images,"account_retired":original_account.is_none()||self.account_retired,"original_account":original_account}),
            )?;
            let path = output.join("owned-resources-retired.json");
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    retain(&path, &receipt)?
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    if read_owned_resource(&path, 32 * 1024 * 1024)? != receipt {
                        return Err(CiError::Message(
                            "resource retirement retry receipt changed original custody".into(),
                        ));
                    }
                }
            }
            File::open(output)?.sync_all()?;
        }
        Ok(())
    }
    /// Transfers only persisted rows belonging to this controller's actual
    /// completed collections. Missing normalized evidence stays non-passed;
    /// the outer ledger retains every untouched required row.
    pub fn collect_case_records(
        &self,
        identity: &SourceIdentity,
        cell: &ProductKey,
        artifact_root: &Path,
        installed_output: &Path,
    ) -> Result<(
        Vec<memcordon_readiness_verifier::CaseRecord>,
        Vec<memcordon_readiness_verifier::Artifact>,
    )> {
        use memcordon_readiness_verifier::{Artifact, CaseEvidence, CaseRecord, CaseState};
        let mut records = Vec::new();
        let mut artifacts = BTreeMap::<String, Artifact>::new();
        let mut keys = BTreeSet::new();
        let (legacy_records, legacy_artifacts) = super::linux_readiness_legacy_cases::normalize(
            installed_output,
            identity,
            cell,
            artifact_root,
        )?;
        for record in legacy_records {
            if !keys.insert(record.key.clone()) {
                return Err(CiError::Message("duplicate frozen legacy key".into()));
            }
            records.push(record);
        }
        for artifact in legacy_artifacts {
            artifacts.insert(artifact.path.clone(), artifact);
        }
        if self.isolation_account_contexts.len() != self.isolation_account_reports.len() {
            return Err(CiError::Message(
                "retained account report lost original case context".into(),
            ));
        }
        for (context, report) in self
            .isolation_account_contexts
            .iter()
            .zip(&self.isolation_account_reports)
        {
            if context.key.target != cell.target
                || context.key.channel.as_ref() != Some(&cell.channel)
                || !keys.insert(context.key.clone())
            {
                return Err(CiError::Message(
                    "retained account probe crosses original source cell or duplicates a row"
                        .into(),
                ));
            }
            let normalized = report.normalize(
                identity,
                &context.key,
                artifact_root,
                &context.owner,
                &context.baseline_contract,
                &context.original_lease,
                &context.acquisition,
                &mut artifacts,
            );
            match normalized {
                Ok(path) => records.push(CaseRecord {
                    key: context.key.clone(),
                    run_id: identity.run_id.clone(),
                    state: CaseState::Passed,
                    reason: None,
                    evidence: Some(path),
                }),
                Err(error) => records.push(CaseRecord {
                    key: context.key.clone(),
                    run_id: identity.run_id.clone(),
                    state: CaseState::Failed,
                    reason: Some(error.to_string()),
                    evidence: None,
                }),
            }
        }
        if self.isolation_import_contexts.len() != self.isolation_import_reports.len() {
            return Err(CiError::Message(
                "retained importer report lost original case context".into(),
            ));
        }
        for (context, report) in self
            .isolation_import_contexts
            .iter()
            .zip(&self.isolation_import_reports)
        {
            if context.key.target != cell.target
                || context.key.channel.as_ref() != Some(&cell.channel)
                || !keys.insert(context.key.clone())
            {
                return Err(CiError::Message(
                    "retained isolation importer crosses original source cell or duplicates a row"
                        .into(),
                ));
            }
            match report.normalize(
                identity,
                &context.key,
                artifact_root,
                &context.owner,
                &context.baseline_contract,
                &context.original_lease,
                &context.acquisition,
                &mut artifacts,
            ) {
                Ok(path) => records.push(CaseRecord {
                    key: context.key.clone(),
                    run_id: identity.run_id.clone(),
                    state: CaseState::Passed,
                    reason: None,
                    evidence: Some(path),
                }),
                Err(error) => records.push(CaseRecord {
                    key: context.key.clone(),
                    run_id: identity.run_id.clone(),
                    state: CaseState::Failed,
                    reason: Some(error.to_string()),
                    evidence: None,
                }),
            }
        }
        for report in &self.lifecycle_reports {
            for record in &report.records {
                if record.run_id != identity.run_id
                    || record.key.target != cell.target
                    || record.key.channel.as_ref() != Some(&cell.channel)
                    || !keys.insert(record.key.clone())
                {
                    return Err(CiError::Message(
                        "lifecycle normalized record crosses source/cell or duplicates a row"
                            .into(),
                    ));
                }
                records.push(record.clone());
            }
            for artifact in &report.artifacts {
                if artifacts
                    .insert(artifact.path.clone(), artifact.clone())
                    .is_some_and(|previous| {
                        previous.sha256 != artifact.sha256 || previous.length != artifact.length
                    })
                {
                    return Err(CiError::Message(
                        "lifecycle artifact path carries conflicting original bytes".into(),
                    ));
                }
            }
        }
        for (key, collection) in &self.completed {
            if key.target != cell.target
                || key.channel.as_ref() != Some(&cell.channel)
                || collection.persisted.key != *key
                || serde_json::to_value(&collection.persisted.identity)?
                    != serde_json::to_value(identity)?
                || !keys.insert(key.clone())
            {
                return Err(CiError::Message(
                    "completed mixed collection crosses selected source/cell or duplicates a row"
                        .into(),
                ));
            }
            for artifact in &collection.persisted.artifacts {
                if artifacts
                    .insert(artifact.path.clone(), artifact.clone())
                    .is_some_and(|previous| {
                        previous.sha256 != artifact.sha256 || previous.length != artifact.length
                    })
                {
                    return Err(CiError::Message(
                        "completed mixed artifact path has conflicting bytes".into(),
                    ));
                }
            }
            let parent = Path::new(&collection.prepared_native_receipt.path)
                .parent()
                .ok_or_else(|| CiError::Message("completed collection prefix absent".into()))?;
            let relative = parent.join("case-evidence.json");
            let path = artifact_root.join(&relative);
            let (state, reason, evidence) = match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
                    CaseState::NotRun,
                    Some("persisted normalized native/semantic case evidence is absent".into()),
                    None,
                ),
                Err(error) => return Err(error.into()),
                Ok(metadata) => {
                    if !metadata.is_file()
                        || metadata.file_type().is_symlink()
                        || metadata.nlink() != 1
                        || metadata.len() > 16 * 1024 * 1024
                    {
                        return Err(CiError::Message(
                            "normalized mixed case evidence custody/type exceeds bound".into(),
                        ));
                    }
                    let bytes = std::fs::read(&path)?;
                    let raw = decode_owned_resource_json(&bytes)?;
                    let decoded: CaseEvidence = serde_json::from_value(raw)?;
                    if decoded.key != *key
                        || decoded.run_id != identity.run_id
                        || decoded.source_commit != identity.source_commit
                        || decoded.source_tree_sha256 != identity.source_tree_sha256
                    {
                        return Err(CiError::Message(
                            "persisted case evidence differs from native collection source/key"
                                .into(),
                        ));
                    }
                    let relative = relative
                        .to_str()
                        .ok_or_else(|| {
                            CiError::Message("normalized evidence path not UTF-8".into())
                        })?
                        .to_owned();
                    artifacts.insert(
                        relative.clone(),
                        Artifact {
                            path: relative.clone(),
                            length: bytes.len() as u64,
                            sha256: hex::encode(Sha256::digest(&bytes)),
                        },
                    );
                    (CaseState::Passed, None, Some(relative))
                }
            };
            records.push(CaseRecord {
                key: key.clone(),
                run_id: identity.run_id.clone(),
                state,
                reason,
                evidence,
            });
        }
        for report in &self.policy_reports {
            let owner = decode_owned_resource_json(&read_owned_resource(
                &report.output_root.join("owner.json"),
                16 * 1024 * 1024,
            )?)?;
            if owner["run_id"] != identity.run_id
                || owner["source_commit"] != identity.source_commit
                || owner["source_tree_sha256"] != identity.source_tree_sha256
                || owner["cell"] != serde_json::to_value(cell)?
            {
                return Err(CiError::Message(
                    "retained policy report differs from original source/cell".into(),
                ));
            }
            for observation in &report.observations {
                if observation.scenario == "v3-preserve-caller" {
                    let key = memcordon_readiness_verifier::CaseKey {
                        target: cell.target.clone(),
                        channel: Some(cell.channel.clone()),
                        evidence_class:
                            memcordon_readiness_verifier::EvidenceClass::InstalledProduct,
                        family: "L-ID-01".into(),
                        scenario: observation.scenario.clone(),
                    };
                    if !keys.insert(key.clone()) {
                        return Err(CiError::Message(
                            "retained malformed ingress duplicates a finite row".into(),
                        ));
                    }
                    match normalize_malformed_ingress(
                        report,
                        observation,
                        identity,
                        &key,
                        artifact_root,
                        &mut artifacts,
                    ) {
                        Ok(path) => records.push(CaseRecord {
                            key,
                            run_id: identity.run_id.clone(),
                            state: CaseState::Passed,
                            reason: None,
                            evidence: Some(path),
                        }),
                        Err(error) => records.push(CaseRecord {
                            key,
                            run_id: identity.run_id.clone(),
                            state: CaseState::Failed,
                            reason: Some(error.to_string()),
                            evidence: None,
                        }),
                    }
                    continue;
                }
                if !matches!(
                    observation.scenario.as_str(),
                    "wrong-caller"
                        | "wrong-plan"
                        | "wrong-image"
                        | "wrong-profile"
                        | "wrong-identity"
                        | "wrong-digest"
                        | "wrong-epoch"
                        | "disabled-grant"
                        | "changed-grant"
                        | "revoke-discovery"
                        | "revoke-preparation"
                        | "revoke-release"
                ) {
                    continue;
                }
                let key = memcordon_readiness_verifier::CaseKey {
                    target: cell.target.clone(),
                    channel: Some(cell.channel.clone()),
                    evidence_class: memcordon_readiness_verifier::EvidenceClass::InstalledProduct,
                    family: if observation.scenario.starts_with("revoke-") {
                        "L-ID-03"
                    } else {
                        "L-ID-02"
                    }
                    .into(),
                    scenario: observation.scenario.clone(),
                };
                if !keys.insert(key.clone()) {
                    return Err(CiError::Message(
                        "retained policy observation duplicates a finite row".into(),
                    ));
                }
                let normalized = normalize_policy_refusal(
                    report,
                    observation,
                    &owner,
                    identity,
                    &key,
                    artifact_root,
                    &mut artifacts,
                );
                match normalized {
                    Ok(path) => records.push(CaseRecord {
                        key,
                        run_id: identity.run_id.clone(),
                        state: CaseState::Passed,
                        reason: None,
                        evidence: Some(path),
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
        }
        for report in &self.image_reports {
            for record in super::linux_image_normalize::collect_import_records(
                report,
                identity,
                cell,
                artifact_root,
                &mut artifacts,
            )? {
                if !keys.insert(record.key.clone()) {
                    return Err(CiError::Message(
                        "retained image observation duplicates a finite row".into(),
                    ));
                }
                records.push(record);
            }
            for record in super::linux_image_normalize::collect_export_records(
                report,
                identity,
                cell,
                artifact_root,
                &mut artifacts,
            )? {
                if !keys.insert(record.key.clone()) {
                    return Err(CiError::Message(
                        "retained export observation duplicates a finite row".into(),
                    ));
                }
                records.push(record);
            }
        }
        for (key, error) in &self.failures {
            if key.target != cell.target || key.channel.as_ref() != Some(&cell.channel) {
                return Err(CiError::Message(
                    "native failure belongs to another cell".into(),
                ));
            }
            if let Some(record) = records.iter_mut().find(|record| record.key == *key) {
                record.state = CaseState::Failed;
                record.reason = Some(error.clone());
            } else {
                records.push(CaseRecord {
                    key: key.clone(),
                    run_id: identity.run_id.clone(),
                    state: CaseState::Failed,
                    reason: Some(error.clone()),
                    evidence: None,
                });
            }
        }
        Ok((records, artifacts.into_values().collect()))
    }
    /// Finalization owns only actual retained frontend Children and native
    /// observation handles. Missing observer custody remains an explicit outer
    /// recovery obligation; no filename/PID claim creates a new cleanup owner.
    pub fn finalize_owned_attempts(&mut self, deadline: std::time::Instant) -> Result<()> {
        let mut failures = Vec::new();
        for (ordinal, report) in self.lifecycle_reports.iter_mut().enumerate() {
            if let Err(error) =
                super::linux_readiness_lifecycle_cases::finalize_report(report, deadline)
            {
                failures.push(format!("retained lifecycle report {ordinal}: {error}"));
            }
        }
        for (ordinal, report) in self.limits_reports.iter_mut().enumerate() {
            if let Err(error) =
                super::linux_readiness_limits_cases::finalize_report(report, deadline)
            {
                failures.push(format!("limits group {ordinal}: {error}"));
            }
        }
        self.image_attempts_settled = false;
        for (ordinal, report) in self.image_reports.iter_mut().enumerate() {
            if let Err(error) =
                super::linux_readiness_image_cases::finalize_attempts(report, deadline)
            {
                failures.push(format!("image group {ordinal}: {error}"));
            }
        }
        self.image_attempts_settled = failures.is_empty();
        self.policy_attempts_settled = false;
        for (ordinal, report) in self.policy_reports.iter_mut().enumerate() {
            if let Err(error) =
                super::linux_readiness_policy_cases::finalize_report(report, deadline)
            {
                failures.push(format!("policy group {ordinal}: {error}"));
            }
        }
        self.policy_attempts_settled = failures.is_empty();
        for (ordinal, report) in self.isolation_account_reports.iter_mut().enumerate() {
            if let Err(error) = report.finalize(deadline) {
                failures.push(format!("isolation account group {ordinal}: {error}"));
            }
        }
        for (ordinal, report) in self.isolation_import_reports.iter_mut().enumerate() {
            if let Err(error) = report.finalize(deadline) {
                failures.push(format!("isolation import group {ordinal}: {error}"));
            }
        }
        for (ordinal, report) in self.cross_attempt_reports.iter_mut().enumerate() {
            if let Err(error) = report.finalize() {
                failures.push(format!("original cross-attempt group {ordinal}: {error}"));
            }
        }
        let mut index = 0;
        while index < self.active.len() {
            let owned = &mut self.active[index];
            #[expect(
                clippy::redundant_closure_call,
                reason = "Fallible cleanup is captured per owned attempt so later owners are still finalized"
            )]
            let settled = (|| -> Result<()> {
                let mut errors = Vec::new();
                match owned.launch.frontend.try_wait() {
                    Ok(None) if std::time::Instant::now() < deadline => {
                        if let Err(error) = owned.launch.frontend.kill() {
                            errors.push(format!("owned frontend signal: {error}"));
                        }
                    }
                    Ok(None) => {
                        errors.push("owned frontend remains after original cleanup cutoff".into())
                    }
                    Ok(Some(_)) => {}
                    Err(error) => errors.push(format!("owned frontend observation: {error}")),
                }
                // Closing the owned input is a real frontend-loss signal; it
                // cannot fabricate provider retirement or consume a journal.
                owned.launch.frontend.stdin.take();
                if let Err(error) = owned
                    .launch
                    .wait_and_capture(deadline.saturating_duration_since(std::time::Instant::now()))
                {
                    errors.push(format!("owned frontend capture/reap: {error}"));
                }
                if let Some(observer) = owned.observer.as_ref() {
                    loop {
                        match observer.native_family_retired(&owned.held) {
                            Ok(true) => break,
                            Err(error) => {
                                errors.push(format!("owned native family observation: {error}"));
                                break;
                            }
                            Ok(false) if std::time::Instant::now() >= deadline => {
                                errors.push("mixed native family/cgroup retirement remains uncertain; exact owners retained".into());
                                break;
                            }
                            Ok(false) => std::thread::sleep(Duration::from_millis(10)),
                        }
                    }
                } else {
                    errors.push("mixed cleanup lacks preauthorization native observer; explicit native journal recovery required".into());
                }
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(CiError::Message(errors.join("; ")))
                }
            })();
            match settled {
                Ok(()) => {
                    self.active.remove(index);
                }
                Err(error) => {
                    failures.push(format!("{:?}: {error}", owned.key));
                    index += 1;
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(CiError::Message(failures.join("; ")))
        }
    }

    fn acquire_owned_resources(&mut self, input: &InstalledMixedDriverInput<'_>) -> Result<()> {
        if self.images.is_some()
            || self.account.is_some()
            || !self.active.is_empty()
            || !self.completed.is_empty()
            || !input.output.is_absolute()
            || !input.admin_root.is_absolute()
            || std::time::Instant::now() >= input.deadline
            || input.deadline >= input.cleanup_deadline
        {
            return Err(CiError::Message(
                "native fixture preparation owner/path/original deadline invalid".into(),
            ));
        }
        std::fs::create_dir(input.output)?;
        let mut ancestor = Some(input.admin_root);
        while let Some(path) = ancestor {
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(CiError::Message(
                    "owned admin image staging ancestry lacks protected root custody".into(),
                ));
            }
            ancestor = path.parent();
        }
        self.images = Some(materialize_until(
            input.payload,
            input.workspace,
            &input.admin_root.join("materialized"),
            &input.identity,
            &input.cell,
            input.deadline,
        )?);
        let admin_metadata = std::fs::symlink_metadata(input.admin_root)?;
        self.persist_resource_checkpoint(
            &input.output.join("owned-resources-images.json"),
            input.admin_root,
            admin_metadata.dev(),
            admin_metadata.ino(),
            &input.identity,
            &input.cell,
            &input.legacy,
        )?;
        self.account = Some(provision_exclusive_account_until(
            &input.identity,
            &input.cell,
            input.output,
            input.deadline,
        )?);
        self.persist_resource_checkpoint(
            &input.output.join("owned-resources-acquired.json"),
            input.admin_root,
            admin_metadata.dev(),
            admin_metadata.ino(),
            &input.identity,
            &input.cell,
            &input.legacy,
        )?;
        Ok(())
    }

    /// The caller owns the selected installed package lifetime. Preparation
    /// imports only measured owned images and retains every acquired resource
    /// here; it runs no installed case and makes no native release claim.
    pub fn prepare_native_component_fixture(
        &mut self,
        input: InstalledMixedDriverInput<'_>,
    ) -> Result<ActivatedMixedPolicy> {
        self.acquire_owned_resources(&input)?;
        let directory = input.output.join("native-component-policy");
        std::fs::create_dir(&directory)?;
        let requirement=memcordon_core::workload_contract_v3::RequirementV3::TcpListener {
            id:id("tcp")?,local_port:memcordon_core::workload_contract_v3::LocalPortV3::KernelAssigned,
            peer:memcordon_core::workload_contract_v3::PrivatePeerV3::DynamicLoopbackWithinThisAttempt,
        };
        activate_owned_policy_staged_until(
            input.legacy.clone(),
            self.images.as_ref().expect("owned images"),
            self.account.as_ref().expect("owned account"),
            &input.identity,
            &input.cell,
            vec![requirement],
            Vec::new(),
            &directory,
            &input.admin_root.join("native-component-policy"),
            input.deadline,
        )
    }

    /// Executes inside an already installed lease. A failed native association
    /// stops further launches and retains the exact live owners for recovery.
    pub fn run_inside_installed_lease(
        &mut self,
        input: InstalledMixedDriverInput<'_>,
        recipes: Vec<InstalledMixedRecipe>,
    ) -> Result<()> {
        if self.images.is_some()
            || self.account.is_some()
            || !self.active.is_empty()
            || !self.completed.is_empty()
        {
            return Err(CiError::Message(
                "installed mixed driver cannot reuse an existing lifetime owner".into(),
            ));
        }
        if recipes.is_empty()
            || recipes.len() > 256
            || !input.output.is_absolute()
            || !input.artifact_root.is_absolute()
            || !input.admin_root.is_absolute()
        {
            return Err(CiError::Message(
                "installed mixed recipe inventory/path bound invalid".into(),
            ));
        }
        let mut keys = BTreeSet::new();
        for recipe in &recipes {
            if recipe.key.target != input.cell.target
                || recipe.key.channel.as_ref() != Some(&input.cell.channel)
                || !keys.insert(recipe.key.clone())
                || recipe.observation_limit.is_zero()
            {
                return Err(CiError::Message(
                    "installed mixed recipe key/timeout differs from selected cell".into(),
                ));
            }
        }
        self.acquire_owned_resources(&input)?;
        for (ordinal, recipe) in recipes.into_iter().enumerate() {
            let key = recipe.key.clone();
            let result = (|| -> Result<()> {
                let remaining = input
                    .deadline
                    .saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(CiError::Message(
                        "installed mixed operation deadline exhausted; cleanup owners retained"
                            .into(),
                    ));
                }
                let timeout = recipe.observation_limit.min(remaining);
                let directory = input.output.join(format!("recipe-{ordinal}"));
                std::fs::create_dir(&directory)?;
                let policy = activate_owned_policy_staged_until(
                    input.legacy.clone(),
                    self.images.as_ref().expect("owned images"),
                    self.account.as_ref().expect("owned account"),
                    &input.identity,
                    &input.cell,
                    recipe.requirements,
                    recipe.output_files,
                    &directory,
                    &input.admin_root.join(format!("recipe-policy-{ordinal}")),
                    input.deadline,
                )?;
                // Public contract bytes carry no private authority. Permit the
                // native caller to read them while the root-owned parent keeps
                // replacement custody with the controller.
                std::fs::set_permissions(
                    directory.join("mixed.contract.json"),
                    std::fs::Permissions::from_mode(0o644),
                )?;
                let prefix = format!(
                    "{}/{}/linux-mixed/recipe-{ordinal}",
                    input.cell.target, input.cell.channel
                );
                let mut challenge_bytes = [0u8; 32];
                File::open("/dev/urandom")?.read_exact(&mut challenge_bytes)?;
                if challenge_bytes.iter().all(|byte| *byte == 0) {
                    return Err(CiError::Message(
                        "native challenge source returned an all-zero value".into(),
                    ));
                }
                let challenge = hex::encode(challenge_bytes);
                if key.family == "L-ISO-02"
                    && ["input-socket", "imported-socket", "caller-writable-tree"]
                        .contains(&key.scenario.as_str())
                {
                    let admin_metadata = std::fs::symlink_metadata(input.admin_root)?;
                    let owner = serde_json::json!({"format":"memcordon.linux-policy-case-owner","revision":1,
                        "run_id":input.identity.run_id,"source_commit":input.identity.source_commit,"source_tree_sha256":input.identity.source_tree_sha256,
                        "cell":input.cell,"lease_id":input.lease_id,"provider":input.provider,"baseline_registry":policy.registry,
                        "baseline_epoch":policy.contract.expected_epoch,"admin_root":input.admin_root,
                        "admin_root_device":admin_metadata.dev(),"admin_root_inode":admin_metadata.ino(),
                        "privileged_policy_root":input.admin_root.join(format!("recipe-policy-{ordinal}"))});
                    retain(
                        &directory.join("isolation-original-owner.json"),
                        &serde_json::to_vec(&owner)?,
                    )?;
                    self.isolation_import_contexts.push(AccountRefusalContext {
                        key: key.clone(),
                        owner,
                        baseline_contract: directory.join("mixed.contract.json"),
                        original_lease: input
                            .output
                            .parent()
                            .ok_or_else(|| {
                                CiError::Message(
                                    "importer original installed lease parent absent".into(),
                                )
                            })?
                            .join("lease-owner.json"),
                        acquisition: input.output.join("owned-resources-acquired.json"),
                    });
                    self.isolation_import_reports
                        .push(super::linux_isolation_cases::ImportRefusalReport::default());
                    let report = self
                        .isolation_import_reports
                        .last_mut()
                        .expect("retained original isolation importer");
                    let imported = report.run(
                        &input,
                        self.images.as_ref().expect("retained original images"),
                        self.account
                            .as_ref()
                            .expect("retained original exclusive account"),
                        &policy,
                        &directory,
                        &key.scenario,
                        &challenge,
                    );
                    if let Some(definition) = report.definition.clone() {
                        self.recovered_case_images.push(definition);
                    }
                    imported?;
                    report.finalize(input.cleanup_deadline)?;
                    return Ok(());
                }
                if key.family == "L-ISO-06"
                    && ["same-uid-process", "account-alias", "stale-reservation"]
                        .contains(&key.scenario.as_str())
                {
                    retain(&directory.join("challenge.bin"), challenge.as_bytes())?;
                    let admin_metadata = std::fs::symlink_metadata(input.admin_root)?;
                    let owner = serde_json::json!({"format":"memcordon.linux-policy-case-owner","revision":1,
                        "run_id":input.identity.run_id,"source_commit":input.identity.source_commit,"source_tree_sha256":input.identity.source_tree_sha256,
                        "cell":input.cell,"lease_id":input.lease_id,"provider":input.provider,"baseline_registry":policy.registry,
                        "baseline_epoch":policy.contract.expected_epoch,"admin_root":input.admin_root,
                        "admin_root_device":admin_metadata.dev(),"admin_root_inode":admin_metadata.ino(),
                        "privileged_policy_root":input.admin_root.join(format!("recipe-policy-{ordinal}"))});
                    retain(
                        &directory.join("account-original-owner.json"),
                        &serde_json::to_vec(&owner)?,
                    )?;
                    self.isolation_account_contexts.push(AccountRefusalContext {
                        key: key.clone(),
                        owner,
                        baseline_contract: directory.join("mixed.contract.json"),
                        original_lease: input
                            .output
                            .parent()
                            .ok_or_else(|| {
                                CiError::Message(
                                    "account original installed lease parent absent".into(),
                                )
                            })?
                            .join("lease-owner.json"),
                        acquisition: input.output.join("owned-resources-acquired.json"),
                    });
                    self.isolation_account_reports
                        .push(super::linux_isolation_cases::AccountRefusalReport::default());
                    let report = self
                        .isolation_account_reports
                        .last_mut()
                        .expect("retained account refusal report");
                    if key.scenario == "same-uid-process" {
                        report.run_same_uid(
                            &input,
                            self.account
                                .as_ref()
                                .expect("retained original exclusive account"),
                            &policy,
                            &directory,
                            &challenge,
                        )?;
                    } else if key.scenario == "account-alias" {
                        report.run_alias(
                            &input,
                            self.account
                                .as_ref()
                                .expect("retained original exclusive account"),
                            &policy,
                            &directory,
                            &challenge,
                        )?;
                    } else {
                        report.run_stale(
                            &input,
                            self.account
                                .as_ref()
                                .expect("retained original exclusive account"),
                            &policy,
                            &directory,
                            &challenge,
                        )?;
                    }
                    report.finalize(input.cleanup_deadline)?;
                    return Ok(());
                }
                if key.family == "L-LIFE-02"
                    || (key.family == "L-LIFE-05" && key.scenario == "report-persistence-failure")
                {
                    let cli_sha256 = hex::encode(Sha256::digest(read_owned_resource(
                        Path::new("/usr/libexec/memcordon"),
                        512 * 1024 * 1024,
                    )?));
                    let agent_sha256 = hex::encode(Sha256::digest(read_owned_resource(
                        Path::new("/usr/libexec/memcordon-sealed-agent"),
                        512 * 1024 * 1024,
                    )?));
                    self.lifecycle_reports
                        .push(super::linux_readiness_lifecycle_cases::LifecycleReport::default());
                    let report = self
                        .lifecycle_reports
                        .last_mut()
                        .expect("retained original lifecycle report");
                    let context = super::linux_readiness_limits_cases::LimitsContext {
                        lease_owner_path: &input
                            .output
                            .parent()
                            .ok_or_else(|| {
                                CiError::Message("original installed lease parent absent".into())
                            })?
                            .join("lease-owner.json"),
                        recovery_harness: input.recovery_harness,
                        identity: &input.identity,
                        cell: &input.cell,
                        provider: input.provider,
                        contract: &policy.contract,
                        contract_path: &directory.join("mixed.contract.json"),
                        artifact_root: input.artifact_root,
                        lease_id: &input.lease_id,
                        selected_cli_sha256: &cli_sha256,
                        selected_agent_sha256: &agent_sha256,
                        work_deadline: input.deadline,
                        cleanup_deadline: input.cleanup_deadline,
                        work_deadline_unix_millis: input.work_deadline_unix_millis,
                        cleanup_deadline_unix_millis: input.cleanup_deadline_unix_millis,
                    };
                    super::linux_readiness_lifecycle_cases::run_case(
                        report,
                        &context,
                        self.account
                            .as_ref()
                            .expect("retained original exclusive account"),
                        key.clone(),
                        &directory.join("frontend"),
                        &prefix,
                        &challenge,
                    )?;
                    super::linux_readiness_lifecycle_cases::normalize_completed(
                        report,
                        self.images
                            .as_ref()
                            .expect("retained original selected images"),
                        &input,
                        &directory,
                    )?;
                    super::linux_readiness_lifecycle_cases::finalize_report(
                        report,
                        input.cleanup_deadline,
                    )?;
                    return Ok(());
                }
                if (["C-STATUS", "L-LIFE-03"].contains(&key.family.as_str())
                    && ["deadline", "memory", "cancellation", "reserved-target-exit"]
                        .contains(&key.scenario.as_str()))
                    || (["C-IO", "L-MIX-05"].contains(&key.family.as_str())
                        && key.scenario == "bounded-large-output")
                    || (key.family == "L-LIFE-05" && key.scenario == "relay-backpressure")
                {
                    let cli_sha256 = hex::encode(Sha256::digest(read_owned_resource(
                        Path::new("/usr/libexec/memcordon"),
                        512 * 1024 * 1024,
                    )?));
                    let agent_sha256 = hex::encode(Sha256::digest(read_owned_resource(
                        Path::new("/usr/libexec/memcordon-sealed-agent"),
                        512 * 1024 * 1024,
                    )?));
                    self.limits_reports
                        .push(super::linux_readiness_limits_cases::LimitsReport::default());
                    let report = self
                        .limits_reports
                        .last_mut()
                        .expect("retained limits report owner");
                    let context = super::linux_readiness_limits_cases::LimitsContext {
                        lease_owner_path: &input
                            .output
                            .parent()
                            .ok_or_else(|| {
                                CiError::Message("original installed lease parent absent".into())
                            })?
                            .join("lease-owner.json"),
                        recovery_harness: input.recovery_harness,
                        identity: &input.identity,
                        cell: &input.cell,
                        provider: input.provider,
                        contract: &policy.contract,
                        contract_path: &directory.join("mixed.contract.json"),
                        artifact_root: input.artifact_root,
                        lease_id: &input.lease_id,
                        selected_cli_sha256: &cli_sha256,
                        selected_agent_sha256: &agent_sha256,
                        work_deadline: input.deadline,
                        cleanup_deadline: input.cleanup_deadline,
                        work_deadline_unix_millis: input.work_deadline_unix_millis,
                        cleanup_deadline_unix_millis: input.cleanup_deadline_unix_millis,
                    };
                    super::linux_readiness_limits_cases::run_case(
                        report,
                        &context,
                        key.clone(),
                        &directory.join("frontend"),
                        &prefix,
                        &challenge,
                    )?;
                    super::linux_readiness_limits_cases::finalize_report(
                        report,
                        input.cleanup_deadline,
                    )?;
                    for (completed_key, mut collection) in report.completed.drain(..) {
                        super::linux_readiness_limits_cases::normalize_completed(
                            &mut collection,
                            &report.controller_actions,
                            self.images.as_ref().expect("owned images"),
                            &input,
                            &prefix,
                            &agent_sha256,
                        )?;
                        self.completed.push((completed_key, collection));
                    }
                    return Ok(());
                }
                if key.family == "L-ISO-03" && key.scenario == "other-attempt-abstract" {
                    let source_output = directory.join("cross-attempt-source");
                    let protected_output =
                        input.admin_root.join(format!("cross-attempt-{ordinal}"));
                    std::fs::create_dir(&protected_output)?;
                    std::fs::set_permissions(
                        &protected_output,
                        std::fs::Permissions::from_mode(0o700),
                    )?;
                    let original_lease = input
                        .output
                        .parent()
                        .ok_or_else(|| {
                            CiError::Message("cross original installed lease parent absent".into())
                        })?
                        .join("lease-owner.json");
                    let original_acquisition = input.output.join("owned-resources-acquired.json");
                    let context = super::linux_cross_attempt_cases::CrossAttemptContext {
                        identity: &input.identity,
                        cell: &input.cell,
                        lease_id: &input.lease_id,
                        provider: input.provider,
                        images: self.images.as_ref().expect("retained original images"),
                        baseline: &policy,
                        primary_account: self.account.as_ref().expect("retained primary account"),
                        output: &source_output,
                        protected_output: &protected_output,
                        artifact_root: input.artifact_root,
                        original_lease: &original_lease,
                        original_acquisition: &original_acquisition,
                        deadline: input.deadline,
                        cleanup_deadline: input.cleanup_deadline,
                        work_deadline_unix_millis: input.work_deadline_unix_millis,
                        cleanup_deadline_unix_millis: input.cleanup_deadline_unix_millis,
                    };
                    self.cross_attempt_reports
                        .push(super::linux_cross_attempt_cases::initialize(&context)?);
                    let report = self
                        .cross_attempt_reports
                        .last_mut()
                        .expect("retained cross-attempt owner before acquisition");
                    super::linux_cross_attempt_cases::run(&context, report)?;
                    report.finalize()?;
                    let canary = report
                        .canary
                        .as_ref()
                        .ok_or_else(|| CiError::Message("cross original canary absent".into()))?
                        .clone();
                    let raw = decode_owned_resource_json(&read_owned_resource(
                        &input.artifact_root.join(&canary.path),
                        1024 * 1024,
                    )?)?;
                    let original_challenge = raw["challenge"].as_str().ok_or_else(|| {
                        CiError::Message("cross original challenge absent".into())
                    })?;
                    let peer_prefix = raw["peer_collection_root"].as_str().ok_or_else(|| {
                        CiError::Message("cross original peer collection path absent".into())
                    })?;
                    let target_prefix =
                        raw["target_collection_root"].as_str().ok_or_else(|| {
                            CiError::Message("cross original target collection path absent".into())
                        })?;
                    let mut peer = report.peer.take().ok_or_else(|| {
                        CiError::Message("cross original peer completion absent".into())
                    })?;
                    normalize_completed_case(
                        &mut peer,
                        context.images,
                        &input,
                        &["own-abstract-held".into(), original_challenge.into()],
                        peer_prefix,
                    )?;
                    let mut target = report.target.take().ok_or_else(|| {
                        CiError::Message("cross original target completion absent".into())
                    })?;
                    let canary_bytes =
                        read_owned_resource(&input.artifact_root.join(&canary.path), 1024 * 1024)?;
                    let normalized_canary =
                        format!("{target_prefix}/other-attempt-abstract-canary.json");
                    retain(&input.artifact_root.join(&normalized_canary), &canary_bytes)?;
                    target
                        .persisted
                        .artifacts
                        .push(memcordon_readiness_verifier::Artifact {
                            path: normalized_canary,
                            length: canary_bytes.len() as u64,
                            sha256: hex::encode(Sha256::digest(&canary_bytes)),
                        });
                    target.persisted.artifacts.extend(peer.persisted.artifacts);
                    archive_cross_attempt_sources(
                        &source_output,
                        input.artifact_root,
                        &mut target.persisted.artifacts,
                    )?;
                    normalize_completed_case(
                        &mut target,
                        context.images,
                        &input,
                        &[
                            "forbidden-abstract".into(),
                            original_challenge.into(),
                            format!("memcordon-readiness-{original_challenge}").into(),
                        ],
                        target_prefix,
                    )?;
                    self.completed.push((key.clone(), target));
                    return Ok(());
                }
                let binary_streams = matches!(
                    recipe.mode.as_str(),
                    "raw-byte-streams" | "empty-input" | "bounded-large-output"
                );
                let host_tcp_canary = if key.family == "L-ISO-01"
                    && ["host-tcp", "nonloopback"].contains(&key.scenario.as_str())
                {
                    let address = if key.scenario == "nonloopback" {
                        super::linux_isolation_cases::host_nonloopback_ipv4()?
                    } else {
                        std::net::Ipv4Addr::LOCALHOST
                    };
                    let listener = std::net::TcpListener::bind((address, 0))?;
                    let address = listener.local_addr()?;
                    let client =
                        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
                    let (accepted, _) = listener.accept()?;
                    let socket = rustix::fs::fstat(&listener)
                        .map_err(|error| CiError::Message(error.to_string()))?;
                    retain(
                        &directory.join("host-tcp-canary.json"),
                        &serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.linux-host-tcp-canary","revision":1,"challenge":challenge,
                            "endpoint":address.to_string(),"socket_inode":socket.st_ino,
                            "network_namespace_inode":std::fs::metadata("/proc/self/ns/net")?.ino(),
                            "baseline_client_connected":client.peer_addr()?==address,"baseline_server_accepted":accepted.local_addr()?==address&&accepted.peer_addr()?==client.local_addr()?,
                        }))?,
                    )?;
                    Some(listener)
                } else {
                    None
                };
                let host_abstract_canary = if key.family == "L-ISO-03"
                    && key.scenario == "host-abstract"
                {
                    use std::os::linux::net::SocketAddrExt;
                    let name = format!("memcordon-readiness-{challenge}");
                    let address =
                        std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
                    let listener = std::os::unix::net::UnixListener::bind_addr(&address)?;
                    let client = std::os::unix::net::UnixStream::connect_addr(&address)?;
                    let (accepted, _) = listener.accept()?;
                    let socket = rustix::fs::fstat(&listener)
                        .map_err(|error| CiError::Message(error.to_string()))?;
                    retain(
                        &directory.join("host-abstract-canary.json"),
                        &serde_json::to_vec(&serde_json::json!({
                            "format":"memcordon.linux-host-abstract-canary","revision":1,"challenge":challenge,"name":name.as_bytes(),
                            "socket_inode":socket.st_ino,"network_namespace_inode":std::fs::metadata("/proc/self/ns/net")?.ino(),
                            "baseline_client_connected":client.peer_addr()?.as_abstract_name()==Some(name.as_bytes()),
                            "baseline_server_accepted":accepted.local_addr()?.as_abstract_name()==Some(name.as_bytes()),
                        }))?,
                    )?;
                    Some(listener)
                } else {
                    None
                };
                let host_path_canary = if key.family == "L-ISO-02"
                    && ["host-run-socket", "host-temp-socket"].contains(&key.scenario.as_str())
                {
                    Some(super::linux_isolation_cases::HostPathSocket::prepare(
                        &directory,
                        &key.scenario,
                        &challenge,
                        input.deadline,
                    )?)
                } else {
                    None
                };
                let mut arguments = vec![
                    std::ffi::OsString::from(recipe.mode),
                    std::ffi::OsString::from(&challenge),
                ];
                arguments.extend(recipe.arguments);
                if let Some(canary) = &host_path_canary {
                    arguments.push(canary.path.as_os_str().to_owned());
                }
                let outside_canary = if key.family == "L-ISO-04"
                    && [
                        "symlink",
                        "dotdot",
                        "proc-root",
                        "proc-cwd",
                        "proc-fd",
                        "hardlink",
                        "opath",
                        "mount-alias",
                    ]
                    .contains(&key.scenario.as_str())
                {
                    let canary = super::linux_isolation_cases::HostOutsideFile::prepare(
                        &directory,
                        &key.scenario,
                        &challenge,
                    )?;
                    arguments.push(canary.probe.as_os_str().to_owned());
                    if let Some((_, fd)) = canary.leaked_descriptor() {
                        arguments.push(fd.to_string().into());
                    }
                    Some(canary)
                } else {
                    None
                };
                if let Some(listener) = &host_tcp_canary {
                    arguments.push(listener.local_addr()?.to_string().into());
                }
                if host_abstract_canary.is_some() {
                    arguments.push(format!("memcordon-readiness-{challenge}").into());
                }
                let image_entrypoint_source = if key.family == "L-IMG-03"
                    && key.scenario == "image-only-entrypoint"
                {
                    let images = self.images.as_ref().expect("owned images");
                    let selected = images
                        .runtime
                        .entrypoints
                        .as_slice()
                        .iter()
                        .find(|entry| entry.id.as_str() == "owned-readiness")
                        .ok_or_else(|| {
                            CiError::Message("owned image entrypoint declaration absent".into())
                        })?;
                    let host_path = Path::new("/").join(selected.path.as_str());
                    let errno = match std::fs::symlink_metadata(&host_path) {
                        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => libc::ENOENT,
                        Err(error) => return Err(error.into()),
                        Ok(_) => {
                            return Err(CiError::Message(
                                "selected image entrypoint exists in host namespace".into(),
                            ));
                        }
                    };
                    let namespace = File::open("/proc/self/ns/mnt")?.metadata()?;
                    let observer_pid = std::process::id();
                    Some(
                        serde_json::json!({"host_path":host_path,"host_stat_errno":errno,
                        "observer":{"pid":observer_pid,"birth":crate::linux_consumer_readiness::process_birth(observer_pid).map_err(CiError::Message)?},
                        "host_mount":{"device":namespace.dev(),"inode":namespace.ino()},"runtime_definition":images.runtime,
                        "fixture_sha256":images.fixture_sha256,"run_id":input.identity.run_id,"lease_id":input.lease_id}),
                    )
                } else {
                    None
                };
                let host_socket_descriptor = if key.family == "L-ISO-05"
                    && ["stdio-host-socket", "extra-host-fd"].contains(&key.scenario.as_str())
                {
                    Some(super::linux_isolation_cases::HostSocketDescriptor::create(
                        if key.scenario == "stdio-host-socket" {
                            0
                        } else {
                            128
                        },
                    )?)
                } else {
                    None
                };
                let launch_input = InstalledMixedLaunchInput {
                    directory: &directory.join("frontend"),
                    contract: &directory.join("mixed.contract.json"),
                    caller_uid: 65534,
                    caller_gid: 65534,
                    target_arguments: &arguments,
                    deadline: &recipe.product_deadline,
                    memory: &recipe.memory,
                };
                let mut launch = match &host_socket_descriptor {
                    Some(canary) if canary.descriptor == 0 => {
                        InstalledMixedLaunch::start_with_host_stdin(
                            launch_input,
                            canary.handoff()?,
                        )?
                    }
                    Some(canary) => InstalledMixedLaunch::start_with_inherited_descriptor(
                        launch_input,
                        Some((canary.handoff()?, canary.descriptor)),
                    )?,
                    None => InstalledMixedLaunch::start_with_inherited_descriptor(
                        launch_input,
                        match &outside_canary {
                            Some(canary) => canary.clone_leaked_descriptor()?,
                            None => None,
                        },
                    )?,
                };
                launch.image_entrypoint_source = image_entrypoint_source;
                launch.outside_canary = outside_canary;
                launch.host_socket_descriptor = host_socket_descriptor;
                self.active.push(OwnedMixedRecipe {
                    key: key.clone(),
                    launch,
                    observer: None,
                    held: Vec::new(),
                    transcript: Vec::new(),
                    prepared_native_receipt: None,
                    host_tcp_canary,
                    host_abstract_canary,
                    host_path_canary,
                });
                let owned = self.active.last_mut().expect("inserted native owner");
                let observer = owned.launch.acquire_prepared(
                    input.provider,
                    &policy.contract,
                    input.artifact_root,
                    &format!("{prefix}/prepared.json"),
                    timeout,
                )?;
                owned.observer = Some(observer);
                // Persist the independently acquired live snapshot before the
                // observation ACK, rather than minting it after retirement.
                owned.prepared_native_receipt = Some(
                    owned
                        .observer
                        .as_ref()
                        .expect("retained native observer")
                        .persist_native_receipt(
                            &input.identity.run_id,
                            input.artifact_root,
                            &format!("{prefix}/prepared-native-before-ack.json"),
                        )
                        .map_err(CiError::Message)?,
                );
                let observer = owned.observer.as_ref().expect("retained native observer");
                if let Some(canary) = owned.launch.outside_canary.as_mut() {
                    canary.observe_frontend(observer.caller.process_id, observer.caller.birth)?;
                }
                if let Some(canary) = owned.launch.host_socket_descriptor.as_mut() {
                    canary.observe_frontend(
                        observer.caller.process_id,
                        observer.caller.birth,
                        &owned.launch.observation_directory,
                    )?;
                }
                observer
                    .acknowledge(&owned.launch.observation_directory)
                    .map_err(CiError::Message)?;
                if binary_streams {
                    owned.launch.frontend.stdin.take();
                    owned.launch.wait_and_capture(
                        input
                            .deadline
                            .saturating_duration_since(std::time::Instant::now())
                            .min(timeout),
                    )?;
                } else {
                    owned.launch.observe_fixture(
                        observer,
                        &challenge,
                        &mut owned.held,
                        &mut owned.transcript,
                        input
                            .deadline
                            .saturating_duration_since(std::time::Instant::now())
                            .min(timeout),
                    )?;
                }
                let mut collected = owned.launch.collect_completed(
                    observer,
                    &owned.held,
                    input.identity.clone(),
                    input.lease_id.clone(),
                    key.clone(),
                    challenge,
                    prefix.clone(),
                    &directory.join("mixed.contract.json"),
                    input.artifact_root,
                    input
                        .deadline
                        .saturating_duration_since(std::time::Instant::now())
                        .min(timeout),
                )?;
                if let Some(listener) = &owned.host_tcp_canary {
                    let canary =
                        read_owned_resource(&directory.join("host-tcp-canary.json"), 64 * 1024)?;
                    let raw = decode_owned_resource_json(&canary)?;
                    if raw.get("endpoint").and_then(serde_json::Value::as_str)
                        != Some(listener.local_addr()?.to_string().as_str())
                    {
                        return Err(CiError::Message(
                            "retained native host canary endpoint changed".into(),
                        ));
                    }
                    let held = rustix::fs::fstat(listener)
                        .map_err(|error| CiError::Message(error.to_string()))?;
                    if raw["socket_inode"].as_u64() != Some(held.st_ino)
                        || raw["network_namespace_inode"].as_u64()
                            != Some(std::fs::metadata("/proc/self/ns/net")?.ino())
                    {
                        return Err(CiError::Message(
                            "original host TCP socket or native namespace changed".into(),
                        ));
                    }
                    let relative = format!("{prefix}/host-tcp-canary.json");
                    retain(&input.artifact_root.join(&relative), &canary)?;
                    collected
                        .persisted
                        .artifacts
                        .push(memcordon_readiness_verifier::Artifact {
                            path: relative,
                            length: canary.len() as u64,
                            sha256: hex::encode(Sha256::digest(&canary)),
                        });
                }
                if owned.host_abstract_canary.is_some() {
                    let canary = read_owned_resource(
                        &directory.join("host-abstract-canary.json"),
                        64 * 1024,
                    )?;
                    let relative = format!("{prefix}/host-abstract-canary.json");
                    retain(&input.artifact_root.join(&relative), &canary)?;
                    collected
                        .persisted
                        .artifacts
                        .push(memcordon_readiness_verifier::Artifact {
                            path: relative,
                            length: canary.len() as u64,
                            sha256: hex::encode(Sha256::digest(&canary)),
                        });
                }
                if let Some(canary) = owned.host_path_canary.take() {
                    canary.settle(&directory)?;
                    for leaf in [
                        "host-path-socket-intent.json",
                        "host-path-socket-allocation.json",
                        "host-path-socket-canary.json",
                    ] {
                        let bytes = read_owned_resource(&directory.join(leaf), 64 * 1024)?;
                        let relative = format!("{prefix}/{leaf}");
                        retain(&input.artifact_root.join(&relative), &bytes)?;
                        collected.persisted.artifacts.push(
                            memcordon_readiness_verifier::Artifact {
                                path: relative,
                                length: bytes.len() as u64,
                                sha256: hex::encode(Sha256::digest(&bytes)),
                            },
                        );
                    }
                }
                let public_bytes = std::fs::read(
                    input
                        .artifact_root
                        .join(format!("{prefix}/provider-request.json")),
                )?;
                let public =
                    memcordon_core::mixed_runtime::MixedRuntimeRequest::parse(&public_bytes)
                        .map_err(CiError::Message)?;
                let (effective, environment) = reconstruct_effective_invocation(
                    &public,
                    self.images.as_ref().expect("owned images"),
                    &observer.observation.admission,
                )?;
                let mut persist =
                    |name: &str,
                     bytes: Vec<u8>|
                     -> Result<memcordon_readiness_verifier::Artifact> {
                        let relative = format!("{prefix}/{name}");
                        retain(&input.artifact_root.join(&relative), &bytes)?;
                        let artifact = memcordon_readiness_verifier::Artifact {
                            path: relative,
                            length: bytes.len() as u64,
                            sha256: hex::encode(Sha256::digest(bytes)),
                        };
                        collected.persisted.artifacts.push(artifact.clone());
                        Ok(artifact)
                    };
                collected.effective_invocation =
                    Some(persist("effective-invocation.bin", effective)?);
                collected.effective_environment = Some(persist(
                    "effective-environment.json",
                    serde_json::to_vec(&environment)?,
                )?);
                collected.prepared_native_receipt = owned
                    .prepared_native_receipt
                    .as_ref()
                    .expect("native receipt persisted before ACK")
                    .clone();
                collected
                    .persisted
                    .artifacts
                    .push(collected.prepared_native_receipt.clone());
                normalize_completed_case(
                    &mut collected,
                    self.images.as_ref().expect("owned images"),
                    &input,
                    &arguments,
                    &prefix,
                )?;
                self.completed.push((key.clone(), collected));
                // Only completed independent native retirement permits dropping
                // the associated held owners. Failure keeps this vector intact.
                self.active.pop();
                Ok(())
            })();
            if let Err(error) = result {
                self.failures.push((key.clone(), error.to_string()));
                retain(
                    &input.output.join("driver-failures.json"),
                    &serde_json::to_vec(&self.failures)?,
                )?;
                return Err(error);
            }
        }
        let baseline_directory = input.output.join("image-cases-baseline");
        std::fs::create_dir(&baseline_directory)?;
        let policy_directory = input.output.join("policy-cases");
        use memcordon_core::workload_contract_v3::{LocalPortV3, PrivatePeerV3, RequirementV3};
        let baseline = activate_owned_policy_staged_until(
            input.legacy.clone(),
            self.images.as_ref().expect("owned images"),
            self.account.as_ref().expect("owned account"),
            &input.identity,
            &input.cell,
            vec![RequirementV3::TcpListener {
                id: id("tcp")?,
                local_port: LocalPortV3::KernelAssigned,
                peer: PrivatePeerV3::DynamicLoopbackWithinThisAttempt,
            }],
            Vec::new(),
            &baseline_directory,
            &input.admin_root.join("image-cases-baseline"),
            input.deadline,
        )?;
        let agent_sha256 = hex::encode(Sha256::digest(read_owned_resource(
            Path::new("/usr/libexec/memcordon-sealed-agent"),
            512 * 1024 * 1024,
        )?));
        let image_report = super::linux_readiness_image_cases::run_import_cases(
            super::linux_readiness_image_cases::ImageCaseContext {
                identity: &input.identity,
                cell: &input.cell,
                lease_id: &input.lease_id,
                activated: &baseline,
                provider: input.provider,
                images: self.images.as_ref().expect("owned images"),
                account: self.account.as_ref().expect("owned account"),
                expected_agent_sha256: &agent_sha256,
                output: &input.output.join("image-cases"),
                artifact_root: input.artifact_root,
                admin_root: input.admin_root,
                deadline: input.deadline,
                cleanup_deadline: input.cleanup_deadline,
                work_deadline_unix_millis: input.work_deadline_unix_millis,
                cleanup_deadline_unix_millis: input.cleanup_deadline_unix_millis,
            },
        )?;
        let image_failed = !image_report.failures.is_empty();
        self.image_reports.push(image_report);
        self.image_attempts_settled = false;
        if image_failed {
            return Err(CiError::Message(
                "installed image/export cases retained failures and native owners".into(),
            ));
        }
        for report in &mut self.image_reports {
            super::linux_readiness_image_cases::finalize_attempts(report, input.cleanup_deadline)?;
            super::linux_export_recovery::recover_report(
                report,
                &input,
                self.account.as_ref().expect("retained original account"),
            )?;
        }
        self.image_attempts_settled = true;
        let policy_baseline_directory = input.output.join("policy-cases-baseline");
        std::fs::create_dir(&policy_baseline_directory)?;
        let baseline = activate_owned_policy_staged_until(
            input.legacy.clone(),
            self.images.as_ref().expect("owned images"),
            self.account.as_ref().expect("owned account"),
            &input.identity,
            &input.cell,
            vec![RequirementV3::TcpListener {
                id: id("tcp")?,
                local_port: LocalPortV3::KernelAssigned,
                peer: PrivatePeerV3::DynamicLoopbackWithinThisAttempt,
            }],
            Vec::new(),
            &policy_baseline_directory,
            &input.admin_root.join("policy-cases-baseline"),
            input.deadline,
        )?;
        let mut report = super::linux_readiness_policy_cases::run(
            super::linux_readiness_policy_cases::PolicyCaseContext {
                identity: &input.identity,
                cell: &input.cell,
                lease_id: &input.lease_id,
                provider: input.provider,
                activated: &baseline,
                account: self.account.as_ref().expect("owned account"),
                output: &policy_directory,
                artifact_root: input.artifact_root,
                admin_root: input.admin_root,
                deadline: input.deadline,
                cleanup_deadline: input.cleanup_deadline,
            },
        )?;
        let failed = !report.failures.is_empty();
        let normalized = if !failed {
            super::linux_readiness_policy_cases::normalize_running(
                &mut report,
                self.images.as_ref().expect("owned images"),
                &input,
            )
        } else {
            Ok(Vec::new())
        };
        self.policy_reports.push(report);
        self.policy_attempts_settled = false;
        self.completed.extend(normalized?);
        if failed {
            return Err(CiError::Message(
                "installed policy cases retained failures and native owners".into(),
            ));
        }
        Ok(())
    }
}

/// Retain actual no-target public observations. This producer performs custody
/// and association checks; the independent verifier owns semantic acceptance.
fn normalize_malformed_ingress(
    report: &super::linux_readiness_policy_cases::PolicyCaseReport,
    observation: &super::linux_readiness_policy_cases::PolicyCaseObservation,
    identity: &SourceIdentity,
    key: &memcordon_readiness_verifier::CaseKey,
    artifact_root: &Path,
    artifacts: &mut BTreeMap<String, memcordon_readiness_verifier::Artifact>,
) -> Result<String> {
    use memcordon_readiness_verifier::{Artifact, LinuxMalformedIngressEvidence};
    if observation.error.is_some()
        || observation.native_exit != Some(0)
        || report.restoration_required
    {
        return Err(CiError::Message(
            "malformed ingress original native operation/policy ownership unsettled".into(),
        ));
    }
    let parent = report.output_root.parent().ok_or_else(|| {
        CiError::Message("malformed ingress original mixed lease parent absent".into())
    })?;
    let original_lease = parent
        .parent()
        .ok_or_else(|| {
            CiError::Message("malformed ingress original installed lease parent absent".into())
        })?
        .join("lease-owner.json");
    let acquisition = parent.join("owned-resources-acquired.json");
    let directory = report.output_root.join("v3-preserve-caller");
    let prefix = format!(
        "{}/{}/policy/v3-preserve-caller",
        key.target,
        key.channel.as_deref().expect("installed ingress channel")
    );
    let destination = artifact_root.join(&prefix);
    std::fs::create_dir_all(
        destination
            .parent()
            .ok_or_else(|| CiError::Message("ingress normalized parent absent".into()))?,
    )?;
    std::fs::create_dir(&destination)?;
    let mut persist = |relative: String, source: &Path| -> Result<String> {
        let bytes = read_policy_observation_file(source, 512 * 1024 * 1024)?;
        retain(&artifact_root.join(&relative), &bytes)?;
        let artifact = Artifact {
            path: relative.clone(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        };
        if artifacts
            .insert(relative.clone(), artifact.clone())
            .is_some_and(|previous| {
                previous.length != artifact.length || previous.sha256 != artifact.sha256
            })
        {
            return Err(CiError::Message(
                "malformed ingress custody conflict".into(),
            ));
        }
        Ok(relative)
    };
    let owner = persist(
        format!("{prefix}/owner.json"),
        &report.output_root.join("owner.json"),
    )?;
    let qualified = report
        .observations
        .iter()
        .find(|row| {
            row.scenario == "restart-fresh-admission"
                && row.error.is_none()
                && row.native_exit == Some(0)
        })
        .ok_or_else(|| {
            CiError::Message("ingress original qualified source admission absent".into())
        })?;
    let activation = persist(
        format!("{prefix}/activation.json"),
        qualified.activation.as_deref().ok_or_else(|| {
            CiError::Message("ingress original qualified native activation absent".into())
        })?,
    )?;
    let original_request = persist(
        format!("{prefix}/original-provider-request.bin"),
        &directory.join("original-provider-request.bin"),
    )?;
    let malformed_request = persist(
        format!("{prefix}/malformed-provider-request.bin"),
        &observation.requested_contract,
    )?;
    let helper_image = persist(
        format!("{prefix}/helper-image.bin"),
        &directory.join("helper-image.bin"),
    )?;
    let invocation = persist(
        format!("{prefix}/invocation.json"),
        observation
            .invocation
            .as_ref()
            .ok_or_else(|| CiError::Message("malformed ingress native invocation absent".into()))?,
    )?;
    let exit = persist(
        format!("{prefix}/native-exit.json"),
        &directory.join("native-exit.json"),
    )?;
    let receipt = persist(
        format!("{prefix}/native-ingress.json"),
        observation
            .result
            .as_ref()
            .ok_or_else(|| CiError::Message("malformed ingress native receipt absent".into()))?,
    )?;
    let stdout = persist(
        format!("{prefix}/stdout.bin"),
        observation
            .stdout
            .as_ref()
            .ok_or_else(|| CiError::Message("malformed ingress stdout absent".into()))?,
    )?;
    let stderr = persist(
        format!("{prefix}/stderr.bin"),
        observation
            .stderr
            .as_ref()
            .ok_or_else(|| CiError::Message("malformed ingress stderr absent".into()))?,
    )?;
    let census = persist(
        format!("{prefix}/native-census.json"),
        &directory.join("native-census.json"),
    )?;
    let acquired =
        decode_owned_resource_json(&read_owned_resource(&acquisition, 32 * 1024 * 1024)?)?;
    let account_source = |field: &str| -> Result<PathBuf> {
        Ok(PathBuf::from(
            acquired["account"][field].as_str().ok_or_else(|| {
                CiError::Message("original ingress account readback source absent".into())
            })?,
        ))
    };
    let account_intent = persist(
        format!("{prefix}/account-intent.json"),
        &account_source("intent")?,
    )?;
    let account_readback = persist(
        format!("{prefix}/account-getent.bin"),
        &account_source("native_readback")?,
    )?;
    let group_readback = persist(
        format!("{prefix}/group-getent.bin"),
        &account_source("group_readback")?,
    )?;
    let original_bytes = read_policy_observation_file(
        &directory.join("original-provider-request.bin"),
        4 * 1024 * 1024,
    )?;
    let mut source_requests = Vec::new();
    for launch in &report.launches {
        for entry in std::fs::read_dir(&launch.observation_directory)? {
            let entry = entry?;
            let name = entry.file_name();
            if name
                .to_str()
                .is_some_and(|name| name.ends_with(".provider-request.bin"))
                && read_policy_observation_file(&entry.path(), 4 * 1024 * 1024)? == original_bytes
            {
                source_requests.push(entry.path());
            }
        }
    }
    if source_requests.len() != 1 {
        return Err(CiError::Message(
            "malformed ingress original native request source absent/ambiguous".into(),
        ));
    }
    let mut original = |source: &Path| -> Result<String> {
        let relative = source
            .strip_prefix(artifact_root)
            .map_err(|error| CiError::Message(error.to_string()))?
            .to_string_lossy()
            .into_owned();
        let bytes = read_policy_observation_file(source, 32 * 1024 * 1024)?;
        let artifact = Artifact {
            path: relative.clone(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        };
        if artifacts
            .insert(relative.clone(), artifact.clone())
            .is_some_and(|previous| {
                previous.length != artifact.length || previous.sha256 != artifact.sha256
            })
        {
            return Err(CiError::Message(
                "original ingress acquisition custody conflict".into(),
            ));
        }
        Ok(relative)
    };
    let original_lease = original(&original_lease)?;
    let acquisition = original(&acquisition)?;
    let original_source_request = original(&source_requests[0])?;
    let original_frontend = original(qualified.invocation.as_deref().ok_or_else(|| {
        CiError::Message("ingress original qualified frontend invocation absent".into())
    })?)?;
    let evidence = LinuxMalformedIngressEvidence {
        format: "memcordon.consumer-readiness.linux-malformed-ingress".into(),
        revision: 1,
        key: key.clone(),
        run_id: identity.run_id.clone(),
        source_commit: identity.source_commit.clone(),
        source_tree_sha256: identity.source_tree_sha256.clone(),
        lease_id: decode_owned_resource_json(&read_owned_resource(
            &report.output_root.join("owner.json"),
            16 * 1024 * 1024,
        )?)?["lease_id"]
            .as_str()
            .ok_or_else(|| CiError::Message("original ingress lease id absent".into()))?
            .into(),
        owner,
        original_lease,
        acquisition,
        activation,
        original_request,
        original_source_request,
        original_frontend,
        malformed_request,
        helper_image,
        invocation,
        exit,
        receipt,
        stdout,
        stderr,
        census,
        account_intent,
        account_readback,
        group_readback,
    };
    let relative = format!("{prefix}/case-evidence.json");
    let bytes = serde_json::to_vec(&evidence)?;
    retain(&artifact_root.join(&relative), &bytes)?;
    artifacts.insert(
        relative.clone(),
        Artifact {
            path: relative.clone(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        },
    );
    Ok(relative)
}

fn normalize_policy_refusal(
    report: &super::linux_readiness_policy_cases::PolicyCaseReport,
    observation: &super::linux_readiness_policy_cases::PolicyCaseObservation,
    owner: &serde_json::Value,
    identity: &SourceIdentity,
    key: &memcordon_readiness_verifier::CaseKey,
    artifact_root: &Path,
    artifacts: &mut BTreeMap<String, memcordon_readiness_verifier::Artifact>,
) -> Result<String> {
    use memcordon_readiness_verifier::{Artifact, LinuxPolicyRefusalEvidence};
    use std::os::unix::process::ExitStatusExt;
    if let Some(error) = &observation.error {
        return Err(CiError::Message(error.clone()));
    }
    let result = observation
        .result
        .as_ref()
        .ok_or_else(|| CiError::Message("policy observation has no actual result".into()))?;
    let launch = report
        .launches
        .iter()
        .find(|launch| launch.result == *result)
        .ok_or_else(|| {
            CiError::Message("policy observation lost its original frontend Child".into())
        })?;
    let status = launch
        .frontend_status
        .ok_or_else(|| CiError::Message("policy frontend native wait is unsettled".into()))?;
    if status.code() != observation.native_exit {
        return Err(CiError::Message(
            "policy frontend wait differs from captured observation".into(),
        ));
    }
    let prefix = format!(
        "{}/{}/policy/{}",
        key.target,
        key.channel.as_deref().expect("installed policy channel"),
        key.scenario
    );
    let destination = artifact_root.join(&prefix);
    std::fs::create_dir_all(
        destination
            .parent()
            .ok_or_else(|| CiError::Message("policy artifact parent absent".into()))?,
    )?;
    std::fs::create_dir(&destination)?;
    let mut persist = |name: &str, bytes: &[u8]| -> Result<String> {
        let relative = format!("{prefix}/{name}");
        retain(&artifact_root.join(&relative), bytes)?;
        let artifact = Artifact {
            path: relative.clone(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        if artifacts
            .insert(relative.clone(), artifact.clone())
            .is_some_and(|previous| {
                previous.length != artifact.length || previous.sha256 != artifact.sha256
            })
        {
            return Err(CiError::Message(
                "policy artifact conflicts with retained bytes".into(),
            ));
        }
        Ok(relative)
    };
    let raw_result = read_policy_observation_file(result, 4 * 1024 * 1024)?;
    memcordon_core::result_v2::ResultV2::parse(&raw_result).map_err(CiError::Message)?;
    let parsed = decode_owned_resource_json(&raw_result)?;
    let invocation = persist(
        "public-invocation.json",
        &serde_json::to_vec(&parsed["invocation"])?,
    )?;
    let frontend_bytes = launch.retained_frontend_invocation()?;
    let frontend_invocation = persist("frontend-invocation.json", &frontend_bytes)?;
    let stdout = read_policy_observation_file(&launch.stdout, 16 * 1024 * 1024)?;
    let stderr = read_policy_observation_file(&launch.stderr, 16 * 1024 * 1024)?;
    let frontend_exit = persist(
        "frontend-exit.json",
        &serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.linux-policy-frontend-exit","revision":1,"process_id":launch.frontend.id(),
        "process_birth":launch.frontend_birth.ok_or_else(||CiError::Message("actual frontend pre-wait birth observation absent".into()))?,
        "raw_wait_status":status.into_raw(),"native_exit":status.code(),"signal":status.signal(),
        "invocation_sha256":hex::encode(Sha256::digest(&frontend_bytes)),
        "stdout_sha256":hex::encode(Sha256::digest(&stdout)),"stderr_sha256":hex::encode(Sha256::digest(&stderr))}))?,
    )?;
    let stdout = persist("stdout.bin", &stdout)?;
    let stderr = persist("stderr.bin", &stderr)?;
    let raw_result = persist("result.json", &raw_result)?;
    let request_paths = std::fs::read_dir(&launch.observation_directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".provider-request.bin"))
        })
        .collect::<Vec<_>>();
    if request_paths.len() != 1 {
        return Err(CiError::Message(
            "policy frontend did not retain exactly one actual provider request".into(),
        ));
    }
    let request_name = request_paths[0]
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CiError::Message("native provider request basename is not UTF8".into()))?;
    let _attempt = request_name
        .strip_suffix(".provider-request.bin")
        .filter(|name| {
            name.len() == 32
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| {
            CiError::Message("native provider request attempt basename differs".into())
        })?;
    let provider_request = persist(
        request_name,
        &read_policy_observation_file(&request_paths[0], 4 * 1024 * 1024)?,
    )?;
    let requested_contract = persist(
        "contract.json",
        &read_policy_observation_file(&observation.requested_contract, 4 * 1024 * 1024)?,
    )?;
    let directory = observation
        .requested_contract
        .parent()
        .ok_or_else(|| CiError::Message("policy case directory absent".into()))?;
    let challenge = persist(
        "challenge.bin",
        &read_policy_observation_file(&directory.join("challenge.bin"), 32)?,
    )?;
    let activation = observation
        .activation
        .as_ref()
        .ok_or_else(|| CiError::Message("policy activation capture absent".into()))?;
    let restoration = observation
        .restoration
        .as_ref()
        .ok_or_else(|| CiError::Message("policy restoration capture absent".into()))?;
    let activation_policy = persist(
        "activation-policy.json",
        &read_policy_observation_file(&activation.with_extension("policy.json"), 16 * 1024 * 1024)?,
    )?;
    let activation_invocation = persist(
        "activation-invocation.json",
        &read_policy_observation_file(&activation.with_extension("invocation.json"), 65536)?,
    )?;
    let activation_stderr = persist(
        "activation-stderr.bin",
        &read_policy_observation_file(&activation.with_extension("stderr.bin"), 16 * 1024 * 1024)?,
    )?;
    let activation_exit = persist(
        "activation-exit.json",
        &read_policy_observation_file(&activation.with_extension("exit.json"), 65536)?,
    )?;
    let activation = persist(
        "activation.json",
        &read_policy_observation_file(activation, 16 * 1024 * 1024)?,
    )?;
    let restoration_policy = persist(
        "restoration-policy.json",
        &read_policy_observation_file(
            &restoration.with_extension("policy.json"),
            16 * 1024 * 1024,
        )?,
    )?;
    let restoration_invocation = persist(
        "restoration-invocation.json",
        &read_policy_observation_file(&restoration.with_extension("invocation.json"), 65536)?,
    )?;
    let restoration_stderr = persist(
        "restoration-stderr.bin",
        &read_policy_observation_file(&restoration.with_extension("stderr.bin"), 16 * 1024 * 1024)?,
    )?;
    let restoration_exit = persist(
        "restoration-exit.json",
        &read_policy_observation_file(&restoration.with_extension("exit.json"), 65536)?,
    )?;
    let restoration = persist(
        "restoration.json",
        &read_policy_observation_file(restoration, 16 * 1024 * 1024)?,
    )?;
    let baseline = report
        .output_root
        .parent()
        .ok_or_else(|| CiError::Message("policy baseline directory absent".into()))?
        .join("policy-cases-baseline");
    let baseline_registry = persist(
        "baseline-policy.json",
        &serde_json::to_vec(&owner["baseline_registry"])?,
    )?;
    let baseline_contract = persist(
        "baseline-contract.json",
        &read_policy_observation_file(&baseline.join("mixed.contract.json"), 4 * 1024 * 1024)?,
    )?;
    let baseline_activation = persist(
        "baseline-activation.json",
        &read_policy_observation_file(&baseline.join("mixed.activation.json"), 16 * 1024 * 1024)?,
    )?;
    let mut earlier_activations = Vec::new();
    if key.scenario == "wrong-epoch" {
        let requested = decode_owned_resource_json(&read_policy_observation_file(
            &observation.requested_contract,
            4 * 1024 * 1024,
        )?)?;
        let candidates = std::iter::once(baseline.join("mixed.activation.json")).chain(
            report
                .observations
                .iter()
                .filter_map(|row| row.restoration.clone()),
        );
        for path in candidates {
            let bytes = read_policy_observation_file(&path, 16 * 1024 * 1024)?;
            let receipt = decode_owned_resource_json(&bytes)?;
            if receipt["epoch"] == requested["expected_epoch"] {
                earlier_activations.push(persist("earlier-activation.json", &bytes)?);
                break;
            }
        }
        if earlier_activations.is_empty() {
            return Err(CiError::Message(
                "stale policy request lost its actual earlier activation".into(),
            ));
        }
    }
    let native_census = persist(
        "native-census.json",
        &read_policy_observation_file(
            &result
                .parent()
                .ok_or_else(|| CiError::Message("policy result source parent absent".into()))?
                .join("native-census.json"),
            16 * 1024 * 1024,
        )?,
    )?;
    let owner_artifact = persist(
        "owner.json",
        &read_policy_observation_file(&report.output_root.join("owner.json"), 16 * 1024 * 1024)?,
    )?;
    let discovery = if key.scenario == "revoke-discovery" {
        use memcordon_readiness_verifier::LinuxPolicyDiscoveryEvidence;
        let mut capture = |name: &str| -> Result<String> {
            persist(
                name,
                &read_policy_observation_file(&directory.join(name), 16 * 1024 * 1024)?,
            )
        };
        Some(LinuxPolicyDiscoveryEvidence {
            contract: capture("discovery-contract.json")?,
            invocation: capture("discovery-invocation.json")?,
            stdout: capture("discovery.json")?,
            stderr: capture("discovery.stderr.bin")?,
            exit: capture("discovery.exit.json")?,
            revocation: capture("discovery-revocation.json")?,
            revocation_policy: capture("discovery-revocation.policy.json")?,
            revocation_invocation: capture("discovery-revocation.invocation.json")?,
            revocation_exit: capture("discovery-revocation.exit.json")?,
            revocation_stderr: capture("discovery-revocation.stderr.bin")?,
        })
    } else {
        None
    };
    let gate = if ["revoke-preparation", "revoke-release"].contains(&key.scenario.as_str()) {
        use memcordon_readiness_verifier::LinuxPolicyGateEvidence;
        let mut capture = |name: &str| -> Result<String> {
            persist(
                name,
                &read_policy_observation_file(&directory.join(name), 16 * 1024 * 1024)?,
            )
        };
        Some(LinuxPolicyGateEvidence {
            prepared: capture("prepared.json")?,
            prepared_native: capture("prepared-native.json")?,
            retirement: capture("prepared-family-retirement.json")?,
            acknowledgment: capture("observer-ack-operation.json")?,
            revocation: capture("revocation.json")?,
            revocation_policy: capture("revocation.policy.json")?,
            revocation_invocation: capture("revocation.invocation.json")?,
            revocation_exit: capture("revocation.exit.json")?,
            revocation_stderr: capture("revocation.stderr.bin")?,
            release: if key.scenario == "revoke-release" {
                Some(capture("release-prepared.json")?)
            } else {
                None
            },
            release_ack: if key.scenario == "revoke-release" {
                Some(capture("release-observer-ack.json")?)
            } else {
                None
            },
        })
    } else {
        None
    };
    let evidence = LinuxPolicyRefusalEvidence {
        format: "memcordon.consumer-readiness.linux-policy-refusal".into(),
        revision: 1,
        key: key.clone(),
        run_id: identity.run_id.clone(),
        source_commit: identity.source_commit.clone(),
        source_tree_sha256: identity.source_tree_sha256.clone(),
        lease_id: owner["lease_id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| CiError::Message("original policy lease absent".into()))?
            .into(),
        baseline_registry,
        baseline_contract,
        baseline_activation,
        earlier_activations,
        discovery,
        gate,
        activation,
        activation_policy,
        activation_invocation,
        activation_exit,
        activation_stderr,
        restoration,
        restoration_policy,
        restoration_invocation,
        restoration_exit,
        restoration_stderr,
        requested_contract,
        provider_request,
        raw_result,
        invocation,
        frontend_invocation,
        frontend_exit,
        stdout,
        stderr,
        challenge,
        native_census,
        owner: owner_artifact,
    };
    persist("case-evidence.json", &serde_json::to_vec(&evidence)?)
}

pub(super) fn read_policy_observation_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() > limit
        || !matches!(before.uid(), 0 | 65533 | 65534)
        || before.mode() & 0o022 != 0
    {
        return Err(CiError::Message(
            "policy observation is not bounded exclusive native file custody".into(),
        ));
    }
    let mut bytes = vec![
        0;
        usize::try_from(before.len()).map_err(|_| CiError::Message(
            "policy observation length overflow".into()
        ))?
    ];
    file.read_exact_at(&mut bytes, 0)?;
    let named = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let stamp = |m: &std::fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.ctime(),
            m.ctime_nsec(),
            m.nlink(),
            m.uid(),
            m.mode(),
        )
    };
    if stamp(&before) != stamp(&file.metadata()?) || stamp(&before) != stamp(&named.metadata()?) {
        return Err(CiError::Message(
            "policy observation native inode changed during collection".into(),
        ));
    }
    let mut readback = vec![0; bytes.len()];
    named.read_exact_at(&mut readback, 0)?;
    if readback != bytes
        || stamp(&before) != stamp(&named.metadata()?)
        || stamp(&before) != stamp(&file.metadata()?)
    {
        return Err(CiError::Message(
            "policy observation named bytes changed during collection".into(),
        ));
    }
    Ok(bytes)
}

struct AdminSourceRetirement {
    path: PathBuf,
    parent: File,
    root: File,
    name: std::ffi::OsString,
    device: u64,
    inode: u64,
    unlinked: bool,
}
impl AdminSourceRetirement {
    fn acquire(path: &Path, device: u64, inode: u64) -> Result<Self> {
        use std::os::fd::AsFd;
        if !path.is_absolute() || device == 0 || inode == 0 {
            return Err(CiError::Message(
                "admin retirement requires original absolute native identity".into(),
            ));
        }
        let mut parent = File::open("/")?;
        let components = path.components().collect::<Vec<_>>();
        let name = path
            .file_name()
            .ok_or_else(|| CiError::Message("admin root leaf absent".into()))?
            .to_owned();
        for component in components
            .iter()
            .skip(1)
            .take(components.len().saturating_sub(2))
        {
            let std::path::Component::Normal(name) = component else {
                return Err(CiError::Message(
                    "admin root has noncanonical ancestry".into(),
                ));
            };
            let fd = rustix::fs::openat2(
                parent.as_fd(),
                *name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH | rustix::fs::ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|e| CiError::Message(e.to_string()))?;
            parent = File::from(fd);
            let metadata = parent.metadata()?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(CiError::Message(
                    "admin root ancestry changed custody".into(),
                ));
            }
        }
        let root = File::from(
            rustix::fs::openat2(
                parent.as_fd(),
                &name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_XDEV,
            )
            .map_err(|e| CiError::Message(e.to_string()))?,
        );
        let actual = root.metadata()?;
        if (actual.dev(), actual.ino()) != (device, inode)
            || actual.uid() != 0
            || actual.mode() & 0o022 != 0
        {
            return Err(CiError::Message(
                "admin root differs from original held creation identity".into(),
            ));
        }
        require_admin_named_inode(&parent, &name, &root)?;
        Ok(Self {
            path: path.to_owned(),
            parent,
            root,
            name,
            device,
            inode,
            unlinked: false,
        })
    }
}

/// Project a completed public execution and its actual native retirement. The
/// finite mechanism author supplies semantics separately; no facet is accepted
/// by this artifact builder.
pub fn completed_case_base(
    collection: &mut CompletedMixedCollection,
    images: &MixedImages,
    input: &InstalledMixedDriverInput<'_>,
    fixture_input: memcordon_readiness_verifier::FixtureInput,
    prefix: &str,
    semantic_path: &str,
) -> Result<memcordon_readiness_verifier::CaseEvidence> {
    use memcordon_readiness_verifier::{
        Artifact, CaseEvidence, NativeInvocation, NativeObservation, OutcomeOrigin,
        RetirementObservation,
    };
    let key = collection.persisted.key.clone();
    if input.work_deadline_unix_millis == 0
        || input.cleanup_deadline_unix_millis <= input.work_deadline_unix_millis
        || std::time::Instant::now() >= input.cleanup_deadline
    {
        return Err(CiError::Message(
            "completed base original cutoff is absent or exhausted".into(),
        ));
    }
    if fixture_input.key != key
        || fixture_input.run_id != input.identity.run_id
        || semantic_path != format!("{prefix}/semantic.json")
        || key.target != input.cell.target
        || key.channel.as_deref() != Some(input.cell.channel.as_str())
        || key.evidence_class != memcordon_readiness_verifier::EvidenceClass::InstalledProduct
        || collection.lease_id != input.lease_id
        || serde_json::to_value(&collection.persisted.identity)?
            != serde_json::to_value(&input.identity)?
    {
        return Err(CiError::Message(
            "completed base crosses finite key/run/semantic namespace".into(),
        ));
    }
    let memcordon_core::result_v2::MixedRuntimeOutcomeV2::Executed {
        admission,
        provider,
        execution,
        retirement,
        ..
    } = &collection.result.runtime.outcome
    else {
        return Err(CiError::Message(
            "completed base requires actual executed carrier".into(),
        ));
    };
    if provider != input.provider || execution.host_target.as_str() != key.target {
        return Err(CiError::Message(
            "completed base crosses selected provider/native target".into(),
        ));
    }
    use memcordon_core::result_v2::MixedOutcomeOriginV2;
    let origin = match execution.outcome_origin {
        MixedOutcomeOriginV2::NativeExit | MixedOutcomeOriginV2::NativeSignal => {
            OutcomeOrigin::Target
        }
        MixedOutcomeOriginV2::Deadline => OutcomeOrigin::Deadline,
        MixedOutcomeOriginV2::MemoryOom => OutcomeOrigin::Memory,
        MixedOutcomeOriginV2::ControlledCancellation => OutcomeOrigin::Interrupted,
        MixedOutcomeOriginV2::Revoked
            if key.family == "L-ID-03" && key.scenario == "revoke-running" =>
        {
            OutcomeOrigin::ProviderFailure
        }
        _ => {
            return Err(CiError::Message(
                "completed base requires a distinct provider-loss/revocation adapter".into(),
            ));
        }
    };
    let invocation: NativeInvocation =
        serde_json::from_value(decode_owned_resource_json(&read_owned_resource(
            &input.artifact_root.join(&collection.public_invocation.path),
            4 * 1024 * 1024,
        )?)?)?;
    let captured = decode_owned_resource_json(&read_owned_resource(
        &input
            .artifact_root
            .join(format!("{prefix}/native-family-retirement.json")),
        4 * 1024 * 1024,
    )?)?;
    let raw_result = read_owned_resource(
        &input.artifact_root.join(format!("{prefix}/result.json")),
        4 * 1024 * 1024,
    )?;
    if decode_owned_resource_json(&raw_result)? != serde_json::to_value(&collection.result)? {
        return Err(CiError::Message(
            "completed carrier differs from retained raw result".into(),
        ));
    }
    let prepared_bytes = read_owned_resource(
        &input.artifact_root.join(format!("{prefix}/prepared.json")),
        4 * 1024 * 1024,
    )?;
    let prepared: memcordon_core::mixed_observation::MixedPreparedObservationV2 =
        serde_json::from_slice(&prepared_bytes)?;
    prepared.validate().map_err(CiError::Message)?;
    let prepared_native_bytes = read_owned_resource(
        &input
            .artifact_root
            .join(&collection.prepared_native_receipt.path),
        4 * 1024 * 1024,
    )?;
    let prepared_native = decode_owned_resource_json(&prepared_native_bytes)?;
    if prepared.provider != *input.provider
        || prepared.admission != *admission
        || prepared.target != execution.target
        || hex::encode(Sha256::digest(&prepared_native_bytes))
            != collection.prepared_native_receipt.sha256
        || prepared_native["format"] != "memcordon.linux-prepared-native-observation"
        || prepared_native["revision"] != 1
        || prepared_native["run_id"] != input.identity.run_id
        || prepared_native["attempt_id"] != admission.attempt_id.as_str()
        || prepared_native["prepared_sha256"] != hex::encode(Sha256::digest(&prepared_bytes))
        || prepared_native["held_before_authorization"] != true
        || prepared_native["target"]["process_id"] != execution.target.pid
        || prepared_native["target"]["birth"] != execution.target.birth
        || captured["format"] != "memcordon.linux-held-family-retirement"
        || captured["revision"] != 1
        || captured["run_id"] != input.identity.run_id
        || captured["lease_id"] != input.lease_id
        || captured["attempt_id"] != admission.attempt_id.as_str()
        || captured["target"]["pid"] != execution.target.pid
        || captured["target"]["birth"] != execution.target.birth
        || captured["target"]["retirement_observed"] != true
        || collection
            .held_processes
            .iter()
            .filter(|process| {
                process.pid == execution.target.pid
                    && process.birth == execution.target.birth
                    && process.retirement_observed
            })
            .count()
            != 1
    {
        return Err(CiError::Message(
            "completed base crosses actual prepared/held target/native retirement association"
                .into(),
        ));
    }
    let retirement_value = serde_json::to_value(retirement)?;
    let proved = |field: &str| retirement_value.get(field) == Some(&serde_json::Value::Bool(true));
    if captured["aggregate_empty"] != true
        || collection
            .held_processes
            .iter()
            .any(|process| !process.retirement_observed)
        || !collection.result.frontend.relay_drained
        || [
            "workload_empty",
            "init_reaped",
            "guardian_reaped",
            "relays_drained_and_closed",
            "namespace_references_closed",
            "root_references_closed",
            "staging_removed",
            "account_quiescent",
            "reservation_retired",
        ]
        .iter()
        .any(|field| !proved(field))
    {
        return Err(CiError::Message(
            "completed base lacks actual capture/provider/native family retirement".into(),
        ));
    }
    let challenge = read_owned_resource(
        &input.artifact_root.join(format!("{prefix}/challenge.bin")),
        32,
    )?;
    if challenge.len() != 32
        || fixture_input.challenge_sha256 != hex::encode(Sha256::digest(&challenge))
    {
        return Err(CiError::Message("completed base challenge differs".into()));
    }
    let fixture = read_owned_resource(
        &images.runtime_source.join("bin/owned-readiness"),
        512 * 1024 * 1024,
    )?;
    if hex::encode(Sha256::digest(&fixture)) != images.fixture_sha256 {
        return Err(CiError::Message(
            "completed selected fixture image changed".into(),
        ));
    }
    let source = serde_json::to_vec(
        &serde_json::json!({"module":super::artifacts::read_file(&input.workspace.join("crates/memcordon-cli/src/bin/consumer_readiness_linux/mod.rs"))?,"entrypoint":super::artifacts::read_file(&input.workspace.join("crates/memcordon-cli/src/bin/memcordon-linux-readiness-fixture.rs"))?}),
    )?;
    let request = collection
        .persisted
        .artifacts
        .iter()
        .find(|artifact| artifact.path == format!("{prefix}/provider-request.json"))
        .cloned()
        .ok_or_else(|| CiError::Message("completed original provider request absent".into()))?;
    let agent = read_owned_resource(
        Path::new("/usr/libexec/memcordon-sealed-agent"),
        512 * 1024 * 1024,
    )?;
    let native = NativeObservation {
        format: "memcordon.consumer-readiness.native".into(),
        revision: 1,
        run_id: input.identity.run_id.clone(),
        lease_id: Some(collection.lease_id.clone()),
        target: key.target.clone(),
        executable_sha256: invocation.executable_sha256,
        invocation_sha256: invocation.association_sha256,
        execution_invocation_sha256: collection
            .effective_invocation
            .as_ref()
            .map(|artifact| artifact.sha256.clone()),
        request_sha256: Some(request.sha256.clone()),
        provider_sha256: Some(hex::encode(Sha256::digest(agent))),
        provider_generation: Some(provider.generation.as_str().into()),
        runtime_manifest_sha256: Some(String::from(provider.runtime_manifest_sha256.clone())),
        attempt_id: Some(admission.attempt_id.as_str().into()),
        root_pid: Some(execution.target.pid),
        root_birth: Some(execution.target.birth),
        attempt_nonce: Some(
            serde_json::to_value(admission.admission_nonce)?
                .as_str()
                .ok_or_else(|| CiError::Message("completed nonce encoding differs".into()))?
                .into(),
        ),
        held_processes: collection.held_processes.clone(),
        frontend_status: collection.frontend_status,
        origin,
        target_status: (execution.native_wait_status & 0x7f == 0)
            .then_some((execution.native_wait_status >> 8) & 0xff),
        authenticated_provider_exchange: true,
        relay_complete: collection.result.frontend.relay_drained,
        result_named_identity_verified: true,
        result_readback_verified: true,
        application_stage: None,
    };
    let retired = RetirementObservation {
        format: "memcordon.consumer-readiness.retirement".into(),
        revision: 1,
        run_id: input.identity.run_id.clone(),
        attempt_id: native.attempt_id.clone(),
        root_pid: native.root_pid,
        root_birth: native.root_birth,
        target_reaped_or_absent: captured["target"]["retirement_observed"] == true,
        aggregate_empty: proved("workload_empty"),
        relays_retired: proved("relays_drained_and_closed"),
        guardian_retired: proved("guardian_reaped"),
        native_handles_closed: proved("namespace_references_closed")
            && proved("root_references_closed"),
        independently_observed: captured["aggregate_empty"] == true,
        namespace_init_reaped: Some(proved("init_reaped")),
        private_root_closed: Some(proved("root_references_closed") && proved("staging_removed")),
        exports_finalized: Some(
            collection
                .persisted
                .artifacts
                .iter()
                .any(|artifact| artifact.path == collection.export_receipt.path),
        ),
        account_reservation_retired: Some(
            proved("account_quiescent") && proved("reservation_retired"),
        ),
        final_job_handles_closed: None,
        active_processes_zero: None,
        outstanding: Vec::new(),
        failed_operations: Vec::new(),
    };
    let mut persist = |name: &str, bytes: &[u8]| -> Result<Artifact> {
        if std::time::Instant::now() >= input.cleanup_deadline {
            return Err(CiError::Message(
                "completed base publication exceeded original cleanup cutoff".into(),
            ));
        }
        let path = format!("{prefix}/{name}");
        retain(&input.artifact_root.join(&path), bytes)?;
        let artifact = Artifact {
            path,
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        collection.persisted.artifacts.push(artifact.clone());
        Ok(artifact)
    };
    let fixture = persist("fixture.bin", &fixture)?;
    let source = persist("fixture-source.json", &source)?;
    let descriptor = persist("fixture-input.json", &serde_json::to_vec(&fixture_input)?)?;
    let native = persist("native-observation.json", &serde_json::to_vec(&native)?)?;
    let retired = persist("retirement.json", &serde_json::to_vec(&retired)?)?;
    if std::time::Instant::now() >= input.cleanup_deadline {
        return Err(CiError::Message(
            "completed base completion exceeded original cleanup cutoff".into(),
        ));
    }
    Ok(CaseEvidence {
        format: "memcordon.consumer-readiness.case".into(),
        revision: 1,
        key,
        run_id: input.identity.run_id.clone(),
        source_commit: input.identity.source_commit.clone(),
        source_tree_sha256: input.identity.source_tree_sha256.clone(),
        lease_id: Some(collection.lease_id.clone()),
        fixture: fixture.path,
        fixture_source: source.path,
        fixture_sha256: fixture.sha256,
        fixture_source_sha256: source.sha256,
        input: descriptor.path,
        input_sha256: descriptor.sha256,
        invocation: collection.public_invocation.path.clone(),
        request: Some(format!("{prefix}/contract.json")),
        raw_result: Some(format!("{prefix}/result.json")),
        provider_request: Some(request.path),
        authenticated_terminal: None,
        windows_loss: None,
        execution_invocation: collection
            .effective_invocation
            .as_ref()
            .map(|artifact| artifact.path.clone()),
        execution_environment: collection
            .effective_environment
            .as_ref()
            .map(|artifact| artifact.path.clone()),
        transcript: None,
        inventory: None,
        qualification: None,
        export_receipt: Some(collection.export_receipt.path.clone()),
        prepared_observation: collection
            .persisted
            .artifacts
            .iter()
            .find(|artifact| artifact.path == format!("{prefix}/prepared.json"))
            .map(|artifact| artifact.path.clone()),
        prepared_native_receipt: Some(collection.prepared_native_receipt.path.clone()),
        native_observation: native.path,
        retirement: retired.path,
        semantic_observation: semantic_path.into(),
        component_recipe_id: None,
    })
}

fn archive_cross_attempt_sources(
    directory: &Path,
    root: &Path,
    artifacts: &mut Vec<memcordon_readiness_verifier::Artifact>,
) -> Result<()> {
    let mut pending = vec![directory.to_path_buf()];
    let mut count = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            count += 1;
            if count > 4096 {
                return Err(CiError::Message(
                    "cross original source archive exceeds finite bound".into(),
                ));
            }
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                let source = entry.path();
                let path = source
                    .strip_prefix(root)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .to_str()
                    .ok_or_else(|| {
                        CiError::Message("cross original archive path is not UTF-8".into())
                    })?
                    .to_owned();
                let bytes = read_owned_resource(&source, 64 * 1024 * 1024)?;
                let artifact = memcordon_readiness_verifier::Artifact {
                    path,
                    length: bytes.len() as u64,
                    sha256: hex::encode(Sha256::digest(&bytes)),
                };
                if let Some(previous) = artifacts
                    .iter()
                    .find(|existing| existing.path == artifact.path)
                {
                    if previous.length != artifact.length || previous.sha256 != artifact.sha256 {
                        return Err(CiError::Message(
                            "cross original archive artifact changed".into(),
                        ));
                    }
                } else {
                    artifacts.push(artifact);
                }
            } else {
                return Err(CiError::Message(
                    "cross original archive contains nonregular source".into(),
                ));
            }
        }
    }
    Ok(())
}

fn normalize_completed_case(
    collection: &mut CompletedMixedCollection,
    images: &MixedImages,
    input: &InstalledMixedDriverInput<'_>,
    arguments: &[std::ffi::OsString],
    prefix: &str,
) -> Result<()> {
    use memcordon_readiness_verifier::{
        Artifact, BehaviorArtifact, ByteComparison, CaseEvidence, FixtureBehavior, FixtureInput,
        NativeArguments, NativeInvocation, NativeObservation, OperationObservation, OutcomeOrigin,
        RetirementObservation, SemanticObservation,
    };
    use std::os::unix::ffi::OsStrExt;
    let key = collection.persisted.key.clone();
    // Each additional family needs its own factual semantic adapter. These
    // selected families have exact native exit and byte-vector contracts.
    let status = key.family == "C-STATUS"
        && [
            "zero", "nonzero", "exit-123", "exit-124", "exit-125", "exit-126", "exit-127",
        ]
        .contains(&key.scenario.as_str());
    let current_result = key.family == "C-PARSER" && key.scenario == "valid-current-result";
    let admission_positive = key.family == "C-ADMISSION" && key.scenario == "positive";
    let cooperation = key.family == "L-MIX-04" && key.scenario == "cooperation";
    let endpoint_mismatch = key.family == "L-MIX-02" && key.scenario == "endpoint-mismatch";
    let build = (key.family == "L-MIX-01" && key.scenario == "joint-build-tcp-unix-http")
        || (key.family == "L-IMG-03"
            && ["dynamic-rust-build-and-exec", "image-only-entrypoint"]
                .contains(&key.scenario.as_str()));
    let bytes = ["C-IO", "L-MIX-05"].contains(&key.family.as_str())
        && ["binary-streams", "empty-input"].contains(&key.scenario.as_str());
    let root_first = (key.family == "L-LIFE-01"
        && key.scenario == "root-first-resource-descendant")
        || (key.family == "C-LIFETIME" && key.scenario == "root-first");
    let host_denial = (key.family == "L-ISO-01"
        && ["host-tcp", "nonloopback"].contains(&key.scenario.as_str()))
        || (key.family == "L-ISO-03"
            && ["host-abstract", "other-attempt-abstract"].contains(&key.scenario.as_str()));
    let host_path_denial = key.family == "L-ISO-02"
        && ["host-run-socket", "host-temp-socket"].contains(&key.scenario.as_str());
    let rights = key.family == "L-MIX-03" && key.scenario == "listener-and-file-transfer";
    let native_argv = key.family == "C-IO" && key.scenario == "native-argv";
    let binary_file = key.family == "C-IO" && key.scenario == "binary-file";
    let empty_message =
        ["C-IO", "L-MIX-05"].contains(&key.family.as_str()) && key.scenario == "empty-message";
    let own_abstract = key.family == "L-ISO-03" && key.scenario == "own-abstract-positive";
    let descriptor_isolation = key.family == "L-ISO-05"
        && ["stdio-host-socket", "extra-host-fd"].contains(&key.scenario.as_str());
    let outside = key.family == "L-ISO-04"
        && [
            "symlink",
            "dotdot",
            "proc-root",
            "proc-cwd",
            "proc-fd",
            "hardlink",
            "opath",
            "mount-alias",
        ]
        .contains(&key.scenario.as_str());
    let authority = (key.family == "L-ISO-01"
        && ["ipv6", "udp", "raw", "packet", "netlink"].contains(&key.scenario.as_str()))
        || (key.family == "L-ISO-05"
            && ["pidfd-getfd", "ptrace", "namespace-entry"].contains(&key.scenario.as_str()));
    if !status
        && !current_result
        && !admission_positive
        && !cooperation
        && !endpoint_mismatch
        && !build
        && !bytes
        && !root_first
        && !host_denial
        && !host_path_denial
        && !rights
        && !native_argv
        && !binary_file
        && !empty_message
        && !own_abstract
        && !descriptor_isolation
        && !authority
        && !outside
    {
        return Ok(());
    }
    let memcordon_core::result_v2::MixedRuntimeOutcomeV2::Executed {
        admission,
        provider,
        execution,
        retirement,
        ..
    } = &collection.result.runtime.outcome
    else {
        return Err(CiError::Message(
            "normalized executed row has no native execution".into(),
        ));
    };
    if serde_json::to_value(execution.outcome_origin)?
        != serde_json::Value::String("native-exit".into())
        || execution.native_wait_status & 0x7f != 0
    {
        return Err(CiError::Message(
            "natural status/byte row has a different native cause".into(),
        ));
    }
    let actual_invocation: NativeInvocation =
        serde_json::from_value(decode_owned_resource_json(&read_owned_resource(
            &input.artifact_root.join(&collection.public_invocation.path),
            4 * 1024 * 1024,
        )?)?)?;
    let captured_retirement = decode_owned_resource_json(&read_owned_resource(
        &input
            .artifact_root
            .join(format!("{prefix}/native-family-retirement.json")),
        4 * 1024 * 1024,
    )?)?;
    if captured_retirement.get("aggregate_empty") != Some(&serde_json::Value::Bool(true))
        || collection
            .held_processes
            .iter()
            .any(|process| !process.retirement_observed)
    {
        return Err(CiError::Message(
            "normalized row has no completed independent native family observation".into(),
        ));
    }
    let retirement_value = serde_json::to_value(retirement)?;
    let proved = |field: &str| retirement_value.get(field) == Some(&serde_json::Value::Bool(true));
    if [
        "workload_empty",
        "init_reaped",
        "guardian_reaped",
        "relays_drained_and_closed",
        "namespace_references_closed",
        "root_references_closed",
        "staging_removed",
        "account_quiescent",
        "reservation_retired",
    ]
    .iter()
    .any(|field| !proved(field))
    {
        return Err(CiError::Message(
            "actual native provider retirement is incomplete".into(),
        ));
    }
    let fixture = read_owned_resource(
        &images.runtime_source.join("bin/owned-readiness"),
        512 * 1024 * 1024,
    )?;
    if hex::encode(Sha256::digest(&fixture)) != images.fixture_sha256 {
        return Err(CiError::Message(
            "selected native fixture image measurement changed".into(),
        ));
    }
    let fixture_source = serde_json::to_vec(&serde_json::json!({
        "module":super::artifacts::read_file(&input.workspace.join("crates/memcordon-cli/src/bin/consumer_readiness_linux/mod.rs"))?,
        "entrypoint":super::artifacts::read_file(&input.workspace.join("crates/memcordon-cli/src/bin/memcordon-linux-readiness-fixture.rs"))?,
    }))?;
    let mut added = Vec::new();
    let mut persist = |name: &str, bytes: &[u8]| -> Result<Artifact> {
        let relative = format!("{prefix}/{name}");
        retain(&input.artifact_root.join(&relative), bytes)?;
        let artifact = Artifact {
            path: relative,
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        added.push(artifact.clone());
        Ok(artifact)
    };
    let fixture_artifact = persist("fixture.bin", &fixture)?;
    let source_artifact = persist("fixture-source.json", &fixture_source)?;
    let challenge_path = format!("{prefix}/challenge.bin");
    let challenge = read_owned_resource(&input.artifact_root.join(&challenge_path), 32)?;
    let build_manifest = if build {
        Some(persist(
            "measured-build-inputs.json",
            &serde_json::to_vec(
                &serde_json::json!({"runtime":images.runtime,"input":images.input}),
            )?,
        )?)
    } else {
        None
    };
    let vector: Vec<u8> = if ["empty-input", "empty-message"].contains(&key.scenario.as_str()) {
        Vec::new()
    } else {
        (u8::MIN..=u8::MAX).collect()
    };
    let fixture_input = FixtureInput {
        format: "memcordon.consumer-readiness.input".into(),
        revision: 1,
        run_id: input.identity.run_id.clone(),
        key: key.clone(),
        challenge_sha256: hex::encode(Sha256::digest(&challenge)),
        binary: vector.clone(),
        target_argv: NativeArguments::UnixBytes(
            arguments
                .iter()
                .map(|argument| argument.as_bytes().to_vec())
                .collect(),
        ),
        deadline_millis: None,
        memory_bytes: None,
        toolchain_identity: build_manifest
            .as_ref()
            .map(|artifact| artifact.sha256.clone()),
    };
    let input_artifact = persist("fixture-input.json", &serde_json::to_vec(&fixture_input)?)?;
    let agent = read_owned_resource(
        Path::new("/usr/libexec/memcordon-sealed-agent"),
        512 * 1024 * 1024,
    )?;
    let request_artifact = collection
        .persisted
        .artifacts
        .iter()
        .find(|artifact| artifact.path == format!("{prefix}/provider-request.json"))
        .ok_or_else(|| CiError::Message("actual request bytes absent".into()))?;
    let native = NativeObservation {
        format: "memcordon.consumer-readiness.native".into(),
        revision: 1,
        run_id: input.identity.run_id.clone(),
        lease_id: Some(collection.lease_id.clone()),
        target: key.target.clone(),
        executable_sha256: actual_invocation.executable_sha256.clone(),
        invocation_sha256: actual_invocation.association_sha256.clone(),
        execution_invocation_sha256: collection
            .effective_invocation
            .as_ref()
            .map(|artifact| artifact.sha256.clone()),
        request_sha256: Some(request_artifact.sha256.clone()),
        provider_sha256: Some(hex::encode(Sha256::digest(agent))),
        provider_generation: Some(provider.generation.as_str().into()),
        runtime_manifest_sha256: Some(String::from(provider.runtime_manifest_sha256.clone())),
        attempt_id: Some(admission.attempt_id.as_str().into()),
        root_pid: Some(execution.target.pid),
        root_birth: Some(execution.target.birth),
        attempt_nonce: Some(
            serde_json::to_value(admission.admission_nonce)?
                .as_str()
                .ok_or_else(|| CiError::Message("actual admission nonce encoding differs".into()))?
                .into(),
        ),
        held_processes: collection.held_processes.clone(),
        frontend_status: collection.frontend_status,
        origin: if endpoint_mismatch {
            OutcomeOrigin::ApplicationRefusal
        } else {
            OutcomeOrigin::Target
        },
        target_status: Some((execution.native_wait_status >> 8) & 0xff),
        authenticated_provider_exchange: true,
        relay_complete: collection.result.frontend.relay_drained,
        result_named_identity_verified: true,
        result_readback_verified: true,
        application_stage: endpoint_mismatch.then(|| "endpoint-policy".into()),
    };
    let native_artifact = persist("native-observation.json", &serde_json::to_vec(&native)?)?;
    let retired = RetirementObservation {
        format: "memcordon.consumer-readiness.retirement".into(),
        revision: 1,
        run_id: input.identity.run_id.clone(),
        attempt_id: native.attempt_id.clone(),
        root_pid: native.root_pid,
        root_birth: native.root_birth,
        target_reaped_or_absent: captured_retirement["target"]["retirement_observed"] == true,
        aggregate_empty: proved("workload_empty"),
        relays_retired: proved("relays_drained_and_closed"),
        guardian_retired: proved("guardian_reaped"),
        native_handles_closed: proved("namespace_references_closed")
            && proved("root_references_closed"),
        independently_observed: captured_retirement["aggregate_empty"] == true,
        namespace_init_reaped: Some(proved("init_reaped")),
        private_root_closed: Some(proved("root_references_closed") && proved("staging_removed")),
        exports_finalized: Some(
            collection
                .persisted
                .artifacts
                .iter()
                .any(|artifact| artifact.path == collection.export_receipt.path),
        ),
        account_reservation_retired: Some(
            proved("account_quiescent") && proved("reservation_retired"),
        ),
        final_job_handles_closed: None,
        active_processes_zero: None,
        outstanding: Vec::new(),
        failed_operations: Vec::new(),
    };
    let retirement_artifact = persist("retirement.json", &serde_json::to_vec(&retired)?)?;
    let mut comparisons = Vec::new();
    if binary_file {
        let expected = persist("expected-binary-file.bin", &vector)?;
        comparisons.push(ByteComparison {
            role: "file".into(),
            actual: format!("{prefix}/exported/work/binary-file.bin"),
            expected: expected.path,
        });
    }
    if native_argv {
        let rows = collection
            .persisted
            .transcript
            .iter()
            .filter(|row| row.operation == "native-argv-observed")
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(CiError::Message(
                "actual native argv receipt cardinality differs".into(),
            ));
        }
        let observed: Vec<Vec<u8>> = serde_json::from_value(rows[0].observation["argv"].clone())?;
        let actual = persist(
            "native-argv.json",
            &serde_json::to_vec(&NativeArguments::UnixBytes(observed))?,
        )?;
        let expected = persist(
            "expected-native-argv.json",
            &serde_json::to_vec(&fixture_input.target_argv)?,
        )?;
        comparisons.push(ByteComparison {
            role: "native-argv".into(),
            actual: actual.path,
            expected: expected.path,
        });
    }
    if bytes {
        for role in ["stdout", "stderr"] {
            let expected = persist(&format!("expected-{role}.bin"), &vector)?;
            comparisons.push(ByteComparison {
                role: role.into(),
                actual: format!("{prefix}/{role}.bin"),
                expected: expected.path,
            });
        }
    }
    let mut operations = Vec::new();
    let mut behavior = None;
    let mut negative_probe = None;
    if descriptor_isolation {
        let rows = collection
            .persisted
            .transcript
            .iter()
            .filter(|row| row.operation == "native-descriptor-isolation")
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(CiError::Message(
                "actual native descriptor probe absent/repeated".into(),
            ));
        }
        let transcript = format!("{prefix}/stdout.bin");
        operations.push(OperationObservation {
            operation: "native-authority-probe".into(),
            observer: "owned-fixture-behavior".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            native_receipt: transcript.clone(),
        });
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: vec![BehaviorArtifact {
                role: "host-socket-descriptor".into(),
                path: format!("{prefix}/host-socket-descriptor-retired.json"),
            }],
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if outside {
        let rows = collection
            .persisted
            .transcript
            .iter()
            .filter(|row| row.operation == "native-outside-file-denied")
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(CiError::Message(
                "actual outside native pathname denial absent".into(),
            ));
        }
        let transcript = format!("{prefix}/stdout.bin");
        let errno = rows[0].observation["native_errno"]
            .as_i64()
            .ok_or_else(|| CiError::Message("outside native syscall errno absent".into()))?;
        negative_probe = Some(memcordon_readiness_verifier::NegativeProbe {
            stage: key.scenario.clone(),
            domain: "linux".into(),
            native_code: errno,
            receipt: transcript.clone(),
        });
        operations.push(OperationObservation {
            operation: "native-authority-probe".into(),
            observer: "owned-fixture-behavior".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            native_receipt: transcript.clone(),
        });
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: vec![BehaviorArtifact {
                role: "outside-file-canary".into(),
                path: format!("{prefix}/outside-file-canary.json"),
            }],
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if endpoint_mismatch {
        if native.target_status != Some(42) {
            return Err(CiError::Message(
                "actual application endpoint refusal did not exit42".into(),
            ));
        }
        let rows = collection
            .persisted
            .transcript
            .iter()
            .filter(|row| row.operation == "application-endpoint-mismatch")
            .collect::<Vec<_>>();
        if rows.len() != 1
            || rows[0].observation["application_status"] != 42
            || rows[0].observation["readiness_reached"] != false
        {
            return Err(CiError::Message(
                "actual endpoint policy refusal observation absent or substituted".into(),
            ));
        }
        let transcript = format!("{prefix}/stdout.bin");
        for operation in [
            "tcp-owned-listener",
            "second-reserved-listener",
            "application-endpoint-refusal",
        ] {
            operations.push(OperationObservation {
                operation: operation.into(),
                observer: "owned-fixture-behavior".into(),
                attempt_id: native.attempt_id.clone(),
                root_pid: native.root_pid,
                native_receipt: transcript.clone(),
            });
        }
        negative_probe = Some(memcordon_readiness_verifier::NegativeProbe {
            stage: key.scenario.clone(),
            domain: "application".into(),
            native_code: 42,
            receipt: transcript.clone(),
        });
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: vec![BehaviorArtifact {
                role: "native-endpoint-mismatch".into(),
                path: format!("{prefix}/native-endpoint-mismatch.json"),
            }],
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if cooperation {
        let rows = collection
            .persisted
            .transcript
            .iter()
            .filter(|row| row.operation == "same-attempt-cooperation-complete")
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(CiError::Message(
                "actual cooperation completion cardinality differs".into(),
            ));
        }
        let received: Vec<u8> =
            serde_json::from_value(rows[0].observation["server_received"].clone())?;
        let actual = persist("cooperation-received.bin", &received)?;
        let expected = persist(
            "expected-cooperation.bin",
            hex::encode(&challenge).as_bytes(),
        )?;
        comparisons.push(ByteComparison {
            role: "cooperation".into(),
            actual: actual.path.clone(),
            expected: expected.path,
        });
        let transcript = format!("{prefix}/stdout.bin");
        operations.push(OperationObservation {
            operation: "same-attempt-cooperation".into(),
            observer: "owned-fixture-behavior".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            native_receipt: transcript.clone(),
        });
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: vec![
                BehaviorArtifact {
                    role: "cooperation".into(),
                    path: actual.path,
                },
                BehaviorArtifact {
                    role: "native-retirement".into(),
                    path: format!("{prefix}/native-family-retirement.json"),
                },
            ],
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if current_result || admission_positive {
        let raw = collection
            .persisted
            .artifacts
            .iter()
            .find(|artifact| artifact.path == format!("{prefix}/result.json"))
            .ok_or_else(|| CiError::Message("actual current result artifact absent".into()))?;
        operations.push(OperationObservation {
            operation: if current_result {
                "strict-current-result-decoded"
            } else {
                "admission-granted"
            }
            .into(),
            observer: if current_result {
                "owned-current-result"
            } else {
                "owned-admission"
            }
            .into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            native_receipt: raw.path.clone(),
        });
    }
    if authority {
        let rows = collection
            .persisted
            .transcript
            .iter()
            .filter(|row| row.operation == "native-authority-denied")
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(CiError::Message(
                "actual selected authority denial cardinality differs".into(),
            ));
        }
        let code = rows[0].observation["native_errno"]
            .as_i64()
            .ok_or_else(|| CiError::Message("actual authority errno absent".into()))?;
        let transcript = format!("{prefix}/stdout.bin");
        negative_probe = Some(memcordon_readiness_verifier::NegativeProbe {
            stage: key.scenario.clone(),
            domain: "linux".into(),
            native_code: code,
            receipt: transcript.clone(),
        });
        operations.push(OperationObservation {
            operation: "native-authority-probe".into(),
            observer: "owned-fixture-behavior".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            native_receipt: transcript.clone(),
        });
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: Vec::new(),
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if own_abstract {
        let held = arguments
            .first()
            .is_some_and(|argument| argument == "own-abstract-held");
        let rows = collection
            .persisted
            .transcript
            .iter()
            .filter(|row| {
                row.operation
                    == if held {
                        "other-attempt-abstract-held"
                    } else {
                        "unix-abstract-round-trip"
                    }
            })
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(CiError::Message(
                "actual own abstract receipt cardinality differs".into(),
            ));
        }
        let received: Vec<u8> = serde_json::from_value(rows[0].observation["bytes"].clone())?;
        let actual = persist("received-unix-abstract.bin", &received)?;
        let expected = persist("expected-unix-abstract.bin", b"abstract-unix-readiness")?;
        comparisons.push(ByteComparison {
            role: "unix-abstract".into(),
            actual: actual.path.clone(),
            expected: expected.path,
        });
        let transcript = format!("{prefix}/stdout.bin");
        operations.push(OperationObservation {
            operation: "unix-abstract-exchange".into(),
            observer: "owned-fixture-behavior".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            native_receipt: transcript.clone(),
        });
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: vec![BehaviorArtifact {
                role: "unix-abstract".into(),
                path: actual.path,
            }],
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if empty_message {
        let rows = collection
            .persisted
            .transcript
            .iter()
            .filter(|row| row.operation == "empty-message-exchanged")
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(CiError::Message(
                "actual empty message receipt cardinality differs".into(),
            ));
        }
        let payload: Vec<u8> = serde_json::from_value(rows[0].observation["payload"].clone())?;
        let actual = persist("received-message.bin", &payload)?;
        let expected = persist("expected-message.bin", &[])?;
        comparisons.push(ByteComparison {
            role: "message".into(),
            actual: actual.path.clone(),
            expected: expected.path,
        });
        let transcript = format!("{prefix}/stdout.bin");
        operations.push(OperationObservation {
            operation: "empty-message-exchanged".into(),
            observer: "owned-fixture-behavior".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            native_receipt: transcript.clone(),
        });
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: vec![BehaviorArtifact {
                role: "message".into(),
                path: actual.path,
            }],
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if native_argv {
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript: format!("{prefix}/stdout.bin"),
            expected_token: None,
            peer_artifacts: vec![BehaviorArtifact {
                role: "native-argv".into(),
                path: format!("{prefix}/native-argv.json"),
            }],
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if rights || build {
        let rows = collection
            .persisted
            .transcript
            .iter()
            .filter(|row| row.operation == "scm-rights-regular-and-listener")
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err(CiError::Message(
                "descriptor transfer actual receipt cardinality differs".into(),
            ));
        }
        let transcript = format!("{prefix}/stdout.bin");
        let mut peers = Vec::new();
        for (role, field, expected) in [
            (
                "transferred-file",
                "file_bytes",
                b"descriptor-readiness".as_slice(),
            ),
            ("tcp", "network_bytes", b"rights-listener".as_slice()),
        ] {
            let actual: Vec<u8> = serde_json::from_value(rows[0].observation[field].clone())?;
            let product = persist(&format!("received-{role}.bin"), &actual)?;
            let expected = persist(&format!("expected-{role}.bin"), expected)?;
            comparisons.push(ByteComparison {
                role: role.into(),
                actual: product.path.clone(),
                expected: expected.path,
            });
            peers.push(BehaviorArtifact {
                role: role.into(),
                path: product.path,
            });
        }
        for operation in ["scm-rights-listener", "scm-rights-private-file"] {
            operations.push(OperationObservation {
                operation: operation.into(),
                observer: "owned-fixture-behavior".into(),
                attempt_id: native.attempt_id.clone(),
                root_pid: native.root_pid,
                native_receipt: transcript.clone(),
            });
        }
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: peers,
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
        if key.family == "L-IMG-03" && key.scenario == "image-only-entrypoint" {
            for operation in ["host-entrypoint-absent", "image-entrypoint-executed"] {
                operations.push(OperationObservation {
                    operation: operation.into(),
                    observer: "owned-image-entrypoint".into(),
                    attempt_id: native.attempt_id.clone(),
                    root_pid: native.root_pid,
                    native_receipt: format!("{prefix}/image-entrypoint.json"),
                });
            }
        }
    }
    if build {
        let transcript = format!("{prefix}/stdout.bin");
        let row =
            |operation: &str| -> Result<&crate::linux_consumer_readiness::LinuxTranscriptRow> {
                let rows = collection
                    .persisted
                    .transcript
                    .iter()
                    .filter(|row| row.operation == operation)
                    .collect::<Vec<_>>();
                if rows.len() != 1 {
                    return Err(CiError::Message(format!(
                        "actual build {operation} receipt cardinality differs"
                    )));
                }
                Ok(rows[0])
            };
        let mut peers = behavior
            .take()
            .expect("build SCM behavior retained")
            .peer_artifacts;
        for (role, operation, field, expected) in [
            (
                "http",
                "http-round-trip",
                "request",
                b"GET /readiness HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    .as_slice(),
            ),
            (
                "http-response",
                "http-round-trip",
                "response",
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreadiness"
                    .as_slice(),
            ),
            (
                "unix-path",
                "unix-path-round-trip",
                "bytes",
                b"path-unix-readiness".as_slice(),
            ),
            (
                "unix-abstract",
                "unix-abstract-round-trip",
                "bytes",
                b"abstract-unix-readiness".as_slice(),
            ),
            (
                "unix-pair",
                "unix-stream-pair-round-trip",
                "bytes",
                b"R".as_slice(),
            ),
        ] {
            let actual: Vec<u8> =
                serde_json::from_value(row(operation)?.observation[field].clone())?;
            let artifact = persist(&format!("received-build-{role}.bin"), &actual)?;
            let expected = persist(&format!("expected-build-{role}.bin"), expected)?;
            comparisons.push(ByteComparison {
                role: role.into(),
                actual: artifact.path.clone(),
                expected: expected.path,
            });
            peers.push(BehaviorArtifact {
                role: role.into(),
                path: artifact.path,
            });
        }
        let expected = persist("expected-compiled-child.bin", &vector)?;
        comparisons.push(ByteComparison {
            role: "compiled-child".into(),
            actual: format!("{prefix}/exported/work/generated-readiness-artifact.bin"),
            expected: expected.path,
        });
        for (role, name) in [
            ("generated-created", "generated-child-created.json"),
            ("generated-retired", "generated-child-retired.json"),
            ("generated-executable", "generated-child-executable.bin"),
        ] {
            peers.push(BehaviorArtifact {
                role: role.into(),
                path: format!("{prefix}/exported/work/{name}"),
            });
        }
        for (role, name) in [
            ("native-compiler-live", "native-offline-compiler-live.json"),
            ("native-generated-live", "native-generated-child-live.json"),
        ] {
            peers.push(BehaviorArtifact {
                role: role.into(),
                path: format!("{prefix}/{name}"),
            });
        }
        peers.push(BehaviorArtifact {
            role: "toolchain-inputs".into(),
            path: build_manifest
                .as_ref()
                .expect("measured manifest")
                .path
                .clone(),
        });
        peers.push(BehaviorArtifact {
            role: "build-request".into(),
            path: format!("{prefix}/contract.json"),
        });
        for relative in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "src/main.rs",
            "tests/generated_child.rs",
        ] {
            let bytes = read_owned_resource(
                &images.input_source.join("owned-source").join(relative),
                4 * 1024 * 1024,
            )?;
            let artifact = persist(&format!("locked-source/{relative}"), &bytes)?;
            peers.push(BehaviorArtifact {
                role: format!("locked-source-{relative}"),
                path: artifact.path,
            });
        }
        for operation in [
            "tcp-owned-listener",
            "tcp-conflicting-bind",
            "http-exchange",
            "unix-path-exchange",
            "unix-abstract-exchange",
            "unix-stream-pair",
            "locked-rust-compile",
            "compiled-tests",
            "generated-executable",
        ] {
            operations.push(OperationObservation {
                operation: operation.into(),
                observer: "owned-fixture-behavior".into(),
                attempt_id: native.attempt_id.clone(),
                root_pid: native.root_pid,
                native_receipt: transcript.clone(),
            });
        }
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: peers,
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if host_path_denial {
        let transcript = format!("{prefix}/stdout.bin");
        let observed = collection
            .persisted
            .transcript
            .iter()
            .filter(|row| row.operation == "forbidden-unix-path-denied")
            .collect::<Vec<_>>();
        if observed.len() != 1 {
            return Err(CiError::Message(
                "host Unix socket probe did not retain exactly one native denial".into(),
            ));
        }
        let code = observed[0].observation["native_errno"]
            .as_i64()
            .ok_or_else(|| CiError::Message("host Unix socket native denial absent".into()))?;
        negative_probe = Some(memcordon_readiness_verifier::NegativeProbe {
            stage: key.scenario.clone(),
            domain: "linux".into(),
            native_code: code,
            receipt: transcript.clone(),
        });
        operations.push(OperationObservation {
            operation: "native-authority-probe".into(),
            observer: "owned-fixture-behavior".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            native_receipt: transcript.clone(),
        });
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: vec![
                BehaviorArtifact {
                    role: "host-path-socket-canary".into(),
                    path: format!("{prefix}/host-path-socket-canary.json"),
                },
                BehaviorArtifact {
                    role: "host-path-socket-intent".into(),
                    path: format!("{prefix}/host-path-socket-intent.json"),
                },
                BehaviorArtifact {
                    role: "host-path-socket-allocation".into(),
                    path: format!("{prefix}/host-path-socket-allocation.json"),
                },
            ],
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if host_denial {
        let transcript = format!("{prefix}/stdout.bin");
        let expected = if key.family == "L-ISO-01" {
            "forbidden-tcp-denied"
        } else {
            "forbidden-abstract-denied"
        };
        let rows = &collection.persisted.transcript;
        let observed = rows
            .iter()
            .filter(|row| row.operation == expected)
            .collect::<Vec<_>>();
        if observed.len() != 1 {
            return Err(CiError::Message(
                "host probe did not publish exactly one actual native denial".into(),
            ));
        }
        let code = observed[0].observation["native_errno"]
            .as_i64()
            .ok_or_else(|| CiError::Message("actual host probe errno absent".into()))?;
        negative_probe = Some(memcordon_readiness_verifier::NegativeProbe {
            stage: key.scenario.clone(),
            domain: "linux".into(),
            native_code: code,
            receipt: transcript.clone(),
        });
        operations.push(OperationObservation {
            operation: "native-authority-probe".into(),
            observer: "owned-fixture-behavior".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            native_receipt: transcript.clone(),
        });
        let role = if key.family == "L-ISO-01" {
            "host-tcp-canary"
        } else if key.scenario == "other-attempt-abstract" {
            "other-attempt-abstract-canary"
        } else {
            "host-abstract-canary"
        };
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: vec![BehaviorArtifact {
                role: role.into(),
                path: format!("{prefix}/{role}.json"),
            }],
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    if root_first {
        let expected = persist("expected-descendant.bin", &vector)?;
        comparisons.push(ByteComparison {
            role: "descendant".into(),
            actual: format!("{prefix}/exported/work/orphan-descendant.bin"),
            expected: expected.path,
        });
        let transcript = format!("{prefix}/stdout.bin");
        for operation in [
            "held-descendant-identity",
            "descendant-natural-completion",
            "root-exited-before-held-descendant",
        ] {
            operations.push(OperationObservation {
                operation: operation.into(),
                observer: "owned-fixture-behavior".into(),
                attempt_id: native.attempt_id.clone(),
                root_pid: native.root_pid,
                native_receipt: transcript.clone(),
            });
        }
        behavior = Some(FixtureBehavior {
            descriptor: input_artifact.path.clone(),
            transcript,
            expected_token: None,
            peer_artifacts: vec![
                BehaviorArtifact {
                    role: "orphan-completion".into(),
                    path: format!("{prefix}/exported/work/orphan-completion.json"),
                },
                BehaviorArtifact {
                    role: "native-retirement".into(),
                    path: format!("{prefix}/native-family-retirement.json"),
                },
            ],
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        });
    }
    let semantic = SemanticObservation {
        format: "memcordon.consumer-readiness.semantic".into(),
        revision: 1,
        run_id: input.identity.run_id.clone(),
        key: key.clone(),
        challenge: challenge_path,
        operations,
        comparisons,
        counters: BTreeMap::new(),
        negative_probe,
        component_test: None,
        component_actors: None,
        windows_capacity: None,
        windows_refusal: None,
        fixture_behavior: behavior,
    };
    let semantic_artifact = persist("semantic.json", &serde_json::to_vec(&semantic)?)?;
    let evidence = CaseEvidence {
        format: "memcordon.consumer-readiness.case".into(),
        revision: 1,
        key,
        run_id: input.identity.run_id.clone(),
        source_commit: input.identity.source_commit.clone(),
        source_tree_sha256: input.identity.source_tree_sha256.clone(),
        lease_id: Some(collection.lease_id.clone()),
        fixture: fixture_artifact.path,
        fixture_source: source_artifact.path,
        fixture_sha256: fixture_artifact.sha256,
        fixture_source_sha256: source_artifact.sha256,
        input: input_artifact.path,
        input_sha256: input_artifact.sha256,
        invocation: collection.public_invocation.path.clone(),
        request: Some(format!("{prefix}/contract.json")),
        raw_result: Some(format!("{prefix}/result.json")),
        provider_request: Some(request_artifact.path.clone()),
        authenticated_terminal: None,
        windows_loss: None,
        execution_invocation: collection
            .effective_invocation
            .as_ref()
            .map(|artifact| artifact.path.clone()),
        execution_environment: collection
            .effective_environment
            .as_ref()
            .map(|artifact| artifact.path.clone()),
        transcript: None,
        inventory: None,
        qualification: None,
        export_receipt: Some(collection.export_receipt.path.clone()),
        prepared_observation: collection
            .persisted
            .artifacts
            .iter()
            .find(|artifact| artifact.path == format!("{prefix}/prepared.json"))
            .map(|artifact| artifact.path.clone()),
        prepared_native_receipt: Some(collection.prepared_native_receipt.path.clone()),
        native_observation: native_artifact.path,
        retirement: retirement_artifact.path,
        semantic_observation: semantic_artifact.path,
        component_recipe_id: None,
    };
    persist("case-evidence.json", &serde_json::to_vec(&evidence)?)?;
    collection.persisted.artifacts.extend(added);
    Ok(())
}

fn require_protected_absence(path: &Path) -> Result<()> {
    use std::os::fd::AsFd;
    let mut parent = File::from(
        rustix::fs::open(
            "/",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            if matches!(component, std::path::Component::RootDir) {
                continue;
            }
            return Err(CiError::Message(
                "protected absence path not normalized".into(),
            ));
        };
        let metadata = parent.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "protected absence ancestor lacks root custody".into(),
            ));
        }
        match rustix::fs::openat(
            parent.as_fd(),
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ) {
            Ok(child) => parent = File::from(child),
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(error) => {
                return Err(CiError::Message(format!(
                    "protected absence unresolved: {error}"
                )));
            }
        }
    }
    Err(CiError::Message(
        "retired resource remains natively present".into(),
    ))
}

fn require_admin_named_inode(parent: &File, name: &std::ffi::OsStr, held: &File) -> Result<()> {
    use std::os::fd::AsFd;
    let actual = held.metadata()?;
    let named = rustix::fs::statat(parent.as_fd(), name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| CiError::Message(e.to_string()))?;
    if (actual.dev(), actual.ino()) != (named.st_dev, named.st_ino) {
        return Err(CiError::Message(
            "owned admin member named identity changed".into(),
        ));
    }
    Ok(())
}

pub(super) fn retire_admin_children(
    parent: &File,
    device: u64,
    deadline: std::time::Instant,
    depth: usize,
    count: &mut usize,
) -> Result<()> {
    use std::os::fd::{AsFd, AsRawFd};
    if depth > 128 {
        return Err(CiError::Message(
            "owned admin source tree depth exceeds finite bound".into(),
        ));
    }
    // /proc/self/fd resolves this process's retained native directory, never a
    // caller-provided symlink or a reopened pathname of a detached owner.
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd()))? {
        let name = entry?.file_name();
        *count += 1;
        if *count > 131_072 || std::time::Instant::now() >= deadline {
            return Err(CiError::Message(
                "owned admin retirement count/deadline exhausted".into(),
            ));
        }
        let held = File::from(
            rustix::fs::openat2(
                parent.as_fd(),
                &name,
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_XDEV,
            )
            .map_err(|e| CiError::Message(e.to_string()))?,
        );
        let metadata = held.metadata()?;
        if metadata.dev() != device || metadata.uid() != 0 || metadata.nlink() == 0 {
            return Err(CiError::Message(
                "admin member no longer belongs to owned native tree".into(),
            ));
        }
        let flags = if metadata.is_dir() {
            if metadata.mode() & 0o022 != 0 {
                return Err(CiError::Message(
                    "admin source directory is writable by another principal".into(),
                ));
            }
            let directory = File::from(
                rustix::fs::openat2(
                    parent.as_fd(),
                    &name,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                    rustix::fs::ResolveFlags::BENEATH
                        | rustix::fs::ResolveFlags::NO_SYMLINKS
                        | rustix::fs::ResolveFlags::NO_XDEV,
                )
                .map_err(|e| CiError::Message(e.to_string()))?,
            );
            if (directory.metadata()?.dev(), directory.metadata()?.ino())
                != (metadata.dev(), metadata.ino())
            {
                return Err(CiError::Message(
                    "admin directory changed before recursive native retirement".into(),
                ));
            }
            retire_admin_children(&directory, device, deadline, depth + 1, count)?;
            directory.sync_all()?;
            rustix::fs::AtFlags::REMOVEDIR
        } else {
            if (!metadata.is_file() && !metadata.file_type().is_symlink()) || metadata.nlink() != 1
            {
                return Err(CiError::Message(
                    "admin member is special or aliased; exact tree owner retained".into(),
                ));
            }
            rustix::fs::AtFlags::empty()
        };
        require_admin_named_inode(parent, &name, &held)?;
        rustix::fs::unlinkat(parent.as_fd(), &name, flags)
            .map_err(|e| CiError::Message(e.to_string()))?;
        if held.metadata()?.nlink() != 0 {
            return Err(CiError::Message(
                "admin member remains linked after owned unlink".into(),
            ));
        }
        parent.sync_all()?;
    }
    parent.sync_all()?;
    Ok(())
}

/// Source-controlled recipes for the already implemented native fixture
/// modes. Unlisted manifest rows remain missing until their distinct driver is
/// implemented; this list never narrows the independent required inventory.
pub fn owned_fixture_recipes(cell: &ProductKey) -> Result<Vec<InstalledMixedRecipe>> {
    use memcordon_core::workload_contract_v3::{
        DeniedOperationV3 as D, LocalPortV3, PrivatePeerV3, RequirementV3 as R,
    };
    use memcordon_readiness_verifier::{CaseKey, EvidenceClass};
    let tcp = R::TcpListener {
        id: id("tcp")?,
        local_port: LocalPortV3::KernelAssigned,
        peer: PrivatePeerV3::DynamicLoopbackWithinThisAttempt,
    };
    let unix = vec![
        R::UnixStreamPair { id: id("pair")? },
        R::UnixPathStream {
            id: id("pathname")?,
            writable_root: id("work")?,
        },
        R::UnixAbstractStream {
            id: id("abstract")?,
        },
        R::IntraAttemptDescriptorTransfer { id: id("rights")? },
    ];
    let mut result = Vec::new();
    let mut add = |family: &str,
                   scenario: &str,
                   mode: &str,
                   args: Vec<std::ffi::OsString>,
                   requirements: Vec<R>,
                   outputs: Vec<RootRelativePath>,
                   deadline: &str| {
        result.push(InstalledMixedRecipe {
            key: CaseKey {
                target: cell.target.clone(),
                channel: Some(cell.channel.clone()),
                evidence_class: EvidenceClass::InstalledProduct,
                family: family.into(),
                scenario: scenario.into(),
            },
            mode: mode.into(),
            arguments: args,
            requirements,
            output_files: outputs,
            memory: "+2GiB".into(),
            product_deadline: format!("+{deadline}").into(),
            observation_limit: Duration::from_secs(600),
        });
    };
    let mut joint = vec![tcp.clone()];
    joint.extend(unix.clone());
    joint.push(R::GeneratedExecutable {
        id: id("generated")?,
        writable_root: id("work")?,
    });
    let build_args = vec![
        "/work",
        "/toolchain/bin/cargo",
        "/toolchain/bin/rustc",
        "/usr/bin/cc",
        "/owned-source/Cargo.toml",
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .collect::<Vec<_>>();
    let exports = [
        "generated-readiness-artifact.bin",
        "generated-child-executable.bin",
        "generated-child-created.json",
        "generated-child-retired.json",
    ]
    .iter()
    .map(|name| path(&Path::new("work").join(name)))
    .collect::<Result<Vec<_>>>()?;
    add(
        "L-MIX-01",
        "joint-build-tcp-unix-http",
        "joint",
        build_args.clone(),
        joint.clone(),
        exports.clone(),
        "300s",
    );
    add(
        "L-IMG-03",
        "dynamic-rust-build-and-exec",
        "joint",
        build_args.clone(),
        joint.clone(),
        exports.clone(),
        "300s",
    );
    add(
        "L-IMG-03",
        "image-only-entrypoint",
        "joint",
        build_args.clone(),
        joint.clone(),
        exports,
        "300s",
    );
    for scenario in ["deadline", "memory", "cancellation", "reserved-target-exit"] {
        add(
            "L-LIFE-03",
            scenario,
            "joint",
            build_args.clone(),
            joint.clone(),
            Vec::new(),
            "300s",
        );
    }
    for scenario in ["deadline", "memory"] {
        add(
            "C-STATUS",
            scenario,
            "population-deadline",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "300s",
        );
    }
    add(
        "L-MIX-02",
        "endpoint-mismatch",
        "endpoint-mismatch",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    add(
        "L-MIX-03",
        "listener-and-file-transfer",
        "unix-rights",
        vec!["/work".into()],
        unix.clone(),
        Vec::new(),
        "30s",
    );
    add(
        "L-MIX-04",
        "cooperation",
        "cooperation",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    add(
        "C-IO",
        "binary-streams",
        "raw-byte-streams",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "30s",
    );
    add(
        "L-MIX-05",
        "binary-streams",
        "raw-byte-streams",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "30s",
    );
    for family in ["C-IO", "L-MIX-05"] {
        add(
            family,
            "empty-message",
            "empty-message",
            Vec::new(),
            vec![R::UnixStreamPair {
                id: id("empty-pair")?,
            }],
            Vec::new(),
            "30s",
        );
    }
    add(
        "C-IO",
        "binary-file",
        "binary-file",
        Vec::new(),
        Vec::new(),
        vec![path(Path::new("work/binary-file.bin"))?],
        "30s",
    );
    for family in ["C-IO", "L-MIX-05"] {
        add(
            family,
            "empty-input",
            "empty-input",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "30s",
        );
        add(
            family,
            "bounded-large-output",
            "bounded-large-output",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "30s",
        );
    }
    for (scenario, mode, operation) in [
        ("ipv6", "authority-denial", D::Inet6),
        ("udp", "authority-denial", D::Udp),
        ("raw", "authority-denial", D::Raw),
        ("packet", "authority-denial", D::Packet),
        ("netlink", "authority-denial", D::Netlink),
    ] {
        add(
            "L-ISO-01",
            scenario,
            mode,
            vec![scenario.into()],
            vec![
                tcp.clone(),
                R::ExpectedDenial {
                    id: id("denial")?,
                    operation,
                },
            ],
            Vec::new(),
            "30s",
        );
    }
    add(
        "L-ISO-01",
        "host-tcp",
        "forbidden-tcp",
        Vec::new(),
        vec![
            tcp.clone(),
            R::ExpectedDenial {
                id: id("host-tcp-denial")?,
                operation: D::HostTcp,
            },
        ],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-01",
        "nonloopback",
        "forbidden-tcp",
        Vec::new(),
        vec![
            tcp.clone(),
            R::ExpectedDenial {
                id: id("nonloopback-denial")?,
                operation: D::HostTcp,
            },
        ],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-03",
        "host-abstract",
        "forbidden-abstract",
        Vec::new(),
        vec![
            tcp.clone(),
            R::ExpectedDenial {
                id: id("host-abstract-denial")?,
                operation: D::HostUnixAbstract,
            },
        ],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-03",
        "other-attempt-abstract",
        "forbidden-abstract",
        Vec::new(),
        vec![
            R::UnixAbstractStream {
                id: id("own-abstract")?,
            },
            R::ExpectedDenial {
                id: id("other-attempt-denial")?,
                operation: D::OtherAttempt,
            },
        ],
        Vec::new(),
        "30s",
    );
    for scenario in ["host-run-socket", "host-temp-socket"] {
        add(
            "L-ISO-02",
            scenario,
            "forbidden-unix-path",
            Vec::new(),
            vec![
                R::UnixStreamPair { id: id("pair")? },
                R::ExpectedDenial {
                    id: id("host-path-denial")?,
                    operation: D::HostUnixPath,
                },
            ],
            Vec::new(),
            "30s",
        );
    }
    for scenario in ["input-socket", "imported-socket", "caller-writable-tree"] {
        add(
            "L-ISO-02",
            scenario,
            "forbidden-unix-path",
            Vec::new(),
            vec![R::UnixStreamPair { id: id("pair")? }],
            Vec::new(),
            "30s",
        );
    }
    add(
        "L-ISO-03",
        "own-abstract-positive",
        "own-abstract",
        Vec::new(),
        vec![R::UnixAbstractStream {
            id: id("own-abstract")?,
        }],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-06",
        "same-uid-process",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-06",
        "account-alias",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    add(
        "L-ISO-06",
        "stale-reservation",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    for (scenario, operation) in [
        ("pidfd-getfd", D::ProcessImport),
        ("ptrace", D::ProcessImport),
        ("namespace-entry", D::NamespaceEntry),
    ] {
        add(
            "L-ISO-05",
            scenario,
            "authority-denial",
            vec![scenario.into()],
            vec![
                tcp.clone(),
                R::ExpectedDenial {
                    id: id("denial")?,
                    operation,
                },
            ],
            Vec::new(),
            "30s",
        );
    }
    for scenario in ["stdio-host-socket", "extra-host-fd"] {
        add(
            "L-ISO-05",
            scenario,
            "descriptor-isolation",
            Vec::new(),
            vec![R::UnixStreamPair { id: id("pair")? }],
            Vec::new(),
            "30s",
        );
    }
    for (scenario, status) in [
        ("zero", 0),
        ("nonzero", 42),
        ("exit-123", 123),
        ("exit-124", 124),
        ("exit-125", 125),
        ("exit-126", 126),
        ("exit-127", 127),
    ] {
        add(
            "C-STATUS",
            scenario,
            "bytes-argv-status",
            vec![status.to_string().into()],
            Vec::new(),
            Vec::new(),
            "30s",
        );
    }
    add(
        "C-PARSER",
        "valid-current-result",
        "bytes-argv-status",
        vec!["0".into()],
        Vec::new(),
        Vec::new(),
        "30s",
    );
    let orphan_output = vec![
        path(Path::new("work/orphan-descendant.bin"))?,
        path(Path::new("work/orphan-completion.json"))?,
    ];
    for actor in ["frontend", "worker", "guardian", "control"] {
        for phase in ["allocation", "release", "drain"] {
            add(
                "L-LIFE-02",
                &format!("{actor}-{phase}"),
                if phase == "drain" {
                    "root-first"
                } else {
                    "held-tree"
                },
                Vec::new(),
                Vec::new(),
                if phase == "drain" {
                    orphan_output.clone()
                } else {
                    Vec::new()
                },
                "300s",
            );
        }
    }
    add(
        "L-LIFE-01",
        "root-first-resource-descendant",
        "root-first",
        Vec::new(),
        Vec::new(),
        orphan_output.clone(),
        "30s",
    );
    add(
        "L-LIFE-05",
        "relay-backpressure",
        "bounded-large-output",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "30s",
    );
    for scenario in [
        "symlink",
        "dotdot",
        "proc-root",
        "proc-cwd",
        "proc-fd",
        "hardlink",
        "opath",
        "mount-alias",
    ] {
        add(
            "L-ISO-04",
            scenario,
            "outside-file",
            vec![scenario.into()],
            Vec::new(),
            Vec::new(),
            "30s",
        );
    }
    add(
        "L-LIFE-05",
        "report-persistence-failure",
        "bytes-argv-status",
        vec!["0".into()],
        Vec::new(),
        Vec::new(),
        "300s",
    );
    add(
        "C-LIFETIME",
        "root-first",
        "root-first",
        Vec::new(),
        Vec::new(),
        orphan_output,
        "30s",
    );
    add(
        "C-STATUS",
        "deadline",
        "population-deadline",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        "2s",
    );
    add(
        "C-ADMISSION",
        "positive",
        "tcp-http",
        Vec::new(),
        vec![tcp.clone()],
        Vec::new(),
        "30s",
    );
    use std::os::unix::ffi::OsStringExt;
    add(
        "C-IO",
        "native-argv",
        "bytes-argv-status",
        vec![
            "0".into(),
            std::ffi::OsString::from_vec(vec![0x61, 0xff, 0x62]),
        ],
        Vec::new(),
        Vec::new(),
        "30s",
    );
    Ok(result)
}

fn capture_native_stream(
    mut stream: impl Read,
    destination: PathBuf,
    gate: Option<(
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::time::Instant,
    )>,
) -> std::io::Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let mut total = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        if let Some((held, deadline)) = &gate {
            while held.load(std::sync::atomic::Ordering::Acquire) {
                if std::time::Instant::now() >= *deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "original output capture hold deadline elapsed",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| std::io::Error::other("native capture overflow"))?;
        if total > 512 * 1024 * 1024 {
            return Err(std::io::Error::other(
                "native capture exceeds finite bound; partial bytes retained",
            ));
        }
        output.write_all(&buffer[..count])?;
        output.flush()?;
    }
    output.sync_all()
}

impl InstalledMixedLaunch {
    pub fn retained_frontend_wait(&self) -> Result<serde_json::Value> {
        use std::os::unix::process::ExitStatusExt;
        let status = self.frontend_status.ok_or_else(|| {
            CiError::Message("actual frontend Child wait remains unsettled".into())
        })?;
        let command = self.retained_frontend_invocation()?;
        let stdout = read_policy_observation_file(&self.stdout, 16 * 1024 * 1024)?;
        let stderr = read_policy_observation_file(&self.stderr, 16 * 1024 * 1024)?;
        Ok(
            serde_json::json!({"format":"memcordon.linux-policy-frontend-exit","revision":1,"process_id":self.frontend.id(),
            "process_birth":self.frontend_birth.ok_or_else(||CiError::Message("actual frontend birth observation absent".into()))?,
            "raw_wait_status":status.into_raw(),"native_exit":status.code(),"signal":status.signal(),
            "invocation_sha256":hex::encode(Sha256::digest(&command)),"stdout_sha256":hex::encode(Sha256::digest(&stdout)),
            "stderr_sha256":hex::encode(Sha256::digest(&stderr))}),
        )
    }

    pub fn hold_original_frontend(
        &self,
    ) -> Result<crate::linux_consumer_readiness::HeldLinuxProcess> {
        let birth = self
            .frontend_birth
            .ok_or_else(|| CiError::Message("original frontend birth custody absent".into()))?;
        crate::linux_consumer_readiness::HeldLinuxProcess::acquire(self.frontend.id(), birth)
            .map_err(CiError::Message)
    }
    /// Read the exact controller command retained before spawn. A replacement
    /// with identical bytes still fails the named native identity check.
    pub fn retained_frontend_invocation(&self) -> Result<Vec<u8>> {
        let file = &self.frontend_invocation_owner;
        let before = file.metadata()?;
        if before.len() != self.frontend_invocation_bytes.len() as u64 || before.len() > 65536 {
            return Err(CiError::Message(
                "retained frontend command length differs".into(),
            ));
        }
        let mut bytes = vec![0u8; before.len() as usize];
        file.read_exact_at(&mut bytes, 0)?;
        let path = self
            .observation_directory
            .parent()
            .ok_or_else(|| CiError::Message("frontend command parent absent".into()))?
            .join("frontend-invocation.json");
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let named_metadata = named.metadata()?;
        let after = file.metadata()?;
        let stamp = |value: &std::fs::Metadata| {
            (
                value.dev(),
                value.ino(),
                value.len(),
                value.ctime(),
                value.ctime_nsec(),
                value.nlink(),
                value.uid(),
                value.mode(),
            )
        };
        let mut named_bytes = vec![0u8; self.frontend_invocation_bytes.len()];
        named.read_exact_at(&mut named_bytes, 0)?;
        if stamp(&before) != stamp(&after)
            || stamp(&after) != stamp(&named_metadata)
            || after.nlink() != 1
            || after.uid() != 0
            || after.mode() & 0o022 != 0
            || bytes != self.frontend_invocation_bytes
            || named_bytes != bytes
            || stamp(&named_metadata) != stamp(&named.metadata()?)
        {
            return Err(CiError::Message(
                "retained frontend command native identity/bytes changed".into(),
            ));
        }
        Ok(bytes)
    }
    /// Selected installed CLI only. setpriv performs the supported native
    /// caller transition without a shell or inherited supplementary groups.
    pub fn start(input: InstalledMixedLaunchInput<'_>) -> Result<Self> {
        Self::start_with_delivery_controls(input, false, None)
    }

    pub fn start_with_delivery_controls(
        input: InstalledMixedLaunchInput<'_>,
        report_directory: bool,
        capture_hold_until: Option<std::time::Instant>,
    ) -> Result<Self> {
        Self::start_controls(input, report_directory, capture_hold_until, None, None)
    }
    pub fn start_with_inherited_descriptor(
        input: InstalledMixedLaunchInput<'_>,
        descriptor: Option<(std::os::fd::OwnedFd, i32)>,
    ) -> Result<Self> {
        Self::start_controls(input, false, None, descriptor, None)
    }
    pub fn start_with_host_stdin(
        input: InstalledMixedLaunchInput<'_>,
        stdin: std::os::fd::OwnedFd,
    ) -> Result<Self> {
        Self::start_controls(input, false, None, None, Some(stdin))
    }
    fn start_controls(
        input: InstalledMixedLaunchInput<'_>,
        report_directory: bool,
        capture_hold_until: Option<std::time::Instant>,
        inherited: Option<(std::os::fd::OwnedFd, i32)>,
        host_stdin: Option<std::os::fd::OwnedFd>,
    ) -> Result<Self> {
        if !input.directory.is_absolute()
            || !input.contract.is_absolute()
            || input.caller_uid == 0
            || input.caller_gid == 0
        {
            return Err(CiError::Message(
                "installed mixed caller paths/identity invalid".into(),
            ));
        }
        std::fs::create_dir(input.directory)?;
        std::fs::set_permissions(input.directory, std::fs::Permissions::from_mode(0o700))?;
        let uid = rustix::process::Uid::from_raw(input.caller_uid);
        let gid = rustix::process::Gid::from_raw(input.caller_gid);
        rustix::fs::chown(input.directory, Some(uid), Some(gid))
            .map_err(|e| CiError::Message(e.to_string()))?;
        let observation_directory = input.directory.join("observations");
        std::fs::create_dir(&observation_directory)?;
        std::fs::set_permissions(
            &observation_directory,
            std::fs::Permissions::from_mode(0o700),
        )?;
        rustix::fs::chown(&observation_directory, Some(uid), Some(gid))
            .map_err(|e| CiError::Message(e.to_string()))?;
        let result = input.directory.join("result.json");
        let stdout = input.directory.join("stdout.bin");
        let stderr = input.directory.join("stderr.bin");
        if report_directory {
            std::fs::create_dir(&result)?;
            std::fs::set_permissions(&result, std::fs::Permissions::from_mode(0o700))?;
            rustix::fs::chown(&result, Some(uid), Some(gid))
                .map_err(|error| CiError::Message(error.to_string()))?;
        }
        let mut command = std::process::Command::new("/usr/bin/setpriv");
        command
            .arg("--reuid")
            .arg(input.caller_uid.to_string())
            .arg("--regid")
            .arg(input.caller_gid.to_string())
            .arg("--clear-groups")
            .arg("--")
            .arg("/usr/libexec/memcordon")
            .arg(input.memory)
            .arg(input.deadline)
            .arg("--sealed")
            .arg("--workload-contract")
            .arg(input.contract)
            .arg("--report-format")
            .arg("result-v2")
            .arg("--report")
            .arg(&result)
            .arg("--mixed-observation-directory")
            .arg(&observation_directory)
            .arg("--image-entrypoint")
            .arg("owned-readiness")
            .arg("--")
            .args(input.target_arguments)
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Some(stdin) = host_stdin {
            command.stdin(std::process::Stdio::from(stdin));
        }
        if let Some((source, destination)) = inherited {
            if destination != 128 {
                return Err(CiError::Message(
                    "hostile original descriptor handoff differs from finite probe".into(),
                ));
            }
            memcordon_platform::test_support::inherit_test_descriptor_at(
                &mut command,
                source,
                destination,
            )?;
        }
        // Retain the actual native command operands before crossing the spawn
        // boundary. This receipt describes the controller's invocation; it
        // does not substitute for the frontend's public association digest.
        use std::os::unix::ffi::OsStrExt;
        let command_receipt = serde_json::json!({
            "format":"memcordon.linux-owned-frontend-invocation","revision":1,
            "program":command.get_program().as_bytes(),
            "arguments":command.get_args().map(|argument|argument.as_bytes().to_vec()).collect::<Vec<_>>(),
            "environment_cleared":true,"caller_uid":input.caller_uid,"caller_gid":input.caller_gid,
            "selected_cli_sha256":hex::encode(Sha256::digest(read_owned_resource(Path::new("/usr/libexec/memcordon"),512*1024*1024)?)),
        });
        let frontend_invocation_bytes = serde_json::to_vec(&command_receipt)?;
        let frontend_invocation_path = input.directory.join("frontend-invocation.json");
        retain(&frontend_invocation_path, &frontend_invocation_bytes)?;
        let frontend_invocation_owner = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&frontend_invocation_path)?;
        let command_metadata = frontend_invocation_owner.metadata()?;
        if !command_metadata.is_file()
            || command_metadata.uid() != 0
            || command_metadata.nlink() != 1
            || command_metadata.mode() & 0o022 != 0
        {
            return Err(CiError::Message(
                "native frontend command source custody differs before spawn".into(),
            ));
        }
        let mut frontend = command.spawn()?;
        // An exited but unreaped Child still owns this PID. Birth capture
        // failure retains the Child and capture owners for explicit cleanup.
        let (frontend_birth, mut capture_failures) =
            match crate::linux_consumer_readiness::process_birth(frontend.id()) {
                Ok(birth) => (Some(birth), Vec::new()),
                Err(error) => (
                    None,
                    vec![format!("actual frontend birth capture failed: {error}")],
                ),
            };
        let stdout_pipe = frontend
            .stdout
            .take()
            .expect("requested native stdout pipe");
        let stderr_pipe = frontend
            .stderr
            .take()
            .expect("requested native stderr pipe");
        let capture_gate = capture_hold_until
            .map(|_| std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)));
        let mut capture_pipe_owners = Vec::new();
        if capture_gate.is_some() {
            for duplicate in [rustix::io::dup(&stdout_pipe), rustix::io::dup(&stderr_pipe)] {
                match duplicate {
                    Ok(fd) => capture_pipe_owners.push(File::from(fd)),
                    Err(error) => capture_failures
                        .push(format!("native capture pipe retention failed: {error}")),
                }
            }
        }
        let stdout_gate = capture_gate
            .as_ref()
            .zip(capture_hold_until)
            .map(|(gate, deadline)| (gate.clone(), deadline));
        let stderr_gate = stdout_gate.clone();
        let stdout_path = stdout.clone();
        let stderr_path = stderr.clone();
        let stdout_worker = std::thread::spawn(move || {
            capture_native_stream(stdout_pipe, stdout_path, stdout_gate)
        });
        let stderr_worker = std::thread::spawn(move || {
            capture_native_stream(stderr_pipe, stderr_path, stderr_gate)
        });
        Ok(Self {
            frontend,
            stdout_worker: Some(stdout_worker),
            stderr_worker: Some(stderr_worker),
            stdout,
            stderr,
            result,
            observation_directory,
            frontend_status: None,
            frontend_birth,
            frontend_invocation_owner,
            frontend_invocation_bytes,
            capture_failures,
            image_entrypoint_source: None,
            image_entrypoint_owner: None,
            capture_gate,
            capture_pipe_owners,
            build_file_owners: Vec::new(),
            outside_canary: None,
            host_socket_descriptor: None,
        })
    }

    pub fn retained_output_backpressure(&self) -> Result<serde_json::Value> {
        if !self
            .capture_gate
            .as_ref()
            .is_some_and(|gate| gate.load(std::sync::atomic::Ordering::Acquire))
            || self.capture_pipe_owners.len() != 2
        {
            return Err(CiError::Message(
                "original native output capture hold is not active".into(),
            ));
        }
        let birth = self.frontend_birth.ok_or_else(|| {
            CiError::Message("original backpressure frontend birth absent".into())
        })?;
        let frontend =
            crate::linux_consumer_readiness::HeldLinuxProcess::acquire(self.frontend.id(), birth)
                .map_err(CiError::Message)?;
        if frontend.exited().map_err(CiError::Message)? {
            return Err(CiError::Message(
                "original frontend exited before native queue measurement".into(),
            ));
        }
        let mut pipes = Vec::new();
        for (index, pipe) in self.capture_pipe_owners.iter().enumerate() {
            let metadata = pipe.metadata()?;
            let descriptor = index + 1;
            let path = format!("/proc/{}/fd/{descriptor}", self.frontend.id());
            let before = std::fs::read_link(&path)?;
            let expected = format!("pipe:[{}]", metadata.ino());
            if before.as_os_str().as_encoded_bytes() != expected.as_bytes() {
                return Err(CiError::Message(
                    "actual frontend stream differs from retained native capture pipe".into(),
                ));
            }
            let capacity = rustix::pipe::fcntl_getpipe_size(pipe)
                .map_err(|error| CiError::Message(error.to_string()))?;
            let queued = rustix::io::ioctl_fionread(pipe)
                .map_err(|error| CiError::Message(error.to_string()))?;
            if std::fs::read_link(&path)? != before {
                return Err(CiError::Message(
                    "actual frontend output descriptor changed during queue measurement".into(),
                ));
            }
            pipes.push(serde_json::json!({"device":metadata.dev(),"inode":metadata.ino(),"mode":metadata.mode(),
                "native_descriptor":descriptor,"source_link":before.as_os_str().as_encoded_bytes(),
                "capacity_bytes":capacity,"queued_bytes":queued}));
        }
        if frontend.exited().map_err(CiError::Message)?
            || crate::linux_consumer_readiness::process_birth(self.frontend.id())
                .map_err(CiError::Message)?
                != birth
        {
            return Err(CiError::Message(
                "original frontend changed during native backpressure observation".into(),
            ));
        }
        Ok(
            serde_json::json!({"format":"memcordon.linux-native-output-backpressure","revision":1,
            "frontend_pid":self.frontend.id(),"frontend_birth":self.frontend_birth,"capture_held":true,"native_frontend_live":frontend.retirement_identity().map_err(CiError::Message)?,"pipes":pipes}),
        )
    }

    pub fn resume_output_capture(&mut self) -> Result<()> {
        let gate = self
            .capture_gate
            .as_ref()
            .ok_or_else(|| CiError::Message("original capture hold owner absent".into()))?;
        if !gate.swap(false, std::sync::atomic::Ordering::AcqRel) {
            return Err(CiError::Message(
                "original output capture already resumed".into(),
            ));
        }
        self.capture_pipe_owners.clear();
        Ok(())
    }

    fn close_build_observers(&mut self) -> Result<()> {
        let mut closures = Vec::new();
        for file in self.build_file_owners.drain(..) {
            let metadata = file.metadata()?;
            let closed = memcordon_platform::linux_checked_close(file.into());
            closures.push(serde_json::json!({"device":metadata.dev(),"inode":metadata.ino(),"closed":closed.is_ok(),"native_errno":closed.as_ref().err().and_then(std::io::Error::raw_os_error)}));
            if let Err(error) = closed {
                self.capture_failures
                    .push(format!("native build observer descriptor close: {error}"));
            }
        }
        if !closures.is_empty() {
            retain(
                &self
                    .stdout
                    .parent()
                    .ok_or_else(|| {
                        CiError::Message("owned native build close directory absent".into())
                    })?
                    .join("native-build-observer-close.json"),
                &serde_json::to_vec(&closures)?,
            )?;
        }
        if !self.capture_failures.is_empty() {
            return Err(CiError::Message(self.capture_failures.join("; ")));
        }
        Ok(())
    }

    pub fn release_fixture_barrier(&mut self) -> Result<()> {
        self.frontend
            .stdin
            .as_mut()
            .ok_or_else(|| CiError::Message("actual frontend input owner absent".into()))?
            .write_all(b"R")?;
        Ok(())
    }

    pub fn acquire_prepared(
        &self,
        provider: &memcordon_core::PublicProviderBindingV1,
        request: &memcordon_core::workload_contract_v3::WorkloadContractV3,
        destination: &Path,
        relative: &str,
        timeout: Duration,
    ) -> Result<crate::linux_consumer_readiness::PreparedLinuxObserver> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| CiError::Message("prepared observation timeout overflow".into()))?;
        loop {
            let mut named = Vec::new();
            for entry in std::fs::read_dir(&self.observation_directory)? {
                let entry = entry?;
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(".prepared.json"))
                {
                    named.push(entry.path());
                }
            }
            if named.len() > 1 {
                return Err(CiError::Message(
                    "one installed launch produced multiple prepared associations".into(),
                ));
            }
            if let Some(named) = named.first() {
                let bytes = read_policy_observation_file(named, 4 * 1024 * 1024)?;
                memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
                    .map_err(CiError::Message)?;
                let observation: memcordon_core::mixed_observation::MixedPreparedObservationV2 =
                    serde_json::from_slice(&bytes)?;
                return crate::linux_consumer_readiness::PreparedLinuxObserver::acquire_named(
                    &self.observation_directory,
                    provider,
                    request,
                    observation.admission.attempt_id.as_str(),
                    destination,
                    relative,
                )
                .map_err(CiError::Message);
            }
            if std::time::Instant::now() >= deadline {
                return Err(CiError::Message("no authenticated prepared observation before native timeout; launch owner retained".into()));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Holds every declared member in the already authenticated target PID
    /// namespace before publishing a fixture release byte. The native handles
    /// stay in the returned vector through final retirement observation.
    pub fn hold_fixture_tree(
        &self,
        observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
        tree: &serde_json::Value,
    ) -> Result<Vec<crate::linux_consumer_readiness::HeldLinuxProcess>> {
        let mut result = Vec::new();
        self.hold_fixture_tree_into(observer, tree, &mut result)?;
        Ok(result)
    }

    pub fn hold_fixture_tree_into(
        &self,
        observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
        tree: &serde_json::Value,
        result: &mut Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    ) -> Result<()> {
        fn acquire(
            root: &crate::linux_consumer_readiness::HeldLinuxProcess,
            parent: &crate::linux_consumer_readiness::HeldLinuxProcess,
            tree: &serde_json::Value,
            output: &mut Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
            seen: &mut BTreeSet<(u32, u64)>,
        ) -> Result<()> {
            let pid = u32::try_from(
                tree.get("pid")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| CiError::Message("fixture cohort PID absent".into()))?,
            )
            .map_err(|e| CiError::Message(e.to_string()))?;
            let birth = tree
                .get("birth")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| CiError::Message("fixture cohort birth absent".into()))?;
            if !seen.insert((pid, birth)) || output.len() >= 256 {
                return Err(CiError::Message(
                    "fixture cohort duplicate identity or bound exceeded".into(),
                ));
            }
            let mut held = root
                .hold_namespace_member(pid, birth)
                .map_err(CiError::Message)?;
            held.verify_parent(parent).map_err(CiError::Message)?;
            let index = output.len();
            output.push(held);
            if let Some(members) = tree.get("members") {
                // A separate held descriptor keeps the native parent borrowed
                // while descendants append to the retained cohort vector.
                let parent = crate::linux_consumer_readiness::HeldLinuxProcess::acquire(
                    output[index].process_id,
                    output[index].birth,
                )
                .map_err(CiError::Message)?;
                for member in members
                    .as_array()
                    .ok_or_else(|| CiError::Message("cohort members not an array".into()))?
                {
                    acquire(root, &parent, member, output, seen)?;
                }
            }
            Ok(())
        }
        let start = result.len();
        acquire(
            &observer.target,
            &observer.target,
            tree,
            result,
            &mut BTreeSet::new(),
        )?;
        if observer.target.exited().map_err(CiError::Message)?
            || result[start..]
                .iter()
                .any(|held| held.exited().unwrap_or(true))
        {
            return Err(CiError::Message(
                "native cohort ceased to be held live before fixture barrier".into(),
            ));
        }
        Ok(())
    }

    /// Drives only fixture barriers. Native provider authorization is already
    /// governed by its own retained lease; these bytes cannot authorize it.
    /// Caller-owned vectors retain every acquired handle and parsed row even
    /// when the next observation or frontend operation fails.
    pub fn observe_fixture(
        &mut self,
        observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
        challenge: &str,
        held: &mut Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
        rows: &mut Vec<crate::linux_consumer_readiness::LinuxTranscriptRow>,
        timeout: Duration,
    ) -> Result<()> {
        self.observe_fixture_with_hook(observer, challenge, held, rows, timeout, |_, _| Ok(()))
    }

    /// The callback runs after native cohort acquisition and row retention,
    /// before any fixture release byte. It is CI controller observation only.
    pub fn observe_fixture_with_hook(
        &mut self,
        observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
        challenge: &str,
        held: &mut Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
        rows: &mut Vec<crate::linux_consumer_readiness::LinuxTranscriptRow>,
        timeout: Duration,
        mut hook: impl FnMut(&crate::linux_consumer_readiness::LinuxTranscriptRow, u32) -> Result<()>,
    ) -> Result<()> {
        self.observe_fixture_with_decision(observer, challenge, held, rows, timeout, |row, pid| {
            hook(row, pid)?;
            Ok(FixtureBarrierDecision::Continue)
        })
    }

    pub fn observe_fixture_with_decision(
        &mut self,
        observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
        challenge: &str,
        held: &mut Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
        rows: &mut Vec<crate::linux_consumer_readiness::LinuxTranscriptRow>,
        timeout: Duration,
        mut hook: impl FnMut(
            &crate::linux_consumer_readiness::LinuxTranscriptRow,
            u32,
        ) -> Result<FixtureBarrierDecision>,
    ) -> Result<()> {
        self.observe_fixture_with_release_observation(
            observer,
            challenge,
            held,
            rows,
            timeout,
            |row, pid, released| {
                if released {
                    Ok(FixtureBarrierDecision::Continue)
                } else {
                    hook(row, pid)
                }
            },
        )
    }

    /// A second callback observes effects after the real controller byte has
    /// released a held fixture. It cannot release provider authorization.
    pub fn observe_fixture_with_release_observation(
        &mut self,
        observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
        challenge: &str,
        held: &mut Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
        rows: &mut Vec<crate::linux_consumer_readiness::LinuxTranscriptRow>,
        timeout: Duration,
        mut hook: impl FnMut(
            &crate::linux_consumer_readiness::LinuxTranscriptRow,
            u32,
            bool,
        ) -> Result<FixtureBarrierDecision>,
    ) -> Result<()> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| CiError::Message("fixture observation timeout overflow".into()))?;
        let mut consumed = 0usize;
        loop {
            if self.stdout.exists() {
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&self.stdout)?;
                if file.metadata()?.len() > 16 * 1024 * 1024 {
                    return Err(CiError::Message(
                        "live fixture transcript exceeds finite bound".into(),
                    ));
                }
                let mut bytes = Vec::new();
                file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                if bytes.len() < consumed {
                    return Err(CiError::Message(
                        "actual capture shrank during native observation".into(),
                    ));
                }
                while let Some(end) = bytes[consumed..].iter().position(|byte| *byte == b'\n') {
                    let line = &bytes[consumed..consumed + end];
                    consumed += end + 1;
                    memcordon_core::workload_contract::reject_duplicate_json_keys(line)
                        .map_err(CiError::Message)?;
                    let row: crate::linux_consumer_readiness::LinuxTranscriptRow =
                        serde_json::from_slice(line)?;
                    if row.challenge != challenge || row.sequence != rows.len() as u64 + 1 {
                        return Err(CiError::Message(
                            "fixture live challenge/sequence differs".into(),
                        ));
                    }
                    let release = match row.operation.as_str() {
                        "offline-compiler-held" | "joint-generated-child-held" => {
                            if let ("offline-compiler-held", Some(source)) =
                                (row.operation.as_str(), &self.image_entrypoint_source)
                            {
                                let mut owner =
                                    crate::linux_consumer_readiness::HeldLinuxProcess::acquire(
                                        observer.target.process_id,
                                        observer.target.birth,
                                    )
                                    .map_err(CiError::Message)?;
                                let executable = owner
                                    .hold_executable_image(deadline)
                                    .map_err(CiError::Message)?;
                                if executable["sha256"] != source["fixture_sha256"] {
                                    return Err(CiError::Message("actual image entrypoint proc executable differs from approved fixture".into()));
                                }
                                let raw = serde_json::json!({"format":"memcordon.linux-image-entrypoint","revision":1,"source":source,
                                        "challenge":row.challenge,"attempt_id":observer.observation.admission.attempt_id,
                                        "target":owner.live_snapshot().map_err(CiError::Message)?,"executable":executable});
                                self.image_entrypoint_owner = Some(owner);
                                retain(
                                    &self
                                        .stdout
                                        .parent()
                                        .ok_or_else(|| {
                                            CiError::Message(
                                                "owned image entrypoint capture directory absent"
                                                    .into(),
                                            )
                                        })?
                                        .join("image-entrypoint.json"),
                                    &serde_json::to_vec(&raw)?,
                                )?;
                            }
                            let tree = if row.operation == "offline-compiler-held" {
                                &row.observation
                            } else {
                                row.observation.get("native_tree").ok_or_else(|| {
                                    CiError::Message("actual generated native tree absent".into())
                                })?
                            };
                            self.hold_fixture_tree_into(observer, tree, held)?;
                            let mut unique = BTreeSet::new();
                            held.retain(|process| {
                                unique.insert((process.process_id, process.birth))
                            });
                            let mut members = Vec::new();
                            fn identities(
                                tree: &serde_json::Value,
                                result: &mut BTreeSet<(u64, u64)>,
                            ) -> Result<()> {
                                let pid = tree["pid"].as_u64().ok_or_else(|| {
                                    CiError::Message("native compiler tree PID absent".into())
                                })?;
                                let birth = tree["birth"].as_u64().ok_or_else(|| {
                                    CiError::Message("native compiler tree birth absent".into())
                                })?;
                                if !result.insert((pid, birth)) {
                                    return Err(CiError::Message(
                                        "native compiler tree identity duplicated".into(),
                                    ));
                                }
                                for child in tree["members"].as_array().ok_or_else(|| {
                                    CiError::Message("native compiler tree members absent".into())
                                })? {
                                    identities(child, result)?;
                                }
                                Ok(())
                            }
                            let mut selected = BTreeSet::new();
                            identities(tree, &mut selected)?;
                            for process in held.iter_mut().filter(|process| {
                                process.namespace_pid.is_some_and(|pid| {
                                    selected.contains(&(u64::from(pid), process.birth))
                                })
                            }) {
                                members.push(serde_json::json!({"native":process.live_snapshot().map_err(CiError::Message)?,
                                    "identity":process.retirement_identity().map_err(CiError::Message)?,
                                    "executable":process.hold_executable_image(deadline).map_err(CiError::Message)?}));
                            }
                            if members.len() != selected.len() {
                                return Err(CiError::Message(
                                    "retained compiler tree mapping incomplete".into(),
                                ));
                            }
                            let name = if row.operation == "offline-compiler-held" {
                                "native-offline-compiler-live.json"
                            } else {
                                "native-generated-child-live.json"
                            };
                            let raw = serde_json::json!({"format":"memcordon.linux-native-build-barrier","revision":1,
                                "stage":row.operation,"challenge":row.challenge,"attempt_id":observer.observation.admission.attempt_id,
                                "root_pid":observer.target.process_id,"root_birth":observer.target.birth,"members":members});
                            retain(
                                &self
                                    .stdout
                                    .parent()
                                    .ok_or_else(|| {
                                        CiError::Message(
                                            "owned compiler capture directory absent".into(),
                                        )
                                    })?
                                    .join(name),
                                &serde_json::to_vec(&raw)?,
                            )?;
                            if row.operation == "joint-generated-child-held" {
                                let root = File::open(format!(
                                    "/proc/{}/root",
                                    observer.target.process_id
                                ))?;
                                let metadata = root.metadata()?;
                                if metadata.dev() != observer.observation.root_device
                                    || metadata.ino() != observer.observation.root_inode
                                    || observer.target.exited().map_err(CiError::Message)?
                                {
                                    return Err(CiError::Message("actual generated source root differs from held prepared native root".into()));
                                }
                                let work = File::from(
                                    rustix::fs::openat(
                                        &root,
                                        "work",
                                        rustix::fs::OFlags::RDONLY
                                            | rustix::fs::OFlags::DIRECTORY
                                            | rustix::fs::OFlags::NOFOLLOW
                                            | rustix::fs::OFlags::CLOEXEC,
                                        rustix::fs::Mode::empty(),
                                    )
                                    .map_err(|error| CiError::Message(error.to_string()))?,
                                );
                                for (source, name) in [
                                    (
                                        "generated-child-created.json",
                                        "native-generated-created.json",
                                    ),
                                    (
                                        "generated-child-executable.bin",
                                        "native-generated-executable.bin",
                                    ),
                                ] {
                                    let file = File::from(
                                        rustix::fs::openat(
                                            &work,
                                            source,
                                            rustix::fs::OFlags::RDONLY
                                                | rustix::fs::OFlags::NOFOLLOW
                                                | rustix::fs::OFlags::CLOEXEC,
                                            rustix::fs::Mode::empty(),
                                        )
                                        .map_err(|error| CiError::Message(error.to_string()))?,
                                    );
                                    let before = file.metadata()?;
                                    if !before.is_file()
                                        || before.nlink() != 1
                                        || before.len() > 64 * 1024 * 1024
                                    {
                                        return Err(CiError::Message("actual generated source custody exceeds finite regular bound".into()));
                                    }
                                    let mut bytes = vec![0u8; before.len() as usize];
                                    file.read_exact_at(&mut bytes, 0)?;
                                    let after = file.metadata()?;
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
                                    ) || observer.target.exited().map_err(CiError::Message)?
                                    {
                                        return Err(CiError::Message("actual generated source changed at physical held-child barrier".into()));
                                    }
                                    retain(
                                        &self
                                            .stdout
                                            .parent()
                                            .ok_or_else(|| {
                                                CiError::Message(
                                                    "original generated capture directory absent"
                                                        .into(),
                                                )
                                            })?
                                            .join(name),
                                        &bytes,
                                    )?;
                                    self.build_file_owners.push(file);
                                }
                                self.build_file_owners.push(work);
                                self.build_file_owners.push(root);
                            }
                            true
                        }
                        "application-endpoint-mismatch" => {
                            let parse = |field: &str| -> Result<std::net::SocketAddrV4> {
                                row.observation[field]
                                    .as_str()
                                    .ok_or_else(|| {
                                        CiError::Message(
                                            "actual endpoint mismatch address absent".into(),
                                        )
                                    })?
                                    .parse()
                                    .map_err(|error: std::net::AddrParseError| {
                                        CiError::Message(error.to_string())
                                    })
                            };
                            let mut receipt = observer
                                .target
                                .observe_loopback_listeners([
                                    parse("intended")?,
                                    parse("observed")?,
                                ])
                                .map_err(CiError::Message)?;
                            receipt["challenge"] = row.challenge.clone().into();
                            receipt["attempt_id"] = observer
                                .observation
                                .admission
                                .attempt_id
                                .as_str()
                                .to_owned()
                                .into();
                            retain(
                                &self
                                    .stdout
                                    .parent()
                                    .ok_or_else(|| {
                                        CiError::Message("owned capture directory absent".into())
                                    })?
                                    .join("native-endpoint-mismatch.json"),
                                &serde_json::to_vec(&receipt)?,
                            )?;
                            true
                        }
                        "same-attempt-cooperation-held"
                        | "descendant-competing-bind-held"
                        | "joint-descendant-tree-held"
                        | "root-exiting-before-held-descendant"
                        | "intermediate-and-descendant-held-before-exit" => {
                            self.hold_fixture_tree_into(observer, &row.observation, held)?;
                            true
                        }
                        "memory-pressure-ready" => true,
                        "memory-pressure-descendant-held" => {
                            let tree = row.observation.get("native_tree").ok_or_else(|| {
                                CiError::Message("actual memory descendant tree absent".into())
                            })?;
                            self.hold_fixture_tree_into(observer, tree, held)?;
                            true
                        }
                        "churn-cohort-held" => {
                            let tree = row.observation.get("native_tree").ok_or_else(|| {
                                CiError::Message("actual churn tree absent".into())
                            })?;
                            let start = held.len();
                            self.hold_fixture_tree_into(observer, tree, held)?;
                            if held.len() - start != 64 {
                                return Err(CiError::Message(
                                    "actual held churn cohort differs from sixty-four".into(),
                                ));
                            }
                            true
                        }
                        "population-held-until-native-deadline" => {
                            let children = row
                                .observation
                                .get("children")
                                .and_then(serde_json::Value::as_array)
                                .ok_or_else(|| {
                                    CiError::Message("actual population children absent".into())
                                })?;
                            if children.len() != 256 {
                                return Err(CiError::Message("actual held deadline population differs from 257 including root".into()));
                            }
                            let start = held.len();
                            for child in children {
                                self.hold_fixture_tree_into(observer, child, held)?;
                            }
                            let members=held[start..].iter().map(|process|Ok(serde_json::json!({
                                "native":process.live_snapshot().map_err(CiError::Message)?,
                                "identity":process.retirement_identity().map_err(CiError::Message)?
                            }))).collect::<Result<Vec<_>>>()?;
                            let receipt = serde_json::json!({"format":"memcordon.linux-native-deadline-population","revision":1,
                                "attempt_id":observer.observation.admission.attempt_id.as_str(),"challenge":row.challenge,
                                "root":observer.target.live_snapshot().map_err(CiError::Message)?,"members":members});
                            retain(
                                &self
                                    .stdout
                                    .parent()
                                    .ok_or_else(|| {
                                        CiError::Message("owned capture directory absent".into())
                                    })?
                                    .join("native-deadline-population.json"),
                                &serde_json::to_vec(&receipt)?,
                            )?;
                            false
                        }
                        _ => false,
                    };
                    rows.push(row);
                    let retained = rows.last().expect("actual fixture row retained");
                    let decision = if matches!(
                        retained.operation.as_str(),
                        "population-held-until-native-deadline"
                            | "memory-pressure-ready"
                            | "memory-pressure-descendant-held"
                            | "offline-compiler-held"
                            | "joint-generated-child-held"
                    ) {
                        hook(retained, self.frontend.id(), false)?
                    } else {
                        FixtureBarrierDecision::Continue
                    };
                    if release && decision == FixtureBarrierDecision::Continue {
                        self.release_fixture_barrier()?;
                        hook(retained, self.frontend.id(), true)?;
                    }
                }
            }
            if let Some(status) = self.frontend.try_wait()? {
                self.frontend_status = Some(status);
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(CiError::Message(
                    "fixture observation timeout; native launch/cohort owners retained".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn capture_owners_settled(&self) -> bool {
        self.frontend_status.is_some()
            && self.stdout_worker.is_none()
            && self.stderr_worker.is_none()
    }

    pub fn wait_and_capture(&mut self, timeout: Duration) -> Result<std::process::ExitStatus> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| CiError::Message("native capture deadline overflow".into()))?;
        loop {
            if let Some(status) = self.frontend.try_wait()? {
                self.frontend_status = Some(status);
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(CiError::Message("installed frontend remains owned after capture deadline; provider recovery required".into()));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        for worker in [&mut self.stdout_worker, &mut self.stderr_worker] {
            while worker.as_ref().is_some_and(|value| !value.is_finished()) {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if worker.as_ref().is_some_and(|value| !value.is_finished()) {
                continue;
            }
            if let Some(worker) = worker.take() {
                match worker.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => self
                        .capture_failures
                        .push(format!("native capture IO failure: {error}")),
                    Err(_) => self
                        .capture_failures
                        .push("native capture worker panicked; partial evidence retained".into()),
                }
            }
        }
        if self.stdout_worker.is_some() || self.stderr_worker.is_some() {
            return Err(CiError::Message(
                "capture worker remains owned after frontend retirement".into(),
            ));
        }
        if !self.build_file_owners.is_empty() {
            self.close_build_observers()?;
        }
        if let Some(canary) = self.outside_canary.take() {
            canary.settle(self.stdout.parent().ok_or_else(|| {
                CiError::Message("original outside canary observation directory absent".into())
            })?)?;
        }
        if let Some(canary) = self.host_socket_descriptor.take() {
            canary.settle(&self.observation_directory)?;
        }
        if !self.capture_failures.is_empty() {
            return Err(CiError::Message(self.capture_failures.join("; ")));
        }
        Ok(self.frontend_status.expect("observed native frontend exit"))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Completed evidence binds original invocation, native observations, image, policy, and artifact custody independently"
    )]
    pub fn collect_completed(
        &mut self,
        observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
        held: &[crate::linux_consumer_readiness::HeldLinuxProcess],
        identity: SourceIdentity,
        lease_id: String,
        key: memcordon_readiness_verifier::CaseKey,
        challenge: String,
        artifact_prefix: String,
        contract: &Path,
        destination: &Path,
        timeout: Duration,
    ) -> Result<CompletedMixedCollection> {
        let status = self.wait_and_capture(timeout)?;
        if !observer
            .native_family_retired(held)
            .map_err(CiError::Message)?
        {
            return Err(CiError::Message("native target/init/guardian/cohort/cgroup retirement not observed; owners retained".into()));
        }
        let raw_result = crate::linux_consumer_readiness::measured(&self.result, 4 * 1024 * 1024)
            .map_err(CiError::Message)?;
        let result =
            memcordon_core::result_v2::ResultV2::parse(&raw_result).map_err(CiError::Message)?;
        let frontend_status = status.code().ok_or_else(|| {
            CiError::Message("frontend terminated by native signal; no invented exit status".into())
        })?;
        if result.wrapper_status != frontend_status
            || !result.frontend.relay_drained
            || result.frontend.relay_error.is_some()
        {
            return Err(CiError::Message(
                "actual frontend delivery/drain/status failed; original products retained".into(),
            ));
        }
        let memcordon_core::result_v2::MixedRuntimeOutcomeV2::Executed {
            admission,
            provider,
            execution,
            retirement,
            ..
        } = &result.runtime.outcome
        else {
            return Err(CiError::Message(
                "executed collection cannot substitute a rejected or indeterminate carrier".into(),
            ));
        };
        if admission != &observer.observation.admission
            || provider != &observer.observation.provider
            || execution.target != observer.observation.target
            || execution.namespace_init != observer.observation.namespace_init
            || execution.guardian != observer.observation.guardian
            || execution.root_device != observer.observation.root_device
            || execution.root_inode != observer.observation.root_inode
        {
            return Err(CiError::Message(
                "final actual provider execution differs from preauthorization native owner".into(),
            ));
        }
        let provider_request = self
            .observation_directory
            .join(admission.attempt_id.as_str())
            .with_extension("provider-request.bin");
        let receipt_relative = format!("{artifact_prefix}/prepared-native.json");
        let prepared_native_receipt = observer
            .persist_native_receipt(&identity.run_id, destination, &receipt_relative)
            .map_err(CiError::Message)?;
        let mut persisted = crate::linux_consumer_readiness::collect(
            crate::linux_consumer_readiness::LinuxCollectionInput {
                identity,
                key,
                challenge: challenge.clone(),
                artifact_prefix: artifact_prefix.clone(),
                result: self.result.clone(),
                stdout: self.stdout.clone(),
                stderr: self.stderr.clone(),
                transcript: None,
                provider_request,
                contract: contract.to_path_buf(),
            },
            destination,
        )
        .map_err(CiError::Message)?;
        if persisted.key.family == "L-ISO-04"
            && [
                "symlink",
                "dotdot",
                "proc-root",
                "proc-cwd",
                "proc-fd",
                "hardlink",
                "opath",
                "mount-alias",
            ]
            .contains(&persisted.key.scenario.as_str())
        {
            let raw = crate::linux_consumer_readiness::measured(
                &self
                    .stdout
                    .parent()
                    .ok_or_else(|| {
                        CiError::Message("original outside canary source directory absent".into())
                    })?
                    .join("outside-file-canary.json"),
                65536,
            )
            .map_err(CiError::Message)?;
            let relative = format!("{artifact_prefix}/outside-file-canary.json");
            retain(&destination.join(&relative), &raw)?;
            persisted
                .artifacts
                .push(memcordon_readiness_verifier::Artifact {
                    path: relative,
                    length: raw.len() as u64,
                    sha256: hex::encode(Sha256::digest(&raw)),
                });
        }
        if persisted.key.family == "L-ISO-05"
            && ["stdio-host-socket", "extra-host-fd"].contains(&persisted.key.scenario.as_str())
        {
            let raw = crate::linux_consumer_readiness::measured(
                &self
                    .observation_directory
                    .join("host-socket-descriptor-retired.json"),
                65536,
            )
            .map_err(CiError::Message)?;
            let relative = format!("{artifact_prefix}/host-socket-descriptor-retired.json");
            retain(&destination.join(&relative), &raw)?;
            persisted
                .artifacts
                .push(memcordon_readiness_verifier::Artifact {
                    path: relative,
                    length: raw.len() as u64,
                    sha256: hex::encode(Sha256::digest(&raw)),
                });
        }
        if persisted.key.family == "L-MIX-02" && persisted.key.scenario == "endpoint-mismatch" {
            let raw = crate::linux_consumer_readiness::measured(
                &self
                    .stdout
                    .parent()
                    .ok_or_else(|| {
                        CiError::Message("owned endpoint observation directory absent".into())
                    })?
                    .join("native-endpoint-mismatch.json"),
                65536,
            )
            .map_err(CiError::Message)?;
            let relative = format!("{artifact_prefix}/native-endpoint-mismatch.json");
            retain(&destination.join(&relative), &raw)?;
            persisted
                .artifacts
                .push(memcordon_readiness_verifier::Artifact {
                    path: relative,
                    length: raw.len() as u64,
                    sha256: hex::encode(Sha256::digest(&raw)),
                });
        }
        if ["L-MIX-01", "L-IMG-03", "L-LIFE-03"].contains(&persisted.key.family.as_str()) {
            self.close_build_observers()?;
            let mut names = vec![
                "native-offline-compiler-live.json",
                "native-generated-child-live.json",
                "native-generated-created.json",
                "native-generated-executable.bin",
                "native-build-observer-close.json",
            ];
            if self.image_entrypoint_source.is_some() {
                let owner = self.image_entrypoint_owner.as_ref().ok_or_else(|| {
                    CiError::Message("image entrypoint retained native owner absent".into())
                })?;
                if !owner.exited().map_err(CiError::Message)? {
                    return Err(CiError::Message(
                        "image entrypoint native owner remains live after collection".into(),
                    ));
                }
                names.push("image-entrypoint.json");
            }
            for name in names {
                let raw = crate::linux_consumer_readiness::measured(
                    &self
                        .stdout
                        .parent()
                        .ok_or_else(|| {
                            CiError::Message("owned build observation directory absent".into())
                        })?
                        .join(name),
                    64 * 1024 * 1024,
                )
                .map_err(CiError::Message)?;
                let relative = format!("{artifact_prefix}/{name}");
                retain(&destination.join(&relative), &raw)?;
                persisted
                    .artifacts
                    .push(memcordon_readiness_verifier::Artifact {
                        path: relative,
                        length: raw.len() as u64,
                        sha256: hex::encode(Sha256::digest(&raw)),
                    });
            }
        }
        if persisted
            .artifacts
            .iter()
            .find(|artifact| artifact.path == format!("{artifact_prefix}/result.json"))
            .map(|artifact| artifact.sha256.as_str())
            != Some(hex::encode(Sha256::digest(&raw_result)).as_str())
        {
            return Err(CiError::Message(
                "named result changed between native parsing and persisted custody capture".into(),
            ));
        }
        let mut held_processes = vec![
            observer
                .target
                .retirement_identity()
                .map_err(CiError::Message)?,
        ];
        for process in held {
            held_processes.push(process.retirement_identity().map_err(CiError::Message)?);
        }
        let native_retirement = serde_json::json!({
            "format":"memcordon.linux-held-family-retirement","revision":1,
            "run_id":persisted.identity.run_id,"lease_id":lease_id,
            "attempt_id":admission.attempt_id,
            "target":observer.target.retirement_identity().map_err(CiError::Message)?,
            "namespace_init":observer.namespace_init.retirement_identity().map_err(CiError::Message)?,
            "guardian":observer.guardian.retirement_identity().map_err(CiError::Message)?,
            "descendants":held_processes.iter().skip(1).collect::<Vec<_>>(),
            "namespace_members":held.iter().map(|process|serde_json::json!({"pid":process.process_id,"birth":process.birth,"namespace_pid":process.namespace_pid})).collect::<Vec<_>>(),
            "aggregate_empty":observer.native_family_retired(held).map_err(CiError::Message)?,
        });
        let native_retirement_bytes = serde_json::to_vec(&native_retirement)?;
        let native_retirement_relative = format!("{artifact_prefix}/native-family-retirement.json");
        retain(
            &destination.join(&native_retirement_relative),
            &native_retirement_bytes,
        )?;
        persisted
            .artifacts
            .push(memcordon_readiness_verifier::Artifact {
                path: native_retirement_relative,
                length: native_retirement_bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&native_retirement_bytes)),
            });
        use base64::Engine;
        use memcordon_readiness_verifier::{
            Artifact, BudgetToken, NativeArguments, NativeEnvironment, NativeInvocation,
        };
        let challenge_bytes =
            hex::decode(&challenge).map_err(|error| CiError::Message(error.to_string()))?;
        if challenge_bytes.len() != 32 || challenge_bytes.iter().all(|byte| *byte == 0) {
            return Err(CiError::Message(
                "completed collection challenge is not a fresh native vector".into(),
            ));
        }
        let challenge_relative = format!("{artifact_prefix}/challenge.bin");
        retain(&destination.join(&challenge_relative), &challenge_bytes)?;
        persisted.artifacts.push(Artifact {
            path: challenge_relative,
            length: challenge_bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&challenge_bytes)),
        });
        let invocation_value = serde_json::to_value(&result.invocation)?;
        let arguments = result
            .invocation
            .argv
            .iter()
            .map(|argument| {
                let value = serde_json::to_value(argument)?;
                match value.get("raw").filter(|raw| !raw.is_null()) {
                    None => Ok(value
                        .get("display")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            CiError::Message("actual public argument display absent".into())
                        })?
                        .as_bytes()
                        .to_vec()),
                    Some(raw) => {
                        if raw.get("encoding").and_then(serde_json::Value::as_str)
                            != Some("unix-bytes-base64")
                        {
                            return Err(CiError::Message(
                                "actual Linux public argument encoding differs".into(),
                            ));
                        }
                        base64::engine::general_purpose::STANDARD
                            .decode(
                                raw.get("data")
                                    .and_then(serde_json::Value::as_str)
                                    .ok_or_else(|| {
                                        CiError::Message("actual public raw argument absent".into())
                                    })?,
                            )
                            .map_err(|error| CiError::Message(error.to_string()))
                    }
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let environment_bytes = serde_json::to_vec(&NativeEnvironment::UnixBytes(Vec::new()))?;
        let environment_relative = format!("{artifact_prefix}/public-environment.json");
        retain(&destination.join(&environment_relative), &environment_bytes)?;
        let public_environment = Artifact {
            path: environment_relative.clone(),
            length: environment_bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&environment_bytes)),
        };
        let launch_receipt = decode_owned_resource_json(&read_owned_resource(
            &self
                .result
                .parent()
                .ok_or_else(|| CiError::Message("frontend directory absent".into()))?
                .join("frontend-invocation.json"),
            4 * 1024 * 1024,
        )?)?;
        let public_native = NativeInvocation {
            format: "memcordon.consumer-readiness.invocation".into(),
            revision: 1,
            arguments: NativeArguments::UnixBytes(arguments),
            executable_sha256: launch_receipt
                .get("selected_cli_sha256")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CiError::Message("actual selected CLI measurement absent".into()))?
                .into(),
            environment: environment_relative,
            environment_sha256: public_environment.sha256.clone(),
            association_sha256: hex::encode(Sha256::digest(serde_json::to_vec(
                &result.invocation,
            )?)),
            budget_tokens: invocation_value
                .get("budget_tokens")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| CiError::Message("actual public budgets absent".into()))?
                .iter()
                .map(|token| {
                    serde_json::from_value::<BudgetToken>(token.clone()).map_err(CiError::from)
                })
                .collect::<Result<Vec<_>>>()?,
            memory_token: result.invocation.memory_token.clone(),
            deadline_token: result.invocation.deadline_token.clone(),
        };
        let invocation_bytes = serde_json::to_vec(&public_native)?;
        let invocation_relative = format!("{artifact_prefix}/public-invocation.json");
        retain(&destination.join(&invocation_relative), &invocation_bytes)?;
        let public_invocation = Artifact {
            path: invocation_relative,
            length: invocation_bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&invocation_bytes)),
        };
        persisted.artifacts.extend([
            public_invocation.clone(),
            public_environment.clone(),
            prepared_native_receipt.clone(),
            observer.persisted_observation.clone(),
        ]);
        let export_path = PathBuf::from("/run/memcordon")
            .join(format!("private-export-{}", admission.attempt_id.as_str()))
            .join("export-receipt.json");
        let export_bytes = read_protected_export(&export_path, 4 * 1024 * 1024)?;
        if hex::encode(Sha256::digest(&export_bytes))
            != String::from(retirement.export_receipt_sha256.clone())
        {
            return Err(CiError::Message(
                "actual protected export receipt differs from authenticated retirement".into(),
            ));
        }
        let export_raw = decode_owned_resource_json(&export_bytes)?;
        if export_raw.get("format").and_then(serde_json::Value::as_str)
            != Some("memcordon.private-export")
            || export_raw
                .get("revision")
                .and_then(serde_json::Value::as_u64)
                != Some(1)
            || export_raw.get("attempt_id") != Some(&serde_json::to_value(&admission.attempt_id)?)
            || export_raw.get("root_layout")
                != Some(&serde_json::to_value(&admission.request.root_layout)?)
            || export_raw.get("identity")
                != Some(&serde_json::to_value(
                    &admission.request.execution_identity,
                )?)
        {
            return Err(CiError::Message(
                "actual export receipt belongs to another attempt".into(),
            ));
        }
        let export_relative = format!("{artifact_prefix}/export-receipt.json");
        retain(&destination.join(&export_relative), &export_bytes)?;
        let export_receipt = Artifact {
            path: export_relative,
            length: export_bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&export_bytes)),
        };
        persisted.artifacts.push(export_receipt.clone());
        let files = export_raw
            .get("files")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| CiError::Message("actual export file table absent".into()))?;
        if files.len() > 128 {
            return Err(CiError::Message(
                "actual export file table exceeds finite selected bound".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for selected in files {
            let name = selected
                .get("path")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| CiError::Message("actual export member path absent".into()))?;
            if name.is_empty()
                || name.contains(['\\', ':', '\0'])
                || name
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || !seen.insert(name)
            {
                return Err(CiError::Message(
                    "actual export member path aliases another authority".into(),
                ));
            }
            let length = selected
                .get("length")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| CiError::Message("actual export member length absent".into()))?;
            total = total
                .checked_add(length)
                .ok_or_else(|| CiError::Message("actual export byte total overflow".into()))?;
            if length > 64 * 1024 * 1024 || total > 256 * 1024 * 1024 {
                return Err(CiError::Message(
                    "actual export products exceed bounded evidence capture".into(),
                ));
            }
            let bytes = read_protected_export(
                &export_path
                    .parent()
                    .expect("native export directory")
                    .join(name),
                length,
            )?;
            let digest = hex::encode(Sha256::digest(&bytes));
            if bytes.len() as u64 != length
                || selected.get("sha256").and_then(serde_json::Value::as_str)
                    != Some(digest.as_str())
            {
                return Err(CiError::Message(
                    "actual export product differs from native immutable receipt".into(),
                ));
            }
            let relative = format!("{artifact_prefix}/exported/{name}");
            std::fs::create_dir_all(
                destination
                    .join(&relative)
                    .parent()
                    .expect("finite export parent"),
            )?;
            retain(&destination.join(&relative), &bytes)?;
            persisted.artifacts.push(Artifact {
                path: relative,
                length,
                sha256: digest,
            });
        }
        if lease_id.is_empty() || lease_id.len() > 256 {
            return Err(CiError::Message(
                "completed collection lacks exact installed lease identity".into(),
            ));
        }
        Ok(CompletedMixedCollection {
            lease_id,
            persisted,
            result,
            held_processes,
            prepared_native_receipt,
            frontend_status,
            effective_invocation: None,
            effective_environment: None,
            public_invocation,
            public_environment,
            export_receipt,
        })
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedImages {
    pub runtime: RuntimeImageDefinitionV1,
    pub input: RuntimeImageDefinitionV1,
    pub runtime_definition: PathBuf,
    pub input_definition: PathBuf,
    pub runtime_source: PathBuf,
    pub input_source: PathBuf,
    pub fixture_sha256: String,
    pub native_linker: PathBuf,
    pub import_receipts: Vec<PathBuf>,
}

pub use crate::consumer_readiness_ledger::{ExclusiveAccount, validate_account_creation_paths};

/// The outer installed owner consumes the durable intent even when useradd or
/// its readback fails. This function never silently removes a partly created
/// account and never reuses the legacy delegated identity.
pub fn provision_exclusive_account(
    identity: &SourceIdentity,
    cell: &ProductKey,
    output: &Path,
) -> Result<ExclusiveAccount> {
    provision_exclusive_account_until(
        identity,
        cell,
        output,
        std::time::Instant::now() + Duration::from_secs(120),
    )
}
pub fn provision_exclusive_account_until(
    identity: &SourceIdentity,
    cell: &ProductKey,
    output: &Path,
    deadline: std::time::Instant,
) -> Result<ExclusiveAccount> {
    provision_account_for_original_lifetime(identity, cell, output, deadline, None)
}

/// Distinct account ownership within the same original installed lifetime.
/// The discriminator is a finite controller role, never a substituted run or
/// product identity.
pub fn provision_cross_attempt_account_until(
    identity: &SourceIdentity,
    cell: &ProductKey,
    output: &Path,
    deadline: std::time::Instant,
) -> Result<ExclusiveAccount> {
    provision_account_for_original_lifetime(
        identity,
        cell,
        output,
        deadline,
        Some("other-attempt-abstract-peer"),
    )
}

pub fn recover_cross_attempt_account_until(
    identity: &SourceIdentity,
    cell: &ProductKey,
    output: &Path,
    deadline: std::time::Instant,
) -> Result<Option<ExclusiveAccount>> {
    let intent_path = output.join("exclusive-account-intent.json");
    let intent_bytes = match read_owned_resource(&intent_path, 64 * 1024) {
        Ok(bytes) => bytes,
        Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let intent = decode_owned_resource_json(&intent_bytes)?;
    let discriminator = Sha256::digest(serde_json::to_vec(&(
        identity,
        cell,
        "other-attempt-abstract-peer",
    ))?);
    let number = u64::from_le_bytes(
        discriminator
            .chunks_exact(std::mem::size_of::<u64>())
            .next()
            .expect("SHA256 discriminator")
            .try_into()
            .expect("u64 discriminator width"),
    );
    let name = format!("mc-ready-{number:x}");
    let fields = [
        "format",
        "revision",
        "run_id",
        "cell",
        "account_name",
        "native_absence_verified",
        "creation_attempted",
        "purpose",
    ];
    if intent.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) || intent["format"] != "memcordon.owned-readiness-account-intent"
        || intent["revision"] != 2
        || intent["run_id"] != identity.run_id
        || intent["cell"] != serde_json::to_value(cell)?
        || intent["account_name"] != name
        || intent["native_absence_verified"] != true
        || intent["creation_attempted"] != true
        || intent["purpose"] != "other-attempt-abstract-peer"
    {
        return Err(CiError::Message(
            "cross account recovery crosses original creation intent".into(),
        ));
    }
    let lookup = |database: &str| -> Result<memcordon_testkit::ObservedOutput> {
        let captured = CommandSpec::new("/usr/bin/getent", output, Duration::from_secs(30))
            .bounded_until(deadline)
            .args([database, &name])
            .output_quiet()?;
        let bytes = serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.owned-readiness-account-recovery-lookup","revision":1,
            "identity":identity,"cell":cell,"intent_sha256":hex::encode(Sha256::digest(&intent_bytes)),"program":"/usr/bin/getent",
            "arguments":[database,&name],"native_exit":captured.status.code(),"stdout":captured.stdout,"stderr":captured.stderr}),
        )?;
        let mut retained = false;
        for ordinal in 0..128 {
            let path = output.join(format!(
                "exclusive-account-recovery-{database}-{ordinal}.json"
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    File::open(output)?.sync_all()?;
                    retained = true;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        if !retained {
            return Err(CiError::Message(
                "original account recovery capture bound exhausted".into(),
            ));
        }
        Ok(captured)
    };
    let passwd = lookup("passwd")?;
    let group = lookup("group")?;
    let named_absent = passwd.status.code() == Some(2)
        && passwd.stdout.is_empty()
        && group.status.code() == Some(2)
        && group.stdout.is_empty();
    let original_passwd = output.join("exclusive-account-getent.bin");
    let original_group = output.join("exclusive-group-getent.bin");
    if named_absent && !original_passwd.exists() && !original_group.exists() {
        return Ok(None);
    }
    if !named_absent && (!passwd.status.success() || !group.status.success()) {
        return Err(CiError::Message(
            "partial cross account/group ownership lacks complete native lookup; intent retained"
                .into(),
        ));
    }
    let passwd_bytes = if named_absent {
        read_owned_resource(&original_passwd, 4096)?
    } else {
        passwd.stdout.clone()
    };
    let group_bytes = if named_absent {
        read_owned_resource(&original_group, 4096)?
    } else {
        group.stdout.clone()
    };
    let invocation_bytes = read_owned_resource(
        &output.join("exclusive-account-useradd-invocation.json"),
        64 * 1024,
    )?;
    let invocation = decode_owned_resource_json(&invocation_bytes)?;
    let creation = decode_owned_resource_json(&read_owned_resource(
        &output.join("exclusive-account-useradd-creation.json"),
        64 * 1024,
    )?)?;
    let exit = decode_owned_resource_json(&read_owned_resource(
        &output.join("exclusive-account-useradd-exit.json"),
        64 * 1024,
    )?)?;
    let stdout = read_owned_resource(
        &output.join("exclusive-account-useradd-stdout.bin"),
        1024 * 1024,
    )?;
    let stderr = read_owned_resource(
        &output.join("exclusive-account-useradd-stderr.bin"),
        1024 * 1024,
    )?;
    let original_image = read_owned_resource(
        &output.join("exclusive-account-useradd-image.bin"),
        64 * 1024 * 1024,
    )?;
    let closed = |value: &serde_json::Value, fields: &[&str]| {
        value.as_object().is_some_and(|object| {
            object.len() == fields.len() && object.keys().all(|key| fields.contains(&key.as_str()))
        })
    };
    if !closed(
        &invocation,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "purpose",
            "program",
            "program_sha256",
            "arguments",
            "cwd",
            "intent_sha256",
        ],
    ) || !closed(
        &creation,
        &[
            "format",
            "revision",
            "process_id",
            "birth",
            "invocation_sha256",
            "kernel_image",
        ],
    ) || !closed(
        &creation["kernel_image"],
        &["device", "inode", "length", "sha256"],
    ) || !closed(
        &exit,
        &[
            "format",
            "revision",
            "held",
            "raw_wait_status",
            "native_exit",
            "signal",
            "invocation_sha256",
            "stdout_sha256",
            "stderr_sha256",
        ],
    ) || !closed(
        &exit["held"],
        &[
            "pid",
            "birth",
            "parent_pid",
            "parent_birth",
            "retirement_observed",
        ],
    ) || original_image.is_empty()
        || invocation["program_sha256"] != hex::encode(Sha256::digest(&original_image))
        || creation["kernel_image"]["length"] != original_image.len() as u64
        || creation["kernel_image"]["device"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || creation["kernel_image"]["inode"]
            .as_u64()
            .is_none_or(|value| value == 0)
    {
        return Err(CiError::Message(
            "cross account original creator image/closed custody schema differs".into(),
        ));
    }
    let arguments = [
        "--system",
        "--no-create-home",
        "--shell",
        "/usr/sbin/nologin",
        "--user-group",
        "--",
        &name,
    ];
    if invocation["format"] != "memcordon.owned-readiness-account-creation-invocation"
        || invocation["revision"] != 1
        || invocation["identity"] != serde_json::to_value(identity)?
        || invocation["cell"] != serde_json::to_value(cell)?
        || invocation["purpose"] != "other-attempt-abstract-peer"
        || invocation["program"] != "/usr/sbin/useradd"
        || invocation["arguments"] != serde_json::to_value(arguments)?
        || invocation["cwd"] != serde_json::to_value(output)?
        || invocation["intent_sha256"] != hex::encode(Sha256::digest(&intent_bytes))
        || creation["format"] != "memcordon.owned-readiness-account-creation"
        || creation["revision"] != 1
        || creation["process_id"].as_u64().is_none_or(|pid| pid == 0)
        || creation["birth"].as_u64().is_none_or(|birth| birth == 0)
        || creation["invocation_sha256"] != hex::encode(Sha256::digest(&invocation_bytes))
        || creation["kernel_image"]["sha256"] != invocation["program_sha256"]
        || exit["format"] != "memcordon.owned-readiness-account-creation-exit"
        || exit["revision"] != 1
        || exit["held"]["pid"] != creation["process_id"]
        || exit["held"]["birth"] != creation["birth"]
        || exit["held"]["retirement_observed"] != true
        || exit["raw_wait_status"] != 0
        || exit["native_exit"] != 0
        || !exit["signal"].is_null()
        || exit["invocation_sha256"] != hex::encode(Sha256::digest(&invocation_bytes))
        || exit["stdout_sha256"] != hex::encode(Sha256::digest(&stdout))
        || exit["stderr_sha256"] != hex::encode(Sha256::digest(&stderr))
    {
        return Err(CiError::Message("partial account recovery lacks original successful useradd Child/kernel/PIDFD/wait custody".into()));
    }
    let text =
        std::str::from_utf8(&passwd_bytes).map_err(|error| CiError::Message(error.to_string()))?;
    let rows = text.lines().collect::<Vec<_>>();
    if rows.len() != 1 {
        return Err(CiError::Message(
            "recovered account native passwd row differs".into(),
        ));
    }
    let values = rows[0].split(':').collect::<Vec<_>>();
    if values.len() != 7 || values[0] != name || values[6] != "/usr/sbin/nologin" {
        return Err(CiError::Message(
            "recovered account native name/shell differs".into(),
        ));
    }
    let uid = values[2]
        .parse::<u32>()
        .map_err(|error| CiError::Message(error.to_string()))?;
    let gid = values[3]
        .parse::<u32>()
        .map_err(|error| CiError::Message(error.to_string()))?;
    if [0, 65533, 65534].contains(&uid)
        || [0, 65533, 65534].contains(&gid)
        || group_bytes != format!("{name}:x:{gid}:\n").as_bytes()
    {
        return Err(CiError::Message(
            "recovered account aliases another principal or native group".into(),
        ));
    }
    let native_readback = output.join("exclusive-account-getent.bin");
    let group_readback = output.join("exclusive-group-getent.bin");
    for (path, bytes) in [
        (&native_readback, &passwd_bytes),
        (&group_readback, &group_bytes),
    ] {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => retain(path, bytes)?,
            Ok(_) => {
                if read_owned_resource(path, 4096)? != *bytes {
                    return Err(CiError::Message(
                        "recovered account native identity replaces original readback".into(),
                    ));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(Some(ExclusiveAccount {
        name,
        uid,
        gid,
        intent: intent_path,
        native_readback,
        group_readback,
    }))
}

fn provision_account_for_original_lifetime(
    identity: &SourceIdentity,
    cell: &ProductKey,
    output: &Path,
    deadline: std::time::Instant,
    purpose: Option<&str>,
) -> Result<ExclusiveAccount> {
    if std::time::Instant::now() >= deadline {
        return Err(CiError::Message(
            "exclusive account acquisition exhausted its original work cutoff".into(),
        ));
    }
    let discriminator = match purpose {
        None => serde_json::to_vec(&(identity, cell))?,
        Some("other-attempt-abstract-peer") => {
            serde_json::to_vec(&(identity, cell, "other-attempt-abstract-peer"))?
        }
        Some(_) => {
            return Err(CiError::Message(
                "unknown finite original account purpose".into(),
            ));
        }
    };
    let nonce = Sha256::digest(discriminator);
    let account_number = u64::from_le_bytes(
        nonce
            .chunks_exact(std::mem::size_of::<u64>())
            .next()
            .expect("SHA-256 contains a native account discriminator")
            .try_into()
            .expect("account discriminator has the u64 byte width"),
    );
    let name = format!("mc-ready-{account_number:x}");
    let lookup = CommandSpec::new("/usr/bin/getent", output, Duration::from_secs(30))
        .bounded_until(deadline)
        .arg("passwd")
        .arg(&name)
        .output()?;
    if lookup.status.code() != Some(2) || !lookup.stdout.is_empty() {
        return Err(CiError::Message("fresh readiness account already exists or native lookup failed; no account creation attempted".into()));
    }
    let intent = output.join("exclusive-account-intent.json");
    let mut intent_value = serde_json::json!({"format":"memcordon.owned-readiness-account-intent","revision":if purpose.is_some(){2}else{1},
        "run_id":identity.run_id,"cell":cell,"account_name":name,"native_absence_verified":true,"creation_attempted":true});
    if let Some(purpose) = purpose {
        intent_value["purpose"] = purpose.into();
    }
    retain(&intent, &serde_json::to_vec(&intent_value)?)?;
    File::open(output)?.sync_all()?;
    let creation_arguments = [
        "--system",
        "--no-create-home",
        "--shell",
        "/usr/sbin/nologin",
        "--user-group",
        "--",
        &name,
    ];
    let creation_program = File::open("/usr/sbin/useradd")?;
    let creation_program_metadata = creation_program.metadata()?;
    if !creation_program_metadata.is_file()
        || creation_program_metadata.uid() != 0
        || creation_program_metadata.mode() & 0o022 != 0
        || creation_program_metadata.nlink() != 1
    {
        return Err(CiError::Message(
            "native account creation executable lacks protected original custody".into(),
        ));
    }
    let creation_program_bytes =
        read_owned_resource(Path::new("/usr/sbin/useradd"), 64 * 1024 * 1024)?;
    retain(
        &output.join("exclusive-account-useradd-image.bin"),
        &creation_program_bytes,
    )?;
    let invocation = serde_json::to_vec(
        &serde_json::json!({"format":"memcordon.owned-readiness-account-creation-invocation","revision":1,
        "identity":identity,"cell":cell,"purpose":purpose,"program":"/usr/sbin/useradd","program_sha256":hex::encode(Sha256::digest(&creation_program_bytes)),
        "arguments":creation_arguments,"cwd":output,"intent_sha256":hex::encode(Sha256::digest(std::fs::read(&intent)?))}),
    )?;
    retain(
        &output.join("exclusive-account-useradd-invocation.json"),
        &invocation,
    )?;
    let mut creation_owner = None;
    let created=CommandSpec::new("/usr/sbin/useradd",output,Duration::from_secs(30)).bounded_until(deadline)
        .args(creation_arguments).output_quiet_with_creation(|child|{
            let pid=child.id();let birth=crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)?;
            creation_owner=Some(crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid,birth).map_err(CiError::Message)?);
            let held=creation_owner.as_mut().expect("original creator retained");
            let image=held.hold_executable_image(deadline).map_err(CiError::Message)?;
            if image["device"]!=creation_program_metadata.dev()||image["inode"]!=creation_program_metadata.ino()
                ||image["length"]!=creation_program_metadata.len()||image["sha256"]!=hex::encode(Sha256::digest(&creation_program_bytes)){
                return Err(CiError::Message("native account creator kernel image differs from original program".into()));
            }
            retain(&output.join("exclusive-account-useradd-creation.json"),&serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.owned-readiness-account-creation","revision":1,"process_id":pid,"birth":birth,
                "invocation_sha256":hex::encode(Sha256::digest(&invocation)),"kernel_image":image}))?)?;
            Ok(())
        })?;
    use std::os::unix::process::ExitStatusExt;
    let creation_owner = creation_owner.ok_or_else(|| {
        CiError::Message("native account creator original Child custody absent".into())
    })?;
    let creation_identity = creation_owner
        .retirement_identity()
        .map_err(CiError::Message)?;
    if !creation_identity.retirement_observed {
        return Err(CiError::Message(
            "native account creator PIDFD remains live after original Child wait".into(),
        ));
    }
    retain(
        &output.join("exclusive-account-useradd-stdout.bin"),
        &created.stdout,
    )?;
    retain(
        &output.join("exclusive-account-useradd-stderr.bin"),
        &created.stderr,
    )?;
    retain(
        &output.join("exclusive-account-useradd-exit.json"),
        &serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.owned-readiness-account-creation-exit","revision":1,"held":creation_identity,
        "raw_wait_status":created.status.into_raw(),"native_exit":created.status.code(),"signal":created.status.signal(),
        "invocation_sha256":hex::encode(Sha256::digest(&invocation)),"stdout_sha256":hex::encode(Sha256::digest(&created.stdout)),
        "stderr_sha256":hex::encode(Sha256::digest(&created.stderr))}))?,
    )?;
    if !created.status.success() {
        return Err(CiError::Message(
            "native account creation failed; original creation custody retained".into(),
        ));
    }
    let readback = CommandSpec::new("/usr/bin/getent", output, Duration::from_secs(30))
        .bounded_until(deadline)
        .arg("passwd")
        .arg(&name)
        .run()?;
    let native_readback = output.join("exclusive-account-getent.bin");
    retain(&native_readback, &readback)?;
    if readback.len() > 4096 {
        return Err(CiError::Message(
            "native account readback exceeds finite bound".into(),
        ));
    }
    let text = std::str::from_utf8(&readback).map_err(|e| CiError::Message(e.to_string()))?;
    let rows = text.lines().collect::<Vec<_>>();
    if rows.len() != 1 {
        return Err(CiError::Message(
            "native account readback is not one exact account".into(),
        ));
    }
    let fields = rows[0].split(':').collect::<Vec<_>>();
    if fields.len() != 7 || fields[0] != name || fields[6] != "/usr/sbin/nologin" {
        return Err(CiError::Message(
            "created native account readback differs".into(),
        ));
    }
    let uid = fields[2]
        .parse::<u32>()
        .map_err(|e| CiError::Message(e.to_string()))?;
    let gid = fields[3]
        .parse::<u32>()
        .map_err(|e| CiError::Message(e.to_string()))?;
    if [0, 65533, 65534].contains(&uid) || [0, 65533, 65534].contains(&gid) {
        return Err(CiError::Message(
            "fresh exclusive account aliases root/caller/legacy identity; cleanup intent retained"
                .into(),
        ));
    }
    File::open(output)?.sync_all()?;
    let group = CommandSpec::new("/usr/bin/getent", output, Duration::from_secs(30))
        .bounded_until(deadline)
        .args(["group", &name])
        .run()?;
    let group_text = std::str::from_utf8(&group).map_err(|e| CiError::Message(e.to_string()))?;
    let expected = format!("{name}:x:{gid}:\n");
    if group_text != expected {
        return Err(CiError::Message(
            "fresh native group creation readback differs; intent retained".into(),
        ));
    }
    let group_readback = output.join("exclusive-group-getent.bin");
    retain(&group_readback, &group)?;
    Ok(ExclusiveAccount {
        name,
        uid,
        gid,
        intent,
        native_readback,
        group_readback,
    })
}

/// Captures native credentials and the provider's actual attempt namespace.
/// This is read-only evidence; it never removes a process or cgroup by name.
#[expect(
    clippy::too_many_arguments,
    reason = "Refusal census binds original policy, account, invocation, lease, acquisition, and artifact custody"
)]
pub fn persist_policy_refusal_census(
    account: &ExclusiveAccount,
    provider: &memcordon_core::PublicProviderBindingV1,
    identity: &SourceIdentity,
    cell: &ProductKey,
    lease_id: &str,
    scenario: &str,
    attempt: &str,
    raw_result: &[u8],
    provider_request: &[u8],
    destination: &Path,
    deadline: std::time::Instant,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if attempt.len() != 32
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CiError::Message(
            "native refusal census attempt basename differs".into(),
        ));
    }
    let mut cgroup_ancestors = vec![File::open("/")?];
    for component in ["sys", "fs", "cgroup", "memcordon-sealed"] {
        let file = File::from(
            rustix::fs::openat(
                cgroup_ancestors.last().expect("held cgroup ancestor"),
                component,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        let metadata = file.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "native cgroup census ancestor custody differs".into(),
            ));
        }
        cgroup_ancestors.push(file);
    }
    let root = cgroup_ancestors
        .last()
        .expect("held native cgroup root")
        .try_clone()?;
    let before = root.metadata()?;
    let filesystem_type = rustix::fs::fstatfs(&root)
        .map_err(|error| CiError::Message(error.to_string()))?
        .f_type as u64;
    if filesystem_type != 0x63677270 {
        return Err(CiError::Message(
            "native policy census parent is not cgroup2".into(),
        ));
    }
    if before.uid() != 0 || !before.is_dir() || before.mode() & 0o022 != 0 {
        return Err(CiError::Message(
            "native provider cgroup census root custody differs".into(),
        ));
    }
    let mut tasks = Vec::new();
    let mut retained_status_bytes = 0usize;
    let mut credential_entries = 0usize;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let entries = match std::fs::read_dir(entry.path().join("task")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for task in entries {
            if tasks.len() >= 65536 || std::time::Instant::now() >= deadline {
                return Err(CiError::Message(
                    "native policy census exceeds original cutoff/task bound".into(),
                ));
            }
            let task = task?;
            let tid = task
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
                .ok_or_else(|| CiError::Message("native task name malformed".into()))?;
            let task_birth = || -> std::io::Result<u64> {
                let mut text = String::new();
                File::open(task.path().join("stat"))?
                    .take(65537)
                    .read_to_string(&mut text)?;
                if text.len() > 65536 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "native task stat exceeds bound",
                    ));
                }
                let (_, fields) = text.rsplit_once(')').ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "native task stat malformed",
                    )
                })?;
                fields
                    .split_whitespace()
                    .nth(19)
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "native task birth absent",
                        )
                    })?
                    .parse()
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            };
            let birth = match task_birth() {
                Ok(birth) => birth,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let status = match (|| -> std::io::Result<String> {
                let mut status = String::new();
                File::open(task.path().join("status"))?
                    .take(65537)
                    .read_to_string(&mut status)?;
                Ok(status)
            })() {
                Ok(status) if status.len() <= 65536 => status,
                Ok(_) => {
                    return Err(CiError::Message(
                        "native credential status exceeds bound".into(),
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let credentials = |prefix: &str, required: Option<usize>| -> Result<Vec<u32>> {
                let line = status
                    .lines()
                    .find(|line| line.starts_with(prefix))
                    .ok_or_else(|| {
                        CiError::Message("native census credential row absent".into())
                    })?;
                let values = line[prefix.len()..]
                    .split_whitespace()
                    .map(str::parse::<u32>)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|error| CiError::Message(error.to_string()))?;
                if required.is_some_and(|count| values.len() != count) || values.len() > 65536 {
                    return Err(CiError::Message(
                        "native census credential vector differs".into(),
                    ));
                }
                Ok(values)
            };
            let uid = credentials("Uid:", Some(4))?;
            let gid = credentials("Gid:", Some(4))?;
            let groups = credentials("Groups:", None)?;
            retained_status_bytes =
                retained_status_bytes
                    .checked_add(status.len())
                    .ok_or_else(|| {
                        CiError::Message("native census status byte count overflow".into())
                    })?;
            credential_entries = credential_entries
                .checked_add(uid.len() + gid.len() + groups.len())
                .ok_or_else(|| {
                    CiError::Message("native census credential count overflow".into())
                })?;
            if retained_status_bytes > 8 * 1024 * 1024 || credential_entries > 262144 {
                return Err(CiError::Message(
                    "native census aggregate credential/status bound exceeded".into(),
                ));
            }
            if uid.contains(&account.uid)
                || gid.contains(&account.gid)
                || groups.contains(&account.gid)
            {
                return Err(CiError::Message(
                    "exclusive target identity remains in actual native task census".into(),
                ));
            }
            let after_birth = match task_birth() {
                Ok(birth) => birth,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if after_birth != birth {
                return Err(CiError::Message(
                    "native credential task birth changed during census".into(),
                ));
            }
            tasks.push(serde_json::json!({"pid":pid,"tid":tid,"birth":birth,"uids":uid,"gids":gid,"groups":groups}));
        }
    }
    let mut cgroups = Vec::new();
    for (ordinal, entry) in std::fs::read_dir(format!(
        "/proc/self/fd/{}",
        std::os::fd::AsRawFd::as_raw_fd(&root)
    ))?
    .enumerate()
    {
        if ordinal >= 4096 {
            return Err(CiError::Message(
                "native cgroup parent entry bound exceeded".into(),
            ));
        }
        if std::time::Instant::now() >= deadline {
            return Err(CiError::Message(
                "native cgroup census crossed original cutoff".into(),
            ));
        }
        let entry = entry?;
        let name = entry.file_name();
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            cgroups.push(name.as_encoded_bytes().to_vec());
        }
    }
    if !cgroups.is_empty() {
        return Err(CiError::Message(
            "native provider attempt cgroups remain after no-target refusal".into(),
        ));
    }
    let named = File::from(
        rustix::fs::openat(
            &cgroup_ancestors[3],
            "memcordon-sealed",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| CiError::Message(error.to_string()))?,
    );
    let after = named.metadata()?;
    if (before.dev(), before.ino(), before.uid(), before.mode())
        != (after.dev(), after.ino(), after.uid(), after.mode())
    {
        return Err(CiError::Message(
            "native cgroup census parent replaced".into(),
        ));
    }
    let absent = |parent: &File| -> Result<i32> {
        match rustix::fs::statat(parent, attempt, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(libc::ENOENT),
            Err(error) => Err(CiError::Message(error.to_string())),
            Ok(_) => Err(CiError::Message(
                "native attempt path remains after no-target refusal".into(),
            )),
        }
    };
    let cgroup_absence_errno = absent(&root)?;
    let mut state_ancestors = vec![File::open("/")?];
    for component in ["var", "lib", "memcordon", "sealed"] {
        let file = File::from(
            rustix::fs::openat(
                state_ancestors.last().expect("held state ancestor"),
                component,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        let metadata = file.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "native refusal journal ancestor custody differs".into(),
            ));
        }
        state_ancestors.push(file);
    }
    let state = state_ancestors.last().expect("held native state root");
    let state_metadata = state.metadata()?;
    let journal_absence_errno = absent(state)?;
    for (ordinal, component) in ["var", "lib", "memcordon", "sealed"].iter().enumerate() {
        let named = File::from(
            rustix::fs::openat(
                &state_ancestors[ordinal],
                *component,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        let actual = named.metadata()?;
        let held = state_ancestors[ordinal + 1].metadata()?;
        if (actual.dev(), actual.ino(), actual.uid(), actual.mode())
            != (held.dev(), held.ino(), held.uid(), held.mode())
        {
            return Err(CiError::Message(
                "native refusal journal ancestor replaced during census".into(),
            ));
        }
    }
    for (ordinal, component) in ["sys", "fs", "cgroup", "memcordon-sealed"]
        .iter()
        .enumerate()
    {
        let named = File::from(
            rustix::fs::openat(
                &cgroup_ancestors[ordinal],
                *component,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        let actual = named.metadata()?;
        let held = cgroup_ancestors[ordinal + 1].metadata()?;
        if (actual.dev(), actual.ino(), actual.uid(), actual.mode())
            != (held.dev(), held.ino(), held.uid(), held.mode())
        {
            return Err(CiError::Message(
                "native cgroup census ancestor replaced".into(),
            ));
        }
    }
    absent(state)?;
    absent(&root)?;
    let bytes = serde_json::to_vec(
        &serde_json::json!({"format":"memcordon.linux-policy-native-census","revision":1,
        "identity":identity,"cell":cell,"lease_id":lease_id,"scenario":scenario,"attempt_id":attempt,"provider":provider,"account":account,
        "result_sha256":hex::encode(Sha256::digest(raw_result)),"request_sha256":hex::encode(Sha256::digest(provider_request)),
        "tasks":tasks,"cgroup_root":{"path":"/sys/fs/cgroup/memcordon-sealed","device":before.dev(),"inode":before.ino(),"uid":before.uid(),"mode":before.mode(),"filesystem_type":filesystem_type,"attempt_directories":cgroups,"attempt_absence_errno":cgroup_absence_errno},
        "journal_root":{"path":"/var/lib/memcordon/sealed","device":state_metadata.dev(),"inode":state_metadata.ino(),"uid":state_metadata.uid(),"mode":state_metadata.mode(),"attempt_absence_errno":journal_absence_errno}}),
    )?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(CiError::Message(
            "native policy census receipt exceeds bound".into(),
        ));
    }
    retain(destination, &bytes)
}

pub(super) fn observe_account_quiescence(
    uid: u32,
    gid: u32,
    deadline: std::time::Instant,
) -> Result<()> {
    let mut count = 0usize;
    for process in std::fs::read_dir("/proc")? {
        let process = process?;
        if !process
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let tasks = match std::fs::read_dir(process.path().join("task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for task in tasks {
            count += 1;
            if count > 1_048_576 || std::time::Instant::now() >= deadline {
                return Err(CiError::Message(
                    "native account quiescence scan exceeds count/deadline; identity retained"
                        .into(),
                ));
            }
            let status = match std::fs::read_to_string(task?.path().join("status")) {
                Ok(status) => status,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for (prefix, owned, required) in
                [("Uid:", uid, 4), ("Gid:", gid, 4), ("Groups:", gid, 0)]
            {
                let line = status
                    .lines()
                    .find(|line| line.starts_with(prefix))
                    .ok_or_else(|| CiError::Message("native task credential row absent".into()))?;
                let values = line[prefix.len()..]
                    .split_whitespace()
                    .map(str::parse::<u32>)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| CiError::Message(e.to_string()))?;
                if (required != 0 && values.len() != required) || values.contains(&owned) {
                    return Err(CiError::Message(
                        "owned UID/GID remains live in native task credentials".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

pub struct ActivatedMixedPolicy {
    pub registry: memcordon_core::workload_registry_v3::RuntimePrivatePolicyRegistryV3,
    pub contract: memcordon_core::workload_contract_v3::WorkloadContractV3,
    pub policy_path: PathBuf,
    pub activation_path: PathBuf,
}

#[expect(
    clippy::too_many_arguments,
    reason = "Policy activation binds independent installed image, account, lease, source, and destination custody"
)]
pub fn activate_owned_policy(
    legacy: memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry,
    images: &MixedImages,
    account: &ExclusiveAccount,
    identity: &SourceIdentity,
    cell: &ProductKey,
    requirements: Vec<memcordon_core::workload_contract_v3::RequirementV3>,
    output_files: Vec<RootRelativePath>,
    output: &Path,
) -> Result<ActivatedMixedPolicy> {
    activate_owned_policy_until(
        legacy,
        images,
        account,
        identity,
        cell,
        requirements,
        output_files,
        output,
        std::time::Instant::now() + Duration::from_secs(60),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Policy activation additionally binds its original finite deadline"
)]
pub fn activate_owned_policy_until(
    legacy: memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry,
    images: &MixedImages,
    account: &ExclusiveAccount,
    identity: &SourceIdentity,
    cell: &ProductKey,
    requirements: Vec<memcordon_core::workload_contract_v3::RequirementV3>,
    output_files: Vec<RootRelativePath>,
    output: &Path,
    deadline: std::time::Instant,
) -> Result<ActivatedMixedPolicy> {
    activate_owned_policy_staged_until(
        legacy,
        images,
        account,
        identity,
        cell,
        requirements,
        output_files,
        output,
        output,
        deadline,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Staged policy activation independently binds original lease, acquisition, image, account, stage, and deadline"
)]
pub fn activate_owned_policy_staged_until(
    legacy: memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry,
    images: &MixedImages,
    account: &ExclusiveAccount,
    identity: &SourceIdentity,
    cell: &ProductKey,
    requirements: Vec<memcordon_core::workload_contract_v3::RequirementV3>,
    output_files: Vec<RootRelativePath>,
    output: &Path,
    protected_output: &Path,
    deadline: std::time::Instant,
) -> Result<ActivatedMixedPolicy> {
    if std::time::Instant::now() >= deadline {
        return Err(CiError::Message(
            "original policy work cutoff exhausted".into(),
        ));
    }
    use memcordon_core::workload_contract::{AuthorizationRef, PolicyEpoch};
    use memcordon_core::workload_contract_v3::*;
    use memcordon_core::workload_registry_v3::*;
    use std::num::{NonZeroU32, NonZeroU64};
    let runtime_image = images.runtime.reference().map_err(CiError::Message)?;
    let input_image = images.input.reference().map_err(CiError::Message)?;
    let declaration = serde_json::to_vec(
        &serde_json::json!({"format":"memcordon.owned-readiness-exclusive-use-declaration","revision":1,
        "run_id":identity.run_id,"cell":cell,"account":account.name,"uid":account.uid,"gid":account.gid,
        "purpose":"exclusive installed readiness attempt identity; no unrelated login or workload"}),
    )?;
    let declaration_path = output.join("exclusive-use-policy.json");
    retain(&declaration_path, &declaration)?;
    let execution = ExclusiveIdentityDefinitionV3 {
        identity_id: id("owned-readiness-identity")?,
        enabled: true,
        uid: NonZeroU32::new(account.uid)
            .ok_or_else(|| CiError::Message("exclusive UID zero".into()))?,
        gid: NonZeroU32::new(account.gid)
            .ok_or_else(|| CiError::Message("exclusive GID zero".into()))?,
        supplementary_groups: BoundedVec::default(),
        exclusive_use_policy: BoundObjectRef {
            id: id("owned-exclusive-use")?,
            digest: DiagnosticSha256::from_bytes(Sha256::digest(&declaration).into()),
        },
        reservation_key: id("owned-readiness-reservation")?,
    };
    let execution_identity = execution.reference().map_err(CiError::Message)?;
    let layout = RootLayoutDefinitionV1 {
        format: "memcordon.root-layout".into(),
        revision: 1,
        layout_id: id("owned-readiness-root")?,
        runtime_image: runtime_image.clone(),
        input_image: input_image.clone(),
        writable_roots: bounded([WritableRootV1 {
            id: id("work")?,
            path: path(Path::new("work"))?,
            byte_limit: NonZeroU64::new(IMAGE_TOTAL_BYTES).expect("nonzero image bound"),
            generated_execution: true,
        }])?,
        output_files: bounded(output_files)?,
    };
    let root_layout = layout.reference().map_err(CiError::Message)?;
    let requirements: BoundedVec<RequirementV3, 64> = bounded(requirements)?;
    let approved = serde_json::to_vec(&(
        &runtime_image,
        &input_image,
        &root_layout,
        &execution_identity,
        &requirements,
    ))?;
    let approved_plan_digest = DiagnosticSha256::from_bytes(Sha256::digest(&approved).into());
    retain(&output.join("approved-plan.json"), &approved)?;
    let profile = profile_reference();
    let grant = PolicyGrantV3 {
        id: id("owned-readiness-grant")?,
        revision: NonZeroU64::new(1).expect("one"),
        enabled: true,
        callers: bounded([memcordon_core::workload_registry::CallerSelector::Linux {
            uid: 65534,
        }])?,
        approved_plans: bounded([approved_plan_digest.clone()])?,
        profile: profile.clone(),
        execution_identity: execution_identity.clone(),
        runtime_image: runtime_image.clone(),
        input_image: input_image.clone(),
        root_layout: root_layout.clone(),
    };
    let registry = RuntimePrivatePolicyRegistryV3 {
        format: "memcordon.local-private-policy".into(),
        revision: 2,
        legacy,
        execution_identities: bounded([execution])?,
        images: bounded([images.runtime.clone(), images.input.clone()])?,
        root_layouts: bounded([layout])?,
        grants: bounded([grant])?,
        active_attempt_disposition:
            memcordon_core::workload_registry::GrantChangeDisposition::DrainExisting,
    };
    registry.validate().map_err(CiError::Message)?;
    let policy_bytes = serde_json::to_vec(&registry)?;
    let policy_path = output.join("mixed.policy.json");
    retain(&policy_path, &policy_bytes)?;
    File::open(output)?.sync_all()?;
    use std::os::fd::AsFd;
    let mut source_directories = Vec::new();
    if protected_output != output {
        let parent = protected_output
            .parent()
            .ok_or_else(|| CiError::Message("protected policy parent absent".into()))?;
        source_directories = super::linux_native_component::protected_directory(parent)?;
        let name = protected_output
            .file_name()
            .ok_or_else(|| CiError::Message("protected policy source name absent".into()))?;
        retain(
            &output.join("protected-policy-source-intent.json"),
            &serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.owned-readiness-policy-source-intent","revision":1,"run_id":identity.run_id,
            "source_commit":identity.source_commit,"source_tree_sha256":identity.source_tree_sha256,
            "cell":cell,"path":protected_output,"policy_sha256":hex::encode(Sha256::digest(&policy_bytes))}))?,
        )?;
        File::open(output)?.sync_all()?;
        rustix::fs::mkdirat(
            source_directories
                .last()
                .expect("held protected parent")
                .as_fd(),
            name,
            rustix::fs::Mode::from_raw_mode(0o700),
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        source_directories
            .last()
            .expect("held protected parent")
            .sync_all()?;
    }
    source_directories.extend(super::linux_native_component::protected_directory(
        protected_output,
    )?);
    let protected_policy = protected_output.join("mixed.policy.json");
    if protected_output != output {
        retain(&protected_policy, &policy_bytes)?;
        source_directories
            .last()
            .expect("held policy directory")
            .sync_all()?;
    }
    let policy_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&protected_policy)?;
    let policy_identity = policy_file.metadata()?;
    if policy_identity.uid() != 0
        || policy_identity.mode() & 0o022 != 0
        || policy_identity.nlink() != 1
        || !policy_identity.is_file()
        || read_owned_resource(&protected_policy, policy_bytes.len() as u64)? != policy_bytes
    {
        return Err(CiError::Message(
            "protected policy source native identity/readback differs".into(),
        ));
    }
    let activation = CommandSpec::new(
        "/usr/libexec/memcordon-sealed-agent",
        output,
        Duration::from_secs(60),
    )
    .bounded_until(deadline)
    .arg("package")
    .arg("policy")
    .arg("apply")
    .arg("--file")
    .arg(&protected_policy)
    .run()?;
    let named = std::fs::symlink_metadata(&protected_policy)?;
    let after = policy_file.metadata()?;
    let identity_tuple = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.uid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if identity_tuple(&named) != identity_tuple(&policy_identity)
        || identity_tuple(&after) != identity_tuple(&policy_identity)
        || read_owned_resource(&protected_policy, policy_bytes.len() as u64)? != policy_bytes
    {
        return Err(CiError::Message(
            "protected policy source changed during native apply".into(),
        ));
    }
    let activation_path = output.join("mixed.activation.json");
    retain(&activation_path, &activation)?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&activation)
        .map_err(CiError::Message)?;
    let actual: serde_json::Value = serde_json::from_slice(&activation)?;
    if actual.get("format").and_then(serde_json::Value::as_str)
        != Some("memcordon.local-private-activation")
        || actual.get("revision").and_then(serde_json::Value::as_u64) != Some(2)
        || actual.get("registry") != Some(&serde_json::to_value(&registry)?)
        || actual.get("registry_digest")
            != Some(&serde_json::to_value(
                registry.canonical_digest().map_err(CiError::Message)?,
            )?)
    {
        return Err(CiError::Message(
            "actual mixed activation differs from exact owned policy".into(),
        ));
    }
    let epoch: PolicyEpoch = serde_json::from_value(
        actual
            .get("epoch")
            .cloned()
            .ok_or_else(|| CiError::Message("actual mixed activation epoch absent".into()))?,
    )?;
    let contract = WorkloadContractV3 {
        schema_version: ContractVersionThree::default(),
        workload_plan_digest: approved_plan_digest.clone(),
        authorized_profile: profile,
        authorization: AuthorizationRef {
            grant_id: id("owned-readiness-grant")?,
            grant_revision: NonZeroU64::new(1).expect("one"),
            approved_plan_digest,
        },
        ceiling: MixedPrivateCeiling::FreshRootIpv4TcpUnixStreamsIntraAttemptNoGain,
        requirements,
        execution_identity,
        runtime_image,
        input_image,
        root_layout,
        launch: ImageLaunchV1 {
            entrypoint: id("owned-readiness")?,
            working_directory: path(Path::new("work"))?,
        },
        expected_epoch: epoch,
    };
    contract.validate().map_err(CiError::Message)?;
    retain(
        &output.join("mixed.contract.json"),
        &serde_json::to_vec(&contract)?,
    )?;
    File::open(output)?.sync_all()?;
    Ok(ActivatedMixedPolicy {
        registry,
        contract,
        policy_path,
        activation_path,
    })
}

fn id(value: &str) -> Result<LogicalId> {
    LogicalId::new(value.into()).map_err(CiError::Message)
}
fn path(value: &Path) -> Result<RootRelativePath> {
    RootRelativePath::new(
        value
            .to_str()
            .ok_or_else(|| CiError::Message("image path not UTF-8".into()))?
            .into(),
    )
    .map_err(CiError::Message)
}
fn bounded<T, const N: usize>(values: impl IntoIterator<Item = T>) -> Result<BoundedVec<T, N>> {
    let mut result = BoundedVec::default();
    for value in values {
        result.try_push(value).map_err(|_| {
            CiError::Message("owned image inventory exceeds frozen native bound".into())
        })?;
    }
    Ok(result)
}

pub(super) fn read_protected_export(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
    use std::os::fd::AsFd;
    let components = path.components().collect::<Vec<_>>();
    if !matches!(components.first(), Some(std::path::Component::RootDir))
        || !(5..=68).contains(&components.len())
    {
        return Err(CiError::Message(
            "protected export path is not the finite native receipt path".into(),
        ));
    }
    let mut directories = vec![File::from(
        rustix::fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| CiError::Message(e.to_string()))?,
    )];
    let names = components
        .iter()
        .skip(1)
        .map(|part| match part {
            std::path::Component::Normal(name) => Ok(*name),
            _ => Err(CiError::Message(
                "protected export path has alias components".into(),
            )),
        })
        .collect::<Result<Vec<_>>>()?;
    if names[0] != std::ffi::OsStr::new("run")
        || names[1] != std::ffi::OsStr::new("memcordon")
        || !names[2]
            .to_str()
            .is_some_and(|name| name.starts_with("private-export-"))
    {
        return Err(CiError::Message(
            "protected export does not belong to the native export store".into(),
        ));
    }
    for name in &names[..names.len() - 1] {
        let child = File::from(
            openat2(
                directories.last().expect("held root").as_fd(),
                *name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|e| CiError::Message(e.to_string()))?,
        );
        let metadata = child.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "native export ancestry is not root protected".into(),
            ));
        }
        directories.push(child);
    }
    let leaf = *names.last().expect("finite leaf");
    let file = File::from(
        openat2(
            directories.last().expect("held parent").as_fd(),
            leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(|e| CiError::Message(e.to_string()))?,
    );
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() > maximum
    {
        return Err(CiError::Message(
            "native export receipt custody exceeds bound".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&file).take(maximum + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || (before.len(), before.mtime(), before.mtime_nsec())
            != (after.len(), after.mtime(), after.mtime_nsec())
    {
        return Err(CiError::Message(
            "native export receipt changed during bounded read".into(),
        ));
    }
    for (index, name) in names[..names.len() - 1].iter().enumerate() {
        require_admin_named_inode(&directories[index], name, &directories[index + 1])?;
    }
    require_admin_named_inode(directories.last().expect("held parent"), leaf, &file)?;
    Ok(bytes)
}

struct ImageBuilder {
    root: PathBuf,
    entries: BTreeMap<RootRelativePath, ImageEntryV1>,
    originals: BTreeMap<RootRelativePath, PathBuf>,
    total_bytes: u64,
    deadline: std::time::Instant,
}
impl ImageBuilder {
    fn new(root: PathBuf, deadline: std::time::Instant) -> Result<Self> {
        if std::time::Instant::now() >= deadline {
            return Err(CiError::Message(
                "native image acquisition exhausted its original work cutoff".into(),
            ));
        }
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            root,
            entries: BTreeMap::new(),
            originals: BTreeMap::new(),
            total_bytes: 0,
            deadline,
        })
    }
    fn regular(&mut self, source: &Path, member: &Path) -> Result<()> {
        if std::time::Instant::now() >= self.deadline {
            return Err(CiError::Message(
                "native image copy exhausted its original work cutoff".into(),
            ));
        }
        let relative = path(member)?;
        if self.entries.contains_key(&relative) {
            return Ok(());
        }
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(source)?;
        let before = held.metadata()?;
        if !before.is_file()
            || before.len() > memcordon_core::workload_registry_v3::IMAGE_ENTRY_BYTES
        {
            return Err(CiError::Message(
                "toolchain input is not a bounded native regular file".into(),
            ));
        }
        let total = self
            .total_bytes
            .checked_add(before.len())
            .ok_or_else(|| CiError::Message("image byte inventory overflow".into()))?;
        if self.entries.len() >= memcordon_core::workload_registry_v3::IMAGE_ENTRIES
            || total > memcordon_core::workload_registry_v3::IMAGE_TOTAL_BYTES
        {
            return Err(CiError::Message(
                "native image inventory exceeds its finite bound before copying".into(),
            ));
        }
        let mut bytes = Vec::new();
        let mut reader = held.try_clone()?.take(before.len() + 1);
        let mut chunk = [0u8; 64 * 1024];
        loop {
            if std::time::Instant::now() >= self.deadline {
                return Err(CiError::Message(
                    "native image read exhausted its original work cutoff".into(),
                ));
            }
            let count = reader.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        let after = held.metadata()?;
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
        ) || bytes.len() as u64 != before.len()
        {
            return Err(CiError::Message(
                "native toolchain input changed while copied".into(),
            ));
        }
        let output = self.root.join(member);
        std::fs::create_dir_all(
            output
                .parent()
                .ok_or_else(|| CiError::Message("member parent absent".into()))?,
        )?;
        let executable = before.mode() & 0o111 != 0;
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)?;
        for chunk in bytes.chunks(64 * 1024) {
            if std::time::Instant::now() >= self.deadline {
                return Err(CiError::Message(
                    "native image write exhausted its original work cutoff".into(),
                ));
            }
            target.write_all(chunk)?;
        }
        target.set_permissions(std::fs::Permissions::from_mode(if executable {
            0o555
        } else {
            0o444
        }))?;
        target.sync_all()?;
        self.entries.insert(
            relative.clone(),
            ImageEntryV1::Regular {
                path: relative.clone(),
                sha256: DiagnosticSha256::from_bytes(Sha256::digest(&bytes).into()),
                size: bytes.len() as u64,
                executable,
            },
        );
        self.originals.insert(relative, source.to_path_buf());
        self.total_bytes = total;
        Ok(())
    }
    fn tree(&mut self, source: &Path, member: &Path, native_target: &str) -> Result<()> {
        if std::time::Instant::now() >= self.deadline {
            return Err(CiError::Message(
                "native image traversal exhausted its original work cutoff".into(),
            ));
        }
        let metadata = std::fs::symlink_metadata(source)?;
        if metadata.file_type().is_symlink() {
            // Fresh regular copies eliminate caller aliases. The imported image
            // never shares the original inode or follows a link during import.
            return self.regular(&std::fs::canonicalize(source)?, member);
        }
        if metadata.is_file() {
            return self.regular(source, member);
        }
        if !metadata.is_dir() {
            return Err(CiError::Message(
                "toolchain source includes a special object".into(),
            ));
        }
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let name = entry.file_name();
            if member == Path::new("toolchain/lib/rustlib") {
                let text = name.to_string_lossy();
                if text.contains("-unknown-") && text != native_target {
                    continue;
                }
            }
            if member == Path::new("toolchain/share") && name == "doc" {
                continue;
            }
            self.tree(&entry.path(), &member.join(name), native_target)?;
        }
        Ok(())
    }
    fn host_member(&mut self, source: &Path) -> Result<()> {
        let canonical = std::fs::canonicalize(source)?;
        self.regular(
            &canonical,
            source
                .strip_prefix("/")
                .map_err(|e| CiError::Message(e.to_string()))?,
        )
    }
    fn dependencies(&mut self, target: &str, libraries: &[PathBuf]) -> Result<()> {
        let mut checked = BTreeSet::new();
        loop {
            let pending = self
                .originals
                .iter()
                .find(|(member, _)| !checked.contains(*member))
                .map(|(member, source)| (member.clone(), source.clone()));
            let Some((member, _source)) = pending else {
                break;
            };
            checked.insert(member.clone());
            let held = File::open(self.root.join(member.as_str()))?;
            let length = held.metadata()?.len();
            let Some(elf) = memcordon_core::elf_closure::inspect(
                |offset, buffer| {
                    held.read_exact_at(buffer, offset)
                        .map_err(|e| e.to_string())
                },
                length,
                target,
            )
            .map_err(CiError::Message)?
            else {
                continue;
            };
            if let Some(interpreter) = elf.interpreter {
                self.host_member(Path::new(&interpreter))?;
            }
            for needed in elf.needed {
                let selected = libraries
                    .iter()
                    .map(|directory| directory.join(&needed))
                    .find(|candidate| candidate.is_file())
                    .ok_or_else(|| {
                        CiError::Message(format!(
                            "native ELF dependency missing from measured compiler SDK: {needed}"
                        ))
                    })?;
                if !self.originals.values().any(|source| source == &selected) {
                    self.host_member(&selected)?;
                }
            }
        }
        Ok(())
    }
    fn definition(
        self,
        image_id: &str,
        target: &str,
        entrypoints: Vec<ImageEntrypointV1>,
        libraries: &[PathBuf],
    ) -> Result<RuntimeImageDefinitionV1> {
        let library_directories = libraries
            .iter()
            .filter_map(|directory| directory.strip_prefix("/").ok())
            .map(path)
            .collect::<Result<Vec<_>>>()?;
        let value = RuntimeImageDefinitionV1 {
            format: "memcordon.runtime-image".into(),
            revision: 1,
            image_id: id(image_id)?,
            target: target.into(),
            entries: bounded(self.entries.into_values())?,
            entrypoints: bounded(entrypoints)?,
            library_directories: bounded(library_directories)?,
            startup_environment: BoundedVec::default(),
        };
        value.validate().map_err(CiError::Message)?;
        Ok(value)
    }
}

pub(super) fn retain(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn decode_owned_resource_json(bytes: &[u8]) -> Result<serde_json::Value> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(CiError::Message("owned resource JSON exceeds bound".into()));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(bytes)?)
}

pub(super) fn read_owned_resource(path: &Path, bound: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() > bound
    {
        return Err(CiError::Message(
            "owned resource readback custody differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.try_clone()?.take(bound + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if bytes.len() as u64 != before.len()
        || named.file_type().is_symlink()
        || (named.dev(), named.ino()) != (before.dev(), before.ino())
        || (after.len(), after.mtime(), after.mtime_nsec())
            != (before.len(), before.mtime(), before.mtime_nsec())
    {
        return Err(CiError::Message(
            "owned resource readback named/native identity changed".into(),
        ));
    }
    Ok(bytes)
}

pub fn materialize(
    payload: &MaterializedPayload,
    workspace: &Path,
    output: &Path,
    identity: &SourceIdentity,
    cell: &ProductKey,
) -> Result<MixedImages> {
    materialize_until(
        payload,
        workspace,
        output,
        identity,
        cell,
        std::time::Instant::now() + Duration::from_secs(900),
    )
}
pub fn materialize_until(
    payload: &MaterializedPayload,
    workspace: &Path,
    output: &Path,
    identity: &SourceIdentity,
    cell: &ProductKey,
    deadline: std::time::Instant,
) -> Result<MixedImages> {
    if std::time::Instant::now() >= deadline {
        return Err(CiError::Message(
            "mixed materialization exhausted its original work cutoff".into(),
        ));
    }
    if !cell.target.ends_with("linux-gnu")
        || payload.distribution.target != cell.target
        || identity.run_id.is_empty()
        || payload.source.commit() != identity.source_commit
        || payload.source.version().to_string() != identity.version
    {
        return Err(CiError::Message(
            "mixed materialization product/source cell differs".into(),
        ));
    }
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(CiError::Message(
            "owned native mixed materialization requires the outer installed owner's root helper"
                .into(),
        ));
    }
    std::fs::create_dir(output)?;
    std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700))?;
    let build = output.join("fixture-build");
    CommandSpec::cargo("rustup", workspace, "1.97.1", Duration::from_secs(600))
        .bounded_until(deadline)
        .arg("build")
        .arg("--locked")
        .arg("--package")
        .arg("memcordon")
        .arg("--features")
        .arg("test-fixtures")
        .arg("--bin")
        .arg("memcordon-linux-readiness-fixture")
        .arg("--target")
        .arg(&cell.target)
        .arg("--target-dir")
        .arg(&build)
        .run()?;
    let fixture = build
        .join(&cell.target)
        .join("debug/memcordon-linux-readiness-fixture");
    let fixture_bytes = std::fs::read(&fixture)?;
    super::target::validate_executable(&fixture_bytes, &cell.target)?;
    let rustc = CommandSpec::new("rustup", workspace, Duration::from_secs(30))
        .bounded_until(deadline)
        .arg("which")
        .arg("--toolchain")
        .arg("1.97.1")
        .arg("rustc")
        .run()?;
    let rustc = PathBuf::from(
        std::str::from_utf8(&rustc)
            .map_err(|e| CiError::Message(e.to_string()))?
            .trim(),
    );
    let sysroot = CommandSpec::new(&rustc, workspace, Duration::from_secs(30))
        .bounded_until(deadline)
        .arg("--print")
        .arg("sysroot")
        .run()?;
    let sysroot = PathBuf::from(
        std::str::from_utf8(&sysroot)
            .map_err(|e| CiError::Message(e.to_string()))?
            .trim(),
    );
    let machine = if cell.target.starts_with("x86_64-") {
        "x86_64-linux-gnu"
    } else {
        "aarch64-linux-gnu"
    };
    let mut libraries = vec![
        Path::new("/lib").join(machine),
        Path::new("/usr/lib").join(machine),
        PathBuf::from("/lib64"),
        PathBuf::from("/usr/lib64"),
        PathBuf::from("/lib"),
        PathBuf::from("/usr/lib"),
    ];
    let runtime_source = output.join("runtime-source");
    let input_source = output.join("input-source");
    let mut runtime = ImageBuilder::new(runtime_source.clone(), deadline)?;
    runtime.tree(&sysroot, Path::new("toolchain"), &cell.target)?;
    runtime.regular(&fixture, Path::new("bin/owned-readiness"))?;
    for executable in ["/usr/bin/cc", "/usr/bin/as", "/usr/bin/ld"] {
        runtime.host_member(Path::new(executable))?;
    }
    let gcc = Path::new("/usr/lib/gcc").join(machine);
    if gcc.is_dir() {
        runtime.tree(
            &gcc,
            gcc.strip_prefix("/")
                .map_err(|e| CiError::Message(e.to_string()))?,
            &cell.target,
        )?;
    }
    if gcc.is_dir() {
        for version in std::fs::read_dir(&gcc)? {
            let directory = version?.path();
            if directory.is_dir() {
                libraries.push(directory);
            }
        }
    }
    let search = CommandSpec::new("/usr/bin/cc", workspace, Duration::from_secs(30))
        .bounded_until(deadline)
        .arg("-print-search-dirs")
        .run()?;
    let search = std::str::from_utf8(&search).map_err(|e| CiError::Message(e.to_string()))?;
    for directory in search
        .lines()
        .find_map(|line| line.strip_prefix("libraries: ="))
        .ok_or_else(|| CiError::Message("native compiler SDK library catalogue absent".into()))?
        .split(':')
    {
        let source = Path::new(directory);
        if source.is_absolute() && source.is_dir() {
            let canonical = std::fs::canonicalize(source)?;
            if !libraries.contains(&canonical) {
                libraries.push(canonical);
            }
        }
    }
    for support in [
        "crt1.o",
        "Scrt1.o",
        "crti.o",
        "crtn.o",
        "crtbegin.o",
        "crtbeginS.o",
        "crtend.o",
        "crtendS.o",
        "libgcc.a",
        "libgcc_s.so",
        "libgcc_s.so.1",
        "libc.so",
        "libc.so.6",
        "libc_nonshared.a",
        "libpthread.a",
        "librt.a",
        "libdl.a",
        "libutil.a",
        "libm.so",
        "libm.so.6",
        "libmvec.so",
        "libmvec.so.1",
    ] {
        for directory in &libraries {
            let discovered = directory.join(support);
            if discovered.is_file() {
                runtime.host_member(&discovered)?;
            }
        }
    }
    let mut source_libraries = vec![
        sysroot.join("lib"),
        sysroot.join("lib/rustlib").join(&cell.target).join("lib"),
    ];
    source_libraries.extend(libraries.iter().cloned());
    runtime.dependencies(&cell.target, &source_libraries)?;
    let mut input = ImageBuilder::new(input_source.clone(), deadline)?;
    for relative in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "src/main.rs",
        "tests/generated_child.rs",
    ] {
        input.regular(
            &workspace
                .join("tests/fixtures/linux_readiness")
                .join(relative),
            &Path::new("owned-source").join(relative),
        )?;
    }
    libraries.insert(0, PathBuf::from("/toolchain/lib"));
    libraries.insert(
        1,
        Path::new("/toolchain/lib/rustlib")
            .join(&cell.target)
            .join("lib"),
    );
    let runtime = runtime.definition(
        "owned-readiness-runtime",
        &cell.target,
        vec![ImageEntrypointV1 {
            id: id("owned-readiness")?,
            path: path(Path::new("bin/owned-readiness"))?,
        }],
        &libraries,
    )?;
    let input = input.definition("owned-readiness-source", &cell.target, Vec::new(), &[])?;
    let runtime_definition = output.join("runtime-image.json");
    let input_definition = output.join("input-image.json");
    retain(&runtime_definition, &serde_json::to_vec(&runtime)?)?;
    retain(&input_definition, &serde_json::to_vec(&input)?)?;
    let mut import_receipts = Vec::new();
    for (label, definition, source) in [
        ("runtime", &runtime_definition, &runtime_source),
        ("input", &input_definition, &input_source),
    ] {
        let intent = output.join(label).with_extension("import-intent.json");
        retain(
            &intent,
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.owned-readiness-image-import-intent","revision":1,
            "run_id":identity.run_id,"source_commit":identity.source_commit,"cell":cell,"definition":definition,"source_root":source,
            "image":if label=="runtime"{runtime.reference().map_err(CiError::Message)?}else{input.reference().map_err(CiError::Message)?}}),
            )?,
        )?;
        File::open(output)?.sync_all()?;
        let bytes = CommandSpec::new(
            "/usr/libexec/memcordon-sealed-agent",
            workspace,
            Duration::from_secs(180),
        )
        .bounded_until(deadline)
        .arg("package")
        .arg("policy")
        .arg("image")
        .arg("install")
        .arg("--definition")
        .arg(definition)
        .arg("--source-root")
        .arg(source)
        .arg("--json")
        .run()?;
        let receipt = output.join(label).with_extension("import.json");
        retain(&receipt, &bytes)?;
        import_receipts.push(receipt);
    }
    Ok(MixedImages {
        runtime,
        input,
        runtime_definition,
        input_definition,
        runtime_source,
        input_source,
        fixture_sha256: hex::encode(Sha256::digest(fixture_bytes)),
        native_linker: PathBuf::from("/usr/bin/cc"),
        import_receipts,
    })
}
