//! Installed caller-byte workloads. No policy registry or image installation enters this driver.
use super::linux_request_fixture::{CallerRequestFixture, CallerSession, CallerSnapshot};
use super::linux_request_launch::{LaunchInput, RequestLaunch};
use crate::linux_consumer_readiness::HeldLinuxProcess;
use crate::{CiError, Result};
use memcordon_core::workload_bundle::SnapshotManifestV1;
use memcordon_core::workload_request::WorkloadAttemptAssociationV1;
use memcordon_core::workload_request::{PrivateRootLayoutV1, RootRelativePath};
use memcordon_core::{BoundedVec, PublicProviderBindingV1};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn hold_child_tree(
    anchor: &HeldLinuxProcess,
    parent: &HeldLinuxProcess,
    tree: &serde_json::Value,
    depth: usize,
    owners: &mut Vec<HeldLinuxProcess>,
    snapshots: &mut Vec<serde_json::Value>,
) -> Result<()> {
    if depth > 8 || owners.len() >= 512 {
        return Err(CiError::Message(
            "actual child ancestry exceeds finite observation bound".into(),
        ));
    }
    let pid = u32::try_from(
        tree["pid"]
            .as_u64()
            .ok_or_else(|| CiError::Message("held child native namespace PID absent".into()))?,
    )
    .map_err(|e| CiError::Message(e.to_string()))?;
    let birth = tree["birth"]
        .as_u64()
        .ok_or_else(|| CiError::Message("held child native birth absent".into()))?;
    let mut child = anchor
        .hold_namespace_member(pid, birth)
        .map_err(CiError::Message)?;
    child.verify_parent(parent).map_err(CiError::Message)?;
    snapshots.push(serde_json::json!({"snapshot":child.live_snapshot().map_err(CiError::Message)?,"credentials":child.native_credentials().map_err(CiError::Message)?,"identity":child.retirement_identity().map_err(CiError::Message)?,"namespace_pid":pid}));
    if let Some(members) = tree["members"].as_array() {
        for member in members {
            hold_child_tree(anchor, &child, member, depth + 1, owners, snapshots)?;
        }
    }
    owners.push(child);
    Ok(())
}

pub fn hold_current_attempt(
    association: &WorkloadAttemptAssociationV1,
    cutoff: Instant,
) -> Result<(Vec<HeldLinuxProcess>, serde_json::Value)> {
    let path =
        Path::new("/var/lib/memcordon/workload-attempts").join(hex::encode(association.attempt));
    loop {
        if Instant::now() >= cutoff {
            return Err(CiError::Message(
                "original live native observation cutoff expired".into(),
            ));
        }
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > 512 * 1024
        {
            return Err(CiError::Message(
                "protected current journal custody differs".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(512 * 1024 + 1).read_to_end(&mut bytes)?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
            .map_err(CiError::Message)?;
        let record: serde_json::Value = serde_json::from_slice(&bytes)?;
        if record["association"] != serde_json::to_value(association)? {
            return Err(CiError::Message(
                "live protected journal selects another original attempt".into(),
            ));
        }
        if record["native"].is_null() {
            std::thread::sleep(std::time::Duration::from_millis(1));
            continue;
        }
        let mut held = Vec::new();
        let mut snapshots = Vec::new();
        for role in ["worker", "control", "guardian", "namespace_init", "target"] {
            let pid = u32::try_from(
                record[role]["pid"]
                    .as_u64()
                    .ok_or_else(|| CiError::Message("live native PID absent".into()))?,
            )
            .map_err(|e| CiError::Message(e.to_string()))?;
            let birth = record[role]["start_time"]
                .as_u64()
                .ok_or_else(|| CiError::Message("live native birth absent".into()))?;
            let owner = HeldLinuxProcess::acquire(pid, birth).map_err(CiError::Message)?;
            let snapshot = owner.live_snapshot().map_err(CiError::Message)?;
            snapshots.push(serde_json::json!({"role":role,"snapshot":snapshot,"credentials":owner.native_credentials().map_err(CiError::Message)?}));
            held.push(owner);
        }
        let target = snapshots.last().expect("actual target snapshot");
        let target_snapshot = &target["snapshot"];
        for (observed, reported) in [
            ("mount", "mount_namespace"),
            ("pid", "pid_namespace"),
            ("network", "network_namespace"),
            ("ipc", "ipc_namespace"),
        ] {
            if target_snapshot[observed] != record["native"][reported] {
                return Err(CiError::Message(
                    "provider native namespace differs from independently held target".into(),
                ));
            }
        }
        let root = std::fs::metadata(
            Path::new("/proc")
                .join(held.last().expect("held target").process_id.to_string())
                .join("root"),
        )?;
        if Some(root.dev()) != record["native"]["root_device"].as_u64()
            || Some(root.ino()) != record["native"]["root_inode"].as_u64()
        {
            return Err(CiError::Message(
                "held target root differs from original native provider root".into(),
            ));
        }
        return Ok((
            held,
            serde_json::json!({"format":"memcordon.linux-current-held","revision":1,"association":association,"native":record["native"],"processes":snapshots,"root":{"device":root.dev(),"inode":root.ino()}}),
        ));
    }
}

pub struct CallerImages {
    pub minimal: Option<Box<CallerImages>>,
    pub runtime: SnapshotManifestV1,
    pub input: SnapshotManifestV1,
    pub runtime_manifest: PathBuf,
    pub input_manifest: PathBuf,
    pub runtime_source: PathBuf,
    pub input_source: PathBuf,
}

pub(super) fn caller_tree(
    path: &Path,
    caller: &CallerSession,
    cutoff: Instant,
    remaining: &mut usize,
) -> Result<()> {
    if Instant::now() >= cutoff || *remaining == 0 {
        return Err(CiError::Message(
            "caller source ownership cutoff/count exhausted".into(),
        ));
    }
    *remaining -= 1;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if (!before.is_dir() && !before.is_file() && !before.file_type().is_symlink())
        || (before.is_file() && before.nlink() != 1)
    {
        return Err(CiError::Message(
            "fresh caller source has unexpected native custody".into(),
        ));
    }
    if before.is_dir() {
        for child in std::fs::read_dir(path)? {
            caller_tree(&child?.path(), caller, cutoff, remaining)?;
        }
    }
    rustix::fs::chownat(
        &file,
        "",
        Some(rustix::process::Uid::from_raw(caller.uid)),
        Some(rustix::process::Gid::from_raw(caller.gid)),
        rustix::fs::AtFlags::EMPTY_PATH | rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(std::io::Error::from)?;
    let named = std::fs::symlink_metadata(path)?;
    if (before.dev(), before.ino()) != (named.dev(), named.ino())
        || named.uid() != caller.uid
        || named.gid() != caller.gid
    {
        return Err(CiError::Message(
            "fresh caller source was replaced during ownership transfer".into(),
        ));
    }
    Ok(())
}

impl CallerImages {
    pub fn minimal(&self) -> &Self {
        self.minimal.as_deref().unwrap_or(self)
    }
    pub fn materialize(
        copied: super::linux_test_images::PreparedImages,
        output: &Path,
        caller: &CallerSession,
        cutoff: Instant,
    ) -> Result<Self> {
        let runtime = copied.runtime;
        let input = copied.input;
        runtime.validate().map_err(CiError::Message)?;
        input.validate().map_err(CiError::Message)?;
        let runtime_manifest = output.join("runtime-snapshot.json");
        let input_manifest = output.join("input-snapshot.json");
        let minimal_manifest = output.join("minimal-runtime-snapshot.json");
        super::source::write_diagnostic_json(&minimal_manifest, &copied.minimal_runtime)?;
        super::source::write_diagnostic_json(&runtime_manifest, &runtime)?;
        super::source::write_diagnostic_json(&input_manifest, &input)?;
        let mut remaining = 2 * (16384 * 65 + 128);
        caller_tree(&copied.runtime_source, caller, cutoff, &mut remaining)?;
        caller_tree(&copied.input_source, caller, cutoff, &mut remaining)?;
        caller_tree(
            &copied.minimal_runtime_source,
            caller,
            cutoff,
            &mut remaining,
        )?;
        // Parent traversal does not grant source bytes to the provider. The
        // installed unprivileged packer opens these sources as the actual caller.
        std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o755))?;
        Ok(Self {
            minimal: Some(Box::new(Self {
                minimal: None,
                runtime: copied.minimal_runtime,
                input: input.clone(),
                runtime_manifest: minimal_manifest,
                input_manifest: input_manifest.clone(),
                runtime_source: copied.minimal_runtime_source,
                input_source: copied.input_source.clone(),
            })),
            runtime,
            input,
            runtime_manifest,
            input_manifest,
            runtime_source: copied.runtime_source,
            input_source: copied.input_source,
        })
    }
}

pub struct TestInput<'a> {
    pub controller_directory: &'a Path,
    pub caller: &'a CallerSession,
    pub images: &'a CallerImages,
    pub provider: &'a PublicProviderBindingV1,
    pub directory: &'a Path,
    pub work_cutoff: Instant,
    pub cleanup_cutoff: Instant,
}
pub struct ExecutedCase {
    pub frontend_wait: std::process::ExitStatus,
    pub frontend_identity: (u32, u64),
    pub start: Vec<u8>,
    pub lifetime: memcordon_core::Lifetime,
    pub memory_bytes: Option<u64>,
    pub deadline_millis: Option<u64>,
    pub arguments: Vec<Vec<u8>>,
    pub locator: WorkloadAttemptAssociationV1,
    pub controller: serde_json::Value,
    pub retirement: serde_json::Value,
    pub outputs: Vec<(RootRelativePath, Vec<u8>)>,
    pub prepared: Vec<u8>,
    pub prepared_ack: Option<Vec<u8>>,
    pub key: super::linux_test_scenarios::ScenarioName,
    pub challenge: String,
    pub request: memcordon_core::workload_request::WorkloadRequestV1,
    pub result: Option<memcordon_core::result_v3::ResultV3>,
    pub recovery: Option<Vec<u8>>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub directory: PathBuf,
}

pub fn is_isolation_case(key: &super::linux_test_scenarios::ScenarioName) -> bool {
    matches!(
        (key.family.as_str(), key.scenario.as_str()),
        ("L-MIX-04", "cross-attempt")
            | ("L-ISO-01", "host-tcp" | "nonloopback")
            | (
                "L-ISO-02",
                "host-temp-socket"
                    | "input-socket"
                    | "imported-socket"
                    | "caller-writable-tree"
                    | "host-tree-mount-import-rejected",
            )
            | ("L-ISO-03", "host-abstract" | "other-attempt-abstract")
            | ("L-ISO-04", _)
            | ("L-ISO-05", "stdio-host-socket" | "extra-host-fd")
            | ("L-ISO-06", _)
    )
}

/// Execute one real operation and settle its live native owners before return.
pub fn run_recipe(
    input: TestInput<'_>,
    recipe: super::linux_test_scenarios::Scenario,
) -> Result<ExecutedCase> {
    run_recipe_inner(input, recipe, None, None, None, None, None)
}
pub fn run_recipe_with_intervention(
    input: TestInput<'_>,
    recipe: super::linux_test_scenarios::Scenario,
    intervention: &mut dyn FnMut(
        &mut RequestLaunch,
        &WorkloadAttemptAssociationV1,
    ) -> Result<serde_json::Value>,
) -> Result<ExecutedCase> {
    run_recipe_inner(input, recipe, Some(intervention), None, None, None, None)
}
pub fn run_recipe_with_descriptors(
    input: TestInput<'_>,
    recipe: super::linux_test_scenarios::Scenario,
    extra: Option<&File>,
    stdin_socket: Option<&File>,
) -> Result<ExecutedCase> {
    use std::os::unix::fs::FileTypeExt;
    if let Some(file) = stdin_socket
        && !file.metadata()?.file_type().is_socket()
    {
        return Err(CiError::Message(
            "explicit original stdin descriptor is not a held native socket".into(),
        ));
    }
    run_recipe_inner(input, recipe, None, extra, stdin_socket, None, None)
}
type Intervention<'a> =
    dyn FnMut(&mut RequestLaunch, &WorkloadAttemptAssociationV1) -> Result<serde_json::Value> + 'a;
type BeforeRequest<'a> = dyn FnMut(&CallerRequestFixture) -> Result<()> + 'a;
type OpenedRequest<'a> = dyn FnMut(&mut RequestLaunch, &CallerRequestFixture) -> Result<()> + 'a;

pub fn run_recipe_with_source(
    input: TestInput<'_>,
    recipe: super::linux_test_scenarios::Scenario,
    before: &mut BeforeRequest<'_>,
    opened: &mut OpenedRequest<'_>,
    intervention: Option<&mut Intervention<'_>>,
) -> Result<ExecutedCase> {
    run_recipe_inner(
        input,
        recipe,
        intervention,
        None,
        None,
        Some(before),
        Some(opened),
    )
}
fn run_recipe_inner(
    mut input: TestInput<'_>,
    mut recipe: super::linux_test_scenarios::Scenario,
    mut intervention: Option<&mut Intervention<'_>>,
    extra_descriptor: Option<&File>,
    stdin_socket: Option<&File>,
    mut before: Option<&mut BeforeRequest<'_>>,
    mut opened: Option<&mut OpenedRequest<'_>>,
) -> Result<ExecutedCase> {
    if !recipe.mode.starts_with("joint") {
        input.images = input.images.minimal();
    }
    input.work_cutoff = input.work_cutoff.min(
        Instant::now()
            .checked_add(recipe.observation_limit)
            .ok_or_else(|| {
                CiError::Message("case observation cutoff exceeds native clock range".into())
            })?,
    );
    if Instant::now() >= input.work_cutoff {
        return Err(CiError::Message(
            "original Linux case cutoff expired".into(),
        ));
    }
    std::fs::create_dir(input.directory)?;
    let directory = File::open(input.directory)?;
    rustix::fs::fchown(
        &directory,
        Some(rustix::process::Uid::from_raw(input.caller.uid)),
        Some(rustix::process::Gid::from_raw(input.caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    std::fs::set_permissions(input.directory, std::fs::Permissions::from_mode(0o700))?;
    let host_service_socket =
        if recipe.key.family == "L-ISO-02" && recipe.key.scenario == "host-run-socket" {
            let path = Path::new("/run/memcordon/sealed-agent.sock");
            let held = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            let metadata = held.metadata()?;
            if metadata.mode() & libc::S_IFMT != libc::S_IFSOCK
                || metadata.uid() != 0
                || metadata.nlink() != 1
            {
                return Err(CiError::Message(
                    "current provider socket native custody differs".into(),
                ));
            }
            recipe.arguments = vec![path.as_os_str().to_owned()];
            Some((held, metadata))
        } else {
            None
        };
    let mut roots = BoundedVec::default();
    roots
        .try_push(memcordon_core::workload_files::WritableRootV1 {
            id: memcordon_core::identifiers::LogicalId::new("work".into())
                .map_err(CiError::Message)?,
            path: RootRelativePath::new("work".into()).map_err(CiError::Message)?,
            byte_limit: std::num::NonZeroU64::new(if recipe.mode.starts_with("joint") {
                64 * 1024 * 1024
            } else {
                8 * 1024 * 1024
            })
            .expect("finite nonzero work budget"),
            generated_execution: true,
        })
        .map_err(|_| CiError::Message("root inventory full".into()))?;
    let selected_outputs = recipe.output_files.clone();
    let mut outputs = BoundedVec::default();
    for value in recipe.output_files.clone() {
        outputs
            .try_push(value)
            .map_err(|_| CiError::Message("output inventory exceeds bound".into()))?;
    }
    let mut requirements = BoundedVec::default();
    for value in recipe.requirements {
        requirements
            .try_push(value)
            .map_err(|_| CiError::Message("requirement inventory exceeds bound".into()))?;
    }
    let fixture = CallerRequestFixture::pack(
        input.caller,
        input.directory,
        CallerSnapshot {
            manifest: &input.images.runtime,
            manifest_path: &input.images.runtime_manifest,
            source_root: &input.images.runtime_source,
        },
        CallerSnapshot {
            manifest: &input.images.input,
            manifest_path: &input.images.input_manifest,
            source_root: &input.images.input_source,
        },
        memcordon_core::identifiers::LogicalId::new("owned-readiness".into())
            .map_err(CiError::Message)?,
        PrivateRootLayoutV1 {
            writable_roots: roots,
            output_files: outputs,
        },
        requirements,
        input.work_cutoff,
    )?;
    if let Some(before) = before.as_mut() {
        before(&fixture)?;
    }
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| CiError::Message(e.to_string()))?;
    let challenge = hex::encode(nonce);
    let interactive = matches!(
        recipe.mode.as_str(),
        "joint"
            | "joint-memory"
            | "joint-reserved-exit"
            | "cooperation"
            | "own-abstract-held"
            | "root-first"
            | "export-object"
            | "relay-backpressure"
            | "isolation-listener"
            | "image-custody"
            | "snapshot-read-held"
    );
    let empty_input = recipe.mode == "empty-input";
    let lifetime = if recipe.mode == "root-first" {
        memcordon_core::Lifetime::Workload
    } else {
        memcordon_core::Lifetime::Command
    };
    let memory_headroom = match recipe.memory.to_str() {
        Some("+128MiB") => 128 * 1024 * 1024,
        Some("+2GiB") => 2 * 1024 * 1024 * 1024,
        _ => {
            return Err(CiError::Message(
                "current fixture original memory operand has no explicit byte expectation".into(),
            ));
        }
    };
    let (memory_operand, memory_bytes) = super::linux_snapshot_budget::memory_budget(
        &input.images.runtime,
        &input.images.input,
        memory_headroom,
    )?;
    let seconds = recipe
        .product_deadline
        .to_str()
        .and_then(|value| value.strip_prefix('+'))
        .and_then(|value| value.strip_suffix('s'))
        .ok_or_else(|| {
            CiError::Message(
                "current fixture original deadline must be explicit whole seconds".into(),
            )
        })?
        .parse::<u64>()
        .map_err(|error| CiError::Message(error.to_string()))?;
    let original_deadline_millis = seconds
        .checked_mul(1000)
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            CiError::Message("current fixture original deadline overflow or zero".into())
        })?;
    let mut arguments = vec![recipe.mode.clone().into(), challenge.clone().into()];
    arguments.extend(recipe.arguments);
    use std::os::unix::ffi::OsStrExt;
    let argument_bytes = arguments
        .iter()
        .map(|argument| argument.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let output = input.directory.join("outputs");
    std::fs::create_dir(&output)?;
    let output_owner = File::open(&output)?;
    rustix::fs::fchown(
        &output_owner,
        Some(rustix::process::Uid::from_raw(input.caller.uid)),
        Some(rustix::process::Gid::from_raw(input.caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    let gate_path = input.directory.join("finite-stdin.bin");
    let mut gate_writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&gate_path)?;
    if !empty_input {
        gate_writer.write_all(b"RRRRRRRRRRRRRRRR")?;
    }
    gate_writer.sync_all()?;
    drop(gate_writer);
    let gate = File::open(gate_path)?;
    let observation_directory = input.directory.join("provider-observations");
    std::fs::create_dir(&observation_directory)?;
    let observation_owner = File::open(&observation_directory)?;
    rustix::fs::fchown(
        &observation_owner,
        Some(rustix::process::Uid::from_raw(input.caller.uid)),
        Some(rustix::process::Gid::from_raw(input.caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    std::fs::set_permissions(
        &observation_directory,
        std::fs::Permissions::from_mode(0o700),
    )?;
    let mut launch = RequestLaunch::start(LaunchInput {
        extra_descriptor,
        lifetime,
        controller_directory: input.controller_directory,
        observation_directory: Some(&observation_directory),
        interactive,
        stdin: if interactive {
            if stdin_socket.is_some() {
                return Err(CiError::Message(
                    "interactive source cannot also override original stdin with a socket".into(),
                ));
            }
            None
        } else {
            Some(stdin_socket.unwrap_or(&gate))
        },
        caller: input.caller,
        fixture: &fixture,
        directory: input.directory,
        provider: input.provider,
        entrypoint: std::ffi::OsStr::new("owned-readiness"),
        arguments: &arguments,
        memory: &memory_operand,
        deadline: &recipe.product_deadline,
        output_directory: Some(&output),
        work_cutoff: input.work_cutoff,
        cleanup_cutoff: input.cleanup_cutoff,
    })?;
    let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<ExecutedCase> {
            if let Some(opened) = opened.as_mut() {
                opened(&mut launch, &fixture)?;
            }
            let original_frontend = launch.retain_frontend(input.work_cutoff)?;
            let frontend_identity = (original_frontend.process_id, original_frontend.birth);
            let locator_path = input.directory.join("workload-observation.json");
            while !locator_path.try_exists()? {
                if Instant::now() >= input.work_cutoff {
                    return Err(CiError::Message(
                        "original attempt locator cutoff expired".into(),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let locator = launch.association()?;
            let prepared_name = format!("{}.prepared.json", hex::encode(locator.attempt));
            let prepared_path = observation_directory.join(&prepared_name);
            while !prepared_path.try_exists()? {
                if Instant::now() >= input.work_cutoff {
                    return Err(CiError::Message(
                        "original native prepared observation cutoff expired".into(),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let mut prepared_file = File::from(
                rustix::fs::openat(
                    &observation_owner,
                    prepared_name.as_str(),
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(std::io::Error::from)?,
            );
            let metadata = prepared_file.metadata()?;
            if !metadata.is_file()
                || metadata.uid() != input.caller.uid
                || metadata.mode() & 0o022 != 0
                || metadata.nlink() != 1
                || metadata.len() > 65536
            {
                return Err(CiError::Message(
                    "original caller prepared observation custody differs".into(),
                ));
            }
            let mut prepared = Vec::new();
            (&mut prepared_file)
                .take(65537)
                .read_to_end(&mut prepared)?;
            let decoded = memcordon_core::result_v3::LinuxWorkloadPreparedV1::parse(&prepared)
                .map_err(CiError::Message)?;
            let start_name = format!("{}.start.json", hex::encode(locator.attempt));
            let mut start_file = File::from(
                rustix::fs::openat(
                    &observation_owner,
                    start_name.as_str(),
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(std::io::Error::from)?,
            );
            let start_metadata = start_file.metadata()?;
            if !start_metadata.is_file()
                || start_metadata.uid() != input.caller.uid
                || start_metadata.nlink() != 1
                || start_metadata.mode() & 0o022 != 0
                || start_metadata.len() > 1024 * 1024 - 72
            {
                return Err(CiError::Message(
                    "original caller start observation custody differs".into(),
                ));
            }
            let mut start = Vec::new();
            (&mut start_file)
                .take(1024 * 1024 - 71)
                .read_to_end(&mut start)?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&start)
                .map_err(CiError::Message)?;
            let start_value: memcordon_core::workload_request::WorkloadStartV1 =
                serde_json::from_slice(&start)?;
            if start_value
                .request
                .digest()
                .map_err(|error| CiError::Message(error.to_string()))?
                != locator.request_sha256
                || memcordon_core::workload_request::invocation_digest(
                    &start_value.native_launch,
                    start_value.working_directory.as_ref(),
                )
                .map_err(|error| CiError::Message(error.to_string()))?
                    != decoded.request.invocation_sha256
                || memcordon_core::workload_request::resource_policy_digest(
                    &start_value.native_launch,
                    start_value.attempt_deadline_millis,
                )
                .map_err(|error| CiError::Message(error.to_string()))?
                    != decoded.request.resource_policy_sha256
            {
                return Err(CiError::Message(
            "original start wire differs from authenticated prepared invocation/resource binding"
                .into(),
        ));
            }
            if decoded.association != locator
                || (decoded.native.caller.pid, decoded.native.caller.birth) != frontend_identity
            {
                return Err(CiError::Message(
                    "prepared native caller/attempt differs from the original Child".into(),
                ));
            }
            let (mut held, mut controller) = hold_current_attempt(&locator, input.work_cutoff)?;
            if recipe.key.family == "L-IMG-04"
                && matches!(
                    recipe.key.scenario.as_str(),
                    "export-fifo" | "export-device"
                )
            {
                let root =
                    super::linux_current_exports::ExportRoot::hold(&held[4], &decoded.native)?;
                controller["export_injection"] = root.inject(&recipe.key.scenario)?;
            }
            if let Some((socket, before)) = &host_service_socket {
                let metadata = socket.metadata()?;
                if (before.dev(), before.ino()) != (metadata.dev(), metadata.ino()) {
                    return Err(CiError::Message(
                        "held original service socket changed".into(),
                    ));
                }
                controller["host_service_socket"] = serde_json::json!({"path":"/run/memcordon/sealed-agent.sock","device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":metadata.mode(),"provider_control":locator.control});
            }
            let mut caller_sources = Vec::new();
            for (role, path) in [
                ("runtime", &input.images.runtime_source),
                ("input", &input.images.input_source),
            ] {
                let root = File::from(
                    rustix::fs::open(
                        path,
                        rustix::fs::OFlags::RDONLY
                            | rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC,
                        rustix::fs::Mode::empty(),
                    )
                    .map_err(std::io::Error::from)?,
                );
                let metadata = root.metadata()?;
                if metadata.uid() != input.caller.uid
                    || metadata.gid() != input.caller.gid
                    || metadata.mode() & 0o200 == 0
                {
                    return Err(CiError::Message(
                        "ordinary caller source root custody/write permission differs".into(),
                    ));
                }
                caller_sources.push(serde_json::json!({"role":role,"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode()}));
            }
            let bundle = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&fixture.bundle)?;
            let bundle_metadata = bundle.metadata()?;
            if !bundle_metadata.is_file()
                || bundle_metadata.uid() != input.caller.uid
                || bundle_metadata.gid() != input.caller.gid
                || bundle_metadata.nlink() != 1
            {
                return Err(CiError::Message(
                    "actual ordinary caller pack output custody differs".into(),
                ));
            }
            controller["caller_inputs"] = serde_json::json!({"format":"memcordon.linux-caller-input-observation","revision":1,"sources":caller_sources,"runtime_digest":input.images.runtime.digest().map_err(CiError::Message)?,"input_digest":input.images.input.digest().map_err(CiError::Message)?,"bundle":{"device":bundle_metadata.dev(),"inode":bundle_metadata.ino(),"uid":bundle_metadata.uid(),"gid":bundle_metadata.gid(),"length":bundle_metadata.len()}});
            let observe_deadline = matches!(recipe.key.family.as_str(), "C-STATUS" | "L-LIFE-03")
                && recipe.key.scenario == "deadline";
            let deadline_millis = if observe_deadline && recipe.key.family == "C-STATUS" {
                if recipe.product_deadline != "+2s" {
                    return Err(CiError::Message(
                        "deadline demand original configured duration differs".into(),
                    ));
                }
                Some(2000_u64)
            } else {
                Some(original_deadline_millis)
            };
            if controller["native"] != serde_json::to_value(&decoded.native)? {
                return Err(CiError::Message(
                    "public prepared facts differ from protected original native journal".into(),
                ));
            }
            let report_failure = recipe.key.family == "L-LIFE-05"
                && recipe.key.scenario == "report-persistence-failure";
            if report_failure {
                let before = directory.metadata()?;
                directory.set_permissions(std::fs::Permissions::from_mode(0o500))?;
                let after = directory.metadata()?;
                controller["report_directory"] = serde_json::json!({"device":before.dev(),"inode":before.ino(),"uid":before.uid(),"before_mode":before.mode(),"blocked_mode":after.mode(),"same_native_inode":(before.dev(),before.ino())==(after.dev(),after.ino())});
            }
            let acknowledgment = memcordon_core::result_v3::WorkloadPreparedAckV1 {
                format: "memcordon.workload-prepared-ack".into(),
                revision: 1,
                association: locator.clone(),
                prepared_sha256: memcordon_core::hash_bytes(&prepared),
            };
            let held_cancel =
                recipe.key.family == "C-CANCEL" && recipe.key.scenario == "held-before-release";
            let prepared_ack = if held_cancel {
                None
            } else {
                Some(serde_json::to_vec(&acknowledgment)?)
            };
            if held_cancel {
                let frontend = launch.retain_frontend(input.work_cutoff)?;
                frontend
                    .signal_interrupt()
                    .map_err(CiError::Message)?
                    .map_err(|code| {
                        CiError::Message(format!(
                            "original held frontend cancellation failed: {code}"
                        ))
                    })?;
                controller["cancellation"] = serde_json::json!({"format":"memcordon.linux-native-cancellation","revision":1,"phase":"held-before-release","frontend":{"pid":frontend.process_id,"birth":frontend.birth},"signal":2,"native_signal_result":0});
            } else {
                let mut temporary = tempfile::NamedTempFile::new_in(&observation_directory)?;
                temporary.write_all(
                    prepared_ack
                        .as_deref()
                        .expect("actual acknowledgment bytes retained"),
                )?;
                rustix::fs::fchown(
                    temporary.as_file(),
                    Some(rustix::process::Uid::from_raw(input.caller.uid)),
                    Some(rustix::process::Gid::from_raw(input.caller.gid)),
                )
                .map_err(std::io::Error::from)?;
                temporary.as_file().sync_all()?;
                temporary
                    .persist_noclobber(observation_directory.join(format!(
                        "{}.prepared-ack.json",
                        hex::encode(locator.attempt)
                    )))
                    .map_err(|e| e.error)?;
                observation_owner.sync_all()?;
            }
            let intervened = intervention.is_some();
            if let Some(callback) = intervention.take() {
                launch.send_input(b"R".to_vec())?;
                controller["intervention"] = callback(&mut launch, &locator)?;
                launch.close_input();
            }
            if recipe.key.family == "C-CANCEL" && recipe.key.scenario == "after-release" {
                let snapshot = launch.snapshot_until(input.work_cutoff)?;
                loop {
                    if Instant::now() >= input.work_cutoff {
                        return Err(CiError::Message(
                            "original released cancellation demand cutoff exhausted".into(),
                        ));
                    }
                    let bytes = snapshot.stdout()?;
                    if bytes
                        .split_inclusive(|byte| *byte == b'\n')
                        .filter(|line| line.ends_with(b"\n"))
                        .any(|line| {
                            serde_json::from_slice::<serde_json::Value>(line).is_ok_and(|row| {
                                row["operation"] == "deadline-demand-started"
                                    && row["challenge"] == challenge
                            })
                        })
                    {
                        break;
                    }
                    if launch.capture_finished() {
                        return Err(CiError::Message(
                            "original target retired before released cancellation demand".into(),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                let frontend = launch.retain_frontend(input.work_cutoff)?;
                frontend
                    .signal_interrupt()
                    .map_err(CiError::Message)?
                    .map_err(|code| {
                        CiError::Message(format!(
                            "original released frontend cancellation failed: {code}"
                        ))
                    })?;
                controller["cancellation"] = serde_json::json!({"format":"memcordon.linux-native-cancellation","revision":1,"phase":"after-release","frontend":{"pid":frontend.process_id,"birth":frontend.birth},"signal":2,"native_signal_result":0});
            }
            if recipe.mode == "relay-backpressure" {
                let snapshot = launch.snapshot_until(input.work_cutoff)?;
                loop {
                    if Instant::now() >= input.work_cutoff || launch.capture_finished() {
                        return Err(CiError::Message(
                            "original relay pressure readiness absent".into(),
                        ));
                    }
                    let bytes = snapshot.stdout()?;
                    if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
                        let row: serde_json::Value = serde_json::from_slice(&bytes[..end])?;
                        if row["operation"] != "relay-pressure-ready"
                            || row["challenge"] != challenge
                        {
                            return Err(CiError::Message(
                                "original relay pressure source readiness differs".into(),
                            ));
                        }
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                let frontend = HeldLinuxProcess::acquire(frontend_identity.0, frontend_identity.1)
                    .map_err(CiError::Message)?;
                controller["relay_pressure"] = super::linux_current_relay::observe(
                    &frontend,
                    &held[4],
                    input.work_cutoff,
                    || launch.send_input(b"R".to_vec()),
                )?;
                launch.close_input();
            }
            if interactive && !intervened && recipe.mode != "relay-backpressure" {
                let snapshot = launch.snapshot_until(input.work_cutoff)?;
                let mut handled = std::collections::BTreeSet::new();
                let mut stages = Vec::new();
                let mut export_writer = None;
                loop {
                    if Instant::now() >= input.work_cutoff {
                        return Err(CiError::Message(
                            "actual child-held phase exceeded original work cutoff".into(),
                        ));
                    }
                    let raw = snapshot.stdout()?;
                    for line in raw
                        .split_inclusive(|byte| *byte == b'\n')
                        .filter(|line| line.ends_with(b"\n"))
                    {
                        let row: serde_json::Value = serde_json::from_slice(line)?;
                        let Some(operation) = row["operation"].as_str() else {
                            continue;
                        };
                        if ![
                            "descendant-competing-bind-held",
                            "joint-descendant-tree-held",
                            "offline-compiler-held",
                            "joint-generated-child-held",
                            "same-attempt-cooperation-held",
                            "other-attempt-abstract-held",
                            "root-exiting-before-held-descendant",
                            "export-writer-held",
                            "export-object-ready",
                            "memory-pressure-descendant-held",
                        ]
                        .contains(&operation)
                            || !handled.insert(operation.to_owned())
                        {
                            continue;
                        }
                        if row["challenge"] != challenge {
                            return Err(CiError::Message(
                                "actual child-held phase challenge differs".into(),
                            ));
                        }
                        let observation = &row["observation"];
                        let tree = if observation["native_tree"].is_null() {
                            observation
                        } else {
                            &observation["native_tree"]
                        };
                        let mut children = Vec::new();
                        let mut child_snapshots = Vec::new();
                        if !tree["pid"].is_null() {
                            hold_child_tree(
                                &held[3],
                                &held[4],
                                tree,
                                0,
                                &mut children,
                                &mut child_snapshots,
                            )?;
                        }
                        stages.push(serde_json::json!({"operation":operation,"sequence":row["sequence"],"children":child_snapshots}));
                        if recipe.key.family == "L-LIFE-03"
                            && operation == "joint-generated-child-held"
                            && matches!(recipe.key.scenario.as_str(), "deadline" | "cancellation")
                        {
                            if recipe.key.scenario == "cancellation" {
                                let frontend = launch.retain_frontend(input.work_cutoff)?;
                                frontend
                                    .signal_interrupt()
                                    .map_err(CiError::Message)?
                                    .map_err(|code| {
                                        CiError::Message(format!(
                                            "joint resource cancellation signal failed: {code}"
                                        ))
                                    })?;
                                controller["resource_cancellation"] = serde_json::json!({"frontend":{"pid":frontend.process_id,"birth":frontend.birth},"signal":2,"native_signal_result":0});
                            }
                            held.extend(children);
                            // Keep the generated child, compiler, TCP and UNIX
                            // owners held until the original resource event.
                            continue;
                        }
                        if recipe.key.family == "L-LIFE-03"
                            && recipe.key.scenario == "memory"
                            && operation == "memory-pressure-descendant-held"
                        {
                            if children.len() != 1 {
                                return Err(CiError::Message(
                                    "joint pressure allocator native identity absent".into(),
                                ));
                            }
                            children[0]
                                .signal_continue()
                                .map_err(CiError::Message)?
                                .map_err(|code| {
                                    CiError::Message(format!(
                                        "joint allocator resume failed: {code}"
                                    ))
                                })?;
                            controller["resource_allocator"] = serde_json::json!({"pid":children[0].process_id,"birth":children[0].birth,"continued":true});
                            held.extend(children);
                            continue;
                        }
                        if operation == "export-writer-held" {
                            if children.len() != 1 {
                                return Err(CiError::Message(
                                    "export writer has no exact original native child".into(),
                                ));
                            }
                            export_writer = Some(held.len());
                            held.extend(children);
                            continue;
                        }
                        if operation == "export-object-ready" {
                            if !super::linux_current_exports::output_empty(&output_owner)? {
                                return Err(CiError::Message(
                                    "outputs were delivered before original workload retirement"
                                        .into(),
                                ));
                            }
                            let root = super::linux_current_exports::ExportRoot::hold(
                                &held[4],
                                &decoded.native,
                            )?;
                            controller["export_candidate"] = root.snapshot(&recipe.key.scenario)?;
                            controller["export_candidate"]["output_empty_before_release"] =
                                true.into();
                            if recipe.key.scenario == "export-concurrent-writer" {
                                let index = export_writer.ok_or_else(|| {
                                    CiError::Message("original export writer was not held".into())
                                })?;
                                let writer = &held[index];
                                let mut first = root.writer_sample()?;
                                loop {
                                    let value: Vec<u8> =
                                        serde_json::from_value(first["bytes"].clone())?;
                                    if value.len() == 14
                                        && value.get(..8) != Some(b"writer-i".as_slice())
                                    {
                                        break;
                                    }
                                    if Instant::now() >= input.work_cutoff
                                        || writer.exited().map_err(CiError::Message)?
                                    {
                                        return Err(CiError::Message(
                                            "original writer did not reach live mutation".into(),
                                        ));
                                    }
                                    std::thread::sleep(std::time::Duration::from_millis(1));
                                    first = root.writer_sample()?;
                                }
                                let second = loop {
                                    if Instant::now() >= input.work_cutoff
                                        || writer.exited().map_err(CiError::Message)?
                                    {
                                        return Err(CiError::Message("original writer retired before concurrent mutation observation".into()));
                                    }
                                    let sample = root.writer_sample()?;
                                    if sample["bytes"] != first["bytes"] {
                                        break sample;
                                    }
                                    std::thread::sleep(std::time::Duration::from_millis(1));
                                };
                                launch.send_input(b"S".to_vec())?;
                                while !writer.exited().map_err(CiError::Message)? {
                                    if Instant::now() >= input.work_cutoff {
                                        return Err(CiError::Message(
                                            "original export writer did not retire".into(),
                                        ));
                                    }
                                    std::thread::sleep(std::time::Duration::from_millis(1));
                                }
                                controller["export_writer_native"] = serde_json::json!({"writer":{"pid":writer.process_id,"birth":writer.birth},"first":first,"second":second,"final":root.writer_sample()?,"pidfd_readable_after_stop":true,"target_alive_after_writer":!held[4].exited().map_err(CiError::Message)?});
                            }
                            drop(root);
                            launch.send_input(b"R".to_vec())?;
                            continue;
                        }
                        if operation == "root-exiting-before-held-descendant" {
                            if children.len() != 1 {
                                return Err(CiError::Message(
                                    "root-first must hold one actual original descendant".into(),
                                ));
                            }
                            let child = &children[0];
                            child
                                .signal_stop()
                                .map_err(CiError::Message)?
                                .map_err(|code| {
                                    CiError::Message(format!(
                                        "original root-first child stop failed: {code}"
                                    ))
                                })?;
                            child
                                .observe_stopped_until(input.work_cutoff)
                                .map_err(CiError::Message)?;
                            launch.send_input(b"R".to_vec())?;
                            while !held[4].exited().map_err(CiError::Message)? {
                                if Instant::now() >= input.work_cutoff {
                                    return Err(CiError::Message(
                                        "original root-first target wait cutoff exhausted".into(),
                                    ));
                                }
                                std::thread::sleep(std::time::Duration::from_millis(1));
                            }
                            let descendant_at_root = child.exited().map_err(CiError::Message)?;
                            if descendant_at_root {
                                return Err(CiError::Message(
                                "original descendant retired before native root-first observation"
                                    .into(),
                            ));
                            }
                            child
                                .signal_continue()
                                .map_err(CiError::Message)?
                                .map_err(|code| {
                                    CiError::Message(format!(
                                        "original root-first child resume failed: {code}"
                                    ))
                                })?;
                            while !child.exited().map_err(CiError::Message)? {
                                if Instant::now() >= input.work_cutoff {
                                    return Err(CiError::Message(
                                        "original root-first descendant wait cutoff exhausted"
                                            .into(),
                                    ));
                                }
                                std::thread::sleep(std::time::Duration::from_millis(1));
                            }
                            controller["root_first_native"] = serde_json::json!({"format":"memcordon.linux-root-first-native","revision":1,"root":decoded.native.target,"descendant":{"pid":child.process_id,"birth":child.birth,"namespace_pid":tree["pid"]},"root_pidfd_readable_before_descendant_exit":true,"descendant_pidfd_readable_when_root_retired":descendant_at_root,"descendant_pidfd_readable_after_completion":true});
                            held.extend(children);
                            continue;
                        }
                        held.extend(children);
                        launch.send_input(b"R".to_vec())?;
                    }
                    if launch.capture_finished() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                controller["held_stages"] = serde_json::to_value(stages)?;
                launch.close_input();
            }
            let deadline_wait = if observe_deadline {
                while !held[4].exited().map_err(CiError::Message)? {
                    if Instant::now() >= input.work_cutoff {
                        return Err(CiError::Message(
                            "original deadline target observation cutoff exhausted".into(),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Some(super::linux_test_images::monotonic_millis()?)
            } else {
                None
            };
            let observed = launch.capture_until(input.work_cutoff)?;
            let frontend_wait = observed.status;
            let stdout = observed.stdout.clone();
            let stderr = observed.stderr.clone();
            if report_failure {
                use std::os::unix::process::ExitStatusExt;
                controller["report_directory"]["frontend_wait"] = serde_json::json!({"status":frontend_wait.code(),"raw_wait_status":frontend_wait.into_raw(),"frontend":{"pid":frontend_identity.0,"birth":frontend_identity.1}});
                directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
                let after = directory.metadata()?;
                controller["report_directory"]["restored_mode"] = after.mode().into();
                controller["report_directory"]["result_absent"] =
                    match std::fs::symlink_metadata(input.directory.join("workload-result.json")) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                        Err(error) => return Err(error.into()),
                        Ok(_) => false,
                    }
                    .into();
                let recovery = launch.recover()?;
                let mut retired = Vec::new();
                for process in &held {
                    if !process.exited().map_err(CiError::Message)? {
                        return Err(CiError::Message(
                            "original report-failure native owner remains live".into(),
                        ));
                    }
                    retired.push(serde_json::json!({"pid":process.process_id,"birth":process.birth,"pidfd_readable":true}));
                }
                controller["report_directory"]["recovery_wait"] = serde_json::json!({"status":recovery.process.status.code(),"raw_wait_status":recovery.process.status.into_raw()});
                let request = memcordon_core::workload_request::WorkloadRequestV1::parse(
                    &std::fs::read(&fixture.request)?,
                )
                .map_err(|error| CiError::Message(error.to_string()))?;
                launch.retire_bundle_exact(&fixture)?;
                return Ok(ExecutedCase {
                    frontend_wait,
                    frontend_identity,
                    start,
                    lifetime,
                    memory_bytes: Some(memory_bytes),
                    deadline_millis,
                    arguments: argument_bytes,
                    locator: launch.association()?,
                    controller,
                    retirement: serde_json::json!({"format":"memcordon.linux-current-retirement","revision":1,"held_processes":retired,"terminal_cleanup":recovery.terminal.cleanup}),
                    outputs: Vec::new(),
                    prepared,
                    prepared_ack,
                    key: recipe.key,
                    challenge,
                    request,
                    result: None,
                    recovery: Some(recovery.raw_terminal),
                    stdout,
                    stderr,
                    directory: input.directory.into(),
                });
            }
            let result = launch.result().map_err(|error| {
                error.context(format!(
                    "scenario={}/{}; original frontend status={:?}; stderr-bytes={}; stderr={}",
                    recipe.key.family,
                    recipe.key.scenario,
                    frontend_wait,
                    stderr.len(),
                    crate::linux_result_publication::stderr_detail(&stderr)
                ))
            })?;
            crate::linux_result_publication::wrapper_status(
                frontend_wait.code(),
                result.outcome.wrapper_status,
            )
            .map_err(|error| {
                CiError::Message(error).context(format!(
                    "scenario={}/{}; original frontend status={:?}; stderr-bytes={}; stderr={}",
                    recipe.key.family,
                    recipe.key.scenario,
                    frontend_wait,
                    stderr.len(),
                    crate::linux_result_publication::stderr_detail(&stderr)
                ))
            })?;
            if let Some((socket, before)) = &host_service_socket {
                let named = std::fs::symlink_metadata("/run/memcordon/sealed-agent.sock")?;
                let after = socket.metadata()?;
                if (before.dev(), before.ino(), before.mode())
                    != (named.dev(), named.ino(), named.mode())
                    || (before.dev(), before.ino(), before.mode())
                        != (after.dev(), after.ino(), after.mode())
                {
                    return Err(CiError::Message(
                        "original public service socket replaced during private-path probe".into(),
                    ));
                }
                controller["host_service_socket"]["named_identity_preserved"] = true.into();
            }
            if let Some(observed) = deadline_wait {
                let result_value = serde_json::to_value(&result)?;
                controller["deadline_observation"] = serde_json::json!({"format":"memcordon.linux-deadline-observation","revision":1,"target":result_value["runtime"]["native"]["target"],"release_monotonic_millis":result_value["runtime"]["native"]["release_monotonic_millis"],"wait_observed_monotonic_millis":observed,"deadline_millis":deadline_millis,"target_pidfd_readable":true});
            }
            let mut outputs = Vec::new();
            let rejected_export = recipe.key.family == "L-IMG-04"
                && recipe.key.scenario != "export-concurrent-writer";
            if rejected_export {
                if result.output_delivery
                    != Some(memcordon_core::result_v3::OutputDeliveryStateV3::Incomplete)
                    || !super::linux_current_exports::output_empty(&output_owner)?
                {
                    return Err(CiError::Message(
                        "unsafe export materialized caller bytes or lost incomplete delivery"
                            .into(),
                    ));
                }
                controller["rejected_export_output_empty"] = true.into();
            }
            for path in if rejected_export {
                Vec::new()
            } else {
                selected_outputs
            } {
                let mut parent = output_owner.try_clone()?;
                let components = path.as_str().split('/').collect::<Vec<_>>();
                for (index, component) in components.iter().enumerate() {
                    let last = index + 1 == components.len();
                    let flags = rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC
                        | if last {
                            rustix::fs::OFlags::empty()
                        } else {
                            rustix::fs::OFlags::DIRECTORY
                        };
                    let file = File::from(
                        rustix::fs::openat(&parent, *component, flags, rustix::fs::Mode::empty())
                            .map_err(std::io::Error::from)?,
                    );
                    let metadata = file.metadata()?;
                    if metadata.uid() != input.caller.uid
                        || (last
                            && (!metadata.is_file()
                                || metadata.nlink() != 1
                                || metadata.len() > 512 * 1024 * 1024))
                    {
                        return Err(CiError::Message(
                            "original caller output custody or byte bound differs".into(),
                        ));
                    }
                    parent = file;
                }
                let before = parent.metadata()?;
                let mut bytes = Vec::new();
                (&mut parent)
                    .take(before.len() + 1)
                    .read_to_end(&mut bytes)?;
                let after = parent.metadata()?;
                if bytes.len() as u64 != before.len()
                    || (
                        before.dev(),
                        before.ino(),
                        before.len(),
                        before.mtime(),
                        before.mtime_nsec(),
                        before.ctime(),
                        before.ctime_nsec(),
                    ) != (
                        after.dev(),
                        after.ino(),
                        after.len(),
                        after.mtime(),
                        after.mtime_nsec(),
                        after.ctime(),
                        after.ctime_nsec(),
                    )
                {
                    return Err(CiError::Message(
                        "original caller output changed during capture".into(),
                    ));
                }
                outputs.push((path, bytes));
            }
            let locator = launch.association()?;
            let mut retirement = Vec::new();
            for owner in held {
                while !owner.exited().map_err(CiError::Message)? {
                    if Instant::now() >= input.cleanup_cutoff {
                        return Err(CiError::Message(
                            "held native process retirement cutoff expired".into(),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                retirement.push(
            serde_json::json!({"pid":owner.process_id,"birth":owner.birth,"pidfd_readable":true}),
        );
            }
            let request = memcordon_core::workload_request::WorkloadRequestV1::parse(
                &std::fs::read(&fixture.request)?,
            )
            .map_err(|e| CiError::Message(e.to_string()))?;
            launch.retire_bundle_exact(&fixture)?;
            Ok(ExecutedCase {
                frontend_wait,
                frontend_identity,
                start,
                lifetime,
                prepared_ack,
                memory_bytes: Some(memory_bytes),
                deadline_millis,
                arguments: argument_bytes,
                prepared,
                locator,
                controller,
                outputs,
                retirement: serde_json::json!({"format":"memcordon.linux-current-retirement","revision":1,"held_processes":retirement,"terminal_cleanup":result.cleanup}),
                key: recipe.key,
                challenge,
                request,
                result: Some(result),
                recovery: None,
                stdout,
                stderr,
                directory: input.directory.into(),
            })
        },
    ));
    let restored = directory.set_permissions(std::fs::Permissions::from_mode(0o700));
    let _retirement = crate::cancellation::retirement_scope(input.cleanup_cutoff);
    let execution = match execution {
        Ok(result) => result,
        Err(panic) => {
            if let Err(error) = restored {
                eprintln!("caller directory restoration after unwind: {error}");
            }
            match launch.cancel_and_settle(input.cleanup_cutoff) {
                Ok(_) => {
                    if let Err(error) = launch.retire_bundle_exact(&fixture) {
                        eprintln!("caller input retirement after unwind: {error}");
                    }
                }
                Err(error) => eprintln!("native request settlement after unwind: {error}"),
            }
            std::panic::resume_unwind(panic)
        }
    };
    let execution = match restored {
        Ok(()) => execution,
        Err(error) => {
            let restoration = CiError::from(error).context("caller directory restoration");
            Err(match execution {
                Ok(_) => restoration,
                Err(primary) => CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(restoration),
                },
            })
        }
    };
    match execution {
        Ok(case) => Ok(case),
        Err(primary) => match launch.cancel_and_settle(input.cleanup_cutoff) {
            Ok(_) => match launch.retire_bundle_exact(&fixture) {
                Ok(()) => Err(primary),
                Err(retirement) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(retirement.context("original caller input retirement")),
                }),
            },
            Err(cleanup) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(cleanup.context("original frontend settlement")),
            }),
        },
    }
}
