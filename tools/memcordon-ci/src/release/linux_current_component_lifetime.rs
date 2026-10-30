//! Real installed lifetime for current native boundary experiments. Every
//! package/account mutation has a protected original owner before execution.
use super::{
    artifacts,
    installed_consumer::{self, MaterializedPayload},
    linux_current_installed::{CallerImages, hold_current_attempt},
    linux_request_fixture::{CallerRequestFixture, CallerSession, CallerSnapshot},
    linux_request_launch::{LaunchInput, RequestLaunch},
    source,
};
use crate::{
    CiError, Result,
    command::{CommandSpec, require_successful_output},
    readiness_identity::SourceIdentity,
};
use memcordon_readiness_verifier::{Artifact, CaseRecord, ComponentBuild, ProductKey};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn private(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    source::write_json(path, value)
}
fn owned_directory(path: &Path, caller: &CallerSession) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    rustix::fs::fchown(
        &fs::File::open(path)?,
        Some(rustix::process::Uid::from_raw(caller.uid)),
        Some(rustix::process::Gid::from_raw(caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    Ok(())
}
fn journal(
    association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
) -> Result<Vec<u8>> {
    let path =
        Path::new("/var/lib/memcordon/workload-attempts").join(hex::encode(association.attempt));
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > 512 * 1024
    {
        return Err(CiError::Message(
            "current experiment journal custody differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file).take(512 * 1024 + 1).read_to_end(&mut bytes)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if value["association"] != serde_json::to_value(association)? {
        return Err(CiError::Message(
            "current experiment journal selects another attempt".into(),
        ));
    }
    Ok(bytes)
}
fn wait_until(cutoff: Instant, mut observed: impl FnMut() -> Result<bool>) -> Result<()> {
    loop {
        if Instant::now() >= cutoff {
            return Err(CiError::Message(
                "original native experiment phase cutoff exhausted".into(),
            ));
        }
        if observed()? {
            return Ok(());
        }
        if Instant::now() >= cutoff {
            return Err(CiError::Message(
                "original native experiment phase cutoff exhausted".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub struct ComponentLifetimeInputs<'a> {
    pub root: &'a Path,
    pub payload: &'a MaterializedPayload,
    pub identity: &'a SourceIdentity,
    pub key: &'a ProductKey,
    pub scope: &'a Path,
    pub prefix: &'a str,
    pub destination: &'a Path,
    pub build: &'a ComponentBuild,
    pub source_artifact: &'a Artifact,
    pub work: Instant,
    pub cleanup: Instant,
    pub cleanup_unix: u64,
}

pub fn run(inputs: ComponentLifetimeInputs<'_>) -> Result<(Vec<CaseRecord>, Vec<Artifact>)> {
    let ComponentLifetimeInputs {
        root,
        payload,
        identity,
        key,
        scope,
        prefix,
        destination,
        build,
        source_artifact,
        work,
        cleanup,
        cleanup_unix,
    } = inputs;
    if !rustix::process::geteuid().is_root() || Instant::now() >= work || work >= cleanup {
        return Err(CiError::Message(
            "current native lifetime requires original privileged controller and cutoffs".into(),
        ));
    }
    installed_consumer::require_current_runtime(payload)?;
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|error| CiError::Message(error.to_string()))?;
    let suffix = hex::encode(nonce);
    let caller_name = format!("mc-fixture-{suffix}");
    let working = Path::new("/tmp").join(format!("memcordon-current-{suffix}"));
    let admin = scope.join("current-images");
    let agent = admin.join("memcordon-sealed-agent");
    for binary in &payload.distribution.binaries {
        if !matches!(fs::symlink_metadata(Path::new("/usr/libexec").join(binary)),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
        {
            return Err(CiError::Message(
                "native component lifetime refuses existing unmanaged package".into(),
            ));
        }
    }
    let metadata = fs::metadata(scope)?;
    let clock = crate::ci_operation_time::clock_reading()?;
    let counter = clock
        .millis
        .checked_add(
            u64::try_from(
                cleanup
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        )
        .ok_or_else(|| CiError::Message("native component cutoff overflow".into()))?;
    let mut owner = json!({"format":"memcordon.current-installed-owner","revision":1,"lease_id":format!("native-{}-{suffix}",identity.run_id),"source":identity,"cell":key,
        "caller":caller_name,"caller_marker":format!("memcordon-current-{suffix}"),"working":working,"working_identity":null,"admin":admin,"admin_identity":null,
        "selected_agent":agent,"selected_agent_sha256":null,"uninstall_required":true,"installed_binaries":payload.distribution.binaries,
        "cleanup_deadline_unix_millis":cleanup_unix,"clock_domain":clock.domain,"cleanup_cutoff_millis":counter,
        "controller":{"pid":std::process::id(),"birth":crate::linux_consumer_readiness::process_birth(std::process::id()).map_err(CiError::Message)?,"boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()},
        "lifetime":{"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":metadata.mode()}});
    private(&scope.join("current-owner.json"), &owner)?;
    let lease_id = owner["lease_id"].clone();
    let lifecycle =
        std::sync::Mutex::new(memcordon_readiness_verifier::InstalledLifecycleJournal {
            format: "memcordon.consumer-readiness.installed-journal".into(),
            revision: 1,
            run_id: identity.run_id.clone(),
            lease_id: lease_id.as_str().expect("native lease string").into(),
            key: key.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            events: vec![memcordon_readiness_verifier::InstalledLifecycleEvent {
                sequence: 1,
                phase: "owned-before-mutation".into(),
                operation: "actual-native-component-controller-and-original-cutoff".into(),
                succeeded: true,
                native_receipt: "current-owner.json".into(),
            }],
        });
    private(
        &scope.join("installed-journal.json"),
        &*lifecycle.lock().expect("original controller journal"),
    )?;
    let sequence = std::sync::atomic::AtomicU64::new(0);
    let operation = |program: &Path,
                     args: &[&str],
                     cutoff: Instant|
     -> Result<memcordon_testkit::ObservedOutput> {
        let ordinal = sequence.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if ordinal >= 128 {
            return Err(CiError::Message(
                "native component root operation inventory exceeds bound".into(),
            ));
        }
        let path = scope.join(format!("root-operation-{ordinal}.json"));
        let intent = json!({"format":"memcordon.current-root-operation","revision":1,"lease_id":lease_id,"program":program,"arguments":args,"process":null});
        private(&path, &intent)?;
        let output=CommandSpec::new(program,root,Duration::from_secs(300)).bounded_until(cutoff).args(args.iter().copied()).output_quiet_with_exec_observation(|child| {
            let mut observed=intent.clone();observed["process"]=json!({"pid":child.id(),"birth":crate::linux_consumer_readiness::process_birth(child.id()).map_err(CiError::Message)?});private(&path,&observed)
        })?;
        let capture = format!("root-capture-{ordinal}.json");
        private(
            &scope.join(&capture),
            &json!({"status":output.status.code(),"stdout":output.stdout,"stderr":output.stderr}),
        )?;
        let mut journal = lifecycle.lock().expect("original controller journal");
        let sequence = journal.events.len() as u64 + 1;
        journal
            .events
            .push(memcordon_readiness_verifier::InstalledLifecycleEvent {
                sequence,
                phase: if args.first() == Some(&"package") {
                    args.get(1).copied().unwrap_or("native-operation")
                } else {
                    "native-operation"
                }
                .into(),
                operation: args.join(" "),
                succeeded: output.status.success(),
                native_receipt: capture,
            });
        private(&scope.join("installed-journal.json"), &*journal)?;
        Ok(output)
    };
    let mut installed = false;
    let mut caller_issued = false;
    let mut pins = Vec::new();
    let mut records = Vec::new();
    let mut artifacts = Vec::new();
    let mut failures = Vec::new();
    // The lease id is immutable; avoid keeping a mutable JSON borrow across
    // owner updates and actual root child acquisition.
    let body = (|| -> Result<()> {
        fs::create_dir(&admin)?;
        fs::set_permissions(&admin, fs::Permissions::from_mode(0o700))?;
        let metadata = fs::metadata(&admin)?;
        owner["admin_identity"] = json!({"device":metadata.dev(),"inode":metadata.ino()});
        private(&scope.join("current-owner.json"), &owner)?;
        pins = super::linux_current_lease::protect_payload(payload, &admin, work)?;
        owner["selected_agent_sha256"] = artifacts::checksum(&artifacts::read_file(&agent)?).into();
        private(&scope.join("current-owner.json"), &owner)?;
        installed = true;
        require_successful_output(
            "current native component package install",
            &operation(&agent, &["package", "install"], work)?,
        )?;
        let verified = operation(&agent, &["package", "verify", "--json"], work)?;
        require_successful_output("current native component package verify", &verified)?;
        let manifest_bytes = fs::read("/usr/libexec/memcordon-runtime-manifest.json")?;
        let manifest =
            memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&manifest_bytes)
                .map_err(CiError::Message)?;
        let provider = manifest
            .public_binding(&manifest_bytes)
            .map_err(CiError::Message)?;
        if provider.source_commit.as_str() != identity.source_commit {
            return Err(CiError::Message(
                "native component installed source differs".into(),
            ));
        }
        caller_issued = true;
        require_successful_output(
            "native component caller allocation",
            &operation(
                Path::new("/usr/sbin/useradd"),
                &[
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--home-dir",
                    "/nonexistent",
                    "--shell",
                    "/usr/sbin/nologin",
                    "--password",
                    "!",
                    "--comment",
                    owner["caller_marker"]
                        .as_str()
                        .expect("fixed allocation marker"),
                    "--groups",
                    "memcordon",
                    &caller_name,
                ],
                work,
            )?,
        )?;
        let uid = operation(Path::new("/usr/bin/id"), &["-u", &caller_name], work)?;
        require_successful_output("native caller UID", &uid)?;
        let gid = operation(Path::new("/usr/bin/id"), &["-g", &caller_name], work)?;
        require_successful_output("native caller GID", &gid)?;
        let parse = |bytes: &[u8]| -> Result<u32> {
            std::str::from_utf8(bytes)
                .map_err(|error| CiError::Message(error.to_string()))?
                .trim()
                .parse()
                .map_err(|error: std::num::ParseIntError| CiError::Message(error.to_string()))
        };
        let caller = CallerSession {
            uid: parse(&uid.stdout)?,
            gid: parse(&gid.stdout)?,
            installed_cli: PathBuf::from("/usr/libexec/memcordon"),
        };
        if caller.uid == 0 || caller.gid == 0 {
            return Err(CiError::Message(
                "native experiment caller unexpectedly privileged".into(),
            ));
        }
        owner["caller_uid"] = caller.uid.into();
        owner["caller_gid"] = caller.gid.into();
        private(&scope.join("current-owner.json"), &owner)?;
        fs::create_dir(&working)?;
        fs::set_permissions(&working, fs::Permissions::from_mode(0o755))?;
        let metadata = fs::metadata(&working)?;
        owner["working_identity"] = json!({"device":metadata.dev(),"inode":metadata.ino()});
        private(&scope.join("current-owner.json"), &owner)?;
        let images = CallerImages::materialize(
            payload,
            root,
            &working.join("images"),
            identity,
            key,
            &caller,
            work,
        )?;
        for (ordinal, scenario) in [
            "release-barrier",
            "journal-barrier",
            "crash-before-root-retirement",
            "lost-terminal-response",
        ]
        .into_iter()
        .enumerate()
        {
            let controller = scope.join(format!("case-{ordinal}"));
            fs::create_dir(&controller)?;
            fs::set_permissions(&controller, fs::Permissions::from_mode(0o700))?;
            let directory = working.join(format!("case-{ordinal}"));
            owned_directory(&directory, &caller)?;
            let captured = experiment(
                &caller,
                &images,
                &provider,
                ExperimentContext {
                    controller: &controller,
                    directory: &directory,
                    scenario,
                    facet: scenario,
                    work,
                    cleanup,
                },
            )?;
            let observed = super::linux_current_components::collect_lifecycle(
                identity,
                build,
                source_artifact,
                &captured,
                prefix,
                destination,
                &identity.version,
            )?;
            records.extend(observed.0);
            artifacts.extend(observed.1);
        }
        Ok(())
    })();
    if let Err(error) = body {
        failures.push(error.to_string());
    }
    let mut package_settled = !installed;
    if installed {
        match operation(&agent, &["package", "uninstall"], cleanup).and_then(|output| {
            require_successful_output("current native component package finalization", &output)
        }) {
            Ok(()) => package_settled = true,
            Err(error) => failures.push(error.to_string()),
        }
    }
    if package_settled {
        owner["uninstall_required"] = json!(false);
        private(&scope.join("current-owner.json"), &owner)?;
    }
    if caller_issued
        && package_settled
        && let Err(error) = super::linux_current_lease::retire_caller(root, &owner, cleanup)
    {
        failures.push(error.to_string());
    }
    if failures.is_empty() {
        super::linux_current_lease::observe_paths()?;
        super::linux_current_lease::units(root, cleanup)?;
        if !owner["working_identity"].is_null() {
            super::linux_current_lease::retire_fixture_tree(
                &working,
                &owner["working_identity"],
                cleanup,
            )?;
        }
        drop(pins);
        if !owner["admin_identity"].is_null() {
            super::linux_current_lease::retire_fixture_tree(
                &admin,
                &owner["admin_identity"],
                cleanup,
            )?;
        }
    }
    private(
        &scope.join("current-component-finalization.json"),
        &json!({"format":"memcordon.current-native-component-finalization","revision":1,"source":identity,"cell":key,"failures":failures}),
    )?;
    private(
        &scope.join("current-component-observations.json"),
        &json!({"format":"memcordon.current-native-component-observations","revision":1,"source":identity,"cell":key,"records":records,"artifacts":artifacts,"failures":failures}),
    )?;
    if failures.is_empty() {
        Ok((records, artifacts))
    } else {
        Err(CiError::Message(failures.join("; ")))
    }
}

pub fn retained_observations(
    scope: &Path,
    identity: &SourceIdentity,
    key: &ProductKey,
) -> Result<(Vec<CaseRecord>, Vec<Artifact>)> {
    let path = scope.join("current-component-observations.json");
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > 16 * 1024 * 1024
    {
        return Err(CiError::Message(
            "original native component frame custody differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let frame: Value = serde_json::from_slice(&bytes)?;
    if frame["format"] != "memcordon.current-native-component-observations"
        || frame["revision"] != 1
        || frame["source"] != serde_json::to_value(identity)?
        || frame["cell"] != serde_json::to_value(key)?
    {
        return Err(CiError::Message(
            "original component frame source/cell differs".into(),
        ));
    }
    Ok((
        serde_json::from_value(frame["records"].clone())?,
        serde_json::from_value(frame["artifacts"].clone())?,
    ))
}

pub struct Experiment {
    pub scenario: String,
    pub directory: PathBuf,
    pub files: std::collections::BTreeMap<String, Vec<u8>>,
}

pub(super) struct ExperimentContext<'a> {
    pub controller: &'a Path,
    pub directory: &'a Path,
    pub scenario: &'a str,
    pub facet: &'a str,
    pub work: Instant,
    pub cleanup: Instant,
}

pub(super) fn experiment(
    caller: &CallerSession,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    context: ExperimentContext<'_>,
) -> Result<Experiment> {
    let ExperimentContext {
        controller,
        directory,
        scenario,
        facet,
        work,
        cleanup,
    } = context;
    experiment_with_intervention(
        caller, images, provider, controller, directory, scenario, facet, work, cleanup, None,
    )
}

pub(super) type PreparedIntervention<'a> = dyn FnMut(
        &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
        &[crate::linux_consumer_readiness::HeldLinuxProcess],
    ) -> Result<std::collections::BTreeMap<String, Vec<u8>>>
    + 'a;

pub(super) fn pack_experiment(
    caller: &CallerSession,
    images: &CallerImages,
    directory: &Path,
    work: Instant,
) -> Result<CallerRequestFixture> {
    use memcordon_core::{
        BoundedVec,
        identifiers::LogicalId,
        workload_files::WritableRootV1,
        workload_request::{PrivateRootLayoutV1, RootRelativePath},
    };
    let mut roots = BoundedVec::default();
    roots
        .try_push(WritableRootV1 {
            id: LogicalId::new("work".into()).map_err(CiError::Message)?,
            path: RootRelativePath::new("work".into()).map_err(CiError::Message)?,
            byte_limit: std::num::NonZeroU64::new(8 * 1024 * 1024).expect("finite budget"),
            generated_execution: false,
        })
        .map_err(|_| CiError::Message("finite work root inventory full".into()))?;
    CallerRequestFixture::pack(
        caller,
        directory,
        CallerSnapshot {
            manifest: &images.runtime,
            manifest_path: &images.runtime_manifest,
            source_root: &images.runtime_source,
        },
        CallerSnapshot {
            manifest: &images.input,
            manifest_path: &images.input_manifest,
            source_root: &images.input_source,
        },
        LogicalId::new("owned-readiness".into()).map_err(CiError::Message)?,
        PrivateRootLayoutV1 {
            writable_roots: roots,
            output_files: BoundedVec::default(),
        },
        BoundedVec::default(),
        work,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn experiment_with_intervention(
    caller: &CallerSession,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    controller: &Path,
    directory: &Path,
    scenario: &str,
    facet: &str,
    work: Instant,
    cleanup: Instant,
    intervention: Option<&mut PreparedIntervention<'_>>,
) -> Result<Experiment> {
    experiment_with_phases(
        caller,
        images,
        provider,
        controller,
        directory,
        scenario,
        facet,
        work,
        cleanup,
        intervention,
        None,
    )
}

pub(super) type ReleasedIntervention<'a> = dyn FnMut(
        &mut RequestLaunch,
        &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
        &[crate::linux_consumer_readiness::HeldLinuxProcess],
        &mut Value,
    ) -> Result<std::collections::BTreeMap<String, Vec<u8>>>
    + 'a;

#[allow(clippy::too_many_arguments)]
pub(super) fn experiment_with_phases(
    caller: &CallerSession,
    images: &CallerImages,
    provider: &memcordon_core::PublicProviderBindingV1,
    controller: &Path,
    directory: &Path,
    scenario: &str,
    facet: &str,
    work: Instant,
    cleanup: Instant,
    mut intervention: Option<&mut PreparedIntervention<'_>>,
    mut released_intervention: Option<&mut ReleasedIntervention<'_>>,
) -> Result<Experiment> {
    let images = images.minimal();
    let fixture = pack_experiment(caller, images, directory, work)?;
    let (memory, memory_bytes) = super::linux_snapshot_budget::memory_budget(
        &images.runtime,
        &images.input,
        128 * 1024 * 1024,
    )?;
    let observations = directory.join("observations");
    owned_directory(&observations, caller)?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| CiError::Message(error.to_string()))?;
    let challenge = hex::encode(nonce);
    let arguments = vec![
        "exec-held".into(),
        challenge.clone().into(),
        "/bin/owned-readiness".into(),
        "binary-file".into(),
        challenge.clone().into(),
    ];
    let mut launch = RequestLaunch::start(LaunchInput {
        extra_descriptor: None,
        lifetime: memcordon_core::Lifetime::Command,
        controller_directory: controller,
        observation_directory: Some(&observations),
        stdin: None,
        interactive: true,
        caller,
        fixture: &fixture,
        directory,
        provider,
        entrypoint: std::ffi::OsStr::new("owned-readiness"),
        arguments: &arguments,
        memory: memory.as_os_str(),
        deadline: std::ffi::OsStr::new("+30s"),
        output_directory: None,
        work_cutoff: work,
        cleanup_cutoff: cleanup,
    })?;
    let body = (|| -> Result<Experiment> {
        let frontend = launch.retain_frontend(work)?;
        let frontend_identity = json!({"pid":frontend.process_id,"birth":frontend.birth});
        wait_until(work, || {
            Ok(directory.join("workload-observation.json").try_exists()?)
        })?;
        let association = launch.association()?;
        let name = hex::encode(association.attempt);
        wait_until(work, || {
            Ok(observations
                .join(format!("{name}.prepared.json"))
                .try_exists()?)
        })?;
        let prepared = fs::read(observations.join(format!("{name}.prepared.json")))?;
        let decoded = memcordon_core::result_v3::LinuxWorkloadPreparedV1::parse(&prepared)
            .map_err(CiError::Message)?;
        if decoded.association != association {
            return Err(CiError::Message(
                "native prepared observation changed original locator".into(),
            ));
        }
        let (held, held_before) = hold_current_attempt(&association, work)?;
        if held.len() != 5 {
            return Err(CiError::Message(
                "native experiment original process inventory differs".into(),
            ));
        }
        let before = journal(&association)?;
        let cgroup_path = Path::new("/sys/fs/cgroup/memcordon-sealed").join(&name);
        let cgroup = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&cgroup_path)?;
        let cgroup_metadata = cgroup.metadata()?;
        if !cgroup_metadata.is_dir() || cgroup_metadata.uid() != 0 {
            return Err(CiError::Message(
                "actual original native cgroup custody differs".into(),
            ));
        }
        let cgroup_observation = json!({"path":cgroup_path,"device":cgroup_metadata.dev(),"inode":cgroup_metadata.ino()});
        drop(cgroup);
        let input_path = Path::new("/var/lib/memcordon/workload-inputs").join(&name);
        let staging_path = Path::new("/run/memcordon").join(format!("private-root-{name}"));
        let footprint_path = Path::new("/var/lib/memcordon/workload-resources").join(&name);
        let mut allocations = Vec::new();
        for (role, path) in [
            ("input-staging", &input_path),
            ("root-staging", &staging_path),
        ] {
            let directory = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            let metadata = directory.metadata()?;
            if !metadata.is_dir() || metadata.uid() != 0 {
                return Err(CiError::Message(
                    "native staging acquisition custody differs".into(),
                ));
            }
            allocations.push(
                json!({"role":role,"path":path,"device":metadata.dev(),"inode":metadata.ino()}),
            );
        }
        let mut charge = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&footprint_path)?;
        let metadata = charge.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.len() != 8
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(CiError::Message(
                "native footprint charge custody differs".into(),
            ));
        }
        let mut charge_bytes = [0u8; 8];
        charge.read_exact(&mut charge_bytes)?;
        drop(charge);
        allocations.push(json!({"role":"footprint","path":footprint_path,"device":metadata.dev(),"inode":metadata.ino(),"bytes":charge_bytes}));
        let original: Value = serde_json::from_slice(&before)?;
        let start = fs::read(observations.join(format!("{name}.start.json")))?;
        let mut files = std::collections::BTreeMap::from([
            ("request.json".into(), fs::read(&fixture.request)?),
            (
                "attempt.json".into(),
                fs::read(directory.join("workload-observation.json"))?,
            ),
            ("prepared.json".into(), prepared.clone()),
            ("start.json".into(), start),
            ("journal-before.json".into(), before),
            ("held-before.json".into(), serde_json::to_vec(&held_before)?),
        ]);
        files.insert(
            "cgroup-before.json".into(),
            serde_json::to_vec(&cgroup_observation)?,
        );
        files.insert(
            "allocations-before.json".into(),
            serde_json::to_vec(&allocations)?,
        );
        use std::os::unix::ffi::OsStrExt;
        files.insert("operands.json".into(),serde_json::to_vec(&json!({"working_directory":null,"memory_bytes":memory_bytes,"deadline_millis":30000,"lifetime":"command","target_argv":memcordon_readiness_verifier::NativeArguments::UnixBytes(arguments.iter().map(|value:&std::ffi::OsString|value.as_bytes().to_vec()).collect())}))?);
        files.insert(
            "provider-manifest.json".into(),
            fs::read("/usr/libexec/memcordon-runtime-manifest.json")?,
        );
        private(
            &controller.join(format!("current-attempt-{name}.json")),
            &json!({
                "format":"memcordon.current-controller-attempt-capture","revision":1,
                "scenario":scenario,"association":association,"captures":files
            }),
        )?;
        let mut action = json!({"format":"memcordon.current-native-component-action","revision":1,"scenario":scenario,"frontend":frontend_identity,"association":association,"challenge":challenge,"prepared_ack":false,"signal":null,"victim":null,"native_signal_result":null,"released_stdout":null,"service":null});
        if let Some(intervention) = intervention.as_mut() {
            for (name, bytes) in intervention(&association, &held)? {
                if files.insert(name, bytes).is_some() {
                    return Err(CiError::Message(
                        "owner intervention overwrote an original native capture".into(),
                    ));
                }
            }
            let captures: std::collections::BTreeMap<_, _> = files
                .iter()
                .filter(|(name, _)| name.as_str() != "owner-probe.bin")
                .collect();
            private(
                &controller.join(format!("current-attempt-{name}.json")),
                &json!({"format":"memcordon.current-controller-attempt-capture","revision":1,"scenario":scenario,"association":association,"captures":captures}),
            )?;
        }
        if facet != "journal-barrier" {
            let ack = memcordon_core::result_v3::WorkloadPreparedAckV1 {
                format: "memcordon.workload-prepared-ack".into(),
                revision: 1,
                association: association.clone(),
                prepared_sha256: memcordon_core::hash_bytes(&prepared),
            };
            let bytes = serde_json::to_vec(&ack)?;
            let mut file = tempfile::NamedTempFile::new_in(&observations)?;
            file.write_all(&bytes)?;
            rustix::fs::fchown(
                file.as_file(),
                Some(rustix::process::Uid::from_raw(caller.uid)),
                Some(rustix::process::Gid::from_raw(caller.gid)),
            )
            .map_err(std::io::Error::from)?;
            file.as_file().sync_all()?;
            file.persist_noclobber(observations.join(format!("{name}.prepared-ack.json")))
                .map_err(|error| CiError::Message(error.to_string()))?;
            files.insert("prepared-ack.json".into(), bytes);
            action["prepared_ack"] = json!(true);
            let snapshot = launch.snapshot_until(work)?;
            wait_until(work, || Ok(!snapshot.stdout()?.is_empty()))?;
            let stdout = snapshot.stdout()?;
            action["released_stdout"] = json!(artifacts::checksum(&stdout));
            files.insert("released-stdout.bin".into(), stdout);
            let released = journal(&association)?;
            let value: Value = serde_json::from_slice(&released)?;
            if value["native"]["exec_observed"] != true {
                return Err(CiError::Message(
                    "fixture stdout preceded durable actual exec observation".into(),
                ));
            }
            files.insert("journal-released.json".into(), released);
        }
        let mut service_hold = None;
        if facet == "released-service-loss" {
            let query = CommandSpec::new("/usr/bin/systemctl", controller, Duration::from_secs(30))
                .bounded_until(work)
                .args([
                    "show",
                    "--property=MainPID",
                    "--value",
                    "memcordon-sealed-agent.service",
                ])
                .output_quiet()?;
            require_successful_output("actual original service instance query", &query)?;
            let pid = std::str::from_utf8(&query.stdout)
                .map_err(|error| CiError::Message(error.to_string()))?
                .trim()
                .parse::<u32>()
                .map_err(|error| CiError::Message(error.to_string()))?;
            if pid <= 1 {
                return Err(CiError::Message(
                    "actual original service instance is absent".into(),
                ));
            }
            let birth =
                crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)?;
            let mut process =
                crate::linux_consumer_readiness::HeldLinuxProcess::acquire(pid, birth)
                    .map_err(CiError::Message)?;
            let image = process
                .hold_executable_image(work)
                .map_err(CiError::Message)?;
            let manifest: Value = serde_json::from_slice(&files["provider-manifest.json"])?;
            if !manifest["components"].as_array().is_some_and(|components| {
                components.iter().any(|component| {
                    component["id"] == "sealed-agent" && component["sha256"] == image["sha256"]
                })
            }) {
                return Err(CiError::Message(
                    "held original service image differs from installed selected component".into(),
                ));
            }
            action["service"] = json!({"unit":"memcordon-sealed-agent.service","query_status":query.status.code(),"query_stdout":query.stdout,"query_stderr":query.stderr,"process":{"pid":pid,"birth":birth},"image":image,"pidfd_readable":false});
            service_hold = Some(process);
        }
        let intervened = if let Some(intervention) = released_intervention.as_mut() {
            for (name, bytes) in intervention(&mut launch, &association, &held, &mut action)? {
                if files.insert(name, bytes).is_some() {
                    return Err(CiError::Message(
                        "native phase intervention overwrote original observed capture".into(),
                    ));
                }
            }
            true
        } else {
            false
        };
        if !intervened {
            if facet == "release-barrier" {
                launch.send_input(b"R".to_vec())?;
                launch.close_input();
            } else {
                let victim = if facet == "lost-terminal-response" {
                    launch.retain_frontend(work)?
                } else if facet == "released-guardian-loss" {
                    &held[2]
                } else if facet == "released-control-loss" {
                    &held[1]
                } else if facet == "released-service-loss" {
                    service_hold.as_ref().expect("actual held original service")
                } else {
                    &held[0]
                };
                action["signal"] = json!(9);
                action["victim"] = json!({"pid":victim.process_id,"birth":victim.birth});
                victim
                    .signal_kill()
                    .map_err(CiError::Message)?
                    .map_err(|code| {
                        CiError::Message(format!(
                            "exact original native victim SIGKILL failed: {code}"
                        ))
                    })?;
                action["native_signal_result"] = json!(0);
            }
        }
        launch.close_input();
        let capture = launch.capture_until(cleanup)?;
        files.insert("stdout.bin".into(), capture.stdout.clone());
        files.insert("stderr.bin".into(), capture.stderr.clone());
        use std::os::unix::process::ExitStatusExt;
        let raw_wait_status = capture.status.into_raw();
        match fs::read(directory.join("workload-result.json")) {
            Ok(bytes) => {
                files.insert("result.json".into(), bytes);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        files.insert(
            "frontend-wait.json".into(),
            serde_json::to_vec(
                &json!({"status":capture.status.code(),"raw_wait_status":raw_wait_status}),
            )?,
        );
        if facet == "release-barrier" {
            let result = launch.result()?;
            if result.outcome.wrapper_status != 0 {
                return Err(CiError::Message(
                    "actual released native workload failed".into(),
                ));
            }
            files.insert(
                "result.json".into(),
                fs::read(directory.join("workload-result.json"))?,
            );
        } else {
            wait_until(cleanup, || held[0].exited().map_err(CiError::Message))?;
            wait_until(cleanup, || held[1].exited().map_err(CiError::Message))?;
            let recovery = launch.recover()?;
            files.insert("recovery.json".into(), recovery.raw_terminal.clone());
            files.insert("recovery-process.json".into(),serde_json::to_vec(&json!({"status":recovery.process.status.code(),"stdout":recovery.process.stdout,"stderr":recovery.process.stderr}))?);
            if facet == "repeated-recovery" {
                let repeated = launch.recover()?;
                files.insert("recovery-repeat.json".into(), repeated.raw_terminal.clone());
                files.insert("recovery-repeat-process.json".into(),serde_json::to_vec(&json!({"status":repeated.process.status.code(),"stdout":repeated.process.stdout,"stderr":repeated.process.stderr}))?);
            }
        }
        let mut retired = Vec::new();
        for process in &held {
            wait_until(cleanup, || process.exited().map_err(CiError::Message))?;
            retired.push(
                json!({"pid":process.process_id,"birth":process.birth,"pidfd_readable":true}),
            );
        }
        files.insert("journal-after.json".into(), journal(&association)?);
        if let Some(service) = service_hold.as_ref() {
            wait_until(cleanup, || service.exited().map_err(CiError::Message))?;
            action["service"]["pidfd_readable"] = json!(true);
        }
        let mut absent = Vec::new();
        for path in [&cgroup_path, &input_path, &staging_path, &footprint_path] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    absent.push(json!({"path":path,"absent":true}))
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    return Err(CiError::Message(format!(
                        "actual native resource remains after reported cleanup: {}",
                        path.display()
                    )));
                }
            }
        }
        files.insert(
            "allocations-after.json".into(),
            serde_json::to_vec(&absent)?,
        );
        action["retired"] = serde_json::to_value(retired)?;
        action["prepared_journal_phase"] = original["phase"].clone();
        files.insert("action.json".into(), serde_json::to_vec(&action)?);
        let acknowledged = caller
            .command(directory, cleanup)?
            .args(["workload", "acknowledge", "--observation"])
            .arg(directory.join("workload-observation.json"))
            .output_quiet()?;
        require_successful_output(
            "actual current native component metadata acknowledgment",
            &acknowledged,
        )?;
        if !matches!(fs::symlink_metadata(Path::new("/var/lib/memcordon/workload-attempts").join(&name)),Err(error)if error.kind()==std::io::ErrorKind::NotFound)
        {
            return Err(CiError::Message(
                "acknowledged original native record remains or is ambiguous".into(),
            ));
        }
        files.insert("acknowledgment-process.json".into(),serde_json::to_vec(&json!({"status":acknowledged.status.code(),"stdout":acknowledged.stdout,"stderr":acknowledged.stderr}))?);
        files.insert(
            "entrypoint.bin".into(),
            artifacts::read_file(&images.runtime_source.join("bin/owned-readiness"))?,
        );
        files.insert(
            "runtime-snapshot.json".into(),
            images.runtime.canonical_bytes().map_err(CiError::Message)?,
        );
        files.insert(
            "input-snapshot.json".into(),
            images.input.canonical_bytes().map_err(CiError::Message)?,
        );
        Ok(Experiment {
            scenario: scenario.into(),
            directory: directory.into(),
            files,
        })
    })();
    match body {
        Ok(experiment) => {
            launch.retire_bundle_exact(&fixture)?;
            Ok(experiment)
        }
        Err(primary) => match launch.cancel_and_settle(cleanup) {
            Ok(_) => Err(primary),
            Err(settlement) => Err(CiError::Message(format!(
                "{primary}; original frontend settlement incomplete: {settlement}"
            ))),
        },
    }
}
