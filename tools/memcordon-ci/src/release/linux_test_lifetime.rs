//! Real installed lifetime for current native boundary experiments. Every
//! package/account mutation has a protected original owner before execution.
use super::{
    artifacts,
    linux_request_fixture::{CallerRequestFixture, CallerSession, CallerSnapshot},
    linux_request_launch::{LaunchInput, RequestLaunch},
    linux_test_execution::{CallerImages, hold_current_attempt},
};
use crate::{
    CiError, Result,
    command::{CommandSpec, require_successful_output},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

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
    let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Experiment> {
        let frontend = launch.retain_frontend(work)?;
        let frontend_identity = json!({"pid":frontend.process_id,"birth":frontend.birth});
        launch.wait_for_event(work, "workload observation", || {
            Ok(directory.join("workload-observation.json").try_exists()?)
        })?;
        let association = launch.association()?;
        let name = hex::encode(association.attempt);
        launch.wait_for_event(work, "prepared observation", || {
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
        files.insert("operands.json".into(),serde_json::to_vec(&json!({"working_directory":null,"memory_bytes":memory_bytes,"deadline_millis":30000,"lifetime":"command","target_argv":arguments.iter().map(|value:&std::ffi::OsString|value.as_bytes().to_vec()).collect::<Vec<_>>()}))?);
        files.insert(
            "provider-manifest.json".into(),
            fs::read("/usr/libexec/memcordon-runtime-manifest.json")?,
        );
        let mut action = json!({"format":"memcordon.current-native-component-action","revision":1,"scenario":scenario,"frontend":frontend_identity,"association":association,"challenge":challenge,"prepared_ack":false,"signal":null,"victim":null,"native_signal_result":null,"released_stdout":null,"service":null});
        if let Some(intervention) = intervention.as_mut() {
            for (name, bytes) in intervention(&association, &held)? {
                if files.insert(name, bytes).is_some() {
                    return Err(CiError::Message(
                        "owner intervention overwrote an original native capture".into(),
                    ));
                }
            }
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
            launch.wait_for_event(work, "released stdout", || {
                Ok(!snapshot.stdout()?.is_empty())
            })?;
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
    }));
    let _retirement = crate::cancellation::retirement_scope(cleanup);
    let body = match body {
        Ok(result) => result,
        Err(panic) => {
            match launch.cancel_and_settle(cleanup) {
                Ok(_) => {
                    if let Err(error) = launch.retire_bundle_exact(&fixture) {
                        eprintln!("native input retirement after unwind: {error}");
                    }
                }
                Err(error) => eprintln!("native request settlement after unwind: {error}"),
            }
            std::panic::resume_unwind(panic)
        }
    };
    match body {
        Ok(experiment) => {
            launch.retire_bundle_exact(&fixture)?;
            Ok(experiment)
        }
        Err(primary) => match launch.cancel_and_settle(cleanup) {
            Ok(settled) => Err(primary.context(format!("original frontend settlement: {settled}"))),
            Err(settlement) => Err(CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(settlement),
            }),
        },
    }
}
