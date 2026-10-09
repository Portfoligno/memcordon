//! Separate selected-package lifetime for original native component fixtures.
//! The caller retains this owner through every setup and finalization error.
use super::{
    artifacts,
    installed_consumer::{MaterializedPayload, binary_path},
    linux_mixed_installed::{
        ActivatedMixedPolicy, InstalledMixedDriver, InstalledMixedDriverInput,
    },
};
use crate::{CiError, Result, command::CommandSpec, consumer_readiness_ledger::SourceIdentity};
use memcordon_readiness_verifier::ProductKey;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub struct NativeLinuxPackageLease {
    pub driver: InstalledMixedDriver,
    payload: MaterializedPayload,
    agent: PathBuf,
    held_agent: fs::File,
    agent_sha256: String,
    output: PathBuf,
    legacy: memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry,
    install_issued: bool,
    uninstall_issued: bool,
    uninstall_succeeded: bool,
    failures: Vec<String>,
    native_settled: bool,
    resources_retired: bool,
    recovery_processes: Vec<NativeRecoveryProcess>,
    recovery_observation_files: Vec<fs::File>,
}

struct NativeRecoveryProcess {
    process_id: u32,
    birth: u64,
    pidfd: std::os::fd::OwnedFd,
    image: Option<fs::File>,
}

fn observe_original_absence(
    role: &str,
    path: &Path,
    original: &serde_json::Value,
    journal: &serde_json::Value,
    deadline: Instant,
    owners: &mut Vec<fs::File>,
) -> Result<serde_json::Value> {
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(CiError::Message(
            "original recovery leaf path is not normalized".into(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| CiError::Message("original recovery leaf parent absent".into()))?;
    if parent != Path::new("/var/lib/memcordon/sealed") {
        return Err(CiError::Message(
            "original recovery leaf crosses native state parent".into(),
        ));
    }
    let start = owners.len();
    owners.push(
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?,
    );
    for name in ["var", "lib", "memcordon", "sealed"] {
        if Instant::now() >= deadline {
            return Err(CiError::Message(
                "native recovery ancestry cutoff exhausted".into(),
            ));
        }
        let file = fs::File::from(
            rustix::fs::openat(
                owners.last().expect("parent retained"),
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        let metadata = file.metadata()?;
        owners.push(file);
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "native recovery parent protection differs".into(),
            ));
        }
    }
    let held = owners.last().expect("state parent retained");
    let before = held.metadata()?;
    if journal["parent_device"] != before.dev()
        || journal["parent_inode"] != before.ino()
        || journal["parent_uid"] != before.uid()
        || journal["parent_mode"] != before.mode()
    {
        return Err(CiError::Message(
            "native recovered parent differs from original journal owner".into(),
        ));
    }
    let name = path
        .file_name()
        .ok_or_else(|| CiError::Message("native recovery basename absent".into()))?;
    let absent = || -> Result<()> {
        match rustix::fs::statat(held, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
            Err(error) => Err(CiError::Message(error.to_string())),
            Ok(_) => Err(CiError::Message(
                "original native recovery leaf remains present".into(),
            )),
        }
    };
    absent()?;
    for (index, name) in ["var", "lib", "memcordon", "sealed"]
        .into_iter()
        .enumerate()
    {
        let named = fs::File::from(
            rustix::fs::openat(
                &owners[start + index],
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        let original = owners[start + index + 1].metadata()?;
        let current = named.metadata()?;
        if (
            original.dev(),
            original.ino(),
            original.uid(),
            original.mode(),
            original.nlink(),
        ) != (
            current.dev(),
            current.ino(),
            current.uid(),
            current.mode(),
            current.nlink(),
        ) {
            return Err(CiError::Message(
                "native recovered parent ancestry reassociated".into(),
            ));
        }
    }
    absent()?;
    held.sync_all()?;
    if Instant::now() >= deadline {
        return Err(CiError::Message(
            "native recovery absence crossed original cutoff".into(),
        ));
    }
    Ok(
        serde_json::json!({"role":role,"original":original,"path":path,"basename":name,
        "parent_path":parent,"parent_device":before.dev(),"parent_inode":before.ino(),"parent_uid":before.uid(),
        "parent_mode":before.mode(),"native_errno":libc::ENOENT}),
    )
}

fn observe_recovery_credentials(
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> Result<Vec<serde_json::Value>> {
    use std::io::Read;
    let mut rows = Vec::new();
    let mut scanned = 0usize;
    let mut retained_bytes = 0usize;
    let mut scalars = 0usize;
    let read = |path: &Path| -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "native task file exceeds bound",
            ));
        }
        Ok(bytes)
    };
    for process in fs::read_dir("/proc")? {
        let process = process?;
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let tasks = match fs::read_dir(process.path().join("task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for task in tasks {
            scanned += 1;
            if scanned > 1_048_576 || Instant::now() >= deadline {
                return Err(CiError::Message(
                    "native recovery census count/cutoff exhausted".into(),
                ));
            }
            let task = task?;
            let tid = task
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
                .ok_or_else(|| CiError::Message("native task identifier malformed".into()))?;
            let birth = || -> std::io::Result<u64> {
                let bytes = read(&task.path().join("stat"))?;
                let text = std::str::from_utf8(&bytes).map_err(std::io::Error::other)?;
                text.rsplit_once(')')
                    .and_then(|(_, fields)| fields.split_whitespace().nth(19))
                    .ok_or_else(|| std::io::Error::other("native task birth absent"))?
                    .parse()
                    .map_err(std::io::Error::other)
            };
            let before = match birth() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let status = match read(&task.path().join("status")) {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            retained_bytes = retained_bytes
                .checked_add(status.len())
                .ok_or_else(|| CiError::Message("native census bytes overflow".into()))?;
            let text = std::str::from_utf8(&status)
                .map_err(|error| CiError::Message(error.to_string()))?;
            let credentials = |prefix: &str, required: Option<usize>| -> Result<Vec<u32>> {
                let matches = text
                    .lines()
                    .filter(|line| line.starts_with(prefix))
                    .collect::<Vec<_>>();
                if matches.len() != 1 {
                    return Err(CiError::Message(
                        "native credential row absent/duplicated".into(),
                    ));
                }
                let values = matches[0][prefix.len()..]
                    .split_whitespace()
                    .map(str::parse::<u32>)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|error| CiError::Message(error.to_string()))?;
                if required.is_some_and(|count| values.len() != count) {
                    return Err(CiError::Message(
                        "native credential vector length differs".into(),
                    ));
                }
                Ok(values)
            };
            let uids = credentials("Uid:", Some(4))?;
            let gids = credentials("Gid:", Some(4))?;
            let groups = credentials("Groups:", None)?;
            scalars = scalars
                .checked_add(uids.len() + gids.len() + groups.len())
                .ok_or_else(|| CiError::Message("native census scalar overflow".into()))?;
            if retained_bytes > 8 * 1024 * 1024 || scalars > 262144 {
                return Err(CiError::Message(
                    "native census aggregate bound exceeded".into(),
                ));
            }
            if uids.contains(&uid) || gids.contains(&gid) || groups.contains(&gid) {
                return Err(CiError::Message(
                    "original exclusive native account remains live".into(),
                ));
            }
            let after = match birth() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if before != after || before == 0 {
                return Err(CiError::Message(
                    "native task birth changed during recovery census".into(),
                ));
            }
            rows.push(serde_json::json!({"pid":pid,"tid":tid,"birth":before,"uids":uids,"gids":gids,"groups":groups}));
        }
    }
    if Instant::now() >= deadline {
        return Err(CiError::Message(
            "native recovery census completed after cutoff".into(),
        ));
    }
    Ok(rows)
}
impl NativeRecoveryProcess {
    fn exited(&self) -> Result<bool> {
        let mut fds = [rustix::event::PollFd::new(
            &self.pidfd,
            rustix::event::PollFlags::IN,
        )];
        let count = rustix::event::poll(
            &mut fds,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        if fds[0]
            .revents()
            .intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL)
        {
            return Err(CiError::Message("native recovery PIDFD poll failed".into()));
        }
        Ok(count > 0
            && fds[0]
                .revents()
                .intersects(rustix::event::PollFlags::IN | rustix::event::PollFlags::HUP))
    }
}

impl NativeLinuxPackageLease {
    /// Replay persisted native cleanup after a fully retired component worker,
    /// before the next recipe may authenticate the same exclusive account.
    pub fn recover_component(
        &mut self,
        workspace: &Path,
        directory: &Path,
        deadline: Instant,
        original_work_unix: u64,
        original_cleanup_unix: u64,
    ) -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::ExitStatusExt;
        self.verify_agent()?;
        if Instant::now() >= deadline {
            return Err(CiError::Message(
                "original component recovery cutoff exhausted".into(),
            ));
        }
        let read = |name: &str| -> Result<Vec<u8>> {
            crate::linux_consumer_readiness::measured(&directory.join(name), 16 * 1024 * 1024)
                .map_err(CiError::Message)
        };
        let decode = |bytes: &[u8]| -> Result<serde_json::Value> {
            memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)
                .map_err(CiError::Message)?;
            Ok(serde_json::from_slice(bytes)?)
        };
        let input_bytes = read("native-input.json")?;
        let boundary_bytes = read("account-boundary.json")?;
        let ownership_bytes = read("account-ownership.json")?;
        let input = decode(&input_bytes)?;
        let boundary = decode(&boundary_bytes)?;
        let _ownership = decode(&ownership_bytes)?;
        if input["run_id"] != boundary["run_id"]
            || input["recipe_id"] != boundary["recipe_id"]
            || input["native_target"] != boundary["native_target"]
            || input["artifact_root"] != serde_json::to_value(directory)?
            || input["fixture_sha256"] != boundary["fixture_sha256"]
            || input["work_deadline_unix_millis"] != original_work_unix
            || input["cleanup_deadline_unix_millis"] != original_cleanup_unix
            || !input["cleanup_deadline_unix_millis"]
                .as_u64()
                .zip(input["work_deadline_unix_millis"].as_u64())
                .is_some_and(|(cleanup, work)| work < cleanup)
        {
            return Err(CiError::Message(
                "component recovery crosses original delivered boundary/cutoff".into(),
            ));
        }
        let checkpoint_bytes = crate::linux_consumer_readiness::measured(
            &self.output.join("resources/owned-resources-acquired.json"),
            16 * 1024 * 1024,
        )
        .map_err(CiError::Message)?;
        let checkpoint = decode(&checkpoint_bytes)?;
        if checkpoint["identity"]["run_id"] != input["run_id"]
            || checkpoint["identity"]["source_commit"] != self.payload.source.commit()
            || checkpoint["cell"]["target"] != input["native_target"]
        {
            return Err(CiError::Message(
                "component recovery acquired source/account differs".into(),
            ));
        }
        let arguments = ["package", "policy", "recover", "--json"];
        let package_owner_bytes = crate::linux_consumer_readiness::measured(
            &self.output.join("native-package-owner.json"),
            16 * 1024 * 1024,
        )
        .map_err(CiError::Message)?;
        let package_owner = decode(&package_owner_bytes)?;
        let selected_program = self.held_agent.metadata()?;
        if package_owner["cleanup_agent_sha256"] != self.agent_sha256
            || package_owner["cleanup_agent_device"] != selected_program.dev()
            || package_owner["cleanup_agent_inode"] != selected_program.ino()
            || package_owner["source"] != serde_json::to_value(&self.payload.source)?
        {
            return Err(CiError::Message(
                "original native package owner differs from selected recovery executable".into(),
            ));
        }
        let invocation = serde_json::json!({"format":"memcordon.native-component-recovery-invocation","revision":1,
            "identity":checkpoint["identity"],"run_id":input["run_id"],"recipe_id":input["recipe_id"],"native_target":input["native_target"],
            "program":self.agent.as_os_str().as_bytes(),"arguments":arguments.iter().map(|value|value.as_bytes()).collect::<Vec<_>>(),
            "package_owner_sha256":artifacts::checksum(&package_owner_bytes),
            "selected_program":{"device":selected_program.dev(),"inode":selected_program.ino(),"length":selected_program.len(),"links":selected_program.nlink(),"uid":selected_program.uid(),"mode":selected_program.mode()},
            "working_directory":workspace.as_os_str().as_bytes(),"executable_sha256":self.agent_sha256,"environment":[],
            "work_deadline_unix_millis":input["work_deadline_unix_millis"],"cleanup_deadline_unix_millis":input["cleanup_deadline_unix_millis"],
            "boundary_sha256":artifacts::checksum(&boundary_bytes),
            "ownership_sha256":artifacts::checksum(&ownership_bytes)});
        super::source::write_json(
            &directory.join("native-recovery-invocation.json"),
            &invocation,
        )?;
        let invocation_bytes = crate::linux_consumer_readiness::measured(
            &directory.join("native-recovery-invocation.json"),
            4 * 1024 * 1024,
        )
        .map_err(CiError::Message)?;
        self.verify_agent()?;
        let mut process_observation = None;
        let expected_image = self.held_agent.metadata()?;
        let captured = CommandSpec::new(&self.agent, workspace, Duration::from_secs(300))
            .args(arguments)
            .cleared_environment()
            .bounded_until(deadline)
            .output_limit(4 * 1024 * 1024)
            .output_quiet_with_creation(|child| {
                let birth = crate::linux_consumer_readiness::process_birth(child.id())
                    .map_err(CiError::Message)?;
                let pid = rustix::process::Pid::from_raw(
                    i32::try_from(child.id())
                        .map_err(|error| CiError::Message(error.to_string()))?,
                )
                .ok_or_else(|| CiError::Message("native recovery creation PID absent".into()))?;
                let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
                    .map_err(|error| CiError::Message(error.to_string()))?;
                self.recovery_processes.push(NativeRecoveryProcess {
                    process_id: child.id(),
                    birth,
                    pidfd,
                    image: None,
                });
                let held = self
                    .recovery_processes
                    .last_mut()
                    .expect("creation owner retained");
                if crate::linux_consumer_readiness::process_birth(child.id())
                    .map_err(CiError::Message)?
                    != birth
                {
                    return Err(CiError::Message(
                        "native recovery creation birth changed".into(),
                    ));
                }
                let image = match fs::File::open(format!("/proc/{}/exe", child.id())) {
                    Ok(file) => {
                        let metadata = file.metadata()?;
                        if (metadata.dev(), metadata.ino())
                            != (expected_image.dev(), expected_image.ino())
                        {
                            return Err(CiError::Message(
                                "actual native recovery process image differs".into(),
                            ));
                        }
                        held.image = Some(file);
                        serde_json::json!({"device":metadata.dev(),"inode":metadata.ino()})
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::NotFound && held.exited()? =>
                    {
                        serde_json::Value::Null
                    }
                    Err(error) => return Err(error.into()),
                };
                process_observation =
                    Some(serde_json::json!({"process_id":child.id(),"birth":birth,"image":image}));
                Ok(())
            })?;
        let retired_owner = self
            .recovery_processes
            .last()
            .ok_or_else(|| CiError::Message("native recovery creation owner absent".into()))?;
        if !retired_owner.exited()? {
            return Err(CiError::Message(
                "native recovery creation process remains held live".into(),
            ));
        }
        let retired = serde_json::json!({"process_id":retired_owner.process_id,"birth":retired_owner.birth,"pidfd_retirement_observed":true});
        self.verify_agent()?;
        super::source::write_json(
            &directory.join("native-recovery-process.json"),
            &serde_json::json!({"format":"memcordon.native-component-recovery-process","revision":1,
                "invocation_sha256":artifacts::checksum(&invocation_bytes),"creation":process_observation,
                "native_wait_status":captured.status.into_raw(),"retirement":retired}),
        )?;
        let capture = serde_json::json!({"format":"memcordon.native-component-recovery-capture","revision":1,
            "invocation_sha256":artifacts::checksum(&invocation_bytes),"native_wait_status":captured.status.into_raw(),"status":captured.status.code(),
            "stdout":captured.stdout,"stderr":captured.stderr,"stdout_sha256":artifacts::checksum(&captured.stdout),"stderr_sha256":artifacts::checksum(&captured.stderr)});
        super::source::write_json(&directory.join("native-recovery-capture.json"), &capture)?;
        if !captured.status.success() || captured.stdout.len() > 4 * 1024 * 1024 {
            return Err(CiError::Message(
                "component native recovery did not complete".into(),
            ));
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&captured.stdout)
            .map_err(CiError::Message)?;
        let response: serde_json::Value = serde_json::from_slice(&captured.stdout)?;
        if !response.as_object().is_some_and(|object| object.len() == 3)
            || response["format"] != "memcordon.native-recovery"
            || response["revision"] != 1
            || response["outstanding"] != serde_json::json!([])
        {
            return Err(CiError::Message(
                "component native recovery retains original ownership obligations".into(),
            ));
        }
        if Instant::now() >= deadline {
            return Err(CiError::Message(
                "original component recovery completed after cutoff".into(),
            ));
        }
        let uid = u32::try_from(
            checkpoint["account"]["uid"]
                .as_u64()
                .ok_or_else(|| CiError::Message("original acquired account UID absent".into()))?,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let gid = u32::try_from(
            checkpoint["account"]["gid"]
                .as_u64()
                .ok_or_else(|| CiError::Message("original acquired account GID absent".into()))?,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        if _ownership["account"]["account_uid"] != uid
            || _ownership["account"]["attempt_id"] != boundary["native"]["attempt_id"]
        {
            return Err(CiError::Message(
                "recovered native account/attempt association differs".into(),
            ));
        }
        let mut absence = Vec::new();
        for (role, original, path) in [
            (
                "journal",
                &_ownership["journal"],
                _ownership["journal"]["path"].as_str(),
            ),
            (
                "reference",
                &_ownership["account"]["reference"],
                _ownership["account"]["reference_path"].as_str(),
            ),
            (
                "reservation",
                &_ownership["account"]["reservation"],
                _ownership["account"]["reservation"]["path"].as_str(),
            ),
        ] {
            let path =
                Path::new(path.ok_or_else(|| {
                    CiError::Message("original owned recovery path absent".into())
                })?);
            absence.push(observe_original_absence(
                role,
                path,
                original,
                &_ownership["journal"],
                deadline,
                &mut self.recovery_observation_files,
            )?);
        }
        let tasks = observe_recovery_credentials(uid, gid, deadline)?;
        super::source::write_json(
            &directory.join("recovered-ownership.json"),
            &serde_json::json!({"format":"memcordon.native-component-recovered-ownership","revision":1,
                "identity":checkpoint["identity"],"run_id":input["run_id"],"recipe_id":input["recipe_id"],"native_target":input["native_target"],
                "boundary_sha256":artifacts::checksum(&boundary_bytes),"ownership_sha256":artifacts::checksum(&ownership_bytes),
                "checkpoint_sha256":artifacts::checksum(&checkpoint_bytes),"attempt_id":boundary["native"]["attempt_id"],
                "account_uid":uid,"account_gid":gid,"work_deadline_unix_millis":original_work_unix,"cleanup_deadline_unix_millis":original_cleanup_unix,
                "absent_owned_leaves":absence,"tasks":tasks}),
        )?;
        Ok(())
    }
    /// Reconstruct cleanup resources from the original protected records only.
    /// Lost command output or execution evidence is never reconstructed.
    pub fn recover(
        workspace: &Path,
        identity: &SourceIdentity,
        target: &str,
        admin: &Path,
        output: &Path,
        cleanup: Instant,
    ) -> Result<Self> {
        super::linux_native_component::protected_directory(admin)?;
        super::linux_native_component::protected_directory(output)?;
        fn read(path: &Path) -> Result<serde_json::Value> {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || metadata.nlink() != 1
            {
                return Err(CiError::Message(
                    "original native package record protection differs".into(),
                ));
            }
            let bytes = crate::linux_consumer_readiness::measured(path, 16 * 1024 * 1024)
                .map_err(CiError::Message)?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                .map_err(CiError::Message)?;
            Ok(serde_json::from_slice(&bytes)?)
        }
        let owner = read(&output.join("native-package-owner.json"))?;
        let agent = admin.join("native-package-cleanup-agent");
        let held_agent = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&agent)?;
        let native = held_agent.metadata()?;
        let agent_sha256 = artifacts::checksum(
            &crate::linux_consumer_readiness::measured(&agent, 512 * 1024 * 1024)
                .map_err(CiError::Message)?,
        );
        let payload = super::installed_consumer::materialize_native(
            &workspace.join(".release/target"),
            admin,
        )?;
        if payload.source.commit() != identity.source_commit
            || payload.source.version().to_string() != identity.version
            || payload.distribution.target != target
        {
            return Err(CiError::Message(
                "recovered original native package source differs".into(),
            ));
        }
        let legacy: memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry =
            serde_json::from_value(owner["legacy"].clone())?;
        legacy.validate().map_err(CiError::Message)?;
        if owner
            != serde_json::json!({"format":"memcordon.consumer-readiness.native-package-owner","revision":1,"source":payload.source,"distribution":payload.distribution,"cleanup_agent":agent,"cleanup_agent_sha256":agent_sha256,"cleanup_agent_device":native.dev(),"cleanup_agent_inode":native.ino(),"original_installation_absent":true,"legacy":legacy})
        {
            return Err(CiError::Message(
                "original native package owner association differs".into(),
            ));
        }
        let cell = ProductKey {
            target: target.into(),
            channel: "candidate-native".into(),
        };
        let install_issued = match read(&output.join("native-package-install-intent.json")) {
            Ok(record) => {
                if record
                    != serde_json::json!({"source":identity,"cell":cell,"cleanup_agent_sha256":agent_sha256,"uninstall_required":true})
                {
                    return Err(CiError::Message(
                        "original native install intent association differs".into(),
                    ));
                }
                true
            }
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let uninstall_issued = match read(&output.join("native-package-uninstall-intent.json")) {
            Ok(record) => {
                if record
                    != serde_json::json!({"cleanup_agent_sha256":agent_sha256,"owned_attempts_and_resources_settled":true})
                {
                    return Err(CiError::Message(
                        "original native uninstall intent differs".into(),
                    ));
                }
                true
            }
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let uninstall_succeeded = if uninstall_issued {
            let capture = read(&output.join("native-package-uninstall.json"))?;
            if !capture.as_object().is_some_and(|fields| {
                fields.len() == 3
                    && fields.contains_key("status")
                    && fields.contains_key("stdout")
                    && fields.contains_key("stderr")
            }) || serde_json::from_value::<Vec<u8>>(capture["stdout"].clone()).is_err()
                || serde_json::from_value::<Vec<u8>>(capture["stderr"].clone()).is_err()
            {
                return Err(CiError::Message(
                    "original native uninstall capture shape differs".into(),
                ));
            }
            capture["status"] == 0
        } else {
            false
        };
        let setup_started = match read(&output.join("native-resource-setup-intent.json")) {
            Ok(record) => {
                if record
                    != serde_json::json!({"source":identity,"cell":cell,"resource_setup_required":true})
                {
                    return Err(CiError::Message(
                        "original native resource setup intent association differs".into(),
                    ));
                }
                true
            }
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let mut value = Self {
            driver: Default::default(),
            payload,
            agent,
            held_agent,
            agent_sha256,
            output: output.to_owned(),
            legacy,
            install_issued,
            uninstall_issued,
            uninstall_succeeded,
            failures: Vec::new(),
            native_settled: false,
            resources_retired: false,
            recovery_processes: Vec::new(),
            recovery_observation_files: Vec::new(),
        };
        value.verify_agent()?;
        if install_issued {
            // Reconstruct original resource custody before finalization. A
            // successful accepted uninstall already includes its locked journal
            // and native recovery gates; no retired public recovery command or
            // synthetic standalone recovery receipt is part of this boundary.
            let resources = output.join("resources");
            match fs::symlink_metadata(&resources) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if setup_started {
                        return Err(CiError::Message(
                            "started native resource setup lost its custody records".into(),
                        ));
                    }
                    value.resources_retired = true;
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    let original_admin = fs::symlink_metadata(admin)?;
                    if resources
                        .join("owned-resources-retired.json")
                        .try_exists()?
                    {
                        InstalledMixedDriver::assess_retired_resources(
                            &resources,
                            identity,
                            &cell,
                            admin,
                            original_admin.dev(),
                            original_admin.ino(),
                            workspace,
                            cleanup,
                        )?;
                        value.resources_retired = true;
                    } else {
                        let checkpoint = if resources
                            .join("owned-resources-acquired.json")
                            .try_exists()?
                        {
                            Some(resources.join("owned-resources-acquired.json"))
                        } else if resources.join("owned-resources-images.json").try_exists()? {
                            Some(resources.join("owned-resources-images.json"))
                        } else {
                            None
                        };
                        value.driver = if let Some(checkpoint) = checkpoint {
                            InstalledMixedDriver::recover_owned_resources(
                                &checkpoint,
                                identity,
                                &cell,
                                admin,
                                original_admin.dev(),
                                original_admin.ino(),
                                &value.legacy,
                            )?
                        } else {
                            InstalledMixedDriver::recover_partial_acquisition(
                                &resources, identity, &cell, admin,
                            )?
                        };
                    }
                }
            }
        }
        Ok(value)
    }

    /// Acquisition copies the measured cleanup executable but installs nothing.
    pub fn acquire(payload: MaterializedPayload, admin: &Path, output: &Path) -> Result<Self> {
        if !rustix::process::geteuid().is_root() {
            return Err(CiError::Message(
                "original component package requires owned administrator controller".into(),
            ));
        }
        let ancestry = super::linux_native_component::protected_directory(admin)?;
        fs::create_dir(output)?;
        for binary in &payload.distribution.binaries {
            match fs::symlink_metadata(Path::new("/usr/libexec").join(binary)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    return Err(CiError::Message(
                        "original component package refuses an existing selected installation"
                            .into(),
                    ));
                }
            }
        }
        let original = binary_path(
            &payload.directory,
            "memcordon-sealed-agent",
            &payload.distribution.target,
        );
        let bytes = crate::linux_consumer_readiness::measured(&original, 512 * 1024 * 1024)
            .map_err(CiError::Message)?;
        let agent = admin.join("native-package-cleanup-agent");
        let mut held_agent = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&agent)?;
        held_agent.write_all(&bytes)?;
        held_agent.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o555))?;
        held_agent.sync_all()?;
        ancestry
            .last()
            .ok_or_else(|| CiError::Message("held package administrator parent absent".into()))?
            .sync_all()?;
        let held_agent = super::native_executable::retain_readonly(&agent, held_agent)?;
        let legacy = memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry {
            format: "memcordon.local-private-policy".into(),
            revision: 1,
            profiles: Default::default(),
            execution_identities: Default::default(),
            grants: Default::default(),
            active_attempt_disposition:
                memcordon_core::workload_registry::GrantChangeDisposition::DrainExisting,
        };
        legacy.validate().map_err(CiError::Message)?;
        let value = Self {
            driver: Default::default(),
            payload,
            agent,
            held_agent,
            agent_sha256: artifacts::checksum(&bytes),
            output: output.to_path_buf(),
            legacy,
            install_issued: false,
            uninstall_issued: false,
            uninstall_succeeded: false,
            failures: Vec::new(),
            native_settled: false,
            resources_retired: false,
            recovery_processes: Vec::new(),
            recovery_observation_files: Vec::new(),
        };
        value.verify_agent()?;
        super::source::write_json(
            &value.output.join("native-package-owner.json"),
            &serde_json::json!({"format":"memcordon.consumer-readiness.native-package-owner","revision":1,"source":value.payload.source,"distribution":value.payload.distribution,"cleanup_agent":value.agent,"cleanup_agent_sha256":value.agent_sha256,"cleanup_agent_device":value.held_agent.metadata()?.dev(),"cleanup_agent_inode":value.held_agent.metadata()?.ino(),"original_installation_absent":true,"legacy":value.legacy}),
        )?;
        Ok(value)
    }

    fn verify_agent(&self) -> Result<()> {
        let held = self.held_agent.metadata()?;
        let named = fs::symlink_metadata(&self.agent)?;
        if !named.is_file()
            || named.uid() != 0
            || named.mode() & 0o7777 != 0o555
            || named.nlink() != 1
            || (held.dev(), held.ino()) != (named.dev(), named.ino())
            || artifacts::checksum(
                &crate::linux_consumer_readiness::measured(&self.agent, 512 * 1024 * 1024)
                    .map_err(CiError::Message)?,
            ) != self.agent_sha256
        {
            return Err(CiError::Message(
                "original cleanup agent native named identity differs".into(),
            ));
        }
        Ok(())
    }

    /// Called only after this owner has been retained by the outer native job.
    #[expect(
        clippy::too_many_arguments,
        reason = "Installation binds exact source, product, admin, artifact and finite owner custody"
    )]
    pub fn install_and_prepare(
        &mut self,
        workspace: &Path,
        identity: &SourceIdentity,
        cell: &ProductKey,
        admin: &Path,
        artifact_root: &Path,
        work: Instant,
        cleanup: Instant,
        work_unix: u64,
        cleanup_unix: u64,
    ) -> Result<ActivatedMixedPolicy> {
        if self.install_issued || work >= cleanup {
            return Err(CiError::Message(
                "native package setup cannot start another lifetime".into(),
            ));
        }
        self.verify_agent()?;
        let payload = &self.payload;
        // Installation snapshots current_exe and its complete selected sibling
        // graph. The independent cleanup copy intentionally has no such graph.
        let _source_ancestry =
            super::linux_native_component::protected_directory(&payload.directory)?;
        let source_agent = binary_path(
            &payload.directory,
            "memcordon-sealed-agent",
            &payload.distribution.target,
        );
        let source_image = super::native_executable::pin_install_image(&source_agent)?;
        let held = source_image.metadata()?;
        let named = fs::symlink_metadata(&source_agent)?;
        if (held.dev(), held.ino()) != (named.dev(), named.ino())
            || artifacts::checksum(
                &crate::linux_consumer_readiness::measured(&source_agent, 512 * 1024 * 1024)
                    .map_err(CiError::Message)?,
            ) != self.agent_sha256
        {
            return Err(CiError::Message(
                "native install source agent identity differs".into(),
            ));
        }
        super::source::write_json(
            &self.output.join("native-package-install-intent.json"),
            &serde_json::json!({"source":identity,"cell":cell,"cleanup_agent_sha256":self.agent_sha256,"uninstall_required":true}),
        )?;
        self.install_issued = true;
        let observed = CommandSpec::new(&source_agent, workspace, Duration::from_secs(300))
            .args(["package", "install"])
            .bounded_until(work)
            .output_quiet()?;
        drop(source_image);
        let success = observed.status.success();
        super::source::write_json(
            &self.output.join("native-package-install.json"),
            &serde_json::json!({"status":observed.status.code(),"stdout":observed.stdout,"stderr":observed.stderr}),
        )?;
        if !success {
            return Err(CiError::Message(
                super::native_package_diagnostics::install_failure(
                    observed.status.code(),
                    &observed.stdout,
                    &observed.stderr,
                ),
            ));
        }
        for binary in &payload.distribution.binaries {
            let selected = crate::linux_consumer_readiness::measured(
                &binary_path(&payload.directory, binary, &payload.distribution.target),
                512 * 1024 * 1024,
            )
            .map_err(CiError::Message)?;
            if crate::linux_consumer_readiness::measured(
                &Path::new("/usr/libexec").join(binary),
                512 * 1024 * 1024,
            )
            .map_err(CiError::Message)?
                != selected
            {
                return Err(CiError::Message(
                    "native component installed binary differs from selected bytes".into(),
                ));
            }
        }
        let expected = super::installed_consumer::measured_manifest(
            &payload.source,
            &payload.distribution,
            &payload.directory,
        )?;
        let bytes = crate::linux_consumer_readiness::measured(
            Path::new("/usr/libexec/memcordon-runtime-manifest.json"),
            4 * 1024 * 1024,
        )
        .map_err(CiError::Message)?;
        if memcordon_core::runtime_manifest::RuntimeManifest::parse(&bytes)
            .map_err(CiError::Message)?
            != expected
        {
            return Err(CiError::Message(
                "native component installed provider differs".into(),
            ));
        }
        let provider = expected.public_binding(&bytes).map_err(CiError::Message)?;
        super::source::write_json(
            &self.output.join("native-resource-setup-intent.json"),
            &serde_json::json!({"source":identity,"cell":cell,"resource_setup_required":true}),
        )?;
        let resources = self.output.join("resources");
        fs::create_dir(&resources)?;
        self.driver
            .prepare_native_component_fixture(InstalledMixedDriverInput {
                payload,
                provider: &provider,
                legacy: self.legacy.clone(),
                workspace,
                output: &resources,
                artifact_root,
                admin_root: admin,
                identity: identity.clone(),
                lease_id: format!("{}-original-native-component", identity.run_id),
                cell: cell.clone(),
                deadline: work,
                cleanup_deadline: cleanup,
                work_deadline_unix_millis: work_unix,
                cleanup_deadline_unix_millis: cleanup_unix,
            })
    }

    /// Native recovery/resources precede one final uninstall. Failed facts are
    /// retained even when later readback observes that native owners settled.
    pub fn finalize(&mut self, workspace: &Path, cleanup: Instant) -> Result<()> {
        let mut current = Vec::new();
        for process in &self.recovery_processes {
            match process.exited() {
                Ok(true) => {}
                Ok(false) => {
                    current.push("actual native recovery process remains held live".into())
                }
                Err(error) => current.push(format!(
                    "native recovery process retirement uncertainty: {error}"
                )),
            }
        }
        if let Err(error) = self.driver.finalize_owned_attempts(cleanup) {
            current.push(error.to_string());
        }
        if let Err(error) = self.verify_agent() {
            current.push(error.to_string());
        }
        let payload = &self.payload;
        if self.install_issued {
            // Owned attempts and resources settle here. The accepted package
            // uninstall performs locked journal/native recovery and refuses live
            // or ambiguous attempts before removal; the public recover route is
            // retired and cannot authorize this cleanup.
            if current.is_empty() && !self.resources_retired {
                let resource_stage = (|| -> Result<()> {
                    match fs::symlink_metadata(self.output.join("resources")) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            if self
                                .output
                                .join("native-resource-setup-intent.json")
                                .try_exists()?
                            {
                                current.push(
                                    "started native resource setup lost its custody records".into(),
                                );
                            } else {
                                self.resources_retired = true;
                            }
                        }
                        Err(error) => return Err(error.into()),
                        Ok(_) => match self.driver.finalize_owned_resources(
                            workspace,
                            &self.output.join("resources"),
                            &self.legacy,
                            cleanup,
                        ) {
                            Ok(()) => self.resources_retired = true,
                            Err(error) => current.push(error.to_string()),
                        },
                    }
                    Ok(())
                })();
                if let Err(error) = resource_stage {
                    current.push(error.to_string());
                }
            }
            if current.is_empty() && !self.uninstall_issued {
                let uninstall = (|| -> Result<()> {
                    super::source::write_json(
                        &self.output.join("native-package-uninstall-intent.json"),
                        &serde_json::json!({"cleanup_agent_sha256":self.agent_sha256,"owned_attempts_and_resources_settled":true}),
                    )?;
                    self.uninstall_issued = true;
                    let observed =
                        CommandSpec::new(&self.agent, workspace, Duration::from_secs(300))
                            .args(["package", "uninstall"])
                            .bounded_until(cleanup)
                            .output_quiet()?;
                    self.uninstall_succeeded = observed.status.success();
                    super::source::write_json(
                        &self.output.join("native-package-uninstall.json"),
                        &serde_json::json!({"status":observed.status.code(),"stdout":observed.stdout,"stderr":observed.stderr}),
                    )?;
                    Ok(())
                })();
                if let Err(error) = uninstall {
                    current.push(error.to_string());
                }
            }
            {
                let observation = (|| -> Result<()> {
                    if !self.uninstall_succeeded {
                        current.push(
                            "original native package uninstall lacks actual successful capture"
                                .into(),
                        );
                    }
                    let mut remaining = Vec::new();
                    for binary in &payload.distribution.binaries {
                        let path = Path::new("/usr/libexec").join(binary);
                        match fs::symlink_metadata(&path) {
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => current.push(format!("{}: {error}", path.display())),
                            Ok(_) => remaining.push(path),
                        }
                    }
                    for path in [
                        "/usr/libexec/memcordon-runtime-manifest.json",
                        "/usr/libexec/memcordon-arm32-abi-helper",
                        "/usr/lib/tmpfiles.d/memcordon.conf",
                        "/run/memcordon",
                        "/var/lib/memcordon/sealed",
                        "/sys/fs/cgroup/memcordon-sealed",
                    ] {
                        match fs::symlink_metadata(path) {
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => current.push(format!("{path}: {error}")),
                            Ok(_) => remaining.push(PathBuf::from(path)),
                        }
                    }
                    let mut units = Vec::new();
                    for unit in &payload.distribution.units {
                        let path = Path::new("/usr/lib/systemd/system").join(unit);
                        match fs::symlink_metadata(&path) {
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => current.push(format!("{}: {error}", path.display())),
                            Ok(_) => remaining.push(path),
                        }
                        let observed = match CommandSpec::new(
                            "/usr/bin/systemctl",
                            workspace,
                            Duration::from_secs(30),
                        )
                        .args([
                            "show",
                            unit.as_str(),
                            "--property=ActiveState",
                            "--property=MainPID",
                        ])
                        .bounded_until(cleanup)
                        .output_quiet()
                        {
                            Ok(value) => value,
                            Err(error) => {
                                current.push(format!("{unit}: {error}"));
                                continue;
                            }
                        };
                        let text = match std::str::from_utf8(&observed.stdout) {
                            Ok(value) => value,
                            Err(error) => {
                                current.push(format!("{unit}: {error}"));
                                continue;
                            }
                        };
                        if !observed.status.success()
                            || !text.lines().any(|line| line == "ActiveState=inactive")
                            || !text.lines().any(|line| line == "MainPID=0")
                        {
                            current
                                .push(format!("original native unit remains unresolved: {unit}"));
                        }
                        units.push(serde_json::json!({"unit":unit,"status":observed.status.code(),"stdout":observed.stdout,"stderr":observed.stderr}));
                    }
                    if !remaining.is_empty() {
                        current.push("original native selected package paths remain".into());
                    }
                    super::source::write_json(
                        &self.output.join("native-package-removal.json"),
                        &serde_json::json!({"uninstall_succeeded":self.uninstall_succeeded,"remaining_paths":remaining,"units":units,"failures":current}),
                    )?;
                    self.native_settled = current.is_empty();
                    Ok(())
                })();
                if let Err(error) = observation {
                    self.native_settled = false;
                    current.push(error.to_string());
                }
            }
        } else {
            self.native_settled = true;
        }
        self.failures.extend(current);
        if self.failures.is_empty() {
            Ok(())
        } else {
            Err(CiError::Message(self.failures.join("; ")))
        }
    }
    pub fn native_settled(&self) -> bool {
        self.native_settled
    }
}
