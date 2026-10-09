//! Installed lifecycle interventions retain native ownership before acting.
//! These receipts do not manufacture a terminal carrier for a dead frontend.
use crate::linux_consumer_readiness::HeldLinuxProcess;
use crate::{CiError, Result};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::Instant;

/// The duplicate refers to the actual selected worker socket. Closing this
/// local descriptor alone cannot simulate control loss; shutdown acts on the
/// native connection shared with that worker.
pub struct HeldControlConnection {
    socket: File,
    worker_pid: u32,
    worker_birth: u64,
    caller_pid: u32,
    caller_birth: u64,
    source_descriptor: i32,
    device: u64,
    inode: u64,
    peer_uid: u32,
    peer_gid: u32,
    caller_status: Vec<u8>,
}

impl HeldControlConnection {
    pub fn acquire(
        worker: &HeldLinuxProcess,
        caller: &HeldLinuxProcess,
        caller_uid: u32,
        caller_gid: u32,
        deadline: Instant,
    ) -> Result<Self> {
        require_live(worker, caller, deadline)?;
        if caller_uid == 0 || caller_gid == 0 {
            return Err(CiError::Message(
                "lifecycle control caller must be the actual unprivileged owner".into(),
            ));
        }
        use std::io::Read;
        let mut caller_status = Vec::new();
        File::open(format!("/proc/{}/status", caller.process_id))?
            .take(65537)
            .read_to_end(&mut caller_status)?;
        if caller_status.len() > 65536 {
            return Err(CiError::Message(
                "native caller status exceeds bound".into(),
            ));
        }
        let status = std::str::from_utf8(&caller_status)
            .map_err(|error| CiError::Message(error.to_string()))?;
        for (field, expected) in [("Uid:", caller_uid), ("Gid:", caller_gid)] {
            let fields = status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .ok_or_else(|| CiError::Message("native caller credentials absent".into()))?
                .split_whitespace()
                .map(str::parse::<u32>)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|error| CiError::Message(error.to_string()))?;
            if fields != vec![expected; 4] {
                return Err(CiError::Message(
                    "native control caller credentials differ from original launch".into(),
                ));
            }
        }
        let pidfd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(worker.process_id as i32)
                .ok_or_else(|| CiError::Message("control worker PID differs".into()))?,
            rustix::process::PidfdFlags::empty(),
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let mut selected = None;
        let entries = std::fs::read_dir(format!("/proc/{}/fd", worker.process_id))?;
        let mut count = 0usize;
        for entry in entries {
            require_live(worker, caller, deadline)?;
            count += 1;
            if count > 4096 {
                return Err(CiError::Message(
                    "selected native worker descriptor census exceeds bound".into(),
                ));
            }
            let entry = entry?;
            let Some(descriptor) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            let link = std::fs::read_link(entry.path())?;
            if !link.as_os_str().as_encoded_bytes().starts_with(b"socket:[") {
                continue;
            }
            let socket = File::from(
                rustix::process::pidfd_getfd(
                    &pidfd,
                    descriptor as _,
                    rustix::process::PidfdGetfdFlags::empty(),
                )
                .map_err(|error| CiError::Message(error.to_string()))?,
            );
            let socket_type = rustix::net::sockopt::socket_type(&socket)
                .map_err(|error| CiError::Message(error.to_string()))?;
            if socket_type != rustix::net::SocketType::STREAM {
                continue;
            }
            if rustix::net::getsockname(&socket)
                .map_err(|error| CiError::Message(error.to_string()))?
                .address_family()
                != rustix::net::AddressFamily::UNIX
            {
                continue;
            }
            let peer = rustix::net::sockopt::socket_peercred(&socket)
                .map_err(|error| CiError::Message(error.to_string()))?;
            if peer.pid.as_raw_nonzero().get() != caller.process_id as i32
                || peer.uid.as_raw() != caller_uid
                || peer.gid.as_raw() != caller_gid
            {
                continue;
            }
            let before = socket.metadata()?;
            let expected = format!("socket:[{}]", before.ino());
            if link != std::path::PathBuf::from(expected) || before.ino() == 0 {
                return Err(CiError::Message(
                    "duplicated control socket differs from held native worker descriptor".into(),
                ));
            }
            let owner = Self {
                socket,
                worker_pid: worker.process_id,
                worker_birth: worker.birth,
                caller_pid: caller.process_id,
                caller_birth: caller.birth,
                source_descriptor: descriptor,
                device: before.dev(),
                inode: before.ino(),
                peer_uid: peer.uid.as_raw(),
                peer_gid: peer.gid.as_raw(),
                caller_status: caller_status.clone(),
            };
            if selected.replace(owner).is_some() {
                return Err(CiError::Message(
                    "selected worker has multiple caller-associated control connections".into(),
                ));
            }
        }
        require_live(worker, caller, deadline)?;
        selected.ok_or_else(|| {
            CiError::Message("actual caller-associated native control connection absent".into())
        })
    }

    pub fn shutdown(
        &self,
        worker: &HeldLinuxProcess,
        caller: &HeldLinuxProcess,
        deadline: Instant,
    ) -> Result<serde_json::Value> {
        require_live(worker, caller, deadline)?;
        if (
            worker.process_id,
            worker.birth,
            caller.process_id,
            caller.birth,
        ) != (
            self.worker_pid,
            self.worker_birth,
            self.caller_pid,
            self.caller_birth,
        ) {
            return Err(CiError::Message(
                "control shutdown crosses original held worker/caller".into(),
            ));
        }
        let before = self.socket.metadata()?;
        let named = std::fs::read_link(format!(
            "/proc/{}/fd/{}",
            worker.process_id, self.source_descriptor
        ))?;
        if (before.dev(), before.ino()) != (self.device, self.inode)
            || named != std::path::PathBuf::from(format!("socket:[{}]", self.inode))
        {
            return Err(CiError::Message(
                "native control socket was replaced before shutdown".into(),
            ));
        }
        let observed = rustix::net::shutdown(&self.socket, rustix::net::Shutdown::Both);
        let status = if observed.is_ok() { 0 } else { -1 };
        let errno = observed.err().map(|error| error.raw_os_error());
        let after = self.socket.metadata()?;
        if (after.dev(), after.ino()) != (self.device, self.inode) {
            return Err(CiError::Message(
                "native control socket changed during shutdown".into(),
            ));
        }
        Ok(
            serde_json::json!({"format":"memcordon.linux-lifecycle-control-shutdown","revision":1,
            "worker":{"pid":self.worker_pid,"birth":self.worker_birth},"caller":{"pid":self.caller_pid,"birth":self.caller_birth},
            "source_descriptor":self.source_descriptor,"device":self.device,"inode":self.inode,
            "peer_uid":self.peer_uid,"peer_gid":self.peer_gid,"socket_type":libc::SOCK_STREAM,
            "socket_domain":libc::AF_UNIX,"caller_status_bytes":self.caller_status,
            "native_how":libc::SHUT_RDWR,"native_status":status,"native_errno":errno}),
        )
    }
}

fn require_live(
    worker: &HeldLinuxProcess,
    caller: &HeldLinuxProcess,
    deadline: Instant,
) -> Result<()> {
    if Instant::now() >= deadline
        || worker.exited().map_err(CiError::Message)?
        || caller.exited().map_err(CiError::Message)?
        || crate::linux_consumer_readiness::process_birth(worker.process_id)
            .map_err(CiError::Message)?
            != worker.birth
        || crate::linux_consumer_readiness::process_birth(caller.process_id)
            .map_err(CiError::Message)?
            != caller.birth
    {
        return Err(CiError::Message(
            "original lifecycle control owners/cutoff are no longer live".into(),
        ));
    }
    Ok(())
}

#[derive(Default)]
pub struct LifecycleReport {
    original_work_deadline: Option<Instant>,
    original_cleanup_deadline: Option<Instant>,
    pub native: super::linux_readiness_limits_cases::LimitsReport,
    workers: Vec<HeldLinuxProcess>,
    actor_owners: Vec<HeldLinuxProcess>,
    controls: Vec<HeldControlConnection>,
    files: Vec<File>,
    directories: Vec<File>,
    pub observations: Vec<serde_json::Value>,
    pub completed: Vec<(memcordon_readiness_verifier::CaseKey, std::path::PathBuf)>,
    pub records: Vec<memcordon_readiness_verifier::CaseRecord>,
    pub artifacts: Vec<memcordon_readiness_verifier::Artifact>,
}

impl LifecycleReport {
    pub fn native_owners_settled(&self) -> bool {
        self.native.native_owners_settled()
            && self.workers.is_empty()
            && self.actor_owners.is_empty()
            && self.controls.is_empty()
            && self.files.is_empty()
            && self.directories.is_empty()
    }
}

pub fn finalize_report(report: &mut LifecycleReport, deadline: Instant) -> Result<()> {
    if report
        .original_cleanup_deadline
        .is_some_and(|original| original != deadline)
    {
        return Err(CiError::Message(
            "lifecycle finalization changed original cleanup cutoff".into(),
        ));
    }
    super::linux_readiness_limits_cases::finalize_report(&mut report.native, deadline)?;
    for worker in report.workers.iter().chain(&report.actor_owners) {
        while !worker.exited().map_err(CiError::Message)? {
            if Instant::now() >= deadline {
                return Err(CiError::Message(
                    "original lifecycle cleanup cutoff exhausted; native worker retained".into(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    report.controls.clear();
    report.workers.clear();
    report.actor_owners.clear();
    report.files.clear();
    report.directories.clear();
    Ok(())
}

/// Retain the Child, capture threads and native family before crossing the
/// first controller boundary. Failure leaves every acquired owner in report.
pub fn begin_case(
    report: &mut LifecycleReport,
    context: &super::linux_readiness_limits_cases::LimitsContext<'_>,
    key: &memcordon_readiness_verifier::CaseKey,
    directory: &std::path::Path,
    prefix: &str,
    challenge: &str,
) -> Result<usize> {
    use super::linux_mixed_installed::{
        InstalledMixedLaunch, InstalledMixedLaunchInput, OwnedMixedRecipe,
    };
    let delivery = key.family == "L-LIFE-05" && key.scenario == "report-persistence-failure";
    if (!delivery && key.family != "L-LIFE-02")
        || key.target != context.cell.target
        || key.channel.as_deref() != Some(context.cell.channel.as_str())
        || key.evidence_class != memcordon_readiness_verifier::EvidenceClass::InstalledProduct
        || context.work_deadline >= context.cleanup_deadline
        || Instant::now() >= context.work_deadline
    {
        return Err(CiError::Message(
            "lifecycle original installed owner/cutoff differs".into(),
        ));
    }
    if !report.native.owners.is_empty() || !report.completed.is_empty() {
        return Err(CiError::Message(
            "one lifecycle report cannot replace its original native attempt".into(),
        ));
    }
    if !directory.is_absolute()
        || !context.artifact_root.is_absolute()
        || context.lease_id.is_empty()
        || prefix
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || prefix.contains(['\\', ':'])
    {
        return Err(CiError::Message(
            "lifecycle original artifact namespace differs".into(),
        ));
    }
    let (actor, phase) = if delivery {
        ("delivery", "completion")
    } else {
        key.scenario
            .split_once('-')
            .ok_or_else(|| CiError::Message("lifecycle finite selector absent".into()))?
    };
    if !delivery
        && (!["frontend", "worker", "guardian", "control"].contains(&actor)
            || !["allocation", "release", "drain"].contains(&phase))
    {
        return Err(CiError::Message("lifecycle finite selector differs".into()));
    }
    if report
        .original_work_deadline
        .is_some_and(|original| original != context.work_deadline)
        || report
            .original_cleanup_deadline
            .is_some_and(|original| original != context.cleanup_deadline)
    {
        return Err(CiError::Message(
            "lifecycle report changed original work/cleanup cutoff".into(),
        ));
    }
    report.original_work_deadline = Some(context.work_deadline);
    report.original_cleanup_deadline = Some(context.cleanup_deadline);
    if context.work_deadline_unix_millis == 0
        || context.cleanup_deadline_unix_millis <= context.work_deadline_unix_millis
    {
        return Err(CiError::Message(
            "lifecycle original wall cutoffs are absent".into(),
        ));
    }
    let challenge_bytes =
        hex::decode(challenge).map_err(|error| CiError::Message(error.to_string()))?;
    if challenge_bytes.len() != 32 || challenge_bytes.iter().all(|byte| *byte == 0) {
        return Err(CiError::Message(
            "actual lifecycle fixture challenge differs".into(),
        ));
    }
    std::fs::create_dir_all(context.artifact_root.join(prefix))?;
    retain_bytes(
        &context.artifact_root.join(prefix).join("challenge.bin"),
        &challenge_bytes,
        &mut report.files,
    )?;
    let mut args = vec![
        std::ffi::OsString::from(if delivery {
            "bytes-argv-status"
        } else if phase == "drain" {
            "root-first"
        } else {
            "held-tree"
        }),
        std::ffi::OsString::from(challenge),
    ];
    if delivery {
        args.push("0".into());
    }
    let launch = InstalledMixedLaunch::start_with_delivery_controls(
        InstalledMixedLaunchInput {
            directory,
            contract: context.contract_path,
            caller_uid: 65534,
            caller_gid: 65534,
            target_arguments: &args,
            deadline: std::ffi::OsStr::new("+300s"),
            memory: std::ffi::OsStr::new("+512M"),
        },
        delivery,
        None,
    )?;
    let index = report.native.owners.len();
    report.native.owners.push(OwnedMixedRecipe {
        key: key.clone(),
        launch,
        observer: None,
        held: Vec::new(),
        transcript: Vec::new(),
        prepared_native_receipt: None,
        host_tcp_canary: None,
        host_abstract_canary: None,
        host_path_canary: None,
    });
    let observer = report.native.owners[index].launch.acquire_prepared(
        context.provider,
        context.contract,
        context.artifact_root,
        &format!("{prefix}/prepared.json"),
        context
            .work_deadline
            .saturating_duration_since(Instant::now()),
    )?;
    report.native.owners[index].observer = Some(observer);
    let owner = &mut report.native.owners[index];
    let observer = owner
        .observer
        .as_ref()
        .expect("retained original native prepared observer");
    owner.prepared_native_receipt = Some(
        observer
            .persist_native_receipt(
                &context.identity.run_id,
                context.artifact_root,
                &format!("{prefix}/prepared-native-before-ack.json"),
            )
            .map_err(CiError::Message)?,
    );
    let invocation = owner.launch.retained_frontend_invocation()?;
    retain_bytes(
        &context
            .artifact_root
            .join(prefix)
            .join("frontend-invocation.json"),
        &invocation,
        &mut report.files,
    )?;
    let preinput = serde_json::json!({"format":"memcordon.linux-lifecycle-frontend-preinput","revision":1,
        "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"key":key,
        "process":observer.caller.retirement_identity().map_err(CiError::Message)?,"held_at_prepared_barrier":true,
        "invocation_sha256":super::artifacts::checksum(&invocation),"work_deadline_unix_millis":context.work_deadline_unix_millis,
        "cleanup_deadline_unix_millis":context.cleanup_deadline_unix_millis});
    retain_bytes(
        &context
            .artifact_root
            .join(prefix)
            .join("frontend-preinput.json"),
        &serde_json::to_vec(&preinput)?,
        &mut report.files,
    )?;
    let worker_source = super::linux_readiness_image_cases::retain_prepared_worker(
        observer,
        context.selected_agent_sha256,
        context.work_deadline,
        &mut report.directories,
        &mut report.files,
        &mut report.workers,
    )?;
    let worker_index = report.workers.len() - 1;
    if actor == "control" {
        report.controls.push(HeldControlConnection::acquire(
            &report.workers[worker_index],
            &observer.caller,
            65534,
            65534,
            context.work_deadline,
        )?);
    }
    let (journal, record) = retain_phase_journal(
        observer.observation.admission.attempt_id.as_str(),
        context.work_deadline,
        &mut report.files,
    )?;
    retain_bytes(
        &context
            .artifact_root
            .join(prefix)
            .join("allocation-phase-journal.bin"),
        &journal,
        &mut report.files,
    )?;
    report.observations.push(serde_json::json!({"format":"memcordon.linux-lifecycle-allocation","revision":1,
        "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"key":key,
        "attempt_id":observer.observation.admission.attempt_id,"worker_index":worker_index,"worker_source":worker_source,
        "phase":record["phase"],"release_knowledge":record["release_knowledge"],
        "journal_sha256":super::artifacts::checksum(&journal),"prepared":observer.observation,
        "frontend_invocation":serde_json::from_slice::<serde_json::Value>(&owner.launch.retained_frontend_invocation()?)?}));
    Ok(index)
}

fn retain_bytes(path: &std::path::Path, bytes: &[u8], owners: &mut Vec<File>) -> Result<()> {
    use std::io::Write;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    owners.push(file.try_clone()?);
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| CiError::Message("lifecycle retained artifact parent absent".into()))?,
    )?
    .sync_all()?;
    Ok(())
}

pub fn intervene(
    report: &mut LifecycleReport,
    context: &super::linux_readiness_limits_cases::LimitsContext<'_>,
    index: usize,
    directory: &std::path::Path,
) -> Result<()> {
    let owner = report
        .native
        .owners
        .get(index)
        .ok_or_else(|| CiError::Message("original lifecycle launch owner absent".into()))?;
    let (actor, phase) = owner
        .key
        .scenario
        .split_once('-')
        .ok_or_else(|| CiError::Message("actual lifecycle selector absent".into()))?;
    let observer = owner
        .observer
        .as_ref()
        .ok_or_else(|| CiError::Message("original lifecycle observer absent".into()))?;
    let worker_index = report
        .observations
        .iter()
        .find(|observation| {
            observation["key"]
                == serde_json::to_value(&owner.key).unwrap_or(serde_json::Value::Null)
        })
        .and_then(|observation| observation["worker_index"].as_u64())
        .ok_or_else(|| CiError::Message("original lifecycle worker association absent".into()))?
        as usize;
    let worker = report
        .workers
        .get(worker_index)
        .ok_or_else(|| CiError::Message("original lifecycle native worker owner absent".into()))?;
    let (journal, record) = retain_phase_journal(
        observer.observation.admission.attempt_id.as_str(),
        context.work_deadline,
        &mut report.files,
    )?;
    let mut barrier = None;
    match phase {
        "allocation"
            if record["phase"] == "checkpoint-committed"
                && record["release_knowledge"] == "not-released" => {}
        "release"
            if record["phase"] == "checkpoint-committed"
                && record["release_knowledge"] == "not-released" =>
        {
            let path = owner
                .launch
                .observation_directory
                .join(observer.observation.admission.attempt_id.as_str())
                .with_extension("release-prepared.json");
            let bytes = read_caller_observation(&path, context.work_deadline, &mut report.files)?;
            memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
                .map_err(CiError::Message)?;
            let observed: memcordon_core::mixed_observation::MixedReleaseObservationV2 =
                serde_json::from_slice(&bytes)?;
            observed.validate().map_err(CiError::Message)?;
            if observed.prepared != observer.observation || observed.authorizes_launch {
                return Err(CiError::Message(
                    "actual final release barrier crossed original prepared owner".into(),
                ));
            }
            retain_bytes(
                &directory.join("release-prepared.json"),
                &bytes,
                &mut report.files,
            )?;
            barrier = Some(serde_json::to_value(observed)?);
        }
        "drain"
            if record["phase"] == "retiring"
                && record["release_knowledge"] == "exec-observed"
                && observer.target.exited().map_err(CiError::Message)? => {}
        _ => {
            return Err(CiError::Message(
                "actual native lifecycle phase has not reached selected intervention barrier"
                    .into(),
            ));
        }
    }
    if record["frontend"]["pid"] != observer.caller.process_id
        || record["frontend"]["start_time"] != observer.caller.birth
        || record["mixed_worker"]["pid"] != worker.process_id
        || record["mixed_worker"]["start_time"] != worker.birth
        || record["guardian"]["pid"] != observer.guardian.process_id
        || record["guardian"]["start_time"] != observer.guardian.birth
    {
        return Err(CiError::Message(
            "current lifecycle journal replaces original held actors".into(),
        ));
    }
    retain_bytes(
        &directory.join("phase-journal.bin"),
        &journal,
        &mut report.files,
    )?;
    let target = match actor {
        "frontend" => &observer.caller,
        "worker" | "control" => worker,
        "guardian" => &observer.guardian,
        _ => return Err(CiError::Message("unknown lifecycle native actor".into())),
    };
    let identity = target.retirement_identity().map_err(CiError::Message)?;
    report.actor_owners.push(
        HeldLinuxProcess::acquire(target.process_id, target.birth).map_err(CiError::Message)?,
    );
    let image = report
        .actor_owners
        .last_mut()
        .expect("retained selected actor image owner")
        .hold_executable_image(context.work_deadline)
        .map_err(CiError::Message)?;
    let selected_image = if actor == "frontend" {
        context.selected_cli_sha256
    } else {
        context.selected_agent_sha256
    };
    if image["sha256"] != selected_image || target.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "actual lifecycle actor image differs from selected installed owner".into(),
        ));
    }
    let intent = serde_json::json!({"format":"memcordon.linux-lifecycle-controller-intent","revision":1,
        "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"key":owner.key,
        "attempt_id":observer.observation.admission.attempt_id,"actor":identity,"phase":record["phase"],
        "release_knowledge":record["release_knowledge"],"journal_sha256":super::artifacts::checksum(&journal),
        "release_barrier":barrier,"native_image":image,"selected_image_sha256":selected_image,
        "native_operation":if actor=="control"{"socket-shutdown"}else{"pidfd-sigkill"}});
    retain_bytes(
        &directory.join("controller-intent.json"),
        &serde_json::to_vec(&intent)?,
        &mut report.files,
    )?;
    let action = if actor == "control" {
        let connection = report
            .controls
            .iter()
            .find(|connection| {
                connection.worker_pid == worker.process_id
                    && connection.worker_birth == worker.birth
            })
            .ok_or_else(|| {
                CiError::Message("original lifecycle control connection absent".into())
            })?;
        connection.shutdown(worker, &observer.caller, context.work_deadline)?
    } else {
        let native = target.signal_kill().map_err(CiError::Message)?;
        serde_json::json!({"format":"memcordon.linux-lifecycle-pidfd-kill","revision":1,"actor":identity,
            "signal":9,"native_status":if native.is_ok(){0}else{-1},"native_errno":native.err()})
    };
    retain_bytes(
        &directory.join("controller-action.json"),
        &serde_json::to_vec(&action)?,
        &mut report.files,
    )?;
    report.observations.push(
        serde_json::json!({"format":"memcordon.linux-lifecycle-intervention","revision":1,
        "key":owner.key,"intent":intent,"action":action}),
    );
    if action["native_status"] != 0 {
        return Err(CiError::Message(
            "actual lifecycle intervention native syscall failed; owners retained".into(),
        ));
    }
    Ok(())
}

fn read_caller_observation(
    path: &std::path::Path,
    deadline: Instant,
    owners: &mut Vec<File>,
) -> Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    if Instant::now() >= deadline {
        return Err(CiError::Message(
            "original native observation cutoff exhausted".into(),
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    owners.push(file.try_clone()?);
    if !before.is_file()
        || before.uid() != 65534
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() > 4 * 1024 * 1024
    {
        return Err(CiError::Message(
            "actual caller observation file custody differs".into(),
        ));
    }
    let mut bytes = vec![0; before.len() as usize];
    file.read_exact_at(&mut bytes, 0)?;
    let named = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let actual = named.metadata()?;
    let after = file.metadata()?;
    let stamp = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.nlink(),
            metadata.uid(),
            metadata.mode(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    let mut named_bytes = vec![0; bytes.len()];
    named.read_exact_at(&mut named_bytes, 0)?;
    if stamp(&before) != stamp(&after)
        || stamp(&after) != stamp(&actual)
        || bytes != named_bytes
        || Instant::now() >= deadline
    {
        return Err(CiError::Message(
            "actual caller observation was replaced during custody capture".into(),
        ));
    }
    Ok(bytes)
}

pub fn run_case(
    report: &mut LifecycleReport,
    context: &super::linux_readiness_limits_cases::LimitsContext<'_>,
    account: &super::linux_mixed_installed::ExclusiveAccount,
    key: memcordon_readiness_verifier::CaseKey,
    directory: &std::path::Path,
    prefix: &str,
    challenge: &str,
) -> Result<()> {
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    let root = context.artifact_root.join(prefix);
    let index = begin_case(report, context, &key, directory, prefix, challenge)?;
    let delivery = key.family == "L-LIFE-05";
    let phase = key
        .scenario
        .split_once('-')
        .expect("validated lifecycle selector")
        .1;
    if phase == "release" {
        let observations = report.native.owners[index]
            .launch
            .observation_directory
            .clone();
        let marker = observations.join("release-observer.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&marker)?;
        file.write_all(br#"{"format":"memcordon.mixed-release-observer","revision":2}"#)?;
        file.sync_all()?;
        rustix::fs::fchown(&file, Some(rustix::process::Uid::from_raw(65534)), None)
            .map_err(|error| CiError::Message(error.to_string()))?;
        report.files.push(file);
        let observer = report.native.owners[index]
            .observer
            .as_ref()
            .expect("retained native observer");
        observer
            .acknowledge(&observations)
            .map_err(CiError::Message)?;
        let path = observations
            .join(observer.observation.admission.attempt_id.as_str())
            .with_extension("release-prepared.json");
        loop {
            if Instant::now() >= context.work_deadline {
                return Err(CiError::Message(
                    "original final release barrier cutoff exhausted".into(),
                ));
            }
            match std::fs::symlink_metadata(&path) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            if observer.target.exited().map_err(CiError::Message)?
                || observer.guardian.exited().map_err(CiError::Message)?
            {
                return Err(CiError::Message(
                    "native release family exited before selected barrier".into(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    } else if phase == "drain" {
        let owner = &mut report.native.owners[index];
        let observer = owner.observer.as_ref().expect("retained native observer");
        observer
            .acknowledge(&owner.launch.observation_directory)
            .map_err(CiError::Message)?;
        loop {
            if Instant::now() >= context.work_deadline {
                return Err(CiError::Message(
                    "original drain fixture cutoff exhausted".into(),
                ));
            }
            if owner.launch.stdout.exists() {
                let bytes = super::linux_mixed_installed::read_owned_resource(
                    &owner.launch.stdout,
                    16 * 1024 * 1024,
                )?;
                if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
                    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes[..end])
                        .map_err(CiError::Message)?;
                    let row: crate::linux_consumer_readiness::LinuxTranscriptRow =
                        serde_json::from_slice(&bytes[..end])?;
                    if row.challenge != challenge
                        || row.sequence != 1
                        || row.operation != "root-exiting-before-held-descendant"
                    {
                        return Err(CiError::Message(
                            "actual drain held descendant transcript differs".into(),
                        ));
                    }
                    owner.launch.hold_fixture_tree_into(
                        observer,
                        &row.observation,
                        &mut owner.held,
                    )?;
                    owner.transcript.push(row);
                    owner.launch.release_fixture_barrier()?;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        loop {
            if Instant::now() >= context.work_deadline {
                return Err(CiError::Message(
                    "original native drain phase cutoff exhausted".into(),
                ));
            }
            let probe_owners = report.files.len();
            let (_, record) = retain_phase_journal(
                observer.observation.admission.attempt_id.as_str(),
                context.work_deadline,
                &mut report.files,
            )?;
            if record["phase"] == "retiring"
                && record["release_knowledge"] == "exec-observed"
                && observer.target.exited().map_err(CiError::Message)?
            {
                break;
            }
            // Unselected transient observations establish no receipt. Closing
            // those readonly probes cannot release a native cleanup owner.
            report.files.truncate(probe_owners);
            std::thread::yield_now();
        }
    }
    if delivery {
        let owner = &report.native.owners[index];
        owner
            .observer
            .as_ref()
            .expect("retained actual prepared observer")
            .acknowledge(&owner.launch.observation_directory)
            .map_err(CiError::Message)?;
        let destination = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&owner.launch.result)?;
        let metadata = destination.metadata()?;
        retain_bytes(
            &root.join("report-destination.json"),
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.linux-report-destination","revision":1,
            "path":owner.launch.result.as_os_str().as_encoded_bytes(),"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"gid":metadata.gid(),"mode":metadata.mode(),"is_directory":metadata.is_dir()}),
            )?,
            &mut report.files,
        )?;
        report.files.push(destination);
    } else {
        intervene(report, context, index, &root)?;
    }
    let owner = &mut report.native.owners[index];
    owner.launch.frontend.stdin.take();
    owner.launch.wait_and_capture(
        context
            .cleanup_deadline
            .saturating_duration_since(Instant::now()),
    )?;
    let wait = owner.launch.retained_frontend_wait()?;
    for (name, path) in [
        ("stdout.bin", &owner.launch.stdout),
        ("stderr.bin", &owner.launch.stderr),
    ] {
        retain_bytes(
            &root.join(name),
            &super::linux_mixed_installed::read_owned_resource(path, 16 * 1024 * 1024)?,
            &mut report.files,
        )?;
    }
    retain_bytes(
        &root.join("frontend-wait.json"),
        &serde_json::to_vec(&wait)?,
        &mut report.files,
    )?;
    let request_path = owner
        .launch
        .observation_directory
        .join(
            owner
                .observer
                .as_ref()
                .expect("retained native observer")
                .observation
                .admission
                .attempt_id
                .as_str(),
        )
        .with_extension("provider-request.bin");
    let request =
        read_caller_observation(&request_path, context.cleanup_deadline, &mut report.files)?;
    retain_bytes(
        &root.join("provider-request.bin"),
        &request,
        &mut report.files,
    )?;
    if delivery {
        let terminal_path = owner
            .launch
            .observation_directory
            .join(
                owner
                    .observer
                    .as_ref()
                    .expect("retained actual observer")
                    .observation
                    .admission
                    .attempt_id
                    .as_str(),
            )
            .with_extension("provider-terminal.json");
        let terminal =
            read_caller_observation(&terminal_path, context.cleanup_deadline, &mut report.files)?;
        retain_bytes(
            &root.join("provider-terminal.json"),
            &terminal,
            &mut report.files,
        )?;
        let delivery_receipt = read_caller_observation(
            &owner
                .launch
                .observation_directory
                .join("report-delivery-failure.json"),
            context.cleanup_deadline,
            &mut report.files,
        )?;
        retain_bytes(
            &root.join("report-delivery-failure.json"),
            &delivery_receipt,
            &mut report.files,
        )?;
    }
    let raw_result = if delivery {
        None
    } else {
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&owner.launch.result)
        {
            Ok(file) => {
                use std::io::Read;
                let mut bytes = Vec::new();
                file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
                if bytes.len() > 16 * 1024 * 1024 {
                    return Err(CiError::Message(
                        "actual lifecycle result exceeds bound".into(),
                    ));
                }
                retain_bytes(&root.join("actual-result.json"), &bytes, &mut report.files)?;
                Some(bytes)
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
            Err(error) => return Err(error.into()),
        }
    };
    let original_carrier = if delivery {
        let receipt: serde_json::Value =
            serde_json::from_slice(&super::linux_mixed_installed::read_owned_resource(
                &root.join("report-delivery-failure.json"),
                32 * 1024 * 1024,
            )?)?;
        Some(serde_json::from_value::<Vec<u8>>(
            receipt["submitted_report"].clone(),
        )?)
    } else {
        raw_result.clone()
    };
    if let Some(bytes) = original_carrier {
        let carrier: memcordon_core::result_v2::ResultV2 = serde_json::from_slice(&bytes)?;
        if let memcordon_core::result_v2::MixedRuntimeOutcomeV2::Executed {
            admission,
            retirement,
            ..
        } = &carrier.runtime.outcome
        {
            let path = std::path::Path::new("/run/memcordon")
                .join(format!("private-export-{}", admission.attempt_id.as_str()))
                .join("export-receipt.json");
            let exported =
                super::linux_mixed_installed::read_protected_export(&path, 4 * 1024 * 1024)?;
            if super::artifacts::checksum(&exported)
                != String::from(retirement.export_receipt_sha256.clone())
                || admission
                    != &owner
                        .observer
                        .as_ref()
                        .expect("original prepared owner")
                        .observation
                        .admission
            {
                return Err(CiError::Message(
                    "actual lifecycle export receipt crosses original authorized carrier".into(),
                ));
            }
            retain_bytes(
                &root.join("export-receipt.json"),
                &exported,
                &mut report.files,
            )?;
            if !delivery && key.scenario.ends_with("-drain") {
                for (source, name) in [
                    ("work/orphan-descendant.bin", "export-orphan-descendant.bin"),
                    (
                        "work/orphan-completion.json",
                        "export-orphan-completion.json",
                    ),
                ] {
                    let bytes = super::linux_mixed_installed::read_protected_export(
                        &path
                            .parent()
                            .expect("actual export receipt parent")
                            .join(source),
                        4 * 1024 * 1024,
                    )?;
                    retain_bytes(&root.join(name), &bytes, &mut report.files)?;
                }
            }
        }
    }
    let invocation = serde_json::json!({"format":"memcordon.linux-lifecycle-native-recovery-invocation","revision":1,
        "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"key":key,
        "program":"/usr/libexec/memcordon-sealed-agent","arguments":["package","policy","recover","--json"],
        "cwd_native_bytes":root.as_os_str().as_encoded_bytes(),"timeout_millis":60000,
        "work_deadline_unix_millis":context.work_deadline_unix_millis,"cleanup_deadline_unix_millis":context.cleanup_deadline_unix_millis,
        "cleanup_deadline_scope":"original-installed-lease","cleared_environment":true,"selected_agent_sha256":context.selected_agent_sha256});
    let invocation_bytes = serde_json::to_vec(&invocation)?;
    retain_bytes(
        &root.join("native-recovery-invocation.json"),
        &invocation_bytes,
        &mut report.files,
    )?;
    let mut process = None;
    let recovery_owner_index = report.workers.len();
    let recovery = crate::command::CommandSpec::new(
        "/usr/libexec/memcordon-sealed-agent",
        &root,
        std::time::Duration::from_secs(60),
    )
    .args(["package", "policy", "recover", "--json"])
    .cleared_environment()
    .bounded_until(context.cleanup_deadline)
    .output_quiet_with_creation(|child| {
        let birth =
            crate::linux_consumer_readiness::process_birth(child.id()).map_err(CiError::Message)?;
        let mut held = HeldLinuxProcess::acquire(child.id(), birth).map_err(CiError::Message)?;
        let image = held
            .hold_executable_image(context.cleanup_deadline)
            .map_err(CiError::Message)?;
        if image["sha256"] != context.selected_agent_sha256 {
            return Err(CiError::Message(
                "actual native recovery agent image differs".into(),
            ));
        }
        let identity = held.retirement_identity().map_err(CiError::Message)?;
        report.workers.push(held);
        process = Some((identity, image));
        Ok(())
    })?;
    let (preinput, image) = process.ok_or_else(|| {
        CiError::Message("actual native recovery creation identity absent".into())
    })?;
    let recovery_owner = report
        .workers
        .get(recovery_owner_index)
        .ok_or_else(|| CiError::Message("actual native recovery wait owner absent".into()))?;
    if !recovery_owner.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "actual native recovery Child wait did not settle original PIDFD".into(),
        ));
    }
    let process = recovery_owner
        .retirement_identity()
        .map_err(CiError::Message)?;
    let process = serde_json::json!({"format":"memcordon.linux-lifecycle-native-recovery-process","revision":1,
        "preinput":preinput,"process":process,"native_image":image,"invocation_sha256":super::artifacts::checksum(&invocation_bytes),
        "raw_wait_status":recovery.status.into_raw(),"native_exit":recovery.status.code(),"signal":recovery.status.signal(),
        "stdout_sha256":super::artifacts::checksum(&recovery.stdout),"stderr_sha256":super::artifacts::checksum(&recovery.stderr)});
    retain_bytes(
        &root.join("native-recovery-process.json"),
        &serde_json::to_vec(&process)?,
        &mut report.files,
    )?;
    retain_bytes(
        &root.join("native-recovery-stdout.bin"),
        &recovery.stdout,
        &mut report.files,
    )?;
    retain_bytes(
        &root.join("native-recovery-stderr.bin"),
        &recovery.stderr,
        &mut report.files,
    )?;
    if !recovery.status.success() {
        return Err(CiError::Message(
            "actual native lifecycle recovery retains outstanding obligations".into(),
        ));
    }
    let owner = &report.native.owners[index];
    let observer = owner.observer.as_ref().expect("retained native observer");
    if !observer
        .native_family_retired(&owner.held)
        .map_err(CiError::Message)?
        || report
            .workers
            .iter()
            .any(|worker| !worker.exited().unwrap_or(false))
    {
        return Err(CiError::Message(
            "actual lifecycle native family/worker recovery remains unsettled".into(),
        ));
    }
    let original_worker = report
        .observations
        .iter()
        .find(|observation| {
            observation["key"] == serde_json::to_value(&key).unwrap_or(serde_json::Value::Null)
        })
        .and_then(|observation| observation["worker_index"].as_u64())
        .ok_or_else(|| {
            CiError::Message("original lifecycle worker source association absent".into())
        })? as usize;
    let mut descendants = Vec::new();
    for held in &owner.held {
        descendants.push(serde_json::json!({"identity":held.retirement_identity().map_err(CiError::Message)?,"namespace_pid":held.namespace_pid}));
    }
    let intent: serde_json::Value = if delivery {
        serde_json::json!({"actor":{"pid":observer.caller.process_id,"birth":observer.caller.birth}})
    } else {
        serde_json::from_slice(&std::fs::read(root.join("controller-intent.json"))?)?
    };
    let actor_pid = intent["actor"]["pid"]
        .as_u64()
        .ok_or_else(|| CiError::Message("original lifecycle actor PID absent".into()))?;
    let actor_birth = intent["actor"]["birth"]
        .as_u64()
        .ok_or_else(|| CiError::Message("original lifecycle actor birth absent".into()))?;
    let mut actors = report
        .actor_owners
        .iter()
        .filter(|actor| u64::from(actor.process_id) == actor_pid && actor.birth == actor_birth);
    let selected_actor = if delivery {
        &observer.caller
    } else {
        actors.next().ok_or_else(|| {
            CiError::Message("original lifecycle controller actor owner absent".into())
        })?
    };
    if actors.next().is_some() {
        return Err(CiError::Message(
            "original lifecycle controller actor owner is ambiguous".into(),
        ));
    }
    let settlement = serde_json::json!({"format":"memcordon.linux-lifecycle-native-family-retirement","revision":1,
        "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"key":key,
        "attempt_id":observer.observation.admission.attempt_id,
        "frontend":observer.caller.retirement_identity().map_err(CiError::Message)?,
        "target":observer.target.retirement_identity().map_err(CiError::Message)?,
        "namespace_init":observer.namespace_init.retirement_identity().map_err(CiError::Message)?,
        "guardian":observer.guardian.retirement_identity().map_err(CiError::Message)?,
        "worker":report.workers.get(original_worker).ok_or_else(||CiError::Message("original lifecycle selected worker owner absent".into()))?.retirement_identity().map_err(CiError::Message)?,
        "actor":selected_actor.retirement_identity().map_err(CiError::Message)?,
        "descendants":descendants,"transcript":owner.transcript});
    retain_bytes(
        &root.join("native-family-retirement.json"),
        &serde_json::to_vec(&settlement)?,
        &mut report.files,
    )?;
    super::linux_mixed_installed::persist_policy_refusal_census(
        account,
        context.provider,
        context.identity,
        context.cell,
        context.lease_id,
        &key.scenario,
        observer.observation.admission.attempt_id.as_str(),
        raw_result.as_deref().unwrap_or(&[]),
        &request,
        &root.join("recovered-ownership.json"),
        context.cleanup_deadline,
    )?;
    let evidence = root.join("lifecycle-loss-raw.json");
    retain_bytes(
        &evidence,
        &serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.linux-lifecycle-loss-raw","revision":1,
        "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"key":key,"observations":report.observations,
        "frontend_wait":wait,"result_present":raw_result.is_some(),"result_absence_errno":if raw_result.is_none()&&!delivery{Some(libc::ENOENT)}else{None},"report_destination_directory":delivery}),
        )?,
        &mut report.files,
    )?;
    report.completed.push((key, evidence));
    Ok(())
}

pub fn normalize_completed(
    report: &mut LifecycleReport,
    images: &super::linux_mixed_installed::MixedImages,
    input: &super::linux_mixed_installed::InstalledMixedDriverInput<'_>,
    actual_policy_directory: &std::path::Path,
) -> Result<()> {
    use memcordon_readiness_verifier::{
        Artifact, BehaviorArtifact, CaseRecord, CaseState, FixtureInput,
        LinuxLifecycleLossEvidence, NativeArguments,
    };
    for (key, raw_path) in &report.completed {
        if Instant::now() >= input.cleanup_deadline
            || key.target != input.cell.target
            || key.channel.as_deref() != Some(input.cell.channel.as_str())
        {
            return Err(CiError::Message(
                "lifecycle normalization changed original owner/cutoff".into(),
            ));
        }
        let directory = raw_path
            .parent()
            .ok_or_else(|| CiError::Message("lifecycle raw source parent absent".into()))?;
        let prefix = directory
            .strip_prefix(input.artifact_root)
            .map_err(|error| CiError::Message(error.to_string()))?
            .to_str()
            .ok_or_else(|| CiError::Message("lifecycle artifact namespace is not UTF8".into()))?;
        let mut added = Vec::new();
        let mut persist = |name: &str, bytes: &[u8]| -> Result<Artifact> {
            if Instant::now() >= input.cleanup_deadline {
                return Err(CiError::Message(
                    "original lifecycle normalization cutoff exhausted".into(),
                ));
            }
            let relative = format!("{prefix}/{name}");
            retain_bytes(
                &input.artifact_root.join(&relative),
                bytes,
                &mut report.files,
            )?;
            let artifact = Artifact {
                path: relative,
                length: bytes.len() as u64,
                sha256: super::artifacts::checksum(bytes),
            };
            added.push(artifact.clone());
            Ok(artifact)
        };
        let fixture = super::linux_mixed_installed::read_owned_resource(
            &images.runtime_source.join("bin/owned-readiness"),
            512 * 1024 * 1024,
        )?;
        if super::artifacts::checksum(&fixture) != images.fixture_sha256 {
            return Err(CiError::Message(
                "lifecycle selected original fixture image changed".into(),
            ));
        }
        let source = serde_json::to_vec(&serde_json::json!({
            "module":super::artifacts::read_file(&input.workspace.join("crates/memcordon-cli/src/bin/consumer_readiness_linux/mod.rs"))?,
            "entrypoint":super::artifacts::read_file(&input.workspace.join("crates/memcordon-cli/src/bin/memcordon-linux-readiness-fixture.rs"))?}))?;
        let fixture = persist("fixture.bin", &fixture)?;
        let source = persist("fixture-source.json", &source)?;
        let challenge = super::linux_mixed_installed::read_owned_resource(
            &directory.join("challenge.bin"),
            32,
        )?;
        if challenge.len() != 32 || challenge.iter().all(|byte| *byte == 0) {
            return Err(CiError::Message(
                "retained lifecycle original challenge changed".into(),
            ));
        }
        let invocation: serde_json::Value =
            serde_json::from_slice(&super::linux_mixed_installed::read_owned_resource(
                &directory.join("frontend-invocation.json"),
                65536,
            )?)?;
        let arguments: Vec<Vec<u8>> = serde_json::from_value(invocation["arguments"].clone())?;
        let marker = arguments
            .windows(3)
            .enumerate()
            .filter(|(_, values)| {
                values[0] == b"--image-entrypoint"
                    && values[1] == b"owned-readiness"
                    && values[2] == b"--"
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if marker.len() != 1 {
            return Err(CiError::Message(
                "actual lifecycle frontend entrypoint argument association differs".into(),
            ));
        }
        let target = arguments[marker[0] + 3..].to_vec();
        let delivery = key.family == "L-LIFE-05";
        let phase = key
            .scenario
            .split_once('-')
            .ok_or_else(|| CiError::Message("actual lifecycle finite selector absent".into()))?
            .1;
        let mut expected = vec![
            if delivery {
                b"bytes-argv-status".to_vec()
            } else if phase == "drain" {
                b"root-first".to_vec()
            } else {
                b"held-tree".to_vec()
            },
            hex::encode(&challenge).into_bytes(),
        ];
        if delivery {
            expected.push(b"0".to_vec());
        }
        if target != expected {
            return Err(CiError::Message(
                "actual lifecycle native target arguments changed".into(),
            ));
        }
        let descriptor = FixtureInput {
            format: "memcordon.consumer-readiness.input".into(),
            revision: 1,
            run_id: input.identity.run_id.clone(),
            key: key.clone(),
            challenge_sha256: super::artifacts::checksum(&challenge),
            binary: Vec::new(),
            target_argv: NativeArguments::UnixBytes(target),
            deadline_millis: Some(300_000),
            memory_bytes: Some(512 * 1024 * 1024),
            toolchain_identity: None,
        };
        let descriptor = persist("fixture-input.json", &serde_json::to_vec(&descriptor)?)?;
        let lease_path = input
            .output
            .parent()
            .ok_or_else(|| {
                CiError::Message("original installed lifecycle lease scope absent".into())
            })?
            .join("lease-owner.json");
        let lease_bytes =
            super::linux_mixed_installed::read_owned_resource(&lease_path, 32 * 1024 * 1024)?;
        let lease = persist("original-lease-owner.json", &lease_bytes)?;
        let original_lease = lease_path
            .strip_prefix(input.artifact_root)
            .map_err(|error| CiError::Message(error.to_string()))?
            .to_string_lossy()
            .into_owned();
        let acquisition = persist(
            "original-acquisition.json",
            &super::linux_mixed_installed::read_owned_resource(
                &input.output.join("owned-resources-acquired.json"),
                32 * 1024 * 1024,
            )?,
        )?;
        let activation = persist(
            "original-activation.json",
            &super::linux_mixed_installed::read_owned_resource(
                &actual_policy_directory.join("mixed.activation.json"),
                16 * 1024 * 1024,
            )?,
        )?;
        let contract = persist(
            "original-contract.json",
            &super::linux_mixed_installed::read_owned_resource(
                &actual_policy_directory.join("mixed.contract.json"),
                4 * 1024 * 1024,
            )?,
        )?;
        let manifest = persist(
            "selected-runtime-manifest.json",
            &super::linux_mixed_installed::read_owned_resource(
                std::path::Path::new("/usr/libexec/memcordon-runtime-manifest.json"),
                4 * 1024 * 1024,
            )?,
        )?;
        let cli = persist(
            "selected-cli-image.bin",
            &super::linux_mixed_installed::read_owned_resource(
                std::path::Path::new("/usr/libexec/memcordon"),
                512 * 1024 * 1024,
            )?,
        )?;
        let agent = persist(
            "selected-agent-image.bin",
            &super::linux_mixed_installed::read_owned_resource(
                std::path::Path::new("/usr/libexec/memcordon-sealed-agent"),
                512 * 1024 * 1024,
            )?,
        )?;
        let owner = persist(
            "lifecycle-owner.json",
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.linux-lifecycle-owner","revision":1,
            "identity":input.identity,"cell":input.cell,"lease_id":input.lease_id,"provider":input.provider,
            "lease_owner":lease.path,"acquisition":acquisition.path,"activation":activation.path,"contract":contract.path,
            "runtime_manifest":manifest.path,"selected_cli":cli.path,"selected_agent":agent.path,
            "work_deadline_unix_millis":input.work_deadline_unix_millis,"cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis}),
            )?,
        )?;
        let mut peers = Vec::new();
        for name in [
            "challenge.bin",
            "frontend-invocation.json",
            "frontend-preinput.json",
            "frontend-wait.json",
            "stdout.bin",
            "stderr.bin",
            "prepared.json",
            "prepared-native-before-ack.json",
            "allocation-phase-journal.bin",
            "phase-journal.bin",
            "controller-intent.json",
            "controller-action.json",
            "provider-request.bin",
            "native-family-retirement.json",
            "native-recovery-invocation.json",
            "native-recovery-process.json",
            "native-recovery-stdout.bin",
            "native-recovery-stderr.bin",
            "recovered-ownership.json",
            "original-lease-owner.json",
            "original-acquisition.json",
            "original-activation.json",
            "original-contract.json",
            "selected-runtime-manifest.json",
            "selected-cli-image.bin",
            "selected-agent-image.bin",
        ] {
            if delivery
                && [
                    "phase-journal.bin",
                    "controller-intent.json",
                    "controller-action.json",
                ]
                .contains(&name)
            {
                continue;
            }
            let path = format!("{prefix}/{name}");
            let bytes = super::linux_mixed_installed::read_owned_resource(
                &input.artifact_root.join(&path),
                512 * 1024 * 1024,
            )?;
            if !added.iter().any(|artifact| artifact.path == path) {
                added.push(Artifact {
                    path: path.clone(),
                    length: bytes.len() as u64,
                    sha256: super::artifacts::checksum(&bytes),
                });
            }
            peers.push(BehaviorArtifact {
                role: name.into(),
                path,
            });
        }
        for name in [
            "actual-result.json",
            "release-prepared.json",
            "report-destination.json",
            "provider-terminal.json",
            "report-delivery-failure.json",
            "export-receipt.json",
            "export-orphan-descendant.bin",
            "export-orphan-completion.json",
        ] {
            let path = format!("{prefix}/{name}");
            match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(input.artifact_root.join(&path))
            {
                Ok(_) => {
                    let bytes = super::linux_mixed_installed::read_owned_resource(
                        &input.artifact_root.join(&path),
                        16 * 1024 * 1024,
                    )?;
                    added.push(Artifact {
                        path: path.clone(),
                        length: bytes.len() as u64,
                        sha256: super::artifacts::checksum(&bytes),
                    });
                    peers.push(BehaviorArtifact {
                        role: name.into(),
                        path,
                    });
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let raw = raw_path
            .strip_prefix(input.artifact_root)
            .map_err(|error| CiError::Message(error.to_string()))?
            .to_str()
            .ok_or_else(|| CiError::Message("actual lifecycle raw path is not UTF8".into()))?
            .to_owned();
        let raw_bytes =
            super::linux_mixed_installed::read_owned_resource(raw_path, 32 * 1024 * 1024)?;
        added.push(Artifact {
            path: original_lease,
            length: lease_bytes.len() as u64,
            sha256: super::artifacts::checksum(&lease_bytes),
        });
        added.push(Artifact {
            path: raw.clone(),
            length: raw_bytes.len() as u64,
            sha256: super::artifacts::checksum(&raw_bytes),
        });
        let evidence = LinuxLifecycleLossEvidence {
            format: if delivery {
                "memcordon.consumer-readiness.linux-delivery"
            } else {
                "memcordon.consumer-readiness.linux-lifecycle-loss"
            }
            .into(),
            revision: 1,
            key: key.clone(),
            run_id: input.identity.run_id.clone(),
            source_commit: input.identity.source_commit.clone(),
            source_tree_sha256: input.identity.source_tree_sha256.clone(),
            lease_id: input.lease_id.clone(),
            fixture: fixture.path,
            fixture_sha256: fixture.sha256,
            fixture_source: source.path,
            fixture_source_sha256: source.sha256,
            input: descriptor.path,
            owner: owner.path,
            raw,
            artifacts: peers,
        };
        let path = format!("{prefix}/case-evidence.json");
        let bytes = serde_json::to_vec(&evidence)?;
        retain_bytes(&input.artifact_root.join(&path), &bytes, &mut report.files)?;
        added.push(Artifact {
            path: path.clone(),
            length: bytes.len() as u64,
            sha256: super::artifacts::checksum(&bytes),
        });
        report.artifacts.extend(added);
        report.records.push(CaseRecord {
            key: key.clone(),
            run_id: input.identity.run_id.clone(),
            state: CaseState::Passed,
            reason: None,
            evidence: Some(path),
        });
    }
    Ok(())
}

/// Capture the current actual durable journal without following a replaced
/// leaf, retaining its descriptor through independent final settlement.
pub fn retain_phase_journal(
    attempt: &str,
    deadline: Instant,
    owners: &mut Vec<File>,
) -> Result<(Vec<u8>, serde_json::Value)> {
    if Instant::now() >= deadline
        || attempt.len() != 32
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CiError::Message(
            "lifecycle phase attempt/cutoff differs".into(),
        ));
    }
    let path = std::path::PathBuf::from("/var/lib/memcordon/sealed").join(attempt);
    let ancestry_start = owners.len();
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    owners.push(root);
    for component in ["var", "lib", "memcordon", "sealed"] {
        let next = File::from(
            rustix::fs::openat(
                owners.last().expect("held native journal parent"),
                component,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        let metadata = next.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() == 0
        {
            return Err(CiError::Message(
                "actual lifecycle journal ancestry is not protected held root custody".into(),
            ));
        }
        owners.push(next);
    }
    let file = File::from(
        rustix::fs::openat(
            owners.last().expect("held sealed journal directory"),
            attempt,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| CiError::Message(error.to_string()))?,
    );
    let before = file.metadata()?;
    owners.push(file.try_clone()?);
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || before.len() > 1024 * 1024
    {
        return Err(CiError::Message(
            "actual lifecycle phase journal custody differs".into(),
        ));
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    let text = std::str::from_utf8(&bytes).map_err(|error| CiError::Message(error.to_string()))?;
    let (body, digest) = text
        .rsplit_once("digest=")
        .ok_or_else(|| CiError::Message("phase journal checksum absent".into()))?;
    if digest != format!("{}\n", super::artifacts::checksum(body.as_bytes())) {
        return Err(CiError::Message(
            "actual phase journal checksum differs".into(),
        ));
    }
    let mut lines = body.lines();
    if lines.next() != Some("format=memcordon.private-native-journal")
        || lines.next() != Some("revision=1")
    {
        return Err(CiError::Message(
            "actual lifecycle journal envelope differs".into(),
        ));
    }
    let group = lines
        .next()
        .and_then(|line| line.strip_prefix("cgroup="))
        .ok_or_else(|| CiError::Message("phase journal cgroup absent".into()))?;
    let payload = lines
        .next()
        .and_then(|line| line.strip_prefix("payload="))
        .ok_or_else(|| CiError::Message("phase journal payload absent".into()))?;
    if lines.next().is_some() || group != attempt {
        return Err(CiError::Message(
            "phase journal original cgroup/envelope differs".into(),
        ));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(payload.as_bytes())
        .map_err(CiError::Message)?;
    let record: serde_json::Value = serde_json::from_slice(payload.as_bytes())?;
    if record["attempt_id"] != attempt {
        return Err(CiError::Message(
            "actual phase journal attempt differs".into(),
        ));
    }
    let held = owners
        .last()
        .expect("retained lifecycle journal descriptor")
        .metadata()?;
    let named = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?
        .metadata()?;
    let stamp = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.nlink(),
            metadata.uid(),
            metadata.mode(),
        )
    };
    if stamp(&before) != stamp(&held) || stamp(&held) != stamp(&named) || Instant::now() >= deadline
    {
        return Err(CiError::Message(
            "actual lifecycle journal changed during phase capture".into(),
        ));
    }
    for (index, name) in [
        "/",
        "/var",
        "/var/lib",
        "/var/lib/memcordon",
        "/var/lib/memcordon/sealed",
    ]
    .iter()
    .enumerate()
    {
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(name)?;
        let held = owners[ancestry_start + index].metadata()?;
        let current = named.metadata()?;
        if (held.dev(), held.ino(), held.uid(), held.mode())
            != (current.dev(), current.ino(), current.uid(), current.mode())
        {
            return Err(CiError::Message(
                "actual lifecycle journal ancestor replaced during phase capture".into(),
            ));
        }
    }
    Ok((bytes, record))
}
