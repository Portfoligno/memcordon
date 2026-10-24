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
    control_pid: u32,
    control_birth: u64,
    control_source: serde_json::Value,
    control_status: Vec<u8>,
    caller_image_owner: HeldLinuxProcess,
    caller_image: serde_json::Value,
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
        control: &HeldLinuxProcess,
        control_source: serde_json::Value,
        caller: &HeldLinuxProcess,
        caller_credentials: (u32, u32),
        expected_cli_sha256: &str,
        deadline: Instant,
    ) -> Result<Self> {
        let (caller_uid, caller_gid) = caller_credentials;
        require_live(worker, caller, deadline)?;
        control
            .verify_intervention_image(deadline)
            .map_err(CiError::Message)?;
        let control_status = native_credentials(control, 0, 0)?;
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
            if peer.pid.as_raw_nonzero().get() != control.process_id as i32
                || peer.uid.as_raw() != 0
                || peer.gid.as_raw() != 0
            {
                continue;
            }
            let before = socket.metadata()?;
            let expected = format!("socket:[{}]", before.ino());
            if link != std::path::Path::new(&expected) || before.ino() == 0 {
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
                control_pid: control.process_id,
                control_birth: control.birth,
                control_source: control_source.clone(),
                control_status: control_status.clone(),
                caller_image_owner: caller.duplicate_for_intervention(deadline).map_err(
                    |failure| {
                        CiError::Message(format!(
                            "original frontend image capability failed: {failure:?}"
                        ))
                    },
                )?,
                caller_image: serde_json::Value::Null,
                source_descriptor: descriptor,
                device: before.dev(),
                inode: before.ino(),
                peer_uid: peer.uid.as_raw(),
                peer_gid: peer.gid.as_raw(),
                caller_status: caller_status.clone(),
            };
            let mut owner = owner;
            owner.caller_image = owner
                .caller_image_owner
                .hold_executable_image(deadline)
                .map_err(CiError::Message)?;
            if owner.caller_image["sha256"] != expected_cli_sha256 {
                return Err(CiError::Message(
                    "original frontend image differs from selected CLI".into(),
                ));
            }
            if selected.replace(owner).is_some() {
                return Err(CiError::Message(
                    "selected worker has multiple caller-associated control connections".into(),
                ));
            }
        }
        require_live(worker, caller, deadline)?;
        control
            .verify_intervention_image(deadline)
            .map_err(CiError::Message)?;
        selected.ok_or_else(|| {
            CiError::Message("actual caller-associated native control connection absent".into())
        })
    }

    pub fn shutdown(
        &self,
        worker: &HeldLinuxProcess,
        control: &HeldLinuxProcess,
        caller: &HeldLinuxProcess,
        deadline: Instant,
    ) -> Result<serde_json::Value> {
        require_live(worker, caller, deadline)?;
        let control_image_check = control
            .verify_intervention_image(deadline)
            .map_err(CiError::Message)?;
        let worker_image_check = worker
            .verify_intervention_image(deadline)
            .map_err(CiError::Message)?;
        let caller_image_check = self
            .caller_image_owner
            .verify_intervention_image(deadline)
            .map_err(CiError::Message)?;
        native_credentials(control, 0, 0)?;
        native_credentials(caller, 65534, 65534)?;
        if control.process_id != self.control_pid || control.birth != self.control_birth {
            return Err(CiError::Message(
                "control/frontend original identity or credentials changed".into(),
            ));
        }
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
            || named != std::path::Path::new(&format!("socket:[{}]", self.inode))
        {
            return Err(CiError::Message(
                "native control socket was replaced before shutdown".into(),
            ));
        }
        let peer = rustix::net::sockopt::socket_peercred(&self.socket)
            .map_err(|error| CiError::Message(error.to_string()))?;
        if peer.pid.as_raw_nonzero().get() != self.control_pid as i32
            || peer.uid.as_raw() != self.peer_uid
            || peer.gid.as_raw() != self.peer_gid
        {
            return Err(CiError::Message(
                "original authenticated control socket peer changed".into(),
            ));
        }
        require_live(worker, caller, deadline)?;
        control
            .verify_intervention_image(deadline)
            .map_err(CiError::Message)?;
        worker
            .verify_intervention_image(deadline)
            .map_err(CiError::Message)?;
        self.caller_image_owner
            .verify_intervention_image(deadline)
            .map_err(CiError::Message)?;
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
            serde_json::json!({"format":"memcordon.linux-lifecycle-control-shutdown","revision":2,
            "worker":{"pid":self.worker_pid,"birth":self.worker_birth},"caller":{"pid":self.caller_pid,"birth":self.caller_birth},
            "control":self.control_source,"control_status_bytes":self.control_status,
            "caller_image":self.caller_image,
            "worker_image_check":worker_image_check,"control_image_check":control_image_check,"caller_image_check":caller_image_check,
            "source_descriptor":self.source_descriptor,"device":self.device,"inode":self.inode,
            "peer_pid":self.control_pid,"peer_uid":self.peer_uid,"peer_gid":self.peer_gid,"socket_type":libc::SOCK_STREAM,
            "socket_domain":libc::AF_UNIX,"caller_status_bytes":self.caller_status,
            "native_how":libc::SHUT_RDWR,"native_status":status,"native_errno":errno}),
        )
    }
}

fn native_credentials(owner: &HeldLinuxProcess, uid: u32, gid: u32) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    File::open(format!("/proc/{}/status", owner.process_id))?
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(CiError::Message(
            "native control credential source exceeds bound".into(),
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| CiError::Message(error.to_string()))?;
    for (field, expected) in [("Uid:", uid), ("Gid:", gid)] {
        let values = text
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .ok_or_else(|| CiError::Message("native control credential field absent".into()))?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| CiError::Message(error.to_string()))?;
        if values != vec![expected; 4] {
            return Err(CiError::Message("native control credentials differ".into()));
        }
    }
    Ok(bytes)
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
    fixture_budget: Option<LifecycleFixtureBudget>,
    fixture_exports: Vec<super::fixture_export_retirement::Owner>,
    original_work_deadline: Option<Instant>,
    original_cleanup_deadline: Option<Instant>,
    pub native: super::linux_readiness_limits_cases::LimitsReport,
    workers: Vec<HeldLinuxProcess>,
    actor_owners: Vec<InterventionOwner>,
    controls: Vec<HeldControlConnection>,
    files: Vec<File>,
    directories: Vec<File>,
    pub observations: Vec<serde_json::Value>,
    pub completed: Vec<(memcordon_readiness_verifier::CaseKey, std::path::PathBuf)>,
    pub records: Vec<memcordon_readiness_verifier::CaseRecord>,
    pub artifacts: Vec<memcordon_readiness_verifier::Artifact>,
}

struct InterventionOwner {
    key: memcordon_readiness_verifier::CaseKey,
    attempt: String,
    role: String,
    owner: HeldLinuxProcess,
    image: Option<serde_json::Value>,
}

struct LifecycleFixtureBudget {
    budget: super::linux_fixture_memory_budget::FrozenImageMemoryBudget,
    receipt: Vec<u8>,
    file: File,
}

impl LifecycleReport {
    pub fn native_owners_settled(&self) -> bool {
        self.native.native_owners_settled()
            && self.fixture_exports.iter().all(|owner| owner.settled())
            && self.workers.is_empty()
            && self.actor_owners.is_empty()
            && self.controls.is_empty()
            && self.files.is_empty()
            && self.directories.is_empty()
            && self.fixture_budget.is_none()
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
    for owner in &mut report.fixture_exports {
        owner.retire()?;
    }
    for worker in report
        .workers
        .iter()
        .chain(report.actor_owners.iter().map(|actor| &actor.owner))
    {
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
    report.fixture_budget = None;
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
    context
        .publication
        .verify_selection(context.identity, context.cell, context.lease_id)?;
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
    if !report.native.owners.is_empty()
        || !report.completed.is_empty()
        || report.fixture_budget.is_some()
    {
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
    // The nested report retains the Child even if prepared authentication fails.
    // Its cleanup authority must exist before that first owner is acquired.
    report
        .native
        .bind_original_cutoffs(context.work_deadline, context.cleanup_deadline)?;
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
    // The unchanged workload headroom excludes the already admitted image
    // inventory, whose tmpfs copy is charged to this same attempt.
    let budget = super::linux_fixture_memory_budget::FrozenImageMemoryBudget::for_images(
        &context.images.runtime,
        &context.images.input,
        &context.contract.runtime_image,
        &context.contract.input_image,
        super::linux_readiness_limits_cases::native_fixture_page_bytes()?,
        512 * 1024 * 1024,
    )
    .map_err(CiError::Message)?;
    let receipt = serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.linux-fixture-memory-budget", "revision":1,
        "source":context.identity, "cell":context.cell, "lease_id":context.lease_id,
        "key":key, "budget":budget,
    }))?;
    let receipt_path = context
        .artifact_root
        .join(prefix)
        .join("fixture-memory-budget.json");
    retain_bytes(&receipt_path, &receipt, &mut report.files)?;
    let file = report
        .files
        .last()
        .ok_or_else(|| CiError::Message("held fixture budget absent".into()))?
        .try_clone()?;
    let memory = budget.token();
    report
        .artifacts
        .push(memcordon_readiness_verifier::Artifact {
            path: format!("{prefix}/fixture-memory-budget.json"),
            length: receipt.len() as u64,
            sha256: super::artifacts::checksum(&receipt),
        });
    report.fixture_budget = Some(LifecycleFixtureBudget {
        budget,
        receipt,
        file,
    });
    let launch = InstalledMixedLaunch::start_with_delivery_controls(
        InstalledMixedLaunchInput {
            directory,
            contract: context.contract_path,
            caller_uid: 65534,
            caller_gid: 65534,
            target_arguments: &args,
            deadline: std::ffi::OsStr::new("+300s"),
            memory: std::ffi::OsStr::new(&memory),
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
    {
        use std::io::Read;
        let group = observer
            .retain_cgroup_descriptor()
            .map_err(CiError::Message)?;
        let maximum = File::from(
            rustix::fs::openat(
                &group,
                "memory.max",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|error| CiError::Message(error.to_string()))?,
        );
        let mut bytes = Vec::new();
        (&maximum).take(65).read_to_end(&mut bytes)?;
        let observed = std::str::from_utf8(&bytes)
            .ok()
            .filter(|_| bytes.len() <= 64)
            .and_then(|text| text.trim_end_matches('\n').parse::<u64>().ok())
            .ok_or_else(|| CiError::Message("lifecycle native memory.max invalid".into()))?;
        let frozen = report
            .fixture_budget
            .as_ref()
            .expect("original fixture budget retained");
        frozen
            .budget
            .require_maximum(observed)
            .map_err(CiError::Message)?;
        let receipt = serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-lifecycle-memory-max", "revision":1,
            "key":key, "attempt_id":observer.observation.admission.attempt_id.as_str(),
            "cgroup_inode":group.metadata()?.ino(), "memory_max":observed,
            "budget_sha256":super::artifacts::checksum(&frozen.receipt),
        }))?;
        retain_bytes(
            &context
                .artifact_root
                .join(prefix)
                .join("fixture-memory-max.json"),
            &receipt,
            &mut report.files,
        )?;
        report.files.push(maximum);
        report.directories.push(group);
    }
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
        let control_source = super::linux_readiness_image_cases::retain_prepared_control(
            &worker_source,
            observer,
            context.selected_agent_sha256,
            context.work_deadline,
            &mut report.workers,
        )?;
        let control = report
            .workers
            .last()
            .expect("retained authenticated control");
        report.controls.push(HeldControlConnection::acquire(
            &report.workers[worker_index],
            control,
            control_source,
            &observer.caller,
            (65534, 65534),
            context.selected_cli_sha256,
            context.work_deadline,
        )?);
    }
    if !delivery {
        let selected = match actor {
            "frontend" => &observer.caller,
            "worker" | "control" => &report.workers[worker_index],
            "guardian" => &observer.guardian,
            _ => {
                return Err(CiError::Message(
                    "unknown original lifecycle intervention actor".into(),
                ));
            }
        };
        let attempt = observer.observation.admission.attempt_id.as_str();
        let duplicated = selected.duplicate_for_intervention(context.work_deadline);
        let acquisition = match duplicated.as_ref() {
            Ok(owner) => {
                serde_json::json!({"acquired":true,"pid":owner.process_id,"birth":owner.birth,"original_pidfd_duplicated":true})
            }
            Err(error) => serde_json::json!({"acquired":false,"failure":error}),
        };
        let early = serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.lifecycle-intervention-early-ownership","revision":1,"diagnostic_only":true,
            "key":key,"attempt_id":attempt,"role":actor,"stage":"prepared-before-release",
            "expected_pid":selected.process_id,"expected_birth":selected.birth,
            "acquisition":acquisition
        }))?;
        let early_retained = super::linux_lifecycle_diagnostics::publish(
            context.publication,
            &context
                .artifact_root
                .join(prefix)
                .join("intervention-early-ownership.json"),
            &early,
            &mut report.artifacts,
        );
        let duplicate = match duplicated {
            Ok(owner) => owner,
            Err(primary) => {
                return Err(CiError::Message(format!(
                    "original {actor} intervention capability at prepared barrier failed: {primary:?}; evidence={:?}",
                    early_retained.as_ref().map(|_| ())
                )));
            }
        };
        // Store cleanup custody before any further fallible image measurement.
        report.actor_owners.push(InterventionOwner {
            key: key.clone(),
            attempt: attempt.to_owned(),
            role: actor.to_owned(),
            owner: duplicate,
            image: None,
        });
        report.files.push(early_retained?);
        let selected = report
            .actor_owners
            .last_mut()
            .expect("original selected actor retained");
        let image = selected
            .owner
            .hold_executable_image(context.work_deadline)
            .map_err(|error| {
                CiError::Message(format!(
                    "original {actor} pid={} birth={} early executable measurement: {error}",
                    selected.owner.process_id, selected.owner.birth
                ))
            })?;
        let expected_image = if actor == "frontend" {
            context.selected_cli_sha256
        } else {
            context.selected_agent_sha256
        };
        if image["sha256"] != expected_image {
            return Err(CiError::Message(format!(
                "original {actor} prepared executable differs from selected installed image"
            )));
        }
        selected.image = Some(image.clone());
        let measured = serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.lifecycle-intervention-early-image","revision":1,
            "diagnostic_only":true,"key":key,"attempt_id":attempt,"role":actor,"native_image":image,"selected_image_sha256":expected_image}),
        )?;
        report
            .files
            .push(super::linux_lifecycle_diagnostics::publish(
                context.publication,
                &context
                    .artifact_root
                    .join(prefix)
                    .join("intervention-early-image.json"),
                &measured,
                &mut report.artifacts,
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
    let errors = retain_existing_context(context, &context.artifact_root.join(prefix), report);
    if !errors.is_empty() {
        return Err(CiError::Message(format!(
            "original lifecycle allocation context retention failed: {errors:?}"
        )));
    }
    Ok(index)
}

fn retain_existing_context(
    context: &super::linux_readiness_limits_cases::LimitsContext<'_>,
    directory: &std::path::Path,
    report: &mut LifecycleReport,
) -> Vec<String> {
    let mut errors = Vec::new();
    for name in [
        "allocation-phase-journal.bin",
        "frontend-preinput.json",
        "frontend-invocation.json",
        "prepared-native-before-ack.json",
    ] {
        let mut captured = Vec::new();
        match super::linux_lifecycle_diagnostics::register_existing(
            context.publication,
            &directory.join(name),
            &mut captured,
        ) {
            Ok(file) => {
                for artifact in captured {
                    match report
                        .artifacts
                        .iter()
                        .find(|old| old.path == artifact.path)
                    {
                        Some(old)
                            if old.length == artifact.length && old.sha256 == artifact.sha256 => {}
                        Some(_) => errors.push(format!(
                            "existing context {name} changed from original registered bytes"
                        )),
                        None => report.artifacts.push(artifact),
                    }
                }
                report.files.push(file);
            }
            Err(error) => errors.push(format!("existing context {name}: {error}")),
        }
    }
    errors
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
    // This runs before any new phase probe, so failed capture cannot erase
    // independently retained original input/owner evidence.
    let mut diagnostic_errors = retain_existing_context(context, directory, report);
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
    // Register independent existing context even if a new publication fails.
    let (journal, record) = retain_phase_journal(
        observer.observation.admission.attempt_id.as_str(), context.work_deadline, &mut report.files,
    ).map_err(|primary| CiError::Message(format!("selected lifecycle phase={phase}; {primary}; existing context retention={diagnostic_errors:?}")))?;
    let journal_metadata = report
        .files
        .last()
        .expect("retained original phase journal")
        .metadata()?;
    // Preserve the authenticated observation even if the selected barrier fails.
    let journal_capture = super::linux_lifecycle_diagnostics::publish(
        context.publication,
        &directory.join("phase-journal.bin"),
        &journal,
        &mut report.artifacts,
    );
    match journal_capture {
        Ok(file) => report.files.push(file),
        Err(error) => diagnostic_errors.push(format!("phase journal publication: {error}")),
    }
    let secondary = (|| -> Result<()> {
        let witness = serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-lifecycle-barrier-observation","revision":1,
            "diagnostic_only":true,"key":owner.key,"admission":observer.observation.admission,
            "selected_phase":phase,"phase":record["phase"],
            "release_knowledge":record["release_knowledge"],
            "journal_sha256":super::artifacts::checksum(&journal),
            "frontend":observer.caller.retirement_identity().map_err(CiError::Message)?,
            "worker":worker.retirement_identity().map_err(CiError::Message)?,
            "guardian":observer.guardian.retirement_identity().map_err(CiError::Message)?
        }))?;
        report
            .files
            .push(super::linux_lifecycle_diagnostics::publish(
                context.publication,
                &directory.join("barrier-observation.json"),
                &witness,
                &mut report.artifacts,
            )?);
        Ok(())
    })();
    if let Err(error) = secondary {
        diagnostic_errors.push(error.to_string());
    }
    let mut barrier = None;
    let mut retirement_barrier = None;
    match phase {
        "allocation"
            if record["phase"] == "release-intent"
                && record["release_knowledge"] == "possibly-released" => {}
        "release"
            if record["phase"] == "release-intent"
                && record["release_knowledge"] == "possibly-released" =>
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
                && observer.target.exited().map_err(CiError::Message)? =>
        {
            use memcordon_core::mixed_observation::*;
            let bytes = read_caller_observation(
                &owner
                    .launch
                    .observation_directory
                    .join(observer.observation.admission.attempt_id.as_str())
                    .with_extension("retirement-prepared.json"),
                context.work_deadline,
                &mut report.files,
            )?;
            let witness: MixedRetirementObservationV1 =
                parse_retirement(&bytes).map_err(CiError::Message)?;
            witness.validate().map_err(CiError::Message)?;
            let prepared = read_caller_observation(
                &owner
                    .launch
                    .observation_directory
                    .join(observer.observation.admission.attempt_id.as_str())
                    .with_extension("prepared.json"),
                context.work_deadline,
                &mut report.files,
            )?;
            let accepted = read_caller_observation(
                &owner
                    .launch
                    .observation_directory
                    .join(observer.observation.admission.attempt_id.as_str())
                    .with_extension("retirement-enrolled.json"),
                context.work_deadline,
                &mut report.files,
            )?;
            let receipt: MixedRetirementEnrolledV1 =
                parse_retirement(&accepted).map_err(CiError::Message)?;
            if !witness.binding.matches(&observer.observation, &prepared)
                || receipt.binding != witness.binding
                || receipt.enrollment_sha256 != witness.enrollment_sha256
                || witness.caller.pid != observer.caller.process_id
                || witness.caller.birth != observer.caller.birth
                || witness.target != observer.observation.target
                || witness.namespace_init != observer.observation.namespace_init
                || witness.guardian.pid != observer.guardian.process_id
                || witness.guardian.birth != observer.guardian.birth
                || witness.worker.pid != worker.process_id
                || witness.worker.birth != worker.birth
                || witness.journal.sha256 != retirement_digest(&journal)
                || witness.journal.length != journal.len() as u64
                || witness.journal.device != journal_metadata.dev()
                || witness.journal.inode != journal_metadata.ino()
                || monotonic_millis()? >= witness.observation_deadline_monotonic_millis
                || witness.boot_identity.as_str()
                    != std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
            {
                return Err(CiError::Message("retirement witness differs from original admitted native journal/owners/cutoff".into()));
            }
            retain_bytes(
                &directory.join("retirement-prepared.json"),
                &bytes,
                &mut report.files,
            )?;
            retain_bytes(
                &directory.join("retirement-enrolled.json"),
                &accepted,
                &mut report.files,
            )?;
            retirement_barrier = Some(serde_json::to_value(witness)?);
        }
        _ => {
            return Err(CiError::Message(format!(
                "actual native lifecycle phase has not reached selected {phase} intervention barrier: phase={} release_knowledge={}; diagnostic capture errors={diagnostic_errors:?}",
                record["phase"], record["release_knowledge"]
            )));
        }
    }
    if !diagnostic_errors.is_empty() {
        return Err(CiError::Message(format!(
            "lifecycle barrier diagnostic capture incomplete: {diagnostic_errors:?}"
        )));
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
    let target = match actor {
        "frontend" => &observer.caller,
        "worker" | "control" => worker,
        "guardian" => &observer.guardian,
        _ => return Err(CiError::Message("unknown lifecycle native actor".into())),
    };
    let mut retained = report.actor_owners.iter().filter(|retained| {
        retained.key == owner.key
            && retained.attempt == observer.observation.admission.attempt_id.as_str()
            && retained.role == actor
    });
    let selected = retained.next().ok_or_else(|| {
        CiError::Message("original prepared intervention capability absent".into())
    })?;
    if retained.next().is_some()
        || selected.owner.process_id != target.process_id
        || selected.owner.birth != target.birth
    {
        return Err(CiError::Message(
            "original prepared intervention capability association differs".into(),
        ));
    }
    let identity = selected
        .owner
        .retirement_identity()
        .map_err(CiError::Message)?;
    let image = selected.image.as_ref().ok_or_else(|| {
        CiError::Message("original prepared intervention image pin absent".into())
    })?;
    let selected_image = if actor == "frontend" {
        context.selected_cli_sha256
    } else {
        context.selected_agent_sha256
    };
    if image["sha256"] != selected_image {
        return Err(CiError::Message(
            "actual lifecycle actor image differs from selected installed owner".into(),
        ));
    }
    let intent = serde_json::json!({"format":"memcordon.linux-lifecycle-controller-intent","revision":1,
        "identity":context.identity,"cell":context.cell,"lease_id":context.lease_id,"key":owner.key,
        "attempt_id":observer.observation.admission.attempt_id,"actor":identity,"phase":record["phase"],
        "release_knowledge":record["release_knowledge"],"journal_sha256":super::artifacts::checksum(&journal),
        "release_barrier":barrier,"retirement_barrier":retirement_barrier,"native_image":image,"selected_image_sha256":selected_image,
        "native_operation":if actor=="control"{"socket-shutdown"}else{"pidfd-sigkill"}});
    retain_bytes(
        &directory.join("controller-intent.json"),
        &serde_json::to_vec(&intent)?,
        &mut report.files,
    )?;
    let current_image = match selected
        .owner
        .verify_intervention_image(context.work_deadline)
    {
        Ok(value) => value,
        Err(primary) => {
            let failure = serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.lifecycle-intervention-not-performed","revision":1,
                "diagnostic_only":true,"key":owner.key,"attempt_id":selected.attempt,"role":actor,"stage":"immediate-pre-action-current-image-and-liveness",
                "expected_identity":identity,"observed_retirement":selected.owner.retirement_identity(),"phase":record["phase"],"release_knowledge":record["release_knowledge"],
                "original_work_deadline_unix_millis":context.work_deadline_unix_millis,"reason":primary}),
            )?;
            let published = super::linux_lifecycle_diagnostics::publish(
                context.publication,
                &directory.join("intervention-not-performed.json"),
                &failure,
                &mut report.artifacts,
            );
            let evidence = match published {
                Ok(file) => {
                    report.files.push(file);
                    Ok(())
                }
                Err(error) => Err(error.to_string()),
            };
            return Err(CiError::Message(format!(
                "selected {actor} intervention not performed: {primary}; evidence={evidence:?}"
            )));
        }
    };
    if Instant::now() >= context.work_deadline {
        return Err(CiError::Message(
            "original intervention cutoff expired immediately before action".into(),
        ));
    }
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
        let control = report
            .workers
            .iter()
            .find(|process| {
                process.process_id == connection.control_pid
                    && process.birth == connection.control_birth
            })
            .ok_or_else(|| {
                CiError::Message("retained authenticated control owner absent".into())
            })?;
        if record["mixed_control"]
            != serde_json::json!({"pid":control.process_id,"start_time":control.birth})
        {
            return Err(CiError::Message(
                "phase journal changed original authenticated control".into(),
            ));
        }
        match connection.shutdown(worker, control, &observer.caller, context.work_deadline) {
            Ok(mut value) => {
                value["current_image_check"] = current_image;
                value
            }
            Err(reason) => {
                serde_json::json!({"format":"memcordon.linux-lifecycle-control-not-performed","revision":1,
                "native_status":-1,"not_performed_reason":reason.to_string(),"current_image_check":current_image})
            }
        }
    } else {
        match selected.owner.signal_kill() {
            Ok(native) => {
                serde_json::json!({"format":"memcordon.linux-lifecycle-pidfd-kill","revision":1,"actor":identity,
                "signal":9,"native_status":if native.is_ok(){0}else{-1},"native_errno":native.err(),"current_image_check":current_image})
            }
            Err(reason) => {
                serde_json::json!({"format":"memcordon.linux-lifecycle-pidfd-kill","revision":1,"actor":identity,
                "signal":9,"native_status":-1,"native_errno":null,"not_performed_reason":reason,"current_image_check":current_image})
            }
        }
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

#[allow(unsafe_code)] // Read only the native monotonic scalar used by the enrolled original owner.
fn monotonic_millis() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: CLOCK_MONOTONIC writes one valid initialized native timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut time) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let seconds = u64::try_from(time.tv_sec).map_err(|e| CiError::Message(e.to_string()))?;
    let nanos = u64::try_from(time.tv_nsec).map_err(|e| CiError::Message(e.to_string()))?;
    seconds
        .checked_mul(1000)
        .and_then(|v| v.checked_add(nanos / 1_000_000))
        .ok_or_else(|| CiError::Message("controller monotonic clock overflow".into()))
}

fn write_retirement_member(
    path: &std::path::Path,
    bytes: &[u8],
    owners: &mut Vec<File>,
) -> Result<()> {
    use std::io::Write;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    rustix::fs::fchown(&file, Some(rustix::process::Uid::from_raw(65534)), None)
        .map_err(|e| CiError::Message(e.to_string()))?;
    File::open(path.parent().expect("fixed observer directory"))?.sync_all()?;
    owners.push(file);
    Ok(())
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
        use memcordon_core::mixed_observation::*;
        let now = monotonic_millis()?;
        let sampled = Instant::now();
        let deadline = |cutoff: Instant| -> Result<u64> {
            now.checked_add(
                u64::try_from(cutoff.saturating_duration_since(sampled).as_millis())
                    .map_err(|e| CiError::Message(e.to_string()))?,
            )
            .ok_or_else(|| CiError::Message("controller original cutoff overflow".into()))
        };
        let configuration = MixedRetirementObserverV1 {
            format: "memcordon.mixed-retirement-observer".into(),
            revision: 1,
            observer: memcordon_core::result_v2::NativeProcessV2 {
                pid: std::process::id(),
                birth: crate::linux_consumer_readiness::process_birth(std::process::id())
                    .map_err(CiError::Message)?,
            },
            boot_identity: memcordon_core::BoundedText::new(
                std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
            )
            .map_err(|e| CiError::Message(e.into()))?,
            observer_work_deadline_monotonic_millis: deadline(context.work_deadline)?,
            observer_cleanup_deadline_monotonic_millis: deadline(context.cleanup_deadline)?,
            phase: MixedRetirementPhaseV1::Retiring,
        };
        configuration.validate().map_err(CiError::Message)?;
        write_retirement_member(
            &owner
                .launch
                .observation_directory
                .join("retirement-observer.json"),
            &encode_retirement(&configuration).map_err(CiError::Message)?,
            &mut report.files,
        )?;
        observer
            .acknowledge(&owner.launch.observation_directory)
            .map_err(CiError::Message)?;
        let accepted_path = owner
            .launch
            .observation_directory
            .join(observer.observation.admission.attempt_id.as_str())
            .with_extension("retirement-enrolled.json");
        while !accepted_path.try_exists()? {
            if Instant::now() >= context.work_deadline
                || observer.caller.exited().map_err(CiError::Message)?
                || observer.guardian.exited().map_err(CiError::Message)?
            {
                return Err(CiError::Message(
                    "original worker did not accept retirement observation before fixture release"
                        .into(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let accepted =
            read_caller_observation(&accepted_path, context.work_deadline, &mut report.files)?;
        let receipt: MixedRetirementEnrolledV1 =
            parse_retirement(&accepted).map_err(CiError::Message)?;
        let prepared_bytes = read_caller_observation(
            &owner
                .launch
                .observation_directory
                .join(observer.observation.admission.attempt_id.as_str())
                .with_extension("prepared.json"),
            context.work_deadline,
            &mut report.files,
        )?;
        let enrollment = MixedRetirementEnrollmentV1 {
            format: "memcordon.mixed-retirement-enrollment".into(),
            revision: 1,
            binding: MixedRetirementBindingV1 {
                attempt_id: observer.observation.admission.attempt_id.clone(),
                admission_nonce: observer.observation.admission.admission_nonce,
                prepared_sha256: retirement_digest(&prepared_bytes),
            },
            observer: configuration,
        };
        if receipt.format != "memcordon.mixed-retirement-enrolled"
            || receipt.revision != 1
            || receipt.binding != enrollment.binding
            || receipt.enrollment_sha256
                != retirement_digest(&encode_retirement(&enrollment).map_err(CiError::Message)?)
        {
            return Err(CiError::Message(
                "original worker retirement acceptance differs from exact enrollment".into(),
            ));
        }
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
            let observation = owner
                .launch
                .observation_directory
                .join(observer.observation.admission.attempt_id.as_str())
                .with_extension("retirement-prepared.json");
            if observation.try_exists()? {
                break;
            }
            if owner
                .launch
                .observation_directory
                .join(observer.observation.admission.attempt_id.as_str())
                .with_extension("retirement-result.json")
                .try_exists()?
            {
                return Err(CiError::Message(
                    "original retirement observation failed before witness publication".into(),
                ));
            }
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
        let intervention = intervene(report, context, index, &root);
        if phase == "drain" {
            let owner = &report.native.owners[index];
            let observer = owner.observer.as_ref().expect("original drain observer");
            // A deliberately killed frontend cannot acknowledge. Native loss
            // containment and independent retirement remain the actual proof.
            if !observer.caller.exited().map_err(CiError::Message)? {
                use memcordon_core::mixed_observation::*;
                let witness_bytes = read_caller_observation(
                    &owner
                        .launch
                        .observation_directory
                        .join(observer.observation.admission.attempt_id.as_str())
                        .with_extension("retirement-prepared.json"),
                    context.work_deadline,
                    &mut report.files,
                )?;
                let witness: MixedRetirementObservationV1 =
                    parse_retirement(&witness_bytes).map_err(CiError::Message)?;
                let disposition = match &intervention {
                    Ok(()) => MixedRetirementDispositionV1::Completed,
                    Err(_) => MixedRetirementDispositionV1::Aborted {
                        detail: memcordon_core::BoundedText::new(
                            "original controller intervention failed",
                        )
                        .expect("fixed detail"),
                    },
                };
                let ack = MixedRetirementAcknowledgmentV1 {
                    format: "memcordon.mixed-retirement-acknowledgment".into(),
                    revision: 1,
                    binding: witness.binding,
                    enrollment_sha256: witness.enrollment_sha256,
                    witness_sha256: retirement_digest(&witness_bytes),
                    disposition,
                };
                write_retirement_member(
                    &owner
                        .launch
                        .observation_directory
                        .join(observer.observation.admission.attempt_id.as_str())
                        .with_extension("retirement-observer-ack.json"),
                    &encode_retirement(&ack).map_err(CiError::Message)?,
                    &mut report.files,
                )?;
            }
        }
        intervention?;
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
            let export_receipt: serde_json::Value = serde_json::from_slice(&exported)?;
            if export_receipt["root_layout"]
                != serde_json::to_value(&admission.request.root_layout)?
                || export_receipt["identity"]
                    != serde_json::to_value(&admission.request.execution_identity)?
            {
                return Err(CiError::Message(
                    "lifecycle export receipt differs from original fixture authority".into(),
                ));
            }
            let export_owner = super::fixture_export_retirement::prepare(
                path.parent().expect("authenticated export root"),
                &exported,
                0,
                context.cleanup_deadline,
                &root.join("fixture-export-retirement-journal.jsonl"),
                |name, bytes| {
                    let destination = root.join("exported").join(name);
                    std::fs::create_dir_all(destination.parent().expect("finite export parent"))?;
                    retain_bytes(&destination, bytes, &mut report.files)
                },
            )?;
            report.fixture_exports.push(export_owner);
            let export_retirement = report
                .fixture_exports
                .last_mut()
                .expect("original export owner")
                .retire()?;
            retain_bytes(
                &root.join("fixture-export-retirement.json"),
                &serde_json::to_vec(&export_retirement)?,
                &mut report.files,
            )?;
            let journal = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(root.join("fixture-export-retirement-journal.jsonl"))?;
            report.files.push(journal);
        }
    }
    // Orphan recovery refuses live frontend/worker owners. Package-lease
    // release is not process retirement; use the original held pidfds only.
    let selected_worker = report
        .observations
        .iter()
        .find(|observation| {
            observation["key"] == serde_json::to_value(&key).unwrap_or(serde_json::Value::Null)
        })
        .and_then(|observation| observation["worker_index"].as_u64())
        .and_then(|index| usize::try_from(index).ok())
        .and_then(|index| report.workers.get(index))
        .ok_or_else(|| {
            CiError::Message(
                "original lifecycle selected worker source association absent before recovery"
                    .into(),
            )
        })?;
    let observer = report.native.owners[index]
        .observer
        .as_ref()
        .ok_or_else(|| {
            CiError::Message("original lifecycle frontend owner absent before recovery".into())
        })?;
    let sample = || -> std::result::Result<super::linux_recovery_owners::Owners, String> {
        Ok(super::linux_recovery_owners::Owners {
            frontend: observer.caller.retirement_identity().map_err(|error| format!("original frontend pid={} birth={} held-pidfd retirement observation: {error}", observer.caller.process_id, observer.caller.birth))?,
            worker: selected_worker.retirement_identity().map_err(|error| format!("original selected worker pid={} birth={} held-pidfd retirement observation: {error}", selected_worker.process_id, selected_worker.birth))?,
        })
    };
    let before = sample().map_err(CiError::Message)?;
    let retirement =
        super::linux_recovery_owners::await_retirement(before, context.cleanup_deadline, sample);
    let retirement_bytes = serde_json::to_vec(&serde_json::json!({
        "format":"memcordon.linux-original-recovery-owner-precondition","revision":1,
        "diagnostic_only":true,"identity":context.identity,"cell":context.cell,
        "lease_id":context.lease_id,"key":key,"attempt_id":observer.observation.admission.attempt_id,
        "original_cleanup_deadline_unix_millis":context.cleanup_deadline_unix_millis,
        "observation":retirement,
        "frontend_still_live":!retirement.after.frontend.retirement_observed,
        "worker_still_live":!retirement.after.worker.retirement_observed,
        "target_init_guardian":"not a precondition; original recovery retains their cleanup responsibility"
    }))?;
    let retained = super::linux_lifecycle_diagnostics::publish(
        context.publication,
        &root.join(crate::linux_consumer_readiness::recovery_artifact_tree::LIFECYCLE_RECOVERY_OWNER_PRECONDITION),
        &retirement_bytes,
        &mut report.artifacts,
    );
    if !retirement.retired {
        return Err(CiError::Message(format!(
            "{}; frontend={:?}; worker={:?}; precondition publication={:?}",
            retirement.reason,
            retirement.after.frontend,
            retirement.after.worker,
            retained.as_ref().map(|_| ())
        )));
    }
    report.files.push(retained?);
    use super::linux_original_recovery::{contract, record};
    let original_input = contract::Input {
        format: "memcordon.original-native-recovery-input".into(),
        revision: 1,
        identity: contract::Identity {
            run_id: context.identity.run_id.clone(),
            source_commit: context.identity.source_commit.clone(),
            source_tree_sha256: context.identity.source_tree_sha256.clone(),
            version: context.identity.version.clone(),
        },
        native_target: context.cell.target.clone(),
        scope_id: context.lease_id.into(),
        artifact_root: root.clone(),
        original_artifact_root: root.clone(),
        origin_sha256: String::new(),
        work_deadline_unix_millis: context.work_deadline_unix_millis,
        cleanup_deadline_unix_millis: context.cleanup_deadline_unix_millis,
        recovery_harness_owner_sha256: context.recovery_harness.owner_sha256()?,
        context: if delivery {
            contract::Context::Delivery {
                lease_owner: record(context.lease_owner_path)?,
                prepared: record(&root.join("prepared.json"))?,
                allocation_journal: record(&root.join("allocation-phase-journal.bin"))?,
                report_destination: record(&root.join("report-destination.json"))?,
                report_delivery_failure: record(&root.join("report-delivery-failure.json"))?,
            }
        } else {
            contract::Context::Lifecycle {
                lease_owner: record(context.lease_owner_path)?,
                prepared: record(&root.join("prepared.json"))?,
                allocation_journal: record(&root.join("allocation-phase-journal.bin"))?,
                phase_journal: record(&root.join("phase-journal.bin"))?,
                controller_intent: record(&root.join("controller-intent.json"))?,
                controller_action: record(&root.join("controller-action.json"))?,
            }
        },
    };
    let recovery_result = super::linux_original_recovery::run(
        context.recovery_harness,
        &original_input,
        context.cleanup_deadline,
    );
    // These attempts are nested under this selected recipe root, not the global
    // artifact root. Register partial/failed evidence before propagating Err.
    let recovery_retention = (|| -> Result<()> {
        let (files, issues) =
            crate::linux_consumer_readiness::recovery_artifact_tree::collect_diagnostic_attempts(
                &root,
                |path, bound| {
                    super::linux_mixed_installed::read_owned_resource(path, bound)
                        .map_err(|error| error.to_string())
                },
            )
            .map_err(CiError::Message)?;
        for (path, bytes) in files {
            let path = root.join(path);
            let held = super::linux_lifecycle_diagnostics::register_existing(
                context.publication,
                &path,
                &mut report.artifacts,
            )?;
            if held.metadata()?.len() != bytes.len() as u64
                || report
                    .artifacts
                    .last()
                    .is_none_or(|artifact| artifact.sha256 != super::artifacts::checksum(&bytes))
            {
                return Err(CiError::Message(
                    "original recovery retained diagnostic extent changed".into(),
                ));
            }
            report.files.push(held);
        }
        let inventory = serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.original-recovery-selected-attempt-inventory","revision":1,"diagnostic_only":true,"issues":issues}),
        )?;
        report
            .files
            .push(super::linux_lifecycle_diagnostics::publish(
                context.publication,
                &root.join(crate::linux_consumer_readiness::recovery_artifact_tree::LIFECYCLE_RECOVERY_DIAGNOSTIC_INVENTORY),
                &inventory,
                &mut report.artifacts,
            )?);
        Ok(())
    })();
    let recovery = match recovery_result {
        Ok(recovery) => {
            recovery_retention?;
            recovery
        }
        Err(primary) => {
            return Err(CiError::Message(format!(
                "{primary}; selected original recovery diagnostic retention={recovery_retention:?}"
            )));
        }
    };
    let mut invocation = recovery.invocation.clone();
    invocation["original_fixture"] = recovery.proof().clone();
    invocation["original_fixture"]["acquisition_artifacts"] =
        super::linux_recovery_harness::acquisition_artifacts(
            context.artifact_root,
            &context
                .lease_owner_path
                .parent()
                .ok_or_else(|| CiError::Message("original lifecycle lease parent absent".into()))?
                .join("recovery-harness-acquisition"),
        )?;
    let invocation_bytes = serde_json::to_vec(&invocation)?;
    retain_bytes(
        &root.join("native-recovery-invocation.json"),
        &invocation_bytes,
        &mut report.files,
    )?;
    let process = &recovery.process;
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
    let mut actors = report.actor_owners.iter().filter(|actor| {
        actor.key == key
            && actor.attempt == observer.observation.admission.attempt_id.as_str()
            && u64::from(actor.owner.process_id) == actor_pid
            && actor.owner.birth == actor_birth
    });
    let selected_actor = if delivery {
        &observer.caller
    } else {
        &actors
            .next()
            .ok_or_else(|| {
                CiError::Message("original lifecycle controller actor owner absent".into())
            })?
            .owner
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
        let frozen = report
            .fixture_budget
            .as_ref()
            .ok_or_else(|| CiError::Message("original lifecycle fixture budget absent".into()))?;
        let reconstructed =
            super::linux_fixture_memory_budget::FrozenImageMemoryBudget::for_images(
                &images.runtime,
                &images.input,
                &images.runtime.reference().map_err(CiError::Message)?,
                &images.input.reference().map_err(CiError::Message)?,
                frozen.budget.page_bytes,
                512 * 1024 * 1024,
            )
            .map_err(CiError::Message)?;
        if serde_json::to_vec(&reconstructed)? != serde_json::to_vec(&frozen.budget)? {
            return Err(CiError::Message(
                "lifecycle fixture budget differs from original images".into(),
            ));
        }
        {
            use std::io::{Read, Seek, SeekFrom};
            let mut held = frozen.file.try_clone()?;
            held.seek(SeekFrom::Start(0))?;
            let mut receipt = Vec::new();
            held.take(frozen.receipt.len() as u64 + 1)
                .read_to_end(&mut receipt)?;
            let named = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory.join("fixture-memory-budget.json"))?;
            let before = frozen.file.metadata()?;
            let after = named.metadata()?;
            if receipt != frozen.receipt
                || before.dev() != after.dev()
                || before.ino() != after.ino()
                || before.nlink() != 1
                || before.len() != frozen.receipt.len() as u64
            {
                return Err(CiError::Message(
                    "held lifecycle fixture budget changed".into(),
                ));
            }
        }
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
            memory_bytes: Some(frozen.budget.limit_bytes),
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
        let recovery_invocation: serde_json::Value =
            serde_json::from_slice(&super::linux_mixed_installed::read_owned_resource(
                &directory.join("native-recovery-invocation.json"),
                1024 * 1024,
            )?)?;
        if let Some(references) =
            recovery_invocation["original_fixture"]["acquisition_artifacts"].as_object()
        {
            for (leaf, reference) in references {
                let path = reference.as_str().ok_or_else(|| {
                    CiError::Message("lifecycle recovery acquisition reference malformed".into())
                })?;
                let bytes = super::linux_mixed_installed::read_owned_resource(
                    &input.artifact_root.join(path),
                    if leaf == "acquisition-2.bin" {
                        512 * 1024 * 1024
                    } else {
                        16 * 1024 * 1024
                    },
                )?;
                if !added.iter().any(|artifact| artifact.path == path) {
                    added.push(Artifact {
                        path: path.into(),
                        length: bytes.len() as u64,
                        sha256: super::artifacts::checksum(&bytes),
                    });
                }
            }
        }
        let mut peers = Vec::new();
        for name in [
            "fixture-memory-budget.json",
            "fixture-memory-max.json",
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
            "retirement-prepared.json",
            "retirement-enrolled.json",
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
        for artifact in added {
            if let Some(original) = report
                .artifacts
                .iter()
                .find(|value| value.path == artifact.path)
            {
                if original.length != artifact.length || original.sha256 != artifact.sha256 {
                    return Err(CiError::Message(
                        "lifecycle frozen artifact changed before normalization".into(),
                    ));
                }
            } else {
                report.artifacts.push(artifact);
            }
        }
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
    // Probes own their descriptors transactionally. Only a selected stable
    // snapshot may extend the caller's retained custody.
    let mut ancestry = Vec::new();
    let mut original_ancestry = Vec::new();
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let metadata = root.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() == 0
    {
        return Err(CiError::Message(
            "actual lifecycle journal root custody differs".into(),
        ));
    }
    ancestry.push(root);
    original_ancestry.push((
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.mode(),
    ));
    for component in ["var", "lib", "memcordon", "sealed"] {
        let next = File::from(
            rustix::fs::openat(
                ancestry.last().expect("held native journal parent"),
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
        original_ancestry.push((
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.mode(),
        ));
        ancestry.push(next);
    }
    let names = [
        "/",
        "/var",
        "/var/lib",
        "/var/lib/memcordon",
        "/var/lib/memcordon/sealed",
    ];
    let verify_ancestry = || -> Result<()> {
        for (index, name) in names.iter().enumerate() {
            let named = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(name)?;
            let held = ancestry[index].metadata()?;
            let current = named.metadata()?;
            if (held.dev(), held.ino(), held.uid(), held.mode()) != original_ancestry[index]
                || (current.dev(), current.ino(), current.uid(), current.mode())
                    != original_ancestry[index]
                || held.nlink() == 0
                || current.nlink() == 0
                || held.uid() != 0
                || held.mode() & 0o022 != 0
                || current.uid() != 0
                || current.mode() & 0o022 != 0
            {
                return Err(CiError::Message(
                    "actual lifecycle journal ancestor replaced during phase capture".into(),
                ));
            }
        }
        Ok(())
    };
    let mut expected = None;
    let mut advances = 0_u64;
    let mut history = std::collections::VecDeque::new();
    loop {
        verify_ancestry()?;
        let capture = super::linux_phase_journal::capture(
            ancestry.last().expect("held sealed journal directory"),
            attempt,
            0,
            expected.as_ref(),
            deadline,
        );
        let diagnostic = capture.diagnostic();
        verify_ancestry()?;
        match capture {
            super::linux_phase_journal::Capture::Stable(snapshot) => {
                if Instant::now() >= deadline {
                    return Err(CiError::Message(format!(
                        "actual lifecycle journal original cutoff expired before custody commit; advances={advances}; history={history:?}"
                    )));
                }
                let (bytes, record, held) = (snapshot.bytes, snapshot.record, snapshot.held);
                owners.append(&mut ancestry);
                owners.push(held);
                return Ok((bytes, record));
            }
            super::linux_phase_journal::Capture::GenerationAdvanced { association, .. } => {
                advances = advances.saturating_add(1);
                if history.len() == 8 {
                    history.pop_front();
                }
                history.push_back(diagnostic);
                if expected.is_none() {
                    expected = Some(association);
                }
                std::thread::yield_now();
            }
            _ => {
                return Err(CiError::Message(format!(
                    "actual lifecycle journal capture failed; attempt={attempt}; advances={advances}; diagnostic={diagnostic}; history={history:?}"
                )));
            }
        }
    }
}
