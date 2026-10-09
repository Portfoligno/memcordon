//! Retained native owners for installed Linux limit observations.
use super::linux_mixed_installed::{
    CompletedMixedCollection, InstalledMixedLaunch, InstalledMixedLaunchInput, OwnedMixedRecipe,
};
use crate::consumer_readiness_ledger::SourceIdentity;
use crate::{CiError, Result};
use memcordon_readiness_verifier::CaseKey;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

pub struct LimitsContext<'a> {
    pub identity: &'a SourceIdentity,
    pub cell: &'a memcordon_readiness_verifier::ProductKey,
    pub provider: &'a memcordon_core::PublicProviderBindingV1,
    pub contract: &'a memcordon_core::workload_contract_v3::WorkloadContractV3,
    pub contract_path: &'a Path,
    pub artifact_root: &'a Path,
    pub lease_id: &'a str,
    pub selected_cli_sha256: &'a str,
    pub selected_agent_sha256: &'a str,
    pub work_deadline: Instant,
    pub cleanup_deadline: Instant,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
}

#[derive(Default)]
pub struct LimitsReport {
    original_work_deadline: Option<Instant>,
    original_cleanup_deadline: Option<Instant>,
    pub owners: Vec<OwnedMixedRecipe>,
    pub completed: Vec<(CaseKey, CompletedMixedCollection)>,
    pub failures: Vec<(CaseKey, String)>,
    pub cleanup_failures: Vec<String>,
    controller_owners: Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    pub controller_actions: Vec<serde_json::Value>,
    controller_action_files: Vec<std::fs::File>,
    memory_workers: Vec<crate::linux_consumer_readiness::HeldLinuxProcess>,
    memory_resume_required: std::collections::BTreeSet<usize>,
    memory_files: Vec<std::fs::File>,
    memory_directories: Vec<std::fs::File>,
    memory_intervals: Vec<MemoryEventInterval>,
}

pub struct MemoryEventInterval {
    group: std::fs::File,
    events: std::fs::File,
    maximum: std::fs::File,
    before: Vec<u8>,
    key: CaseKey,
    attempt: String,
    worker_index: usize,
}

fn read_memory_counter_file(file: &std::fs::File, deadline: Instant) -> Result<Vec<u8>> {
    use std::os::unix::fs::{FileExt, MetadataExt};
    remaining(deadline)?;
    let before = file.metadata()?;
    if !before.is_file() || before.uid() != 0 || before.mode() & 0o022 != 0 {
        return Err(CiError::Message(
            "held native memory counter protection differs".into(),
        ));
    }
    let mut bytes = vec![0u8; 65537];
    let mut length = 0;
    loop {
        remaining(deadline)?;
        let count = file.read_at(&mut bytes[length..], length as u64)?;
        if count == 0 {
            break;
        }
        length += count;
        if length > 65536 {
            return Err(CiError::Message(
                "native memory counter exceeds bound".into(),
            ));
        }
    }
    let after = file.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.uid(),
        before.mode(),
        before.nlink(),
    ) != (
        after.dev(),
        after.ino(),
        after.uid(),
        after.mode(),
        after.nlink(),
    ) {
        return Err(CiError::Message(
            "native memory counter identity changed".into(),
        ));
    }
    bytes.truncate(length);
    remaining(deadline)?;
    Ok(bytes)
}

fn memory_counters(bytes: &[u8]) -> Result<std::collections::BTreeMap<String, u64>> {
    let text = std::str::from_utf8(bytes).map_err(|error| CiError::Message(error.to_string()))?;
    let mut result = std::collections::BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let name = fields
            .next()
            .ok_or_else(|| CiError::Message("memory counter name absent".into()))?;
        let value = fields
            .next()
            .ok_or_else(|| CiError::Message("memory counter value absent".into()))?;
        if fields.next().is_some()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || result.contains_key(name)
        {
            return Err(CiError::Message(
                "native memory counters duplicated/malformed".into(),
            ));
        }
        let parsed = value
            .parse::<u64>()
            .map_err(|error| CiError::Message(error.to_string()))?;
        if parsed.to_string() != value {
            return Err(CiError::Message(
                "native memory counter decimal differs".into(),
            ));
        }
        result.insert(name.to_owned(), parsed);
    }
    if result.keys().map(String::as_str).collect::<Vec<_>>()
        != ["high", "low", "max", "oom", "oom_group_kill", "oom_kill"]
    {
        return Err(CiError::Message(
            "native memory event inventory differs".into(),
        ));
    }
    Ok(result)
}

/// Arm actual selected cgroup counters only after the journalled worker is
/// independently observed stopped. The allocator release remains caller-owned.
pub fn arm_memory_events(
    report: &mut LimitsReport,
    observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
    key: &CaseKey,
    worker_index: usize,
    deadline: Instant,
) -> Result<usize> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    if report.original_work_deadline != Some(deadline)
        || !matches!(
            (key.family.as_str(), key.scenario.as_str()),
            ("C-STATUS", "memory") | ("L-LIFE-03", "memory")
        )
    {
        return Err(CiError::Message(
            "memory interval differs from original work cutoff/frozen memory key".into(),
        ));
    }
    let worker = report
        .memory_workers
        .get(worker_index)
        .ok_or_else(|| CiError::Message("memory interval worker owner absent".into()))?;
    if !report.memory_resume_required.contains(&worker_index) {
        return Err(CiError::Message(
            "memory interval lacks original resume obligation".into(),
        ));
    }
    observe_stopped_worker(worker, deadline, &mut report.memory_files)?;
    let group = observer
        .retain_cgroup_descriptor()
        .map_err(CiError::Message)?;
    let events = std::fs::File::from(
        rustix::fs::openat(
            &group,
            "memory.events",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| CiError::Message(error.to_string()))?,
    );
    let maximum = std::fs::File::from(
        rustix::fs::openat(
            &group,
            "memory.max",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|error| CiError::Message(error.to_string()))?,
    );
    let index = report.memory_intervals.len();
    report.memory_intervals.push(MemoryEventInterval {
        group,
        events,
        maximum,
        before: Vec::new(),
        key: key.clone(),
        attempt: observer
            .observation
            .admission
            .attempt_id
            .as_str()
            .to_owned(),
        worker_index,
    });
    let interval = &mut report.memory_intervals[index];
    if rustix::fs::fstatfs(&interval.group)
        .map_err(|error| CiError::Message(error.to_string()))?
        .f_type as u64
        != 0x63677270
        || interval.group.metadata()?.nlink() == 0
    {
        return Err(CiError::Message(
            "memory interval actual selected cgroup is absent/notcgroup2".into(),
        ));
    }
    interval.before = read_memory_counter_file(&interval.events, deadline)?;
    if memory_counters(&interval.before)?["oom_kill"] != 0 {
        return Err(CiError::Message(
            "memory interval already observed OOM before allocator release".into(),
        ));
    }
    let maximum = read_memory_counter_file(&interval.maximum, deadline)?;
    let limit = std::str::from_utf8(&maximum)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .parse::<u64>()
        .map_err(|error| CiError::Message(error.to_string()))?;
    let expected_limit = if key.family == "L-LIFE-03" {
        512 * 1024 * 1024
    } else {
        128 * 1024 * 1024
    };
    if limit != expected_limit {
        return Err(CiError::Message(
            "native memory maximum differs from actual selected memory budget".into(),
        ));
    }
    observe_stopped_worker(
        &report.memory_workers[worker_index],
        deadline,
        &mut report.memory_files,
    )?;
    let stamp = interval.group.metadata()?;
    let events_stamp = interval.events.metadata()?;
    let maximum_stamp = interval.maximum.metadata()?;
    let membership_path = Path::new("/proc")
        .join(observer.target.process_id.to_string())
        .join("cgroup");
    let membership = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&membership_path)?;
    report.memory_files.push(membership.try_clone()?);
    let mut membership_bytes = Vec::new();
    std::io::Read::take(&membership, 4097).read_to_end(&mut membership_bytes)?;
    if membership_bytes.len() > 4096 || observer.target.exited().map_err(CiError::Message)? {
        return Err(CiError::Message(
            "memory interval target membership changed/exceeded bound".into(),
        ));
    }
    report.controller_actions.push(serde_json::json!({"format":"memcordon.linux-memory-events-armed","revision":1,"key":key,
        "attempt_id":interval.attempt,"worker_index":worker_index,"group_device":stamp.dev(),"group_inode":stamp.ino(),
        "events_device":events_stamp.dev(),"events_inode":events_stamp.ino(),"maximum_device":maximum_stamp.dev(),"maximum_inode":maximum_stamp.ino(),
        "target":{"pid":observer.target.process_id,"birth":observer.target.birth},"target_membership":membership_bytes,
        "before":interval.before,"memory_max":maximum}));
    Ok(index)
}

/// Wait for actual kernel OOM evidence while the same selected worker remains
/// stopped. Returning does not resume or relinquish any owner.
pub fn observe_memory_oom(
    report: &mut LimitsReport,
    index: usize,
    deadline: Instant,
) -> Result<serde_json::Value> {
    use std::os::unix::fs::MetadataExt;
    if report.original_work_deadline != Some(deadline) {
        return Err(CiError::Message(
            "memory observation differs from original work cutoff".into(),
        ));
    }
    let interval = report
        .memory_intervals
        .get(index)
        .ok_or_else(|| CiError::Message("armed memory interval absent".into()))?;
    let before = memory_counters(&interval.before)?;
    loop {
        remaining(deadline)?;
        if report.memory_workers[interval.worker_index]
            .exited()
            .map_err(CiError::Message)?
        {
            return Err(CiError::Message(
                "stopped native memory worker exited during counter interval".into(),
            ));
        }
        let after_bytes = read_memory_counter_file(&interval.events, deadline)?;
        let after = memory_counters(&after_bytes)?;
        if before.iter().any(|(name, value)| after[name] < *value) {
            return Err(CiError::Message(
                "native memory counters moved backwards".into(),
            ));
        }
        if after["oom_kill"] > before["oom_kill"] && after["oom"] > before["oom"] {
            observe_stopped_worker(
                &report.memory_workers[interval.worker_index],
                deadline,
                &mut report.memory_files,
            )?;
            let stamp = interval.group.metadata()?;
            let events_stamp = interval.events.metadata()?;
            let maximum_stamp = interval.maximum.metadata()?;
            if stamp.nlink() == 0 {
                return Err(CiError::Message(
                    "selected cgroup retired before OOM interval capture".into(),
                ));
            }
            let receipt = serde_json::json!({"format":"memcordon.linux-memory-events-transition","revision":1,"key":interval.key,
                "attempt_id":interval.attempt,"worker_index":interval.worker_index,"group_device":stamp.dev(),"group_inode":stamp.ino(),
                "events_device":events_stamp.dev(),"events_inode":events_stamp.ino(),"maximum_device":maximum_stamp.dev(),"maximum_inode":maximum_stamp.ino(),
                "before":interval.before,"after":after_bytes});
            remaining(deadline)?;
            report.controller_actions.push(receipt.clone());
            return Ok(receipt);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

impl LimitsReport {
    /// Persist original controller observations while their native owners are
    /// still held. These factual bytes supply no runtime authority.
    fn persist_controller_actions(&mut self, directory: &Path, deadline: Instant) -> Result<()> {
        use std::io::{Read, Write};
        remaining(deadline)?;
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory)?;
        for (index, action) in self.controller_actions.iter().enumerate() {
            let path = directory.join(format!("controller-action-{index}.json"));
            let bytes = serde_json::to_vec(action)?;
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
            {
                Ok(mut file) => {
                    self.controller_action_files.push(file.try_clone()?);
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&path)?;
                    use std::os::unix::fs::MetadataExt;
                    let metadata = file.metadata()?;
                    if !metadata.is_file()
                        || metadata.nlink() != 1
                        || metadata.uid() != 0
                        || metadata.mode() & 0o7777 != 0o600
                        || metadata.len() != bytes.len() as u64
                    {
                        return Err(CiError::Message(
                            "controller action named custody differs".into(),
                        ));
                    }
                    let mut actual = Vec::new();
                    std::io::Read::take(&file, bytes.len() as u64 + 1).read_to_end(&mut actual)?;
                    if actual != bytes {
                        return Err(CiError::Message(
                            "controller action named bytes differ".into(),
                        ));
                    }
                }
                Err(error) => return Err(error.into()),
            }
            remaining(deadline)?;
        }
        parent.sync_all()?;
        Ok(())
    }
    /// Actual owner settlement is independent of retained operation failures.
    pub fn native_owners_settled(&self) -> bool {
        self.owners.is_empty()
            && self.controller_owners.is_empty()
            && self.memory_workers.is_empty()
            && self.memory_resume_required.is_empty()
    }
}

/// Retain the genuinely journalled selected worker before any controller stop.
/// Its resume obligation is recorded even when the signal/observation fails.
pub fn pause_memory_worker(
    report: &mut LimitsReport,
    observer: &crate::linux_consumer_readiness::PreparedLinuxObserver,
    context: &LimitsContext<'_>,
    key: &CaseKey,
    directory: &Path,
    challenge: &str,
) -> Result<serde_json::Value> {
    use std::io::{Read, Write};
    use std::os::unix::fs::MetadataExt;
    if context.work_deadline >= context.cleanup_deadline
        || report
            .original_work_deadline
            .is_some_and(|original| original != context.work_deadline)
        || report
            .original_cleanup_deadline
            .is_some_and(|original| original != context.cleanup_deadline)
        || key.target != context.cell.target
        || key.channel.as_deref() != Some(context.cell.channel.as_str())
        || !matches!(
            (key.family.as_str(), key.scenario.as_str()),
            ("C-STATUS", "memory") | ("L-LIFE-03", "memory")
        )
        || observer.observation.provider != *context.provider
        || observer.observation.admission.request != *context.contract
    {
        return Err(CiError::Message(
            "memory controller original owner/request differs".into(),
        ));
    }
    report.original_work_deadline = Some(context.work_deadline);
    report.original_cleanup_deadline = Some(context.cleanup_deadline);
    remaining(context.work_deadline)?;
    let parent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)?;
    let parent_identity = parent.metadata()?;
    report.memory_directories.push(parent);
    if parent_identity.uid() != 0
        || parent_identity.mode() & 0o022 != 0
        || parent_identity.nlink() == 0
    {
        return Err(CiError::Message(
            "memory controller intent parent is not owned protected directory".into(),
        ));
    }
    let original_workers = report.memory_workers.len();
    let source = super::linux_readiness_image_cases::retain_prepared_worker(
        observer,
        context.selected_agent_sha256,
        context.work_deadline,
        &mut report.memory_directories,
        &mut report.memory_files,
        &mut report.memory_workers,
    )?;
    if report.memory_workers.len() != original_workers + 1 {
        return Err(CiError::Message(
            "memory controller worker acquisition count differs".into(),
        ));
    }
    let worker_index = original_workers;
    let identity = report.memory_workers[worker_index]
        .retirement_identity()
        .map_err(CiError::Message)?;
    let intent = serde_json::json!({"format":"memcordon.linux-memory-worker-stop-intent","revision":1,"source":context.identity,"cell":context.cell,
        "lease_id":context.lease_id,"key":key,"challenge":challenge,"worker":identity,"selected_worker_source":source,"signal":19});
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("memory-worker-stop-intent.json"))?;
    report.memory_files.push(file);
    let file = report
        .memory_files
        .last_mut()
        .expect("retained memory stop intent");
    let intent_bytes = serde_json::to_vec(&intent)?;
    file.write_all(&intent_bytes)?;
    file.sync_all()?;
    let held = file.metadata()?;
    let named = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("memory-worker-stop-intent.json"))?;
    let metadata = named.metadata()?;
    if !held.is_file()
        || held.nlink() != 1
        || held.uid() != 0
        || held.mode() & 0o7777 != 0o600
        || (
            held.dev(),
            held.ino(),
            held.len(),
            held.ctime(),
            held.ctime_nsec(),
            held.uid(),
            held.mode(),
            held.nlink(),
        ) != (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.ctime(),
            metadata.ctime_nsec(),
            metadata.uid(),
            metadata.mode(),
            metadata.nlink(),
        )
    {
        return Err(CiError::Message(
            "memory worker stop intent native named identity changed".into(),
        ));
    }
    let mut actual = Vec::new();
    std::io::Read::take(&named, (intent_bytes.len() + 1) as u64).read_to_end(&mut actual)?;
    if actual != intent_bytes {
        return Err(CiError::Message(
            "memory worker stop intent named bytes changed".into(),
        ));
    }
    let named_parent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)?;
    let current = named_parent.metadata()?;
    if (
        parent_identity.dev(),
        parent_identity.ino(),
        parent_identity.uid(),
        parent_identity.mode(),
    ) != (current.dev(), current.ino(), current.uid(), current.mode())
    {
        return Err(CiError::Message("memory stop intent parent changed".into()));
    }
    named_parent.sync_all()?;
    remaining(context.work_deadline)?;
    report.memory_resume_required.insert(worker_index);
    let signal = report.memory_workers[worker_index]
        .signal_stop()
        .map_err(CiError::Message)?;
    let action = serde_json::json!({"format":"memcordon.linux-memory-worker-stop","revision":1,"worker":identity,"signal":19,
        "syscall_succeeded":signal.is_ok(),"native_errno":signal.err()});
    report.controller_actions.push(action.clone());
    if signal.is_err() {
        return Err(CiError::Message(
            "selected native worker stop syscall failed".into(),
        ));
    }
    let stopped = observe_stopped_worker(
        &report.memory_workers[worker_index],
        context.work_deadline,
        &mut report.memory_files,
    )?;
    report.controller_actions.push(serde_json::json!({"format":"memcordon.linux-memory-worker-stopped","revision":1,
        "key":key,"attempt_id":observer.observation.admission.attempt_id,"worker":identity,"selected_worker_source":source,"actual_stop":action,"stopped":stopped}));
    Ok(serde_json::json!({"selected_worker_source":source,"actual_stop":action,"stopped":stopped}))
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        return Err(CiError::Message(
            "original limit-case cutoff exhausted".into(),
        ));
    }
    Ok(duration)
}

/// Observe the kernel stop state of the same retained worker. A successful
/// signal call alone does not establish this pre-allocation boundary.
pub fn observe_stopped_worker(
    worker: &crate::linux_consumer_readiness::HeldLinuxProcess,
    deadline: Instant,
    retained_files: &mut Vec<std::fs::File>,
) -> Result<serde_json::Value> {
    use std::io::{Read, Seek, SeekFrom};
    let path = Path::new("/proc")
        .join(worker.process_id.to_string())
        .join("stat");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    retained_files.push(file);
    let file = retained_files
        .last_mut()
        .expect("retained native worker stat");
    loop {
        remaining(deadline)?;
        if worker.exited().map_err(CiError::Message)?
            || crate::linux_consumer_readiness::process_birth(worker.process_id)
                .map_err(CiError::Message)?
                != worker.birth
        {
            return Err(CiError::Message(
                "retained worker changed before stop observation".into(),
            ));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut *file).take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(CiError::Message(
                "native worker stat exceeds finite bound".into(),
            ));
        }
        let opening = bytes
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| CiError::Message("native worker stat lacks PID".into()))?;
        let observed_pid = std::str::from_utf8(&bytes[..opening])
            .map_err(|error| CiError::Message(error.to_string()))?
            .parse::<u32>()
            .map_err(|error| CiError::Message(error.to_string()))?;
        if observed_pid != worker.process_id {
            return Err(CiError::Message("native worker stat PID differs".into()));
        }
        let closing = bytes
            .iter()
            .rposition(|byte| *byte == b')')
            .ok_or_else(|| CiError::Message("native worker stat has no command boundary".into()))?;
        let state = bytes
            .get(closing + 2)
            .copied()
            .ok_or_else(|| CiError::Message("native worker stat lacks state".into()))?;
        let fields = std::str::from_utf8(&bytes[closing + 2..])
            .map_err(|error| CiError::Message(error.to_string()))?
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        let observed_birth = fields
            .get(19)
            .ok_or_else(|| CiError::Message("native worker stat lacks birth".into()))?
            .parse::<u64>()
            .map_err(|error| CiError::Message(error.to_string()))?;
        if observed_birth != worker.birth
            || worker.exited().map_err(CiError::Message)?
            || crate::linux_consumer_readiness::process_birth(worker.process_id)
                .map_err(CiError::Message)?
                != worker.birth
        {
            return Err(CiError::Message(
                "native worker changed during stop observation".into(),
            ));
        }
        if matches!(state, b'T' | b't') {
            remaining(deadline)?;
            return Ok(
                serde_json::json!({"format":"memcordon.linux-limit-worker-stopped","revision":1,
                "process_id":worker.process_id,"birth":worker.birth,"state":char::from(state).to_string(),
                "native_stat_bytes":bytes}),
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The caller retains this report before invoking any case. It supplies an
/// already activated genuine policy and caller-traversable owned directory.
pub fn run_case(
    report: &mut LimitsReport,
    context: &LimitsContext<'_>,
    key: CaseKey,
    directory: &Path,
    prefix: &str,
    challenge: &str,
) -> Result<()> {
    let outcome = (|| -> Result<()> {
        if context.work_deadline >= context.cleanup_deadline
            || key.target != context.cell.target
            || key.channel.as_deref() != Some(context.cell.channel.as_str())
            || !matches!(
                key.target.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
            || key.evidence_class != memcordon_readiness_verifier::EvidenceClass::InstalledProduct
            || key.channel.is_none()
            || context.lease_id.is_empty()
            || !directory.is_absolute()
            || !context.artifact_root.is_absolute()
            || prefix
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
            || prefix.contains(['\\', ':'])
        {
            return Err(CiError::Message(
                "limit-case original owner association differs".into(),
            ));
        }
        let challenge_bytes =
            hex::decode(challenge).map_err(|error| CiError::Message(error.to_string()))?;
        if challenge_bytes.len() != 32 || challenge_bytes.iter().all(|byte| *byte == 0) {
            return Err(CiError::Message(
                "limit-case native challenge differs".into(),
            ));
        }
        if report
            .original_cleanup_deadline
            .is_some_and(|original| original != context.cleanup_deadline)
            || report
                .original_work_deadline
                .is_some_and(|original| original != context.work_deadline)
        {
            return Err(CiError::Message(
                "limit report original cleanup owner changed".into(),
            ));
        }
        let (mode, memory, deadline, raw) = match (key.family.as_str(), key.scenario.as_str()) {
            ("C-STATUS", "deadline") => ("population-deadline", "+2GiB", "+30s", false),
            ("C-STATUS", "memory") => ("memory-pressure-descendant", "+128M", "+300s", false),
            ("L-LIFE-03", "memory") => ("joint-memory", "+512M", "+300s", false),
            ("L-LIFE-03", "deadline") => ("joint", "+2GiB", "+300s", false),
            ("L-LIFE-03", "cancellation") => ("joint", "+2GiB", "+300s", false),
            ("L-LIFE-03", "reserved-target-exit") => {
                ("joint-reserved-exit", "+2GiB", "+300s", false)
            }
            ("C-IO", "bounded-large-output") | ("L-MIX-05", "bounded-large-output") => {
                ("bounded-large-output", "+256M", "+30s", true)
            }
            ("L-LIFE-05", "relay-backpressure") => ("bounded-large-output", "+256M", "+30s", true),
            _ => {
                return Err(CiError::Message(
                    "case does not belong to this concrete limit mechanism".into(),
                ));
            }
        };
        let mut arguments = vec![
            std::ffi::OsString::from(mode),
            std::ffi::OsString::from(challenge),
        ];
        if matches!(mode, "joint" | "joint-reserved-exit" | "joint-memory") {
            use memcordon_core::workload_contract_v3::RequirementV3;
            let requirements = context.contract.requirements.as_slice();
            let required = [
                requirements
                    .iter()
                    .any(|value| matches!(value, RequirementV3::TcpListener { .. })),
                requirements
                    .iter()
                    .any(|value| matches!(value, RequirementV3::UnixStreamPair { .. })),
                requirements
                    .iter()
                    .any(|value| matches!(value, RequirementV3::UnixPathStream { .. })),
                requirements
                    .iter()
                    .any(|value| matches!(value, RequirementV3::UnixAbstractStream { .. })),
                requirements.iter().any(|value| {
                    matches!(value, RequirementV3::IntraAttemptDescriptorTransfer { .. })
                }),
                requirements
                    .iter()
                    .any(|value| matches!(value, RequirementV3::GeneratedExecutable { .. })),
            ];
            if required.iter().any(|present| !present) {
                return Err(CiError::Message(
                    "mixed limit requires the actual complete joint contract".into(),
                ));
            }
            arguments.extend(
                [
                    "/work",
                    "/toolchain/bin/cargo",
                    "/toolchain/bin/rustc",
                    "/usr/bin/cc",
                    "/owned-source/Cargo.toml",
                ]
                .into_iter()
                .map(std::ffi::OsString::from),
            );
        }
        remaining(context.work_deadline)?;
        report.original_cleanup_deadline = Some(context.cleanup_deadline);
        report.original_work_deadline = Some(context.work_deadline);
        let backpressure = key.family == "L-LIFE-05" && key.scenario == "relay-backpressure";
        let launch = InstalledMixedLaunch::start_with_delivery_controls(
            InstalledMixedLaunchInput {
                directory,
                contract: context.contract_path,
                caller_uid: 65534,
                caller_gid: 65534,
                target_arguments: &arguments,
                deadline: std::ffi::OsStr::new(deadline),
                memory: std::ffi::OsStr::new(memory),
            },
            false,
            backpressure.then_some(context.work_deadline),
        )?;
        report.owners.push(OwnedMixedRecipe {
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
        // The local owner remains live across every fallible callback and is
        // restored before propagating the operation result to the finalizer.
        let mut owner = report.owners.pop().expect("retained native creation owner");
        let operation = (|| -> Result<()> {
            let observer = owner.launch.acquire_prepared(
                context.provider,
                context.contract,
                context.artifact_root,
                &format!("{prefix}/prepared.json"),
                remaining(context.work_deadline)?,
            )?;
            owner.observer = Some(observer);
            let observer = owner.observer.as_ref().expect("retained native observer");
            owner.prepared_native_receipt = Some(
                observer
                    .persist_native_receipt(
                        &context.identity.run_id,
                        context.artifact_root,
                        &format!("{prefix}/prepared-native-before-ack.json"),
                    )
                    .map_err(CiError::Message)?,
            );
            observer
                .acknowledge(&owner.launch.observation_directory)
                .map_err(CiError::Message)?;
            if raw {
                owner.launch.frontend.stdin.take();
                if backpressure {
                    loop {
                        remaining(context.work_deadline)?;
                        let receipt = owner.launch.retained_output_backpressure()?;
                        let pipes = receipt["pipes"].as_array().ok_or_else(|| {
                            CiError::Message("actual output pipe census absent".into())
                        })?;
                        if pipes.iter().any(|pipe| {
                            pipe["queued_bytes"]
                                .as_u64()
                                .zip(pipe["capacity_bytes"].as_u64())
                                .is_some_and(|(queued, capacity)| {
                                    capacity > 0 && queued == capacity
                                })
                        }) {
                            report.controller_actions.push(receipt);
                            report.persist_controller_actions(directory, context.work_deadline)?;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    owner.launch.resume_output_capture()?;
                    report.controller_actions.push(serde_json::json!({"format":"memcordon.linux-output-capture-resumed","revision":1,"key":key,"capture_resumed":true}));
                    report.persist_controller_actions(directory, context.work_deadline)?;
                }
                owner
                    .launch
                    .wait_and_capture(remaining(context.work_deadline)?)?;
            } else {
                let hold_joint = key.family == "L-LIFE-03"
                    && matches!(key.scenario.as_str(), "deadline" | "cancellation");
                let cancel_joint = key.family == "L-LIFE-03" && key.scenario == "cancellation";
                let mut joint_barrier_held = false;
                owner.launch.observe_fixture_with_release_observation(
                observer,
                challenge,
                &mut owner.held,
                &mut owner.transcript,
                remaining(context.work_deadline)?,
                |row, frontend_pid, released| {
                    if released {
                        if row.operation == "memory-pressure-descendant-held" {
                            let index = report.memory_intervals.len().checked_sub(1)
                                .ok_or_else(|| CiError::Message("memory allocator lacks armed native interval".into()))?;
                            observe_memory_oom(report, index, context.work_deadline)?;
                            let worker_index = report.memory_intervals[index].worker_index;
                            let resumed = report.memory_workers[worker_index].signal_continue().map_err(CiError::Message)?;
                            report.controller_actions.push(serde_json::json!({"format":"memcordon.linux-memory-worker-resume","revision":1,
                                "worker":report.memory_workers[worker_index].retirement_identity().map_err(CiError::Message)?,
                                "signal":18,"syscall_succeeded":resumed.is_ok(),"native_errno":resumed.err()}));
                            if resumed.is_err() { return Err(CiError::Message("selected memory worker resume failed; original obligation retained".into())); }
                            report.memory_resume_required.remove(&worker_index);
                            report.persist_controller_actions(directory, context.work_deadline)?;
                        }
                        return Ok(super::linux_mixed_installed::FixtureBarrierDecision::Continue);
                    }
                    if row.operation == "memory-pressure-descendant-held" {
                        pause_memory_worker(report, observer, context, &key, directory, challenge)?;
                        let worker_index = report.memory_workers.len().checked_sub(1)
                            .ok_or_else(|| CiError::Message("memory worker owner absent".into()))?;
                        arm_memory_events(report, observer, &key, worker_index, context.work_deadline)?;
                        report.persist_controller_actions(directory, context.work_deadline)?;
                    }
                    if row.operation == "population-held-until-native-deadline" {
                        report.controller_actions.push(serde_json::from_slice(&std::fs::read(directory.join("native-deadline-population.json"))?)?);
                        report.persist_controller_actions(directory, context.work_deadline)?;
                    }
                    Ok(
                        if hold_joint && row.operation == "joint-generated-child-held" {
                            joint_barrier_held = true;
                            if cancel_joint {
                                use std::io::Write;
                                let birth = crate::linux_consumer_readiness::process_birth(frontend_pid).map_err(CiError::Message)?;
                                let controller = crate::linux_consumer_readiness::HeldLinuxProcess::acquire(frontend_pid, birth).map_err(CiError::Message)?;
                                report.controller_owners.push(controller);
                                let controller = report.controller_owners.last_mut().expect("retained frontend PIDFD owner");
                                let image = controller.hold_executable_image(context.work_deadline).map_err(CiError::Message)?;
                                if image["sha256"] != context.selected_cli_sha256 {
                                    return Err(CiError::Message("held cancellation frontend image differs from selected CLI".into()));
                                }
                                let identity = controller.retirement_identity().map_err(CiError::Message)?;
                                let intent = serde_json::json!({"format":"memcordon.linux-limit-controller-interrupt-intent","revision":1,
                                    "run_id":context.identity.run_id,"lease_id":context.lease_id,"key":key,"challenge":challenge,
                                    "held_frontend":identity,"image":image,"barrier_sequence":row.sequence,"barrier_operation":row.operation,"signal":2});
                                let intent_file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
                                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(directory.join("controller-interrupt-intent.json"))?;
                                report.controller_action_files.push(intent_file);
                                let intent_file = report.controller_action_files.last_mut().expect("retained controller intent owner");
                                intent_file.write_all(&serde_json::to_vec(&intent)?)?;
                                intent_file.sync_all()?;
                                std::fs::File::open(directory)?.sync_all()?;
                                let actual = controller.signal_interrupt().map_err(CiError::Message)?;
                                let action = serde_json::json!({"format":"memcordon.linux-limit-controller-interrupt","revision":1,
                                    "run_id":context.identity.run_id,"lease_id":context.lease_id,"key":key,"challenge":challenge,
                                    "held_frontend":identity,"image":image,"barrier_sequence":row.sequence,"barrier_operation":row.operation,
                                    "signal":2,"syscall_succeeded":actual.is_ok(),"native_errno":actual.err()});
                                report.controller_actions.push(action.clone());
                                let file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
                                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(directory.join("controller-interrupt.json"))?;
                                report.controller_action_files.push(file);
                                let file = report.controller_action_files.last_mut().expect("retained controller receipt owner");
                                file.write_all(&serde_json::to_vec(&action)?)?;
                                file.sync_all()?;
                                std::fs::File::open(directory)?.sync_all()?;
                                if actual.is_err() { return Err(CiError::Message("actual frontend interrupt syscall failed".into())); }
                            }
                            super::linux_mixed_installed::FixtureBarrierDecision::WithholdRelease
                        } else {
                            super::linux_mixed_installed::FixtureBarrierDecision::Continue
                        },
                    )
                },
            )?;
                if hold_joint && !joint_barrier_held {
                    return Err(CiError::Message(
                        "mixed deadline lacked the actual held build/socket barrier".into(),
                    ));
                }
            }
            let mut collected = owner.launch.collect_completed(
                observer,
                &owner.held,
                context.identity.clone(),
                context.lease_id.to_owned(),
                key.clone(),
                challenge.to_owned(),
                prefix.to_owned(),
                context.contract_path,
                context.artifact_root,
                remaining(context.work_deadline)?,
            )?;
            collected.prepared_native_receipt = owner
                .prepared_native_receipt
                .as_ref()
                .expect("native receipt persisted before ACK")
                .clone();
            collected
                .persisted
                .artifacts
                .push(collected.prepared_native_receipt.clone());
            report.completed.push((key.clone(), collected));
            Ok(())
        })();
        report.owners.push(owner);
        operation
    })();
    if let Err(error) = &outcome {
        report.failures.push((key, error.to_string()));
    }
    outcome
}

/// Projects actual captured effects after complete native retirement. Expected
/// behavior remains in the independent decoder, never in these documents.
pub fn normalize_completed(
    collection: &mut CompletedMixedCollection,
    actions: &[serde_json::Value],
    images: &super::linux_mixed_installed::MixedImages,
    input: &super::linux_mixed_installed::InstalledMixedDriverInput<'_>,
    prefix: &str,
    selected_agent_sha256: &str,
) -> Result<()> {
    use memcordon_readiness_verifier::{
        Artifact, BehaviorArtifact, ByteComparison, FixtureBehavior, FixtureInput, NativeArguments,
        OperationObservation, SemanticObservation,
    };
    let key = collection.persisted.key.clone();
    let original_artifact_paths = collection
        .persisted
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut persist = |name: &str, bytes: &[u8]| -> Result<Artifact> {
        remaining(input.cleanup_deadline)?;
        let path = format!("{prefix}/{name}");
        let output = input.artifact_root.join(&path);
        std::fs::create_dir_all(
            output
                .parent()
                .ok_or_else(|| CiError::Message("limit artifact parent absent".into()))?,
        )?;
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&output)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::File::open(
            output
                .parent()
                .ok_or_else(|| CiError::Message("limit artifact parent absent".into()))?,
        )?
        .sync_all()?;
        let artifact = Artifact {
            path,
            length: bytes.len() as u64,
            sha256: super::artifacts::checksum(bytes),
        };
        collection.persisted.artifacts.push(artifact.clone());
        Ok(artifact)
    };
    let public = memcordon_core::mixed_runtime::MixedRuntimeRequest::parse(&std::fs::read(
        input
            .artifact_root
            .join(format!("{prefix}/provider-request.json")),
    )?)
    .map_err(CiError::Message)?;
    let (effective, environment) = super::linux_mixed_installed::reconstruct_effective_invocation(
        &public,
        images,
        match &collection.result.runtime.outcome {
            memcordon_core::result_v2::MixedRuntimeOutcomeV2::Executed { admission, .. } => {
                admission
            }
            _ => {
                return Err(CiError::Message(
                    "limit projection has no actual executed result".into(),
                ));
            }
        },
    )?;
    collection.effective_invocation = Some(persist("effective-invocation.bin", &effective)?);
    collection.effective_environment = Some(persist(
        "effective-environment.json",
        &serde_json::to_vec(&environment)?,
    )?);
    let controller = persist(
        "limit-controller-actions.json",
        &serde_json::to_vec(actions)?,
    )?;
    let agent_bytes = super::linux_mixed_installed::read_owned_resource(
        Path::new("/usr/libexec/memcordon-sealed-agent"),
        512 * 1024 * 1024,
    )?;
    if super::artifacts::checksum(&agent_bytes) != selected_agent_sha256 {
        return Err(CiError::Message(
            "selected installed agent changed across limit execution".into(),
        ));
    }
    let agent = persist("limit-agent-image.bin", &agent_bytes)?;
    let invocation: memcordon_readiness_verifier::NativeInvocation = serde_json::from_slice(
        &std::fs::read(input.artifact_root.join(&collection.public_invocation.path))?,
    )?;
    let NativeArguments::UnixBytes(public_argv) = &invocation.arguments else {
        return Err(CiError::Message(
            "limit native argv encoding differs".into(),
        ));
    };
    if public_argv.first().map(Vec::as_slice) != Some(b"owned-readiness") {
        return Err(CiError::Message("limit public entrypoint differs".into()));
    }
    let challenge = std::fs::read(input.artifact_root.join(format!("{prefix}/challenge.bin")))?;
    let budget = match (key.family.as_str(), key.scenario.as_str()) {
        ("C-STATUS", "deadline") => (Some(30_000), Some(2 * 1024 * 1024 * 1024)),
        ("C-STATUS", "memory") => (Some(300_000), Some(128 * 1024 * 1024)),
        ("L-LIFE-03", "memory") => (Some(300_000), Some(512 * 1024 * 1024)),
        ("L-LIFE-03", _) => (Some(300_000), Some(2 * 1024 * 1024 * 1024)),
        _ => (Some(30_000), Some(256 * 1024 * 1024)),
    };
    let fixture_input = FixtureInput {
        format: "memcordon.consumer-readiness.input".into(),
        revision: 1,
        run_id: input.identity.run_id.clone(),
        key: key.clone(),
        challenge_sha256: super::artifacts::checksum(&challenge),
        binary: Vec::new(),
        target_argv: NativeArguments::UnixBytes(public_argv.iter().skip(1).cloned().collect()),
        deadline_millis: budget.0,
        memory_bytes: budget.1,
        toolchain_identity: None,
    };
    if !matches!(fixture_input.target_argv, NativeArguments::UnixBytes(_)) {
        return Err(CiError::Message(
            "limit native argv encoding differs".into(),
        ));
    }
    let descriptor = persist(
        "limit-descriptor.json",
        &serde_json::to_vec(&fixture_input)?,
    )?;
    let transcript = format!("{prefix}/stdout.bin");
    let raw = ["C-IO", "L-MIX-05"].contains(&key.family.as_str())
        || (key.family == "L-LIFE-05" && key.scenario == "relay-backpressure");
    let mut peers = vec![
        BehaviorArtifact {
            role: "limit-agent-image".into(),
            path: agent.path,
        },
        BehaviorArtifact {
            role: "limit-controller".into(),
            path: controller.path,
        },
        BehaviorArtifact {
            role: "limit-provider-request".into(),
            path: format!("{prefix}/provider-request.json"),
        },
    ];
    if key.family == "L-LIFE-03" {
        for (role, name) in [
            ("native-compiler-live", "native-offline-compiler-live.json"),
            ("native-generated-live", "native-generated-child-live.json"),
            ("generated-created", "native-generated-created.json"),
            ("generated-executable", "native-generated-executable.bin"),
            (
                "native-build-observer-close",
                "native-build-observer-close.json",
            ),
        ] {
            let path = format!("{prefix}/{name}");
            if !original_artifact_paths.contains(&path) {
                return Err(CiError::Message("actual joint limit lacks independently retained compiler/generated executable custody".into()));
            }
            peers.push(BehaviorArtifact {
                role: role.into(),
                path,
            });
        }
        let manifest = persist(
            "measured-build-inputs.json",
            &serde_json::to_vec(
                &serde_json::json!({"runtime":images.runtime,"input":images.input}),
            )?,
        )?;
        peers.push(BehaviorArtifact {
            role: "toolchain-inputs".into(),
            path: manifest.path,
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
            let bytes = super::linux_mixed_installed::read_owned_resource(
                &images.input_source.join("owned-source").join(relative),
                4 * 1024 * 1024,
            )?;
            let artifact = persist(&format!("locked-source/{relative}"), &bytes)?;
            peers.push(BehaviorArtifact {
                role: format!("source-{relative}"),
                path: artifact.path,
            });
        }
    }
    let mut comparisons = Vec::new();
    let mut counters = std::collections::BTreeMap::new();
    if raw {
        let expected = (0..256 * 8192usize)
            .map(|index| (index % 256) as u8)
            .collect::<Vec<_>>();
        let expected = persist("limit-expected-stream.bin", &expected)?;
        for role in ["stdout", "stderr"] {
            let actual = format!("{prefix}/{role}.bin");
            comparisons.push(ByteComparison {
                role: role.into(),
                actual: actual.clone(),
                expected: expected.path.clone(),
            });
            peers.push(BehaviorArtifact {
                role: role.into(),
                path: actual,
            });
            counters.insert(format!("{role}-bytes"), 256 * 8192);
        }
    }
    let operation = if raw {
        if key.family == "L-LIFE-05" && key.scenario == "relay-backpressure" {
            "backpressure-observed"
        } else {
            "stdout-bytes"
        }
    } else {
        match key.scenario.as_str() {
            "deadline" => "deadline-expired",
            "memory" => "memory-limit-confirmed",
            "cancellation" => "controlled-cancellation",
            "reserved-target-exit" => "reserved-native-target-exit",
            _ => return Err(CiError::Message("unknown finite limit projection".into())),
        }
    };
    let mut operations = vec![OperationObservation {
        operation: operation.into(),
        observer: "owned-fixture-behavior".into(),
        attempt_id: Some(match &collection.result.runtime.outcome {
            memcordon_core::result_v2::MixedRuntimeOutcomeV2::Executed { admission, .. } => {
                admission.attempt_id.as_str().into()
            }
            _ => unreachable!(),
        }),
        root_pid: collection.held_processes.first().map(|process| process.pid),
        native_receipt: transcript.clone(),
    }];
    if raw {
        for name in ["stdout-bytes", "stderr-bytes"] {
            if name == operation {
                continue;
            }
            let mut row = operations[0].clone();
            row.operation = name.into();
            operations.push(row);
        }
    }
    if key.family == "L-LIFE-05" && key.scenario == "relay-backpressure" {
        for name in [
            "fault-relay-backpressure",
            "original-cause-retained",
            "independent-retirement",
        ] {
            let mut row = operations[0].clone();
            row.operation = name.into();
            operations.push(row);
        }
    }
    let semantic = SemanticObservation {
        format: "memcordon.consumer-readiness.semantic".into(),
        revision: 1,
        run_id: input.identity.run_id.clone(),
        key: key.clone(),
        challenge: format!("{prefix}/challenge.bin"),
        operations,
        comparisons,
        counters,
        negative_probe: None,
        component_test: None,
        component_actors: None,
        windows_capacity: None,
        windows_refusal: None,
        fixture_behavior: Some(FixtureBehavior {
            descriptor: descriptor.path,
            transcript,
            expected_token: None,
            peer_artifacts: peers,
            native_binding: Some(collection.prepared_native_receipt.path.clone()),
        }),
    };
    let semantic_path = persist("semantic.json", &serde_json::to_vec(&semantic)?)?.path;
    let evidence = super::linux_mixed_installed::completed_case_base(
        collection,
        images,
        input,
        fixture_input,
        prefix,
        &semantic_path,
    )?;
    let bytes = serde_json::to_vec(&evidence)?;
    remaining(input.cleanup_deadline)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(
            input
                .artifact_root
                .join(format!("{prefix}/case-evidence.json")),
        )?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Signal, capture and native-family observations remain independent. Failed
/// evidence never releases an unresolved native owner or renews its cutoff.
pub fn finalize_report(report: &mut LimitsReport, deadline: Instant) -> Result<()> {
    let deadline = match report.original_cleanup_deadline {
        Some(original) => deadline.min(original),
        None if report.owners.is_empty()
            && report.controller_owners.is_empty()
            && report.memory_workers.is_empty() =>
        {
            return Ok(());
        }
        None => {
            return Err(CiError::Message(
                "limit native owners lack original cleanup cutoff".into(),
            ));
        }
    };
    let mut errors = Vec::new();
    for index in report
        .memory_resume_required
        .iter()
        .copied()
        .collect::<Vec<_>>()
    {
        if Instant::now() >= deadline {
            errors.push("original memory resume cutoff exhausted; worker retained".into());
            continue;
        }
        match report.memory_workers[index].exited() {
            Ok(true) => {
                let identity = report.memory_workers[index].retirement_identity();
                report.controller_actions.push(serde_json::json!({"format":"memcordon.linux-memory-worker-resume","revision":1,
                    "worker_index":index,"worker":identity.as_ref().ok(),"signal":18,"applicability":"exited-before-resume",
                    "syscall_succeeded":null,"native_errno":null,"observation_error":identity.as_ref().err()}));
                if let Err(error) = identity {
                    errors.push(error);
                    continue;
                }
                report.memory_resume_required.remove(&index);
            }
            Ok(false) => {
                let identity = report.memory_workers[index].retirement_identity();
                let action = report.memory_workers[index].signal_continue();
                report.controller_actions.push(serde_json::json!({"format":"memcordon.linux-memory-worker-resume","revision":1,
                    "worker_index":index,"worker":identity.as_ref().ok(),"signal":18,"applicability":"native-signal",
                    "syscall_succeeded":action.as_ref().ok().map(|result|result.is_ok()),
                    "native_errno":action.as_ref().ok().and_then(|result|result.as_ref().err()),
                    "observation_error":identity.as_ref().err(),"association_error":action.as_ref().err()}));
                if let Err(error) = identity {
                    errors.push(error);
                }
                match action {
                    Ok(Ok(())) => {
                        report.memory_resume_required.remove(&index);
                    }
                    Ok(Err(errno)) => {
                        errors.push(format!("native memory worker resume failed: errno {errno}"))
                    }
                    Err(error) => errors.push(error),
                }
            }
            Err(error) => errors.push(error),
        }
    }
    let mut settled = Vec::new();
    for (index, owner) in report.owners.iter_mut().enumerate() {
        if Instant::now() >= deadline {
            errors.push("original limit cleanup cutoff exhausted; owners retained".into());
            continue;
        }
        match owner.launch.frontend.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = owner.launch.frontend.kill() {
                    errors.push(error.to_string());
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
        owner.launch.frontend.stdin.take();
        if let Err(error) =
            remaining(deadline).and_then(|budget| owner.launch.wait_and_capture(budget))
        {
            errors.push(error.to_string());
        }
        let captured = owner.launch.capture_owners_settled();
        let retired = match &owner.observer {
            Some(observer) => loop {
                match observer.native_family_retired(&owner.held) {
                    Ok(true) => break true,
                    Ok(false) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Ok(false) => {
                        errors
                            .push("limit native family remains at original cleanup cutoff".into());
                        break false;
                    }
                    Err(error) => {
                        errors.push(error);
                        break false;
                    }
                }
            },
            None => {
                errors.push(
                    "limit native observer absent; package recovery obligation retained".into(),
                );
                false
            }
        };
        if captured && retired {
            settled.push(index);
        }
    }
    for index in settled.into_iter().rev() {
        report.owners.remove(index);
    }
    let mut settled_controllers = Vec::new();
    for (index, controller) in report.controller_owners.iter().enumerate() {
        loop {
            match controller.exited() {
                Ok(true) => {
                    settled_controllers.push(index);
                    break;
                }
                Ok(false) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Ok(false) => {
                    errors.push("limit controller remains at original cleanup cutoff".into());
                    break;
                }
                Err(error) => {
                    errors.push(error);
                    break;
                }
            }
        }
    }
    for index in settled_controllers.into_iter().rev() {
        report.controller_owners.remove(index);
    }
    let mut workers_retired = true;
    for worker in &report.memory_workers {
        loop {
            match worker.exited() {
                Ok(true) => break,
                Ok(false) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Ok(false) => {
                    errors.push("native memory worker remains at original cleanup cutoff".into());
                    workers_retired = false;
                    break;
                }
                Err(error) => {
                    errors.push(error);
                    workers_retired = false;
                    break;
                }
            }
        }
    }
    if workers_retired && report.memory_resume_required.is_empty() {
        report.memory_intervals.clear();
        report.memory_workers.clear();
        report.memory_files.clear();
        report.memory_directories.clear();
    }
    for error in errors {
        if !report.cleanup_failures.contains(&error) {
            report.cleanup_failures.push(error);
        }
    }
    if report.cleanup_failures.is_empty() {
        Ok(())
    } else {
        Err(CiError::Message(report.cleanup_failures.join("; ")))
    }
}
