use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StopDisposition {
    Controlled,
    SessionAbsent,
    #[default]
    Failed,
}

impl StopDisposition {
    pub fn can_open(self) -> bool {
        matches!(self, Self::Controlled | Self::SessionAbsent)
    }

    pub fn allows_complete_coverage(self) -> bool {
        matches!(self, Self::Controlled)
    }
}

#[derive(Clone, Copy)]
pub enum EventClass {
    Process,
    Thread,
    FileIo,
    Image,
}

impl EventClass {
    pub fn supports(self, version: u8) -> bool {
        match self {
            Self::Process | Self::Thread => matches!(version, 2..=4),
            Self::FileIo | Self::Image => matches!(version, 2..=3),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Target {
    pub pid: u32,
    pub birth_filetime: u64,
    pub parent_pid: u32,
    pub parent_birth_filetime: u64,
    pub native_status: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Process {
    pub pid: u32,
    pub parent: u32,
    pub key: u64,
    pub at: u64,
    pub start: bool,
    pub status: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Thread {
    pub pid: u32,
    pub tid: u32,
    pub at: u64,
    pub start: bool,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Location {
    pub basename: String,
    pub directory_role: &'static str,
    pub location_key: String,
}

impl Location {
    pub fn from_path(path: &str) -> Option<Self> {
        let normalized = path.replace('/', "\\").to_lowercase();
        let (_, basename) = normalized.rsplit_once('\\').unwrap_or(("", &normalized));
        if basename.is_empty() || basename.len() > 120 || basename.chars().any(char::is_control) {
            return None;
        }
        // Dependency lookup is basename-oriented. Suppress unrelated file names
        // touched by the measured compiler and every host-specific directory.
        if ![".dll", ".exe", ".drv", ".ocx", ".sys"]
            .iter()
            .any(|extension| basename.ends_with(extension))
        {
            return None;
        }
        let (role, suffix) = [
            ("windows-system32", "\\windows\\system32\\"),
            ("windows-system32", "\\systemroot\\system32\\"),
            ("windows-sysarm32", "\\windows\\sysarm32\\"),
            ("windows-syswow64", "\\windows\\syswow64\\"),
            ("windows-component-store", "\\windows\\winsxs\\"),
            ("staged-compiler-bin", "\\locked-inputs\\toolchain\\bin\\"),
            ("staged-toolchain", "\\locked-inputs\\toolchain\\"),
            ("rust-toolchain", "\\toolchains\\"),
            ("rust-runtime", "\\lib\\rustlib\\"),
        ]
        .into_iter()
        .find_map(|(role, marker)| normalized.split_once(marker).map(|(_, tail)| (role, tail)))
        .unwrap_or(("other", normalized.as_str()));
        let mut hash = Sha256::new();
        hash.update(role.as_bytes());
        hash.update([0]);
        hash.update(suffix.as_bytes());
        Some(Self {
            basename: basename.to_owned(),
            directory_role: role,
            location_key: hex::encode(hash.finalize()),
        })
    }
}

#[derive(Debug)]
pub struct Generation {
    pub start: u64,
    pub end: u64,
    threads: BTreeMap<u32, Vec<(u64, u64)>>,
    pub ambiguous_threads: usize,
    pub parent_start_observed: bool,
}

impl Generation {
    pub fn contains(&self, at: u64) -> bool {
        self.start <= at && at <= self.end
    }

    pub fn issued(&self, tid: u32, at: u64) -> bool {
        self.threads
            .get(&tid)
            .is_some_and(|lives| lives.iter().any(|&(start, end)| start <= at && at < end))
    }
}

pub fn attribute(
    target: Target,
    processes: &[Process],
    threads: &mut [Thread],
    birth_matches: impl Fn(u64, u64) -> bool,
) -> Result<Generation, &'static str> {
    if target.pid == 0
        || target.parent_pid == 0
        || target.pid == target.parent_pid
        || target.parent_birth_filetime == 0
        || target.parent_birth_filetime >= target.birth_filetime
    {
        return Err("invalid-held-parent-generation");
    }
    let mut candidates = processes.iter().filter(|event| {
        event.start && event.pid == target.pid && birth_matches(event.at, target.birth_filetime)
    });
    let start = candidates.next().ok_or("compiler-process-start-missing")?;
    if candidates.next().is_some() || start.parent != target.parent_pid || start.key == 0 {
        return Err("ambiguous-compiler-process-start");
    }
    let mut ends = processes.iter().filter(|event| {
        !event.start && event.pid == target.pid && event.key == start.key && event.at > start.at
    });
    let end = ends.next().ok_or("compiler-process-end-missing")?;
    if ends.next().is_some()
        || end.status != target.native_status
        || processes.iter().any(|event| {
            event.start
                && event.pid == target.pid
                && event.at >= start.at
                && event.at <= end.at
                && !std::ptr::eq(start, event)
        })
    {
        return Err("ambiguous-compiler-process-lifetime");
    }
    // A captured parent start must match the independently measured parent.
    // The held parent can precede logger start in the ordinary case.
    let parent = processes
        .iter()
        .filter(|event| event.start && event.pid == target.parent_pid && event.at <= start.at)
        .max_by_key(|event| event.at);
    if parent.is_some_and(|parent| !birth_matches(parent.at, target.parent_birth_filetime))
        || processes.iter().any(|event| {
            !event.start
                && event.pid == target.parent_pid
                && event.at <= start.at
                && parent.is_none_or(|parent| event.at >= parent.at)
        })
    {
        return Err("parent-generation-mismatch");
    }
    let mut generation = Generation {
        start: start.at,
        end: end.at,
        threads: BTreeMap::new(),
        ambiguous_threads: 0,
        parent_start_observed: parent.is_some(),
    };
    threads.sort_unstable_by_key(|event| (event.tid, event.at));
    for events in threads.chunk_by(|left, right| left.tid == right.tid) {
        if !events
            .iter()
            .any(|event| event.start && event.pid == target.pid && generation.contains(event.at))
        {
            continue;
        }
        let mut lives = Vec::new();
        let mut active = None;
        let mut ambiguous = events.windows(2).any(|pair| pair[0].at == pair[1].at);
        for event in events.iter().filter(|event| event.at <= end.at) {
            if event.start {
                if active.replace(*event).is_some() {
                    ambiguous = true;
                }
            } else if let Some(previous) = active.take() {
                if previous.pid != event.pid {
                    ambiguous = true;
                } else if previous.pid == target.pid && previous.at >= start.at {
                    lives.push((previous.at, event.at));
                }
            }
        }
        if let Some(previous) = active
            && previous.pid == target.pid
            && previous.at >= start.at
        {
            // Process end can be observed before its last thread end.
            lives.push((previous.at, end.at));
        }
        if ambiguous {
            generation.ambiguous_threads += 1;
        } else {
            generation.threads.insert(events[0].tid, lives);
        }
    }
    if generation.threads.is_empty() {
        return Err("compiler-thread-generation-missing");
    }
    Ok(generation)
}

pub enum Operation {
    Create(Option<Location>),
    End(u32),
}

pub struct FileEvent {
    pub at: u64,
    pub irp: u64,
    pub operation: Operation,
}

#[derive(Serialize)]
pub struct Probe {
    pub at_qpc: u64,
    pub end_qpc: Option<u64>,
    pub ntstatus: Option<u32>,
    pub state: &'static str,
    #[serde(flatten)]
    pub location: Location,
}

#[derive(Default, Serialize)]
pub struct Pairs {
    pub matched: usize,
    pub unmatched: usize,
    pub ambiguous: usize,
    pub probes: Vec<Probe>,
}

impl Pairs {
    pub fn truncate(&mut self, retain: usize) -> bool {
        let truncated = self.probes.len() > retain;
        self.probes.truncate(retain);
        truncated
    }
}

pub fn pair(mut events: Vec<FileEvent>) -> Pairs {
    events.sort_unstable_by_key(|event| (event.irp, event.at));
    let mut result = Pairs::default();
    for batch in events.chunk_by(|left, right| left.irp == right.irp) {
        let mut pending = Vec::new();
        for simultaneous in batch.chunk_by(|left, right| left.at == right.at) {
            let mut ends = simultaneous
                .iter()
                .filter_map(|event| match event.operation {
                    Operation::End(status) => Some(status),
                    Operation::Create(_) => None,
                });
            let first_end = ends.next();
            let unique_end = ends.next().is_none();
            let creates = simultaneous
                .iter()
                .filter(|event| matches!(event.operation, Operation::Create(_)));
            if let Some(status) = first_end {
                let can_pair = unique_end && simultaneous.len() == 1 && pending.len() == 1;
                let completion = can_pair.then_some((simultaneous[0].at, status));
                for event in pending.drain(..).chain(creates) {
                    record(&mut result, event, completion, !can_pair);
                }
            } else {
                pending.extend(creates);
            }
        }
        let overlapping = pending.len() > 1;
        for event in pending {
            record(&mut result, event, None, overlapping);
        }
    }
    result.probes.sort_unstable_by_key(|row| row.at_qpc);
    result
}

fn record(result: &mut Pairs, event: &FileEvent, completion: Option<(u64, u32)>, ambiguous: bool) {
    let Operation::Create(Some(location)) = &event.operation else {
        return;
    };
    let (end, status, state) = if ambiguous {
        result.ambiguous += 1;
        (None, None, "ambiguous")
    } else if let Some((end, status)) = completion {
        result.matched += 1;
        (Some(end), Some(status), "matched")
    } else {
        result.unmatched += 1;
        (None, None, "unmatched")
    };
    result.probes.push(Probe {
        at_qpc: event.at,
        end_qpc: end,
        ntstatus: status,
        state,
        location: Location {
            basename: location.basename.clone(),
            directory_role: location.directory_role,
            location_key: location.location_key.clone(),
        },
    });
}
