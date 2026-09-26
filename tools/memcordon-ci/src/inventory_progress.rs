//! Bounded inventory evidence, excluded from content identities.
//! Inclusive envelopes and exclusive actor time are separate cumulative times.
#[path = "inventory_observation.rs"]
mod observation;
#[path = "inventory_report.rs"]
mod report;
use observation::Observer;
pub use observation::{CancellationToken, Snapshot, TaskClass, TaskState};
pub use report::set_report_directory;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Metadata,
    Canonicalize,
    Directory,
    Symlink,
    Access,
    Open,
    ReadHash,
    DirectoryOpen,
    DirectoryNext,
    DirectorySort,
    Precheck,
    Identity,
    PostMetadata,
    Reopen,
    PathMetadata,
    PathIdentity,
    Read,
    HashUpdate,
    HashFinalize,
    QueueWait,
    RootDrain,
    Join,
    DirectoryBarrier,
    Serialize,
    Write,
}
const OPERATIONS: [Operation; observation::OPERATION_COUNT] = [
    Operation::Metadata,
    Operation::Canonicalize,
    Operation::Directory,
    Operation::Symlink,
    Operation::Access,
    Operation::Open,
    Operation::ReadHash,
    Operation::DirectoryOpen,
    Operation::DirectoryNext,
    Operation::DirectorySort,
    Operation::Precheck,
    Operation::Identity,
    Operation::PostMetadata,
    Operation::Reopen,
    Operation::PathMetadata,
    Operation::PathIdentity,
    Operation::Read,
    Operation::HashUpdate,
    Operation::HashFinalize,
    Operation::QueueWait,
    Operation::RootDrain,
    Operation::Join,
    Operation::DirectoryBarrier,
    Operation::Serialize,
    Operation::Write,
];
struct Shared {
    root: PathBuf,
    domain: ReportDomain,
    root_ordinal: u64,
    limits: [usize; 3],
    observation: Observer,
    stop: Mutex<bool>,
    wake: Condvar,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportDomain {
    Standalone,
    Source,
    Native,
}
impl ReportDomain {
    fn name(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Source => "source",
            Self::Native => "native",
        }
    }
}

/// Bounded per-domain totals, written after both controllers have settled.
pub struct DomainSummary {
    pub domain: ReportDomain,
    pub roots: u64,
    pub elapsed_ns: u128,
    pub files: u64,
    pub bytes: u64,
    pub complete: bool,
}

pub fn finish_domains(domains: &[DomainSummary]) {
    report::persist_domains(domains);
}

// One bounded writer for the process, not one blocked stderr writer per root.
fn emit(line: String, wait: bool) {
    type Message = (String, mpsc::SyncSender<()>);
    static OUTPUT: OnceLock<mpsc::SyncSender<Message>> = OnceLock::new();
    let sender = OUTPUT.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<Message>(16);
        thread::spawn(move || {
            for (line, ack) in receiver {
                eprintln!("{line}");
                let _ = ack.try_send(());
            }
        });
        sender
    });
    let (ack, done) = mpsc::sync_channel(1);
    if sender.try_send((line, ack)).is_ok() && wait {
        let _ = done.recv_timeout(Duration::from_millis(100));
    }
}
impl Shared {
    fn snapshot(&self) -> String {
        let snapshot = self.observation.snapshot();
        let mut counts = [0_u64; OPERATIONS.len()];
        let mut costs = [0_u64; OPERATIONS.len()];
        let (mut bytes, mut reads, mut read_ns, mut hash_ns) = (0, 0, 0, 0);
        let mut active = Vec::new();
        for actor in &snapshot.actors {
            if let Some(counters) = &actor.counters {
                for i in 0..OPERATIONS.len() {
                    counts[i] += counters.counts[i];
                    costs[i] += counters.inclusive_ns[i];
                }
                bytes += counters.bytes;
                reads += counters.read_calls;
                read_ns += counters.read_ns;
                hash_ns += counters.hash_ns;
            }
            if let Some(operation) = actor.operation {
                active.push(format!(
                    "operation={:?} path={:?} operation_ms={}",
                    OPERATIONS[operation],
                    actor.path,
                    snapshot.elapsed_ns.saturating_sub(actor.started_ns) / 1_000_000
                ));
            }
        }
        let costs = OPERATIONS
            .iter()
            .enumerate()
            .map(|(i, op)| {
                format!(
                    "{op:?}_count={} {op:?}_ms={}",
                    counts[i],
                    costs[i] / 1_000_000
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let active = if active.is_empty() {
            "operation=idle".to_owned()
        } else {
            active.join(" ")
        };
        let root: String = self
            .root
            .as_os_str()
            .to_string_lossy()
            .chars()
            .take(256)
            .collect();
        format!(
            "root={root:?} elapsed_ms={} {costs} bytes={bytes} read_calls={reads} read_ms={} hash_ms={} files_attempted={} files_completed={} files_validated={} files_committed={} manifest_bytes_committed={} outstanding={} sample=actor_publication_vector {active}",
            snapshot.elapsed_ns / 1_000_000,
            read_ns / 1_000_000,
            hash_ns / 1_000_000,
            snapshot.tasks.files_attempted,
            snapshot.tasks.files_completed,
            snapshot.tasks.files_validated,
            snapshot.tasks.files_committed,
            snapshot.tasks.committed_bytes,
            snapshot.outstanding
        )
    }
}
pub struct InventoryProgress {
    shared: Arc<Shared>,
    observer: Option<JoinHandle<()>>,
}
impl InventoryProgress {
    pub fn worker(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            observer: None,
        }
    }
    pub fn new(root: &Path) -> Self {
        Self::with_intervals(root, Duration::from_secs(1), Duration::from_secs(30))
    }
    pub fn new_with_interval(root: &Path, interval: Duration) -> Self {
        Self::with_intervals(root, interval, interval)
    }
    fn with_intervals(root: &Path, interval: Duration, human_interval: Duration) -> Self {
        Self::configured(
            root,
            interval,
            human_interval,
            ReportDomain::Standalone,
            0,
            [32, 16, 16],
        )
    }
    pub fn for_domain(root: &Path, domain: ReportDomain, ordinal: u64, limits: [usize; 3]) -> Self {
        Self::configured(
            root,
            Duration::from_secs(1),
            Duration::from_secs(30),
            domain,
            ordinal,
            limits,
        )
    }
    fn configured(
        root: &Path,
        interval: Duration,
        human_interval: Duration,
        domain: ReportDomain,
        root_ordinal: u64,
        limits: [usize; 3],
    ) -> Self {
        assert!(
            !interval.is_zero(),
            "inventory progress interval must be positive"
        );
        let shared = Arc::new(Shared {
            root: root.to_path_buf(),
            domain,
            root_ordinal,
            limits,
            observation: Observer::new(),
            stop: Mutex::new(false),
            wake: Condvar::new(),
        });
        let state = Arc::clone(&shared);
        let observer = thread::spawn(move || {
            let mut last_human = std::time::Instant::now();
            loop {
                let stop = state.stop.lock().expect("progress stop poisoned");
                let (stop, _) = state
                    .wake
                    .wait_timeout_while(stop, interval, |s| !*s)
                    .expect("progress stop poisoned");
                if *stop {
                    break;
                }
                drop(stop);
                report::persist(&state, None, false);
                if last_human.elapsed() >= human_interval {
                    emit(
                        format!("[native inventory] progress {}", state.snapshot()),
                        false,
                    );
                    last_human = std::time::Instant::now();
                }
            }
        });
        Self {
            shared,
            observer: Some(observer),
        }
    }
    pub fn run<T, E>(
        &self,
        operation: Operation,
        path: &Path,
        action: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let _span = self.shared.observation.span(operation as usize, path);
        action()
    }
    pub fn record_chunk(&self, read: Duration, hash: Duration, bytes: u64) {
        self.shared.observation.record_chunk(read, hash, bytes);
    }
    pub fn cancellation(&self) -> CancellationToken {
        self.shared.observation.cancellation()
    }
    pub fn task_transition(
        &self,
        task_id: u64,
        class: TaskClass,
        state: TaskState,
    ) -> std::io::Result<()> {
        self.shared
            .observation
            .task_transition(task_id, class, state)
    }
    pub fn file_validated(&self, bytes: u64) {
        self.shared.observation.file_validated(bytes);
    }
    pub fn task_dependency(
        &self,
        id: u64,
        parent: Option<u64>,
        ordinal: Option<u64>,
    ) -> std::io::Result<()> {
        self.shared.observation.task_dependency(id, parent, ordinal)
    }
    pub fn file_committed(&self, bytes: u64) {
        self.shared.observation.file_committed(bytes);
    }
    pub fn structured_snapshot(&self) -> Snapshot {
        self.shared.observation.snapshot()
    }
    pub fn snapshot(&self) -> String {
        self.shared.snapshot()
    }
    pub fn finish(&mut self, success: bool) {
        self.stop();
        report::persist(&self.shared, Some(success), true);
        emit(
            format!(
                "[native inventory] {} {}",
                if success { "complete" } else { "failed" },
                self.snapshot()
            ),
            true,
        );
    }
    fn stop(&mut self) {
        if let Some(observer) = self.observer.take() {
            *self.shared.stop.lock().expect("progress stop poisoned") = true;
            self.shared.wake.notify_all();
            observer.join().expect("inventory observer panicked");
        }
    }
}
impl Drop for InventoryProgress {
    fn drop(&mut self) {
        self.stop();
    }
}
