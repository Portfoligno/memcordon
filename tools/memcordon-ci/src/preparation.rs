//! Pinned tool preparation for selected CI work.
#[cfg(test)]
#[path = "../tests/private/owned_reporting.rs"]
mod owned_reporting;
use crate::performance_plan::{Layout, PerformancePlan};
use crate::{
    CiError, Result,
    bootstrap_profile::BootstrapProfile,
    command::{CommandSpec, rustup_cargo},
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairClass {
    Balanced,
    ProductAndNative,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Allocation {
    pub parallel: bool,
    pub first: std::num::NonZeroUsize,
    pub second: std::num::NonZeroUsize,
}

pub fn allocate_pair(
    inherited: std::num::NonZeroUsize,
    requested_parallel: bool,
    already_in_lane: bool,
    class: PairClass,
) -> Allocation {
    let workers = inherited.get().min(4);
    let parallel = requested_parallel && !already_in_lane && workers >= 2;
    let (first, second) = if !parallel {
        (workers, workers)
    } else {
        match class {
            PairClass::Balanced => (workers.div_ceil(2), workers / 2),
            PairClass::ProductAndNative => (1, workers - 1),
        }
    };
    Allocation {
        parallel,
        first: std::num::NonZeroUsize::new(first).expect("positive root allocation"),
        second: std::num::NonZeroUsize::new(second).expect("positive root allocation"),
    }
}

/// A root discovers capacity once; every descendant spends its inherited share.
pub fn compiler_budget() -> usize {
    active_group().map_or_else(
        || {
            std::thread::available_parallelism()
                .map_or(1, |count| count.get())
                .clamp(1, 4)
        },
        |group| group.compiler_jobs(),
    )
}

/// Retention is a separate owner phase with an already reserved absolute tail.
/// A work stop never grants extra time and never prevents required retirement.
pub(crate) fn with_finalization<T>(
    deadline: Instant,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    // Optional cache copying must not spend time reserved for native retirement.
    if let Some(signal) = crate::cancellation::observed() {
        return Err(CiError::SettledCancellation(format!(
            "optional retention omitted after external interruption: {signal:?}"
        )));
    }
    let previous = ACTIVE_GROUP.with(|group| group.replace(None));
    let inherited_jobs = previous.as_ref().map(GroupStop::compiler_jobs);
    let inherited_parallel_lane = previous
        .as_ref()
        .is_some_and(GroupStop::inside_parallel_lane);
    let _restore = GroupGuard(previous);
    let mut finalization = new_group(crate::failure_mode::FailureMode::CollectAll, deadline);
    if let Some(jobs) = inherited_jobs {
        finalization.compiler_jobs = jobs;
    }
    finalization.inside_parallel_lane = inherited_parallel_lane;
    // Optional copy/context errors are reported by their controller. They must
    // neither notify the work observer nor create a competing primary cause.
    let _owner = GroupGuard::install(finalization);
    with_operation(
        crate::failure_mode::FailureMode::CollectAll,
        deadline,
        operation,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaneId {
    First,
    Second,
}

#[derive(Debug)]
pub struct PairOutcome<A, B> {
    pub first: crate::work_outcome::WorkOutcome<A>,
    pub second: crate::work_outcome::WorkOutcome<B>,
    pub first_cause: Option<LaneId>,
    pub timing: (Option<u64>, Option<u64>, u64),
}

impl PairOutcome<(), ()> {
    pub fn into_result(self) -> Result<()> {
        let (primary, secondary) = if self.first_cause == Some(LaneId::Second) {
            (self.second, self.first)
        } else {
            (self.first, self.second)
        };
        crate::work_outcome::join_completed(primary, secondary).into_result()
    }
}

/// Retain outcomes in fixed slots while the existing scoped owner handles
/// admission, cancellation and joins. No outcome or settlement is deserialized.
pub fn complete_owned_pair<A: Send, B: Send>(
    layout: Layout,
    allocation: [usize; 2],
    first: impl FnOnce() -> crate::work_outcome::WorkOutcome<A> + Send,
    second: impl FnOnce() -> crate::work_outcome::WorkOutcome<B> + Send,
) -> PairOutcome<A, B> {
    let first_slot = std::sync::Mutex::new(None);
    let second_slot = std::sync::Mutex::new(None);
    let cause = std::sync::atomic::AtomicUsize::new(usize::MAX);
    let observed_cause = std::sync::Mutex::new(None);
    let nested = active_group().is_some_and(|group| group.inside_parallel_lane());
    let owner_errors = std::sync::Mutex::new([None, None]);
    let started = Instant::now();
    let observe = |ordinal, failed| {
        if failed {
            let _ = cause.compare_exchange(
                usize::MAX,
                ordinal,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            );
        }
        if failed {
            Err(CiError::SettledCommandFailure(
                "owned lane failed; full outcome retained".into(),
            ))
        } else {
            Ok(())
        }
    };
    let mode = active_group().map_or(crate::failure_mode::FailureMode::StopAfterFailure, |g| {
        g.mode()
    });
    let owner_result = complete_lanes_observed(
        layout,
        mode,
        allocation,
        Some(&owner_errors),
        || {
            *observed_cause.lock().expect("pair observation slot") = active_group()
                .filter(|group| group.inside_parallel_lane)
                .map(|group| group.pair_failure);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(first))
                .unwrap_or_else(|_| {
                    crate::work_outcome::WorkOutcome::from_result(Err(CiError::Message(
                        "first owned lane panicked".into(),
                    )))
                });
            let failed = !outcome.is_ok();
            if outcome.writers() == crate::work_outcome::WriterSettlement::Unknown
                && let Some(group) = active_group()
            {
                group.close_admission();
                group.request_failure_notice(memcordon_testkit::NativeFailureNotice {
                    cause: memcordon_testkit::NativeFailureCause::OwnershipUncertain,
                    status: None,
                });
            }
            *first_slot.lock().expect("first outcome slot") = Some(outcome);
            observe(0, failed)
        },
        || {
            *observed_cause.lock().expect("pair observation slot") = active_group()
                .filter(|group| group.inside_parallel_lane)
                .map(|group| group.pair_failure);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(second))
                .unwrap_or_else(|_| {
                    crate::work_outcome::WorkOutcome::from_result(Err(CiError::Message(
                        "second owned lane panicked".into(),
                    )))
                });
            let failed = !outcome.is_ok();
            if outcome.writers() == crate::work_outcome::WriterSettlement::Unknown
                && let Some(group) = active_group()
            {
                group.close_admission();
                group.request_failure_notice(memcordon_testkit::NativeFailureNotice {
                    cause: memcordon_testkit::NativeFailureCause::OwnershipUncertain,
                    status: None,
                });
            }
            *second_slot.lock().expect("second outcome slot") = Some(outcome);
            observe(1, failed)
        },
    );
    let [first_owner_error, second_owner_error] =
        owner_errors.into_inner().expect("scoped owner errors");
    let owner_cause = if first_owner_error.is_some() {
        Some(LaneId::First)
    } else if second_owner_error.is_some() {
        Some(LaneId::Second)
    } else {
        None
    };
    let mut owner_error = if first_owner_error.is_none()
        && second_owner_error.is_none()
        && cause.load(std::sync::atomic::Ordering::Acquire) == usize::MAX
    {
        owner_result.err()
    } else {
        None
    };
    let first = first_slot
        .into_inner()
        .expect("first outcome slot")
        .unwrap_or_else(|| {
            crate::work_outcome::WorkOutcome::observed(
                Err(first_owner_error
                    .or_else(|| owner_error.take())
                    .unwrap_or(CiError::NotStartedAfterFailure)),
                crate::work_outcome::WriterSettlement::NotStarted,
            )
        });
    // Different value types require a separate construction for the second slot.
    let second = second_slot
        .into_inner()
        .expect("second outcome slot")
        .unwrap_or_else(|| {
            crate::work_outcome::WorkOutcome::observed(
                Err(second_owner_error
                    .or_else(|| owner_error.take())
                    .unwrap_or(CiError::NotStartedAfterFailure)),
                crate::work_outcome::WriterSettlement::NotStarted,
            )
        });
    let observed = observed_cause
        .into_inner()
        .expect("pair observation slot")
        .map(|slot| slot.load(std::sync::atomic::Ordering::Acquire));
    let first_cause = match observed.filter(|_| !nested) {
        Some(1) => Some(LaneId::First),
        Some(2) => Some(LaneId::Second),
        _ => match cause.load(std::sync::atomic::Ordering::Acquire) {
            0 => Some(LaneId::First),
            1 => Some(LaneId::Second),
            _ => None,
        },
    }
    .or(owner_cause);
    let timing = active_group().map_or(
        (
            None,
            None,
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        ),
        |g| g.timing(),
    );
    PairOutcome {
        first,
        second,
        first_cause,
        timing,
    }
}

#[derive(Clone, Debug)]
pub struct GroupStop {
    pub requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mode: crate::failure_mode::FailureMode,
    deadline: Instant,
    inside_parallel_lane: bool,
    compiler_jobs: usize,
    lane: usize,
    first_failure: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pair_failure: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    started: Instant,
    first_failure_micros: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stop_requested_micros: std::sync::Arc<std::sync::atomic::AtomicU64>,
    notice: std::sync::Arc<std::sync::OnceLock<FailureNotice>>,
    notice_sender: Option<std::sync::mpsc::SyncSender<FailureNotice>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureNotice {
    pub operation: &'static str,
    pub lane: usize,
    pub elapsed_micros: u64,
    pub cause: memcordon_testkit::NativeFailureCause,
    pub status: Option<std::process::ExitStatus>,
}

struct GroupGuard(Option<GroupStop>);

impl GroupGuard {
    fn install(stop: GroupStop) -> Self {
        Self(ACTIVE_GROUP.with(|group| group.replace(Some(stop))))
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        ACTIVE_GROUP.with(|group| *group.borrow_mut() = self.0.take());
    }
}

/// Establish one absolute operation budget; nested calls inherit its mode and stop flag.
pub fn with_operation<T>(
    mode: crate::failure_mode::FailureMode,
    deadline: Instant,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    crate::cancellation::check_admission()?;
    if active_group().is_none() {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<FailureNotice>(1);
        let done = std::sync::atomic::AtomicBool::new(false);
        return std::thread::scope(|scope| {
            let observer_done = &done;
            let observer = std::thread::Builder::new().name("ci-failure-observer".into())
                .spawn_scoped(scope, move || {
                    loop {
                        match receiver.recv_timeout(Duration::from_millis(25)) {
                            Ok(notice) => eprintln!("[ci failure] operation={} lane={} observed-us={} cause={:?} status={:?}; settling owned work", notice.operation, notice.lane, notice.elapsed_micros, notice.cause, notice.status),
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) if observer_done.load(std::sync::atomic::Ordering::Acquire) => break,
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => (),
                        }
                    }
                }).map_err(CiError::Io)?;
            let mut root = new_group(mode, deadline);
            root.notice_sender = Some(sender);
            let notice = root.notice.clone();
            let guard = GroupGuard::install(root);
            let result = with_operation(mode, deadline, operation);
            drop(guard);
            done.store(true, std::sync::atomic::Ordering::Release);
            let observed = observer
                .join()
                .map_err(|_| CiError::Message("failure observer panicked".into()));
            // The retained slot survives even if a bounded notification could not queue.
            let _ = notice.get();
            crate::work_outcome::WorkOutcome::from_result(result)
                .postcondition(observed)
                .into_result()
        });
    }
    if active_group().is_some_and(|group| group.mode != mode) {
        return Err(CiError::Message(
            "nested operation cannot replace the root failure mode".into(),
        ));
    }
    let stop = active_group().map_or_else(
        || GroupStop {
            requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            mode,
            deadline,
            inside_parallel_lane: false,
            compiler_jobs: std::thread::available_parallelism()
                .map_or(1, |count| count.get())
                .clamp(1, 4),
            lane: 0,
            first_failure: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX)),
            pair_failure: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX)),
            started: Instant::now(),
            first_failure_micros: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            stop_requested_micros: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            notice: std::sync::Arc::new(std::sync::OnceLock::new()),
            notice_sender: None,
        },
        |mut inherited| {
            inherited.deadline = inherited.deadline.min(deadline);
            inherited
        },
    );
    if !stop.may_start() {
        return Err(CiError::NotStartedAfterFailure);
    }
    let _guard = GroupGuard::install(stop.clone());
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).unwrap_or_else(|_| {
            crate::work_outcome::WorkOutcome::observed(
                Err(CiError::Message("operation panicked".into())),
                crate::work_outcome::WriterSettlement::Unknown,
            )
            .into_result()
        });
    if result
        .as_ref()
        .err()
        .is_some_and(crate::work_outcome::has_unresolved_owner)
    {
        stop.close_admission();
    }
    if result.is_err() {
        stop.request_after_failure();
    }
    result
}

/// Nested owners may narrow the deadline, while the root owns the failure mode.
pub fn with_nested_operation<T>(
    deadline: Instant,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let group = active_group()
        .ok_or_else(|| CiError::Message("nested operation has no root owner".into()))?;
    with_operation(group.mode, deadline, operation)
}

pub(crate) fn with_inherited_group<T>(
    stop: GroupStop,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let mode = stop.mode;
    let deadline = stop.deadline;
    let _guard = GroupGuard::install(stop);
    with_operation(mode, deadline, operation)
}

thread_local! {
    static ACTIVE_GROUP: std::cell::RefCell<Option<GroupStop>> = const { std::cell::RefCell::new(None) };
}

pub fn active_group() -> Option<GroupStop> {
    ACTIVE_GROUP.with(|group| group.borrow().clone())
}

impl GroupStop {
    pub fn may_start(&self) -> bool {
        if Instant::now() >= self.deadline {
            self.close_admission();
            self.request_failure_notice(memcordon_testkit::NativeFailureNotice {
                cause: memcordon_testkit::NativeFailureCause::DeadlineReached,
                status: None,
            });
        }
        !self.requested.load(std::sync::atomic::Ordering::Acquire)
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn mode(&self) -> crate::failure_mode::FailureMode {
        self.mode
    }
    pub fn compiler_jobs(&self) -> usize {
        self.compiler_jobs
    }
    pub fn inside_parallel_lane(&self) -> bool {
        self.inside_parallel_lane
    }
    pub fn request_after_failure(&self) {
        self.request_failure_notice(memcordon_testkit::NativeFailureNotice {
            cause: memcordon_testkit::NativeFailureCause::InputOrAssertionFailure,
            status: None,
        });
    }
    pub fn request_failure_notice(&self, observed: memcordon_testkit::NativeFailureNotice) {
        self.request_command_failure_notice("operation", observed);
    }
    pub(crate) fn request_command_failure_notice(
        &self,
        operation: &'static str,
        observed: memcordon_testkit::NativeFailureNotice,
    ) {
        let elapsed_micros = self.elapsed_micros();
        // Close admission before the observer can block on any output consumer.
        if self.mode == crate::failure_mode::FailureMode::StopAfterFailure {
            self.close_admission();
        }
        let first_root_cause = self
            .first_failure
            .compare_exchange(
                usize::MAX,
                self.lane,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok();
        let _ = self.pair_failure.compare_exchange(
            usize::MAX,
            self.lane,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
        if first_root_cause {
            let _ = self.first_failure_micros.compare_exchange(
                u64::MAX,
                elapsed_micros,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            );
            let notice = FailureNotice {
                operation,
                lane: self.lane,
                elapsed_micros,
                cause: observed.cause,
                status: observed.status,
            };
            if self.notice.set(notice).is_ok()
                && let Some(sender) = &self.notice_sender
            {
                let _ = sender.try_send(notice);
            }
        }
        if self.mode == crate::failure_mode::FailureMode::StopAfterFailure {
            self.close_admission();
        }
    }
    /// Unknown native ownership is terminal even during diagnostic collection.
    pub fn close_admission(&self) {
        let _ = self.stop_requested_micros.compare_exchange(
            u64::MAX,
            self.elapsed_micros(),
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
        self.requested
            .store(true, std::sync::atomic::Ordering::Release);
    }
    fn elapsed_micros(&self) -> u64 {
        self.started
            .elapsed()
            .as_micros()
            .min(u128::from(u64::MAX - 1)) as u64
    }
    pub fn timing(&self) -> (Option<u64>, Option<u64>, u64) {
        let observed = self
            .first_failure_micros
            .load(std::sync::atomic::Ordering::Acquire);
        let stopped = self
            .stop_requested_micros
            .load(std::sync::atomic::Ordering::Acquire);
        (
            (observed != u64::MAX).then_some(observed),
            (stopped != u64::MAX).then_some(stopped),
            self.elapsed_micros(),
        )
    }
    pub fn first_notice(&self) -> Option<FailureNotice> {
        self.notice.get().copied()
    }
}

fn new_group(mode: crate::failure_mode::FailureMode, deadline: Instant) -> GroupStop {
    GroupStop {
        requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        mode,
        deadline,
        inside_parallel_lane: false,
        compiler_jobs: compiler_budget(),
        lane: 0,
        first_failure: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX)),
        pair_failure: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX)),
        started: Instant::now(),
        first_failure_micros: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        stop_requested_micros: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        notice: std::sync::Arc::new(std::sync::OnceLock::new()),
        notice_sender: None,
    }
}

/// Two scoped owners, completion-order failures and no abandoned active lane.
/// Native command supervision supplies cleanup; joining alone is not a deadline.
pub fn complete_lanes(
    layout: Layout,
    first: impl FnOnce() -> Result<()> + Send,
    second: impl FnOnce() -> Result<()> + Send,
) -> Result<()> {
    complete_lanes_with_failure(
        layout,
        active_group().map_or(
            crate::failure_mode::FailureMode::StopAfterFailure,
            |group| group.mode,
        ),
        first,
        second,
    )
}

pub fn complete_lanes_with_failure(
    layout: Layout,
    mode: crate::failure_mode::FailureMode,
    first: impl FnOnce() -> Result<()> + Send,
    second: impl FnOnce() -> Result<()> + Send,
) -> Result<()> {
    if active_group().is_none() {
        return with_operation(mode, Instant::now() + Duration::from_secs(45 * 60), || {
            complete_lanes_with_failure(layout, mode, first, second)
        });
    }
    let workers = active_group().map_or_else(
        || {
            std::thread::available_parallelism()
                .map_or(1, |count| count.get())
                .clamp(1, 4)
        },
        |group| group.compiler_jobs,
    );
    let first_jobs = (workers / 2).max(1);
    complete_lanes_with_allocation(
        layout,
        mode,
        [first_jobs, workers.saturating_sub(first_jobs).max(1)],
        first,
        second,
    )
}

pub fn complete_lanes_with_allocation(
    layout: Layout,
    mode: crate::failure_mode::FailureMode,
    compiler_jobs: [usize; 2],
    first: impl FnOnce() -> Result<()> + Send,
    second: impl FnOnce() -> Result<()> + Send,
) -> Result<()> {
    complete_lanes_observed(layout, mode, compiler_jobs, None, first, second)
}

fn complete_lanes_observed(
    layout: Layout,
    mode: crate::failure_mode::FailureMode,
    compiler_jobs: [usize; 2],
    owner_errors: Option<&std::sync::Mutex<[Option<CiError>; 2]>>,
    first: impl FnOnce() -> Result<()> + Send,
    second: impl FnOnce() -> Result<()> + Send,
) -> Result<()> {
    if active_group().is_none() {
        return with_operation(mode, Instant::now() + Duration::from_secs(45 * 60), || {
            complete_lanes_observed(layout, mode, compiler_jobs, owner_errors, first, second)
        });
    }
    if active_group().is_some_and(|group| group.mode != mode) {
        return Err(CiError::Message(
            "nested lanes cannot replace the root failure mode".into(),
        ));
    }
    let mut stop = active_group().unwrap_or_else(|| GroupStop {
        requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        mode,
        deadline: Instant::now() + Duration::from_secs(45 * 60),
        inside_parallel_lane: false,
        compiler_jobs: std::thread::available_parallelism()
            .map_or(1, |count| count.get())
            .clamp(1, 4),
        lane: 0,
        first_failure: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX)),
        pair_failure: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX)),
        started: Instant::now(),
        first_failure_micros: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        stop_requested_micros: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        notice: std::sync::Arc::new(std::sync::OnceLock::new()),
        notice_sender: None,
    });
    if !stop.inside_parallel_lane {
        stop.pair_failure = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
    }
    let mode = stop.mode;
    let layout = if stop.inside_parallel_lane || stop.compiler_jobs == 1 {
        Layout::Serial
    } else {
        layout
    };
    if compiler_jobs.contains(&0)
        || (layout == Layout::Parallel
            && compiler_jobs[0]
                .checked_add(compiler_jobs[1])
                .is_none_or(|jobs| jobs > stop.compiler_jobs))
    {
        return Err(CiError::Message(
            "compiler lane allocation exceeds root budget".into(),
        ));
    }
    let run = |operation: Box<dyn FnOnce() -> Result<()> + Send + '_>, stop: GroupStop| {
        if !stop.may_start() {
            return Err(CiError::NotStartedAfterFailure);
        }
        let _guard = GroupGuard::install(stop.clone());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
            .unwrap_or_else(|_| Err(CiError::Message("scoped lane panicked".into())));
        if result.is_err() {
            stop.request_after_failure();
        }
        result
    };
    let (first, second) = match layout {
        Layout::Serial => {
            let first = run(Box::new(first), stop.clone());
            if first.is_err() && mode == crate::failure_mode::FailureMode::StopAfterFailure {
                return first;
            }
            (first, run(Box::new(second), stop.clone()))
        }
        Layout::Parallel => std::thread::scope(|scope| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(2);
            let first_sender = sender.clone();
            let mut first_stop = stop.clone();
            first_stop.inside_parallel_lane = true;
            first_stop.compiler_jobs = compiler_jobs[0].min(stop.compiler_jobs);
            first_stop.lane = 1;
            let mut second_stop = first_stop.clone();
            second_stop.lane = 2;
            second_stop.compiler_jobs = compiler_jobs[1].min(stop.compiler_jobs);
            let first = owner_spawn_admission(0).and_then(|()| {
                std::thread::Builder::new()
                    .name("ci-source-lane".into())
                    .spawn_scoped(scope, move || {
                        let result = run(Box::new(first), first_stop);
                        let _ = first_sender.send((0, result));
                    })
            });
            if first.is_err() {
                let mut failed = stop.clone();
                failed.lane = 1;
                failed.request_failure_notice(memcordon_testkit::NativeFailureNotice {
                    cause: memcordon_testkit::NativeFailureCause::OwnerSpawnFailure,
                    status: None,
                });
            }
            let second = owner_spawn_admission(1).and_then(|()| {
                std::thread::Builder::new()
                    .name("ci-auxiliary-lane".into())
                    .spawn_scoped(scope, move || {
                        let result = run(Box::new(second), second_stop);
                        let _ = sender.send((1, result));
                    })
            });
            let mut results = [None, None];
            let mut primary = if first.is_err() {
                Some(0)
            } else if second.is_err() {
                let mut failed = stop.clone();
                failed.lane = 2;
                failed.request_failure_notice(memcordon_testkit::NativeFailureNotice {
                    cause: memcordon_testkit::NativeFailureCause::OwnerSpawnFailure,
                    status: None,
                });
                Some(1)
            } else {
                None
            };
            for (ordinal, result) in receiver {
                if let Err(error) = &result {
                    for line in error.to_string().lines() {
                        let safe: String = line.chars().flat_map(char::escape_default).collect();
                        eprintln!("[ci lane {ordinal}] failed: {safe}");
                    }
                    if primary.is_none()
                        && !matches!(
                            error,
                            CiError::Cancelled(_)
                                | CiError::SettledCancellation(_)
                                | CiError::NotStartedAfterFailure
                        )
                    {
                        primary = Some(ordinal);
                    }
                }
                results[ordinal] = Some(result);
            }
            for (ordinal, owner) in [first, second].into_iter().enumerate() {
                if let Err(error) = owner.map_err(CiError::Io).and_then(|owner| {
                    owner
                        .join()
                        .map_err(|_| CiError::Message("scoped owner panicked".into()))
                }) {
                    if let Some(owner_errors) = owner_errors {
                        owner_errors.lock().expect("scoped owner errors")[ordinal] = Some(error);
                        results[ordinal] = Some(Err(CiError::NotStartedAfterFailure));
                    } else {
                        results[ordinal] = Some(Err(error));
                    }
                }
            }
            let observed = stop.pair_failure.load(std::sync::atomic::Ordering::Acquire);
            let primary = if observed == 1 || observed == 2 {
                observed - 1
            } else {
                primary.unwrap_or(0)
            };
            (
                results[primary].take().expect("primary owner settled"),
                results[1 - primary].take().expect("peer owner settled"),
            )
        }),
    };
    crate::work_outcome::join_completed(
        crate::work_outcome::WorkOutcome::from_result(first),
        crate::work_outcome::WorkOutcome::from_result(second),
    )
    .into_result()
}

pub fn remaining(deadline: Instant, limit: Duration) -> Result<Duration> {
    crate::cancellation::check_admission()?;
    let deadline = if let Some(retirement) = crate::cancellation::retirement_deadline() {
        deadline.min(retirement)
    } else {
        active_group().map_or(deadline, |group| deadline.min(group.deadline))
    };
    let budget = deadline.saturating_duration_since(Instant::now());
    if budget.is_zero() {
        return crate::work_outcome::WorkOutcome::before_start(Err(CiError::Message(
            "original operation group deadline expired".into(),
        )));
    }
    Ok(budget.min(limit))
}

#[cfg(test)]
thread_local! {
    static FAILED_OWNER_SPAWN: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

fn owner_spawn_admission(_lane: usize) -> std::io::Result<()> {
    crate::cancellation::check_admission()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Interrupted, error.to_string()))?;
    #[cfg(test)]
    if FAILED_OWNER_SPAWN.with(|slot| slot.get() == Some(_lane)) {
        return Err(std::io::Error::other("injected owner spawn failure"));
    }
    Ok(())
}

pub fn observed(command: CommandSpec, directory: &Path, name: &str) -> Result<()> {
    command.output_owned().validate_after(|result| {
    let stdout = fs::write(
        directory.join(name).with_extension("stdout.bin"),
        &result.stdout,
    );
    let stderr = fs::write(
        directory.join(name).with_extension("stderr.bin"),
        &result.stderr,
    );
    if !result.status.success() {
        return Err(CiError::SettledCommandFailure(format!(
            "operation {name} failed with {:?}; stdout collection={stdout:?}; stderr collection={stderr:?}\nstdout:\n{}\nstderr:\n{}",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr),
        )));
    }
    stdout?;
    stderr?;
    Ok(())
    }).map(|_| ()).into_result()
}

pub fn auxiliary_tool(root: &Path, name: &str) -> Result<PathBuf> {
    let filename = match (name, cfg!(windows)) {
        ("cargo-fuzz", false) => "cargo-fuzz",
        ("cargo-fuzz", true) => "cargo-fuzz.exe",
        ("cargo-audit", false) => "cargo-audit",
        ("cargo-audit", true) => "cargo-audit.exe",
        ("cargo-deny", false) => "cargo-deny",
        ("cargo-deny", true) => "cargo-deny.exe",
        _ => return Err(CiError::Message("unsupported auxiliary tool".into())),
    };
    Ok(root.join("target/ci-tools/bin").join(filename))
}

pub fn ensure_auxiliary_tool(
    root: &Path,
    _profile: BootstrapProfile,
    name: &str,
    version: &str,
) -> Result<PathBuf> {
    ensure_auxiliary_tool_until(
        root,
        _profile,
        name,
        version,
        Instant::now() + Duration::from_secs(45 * 60),
    )
}

pub fn ensure_auxiliary_tool_until(
    root: &Path,
    profile: BootstrapProfile,
    name: &str,
    version: &str,
    deadline: Instant,
) -> Result<PathBuf> {
    let _ = profile;
    let toolchain = crate::config::toolchains(root)?.stable;
    ensure_one_auxiliary_until(
        root,
        name,
        version,
        &toolchain,
        deadline,
        std::num::NonZeroUsize::new(compiler_budget()).expect("positive inherited compiler budget"),
    )
}

/// Each tool slot has exactly one in-process acquisition owner. Distinct tools
/// never replace or inspect one another's executable or shared bin directory.
pub fn ensure_one_auxiliary_until(
    root: &Path,
    name: &str,
    version: &str,
    toolchain: &str,
    deadline: Instant,
    compiler_jobs: std::num::NonZeroUsize,
) -> Result<PathBuf> {
    static OWNERS: std::sync::Mutex<[bool; 3]> = std::sync::Mutex::new([false; 3]);
    let slot = match name {
        "cargo-audit" => 0,
        "cargo-deny" => 1,
        "cargo-fuzz" => 2,
        _ => return Err(CiError::Message("unsupported auxiliary tool".into())),
    };
    struct Owner(usize);
    impl Drop for Owner {
        fn drop(&mut self) {
            OWNERS.lock().expect("tool owners poisoned")[self.0] = false;
        }
    }
    {
        let mut owners = OWNERS.lock().expect("tool owners poisoned");
        if owners[slot] {
            return Err(CiError::Message(
                "duplicate concurrent auxiliary acquisition".into(),
            ));
        }
        owners[slot] = true;
    }
    let _owner = Owner(slot);
    remaining(deadline, Duration::from_secs(1))?;
    validate_auxiliary_directory(&root.join("target/ci-tools/bin"))?;
    validate_auxiliary_directory(&root.join("target/ci-preparation"))?;
    validate_auxiliary_directory(&root.join("target/ci-tools-build").join(name))?;
    let destination = auxiliary_tool(root, name)?;
    crate::workflow_output::revoke_compilation(tool_ready_fact(name))?;
    if valid_auxiliary_version(root, &destination, version, deadline)? {
        crate::workflow_output::compilation_complete(tool_ready_fact(name))?;
        return Ok(destination);
    }
    let staging_parent = root.join("target/ci-preparation");
    fs::create_dir_all(&staging_parent)?;
    let staging = tempfile::Builder::new()
        .prefix(name)
        .tempdir_in(staging_parent)?;
    let family = crate::download_cache::DownloadFamily::for_purpose(name);
    let before = crate::download_cache::context_until(root, family, deadline)?;
    crate::workflow_output::revoke_compilation(tool_build_fact(name))?;
    observed(
        rustup_cargo(
            root,
            toolchain,
            ["install", "--locked", "--version", version, name, "--root"],
            remaining(deadline, Duration::from_secs(1200))?,
        )
        .arg(staging.path())
        .arg("--target-dir")
        .arg(root.join("target/ci-tools-build").join(name))
        .arg("--jobs")
        .arg(compiler_jobs.get().min(4).to_string())
        .bounded_until(deadline),
        staging.path(),
        name,
    )?;
    crate::workflow_output::compilation_complete(tool_build_fact(name))?;
    let staged = staging
        .path()
        .join("bin")
        .join(destination.file_name().expect("tool filename"));
    if !valid_auxiliary_version(root, &staged, version, deadline)? {
        return crate::work_outcome::WorkOutcome::from_result(Ok(()))
            .postcondition(Err(CiError::Message(
                "staged auxiliary version differs from selected pin".into(),
            )))
            .map(|_| destination)
            .into_result();
    }
    crate::work_outcome::WorkOutcome::from_result(Ok(()))
        .validate_after(|_| promote_auxiliary(&staged, &destination))
        .into_result()?;
    crate::workflow_output::compilation_complete(tool_ready_fact(name))?;
    if crate::download_cache::packaged_lock_present(root, name, version).unwrap_or_else(|error| {
        eprintln!("tool download lock inspection unavailable: {error}");
        false
    }) {
        crate::download_cache::record(
            family,
            &before,
            &crate::download_cache::context_until(root, family, deadline)?,
        );
    }
    Ok(destination)
}

fn tool_build_fact(name: &str) -> &'static str {
    match name {
        "cargo-audit" => "tool-cargo-audit-build-complete",
        "cargo-deny" => "tool-cargo-deny-build-complete",
        "cargo-fuzz" => "tool-cargo-fuzz-build-complete",
        _ => unreachable!("validated auxiliary tool"),
    }
}

fn tool_ready_fact(name: &str) -> &'static str {
    match name {
        "cargo-audit" => "tool-cargo-audit-ready",
        "cargo-deny" => "tool-cargo-deny-ready",
        "cargo-fuzz" => "tool-cargo-fuzz-ready",
        _ => unreachable!("validated auxiliary tool"),
    }
}

fn validate_auxiliary_directory(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if let Ok(metadata) = fs::symlink_metadata(ancestor) {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(CiError::Message(
                    "unsafe auxiliary directory ancestor".into(),
                ));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(CiError::Message("auxiliary directory reparse point".into()));
                }
            }
        } else if let Err(error) = fs::symlink_metadata(ancestor)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error.into());
        }
    }
    Ok(())
}

fn promote_auxiliary(staged: &Path, destination: &Path) -> Result<()> {
    let parent = destination.parent().expect("tool bin parent");
    validate_auxiliary_directory(parent)?;
    fs::create_dir_all(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix("promotion-")
        .tempdir_in(parent)?;
    let replacement = temporary.path().join("new");
    let backup = temporary.path().join("previous");
    fs::copy(staged, &replacement)?;
    fs::set_permissions(&replacement, fs::metadata(staged)?.permissions())?;
    let previous = match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(CiError::Message(
                        "auxiliary destination reparse point".into(),
                    ));
                }
            }
            true
        }
        Ok(_) => return Err(CiError::Message("unsafe auxiliary destination kind".into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if previous {
        fs::rename(destination, &backup)?;
    }
    if let Err(error) = fs::rename(&replacement, destination) {
        if previous {
            fs::rename(&backup, destination)?;
        }
        return Err(error.into());
    }
    Ok(())
}

fn valid_auxiliary_version(
    root: &Path,
    path: &Path,
    version: &str,
    deadline: Instant,
) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Ok(false);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Ok(false);
        }
    }
    let output = match CommandSpec::new(path, root, Duration::from_secs(30))
        .arg("--version")
        .bounded_until(deadline)
        .defer_group_failure()
        .output_quiet()
    {
        Ok(output) => output,
        Err(CiError::CommandSpawnFailure(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(output.status.success()
        && std::str::from_utf8(&output.stdout)
            .ok()
            .is_some_and(|text| text.split_whitespace().any(|token| token == version)))
}

pub fn prepare(root: &Path, profile: BootstrapProfile) -> Result<()> {
    prepare_until(root, profile, Instant::now() + Duration::from_secs(45 * 60))
}

pub fn prepare_with_failure(
    root: &Path,
    profile: BootstrapProfile,
    mode: crate::failure_mode::FailureMode,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(45 * 60);
    with_operation(mode, deadline, || prepare_until(root, profile, deadline))
}

pub fn prepare_until(
    root: &Path,
    profile: BootstrapProfile,
    parent_deadline: Instant,
) -> Result<()> {
    prepare_selected_until(root, profile, parent_deadline, None)
}

fn prepare_selected_until(
    root: &Path,
    profile: BootstrapProfile,
    parent_deadline: Instant,
    selected_tool: Option<&str>,
) -> Result<()> {
    let deadline = parent_deadline.min(Instant::now() + Duration::from_secs(45 * 60));
    let toolchains = crate::config::toolchains(root)?;
    let tools = crate::config::tools(root)?;
    let layout = PerformancePlan::read(root)?.preparation.selected;
    let report_root = root.join("target/ci/reports/preparation");
    fs::create_dir_all(&report_root)?;
    let reports = tempfile::Builder::new()
        .prefix("operations-")
        .tempdir_in(&report_root)?
        .keep();
    let source_reports = reports.join("source");
    let auxiliary_reports = reports.join("auxiliary");
    fs::create_dir(&source_reports)?;
    fs::create_dir(&auxiliary_reports)?;
    let mut selected = vec![toolchains.stable.as_str()];
    match profile {
        BootstrapProfile::Msrv => selected.push(&toolchains.msrv),
        BootstrapProfile::Miri | BootstrapProfile::Fuzz => selected.push(&toolchains.miri),
        BootstrapProfile::ReleasePreflight => {
            selected.extend([toolchains.msrv.as_str(), toolchains.miri.as_str()])
        }
        _ => {}
    }
    for (index, toolchain) in selected.into_iter().enumerate() {
        observed(
            CommandSpec::new(
                "rustup",
                root,
                remaining(deadline, Duration::from_secs(900))?,
            )
            .args(["toolchain", "install", toolchain, "--profile", "minimal"])
            .bounded_until(deadline),
            &reports,
            &index.to_string(),
        )?;
    }
    let mut installs = Vec::new();
    if matches!(
        profile,
        BootstrapProfile::Fuzz | BootstrapProfile::ReleasePreflight
    ) {
        installs.push(("cargo-fuzz", tools.cargo_fuzz.as_str()));
    }
    if matches!(
        profile,
        BootstrapProfile::SupplyChain | BootstrapProfile::ReleasePreflight
    ) {
        installs.extend([
            ("cargo-audit", tools.cargo_audit.as_str()),
            ("cargo-deny", tools.cargo_deny.as_str()),
        ]);
    }
    if let Some(selected) = selected_tool {
        installs.retain(|(package, _)| *package == selected);
    }
    complete_lanes(
        layout,
        || {
            crate::download_cache::fetch_until(
                root,
                crate::download_cache::DownloadFamily::Workspace,
                deadline,
                Some(&source_reports),
            )?;
            if matches!(
                profile,
                BootstrapProfile::Fuzz | BootstrapProfile::ReleasePreflight
            ) {
                crate::download_cache::fetch_until(
                    root,
                    crate::download_cache::DownloadFamily::Fuzz,
                    deadline,
                    Some(&source_reports),
                )?;
            }
            observed(
                rustup_cargo(
                    root,
                    &toolchains.stable,
                    ["metadata", "--locked", "--format-version", "1"],
                    remaining(deadline, Duration::from_secs(900))?,
                )
                .bounded_until(deadline),
                &source_reports,
                "metadata",
            )
        },
        || {
            if matches!(
                profile,
                BootstrapProfile::Miri | BootstrapProfile::ReleasePreflight
            ) {
                observed(
                    CommandSpec::new(
                        "rustup",
                        root,
                        remaining(deadline, Duration::from_secs(900))?,
                    )
                    .args([
                        "component",
                        "add",
                        "--toolchain",
                        &toolchains.miri,
                        "miri",
                        "rust-src",
                    ])
                    .bounded_until(deadline),
                    &auxiliary_reports,
                    "miri-component",
                )?;
                crate::miri_cache::ensure(root, &toolchains.miri, deadline)?;
            }
            for (package, version) in &installs {
                ensure_one_auxiliary_until(
                    root,
                    package,
                    version,
                    &toolchains.stable,
                    deadline,
                    std::num::NonZeroUsize::new(compiler_budget())
                        .expect("positive inherited compiler budget"),
                )?;
            }
            Ok(())
        },
    )?;
    remaining(deadline, Duration::from_secs(1))?;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/private/auxiliary_promotion.rs"]
mod auxiliary_promotion;

#[cfg(all(test, unix))]
#[path = "../tests/private/cancellation_operation_fixture.rs"]
pub(crate) mod cancellation_fixture;
