//! Bounded public reads. Every started worker is joined before any error returns.
use crate::{CiError, Result, failure_mode::FailureMode};
use std::num::NonZeroUsize;
use std::sync::{Mutex, mpsc};
use std::time::Instant;

#[derive(Clone)]
struct ReadScope {
    deadline: Instant,
    mode: FailureMode,
    stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
thread_local! {
    static READ_SCOPE: std::cell::RefCell<Option<ReadScope>> = const { std::cell::RefCell::new(None) };
}
struct ReadGuard(Option<ReadScope>);
impl ReadGuard {
    fn install(scope: ReadScope) -> Self {
        Self(READ_SCOPE.with(|active| active.replace(Some(scope))))
    }
}
impl Drop for ReadGuard {
    fn drop(&mut self) {
        READ_SCOPE.with(|active| *active.borrow_mut() = self.0.take());
    }
}

pub fn map_public_reads_ordered<T: Sync, U: Send>(
    inputs: &[T],
    maximum_workers: NonZeroUsize,
    deadline: Instant,
    operation: impl Fn(usize, &T, Instant) -> Result<U> + Sync,
) -> Result<Vec<U>> {
    map_reads(
        inputs,
        maximum_workers,
        deadline,
        FailureMode::CollectAll,
        false,
        operation,
    )
}

/// Read-only validators may stop admitting reads on an observed error. Active
/// callbacks retain their original deadline and are always joined. Errors use
/// observation order; the compatibility API instead retains input-order errors.
pub fn map_public_reads_with_failure<T: Sync, U: Send>(
    inputs: &[T],
    maximum_workers: NonZeroUsize,
    deadline: Instant,
    mode: FailureMode,
    operation: impl Fn(usize, &T, Instant) -> Result<U> + Sync,
) -> Result<Vec<U>> {
    map_reads(inputs, maximum_workers, deadline, mode, true, operation)
}

fn map_reads<T: Sync, U: Send>(
    inputs: &[T],
    maximum_workers: NonZeroUsize,
    deadline: Instant,
    mode: FailureMode,
    observation_order: bool,
    operation: impl Fn(usize, &T, Instant) -> Result<U> + Sync,
) -> Result<Vec<U>> {
    if let Some(scope) = READ_SCOPE.with(|active| active.borrow().clone()) {
        // Descendants use the active callback owner and original read budget.
        let deadline = deadline.min(scope.deadline);
        let mut results = Vec::with_capacity(inputs.len());
        for (ordinal, input) in inputs.iter().enumerate() {
            if Instant::now() >= deadline
                || scope.stopped.load(std::sync::atomic::Ordering::Acquire)
            {
                if results.iter().any(Result::is_err) {
                    break;
                }
                return Err(CiError::NotStartedAfterFailure);
            }
            let result = operation(ordinal, input, deadline);
            if result.is_err()
                && (scope.mode == FailureMode::StopAfterFailure
                    || result
                        .as_ref()
                        .err()
                        .is_some_and(crate::work_outcome::has_unresolved_owner))
            {
                scope
                    .stopped
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            results.push(result);
        }
        let mut primary = None;
        let mut values = Vec::new();
        let mut secondary_count = 0;
        for result in results {
            match result {
                Ok(value) => values.push(value),
                Err(error) => match primary.take() {
                    None => primary = Some(error),
                    Some(first) => {
                        secondary_count += 1;
                        primary = Some(if secondary_count <= 8 {
                            CiError::LaneFailures {
                                primary: Box::new(first),
                                secondary: Box::new(error),
                            }
                        } else {
                            first
                        });
                    }
                },
            }
        }
        if secondary_count > 8 {
            eprintln!(
                "nested public reads omitted-secondary-errors={}",
                secondary_count - 8
            );
        }
        return primary.map_or(Ok(values), Err);
    }
    let inherited = crate::preparation::active_group();
    let deadline = inherited
        .as_ref()
        .map_or(deadline, |group| deadline.min(group.deadline()));
    let mode = inherited.as_ref().map_or(mode, |group| group.mode());
    let read_scope = ReadScope {
        deadline,
        mode,
        stopped: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let admission = Mutex::new((0usize, false, None::<usize>));
    let maximum = maximum_workers.get().min(4).min(inputs.len());
    let mut outcomes: Vec<Option<Result<U>>> = (0..inputs.len()).map(|_| None).collect();
    let mut spawn_error = None;
    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(4);
        let mut workers = Vec::new();
        for _ in 0..maximum {
            let sender = sender.clone();
            let admission = &admission;
            let operation = &operation;
            let inherited = &inherited;
            let read_scope = read_scope.clone();
            match std::thread::Builder::new().spawn_scoped(scope, move || {
                let _read_guard = ReadGuard::install(read_scope.clone());
                loop {
                    let ordinal = {
                        let mut state = admission.lock().expect("public read admission poisoned");
                        if state.1
                            || read_scope
                                .stopped
                                .load(std::sync::atomic::Ordering::Acquire)
                            || state.0 == inputs.len()
                            || Instant::now() >= deadline
                            || inherited.as_ref().is_some_and(|group| !group.may_start())
                        {
                            break;
                        }
                        let ordinal = state.0;
                        state.0 += 1;
                        ordinal
                    };
                    let started = Instant::now();
                    let caught =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                            || match inherited {
                                Some(group) => {
                                    crate::preparation::with_inherited_group(group.clone(), || {
                                        operation(ordinal, &inputs[ordinal], deadline)
                                    })
                                }
                                None => operation(ordinal, &inputs[ordinal], deadline),
                            },
                        ));
                    let panicked = caught.is_err();
                    let outcome = caught.unwrap_or_else(|_| {
                        Err(CiError::Message("public read worker panicked".into()))
                    });
                    if outcome.is_err() {
                        let mut state = admission.lock().expect("public read admission poisoned");
                        if !matches!(
                            &outcome,
                            Err(CiError::NotStartedAfterFailure
                                | CiError::Cancelled(_)
                                | CiError::SettledCancellation(_))
                        ) {
                            state.2.get_or_insert(ordinal);
                        }
                        if mode == FailureMode::StopAfterFailure
                            || panicked
                            || outcome
                                .as_ref()
                                .err()
                                .is_some_and(crate::work_outcome::has_unresolved_owner)
                        {
                            state.1 = true;
                            read_scope
                                .stopped
                                .store(true, std::sync::atomic::Ordering::Release);
                            if let Some(group) = inherited {
                                group.close_admission();
                            }
                        }
                    }
                    if sender.send((ordinal, started.elapsed(), outcome)).is_err() {
                        break;
                    }
                }
            }) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    admission.lock().expect("public read admission poisoned").1 = true;
                    spawn_error = Some(CiError::Io(error));
                    break;
                }
            }
        }
        drop(sender);
        for (ordinal, duration, outcome) in receiver {
            eprintln!(
                "public read ordinal={ordinal} duration-ms={} status={}",
                duration.as_millis(),
                if outcome.is_ok() { "ok" } else { "failed" }
            );
            outcomes[ordinal] = Some(outcome);
        }
        for worker in workers {
            if worker.join().is_err() && spawn_error.is_none() {
                spawn_error = Some(CiError::Message("public read coordinator panicked".into()));
            }
        }
    });
    if let Some(error) = spawn_error {
        return Err(error);
    }
    let first_observed = admission
        .into_inner()
        .expect("public read admission poisoned")
        .2;
    let unstarted = outcomes.iter().filter(|outcome| outcome.is_none()).count();
    if unstarted != 0 {
        eprintln!("public reads not-started={unstarted}");
    }
    if observation_order && let Some(ordinal) = first_observed {
        let mut primary = outcomes[ordinal]
            .take()
            .expect("observed read retained")
            .err()
            .expect("observed failure");
        let mut secondary_count = 0;
        for secondary in outcomes
            .iter_mut()
            .filter_map(|outcome| outcome.take().and_then(Result::err))
        {
            secondary_count += 1;
            if secondary_count <= 8 {
                primary = CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                };
            }
        }
        if secondary_count > 8 {
            eprintln!(
                "public reads omitted-secondary-errors={}",
                secondary_count - 8
            );
        }
        return Err(primary);
    }
    outcomes
        .into_iter()
        .map(|outcome| {
            outcome.unwrap_or_else(|| {
                Err(CiError::Message(
                    "public read not started before failure or original deadline".into(),
                ))
            })
        })
        .collect()
}
