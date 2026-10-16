//! Bounded public reads. Every started worker is joined before any error returns.
use crate::{CiError, Result, failure_mode::FailureMode};
use std::num::NonZeroUsize;
use std::sync::{Mutex, mpsc};
use std::time::Instant;

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
    let inherited = crate::preparation::active_group();
    let deadline = inherited
        .as_ref()
        .map_or(deadline, |group| deadline.min(group.deadline()));
    let mode = inherited.as_ref().map_or(mode, |group| group.mode());
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
            match std::thread::Builder::new().spawn_scoped(scope, move || {
                loop {
                    let ordinal = {
                        let mut state = admission.lock().expect("public read admission poisoned");
                        if state.1
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
                    let outcome =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                            || match inherited {
                                Some(group) => {
                                    crate::preparation::with_inherited_group(group.clone(), || {
                                        operation(ordinal, &inputs[ordinal], deadline)
                                    })
                                }
                                None => operation(ordinal, &inputs[ordinal], deadline),
                            },
                        ))
                        .unwrap_or_else(|_| {
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
                        if mode == FailureMode::StopAfterFailure {
                            state.1 = true;
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
        for secondary in outcomes
            .iter_mut()
            .filter_map(|outcome| outcome.take().and_then(Result::err))
            .take(8)
        {
            primary = CiError::LaneFailures {
                primary: Box::new(primary),
                secondary: Box::new(secondary),
            };
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
