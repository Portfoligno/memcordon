//! Bounded public reads. Every started worker is joined before any error returns.
use crate::{CiError, Result};
use std::num::NonZeroUsize;
use std::time::Instant;

pub fn map_public_reads_ordered<T: Sync, U: Send>(
    inputs: &[T],
    maximum_workers: NonZeroUsize,
    deadline: Instant,
    operation: impl Fn(usize, &T, Instant) -> Result<U> + Sync,
) -> Result<Vec<U>> {
    let maximum = maximum_workers.get().min(4);
    let mut outcomes = Vec::with_capacity(inputs.len());
    for (batch_index, batch) in inputs.chunks(maximum).enumerate() {
        std::thread::scope(|scope| {
            let workers: Vec<_> = batch
                .iter()
                .enumerate()
                .map(|(offset, input)| {
                    let ordinal = batch_index * maximum + offset;
                    let operation = &operation;
                    scope.spawn(move || {
                        let started = Instant::now();
                        let outcome = if started >= deadline {
                            Err(CiError::Message(
                                "public read phase deadline expired".into(),
                            ))
                        } else {
                            operation(ordinal, input, deadline)
                        };
                        (ordinal, started.elapsed(), outcome)
                    })
                })
                .collect();
            for (offset, worker) in workers.into_iter().enumerate() {
                let outcome = match worker.join() {
                    Ok((ordinal, duration, outcome)) => {
                        eprintln!(
                            "public read ordinal={ordinal} duration-ms={} status={}",
                            duration.as_millis(),
                            if outcome.is_ok() { "ok" } else { "failed" }
                        );
                        outcome
                    }
                    Err(_) => {
                        let ordinal = batch_index * maximum + offset;
                        eprintln!(
                            "public read ordinal={ordinal} duration-ms=unavailable status=panicked"
                        );
                        Err(CiError::Message("public read worker panicked".into()))
                    }
                };
                outcomes.push(outcome);
            }
        });
    }
    outcomes.into_iter().collect()
}
