//! Invocation-local observations of owned work. These are never serialized authority.
use crate::{CiError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterSettlement {
    NotStarted,
    Settled,
    Unknown,
}

impl WriterSettlement {
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Settled, _) | (_, Self::Settled) => Self::Settled,
            _ => Self::NotStarted,
        }
    }

    pub fn permits_reading(self) -> bool {
        self != Self::Unknown
    }
}

/// Finite facts for this invocation, never restored from a cache.
#[derive(Clone, Debug, Default)]
pub struct CompilationFacts(std::collections::BTreeSet<&'static str>);

impl CompilationFacts {
    pub(crate) fn establish(&mut self, fact: &'static str) {
        self.0.insert(fact);
    }

    pub fn revoke(&mut self, fact: &'static str) {
        self.0.remove(fact);
    }

    pub(crate) fn outputs(&self) -> Vec<(&'static str, String)> {
        self.0.iter().map(|fact| (*fact, "true".into())).collect()
    }
}

#[derive(Debug)]
pub struct WorkOutcome<T> {
    result: Result<T>,
    writers: WriterSettlement,
    facts: CompilationFacts,
}

/// Explicit local sequencing for an owner with synchronous assembly between
/// native operations. Every child-producing call must pass through `observe`;
/// `finish` is only for the enclosing synchronous result, including early `?`.
pub(crate) struct WorkSequence {
    writers: WriterSettlement,
}

impl WorkSequence {
    pub(crate) fn after_settled() -> Self {
        Self {
            writers: WriterSettlement::Settled,
        }
    }

    pub(crate) fn observe<T>(&mut self, outcome: WorkOutcome<T>) -> Result<T> {
        let (result, writers, facts) = outcome.into_parts();
        self.writers = self.writers.join(writers);
        WorkOutcome {
            result,
            writers: self.writers,
            facts,
        }
        .into_result()
    }

    pub(crate) fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        if result.as_ref().err().is_some_and(has_unresolved_owner) {
            self.writers = self.writers.join(WriterSettlement::Unknown);
        }
        match result {
            Err(CiError::OwnedWork {
                source,
                writers,
                facts,
            }) => WorkOutcome {
                result: Err(*source),
                writers: self.writers.join(writers),
                facts,
            }
            .into_result(),
            Err(CiError::Process(error)) => {
                let writers = self.writers.join(native_error_settlement(&error));
                WorkOutcome::observed(Err(CiError::Process(error)), writers).into_result()
            }
            result => WorkOutcome::observed(result, self.writers).into_result(),
        }
    }
}

impl<T> WorkOutcome<T> {
    /// An explicitly omitted lane owns no process or mutable compiler root.
    pub fn not_started(value: T) -> Self {
        Self::observed(Ok(value), WriterSettlement::NotStarted)
    }
    pub(crate) fn observed(result: Result<T>, writers: WriterSettlement) -> Self {
        Self {
            result,
            writers,
            facts: CompilationFacts::default(),
        }
    }

    pub(crate) fn before_start(result: Result<T>) -> Result<T> {
        Self::observed(result, WriterSettlement::NotStarted).into_result()
    }

    /// Compatibility adapter: only typed native observations survive an error.
    /// An arbitrary semantic or I/O error never invents settled ownership.
    pub fn from_result(result: Result<T>) -> Self {
        match result {
            Err(CiError::OwnedWork {
                source,
                writers,
                facts,
            }) => Self {
                writers: if has_unresolved_owner(&source) {
                    writers.join(WriterSettlement::Unknown)
                } else {
                    writers
                },
                result: Err(*source),
                facts,
            },
            result => {
                let writers = result
                    .as_ref()
                    .map_or_else(error_settlement, |_| WriterSettlement::Settled);
                Self::observed(result, writers)
            }
        }
    }

    pub fn writers(&self) -> WriterSettlement {
        self.writers
    }
    pub fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> WorkOutcome<U> {
        WorkOutcome {
            result: self.result.map(map),
            writers: self.writers,
            facts: self.facts,
        }
    }

    /// Transform returned data synchronously without discarding its owner fact.
    pub fn map_validated<U>(self, map: impl FnOnce(T) -> Result<U>) -> WorkOutcome<U> {
        WorkOutcome {
            result: self.result.and_then(map),
            writers: self.writers,
            facts: self.facts,
        }
    }

    /// Synchronous validation only: the closure must not start native work.
    pub fn validate_after(mut self, validation: impl FnOnce(&T) -> Result<()>) -> Self {
        if let Ok(value) = &self.result
            && let Err(error) = validation(value)
        {
            self.result = Err(error);
        }
        self
    }

    /// An unconditional synchronous postcondition preserves the primary failure.
    pub fn postcondition(mut self, validation: Result<()>) -> Self {
        if let Err(secondary) = validation {
            self.result = match self.result {
                Ok(_) => Err(secondary),
                Err(primary) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(secondary),
                }),
            };
        }
        self
    }

    /// Finalization may run native identity readers. Preserve their actual
    /// unresolved ownership without reclassifying synchronous copy failures.
    pub fn post_finalization(mut self, validation: Result<()>) -> Self {
        if validation.as_ref().err().is_some_and(has_unresolved_owner) {
            self.writers = self.writers.join(WriterSettlement::Unknown);
        }
        self.postcondition(validation)
    }

    pub fn then_owned<U>(self, next: impl FnOnce(T) -> WorkOutcome<U>) -> WorkOutcome<U> {
        let Self {
            result,
            writers,
            mut facts,
        } = self;
        match result {
            Err(error) => WorkOutcome {
                result: Err(error),
                writers,
                facts,
            },
            Ok(value) => {
                let next = next(value);
                facts.0.extend(next.facts.0);
                WorkOutcome {
                    result: next.result,
                    writers: writers.join(next.writers),
                    facts,
                }
            }
        }
    }

    pub(crate) fn fact(mut self, fact: &'static str) -> Self {
        if self.result.is_ok() {
            self.facts.establish(fact);
        }
        self
    }

    pub fn into_result(self) -> Result<T> {
        self.result.map_err(|source| {
            // Keep compatibility with native cancellation/first-error dispatch.
            // Only errors that need additional observation receive an envelope.
            if self.facts.0.is_empty()
                && matches!(
                    &source,
                    CiError::SettledCommandFailure(_)
                        | CiError::SettledCancellation(_)
                        | CiError::NotStartedAfterFailure
                        | CiError::CommandSpawnFailure(_)
                )
                && error_settlement(&source) == self.writers
            {
                source
            } else {
                CiError::OwnedWork {
                    source: Box::new(source),
                    writers: self.writers,
                    facts: self.facts,
                }
            }
        })
    }

    pub(crate) fn into_parts(self) -> (Result<T>, WriterSettlement, CompilationFacts) {
        (self.result, self.writers, self.facts)
    }
}

/// Called only after both owners have joined; ordering is chosen by the owner.
pub fn join_completed(first: WorkOutcome<()>, second: WorkOutcome<()>) -> WorkOutcome<()> {
    let (first, writers, mut facts) = first.into_parts();
    let (second, other_writers, other_facts) = second.into_parts();
    facts.0.extend(other_facts.0);
    let result = match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(secondary)) => Err(CiError::LaneFailures {
            primary: Box::new(primary),
            secondary: Box::new(secondary),
        }),
    };
    WorkOutcome {
        result,
        writers: writers.join(other_writers),
        facts,
    }
}

/// Optional projections may ignore unavailable inputs, but never unresolved owners.
#[doc(hidden)]
pub fn has_unresolved_owner(error: &CiError) -> bool {
    match error {
        CiError::OwnedWork {
            writers, source, ..
        } => *writers == WriterSettlement::Unknown || has_unresolved_owner(source),
        CiError::CacheSafety(source) | CiError::Context { source, .. } => {
            has_unresolved_owner(source)
        }
        CiError::Process(error) => native_error_settlement(error) == WriterSettlement::Unknown,
        CiError::Cancelled(_) => true,
        CiError::LaneFailures { primary, secondary } => {
            has_unresolved_owner(primary) || has_unresolved_owner(secondary)
        }
        _ => false,
    }
}

fn error_settlement(error: &CiError) -> WriterSettlement {
    match error {
        CiError::Context { source, .. } => error_settlement(source),
        CiError::OwnedWork { writers, .. } => *writers,
        CiError::NotStartedAfterFailure | CiError::CommandSpawnFailure(_) => {
            WriterSettlement::NotStarted
        }
        CiError::SettledCommandFailure(_) | CiError::SettledCancellation(_) => {
            WriterSettlement::Settled
        }
        CiError::LaneFailures { primary, secondary } => {
            error_settlement(primary).join(error_settlement(secondary))
        }
        CiError::Process(error) => native_error_settlement(error),
        _ => WriterSettlement::Unknown,
    }
}

/// Observe the actual testkit contract before formatting any native failure.
pub(crate) fn native_settlement<T>(
    result: &std::result::Result<T, memcordon_testkit::ProcessTestError>,
) -> WriterSettlement {
    match result {
        Ok(_) => WriterSettlement::Settled,
        Err(error) => native_error_settlement(error),
    }
}

fn native_error_settlement(error: &memcordon_testkit::ProcessTestError) -> WriterSettlement {
    use memcordon_testkit::ProcessTestError as E;
    let settled = match error {
        E::Spawn(_) => return WriterSettlement::NotStarted,
        // OutputLimit.cleanup includes termination, wait, both reader joins and
        // callback join in the native runner, unlike Timeout's separate bits.
        E::OutputLimit { cleanup, .. } => cleanup.is_ok(),
        E::Timeout {
            cleanup,
            observation,
            ..
        } => cleanup.is_ok() && observation.settlement_complete,
        E::Cancelled {
            cleanup,
            observation,
            ..
        } => {
            cleanup.is_ok()
                && observation.callback_completed
                && observation.stdout_reader_finished
                && observation.stderr_reader_finished
        }
        E::Callback {
            cleanup,
            capture_complete,
            ..
        } => cleanup.is_ok() && *capture_complete,
        E::Wait(_) | E::Output(_) => false,
    };
    if settled {
        WriterSettlement::Settled
    } else {
        WriterSettlement::Unknown
    }
}
