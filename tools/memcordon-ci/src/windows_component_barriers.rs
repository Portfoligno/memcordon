//! Original component barrier ownership. The observer is deliberately never signaled.
use std::{io, sync::Arc};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementStage {
    OwnerStatus,
    ExactRecovery,
    Converge,
    HeldRetirement,
}

pub struct SettlementErrors<E> {
    operational: Option<E>,
    diagnostic: Option<E>,
}

impl<E> Default for SettlementErrors<E> {
    fn default() -> Self {
        Self {
            operational: None,
            diagnostic: None,
        }
    }
}

impl<E> SettlementErrors<E> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn diagnostic<T>(&mut self, result: Result<T, E>) {
        let _ = self.capture_diagnostic(result);
    }
    pub fn capture_diagnostic<T>(&mut self, result: Result<T, E>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                if self.diagnostic.is_none() {
                    self.diagnostic = Some(error);
                }
                None
            }
        }
    }
    pub fn operation<T>(&mut self, result: Result<T, E>) {
        let _ = self.capture_operation(result);
    }
    pub fn capture_operation<T>(&mut self, result: Result<T, E>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                if self.operational.is_none() {
                    self.operational = Some(error);
                }
                None
            }
        }
    }
    pub fn finish(self, combine: impl FnOnce(E, E) -> E) -> Result<(), E> {
        match (self.operational, self.diagnostic) {
            (Some(operational), Some(diagnostic)) => Err(combine(operational, diagnostic)),
            (Some(error), None) | (None, Some(error)) => Err(error),
            (None, None) => Ok(()),
        }
    }
}

/// Each independent settlement phase is attempted once under the same original
/// cutoff. Diagnostic failures never become authority or suppress later phases.
pub fn settle<C: Copy, E>(
    cutoff: C,
    combine: impl FnOnce(E, E) -> E,
    mut run: impl FnMut(SettlementStage, C, &mut SettlementErrors<E>) -> Result<(), E>,
) -> Result<(), E> {
    let mut errors = SettlementErrors::new();
    for stage in [
        SettlementStage::OwnerStatus,
        SettlementStage::ExactRecovery,
        SettlementStage::Converge,
        SettlementStage::HeldRetirement,
    ] {
        let result = run(stage, cutoff, &mut errors);
        if stage == SettlementStage::OwnerStatus {
            errors.diagnostic(result);
        } else {
            errors.operation(result);
        }
    }
    errors.finish(combine)
}

pub struct ComponentBarriers<T> {
    start: Option<Arc<T>>,
    // Kept outside the short actor callback, through original retirement/recovery.
    _observer: Option<T>,
}

impl<T> ComponentBarriers<T> {
    pub fn create(
        start_name: Option<&str>,
        hold_toolchain: bool,
        mut create_fresh: impl FnMut(&str) -> io::Result<T>,
    ) -> io::Result<Self> {
        if hold_toolchain && start_name.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "held component toolchain requires its original start barrier",
            ));
        }
        let start = start_name.map(&mut create_fresh).transpose()?.map(Arc::new);
        let observer = if hold_toolchain {
            let name = start_name.expect("validated original start barrier");
            Some(create_fresh(&format!("{name}-toolchain-observer"))?)
        } else {
            None
        };
        Ok(Self {
            start,
            _observer: observer,
        })
    }

    /// Only the start event enters the callback; the outer observer owner stays put.
    pub fn callback_start(&self) -> Option<Arc<T>> {
        self.start.as_ref().map(Arc::clone)
    }
}
