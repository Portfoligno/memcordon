//! Same-invocation Rust result provenance, independent of optional diagnostics.
use std::any::Any;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    TcpListenerBind,
    TcpStreamConnect,
}

#[derive(Clone, Copy, Debug)]
pub struct CallbackProof {
    pub operation: Operation,
    pub version: u32,
    pub called: u32,
    pub callback_outcome: u32,
    pub clock_live: u32,
    pub raw_error_present: u32,
    pub raw_error: i32,
    pub original_thread: u32,
    pub expected_thread: u32,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub cutoff_qpc: u64,
    pub expected_cutoff_qpc: u64,
    pub frequency: u64,
    pub expected_frequency: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalListenerIoFailure {
    raw_os_error: i32,
}

impl OriginalListenerIoFailure {
    pub fn api(self) -> Operation {
        Operation::TcpListenerBind
    }

    pub fn raw_os_error(self) -> i32 {
        self.raw_os_error
    }
}

pub enum InvokeOutcome<A> {
    Returned(A),
    Panicked,
    AlreadyInvoked,
}

pub struct Invocation<T> {
    result: Option<io::Result<T>>,
    panic: Option<Box<dyn Any + Send>>,
    invoked: bool,
}

impl<T> Default for Invocation<T> {
    fn default() -> Self {
        Self {
            result: None,
            panic: None,
            invoked: false,
        }
    }
}

impl<T> Invocation<T> {
    /// Ancillary state is captured by the caller immediately after the native
    /// operation, before this helper performs any other work.
    pub fn invoke_once<A>(
        &mut self,
        operation: impl FnOnce() -> (io::Result<T>, A),
    ) -> InvokeOutcome<A> {
        if self.invoked {
            return InvokeOutcome::AlreadyInvoked;
        }
        self.invoked = true;
        match catch_unwind(AssertUnwindSafe(operation)) {
            Ok((result, ancillary)) => {
                self.result = Some(result);
                InvokeOutcome::Returned(ancillary)
            }
            Err(payload) => {
                self.panic = Some(payload);
                InvokeOutcome::Panicked
            }
        }
    }

    pub fn invoked(&self) -> bool {
        self.invoked
    }
    pub fn result_ref(&self) -> Option<&io::Result<T>> {
        self.result.as_ref()
    }
    pub fn take_result(&mut self) -> Option<io::Result<T>> {
        self.result.take()
    }
    pub fn take_panic(&mut self) -> Option<Box<dyn Any + Send>> {
        self.panic.take()
    }

    pub fn freeze_listener_failure(
        &self,
        proof: &CallbackProof,
    ) -> Option<OriginalListenerIoFailure> {
        if !self.invoked
            || self.panic.is_some()
            || proof.operation != Operation::TcpListenerBind
            || !matches!(proof.version, 4 | 5)
            || proof.called != 1
            || proof.callback_outcome != 2
            || proof.clock_live != 1
            || proof.raw_error_present != 1
            || proof.original_thread == 0
            || proof.original_thread != proof.expected_thread
            || proof.frequency == 0
            || proof.frequency != proof.expected_frequency
            || proof.cutoff_qpc != proof.expected_cutoff_qpc
            || proof.started_qpc == 0
            || proof.finished_qpc < proof.started_qpc
            || proof.finished_qpc >= proof.cutoff_qpc
        {
            return None;
        }
        let raw = self.result.as_ref()?.as_ref().err()?.raw_os_error()?;
        (raw == proof.raw_error).then_some(OriginalListenerIoFailure { raw_os_error: raw })
    }
}
