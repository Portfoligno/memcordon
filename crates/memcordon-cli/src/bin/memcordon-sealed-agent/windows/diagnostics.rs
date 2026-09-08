//! Attempt-local capture remains alive until the outer attempt scope unwinds.
use memcordon_core::{CausalEventV1, WindowsCausalDiagnosticsV1};

#[cfg(test)]
#[path = "../../../../tests/sealed_agent/windows_causal_capture.rs"]
mod causal_capture_tests;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

thread_local! {
    static CURRENT: RefCell<Option<Rc<RefCell<WindowsCausalDiagnosticsV1>>>> = const { RefCell::new(None) };
    static PHASE: Cell<memcordon_core::AttemptObservationPhaseV1> = const { Cell::new(memcordon_core::AttemptObservationPhaseV1::BeforeAuthorization) };
    static CAPTURE_LOST: Cell<bool> = const { Cell::new(false) };
}

pub(super) struct AttemptDiagnosticScope {
    previous: Option<Rc<RefCell<WindowsCausalDiagnosticsV1>>>,
    previous_phase: memcordon_core::AttemptObservationPhaseV1,
    previous_loss: bool,
}
impl AttemptDiagnosticScope {
    pub(super) fn enter() -> Self {
        let slot = Rc::new(RefCell::new(WindowsCausalDiagnosticsV1::default()));
        let previous = CURRENT.with(|current| current.replace(Some(slot)));
        let previous_phase =
            PHASE.replace(memcordon_core::AttemptObservationPhaseV1::BeforeAuthorization);
        let previous_loss = CAPTURE_LOST.replace(false);
        Self {
            previous,
            previous_phase,
            previous_loss,
        }
    }
}
impl Drop for AttemptDiagnosticScope {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            current.replace(self.previous.take());
        });
        PHASE.set(self.previous_phase);
        CAPTURE_LOST.set(self.previous_loss);
    }
}

pub(super) fn set_phase(phase: memcordon_core::AttemptObservationPhaseV1) {
    PHASE.set(phase);
}

pub(super) fn capture(mut event: CausalEventV1) {
    event.observed_phase = PHASE.get();
    CURRENT.with(|current| {
        if let Ok(current) = current.try_borrow() {
            if let Some(slot) = current.as_ref() {
                if let Ok(mut journal) = slot.try_borrow_mut() {
                    if event.category == memcordon_core::FailureCategoryV1::Persistence {
                        journal.loss.persistence_failure_observed = true;
                    }
                    if journal.observe(event).is_err() {
                        journal.loss.writer_unavailable = true;
                    }
                } else {
                    CAPTURE_LOST.set(true);
                }
            }
        } else {
            CAPTURE_LOST.set(true);
        }
    });
}

pub(crate) fn capture_native(
    operation: memcordon_core::FailureOperationV1,
    native_code: Option<i32>,
    code: memcordon_core::FailureCodeV1,
) {
    capture(CausalEventV1 {
        sequence: 0,
        origin: memcordon_core::DiagnosticOriginV1::Launcher,
        category: match operation {
            memcordon_core::FailureOperationV1::InstallPolicy
            | memcordon_core::FailureOperationV1::VerifyPolicy => {
                memcordon_core::FailureCategoryV1::Admission
            }
            memcordon_core::FailureOperationV1::ReadControlFrame => {
                memcordon_core::FailureCategoryV1::Transport
            }
            memcordon_core::FailureOperationV1::VerifySuspendedTarget => {
                memcordon_core::FailureCategoryV1::Launch
            }
            _ => memcordon_core::FailureCategoryV1::Monitor,
        },
        operation,
        code,
        native_code: native_code.map(|value| {
            memcordon_core::NativeFailureCodeV1::Win32(u32::from_ne_bytes(value.to_ne_bytes()))
        }),
        observed_phase: memcordon_core::AttemptObservationPhaseV1::Monitoring,
        safe_detail: memcordon_core::SafeDiagnosticDetailV1::NoAdditionalDetail,
        detail_redacted: true,
        detail_truncated: false,
        terminalization_reference: None,
    });
}

pub(super) fn merge_into(target: &mut WindowsCausalDiagnosticsV1) {
    target.loss.writer_unavailable |= CAPTURE_LOST.get();
    CURRENT.with(|current| {
        let Ok(current) = current.try_borrow() else {
            target.loss.writer_unavailable = true;
            return;
        };
        let Some(slot) = current.as_ref() else {
            return;
        };
        let Ok(journal) = slot.try_borrow() else {
            target.loss.writer_unavailable = true;
            return;
        };
        if journal.sequence > target.sequence {
            let watermark = target.durable_through_sequence;
            let loss = target.loss.clone();
            journal.copy_into_reserved(target);
            target.durable_through_sequence = watermark;
            target.loss.writer_unavailable |= loss.writer_unavailable;
            target.loss.persistence_failure_observed |= loss.persistence_failure_observed;
        }
    });
}

/// All record-side observations use the same attempt-local sequence owner as
/// errors captured at their source. Recovery without a live scope owns its
/// record directly.
pub(super) fn observe_record(
    target: &mut WindowsCausalDiagnosticsV1,
    event: CausalEventV1,
    secondary: bool,
) {
    merge_into(target);
    let result = if secondary {
        target.observe_secondary(event)
    } else {
        target.observe(event)
    };
    if result.is_err() {
        target.loss.writer_unavailable = true;
    }
    CURRENT.with(|current| {
        let Ok(current) = current.try_borrow() else {
            CAPTURE_LOST.set(true);
            return;
        };
        let Some(slot) = current.as_ref() else {
            return;
        };
        let Ok(mut journal) = slot.try_borrow_mut() else {
            CAPTURE_LOST.set(true);
            return;
        };
        target.copy_into_reserved(&mut journal);
    });
}
