use memcordon_core::{
    WindowsLauncherStartupReasonV1 as Reason, WindowsLauncherStartupStageV1 as Stage,
};

/// Diagnostic selection only; this state grants no startup or retirement authority.
pub(super) struct LauncherStartupProgress {
    current: Stage,
    first_failure: Option<(Stage, Reason, Option<u32>)>,
}

impl LauncherStartupProgress {
    pub(super) const fn new() -> Self {
        Self {
            current: Stage::ProcessProtection,
            first_failure: None,
        }
    }

    pub(super) fn stage(&mut self, stage: Stage) {
        self.current = stage;
        if stage == Stage::ServiceLoop {
            self.first_failure = None;
        }
    }

    pub(super) fn failure(&mut self, reason: Reason, native_code: Option<u32>) {
        if self.first_failure.is_none() {
            self.first_failure = Some((self.current, reason, native_code));
        }
    }

    pub(super) fn reset(&mut self) {
        *self = Self::new();
    }

    pub(super) fn observation(&self) -> (Stage, Reason, Option<u32>) {
        self.first_failure
            .unwrap_or((self.current, Reason::OperationFailed, None))
    }
}
