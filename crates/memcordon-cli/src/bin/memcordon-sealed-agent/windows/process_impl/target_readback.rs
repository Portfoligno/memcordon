//! Creation measurements remain real even when certification selects a mismatch.
use memcordon_core::WindowsSealedMutant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readback {
    SelectedSkip,
    ObserveMismatch,
    VerifyAssignment,
}

pub fn readback(mutant: Option<WindowsSealedMutant>) -> Readback {
    match mutant {
        Some(WindowsSealedMutant::SkipTargetTokenReadback) => Readback::SelectedSkip,
        Some(
            WindowsSealedMutant::UseCreateProcessW
            | WindowsSealedMutant::CreateUnderServiceToken
            | WindowsSealedMutant::TrustClientToken,
        ) => Readback::ObserveMismatch,
        _ => Readback::VerifyAssignment,
    }
}
