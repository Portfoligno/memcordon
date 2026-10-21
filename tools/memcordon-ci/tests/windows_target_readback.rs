#[path = "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process_impl/target_readback.rs"]
mod target_readback;

use memcordon_core::WindowsSealedMutant;
use target_readback::{Readback, readback};

#[test]
fn mismatching_creation_preserves_measurement_without_accepting_assignment() {
    for mutant in [
        WindowsSealedMutant::UseCreateProcessW,
        WindowsSealedMutant::CreateUnderServiceToken,
        WindowsSealedMutant::TrustClientToken,
    ] {
        assert_eq!(
            readback(Some(mutant)),
            Readback::ObserveMismatch,
            "{mutant:?}"
        );
    }
    assert_eq!(
        readback(Some(WindowsSealedMutant::SkipTargetTokenReadback)),
        Readback::SelectedSkip
    );
}

#[test]
fn ordinary_and_unrelated_mutant_creation_still_require_assignment_verification() {
    assert_eq!(readback(None), Readback::VerifyAssignment);
    for mutant in memcordon_core::WINDOWS_RELEASE_MUTANT_VARIANTS {
        if !matches!(
            mutant,
            WindowsSealedMutant::UseCreateProcessW
                | WindowsSealedMutant::CreateUnderServiceToken
                | WindowsSealedMutant::TrustClientToken
                | WindowsSealedMutant::SkipTargetTokenReadback
        ) {
            assert_eq!(
                readback(Some(*mutant)),
                Readback::VerifyAssignment,
                "{mutant:?}"
            );
        }
    }
}
