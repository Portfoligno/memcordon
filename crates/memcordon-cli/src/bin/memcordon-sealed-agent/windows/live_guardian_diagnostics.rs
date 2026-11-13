use std::fmt;

use memcordon_core::WindowsProcessIdentityV1;

/// Facts evaluated once from an authenticated, exactly matched record.
/// These diagnostics confer no association or authority to resume a target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct AssociationRefusalPredicates {
    pub duplicate_match: bool,
    pub boot_mismatch: bool,
    pub provider_mismatch: bool,
    pub target_not_released: bool,
    pub resume_not_attempted: bool,
    pub authorization_missing: bool,
}

impl AssociationRefusalPredicates {
    pub fn refusal(
        self,
        expected_guardian: &WindowsProcessIdentityV1,
        record_revision: u64,
    ) -> Option<AssociationRefusal> {
        (self.duplicate_match
            || self.boot_mismatch
            || self.provider_mismatch
            || self.target_not_released
            || self.resume_not_attempted
            || self.authorization_missing)
            .then(|| AssociationRefusal {
                expected_guardian: expected_guardian.clone(),
                record_revision,
                predicates: self,
            })
    }
}

/// Only constructed at the matching-record refusal, after the initial liveness
/// check and before the final liveness check. No additional native query runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AssociationRefusal {
    expected_guardian: WindowsProcessIdentityV1,
    record_revision: u64,
    predicates: AssociationRefusalPredicates,
}

impl fmt::Display for AssociationRefusal {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only fixed labels, integer identities/revision and booleans enter the
        // existing bounded query error carrier. No record text is exported.
        let predicates = self.predicates;
        write!(
            output,
            "live guardian association is ambiguous or not released; diagnostic-revision=1; guardian-pid={}; guardian-birth={}; record-revision={}; duplicate-match={}; boot-mismatch={}; provider-mismatch={}; target-not-released={}; resume-not-attempted={}; authorization-missing={}; liveness-before-inventory=passed; liveness-after-inventory=not-reached",
            self.expected_guardian.process_id,
            self.expected_guardian.creation_time_100ns,
            self.record_revision,
            predicates.duplicate_match,
            predicates.boot_mismatch,
            predicates.provider_mismatch,
            predicates.target_not_released,
            predicates.resume_not_attempted,
            predicates.authorization_missing,
        )
    }
}
