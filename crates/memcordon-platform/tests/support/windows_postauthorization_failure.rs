#[path = "../../../memcordon-core/tests/support/windows_postauthorization.rs"]
mod fixture;

#[test]
fn authenticated_failed_receipt_preserves_actual_release_and_retirement_facts() {
    let rejection = fixture::rejection();
    let projection = rejection.provider_failure.clone().unwrap();
    let binding = projection.provider_binding.clone();
    let attempt = String::from(projection.attempt_id.clone());
    let request = String::from(projection.request_sha256.clone());
    let error = super::bound_rejection_error(rejection.clone(), None, &binding, &attempt, &request);
    assert!(error.target_released);
    assert_eq!(
        error.authorization_offset,
        Some(std::time::Duration::from_millis(7))
    );
    assert_eq!(error.target_pid, Some(1234));
    assert!(error.cleanup.direct_child_reaped);
    assert_eq!(error.cleanup.workload_empty, Some(true));
    assert!(!error.workload_may_be_alive);
    assert!(
        error
            .restart_safety
            .as_ref()
            .expect("authenticated receipt carries actual retirement proof")
            .is_safe_for(memcordon_core::BoundaryRequirement::Sealed)
    );
    assert!(
        error.runtime.is_none(),
        "receipt does not contain a runtime clock origin"
    );
    assert_eq!(
        error.windows_provider_rejection_v2.as_deref(),
        Some(&rejection)
    );
    let retained = error.provider_failure.as_ref().unwrap();
    assert_eq!(retained, &projection);
    assert_eq!(
        error.provider_association.as_ref().unwrap().provider,
        binding
    );
    assert_eq!(
        String::from(
            error
                .provider_association
                .as_ref()
                .unwrap()
                .attempt_id
                .clone()
        ),
        attempt
    );
    let substituted =
        super::bound_rejection_error(rejection, None, &binding, &"01".repeat(32), &request);
    assert!(!substituted.target_released);
    assert!(substituted.authorization_offset.is_none());
    assert!(substituted.provider_failure.is_none());
    assert_eq!(substituted.code, "MCSEALED-WINDOWS-TRANSPORT");
}
