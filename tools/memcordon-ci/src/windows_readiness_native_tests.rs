//! Current Windows component regressions, executed and asserted by libtest.
pub const REQUIRED_TESTS: &[&str] = &[
    "windows::record::record_fault_tests::native_publication_fault_matrix_preserves_original_and_honest_commit_boundary",
    "windows::record::record_fault_tests::native_rename_sharing_failure_retains_typed_code_and_original",
    "windows::record::record_fault_tests::native_publisher_process_exit_preserves_atomic_old_or_new_record",
    "windows::record::record_fault_tests::frozen_native_publication_does_not_own_workload_job_cleanup",
    "windows::record::record_fault_tests::native_settlement_reservation_requires_local_writer_retirement",
    "windows::control_service::retained_binding_tests::authenticated_retained_binding_rejects_other_attempt_request_process_creation_and_token",
    "windows_postauthorization_retirement::terminal_seed_freezes_before_proof_and_rejects_replacement",
    "windows_postauthorization_retirement::frozen_seed_accepts_only_matching_later_retirement_proof",
    "windows_postauthorization_retirement::receiptless_posttarget_rejection_cannot_bypass_terminal_binding",
    "windows::record::record_fault_tests::native_durable_record_rejects_provider_generation_substitution",
    "windows::record::record_fault_tests::native_provider_projection_preserves_original_and_reports_bounded_loss",
    "windows_postauthorization_retirement::suspended_postauthorization_rejection_stages_replays_and_retires_bound_outbox",
    "windows::record::record_fault_tests::native_terminal_outbox_crash_preserves_exact_replay_boundary",
    "windows::diagnostics::causal_capture_tests::native_invalid_handle_capture_preserves_first_cause_across_phase_change",
];
