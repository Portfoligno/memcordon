use crate::windows::process::{
    LoaderObjectSecurityOutcomeForTest, classify_loader_object_security_for_test,
    loader_object_security_authority_labels_for_test,
    loader_object_security_evidence_validity_for_test, loader_object_security_gate_for_test,
    render_loader_object_security_canary_for_test,
};

use LoaderObjectSecurityOutcomeForTest::{Failed, Passed};

const STATUS_DLL_INIT_FAILED: i32 = 0xc000_0142_u32 as i32;
const PHASE: &str = "pre-initial-breakpoint-static-loader";

#[test]
fn object_security_authorities_are_typed_and_split_before_the_paired_comparison() {
    assert_eq!(
        loader_object_security_authority_labels_for_test(),
        [
            "launcher-explicit-v1",
            "target-aware-process-v1",
            "target-aware-thread-v1",
            "target-aware-both-v1",
        ]
    );
}

#[test]
fn object_security_gate_requires_stable_profile_and_equal_exact_loader_failures() {
    assert!(loader_object_security_gate_for_test(
        "classified-borrowed-stable",
        Some(STATUS_DLL_INIT_FAILED),
        Some(STATUS_DLL_INIT_FAILED),
        true,
    ));

    for (profile, baseline, comparison, same_phase) in [
        (
            "classified-owned-loaded-unloaded",
            Some(STATUS_DLL_INIT_FAILED),
            Some(STATUS_DLL_INIT_FAILED),
            true,
        ),
        (
            "classified-borrowed-stable",
            None,
            Some(STATUS_DLL_INIT_FAILED),
            true,
        ),
        (
            "classified-borrowed-stable",
            Some(STATUS_DLL_INIT_FAILED),
            Some(5),
            true,
        ),
        (
            "classified-borrowed-stable",
            Some(STATUS_DLL_INIT_FAILED),
            Some(STATUS_DLL_INIT_FAILED),
            false,
        ),
    ] {
        assert!(!loader_object_security_gate_for_test(
            profile, baseline, comparison, same_phase,
        ));
    }
}

#[test]
fn object_security_classification_is_exhaustive_and_never_treats_evidence_as_qualification() {
    let failed = || Failed {
        native: STATUS_DLL_INIT_FAILED,
        phase: PHASE,
    };
    assert_eq!(
        classify_loader_object_security_for_test(failed(), Passed, failed(), None, true),
        "process-object-security-causal"
    );
    assert_eq!(
        classify_loader_object_security_for_test(failed(), failed(), Passed, None, true),
        "thread-object-security-causal"
    );
    assert_eq!(
        classify_loader_object_security_for_test(failed(), failed(), failed(), Some(Passed), true),
        "combined-object-security-causal"
    );
    assert_eq!(
        classify_loader_object_security_for_test(
            failed(),
            failed(),
            failed(),
            Some(failed()),
            true,
        ),
        "classified-common-failure"
    );
    assert_eq!(
        classify_loader_object_security_for_test(
            failed(),
            Failed {
                native: 5,
                phase: "different",
            },
            failed(),
            Some(failed()),
            true,
        ),
        "differing-inconclusive"
    );
    assert_eq!(
        classify_loader_object_security_for_test(failed(), failed(), failed(), None, true),
        "invalid"
    );
    assert_eq!(
        classify_loader_object_security_for_test(
            failed(),
            failed(),
            failed(),
            Some(failed()),
            false
        ),
        "invalid"
    );
    assert_eq!(
        classify_loader_object_security_for_test(Passed, failed(), failed(), Some(failed()), true),
        "invalid"
    );
}

#[test]
fn object_security_diagnostic_hashes_details_and_cannot_promote_or_run_workload() {
    const PRIMARY_SECRET: &str = "primary SDDL SID=S-1-5-private handle=0xfeed";
    const COMPARISON_SECRET: &str = "comparison account=private-user DACL=value";
    let diagnostic = render_loader_object_security_canary_for_test(
        "classified-common-failure",
        PRIMARY_SECRET,
        COMPARISON_SECRET,
    );
    assert_ordered_substrings(
        &diagnostic,
        &[
            "loader_object_security_prerequisite_canary=v1",
            "state=classified-common-failure",
            "primary_sha256=",
            "comparison_sha256=",
            "object_security_values_redacted=true",
            "workload_executed=false",
            "qualification_promoted=false",
        ],
    );
    for secret in [
        PRIMARY_SECRET,
        COMPARISON_SECRET,
        "S-1-5-private",
        "private-user",
        "0xfeed",
        "DACL=value",
    ] {
        assert!(!diagnostic.contains(secret), "diagnostic leaked {secret}");
    }
}

#[test]
fn object_security_evidence_requires_exact_true_environment_profile_authority() {
    let baseline = complete_evidence("true");
    let comparison = complete_evidence("true");
    let valid = loader_object_security_evidence_validity_for_test(
        &baseline,
        &[comparison.as_str()],
        true,
        true,
    );
    assert!(valid.common_evidence_valid);
    assert!(valid.descriptor_evidence_present);
    assert!(valid.invariants_valid);
    assert_eq!(valid.invariant_error, None);

    let missing = comparison.replace("environment_profile_loaded=true ", "");
    let false_on_every_cell = complete_evidence("false");
    let different = complete_evidence("false");
    let stale_alias = comparison.replace("environment_profile_loaded=true", "profile_loaded=true");
    for (name, invalid_baseline, invalid_comparison) in [
        ("missing", baseline.as_str(), missing.as_str()),
        (
            "false",
            false_on_every_cell.as_str(),
            false_on_every_cell.as_str(),
        ),
        ("different", baseline.as_str(), different.as_str()),
        ("stale-alias", stale_alias.as_str(), comparison.as_str()),
    ] {
        let evidence = loader_object_security_evidence_validity_for_test(
            invalid_baseline,
            &[invalid_comparison],
            true,
            true,
        );
        assert!(
            !evidence.common_evidence_valid,
            "{name} profile authority was accepted"
        );
        assert!(
            evidence.descriptor_evidence_present,
            "{name} profile error was mislabeled as missing descriptor evidence"
        );
        assert!(!evidence.invariants_valid);
        assert!(
            evidence
                .invariant_error
                .as_deref()
                .is_some_and(|error| error.contains("environment_profile_loaded")),
            "{name} profile authority did not retain a field-specific invariant"
        );
    }
}

#[test]
fn object_security_descriptor_evidence_and_aggregate_invariants_are_independent() {
    let baseline = complete_evidence("true");
    let profile_mismatch = complete_evidence("false");
    let common_invalid = loader_object_security_evidence_validity_for_test(
        &baseline,
        &[profile_mismatch.as_str()],
        true,
        true,
    );
    assert!(!common_invalid.common_evidence_valid);
    assert!(common_invalid.descriptor_evidence_present);
    assert!(!common_invalid.invariants_valid);

    let descriptor_missing = baseline.replace("process_object_live_sha256=process ", "");
    let descriptor_invalid = loader_object_security_evidence_validity_for_test(
        &baseline,
        &[descriptor_missing.as_str()],
        true,
        true,
    );
    assert!(descriptor_invalid.common_evidence_valid);
    assert!(!descriptor_invalid.descriptor_evidence_present);
    assert!(!descriptor_invalid.invariants_valid);
    assert_eq!(
        descriptor_invalid.invariant_error.as_deref(),
        Some("live object security evidence is incomplete")
    );
}

fn complete_evidence(environment_profile_loaded: &str) -> String {
    format!(
        "matrix_cell=production debug_mode=false environment_classification=target-token-userenv-borrowed-profile-v1 environment_sha256=environment environment_keys_sha256=keys environment_profile_loaded={environment_profile_loaded} source_token_sha256=source source_token_id=1 source_modified_id=2 source_authentication_id=3 source_session_id=4 desktop_sha256=desktop binary_sha256=binary current_directory_sha256=current creation_flags=0x00000404 job_membership_attested=true process_object_live_sha256=process process_object_dacl_protected=true process_object_ace_count=4 process_object_requested=0x00101040 process_object_target_allowed=true process_object_target_granted=0x00101040 process_object_launcher_allowed=true process_object_launcher_granted=0x001f0fff thread_object_live_sha256=thread thread_object_dacl_protected=true thread_object_ace_count=3 thread_object_requested=0x00121800 thread_object_target_allowed=true thread_object_target_granted=0x00121800 thread_object_launcher_allowed=true thread_object_launcher_granted=0x001fffff"
    )
}

fn assert_ordered_substrings(haystack: &str, needles: &[&str]) {
    let mut cursor = 0;
    for needle in needles {
        let offset = haystack[cursor..].find(needle).unwrap_or_else(|| {
            panic!("missing ordered object-security token {needle}: {haystack}")
        });
        cursor += offset + needle.len();
    }
}
