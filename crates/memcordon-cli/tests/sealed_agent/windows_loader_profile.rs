use crate::windows::process::{
    LoaderProfileHiveStateV1, LoaderProfileLifecycleEventV1,
    classify_loader_profile_observations_for_test, loader_profile_lifecycle_valid_for_test,
    preserve_loader_profile_primary_for_test, render_loader_profile_canary_for_test,
};

use LoaderProfileHiveStateV1::{Absent, AccessDenied, AlreadyLoadedBorrowed, QueryFailed};
use LoaderProfileLifecycleEventV1::{
    EnvironmentCreated, EnvironmentDestroyed, JobEmpty, ObservedAfter, ObservedBefore,
    ProcessCompleted, ProfileLoaded, ProfileUnloaded,
};

#[test]
fn profile_applicability_requires_typed_exact_sid_hive_observations() {
    assert_eq!(
        classify_loader_profile_observations_for_test(
            AlreadyLoadedBorrowed,
            None,
            AlreadyLoadedBorrowed,
            true,
        ),
        "classified-borrowed-stable"
    );
    assert_eq!(
        classify_loader_profile_observations_for_test(
            Absent,
            Some(AlreadyLoadedBorrowed),
            Absent,
            true,
        ),
        "classified-owned-loaded-unloaded"
    );

    for invalid in [
        classify_loader_profile_observations_for_test(
            AlreadyLoadedBorrowed,
            Some(AlreadyLoadedBorrowed),
            AlreadyLoadedBorrowed,
            true,
        ),
        classify_loader_profile_observations_for_test(AlreadyLoadedBorrowed, None, Absent, true),
        classify_loader_profile_observations_for_test(Absent, None, Absent, true),
        classify_loader_profile_observations_for_test(
            Absent,
            Some(AlreadyLoadedBorrowed),
            Absent,
            false,
        ),
        classify_loader_profile_observations_for_test(
            Absent,
            Some(AlreadyLoadedBorrowed),
            AlreadyLoadedBorrowed,
            true,
        ),
        classify_loader_profile_observations_for_test(AccessDenied, None, AccessDenied, false),
        classify_loader_profile_observations_for_test(QueryFailed(5), None, QueryFailed(5), false),
    ] {
        assert!(invalid.starts_with("invalid-"));
    }
}

#[test]
fn borrowed_profile_runs_one_exact_cell_without_load_or_unload() {
    let borrowed = [
        ObservedBefore,
        EnvironmentCreated,
        EnvironmentDestroyed,
        ProcessCompleted,
        JobEmpty,
        ObservedAfter,
    ];
    assert!(loader_profile_lifecycle_valid_for_test(&borrowed, true));
    assert!(!borrowed.contains(&ProfileLoaded));
    assert!(!borrowed.contains(&ProfileUnloaded));

    let mut loads_borrowed = borrowed.to_vec();
    loads_borrowed.insert(1, ProfileLoaded);
    assert!(!loader_profile_lifecycle_valid_for_test(
        &loads_borrowed,
        true
    ));

    let mut unloads_borrowed = borrowed.to_vec();
    unloads_borrowed.insert(unloads_borrowed.len() - 1, ProfileUnloaded);
    assert!(!loader_profile_lifecycle_valid_for_test(
        &unloads_borrowed,
        true
    ));
}

#[test]
fn absent_profile_lease_orders_load_environment_terminal_job_empty_and_unload() {
    let owned = [
        ObservedBefore,
        ProfileLoaded,
        EnvironmentCreated,
        EnvironmentDestroyed,
        ProcessCompleted,
        JobEmpty,
        ProfileUnloaded,
        ObservedAfter,
    ];
    assert!(loader_profile_lifecycle_valid_for_test(&owned, false));

    let mut unload_before_terminal = owned;
    unload_before_terminal.swap(4, 6);
    assert!(!loader_profile_lifecycle_valid_for_test(
        &unload_before_terminal,
        false
    ));

    let mut unload_before_job_empty = owned;
    unload_before_job_empty.swap(5, 6);
    assert!(!loader_profile_lifecycle_valid_for_test(
        &unload_before_job_empty,
        false
    ));

    let mut environment_before_load = owned;
    environment_before_load.swap(1, 2);
    assert!(!loader_profile_lifecycle_valid_for_test(
        &environment_before_load,
        false
    ));

    let missing_environment_retirement = [
        ObservedBefore,
        ProfileLoaded,
        EnvironmentCreated,
        ProcessCompleted,
        JobEmpty,
        ProfileUnloaded,
        ObservedAfter,
    ];
    assert!(!loader_profile_lifecycle_valid_for_test(
        &missing_environment_retirement,
        false
    ));
}

#[test]
fn profile_cleanup_failure_preserves_the_primary_loader_failure() {
    const PRIMARY: &str = "primary-loader-status-0xc0000142";
    const CLEANUP_SECRET: &str = "UnloadUserProfile failed for private-user-profile";

    assert_eq!(
        preserve_loader_profile_primary_for_test(PRIMARY, None),
        PRIMARY
    );
    let combined = preserve_loader_profile_primary_for_test(PRIMARY, Some(CLEANUP_SECRET));
    assert!(combined.starts_with(PRIMARY));
    assert!(combined.contains("profile_child_cleanup=[cleanup_error_sha256="));
    assert!(!combined.contains(CLEANUP_SECRET));
}

#[test]
fn profile_canary_diagnostic_is_observed_bounded_redacted_and_never_promotes() {
    const PRIMARY_SECRET: &str = "primary detail C:\\Users\\private-user";
    const COMPARISON_SECRET: &str = "comparison registry value private-value";
    const CLEANUP_SECRET: &str = "hProfile=0xfeedbeef username=private-user";

    let diagnostic = render_loader_profile_canary_for_test(
        "classified-owned-loaded-unloaded",
        Absent,
        Absent,
        PRIMARY_SECRET,
        COMPARISON_SECRET,
        CLEANUP_SECRET,
    );
    assert_ordered_substrings(
        &diagnostic,
        &[
            "loader_profile_prerequisite_canary=v1",
            "state=classified-owned-loaded-unloaded",
            "before_state=absent",
            "after_state=absent",
            "before_profile_directory_sha256=",
            "after_profile_directory_sha256=",
            "before_profile_directory_exists=true",
            "after_profile_directory_exists=true",
            "profile_binding_sha256=",
            "baseline=[outcome=failed native=0xc0000142 phase=pre-initial-breakpoint-static-loader detail_sha256=",
            "comparison=[outcome=failed native=0xc0000142 phase=pre-initial-breakpoint-static-loader detail_sha256=",
            "lifecycle=[cleanup_detail_sha256=",
            "profile_values_redacted=true",
            "workload_executed=false",
            "qualification_promoted=false",
        ],
    );
    assert!(!diagnostic.contains("profile_loaded=false"));
    for secret in [
        PRIMARY_SECRET,
        COMPARISON_SECRET,
        CLEANUP_SECRET,
        "private-user",
        "private-value",
        "0xfeedbeef",
        "C:\\Users",
    ] {
        assert!(
            !diagnostic.contains(secret),
            "profile diagnostic leaked {secret}"
        );
    }
}

fn assert_ordered_substrings(haystack: &str, needles: &[&str]) {
    let mut cursor = 0;
    for needle in needles {
        let offset = haystack[cursor..]
            .find(needle)
            .unwrap_or_else(|| panic!("missing ordered profile token {needle}: {haystack}"));
        cursor += offset + needle.len();
    }
}
