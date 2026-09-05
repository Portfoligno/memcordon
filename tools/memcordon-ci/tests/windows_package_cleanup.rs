use std::cell::{Cell, RefCell};

use memcordon_ci::windows_package_cleanup::{
    ActivePackageMutation, certify_active_package_mutation, complete_optional_install_cleanup,
};
use memcordon_ci::{CiError, Result};

#[test]
fn active_mutations_observe_each_attempt_and_choose_postconditions() {
    let events = RefCell::new(Vec::new());
    let next_hold = Cell::new(0);
    for mutation in [
        ActivePackageMutation::Upgrade,
        ActivePackageMutation::Uninstall,
    ] {
        let hold = next_hold.get();
        next_hold.set(hold + 1);
        certify_active_package_mutation(
            mutation,
            || {
                events.borrow_mut().push((hold, "active"));
                Ok(())
            },
            || {
                events.borrow_mut().push((hold, "mutate"));
                Ok(())
            },
            || {
                events.borrow_mut().push((hold, "terminal"));
                Ok(())
            },
            || {
                events.borrow_mut().push((hold, "qualified-and-empty"));
                Ok(())
            },
            || {
                events.borrow_mut().push((hold, "absent"));
                Ok(())
            },
        )
        .unwrap();
    }
    assert_eq!(
        events.into_inner(),
        [
            (0, "active"),
            (0, "mutate"),
            (0, "terminal"),
            (0, "qualified-and-empty"),
            (1, "active"),
            (1, "mutate"),
            (1, "terminal"),
            (1, "absent"),
        ]
    );
}

#[test]
fn active_mutation_failure_prevents_terminal_or_completion_claims() {
    for mutation in [
        ActivePackageMutation::Upgrade,
        ActivePackageMutation::Uninstall,
    ] {
        let result = certify_active_package_mutation(
            mutation,
            || Ok(()),
            || {
                Err(CiError::Message(
                    "mutation failed: native exit 125".to_owned(),
                ))
            },
            || panic!("failed mutation cannot claim client completion"),
            || panic!("failed upgrade cannot claim qualification"),
            || panic!("failed uninstall cannot claim absence"),
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "mutation failed: native exit 125"
        );
    }
}

#[test]
fn missing_active_hold_prevents_mutation() {
    let result = certify_active_package_mutation(
        ActivePackageMutation::Upgrade,
        || {
            Err(CiError::Message(
                "frontend exited before an active attempt".to_owned(),
            ))
        },
        || panic!("must first observe an active attempt"),
        || panic!("no active attempt to retire"),
        || panic!("upgrade never ran"),
        || panic!("uninstall never ran"),
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "frontend exited before an active attempt"
    );
}

#[test]
fn forced_or_unproven_terminal_retirement_cannot_certify_mutation() {
    for mutation in [
        ActivePackageMutation::Upgrade,
        ActivePackageMutation::Uninstall,
    ] {
        let result = certify_active_package_mutation(
            mutation,
            || Ok(()),
            || Ok(()),
            || {
                Err(CiError::Message(
                    "natural terminal evidence unavailable".to_owned(),
                ))
            },
            || panic!("must not certify upgrade without terminal proof"),
            || panic!("must not certify uninstall without terminal proof"),
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "natural terminal evidence unavailable"
        );
    }
}

#[test]
fn successful_uninstall_with_residual_state_never_publishes_completion() {
    let published = Cell::new(false);
    let result = certify_active_package_mutation(
        ActivePackageMutation::Uninstall,
        || Ok(()),
        || Ok(()),
        || Ok(()),
        || panic!("removed provider cannot answer recovery status"),
        || {
            Err(CiError::Message(
                "guardian service still registered".to_owned(),
            ))
        },
    )
    .map(|()| published.set(true));
    assert_eq!(
        result.unwrap_err().to_string(),
        "guardian service still registered"
    );
    assert!(!published.get());
}

#[test]
fn absent_image_skips_uninstall_but_still_proves_full_absence() {
    let uninstall_called = Cell::new(false);
    let absence_called = Cell::new(false);
    let primary = Err(CiError::Message("primary failure".to_owned()));

    let result: Result<()> = complete_optional_install_cleanup(
        primary,
        || Ok(false),
        || {
            uninstall_called.set(true);
            Ok(())
        },
        || {
            absence_called.set(true);
            Ok(true)
        },
    );

    assert_eq!(result.unwrap_err().to_string(), "primary failure");
    assert!(!uninstall_called.get());
    assert!(absence_called.get());
}

#[test]
fn absent_image_with_residual_state_keeps_primary_and_fails_cleanup() {
    let uninstall_called = Cell::new(false);
    let primary = Err(CiError::Message("primary failure".to_owned()));

    let result: Result<()> = complete_optional_install_cleanup(
        primary,
        || Ok(false),
        || {
            uninstall_called.set(true);
            Ok(())
        },
        || Ok(false),
    );

    let error = result.unwrap_err().to_string();
    assert!(error.starts_with("primary failure; secondary cleanup failure:"));
    assert!(error.contains("rollback certification left provider state"));
    assert!(!uninstall_called.get());
}

#[test]
fn present_image_runs_uninstall_and_then_proves_absence() {
    let uninstall_called = Cell::new(false);
    let absence_called = Cell::new(false);

    let result = complete_optional_install_cleanup(
        Ok(true),
        || Ok(true),
        || {
            uninstall_called.set(true);
            Ok(())
        },
        || {
            absence_called.set(true);
            Ok(true)
        },
    );

    assert!(result.unwrap());
    assert!(uninstall_called.get());
    assert!(absence_called.get());
}

#[test]
fn inspection_and_uninstall_failures_are_secondary_to_primary_evidence() {
    for (inspect, uninstall_expected) in [(Err("inspection failure"), false), (Ok(true), true)] {
        let uninstall_called = Cell::new(false);
        let absence_called = Cell::new(false);
        let primary = Err(CiError::Message("primary failure".to_owned()));
        let result: Result<()> = complete_optional_install_cleanup(
            primary,
            || inspect.map_err(|detail| CiError::Message(detail.to_owned())),
            || {
                uninstall_called.set(true);
                Err(CiError::Message("uninstall failure".to_owned()))
            },
            || {
                absence_called.set(true);
                Ok(true)
            },
        );

        let error = result.unwrap_err().to_string();
        assert!(error.starts_with("primary failure; secondary cleanup failure:"));
        assert_eq!(uninstall_called.get(), uninstall_expected);
        assert!(absence_called.get());
    }
}
