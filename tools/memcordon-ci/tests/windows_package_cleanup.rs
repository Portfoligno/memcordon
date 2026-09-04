use std::cell::Cell;

use memcordon_ci::windows_package_cleanup::complete_optional_install_cleanup;
use memcordon_ci::{CiError, Result};

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
