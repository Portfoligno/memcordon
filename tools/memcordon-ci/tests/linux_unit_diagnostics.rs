use std::{cell::RefCell, ffi::OsStr, path::Path, time::Duration};

use memcordon_ci::{
    CiError,
    command::CommandSpec,
    config,
    release::linux_installed_consumer::{
        PRIVATE_UNIT_DIAGNOSTIC_BYTES, PrivateUnitDiagnostic, diagnose_then_cleanup,
        private_unit_diagnostic_command, retain_private_unit_diagnostic,
    },
};
use memcordon_testkit::{ProcessTestError, TimeoutObservation};

fn directory() -> tempfile::TempDir {
    if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}

#[test]
fn native_unit_queries_are_typed_bounded_to_selected_services_without_mutation() {
    let status = private_unit_diagnostic_command(Path::new("/tmp"), PrivateUnitDiagnostic::Status)
        .materialize()
        .unwrap();
    assert_eq!(status.get_program(), OsStr::new("sudo"));
    assert_eq!(status.get_current_dir(), Some(Path::new("/tmp")));
    let units = [
        "memcordon-sealed-agent.service",
        "memcordon-sealed-agent.socket",
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-launcher.socket",
        "memcordon-sealed-network-launcher.service",
        "memcordon-sealed-network-launcher.socket",
    ];
    let expected: Vec<_> = ["-n", "systemctl", "status", "--no-pager", "--full", "--"]
        .into_iter()
        .chain(units)
        .map(OsStr::new)
        .collect();
    assert_eq!(status.get_args().collect::<Vec<_>>(), expected);
    let journal =
        private_unit_diagnostic_command(Path::new("/tmp"), PrivateUnitDiagnostic::Journal)
            .materialize()
            .unwrap();
    let expected: Vec<_> = [
        "-n",
        "journalctl",
        "--boot",
        "--no-pager",
        "--output=short-precise",
        "--lines=200",
    ]
    .into_iter()
    .chain(units.into_iter().flat_map(|unit| ["--unit", unit]))
    .map(OsStr::new)
    .collect();
    assert_eq!(journal.get_program(), OsStr::new("sudo"));
    assert_eq!(journal.get_args().collect::<Vec<_>>(), expected);
}

#[test]
fn actual_nonzero_child_capture_precedes_cleanup_and_never_replaces_primary_errors() {
    let owner = directory();
    let binary = owner
        .path()
        .join(if cfg!(windows) { "child.exe" } else { "child" });
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let compiler = CommandSpec::toolchain_program(
        "rustup",
        owner.path(),
        &config::toolchains(root).unwrap().stable,
        "rustc",
        Duration::from_secs(30),
    )
    .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/linux_unit_diagnostic_child.rs"))
    .args(["--edition", "2024", "-o"])
    .arg(&binary)
    .output_quiet()
    .unwrap();
    assert!(compiler.status.success(), "{compiler:?}");
    let order = RefCell::new(Vec::new());
    let (body, cleanup, diagnostics) = diagnose_then_cleanup(
        Err(CiError::Message("actual private ingress reset".into())),
        || {
            order.borrow_mut().push("diagnostics");
            let mut command = CommandSpec::new(&binary, owner.path(), Duration::from_secs(5))
                .materialize()
                .unwrap();
            retain_private_unit_diagnostic(
                owner.path(),
                PrivateUnitDiagnostic::Status,
                memcordon_testkit::run_with_deadline_output_limit(
                    &mut command,
                    Duration::from_secs(5),
                    PRIVATE_UNIT_DIAGNOSTIC_BYTES,
                ),
            )?;
            let capture: serde_json::Value = serde_json::from_slice(
                &std::fs::read(owner.path().join("unit-status.capture.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(capture["operation_complete"], true);
            assert_eq!(capture["observed_exit_code"], 3);
            assert_eq!(capture["observed_success"], false);
            assert_eq!(
                std::fs::read(owner.path().join("unit-status.stdout.bin")).unwrap(),
                b"actual unit status\xff\n"
            );
            assert_eq!(
                std::fs::read(owner.path().join("unit-status.stderr.bin")).unwrap(),
                b"actual startup rejection\xfe\n"
            );
            // A later attempt cannot overwrite the actual earlier capture.
            retain_private_unit_diagnostic(
                owner.path(),
                PrivateUnitDiagnostic::Status,
                Err(ProcessTestError::Spawn(std::io::Error::other(
                    "later spawn failure",
                ))),
            )
        },
        || {
            order.borrow_mut().push("cleanup");
            Err::<(), _>(CiError::Message("actual uninstall rejected".into()))
        },
    );
    assert_eq!(*order.borrow(), ["diagnostics", "cleanup"]);
    assert!(
        body.unwrap_err()
            .to_string()
            .contains("actual private ingress reset")
    );
    assert!(
        cleanup
            .unwrap_err()
            .to_string()
            .contains("actual uninstall rejected")
    );
    assert!(diagnostics.is_err());
    let capture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(owner.path().join("unit-status.capture.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["observed_exit_code"], 3);
    let (_, cleanup, diagnostics) = diagnose_then_cleanup(
        Ok(()),
        || panic!("successful body must not query native failure diagnostics"),
        || Ok(73),
    );
    assert_eq!(cleanup.unwrap(), 73);
    diagnostics.unwrap();
}

#[test]
fn partial_and_unavailable_unit_outputs_remain_explicit_without_fake_empty_streams() {
    let owner = directory();
    let partial = Err(ProcessTestError::Timeout {
        deadline: Duration::from_secs(10),
        stdout: b"partial unit stdout\xff".to_vec(),
        stderr: b"partial unit stderr\xfe".to_vec(),
        cleanup: Err("collector reaping unknown".into()),
        observation: Box::new(TimeoutObservation {
            child_id: 42,
            observed_status: None,
            callback_completed: false,
            spawn_returned: Duration::from_millis(1),
            boundary_admitted: Duration::from_millis(2),
            timeout_observed: Duration::from_secs(10),
            stdout_reader_finished: false,
            stderr_reader_finished: false,
        }),
    });
    assert!(
        retain_private_unit_diagnostic(owner.path(), PrivateUnitDiagnostic::Journal, partial)
            .is_err()
    );
    let capture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(owner.path().join("unit-journal.capture.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["operation_complete"], false);
    assert_eq!(capture["streams_available"], true);
    assert_eq!(capture["stdout_reader_finished"], false);
    assert!(capture["observed_exit_code"].is_null());
    assert_eq!(
        std::fs::read(owner.path().join("unit-journal.stdout.bin")).unwrap(),
        b"partial unit stdout\xff"
    );
    let unavailable = directory();
    assert!(
        retain_private_unit_diagnostic(
            unavailable.path(),
            PrivateUnitDiagnostic::Status,
            Err(ProcessTestError::Output(std::io::Error::other(
                "reader unavailable"
            )))
        )
        .is_err()
    );
    let capture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(unavailable.path().join("unit-status.capture.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(capture["streams_available"], false);
    assert!(capture["stdout_reader_finished"].is_null());
    assert!(!unavailable.path().join("unit-status.stdout.bin").exists());
    assert!(!unavailable.path().join("unit-status.stderr.bin").exists());
}
