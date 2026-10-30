use super::{CellArguments, CellOperation, privileged_cell_command, toolchain_environment};
use std::{
    ffi::OsString,
    path::PathBuf,
    time::{Duration, Instant},
};

#[test]
fn execution_and_cleanup_preserve_only_the_same_selected_toolchain_and_owner_arguments() {
    let root = tempfile::Builder::new()
        .prefix("readiness caller ")
        .tempdir()
        .unwrap();
    let root = root.path().canonicalize().unwrap();
    let executable = root.join("selected driver with spaces");
    let arguments = CellArguments {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: "candidate-native".into(),
        identity: PathBuf::from("selected identity/source.json"),
        destination: PathBuf::from("selected destination/cell"),
        operation_deadline_unix_millis: 1792324633463,
        owner_preparation_sha256: None,
    };
    let selected_environment = toolchain_environment(
        OsString::from("/selected toolchain/bin:/usr/bin:/bin"),
        PathBuf::from("/selected caller/rustup home"),
    );
    assert_eq!(
        selected_environment,
        [
            OsString::from("PATH=/selected toolchain/bin:/usr/bin:/bin"),
            OsString::from("RUSTUP_HOME=/selected caller/rustup home"),
        ]
    );
    let cutoff = Instant::now() + Duration::from_secs(300);
    for (operation, verb) in [
        (CellOperation::Execute, "consumer-readiness-cell"),
        (CellOperation::Cleanup, "consumer-readiness-cleanup"),
    ] {
        let specification = privileged_cell_command(
            &root,
            &arguments,
            operation,
            selected_environment.clone(),
            &executable,
            cutoff,
        )
        .unwrap();
        let command = specification.materialize().unwrap();
        assert_eq!(command.get_program(), "sudo");
        assert_eq!(command.get_current_dir(), Some(root.as_path()));
        let expected = vec![
            OsString::from("-n"),
            OsString::from("--"),
            OsString::from("/usr/bin/env"),
            selected_environment[0].clone(),
            selected_environment[1].clone(),
            executable.clone().into_os_string(),
            OsString::from(verb),
            OsString::from("--target"),
            OsString::from(&arguments.target),
            OsString::from("--channel"),
            OsString::from(&arguments.channel),
            OsString::from("--identity"),
            std::path::absolute(&arguments.identity)
                .unwrap()
                .into_os_string(),
            OsString::from("--destination"),
            std::path::absolute(&arguments.destination)
                .unwrap()
                .into_os_string(),
            OsString::from("--operation-deadline-unix-millis"),
            OsString::from("1792324633463"),
        ];
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            expected.iter().map(OsString::as_os_str).collect::<Vec<_>>()
        );
        // A spent original monotonic cutoff must prevent this genuine sudo
        // command from starting. No privilege execution or renewed budget.
        let expired = privileged_cell_command(
            &root,
            &arguments,
            operation,
            selected_environment.clone(),
            &executable,
            Instant::now(),
        )
        .unwrap();
        let error = expired.output_quiet().unwrap_err().to_string();
        assert!(error.contains("BudgetExhaustedBeforePhase"), "{error}");
    }
}
