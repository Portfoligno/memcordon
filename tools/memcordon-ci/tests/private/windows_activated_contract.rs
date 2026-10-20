use super::*;

#[test]
fn activated_contract_selection_is_absolute_exclusive_and_shared_by_both_frontends() {
    let cwd = std::env::current_dir().unwrap();
    let owned = tempfile::tempdir_in(&cwd).unwrap();
    let relative = owned.path().strip_prefix(&cwd).unwrap();
    assert!(!relative.is_absolute());
    let key = CaseKey {
        family: "W-ENVELOPE".into(),
        scenario: "restricted".into(),
    };
    // This helper preserves serialized bytes; contract validation belongs to
    // the activation caller, not to this path-selection regression.
    let bytes = b"original activated contract bytes\n";
    let selected = write_activated_contract(relative, &key, bytes).unwrap();
    assert!(selected.is_absolute());
    assert_eq!(
        selected,
        cwd.join(relative)
            .join("W-ENVELOPE")
            .join("restricted")
            .join("requested-contract.json")
    );
    assert_eq!(std::fs::read(&selected).unwrap(), bytes);
    assert!(write_activated_contract(relative, &key, b"replacement").is_err());
    assert_eq!(std::fs::read(&selected).unwrap(), bytes);
    let root = owned.path().to_path_buf();
    let descriptor = descriptor::Descriptor {
        format: "memcordon.fixture-workload".into(),
        revision: 1,
        case: descriptor::Case::Envelope,
        transcript: root.join("events.bin"),
        output_root: root.clone(),
        challenge: vec![1, 2, 3],
        stdout: vec![],
        stderr: vec![],
        arguments: vec![],
        application_status: 0,
        churn_creations: 0,
        churn_live: 0,
        denied_write_paths: vec![],
        sentinel_handles: vec![],
        descendant_gate: None,
        start_gate: None,
        completion_gate: None,
        cohort_gate: None,
        generation_gate: None,
        toolchain: None,
    };
    let mut case = CaseInput {
        key,
        descriptor,
        descriptor_path: root.join("input.json"),
        workload_contract: selected.clone(),
        expected_token: TokenObservation {
            user_sid: vec![1],
            restricted: true,
            integrity_rid: 12288,
            elevated: true,
            restricting_sids: vec![vec![2]],
        },
    };
    let cli = root.join("cli.exe");
    let fixture = root.join("fixture.exe");
    let report = root.join("result.json");
    let selection = root.join("selection.json");
    let observation = root.join("observation.json");
    let original = public_command(&cli, &fixture, &root, &report, &case)
        .unwrap()
        .materialize()
        .unwrap();
    let diagnostic = installed_support_loader_command(
        &cli,
        &fixture,
        &root,
        &report,
        &case,
        &selection,
        &observation,
    )
    .unwrap()
    .materialize()
    .unwrap();
    let original_args: Vec<_> = original.get_args().map(std::ffi::OsStr::to_owned).collect();
    let diagnostic_args: Vec<_> = diagnostic
        .get_args()
        .map(std::ffi::OsStr::to_owned)
        .collect();
    assert_eq!(original.get_program(), diagnostic.get_program());
    assert_eq!(original.get_current_dir(), diagnostic.get_current_dir());
    let target = original_args.iter().position(|arg| arg == "--").unwrap();
    let diagnostic_target = diagnostic_args.iter().position(|arg| arg == "--").unwrap();
    assert_eq!(
        &original_args[target..],
        &diagnostic_args[diagnostic_target..]
    );
    let expected_target = vec![
        std::ffi::OsString::from("--"),
        fixture.into_os_string(),
        "consumer-readiness-windows".into(),
        case.descriptor_path.clone().into_os_string(),
    ];
    assert_eq!(&original_args[target..], expected_target.as_slice());
    for args in [&original_args, &diagnostic_args] {
        let contract = args
            .iter()
            .position(|arg| arg == "--workload-contract")
            .unwrap();
        assert_eq!(args[contract + 1], selected.as_os_str());
        assert_eq!(args[1], "system-restricted-frontend");
    }
    case.workload_contract = relative.join("contract.json");
    assert!(
        installed_support_loader_command(
            &cli,
            &root.join("fixture.exe"),
            &root,
            &report,
            &case,
            &selection,
            &observation
        )
        .is_err()
    );
    case.workload_contract = selected;
    case.descriptor_path = relative.join("input.json");
    assert!(
        installed_support_loader_command(
            &cli,
            &root.join("fixture.exe"),
            &root,
            &report,
            &case,
            &selection,
            &observation
        )
        .is_err()
    );
}
