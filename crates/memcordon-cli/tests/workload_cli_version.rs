use memcordon::invocation::{Invocation, route};

#[test]
fn sealed_defaults_to_current_result_and_ordinary_defaults_to_standard() {
    for (prefix, expected) in [
        (
            vec!["--sealed".into()],
            memcordon_core::ReportFormat::ResultV3,
        ),
        (Vec::new(), memcordon_core::ReportFormat::Standard),
    ] {
        let mut arguments = prefix;
        arguments.push("fixture-target".into());
        let Invocation::Execute(execution) = route(&arguments).unwrap() else {
            panic!("expected execution")
        };
        assert_eq!(execution.output.report_format, expected);
    }
}

#[test]
fn removed_contract_flag_is_an_ordinary_unknown_option() {
    for arguments in [
        vec![
            "--sealed",
            "--workload-contract",
            "absent.json",
            "fixture-target",
        ],
        vec!["doctor", "--workload-contract", "absent.json"],
        vec!["plan", "--workload-contract", "absent.json"],
    ] {
        let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
        assert_eq!(route(&arguments).unwrap_err().code, "MCCLI-UNKNOWN-OPTION");
    }
}

#[test]
fn current_request_requires_sealed_and_unsupported_header_has_no_old_decoder() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("request.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.workload-request", "revision":1,
            "runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},
            "requirements":[]
        }))
        .unwrap(),
    )
    .unwrap();
    let arguments = vec![
        "--sealed".into(),
        "--workload-request".into(),
        path.clone().into_os_string(),
        "fixture-target".into(),
    ];
    let Invocation::Execute(execution) = route(&arguments).unwrap() else {
        panic!("expected execution")
    };
    assert!(execution.policy.workload_request.is_some());
    assert!(route(&arguments[1..]).is_err());
    std::fs::write(&path, br#"{"format":"unsupported.request","revision":29}"#).unwrap();
    assert_eq!(
        route(&arguments).unwrap_err().code,
        "MCUSAGE-WORKLOAD-REQUEST"
    );
}

#[test]
fn output_selection_cannot_mix_standard_and_current_native_formats() {
    for (boundary, format) in [
        (Some("--sealed"), "standard"),
        (None, "result-v3"),
        (Some("--sealed"), "unsupported-result-format"),
    ] {
        let mut arguments = Vec::new();
        if let Some(boundary) = boundary {
            arguments.push(boundary.into());
        }
        arguments.extend([
            "--report-format".into(),
            format.into(),
            "fixture-target".into(),
        ]);
        assert!(route(&arguments).is_err());
    }
}
