use memcordon_windows_loader_lab::workload::WorkloadDiagnosticRequestV1;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn original() -> WorkloadDiagnosticRequestV1 {
    let result = include_bytes!("fixtures/released-initialization-failure.json").to_vec();
    let terminal = include_bytes!("fixtures/released-initialization-terminal.json").to_vec();
    let result_value: Value = serde_json::from_slice(&result).unwrap();
    let terminal_value: Value = serde_json::from_slice(&terminal).unwrap();
    let request_bytes: Vec<u8> =
        serde_json::from_value(terminal_value["provider_request"].clone()).unwrap();
    let original_request: memcordon_core::WindowsLaunchRequestV1 =
        serde_json::from_slice(&request_bytes).unwrap();
    let original_descriptor: Value = serde_json::from_slice(include_bytes!(
        "fixtures/released-initialization-descriptor.json"
    ))
    .unwrap();
    let mut descriptor = original_descriptor.clone();
    descriptor["output_root"] = json!("D:\\diagnostic\\one");
    descriptor["transcript"] = json!("D:\\diagnostic\\one\\fixture-events.bin");
    descriptor["start_gate"] = json!("Local\\memcordon-workload-diagnostic-one");
    let descriptor_path = std::path::PathBuf::from("D:\\diagnostic\\one\\input.json");
    let mut command = original_request.command.clone();
    command.arguments[1] = descriptor_path.to_str().unwrap().encode_utf16().collect();
    WorkloadDiagnosticRequestV1 {
        schema_version: 1,
        default_dacl_probe: None,
        original_result_sha256: digest(&result),
        original_terminal_sha256: digest(&terminal),
        original_result_bytes: result,
        original_terminal_bytes: terminal,
        original_request_bytes: request_bytes,
        original_pid: 8548,
        original_birth: 134370860279853115,
        reference_plan: serde_json::from_str(
            result_value
                .pointer("/attempts/0/boundary_detail/loader_qualification/result/launch_plan_json")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap(),
        image_sha256: "a".repeat(64),
        original_request,
        command,
        original_descriptor_sha256: digest(&serde_json::to_vec(&original_descriptor).unwrap()),
        descriptor_sha256: digest(&serde_json::to_vec(&descriptor).unwrap()),
        original_descriptor,
        descriptor,
        descriptor_path,
        output_directory: "D:\\diagnostic\\one".into(),
        diagnostic_id: "one".into(),
        gate_security_descriptor_sddl: "O:SYD:P(A;;GA;;;SY)(A;;0x00100000;;;RC)".into(),
        work_deadline_tick_ms: 100,
        cleanup_deadline_tick_ms: 200,
    }
}

fn eligibility(
    request: &WorkloadDiagnosticRequestV1,
) -> memcordon_windows_loader_lab::workload::DefaultDaclProbeEligibilityV1 {
    use memcordon_windows_loader_lab::workload::{
        DefaultDaclProbeEligibilityV1, DefaultDaclProbeKindV1, DefaultDaclProbeTargetV1,
    };
    DefaultDaclProbeEligibilityV1 {
        revision: 1,
        kind: DefaultDaclProbeKindV1::QualifiedRestrictedEnvelopeFixture,
        source_commit: request
            .original_request
            .expected_provider_binding
            .source_commit
            .as_str()
            .to_owned(),
        target: DefaultDaclProbeTargetV1::X86_64WindowsMsvc,
        fixture_sha256: request.image_sha256.clone(),
        original_result_sha256: request.original_result_sha256.clone(),
        original_terminal_sha256: request.original_terminal_sha256.clone(),
        original_descriptor_sha256: request.original_descriptor_sha256.clone(),
    }
}

#[test]
fn optional_eligibility_binds_original_source_role_and_all_evidence() {
    let mut request = original();
    request.validate().unwrap();
    let baseline = serde_json::to_vec(&request).unwrap();
    assert!(
        serde_json::from_slice::<Value>(&baseline)
            .unwrap()
            .get("default_dacl_probe")
            .is_none()
    );
    request.default_dacl_probe = Some(eligibility(&request));
    request.validate().unwrap();
    let qualified = serde_json::to_value(&request).unwrap();
    assert_ne!(
        digest(&baseline),
        digest(&serde_json::to_vec(&request).unwrap())
    );
    for field in [
        "source_commit",
        "fixture_sha256",
        "original_result_sha256",
        "original_terminal_sha256",
        "original_descriptor_sha256",
    ] {
        let mut changed = qualified.clone();
        changed["default_dacl_probe"][field] = json!(digest(b"different selected evidence"));
        let changed: WorkloadDiagnosticRequestV1 = serde_json::from_value(changed).unwrap();
        assert!(changed.validate().is_err(), "accepted foreign {field}");
    }
    let mut wrong_revision = request.clone();
    wrong_revision.default_dacl_probe.as_mut().unwrap().revision += 1;
    assert!(wrong_revision.validate().is_err());
    for (field, value) in [
        ("kind", json!("arbitrary-workload")),
        ("target", json!("x86_64-unknown-linux-gnu")),
        ("unknown", json!(true)),
    ] {
        let mut changed = qualified.clone();
        changed["default_dacl_probe"][field] = value;
        assert!(serde_json::from_value::<WorkloadDiagnosticRequestV1>(changed).is_err());
    }
    let mut missing = qualified.clone();
    missing["default_dacl_probe"]
        .as_object_mut()
        .unwrap()
        .remove("fixture_sha256");
    assert!(serde_json::from_value::<WorkloadDiagnosticRequestV1>(missing).is_err());
    let mut null = qualified.clone();
    null["default_dacl_probe"] = Value::Null;
    assert!(serde_json::from_value::<WorkloadDiagnosticRequestV1>(null).is_err());
    let mut oversized = request.clone();
    oversized.default_dacl_probe.as_mut().unwrap().source_commit = String::from_utf8(vec![
        b'a';
        memcordon_windows_loader_lab::workload::MAX_PROBE_ELIGIBILITY_BYTES
            + 1
    ])
    .unwrap();
    assert!(oversized.validate().is_err());
    let mut different_case = request.clone();
    different_case.descriptor["case"] = json!("unrelated");
    different_case.descriptor_sha256 =
        digest(&serde_json::to_vec(&different_case.descriptor).unwrap());
    assert!(different_case.validate().is_err());
    assert!(
        request
            .default_dacl_probe
            .as_ref()
            .unwrap()
            .validate_native(0)
            .is_err()
    );
}

#[test]
fn raw_transport_digest_is_distinct_from_canonical_holder_binding() {
    let mut request = original();
    request.default_dacl_probe = Some(eligibility(&request));
    let canonical = serde_json::to_vec(&request).unwrap();
    WorkloadDiagnosticRequestV1::parse_transport(&canonical, &digest(&canonical)).unwrap();
    let mut spaced = canonical.clone();
    spaced.push(b'\n');
    assert!(WorkloadDiagnosticRequestV1::parse_transport(&spaced, &digest(&canonical)).is_err());
    let parsed = WorkloadDiagnosticRequestV1::parse_transport(&spaced, &digest(&spaced)).unwrap();
    assert_eq!(
        digest(&serde_json::to_vec(&parsed).unwrap()),
        digest(&canonical)
    );
    let duplicate = format!(
        "{{\"schema_version\":1,{}",
        std::str::from_utf8(&canonical)
            .unwrap()
            .strip_prefix('{')
            .unwrap()
    );
    assert!(
        WorkloadDiagnosticRequestV1::parse_transport(
            duplicate.as_bytes(),
            &digest(duplicate.as_bytes())
        )
        .is_err()
    );
    assert!(
        WorkloadDiagnosticRequestV1::parse_transport(&canonical, &digest(b"foreign request bytes"))
            .is_err()
    );
    let oversized = vec![b' '; memcordon_windows_loader_lab::workload::MAX_REQUEST_BYTES + 1];
    assert!(WorkloadDiagnosticRequestV1::parse_transport(&oversized, &digest(&oversized)).is_err());
}

#[cfg(windows)]
#[test]
fn native_request_pin_refuses_writers_replacement_and_foreign_digest() {
    use memcordon_windows_loader_lab::workload::HeldWorkloadRequest;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("request.json");
    let bytes = serde_json::to_vec(&original()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    assert!(HeldWorkloadRequest::open(&path, Some(&digest(b"other request"))).is_err());
    let held = HeldWorkloadRequest::open(&path, Some(&digest(&bytes))).unwrap();
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(std::fs::rename(&path, root.path().join("replaced.json")).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    held.recheck(&path).unwrap();
    drop(held);
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(HeldWorkloadRequest::open(&path, Some(&digest(&bytes))).is_err());
}

#[test]
fn binds_real_released_failure_and_only_explicit_descriptor_differences() {
    original().validate().unwrap();
    let mut changed = original();
    changed.command.program.push(42);
    assert!(changed.validate().is_err());
    let mut changed = original();
    changed.descriptor["application_status"] = json!(99);
    changed.descriptor_sha256 = digest(&serde_json::to_vec(&changed.descriptor).unwrap());
    assert!(changed.validate().is_err());
}

#[test]
fn rejects_foreign_originals_and_incomplete_native_retirement_even_when_rehashed() {
    for pointer in [
        "/terminal/retirement_proof/native_job_empty_observed",
        "/terminal/retirement_proof/owner_capabilities_closed",
    ] {
        let mut changed = original();
        let mut terminal: Value = serde_json::from_slice(&changed.original_terminal_bytes).unwrap();
        *terminal.pointer_mut(pointer).unwrap() = json!(false);
        changed.original_terminal_bytes = serde_json::to_vec(&terminal).unwrap();
        changed.original_terminal_sha256 = digest(&changed.original_terminal_bytes);
        assert!(changed.validate().is_err(), "{pointer}");
    }
    let mut changed = original();
    changed.original_birth += 1;
    assert!(changed.validate().is_err());
    let mut changed = original();
    changed.original_request_bytes.push(b' ');
    assert!(changed.validate().is_err());
}

#[test]
fn rejects_host_relative_or_escaping_diagnostic_paths() {
    let mut changed = original();
    changed.gate_security_descriptor_sddl.push('\0');
    assert!(changed.validate().is_err());
    for path in [
        "input.json",
        "/tmp/input.json",
        "D:\\diagnostic\\one\\..\\input.json",
        "D:\\diagnostic\\other\\input.json",
        "D:/diagnostic/one/input.json",
    ] {
        let mut changed = original();
        changed.descriptor_path = path.into();
        changed.command.arguments[1] = path.encode_utf16().collect();
        assert!(changed.validate().is_err(), "{path}");
    }
}
