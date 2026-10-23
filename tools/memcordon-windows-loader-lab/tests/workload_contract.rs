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
