use memcordon_readiness_verifier::{current::windows::validate_native_recovery_phase, sha256};
use serde_json::json;

#[test]
fn selected_recovery_requires_real_inventory_wait_and_original_bounded_command() {
    let cli =
        json!({"path":"C:\\selected\\memcordon.exe","sha256":sha256(b"actual public client")});
    let provider = json!({"generation":"selected-generation","source_commit":"ab".repeat(20),"runtime_manifest_sha256":sha256(b"manifest")});
    let directory = "C:\\owned\\current";
    let capture = json!({"output_directory":"C:\\owned\\current\\outer-finalization","artifacts":[{"path":"original-native-inventory","sha256":sha256(b"inventory")}],"native_status":0,"deadline_exhausted":false,"recovery":{"Ok":null},"native_quiescence":{"Ok":null}});
    let invocation = json!({"format":"memcordon.windows-native-recovery-invocation","revision":1,"cli":cli,"provider":provider,"cwd":capture["output_directory"],"argv_utf16":["windows-recover".encode_utf16().collect::<Vec<_>>(),"converge".encode_utf16().collect::<Vec<_>>(),"30000".encode_utf16().collect::<Vec<_>>()],"environment_cleared":true,"command_budget_millis":60000});
    let inventory = json!({"schema_version":1,"challenge":"original random native challenge","provider_generation":"selected-generation","current_boot_identity":"actual-boot","executing":0,"incomplete_proof":0,"unacknowledged_outboxes":0,"ack_retirement_in_progress":0,"completed_tombstones":2,"active_admissions":0,"quarantined":0});
    let verify = |invocation: &serde_json::Value,
                  capture: &serde_json::Value,
                  inventory: &serde_json::Value| {
        validate_native_recovery_phase(
            invocation,
            capture,
            &serde_json::to_vec(inventory).unwrap(),
            &cli,
            &provider,
            directory,
        )
    };
    verify(&invocation, &capture, &inventory).unwrap();
    for field in [
        "executing",
        "incomplete_proof",
        "unacknowledged_outboxes",
        "ack_retirement_in_progress",
        "active_admissions",
        "quarantined",
    ] {
        let mut changed = inventory.clone();
        changed[field] = json!(1);
        assert!(verify(&invocation, &capture, &changed).is_err());
    }
    let mut changed = capture.clone();
    changed["native_status"] = json!(126);
    assert!(verify(&invocation, &changed, &inventory).is_err());
    let mut changed = capture.clone();
    changed["deadline_exhausted"] = json!(true);
    assert!(verify(&invocation, &changed, &inventory).is_err());
    let mut changed = invocation.clone();
    changed["command_budget_millis"] = json!(30000);
    assert!(verify(&changed, &capture, &inventory).is_err());
    let mut changed = invocation.clone();
    changed["provider"]["generation"] = json!("foreign");
    assert!(verify(&changed, &capture, &inventory).is_err());
}
