//! Decoder oracle vectors only; these tests do not execute Windows APIs or
//! establish native, installed, or whole-profile readiness.
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

fn event(sequence: u64, operation: &str, phase: &str) -> Value {
    json!({"sequence":sequence,"origin":"launcher","category":"monitor","operation":operation,
        "code":"target-query","native_code":{"win32":6},"observed_phase":phase,
        "safe_detail":"no-additional-detail","detail_redacted":true,"detail_truncated":false,
        "terminalization_reference":null})
}

fn journals() -> (Value, Value) {
    let original =
        json!({"observed":{"event":event(1,"read-target-exit","authorized-before-resume")}});
    let before = json!({"schema_version":1,"original":original,"secondary":[],"sequence":1,"durable_through_sequence":0,
        "loss":{"secondary_events_omitted":0,"secondary_count_saturated":false,"persistence_failure_observed":false,"writer_unavailable":false}});
    let mut after = before.clone();
    after["sequence"] = json!(2);
    after["secondary"] = json!([event(2, "poll-target", "monitoring")]);
    (before, after)
}

fn key() -> CaseKey {
    CaseKey {
        target: "x86_64-pc-windows-msvc".into(),
        channel: None,
        evidence_class: EvidenceClass::NativeComponentRegression,
        family: "W-CAUSAL".into(),
        scenario: "native-code-capture".into(),
    }
}

fn receipt() -> WindowsNativeComponentReceipt {
    WindowsNativeComponentReceipt{format:"memcordon.windows-native-component".into(),revision:1,run_id:"123".into(),recipe_id:"owned-native-tests".into(),
        test_name:"windows::diagnostics::causal_capture_tests::native_invalid_handle_capture_preserves_first_cause_across_phase_change".into(),
        native_target:key().target,executable_sha256:"1".repeat(64),payload:WindowsNativeComponentPayload::CausalCapture{
            before_journal:"before.json".into(),after_journal:"after.json".into(),first_api:"GetProcessTimes".into(),first_return:0,first_win32_code:6,
            second_api:"GetExitCodeProcess".into(),second_return:0,second_win32_code:6,invalid_handle_was_null:true}}
}

fn assess(
    receipt: &WindowsNativeComponentReceipt,
    before: &Value,
    after: &Value,
) -> VerificationResult<()> {
    let directory = tempfile::tempdir().unwrap();
    let mut artifacts = Vec::new();
    for (path, value) in [("before.json", before), ("after.json", after)] {
        let bytes = serde_json::to_vec(value).unwrap();
        std::fs::write(directory.path().join(path), &bytes).unwrap();
        artifacts.push(Artifact {
            path: path.into(),
            length: bytes.len() as u64,
            sha256: sha256(&bytes),
        });
    }
    validate_windows_native_component(receipt, &key(), &artifacts, directory.path())
}

#[test]
fn native_causal_capture_decoder_preserves_exact_first_cause_and_native_domains() {
    let (before, after) = journals();
    let baseline = receipt();
    assess(&baseline, &before, &after).unwrap();
    let mut wrong = baseline.clone();
    let WindowsNativeComponentPayload::CausalCapture {
        first_win32_code, ..
    } = &mut wrong.payload
    else {
        unreachable!()
    };
    *first_win32_code = 0;
    assert!(
        assess(&wrong, &before, &after).is_err(),
        "Rust test success is not a fabricated Win32 success code"
    );
    let mut changed = after.clone();
    changed["original"]["observed"]["event"]["native_code"] = json!({"win32":5});
    assert!(
        assess(&baseline, &before, &changed).is_err(),
        "later failure cannot replace first cause"
    );
    let mut changed = after.clone();
    changed["secondary"][0]["observed_phase"] = json!("authorized-before-resume");
    assert!(
        assess(&baseline, &before, &changed).is_err(),
        "actual phase transition is required"
    );
    let mut changed = after.clone();
    changed["secondary"] = json!([]);
    assert!(
        assess(&baseline, &before, &changed).is_err(),
        "second API observation cannot be omitted"
    );
    let mut wrong = baseline.clone();
    wrong.test_name = "a_different_passing_test".into();
    assert!(
        assess(&wrong, &before, &after).is_err(),
        "unrelated native test is not causal capture"
    );
    let mut changed_before = before.clone();
    let mut changed_after = after.clone();
    for journal in [&mut changed_before, &mut changed_after] {
        journal["original"]["observed"]["event"]["native_code"] = json!({"nt-status":6});
    }
    assert!(
        assess(&baseline, &changed_before, &changed_after).is_err(),
        "jointly edited journals cannot relabel the actual native code domain"
    );
}
