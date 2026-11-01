#[path = "../src/bin/consumer_readiness_windows/gate_directory_record.rs"]
mod record;
use serde_json::{Value, json};

fn trace() -> Value {
    let entry = |sequence, root, output, status, name: &str| {
        let name: Vec<u16> = name.encode_utf16().collect();
        json!({"sequence":sequence,"thread_id":9044,"operation_code":1,"entered":1,"returned":1,
            "invalid_record":false,"coverage_inconclusive":false,"native_status":status,
            "opaque_raw_root":root,"opaque_raw_output":output,"desired_access":15,
            "root_is_null":if root==0 {1}else{0},"attributes_length":48,"attributes_flags":64,
            "arguments_readable":1,"name_readable":1,"name_malformed":0,"name_truncated":0,
            "name_utf16":name,"reported_name_bytes":name.len()*2,"copied_name_units":name.len(),
            "output_handle_readable":if status>=0 {1}else{0},"output_handle_returned":if output!=0 {1}else{0}})
    };
    let mut parent = entry(2, 0, 120, 0, "\\Sessions\\2\\BaseNamedObjects");
    parent["desired_access"] = 2.into();
    json!({"observed_entries_complete":true,"called":1,"original_current_thread_id":9044,
        "source_before_setup_validated":true,"source_after_setup_validated":true,"source_after_call_validated":true,
        "retained_directories":{"handles":[0,456,0,0,0,0,0,0],"errors":[0,0,0,0,0,0,0,0],"raw_handles_are_authority":false},
        "entries":[entry(1,0,0,-1073741790,"\\Sessions\\2\\BaseNamedObjects"),parent,entry(3,120,0,-1073741790,"Restricted")]})
}

#[test]
fn original_reference_and_exact_relative_call_are_linked_without_identity_authority() {
    let input = trace();
    let plans = record::plan(&input).unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].sequence, 2);
    assert_eq!(plans[0].raw_handle, 456);
    assert_eq!(plans[0].flags, 64);
    assert_eq!(plans[0].children.len(), 1);
    let child = &plans[0].children[0];
    assert_eq!(child.sequence, 3);
    assert_eq!(child.flags, 64);
    assert_eq!(child.name, "Restricted".encode_utf16().collect::<Vec<_>>());
    assert_eq!(input, trace());
    let mut different = trace();
    different["entries"][2]["opaque_raw_root"] = 121.into();
    assert!(record::plan(&different).unwrap()[0].children.is_empty());
}

#[test]
fn malformed_or_unavailable_handoffs_fail_without_native_operations() {
    for (path, value) in [
        ("/observed_entries_complete", json!(false)),
        ("/called", json!(0)),
        ("/source_after_call_validated", json!(false)),
        ("/original_current_thread_id", json!(0)),
        ("/entries/2/thread_id", json!(77)),
        ("/entries/2/sequence", json!(4)),
        ("/entries/2/coverage_inconclusive", json!(true)),
        ("/entries/1/output_handle_readable", json!(0)),
        ("/entries/1/native_status", json!(-1)),
        ("/entries/1/opaque_raw_output", Value::Null),
        ("/retained_directories/errors/1", json!(5)),
        (
            "/retained_directories/raw_handles_are_authority",
            json!(true),
        ),
        ("/retained_directories/handles/1", json!("456")),
        ("/retained_directories/handles", json!([456])),
        ("/entries/2/name_utf16", json!([0])),
        ("/entries/2/name_utf16", json!([65536])),
        ("/entries/2/attributes_flags", json!(0)),
        ("/entries/2/reported_name_bytes", json!(1)),
        ("/entries/2/name_truncated", json!(1)),
    ] {
        let mut input = trace();
        *input.pointer_mut(path).unwrap() = value;
        assert!(record::plan(&input).is_err(), "{path}");
    }
}

#[test]
fn later_handle_number_reuse_and_other_access_requests_do_not_reconstruct_failed_identity() {
    let mut input = trace();
    input["entries"][2]["desired_access"] = 3.into();
    assert!(record::plan(&input).unwrap()[0].children.is_empty());
    let mut input = trace();
    let mut reused = input["entries"][1].clone();
    reused["sequence"] = 3.into();
    input["entries"].as_array_mut().unwrap().insert(2, reused);
    input["entries"][3]["sequence"] = 4.into();
    assert!(record::plan(&input).unwrap()[0].children.is_empty());
}
