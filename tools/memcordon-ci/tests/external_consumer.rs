use memcordon_ci::{
    external_consumer::{ExternalConsumerSpec, require_coverage},
    release::artifacts,
};
use serde_json::json;

fn spec() -> serde_json::Value {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path();
    json!({"format":"memcordon.external-consumer","revision":1,
        "target":"x86_64-unknown-linux-gnu","version":"1.2.3","runtime_features":[],
        "selection":"measured-cli","selected_inputs":[],
        "cli":{"path":directory.join("memcordon"),"sha256":artifacts::checksum(b"cli")},
        "workload":{"path":directory.join("consumer"),"sha256":artifacts::checksum(b"consumer")},
        "working_directory":directory,"arguments":[],"requested_contract":{"kind":"standard"},
        "report_format":"result-v1","report_revision":1,"expected_outcome":"completed",
        "expected_native_termination":{"kind":"exit-code","code":0},"expected_wrapper_status":0,
        "coverage":{"kind":"libtest","tests":["first","second"]},"outer_deadline_millis":10000})
}

#[test]
fn expected_inventory_is_trusted_explicit_nonempty_and_named() {
    let bytes = serde_json::to_vec(&spec()).unwrap();
    ExternalConsumerSpec::parse(&bytes).unwrap();
    for field in [
        "format",
        "revision",
        "report_format",
        "report_revision",
        "target",
        "outer_deadline_millis",
        "arguments",
        "runtime_features",
    ] {
        let mut invalid = spec();
        invalid[field] = match field {
            "format" => json!("memcordon.result"),
            "report_format" => json!("schema-11"),
            "target" => json!("unknown-target"),
            "revision" | "report_revision" => json!(2),
            "outer_deadline_millis" => json!(0),
            "runtime_features" => json!(["private-tcp", "private-tcp"]),
            _ => json!([{"display":"a\u{0000}b","raw":null}]),
        };
        assert!(
            ExternalConsumerSpec::parse(&serde_json::to_vec(&invalid).unwrap()).is_err(),
            "{field}"
        );
    }
    for tests in [json!([]), json!(["same", "same"])] {
        let mut invalid = spec();
        invalid["coverage"]["tests"] = tests;
        assert!(ExternalConsumerSpec::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    for selection in ["native-archive", "cargo-packages", "unknown"] {
        let mut invalid = spec();
        invalid["selection"] = json!(selection);
        assert!(ExternalConsumerSpec::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"revision\":1",
        "\"revision\":1,\"revision\":1",
        1,
    );
    assert!(ExternalConsumerSpec::parse(duplicate.as_bytes()).is_err());
}

#[test]
fn full_execution_inventory_and_all_counters_are_required() {
    let expected = vec!["first".into(), "second".into()];
    let valid=b"running 2 tests\ntest first ... ok\ntest second ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n";
    require_coverage(valid, &expected).unwrap();
    let text = std::str::from_utf8(valid).unwrap();
    for (before, after) in [
        ("2 passed", "0 passed"),
        ("0 failed", "1 failed"),
        ("0 ignored", "1 ignored"),
        ("0 measured", "1 measured"),
        ("0 filtered out", "1 filtered out"),
        ("test second ... ok", "test extra ... ok"),
        ("test second ... ok", "test first ... ok"),
        ("test second ... ok", "test second ... ignored"),
        ("test result: ok.", "test result: FAILED."),
        ("2 passed", "184467440737095516160 passed"),
        ("running 2 tests", "running 0 tests"),
        ("running 2 tests", "running 2 test"),
        ("running 2 tests", "running two tests"),
        ("test second ... ok", "test second ... maybe"),
        ("test second ... ok", "test second ok"),
        ("0.01s", "NaNs"),
        ("0.01s", "infs"),
        ("0.01s", "0.01s extra"),
        ("0.01s", "1e3s"),
    ] {
        assert!(
            require_coverage(text.replace(before, after).as_bytes(), &expected).is_err(),
            "{before} → {after}"
        );
    }
    assert!(require_coverage(b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s\n",&expected).is_err());
    assert!(require_coverage(b"test first ... ok\n", &expected).is_err());
    let mut duplicate = valid.to_vec();
    duplicate.extend_from_slice(b"test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n");
    assert!(require_coverage(&duplicate, &expected).is_err());
    let mut unknown = valid.to_vec();
    unknown.extend_from_slice(b"unknown extra executed case\n");
    assert!(require_coverage(&unknown, &expected).is_err());
    assert!(
        require_coverage(
            text.strip_prefix("running 2 tests\n").unwrap().as_bytes(),
            &expected
        )
        .is_err()
    );
    let mut truncated = valid.to_vec();
    truncated.truncate(truncated.len() - b"finished in 0.01s\n".len());
    assert!(require_coverage(&truncated, &expected).is_err());
}

#[cfg(unix)]
#[test]
fn native_argument_display_cannot_hide_substituted_raw_bytes() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut value = spec();
    value["arguments"] = json!([{"display":"wrong","raw":{"encoding":"unix-bytes-base64","data":STANDARD.encode([255])}}]);
    assert!(ExternalConsumerSpec::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    value["arguments"][0]["display"] = json!("�");
    ExternalConsumerSpec::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    value["arguments"][0]["raw"]["encoding"] = json!("windows-u16le-base64");
    assert!(ExternalConsumerSpec::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}
