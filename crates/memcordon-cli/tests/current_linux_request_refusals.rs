//! Pure frontend preparation checks; installed native effects are exercised in CI.
use memcordon::invocation::{Invocation, route};
use serde_json::{Value, json};
use std::{ffi::OsString, path::Path};

fn request() -> Value {
    json!({"format":"memcordon.workload-request","revision":1,
        "runtime":{"kind":"linux-private","profile":"linux-private-workload-v1",
            "inputs":{"runtime_digest":"11".repeat(32),"input_digest":"22".repeat(32),"entrypoint":"owned-readiness"},
            "layout":{"writable_roots":[],"output_files":[]}},"requirements":[]})
}
fn arguments(path: &Path, format: &str) -> Vec<OsString> {
    [
        "+128MiB",
        "+10s",
        "--sealed",
        "--report-format",
        format,
        "--workload-request",
    ]
    .into_iter()
    .map(Into::into)
    .chain([path.as_os_str().to_owned()])
    .chain(
        [
            "--workload-input",
            "caller-input.mci",
            "--report",
            "result.json",
            "--image-entrypoint",
            "owned-readiness",
            "--",
            "bytes-argv-status",
            "refusal-no-target",
            "0",
        ]
        .into_iter()
        .map(Into::into),
    )
    .collect()
}
#[test]
fn current_linux_negative_driver_operands_reach_selected_preparation_errors() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("request.json");
    std::fs::write(&path, serde_json::to_vec(&request()).unwrap()).unwrap();
    assert!(matches!(
        route(&arguments(&path, "result-v3")).unwrap(),
        Invocation::Execute(_)
    ));
    for scenario in [
        "unsupported-profile",
        "malformed-request",
        "unsupported-format",
        "identity-override-rejected",
        "unknown-request-variant",
        "duplicate-request",
    ] {
        let mut value = request();
        let bytes = match scenario {
            "unsupported-profile" => {
                value["runtime"]["profile"] = "unsupported-profile".into();
                serde_json::to_vec(&value).unwrap()
            }
            "unsupported-format" => br#"{"format":"unsupported-request","revision":255}"#.to_vec(),
            "malformed-request" | "duplicate-request" => {
                br#"{"format":"memcordon.workload-request","revision":1,"revision":1}"#.to_vec()
            }
            "identity-override-rejected" => {
                value["runtime"]["uid"] = 0.into();
                serde_json::to_vec(&value).unwrap()
            }
            "unknown-request-variant" => {
                value["runtime"]["kind"] = "unsupported-runtime".into();
                serde_json::to_vec(&value).unwrap()
            }
            _ => unreachable!(),
        };
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(
            route(&arguments(&path, "result-v3")).unwrap_err().code,
            "MCUSAGE-WORKLOAD-REQUEST",
            "{scenario}"
        );
    }
    std::fs::write(&path, serde_json::to_vec(&request()).unwrap()).unwrap();
    assert_eq!(
        route(&arguments(&path, "standard")).unwrap_err().code,
        "MCUSAGE-WORKLOAD-REPORT-FORMAT"
    );
}
