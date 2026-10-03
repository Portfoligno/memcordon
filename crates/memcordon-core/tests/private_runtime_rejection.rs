use memcordon_core::{
    BoundedText, DiagnosticSha256, PublicProviderBindingV1,
    private_runtime::PrivateRuntimeRejection, workload_contract::WorkloadContractV2,
};

fn rejection() -> PrivateRuntimeRejection {
    let contract = WorkloadContractV2::parse(include_bytes!(
        "../../../fuzz/corpus/workload-request/baseline-v2.json"
    ))
    .unwrap();
    PrivateRuntimeRejection {
        format: "memcordon.private-runtime-rejection".into(),
        revision: 1,
        provider: PublicProviderBindingV1 {
            generation: BoundedText::new("1.2.3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            source_commit: BoundedText::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            runtime_manifest_sha256: DiagnosticSha256::from_bytes([7; 32]),
        },
        attempt_id: [1; 16],
        request_sha256: DiagnosticSha256::from_bytes([2; 32]),
        invocation_sha256: DiagnosticSha256::from_bytes([3; 32]),
        contract,
        boundary_allocated: false,
        reservation_may_remain: false,
        detail: BoundedText::new("exact live grant rejected before allocation").unwrap(),
    }
}
#[test]
fn preallocation_rejection_retains_independent_raw_attempt_contract_and_native_invocation() {
    let expected = rejection();
    let bytes = serde_json::to_vec(&expected).unwrap();
    let parse = |bytes: &[u8]| {
        PrivateRuntimeRejection::parse_bound(
            bytes,
            &expected.provider,
            expected.attempt_id,
            &expected.request_sha256,
            &expected.contract,
            &expected.invocation_sha256,
        )
    };
    parse(&bytes).unwrap();
    for case in [
        "namespace",
        "revision",
        "attempt",
        "request",
        "invocation",
        "created",
        "contract",
        "provider",
        "unknown",
    ] {
        let mut value = serde_json::to_value(&expected).unwrap();
        match case {
            "namespace" => {
                value["format"] = serde_json::json!("memcordon.private-runtime-terminal")
            }
            "revision" => value["revision"] = serde_json::json!(2),
            "attempt" => value["attempt_id"] = serde_json::to_value([2; 16]).unwrap(),
            "request" => {
                value["request_sha256"] =
                    serde_json::to_value(DiagnosticSha256::from_bytes([4; 32])).unwrap()
            }
            "invocation" => {
                value["invocation_sha256"] =
                    serde_json::to_value(DiagnosticSha256::from_bytes([4; 32])).unwrap()
            }
            "created" => value["boundary_allocated"] = serde_json::json!(true),
            "contract" => value["contract"]["version"] = serde_json::json!(3),
            "provider" => {
                value["provider"]["source_commit"] =
                    serde_json::json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            }
            "unknown" => value["authorization_token"] = serde_json::json!(true),
            _ => unreachable!(),
        }
        assert!(
            parse(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{case}"
        );
    }
    let mut charged = expected.clone();
    charged.reservation_may_remain = true;
    parse(&serde_json::to_vec(&charged).unwrap()).unwrap();
}
