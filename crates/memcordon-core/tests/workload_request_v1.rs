use memcordon_core::workload_request::{RequestError, WorkloadRequestV1};

fn windows() -> serde_json::Value {
    serde_json::json!({"format":"memcordon.workload-request","revision":1,
        "runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},"requirements":[]})
}

#[test]
fn active_parser_rejects_unsupported_formats_revisions_and_duplicate_keys() {
    for format in ["example.unsupported", "memcordon.request.unknown"] {
        let bytes = serde_json::to_vec(&serde_json::json!({"format":format,"revision":1})).unwrap();
        assert_eq!(
            WorkloadRequestV1::parse(&bytes),
            Err(RequestError::UnsupportedRequestVersion)
        );
    }
    let mut value = windows();
    value["revision"] = 2.into();
    assert_eq!(
        WorkloadRequestV1::parse(&serde_json::to_vec(&value).unwrap()),
        Err(RequestError::UnsupportedRequestVersion)
    );
    assert!(matches!(
        WorkloadRequestV1::parse(
            br#"{"format":"memcordon.workload-request","revision":1,"revision":1}"#
        ),
        Err(RequestError::MalformedRequest(_))
    ));
    for field in [
        "authorization",
        "expected_epoch",
        "execution_identity",
        "approved_plan_digest",
        "uid",
        "gid",
    ] {
        let mut value = windows();
        value[field] = 1.into();
        assert!(
            matches!(
                WorkloadRequestV1::parse(&serde_json::to_vec(&value).unwrap()),
                Err(RequestError::MalformedRequest(_))
            ),
            "accepted authority field {field}"
        );
    }
}

#[test]
fn caller_requests_are_not_administrator_contracts() {
    let request = WorkloadRequestV1::parse(&serde_json::to_vec(&windows()).unwrap()).unwrap();
    assert_eq!(
        WorkloadRequestV1::parse(&request.canonical_bytes().unwrap()).unwrap(),
        request
    );
    let mut value = windows();
    value["requirements"] =
        serde_json::json!([{"kind":"generated_executable","id":"build","writable_root":"out"}]);
    assert!(matches!(
        WorkloadRequestV1::parse(&serde_json::to_vec(&value).unwrap()),
        Err(RequestError::UnsupportedRequirement(_))
    ));
}

#[test]
fn root_paths_cannot_be_host_paths_or_aliases() {
    use memcordon_core::workload_request::RootRelativePath;
    for path in ["", "/etc/passwd", "a/../b", "a//b", "./a", "a/", "a\0b"] {
        assert!(
            RootRelativePath::new(path.into()).is_err(),
            "accepted unsafe path {path:?}"
        );
    }
    assert!(RootRelativePath::new("workspace/out/file".into()).is_ok());
}
