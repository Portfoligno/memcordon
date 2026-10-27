use super::*;

#[test]
fn serialized_pass_omissions_are_explicit_and_do_not_become_complete() {
    let detail = serde_json::to_string(&vec!["\\\""; ERROR_BOUND]).unwrap();
    let records: Vec<_> = (0..THREAD_BOUND)
        .map(|tid| json!({"tid":tid,"error":error("query",io::Error::other(detail.clone()))}))
        .collect();
    let bounded = bounded_pass(json!({"threads":records,"complete":true,"record_omitted_count":0}));
    assert!(serde_json::to_vec(&bounded).unwrap().len() <= PASS_BOUND);
    assert_eq!(bounded["complete"], false);
    assert!(bounded["record_omitted_count"].as_u64().unwrap() > 0);
}

#[test]
fn actual_query_errors_are_labelled_bounded_and_not_zero_counters() {
    let value = error("OpenThread-query-sync", io::Error::from_raw_os_error(5));
    assert_eq!(value["operation"], "OpenThread-query-sync");
    assert_eq!(value["raw_os_error"], 5);
    assert!(value.get("kernel_100ns").is_none());
    let long = error(
        "query",
        io::Error::other(serde_json::to_string(&vec!["λ"; ERROR_BOUND]).unwrap()),
    );
    assert!(long["detail"].as_str().unwrap().len() <= ERROR_BOUND);
    assert_eq!(long["detail_truncated"], true);
}
