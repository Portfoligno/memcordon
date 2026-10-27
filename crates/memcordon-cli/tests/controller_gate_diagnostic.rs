#[path = "../src/bin/consumer_readiness_windows/controller_gate_diagnostic.rs"]
mod diagnostic;
#[path = "../src/bin/consumer_readiness_windows/controller_gate_error.rs"]
mod gate;
use std::{error::Error, io};

#[test]
fn only_missing_thread_token_allows_process_fallback() {
    assert_eq!(
        diagnostic::hex(&[0, 1, 15, 16, 127, 128, 255]),
        "00010f107f80ff"
    );
    assert_eq!(diagnostic::hex(&[]), "");
    assert!(diagnostic::process_fallback(1008));
    for code in [0, 5, 6, 87, 122, u32::MAX] {
        assert!(!diagnostic::process_fallback(code));
    }
    assert_eq!(diagnostic::impersonation_applicable(1), Some(false));
    assert_eq!(diagnostic::impersonation_applicable(2), Some(true));
    for kind in [0, 3, u32::MAX] {
        assert_eq!(diagnostic::impersonation_applicable(kind), None);
    }
}

#[test]
fn completed_native_decision_survives_post_call_expiry_without_claiming_conclusive_comparison() {
    let outcome = diagnostic::access_result(true, None, 0x0010_0000, true, false, None, true);
    assert_eq!(outcome["api_return"], true);
    assert_eq!(outcome["granted_access"], 0x0010_0000_u32);
    assert_eq!(outcome["access_status"], true);
    assert_eq!(outcome["original_work_confirmed"], false);
    assert_eq!(outcome["comparison_conclusive"], false);
    let outcome = diagnostic::access_result(false, Some(5), u32::MAX, true, false, None, true);
    assert_eq!(outcome["raw_os_error"], 5);
    assert!(outcome["granted_access"].is_null());
    assert!(outcome["access_status"].is_null());
}

#[test]
fn sid_group_and_query_extents_are_closed_and_finite() {
    let mut sid = vec![0; 8 + size_of::<u32>()];
    sid[0] = 1;
    sid[1] = 1;
    sid[7] = 5;
    assert_eq!(diagnostic::sid_extent(&sid), Some(sid.len()));
    for length in 0..sid.len() {
        assert_eq!(diagnostic::sid_extent(&sid[..length]), None);
    }
    sid[0] = 2;
    assert_eq!(diagnostic::sid_extent(&sid), None);
    sid[0] = 1;
    sid[1] = (diagnostic::SID_SUBAUTHORITIES + 1) as u8;
    assert_eq!(diagnostic::sid_extent(&sid), None);
    assert!(diagnostic::query_length(diagnostic::QUERY_BOUND));
    assert!(!diagnostic::query_length(0));
    assert!(!diagnostic::query_length(diagnostic::QUERY_BOUND + 1));
    let stride = size_of::<usize>() * 2;
    let start = size_of::<usize>();
    assert!(diagnostic::group_extent(0, stride, start, size_of::<u32>()));
    assert!(!diagnostic::group_extent(
        0,
        stride,
        start,
        size_of::<u32>() - 1
    ));
    let length = start + stride * diagnostic::GROUP_BOUND;
    assert!(diagnostic::group_extent(
        diagnostic::GROUP_BOUND,
        stride,
        start,
        length
    ));
    assert!(!diagnostic::group_extent(
        diagnostic::GROUP_BOUND + 1,
        stride,
        start,
        length
    ));
    assert!(!diagnostic::group_extent(
        diagnostic::GROUP_BOUND,
        stride,
        start,
        length - 1
    ));
    assert!(!diagnostic::group_extent(1, usize::MAX, 1, usize::MAX));
}

#[test]
fn bounded_diagnostic_and_query_failure_never_replace_original_open_error() {
    for observation in [
        Ok(
            diagnostic::encode(&serde_json::json!({"query_complete":false,"raw_os_error":6}))
                .unwrap(),
        ),
        Err(io::Error::from_raw_os_error(6)),
    ] {
        let error = gate::open_diagnostic(io::Error::from_raw_os_error(5), observation);
        let text = error.to_string();
        assert!(text.starts_with("operation=OpenEventW-controller-wait"));
        assert!(text.contains("raw-os-error=Some(5)"));
        assert!(
            text.find("raw-os-error=Some(5)").unwrap()
                < text.find("failure-only-effective-token").unwrap()
        );
        let source = error
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(source.raw_os_error(), Some(5));
        assert_eq!(error.kind(), source.kind());
        assert!(text.len() < diagnostic::RECORD_BOUND);
    }
}

#[test]
fn oversized_unicode_is_explicitly_unavailable_and_unformattable_cause_is_not_rendered() {
    let seed = "界";
    let large = seed.repeat(diagnostic::RECORD_BOUND.div_ceil(seed.len()) + 1);
    assert!(diagnostic::encode(&serde_json::json!({"facts":large})).is_err());
    #[derive(Debug)]
    struct Private;
    impl std::fmt::Display for Private {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("must not render query error")
        }
    }
    impl Error for Private {}
    let error = gate::open_diagnostic(
        io::Error::from_raw_os_error(5),
        Err(io::Error::other(Private)),
    );
    assert!(error.to_string().contains("diagnostic-encoding-failed"));
    assert_eq!(format!("{:?}", error.get_ref().unwrap()), error.to_string());
    // Keep the original unchanged wait/publication formatter mounted in this target too.
    assert!(
        gate::context(gate::Stage::Wait, Some(258), io::Error::other("wait"))
            .to_string()
            .contains("wait-status=Some(258)")
    );
    assert!(
        gate::context(
            gate::Stage::PublishRelease,
            None,
            io::Error::other("publish")
        )
        .to_string()
        .contains("controller-released-transcript")
    );
}
