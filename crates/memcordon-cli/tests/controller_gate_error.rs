#[path = "../src/bin/consumer_readiness_windows/controller_gate_error.rs"]
mod gate;

use std::{error::Error, io};

#[test]
fn native_open_and_publication_failures_remain_distinct_and_keep_original_code() {
    for (stage, operation, access) in [
        (gate::Stage::Open, "OpenEventW-controller-wait", "0x100000"),
        (
            gate::Stage::PublishRelease,
            "controller-released-transcript",
            "0x0",
        ),
    ] {
        let error = gate::context(stage, None, io::Error::from_raw_os_error(5));
        assert_eq!(error.kind(), io::Error::from_raw_os_error(5).kind());
        let text = error.to_string();
        assert!(text.contains(operation));
        assert!(text.contains(access));
        assert!(text.contains("raw-os-error=Some(5)"));
        assert!(format!("{:?}", error.get_ref().unwrap()).contains(operation));
        let source = error
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap();
        assert_eq!(source.raw_os_error(), Some(5));
    }
    let error = gate::open_diagnostic(
        io::Error::from_raw_os_error(5),
        Ok("{\"query_complete\":false}".into()),
    );
    assert!(error.to_string().contains("raw-os-error=Some(5)"));
    assert!(error.to_string().contains("failure-only-effective-token="));
}

#[test]
fn wait_status_and_unformattable_cause_are_not_invented_native_errors() {
    #[derive(Debug)]
    struct Private;
    impl std::fmt::Display for Private {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("private cause must never be formatted")
        }
    }
    impl Error for Private {}
    let error = gate::context(gate::Stage::Wait, Some(258), io::Error::other(Private));
    let text = error.to_string();
    assert!(text.contains("WaitForSingleObject-controller-wait"));
    assert!(text.contains("raw-os-error=None"));
    assert!(text.contains("wait-status=Some(258)"));
    let debug = format!("{:?}", error.get_ref().unwrap());
    assert_eq!(text, debug);
}
