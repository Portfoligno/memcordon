#[path = "../src/bin/consumer_readiness_windows/controller_gate_error.rs"]
mod error;
#[path = "../src/bin/consumer_readiness_windows/controller_gate_resolution.rs"]
mod resolution;
use std::io;

#[test]
fn closed_probe_records_do_not_claim_fixture_identity_or_sync_and_keep_os5_primary() {
    for context in [
        resolution::Context::Controller,
        resolution::Context::FailedFixture,
    ] {
        let observation = resolution::Observation::unavailable(context, "original-work-expired");
        let value = serde_json::to_value(&observation).unwrap();
        assert_eq!(value["attempted"], false);
        assert_eq!(value["open_succeeded"], serde_json::Value::Null);
        assert_eq!(value["same_original_event"], serde_json::Value::Null);
        assert!(serde_json::to_vec(&observation).unwrap().len() < 1024);
        let wrapped =
            error::open_diagnostic(io::Error::from_raw_os_error(5), Ok(value.to_string()));
        assert!(
            wrapped
                .to_string()
                .starts_with("operation=OpenEventW-controller-wait; access=0x100000;")
        );
        assert_eq!(
            wrapped
                .get_ref()
                .unwrap()
                .source()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(5)
        );
    }
    // Exercise the existing closed stages in this external source mount too.
    for stage in [
        error::Stage::Open,
        error::Stage::Wait,
        error::Stage::PublishRelease,
    ] {
        assert!(
            error::context(stage, None, io::Error::from_raw_os_error(5))
                .get_ref()
                .unwrap()
                .source()
                .is_some()
        );
    }
}
