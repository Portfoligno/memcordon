#[path = "../src/bin/consumer_readiness_windows/matched_control_io_diagnostic.rs"]
pub mod diagnostic;

use diagnostic::{QueryFacts, QueryStage, StreamRole};
use std::io;

fn facts(role: StreamRole) -> QueryFacts {
    QueryFacts {
        role,
        first_result: 0,
        first_required: 101,
        first_native_error: Some(122),
        supplied_capacity: Some(101),
        physical_capacity: Some(104),
        second_result: Some(1),
        second_required_observed: Some(0),
        second_native_error: None,
        descriptor: None,
    }
}

#[test]
fn returned_extent_distinguishes_stream_zero_and_overflow_without_native_failure() {
    for (role, role_label, returned) in [
        (StreamRole::Stdout, "Stdout", 0),
        (StreamRole::Stderr, "Stderr", 102),
    ] {
        let mut facts = facts(role);
        facts.second_required_observed = Some(returned);
        let error = facts.error(QueryStage::ReturnedExtent, None);
        let text = error.to_string();
        assert!(text.starts_with("matched original stream security changed:"));
        for field in [
            format!("role={role_label}"),
            "stage=ReturnedExtent".into(),
            "first_result=0 first_required=101 first_native_error=Some(122)".into(),
            "supplied_capacity=Some(101) physical_capacity=Some(104)".into(),
            format!(
                "second_result=Some(1) second_required_observed=Some({returned}) second_native_error=None"
            ),
        ] {
            assert!(text.contains(&field), "{text}");
        }
        assert!(error.get_ref().unwrap().source().is_none());
    }
}

#[test]
fn failed_query_keeps_actual_native_error_and_unattempted_copy_distinct() {
    for stage in [QueryStage::Sizing, QueryStage::Copy] {
        let mut facts = facts(StreamRole::Stderr);
        if matches!(stage, QueryStage::Sizing) {
            facts.first_native_error = Some(5);
            facts.supplied_capacity = None;
            facts.physical_capacity = None;
            facts.second_result = None;
            facts.second_required_observed = None;
        } else {
            facts.second_result = Some(0);
            facts.second_native_error = Some(5);
        }
        let native = io::Error::from_raw_os_error(5);
        let kind = native.kind();
        let error = facts.error(stage, Some(native));
        assert_eq!(error.kind(), kind);
        let source = error.get_ref().unwrap().source().unwrap();
        assert_eq!(
            source.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(5)
        );
        let text = error.to_string();
        if matches!(stage, QueryStage::Sizing) {
            assert!(text.contains("supplied_capacity=None physical_capacity=None second_result=None second_required_observed=None second_native_error=None"));
        } else {
            assert!(text.contains(
                "second_result=Some(0) second_required_observed=Some(0) second_native_error=Some(5)"
            ));
        }
    }
}

#[test]
fn scalar_only_display_is_fixed_and_bounded_even_at_integer_limits() {
    let facts = QueryFacts {
        role: StreamRole::Stdout,
        first_result: i32::MIN,
        first_required: u32::MAX,
        first_native_error: Some(i32::MIN),
        supplied_capacity: Some(u32::MAX),
        physical_capacity: Some(usize::MAX),
        second_result: Some(i32::MIN),
        second_required_observed: Some(u32::MAX),
        second_native_error: Some(i32::MIN),
        descriptor: None,
    };
    let error = facts.error(QueryStage::Copy, Some(io::Error::other("private payload")));
    assert!(error.to_string().len() < 512);
    assert!(!error.to_string().contains("private payload"));
}
