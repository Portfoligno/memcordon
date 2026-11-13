use memcordon_ci::linux_result_publication::{stderr_detail, wrapper_status, writer};
use memcordon_core::{execution_facts::NativeProcessV2, result_v3::DeliveryStateV3};
use std::num::NonZeroU32;

fn prepared(pid: u32) -> DeliveryStateV3 {
    DeliveryStateV3::PreparedBy {
        writer_pid: NonZeroU32::new(pid).unwrap(),
    }
}

#[test]
fn persisted_publication_binds_writer_to_the_original_native_identity() {
    let caller = NativeProcessV2 {
        pid: 42,
        birth: 1234,
    };
    let serialized = serde_json::to_vec(&prepared(caller.pid)).unwrap();
    let actual_delivery = serde_json::from_slice(&serialized).unwrap();
    writer(actual_delivery, &caller, (42, 1234)).unwrap();
    for delivery in [
        prepared(43),
        DeliveryStateV3::Complete,
        DeliveryStateV3::Incomplete,
        DeliveryStateV3::Unknown,
    ] {
        assert!(
            writer(delivery, &caller, (42, 1234)).is_err(),
            "{delivery:?}"
        );
    }
    assert!(writer(prepared(42), &caller, (43, 1234)).is_err());
    assert!(writer(prepared(42), &caller, (42, 1235)).is_err());
    assert!(
        writer(
            prepared(42),
            &NativeProcessV2 {
                pid: 0,
                birth: 1234
            },
            (0, 1234)
        )
        .is_err()
    );
    // A real birth tick can be zero; identity equality, rather than positivity, binds it.
    writer(
        prepared(42),
        &NativeProcessV2 { pid: 42, birth: 0 },
        (42, 0),
    )
    .unwrap();
}

#[test]
fn sole_frontend_wait_must_match_the_reported_wrapper_status() {
    for status in [0, 42, 123, 124, 125, 126, 127, 130] {
        wrapper_status(Some(status), status).unwrap();
        assert!(wrapper_status(Some(status), status + 1).is_err());
        assert!(
            wrapper_status(None, status).is_err(),
            "signal/no normal code must fail"
        );
    }
    assert!(wrapper_status(Some(125), 0).is_err());
    assert!(wrapper_status(Some(0), 125).is_err());
}

#[test]
fn failed_assertion_diagnostics_keep_bounded_original_stderr_head_and_tail() {
    let short = stderr_detail(b"original native failure\n");
    assert!(short.contains("original native failure"));
    assert!(short.contains("omitted=0"));
    let mut bytes = b"original-prefix:".to_vec();
    bytes.extend(std::iter::repeat_n(b'x', 4096));
    bytes.extend_from_slice(b":terminal-native-cause");
    let detail = stderr_detail(&bytes);
    assert!(detail.contains("original-prefix:"));
    assert!(detail.contains(":terminal-native-cause"));
    assert!(detail.contains(&format!("omitted={}", bytes.len() - 2048)));
    assert!(detail.len() < 2300);
}
