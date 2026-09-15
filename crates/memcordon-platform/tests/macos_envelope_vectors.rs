#![cfg(all(target_os = "macos", feature = "test-support"))]

use memcordon_platform::test_support::macos_envelope_receive_manifest_fixture as receive;
use serde_json::{Value, json};

const WIRE: &[u8] = br#"{"version":1,"run":71,"destinations":[0,1,2],"settings":{"mask":8,"ignored":[2,15],"limits":[[4,32,64]]}}"#;

#[test]
fn ancillary_bounds_preserve_sentinel_and_reclaim_received_rights() {
    memcordon_platform::test_support::macos_envelope_ancillary_custody_fixture().unwrap();
}

#[test]
fn native_envelope_transport_preserves_settings_and_exact_destinations() {
    assert_eq!(receive(WIRE, 71, 4).unwrap(), WIRE);
    let mut empty: Value = serde_json::from_slice(WIRE).unwrap();
    empty["destinations"] = json!([]);
    let encoded = serde_json::to_vec(&empty).unwrap();
    let actual: Value = serde_json::from_slice(&receive(&encoded, 71, 1).unwrap()).unwrap();
    assert_eq!(actual, empty);
}

#[test]
fn native_envelope_rejects_binding_count_and_destination_ambiguity() {
    assert!(receive(WIRE, 72, 4).is_err());
    for count in [0, 1, 3, 5] {
        assert!(receive(WIRE, 71, count).is_err(), "rights count {count}");
    }
    for destinations in [json!([-1, 1, 2]), json!([0, 0, 2]), json!([0, 1, i32::MAX])] {
        let mut altered: Value = serde_json::from_slice(WIRE).unwrap();
        altered["destinations"] = destinations;
        assert!(receive(&serde_json::to_vec(&altered).unwrap(), 71, 4).is_err());
    }
}

#[test]
fn native_envelope_rejects_excess_descriptor_rights_at_the_wire_boundary() {
    // Version-one transport admits at most 128 inherited destinations, plus
    // one cwd right. Send one additional unique destination and its right.
    const VERSION_ONE_DESTINATIONS: i32 = 128;
    let mut oversized: Value = serde_json::from_slice(WIRE).unwrap();
    let destinations: Vec<_> = (0..=VERSION_ONE_DESTINATIONS).collect();
    let rights_count = destinations.len() + 1;
    oversized["destinations"] = json!(destinations);
    let failure = receive(&serde_json::to_vec(&oversized).unwrap(), 71, rights_count).unwrap_err();
    assert_eq!(failure.to_string(), "invalid caller descriptor envelope");
}

#[test]
fn native_envelope_rejects_unknown_and_malformed_manifest_fields() {
    for (path, value) in [
        ("/version", json!(2)),
        ("/run", json!(72)),
        ("/settings/mask", json!(-1)),
    ] {
        let mut altered: Value = serde_json::from_slice(WIRE).unwrap();
        *altered.pointer_mut(path).unwrap() = value;
        assert!(receive(&serde_json::to_vec(&altered).unwrap(), 71, 4).is_err());
    }
    for path in ["", "/settings"] {
        let mut altered: Value = serde_json::from_slice(WIRE).unwrap();
        altered.pointer_mut(path).unwrap()["unknown-authority"] = json!(true);
        assert!(receive(&serde_json::to_vec(&altered).unwrap(), 71, 4).is_err());
    }
    for prefix in 0..WIRE.len() {
        assert!(receive(&WIRE[..prefix], 71, 4).is_err(), "prefix {prefix}");
    }
}
