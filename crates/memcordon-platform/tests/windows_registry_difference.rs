#![cfg(feature = "test-support")]
use memcordon_platform::{windows_registry_difference as difference, windows_registry_manifest::*};
use serde_json::Value;
use std::time::{Duration, Instant};

fn units(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}
fn base() -> Manifest {
    Manifest {
        version: VERSION,
        view: View::Native,
        migration_providers: TransportPresence::Absent { lstatus: 2 },
        transports: vec![],
        keys: vec![
            Key {
                root: Root::Winsock2Parameters,
                path: vec![],
                class: vec![],
                values: vec![ValueRecord {
                    name: units("payload"),
                    kind: 3,
                    bytes: b"PRIVATE_NATIVE_CONTENT".to_vec(),
                }],
            },
            Key {
                root: Root::WinsockParameters,
                path: vec![],
                class: vec![],
                values: vec![ValueRecord {
                    name: units("Transports"),
                    kind: 7,
                    bytes: vec![0, 0],
                }],
            },
        ],
    }
}
fn render(expected: &Manifest, actual: &Manifest) -> Value {
    difference::diagnostic(
        Some(expected),
        actual,
        &expected.declaration().unwrap(),
        Instant::now() + Duration::from_secs(5),
        difference::ReadbackStage::Copied,
    )
}
fn category(expected: &Manifest, actual: &Manifest) -> Value {
    render(expected, actual)["difference"]["category"].clone()
}
fn child(name: &str) -> Key {
    Key {
        root: Root::Winsock2Parameters,
        path: vec![units(name)],
        class: vec![],
        values: vec![],
    }
}

#[test]
fn canonical_identity_merge_ignores_order_and_localizes_membership_without_position_shifts() {
    let mut expected = base();
    expected.keys.push(child("A"));
    expected.keys.push(child("B"));
    let mut reordered = expected.clone();
    reordered.keys.reverse();
    for key in &mut reordered.keys {
        key.values.reverse();
    }
    let record = render(&expected, &reordered);
    assert!(record["difference"].is_null(), "{record}");
    assert_eq!(record["expected"]["sha256"], record["actual"]["sha256"]);
    let mut missing = expected.clone();
    missing.keys.remove(2);
    assert_eq!(category(&expected, &missing), "key-missing");
    assert_eq!(
        render(&expected, &missing)["difference"]["location"]["path_components"][0]["utf16_prefix"],
        serde_json::json!(units("A"))
    );
    assert_eq!(category(&missing, &expected), "key-extra");
    let mut renamed = expected.clone();
    renamed.keys[2].path[0] = units("C");
    assert_eq!(category(&expected, &renamed), "key-missing");
}

#[test]
fn native_class_and_value_fields_are_distinct_without_disclosing_payload() {
    let original = base();
    for (mutation, expected_category) in [
        "key-class",
        "value-missing",
        "value-extra",
        "value-type",
        "value-length",
        "value-content",
    ]
    .into_iter()
    .enumerate()
    {
        let mut changed = original.clone();
        match mutation {
            0 => changed.keys[0].class = vec![0xd800, 0xffff],
            1 => {
                changed.keys[0].values.clear();
            }
            2 => changed.keys[0].values.push(ValueRecord {
                name: units("extra"),
                kind: 0,
                bytes: vec![],
            }),
            3 => changed.keys[0].values[0].kind = 4,
            4 => changed.keys[0].values[0].bytes.push(0),
            5 => changed.keys[0].values[0].bytes[3] ^= 1,
            _ => unreachable!(),
        }
        let record = render(&original, &changed);
        assert_eq!(
            record["difference"]["category"], expected_category,
            "{record}"
        );
        let text = serde_json::to_string(&record).unwrap();
        assert!(!text.contains("PRIVATE_NATIVE_CONTENT"));
        assert!(!text.contains("\"bytes\""));
        if mutation == 5 {
            assert_eq!(record["difference"]["first_byte_offset"], 3);
            assert_ne!(
                record["difference"]["expected"]["sha256"],
                record["difference"]["actual"]["sha256"]
            );
        }
    }
    let mut renamed = original.clone();
    renamed.keys[0].values[0].name = units("renamed");
    assert_eq!(category(&original, &renamed), "value-missing");
}

fn transport(present: bool) -> Manifest {
    let mut manifest = base();
    let service = units("ActualService");
    let mut list = service.clone();
    list.extend([0, 0]);
    manifest.keys[1].values[0].bytes = list.into_iter().flat_map(u16::to_le_bytes).collect();
    manifest.transports.push(TransportRoot {
        service: service.clone(),
        presence: if present {
            TransportPresence::Present
        } else {
            TransportPresence::Absent { lstatus: 2 }
        },
    });
    if present {
        manifest.keys.push(Key {
            root: Root::TransportWinsock { service },
            path: vec![],
            class: vec![],
            values: vec![],
        });
    }
    manifest.validate().unwrap();
    manifest
}
#[test]
fn actual_transport_membership_and_witnessed_presence_precede_key_differences() {
    let empty = base();
    let present = transport(true);
    let absent = transport(false);
    assert_eq!(category(&empty, &absent), "transport-extra");
    assert_eq!(category(&absent, &empty), "transport-missing");
    assert_eq!(category(&present, &absent), "transport-presence");
    assert_eq!(category(&absent, &present), "transport-presence");
    let mut invalid = absent.clone();
    invalid.transports[0].presence = TransportPresence::Absent { lstatus: 5 };
    let record = render(&present, &invalid);
    assert_eq!(record["detail_unavailable"], "invalid-actual-manifest");
    assert!(record["difference"].is_null());
}

#[test]
fn migration_presence_is_localized_before_transport_and_root_content_changes() {
    let absent = base();
    let mut present = absent.clone();
    present.migration_providers = TransportPresence::Present;
    present.keys.push(Key {
        root: Root::WinsockMigrationProviders,
        path: vec![],
        class: vec![],
        values: vec![],
    });
    assert_eq!(category(&absent, &present), "migration-providers-presence");
    assert_eq!(category(&present, &absent), "migration-providers-presence");
    let mut changed = present.clone();
    changed.keys.last_mut().unwrap().class = vec![0xd800];
    let record = render(&present, &changed);
    assert_eq!(record["difference"]["category"], "key-class");
    assert_eq!(
        record["difference"]["location"]["root"]["kind"],
        "winsock-migration-providers"
    );
    assert_eq!(
        record["difference"]["location"]["key_identity_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(serde_json::to_vec(&record).unwrap().len() <= difference::RECORD_BYTES);
}

#[test]
fn declaration_only_and_invalid_owner_association_never_invent_expected_content() {
    let expected = base();
    let mut actual = expected.clone();
    actual.keys[0].class.push(1);
    let declaration = expected.declaration().unwrap();
    let record = difference::diagnostic(
        None,
        &actual,
        &declaration,
        Instant::now() + Duration::from_secs(5),
        difference::ReadbackStage::Recipient,
    );
    assert_eq!(record["expected_payload_available"], false);
    assert_eq!(record["stage"], "recipient/readback");
    assert_eq!(record["detail_unavailable"], "expected-payload-unavailable");
    assert!(record["difference"].is_null());
    assert!(record["actual"]["sha256"].is_string());
    let mut wrong = declaration.clone();
    wrong.sha256[0] ^= 1;
    let record = difference::diagnostic(
        Some(&expected),
        &actual,
        &wrong,
        Instant::now() + Duration::from_secs(5),
        difference::ReadbackStage::Sealed,
    );
    assert_eq!(
        record["detail_unavailable"],
        "expected-declaration-association-differs"
    );
    assert_eq!(record["expected_payload_available"], false);
    assert!(record["difference"].is_null());
    let mut duplicate = expected.clone();
    duplicate.keys.push(duplicate.keys[0].clone());
    assert_eq!(
        render(&expected, &duplicate)["detail_unavailable"],
        "invalid-actual-manifest"
    );
    let mut old = declaration;
    old.version -= 1;
    assert_eq!(
        difference::diagnostic(
            Some(&expected),
            &actual,
            &old,
            Instant::now() + Duration::from_secs(5),
            difference::ReadbackStage::Sealed,
        )["detail_unavailable"],
        "invalid-declaration"
    );
}

#[test]
fn truncated_lossless_locations_have_full_hashes_and_serialized_bounds() {
    let mut expected = base();
    for depth in 1..=MAX_DEPTH {
        expected.keys.push(Key {
            root: Root::Winsock2Parameters,
            path: vec![vec![0xffff; 255]; depth],
            class: vec![],
            values: vec![],
        });
    }
    let last = expected.keys.last_mut().unwrap();
    last.values.push(ValueRecord {
        name: vec![0xffff; 16383],
        kind: 3,
        bytes: vec![1],
    });
    let mut actual = expected.clone();
    actual.keys.last_mut().unwrap().values[0].bytes[0] = 2;
    let record = render(&expected, &actual);
    let bytes = serde_json::to_vec(&record).unwrap();
    assert_eq!(record["stage"], "projection/copied-readback");
    assert!(bytes.len() <= difference::RECORD_BYTES, "{}", bytes.len());
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), record);
    let detail = &record["difference"];
    if record["detail_truncated"] == false {
        assert_eq!(detail["location"]["path_truncated"], true);
        assert_eq!(
            detail["location"]["path_components"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(detail["value_name"]["truncated"], true);
        assert_eq!(detail["value_name"]["total_units"], 16383);
        assert_eq!(detail["value_name"]["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(
            detail["location"]["key_identity_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }
    let expired = difference::diagnostic(
        Some(&expected),
        &actual,
        &expected.declaration().unwrap(),
        Instant::now(),
        difference::ReadbackStage::Sealed,
    );
    assert_eq!(expired["detail_unavailable"], "original-cutoff-exhausted");
    assert_eq!(expired["acceptance_authority"], false);
    assert_eq!(expired["stage"], "projection/sealed-readback");
    assert!(serde_json::to_vec(&expired).unwrap().len() <= difference::RECORD_BYTES);
}
