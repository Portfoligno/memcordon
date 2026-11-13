use memcordon_ci::windows_fixture_inventory::{REPORT_BYTES, record, sibling_kind};
use serde_json::json;

#[test]
fn exact_case_insensitive_sibling_forms_do_not_match_unrelated_names() {
    let exe = "memcordon-test-fixture.exe";
    for name in [
        "memcordon-test-fixture.exe.manifest",
        "MEMCORDON-TEST-FIXTURE.EXE.MANIFEST",
    ] {
        assert_eq!(sibling_kind(exe, name), Some("external_manifest"));
    }
    assert_eq!(
        sibling_kind(exe, "memcordon-test-fixture.exe.65535.manifest"),
        Some("external_manifest_id")
    );
    assert_eq!(
        sibling_kind(exe, "memcordon-test-fixture.exe.1.manifest"),
        Some("external_manifest_id")
    );
    assert_eq!(
        sibling_kind(exe, "memcordon-test-fixture.exe.LOCAL"),
        Some("dotlocal")
    );
    for name in [
        "other.exe.manifest",
        "memcordon-test-fixture.exe.manifest.backup",
        "memcordon-test-fixture.exe.65536.manifest",
        "memcordon-test-fixture.exe.-1.manifest",
        "memcordon-test-fixture.exe.foo.manifest",
        "memcordon-test-fixture.exe..manifest",
        "memcordon-test-fixture.exe.localx",
        "memcordon-test-fixturè.exe.manifest",
    ] {
        assert_eq!(sibling_kind(exe, name), None, "{name}");
    }
}

#[test]
fn snapshot_unknowns_and_selected_hash_are_retained_without_redirection_authority() {
    let bytes = record(
        &"a".repeat(40),
        "aarch64-pc-windows-msvc",
        &"b".repeat(64),
        None,
        json!({"status":"incomplete","parser_complete":false,"error":"resource-range"}),
        json!({"image_state":"incomplete","native_error":5,"absence_proved":false}),
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["fixture_sha256"], "b".repeat(64));
    assert!(value["fixture_bytes"].is_null());
    assert_eq!(value["embedded"]["status"], "incomplete");
    assert_eq!(value["deployment"]["native_error"], 5);
    for key in [
        "acceptance_authority",
        "redirection_authorized",
        "loader_eligibility_proved",
        "continuous_sibling_absence_proved",
    ] {
        assert_eq!(value[key], false, "{key}");
    }
    assert!(bytes.len() < REPORT_BYTES);
}

#[test]
fn combined_record_bound_keeps_structural_manifest_and_sibling_facts() {
    let embedded = json!({"status":"manifest_present","parser_complete":true,"manifests":(0..64).map(|id|json!({"name":{"utf16":vec![u16::MAX;128]},"language":id,"sha256":vec![255u8;32]})).collect::<Vec<_>>()});
    let deployment = json!({"siblings":{"complete":true,"rows":(0..64).map(|_|json!({"name_sha256":"c".repeat(64),"kind":"external_manifest_id","state":"regular-file","bytes":123,"sha256":"d".repeat(64)})).collect::<Vec<_>>()}});
    // The production parser enforces its own32KiB reservation first. An oversized
    // caller cannot silently turn the combined report into absence or drop facts.
    assert!(record("commit", "target", "digest", Some(1), embedded, deployment).is_err());
    let embedded = json!({"status":"manifest_present","parser_complete":true,"manifests":[{"name":{"id":1},"language":1033,"payload_bytes":128,"sha256":"e".repeat(64)}]});
    let bytes = record(
        "commit",
        "target",
        "digest",
        Some(512),
        embedded.clone(),
        json!({"siblings":{"complete":true,"rows":[]}}),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["embedded"],
        embedded
    );
}
