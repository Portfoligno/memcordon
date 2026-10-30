use memcordon_ci::native_retirement::NativeSourceRetirement;
use std::path::Path;

#[test]
fn retirement_requires_exact_current_bound_receipt() {
    let path = Path::new("/var/lib/memcordon-native-readiness/source");
    let receipt = NativeSourceRetirement::observed(path.to_path_buf(), 2049, 6815999);
    let bytes = serde_json::to_vec(&receipt).unwrap();
    assert_eq!(
        NativeSourceRetirement::decode_bound(&bytes, path, 2049, 6815999).unwrap(),
        receipt
    );
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for (key, replacement) in [
        (
            "format",
            serde_json::json!("memcordon.owned-readiness-admin-retirement"),
        ),
        ("revision", serde_json::json!(2)),
        ("path", serde_json::json!("/another/source")),
        ("device", serde_json::json!(2050)),
        ("inode", serde_json::json!(6816000)),
        ("absent", serde_json::json!(false)),
        ("visited_entries", serde_json::json!(1)),
    ] {
        let mut changed = value.clone();
        changed[key] = replacement;
        assert!(
            NativeSourceRetirement::decode_bound(
                &serde_json::to_vec(&changed).unwrap(),
                path,
                2049,
                6815999
            )
            .is_err(),
            "{key}"
        );
    }
    for key in ["format", "revision", "path", "device", "inode", "absent"] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(key);
        assert!(
            NativeSourceRetirement::decode_bound(
                &serde_json::to_vec(&changed).unwrap(),
                path,
                2049,
                6815999
            )
            .is_err()
        );
    }
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen("{", "{\"absent\":true,", 1);
    assert!(
        NativeSourceRetirement::decode_bound(duplicate.as_bytes(), path, 2049, 6815999).is_err()
    );
    assert!(NativeSourceRetirement::decode_bound(&vec![b' '; 65537], path, 2049, 6815999).is_err());
}
