#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_linux/path_alias.rs"]
mod producer;

use memcordon_ci::{
    CiError,
    linux_path_alias::{binary, verify_alias},
};
use serde_json::{Value, json};

#[test]
fn real_alias_encoder_and_consumer_preserve_all_exact_lexical_path_operands() {
    let source = b"/tmp/original-host-marker";
    for (kind, probe, errno) in [
        (
            "symlink",
            b"/work/isolation-symbolic-alias".as_slice(),
            None,
        ),
        (
            "dotdot",
            b"/work/../../tmp/original-host-marker".as_slice(),
            None,
        ),
        (
            "proc-root",
            b"/proc/123/root/tmp/original-host-marker".as_slice(),
            None,
        ),
        (
            "proc-cwd",
            b"/proc/123/cwd/original-host-marker".as_slice(),
            None,
        ),
        ("proc-fd", b"/proc/123/fd/42".as_slice(), None),
        (
            "hardlink",
            b"/work/isolation-hardlink-alias".as_slice(),
            Some(18),
        ),
        (
            "mount-alias",
            b"/work/isolation-mount-alias".as_slice(),
            Some(1),
        ),
    ] {
        let encoded = producer::observation(kind, source, probe, errno);
        let wire = serde_json::to_vec(&encoded).unwrap();
        let received: Value = serde_json::from_slice(&wire).unwrap();
        verify_alias(&received, kind, source, probe).unwrap();
        assert_eq!(binary(&received["source"]).unwrap(), source);
        assert_eq!(binary(&received["probe"]).unwrap(), probe);
        assert_eq!(
            received["native_import_errno"],
            serde_json::to_value(errno).unwrap()
        );
        assert!(received["source"].is_array() && received["probe"].is_array());
        if kind == "dotdot" {
            assert!(verify_alias(&received, kind, source, b"/tmp/original-host-marker").is_err());
        }
    }
}

#[test]
fn non_utf8_unix_paths_round_trip_without_normalization_or_text_fallback() {
    let source = b"/tmp/host-\xff\xfe";
    let probe = b"/work/../../tmp/host-\xff\xfe";
    let encoded = producer::observation("dotdot", source, probe, None);
    let received: Value = serde_json::from_slice(&serde_json::to_vec(&encoded).unwrap()).unwrap();
    verify_alias(&received, "dotdot", source, probe).unwrap();
    assert_eq!(binary(&received["source"]).unwrap(), source);
    assert_eq!(binary(&received["probe"]).unwrap(), probe);
    assert!(std::str::from_utf8(&binary(&received["source"]).unwrap()).is_err());
    let replacement_text_bytes = b"/tmp/host-\xef\xbf\xbd\xef\xbf\xbd";
    assert!(verify_alias(&received, "dotdot", replacement_text_bytes, probe).is_err());
    for field in ["source", "probe"] {
        let mut changed = received.clone();
        let bytes = changed[field].as_array_mut().unwrap();
        let last = bytes.last_mut().unwrap();
        *last = json!(last.as_u64().unwrap() ^ 1);
        let error = verify_alias(&changed, "dotdot", source, probe).unwrap_err();
        assert!(error.to_string().contains(&format!("{field} bytes differ")));
        assert!(error.to_string().contains("sha256="));
    }
}

#[test]
fn alternate_or_malformed_wire_representations_are_rejected_with_typed_decode_cause() {
    let source = b"/tmp/host";
    let probe = b"/work/isolation-symbolic-alias";
    let original = producer::observation("symlink", source, probe, None);
    for field in ["source", "probe"] {
        for invalid in [
            json!("/tmp/host"),
            json!({"Unix":source}),
            json!({"Windows":[47,116]}),
            json!([256]),
            json!([-1]),
            json!([1.5]),
            json!(["47"]),
            json!([null]),
            Value::Null,
        ] {
            let mut changed = original.clone();
            changed[field] = invalid;
            assert!(
                verify_alias(&changed, "symlink", source, probe).is_err(),
                "{field}"
            );
        }
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        let error = verify_alias(&missing, "symlink", source, probe).unwrap_err();
        assert!(error.to_string().contains(field));
    }
    for invalid in [
        json!(null),
        json!({"Unix":source}),
        json!("text"),
        json!([256]),
    ] {
        assert!(matches!(binary(&invalid), Err(CiError::Json(_))));
    }
    for kind in [Value::Null, json!("hardlink"), json!([115])] {
        let mut changed = original.clone();
        changed["kind"] = kind;
        assert!(
            verify_alias(&changed, "symlink", source, probe)
                .unwrap_err()
                .to_string()
                .contains("kind differs")
        );
    }
    let mut missing = original;
    missing.as_object_mut().unwrap().remove("kind");
    assert!(verify_alias(&missing, "symlink", source, probe).is_err());
}
