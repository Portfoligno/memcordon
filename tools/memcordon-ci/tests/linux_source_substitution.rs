use memcordon_ci::linux_source_substitution::validate;
use serde_json::{Value, json};

fn fixture() -> (Value, Value, Value) {
    let permission = json!({"mechanism":"fanotify-open-permission","pid":42,"device":7,"inode":11,
        "directory_device":7,"directory_inode":9,"scope_kind":"file","file_uid":1000,"file_length":1024,
        "record_read":false,"record_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "allow_written":true,"allow_errno":null});
    let frontend = json!({"pid":42,"birth":1234});
    let opened =
        json!({"device":7,"inode":11,"sha256":"a".repeat(64),"uid":1000,"links":1,"length":1024});
    let named =
        json!({"device":7,"inode":12,"sha256":"b".repeat(64),"uid":1000,"links":1,"length":1024});
    let receipt = json!({"opened":opened,"named":named,"restored":opened});
    (permission, frontend, receipt)
}

#[test]
fn native_pid_and_changed_phase_facts_pass_without_confusing_restored_original_name() {
    let (permission, frontend, receipt) = fixture();
    validate(&permission, &frontend, &receipt).unwrap();
    assert_eq!(receipt["restored"], receipt["opened"]);
    let mut no_restoration = receipt.clone();
    no_restoration.as_object_mut().unwrap().remove("restored");
    validate(&permission, &frontend, &no_restoration).unwrap();
    let mut restored_only = receipt;
    restored_only.as_object_mut().unwrap().remove("named");
    assert!(validate(&permission, &frontend, &restored_only).is_err());
}

#[test]
fn permission_and_original_frontend_require_the_real_nonzero_u32_pid_field() {
    let (permission, frontend, receipt) = fixture();
    for invalid in [
        Value::Null,
        json!(0),
        json!(-1),
        json!("42"),
        json!(42.5),
        json!(u64::from(u32::MAX) + 1),
        json!([]),
    ] {
        let mut changed = permission.clone();
        changed["pid"] = invalid.clone();
        assert!(validate(&changed, &frontend, &receipt).is_err());
        let mut changed = frontend.clone();
        changed["pid"] = invalid;
        assert!(validate(&permission, &changed, &receipt).is_err());
    }
    for original in [false, true] {
        let mut changed = if original {
            frontend.clone()
        } else {
            permission.clone()
        };
        changed.as_object_mut().unwrap().remove("pid");
        changed["process_id"] = 42.into();
        assert!(
            if original {
                validate(&permission, &changed, &receipt)
            } else {
                validate(&changed, &frontend, &receipt)
            }
            .is_err()
        );
    }
    let mut foreign = permission;
    foreign["pid"] = 43.into();
    assert!(
        validate(&foreign, &frontend, &receipt)
            .unwrap_err()
            .to_string()
            .contains("pid")
    );
}

#[test]
fn inode_and_digest_changes_are_independent_and_missing_or_malformed_facts_are_fatal() {
    let (permission, frontend, receipt) = fixture();
    for field in ["inode", "sha256"] {
        let mut unchanged = receipt.clone();
        unchanged["named"][field] = unchanged["opened"][field].clone();
        assert!(
            validate(&permission, &frontend, &unchanged).is_err(),
            "unchanged {field}"
        );
    }
    for side in ["opened", "named"] {
        for field in ["inode", "sha256"] {
            let mut missing = receipt.clone();
            missing[side].as_object_mut().unwrap().remove(field);
            assert!(
                validate(&permission, &frontend, &missing).is_err(),
                "missing {side}.{field}"
            );
        }
        for invalid in [
            Value::Null,
            json!(0),
            json!(-1),
            json!("11"),
            json!(11.5),
            json!([]),
        ] {
            let mut changed = receipt.clone();
            changed[side]["inode"] = invalid;
            assert!(
                validate(&permission, &frontend, &changed).is_err(),
                "malformed {side}.inode"
            );
        }
        for invalid in [
            Value::Null,
            json!(0),
            json!(""),
            json!("a".repeat(63)),
            json!("a".repeat(65)),
            json!("g".repeat(64)),
            json!(vec![0; 32]),
        ] {
            let mut changed = receipt.clone();
            changed[side]["sha256"] = invalid;
            assert!(
                validate(&permission, &frontend, &changed).is_err(),
                "malformed {side}.sha256"
            );
        }
    }
    let mut same_digest = receipt.clone();
    same_digest["named"]["sha256"] = json!("A".repeat(64));
    assert!(validate(&permission, &frontend, &same_digest).is_err());
    let mut upper_distinct = receipt;
    upper_distinct["named"]["sha256"] = json!("B".repeat(64));
    validate(&permission, &frontend, &upper_distinct).unwrap();
}
