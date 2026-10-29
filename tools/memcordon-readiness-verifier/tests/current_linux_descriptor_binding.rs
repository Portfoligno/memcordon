use memcordon_readiness_verifier::current::linux_isolation::validate_original_descriptor_source;
use serde_json::{Value, json};

fn facts() -> (Value, Value) {
    let source =
        json!({"device":7,"inode":77,"mode":0o100444,"uid":0,"links":1,"flags":0o10000000});
    let mapped = json!({"device":7,"inode":77,"mode":0o100444,"uid":0,"flags":0o10000000,"target_descriptor":128,"fdinfo":"pos:\t0\nflags:\t010000000\nmnt_id:\t12\nino:\t77\n"});
    (mapped, source)
}

#[test]
fn original_descriptor_cannot_be_rebound_to_another_kernel_object_or_slot() {
    let (mapped, source) = facts();
    validate_original_descriptor_source(&mapped, &source, 128).unwrap();
    for (field, value) in [
        ("device", json!(8)),
        ("inode", json!(78)),
        ("mode", json!(0o140777)),
        ("uid", json!(1234)),
        ("flags", json!(0)),
        ("target_descriptor", json!(0)),
    ] {
        let mut changed = mapped.clone();
        changed[field] = value;
        assert!(
            validate_original_descriptor_source(&changed, &source, 128).is_err(),
            "accepted substituted {field}"
        );
    }
    assert!(validate_original_descriptor_source(&mapped, &source, 127).is_err());
}

#[test]
fn native_fdinfo_must_have_one_matching_inode_and_inherited_access_flags() {
    let (mapped, source) = facts();
    for fdinfo in [
        "flags:\t0\nino:\t77\n",
        "flags:\t010000000\nino:\t78\n",
        "flags:\t010000000\nflags:\t010000000\nino:\t77\n",
        "flags:\t010000000\nino:\t77\nino:\t77\n",
        "flags:\t012000000\nino:\t77\n",
        "ino:\t77\n",
    ] {
        let mut changed = mapped.clone();
        changed["fdinfo"] = fdinfo.into();
        assert!(
            validate_original_descriptor_source(&changed, &source, 128).is_err(),
            "accepted native fdinfo {fdinfo:?}"
        );
    }
    let mut unknown = mapped.clone();
    unknown["unsupported_field"] = true.into();
    assert!(validate_original_descriptor_source(&unknown, &source, 128).is_err());
    let mut changed_source = source.clone();
    changed_source["flags"] = json!(0o12000000);
    let mut changed = mapped;
    changed["flags"] = json!(0o12000000);
    changed["fdinfo"] = "flags:\t012000000\nino:\t77\n".into();
    assert!(validate_original_descriptor_source(&changed, &changed_source, 128).is_err());
}
