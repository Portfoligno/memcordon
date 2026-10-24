use super::validate_credential_fields;

#[test]
fn packaged_control_requires_all_four_original_endpoint_group_slots() {
    let original_group = 1234;
    let valid = "Uid:\t0\t0\t0\t0\nGid:\t1234\t1234\t1234\t1234\n";
    validate_credential_fields(valid, "authenticated-control", 101, 201, 0, original_group)
        .unwrap();
    for changed in [
        "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
        "Uid:\t0\t0\t0\t0\nGid:\t1234\t1234\t0\t1234\n",
        "Uid:\t0\t65534\t0\t0\nGid:\t1234\t1234\t1234\t1234\n",
    ] {
        let error = validate_credential_fields(
            changed,
            "authenticated-control",
            101,
            201,
            0,
            original_group,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("credentials differ"));
        assert!(error.contains("pid=101"));
        assert!(error.contains("birth=201"));
        assert!(error.contains("expected="));
    }
    let malformed = "Uid:\t0\t0\t0\t0\nGid:\t1234\t1234\t1234\t1234\t1234\n";
    let error = validate_credential_fields(
        malformed,
        "authenticated-control",
        101,
        201,
        0,
        original_group,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("malformed cardinality"));
    assert!(error.contains("actual_count=5"));
    assert!(error.contains("first_four=[1234, 1234, 1234, 1234]"));
}

#[test]
fn frontend_credentials_remain_separate_from_root_control_role() {
    let frontend = "Uid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\n";
    validate_credential_fields(frontend, "unprivileged-frontend", 102, 202, 65534, 65534).unwrap();
    assert!(
        validate_credential_fields(frontend, "authenticated-control", 102, 202, 0, 1234).is_err()
    );
    let control = "Uid:\t0\t0\t0\t0\nGid:\t1234\t1234\t1234\t1234\n";
    assert!(
        validate_credential_fields(control, "unprivileged-frontend", 101, 201, 65534, 65534)
            .is_err()
    );
}
