use memcordon_ci::linux_package_executable::{MetadataFacts, validate};

fn package_source() -> MetadataFacts {
    MetadataFacts {
        regular: true,
        uid: 0,
        mode: 0o100755,
        links: 1,
        length: 4096,
        access_mode: 0,
    }
}

#[test]
fn protected_package_mode_and_readonly_descriptor_are_separate_requirements() {
    validate(&package_source()).unwrap();
    let mut immutable_image = package_source();
    immutable_image.mode = 0o100555;
    let error = validate(&immutable_image).unwrap_err();
    assert!(error.contains("555"), "observed mode absent: {error}");
    assert!(error.contains("755"), "expected mode absent: {error}");
    for access_mode in [1, 2, 3] {
        let mut writable_descriptor = package_source();
        writable_descriptor.access_mode = access_mode;
        assert!(validate(&writable_descriptor).is_err());
    }
}

#[test]
fn every_original_custody_condition_remains_independently_required() {
    for mutation in 0..8 {
        let mut facts = package_source();
        match mutation {
            0 => facts.regular = false,
            1 => facts.uid = 1234,
            2 => facts.links = 0,
            3 => facts.links = 2,
            4 => facts.length = 0,
            5 => facts.mode = 0o100775,
            6 => facts.mode = 0o100750,
            _ => facts.mode = 0o100644,
        }
        let error = validate(&facts).unwrap_err();
        assert!(error.len() < 512, "unbounded custody diagnostic");
    }
}

#[test]
fn extreme_metadata_stays_rejected_with_bounded_actual_operand_context() {
    let facts = MetadataFacts {
        regular: false,
        uid: u32::MAX,
        mode: u32::MAX,
        links: u64::MAX,
        length: 0,
        access_mode: u32::MAX,
    };
    let error = validate(&facts).unwrap_err();
    assert!(error.len() < 512);
    for operand in ["4294967295", "18446744073709551615", "755"] {
        assert!(
            error.contains(operand),
            "actual/expected operand absent: {error}"
        );
    }
}
