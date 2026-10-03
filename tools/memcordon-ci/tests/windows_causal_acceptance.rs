use memcordon_ci::windows_causal_acceptance::{
    FixtureProcessIdentityV1, WINDOWS_CAUSAL_CONCURRENT_CHILDREN, parse_fixture_readiness,
    validate_fixture_family,
};

#[test]
fn inventory_readiness_rejects_duplicate_ordinals_and_malformed_records() {
    let root = b"MEMCORDON-INVENTORY-READY:{\"kind\":\"inventory-root-ready\",\"ordinal\":null,\"pid\":41,\"birth\":100}\n";
    assert_eq!(
        parse_fixture_readiness(root)
            .expect("one root is valid")
            .len(),
        1
    );
    let duplicate = b"MEMCORDON-INVENTORY-READY:{\"kind\":\"inventory-root-ready\",\"ordinal\":null,\"pid\":41,\"birth\":100}\nMEMCORDON-INVENTORY-READY:{\"kind\":\"inventory-leaf-ready\",\"ordinal\":0,\"pid\":42,\"birth\":101}\nMEMCORDON-INVENTORY-READY:{\"kind\":\"inventory-leaf-ready\",\"ordinal\":0,\"pid\":43,\"birth\":102}\n";
    assert!(parse_fixture_readiness(duplicate).is_err());
    let malformed = b"MEMCORDON-INVENTORY-READY:{\"kind\":\"inventory-root-ready\",\"ordinal\":null,\"pid\":41,\"birth\":100,\"extra\":true}\n";
    assert!(parse_fixture_readiness(malformed).is_err());
    let overflow = b"MEMCORDON-INVENTORY-READY:{\"kind\":\"inventory-leaf-ready\",\"ordinal\":256,\"pid\":42,\"birth\":101}\n";
    assert!(parse_fixture_readiness(overflow).is_err());
}

#[test]
fn installed_family_requires_every_leaf_and_matching_raw_readiness() {
    let family = std::iter::once(FixtureProcessIdentityV1 {
        ordinal: None,
        pid: 41,
        birth: 101,
    })
    .chain(
        (0..WINDOWS_CAUSAL_CONCURRENT_CHILDREN).map(|ordinal| FixtureProcessIdentityV1 {
            ordinal: Some(ordinal),
            pid: u32::try_from(ordinal).expect("ordinal fits u32") + 42,
            birth: u128::try_from(ordinal).expect("ordinal fits u128") + 102,
        }),
    )
    .collect::<Vec<_>>();
    let mut stdout = Vec::new();
    for member in &family {
        let kind = if member.ordinal.is_some() {
            "inventory-leaf-ready"
        } else {
            "inventory-root-ready"
        };
        let line = serde_json::json!({ "kind": kind, "ordinal": member.ordinal, "pid": member.pid, "birth": member.birth });
        stdout.extend_from_slice(b"MEMCORDON-INVENTORY-READY:");
        stdout.extend_from_slice(line.to_string().as_bytes());
        stdout.push(b'\n');
    }
    validate_fixture_family(&stdout, &family).expect("complete observed family is valid");
    assert!(validate_fixture_family(&stdout, &family[..family.len() - 1]).is_err());
    let mut substituted = family.clone();
    substituted[1].birth += 1;
    assert!(validate_fixture_family(&stdout, &substituted).is_err());
    let mut truncated_stdout = stdout.clone();
    let last_line = truncated_stdout
        .iter()
        .rposition(|byte| *byte == b'\n')
        .expect("last line is terminated");
    let previous_line = truncated_stdout[..last_line]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .expect("previous line is terminated");
    truncated_stdout.truncate(previous_line + 1);
    assert!(validate_fixture_family(&truncated_stdout, &family).is_err());
}
