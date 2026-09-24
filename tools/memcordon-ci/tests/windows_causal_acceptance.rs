use std::collections::BTreeMap;

use memcordon_ci::windows_causal_acceptance::{
    ASSERTIONS, FixtureProcessIdentityV1, InstalledCausalAcceptanceV1, InstalledChannel,
    RAW_SUFFIXES, parse_fixture_readiness, validate_artifact_with_raw, validate_fixture_family,
};

fn candidate() -> InstalledCausalAcceptanceV1 {
    InstalledCausalAcceptanceV1 {
        schema_version: 1,
        source_commit: "a".repeat(40),
        target: "x86_64-pc-windows-msvc".to_owned(),
        channel: InstalledChannel::NativeBundle,
        package_version: "0.5.7-dev".to_owned(),
        execution_report_schema: memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
        provider_identity_sha256: "a".repeat(64),
        component_inventory_sha256: "b".repeat(64),
        fixture_sha256: "c".repeat(64),
        runtime_manifest_sha256: "e".repeat(64),
        expected_case: "inventory-capacity-receiptless".to_owned(),
        raw_evidence: RAW_SUFFIXES
            .into_iter()
            .map(|suffix| (suffix.to_owned(), "d".repeat(64)))
            .collect::<BTreeMap<_, _>>(),
        assertion_results: ASSERTIONS
            .into_iter()
            .map(|name| (name.to_owned(), "report.json".to_owned()))
            .collect(),
    }
}

#[test]
fn installed_acceptance_rejects_channel_or_target_substitution_before_raw_reads() {
    let candidate = candidate();
    let bytes = serde_json::to_vec(&candidate).expect("serialize candidate");
    assert!(
        validate_artifact_with_raw(
            &bytes,
            &candidate.source_commit,
            &candidate.target,
            InstalledChannel::CargoPackage,
            |_| panic!("no raw read is permitted"),
        )
        .is_err()
    );
    assert!(
        validate_artifact_with_raw(
            &bytes,
            &candidate.source_commit,
            "aarch64-pc-windows-msvc",
            InstalledChannel::NativeBundle,
            |_| panic!("no raw read is permitted"),
        )
        .is_err()
    );
}

#[test]
fn installed_acceptance_rejects_wrong_schema_and_assertion_inventory() {
    let mut candidate = candidate();
    candidate.execution_report_schema += 1;
    let bytes = serde_json::to_vec(&candidate).expect("serialize candidate");
    assert!(
        validate_artifact_with_raw(
            &bytes,
            &candidate.source_commit,
            &candidate.target,
            candidate.channel,
            |_| panic!("no raw read is permitted"),
        )
        .is_err()
    );
    candidate.execution_report_schema = memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION;
    candidate.assertion_results.remove("capacity-original");
    let bytes = serde_json::to_vec(&candidate).expect("serialize candidate");
    assert!(
        validate_artifact_with_raw(
            &bytes,
            &candidate.source_commit,
            &candidate.target,
            candidate.channel,
            |_| panic!("no raw read is permitted"),
        )
        .is_err()
    );
}

#[test]
fn installed_acceptance_rejects_duplicate_raw_evidence_keys() {
    let bytes = br#"{
        "schema_version":1,
        "source_commit":"source",
        "target":"x86_64-pc-windows-msvc",
        "channel":"native-bundle",
        "package_version":"0.5.7-dev",
        "execution_report_schema":10,
        "provider_identity_sha256":"digest",
        "component_inventory_sha256":"digest",
        "fixture_sha256":"digest",
        "runtime_manifest_sha256":"digest",
        "expected_case":"inventory-capacity-receiptless",
        "raw_evidence":{"report.json":"first","report.json":"second"},
        "assertion_results":{}
    }"#;
    assert!(serde_json::from_slice::<InstalledCausalAcceptanceV1>(bytes).is_err());
}

#[test]
fn installed_acceptance_rejects_oversized_fixture_family_before_map_building() {
    let family = (0..=memcordon_core::WINDOWS_MAX_JOB_PROCESS_IDENTITIES + 1)
        .map(|index| serde_json::json!({"ordinal":index,"pid":index+1,"birth":index+1}))
        .collect::<Vec<_>>();
    let value = serde_json::json!({
        "schema_version":1,
        "image_sha256":"digest",
        "root_ready":true,
        "observed_family":family,
        "root_exited":true,
        "all_matching_processes_gone":true,
    });
    assert!(
        serde_json::from_value::<memcordon_ci::windows_causal_acceptance::FixtureExitEvidenceV1>(
            value
        )
        .is_err()
    );
}

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
        (0..memcordon_core::WINDOWS_MAX_JOB_PROCESS_IDENTITIES).map(|ordinal| {
            FixtureProcessIdentityV1 {
                ordinal: Some(ordinal),
                pid: u32::try_from(ordinal).expect("ordinal fits u32") + 42,
                birth: u128::try_from(ordinal).expect("ordinal fits u128") + 102,
            }
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
        let line = serde_json::json!({
            "kind": kind,
            "ordinal": member.ordinal,
            "pid": member.pid,
            "birth": member.birth,
        });
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
