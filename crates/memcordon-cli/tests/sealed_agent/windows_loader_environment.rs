use std::collections::HashSet;

use crate::windows::process::{
    bounded_user_environment_inventory_for_test, loader_control_matrix_contract_for_test,
    loader_environment_block_for_test, loader_environment_max_units_for_test,
    loader_target_environment_required_for_test,
    render_loader_environment_prerequisite_canary_for_test,
};

const CANONICAL_MINIMAL_SYSTEM: &str = "canonical-minimal-system";
const REQUIRED_KEYS: [&str; 3] = ["SystemDrive", "SystemRoot", "windir"];
const STATUS_DLL_INIT_FAILED: i32 = 0xc000_0142_u32 as i32;
const PRE_ENTRY_PHASE: &str = "pre-initial-breakpoint-static-loader";

#[test]
fn loader_success_matrix_uses_only_canonical_minimal_system_environment() {
    let (production, certification) = loader_control_matrix_contract_for_test();

    assert_eq!(production.0, CANONICAL_MINIMAL_SYSTEM);
    assert_eq!(production.1, "canonical-minimal-system-none-snaps-off");
    assert_eq!(
        certification.map(|cell| cell.0),
        [CANONICAL_MINIMAL_SYSTEM; 6]
    );
    assert_eq!(
        certification.map(|cell| cell.1),
        [
            "canonical-minimal-system-none-snaps-off",
            "canonical-minimal-system-minimal-pump-snaps-off",
            "canonical-minimal-system-full-observer-snaps-off",
            "canonical-minimal-system-none-snaps-on",
            "canonical-minimal-system-minimal-pump-snaps-on",
            "canonical-minimal-system-full-observer-snaps-on",
        ]
    );
}

#[test]
fn canonical_loader_environment_is_explicit_minimal_and_deterministic() {
    let first = loader_environment_block_for_test(true).unwrap();
    let second = loader_environment_block_for_test(true).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.classification, CANONICAL_MINIMAL_SYSTEM);
    assert_eq!(first.keys, REQUIRED_KEYS);
    assert!(first.missing_required.is_empty());
    assert!(first.units.ends_with(&[0, 0]));

    let names = environment_entry_names(&first.units);
    assert_eq!(names.len(), REQUIRED_KEYS.len());
    let normalized = names
        .iter()
        .map(|name| name.to_ascii_uppercase())
        .collect::<HashSet<_>>();
    assert_eq!(normalized.len(), REQUIRED_KEYS.len());
    assert_eq!(
        normalized,
        REQUIRED_KEYS
            .iter()
            .map(|key| key.to_ascii_uppercase())
            .collect()
    );
}

#[test]
fn explicit_empty_environment_cannot_satisfy_the_success_contract() {
    let empty = loader_environment_block_for_test(false).unwrap();

    assert_eq!(empty.classification, "explicit-empty");
    assert_eq!(empty.units, [0, 0]);
    assert!(empty.keys.is_empty());
    assert_eq!(empty.missing_required, REQUIRED_KEYS);

    let (production, certification) = loader_control_matrix_contract_for_test();
    assert_ne!(production.0, empty.classification);
    assert!(
        certification
            .iter()
            .all(|cell| cell.0 != empty.classification)
    );
}

#[test]
fn target_token_environment_canary_requires_exact_classified_common_failure() {
    let required = |invariants_valid,
                    baseline_failed,
                    baseline_status,
                    baseline_phase,
                    comparison_failed,
                    comparison_status,
                    comparison_phase| {
        loader_target_environment_required_for_test(
            invariants_valid,
            baseline_failed,
            baseline_status,
            baseline_phase,
            comparison_failed,
            comparison_status,
            comparison_phase,
        )
    };

    assert!(required(
        true,
        true,
        Some(STATUS_DLL_INIT_FAILED),
        PRE_ENTRY_PHASE,
        true,
        Some(STATUS_DLL_INIT_FAILED),
        PRE_ENTRY_PHASE,
    ));

    for rejected in [
        required(
            false,
            true,
            Some(STATUS_DLL_INIT_FAILED),
            PRE_ENTRY_PHASE,
            true,
            Some(STATUS_DLL_INIT_FAILED),
            PRE_ENTRY_PHASE,
        ),
        required(
            true,
            false,
            None,
            "none",
            true,
            Some(STATUS_DLL_INIT_FAILED),
            PRE_ENTRY_PHASE,
        ),
        required(
            true,
            true,
            Some(STATUS_DLL_INIT_FAILED),
            PRE_ENTRY_PHASE,
            false,
            None,
            "none",
        ),
        required(
            true,
            true,
            Some(5),
            PRE_ENTRY_PHASE,
            true,
            Some(STATUS_DLL_INIT_FAILED),
            PRE_ENTRY_PHASE,
        ),
        required(
            true,
            true,
            Some(STATUS_DLL_INIT_FAILED),
            PRE_ENTRY_PHASE,
            true,
            Some(5),
            PRE_ENTRY_PHASE,
        ),
        required(
            true,
            true,
            Some(STATUS_DLL_INIT_FAILED),
            PRE_ENTRY_PHASE,
            true,
            Some(STATUS_DLL_INIT_FAILED),
            "post-initial-breakpoint",
        ),
    ] {
        assert!(!rejected);
    }
}

#[test]
fn target_token_userenv_inventory_is_bounded_deterministic_and_value_redacted() {
    let block = environment_block(&[
        ("SystemDrive", "C:"),
        ("SystemRoot", r"C:\Windows"),
        ("windir", r"C:\Windows"),
        ("USERPROFILE", r"C:\Users\private-user"),
    ]);
    let inventory = bounded_user_environment_inventory_for_test(Some(&block)).unwrap();
    let repeated = bounded_user_environment_inventory_for_test(Some(&block)).unwrap();

    assert_eq!(inventory, repeated);
    assert_eq!(inventory.units, block.len());
    assert_eq!(inventory.entries, 4);
    assert!(inventory.missing_required.is_empty());
    assert_eq!(inventory.sha256.len(), 64);
    assert_eq!(inventory.keys_sha256.len(), 64);

    let changed_value = environment_block(&[
        ("SystemDrive", "D:"),
        ("SystemRoot", r"C:\Windows"),
        ("windir", r"C:\Windows"),
        ("USERPROFILE", r"C:\Users\another-private-user"),
    ]);
    let changed = bounded_user_environment_inventory_for_test(Some(&changed_value)).unwrap();
    assert_ne!(changed.sha256, inventory.sha256);
    assert_eq!(changed.keys_sha256, inventory.keys_sha256);

    let diagnostic = render_loader_environment_prerequisite_canary_for_test(
        "baseline-environment-digest",
        &inventory.sha256,
        &inventory.keys_sha256,
        inventory.units,
        inventory.entries,
    );
    assert_ordered_substrings(
        &diagnostic,
        &[
            "loader_environment_prerequisite_canary=v1",
            "state=classified-common-failure",
            "baseline_environment=canonical-minimal-system",
            "comparison_environment=target-token-userenv-v1",
            "differing_fields=[environment]",
            "baseline=[environment=canonical-minimal-system",
            "comparison=[environment=target-token-userenv-v1",
            "target_token_instance_sha256=",
            "baseline_environment_sha256=baseline-environment-digest",
            "comparison_environment_sha256=",
            "comparison_environment_keys_sha256=",
            "comparison_environment_units=",
            "comparison_environment_entries=4",
            "profile_loaded=false",
            "matrix_cell=canonical-minimal-system-none-snaps-off",
            "debug_mode=false",
            "creation_flags=0x00080404",
            "invariant_error=none",
            "workload_executed=false",
            "qualification_promoted=false",
        ],
    );
    for secret in [
        "USERPROFILE",
        "private-user",
        "another-private-user",
        r"C:\Users",
    ] {
        assert!(!diagnostic.contains(secret), "diagnostic leaked {secret}");
    }
}

#[test]
fn target_token_userenv_inventory_rejects_null_malformed_and_ambiguous_blocks() {
    let null_error = bounded_user_environment_inventory_for_test(None).unwrap_err();
    assert!(null_error.contains("null"));

    let mut unterminated = environment_block(&[("SystemRoot", r"C:\Windows")]);
    unterminated.pop();
    assert!(
        bounded_user_environment_inventory_for_test(Some(&unterminated))
            .unwrap_err()
            .contains("double-NUL")
    );

    let premature = [
        b'A' as u16,
        b'=' as u16,
        b'1' as u16,
        0,
        0,
        b'B' as u16,
        b'=' as u16,
        b'2' as u16,
        0,
        0,
    ];
    assert!(
        bounded_user_environment_inventory_for_test(Some(&premature))
            .unwrap_err()
            .contains("premature")
    );

    let missing_separator = [b'N' as u16, b'A' as u16, b'M' as u16, b'E' as u16, 0, 0];
    assert!(
        bounded_user_environment_inventory_for_test(Some(&missing_separator))
            .unwrap_err()
            .contains("separator")
    );

    let invalid_utf16 = [0xd800, b'=' as u16, b'x' as u16, 0, 0];
    assert!(
        bounded_user_environment_inventory_for_test(Some(&invalid_utf16))
            .unwrap_err()
            .contains("UTF-16")
    );

    let duplicate = environment_block(&[("SystemRoot", "one"), ("SYSTEMROOT", "two")]);
    assert!(
        bounded_user_environment_inventory_for_test(Some(&duplicate))
            .unwrap_err()
            .contains("duplicate case-insensitive key")
    );

    let maximum_units = loader_environment_max_units_for_test();
    let entry_prefix = [b'A' as u16, b'=' as u16];
    let terminal = [0_u16, 0_u16];
    let payload_units = maximum_units
        .checked_sub(entry_prefix.len() + terminal.len())
        .expect("native environment bound accommodates one entry");
    let mut at_limit = Vec::with_capacity(maximum_units);
    at_limit.extend(entry_prefix);
    at_limit.extend(std::iter::repeat_n(b'x' as u16, payload_units));
    at_limit.extend(terminal);
    let boundary = bounded_user_environment_inventory_for_test(Some(&at_limit)).unwrap();
    assert_eq!(boundary.units, maximum_units);
    assert_eq!(boundary.entries, 1);

    let mut over_limit = at_limit;
    over_limit.insert(over_limit.len() - terminal.len(), b'x' as u16);
    assert!(
        bounded_user_environment_inventory_for_test(Some(&over_limit))
            .unwrap_err()
            .contains("bounded double-NUL")
    );
}

fn environment_entry_names(units: &[u16]) -> Vec<String> {
    units
        .split(|unit| *unit == 0)
        .take_while(|entry| !entry.is_empty())
        .map(|entry| {
            let separator = entry
                .iter()
                .position(|unit| *unit == b'=' as u16)
                .expect("encoded environment entry has a name/value separator");
            String::from_utf16(&entry[..separator]).expect("environment key is valid UTF-16")
        })
        .collect()
}

fn environment_block(entries: &[(&str, &str)]) -> Vec<u16> {
    let mut units = Vec::new();
    for (name, value) in entries {
        units.extend(name.encode_utf16());
        units.push(b'=' as u16);
        units.extend(value.encode_utf16());
        units.push(0);
    }
    units.push(0);
    units
}

fn assert_ordered_substrings(haystack: &str, needles: &[&str]) {
    let mut cursor = 0;
    for needle in needles {
        let offset = haystack[cursor..]
            .find(needle)
            .unwrap_or_else(|| panic!("missing ordered diagnostic token {needle}: {haystack}"));
        cursor += offset + needle.len();
    }
}
