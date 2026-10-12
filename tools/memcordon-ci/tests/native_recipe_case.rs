#![cfg(unix)]
use memcordon_ci::release::native_recipe_case::{admitted, create};

#[test]
fn original_recipe_output_is_exclusive_and_private() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("case");
    create(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let evidence = path.join("original");
    std::fs::write(&evidence, b"original evidence").unwrap();
    assert_eq!(
        create(&path).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read(&evidence).unwrap(), b"original evidence");
}

#[test]
fn only_exact_existing_measured_recipes_are_admitted() {
    let recipes = [
        "native_index_mutations_emit_actual_parser_receipts",
        "operational_parser_receipts::native_operational_parser_mutations_emit_actual_receipts",
        "native_private_tcp::mixed_filter_vectors_emit_actual_component_receipts",
        "native_versions::native_version_vectors_emit_actual_component_receipts",
        "private_attempt::durable_journal_barriers_emit_actual_component_receipts",
        "native_mixed_release::native_leased_release_emit_actual_component_receipt",
        "native_mixed_recovery::native_account_retirement_boundary_emit_actual_receipt",
        "native_mixed_recovery::native_lost_terminal_response_emit_actual_receipt",
    ];
    for recipe in recipes {
        assert!(admitted(recipe));
        assert!(!admitted(&format!("{recipe}-foreign")));
    }
    for recipe in [
        "",
        "recover",
        "native_original_recovery::native_original_recovery_emit_actual_receipt",
        "native_mixed_recovery",
        "native_mixed_release::native_leased_release_emit_actual_component_receipt --ignored",
    ] {
        assert!(!admitted(recipe));
    }
}
