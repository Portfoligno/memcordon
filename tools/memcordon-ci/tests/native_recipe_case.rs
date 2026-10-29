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
        "emit_current_parser_mutations",
        "current_version_vectors::emit_current_request_result_vectors",
        "native_current_filter::current_filter_vectors_emit_actual_component_receipts",
        "protocol_tests::unsupported_current_wire_versions_emit_actual_receipt",
    ];
    for recipe in recipes {
        assert!(admitted(recipe));
        assert!(!admitted(&format!("{recipe}-foreign")));
    }
    for recipe in [
        "",
        "recover",
        "unsupported_recipe",
        "emit_current_parser_mutations --ignored",
    ] {
        assert!(!admitted(recipe));
    }
}
