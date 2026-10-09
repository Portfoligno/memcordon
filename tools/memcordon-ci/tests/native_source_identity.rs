#[path = "../src/release/native_source_identity.rs"]
mod native_source_identity;

#[test]
fn source_refusal_preserves_exact_type_link_and_size_boundaries() {
    let path = std::path::Path::new("original-source");
    native_source_identity::validate(path, true, 1, 64, 64).unwrap();
    for (regular, links, length) in [(false, 1, 64), (true, 0, 64), (true, 2, 64), (true, 1, 65)] {
        let error = native_source_identity::validate(path, regular, links, length, 64).unwrap_err();
        assert!(error.contains("original-source"));
        assert!(error.contains(&format!("regular={regular}")));
        assert!(error.contains(&format!("links={links}")));
        assert!(error.contains(&format!("length={length}")));
        assert!(error.contains("limit=64"));
    }
}

#[test]
fn source_path_diagnostic_is_byte_bounded_and_control_escaped() {
    let path = format!("original\n{}", "界".repeat(20_000));
    let error =
        native_source_identity::validate(std::path::Path::new(&path), true, 2, 1, 64).unwrap_err();
    assert!(error.contains("original\\n"));
    assert!(error.contains("path-truncated=true"));
    assert!(!error.contains('\n'));
    assert!(error.len() < 4 * 1024);
}
