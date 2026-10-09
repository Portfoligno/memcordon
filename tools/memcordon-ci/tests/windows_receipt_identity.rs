#[path = "../src/windows_receipt_identity.rs"]
mod windows_receipt_identity;

#[test]
fn receipt_type_reparse_and_link_refusals_keep_queried_metadata() {
    let path = std::path::Path::new("original-receipt");
    windows_receipt_identity::validate(path, false, 0, 1).unwrap();
    windows_receipt_identity::validate(path, true, 0x10, 7).unwrap();
    for (directory, attributes, links) in [
        (false, 0x400, 1),
        (true, 0x410, 1),
        (false, 0x10, 1),
        (true, 0, 1),
        (false, 0, 0),
        (false, 0, 2),
    ] {
        let message = windows_receipt_identity::validate(path, directory, attributes, links)
            .unwrap_err()
            .to_string();
        assert!(message.contains("original-receipt"));
        assert!(message.contains(&format!("expected-directory={directory}")));
        assert!(message.contains(&format!("attributes=0x{attributes:08x}")));
        assert!(message.contains(&format!("links={links}")));
    }
}

#[test]
fn large_receipt_path_diagnostic_is_bounded_and_escaped() {
    let text = format!("original\n{}", "界".repeat(20_000));
    let message = windows_receipt_identity::validate(std::path::Path::new(&text), false, 0x400, 2)
        .unwrap_err()
        .to_string();
    assert!(message.contains("original\\n"));
    assert!(message.contains("path-truncated=true"));
    assert!(!message.contains('\n'));
    assert!(message.len() < 3 * 1024);
}
