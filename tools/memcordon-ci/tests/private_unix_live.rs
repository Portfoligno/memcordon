use memcordon_ci::private_unix_live::verify_proc_unix_endpoints_absent;

const HEADER: &str = "Num RefCount Protocol Flags Type St Inode Path\n";
const ROW: &str = "00000000: 00000002 00000000 00010000 0001 01 12345 ";

#[test]
fn proc_unix_parser_preserves_path_remainder_and_rejects_ambiguous_names() {
    let pathname = "/tmp/memcordon-private-unix-case-path";
    let abstract_name = "@memcordon-private-unix-case-abstract";
    let unrelated = format!("{HEADER}{ROW}/tmp/unrelated\n");
    assert!(
        verify_proc_unix_endpoints_absent(unrelated.as_bytes(), pathname, abstract_name).is_ok()
    );
    let present_path = format!("{HEADER}{ROW}{pathname}\n");
    assert!(
        verify_proc_unix_endpoints_absent(present_path.as_bytes(), pathname, abstract_name)
            .is_err()
    );
    let present_abstract = format!("{HEADER}{ROW}{abstract_name}\n");
    assert!(
        verify_proc_unix_endpoints_absent(present_abstract.as_bytes(), pathname, abstract_name)
            .is_err()
    );
    let spaced = format!("{HEADER}{ROW}{pathname} with suffix\n");
    assert!(verify_proc_unix_endpoints_absent(spaced.as_bytes(), pathname, abstract_name).is_err());
    let ambiguous = format!("{HEADER}{ROW} {pathname}\n");
    assert!(
        verify_proc_unix_endpoints_absent(ambiguous.as_bytes(), pathname, abstract_name).is_err()
    );
    let truncated = format!("{HEADER}{ROW}/tmp/unrelated");
    assert!(
        verify_proc_unix_endpoints_absent(truncated.as_bytes(), pathname, abstract_name).is_err()
    );
}
