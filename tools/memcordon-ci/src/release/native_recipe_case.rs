//! Exact original measured recipes and their exclusive output allocation.
use std::{fs, os::unix::fs::DirBuilderExt, path::Path};

pub fn admitted(test: &str) -> bool {
    matches!(
        test,
        "emit_current_parser_mutations"
            | "current_version_vectors::emit_current_request_result_vectors"
            | "native_current_filter::current_filter_vectors_emit_actual_component_receipts"
            | "protocol_tests::unsupported_current_wire_versions_emit_actual_receipt"
    )
}

pub fn create(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    fs::File::open(
        path.parent()
            .ok_or_else(|| std::io::Error::other("native recipe parent absent"))?,
    )?
    .sync_all()
}
