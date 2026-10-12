//! Exact original measured recipes and their exclusive output allocation.
use std::{fs, os::unix::fs::DirBuilderExt, path::Path};

pub fn admitted(test: &str) -> bool {
    matches!(
        test,
        "native_index_mutations_emit_actual_parser_receipts"
            | "operational_parser_receipts::native_operational_parser_mutations_emit_actual_receipts"
            | "native_private_tcp::mixed_filter_vectors_emit_actual_component_receipts"
            | "native_versions::native_version_vectors_emit_actual_component_receipts"
            | "private_attempt::durable_journal_barriers_emit_actual_component_receipts"
            | "native_mixed_release::native_leased_release_emit_actual_component_receipt"
            | "native_mixed_recovery::native_account_retirement_boundary_emit_actual_receipt"
            | "native_mixed_recovery::native_lost_terminal_response_emit_actual_receipt"
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
