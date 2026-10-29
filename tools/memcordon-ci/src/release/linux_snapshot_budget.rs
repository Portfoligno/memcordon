//! Memory needed by the actual caller snapshots before scenario RSS headroom.
use crate::{CiError, Result};
use memcordon_core::workload_bundle::{ImageEntryV1, SnapshotManifestV1};
use std::ffi::OsString;

pub fn memory_budget(
    runtime: &SnapshotManifestV1,
    input: &SnapshotManifestV1,
    headroom_bytes: u64,
) -> Result<(OsString, u64)> {
    runtime.validate().map_err(CiError::Message)?;
    input.validate().map_err(CiError::Message)?;
    let page = u64::try_from(rustix::param::page_size())
        .map_err(|error| CiError::Message(format!("native page size: {error}")))?;
    if page == 0 || !page.is_power_of_two() || headroom_bytes == 0 {
        return Err(CiError::Message(
            "native snapshot page size/headroom invalid".into(),
        ));
    }
    let overflow =
        || CiError::Message("current snapshot memory budget exceeds native range".into());
    let mut bytes = headroom_bytes
        .checked_add(128 * 1024 * 1024)
        .ok_or_else(overflow)?;
    for manifest in [runtime, input] {
        for entry in manifest.entries.as_slice() {
            // Inode/dentry and small allocation overhead remain charged even
            // for empty files, symlinks, and directories in the private root.
            bytes = bytes
                .checked_add(page.checked_mul(2).ok_or_else(overflow)?)
                .ok_or_else(overflow)?;
            if let ImageEntryV1::Regular { size, .. } = entry {
                let pages = size.checked_add(page - 1).ok_or_else(overflow)? / page;
                bytes = bytes
                    .checked_add(pages.checked_mul(page).ok_or_else(overflow)?)
                    .ok_or_else(overflow)?;
            }
        }
    }
    let mib = bytes.checked_add(1024 * 1024 - 1).ok_or_else(overflow)? / (1024 * 1024);
    let configured = mib.checked_mul(1024 * 1024).ok_or_else(overflow)?;
    Ok((OsString::from(format!("+{mib}MiB")), configured))
}
