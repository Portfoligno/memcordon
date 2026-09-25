//! Distinct post-exec target image and descriptor witness. The expected image
//! identity comes only from the retained root-protected package descriptor.

use std::os::unix::fs::MetadataExt;

pub(crate) const SELECTOR: &str = "private_tcp::target_exec_and_fd_leak_observed";

pub(crate) fn expected_projection(device: u64, inode: u64) -> Result<[u8; 20], String> {
    if device == 0 || inode == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: pinned image identity absent".into());
    }
    let mut bytes = [0_u8; 20];
    bytes[..8].copy_from_slice(&device.to_le_bytes());
    bytes[8..16].copy_from_slice(&inode.to_le_bytes());
    bytes[16..].copy_from_slice(&super::private_release_descriptors::expected_projection());
    Ok(bytes)
}

pub(crate) fn observe_target_projection() -> Result<[u8; 20], String> {
    let descriptors = super::private_release_descriptors::observe_target_projection()?;
    let metadata = std::fs::metadata("/proc/self/exe")
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: executable: {error}"))?;
    if !metadata.is_file() || metadata.dev() == 0 || metadata.ino() == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: executable identity differs".into());
    }
    let mut bytes = expected_projection(metadata.dev(), metadata.ino())?;
    bytes[16..].copy_from_slice(&descriptors);
    Ok(bytes)
}
