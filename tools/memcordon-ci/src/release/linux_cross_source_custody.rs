//! Exact held directory boundary, never a blanket ownership-based exclusion.
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;

pub fn require_caller_boundary(
    named: &Metadata,
    held: &Metadata,
    original: (u64, u64, u32, u32, u32),
    caller_uid: u32,
    caller_gid: u32,
) -> Result<(), String> {
    let stamp = |metadata: &Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
        )
    };
    if !named.is_dir()
        || !held.is_dir()
        || named.uid() != caller_uid
        || named.gid() != caller_gid
        || named.mode() & 0o7777 != 0o700
        || named.nlink() == 0
        || held.nlink() == 0
        || stamp(named) != stamp(held)
        || stamp(held) != original
    {
        return Err("cross source held caller boundary custody differs".into());
    }
    Ok(())
}
