//! Provider declarations for measured, immutable toolchain-relative ELF search.
pub(super) fn directory(member: &str, search: &str) -> Result<String, String> {
    if member.len() > 4096
        || search.len() > 4096
        || !member.starts_with("toolchain/")
        || member
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
        || !(search.contains("$ORIGIN") || search.contains("${ORIGIN}"))
    {
        return Err("toolchain search lacks bounded original member/ORIGIN authority".into());
    }
    let parent = member
        .rsplit_once('/')
        .ok_or("toolchain member parent absent")?
        .0;
    let expanded = search
        .replace("${ORIGIN}", &format!("/{parent}"))
        .replace("$ORIGIN", &format!("/{parent}"));
    if !expanded.starts_with("/toolchain/") || expanded.contains('$') {
        return Err("toolchain search crosses copied toolchain authority".into());
    }
    let mut parts = Vec::new();
    for part in expanded.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                if parts.len() <= 1 {
                    return Err("toolchain search escapes copied toolchain".into());
                }
                parts.pop();
            }
            value => parts.push(value),
        }
    }
    let normalized = parts.join("/");
    if normalized.len() > 4096 {
        return Err("toolchain search expansion exceeds bound".into());
    }
    Ok(normalized)
}

pub(super) fn declare(directories: &mut Vec<String>, directory: String) -> Result<(), String> {
    if !directories.contains(&directory) {
        if directories.len() >= 32 {
            return Err("toolchain library catalogue exceeds existing directory bound".into());
        }
        directories.push(directory);
    }
    Ok(())
}

/// Publish the actual final manifest, retaining only measured empty searches.
pub(super) fn definition(
    target: &str,
    entries: Vec<memcordon_core::workload_files::ImageEntryV1>,
    entrypoints: Vec<memcordon_core::workload_files::ImageEntrypointV1>,
    host_candidates: Vec<memcordon_core::workload_files::RootRelativePath>,
    measured: &[(
        memcordon_core::workload_files::RootRelativePath,
        String,
        String,
    )],
) -> Result<memcordon_core::workload_bundle::SnapshotManifestV1, String> {
    use memcordon_core::{BoundedVec, workload_files::RootRelativePath};
    fn bounded<T, const N: usize>(
        values: impl IntoIterator<Item = T>,
    ) -> Result<BoundedVec<T, N>, String> {
        let mut result = BoundedVec::default();
        for value in values {
            result
                .try_push(value)
                .map_err(|_| "final image inventory exceeds bound")?;
        }
        Ok(result)
    }
    let mut directories = Vec::new();
    for candidate in host_candidates {
        if entries
            .iter()
            .any(|entry| memcordon_core::workload_files::is_beneath(entry.path(), &candidate))
        {
            declare(&mut directories, candidate.as_str().to_owned())?;
        }
    }
    for (member, search, normalized) in measured {
        if !entries.iter().any(|entry| matches!(entry,memcordon_core::workload_files::ImageEntryV1::Regular{path,..} if path==member))
            || directory(member.as_str(),search)? != *normalized {
            return Err("measured toolchain search differs from original member/ORIGIN normalization".into());
        }
        declare(&mut directories, normalized.clone())?;
    }
    let value = memcordon_core::workload_bundle::SnapshotManifestV1 {
        format: "memcordon.workload-snapshot".into(),
        revision: 1,
        target: target.into(),
        entries: bounded(entries)?,
        entrypoints: bounded(entrypoints)?,
        library_directories: bounded(
            directories
                .into_iter()
                .map(RootRelativePath::new)
                .collect::<Result<Vec<_>, _>>()?,
        )?,
    };
    value.validate()?;
    for (_, _, directory) in measured {
        if !value
            .library_directories
            .as_slice()
            .iter()
            .any(|path| path.as_str() == directory)
        {
            return Err(
                "measured toolchain search was omitted from the final image catalogue".into(),
            );
        }
    }
    Ok(value)
}
