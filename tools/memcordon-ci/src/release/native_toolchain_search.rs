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
