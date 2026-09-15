//! Owner: source governance. Git defines membership, never directory traversal.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use crate::{CiError, Result, command};

pub(super) fn relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        && !path.contains('\\')
}

pub(super) fn sources(root: &Path) -> Result<BTreeSet<String>> {
    // Include nonignored pending additions, matching pre-commit policy semantics.
    // Deleted index entries are excluded; after commit this is the tracked set.
    let output = command::CommandSpec::new("git", root, std::time::Duration::from_secs(120))
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .output()?;
    if !output.status.success() {
        return Err(CiError::Message(format!(
            "source inventory Git command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let bytes = output.stdout;
    let mut paths = BTreeSet::new();
    for bytes in bytes
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
    {
        let path = std::str::from_utf8(bytes)
            .map_err(|_| CiError::Message("source inventory contains a non-UTF-8 path".into()))?;
        if !relative(path) {
            return Err(CiError::Message(format!(
                "source inventory path is unsafe: {path:?}"
            )));
        }
        if path.ends_with(".rs")
            && ["crates/", "tools/", "fuzz/fuzz_targets/"]
                .iter()
                .any(|prefix| path.starts_with(prefix))
            && root.join(path).try_exists()?
        {
            paths.insert(path.to_owned());
        }
    }
    Ok(paths)
}
