use sha2::Digest;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{collections::BTreeMap, fs, path::Path};

pub const LIFECYCLE_RECOVERY_OWNER_PRECONDITION: &str =
    "lifecycle-recovery-owner-precondition.json";
pub const LIFECYCLE_RECOVERY_DIAGNOSTIC_INVENTORY: &str =
    "lifecycle-recovery-diagnostic-inventory.json";

const RETAINED: [&str; 10] = [
    "stage.json",
    "original-native-recovery-origin.json",
    "original-native-recovery-input.json",
    "original-native-recovery-owner.json",
    "original-native-recovery-invocation.json",
    "original-native-recovery-process.json",
    "original-native-recovery-capture.json",
    "original-native-recovery-stdout.bin",
    "original-native-recovery-stderr.bin",
    "original-native-recovery-result.json",
];
const FAILURE_DIAGNOSTIC: &str = "original-native-recovery-failure.json";

/// Failure inventory is deliberately separate from `collect`'s single complete
/// attempt acceptance. Partial or nonzero attempts remain diagnostics only.
pub type DiagnosticInventory = (BTreeMap<String, Vec<u8>>, Vec<String>);

pub fn collect_diagnostic_attempts(
    output: &Path,
    mut read: impl FnMut(&Path, u64) -> Result<Vec<u8>, String>,
) -> Result<DiagnosticInventory, String> {
    let mut files = BTreeMap::new();
    let mut issues = Vec::new();
    let mut attempts = Vec::new();
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(output)
        .map_err(|error| error.to_string())?;
    for (index, entry) in fs::read_dir(output)
        .map_err(|error| error.to_string())?
        .enumerate()
    {
        if index >= 4096 {
            return Err("recovery diagnostic root inventory exceeds bound".into());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(name) = name
            .to_str()
            .filter(|name| name.starts_with("original-recovery-"))
        else {
            continue;
        };
        let suffix = name
            .strip_prefix("original-recovery-")
            .expect("selected prefix");
        if suffix.is_empty()
            || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || attempts.len() >= 16
        {
            return Err("recovery diagnostic attempt name/count differs".into());
        }
        attempts.push(name.to_owned());
    }
    attempts.sort();
    let mut total = 0usize;
    for attempt in attempts {
        let directory = output.join(&attempt);
        let held = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(&directory)
            .map_err(|error| format!("recovery diagnostic directory {directory:?}: {error}"))?;
        let before = held.metadata().map_err(|error| error.to_string())?;
        if before.uid() != root.metadata().map_err(|error| error.to_string())?.uid()
            || before.mode() & 0o022 != 0
        {
            return Err("recovery diagnostic attempt custody differs".into());
        }
        for leaf in RETAINED.into_iter().chain([FAILURE_DIAGNOSTIC]) {
            let path = directory.join(leaf);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if leaf != FAILURE_DIAGNOSTIC {
                        issues.push(format!("{attempt}/{leaf}: absent"));
                    }
                    continue;
                }
                Err(error) => {
                    return Err(format!("recovery diagnostic metadata {path:?}: {error}"));
                }
                Ok(metadata)
                    if !metadata.is_file()
                        || metadata.nlink() != 1
                        || metadata.uid() != before.uid()
                        || metadata.mode() & 0o022 != 0 =>
                {
                    return Err(format!(
                        "recovery diagnostic file custody differs: {path:?}"
                    ));
                }
                Ok(_) => {}
            }
            let remaining = (128 * 1024 * 1024usize)
                .checked_sub(total)
                .ok_or("recovery diagnostic total exceeds bound")?
                .min(16 * 1024 * 1024);
            let bytes = read(&path, remaining as u64)?;
            if bytes.len() > remaining {
                return Err("recovery diagnostic read exceeds bound".into());
            }
            total += bytes.len();
            files.insert(format!("{attempt}/{leaf}"), bytes);
        }
        let association = (|| -> Result<(), String> {
            let get = |leaf| {
                files
                    .get(&format!("{attempt}/{leaf}"))
                    .ok_or_else(|| format!("{attempt}/{leaf}: unavailable for binding"))
            };
            let parse = |bytes: &[u8]| -> Result<serde_json::Value, String> {
                memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
                serde_json::from_slice(bytes).map_err(|error| error.to_string())
            };
            let stage = parse(get("stage.json")?)?;
            let invocation = parse(get("original-native-recovery-invocation.json")?)?;
            let stage_path = stage["stage"]
                .as_str()
                .ok_or("recovery diagnostic stage absent")?;
            if !Path::new(stage_path).is_absolute()
                || Path::new(stage_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    != Some(attempt.as_str())
                || invocation["working_directory"] != stage_path
                || invocation["input_sha256"] != stage["input_sha256"]
                || stage["input_sha256"]
                    != hex::encode(sha2::Sha256::digest(get(
                        "original-native-recovery-input.json",
                    )?))
                || stage["origin_sha256"]
                    != hex::encode(sha2::Sha256::digest(get(
                        "original-native-recovery-origin.json",
                    )?))
            {
                return Err(
                    "recovery diagnostic original stage/input/origin/invocation binding differs"
                        .into(),
                );
            }
            Ok(())
        })();
        if let Err(error) = association {
            issues.push(format!("{attempt}: unbound diagnostic: {error}"));
        }
        let after = held.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(&directory).map_err(|error| error.to_string())?;
        let stamp = |value: &fs::Metadata| {
            (
                value.dev(),
                value.ino(),
                value.uid(),
                value.mode(),
                value.mtime(),
                value.mtime_nsec(),
                value.ctime(),
                value.ctime_nsec(),
            )
        };
        if !named.is_dir() || stamp(&before) != stamp(&after) || stamp(&before) != stamp(&named) {
            return Err("recovery diagnostic attempt replaced during capture".into());
        }
    }
    let named = fs::symlink_metadata(output).map_err(|error| error.to_string())?;
    let held = root.metadata().map_err(|error| error.to_string())?;
    if !named.is_dir() || named.dev() != held.dev() || named.ino() != held.ino() {
        return Err("recovery diagnostic root replaced".into());
    }
    Ok((files, issues))
}

pub fn projected_parent<'a>(path: &'a Path, case: &Path) -> Result<&'a Path, String> {
    let suffix = path
        .strip_prefix(case)
        .map_err(|_| "recovery product escapes case")?;
    let text = suffix
        .to_str()
        .ok_or("recovery product path is not UTF-8")?;
    let segments: Vec<_> = text.split('/').collect();
    let valid_leaf =
        |name: &str| !name.is_empty() && !name.starts_with('.') && !name.contains('\\');
    let valid = match segments.as_slice() {
        [leaf] => valid_leaf(leaf),
        [attempt, leaf] => {
            attempt
                .strip_prefix("original-recovery-")
                .is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
                && (RETAINED.contains(leaf) || *leaf == FAILURE_DIAGNOSTIC)
        }
        _ => false,
    };
    if !valid {
        return Err("recovery product differs from retained tree shape".into());
    }
    path.parent()
        .ok_or_else(|| "recovery product parent absent".into())
}

pub fn collect(
    output: &Path,
    mut read: impl FnMut(&Path, u64) -> Result<Vec<u8>, String>,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut frozen = BTreeMap::new();
    let mut pending = vec![(output.to_path_buf(), String::new())];
    let mut directories = Vec::new();
    let mut attempt = None;
    let mut count = 0usize;
    let mut total = 0usize;
    while let Some((directory, prefix)) = pending.pop() {
        let held = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(&directory)
            .map_err(|error| error.to_string())?;
        let before = held.metadata().map_err(|error| error.to_string())?;
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            count += 1;
            if count > 128 {
                return Err("native recovery raw artifact count exceeds bound".into());
            }
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "native recovery artifact name is not UTF-8")?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
            if metadata.is_dir() && prefix.is_empty() {
                let suffix = name
                    .strip_prefix("original-recovery-")
                    .filter(|suffix| {
                        !suffix.is_empty()
                            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    })
                    .ok_or("native recovery retains unknown directory")?;
                if attempt.replace(name.clone()).is_some() || suffix.is_empty() {
                    return Err("native recovery retains duplicate attempt directories".into());
                }
                pending.push((entry.path(), name));
                continue;
            }
            if name.starts_with('.')
                || !metadata.is_file()
                || metadata.nlink() != 1
                || !prefix.is_empty() && !RETAINED.contains(&name.as_str())
            {
                return Err("native recovery retains unresolved/nonregular artifact".into());
            }
            let limit = (128 * 1024 * 1024usize)
                .checked_sub(total)
                .ok_or("native recovery aggregate capture overflow")?
                .min(16 * 1024 * 1024);
            if metadata.len() > limit as u64 {
                return Err("native recovery raw artifact exceeds capture bound".into());
            }
            let bytes = read(&entry.path(), limit as u64)?;
            if bytes.len() > limit {
                return Err("native recovery raw artifact exceeds capture bound".into());
            }
            total += bytes.len();
            let key = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if frozen.insert(key, bytes).is_some() {
                return Err("native recovery artifact duplicated".into());
            }
        }
        directories.push((directory, held, before));
    }
    for (path, held, before) in directories {
        let after = held.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        let stamp = |metadata: &fs::Metadata| {
            (
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                metadata.uid(),
                metadata.gid(),
                metadata.nlink(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        };
        if !named.is_dir() || stamp(&before) != stamp(&after) || stamp(&before) != stamp(&named) {
            return Err("native recovery original directory custody changed".into());
        }
    }
    if let Some(attempt) = attempt {
        if RETAINED
            .iter()
            .any(|leaf| !frozen.contains_key(&format!("{attempt}/{leaf}")))
        {
            return Err("native recovery retained attempt incomplete".into());
        }
        let parse = |bytes: &[u8]| -> Result<serde_json::Value, String> {
            memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)
                .map_err(|error| error.to_string())?;
            serde_json::from_slice(bytes).map_err(|error| error.to_string())
        };
        let stage = parse(&frozen[&format!("{attempt}/stage.json")])?;
        let invocation = parse(
            frozen
                .get("native-recovery-invocation.json")
                .ok_or("native recovery invocation absent")?,
        )?;
        let stage_path = stage["stage"]
            .as_str()
            .ok_or("native recovery original stage absent")?;
        let input_digest = stage["input_sha256"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("native recovery retained input digest absent")?;
        let invocation_digest = invocation["input_sha256"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("native recovery invocation input digest absent")?;
        let origin_digest = stage["origin_sha256"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or("native recovery retained origin digest absent")?;
        if !Path::new(stage_path).is_absolute()
            || Path::new(stage_path)
                .file_name()
                .and_then(|name| name.to_str())
                != Some(attempt.as_str())
            || invocation["working_directory"] != stage_path
            || invocation_digest != input_digest
            || input_digest
                != hex::encode(sha2::Sha256::digest(
                    &frozen[&format!("{attempt}/original-native-recovery-input.json")],
                ))
            || origin_digest
                != hex::encode(sha2::Sha256::digest(
                    &frozen[&format!("{attempt}/original-native-recovery-origin.json")],
                ))
        {
            return Err("native recovery retained attempt association differs".into());
        }
    }
    Ok(frozen)
}
