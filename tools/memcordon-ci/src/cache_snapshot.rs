//! Bounded immutable copies of settled cache data. An index is never a work result.
use crate::{
    CiError, Result,
    cache_inputs::{KeyInputs, keys},
    cache_restore::{self, CompiledPartition},
    release::artifacts,
};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotKind {
    Compiled,
    RegistryArchives,
    RegistryIndex,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    path: PathBuf,
    size: u64,
    hash: String,
    mode: u32,
    modified: SystemTime,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    revision: u32,
    kind: SnapshotKind,
    compatibility: String,
    roots: Vec<PathBuf>,
    files: Vec<Item>,
}

struct Selection {
    stage: PathBuf,
    roots: Vec<PathBuf>,
    compatibility: String,
    input: String,
    family: &'static str,
    count: usize,
    bytes: u64,
    metadata: usize,
}

pub fn ordinary(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(CiError::Message("unsafe snapshot path kind".into()));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(CiError::Message("snapshot reparse point".into()));
            }
        }
    }
    Ok(())
}

fn selection(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<Selection> {
    let (_slot, roots, compatibility, input, family, count, bytes, metadata) = match kind {
        SnapshotKind::Compiled => {
            let partition = partition
                .ok_or_else(|| CiError::Message("compiled snapshot requires partition".into()))?;
            let slot = match partition {
                CompiledPartition::NativeTests => "native-tests",
                CompiledPartition::Product => "product",
                CompiledPartition::PrivateNativeTests => "private-native-tests",
                CompiledPartition::AuxiliaryProfiles => "auxiliary-profiles",
                CompiledPartition::FuzzTargets => "fuzz-targets",
                CompiledPartition::MiriTargets => {
                    return Err(CiError::Message(
                        "Miri targets do not use staged checkpoints".into(),
                    ));
                }
            };
            let context =
                crate::cache::context_partition(root, purpose, shard, &[], Some(partition))?;
            let crate::cache::OptionalCache::Available { entry } = &context.entries["product"]
            else {
                return Err(CiError::Message(
                    "compiled snapshot inputs unavailable".into(),
                ));
            };
            (
                slot,
                entry.paths.iter().map(|path| root.join(path)).collect(),
                entry.restore_prefix.clone().expect("compiled prefix"),
                entry.exact_key.clone(),
                "compiled-seed",
                500_000,
                6 * 1024 * 1024 * 1024,
                32 * 1024 * 1024,
            )
        }
        SnapshotKind::RegistryArchives | SnapshotKind::RegistryIndex => {
            for (name, value) in std::env::vars_os() {
                let name = name.to_string_lossy().to_ascii_uppercase();
                if name.starts_with("CARGO_SOURCE_")
                    || name.starts_with("CARGO_REGISTRY_")
                    || (name.starts_with("CARGO_REGISTRIES_")
                        && !(name == "CARGO_REGISTRIES_CRATES_IO_PROTOCOL" && value == "sparse"))
                {
                    return Err(CiError::Message(
                        "unmodeled snapshot registry override".into(),
                    ));
                }
            }
            let home = crate::download_cache::cargo_home(root)?;
            ordinary(&home)?;
            let configuration = crate::cache_inputs::registry_seed_configs(root)?;
            let mut facts = configuration;
            facts.insert("scope".into(), "public-crates-io-sparse".into());
            facts.insert("transport-os".into(), std::env::consts::OS.into());
            if kind == SnapshotKind::RegistryIndex {
                if facts
                    .get("registries.crates-io.protocol")
                    .is_some_and(|protocol| protocol != "\"sparse\"")
                    || std::env::var_os("CARGO_REGISTRIES_CRATES_IO_PROTOCOL")
                        .is_some_and(|protocol| protocol != "sparse")
                {
                    return Err(CiError::Message(
                        "index snapshot requires sparse protocol".into(),
                    ));
                }
                let pins = crate::config::toolchains(root)?;
                let reader = crate::command::rustup_cargo(
                    root,
                    &pins.stable,
                    ["-V"],
                    Duration::from_secs(30),
                )
                .output_quiet()?;
                if !reader.status.success() {
                    return Err(CiError::Message("Cargo snapshot reader unavailable".into()));
                }
                facts.insert(
                    "reader".into(),
                    String::from_utf8(reader.stdout)
                        .map_err(|_| CiError::Message("Cargo reader not UTF-8".into()))?,
                );
            }
            let compatibility = artifacts::checksum(&serde_json::to_vec(&facts)?);
            if kind == SnapshotKind::RegistryArchives {
                (
                    "registry-archives",
                    vec![home.join("registry/cache")],
                    compatibility.clone(),
                    compatibility,
                    "registry-archive-seed",
                    50_000,
                    4 * 1024 * 1024 * 1024,
                    16 * 1024 * 1024,
                )
            } else {
                (
                    "registry-index",
                    vec![home.join("registry/index")],
                    compatibility.clone(),
                    compatibility,
                    "registry-index-snapshot",
                    50_000,
                    4 * 1024 * 1024 * 1024,
                    16 * 1024 * 1024,
                )
            }
        }
    };
    let stage = cache_restore::safe_root(root, &stage_relative(kind, partition)?)?;
    Ok(Selection {
        stage,
        roots,
        compatibility,
        input,
        family,
        count,
        bytes,
        metadata,
    })
}

fn identity(selected: &Selection, content: BTreeMap<String, String>) -> Result<(String, String)> {
    keys(&KeyInputs {
        family: selected.family.into(),
        layout_revision: 6,
        compatibility: BTreeMap::from([("inputs".into(), selected.compatibility.clone())]),
        content,
    })
}

fn index_roots(selected: &Selection, kind: SnapshotKind) -> Vec<PathBuf> {
    match kind {
        SnapshotKind::Compiled => selected.roots.clone(),
        SnapshotKind::RegistryArchives => vec![PathBuf::from("registry/cache")],
        SnapshotKind::RegistryIndex => vec![PathBuf::from("registry/index")],
    }
}

fn stage_relative(kind: SnapshotKind, partition: Option<CompiledPartition>) -> Result<PathBuf> {
    let slot = match kind {
        SnapshotKind::RegistryArchives => "registry-archives",
        SnapshotKind::RegistryIndex => "registry-index",
        SnapshotKind::Compiled => match partition
            .ok_or_else(|| CiError::Message("compiled snapshot requires partition".into()))?
        {
            CompiledPartition::NativeTests => "native-tests",
            CompiledPartition::Product => "product",
            CompiledPartition::PrivateNativeTests => "private-native-tests",
            CompiledPartition::AuxiliaryProfiles => "auxiliary-profiles",
            CompiledPartition::FuzzTargets => "fuzz-targets",
            CompiledPartition::MiriTargets => {
                return Err(CiError::Message(
                    "Miri targets do not use staged checkpoints".into(),
                ));
            }
        },
    };
    Ok(Path::new("target/ci-cache-export").join(slot))
}

fn preflight(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<()> {
    cache_restore::safe_root(root, &stage_relative(kind, partition)?)?;
    if kind == SnapshotKind::Compiled {
        let layout = cache_restore::partition_layout(purpose, shard, partition)?;
        for path in layout.directories {
            cache_restore::safe_root(root, &path)?;
        }
        for path in layout.required_files {
            ordinary(&root.join(path))?;
        }
    } else {
        ordinary(&crate::download_cache::cargo_home(root)?)?;
    }
    Ok(())
}

pub fn seed_context(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<()> {
    preflight(root, kind, purpose, shard, partition)?;
    let selected = match selection(root, kind, purpose, shard, partition) {
        Ok(selected) => selected,
        Err(error) => {
            eprintln!("optional seed context unavailable: {error}");
            return crate::workflow_output::write(&[
                ("seed-lookup-key", String::new()),
                ("seed-restore-prefix", String::new()),
                ("seed-import-path", String::new()),
                ("input-key", String::new()),
                ("seed-compatibility", String::new()),
            ]);
        }
    };
    let (_, prefix) = identity(&selected, BTreeMap::new())?;
    let exact_prefix = [
        prefix.as_str(),
        artifacts::checksum(selected.input.as_bytes()).as_str(),
        "-",
    ]
    .concat();
    let lookup = [exact_prefix.as_str(), "lookup"].concat();
    crate::workflow_output::write(&[
        ("seed-lookup-key", lookup),
        (
            "seed-restore-prefix",
            if kind == SnapshotKind::Compiled {
                [exact_prefix, prefix].join("\n")
            } else {
                prefix
            },
        ),
        ("seed-import-path", selected.stage.display().to_string()),
        ("input-key", selected.input),
        ("seed-compatibility", selected.compatibility),
    ])
}

fn source_locks(selected: &Selection, kind: SnapshotKind) -> Result<Vec<File>> {
    if kind == SnapshotKind::Compiled {
        let targets: Vec<_> = selected
            .roots
            .iter()
            .map(|path| {
                if marker_root(path) {
                    path.parent().expect("marker parent").to_path_buf()
                } else {
                    path.clone()
                }
            })
            .collect();
        return cache_restore::settled_locks(&targets);
    }
    let home = selected.roots[0]
        .parent()
        .and_then(Path::parent)
        .expect("registry home");
    let mut locks = Vec::new();
    for name in [".package-cache", ".package-cache-mutate"] {
        let path = home.join(name);
        ordinary(&path)?;
        if !path.try_exists()? {
            continue;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| CiError::Message("source cache has active writer".into()))?;
        locks.push(file);
    }
    Ok(locks)
}

fn allowed(kind: SnapshotKind, relative: &Path) -> bool {
    let parts = relative.components().collect::<Vec<_>>();
    if parts
        .iter()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return false;
    }
    for part in &parts {
        let Some(name) = part.as_os_str().to_str() else {
            return false;
        };
        if name == ".cargo-lock" {
            return false;
        }
        if name.contains(':') || name.contains('\\') || name.ends_with('.') || name.ends_with(' ') {
            return false;
        }
        let stem = name
            .split('.')
            .next()
            .expect("path component stem")
            .to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|suffix| {
                    matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                })
            })
        {
            return false;
        }
    }
    if kind == SnapshotKind::Compiled {
        return true;
    }
    let Some(source) = parts.first().and_then(|part| part.as_os_str().to_str()) else {
        return false;
    };
    if kind == SnapshotKind::RegistryArchives {
        parts.len() == 2
            && matches!(
                source,
                "index.crates.io-1949cf8c6b5b557f" | "index.crates.io-6f17d22bba15001f"
            )
            && relative
                .extension()
                .is_some_and(|extension| extension == "crate")
    } else {
        source == "index.crates.io-1949cf8c6b5b557f"
            && (parts
                .get(1)
                .is_some_and(|part| part.as_os_str() == ".cache")
                || (parts.len() == 2 && parts[1].as_os_str() == "config.json"))
    }
}

fn mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        if metadata.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}

fn public_index_config(path: &Path) -> Result<()> {
    if path.file_name().is_none_or(|name| name != "config.json") {
        return Ok(());
    }
    if fs::metadata(path)?.len() > 64 * 1024 {
        return Err(CiError::Message(
            "sparse source configuration oversized".into(),
        ));
    }
    let config: serde_json::Value = serde_json::from_slice(&artifacts::read_file(path)?)?;
    let table = config
        .as_object()
        .ok_or_else(|| CiError::Message("sparse source configuration malformed".into()))?;
    if table
        .keys()
        .any(|key| !matches!(key.as_str(), "dl" | "api" | "auth-required"))
        || config.get("dl").and_then(serde_json::Value::as_str)
            != Some("https://static.crates.io/crates")
        || config.get("api").and_then(serde_json::Value::as_str) != Some("https://crates.io")
        || config
            .get("auth-required")
            .is_some_and(|value| value != &serde_json::Value::Bool(false))
    {
        return Err(CiError::Message(
            "unmodeled/private sparse source configuration".into(),
        ));
    }
    Ok(())
}

fn copy_file(
    source: &Path,
    destination: &Path,
    deadline: Instant,
    transport: Option<&Item>,
) -> Result<Item> {
    ordinary(destination)?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    copy_open_file(source, destination, deadline, transport, output)
}

fn copy_open_file(
    source: &Path,
    destination: &Path,
    deadline: Instant,
    transport: Option<&Item>,
    mut output: File,
) -> Result<Item> {
    ordinary(source)?;
    ordinary(destination)?;
    let before = fs::symlink_metadata(source)?;
    if !before.is_file() {
        return Err(CiError::Message(
            "snapshot payload is not a regular file".into(),
        ));
    }
    let modified = before.modified()?;
    let mut input = File::open(source)?;
    let opened = input.metadata()?;
    if opened.len() != before.len()
        || opened.modified()? != modified
        || mode(&opened) != mode(&before)
    {
        return Err(CiError::Message(
            "snapshot source changed before copy".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(CiError::Message("snapshot source identity changed".into()));
        }
    }
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(CiError::Message("snapshot copy deadline".into()));
        }
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
        size += count as u64;
        if size > before.len() {
            return Err(CiError::Message("snapshot source grew during copy".into()));
        }
    }
    let after = fs::symlink_metadata(source)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(CiError::Message("snapshot source identity changed".into()));
        }
    }
    if size != before.len()
        || after.len() != size
        || after.modified()? != modified
        || mode(&before) != mode(&after)
    {
        return Err(CiError::Message(
            "snapshot source changed during copy".into(),
        ));
    }
    output.set_times(
        fs::FileTimes::new().set_modified(transport.map_or(modified, |item| item.modified)),
    )?;
    if let Some(item) = transport {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            output.set_permissions(fs::Permissions::from_mode(item.mode))?;
        }
        #[cfg(not(unix))]
        {
            let mut permissions = output.metadata()?.permissions();
            permissions.set_readonly(item.mode & 0o222 == 0);
            output.set_permissions(permissions)?;
        }
    } else {
        output.set_permissions(before.permissions())?;
    }
    Ok(Item {
        path: PathBuf::new(),
        size,
        hash: hex::encode(hash.finalize()),
        mode: mode(&before),
        modified,
    })
}

fn marker_root(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "CACHEDIR.TAG")
}

fn destination(selected: &Selection, item: &Item, kind: SnapshotKind) -> Result<PathBuf> {
    let mut parts = item.path.components();
    let Some(Component::Normal(slot)) = parts.next() else {
        return Err(CiError::Message("unsafe snapshot member".into()));
    };
    let slot: usize = slot
        .to_str()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| CiError::Message("invalid snapshot root slot".into()))?;
    let root = selected
        .roots
        .get(slot)
        .ok_or_else(|| CiError::Message("invalid snapshot root slot".into()))?;
    let relative = parts.as_path();
    if relative.as_os_str().is_empty() || !allowed(kind, relative) {
        return Err(CiError::Message("unsafe snapshot member".into()));
    }
    if marker_root(root) {
        if relative != Path::new("CACHEDIR.TAG") {
            return Err(CiError::Message("invalid marker snapshot member".into()));
        }
        Ok(root.clone())
    } else {
        Ok(root.join(relative))
    }
}

fn content_hash(path: &Path, expected: u64, deadline: Instant) -> Result<String> {
    ordinary(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() != expected {
        return Err(CiError::Message("snapshot file size/kind mismatch".into()));
    }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(CiError::Message("snapshot validation deadline".into()));
        }
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > expected {
            return Err(CiError::Message("snapshot file grew".into()));
        }
        hash.update(&buffer[..count]);
    }
    if total != expected {
        return Err(CiError::Message("snapshot file shortened".into()));
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg_attr(windows, allow(unsafe_code))]
fn free_bytes(path: &Path) -> Result<u64> {
    let existing = path
        .ancestors()
        .find(|path| path.exists())
        .ok_or_else(|| CiError::Message("snapshot filesystem absent".into()))?;
    #[cfg(unix)]
    {
        let status =
            rustix::fs::statvfs(existing).map_err(|error| CiError::Message(error.to_string()))?;
        status
            .f_bavail
            .checked_mul(status.f_frsize)
            .ok_or_else(|| CiError::Message("snapshot free-space overflow".into()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let path: Vec<_> = existing.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut available = 0;
        let result = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                path.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if result == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(available)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = existing;
        Err(CiError::Message(
            "snapshot free-space query unsupported".into(),
        ))
    }
}

pub fn snapshot(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<()> {
    preflight(root, kind, purpose, shard, partition)?;
    let selected = match selection(root, kind, purpose, shard, partition) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("optional snapshot unavailable: {error}");
            return crate::workflow_output::write(&[("snapshot-ready", "false".into())]);
        }
    };
    // Ownership failures are blocking, unlike optional copy/resource failures.
    for path in &selected.roots {
        ordinary(path)?;
    }
    let locks = source_locks(&selected, kind)?;
    if partition == Some(CompiledPartition::AuxiliaryProfiles)
        && !cache_restore::cargo_marker_present(&root.join("target"))?
    {
        return crate::workflow_output::write(&[("snapshot-ready", "false".into())]);
    }
    let result = create(&selected, kind);
    drop(locks);
    match result {
        Ok(key) => {
            let current = selection(root, kind, purpose, shard, partition);
            if !current.is_ok_and(|current| {
                current.input == selected.input
                    && current.compatibility == selected.compatibility
                    && current.roots == selected.roots
            }) {
                eprintln!("optional snapshot inputs changed during copy");
                return crate::workflow_output::write(&[("snapshot-ready", "false".into())]);
            }
            crate::workflow_output::write(&[
                ("snapshot-ready", "true".into()),
                ("snapshot-key", key),
                ("snapshot-path", selected.stage.display().to_string()),
                ("input-key", selected.input),
                ("seed-compatibility", selected.compatibility),
            ])
        }
        Err(error) => {
            eprintln!("optional snapshot copy unavailable: {error}");
            crate::workflow_output::write(&[("snapshot-ready", "false".into())])
        }
    }
}

fn create(selected: &Selection, kind: SnapshotKind) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(300);
    // One immutable staging copy per operation. No live-output hardlinks.
    if selected.stage.try_exists()? {
        return Err(CiError::Message("snapshot staging already exists".into()));
    }
    let payload = selected.stage.join("payload");
    let mut inventory = Vec::new();
    let mut total = 0_u64;
    let mut entries = 0_usize;
    for (slot, source) in selected.roots.iter().enumerate() {
        if !source.try_exists()? {
            continue;
        }
        for entry in walkdir::WalkDir::new(source)
            .follow_links(false)
            .follow_root_links(false)
        {
            let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
            entries += 1;
            if entries > selected.count.saturating_sub(16) || Instant::now() >= deadline {
                return Err(CiError::Message("snapshot inventory exceeds bounds".into()));
            }
            ordinary(entry.path())?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.is_dir() {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(source)
                .map_err(|error| CiError::Message(error.to_string()))?;
            // A required marker is itself a root, represented by a fixed name.
            let relative = if relative.as_os_str().is_empty() {
                Path::new("CACHEDIR.TAG")
            } else {
                relative
            };
            if !allowed(kind, relative) || entry.file_name() == ".cargo-lock" {
                continue;
            }
            if kind == SnapshotKind::RegistryIndex {
                public_index_config(entry.path())?;
            }
            total = total
                .checked_add(metadata.len())
                .ok_or_else(|| CiError::Message("snapshot size overflow".into()))?;
            if inventory.len() >= selected.count || total > selected.bytes {
                return Err(CiError::Message("snapshot payload exceeds bounds".into()));
            }
            let path = PathBuf::from(slot.to_string()).join(relative);
            inventory.push((
                entry.path().to_path_buf(),
                path,
                metadata.len(),
                metadata.modified()?,
                mode(&metadata),
            ));
        }
    }
    if inventory.is_empty() {
        return Err(CiError::Message("snapshot has no reusable payload".into()));
    }
    let required = total
        .checked_add(selected.metadata as u64)
        .and_then(|value| value.checked_add(64 * 1024 * 1024))
        .ok_or_else(|| CiError::Message("snapshot disk requirement overflow".into()))?;
    if free_bytes(&selected.stage)? < required {
        return Err(CiError::Message(
            "snapshot free-space margin insufficient".into(),
        ));
    }
    fs::create_dir_all(&selected.stage)?;
    fs::create_dir(&payload)?;
    let mut files = Vec::new();
    let mut copied_sources = Vec::new();
    for (source, path, size, modified, permissions) in inventory {
        let destination = payload.join(&path);
        fs::create_dir_all(destination.parent().expect("snapshot parent"))?;
        let mut item = copy_file(&source, &destination, deadline, None)?;
        if item.size != size || item.modified != modified || item.mode != permissions {
            return Err(CiError::Message("snapshot inventory changed".into()));
        }
        item.path = path;
        copied_sources.push(source);
        files.push(item);
    }
    for (source, item) in copied_sources.iter().zip(&files) {
        let metadata = fs::symlink_metadata(source)?;
        if metadata.modified()? != item.modified
            || mode(&metadata) != item.mode
            || content_hash(source, item.size, deadline)? != item.hash
        {
            return Err(CiError::Message(
                "snapshot source changed before closure".into(),
            ));
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let content = files
        .iter()
        .map(|item| {
            (
                item.path.display().to_string(),
                serde_json::to_string(&(item.size, &item.hash, item.mode))
                    .expect("file tuple serialization"),
            )
        })
        .collect();
    let (key, prefix) = identity(selected, content)?;
    let suffix = key.strip_prefix(&prefix).expect("snapshot key prefix");
    let key = if kind == SnapshotKind::Compiled {
        [
            prefix.as_str(),
            artifacts::checksum(selected.input.as_bytes()).as_str(),
            "-",
            suffix,
        ]
        .concat()
    } else {
        key
    };
    let index = Index {
        revision: 6,
        kind,
        compatibility: selected.compatibility.clone(),
        roots: index_roots(selected, kind),
        files,
    };
    let mut bytes = serde_json::to_vec(&index)?;
    bytes.push(b'\n');
    if bytes.len() > selected.metadata {
        return Err(CiError::Message("snapshot index exceeds bounds".into()));
    }
    fs::write(selected.stage.join("index.json"), bytes)?;
    Ok(key)
}

pub fn import(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<()> {
    let selected = selection(root, kind, purpose, shard, partition)?;
    for path in &selected.roots {
        ordinary(path)?;
    }
    let locks = source_locks(&selected, kind)?;
    if kind == SnapshotKind::Compiled {
        for path in &selected.roots {
            if !marker_root(path) && path.try_exists()? && fs::read_dir(path)?.next().is_some() {
                return Err(CiError::Message(
                    "compiled seed requires empty destination".into(),
                ));
            }
        }
    }
    // Path safety is blocking even when the optional payload is malformed.
    let index_path = selected.stage.join("index.json");
    ordinary(&index_path)?;
    if index_path.try_exists()? && fs::metadata(&index_path)?.len() <= selected.metadata as u64 {
        if let Ok(index) = artifacts::read_file(&index_path)
            .and_then(|bytes| Ok(serde_json::from_slice::<Index>(&bytes)?))
        {
            for item in &index.files {
                if let Ok(path) = destination(&selected, item, kind) {
                    ordinary(&path)?;
                }
            }
        }
    }
    let result = import_selected(&selected, kind);
    drop(locks);
    if let Err(error) = result {
        eprintln!("optional cache snapshot rejected: {error}");
        if kind == SnapshotKind::Compiled {
            cache_restore::prepare_partition(
                root,
                purpose,
                shard,
                partition,
                cache_restore::RestoreMode::Discard,
            )?;
        }
        return cleanup_selected(root, &selected);
    }
    if kind == SnapshotKind::Compiled {
        cache_restore::prepare_partition(
            root,
            purpose,
            shard,
            partition,
            cache_restore::RestoreMode::Compatible,
        )?;
    }
    cleanup_selected(root, &selected)
}

fn cleanup_stage(root: &Path, stage: &Path) -> Result<()> {
    let relative = stage
        .strip_prefix(root.canonicalize()?)
        .map_err(|_| CiError::Message("snapshot staging escaped checkout".into()))?;
    let checked = cache_restore::safe_root(root, relative)?;
    if checked.try_exists()? {
        if let Err(error) = fs::remove_dir_all(checked) {
            eprintln!("optional owned snapshot staging cleanup incomplete: {error}");
        }
    }
    Ok(())
}

fn cleanup_selected(root: &Path, selected: &Selection) -> Result<()> {
    cleanup_stage(root, &selected.stage)
}

/// Remove only the finite owned staging layout after its cache action finishes.
pub fn cleanup(
    root: &Path,
    kind: SnapshotKind,
    purpose: &str,
    shard: &str,
    partition: Option<CompiledPartition>,
) -> Result<()> {
    if kind == SnapshotKind::Compiled {
        cache_restore::partition_layout(purpose, shard, partition)?;
    }
    let stage = cache_restore::safe_root(root, &stage_relative(kind, partition)?)?;
    cleanup_stage(root, &stage)
}

fn import_selected(selected: &Selection, kind: SnapshotKind) -> Result<()> {
    ordinary(&selected.stage)?;
    for root in &selected.roots {
        ordinary(root)?;
    }
    if kind == SnapshotKind::Compiled {
        for root in &selected.roots {
            if !marker_root(root) && root.try_exists()? && fs::read_dir(root)?.next().is_some() {
                return Err(CiError::Message(
                    "compiled seed requires empty destination".into(),
                ));
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(300);
    let index_path = selected.stage.join("index.json");
    ordinary(&index_path)?;
    if fs::metadata(&index_path)?.len() > selected.metadata as u64 {
        return Err(CiError::Message("snapshot index oversized".into()));
    }
    let index: Index = serde_json::from_slice(&artifacts::read_file(&index_path)?)?;
    if index.revision != 6
        || index.kind != kind
        || index.compatibility != selected.compatibility
        || index.roots != index_roots(selected, kind)
        || index.files.is_empty()
        || index.files.len() > selected.count
    {
        return Err(CiError::Message("snapshot input/layout mismatch".into()));
    }
    let payload = selected.stage.join("payload");
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    // Validate every member and live collision before the first import mutation.
    for item in &index.files {
        let destination = destination(selected, item, kind)?;
        let name = item
            .path
            .to_str()
            .ok_or_else(|| CiError::Message("snapshot member not UTF-8".into()))?;
        if !seen.insert(name.to_lowercase()) || item.mode & !0o777 != 0 {
            return Err(CiError::Message("unsafe/duplicate snapshot member".into()));
        }
        total = total
            .checked_add(item.size)
            .ok_or_else(|| CiError::Message("snapshot size overflow".into()))?;
        if total > selected.bytes {
            return Err(CiError::Message("snapshot payload oversized".into()));
        }
        let source = payload.join(&item.path);
        ordinary(&source)?;
        if kind == SnapshotKind::RegistryIndex {
            public_index_config(&source)?;
        }
        if content_hash(&source, item.size, deadline)? != item.hash {
            return Err(CiError::Message("snapshot payload digest mismatch".into()));
        }
        ordinary(&destination)?;
        if destination.try_exists()?
            && content_hash(&destination, item.size, deadline)? != item.hash
        {
            return Err(CiError::Message(
                "snapshot conflicts with current file".into(),
            ));
        }
    }
    for item in &index.files {
        let destination = destination(selected, item, kind)?;
        if destination.try_exists()? {
            continue;
        }
        fs::create_dir_all(destination.parent().expect("snapshot destination parent"))?;
        // A failed/short copy must never become a live registry archive or
        // sparse-index file. Keep it private until all bytes are validated.
        let temporary = tempfile::NamedTempFile::new_in(
            destination.parent().expect("snapshot destination parent"),
        )?;
        let copied = copy_open_file(
            &payload.join(&item.path),
            temporary.path(),
            deadline,
            Some(item),
            temporary.reopen()?,
        )?;
        if copied.hash != item.hash || copied.size != item.size {
            return Err(CiError::Message("snapshot changed during import".into()));
        }
        temporary
            .persist_noclobber(&destination)
            .map_err(|error| CiError::Io(error.error))?;
    }
    Ok(())
}
