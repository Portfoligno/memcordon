//! Bounded, family-specific cache input projections. Diagnostics never enter keys.
use crate::{
    CiError, Result,
    release::{artifacts, git::Git},
};
use serde::Serialize;
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, Serialize)]
pub struct KeyInputs {
    pub family: String,
    pub layout_revision: u32,
    pub compatibility: BTreeMap<String, String>,
    pub content: BTreeMap<String, String>,
}

pub fn keys(input: &KeyInputs) -> Result<(String, String)> {
    if !matches!(
        input.family.as_str(),
        "downloads" | "index" | "workspace" | "consumer" | "tool" | "tool-build"
    ) {
        return Err(CiError::Message("unknown cache family".into()));
    }
    let compatibility =
        serde_json::to_vec(&(&input.family, input.layout_revision, &input.compatibility))?;
    let content = serde_json::to_vec(&input.content)?;
    if compatibility.len() > 1024 * 1024 || content.len() > 32 * 1024 * 1024 {
        return Err(CiError::Message(
            "cache key projection exceeds bounds".into(),
        ));
    }
    let compatibility = artifacts::checksum(&compatibility);
    let content = artifacts::checksum(&content);
    let prefix = format!("mc-cache-v4-{}-{compatibility}-", input.family);
    Ok((format!("{prefix}{content}"), prefix))
}

/// Package-subtree supersets deliberately include test fixtures and build scripts.
/// Workspace tests additionally embed CI configuration and workflow text.
pub fn local_files(root: &Path, purpose: &str) -> Result<BTreeMap<String, String>> {
    let tracked = Git::new(root)?.text(["ls-files", "--stage", "-z"])?;
    let mut inputs = BTreeMap::new();
    let mut total = 0_u64;
    for record in tracked.split('\0').filter(|record| !record.is_empty()) {
        let (metadata, name) = record
            .split_once('\t')
            .ok_or_else(|| CiError::Message("invalid tracked cache input".into()))?;
        let selected = name == "Cargo.toml"
            || name == "Cargo.lock"
            || name == ".gitattributes"
            || name.starts_with(".cargo/")
            || if purpose.starts_with("fuzz") {
                name.starts_with("fuzz/")
                    || name.starts_with("crates/")
                    || name.starts_with("tools/memcordon-ci/")
                    || name.starts_with("ci/")
            } else if purpose.starts_with("miri") {
                name.starts_with("crates/memcordon-core/")
                    || name.starts_with("crates/memcordon-testkit/")
                    || name.starts_with("crates/memcordon-platform/")
                    || name.starts_with("fuzz/corpus/")
                    || name.starts_with("ci/")
            } else {
                name.starts_with("crates/")
                    || name.starts_with("tools/")
                    || name.starts_with("ci/")
                    || name.starts_with(".github/")
                    || name.starts_with("tests/")
                    || name.starts_with("fuzz/")
                    || name.starts_with("packaging/")
                    || matches!(
                        name,
                        "docs/reference.md" | "docs/spec-workload-contract-v1.md"
                    )
            };
        if !selected {
            continue;
        }
        let mut fields = metadata.split_whitespace();
        let mode = fields
            .next()
            .ok_or_else(|| CiError::Message("cache input mode absent".into()))?;
        let stage = fields.nth(1);
        if !matches!(mode, "100644" | "100755") || stage != Some("0") {
            return Err(CiError::Message(
                "unsupported cache input kind/stage".into(),
            ));
        }
        let path = root.join(name);
        if !path.canonicalize()?.starts_with(root.canonicalize()?) {
            return Err(CiError::Message("cache input escapes repository".into()));
        }
        for parent in path.ancestors().take_while(|path| *path != root) {
            let metadata = std::fs::symlink_metadata(parent)?;
            if metadata.file_type().is_symlink() {
                return Err(CiError::Message("cache input traverses symlink".into()));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(CiError::Message(
                        "cache input traverses reparse point".into(),
                    ));
                }
            }
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(CiError::Message(
                "cache input is not an ordinary file".into(),
            ));
        }
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| CiError::Message("cache inputs overflow".into()))?;
        if inputs.len() >= 100_000 || total > 256 * 1024 * 1024 {
            return Err(CiError::Message(
                "cache input projection exceeds bounds".into(),
            ));
        }
        let bytes = artifacts::read_file(&path)?;
        if path.file_name().is_some_and(|name| name == "Cargo.toml") {
            validate_manifest_paths(root, &path, &bytes, &tracked, purpose)?;
        }
        inputs.insert(
            name.into(),
            serde_json::to_string(&(mode, bytes.len(), artifacts::checksum(&bytes)))?,
        );
    }
    Ok(inputs)
}

/// Explicit Cargo paths are classified before enabling a workspace seed. This
/// is a bounded manifest check, not a second resolver or build-script evaluator.
fn validate_manifest_paths(
    root: &Path,
    manifest: &Path,
    bytes: &[u8],
    tracked: &str,
    purpose: &str,
) -> Result<()> {
    fn paths(value: &toml::Value, output: &mut Vec<String>, depth: usize) -> Result<()> {
        if depth > 32 || output.len() > 4096 {
            return Err(CiError::Message(
                "Cargo path projection exceeds bounds".into(),
            ));
        }
        match value {
            toml::Value::Table(table) => {
                for (key, value) in table {
                    if (key == "path" || key == "build")
                        && let Some(path) = value.as_str()
                    {
                        output.push(path.into());
                    }
                    paths(value, output, depth + 1)?;
                }
            }
            toml::Value::Array(array) => {
                for value in array {
                    paths(value, output, depth + 1)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    let value: toml::Value = toml::from_str(
        std::str::from_utf8(bytes)
            .map_err(|_| CiError::Message("Cargo manifest is not UTF-8".into()))?,
    )?;
    let mut declared = Vec::new();
    paths(&value, &mut declared, 0)?;
    let checkout = root.canonicalize()?;
    for declared in declared {
        let path = manifest
            .parent()
            .expect("Cargo manifest parent")
            .join(declared)
            .canonicalize()?;
        let path = if path.is_dir() {
            path.join("Cargo.toml")
        } else {
            path
        };
        let relative = path
            .strip_prefix(&checkout)
            .map_err(|_| CiError::Message("unmodeled Cargo path outside checkout".into()))?;
        let name = relative
            .to_str()
            .ok_or_else(|| CiError::Message("Cargo path is not UTF-8".into()))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let modeled = name == "Cargo.toml"
            || if purpose.starts_with("miri") {
                name.starts_with("crates/memcordon-core/")
                    || name.starts_with("crates/memcordon-testkit/")
                    || name.starts_with("crates/memcordon-platform/")
            } else if purpose.starts_with("fuzz") {
                name.starts_with("fuzz/")
                    || name.starts_with("crates/")
                    || name.starts_with("tools/memcordon-ci/")
            } else {
                name.starts_with("crates/")
                    || name.starts_with("tools/")
                    || name.starts_with("fuzz/")
                    || name.starts_with("tests/")
            };
        if !modeled
            || !tracked.split('\0').any(|record| {
                record
                    .split_once('\t')
                    .is_some_and(|(_, tracked)| tracked == name)
            })
        {
            return Err(CiError::Message("unmodeled Cargo local/path input".into()));
        }
    }
    Ok(())
}

/// Cargo prefers the extensionless config if both forms exist.
pub fn cargo_configs(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut locations = Vec::new();
    for (index, ancestor) in root.ancestors().enumerate() {
        locations.push((format!("ancestor-config-{index}"), ancestor.join(".cargo")));
    }
    let home = crate::download_cache::cargo_home(root)?;
    if !locations.iter().any(|(_, path)| path == &home) {
        locations.push(("cargo-home-config".into(), home));
    }
    cargo_config_locations(locations, false)
}

pub fn download_configs(root: &Path, install: bool) -> Result<BTreeMap<String, String>> {
    let home = crate::download_cache::cargo_home(root)?;
    let mut locations = Vec::new();
    if !install {
        for (index, ancestor) in root.ancestors().enumerate() {
            locations.push((format!("ancestor-config-{index}"), ancestor.join(".cargo")));
        }
    }
    if !locations.iter().any(|(_, path)| path == &home) {
        locations.push(("cargo-home-config".into(), home));
    }
    cargo_config_locations(locations, true)
}

fn cargo_config_locations(
    locations: Vec<(String, std::path::PathBuf)>,
    downloads: bool,
) -> Result<BTreeMap<String, String>> {
    let mut inputs = BTreeMap::new();
    for (role, directory) in locations {
        let legacy = directory.join("config");
        let path = if legacy.try_exists()? {
            legacy
        } else {
            directory.join("config.toml")
        };
        if !path.try_exists()? {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(CiError::Message("unsafe Cargo configuration".into()));
        }
        let bytes = artifacts::read_file(&path)?;
        // Never retain configuration bytes or credential-bearing values in diagnostics.
        let text = String::from_utf8_lossy(&bytes);
        if downloads {
            let config: toml::Value = toml::from_str(&text).map_err(|_| {
                CiError::Message("download Cargo configuration is malformed".into())
            })?;
            if config.get("source").is_some()
                || config.get("registries").is_some()
                || config.get("registry").is_some()
            {
                return Err(CiError::Message(
                    "custom download registry/source unmodeled".into(),
                ));
            }
            if config
                .get("build")
                .and_then(|build| build.get("target"))
                .is_some()
            {
                return Err(CiError::Message("download target policy unmodeled".into()));
            }
        }
        if [
            "token",
            "credential",
            "include",
            "wrapper",
            "rustc",
            "linker",
            "sysroot",
            "rustflags",
            "rustdocflags",
            "target-dir",
        ]
        .iter()
        .any(|field| text.contains(field))
            || text.contains('@')
        {
            return Err(CiError::Message("unprojected Cargo configuration".into()));
        }
        inputs.insert(role, artifacts::checksum(&bytes));
    }
    Ok(inputs)
}

/// Seed only immutable registry downloads into an already owned fresh Cargo
/// home. Git databases are omitted: their hooks, alternates and remote config
/// cannot be safely classified by this bounded archive copier.
pub fn seed_isolated_downloads(
    shared_home: &Path,
    fresh_home: &Path,
    public_acquisition: bool,
) -> Result<()> {
    fn ordinary_ancestors(path: &Path) -> Result<()> {
        for ancestor in path.ancestors() {
            let metadata = match std::fs::symlink_metadata(ancestor) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() {
                return Err(CiError::Message("download seed traverses symlink".into()));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(CiError::Message(
                        "download seed traverses reparse point".into(),
                    ));
                }
            }
        }
        Ok(())
    }
    if !shared_home.try_exists()? {
        return Ok(());
    }
    if std::fs::symlink_metadata(shared_home)?
        .file_type()
        .is_symlink()
        || std::fs::symlink_metadata(fresh_home)?
            .file_type()
            .is_symlink()
    {
        return Err(CiError::Message("download home is a symlink".into()));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if std::fs::symlink_metadata(shared_home)?.file_attributes() & 0x400 != 0
            || std::fs::symlink_metadata(fresh_home)?.file_attributes() & 0x400 != 0
        {
            return Err(CiError::Message("download home is a reparse point".into()));
        }
    }
    let shared_home = shared_home.canonicalize()?;
    let fresh_home = fresh_home.canonicalize()?;
    ordinary_ancestors(&shared_home)?;
    ordinary_ancestors(&fresh_home)?;
    let source = shared_home.join("registry/cache");
    if !source.try_exists()? {
        return Ok(());
    }
    let destination = fresh_home.join("registry/cache");
    if destination.try_exists()? {
        return Err(CiError::Message(
            "download seed destination already populated".into(),
        ));
    }
    let mut files = Vec::new();
    let mut total = 0_u64;
    ordinary_ancestors(&source)?;
    let mut walk = walkdir::WalkDir::new(&source)
        .follow_links(false)
        .follow_root_links(false)
        .max_depth(2)
        .into_iter();
    while let Some(entry) = walk.next() {
        let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
            walk.skip_current_dir();
            continue;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                walk.skip_current_dir();
                continue;
            }
        }
        if !metadata.is_file() || entry.depth() != 2 {
            continue;
        }
        let filename = entry.file_name().to_string_lossy();
        if !filename.ends_with(".crate")
            || (public_acquisition && filename.starts_with("memcordon"))
        {
            continue;
        }
        if metadata.len() > 64 * 1024 * 1024 {
            continue;
        }
        total = total
            .checked_add(metadata.len())
            .ok_or_else(|| CiError::Message("download seed size overflow".into()))?;
        if files.len() >= 100_000 || total > 2 * 1024 * 1024 * 1024 {
            break;
        }
        let relative = entry
            .path()
            .strip_prefix(&source)
            .map_err(|error| CiError::Message(error.to_string()))?;
        files.push((entry.path().to_path_buf(), destination.join(relative)));
    }
    let mut copied = 0_u64;
    for (source, destination) in files {
        ordinary_ancestors(destination.parent().expect("registry namespace"))?;
        std::fs::create_dir_all(destination.parent().expect("registry namespace"))?;
        ordinary_ancestors(destination.parent().expect("registry namespace"))?;
        let bytes = artifacts::read_file(&source)?;
        if bytes.len() > 64 * 1024 * 1024 {
            continue;
        }
        copied += bytes.len() as u64;
        if copied > 2 * 1024 * 1024 * 1024 {
            break;
        }
        use std::io::Write;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        output.write_all(&bytes)?;
    }
    Ok(())
}

pub fn seed_current_downloads(fresh_home: &Path, public_acquisition: bool) -> Result<()> {
    let shared = std::env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo"))
        });
    if let Some(shared) = shared {
        seed_isolated_downloads(&shared, fresh_home, public_acquisition)?;
    }
    Ok(())
}

/// Called only after the isolated Cargo owner has synchronously settled. Cache
/// transfer errors remain optional and never alter its actual test verdict.
pub fn export_current_downloads(isolated_home: &Path) {
    fn export(isolated_home: &Path) -> Result<()> {
        let shared = std::env::var_os("CARGO_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo"))
            });
        let Some(shared) = shared else {
            return Ok(());
        };
        if !shared.try_exists()? {
            return Ok(());
        }
        if std::fs::symlink_metadata(&shared)?.file_type().is_symlink() {
            return Err(CiError::Message("shared Cargo home is a link".into()));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if std::fs::symlink_metadata(&shared)?.file_attributes() & 0x400 != 0 {
                return Err(CiError::Message(
                    "shared Cargo home is a reparse point".into(),
                ));
            }
        }
        let shared = shared.canonicalize()?;
        let snapshot = tempfile::tempdir()?;
        seed_isolated_downloads(isolated_home, snapshot.path(), true)?;
        let source = snapshot.path().join("registry/cache");
        if !source.try_exists()? {
            return Ok(());
        }
        for entry in walkdir::WalkDir::new(&source)
            .follow_links(false)
            .max_depth(2)
        {
            let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
            if !entry.file_type().is_file() || entry.depth() != 2 {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(snapshot.path())
                .map_err(|error| CiError::Message(error.to_string()))?;
            let destination = shared.join(relative);
            let parent = destination.parent().expect("archive parent");
            let mut checked = shared.clone();
            for component in parent
                .strip_prefix(&shared)
                .expect("shared archive parent")
                .components()
            {
                let std::path::Component::Normal(component) = component else {
                    return Err(CiError::Message("unsafe archive export path".into()));
                };
                checked.push(component);
                match std::fs::symlink_metadata(&checked) {
                    Ok(metadata) => {
                        if !metadata.is_dir() || metadata.file_type().is_symlink() {
                            return Err(CiError::Message("unsafe archive export directory".into()));
                        }
                        #[cfg(windows)]
                        {
                            use std::os::windows::fs::MetadataExt;
                            if metadata.file_attributes() & 0x400 != 0 {
                                return Err(CiError::Message(
                                    "archive export reparse point".into(),
                                ));
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        std::fs::create_dir(&checked)?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let bytes = artifacts::read_file(entry.path())?;
            use std::io::Write;
            let mut output = tempfile::NamedTempFile::new_in(parent)?;
            output.write_all(&bytes)?;
            match output.persist_noclobber(&destination) {
                Ok(_) => (),
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(error.error.into()),
            }
        }
        Ok(())
    }
    if let Err(error) = export(isolated_home) {
        eprintln!("optional isolated download export unavailable: {error}");
    }
}
