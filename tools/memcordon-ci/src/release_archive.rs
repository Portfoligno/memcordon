use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;

use crate::config;
use crate::{CiError, Result};

pub const RUNTIME_MANIFEST: &str = "runtime-manifest.json";

pub const NATIVE_ARCHIVE_STATIC_PATHS: &[&str] = &[
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "docs/linux-sealed-certification.md",
    "docs/reference.md",
    "docs/sealed-provider.md",
    "docs/sealed-supervision.md",
    "docs/assets/banner.png",
    "docs/assets/key-guarantees.png",
    "spec/sealed-linux-v2.md",
    "spec/sealed-provider-protocol-v2.md",
    "spec/sealed-windows-provider-v1.md",
    "spec/sealed-windows-v2.md",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewedCargoBinary {
    pub name: &'static str,
    pub path: &'static str,
    pub doc: Option<bool>,
    pub required_features: Option<&'static [&'static str]>,
}

pub const REVIEWED_CARGO_BINARIES: &[ReviewedCargoBinary] = &[
    ReviewedCargoBinary {
        name: "memcordon",
        path: "src/main.rs",
        doc: None,
        required_features: None,
    },
    ReviewedCargoBinary {
        name: "memcordon-sealed-agent",
        path: "src/bin/memcordon-sealed-agent/main.rs",
        doc: Some(false),
        required_features: None,
    },
    ReviewedCargoBinary {
        name: "memcordon-target-desktop-bootstrap",
        path: "src/bin/memcordon-target-desktop-bootstrap.rs",
        doc: Some(false),
        required_features: None,
    },
    ReviewedCargoBinary {
        name: "memcordon-session-broker",
        path: "src/bin/memcordon-session-broker.rs",
        doc: Some(false),
        required_features: None,
    },
    ReviewedCargoBinary {
        name: "memcordon-test-fixture",
        path: "src/bin/memcordon-test-fixture.rs",
        doc: None,
        required_features: Some(&["test-fixtures"]),
    },
    ReviewedCargoBinary {
        name: "memcordon-sealed-test-fixture",
        path: "src/bin/memcordon-sealed-test-fixture.rs",
        doc: None,
        required_features: Some(&["test-support"]),
    },
    ReviewedCargoBinary {
        name: "memcordon-embedding-fixture",
        path: "src/bin/memcordon-embedding-fixture.rs",
        doc: None,
        required_features: Some(&["test-fixtures"]),
    },
];

fn failure(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}

pub fn configured_default_cargo_binaries(
    release: &config::Release,
) -> Result<BTreeSet<String>> {
    let actual = release
        .assets
        .target
        .iter()
        .flat_map(|target| target.executable.iter())
        .map(|executable| executable.binary.clone())
        .collect::<BTreeSet<_>>();
    let expected = REVIEWED_CARGO_BINARIES
        .iter()
        .filter(|binary| binary.required_features.is_none())
        .map(|binary| binary.name.to_owned())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(failure(
            "release configuration contradicts the reviewed four-default Cargo binary inventory",
        ));
    }
    Ok(actual)
}

pub fn normalized_member_path(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    let package_root = components
        .next()
        .ok_or_else(|| failure("package archive contains an empty path"))?;
    if !matches!(package_root, Component::Normal(_)) {
        return Err(failure(
            "package archive root is not a normal relative path",
        ));
    }
    let mut normalized = PathBuf::new();
    for component in components {
        match component {
            Component::Normal(value) => normalized.push(value),
            _ => {
                return Err(failure(
                    "package archive contains a forbidden path component",
                ));
            }
        }
    }
    Ok(normalized)
}

pub fn validate_crate_readme(path: &Path, package: &str) -> Result<()> {
    let decoder = GzDecoder::new(File::open(path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut documents = BTreeMap::new();
    let mut readme = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let normalized = normalized_member_path(&entry.path()?)?;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        if normalized == Path::new("Cargo.toml") {
            let manifest: toml::Value = toml::from_str(
                std::str::from_utf8(&bytes)
                    .map_err(|_| failure("normalized Cargo.toml is not UTF-8"))?,
            )?;
            readme = manifest
                .get("package")
                .and_then(|value| value.get("readme"))
                .and_then(toml::Value::as_str)
                .map(PathBuf::from);
        }
        documents.insert(normalized, bytes);
    }
    let readme = readme.ok_or_else(|| failure(format!("{package} has no normalized README")))?;
    documents
        .get(&readme)
        .ok_or_else(|| failure(format!("{package} normalized README is absent")))?;
    validate_markdown_documents(&documents)
}

pub fn validate_memcordon_crate_distribution(
    path: &Path,
    configured_default_binaries: &BTreeSet<String>,
) -> Result<()> {
    let decoder = GzDecoder::new(File::open(path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut files = BTreeSet::new();
    let mut manifest = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let normalized = normalized_member_path(&entry.path()?)?;
        if normalized == Path::new("Cargo.toml") {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            manifest = Some(toml::from_str::<toml::Value>(
                std::str::from_utf8(&bytes)
                    .map_err(|_| failure("normalized memcordon Cargo.toml is not UTF-8"))?,
            )?);
        }
        files.insert(normalized);
    }
    for required in [
        "Cargo.toml",
        "Cargo.toml.orig",
        "Cargo.lock",
        "src/lib.rs",
        "src/main.rs",
        "src/bin/memcordon-sealed-agent/main.rs",
        "src/bin/memcordon-sealed-agent/package.rs",
        "src/bin/memcordon-sealed-agent/protocol.rs",
        "src/bin/memcordon-sealed-agent/linux/mod.rs",
        "src/bin/memcordon-sealed-agent/windows/mod.rs",
        "src/bin/memcordon-sealed-agent/windows/control_service.rs",
        "src/bin/memcordon-sealed-agent/windows/launcher_service.rs",
        "src/bin/memcordon-sealed-agent/windows/package.rs",
        "src/bin/memcordon-sealed-agent/windows/qualification.rs",
    ] {
        if !files.contains(Path::new(required)) {
            return Err(failure(format!(
                "memcordon crate archive omits required runtime source: {required}"
            )));
        }
    }
    let manifest = manifest.ok_or_else(|| failure("memcordon crate manifest is absent"))?;
    if manifest
        .get("package")
        .and_then(|value| value.get("autobins"))
        .and_then(toml::Value::as_bool)
        != Some(false)
    {
        return Err(failure(
            "memcordon crate does not disable automatic binaries",
        ));
    }
    let bins = manifest
        .get("bin")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| failure("memcordon crate has no explicit binary inventory"))?;
    let actual_bins = bins
        .iter()
        .map(|bin| {
            let required_features = match bin.get("required-features") {
                None => Ok(None),
                Some(value) => {
                    let features = value
                        .as_array()
                        .ok_or_else(|| failure("binary required-features must be an array"))?;
                    Some(
                        features
                            .iter()
                            .map(|feature| {
                                feature.as_str().ok_or_else(|| {
                                    failure("binary required-features must contain strings")
                                })
                            })
                            .collect::<Result<Vec<_>>>(),
                    )
                    .transpose()
                }
            }?;
            Ok((
                bin.get("name").and_then(toml::Value::as_str),
                bin.get("path").and_then(toml::Value::as_str),
                bin.get("doc").and_then(toml::Value::as_bool),
                required_features,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let expected = REVIEWED_CARGO_BINARIES
        .iter()
        .map(|binary| {
            (
                Some(binary.name),
                Some(binary.path),
                binary.doc,
                binary
                    .required_features
                    .map(|features| features.to_vec()),
            )
        })
        .collect::<Vec<_>>();
    if actual_bins != expected {
        return Err(failure(
            "memcordon crate binary inventory differs from the exact reviewed set",
        ));
    }
    let actual_default_binaries = actual_bins
        .iter()
        .filter(|(_, _, _, required_features)| required_features.is_none())
        .filter_map(|(name, _, _, _)| *name)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if actual_default_binaries != *configured_default_binaries {
        return Err(failure(
            "configured and crate default Cargo binary inventories differ",
        ));
    }
    for binary in REVIEWED_CARGO_BINARIES {
        if !files.contains(Path::new(binary.path)) {
            return Err(failure(format!(
                "memcordon crate archive omits required binary source: {}",
                binary.path
            )));
        }
    }
    for table in ["dependencies", "build-dependencies"] {
        if manifest
            .get(table)
            .and_then(toml::Value::as_table)
            .is_some_and(|dependencies| {
                dependencies.values().any(|dependency| {
                    dependency
                        .as_table()
                        .is_some_and(|specification| specification.contains_key("path"))
                })
            })
        {
            return Err(failure(format!(
                "memcordon normalized crate retains a workspace path in {table}"
            )));
        }
    }
    Ok(())
}

fn markdown_anchor(text: &str) -> String {
    let mut anchor = String::new();
    for character in text.trim().chars() {
        if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
            anchor.push(character.to_ascii_lowercase());
        } else if character.is_whitespace() {
            anchor.push('-');
        }
    }
    anchor
}

fn markdown_anchors(markdown: &str) -> BTreeSet<String> {
    markdown
        .lines()
        .filter_map(|line| {
            let heading = line.trim_start().strip_prefix('#')?;
            let heading = heading.trim_start_matches('#').trim();
            (!heading.is_empty()).then(|| markdown_anchor(heading))
        })
        .collect()
}

fn markdown_links(markdown: &str) -> Vec<&str> {
    let mut links = Vec::new();
    let mut remaining = markdown;
    while let Some(start) = remaining.find("](") {
        remaining = &remaining[start + 2..];
        let Some(end) = remaining.find(')') else {
            break;
        };
        let destination = remaining[..end]
            .split_ascii_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(['<', '>']);
        if !destination.is_empty() {
            links.push(destination);
        }
        remaining = &remaining[end + 1..];
    }
    links
}

fn resolve_document_link<'a>(
    source: &Path,
    destination: &'a str,
) -> Result<(PathBuf, Option<&'a str>)> {
    let (path, anchor) = destination
        .split_once('#')
        .map_or((destination, None), |(path, anchor)| (path, Some(anchor)));
    let mut resolved = if path.is_empty() {
        source.to_path_buf()
    } else {
        source
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf()
    };
    if !path.is_empty() {
        for component in Path::new(path).components() {
            match component {
                Component::Normal(value) => resolved.push(value),
                Component::ParentDir => {
                    if !resolved.pop() {
                        return Err(failure("Markdown link escapes its package or archive"));
                    }
                }
                Component::CurDir => {}
                _ => return Err(failure("Markdown link is not a normal relative path")),
            }
        }
    }
    Ok((resolved, anchor))
}

pub fn validate_markdown_documents(documents: &BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
    for (source, bytes) in documents {
        if source.extension() != Some(OsStr::new("md")) {
            continue;
        }
        let markdown = std::str::from_utf8(bytes)
            .map_err(|_| failure(format!("Markdown document is not UTF-8: {source:?}")))?;
        for destination in markdown_links(markdown) {
            if destination.contains("://") || destination.starts_with("mailto:") {
                continue;
            }
            let (target, anchor) = resolve_document_link(source, destination)?;
            let target_bytes = documents.get(&target).ok_or_else(|| {
                failure(format!(
                    "Markdown link target is absent from package or archive: {source:?} -> {target:?}"
                ))
            })?;
            if let Some(anchor) = anchor.filter(|anchor| !anchor.is_empty()) {
                let target_markdown = std::str::from_utf8(target_bytes).map_err(|_| {
                    failure(format!("Markdown anchor target is not UTF-8: {target:?}"))
                })?;
                if !markdown_anchors(target_markdown).contains(anchor) {
                    return Err(failure(format!(
                        "Markdown anchor is absent: {source:?} -> {target:?}#{anchor}"
                    )));
                }
            }
        }
    }
    Ok(())
}
