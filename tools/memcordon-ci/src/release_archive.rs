use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

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

fn failure(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
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
