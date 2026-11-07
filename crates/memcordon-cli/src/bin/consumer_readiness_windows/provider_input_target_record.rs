//! Namespace shape after native fixture binding; no constructor grants authority.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

pub const RECORD_BYTES: usize = 16 * 1024;
const PATH_UNITS: usize = 256;
const TARGET_ERROR: &str =
    "mutation targets are not the exact private fixture and immediate .local leaves";

pub struct Context<'a> {
    pub paths: &'a [PathBuf],
    /// Production contexts use only the native VerifiedPrivateFixture path.
    pub fixture: &'a Path,
    pub output_root: &'a Path,
    pub parent: &'a Path,
    pub directory: &'a Path,
    pub peer: bool,
    pub file_layout: bool,
}

pub struct Rejection {
    pub predicate: &'static str,
    pub target_index: Option<usize>,
    pub primary: &'static str,
}

pub fn no_dot_components(path: &Path) -> bool {
    !path
        .components()
        .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
}

pub fn output_separate(context: &Context<'_>) -> bool {
    context.output_root.is_absolute()
        && !context.output_root.starts_with(context.directory)
        && !context.output_root.starts_with(context.parent)
}

/// Preserve namespace predicates and exact declared-path comparisons. The
/// actual current image is authorized by the separate native capability.
pub fn reject(context: &Context<'_>) -> Option<Rejection> {
    let reason = if context.paths.len() < if context.file_layout { 3 } else { 2 } {
        Some((
            if context.file_layout {
                "target-count-below-three"
            } else {
                "target-count-below-two"
            },
            None,
        ))
    } else if context.paths.len() > if context.file_layout { 10 } else { 9 } {
        Some((
            if context.file_layout {
                "target-count-above-ten"
            } else {
                "target-count-above-nine"
            },
            None,
        ))
    } else if !context.paths.iter().any(|path| path == context.fixture) {
        Some(("verified-fixture-not-in-declared-targets", None))
    } else if !context.output_root.is_absolute() {
        Some(("output-not-absolute", None))
    } else if context.output_root.starts_with(context.directory) {
        Some(("output-under-current-local-directory", None))
    } else if context.output_root.starts_with(context.parent) {
        Some(("output-under-current-executable-parent", None))
    } else {
        context.paths.iter().enumerate().find_map(|(index, path)| {
            if !path.is_absolute() {
                Some(("target-not-absolute", Some(index)))
            } else if !no_dot_components(path) {
                Some(("target-has-dot-component", Some(index)))
            } else if path != context.fixture && path.parent() != Some(context.directory) {
                Some(("target-not-immediate-current-local-leaf", Some(index)))
            } else {
                None
            }
        })
    };
    if let Some((predicate, target_index)) = reason {
        return Some(Rejection {
            predicate,
            target_index,
            primary: TARGET_ERROR,
        });
    }
    let mut unique = std::collections::BTreeSet::new();
    context.paths.iter().enumerate().find_map(|(index, path)| {
        (!unique.insert(path)).then_some(Rejection {
            predicate: "duplicate-target",
            target_index: Some(index),
            primary: "duplicate private mutation target",
        })
    })
}

pub fn path_record(units: impl Iterator<Item = u16>, include_units: bool) -> Value {
    let mut hasher = Sha256::new();
    let mut prefix = Vec::new();
    let mut count = 0usize;
    for unit in units {
        hasher.update(unit.to_le_bytes());
        if prefix.len() < PATH_UNITS {
            prefix.push(unit);
        }
        count = count.saturating_add(1);
    }
    let sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let extended = prefix.starts_with(&[92, 92, 63, 92]);
    let mut value = json!({"utf16_units":count,"sha256":sha256,
        "extended_length_prefix_observed":extended,
        "unc_prefix_observed":prefix.starts_with(&[92,92])&&!extended,
        "case_or_prefix_normalization_performed":false});
    if include_units {
        value["utf16_prefix"] = json!(prefix);
        value["utf16_truncated"] = json!(count > PATH_UNITS);
    }
    value
}
