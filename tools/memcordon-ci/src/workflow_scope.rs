//! Event scheduling for common work owned by shared Release preparation.
//! This decision says nothing about completion or publication permission.
use std::path::Path;

use crate::{CiError, Result};

pub const RELEASE_TAG_FILTER: &str = "[0-9]+.[0-9]+.[0-9]+*";
const MAXIMUM_CONTEXT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    SharedPreparationPush,
    Standalone,
    DeletedRef,
}

impl Scope {
    pub const fn standalone_common(self) -> bool {
        matches!(self, Self::Standalone)
    }
}

fn decimal_component(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Matches the repository's literal GitHub trigger, not semantic versions.
pub fn matches_release_tag_filter(tag: &str) -> bool {
    if tag.contains('/') {
        return false;
    }
    let Some((major, rest)) = tag.split_once('.') else {
        return false;
    };
    let Some((minor, patch_and_suffix)) = rest.split_once('.') else {
        return false;
    };
    decimal_component(major)
        && decimal_component(minor)
        && patch_and_suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_digit)
}

pub fn classify(event_name: &str, full_ref: &str, deleted: bool) -> Scope {
    if event_name != "push" {
        return Scope::Standalone;
    }
    if deleted {
        return Scope::DeletedRef;
    }
    let branch = full_ref
        .strip_prefix("refs/heads/")
        .is_some_and(|name| !name.is_empty());
    let selected_tag = full_ref
        .strip_prefix("refs/tags/")
        .is_some_and(matches_release_tag_filter);
    if branch || selected_tag {
        Scope::SharedPreparationPush
    } else {
        Scope::Standalone
    }
}

fn validate_context(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAXIMUM_CONTEXT_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(CiError::Message(
            "workflow scope context is malformed".into(),
        ));
    }
    Ok(())
}

/// Reads bounded provider JSON without treating unrelated fields as our schema.
pub fn from_event_file(event_name: &str, full_ref: &str, path: &Path) -> Result<Scope> {
    validate_context(event_name)?;
    validate_context(full_ref)?;
    let event: serde_json::Value = crate::release::source::read_json(path)?;
    let object = event
        .as_object()
        .ok_or_else(|| CiError::Message("workflow event must be an object".into()))?;
    let deleted = if event_name == "push" {
        let reference = object
            .get("ref")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CiError::Message("push event ref is absent or nonstring".into()))?;
        validate_context(reference)?;
        if reference != full_ref {
            return Err(CiError::Message(
                "push event ref differs from GITHUB_REF".into(),
            ));
        }
        object
            .get("deleted")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| CiError::Message("push event deleted is absent or nonboolean".into()))?
    } else {
        false
    };
    Ok(classify(event_name, full_ref, deleted))
}

pub fn emit_from_github() -> Result<()> {
    let required = |name: &str| {
        std::env::var(name).map_err(|_| CiError::Message(format!("workflow scope requires {name}")))
    };
    let scope = from_event_file(
        &required("GITHUB_EVENT_NAME")?,
        &required("GITHUB_REF")?,
        Path::new(&required("GITHUB_EVENT_PATH")?),
    )?;
    crate::workflow_output::write(&[(
        "standalone-common",
        if scope.standalone_common() {
            "true"
        } else {
            "false"
        }
        .to_owned(),
    )])?;
    eprintln!(
        "workflow scope: {}",
        match scope {
            Scope::SharedPreparationPush =>
                "covered push; common work assigned to Release preparation",
            Scope::Standalone => "standalone request or uncovered ref",
            Scope::DeletedRef => "deleted ref",
        }
    );
    Ok(())
}
