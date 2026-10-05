//! Event routing for the shared, credential-free preparation graph.
use super::{
    distribution::Distribution,
    git::Git,
    source::{self, BuildSourceIdentity},
};
use crate::{CiError, Result};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationMode {
    Candidate,
    TaggedReprepare,
    TaggedPublicationOnly,
}

pub struct PreparationSelection {
    pub mode: PreparationMode,
    pub build: BuildSourceIdentity,
}

fn input<'a>(event: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    match event.get("inputs").and_then(|inputs| inputs.get(key)) {
        None => Ok(""),
        Some(serde_json::Value::String(value)) => Ok(value),
        _ => Err(CiError::Message(format!("invalid preparation input {key}"))),
    }
}

/// Concrete event fixtures use this same parser as the Actions adapter.
pub fn select_event(
    root: &Path,
    repository: &str,
    event_name: &str,
    reference: &str,
    sha: &str,
    event: &serde_json::Value,
) -> Result<PreparationSelection> {
    source::validate_repository(repository)?;
    source::validate_oid(sha)?;
    if event_name == "push"
        && (event.get("ref").and_then(serde_json::Value::as_str) != Some(reference)
            || event.get("after").and_then(serde_json::Value::as_str) != Some(sha))
    {
        return Err(CiError::Message(
            "push payload differs from standard selected context".into(),
        ));
    }
    let git = Git::new(root)?;
    let head = git.text(["rev-parse", "--verify", "HEAD"])?;
    let resolved = git.text(["rev-parse", "--verify", sha])?;
    if sha != resolved
        || head != resolved
        || event.get("deleted").and_then(serde_json::Value::as_bool) == Some(true)
    {
        return Err(CiError::Message(
            "preparation requires the exact nondeleted event commit".into(),
        ));
    }
    let mode = match event_name {
        "push" if reference.starts_with("refs/heads/") => PreparationMode::Candidate,
        "push" if reference.starts_with("refs/tags/") => PreparationMode::TaggedReprepare,
        "workflow_dispatch" => {
            let recovery = input(event, "recovery-mode")?;
            match input(event, "preparation-mode")? {
                "candidate" => {
                    if recovery != "reprepare"
                        || [
                            "tag",
                            "original-run-id",
                            "prepared-artifact-id",
                            "tool-artifact-id",
                        ]
                        .iter()
                        .any(|key| input(event, key).map_or(true, |value| !value.is_empty()))
                    {
                        return Err(CiError::Message(
                            "candidate dispatch cannot select a tag or recovery inputs".into(),
                        ));
                    }
                    PreparationMode::Candidate
                }
                "release" => {
                    let tag = reference.strip_prefix("refs/tags/").ok_or_else(|| {
                        CiError::Message("release dispatch must execute from its full tag".into())
                    })?;
                    if tag != input(event, "tag")? || tag.is_empty() {
                        return Err(CiError::Message(
                            "release dispatch tag differs from workflow source".into(),
                        ));
                    }
                    match recovery {
                        "reprepare" => {
                            if [
                                "original-run-id",
                                "prepared-artifact-id",
                                "tool-artifact-id",
                            ]
                            .iter()
                            .any(|key| input(event, key).map_or(true, |value| !value.is_empty()))
                            {
                                return Err(CiError::Message(
                                    "reprepare cannot accept recovery IDs".into(),
                                ));
                            }
                            PreparationMode::TaggedReprepare
                        }
                        "publication-only" => {
                            super::recovery::parse_event(&serde_json::to_vec(event)?)?;
                            PreparationMode::TaggedPublicationOnly
                        }
                        _ => return Err(CiError::Message("unknown recovery mode".into())),
                    }
                }
                _ => return Err(CiError::Message("unknown preparation mode".into())),
            }
        }
        _ => return Err(CiError::Message("unsupported preparation event/ref".into())),
    };
    let build = if mode == PreparationMode::Candidate {
        BuildSourceIdentity::working(root)?
    } else {
        source::select(root, repository, reference)?.into()
    };
    Ok(PreparationSelection { mode, build })
}

pub fn select_preparation(root: &Path) -> Result<PreparationSelection> {
    let required = |name| {
        std::env::var(name)
            .map_err(|_| CiError::Message(format!("missing standard GitHub context {name}")))
    };
    let event = source::read_json::<serde_json::Value>(Path::new(&required("GITHUB_EVENT_PATH")?))?;
    select_event(
        root,
        &required("GITHUB_REPOSITORY")?,
        &required("GITHUB_EVENT_NAME")?,
        &required("GITHUB_REF")?,
        &required("GITHUB_SHA")?,
        &event,
    )
}

pub fn write_preparation_files(root: &Path, selection: &PreparationSelection) -> Result<()> {
    if selection.mode == PreparationMode::Candidate && root.join(".release/source.json").exists() {
        return Err(CiError::Message(
            "candidate selection requires no stale tagged source record".into(),
        ));
    }
    source::write_json(&root.join(".release/build-source.json"), &selection.build)?;
    if let BuildSourceIdentity::Tagged { source } = &selection.build {
        source::write_json(&root.join(".release/source.json"), source)?;
    }
    crate::workflow_output::write(&[
        ("selected-commit", selection.build.commit().into()),
        (
            "preparation-kind",
            if selection.mode == PreparationMode::Candidate {
                "candidate"
            } else {
                "tagged"
            }
            .into(),
        ),
        (
            "recovery-mode",
            if selection.mode == PreparationMode::TaggedPublicationOnly {
                "publication-only"
            } else {
                "reprepare"
            }
            .into(),
        ),
        (
            "public-consumer",
            (selection.mode != PreparationMode::Candidate
                && Distribution::read(root)?.public_consumer)
                .to_string(),
        ),
    ])
}

pub fn read_build_source(
    source_path: Option<&Path>,
    build_path: Option<&Path>,
) -> Result<BuildSourceIdentity> {
    match (source_path, build_path) {
        (Some(_), Some(_)) => Err(CiError::Message(
            "--source and --build-source are mutually exclusive".into(),
        )),
        (_, Some(path)) => source::read_json(path),
        (path, None) => Ok(source::read_json::<source::SelectedSource>(
            path.unwrap_or(Path::new(".release/source.json")),
        )?
        .into()),
    }
}
