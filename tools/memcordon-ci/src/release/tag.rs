//! Explicit maintainer tag effects, separate from release preparation.
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

use super::{
    git::{Git, create_tag_args, push_tag_args},
    source,
};
use crate::{CiError, Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagPlan {
    pub format: String,
    pub revision: u32,
    pub repository: String,
    pub version: Version,
    pub commit: String,
    pub observed_ref: Option<String>,
    pub local_tag_object: Option<String>,
    pub local_checks: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TagEffect {
    Created,
    AlreadyPresent,
    Pushed,
    Matching,
    Absent,
    Conflicting,
    Unknown,
}

impl TagPlan {
    pub fn validate(&self) -> Result<()> {
        if self.format != "memcordon.tag-plan"
            || self.revision != 1
            || self.observed_ref.is_some() != self.local_tag_object.is_some()
        {
            return Err(CiError::Message("unsupported/inconsistent tag plan".into()));
        }
        source::validate_repository(&self.repository)?;
        source::version(&self.version.to_string())?;
        source::validate_oid(&self.commit)?;
        if let Some(object) = &self.local_tag_object {
            source::validate_oid(object)?;
        }
        if self.observed_ref.as_deref().is_some_and(|reference| {
            reference.strip_prefix("refs/tags/") != Some(self.version.to_string().as_str())
        }) {
            return Err(CiError::Message("tag-plan ref/version differs".into()));
        }
        Ok(())
    }
}

pub fn prepare(root: &Path, repository: &str, text: &str, record: &Path) -> Result<()> {
    let version = source::version(text)?;
    source::validate_repository(repository)?;
    let git = Git::new(root)?;
    git.require_clean()?;
    source::public_order(&source::metadata(root)?, &version)?;
    let commit = git.text(["rev-parse", "--verify", "HEAD"])?;
    source::validate_oid(&commit)?;
    if git
        .tags()?
        .iter()
        .any(|(reference, _)| reference.strip_prefix("refs/tags/") == Some(text))
    {
        return Err(CiError::Message(
            "version tag already exists; use explicit inspection instead".into(),
        ));
    }
    source::write_json(
        record,
        &TagPlan {
            format: "memcordon.tag-plan".into(),
            revision: 1,
            repository: repository.into(),
            version,
            commit,
            observed_ref: None,
            local_tag_object: None,
            local_checks: vec![
                "not-run; tag workflow must execute the selected source checks".into(),
            ],
        },
    )
}

pub fn create(root: &Path, record: &Path) -> Result<TagEffect> {
    let mut plan: TagPlan = source::read_json(record)?;
    plan.validate()?;
    let git = Git::new(root)?;
    let version = plan.version.to_string();
    if git.text([
        "rev-parse",
        "--verify",
        "--end-of-options",
        plan.commit.as_str(),
    ])? != plan.commit
    {
        return Err(CiError::Message(
            "recorded commit is not a full canonical object ID".into(),
        ));
    }
    if git.text(["cat-file", "-t", plan.commit.as_str()])? != "commit" {
        return Err(CiError::Message("recorded object is not a commit".into()));
    }
    if let Some((reference, object)) = git
        .tags()?
        .into_iter()
        .find(|(reference, _)| reference.strip_prefix("refs/tags/") == Some(version.as_str()))
    {
        if plan.observed_ref.as_ref() == Some(&reference)
            && plan.local_tag_object.as_ref() == Some(&object)
            && git.tag(&reference)?.commit == plan.commit
        {
            return Ok(TagEffect::AlreadyPresent);
        }
        return Err(CiError::Message(
            "preexisting local tag differs from recorded object".into(),
        ));
    }
    if plan.observed_ref.is_some() {
        return Err(CiError::Message("recorded local tag was removed".into()));
    }
    git.text(create_tag_args(&version, &plan.commit))?;
    let (reference, _) = git
        .tags()?
        .into_iter()
        .find(|(reference, _)| reference.strip_prefix("refs/tags/") == Some(version.as_str()))
        .ok_or_else(|| CiError::Message("created tag absent on readback".into()))?;
    let tag = git.tag(&reference)?;
    if tag.commit != plan.commit {
        return Err(CiError::Message("created tag selects wrong commit".into()));
    }
    plan.observed_ref = Some(tag.full_ref);
    plan.local_tag_object = Some(tag.object);
    source::write_json(record, &plan)?;
    Ok(TagEffect::Created)
}

fn checked_origin(git: &Git, repository: &str) -> Result<()> {
    let config = git.text(["config", "--local", "--list", "--null"])?;
    let mut urls = Vec::new();
    for entry in config.split('\0').filter(|entry| !entry.is_empty()) {
        let (key, value) = entry
            .split_once('\n')
            .ok_or_else(|| CiError::Message("invalid local Git configuration".into()))?;
        let key = key.to_ascii_lowercase();
        if key.starts_with("url.")
            || key.starts_with("http.")
            || key == "remote.origin.pushurl"
            || key == "remote.origin.push"
            || key == "remote.origin.mirror"
            || key == "push.followtags"
            || key == "push.recursesubmodules"
            || key.starts_with("include")
        {
            return Err(CiError::Message(
                "unsupported URL rewrite/mirror/extra-push Git configuration".into(),
            ));
        }
        if key == "remote.origin.url" {
            urls.push(value);
        }
    }
    if urls.len() != 1 {
        return Err(CiError::Message(
            "origin must have exactly one HTTPS URL".into(),
        ));
    }
    let url =
        url::Url::parse(urls[0]).map_err(|_| CiError::Message("origin URL is invalid".into()))?;
    let path = url
        .path()
        .strip_prefix('/')
        .unwrap_or(url.path())
        .strip_suffix(".git")
        .unwrap_or_else(|| url.path().strip_prefix('/').unwrap_or(url.path()));
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || path != repository
    {
        return Err(CiError::Message(
            "origin differs from recorded HTTPS GitHub destination".into(),
        ));
    }
    Ok(())
}

fn authenticated(command: &mut std::process::Command) -> Result<()> {
    use base64::Engine;
    let token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .map_err(|_| CiError::Message("tag transport requires a standard GitHub token".into()))?;
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(CiError::Message("invalid GitHub credential".into()));
    }
    let authorization =
        base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
    command
        .env("GIT_CONFIG_COUNT", "8")
        .env("GIT_CONFIG_KEY_7", "http.extraHeader")
        .env(
            "GIT_CONFIG_VALUE_7",
            format!("Authorization: Basic {authorization}"),
        );
    Ok(())
}

fn remote_state(git: &Git, plan: &TagPlan) -> Result<TagEffect> {
    let expected = plan
        .observed_ref
        .as_deref()
        .ok_or_else(|| CiError::Message("tag has not been created/recorded".into()))?;
    let mut command = git.command(["ls-remote", "--refs", "--tags", "origin", expected]);
    authenticated(&mut command)?;
    let output = match memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(120),
        1024 * 1024,
    ) {
        Ok(output) => output,
        Err(_) => return Ok(TagEffect::Unknown),
    };
    if !output.status.success() {
        return Ok(TagEffect::Unknown);
    }
    let output = std::str::from_utf8(&output.stdout)
        .map_err(|_| CiError::Message("invalid remote ref data".into()))?;
    let mut matches = Vec::new();
    for line in output.lines() {
        let (object, reference) = line
            .split_once('\t')
            .ok_or_else(|| CiError::Message("invalid remote ref row".into()))?;
        source::validate_oid(object)?;
        if reference == expected {
            matches.push(object);
        }
    }
    match matches.as_slice() {
        [] => Ok(TagEffect::Absent),
        [object] if plan.local_tag_object.as_deref() == Some(*object) => Ok(TagEffect::Matching),
        [_] => Ok(TagEffect::Conflicting),
        _ => Ok(TagEffect::Unknown),
    }
}

pub fn inspect(root: &Path, record: &Path) -> Result<TagEffect> {
    let plan: TagPlan = source::read_json(record)?;
    plan.validate()?;
    let git = Git::new(root)?;
    checked_origin(&git, &plan.repository)?;
    remote_state(&git, &plan)
}

pub fn push(root: &Path, record: &Path) -> Result<TagEffect> {
    let plan: TagPlan = source::read_json(record)?;
    plan.validate()?;
    let git = Git::new(root)?;
    checked_origin(&git, &plan.repository)?;
    let reference = plan
        .observed_ref
        .as_deref()
        .ok_or_else(|| CiError::Message("tag has not been created/recorded".into()))?;
    let tag = git.tag(reference)?;
    if tag.commit != plan.commit || Some(&tag.object) != plan.local_tag_object.as_ref() {
        return Err(CiError::Message("local tag changed".into()));
    }
    // The helper publishes only the tag. Source publication remains a separate
    // maintainer operation and must already be observable at this destination.
    let token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .map_err(|_| CiError::Message("tag transport requires a standard GitHub token".into()))?;
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(CiError::Message("invalid GitHub credential".into()));
    }
    let response =
        super::http::ReadBudget::new(std::time::Instant::now() + Duration::from_secs(120)).read(
            &super::http::HttpsTransport,
            &super::http::github_url(&plan.repository, &["commits", &plan.commit])?,
            &[
                ("Authorization".into(), format!("Bearer {token}")),
                ("User-Agent".into(), "memcordon-ci".into()),
            ],
            1024 * 1024,
        )?;
    if response.status != 200
        || super::http::json(&response)?
            .get("sha")
            .and_then(serde_json::Value::as_str)
            != Some(plan.commit.as_str())
    {
        return Err(CiError::Message("recorded source commit is not available in the intended remote; publish source separately".into()));
    }
    match remote_state(&git, &plan)? {
        TagEffect::Matching => return Ok(TagEffect::Matching),
        TagEffect::Absent => {}
        other => return Ok(other),
    }
    let mut command = git.command(push_tag_args(&plan.version.to_string()));
    authenticated(&mut command)?;
    // A lost reply is reconciled; never blindly repeat the mutation.
    let wrote = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(120),
        1024 * 1024,
    );
    let state = remote_state(&git, &plan)?;
    if wrote.is_ok_and(|output| output.status.success()) && state == TagEffect::Matching {
        Ok(TagEffect::Pushed)
    } else {
        Ok(state)
    }
}
