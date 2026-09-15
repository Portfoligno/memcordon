//! Declared behavioral routes and strict native libtest inventory parsing.
//! Listing proves availability only; execution evidence is collected separately.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{CiError, Result};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub suite: String,
    pub cargo_package: String,
    pub cargo_target: String,
    pub test_binary: String,
    pub tests: Vec<String>,
    pub runner: Vec<String>,
    pub skip_policy: SkipPolicy,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SkipPolicy {
    Forbidden,
    ExplicitlyIgnored,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Evidence {
    Behavior,
    Compile,
    Fuzz,
}

impl Coverage {
    pub fn validate(&self) -> Result<()> {
        if [
            &self.suite,
            &self.cargo_package,
            &self.cargo_target,
            &self.test_binary,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
            || self.tests.is_empty()
            || self.runner.is_empty()
        {
            return Err(CiError::Message(
                "coverage route requires suite, package, target, binary, tests and runners".into(),
            ));
        }
        for values in [&self.tests, &self.runner] {
            if values.iter().any(|value| value.trim().is_empty())
                || values.iter().collect::<BTreeSet<_>>().len() != values.len()
            {
                return Err(CiError::Message(
                    "coverage route contains blank or duplicate values".into(),
                ));
            }
        }
        for selector in &self.tests {
            let literal = selector.strip_suffix("::*").unwrap_or(selector);
            if literal.is_empty() || literal.contains('*') {
                return Err(CiError::Message(
                    "coverage selectors allow only exact names or a module ::* suffix".into(),
                ));
            }
        }
        Ok(())
    }

    /// Expand declared module selectors against an observed native binary list.
    /// Every declaration must resolve; an empty match is never coverage.
    pub fn resolve(&self, available: &BTreeSet<String>) -> Result<BTreeSet<String>> {
        self.validate()?;
        let mut resolved = BTreeSet::new();
        for selector in &self.tests {
            let matches: Vec<_> = available
                .iter()
                .filter(|name| {
                    selector
                        .strip_suffix('*')
                        .map_or(*name == selector, |prefix| name.starts_with(prefix))
                })
                .cloned()
                .collect();
            if matches.is_empty() {
                return Err(CiError::Message(format!(
                    "coverage selector has no listed test: {selector}"
                )));
            }
            resolved.extend(matches);
        }
        Ok(resolved)
    }
}

/// Parse `--list --format terse` without accepting arbitrary program output.
pub fn parse_test_list(stdout: &str) -> Result<BTreeSet<String>> {
    let mut tests = BTreeSet::new();
    for line in stdout.lines() {
        let name = line
            .strip_suffix(": test")
            .ok_or_else(|| CiError::Message(format!("unexpected native test-list line: {line}")))?;
        if name.is_empty() || !tests.insert(name.to_owned()) {
            return Err(CiError::Message(
                "empty or duplicate native test name".into(),
            ));
        }
    }
    Ok(tests)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedSource {
    pub source_id: String,
    pub route: Coverage,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub commit: String,
    pub suite: String,
    pub sources: Vec<PlannedSource>,
}

impl Plan {
    pub fn from_sources(commit: String, suite: String, sources: &[super::Source]) -> Result<Self> {
        let sources: Vec<_> = sources
            .iter()
            .flat_map(|source| {
                source
                    .coverage
                    .iter()
                    .filter(|route| route.suite == suite)
                    .map(|route| PlannedSource {
                        source_id: source.id.clone(),
                        route: route.clone(),
                    })
            })
            .collect();
        if sources.is_empty() {
            return Err(CiError::Message(format!(
                "suite has no declared source coverage: {suite}"
            )));
        }
        for source in &sources {
            source.route.validate()?;
        }
        if commit.is_empty() || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CiError::Message(
                "source coverage requires a Git commit identity".into(),
            ));
        }
        Ok(Self {
            schema: 1,
            commit,
            suite,
            sources,
        })
    }
}

pub fn write_plan(root: &std::path::Path, suite: &str, output: &std::path::Path) -> Result<()> {
    let commit = crate::command::git(root, ["rev-parse", "HEAD"])?;
    let commit = String::from_utf8(commit)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
    let plan = Plan::from_sources(commit, suite.to_owned(), &super::read(root)?)?;
    let mut bytes = serde_json::to_vec_pretty(&plan)?;
    bytes.push(b'\n');
    std::fs::write(output, bytes)?;
    Ok(())
}

/// Review aid for module-local libtest declarations; ignored fixture entrypoints
/// require a separate explicit execution route and are not silently promoted.
pub fn declared_test_names(source: &str, ignored: bool) -> Result<Vec<String>> {
    let syntax = syn::parse_file(source).map_err(|error| CiError::Message(error.to_string()))?;
    Ok(syntax
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Fn(function) = item else {
                return None;
            };
            (function
                .attrs
                .iter()
                .any(|attribute| attribute.path().is_ident("test"))
                && function
                    .attrs
                    .iter()
                    .any(|attribute| attribute.path().is_ident("ignore"))
                    == ignored)
                .then(|| function.sig.ident.to_string())
        })
        .collect())
}
