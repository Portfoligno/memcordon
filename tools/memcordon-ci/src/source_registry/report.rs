//! Owner: source governance. Reports are diagnostics and do not attest execution.

use std::fs;
use std::path::Path;

use super::schema::Source;
use crate::{Result, command};
use serde::Serialize;

#[derive(Serialize)]
struct Report<'a> {
    schema: u32,
    commit: String,
    execution_attested: bool,
    sources: &'a [Source],
}

pub(super) fn write(root: &Path, sources: &[Source]) -> Result<()> {
    let commit = String::from_utf8_lossy(&command::git(root, ["rev-parse", "HEAD"])?)
        .trim()
        .to_owned();
    let report = Report {
        schema: 1,
        commit,
        execution_attested: false,
        sources,
    };
    let output = root.join("target/ci/source-presence.json");
    fs::create_dir_all(output.parent().expect("report has a parent"))?;
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    fs::write(output, bytes)?;
    Ok(())
}
