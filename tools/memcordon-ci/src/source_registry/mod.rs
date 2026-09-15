//! Owner: source governance. Inputs are Git inventory, strict declarations and Rust syntax.
//! Output is source accountability, never a claim that declared tests executed.

pub mod coverage;
mod history;
pub mod hosted;
pub mod hosted_client;
mod inventory;
pub mod native_runner;
pub mod observation;
mod policy;
mod report;
mod routing;
mod schema;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::{CiError, Result};
pub use schema::{Domain, Source};

pub fn read(root: &Path) -> Result<Vec<Source>> {
    let directory = root.join("ci/source-presence");
    let mut records = Vec::new();
    let mut files = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    files.sort_by_key(|entry| entry.path());
    for entry in files {
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            let domain: Domain = toml::from_str(&fs::read_to_string(entry.path())?)?;
            if domain.schema != 1 || domain.source.is_empty() {
                return Err(CiError::Message(format!(
                    "unsupported or empty source domain: {:?}",
                    entry.path()
                )));
            }
            records.extend(domain.source);
        }
    }
    records.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(records)
}

/// Validate strict declarations against a supplied inventory (also used by mutation tests).
pub fn validate_records(records: &[Source], inventory: &BTreeSet<String>) -> Result<()> {
    policy::validate(records, inventory)
}

pub fn validate(root: &Path) -> Result<Vec<Source>> {
    let records = read(root)?;
    policy::validate(&records, &inventory::sources(root)?)?;
    history::validate(root, &records)?;
    routing::validate(root, &records)?;
    Ok(records)
}

pub fn validate_history(bytes: &str, records: &[Source]) -> Result<()> {
    history::validate_bytes(bytes, records)
}

pub fn rust_surface(bytes: &str) -> Result<(Vec<String>, Vec<String>)> {
    routing::surface(bytes)
}

pub fn run(root: &Path) -> Result<()> {
    let records = validate(root)?;
    report::write(root, &records)?;
    println!("source presence: {} declarations validated", records.len());
    Ok(())
}

/// Emit observed syntax routes for review; this does not create justifications.
pub fn routes(root: &Path, output: &Path) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(&routing::discover(root)?)?;
    bytes.push(b'\n');
    fs::write(output, bytes)?;
    Ok(())
}
