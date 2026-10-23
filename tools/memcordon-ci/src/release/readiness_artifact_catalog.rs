//! Structural publication admission; filesystem custody remains the caller's proof.
use crate::{CiError, Result};
use memcordon_readiness_verifier::{
    Artifact, MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES, MAX_PRODUCER_ARTIFACTS, MAX_PRODUCER_BYTES,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Instant,
};

pub struct CanonicalCatalog {
    records: Vec<Artifact>,
}
// Same portable public-member path bound enforced by the readiness verifier.
const MAX_PATH_BYTES: usize = 4096;

fn failure(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn live(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(failure("original artifact catalog cutoff exhausted"));
    }
    Ok(())
}

fn plan(
    records: &[Artifact],
    overhead: u64,
    deadline: Instant,
    unique: bool,
) -> Result<Vec<Artifact>> {
    live(deadline)?;
    if records.len() > MAX_PRODUCER_ARTIFACTS {
        return Err(failure("artifact reference catalog exceeds bound"));
    }
    let mut selected: BTreeMap<String, Artifact> = BTreeMap::new();
    let mut directories = BTreeSet::new();
    let mut total = overhead;
    let mut directory_bytes = 0usize;
    for record in records {
        live(deadline)?;
        if record.path.len() > MAX_PATH_BYTES {
            return Err(failure("artifact public member path exceeds bound"));
        }
        let relative = super::artifacts::safe_relative(Path::new(&record.path))?;
        if relative.starts_with("producer")
            || relative.starts_with("cell.json")
            || relative.starts_with("producer-manifest.json")
        {
            return Err(failure("artifact substitutes a reserved public path"));
        }
        if record.length > MAX_ARTIFACT_BYTES
            || record.sha256.len() != 64
            || !record
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(failure("artifact length or SHA256 is outside its contract"));
        }
        if let Some(previous) = selected.get(&record.path) {
            if unique || previous.length != record.length || previous.sha256 != record.sha256 {
                return Err(failure("artifact catalog repeats or conflicts at one path"));
            }
            continue;
        }
        total = total
            .checked_add(record.length)
            .ok_or_else(|| failure("artifact byte total overflow"))?;
        for ancestor in relative
            .ancestors()
            .skip(1)
            .filter(|path| !path.as_os_str().is_empty())
        {
            if !directories.contains(ancestor) {
                directory_bytes = directory_bytes
                    .checked_add(ancestor.as_os_str().as_encoded_bytes().len())
                    .ok_or_else(|| failure("artifact parent metadata total overflow"))?;
                if directory_bytes > MAX_INDEX_BYTES
                    || selected
                        .len()
                        .checked_add(directories.len())
                        .and_then(|count| count.checked_add(4))
                        .is_none_or(|count| count > MAX_PRODUCER_ARTIFACTS)
                {
                    return Err(failure(
                        "artifact parent metadata or member plan exceeds bound",
                    ));
                }
                directories.insert(ancestor.to_path_buf());
            }
        }
        selected.insert(record.path.clone(), record.clone());
    }
    if total > MAX_PRODUCER_BYTES {
        return Err(failure("artifact unique byte plan exceeds producer bound"));
    }
    if selected
        .keys()
        .any(|path| directories.contains(Path::new(path)))
    {
        return Err(failure("artifact path is also a parent directory"));
    }
    if selected
        .len()
        .checked_add(directories.len())
        .and_then(|count| count.checked_add(2))
        .is_none_or(|count| count > MAX_PRODUCER_ARTIFACTS)
    {
        return Err(failure("artifact member and directory plan exceeds bound"));
    }
    live(deadline)?;
    Ok(selected.into_values().collect())
}

impl CanonicalCatalog {
    /// Every reference, including duplicates, must pass the same held-root reader.
    pub fn build(
        records: &[Artifact],
        overhead: u64,
        deadline: Instant,
        mut validate: impl FnMut(&Artifact) -> Result<()>,
    ) -> Result<Self> {
        let canonical = plan(records, overhead, deadline, false)?;
        for record in records {
            live(deadline)?;
            validate(record)?;
            live(deadline)?;
        }
        Ok(Self { records: canonical })
    }
    pub fn into_records(self) -> Vec<Artifact> {
        self.records
    }
}

/// Projection consumes a canonical union, and still rejects accidental duplicates.
pub fn preflight_unique(records: &[Artifact], overhead: u64, deadline: Instant) -> Result<()> {
    plan(records, overhead, deadline, true).map(|_| ())
}
