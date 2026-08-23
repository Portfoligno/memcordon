use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use super::{CGROUP_ROOT, STATE_ROOT};
use sha2::{Digest, Sha256};

pub fn recover() -> Result<Vec<String>, String> {
    let root = Path::new(STATE_ROOT);
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut ambiguous = Vec::new();
    let mut authenticated = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let record = fs::read_to_string(entry.path()).map_err(|error| error.to_string())?;
        let expected = name.to_string_lossy();
        if !integrity_valid(&record)
            || record.lines().find_map(|line| line.strip_prefix("cgroup="))
                != Some(expected.as_ref())
        {
            ambiguous.push(expected.into_owned());
            continue;
        }
        authenticated.insert(name.clone());
        let path = Path::new(CGROUP_ROOT).join(&name);
        if path.exists() {
            super::cgroup::AttemptCgroup::authenticated(path)
                .kill_and_retire(Instant::now() + Duration::from_secs(10))?;
        }
        fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
    }
    let cgroup_root = Path::new(CGROUP_ROOT);
    if cgroup_root.exists() {
        for entry in fs::read_dir(cgroup_root).map_err(|error| error.to_string())? {
            let name = entry.map_err(|error| error.to_string())?.file_name();
            if !authenticated.contains(&name) {
                ambiguous.push(name.to_string_lossy().into_owned());
            }
        }
    }
    ambiguous.sort();
    ambiguous.dedup();
    Ok(ambiguous)
}

fn integrity_valid(record: &str) -> bool {
    let Some((body, digest)) = record.rsplit_once("digest=") else {
        return false;
    };
    let expected: String = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    digest.trim() == expected
}
