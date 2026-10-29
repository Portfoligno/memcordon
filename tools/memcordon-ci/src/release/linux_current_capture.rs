//! Persist already observed current case bytes; this owns no native resources.
use crate::{CiError, Result};
use memcordon_readiness_verifier::{Artifact, CaseRecord, CaseState, current::CaseEvidenceV2};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Component, Path},
};

pub fn persist_case(
    destination: &Path,
    evidence_path: &str,
    evidence: &CaseEvidenceV2,
    mut files: BTreeMap<String, Vec<u8>>,
    state: CaseState,
    reason: Option<String>,
) -> Result<(CaseRecord, Vec<Artifact>)> {
    if files
        .insert(evidence_path.into(), serde_json::to_vec(evidence)?)
        .is_some()
    {
        return Err(CiError::Message(
            "actual case bytes contain duplicate evidence path".into(),
        ));
    }
    let mut inventory = Vec::new();
    for (path, bytes) in files {
        if Path::new(&path).components().count() < 2
            || Path::new(&path)
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(CiError::Message(
                "actual current capture path escapes artifact root".into(),
            ));
        }
        let target = destination.join(&path);
        std::fs::create_dir_all(
            target
                .parent()
                .ok_or_else(|| CiError::Message("capture parent absent".into()))?,
        )?;
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(&target)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        inventory.push(Artifact {
            path,
            length: bytes.len() as u64,
            sha256: super::artifacts::checksum(&bytes),
        });
    }
    Ok((
        CaseRecord {
            key: evidence.key.clone(),
            run_id: evidence.run_id.clone(),
            state,
            reason,
            evidence: Some(evidence_path.into()),
        },
        inventory,
    ))
}
