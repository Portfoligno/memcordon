use memcordon_readiness_verifier::{Artifact, CaseRecord, EvidenceIndex, validate_case_record};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Every hostile record is persisted and checked through the central route.
/// Rehashing mutated peers distinguishes semantic joins from checksum failures.
pub struct PersistedCase {
    pub root: tempfile::TempDir,
    pub index: EvidenceIndex,
    pub record: CaseRecord,
}

impl PersistedCase {
    pub fn write(&mut self, path: &str, bytes: &[u8]) {
        let target = self.root.path().join(path);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, bytes).unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        if let Some(artifact) = self
            .index
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.path == path)
        {
            artifact.sha256 = hash;
            artifact.length = bytes.len() as u64;
        } else {
            self.index.artifacts.push(Artifact {
                path: path.into(),
                length: bytes.len() as u64,
                sha256: hash,
            });
        }
    }
    pub fn json(&mut self, path: &str, value: &Value) {
        self.write(path, &serde_json::to_vec(value).unwrap());
    }
    pub fn mutate(&mut self, path: &str, change: impl FnOnce(&mut Value)) {
        let bytes = std::fs::read(self.root.path().join(path)).unwrap();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        change(&mut value);
        self.json(path, &value);
    }
    pub fn validate(&self) -> Result<(), String> {
        validate_case_record(&self.index, &self.record, self.root.path())
    }
}
