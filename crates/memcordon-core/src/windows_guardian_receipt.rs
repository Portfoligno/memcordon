//! Bound native guardian observation. The checksum is not an authentication
//! code: consumers must independently authenticate the protected receipt file.

use std::fmt::Write;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::WindowsProcessIdentityV1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsGuardianReceiptV2 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub provider_generation: String,
    pub launch_incarnation: String,
    pub original_boot_id: String,
    pub job_identity: String,
    pub guardian_identity: WindowsProcessIdentityV1,
    pub worker_identity: WindowsProcessIdentityV1,
    pub owner_manifest_sha256: String,
    pub termination_requested: bool,
    pub native_job_query_succeeded: bool,
    pub active_processes_zero_observed: bool,
    pub observed_unix_millis: u64,
    pub integrity_sha256: String,
}

/// Values that identify the attempt and sealed owner manifest bound by a guardian receipt.
#[derive(Clone, Copy, Debug)]
pub struct WindowsGuardianReceiptBinding<'a> {
    pub attempt_id: &'a str,
    pub nonce: &'a str,
    pub request_sha256: &'a str,
    pub provider_generation: &'a str,
    pub launch_incarnation: &'a str,
    pub boot_identity: &'a str,
    pub job_identity: &'a str,
    pub owner_manifest_sha256: &'a str,
}

impl WindowsGuardianReceiptV2 {
    pub fn canonical_sha256(&self) -> Result<String, &'static str> {
        let mut canonical = self.clone();
        canonical.integrity_sha256.clear();
        let bytes = serde_json::to_vec(&canonical).map_err(|_| "guardian receipt serialization")?;
        let digest = Sha256::digest(bytes);
        let mut value = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(&mut value, "{byte:02x}").expect("String write cannot fail");
        }
        Ok(value)
    }

    pub fn is_consistent(&self) -> bool {
        fn sha(value: &str) -> bool {
            value.len() == Sha256::output_size() * 2
                && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        }
        self.schema_version == 2
            && sha(&self.attempt_id)
            && !self.nonce.is_empty()
            && sha(&self.request_sha256)
            && !self.provider_generation.is_empty()
            && !self.launch_incarnation.is_empty()
            && !self.original_boot_id.is_empty()
            && sha(&self.job_identity)
            && self.guardian_identity.process_id != 0
            && self.guardian_identity.creation_time_100ns != 0
            && self.worker_identity.process_id != 0
            && self.worker_identity.creation_time_100ns != 0
            && sha(&self.owner_manifest_sha256)
            && self.termination_requested
            && self.native_job_query_succeeded
            && self.active_processes_zero_observed
            && self.observed_unix_millis != 0
            && self
                .canonical_sha256()
                .is_ok_and(|canonical| canonical == self.integrity_sha256)
    }

    pub fn binds(&self, binding: WindowsGuardianReceiptBinding<'_>) -> bool {
        self.is_consistent()
            && self.attempt_id == binding.attempt_id
            && self.nonce == binding.nonce
            && self.request_sha256 == binding.request_sha256
            && self.provider_generation == binding.provider_generation
            && self.launch_incarnation == binding.launch_incarnation
            && self.original_boot_id == binding.boot_identity
            && self.job_identity == binding.job_identity
            && self.owner_manifest_sha256 == binding.owner_manifest_sha256
    }
}
