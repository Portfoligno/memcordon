//! Caller-owned work descriptions. Parsing these values acquires no native authority.
use std::collections::BTreeSet;

use crate::identifiers::LogicalId;
pub use crate::workload_files::{RootRelativePath, WritableRootV1};
pub use crate::workload_requirements::RequirementRequestV1;
use crate::{BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Serialize};

pub const REQUEST_FORMAT: &str = "memcordon.workload-request";
pub const REQUEST_REVISION: u32 = 1;
/// Observation identity for ordinary sealed Linux runs without a private request.
pub const LINUX_CREDENTIAL_PRESERVING_PROFILE: &str = "linux-credential-preserving-sealed-v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadAcknowledgmentV1 {
    pub format: String,
    pub revision: u32,
    pub association: WorkloadAttemptAssociationV1,
    pub record_retired: bool,
}
impl WorkloadAcknowledgmentV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, RequestError> {
        if bytes.len() > 64 * 1024 {
            return Err(RequestError::MalformedRequest(
                "acknowledgment exceeds byte bound".into(),
            ));
        }
        crate::canonical_json::reject_duplicate_json_keys(bytes)
            .map_err(RequestError::MalformedRequest)?;
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|e| RequestError::MalformedRequest(e.to_string()))?;
        if value.format != "memcordon.workload-acknowledgment"
            || value.revision != 1
            || !value.record_retired
        {
            return Err(RequestError::MalformedRequest(
                "invalid acknowledgment observation".into(),
            ));
        }
        value.association.validate()?;
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkloadRejectionCodeV1 {
    MalformedRequest,
    UnsupportedRequestVersion,
    UnsupportedRequirement,
    NativeUnavailable,
    CallerIdentityMismatch,
    InputCapacityUnavailable,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRejectionV1 {
    pub format: String,
    pub revision: u32,
    pub code: WorkloadRejectionCodeV1,
    pub detail: crate::BoundedText<4096>,
}

/// Locate the resource-policy range in the finite native launch-v3 codec.
/// This is byte correlation only; the native launch decoder still validates admission.
pub fn native_resource_bytes(bytes: &[u8]) -> Result<&[u8], RequestError> {
    use std::mem::size_of;
    let malformed =
        || RequestError::MalformedRequest("invalid native launch resource binding".into());
    if bytes.len() > crate::workload_limits::NATIVE_LAUNCH_BYTES {
        return Err(malformed());
    }
    fn take<'a>(remaining: &mut &'a [u8], count: usize) -> Result<&'a [u8], RequestError> {
        let (head, tail) = remaining
            .split_at_checked(count)
            .ok_or_else(|| RequestError::MalformedRequest("truncated native launch".into()))?;
        *remaining = tail;
        Ok(head)
    }
    fn word(remaining: &mut &[u8]) -> Result<usize, RequestError> {
        let bytes: [u8; size_of::<u32>()] = take(remaining, size_of::<u32>())?
            .try_into()
            .expect("word length checked");
        usize::try_from(u32::from_be_bytes(bytes))
            .map_err(|_| RequestError::MalformedRequest("native count overflow".into()))
    }
    fn value(remaining: &mut &[u8]) -> Result<(), RequestError> {
        let count = word(remaining)?;
        if count > 64 * 1024 {
            return Err(RequestError::MalformedRequest(
                "native value exceeds bound".into(),
            ));
        }
        take(remaining, count)?;
        Ok(())
    }
    fn optional(remaining: &mut &[u8]) -> Result<(), RequestError> {
        match take(remaining, size_of::<u8>())?[0] {
            0 => Ok(()),
            1 => {
                take(remaining, size_of::<u64>())?;
                Ok(())
            }
            _ => Err(RequestError::MalformedRequest(
                "unknown native optional tag".into(),
            )),
        }
    }
    let mut remaining = bytes;
    if take(&mut remaining, size_of::<u16>())? != 3_u16.to_be_bytes() {
        return Err(malformed());
    }
    take(&mut remaining, size_of::<u64>())?;
    value(&mut remaining)?;
    let arguments = word(&mut remaining)?;
    if arguments > 4096 {
        return Err(malformed());
    }
    for _ in 0..arguments {
        value(&mut remaining)?;
    }
    let environment = word(&mut remaining)?;
    if environment > 8192 {
        return Err(malformed());
    }
    for _ in 0..environment {
        value(&mut remaining)?;
        value(&mut remaining)?;
    }
    let start = bytes.len() - remaining.len();
    optional(&mut remaining)?;
    match take(&mut remaining, size_of::<u8>())?[0] {
        1 => {
            take(&mut remaining, size_of::<u64>())?;
        }
        2 | 3 => {}
        _ => return Err(malformed()),
    }
    optional(&mut remaining)?;
    if !matches!(take(&mut remaining, size_of::<u8>())?[0], 1 | 2)
        || !matches!(take(&mut remaining, size_of::<u8>())?[0], 1 | 2)
    {
        return Err(malformed());
    }
    for _field in ["poll", "signal-grace", "command-exit-grace", "limit-grace"] {
        take(&mut remaining, size_of::<u64>())?;
    }
    let end = bytes.len() - remaining.len();
    let descriptors = word(&mut remaining)?;
    if descriptors > 8 {
        return Err(malformed());
    }
    take(&mut remaining, descriptors)?;
    match take(&mut remaining, size_of::<u8>())?[0] {
        0 => {}
        1 => return Err(RequestError::UnsupportedRequestVersion),
        _ => return Err(malformed()),
    }
    if !remaining.is_empty() {
        return Err(malformed());
    }
    Ok(&bytes[start..end])
}
pub fn resource_policy_digest(
    native_launch: &[u8],
    attempt_deadline_millis: Option<u64>,
) -> Result<DiagnosticSha256, RequestError> {
    use sha2::{Digest, Sha256};
    let resources = native_resource_bytes(native_launch)?;
    let mut digest = Sha256::new();
    digest.update(b"memcordon.native-resource-policy/version1\0");
    digest.update(
        u64::try_from(resources.len())
            .expect("bounded resources fit u64")
            .to_be_bytes(),
    );
    digest.update(resources);
    digest.update([u8::from(attempt_deadline_millis.is_some())]);
    if let Some(duration) = attempt_deadline_millis {
        digest.update(duration.to_be_bytes());
    }
    Ok(DiagnosticSha256::from_bytes(digest.finalize().into()))
}

/// Current invocation commitment includes the selected private-root cwd as well
/// as the exact finite native argv/resource bytes.
pub fn invocation_digest(
    native_launch: &[u8],
    working_directory: Option<&RootRelativePath>,
) -> Result<DiagnosticSha256, RequestError> {
    use sha2::{Digest, Sha256};
    native_resource_bytes(native_launch)?;
    let mut hash = Sha256::new();
    hash.update(b"memcordon.native-invocation/version1\0");
    hash.update(
        u64::try_from(native_launch.len())
            .expect("bounded native invocation fits u64")
            .to_be_bytes(),
    );
    hash.update(native_launch);
    hash.update([u8::from(working_directory.is_some())]);
    if let Some(path) = working_directory {
        let bytes = path.as_str().as_bytes();
        hash.update(
            u64::try_from(bytes.len())
                .expect("bounded private cwd fits u64")
                .to_be_bytes(),
        );
        hash.update(bytes);
    }
    Ok(DiagnosticSha256::from_bytes(hash.finalize().into()))
}

/// Initial Linux invocation metadata. Native argv/resource bytes use the finite
/// native launch codec; they never contain a source bundle or host output path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadStartV1 {
    pub format: String,
    pub revision: u32,
    pub request: WorkloadRequestV1,
    pub native_launch: Vec<u8>,
    pub working_directory: Option<RootRelativePath>,
    pub attempt_deadline_millis: Option<u64>,
}
impl WorkloadStartV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, RequestError> {
        if bytes.len() > 1024 * 1024 - 72 {
            return Err(RequestError::MalformedRequest(
                "workload start exceeds frame bound".into(),
            ));
        }
        crate::canonical_json::reject_duplicate_json_keys(bytes)
            .map_err(RequestError::MalformedRequest)?;
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|e| RequestError::MalformedRequest(e.to_string()))?;
        if value.format != "memcordon.workload-start" || value.revision != 1 {
            return Err(RequestError::UnsupportedRequestVersion);
        }
        value.request.validate()?;
        if value.request.canonical_bytes()?.len() > crate::workload_limits::REQUEST_BYTES
            || value.native_launch.len() > crate::workload_limits::NATIVE_LAUNCH_BYTES
        {
            return Err(RequestError::MalformedRequest(
                "workload start metadata exceeds bound".into(),
            ));
        }
        Ok(value)
    }
}

/// Describes the provider-assigned live session before native allocation. It is
/// safe to persist as a recovery locator; it supplies no ownership or release gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadAttemptAssociationV1 {
    pub format: String,
    pub revision: u32,
    pub attempt: [u8; 16],
    pub challenge: [u8; 16],
    pub request_sha256: DiagnosticSha256,
    pub boot_id: crate::BoundedText<64>,
    pub provider: crate::PublicProviderBindingV1,
    pub control: crate::execution_facts::NativeProcessV2,
}
impl WorkloadAttemptAssociationV1 {
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.format != "memcordon.workload-attempt"
            || self.revision != 1
            || self.boot_id.as_str().is_empty()
            || self.control.pid == 0
            || !self.provider.is_consistent()
        {
            return Err(RequestError::MalformedRequest(
                "invalid native attempt association".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RequestError {
    #[error("unsupported-request-version")]
    UnsupportedRequestVersion,
    #[error("malformed-request: {0}")]
    MalformedRequest(String),
    #[error("unsupported-requirement: {0}")]
    UnsupportedRequirement(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WorkloadRequestFormat {
    #[serde(rename = "memcordon.workload-request")]
    WorkloadRequest,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(into = "u32")]
pub struct RevisionOne;
impl From<RevisionOne> for u32 {
    fn from(_: RevisionOne) -> Self {
        1
    }
}
impl<'de> Deserialize<'de> for RevisionOne {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if u32::deserialize(d)? == 1 {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("expected revision one"))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LinuxPrivateProfileV1 {
    #[serde(rename = "linux-private-workload-v1")]
    LinuxPrivateWorkload,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WindowsCurrentTokenProfileV1 {
    #[serde(rename = "windows-sealed-current-token-v1")]
    WindowsSealedCurrentToken,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSelectionV1 {
    pub runtime_digest: DiagnosticSha256,
    pub input_digest: DiagnosticSha256,
    pub entrypoint: LogicalId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRootLayoutV1 {
    pub writable_roots: BoundedVec<WritableRootV1, 16>,
    pub output_files: BoundedVec<RootRelativePath, 64>,
}
impl PrivateRootLayoutV1 {
    pub fn digest(&self) -> Result<DiagnosticSha256, RequestError> {
        self.validate()?;
        let mut bytes = b"memcordon.private-root-layout/version1\0".to_vec();
        bytes.extend(
            serde_json::to_vec(self).map_err(|e| RequestError::MalformedRequest(e.to_string()))?,
        );
        Ok(crate::hash_bytes(&bytes))
    }
    pub fn validate(&self) -> Result<(), RequestError> {
        let fail =
            || RequestError::MalformedRequest("unsafe or overlapping root/output layout".into());
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for root in self.writable_roots.as_slice() {
            if !ids.insert(&root.id)
                || !paths.insert(&root.path)
                || root.byte_limit.get() > 16 * 1024 * 1024 * 1024
                || matches!(
                    root.path.as_str().split('/').next(),
                    Some("proc" | "dev" | "sys" | "etc" | "run")
                )
            {
                return Err(fail());
            }
        }
        for path in &paths {
            let mut parent = path.as_str();
            while let Some((prefix, _)) = parent.rsplit_once('/') {
                if paths.iter().any(|p| p.as_str() == prefix) {
                    return Err(fail());
                }
                parent = prefix;
            }
        }
        let mut outputs = BTreeSet::new();
        for output in self.output_files.as_slice() {
            if !outputs.insert(output)
                || !paths.iter().any(|root| {
                    output
                        .as_str()
                        .strip_prefix(root.as_str())
                        .is_some_and(|tail| tail.starts_with('/'))
                })
            {
                return Err(fail());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RuntimeRequestV1 {
    LinuxPrivate {
        profile: LinuxPrivateProfileV1,
        inputs: SnapshotSelectionV1,
        layout: PrivateRootLayoutV1,
    },
    WindowsSealed {
        profile: WindowsCurrentTokenProfileV1,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRequestV1 {
    pub format: WorkloadRequestFormat,
    pub revision: RevisionOne,
    pub runtime: RuntimeRequestV1,
    pub requirements: BoundedVec<RequirementRequestV1, 64>,
}
impl WorkloadRequestV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, RequestError> {
        let malformed = RequestError::MalformedRequest;
        if bytes.len() > crate::workload_limits::REQUEST_BYTES {
            return Err(malformed("request exceeds 64 KiB".into()));
        }
        crate::canonical_json::reject_duplicate_json_keys(bytes).map_err(malformed)?;
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| malformed(e.to_string()))?;
        if value.get("format").and_then(|v| v.as_str()) != Some(REQUEST_FORMAT)
            || value.get("revision").and_then(|v| v.as_u64()) != Some(u64::from(REQUEST_REVISION))
        {
            return Err(RequestError::UnsupportedRequestVersion);
        }
        let request: Self = serde_json::from_value(value).map_err(|e| malformed(e.to_string()))?;
        request.validate()?;
        Ok(request)
    }
    pub fn validate(&self) -> Result<(), RequestError> {
        let mut ids = BTreeSet::new();
        for requirement in self.requirements.as_slice() {
            if !ids.insert(requirement.id()) {
                return Err(RequestError::MalformedRequest(
                    "duplicate requirement id".into(),
                ));
            }
            if matches!(self.runtime, RuntimeRequestV1::WindowsSealed { .. }) {
                return Err(RequestError::UnsupportedRequirement(
                    requirement.id().as_str().into(),
                ));
            }
        }
        if let RuntimeRequestV1::LinuxPrivate { layout, .. } = &self.runtime {
            layout.validate()?;
            for requirement in self.requirements.as_slice() {
                match requirement {
                    RequirementRequestV1::UnixPathStream { writable_root, .. }
                    | RequirementRequestV1::GeneratedExecutable { writable_root, .. } => {
                        let root = layout
                            .writable_roots
                            .as_slice()
                            .iter()
                            .find(|root| &root.id == writable_root)
                            .ok_or_else(|| {
                                RequestError::MalformedRequest(
                                    "requirement refers to absent writable root".into(),
                                )
                            })?;
                        if matches!(
                            requirement,
                            RequirementRequestV1::GeneratedExecutable { .. }
                        ) && !root.generated_execution
                        {
                            return Err(RequestError::UnsupportedRequirement(
                                "generated execution disabled for root".into(),
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RequestError> {
        self.validate()?;
        let mut ordered = self.clone();
        let mut requirements = ordered.requirements.as_slice().to_vec();
        requirements.sort_by(|a, b| a.id().cmp(b.id()));
        ordered.requirements = BoundedVec::default();
        for requirement in requirements {
            ordered
                .requirements
                .try_push(requirement)
                .map_err(|_| RequestError::MalformedRequest("too many requirements".into()))?;
        }
        serde_json::to_vec(&ordered).map_err(|e| RequestError::MalformedRequest(e.to_string()))
    }
    pub fn digest(&self) -> Result<DiagnosticSha256, RequestError> {
        use sha2::{Digest, Sha256};
        Ok(DiagnosticSha256::from_bytes(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }
}
