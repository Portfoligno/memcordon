//! Canonical immutable Linux private B identity shared by CI and installation.

use serde::{Deserialize, Serialize};

use crate::DiagnosticSha256;
use crate::package_inspection_v6::LinuxUnitHashesV6;
use crate::runtime_manifest::{RuntimeComponentRecord, RuntimeComponentRole};
use crate::workload_codec::{Encoder, hash_bytes};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateCandidateStageV2 {
    UnqualifiedCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateCandidateRecordV2 {
    pub schema_version: u32,
    pub stage: PrivateCandidateStageV2,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub runtime_manifest_sha256: DiagnosticSha256,
    pub component_sha256: DiagnosticSha256,
    pub unit_sha256: DiagnosticSha256,
    pub filter_sha256: DiagnosticSha256,
}

impl PrivateCandidateRecordV2 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err("private candidate B record exceeds bound".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let record: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if record.schema_version != 2
            || record.stage != PrivateCandidateStageV2::UnqualifiedCandidate
            || record.version.is_empty()
            || record.version.len() > 64
            || !valid_commit(&record.source_commit)
            || !matches!(
                record.target.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
        {
            return Err("private candidate B record identity differs".into());
        }
        Ok(record)
    }
}

fn valid_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Domain-separated component digest; Q and installed M1 must agree on this
/// exact inventory, including the physical ARM32 helper on ARM64.
pub fn private_component_digest_v2(
    target: &str,
    source_commit: &str,
    version: &str,
    components: &[RuntimeComponentRecord],
) -> Result<DiagnosticSha256, String> {
    if !matches!(
        target,
        "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
    ) || !valid_commit(source_commit)
        || version.is_empty()
        || version.len() > 64
        || components.len()
            != if target == "aarch64-unknown-linux-gnu" {
                3
            } else {
                2
            }
    {
        return Err("private component build identity differs".into());
    }
    let mut sorted = components.to_vec();
    sorted.sort_by_key(|component| match component.role {
        RuntimeComponentRole::PublicCli => 1,
        RuntimeComponentRole::SealedAgent => 2,
        RuntimeComponentRole::Arm32AbiHelper => 3,
        RuntimeComponentRole::DesktopBootstrap => 4,
        RuntimeComponentRole::SessionBroker => 5,
    });
    if sorted[0].role != RuntimeComponentRole::PublicCli
        || sorted[1].role != RuntimeComponentRole::SealedAgent
        || sorted[0].id != "public-cli"
        || sorted[1].id != "sealed-agent"
        || sorted[0].path != "memcordon"
        || sorted[1].path != "memcordon-sealed-agent"
        || (target == "aarch64-unknown-linux-gnu"
            && (sorted[2].role != RuntimeComponentRole::Arm32AbiHelper
                || sorted[2].id != "arm32-abi-helper"
                || sorted[2].path != "memcordon-arm32-abi-helper"))
        || sorted.iter().any(|component| {
            component.size == 0 || component.mode != 0o755 || component.sha256.len() != 64
        })
    {
        return Err("private component inventory differs".into());
    }
    let mut encoder = Encoder::new(b"private-release-components-v2", 4096)?;
    for value in [target, source_commit, version] {
        encoder.count(value.len())?;
        encoder.raw(value.as_bytes())?;
    }
    encoder.count(sorted.len())?;
    for (tag, component) in sorted.iter().enumerate() {
        let mut sha = [0_u8; 32];
        let encoded = component.sha256.as_bytes();
        if !encoded
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("private component digest is invalid".into());
        }
        for (pair, byte) in encoded.chunks_exact(2).zip(&mut sha) {
            let nibble = |value| match value {
                b'0'..=b'9' => Ok(value - b'0'),
                b'a'..=b'f' => Ok(value - b'a' + 10),
                _ => Err("private component digest is invalid"),
            };
            *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        encoder.byte(u8::try_from(tag + 1).expect("bounded components fit u8"))?;
        encoder.count(component.id.len())?;
        encoder.raw(component.id.as_bytes())?;
        encoder.count(component.path.len())?;
        encoder.raw(component.path.as_bytes())?;
        encoder.u64(component.size)?;
        encoder.u64(u64::from(component.mode))?;
        encoder.raw(&sha)?;
    }
    Ok(hash_bytes(&encoder.finish()))
}

pub fn private_unit_digest_v2(units: &LinuxUnitHashesV6) -> DiagnosticSha256 {
    let mut encoder =
        Encoder::new(b"private-release-units-v2", 512).expect("fixed unit identity fits bound");
    for (tag, digest) in [
        (1, &units.control_service),
        (2, &units.control_socket),
        (3, &units.launcher_service),
        (4, &units.launcher_socket),
        (5, &units.tmpfiles),
        (6, &units.network_launcher_service),
        (7, &units.network_launcher_socket),
    ] {
        encoder.byte(tag).expect("fixed unit identity fits bound");
        encoder
            .digest(digest)
            .expect("fixed unit identity fits bound");
    }
    hash_bytes(&encoder.finish())
}
