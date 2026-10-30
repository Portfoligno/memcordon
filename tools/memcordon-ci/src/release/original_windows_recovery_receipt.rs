//! Successful on-disk recovery receipts exclude their own cleanup.json hash.
use crate::{
    CiError, Result, release::artifacts, windows_installed_cases::SelectedArtifact,
    windows_readiness_adapter::RecoveryCleanup,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const ARTIFACT_NAMES: [&str; 4] = [
    "recovery-invocation.json",
    "recovery.stdout.bin",
    "recovery.stderr.bin",
    "guardian-quiescence.json",
];
pub struct ExpectedRecovery<'a> {
    pub directory: &'a Path,
    pub cli: &'a SelectedArtifact,
    pub provider: &'a memcordon_core::PublicProviderBindingV1,
    pub agent_sha256: &'a str,
    pub manifest_sha256: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    format: String,
    revision: u32,
    cli: SelectedArtifact,
    provider: memcordon_core::PublicProviderBindingV1,
    cwd: PathBuf,
    argv_utf16: Vec<Vec<u16>>,
    environment_cleared: bool,
    command_budget_millis: u64,
}
fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(bytes)?)
}
/// The caller must retain each record's native custody for its existing lifetime.
pub fn validate(
    recovery: &RecoveryCleanup,
    expected: &ExpectedRecovery<'_>,
    mut read: impl FnMut(&Path) -> Result<Vec<u8>>,
) -> Result<()> {
    let expected_paths: BTreeSet<_> = ARTIFACT_NAMES
        .map(|name| expected.directory.join(name))
        .into_iter()
        .collect();
    if recovery.output_directory != expected.directory
        || recovery.deadline_exhausted
        || recovery.native_status != Some(0)
        || recovery.recovery.is_err()
        || recovery.native_quiescence.is_err()
        || recovery.artifacts.len() != expected_paths.len()
    {
        return Err(CiError::Message(
            "original successful recovery summary differs".into(),
        ));
    }
    let mut records = BTreeMap::new();
    for receipt in &recovery.artifacts {
        if receipt.path.parent() != Some(expected.directory)
            || !expected_paths.contains(&receipt.path)
            || records.contains_key(&receipt.path)
        {
            return Err(CiError::Message(
                "raw recovery artifact destination duplicated or escaped".into(),
            ));
        }
        let bytes = read(&receipt.path)?;
        if bytes.len() > 16 * 1024 * 1024 || artifacts::checksum(&bytes) != receipt.sha256 {
            return Err(CiError::Message(
                "raw recovery artifact bytes differ".into(),
            ));
        }
        records.insert(receipt.path.clone(), bytes);
    }
    if records.keys().cloned().collect::<BTreeSet<_>>() != expected_paths {
        return Err(CiError::Message(
            "successful recovery raw artifact stems differ".into(),
        ));
    }
    let invocation: Invocation =
        decode(&records[&expected.directory.join("recovery-invocation.json")])?;
    let argv = invocation
        .argv_utf16
        .iter()
        .map(|argument| {
            String::from_utf16(argument).map_err(|error| CiError::Message(error.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    if invocation.format != "memcordon.windows-native-recovery-invocation"
        || invocation.revision != 1
        || serde_json::to_vec(&invocation.cli)? != serde_json::to_vec(expected.cli)?
        || serde_json::to_vec(&invocation.provider)? != serde_json::to_vec(expected.provider)?
        || invocation.cwd != expected.directory
        || !invocation.environment_cleared
        || !(100..=60000).contains(&invocation.command_budget_millis)
        || argv.len() != 3
        || argv[0] != "windows-recover"
        || argv[1] != "converge"
        || argv[2]
            != invocation
                .command_budget_millis
                .saturating_sub(100)
                .min(30000)
                .to_string()
    {
        return Err(CiError::Message(
            "actual recovery invocation differs from original selected CLI/provider".into(),
        ));
    }
    let inventory: memcordon_core::WindowsRecoveryInventoryV1 =
        decode(&records[&expected.directory.join("recovery.stdout.bin")])?;
    if !inventory.is_consistent()
        || inventory.provider_generation != expected.provider.generation.as_str()
        || inventory.executing != 0
        || inventory.incomplete_proof != 0
        || inventory.unacknowledged_outboxes != 0
        || inventory.ack_retirement_in_progress != 0
        || inventory.active_admissions != 0
        || inventory.quarantined != 0
    {
        return Err(CiError::Message(
            "actual original recovery inventory retains selected authority".into(),
        ));
    }
    let guardian = decode(&records[&expected.directory.join("guardian-quiescence.json")])?;
    memcordon_readiness_verifier::current::windows::validate_guardian_quiescence(
        &guardian,
        expected.agent_sha256,
        expected.manifest_sha256,
    )
    .map_err(CiError::Message)
}
