//! Archive actual hostile source imports and their original native settlement.
#![cfg(target_os = "linux")]
use super::linux_isolation_cases::ImportRefusalReport;
use super::linux_mixed_installed::{read_policy_observation_file, retain};
use crate::{CiError, Result, consumer_readiness_ledger::SourceIdentity};
use memcordon_readiness_verifier::{Artifact, CaseKey, LinuxIsolationImportEvidence};
use std::{collections::BTreeMap, path::Path};

impl ImportRefusalReport {
    pub fn normalize(
        &self,
        identity: &SourceIdentity,
        key: &CaseKey,
        artifact_root: &Path,
        owner: &serde_json::Value,
        baseline_contract: &Path,
        original_lease: &Path,
        acquisition: &Path,
        artifacts: &mut BTreeMap<String, Artifact>,
    ) -> Result<String> {
        if !self.native_owners_settled()
            || key.family != "L-ISO-02"
            || !["input-socket", "imported-socket", "caller-writable-tree"]
                .contains(&key.scenario.as_str())
        {
            return Err(CiError::Message(
                "importer original native custody unsettled/finite scope differs".into(),
            ));
        }
        let intents = self
            .artifacts
            .iter()
            .filter(|path| {
                path.file_name().and_then(|name| name.to_str())
                    == Some("isolation-import-intent.json")
            })
            .collect::<Vec<_>>();
        if intents.len() != 1 {
            return Err(CiError::Message(
                "importer original intent absent/ambiguous".into(),
            ));
        }
        let directory = intents[0]
            .parent()
            .ok_or_else(|| CiError::Message("importer original recipe parent absent".into()))?;
        let (_, definition_path) = self.definition.as_ref().ok_or_else(|| {
            CiError::Message("importer original definition custody absent".into())
        })?;
        let prefix = Path::new(&key.target)
            .join(
                key.channel
                    .as_deref()
                    .ok_or_else(|| CiError::Message("importer original channel absent".into()))?,
            )
            .join("isolation-imports")
            .join(&key.scenario);
        std::fs::create_dir_all(artifact_root.join(&prefix))?;
        std::fs::create_dir_all(artifact_root.join(&prefix).join("definition-retirement"))?;
        let mut persist = |name: &str, bytes: &[u8]| -> Result<String> {
            let relative = prefix
                .join(name)
                .to_str()
                .ok_or_else(|| CiError::Message("importer archive path nonUTF8".into()))?
                .to_owned();
            retain(&artifact_root.join(&relative), bytes)?;
            let artifact = Artifact {
                path: relative.clone(),
                length: bytes.len() as u64,
                sha256: super::artifacts::checksum(bytes),
            };
            if let Some(prior) = artifacts.insert(relative.clone(), artifact.clone()) {
                if prior.length != artifact.length || prior.sha256 != artifact.sha256 {
                    return Err(CiError::Message(
                        "importer original archive custody conflict".into(),
                    ));
                }
            }
            Ok(relative)
        };
        let mut capture = |name: &str, path: &Path| {
            persist(name, &read_policy_observation_file(path, 32 * 1024 * 1024)?)
        };
        let contract = capture("contract.json", baseline_contract)?;
        let activation = capture(
            "activation.json",
            &baseline_contract.with_file_name("mixed.activation.json"),
        )?;
        let definition = capture("definition.json", definition_path)?;
        let mut leaf = |name: &str| capture(name, &directory.join(name));
        let intent = leaf("isolation-import-intent.json")?;
        let source = leaf("isolation-import-source.json")?;
        let original_inventory = leaf("isolation-import-original-inventory.json")?;
        let inventory = leaf("isolation-import-inventory.json")?;
        let source_retirement = leaf("isolation-import-source-retired.json")?;
        let source_closure = leaf("isolation-import-source-closed.json")?;
        let invocation = leaf("invocation.json")?;
        let native_creation = leaf("native-creation.json")?;
        let native_process = leaf("native-process.json")?;
        let exit = leaf("exit.json")?;
        let stdout = leaf("stdout.json")?;
        let stderr = leaf("stderr.bin")?;
        let census = leaf("isolation-import-census.json")?;
        let challenge = leaf("isolation-import-challenge.bin")?;
        let replaced_original = if key.scenario == "imported-socket" {
            Some(leaf("socket-replaced-original.bin")?)
        } else {
            None
        };
        drop(leaf);
        let mut retired = |name: &str| {
            capture(
                Path::new("definition-retirement")
                    .join(name)
                    .to_str()
                    .ok_or_else(|| {
                        CiError::Message("importer native retirement path nonUTF8".into())
                    })?,
                &directory.join("definition-retirement").join(name),
            )
        };
        let definition_retirement = retired("invocation.json")?;
        let retirement_creation = retired("native-creation.json")?;
        let retirement_process = retired("native-process.json")?;
        let retirement_exit = retired("exit.json")?;
        let retirement_stdout = retired("stdout.json")?;
        let retirement_stderr = retired("stderr.bin")?;
        drop(retired);
        let acquired: serde_json::Value = serde_json::from_slice(&read_policy_observation_file(
            acquisition,
            32 * 1024 * 1024,
        )?)?;
        let mut account_capture = |field: &str, leaf: &str| -> Result<String> {
            capture(
                leaf,
                Path::new(acquired["account"][field].as_str().ok_or_else(|| {
                    CiError::Message("importer original account source absent".into())
                })?),
            )
        };
        let account_intent = account_capture("intent", "account-intent.json")?;
        let account_readback = account_capture("native_readback", "account-getent.bin")?;
        let group_readback = account_capture("group_readback", "group-getent.bin")?;
        drop(account_capture);
        drop(capture);
        let owner_artifact = persist("owner.json", &serde_json::to_vec(owner)?)?;
        drop(persist);
        let mut original_path = |path: &Path| -> Result<String> {
            let relative = path
                .strip_prefix(artifact_root)
                .map_err(|_| {
                    CiError::Message("importer original authority outside archive root".into())
                })?
                .to_str()
                .ok_or_else(|| CiError::Message("importer original authority path nonUTF8".into()))?
                .to_owned();
            let bytes = read_policy_observation_file(path, 32 * 1024 * 1024)?;
            let artifact = Artifact {
                path: relative.clone(),
                length: bytes.len() as u64,
                sha256: super::artifacts::checksum(&bytes),
            };
            if let Some(prior) = artifacts.insert(relative.clone(), artifact.clone()) {
                if prior.length != artifact.length || prior.sha256 != artifact.sha256 {
                    return Err(CiError::Message(
                        "importer original authority custody conflict".into(),
                    ));
                }
            }
            Ok(relative)
        };
        let original_lease = original_path(original_lease)?;
        let acquisition = original_path(acquisition)?;
        let evidence = LinuxIsolationImportEvidence {
            format: "memcordon.consumer-readiness.linux-isolation-import-refusal".into(),
            revision: 1,
            key: key.clone(),
            run_id: identity.run_id.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            lease_id: owner["lease_id"]
                .as_str()
                .ok_or_else(|| CiError::Message("importer original lease absent".into()))?
                .into(),
            owner: owner_artifact,
            original_lease,
            acquisition,
            activation,
            contract,
            definition,
            intent,
            source,
            original_inventory,
            inventory,
            source_retirement,
            source_closure,
            invocation,
            native_creation,
            native_process,
            exit,
            stdout,
            stderr,
            account_intent,
            account_readback,
            group_readback,
            census,
            challenge,
            definition_retirement,
            retirement_creation,
            retirement_process,
            retirement_exit,
            retirement_stdout,
            retirement_stderr,
            replaced_original,
        };
        let relative = prefix
            .join("case-evidence.json")
            .to_str()
            .ok_or_else(|| CiError::Message("importer original evidence path nonUTF8".into()))?
            .to_owned();
        let bytes = serde_json::to_vec(&evidence)?;
        retain(&artifact_root.join(&relative), &bytes)?;
        artifacts.insert(
            relative.clone(),
            Artifact {
                path: relative.clone(),
                length: bytes.len() as u64,
                sha256: super::artifacts::checksum(&bytes),
            },
        );
        Ok(relative)
    }
}
