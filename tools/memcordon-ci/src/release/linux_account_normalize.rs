//! Retain original account probes; acceptance belongs to the independent decoder.
#![cfg(target_os = "linux")]
use super::linux_isolation_cases::AccountRefusalReport;
use super::linux_mixed_installed::{read_policy_observation_file, retain};
use crate::{CiError, Result, consumer_readiness_ledger::SourceIdentity};
use memcordon_readiness_verifier::{Artifact, CaseKey, LinuxAccountRefusalEvidence};
use std::{collections::BTreeMap, path::Path};

impl AccountRefusalReport {
    #[expect(
        clippy::too_many_arguments,
        reason = "Normalization binds independent original account, lease, acquisition, and artifact custody inputs"
    )]
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
        if key.scenario == "account-alias" {
            if !self.native_owners_settled()
                || !self.launches.is_empty()
                || key.family != "L-ISO-06"
            {
                return Err(CiError::Message(
                    "alias policy refusal has foreign frontend/native owners".into(),
                ));
            }
            let directory = self.alias_policy_directory.as_ref().ok_or_else(|| {
                CiError::Message("alias native policy refusal has not completed".into())
            })?;
            let prefix = Path::new(&key.target)
                .join(
                    key.channel
                        .as_deref()
                        .ok_or_else(|| CiError::Message("alias installed channel absent".into()))?,
                )
                .join("account-refusals")
                .join("account-alias");
            std::fs::create_dir_all(artifact_root.join(&prefix))?;
            let mut persist = |name: &str, bytes: &[u8]| -> Result<String> {
                let relative = prefix
                    .join(name)
                    .to_str()
                    .ok_or_else(|| CiError::Message("alias archive path nonUTF8".into()))?
                    .to_owned();
                retain(&artifact_root.join(&relative), bytes)?;
                let artifact = Artifact {
                    path: relative.clone(),
                    length: bytes.len() as u64,
                    sha256: super::artifacts::checksum(bytes),
                };
                if artifacts
                    .insert(relative.clone(), artifact.clone())
                    .is_some_and(|prior| {
                        prior.length != artifact.length || prior.sha256 != artifact.sha256
                    })
                {
                    return Err(CiError::Message("alias archive custody conflict".into()));
                }
                Ok(relative)
            };
            let mut capture = |name: &str, path: &Path| {
                persist(name, &read_policy_observation_file(path, 32 * 1024 * 1024)?)
            };
            let baseline_contract = capture("baseline-contract.json", baseline_contract)?;
            let baseline_activation = capture(
                "baseline-activation.json",
                &directory.join("mixed.activation.json"),
            )?;
            let candidate_policy = capture(
                "alias-rejection.policy.json",
                &directory.join("alias-rejection.policy.json"),
            )?;
            let mut command =
                |stem: &str| -> Result<memcordon_readiness_verifier::NativeAliasPolicyCommand> {
                    Ok(memcordon_readiness_verifier::NativeAliasPolicyCommand {
                        invocation: capture(
                            &format!("{stem}.invocation.json"),
                            &directory.join(stem).with_extension("invocation.json"),
                        )?,
                        exit: capture(
                            &format!("{stem}.exit.json"),
                            &directory.join(stem).with_extension("exit.json"),
                        )?,
                        stdout: capture(
                            &format!("{stem}.json"),
                            &directory.join(stem).with_extension("json"),
                        )?,
                        stderr: capture(
                            &format!("{stem}.stderr.bin"),
                            &directory.join(stem).with_extension("stderr.bin"),
                        )?,
                    })
                };
            let before = command("alias-before")?;
            let rejected = command("alias-rejection")?;
            let after = command("alias-after")?;
            let original_acquired: serde_json::Value = serde_json::from_slice(
                &read_policy_observation_file(acquisition, 32 * 1024 * 1024)?,
            )?;
            let mut account =
                |field: &str, name: &str| -> Result<String> {
                    capture(
                        name,
                        Path::new(original_acquired["account"][field].as_str().ok_or_else(
                            || CiError::Message("alias original account readback absent".into()),
                        )?),
                    )
                };
            let account_intent = account("intent", "account-intent.json")?;
            let account_readback = account("native_readback", "account-getent.bin")?;
            let group_readback = account("group_readback", "group-getent.bin")?;
            let owner_path = persist("owner.json", &serde_json::to_vec(owner)?)?;
            let mut original_path = |path: &Path| -> Result<String> {
                let relative = path
                    .strip_prefix(artifact_root)
                    .map_err(|_| CiError::Message("alias original source outside archive".into()))?
                    .to_str()
                    .ok_or_else(|| CiError::Message("alias original source nonUTF8".into()))?
                    .to_owned();
                let bytes = read_policy_observation_file(path, 32 * 1024 * 1024)?;
                let artifact = Artifact {
                    path: relative.clone(),
                    length: bytes.len() as u64,
                    sha256: super::artifacts::checksum(&bytes),
                };
                if artifacts
                    .insert(relative.clone(), artifact.clone())
                    .is_some_and(|prior| {
                        prior.length != artifact.length || prior.sha256 != artifact.sha256
                    })
                {
                    return Err(CiError::Message(
                        "alias original source custody conflict".into(),
                    ));
                }
                Ok(relative)
            };
            let evidence = memcordon_readiness_verifier::LinuxAccountAliasPolicyEvidence {
                format: "memcordon.consumer-readiness.linux-account-alias-policy-refusal".into(),
                revision: 1,
                key: key.clone(),
                run_id: identity.run_id.clone(),
                source_commit: identity.source_commit.clone(),
                source_tree_sha256: identity.source_tree_sha256.clone(),
                lease_id: owner["lease_id"]
                    .as_str()
                    .ok_or_else(|| CiError::Message("alias original lease absent".into()))?
                    .into(),
                owner: owner_path,
                original_lease: original_path(original_lease)?,
                acquisition: original_path(acquisition)?,
                baseline_contract,
                baseline_activation,
                account_intent,
                account_readback,
                group_readback,
                candidate_policy,
                before,
                rejected,
                after,
            };
            let relative = prefix
                .join("case-evidence.json")
                .to_str()
                .ok_or_else(|| CiError::Message("alias evidence archive path nonUTF8".into()))?
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
            return Ok(relative);
        }
        if !self.native_owners_settled()
            || self.launches.len() != 1
            || key.family != "L-ISO-06"
            || !["same-uid-process", "account-alias", "stale-reservation"]
                .contains(&key.scenario.as_str())
        {
            return Err(CiError::Message(
                "account original native owners/finite scope unsettled".into(),
            ));
        }
        let launch = &self.launches[0];
        let directory = launch
            .result
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| CiError::Message("account original recipe directory absent".into()))?;
        let prefix = Path::new(&key.target)
            .join(key.channel.as_deref().ok_or_else(|| {
                CiError::Message("account original installed channel absent".into())
            })?)
            .join("account-refusals")
            .join(&key.scenario);
        std::fs::create_dir_all(artifact_root.join(&prefix))?;
        let mut persist = |name: &str, bytes: &[u8]| -> Result<String> {
            let relative = prefix
                .join(name)
                .to_str()
                .ok_or_else(|| CiError::Message("account archive native path nonUTF8".into()))?
                .to_owned();
            retain(&artifact_root.join(&relative), bytes)?;
            let artifact = Artifact {
                path: relative.clone(),
                length: bytes.len() as u64,
                sha256: super::artifacts::checksum(bytes),
            };
            if artifacts
                .insert(relative.clone(), artifact.clone())
                .is_some_and(|prior| {
                    prior.length != artifact.length || prior.sha256 != artifact.sha256
                })
            {
                return Err(CiError::Message("account archive custody conflict".into()));
            }
            Ok(relative)
        };
        let mut capture = |name: &str, path: &Path| {
            persist(name, &read_policy_observation_file(path, 32 * 1024 * 1024)?)
        };
        let baseline = capture("baseline-contract.json", baseline_contract)?;
        let baseline_activation = capture(
            "baseline-activation.json",
            &baseline_contract.with_file_name("mixed.activation.json"),
        )?;
        let alias = key.scenario == "account-alias";
        let contract = capture(
            "contract.json",
            &directory.join(if alias {
                "alias.contract.json"
            } else {
                "mixed.contract.json"
            }),
        )?;
        let activation = capture(
            "activation.json",
            &directory.join("original-activation.json"),
        )?;
        let challenge_source = read_policy_observation_file(&directory.join("challenge.bin"), 64)?;
        let challenge_bytes =
            hex::decode(&challenge_source).map_err(|error| CiError::Message(error.to_string()))?;
        if challenge_source.len() != 64
            || challenge_bytes.len() != 32
            || hex::encode(&challenge_bytes).as_bytes() != challenge_source
        {
            return Err(CiError::Message(
                "account original challenge source is not canonical hex32".into(),
            ));
        }
        let result_bytes = read_policy_observation_file(&launch.result, 4 * 1024 * 1024)?;
        let result_value: serde_json::Value = serde_json::from_slice(&result_bytes)?;
        let result = capture("result.json", &launch.result)?;
        let stdout = capture("stdout.bin", &launch.stdout)?;
        let stderr = capture("stderr.bin", &launch.stderr)?;
        let census = capture("census.json", &directory.join("refusal-census.json"))?;
        let paths = std::fs::read_dir(&launch.observation_directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".provider-request.bin"))
            })
            .collect::<Vec<_>>();
        if paths.len() != 1 {
            return Err(CiError::Message(
                "account original provider request absent/ambiguous".into(),
            ));
        }
        let name = paths[0]
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                CiError::Message("account original provider request leaf nonUTF8".into())
            })?;
        let provider_request = capture(name, &paths[0])?;
        let original_acquired: serde_json::Value = serde_json::from_slice(
            &read_policy_observation_file(acquisition, 32 * 1024 * 1024)?,
        )?;
        let mut account_capture = |field: &str, leaf: &str| -> Result<String> {
            capture(
                leaf,
                Path::new(
                    original_acquired["account"][field]
                        .as_str()
                        .ok_or_else(|| {
                            CiError::Message("account original readback source absent".into())
                        })?,
                ),
            )
        };
        let account_intent = account_capture("intent", "account-intent.json")?;
        let account_readback = account_capture("native_readback", "account-getent.bin")?;
        let group_readback = account_capture("group_readback", "group-getent.bin")?;
        let mut optional = |leaf: &str, enabled: bool| -> Result<Option<String>> {
            if enabled {
                Ok(Some(capture(leaf, &directory.join(leaf))?))
            } else {
                Ok(None)
            }
        };
        let external_intent = optional("external-account-intent.json", !alias)?;
        let external_image = optional("external-account-image.bin", !alias)?;
        let external_live = optional("external-account-live.json", !alias)?;
        let external_retired = optional("external-account-retired.json", !alias)?;
        let external_at_refusal = optional(
            "external-account-at-refusal.json",
            key.scenario == "same-uid-process",
        )?;
        let stale = key.scenario == "stale-reservation";
        let reservation_intent = optional("stale-reservation-intent.json", stale)?;
        let reservation_live = optional("stale-reservation-live.json", stale)?;
        let reservation_retired = optional("stale-reservation-retired.json", stale)?;
        let alias_policy = optional("alias-activation.policy.json", alias)?;
        let alias_invocation = optional("alias-activation.invocation.json", alias)?;
        let alias_exit = optional("alias-activation.exit.json", alias)?;
        let alias_stderr = optional("alias-activation.stderr.bin", alias)?;
        let restoration = optional("alias-restoration.json", alias)?;
        let restoration_policy = optional("alias-restoration.policy.json", alias)?;
        let restoration_invocation = optional("alias-restoration.invocation.json", alias)?;
        let restoration_exit = optional("alias-restoration.exit.json", alias)?;
        let restoration_stderr = optional("alias-restoration.stderr.bin", alias)?;
        let challenge = persist("challenge.bin", &challenge_bytes)?;
        let owner_artifact = persist("owner.json", &serde_json::to_vec(owner)?)?;
        let frontend_invocation = persist(
            "frontend-invocation.json",
            &launch.retained_frontend_invocation()?,
        )?;
        let frontend_exit = persist(
            "frontend-exit.json",
            &serde_json::to_vec(&launch.retained_frontend_wait()?)?,
        )?;
        let public_invocation = persist(
            "public-invocation.json",
            &serde_json::to_vec(&result_value["invocation"])?,
        )?;
        let mut original_path = |path: &Path| -> Result<String> {
            let relative = path
                .strip_prefix(artifact_root)
                .map_err(|_| {
                    CiError::Message("account original acquisition outside archive root".into())
                })?
                .to_str()
                .ok_or_else(|| {
                    CiError::Message("account original acquisition path nonUTF8".into())
                })?
                .to_owned();
            let bytes = read_policy_observation_file(path, 32 * 1024 * 1024)?;
            let artifact = Artifact {
                path: relative.clone(),
                length: bytes.len() as u64,
                sha256: super::artifacts::checksum(&bytes),
            };
            if artifacts
                .insert(relative.clone(), artifact.clone())
                .is_some_and(|prior| {
                    prior.length != artifact.length || prior.sha256 != artifact.sha256
                })
            {
                return Err(CiError::Message(
                    "account original archive custody conflict".into(),
                ));
            }
            Ok(relative)
        };
        let original_lease = original_path(original_lease)?;
        let acquisition = original_path(acquisition)?;
        let evidence = LinuxAccountRefusalEvidence {
            format: "memcordon.consumer-readiness.linux-account-refusal".into(),
            revision: 1,
            key: key.clone(),
            run_id: identity.run_id.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            lease_id: owner["lease_id"]
                .as_str()
                .ok_or_else(|| CiError::Message("account original installed lease absent".into()))?
                .into(),
            owner: owner_artifact,
            original_lease,
            acquisition,
            baseline_contract: baseline,
            baseline_activation,
            contract,
            activation,
            challenge,
            public_invocation,
            frontend_invocation,
            frontend_exit,
            result,
            provider_request,
            stdout,
            stderr,
            census,
            account_intent,
            account_readback,
            group_readback,
            external_intent,
            external_image,
            external_live,
            external_at_refusal,
            external_retired,
            reservation_intent,
            reservation_live,
            reservation_retired,
            alias_policy,
            alias_invocation,
            alias_exit,
            alias_stderr,
            restoration,
            restoration_policy,
            restoration_invocation,
            restoration_exit,
            restoration_stderr,
        };
        let relative = prefix
            .join("case-evidence.json")
            .to_str()
            .ok_or_else(|| CiError::Message("account evidence archive path nonUTF8".into()))?
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
