//! Package observations from the original current installed controller.
use super::{
    artifacts,
    installed_consumer::{MaterializedPayload, binary_path},
    source,
};
use crate::{CiError, Result, readiness_identity::SourceIdentity};
use memcordon_readiness_verifier::{
    Artifact, CaseKey, CaseRecord, CaseState, EvidenceClass, ProductKey, current::CaseEvidenceV2,
};
use std::{fs, path::Path};

/// Publish only a hard link to a previously held, persisted fixture inode.
/// The unknown bytes are an installer negative, never a provider descriptor.
pub(super) fn publish_opaque(
    owner: &mut serde_json::Value,
    lifetime: &Path,
    admin: &Path,
) -> Result<Vec<u8>> {
    use std::{
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let source_path = admin.join("opaque-install-fixture.bin");
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|error| CiError::Message(error.to_string()))?;
    let bytes = [b"opaque-current-install-fixture\0".as_slice(), &nonce].concat();
    let mut source_file = fs::OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&source_path)?;
    source_file.write_all(&bytes)?;
    source_file.sync_all()?;
    let metadata = source_file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.nlink() != 1 {
        return Err(CiError::Message(
            "opaque fixture native source custody differs".into(),
        ));
    }
    owner["opaque_install_fixture"] = serde_json::json!({"source":source_path,"target":"/usr/libexec/memcordon-sealed-agent","device":metadata.dev(),"inode":metadata.ino(),"sha256":artifacts::checksum(&bytes),"length":bytes.len(),"retired":false});
    source::write_json(&lifetime.join("current-owner.json"), owner)?;
    fs::hard_link(&source_path, "/usr/libexec/memcordon-sealed-agent")?;
    fs::File::open("/usr/libexec")?.sync_all()?;
    Ok(bytes)
}

/// Recover only the exact current fixture inode. An unrelated occupied target
/// is retained even if its pathname or contents resemble this experiment.
pub(super) fn retire_opaque(
    owner: &mut serde_json::Value,
    lifetime: &Path,
) -> Result<serde_json::Value> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let probe = &owner["opaque_install_fixture"];
    if probe.is_null() || probe["retired"] == true {
        return Ok(serde_json::Value::Null);
    }
    let source_path = probe["source"]
        .as_str()
        .ok_or_else(|| CiError::Message("opaque fixture source missing".into()))?;
    let source_path = Path::new(source_path);
    let admin = owner["admin"]
        .as_str()
        .ok_or_else(|| CiError::Message("current native admin root absent".into()))?;
    if source_path != Path::new(admin).join("opaque-install-fixture.bin")
        || probe["target"] != "/usr/libexec/memcordon-sealed-agent"
    {
        return Err(CiError::Message(
            "opaque fixture path is not the original finite native role".into(),
        ));
    }
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(admin)?;
    let root_metadata = root.metadata()?;
    if root_metadata.uid() != 0
        || root_metadata.mode() & 0o077 != 0
        || Some(root_metadata.dev()) != owner["admin_identity"]["device"].as_u64()
        || Some(root_metadata.ino()) != owner["admin_identity"]["inode"].as_u64()
    {
        return Err(CiError::Message(
            "opaque fixture original root custody differs".into(),
        ));
    }
    let held = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source_path)?;
    let source_metadata = held.metadata()?;
    if !source_metadata.is_file()
        || source_metadata.uid() != 0
        || source_metadata.mode() & 0o777 != 0o600
        || source_metadata.len() > 256
        || Some(source_metadata.dev()) != probe["device"].as_u64()
        || Some(source_metadata.ino()) != probe["inode"].as_u64()
        || Some(source_metadata.len()) != probe["length"].as_u64()
    {
        return Err(CiError::Message(
            "opaque fixture original inode custody differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    held.take(257).read_to_end(&mut bytes)?;
    if artifacts::checksum(&bytes)
        != probe["sha256"]
            .as_str()
            .ok_or_else(|| CiError::Message("opaque fixture hash missing".into()))?
    {
        return Err(CiError::Message("opaque fixture source changed".into()));
    }
    let target = Path::new("/usr/libexec/memcordon-sealed-agent");
    let observation = match fs::symlink_metadata(target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if source_metadata.nlink() != 1 {
                return Err(CiError::Message(
                    "opaque fixture has an unaccounted native link".into(),
                ));
            }
            serde_json::json!({"absent":true})
        }
        Err(error) => return Err(error.into()),
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 2
                || source_metadata.nlink() != 2
                || (metadata.dev(), metadata.ino())
                    != (source_metadata.dev(), source_metadata.ino())
            {
                return Err(CiError::Message(
                    "occupied target is not original held opaque fixture; retained".into(),
                ));
            }
            let target_file = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(target)?;
            let held_target = target_file.metadata()?;
            if (held_target.dev(), held_target.ino()) != (metadata.dev(), metadata.ino()) {
                return Err(CiError::Message(
                    "opaque target replaced during reacquisition".into(),
                ));
            }
            let mut after = Vec::new();
            target_file.take(257).read_to_end(&mut after)?;
            if after != bytes {
                return Err(CiError::Message(
                    "installer changed original opaque bytes".into(),
                ));
            }
            let named = fs::symlink_metadata(target)?;
            if (named.dev(), named.ino(), named.nlink()) != (metadata.dev(), metadata.ino(), 2) {
                return Err(CiError::Message(
                    "opaque target changed before owned retirement".into(),
                ));
            }
            fs::remove_file(target)?;
            fs::File::open("/usr/libexec")?.sync_all()?;
            serde_json::json!({"path":target,"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),"mode":metadata.mode(),"links":metadata.nlink(),"before":bytes,"after":after,"owned_link_retired":true})
        }
    };
    owner["opaque_install_fixture"]["retired"] = true.into();
    source::write_json(&lifetime.join("current-owner.json"), owner)?;
    Ok(observation)
}

pub(super) fn retain(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    inventory: &mut Vec<Artifact>,
) -> Result<String> {
    source::write_json(path, &serde_json::from_slice::<serde_json::Value>(bytes)?)?;
    let actual = fs::read(path)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|e| CiError::Message(e.to_string()))?
        .to_str()
        .ok_or_else(|| CiError::Message("package artifact path not UTF-8".into()))?
        .to_owned();
    inventory.push(Artifact {
        path: relative.clone(),
        length: actual.len() as u64,
        sha256: artifacts::checksum(&actual),
    });
    Ok(relative)
}

pub(super) fn retain_raw(
    root: &Path,
    path: &Path,
    bytes: &[u8],
    inventory: &mut Vec<Artifact>,
) -> Result<String> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let relative = path
        .strip_prefix(root)
        .map_err(|e| CiError::Message(e.to_string()))?
        .to_str()
        .ok_or_else(|| CiError::Message("package raw path not UTF-8".into()))?
        .to_owned();
    inventory.push(Artifact {
        path: relative.clone(),
        length: bytes.len() as u64,
        sha256: artifacts::checksum(bytes),
    });
    Ok(relative)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Original package operations retain actual source, lease and artifact custody"
)]
pub fn emit(
    root: &Path,
    payload: &MaterializedPayload,
    identity: &SourceIdentity,
    key: &ProductKey,
    lease_id: &str,
    lifetime: &Path,
    artifact_root: &Path,
    fixture_source: &str,
    operation_count: u64,
    inventory: &mut Vec<Artifact>,
) -> Result<Vec<CaseRecord>> {
    let fixture_path = lifetime.join("package-fixture.bin");
    let fixture_bytes = artifacts::read_file(&binary_path(
        &payload.directory,
        "memcordon-sealed-agent",
        &key.target,
    ))?;
    use std::io::Write;
    let mut fixture = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&fixture_path)?;
    fixture.write_all(&fixture_bytes)?;
    fixture.sync_all()?;
    let fixture_path = fixture_path
        .strip_prefix(artifact_root)
        .map_err(|e| CiError::Message(e.to_string()))?
        .to_str()
        .ok_or_else(|| CiError::Message("package fixture path not UTF-8".into()))?
        .to_owned();
    let fixture_sha256 = artifacts::checksum(&fixture_bytes);
    inventory.push(Artifact {
        path: fixture_path.clone(),
        length: fixture_bytes.len() as u64,
        sha256: fixture_sha256.clone(),
    });
    let absence = lifetime.join("native-absence.json");
    let absence = absence
        .strip_prefix(artifact_root)
        .map_err(|e| CiError::Message(e.to_string()))?
        .to_str()
        .ok_or_else(|| CiError::Message("package absence path not UTF-8".into()))?
        .to_owned();
    let mut operations = std::collections::BTreeMap::new();
    for ordinal in 0..operation_count {
        let path = lifetime.join(format!("root-operation-{ordinal}.json"));
        let bytes = fs::read(&path)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let relative = path
            .strip_prefix(artifact_root)
            .map_err(|e| CiError::Message(e.to_string()))?
            .to_str()
            .ok_or_else(|| CiError::Message("native operation path not UTF-8".into()))?
            .to_owned();
        inventory.push(Artifact {
            path: relative.clone(),
            length: bytes.len() as u64,
            sha256: artifacts::checksum(&bytes),
        });
        if value["executable_sha256"] != fixture_sha256 || value["arguments"][0] != "package" {
            continue;
        }
        let Some(operation) = value["arguments"][1].as_str() else {
            continue;
        };
        if value["completed"]["status"] == 0 {
            if operations.insert(operation.to_owned(), relative).is_some() {
                return Err(CiError::Message(
                    "duplicate successful package phase in original lifetime".into(),
                ));
            }
        }
    }
    let mut records = Vec::new();
    let interruption_path = lifetime.join("current-install-interruption-retained.json");
    let interruption = match fs::read(&interruption_path) {
        Ok(bytes) => {
            let native: serde_json::Value = serde_json::from_slice(&bytes)?;
            let operation = native["operation"].as_str().ok_or_else(|| {
                CiError::Message("current interruption original operation absent".into())
            })?;
            operations.insert("interrupted-current".into(), operation.into());
            Some(
                interruption_path
                    .strip_prefix(artifact_root)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .to_str()
                    .ok_or_else(|| {
                        CiError::Message("current interruption artifact path invalid".into())
                    })?
                    .to_owned(),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let opaque_path = lifetime.join("opaque-install-native.json");
    let opaque = match fs::read(&opaque_path) {
        Ok(bytes) => {
            let value: serde_json::Value = serde_json::from_slice(&bytes)?;
            let operation = value["operation"]
                .as_str()
                .ok_or_else(|| CiError::Message("original opaque operation receipt absent".into()))?
                .to_owned();
            operations.insert("opaque-install".into(), operation);
            Some(
                opaque_path
                    .strip_prefix(artifact_root)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .to_str()
                    .ok_or_else(|| CiError::Message("opaque artifact path not UTF-8".into()))?
                    .to_owned(),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    for (family, scenario, selection, operation) in [
        ("C-PACKAGE", "fresh-install", "install", "install"),
        ("C-PACKAGE", "verify", "verify", "verify"),
        ("C-PACKAGE", "upgrade", "upgrade", "upgrade"),
        ("C-PACKAGE", "final-uninstall", "uninstall", "uninstall"),
        (
            "C-INSTALL-CURRENT",
            "interrupted-current-install",
            "interrupted-current",
            "upgrade",
        ),
        (
            "C-INSTALL-CURRENT",
            "current-recovery",
            "upgrade",
            "upgrade",
        ),
        (
            "C-INSTALL-CURRENT",
            "fresh-without-registry",
            "install",
            "install",
        ),
        (
            "C-INSTALL-CURRENT",
            "current-reinstall",
            "upgrade",
            "upgrade",
        ),
        (
            "C-INSTALL-CURRENT",
            "owned-current-uninstall",
            "uninstall",
            "uninstall",
        ),
        (
            "C-INSTALL-CURRENT",
            "opaque-state-refused",
            "opaque-install",
            "install",
        ),
    ] {
        let Some(invocation) = operations.get(selection) else {
            continue;
        };
        let captured: serde_json::Value = source::read_json(&artifact_root.join(invocation))?;
        let stdout: Vec<u8> = serde_json::from_value(captured["completed"]["stdout"].clone())?;
        let stderr: Vec<u8> = serde_json::from_value(captured["completed"]["stderr"].clone())?;
        let stdout = retain_raw(
            artifact_root,
            &lifetime.join(format!("package-{scenario}.stdout.bin")),
            &stdout,
            inventory,
        )?;
        let stderr = retain_raw(
            artifact_root,
            &lifetime.join(format!("package-{scenario}.stderr.bin")),
            &stderr,
            inventory,
        )?;
        let case_key = CaseKey {
            target: key.target.clone(),
            channel: Some(key.channel.clone()),
            family: family.into(),
            scenario: scenario.into(),
            evidence_class: EvidenceClass::InstalledProduct,
        };
        let input = serde_json::json!({"format":"memcordon.linux-current-package-input","revision":1,"run_id":identity.run_id,"key":case_key,"lease_id":lease_id,"operation":operation,"operation_receipt":invocation});
        let input_bytes = serde_json::to_vec(&input)?;
        let input_path = retain(
            artifact_root,
            &lifetime.join(format!("package-{scenario}-input.json")),
            &input_bytes,
            inventory,
        )?;
        let actual_input = fs::read(artifact_root.join(&input_path))?;
        let evidence = CaseEvidenceV2 {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 2,
            key: case_key.clone(),
            run_id: identity.run_id.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            lease_id: Some(lease_id.into()),
            fixture: fixture_path.clone(),
            fixture_source: fixture_source.into(),
            fixture_sha256: fixture_sha256.clone(),
            fixture_source_sha256: identity.source_tree_sha256.clone(),
            input: input_path,
            input_sha256: artifacts::checksum(&actual_input),
            invocation: invocation.clone(),
            request: None,
            raw_result: None,
            attempt_observation: None,
            authenticated_terminal: None,
            recovery: None,
            stdout,
            stderr,
            outputs: Vec::new(),
            native_observation: if scenario == "interrupted-current-install" {
                interruption
                    .clone()
                    .expect("actual interruption capture retained")
            } else if scenario == "current-recovery" {
                lifetime
                    .join("current-recovery-readback.json")
                    .strip_prefix(artifact_root)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .to_str()
                    .ok_or_else(|| {
                        CiError::Message("current recovery artifact path invalid".into())
                    })?
                    .into()
            } else if scenario == "fresh-without-registry" {
                lifetime
                    .join("current-fresh-install-before.json")
                    .strip_prefix(artifact_root)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .to_str()
                    .ok_or_else(|| CiError::Message("fresh install proof path not UTF-8".into()))?
                    .into()
            } else if scenario == "current-reinstall" {
                lifetime
                    .join("installed-upgrade-readback.json")
                    .strip_prefix(artifact_root)
                    .map_err(|error| CiError::Message(error.to_string()))?
                    .to_str()
                    .ok_or_else(|| {
                        CiError::Message("current reinstall proof path not UTF-8".into())
                    })?
                    .into()
            } else if selection == "opaque-install" {
                opaque.clone().expect("original opaque proof retained")
            } else {
                invocation.clone()
            },
            retirement: absence.clone(),
            semantic_observation: if selection == "opaque-install" {
                opaque.clone().expect("original opaque proof retained")
            } else {
                invocation.clone()
            },
            component_recipe_id: None,
        };
        memcordon_readiness_verifier::current::linux_package::verify_observed(
            &evidence,
            &input,
            &|path| fs::read(artifact_root.join(path)).map_err(|e| e.to_string()),
        )
        .map_err(CiError::Message)?;
        let case = retain(
            artifact_root,
            &lifetime.join(format!("package-{scenario}-case.json")),
            &serde_json::to_vec(&evidence)?,
            inventory,
        )?;
        records.push(CaseRecord {
            key: case_key,
            run_id: identity.run_id.clone(),
            state: CaseState::Passed,
            reason: None,
            evidence: Some(case),
        });
    }
    let _ = root;
    Ok(records)
}
