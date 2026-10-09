//! Original measured recovery image custody; reconstruction never builds.
use super::{artifacts, native_component_harness::MeasuredHarness};
use crate::{CiError, Result, consumer_readiness_ledger::SourceIdentity};
use memcordon_readiness_verifier::ProductKey;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryHarnessOwner {
    pub format: String,
    pub revision: u32,
    pub identity: SourceIdentity,
    pub cell: ProductKey,
    pub scope_id: String,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
    pub owner_path: PathBuf,
    pub executable: PathBuf,
    pub sha256: String,
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub mode: u32,
    pub compiler_output: PathBuf,
    pub compiler_output_sha256: String,
    pub compiler_errors: PathBuf,
    pub compiler_errors_sha256: String,
    pub acquisition_records: Vec<(PathBuf, String, u64)>,
}

pub fn acquisition_artifacts(root: &Path, directory: &Path) -> Result<serde_json::Value> {
    let mut references = serde_json::Map::new();
    for leaf in [
        "owner.json",
        "cargo-output.jsonl",
        "cargo-stderr.bin",
        "acquisition-0.bin",
        "acquisition-1.bin",
        "acquisition-2.bin",
        "acquisition-3.bin",
        "acquisition-4.bin",
    ] {
        let path = directory.join(leaf);
        let _ = held_bytes(
            &path,
            if leaf == "acquisition-2.bin" {
                512 * 1024 * 1024
            } else {
                16 * 1024 * 1024
            },
        )?;
        let relative = path
            .strip_prefix(root)
            .map_err(|error| CiError::Message(error.to_string()))?;
        references.insert(
            leaf.into(),
            serde_json::Value::String(
                relative
                    .to_str()
                    .ok_or_else(|| {
                        CiError::Message("recovery acquisition artifact path is not UTF-8".into())
                    })?
                    .into(),
            ),
        );
    }
    Ok(serde_json::Value::Object(references))
}

pub struct HeldRecoveryHarness {
    owner: RecoveryHarnessOwner,
    owner_sha256: String,
    harness: MeasuredHarness,
    image: File,
    _ancestry: Vec<File>,
}

pub fn protected_directory(path: &Path) -> Result<Vec<File>> {
    if !path.is_absolute() {
        return Err(CiError::Message(
            "native component controller path must be absolute".into(),
        ));
    }
    let mut current = PathBuf::from("/");
    let mut held = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => (),
            std::path::Component::Normal(name) => current.push(name),
            _ => {
                return Err(CiError::Message(
                    "native component controller path is not normalized".into(),
                ));
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&current)?;
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "native component controller ancestry is not protected administrator custody"
                    .into(),
            ));
        }
        held.push(file);
    }
    Ok(held)
}

fn held_bytes(path: &Path, limit: u64) -> Result<(File, Vec<u8>)> {
    held_source_bytes(path, limit, true)
}

fn held_source_bytes(path: &Path, limit: u64, require_root: bool) -> Result<(File, Vec<u8>)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || (require_root && before.uid() != 0)
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() > limit
    {
        return Err(CiError::Message(
            "original recovery artifact custody differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.try_clone()?.take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    let stamp = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    if bytes.len() as u64 != before.len()
        || stamp(&before) != stamp(&after)
        || stamp(&after) != stamp(&named)
        || named.file_type().is_symlink()
    {
        return Err(CiError::Message(
            "original recovery artifact changed during held read".into(),
        ));
    }
    Ok((file, bytes))
}

fn create_record(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(
        path.parent()
            .ok_or_else(|| CiError::Message("recovery artifact parent absent".into()))?,
    )?
    .sync_all()?;
    Ok(())
}

impl HeldRecoveryHarness {
    pub fn acquire(
        existing: &MeasuredHarness,
        identity: &SourceIdentity,
        cell: &ProductKey,
        scope_id: &str,
        work: u64,
        cleanup: u64,
        owner_path: &Path,
    ) -> Result<Self> {
        let parent = owner_path
            .parent()
            .ok_or_else(|| CiError::Message("recovery owner parent absent".into()))?;
        let _ancestry = protected_directory(parent)?;
        let image_parent = existing
            .executable
            .parent()
            .ok_or_else(|| CiError::Message("recovery image parent absent".into()))?;
        let _image_ancestry = protected_directory(image_parent)?;
        let (image, bytes) = held_bytes(&existing.executable, 512 * 1024 * 1024)?;
        let metadata = image.metadata()?;
        if artifacts::checksum(&bytes) != existing.sha256 || metadata.mode() & 0o7777 != 0o555 {
            return Err(CiError::Message(
                "recovery image differs from original measured role".into(),
            ));
        }
        let (_, output) = held_source_bytes(&existing.compiler_output, 16 * 1024 * 1024, false)?;
        let (_, errors) = held_source_bytes(&existing.compiler_errors, 16 * 1024 * 1024, false)?;
        if output.len() > 16 * 1024 * 1024 || errors.len() > 16 * 1024 * 1024 {
            return Err(CiError::Message(
                "recovery compiler capture exceeds bound".into(),
            ));
        }
        let compiler_output = parent.join("recovery-cargo-output.jsonl");
        let compiler_errors = parent.join("recovery-cargo-stderr.bin");
        create_record(&compiler_output, &output)?;
        create_record(&compiler_errors, &errors)?;
        let role = existing
            .compiler_output
            .parent()
            .ok_or_else(|| CiError::Message("original compiler role absent".into()))?;
        let acquisition = role
            .parent()
            .ok_or_else(|| CiError::Message("original compiler acquisition absent".into()))?;
        let mut acquisition_records = Vec::new();
        for (name, original, limit) in [
            (
                "recovery-cargo-status.json",
                role.join("cargo-status.json"),
                1024 * 1024,
            ),
            (
                "recovery-native-host.json",
                acquisition.join("native-host.json"),
                1024 * 1024,
            ),
            (
                "recovery-native-compiler.bin",
                acquisition.join("native-compiler.bin"),
                512 * 1024 * 1024,
            ),
            (
                "recovery-compiler-identity.stdout",
                acquisition.join("compiler-identity.stdout"),
                1024 * 1024,
            ),
            (
                "recovery-compiler-identity.stderr",
                acquisition.join("compiler-identity.stderr"),
                1024 * 1024,
            ),
        ] {
            let (_, bytes) = held_source_bytes(&original, limit, false)?;
            if bytes.len() as u64 > limit {
                return Err(CiError::Message(
                    "original recovery acquisition record exceeds bound".into(),
                ));
            }
            let path = parent.join(name);
            create_record(&path, &bytes)?;
            acquisition_records.push((path, artifacts::checksum(&bytes), limit));
        }
        let owner = RecoveryHarnessOwner {
            format: "memcordon.original-native-recovery-harness-owner".into(),
            revision: 1,
            identity: identity.clone(),
            cell: cell.clone(),
            scope_id: scope_id.into(),
            work_deadline_unix_millis: work,
            cleanup_deadline_unix_millis: cleanup,
            owner_path: owner_path.into(),
            executable: existing.executable.clone(),
            sha256: existing.sha256.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            mode: metadata.mode(),
            compiler_output,
            compiler_output_sha256: artifacts::checksum(&output),
            compiler_errors,
            compiler_errors_sha256: artifacts::checksum(&errors),
            acquisition_records,
        };
        create_record(owner_path, &serde_json::to_vec(&owner)?)?;
        Self::reconstruct(&owner, identity, cell, scope_id, work, cleanup)
    }

    pub fn reconstruct(
        owner: &RecoveryHarnessOwner,
        identity: &SourceIdentity,
        cell: &ProductKey,
        scope_id: &str,
        work: u64,
        cleanup: u64,
    ) -> Result<Self> {
        if owner.format != "memcordon.original-native-recovery-harness-owner"
            || owner.revision != 1
            || serde_json::to_value(&owner.identity)? != serde_json::to_value(identity)?
            || owner.cell != *cell
            || owner.scope_id != scope_id
            || owner.work_deadline_unix_millis != work
            || owner.cleanup_deadline_unix_millis != cleanup
            || work == 0
            || work >= cleanup
        {
            return Err(CiError::Message(
                "recovery harness original association differs".into(),
            ));
        }
        let parent = owner
            .owner_path
            .parent()
            .ok_or_else(|| CiError::Message("recovery owner parent absent".into()))?;
        if owner.compiler_output != parent.join("recovery-cargo-output.jsonl")
            || owner.compiler_errors != parent.join("recovery-cargo-stderr.bin")
            || !owner.executable.starts_with(parent)
        {
            return Err(CiError::Message(
                "recovery harness escapes original protected owner".into(),
            ));
        }
        let mut ancestry = protected_directory(parent)?;
        ancestry.extend(protected_directory(owner.executable.parent().ok_or_else(
            || CiError::Message("recovery image parent absent".into()),
        )?)?);
        let (_, owner_bytes) = held_bytes(&owner.owner_path, 1024 * 1024)?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&owner_bytes)
            .map_err(CiError::Message)?;
        let recorded: RecoveryHarnessOwner = serde_json::from_slice(&owner_bytes)?;
        if serde_json::to_vec(&recorded)? != serde_json::to_vec(owner)?
            || owner_bytes != serde_json::to_vec(owner)?
        {
            return Err(CiError::Message(
                "original recovery owner record differs".into(),
            ));
        }
        let (image, _) = held_bytes(&owner.executable, 512 * 1024 * 1024)?;
        let harness = MeasuredHarness {
            executable: owner.executable.clone(),
            sha256: owner.sha256.clone(),
            compiler_output: owner.compiler_output.clone(),
            compiler_errors: owner.compiler_errors.clone(),
        };
        let value = Self {
            owner: owner.clone(),
            owner_sha256: artifacts::checksum(&owner_bytes),
            harness,
            image,
            _ancestry: ancestry,
        };
        value.verify()?;
        Ok(value)
    }

    pub fn owner(&self) -> &RecoveryHarnessOwner {
        &self.owner
    }
    /// Retain actual acquisition bytes before their original admin scope retires.
    pub fn retain_evidence(&self, destination: &Path) -> Result<()> {
        self.verify()?;
        fs::create_dir(destination)?;
        let mut projection = Vec::new();
        let mut entries = vec![
            (
                self.owner.owner_path.clone(),
                "owner.json".to_owned(),
                1024 * 1024,
            ),
            (
                self.owner.compiler_output.clone(),
                "cargo-output.jsonl".to_owned(),
                16 * 1024 * 1024,
            ),
            (
                self.owner.compiler_errors.clone(),
                "cargo-stderr.bin".to_owned(),
                16 * 1024 * 1024,
            ),
        ];
        for (index, (path, _, limit)) in self.owner.acquisition_records.iter().enumerate() {
            entries.push((path.clone(), format!("acquisition-{index}.bin"), *limit));
        }
        for (original, leaf, limit) in entries {
            let (_, bytes) = held_bytes(&original, limit)?;
            create_record(&destination.join(&leaf), &bytes)?;
            projection.push(serde_json::json!({"original":original,"artifact":leaf,"length":bytes.len(),"sha256":artifacts::checksum(&bytes)}));
        }
        self.verify()?;
        create_record(
            &destination.join("projection.json"),
            &serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.original-native-recovery-acquisition-projection","revision":1,"owner_sha256":self.owner_sha256()?,"records":projection}),
            )?,
        )
    }
    pub fn harness(&self) -> &MeasuredHarness {
        &self.harness
    }
    pub fn owner_sha256(&self) -> Result<String> {
        self.verify()?;
        Ok(self.owner_sha256.clone())
    }
    pub fn verify(&self) -> Result<()> {
        let owner_bytes = held_bytes(&self.owner.owner_path, 1024 * 1024)?.1;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&owner_bytes)
            .map_err(CiError::Message)?;
        let recorded: RecoveryHarnessOwner = serde_json::from_slice(&owner_bytes)?;
        if artifacts::checksum(&owner_bytes) != self.owner_sha256
            || serde_json::to_vec(&recorded)? != serde_json::to_vec(&self.owner)?
        {
            return Err(CiError::Message(
                "held recovery owner record changed".into(),
            ));
        }
        let metadata = self.image.metadata()?;
        let (named_image, bytes) = held_bytes(&self.owner.executable, 512 * 1024 * 1024)?;
        let named = named_image.metadata()?;
        if (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mode(),
        ) != (
            self.owner.device,
            self.owner.inode,
            self.owner.length,
            self.owner.mode,
        ) || (named.dev(), named.ino(), named.len(), named.mode())
            != (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.mode(),
            )
            || metadata.mode() & 0o7777 != 0o555
            || artifacts::checksum(&bytes) != self.owner.sha256
        {
            return Err(CiError::Message(
                "held recovery image identity differs".into(),
            ));
        }
        for (path, expected) in [
            (
                &self.owner.compiler_output,
                &self.owner.compiler_output_sha256,
            ),
            (
                &self.owner.compiler_errors,
                &self.owner.compiler_errors_sha256,
            ),
        ] {
            if artifacts::checksum(&held_bytes(path, 16 * 1024 * 1024)?.1) != *expected {
                return Err(CiError::Message(
                    "held recovery compiler capture differs".into(),
                ));
            }
        }
        let parent = self
            .owner
            .owner_path
            .parent()
            .ok_or_else(|| CiError::Message("original recovery owner parent absent".into()))?;
        let mut current = protected_directory(parent)?;
        current.extend(protected_directory(
            self.owner
                .executable
                .parent()
                .ok_or_else(|| CiError::Message("original recovery image parent absent".into()))?,
        )?);
        if current.len() != self._ancestry.len()
            || current.iter().zip(&self._ancestry).any(|(named, held)| {
                match (named.metadata(), held.metadata()) {
                    (Ok(a), Ok(b)) => (a.dev(), a.ino()) != (b.dev(), b.ino()),
                    _ => true,
                }
            })
        {
            return Err(CiError::Message(
                "original recovery harness ancestry changed".into(),
            ));
        }
        let expected_names = [
            ("recovery-cargo-status.json", 1024 * 1024),
            ("recovery-native-host.json", 1024 * 1024),
            ("recovery-native-compiler.bin", 512 * 1024 * 1024),
            ("recovery-compiler-identity.stdout", 1024 * 1024),
            ("recovery-compiler-identity.stderr", 1024 * 1024),
        ];
        if self.owner.acquisition_records.len() != expected_names.len() {
            return Err(CiError::Message(
                "original recovery acquisition inventory differs".into(),
            ));
        }
        for ((path, digest, limit), (name, expected_limit)) in
            self.owner.acquisition_records.iter().zip(expected_names)
        {
            if *path != parent.join(name)
                || *limit != expected_limit
                || artifacts::checksum(&held_bytes(path, *limit)?.1) != *digest
            {
                return Err(CiError::Message(
                    "original recovery acquisition record differs".into(),
                ));
            }
        }
        let json = |name: &str| -> Result<serde_json::Value> {
            let bytes = held_bytes(&parent.join(name), 1024 * 1024)?.1;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                .map_err(CiError::Message)?;
            Ok(serde_json::from_slice(&bytes)?)
        };
        let status = json("recovery-cargo-status.json")?;
        if status["status"] != 0
            || status["package"] != "memcordon"
            || status["test"] != "sealed_agent"
            || status["target"] != self.owner.cell.target
            || status["features"] != "private-tcp,test-support"
        {
            return Err(CiError::Message(
                "recovery harness compiler selection differs".into(),
            ));
        }
        let host = json("recovery-native-host.json")?;
        let selected: super::source::BuildSourceIdentity =
            serde_json::from_value(host["source"].clone())?;
        selected.validate()?;
        if host["format"] != "memcordon.consumer-readiness.original-native-host"
            || host["revision"] != 1
            || host["target"] != self.owner.cell.target
            || selected.commit() != self.owner.identity.source_commit
            || selected.version().to_string() != self.owner.identity.version
            || host["compiler_sha256"] != self.owner.acquisition_records[2].1
        {
            return Err(CiError::Message(
                "recovery harness measured compiler/source association differs".into(),
            ));
        }
        Ok(())
    }
}
