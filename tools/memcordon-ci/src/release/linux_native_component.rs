//! Retained native ownership for root-only component harness recipes.
#![cfg(target_os = "linux")]
use super::{artifacts, native_component_harness::MeasuredHarness, source};
use crate::{CiError, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Child, Stdio},
    thread::JoinHandle,
    time::Instant,
};

pub struct NativeTestOwner {
    _ancestry: Vec<File>,
    publications: std::collections::BTreeMap<String, NativePublication>,
    native_quiescent: bool,
    child: Child,
    pidfd: Option<std::os::fd::OwnedFd>,
    image: File,
    process_id: u32,
    birth: Option<u64>,
    output: PathBuf,
    stdout: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    stdout_bytes: Option<Vec<u8>>,
    stderr_bytes: Option<Vec<u8>>,
    capture_failure: Option<String>,
    status: Option<std::process::ExitStatus>,
    image_sha256: String,
    input_delivered: bool,
    delivery_started: bool,
    admission_refusal: Option<Vec<u8>>,
    admission_refused: bool,
    crash_helpers: Vec<(
        memcordon_core::execution_facts::NativeProcessV2,
        std::os::fd::OwnedFd,
        File,
        bool,
    )>,
    crash_failures: Vec<String>,
}

struct NativePublication {
    file: File,
    bytes: Vec<u8>,
    staged: PathBuf,
    published: PathBuf,
    renamed: bool,
    settled: bool,
}

/// The original native producer keeps this administrator scope through native
/// invocation, evidence copying, and exact source retirement. There is no Drop
/// cleanup: a failed retirement leaves the same held inode available to retry.
pub struct NativeAdminScope {
    path: PathBuf,
    root: File,
    ancestry: Vec<File>,
    batch: Option<NativeRecipeBatch>,
    recovered: Vec<std::os::fd::OwnedFd>,
    recovery_images: Vec<File>,
    recovery_image_identities: Vec<(u64, u64)>,
    settlement_publication: Option<NativePublication>,
}

impl NativeAdminScope {
    /// Publish the source-bound allocation intent before allocating a recipe
    /// directory. A retry never adopts an existing directory as a fresh scope.
    pub fn allocate_owned_scope(
        workspace: &Path,
        identity: &crate::readiness_identity::SourceIdentity,
        target: &str,
        recipe_id: &str,
        artifact_prefix: &str,
        work: u64,
        cleanup: u64,
    ) -> Result<Self> {
        use rustix::fs::{Mode, OFlags, RenameFlags, mkdirat, openat, renameat_with};
        use std::os::unix::fs::OpenOptionsExt;
        if rustix::process::geteuid().as_raw() != 0
            || !workspace.is_absolute()
            || recipe_id.is_empty()
            || artifact_prefix.is_empty()
            || cleanup.checked_sub(work) != Some(15 * 60 * 1000)
        {
            return Err(CiError::Message(
                "original native administrator allocation association differs".into(),
            ));
        }
        let parent_path = Path::new("/var/lib");
        let mut ancestry = protected_directory(parent_path)?;
        let parent = ancestry
            .pop()
            .ok_or_else(|| CiError::Message("native administrator parent absent".into()))?;
        match mkdirat(
            &parent,
            "memcordon-native-readiness",
            Mode::from_bits_truncate(0o700),
        ) {
            Ok(()) => parent.sync_all()?,
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
        let base = File::from(
            openat(
                &parent,
                "memcordon-native-readiness",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?,
        );
        let metadata = base.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err(CiError::Message(
                "native administrator namespace differs".into(),
            ));
        }
        let association = serde_json::json!({"format":"memcordon.consumer-readiness.native-admin-intent","revision":1,
            "workspace":workspace,"identity":identity,"target":target,"recipe_id":recipe_id,"artifact_prefix":artifact_prefix,
            "work_deadline_unix_millis":work,"cleanup_deadline_unix_millis":cleanup});
        let bytes = serde_json::to_vec(&association)?;
        let key = artifacts::checksum(&bytes);
        let base_path = parent_path.join("memcordon-native-readiness");
        let staged = format!("{key}.intent-pending");
        let published = format!("{key}.intent.json");
        let mut intent = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(base_path.join(&staged))?;
        intent.write_all(&bytes)?;
        intent.sync_all()?;
        renameat_with(&base, &staged, &base, &published, RenameFlags::NOREPLACE)
            .map_err(std::io::Error::from)?;
        base.sync_all()?;
        mkdirat(&base, key.as_str(), Mode::from_bits_truncate(0o700))
            .map_err(std::io::Error::from)?;
        base.sync_all()?;
        let path = base_path.join(&key);
        let held = File::from(
            openat(
                &base,
                key.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?,
        );
        let native = held.metadata()?;
        // This exact inode is recorded before any harness copy or process spawn.
        let receipt = serde_json::json!({"format":"memcordon.consumer-readiness.native-admin-owner","revision":1,
            "intent_sha256":key,"association":association,"path":path,"device":native.dev(),"inode":native.ino()});
        let owner_staged = format!("{key}.owner-pending");
        let owner_published = format!("{key}.owner.json");
        let mut owner = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(base_path.join(&owner_staged))?;
        owner.write_all(&serde_json::to_vec(&receipt)?)?;
        owner.sync_all()?;
        renameat_with(
            &base,
            &owner_staged,
            &base,
            &owner_published,
            RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        base.sync_all()?;
        Self::acquire(&path, native.dev(), native.ino())
    }
    /// The outer journal allocates and records this inode before acquisition.
    /// This constructor performs no mutation and cannot manufacture ownership
    /// from a directory pathname alone.
    pub fn acquire(path: &Path, device: u64, inode: u64) -> Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(CiError::Message(
                "native administrator controller differs".into(),
            ));
        }
        let ancestry = protected_directory(path)?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = root.metadata()?;
        if metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o700
            || (metadata.dev(), metadata.ino()) != (device, inode)
        {
            return Err(CiError::Message(
                "recorded native administrator scope differs".into(),
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            root,
            ancestry,
            batch: None,
            recovered: Vec::new(),
            recovery_images: Vec::new(),
            recovery_image_identities: Vec::new(),
            settlement_publication: None,
        })
    }

    /// Reacquire only the original protected image namespace. This restores
    /// cleanup obligations, never lost captures, exit status, or test evidence.
    /// Current recipes acquire actual test children directly. No historical
    /// policy registry, grant, account fixture or installed package is acquired.
    #[expect(
        clippy::too_many_arguments,
        reason = "Original native allocation and phase cutoffs remain explicit"
    )]
    pub fn execute_current_recipes(
        &mut self,
        parser: &MeasuredHarness,
        operational: &MeasuredHarness,
        run_id: &str,
        recipe_id: &str,
        allocation_recipe_id: &str,
        target: &str,
        prefix: &str,
        work: Instant,
        cleanup: Instant,
        work_unix: u64,
        cleanup_unix: u64,
    ) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        self.verify_named()?;
        if self.batch.is_some()
            || work > cleanup
            || Instant::now() >= work
            || target != super::distribution::native_target()?
            || !parser.executable.starts_with(self.path.join("parser"))
            || !operational
                .executable
                .starts_with(self.path.join("operational"))
        {
            return Err(CiError::Message(
                "current native recipe allocation, role or cutoff differs".into(),
            ));
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| CiError::Message("native scope parent absent".into()))?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CiError::Message("native scope name absent".into()))?;
        let intent_bytes = crate::linux_consumer_readiness::measured(
            &parent.join(format!("{name}.intent.json")),
            65536,
        )
        .map_err(CiError::Message)?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&intent_bytes)
            .map_err(CiError::Message)?;
        let intent: serde_json::Value = serde_json::from_slice(&intent_bytes)?;
        if artifacts::checksum(&intent_bytes) != name
            || !super::native_execution_association::matches(
                &intent,
                &super::native_execution_association::Allocation {
                    run_id,
                    recipe_id: allocation_recipe_id,
                    target,
                    artifact_prefix: prefix,
                    work_deadline: work_unix,
                    cleanup_deadline: cleanup_unix,
                },
            )
        {
            return Err(CiError::Message(
                "current native recipe differs from held original allocation".into(),
            ));
        }
        for (role, parser) in [("parser", parser), ("operational", operational)] {
            let metadata = fs::symlink_metadata(&parser.executable)?;
            let expected = serde_json::to_vec(
                &serde_json::json!({"format":"memcordon.consumer-readiness.native-image-owner","revision":1,
            "role":role,"path":parser.executable,"device":metadata.dev(),"inode":metadata.ino(),"sha256":parser.sha256}),
            )?;
            if crate::linux_consumer_readiness::measured(
                &parent.join(format!("{name}.{role}-image-owner.json")),
                65536,
            )
            .map_err(CiError::Message)?
                != expected
                || artifacts::checksum(
                    &crate::linux_consumer_readiness::measured(
                        &parser.executable,
                        512 * 1024 * 1024,
                    )
                    .map_err(CiError::Message)?,
                ) != parser.sha256
            {
                return Err(CiError::Message(
                    "current native parser differs from held measured image".into(),
                ));
            }
        }
        let mut intent = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.path.join("native-execution-intent.json"))?;
        intent.write_all(&serde_json::to_vec(&serde_json::json!({"format":"memcordon.consumer-readiness.native-execution-intent","revision":2,
            "run_id":run_id,"recipe_id":recipe_id,"target":target,"artifact_prefix":prefix}))?)?;
        intent.sync_all()?;
        let output = self.path.join("recipes");
        fs::DirBuilder::new().mode(0o700).create(&output)?;
        self.root.sync_all()?;
        let mut batch = NativeRecipeBatch {
            failures: Vec::new(),
            owners: Vec::new(),
        };
        for (parser, test, name) in [
            (parser, "emit_current_parser_mutations", "current-parser"),
            (
                parser,
                "current_version_vectors::emit_current_request_result_vectors",
                "current-versions",
            ),
            (
                operational,
                "native_current_filter::current_filter_vectors_emit_actual_component_receipts",
                "current-filter",
            ),
            (
                operational,
                "protocol_tests::unsupported_current_wire_versions_emit_actual_receipt",
                "current-wire",
            ),
        ] {
            if Instant::now() >= work {
                batch
                    .failures
                    .push(format!("{test}: original work cutoff exhausted"));
                break;
            }
            let directory = output.join(name);
            let mut challenge = [0u8; 32];
            File::open("/dev/urandom")?.read_exact(&mut challenge)?;
            let mut input = serde_json::json!({"run_id":run_id,"recipe_id":recipe_id,
                "native_target":target,"artifact_root":directory,"artifact_prefix":format!("{prefix}/{name}"),"challenge":challenge});
            if name == "current-wire" {
                input["work_deadline_unix_millis"] = serde_json::json!(work_unix);
                input["cleanup_deadline_unix_millis"] = serde_json::json!(cleanup_unix);
            }
            let input = serde_json::to_vec(&input)?;
            match NativeTestOwner::spawn(parser, test, &self.path, &directory) {
                Ok(mut owner) => {
                    if let Err(error) = owner.deliver(&input).and_then(|()| owner.finish(work)) {
                        batch.failures.push(format!("{test}: {error}"));
                        if let Err(error) = owner.stop() {
                            batch.failures.push(format!("{test}: stop: {error}"));
                        }
                        if let Err(error) = owner.finish(cleanup) {
                            batch.failures.push(format!("{test}: settlement: {error}"));
                        }
                    }
                    if !owner.all_native_publications_settled() {
                        batch.owners.push((test.into(), owner));
                    }
                }
                Err(failure) => {
                    batch.failures.push(format!("{test}: {}", failure.detail));
                    if let Some(owner) = failure.owner {
                        batch.settle_refused(test, owner, cleanup);
                    }
                }
            }
            if !batch.owners.is_empty() {
                break;
            }
        }
        self.batch = Some(batch);
        self.root.sync_all()?;
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Retains the exact original image, source identity, recipe and finite cleanup custody together"
    )]
    pub fn recover_owned_scope(
        workspace: &Path,
        identity: &crate::readiness_identity::SourceIdentity,
        target: &str,
        recipe_id: &str,
        prefix: &str,
        work: u64,
        cleanup: u64,
        deadline: Instant,
    ) -> Result<Self> {
        let association = serde_json::json!({"format":"memcordon.consumer-readiness.native-admin-intent","revision":1,
            "workspace":workspace,"identity":identity,"target":target,"recipe_id":recipe_id,"artifact_prefix":prefix,
            "work_deadline_unix_millis":work,"cleanup_deadline_unix_millis":cleanup});
        if cleanup.checked_sub(work) != Some(15 * 60 * 1000) {
            return Err(CiError::Message(
                "recovered original native deadlines differ".into(),
            ));
        }
        let bytes = serde_json::to_vec(&association)?;
        let key = artifacts::checksum(&bytes);
        let base = Path::new("/var/lib/memcordon-native-readiness");
        protected_directory(base)?;
        let read = |path: &Path| -> Result<Vec<u8>> {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
            {
                return Err(CiError::Message(
                    "original native protected record metadata differs".into(),
                ));
            }
            crate::linux_consumer_readiness::measured(path, 65536).map_err(CiError::Message)
        };
        if read(&base.join(format!("{key}.intent.json")))? != bytes {
            return Err(CiError::Message(
                "original native allocation intent differs".into(),
            ));
        }
        let owner_bytes = read(&base.join(format!("{key}.owner.json")))?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&owner_bytes)
            .map_err(CiError::Message)?;
        let owner: serde_json::Value = serde_json::from_slice(&owner_bytes)?;
        let device = owner["device"]
            .as_u64()
            .ok_or_else(|| CiError::Message("native owner device absent".into()))?;
        let inode = owner["inode"]
            .as_u64()
            .ok_or_else(|| CiError::Message("native owner inode absent".into()))?;
        let path = base.join(&key);
        if owner
            != serde_json::json!({"format":"memcordon.consumer-readiness.native-admin-owner","revision":1,
            "intent_sha256":key,"association":association,"path":path,"device":device,"inode":inode})
        {
            return Err(CiError::Message(
                "recovered native owner source/attempt association differs".into(),
            ));
        }
        let mut scope = Self::acquire(&path, device, inode)?;
        let settled_bytes = match read(&base.join(format!("{key}.native-settlement.json"))) {
            Ok(bytes) => Some(bytes),
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let expected_settlement = serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.consumer-readiness.native-admin-settlement","revision":1,"path":path,"device":device,"inode":inode,"native_owners_settled":true}),
        )?;
        if settled_bytes
            .as_ref()
            .is_some_and(|bytes| bytes != &expected_settlement)
        {
            return Err(CiError::Message(
                "original native settlement record differs".into(),
            ));
        }
        for role in ["parser", "operational"] {
            let image_path = path.join(role).join("native-test-harness");
            let recorded_path = base.join(format!("{key}.{role}-image-owner.json"));
            let recorded = match read(&recorded_path) {
                Ok(bytes) => Some(bytes),
                Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error),
            };
            if let Some(bytes) = &recorded {
                memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)
                    .map_err(CiError::Message)?;
                let record: serde_json::Value = serde_json::from_slice(bytes)?;
                let image_device = record["device"]
                    .as_u64()
                    .ok_or_else(|| CiError::Message("prepared image device absent".into()))?;
                let image_inode = record["inode"]
                    .as_u64()
                    .ok_or_else(|| CiError::Message("prepared image inode absent".into()))?;
                let hash = record["sha256"]
                    .as_str()
                    .ok_or_else(|| CiError::Message("prepared image hash absent".into()))?;
                if hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    || record
                        != serde_json::json!({"format":"memcordon.consumer-readiness.native-image-owner","revision":1,"role":role,"path":image_path,"device":image_device,"inode":image_inode,"sha256":hash})
                {
                    return Err(CiError::Message(
                        "original prepared image record differs".into(),
                    ));
                }
                scope
                    .recovery_image_identities
                    .push((image_device, image_inode));
            }
            let image = match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&image_path)
            {
                Ok(image) => image,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if settled_bytes.is_none()
                        && (recorded.is_some()
                            || path.join("native-execution-intent.json").exists())
                    {
                        return Err(CiError::Message(
                            "prepared native image disappeared without durable native settlement"
                                .into(),
                        ));
                    }
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            protected_directory(image_path.parent().expect("fixed native role parent"))?;
            let metadata = image.metadata()?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o555
            {
                return Err(CiError::Message(
                    "recovered original native image custody differs".into(),
                ));
            }
            if let Some(recorded) = recorded {
                let actual = serde_json::json!({"format":"memcordon.consumer-readiness.native-image-owner","revision":1,"role":role,"path":image_path,"device":metadata.dev(),"inode":metadata.ino(),"sha256":artifacts::checksum(&crate::linux_consumer_readiness::measured(&image_path,512*1024*1024).map_err(CiError::Message)?)});
                if recorded != serde_json::to_vec(&actual)? {
                    return Err(CiError::Message(
                        "prepared native image identity differs from original durable owner".into(),
                    ));
                }
            }
            scope.recovery_images.push(image);
        }
        for entry in fs::read_dir("/proc")? {
            if Instant::now() >= deadline {
                return Err(CiError::Message(
                    "native recovery original deadline exhausted".into(),
                ));
            }
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let image = match File::open(entry.path().join("exe")) {
                Ok(image) => image,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let native = image.metadata()?;
            if !scope
                .recovery_image_identities
                .contains(&(native.dev(), native.ino()))
                && !scope.recovery_images.iter().any(|held| {
                    held.metadata()
                        .is_ok_and(|held| (held.dev(), held.ino()) == (native.dev(), native.ino()))
                })
            {
                continue;
            }
            let before = birth(pid)?;
            let native_pid = rustix::process::Pid::from_raw(
                i32::try_from(pid)
                    .map_err(|_| CiError::Message("recovered native PID exceeds range".into()))?,
            )
            .ok_or_else(|| CiError::Message("recovered native PID absent".into()))?;
            let descriptor =
                rustix::process::pidfd_open(native_pid, rustix::process::PidfdFlags::empty())
                    .map_err(std::io::Error::from)?;
            let after = File::open(entry.path().join("exe"))?.metadata()?;
            if birth(pid)? != before || (after.dev(), after.ino()) != (native.dev(), native.ino()) {
                return Err(CiError::Message(
                    "recovered native image/birth changes during hold".into(),
                ));
            }
            scope.recovered.push(descriptor);
        }
        Ok(scope)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Retirement observation binds the complete original image and recipe custody"
    )]
    pub fn observe_retired_scope(
        workspace: &Path,
        identity: &crate::readiness_identity::SourceIdentity,
        target: &str,
        recipe_id: &str,
        prefix: &str,
        work: u64,
        cleanup: u64,
        receipt_path: &Path,
    ) -> Result<()> {
        let association = serde_json::json!({"format":"memcordon.consumer-readiness.native-admin-intent","revision":1,
            "workspace":workspace,"identity":identity,"target":target,"recipe_id":recipe_id,"artifact_prefix":prefix,
            "work_deadline_unix_millis":work,"cleanup_deadline_unix_millis":cleanup});
        if rustix::process::geteuid().as_raw() != 0
            || cleanup.checked_sub(work) != Some(15 * 60 * 1000)
        {
            return Err(CiError::Message(
                "retired original native association differs".into(),
            ));
        }
        let intent = serde_json::to_vec(&association)?;
        let key = artifacts::checksum(&intent);
        let base = Path::new("/var/lib/memcordon-native-readiness");
        let ancestry = protected_directory(base)?;
        let parent = ancestry
            .last()
            .ok_or_else(|| CiError::Message("retired native parent absent".into()))?;
        let read = |path: &Path| -> Result<Vec<u8>> {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
            {
                return Err(CiError::Message(
                    "original native retirement record metadata differs".into(),
                ));
            }
            crate::linux_consumer_readiness::measured(path, 65536).map_err(CiError::Message)
        };
        if read(&base.join(format!("{key}.intent.json")))? != intent {
            return Err(CiError::Message(
                "retired original native intent differs".into(),
            ));
        }
        let owner_bytes = read(&base.join(format!("{key}.owner.json")))?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&owner_bytes)
            .map_err(CiError::Message)?;
        let owner: serde_json::Value = serde_json::from_slice(&owner_bytes)?;
        let device = owner["device"]
            .as_u64()
            .ok_or_else(|| CiError::Message("retired owner device absent".into()))?;
        let inode = owner["inode"]
            .as_u64()
            .ok_or_else(|| CiError::Message("retired owner inode absent".into()))?;
        let path = base.join(&key);
        if owner
            != serde_json::json!({"format":"memcordon.consumer-readiness.native-admin-owner","revision":1,
            "intent_sha256":key,"association":association,"path":path,"device":device,"inode":inode})
        {
            return Err(CiError::Message(
                "retired original native owner differs".into(),
            ));
        }
        if !receipt_path.is_absolute() {
            return Err(CiError::Message(
                "native retirement receipt must be absolute".into(),
            ));
        }
        let mut receipt_ancestors = Vec::new();
        let mut ancestor_path = PathBuf::from("/");
        for component in receipt_path
            .parent()
            .ok_or_else(|| CiError::Message("native retirement receipt parent absent".into()))?
            .components()
        {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => ancestor_path.push(name),
                _ => {
                    return Err(CiError::Message(
                        "native retirement receipt ancestry not normalized".into(),
                    ));
                }
            }
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&ancestor_path)?;
            receipt_ancestors.push((ancestor_path.clone(), directory));
        }
        let mut held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(receipt_path)?;
        let metadata = held.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(CiError::Message(
                "prior native retirement receipt lacks original administrator custody".into(),
            ));
        }
        let mut bytes = Vec::new();
        (&mut held).take(65537).read_to_end(&mut bytes)?;
        let after = held.metadata()?;
        if bytes.len() > 65536
            || u64::try_from(bytes.len()).ok() != Some(metadata.len())
            || (
                after.dev(),
                after.ino(),
                after.len(),
                after.ctime(),
                after.ctime_nsec(),
            ) != (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
            || read(receipt_path)? != bytes
        {
            return Err(CiError::Message(
                "held original native retirement bytes differ from named readback".into(),
            ));
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
            .map_err(CiError::Message)?;
        let receipt: serde_json::Value = serde_json::from_slice(&bytes)?;
        let visited = receipt["visited_entries"]
            .as_u64()
            .filter(|count| *count <= 131072)
            .ok_or_else(|| {
                CiError::Message("retired native entry observation exceeds bound".into())
            })?;
        if receipt
            != serde_json::json!({"format":"memcordon.owned-readiness-admin-retirement","revision":1,
            "path":path,"device":device,"inode":inode,"native_root_links":0,"named_absent":true,"parent_synced":true,"visited_entries":visited})
        {
            return Err(CiError::Message(
                "prior native retirement receipt association differs".into(),
            ));
        }
        let named = fs::symlink_metadata(receipt_path)?;
        if (named.dev(), named.ino()) != (metadata.dev(), metadata.ino())
            || held.metadata()?.nlink() != 1
        {
            return Err(CiError::Message(
                "prior native retirement receipt named identity changes".into(),
            ));
        }
        for (path, original) in receipt_ancestors {
            let current = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            let old = original.metadata()?;
            let now = current.metadata()?;
            if (old.dev(), old.ino()) != (now.dev(), now.ino()) {
                return Err(CiError::Message(
                    "native retirement receipt named ancestor changes".into(),
                ));
            }
        }
        match rustix::fs::statat(parent, key.as_str(), rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err(CiError::Message("retired native scope reappears".into())),
        }
        parent.sync_all()?;
        Ok(())
    }

    pub(crate) fn verify_named(&self) -> Result<()> {
        let current = protected_directory(&self.path)?;
        if current.len() != self.ancestry.len() {
            return Err(CiError::Message(
                "native administrator ancestry changes".into(),
            ));
        }
        for (original, current) in self.ancestry.iter().zip(current) {
            let old = original.metadata()?;
            let now = current.metadata()?;
            if (old.dev(), old.ino()) != (now.dev(), now.ino()) {
                return Err(CiError::Message(
                    "native administrator named ancestor identity changes".into(),
                ));
            }
        }
        let named = fs::symlink_metadata(&self.path)?;
        let held = self.root.metadata()?;
        if !named.is_dir() || (named.dev(), named.ino()) != (held.dev(), held.ino()) {
            return Err(CiError::Message(
                "native administrator named root identity changes".into(),
            ));
        }
        Ok(())
    }

    pub fn identity(&self) -> Result<(PathBuf, u64, u64)> {
        let metadata = self.root.metadata()?;
        Ok((self.path.clone(), metadata.dev(), metadata.ino()))
    }

    pub fn prepare(&self, role: &str, harness: &MeasuredHarness) -> Result<MeasuredHarness> {
        use std::os::unix::fs::DirBuilderExt;
        self.verify_named()?;
        if !matches!(role, "parser" | "operational") || self.batch.is_some() {
            return Err(CiError::Message(
                "native role preparation changes active scope".into(),
            ));
        }
        let directory = self.path.join(role);
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        self.root.sync_all()?;
        let protected = protect_harness(harness, &directory)?;
        let metadata = fs::symlink_metadata(&protected.executable)?;
        let bytes = serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.consumer-readiness.native-image-owner","revision":1,"role":role,"path":protected.executable,"device":metadata.dev(),"inode":metadata.ino(),"sha256":protected.sha256}),
        )?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| CiError::Message("native scope parent absent".into()))?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CiError::Message("native scope name absent".into()))?;
        let mut record = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent.join(format!("{name}.{role}-image-owner.json")))?;
        record.write_all(&bytes)?;
        record.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(protected)
    }

    pub fn outputs(&self) -> &Path {
        &self.path
    }

    pub fn failures(&self) -> &[String] {
        self.batch
            .as_ref()
            .map_or(&[], |batch| batch.failures.as_slice())
    }

    pub fn settle(&mut self, deadline: Instant) -> Result<()> {
        let mut failures = Vec::new();
        if let Some(Err(error)) = self.batch.as_mut().map(|batch| batch.settle(deadline)) {
            failures.push(error.to_string());
        }
        for descriptor in &self.recovered {
            use rustix::event::{PollFd, PollFlags, Timespec};
            let mut signal_attempted = false;
            loop {
                let mut poll = [PollFd::new(descriptor, PollFlags::IN)];
                rustix::event::poll(
                    &mut poll,
                    Some(&Timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    }),
                )
                .map_err(std::io::Error::from)?;
                if poll[0]
                    .revents()
                    .intersects(PollFlags::ERR | PollFlags::NVAL)
                {
                    failures.push("recovered native pidfd observation failed".into());
                    break;
                }
                if poll[0].revents().intersects(PollFlags::IN | PollFlags::HUP) {
                    break;
                }
                if !signal_attempted {
                    signal_attempted = true;
                    match rustix::process::pidfd_send_signal(
                        descriptor,
                        rustix::process::Signal::KILL,
                    ) {
                        Err(error) if error != rustix::io::Errno::SRCH => {
                            failures.push(format!("recovered native signal failed: {error}"));
                        }
                        _ => {}
                    }
                }
                if Instant::now() >= deadline {
                    failures.push("recovered native original cleanup deadline exhausted".into());
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        if failures.is_empty() {
            self.require_recovered_images_absent(deadline)?;
            self.recovered.clear();
            Ok(())
        } else {
            Err(CiError::Message(failures.join("; ")))
        }
    }

    fn require_recovered_images_absent(&self, deadline: Instant) -> Result<()> {
        for entry in fs::read_dir("/proc")? {
            if Instant::now() >= deadline {
                return Err(CiError::Message(
                    "recovered helper observation deadline exhausted".into(),
                ));
            }
            let entry = entry?;
            if !entry.file_name().to_str().is_some_and(|name| {
                !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
            }) {
                continue;
            }
            match fs::metadata(entry.path().join("exe")) {
                Ok(native) => {
                    if self
                        .recovery_image_identities
                        .contains(&(native.dev(), native.ino()))
                    {
                        return Err(CiError::Message(
                            "recorded native image helper remains live".into(),
                        ));
                    }
                    for image in &self.recovery_images {
                        let held = image.metadata()?;
                        if (native.dev(), native.ino()) == (held.dev(), held.ino()) {
                            return Err(CiError::Message(
                                "recovered native image helper remains live".into(),
                            ));
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub fn retire(&mut self, deadline: Instant) -> Result<serde_json::Value> {
        if !self.recovered.is_empty()
            || self
                .batch
                .as_ref()
                .is_some_and(|batch| !batch.owners.is_empty())
        {
            return Err(CiError::Message(
                "native administrator scope retains process/capture/publication/package owners"
                    .into(),
            ));
        }
        self.require_recovered_images_absent(deadline)?;
        let metadata = self.root.metadata()?;
        if metadata.nlink() != 0 {
            self.verify_named()?;
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| CiError::Message("native scope parent absent".into()))?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| CiError::Message("native scope name absent".into()))?;
        let record = parent.join(format!("{name}.native-settlement.json"));
        let bytes = serde_json::to_vec(
            &serde_json::json!({"format":"memcordon.consumer-readiness.native-admin-settlement","revision":1,"path":self.path,"device":metadata.dev(),"inode":metadata.ino(),"native_owners_settled":true}),
        )?;
        if self.settlement_publication.is_none() {
            match crate::linux_consumer_readiness::measured(&record, 65536) {
                Ok(existing) => {
                    let native = fs::symlink_metadata(&record)?;
                    if !native.is_file()
                        || native.uid() != 0
                        || native.mode() & 0o7777 != 0o600
                        || native.nlink() != 1
                        || existing != bytes
                    {
                        return Err(CiError::Message(
                            "original native settlement retry differs".into(),
                        ));
                    }
                }
                Err(error)
                    if fs::symlink_metadata(&record)
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
                {
                    let staged = parent.join(format!("{name}.native-settlement-pending"));
                    let file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&staged)?;
                    self.settlement_publication = Some(NativePublication {
                        file,
                        bytes: bytes.clone(),
                        staged,
                        published: record.clone(),
                        renamed: false,
                        settled: false,
                    });
                    let _absent_read_error = error;
                }
                Err(error) => return Err(CiError::Message(error)),
            }
        }
        if let Some(publication) = &mut self.settlement_publication {
            use std::io::{Seek, SeekFrom};
            if publication.bytes != bytes {
                return Err(CiError::Message(
                    "owned native settlement bytes change".into(),
                ));
            }
            let named = fs::symlink_metadata(if publication.renamed {
                &publication.published
            } else {
                &publication.staged
            })?;
            let held = publication.file.metadata()?;
            if !named.is_file()
                || named.uid() != 0
                || named.mode() & 0o7777 != 0o600
                || held.nlink() != 1
                || (named.dev(), named.ino()) != (held.dev(), held.ino())
            {
                return Err(CiError::Message(
                    "owned native settlement inode changes".into(),
                ));
            }
            if !publication.renamed {
                publication.file.seek(SeekFrom::Start(0))?;
                publication.file.write_all(&bytes)?;
                publication.file.set_len(bytes.len() as u64)?;
                publication.file.sync_all()?;
                let directory = File::open(parent)?;
                rustix::fs::renameat_with(
                    &directory,
                    publication
                        .staged
                        .file_name()
                        .expect("fixed settlement stage"),
                    &directory,
                    publication
                        .published
                        .file_name()
                        .expect("fixed settlement name"),
                    rustix::fs::RenameFlags::NOREPLACE,
                )
                .map_err(std::io::Error::from)?;
                publication.renamed = true;
            }
            if crate::linux_consumer_readiness::measured(&record, 65536)
                .map_err(CiError::Message)?
                != bytes
            {
                return Err(CiError::Message(
                    "owned native settlement named bytes differ".into(),
                ));
            }
        }
        File::open(parent)?.sync_all()?;
        if Instant::now() >= deadline {
            return Err(CiError::Message(
                "native source retirement cutoff exhausted".into(),
            ));
        }
        super::linux_current_lease::retire_fixture_tree(
            &self.path,
            &serde_json::json!({"device":metadata.dev(),"inode":metadata.ino()}),
            deadline,
        )?;
        Ok(
            serde_json::json!({"format":"memcordon.native-source-retirement","revision":1,
            "path":self.path,"device":metadata.dev(),"inode":metadata.ino(),"absent":true}),
        )
    }
}

/// Actual selected native recipes retain their process owners until cleanup
/// observes settlement. A returned failure never drops an uncertain child.
pub struct NativeRecipeBatch {
    pub failures: Vec<String>,
    owners: Vec<(String, NativeTestOwner)>,
}

impl NativeRecipeBatch {
    pub fn settle(&mut self, deadline: Instant) -> Result<()> {
        let mut remaining = Vec::new();
        for (name, mut owner) in self.owners.drain(..) {
            if let Err(error) = owner.stop() {
                self.failures
                    .push(format!("{name}: native stop retry: {error}"));
            }
            if let Err(error) = owner.finish(deadline) {
                self.failures
                    .push(format!("{name}: native settlement retry: {error}"));
            }
            if !owner.all_native_publications_settled() {
                remaining.push((name, owner));
            }
        }
        self.owners = remaining;
        if !self.owners.is_empty() {
            return Err(CiError::Message(
                "native component process/capture ownership remains unresolved".into(),
            ));
        }
        Ok(())
    }

    fn settle_refused(
        &mut self,
        test: &str,
        mut owner: NativeTestOwner,
        deadline: Instant,
    ) -> bool {
        if let Err(error) = owner.stop() {
            self.failures
                .push(format!("{test}: refused native stop: {error}"));
        }
        if let Err(error) = owner.finish(deadline) {
            self.failures
                .push(format!("{test}: refused native settlement: {error}"));
        }
        if owner.all_native_publications_settled() {
            true
        } else {
            self.owners.push((test.to_owned(), owner));
            false
        }
    }
}

pub struct OwnedNativeTestFailure {
    pub detail: String,
    pub owner: Option<NativeTestOwner>,
}

fn birth(pid: u32) -> Result<u64> {
    let mut bytes = Vec::new();
    File::open(Path::new("/proc").join(pid.to_string()).join("stat"))?
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(CiError::Message(
            "native test proc identity exceeds bound".into(),
        ));
    }
    let stat = std::str::from_utf8(&bytes)
        .map_err(|_| CiError::Message("native test proc identity encoding differs".into()))?;
    let tail = stat
        .rsplit_once(") ")
        .ok_or_else(|| CiError::Message("native test proc identity malformed".into()))?
        .1;
    tail.split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| CiError::Message("native test birth unavailable".into()))
}

fn capture(reader: impl Read + Send + 'static) -> JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(std::io::Error::other(
                "native test stream exceeds capture bound",
            ));
        }
        Ok(bytes)
    })
}

pub(crate) fn protected_directory(path: &Path) -> Result<Vec<File>> {
    if !path.is_absolute() {
        return Err(CiError::Message(
            "native component path must be absolute".into(),
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
                    "native component path is not normalized".into(),
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
                "native component ancestry is not protected".into(),
            ));
        }
        held.push(file);
    }
    Ok(held)
}

/// Copy only measured bytes into the administrator's protected native scope;
/// no source permissions, links or extended attributes are inherited.
pub fn protect_harness(harness: &MeasuredHarness, destination: &Path) -> Result<MeasuredHarness> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(CiError::Message(
            "native harness protection requires its owned administrator".into(),
        ));
    }
    let ancestry = protected_directory(destination)?;
    let bytes = crate::linux_consumer_readiness::measured(&harness.executable, 512 * 1024 * 1024)
        .map_err(CiError::Message)?;
    if artifacts::checksum(&bytes) != harness.sha256 {
        return Err(CiError::Message(
            "actual native harness bytes changed before protected copy".into(),
        ));
    }
    let executable = destination.join("native-test-harness");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&executable)?;
    file.write_all(&bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o555))?;
    file.sync_all()?;
    let _readonly = super::native_executable::retain_readonly(&executable, file)?;
    ancestry
        .last()
        .ok_or_else(|| CiError::Message("native protection directory absent".into()))?
        .sync_all()?;
    if crate::linux_consumer_readiness::measured(&executable, 512 * 1024 * 1024)
        .map_err(CiError::Message)?
        != bytes
    {
        return Err(CiError::Message(
            "protected native harness named readback differs".into(),
        ));
    }
    Ok(MeasuredHarness {
        executable,
        sha256: harness.sha256.clone(),
        compiler_output: harness.compiler_output.clone(),
        compiler_errors: harness.compiler_errors.clone(),
    })
}

impl NativeTestOwner {
    /// The owner is returned even when setup fails after spawn. Its exact Child,
    /// pidfd and capture workers must remain with the outer phase owner.
    #[expect(
        clippy::result_large_err,
        reason = "Failure must return the original live Child, pidfd and capture owners for mandatory retirement"
    )]
    pub fn spawn(
        harness: &MeasuredHarness,
        test: &str,
        workspace: &Path,
        output: &Path,
    ) -> std::result::Result<Self, OwnedNativeTestFailure> {
        let before = (|| -> Result<_> {
            if !super::native_recipe_case::admitted(test) {
                return Err(CiError::Message(
                    "root-only native component recipe is not frozen".into(),
                ));
            }
            if rustix::process::geteuid().as_raw() != 0 {
                return Err(CiError::Message(
                    "native component observer requires the owned administrator controller".into(),
                ));
            }
            let mut ancestry = protected_directory(workspace)?;
            ancestry.extend(protected_directory(
                harness
                    .executable
                    .parent()
                    .ok_or_else(|| CiError::Message("native harness parent absent".into()))?,
            )?);
            ancestry.extend(protected_directory(output.parent().ok_or_else(|| {
                CiError::Message("native component output parent absent".into())
            })?)?);
            super::native_recipe_case::create(output)?;
            ancestry.extend(protected_directory(output)?);
            let image = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&harness.executable)?;
            let metadata = image.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != 0
                || metadata.mode() & 0o222 != 0
                || metadata.len() > 512 * 1024 * 1024
            {
                return Err(CiError::Message(
                    "native harness held image custody differs".into(),
                ));
            }
            let mut bytes = Vec::new();
            (&image)
                .take(512 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if artifacts::checksum(&bytes) != harness.sha256 {
                return Err(CiError::Message(
                    "native harness image differs before spawn".into(),
                ));
            }
            use std::os::unix::ffi::OsStrExt;
            source::write_json(
                &output.join("native-spawn-intent.json"),
                &serde_json::json!({
                "format":"memcordon.linux-native-test-invocation","revision":1,
                "program_bytes":harness.executable.as_os_str().as_bytes(),
                "argv_bytes":[b"--exact".as_slice(),test.as_bytes(),b"--ignored".as_slice(),b"--test-threads=1".as_slice()],
                "environment_cleared":true,"image_sha256":harness.sha256,"test_name":test}),
            )?;
            let child = std::process::Command::new(&harness.executable)
                .current_dir(workspace)
                .env_clear()
                .args(["--exact", test, "--ignored", "--test-threads=1"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            Ok((image, child, ancestry, metadata))
        })();
        let (image, mut child, ancestry, held_image) =
            before.map_err(|error| OwnedNativeTestFailure {
                detail: error.to_string(),
                owner: None,
            })?;
        let process_id = child.id();
        let stdout = child.stdout.take().map(capture);
        let stderr = child.stderr.take().map(capture);
        let mut owner = Self {
            _ancestry: ancestry,
            publications: Default::default(),
            native_quiescent: false,
            child,
            image,
            process_id,
            pidfd: None,
            birth: None,
            output: output.to_owned(),
            stdout,
            stderr,
            stdout_bytes: None,
            stderr_bytes: None,
            capture_failure: None,
            status: None,
            image_sha256: harness.sha256.clone(),
            input_delivered: false,
            delivery_started: false,
            admission_refusal: None,
            admission_refused: false,
            crash_helpers: Vec::new(),
            crash_failures: Vec::new(),
        };
        let mut refusal = serde_json::json!({
            "format":"memcordon.linux-native-test-admission-refusal","revision":1,
            "process_id":process_id,"test_name":test,"image_sha256":harness.sha256,
            "held_image":{"device":held_image.dev(),"inode":held_image.ino(),"size":held_image.len()},
            "observed_image":null,"birth_before":null,"birth_after":null,
            "image_mismatch":null,"birth_mismatch":null,
            "stage":"native-pid-range","input_delivered":false,"admission":false
        });
        let observed = (|| -> Result<()> {
            let pid =
                rustix::process::Pid::from_raw(i32::try_from(process_id).map_err(|_| {
                    CiError::Message("native harness PID exceeds native range".into())
                })?)
                .ok_or_else(|| CiError::Message("native harness PID absent".into()))?;
            refusal["stage"] = serde_json::json!("pidfd-open");
            owner.pidfd = Some(
                rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
                    .map_err(std::io::Error::from)?,
            );
            refusal["stage"] = serde_json::json!("birth-before");
            let observed_birth = birth(process_id)?;
            refusal["birth_before"] = serde_json::json!(observed_birth);
            refusal["stage"] = serde_json::json!("proc-executable-open");
            let executable_file =
                File::open(Path::new("/proc").join(process_id.to_string()).join("exe"))?;
            refusal["stage"] = serde_json::json!("proc-executable-metadata");
            let executable = executable_file.metadata()?;
            refusal["observed_image"] = serde_json::json!({"device":executable.dev(),"inode":executable.ino(),"size":executable.len()});
            refusal["stage"] = serde_json::json!("held-image-metadata");
            let image = owner.image.metadata()?;
            refusal["compared_held_image"] =
                serde_json::json!({"device":image.dev(),"inode":image.ino(),"size":image.len()});
            refusal["stage"] = serde_json::json!("birth-after");
            let final_birth = birth(process_id)?;
            refusal["birth_after"] = serde_json::json!(final_birth);
            let image_mismatch = (executable.dev(), executable.ino()) != (image.dev(), image.ino());
            let birth_mismatch = final_birth != observed_birth;
            refusal["image_mismatch"] = serde_json::json!(image_mismatch);
            refusal["birth_mismatch"] = serde_json::json!(birth_mismatch);
            refusal["stage"] = serde_json::json!("compare-held-image-and-birth");
            if image_mismatch || birth_mismatch {
                return Err(CiError::Message(
                    "native harness exec/birth differs from held selected image".into(),
                ));
            }
            owner.birth = Some(observed_birth);
            refusal["stage"] = serde_json::json!("pre-input-publication");
            source::write_json(
                &output.join("native-pre-input.json"),
                &serde_json::json!({"process_id":process_id,"birth":observed_birth,
                "image_sha256":harness.sha256,"held_before_input_delivery":true,"test_name":test}),
            )
        })();
        match observed {
            Ok(()) => Ok(owner),
            Err(error) => {
                let mut detail = error.to_string();
                owner.admission_refused = true;
                const ERROR_SAMPLE_LIMIT: usize = 4096;
                refusal["error_bytes"] = serde_json::json!(
                    detail
                        .as_bytes()
                        .iter()
                        .copied()
                        .take(ERROR_SAMPLE_LIMIT)
                        .collect::<Vec<_>>()
                );
                refusal["error_length"] = serde_json::json!(detail.len());
                refusal["pidfd_acquired"] = serde_json::json!(owner.pidfd.is_some());
                let publication = (|| -> Result<()> {
                    let bytes = serde_json::to_vec(&refusal)?;
                    if bytes.len() > 65536 {
                        return Err(CiError::Message(
                            "native admission refusal exceeds diagnostic bound".into(),
                        ));
                    }
                    owner.admission_refusal = Some(bytes.clone());
                    owner.publish_owned("native-admission-refusal.json", &bytes)
                })();
                if let Err(error) = publication {
                    detail.push_str(&format!("; native refusal publication: {error}"));
                }
                Err(OwnedNativeTestFailure {
                    detail,
                    owner: Some(owner),
                })
            }
        }
    }

    pub fn deliver(&mut self, request: &[u8]) -> Result<()> {
        if request.len() > 65536
            || self.pidfd.is_none()
            || self.birth.is_none()
            || self.delivery_started
        {
            return Err(CiError::Message(
                "native component input delivery lacks its unique pre-input owner".into(),
            ));
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(request)
            .map_err(CiError::Message)?;
        let mut recorded = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.output.join("native-input.json"))?;
        recorded.write_all(request)?;
        recorded.sync_all()?;
        File::open(&self.output)?.sync_all()?;
        self.delivery_started = true;
        let input = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| CiError::Message("native harness stdin missing".into()))?;
        input.write_all(request)?;
        input.flush()?;
        self.child.stdin.take();
        self.input_delivered = true;
        Ok(())
    }

    fn exited(&mut self) -> Result<bool> {
        use rustix::event::{PollFd, PollFlags, Timespec};
        let Some(fd) = self.pidfd.as_ref() else {
            // Setup can fail before pidfd acquisition. Only the original unreaped
            // Child may observe/reap this process; no PID lookup replaces it.
            if self.status.is_none() {
                self.status = self.child.try_wait()?;
            }
            return Ok(self.status.is_some());
        };
        let mut descriptors = [PollFd::new(fd, PollFlags::IN)];
        let count = rustix::event::poll(
            &mut descriptors,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .map_err(std::io::Error::from)?;
        if descriptors[0]
            .revents()
            .intersects(PollFlags::ERR | PollFlags::NVAL)
        {
            return Err(CiError::Message("native harness pidfd poll failed".into()));
        }
        Ok(count != 0
            && descriptors[0]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP))
    }

    /// Borrowed cleanup is retryable; no error consumes the exact native owner.
    pub fn stop(&mut self) -> Result<()> {
        self.child.stdin.take();
        if !self.exited()? {
            if let Some(pidfd) = &self.pidfd {
                rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL)
                    .map_err(std::io::Error::from)?;
            } else {
                self.child.kill()?;
            }
        }
        Ok(())
    }

    pub fn finish(&mut self, deadline: Instant) -> Result<()> {
        while !self.exited()? {
            if Instant::now() >= deadline {
                return Err(CiError::Message(
                    "native harness retirement deadline exhausted; owner retained".into(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if self.status.is_none() {
            self.status = Some(self.child.wait()?);
        }
        for (_, descriptor, _, retired) in &mut self.crash_helpers {
            let result = (|| -> Result<()> {
                use rustix::event::{PollFd, PollFlags, Timespec};
                let mut poll = [PollFd::new(&*descriptor, PollFlags::IN)];
                rustix::event::poll(
                    &mut poll,
                    Some(&Timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    }),
                )
                .map_err(std::io::Error::from)?;
                match (!poll[0].revents().intersects(PollFlags::IN | PollFlags::HUP)).then(|| {
                    rustix::process::pidfd_send_signal(&*descriptor, rustix::process::Signal::KILL)
                }) {
                    Some(Err(error)) if error != rustix::io::Errno::SRCH => {
                        return Err(std::io::Error::from(error).into());
                    }
                    _ => {}
                }
                loop {
                    let mut poll = [PollFd::new(&*descriptor, PollFlags::IN)];
                    rustix::event::poll(
                        &mut poll,
                        Some(&Timespec {
                            tv_sec: 0,
                            tv_nsec: 0,
                        }),
                    )
                    .map_err(std::io::Error::from)?;
                    if poll[0]
                        .revents()
                        .intersects(PollFlags::ERR | PollFlags::NVAL)
                    {
                        return Err(CiError::Message(
                            "held crash caller retirement poll failed".into(),
                        ));
                    }
                    if poll[0].revents().intersects(PollFlags::IN | PollFlags::HUP) {
                        *retired = true;
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(CiError::Message(
                            "original held crash caller retirement cutoff exhausted".into(),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Ok(())
            })();
            if let Err(error) = result {
                let error = error.to_string();
                if !self.crash_failures.contains(&error) {
                    self.crash_failures.push(error);
                }
            }
        }
        while self
            .stdout
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
            || self
                .stderr
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
        {
            if Instant::now() >= deadline {
                return Err(CiError::Message("native harness capture worker remains outstanding at original retirement deadline".into()));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for (handle, captured) in [
            (&mut self.stdout, &mut self.stdout_bytes),
            (&mut self.stderr, &mut self.stderr_bytes),
        ] {
            if let Some(worker) = handle.take() {
                match worker.join() {
                    Ok(Ok(bytes)) => *captured = Some(bytes),
                    Ok(Err(failure)) => {
                        self.capture_failure.get_or_insert_with(|| {
                            format!("native harness capture failed: {failure}")
                        });
                    }
                    Err(_) => {
                        self.capture_failure.get_or_insert_with(|| {
                            "native harness capture worker panicked".to_owned()
                        });
                    }
                }
            }
        }
        let image = self.image.metadata()?;
        for entry in fs::read_dir("/proc")? {
            if Instant::now() >= deadline {
                return Err(CiError::Message(
                    "native helper absence observation exceeded original retirement deadline"
                        .into(),
                ));
            }
            let entry = entry?;
            if entry.file_name().to_str().is_some_and(|name| {
                !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit())
            }) {
                match fs::metadata(entry.path().join("exe")) {
                    Ok(exe) if (exe.dev(), exe.ino()) == (image.dev(), image.ino()) => {
                        return Err(CiError::Message(
                            "same native harness image helper remains alive".into(),
                        ));
                    }
                    Ok(_) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error.into()),
                }
            }
        }
        self.native_quiescent = self.crash_helpers.iter().all(|entry| entry.3);
        // Capture failures remain the operation's original failure, while
        // native process settlement and every remaining capture owner proceed.
        if let Some(bytes) = self.admission_refusal.clone() {
            self.publish_owned("native-admission-refusal.json", &bytes)?;
        }
        for (name, bytes) in [
            ("stdout.bin", self.stdout_bytes.clone()),
            ("stderr.bin", self.stderr_bytes.clone()),
        ] {
            if let Some(bytes) = bytes {
                self.publish_owned(name, &bytes)?;
            }
        }
        if self.native_quiescent {
            self.publish_owned("native-retirement.json",&serde_json::to_vec(&serde_json::json!({
            "format":"memcordon.linux-native-test-retirement","revision":1,"process_id":self.process_id,
            "birth":self.birth,"image_sha256":self.image_sha256,"held_before_input_delivery":self.birth.is_some(),
            "retirement_observed":true,"same_image_helpers_absent":true}))?)?;
        }
        use std::os::unix::process::ExitStatusExt;
        if self.admission_refused {
            self.publish_owned("native-refusal-exit.json", &serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.linux-native-test-refusal-exit","revision":1,
                "process_id":self.process_id,"birth":self.birth,"image_sha256":self.image_sha256,
                "native_status":self.status.and_then(|status|status.code()),
                "native_signal":self.status.and_then(|status|status.signal()),
                "raw_wait_status":self.status.map(|status|status.into_raw()),"input_delivered":self.input_delivered
            }))?)?;
        }
        self.publish_owned("native-exit.json",&serde_json::to_vec(&serde_json::json!({"native_status":self.status.and_then(|status|status.code()),
            "input_delivered":self.input_delivered,"capture_complete":self.stdout_bytes.is_some() && self.stderr_bytes.is_some() && self.capture_failure.is_none()}))?)?;
        let crash = self
            .publications
            .contains_key("native-crash-controller.json")
            && !self.crash_helpers.is_empty();
        if crash {
            use std::os::unix::process::ExitStatusExt;
            let status = self
                .status
                .ok_or_else(|| CiError::Message("native crash lacks actual wait status".into()))?;
            if self.native_quiescent {
                let worker_retired = self.exited()?;
                self.publish_owned("native-crash-exit.json",&serde_json::to_vec(&serde_json::json!({"format":"memcordon.linux-native-crash-exit","revision":1,"worker_pid":self.process_id,"worker_birth":self.birth,"worker_image_sha256":self.image_sha256,"raw_wait_status":status.into_raw(),"native_signal":status.signal(),"native_exit_code":status.code(),"worker_pidfd_retirement_observed":worker_retired,"caller_pidfd_retirements":self.crash_helpers.iter().filter(|entry|entry.3).map(|(identity,_,_,_)|identity).collect::<Vec<_>>()}))?)?;
            }
        }
        if let Some(error) = &self.capture_failure {
            return Err(CiError::Message(error.clone()));
        }
        if !self.crash_failures.is_empty() {
            return Err(CiError::Message(self.crash_failures.join("; ")));
        }
        if self.status.is_none_or(|status| {
            if crash {
                status.signal() != Some(libc::SIGKILL)
            } else {
                !status.success()
            }
        }) {
            return Err(CiError::Message(
                "actual selected native harness failed; raw native status retained".into(),
            ));
        }
        Ok(())
    }

    pub fn native_and_capture_owners_retired(&self) -> bool {
        self.native_quiescent
            && self.status.is_some()
            && self.stdout.is_none()
            && self.stderr.is_none()
    }

    fn all_native_publications_settled(&self) -> bool {
        self.native_and_capture_owners_retired()
            && (!self.admission_refused
                || (self.admission_refusal.is_some()
                    && self
                        .publications
                        .get("native-refusal-exit.json")
                        .is_some_and(|publication| publication.settled)
                    && self
                        .publications
                        .get("native-admission-refusal.json")
                        .is_some_and(|publication| publication.settled)))
            && self
                .publications
                .get("native-retirement.json")
                .is_some_and(|publication| publication.settled)
            && self
                .publications
                .get("native-exit.json")
                .is_some_and(|publication| publication.settled)
            && (!self
                .publications
                .contains_key("native-crash-controller.json")
                || self
                    .publications
                    .get("native-crash-exit.json")
                    .is_some_and(|publication| publication.settled))
            && self
                .publications
                .values()
                .all(|publication| publication.settled)
    }

    fn publish_owned(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        use std::{
            io::{Seek, SeekFrom},
            os::unix::fs::OpenOptionsExt,
        };
        if !matches!(
            name,
            "stdout.bin"
                | "stderr.bin"
                | "native-retirement.json"
                | "native-exit.json"
                | "native-crash-controller.json"
                | "native-crash-exit.json"
                | "native-admission-refusal.json"
                | "native-refusal-exit.json"
        ) {
            return Err(CiError::Message(
                "native component publication name is not owned".into(),
            ));
        }
        let staged_name = format!(".{name}.pending");
        if !self.publications.contains_key(name) {
            let staged = self.output.join(&staged_name);
            let published = self.output.join(name);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&staged)?;
            self.publications.insert(
                name.into(),
                NativePublication {
                    file,
                    bytes: bytes.to_vec(),
                    staged,
                    published,
                    renamed: false,
                    settled: false,
                },
            );
        }
        let publication = self
            .publications
            .get_mut(name)
            .expect("retained native publication");
        if publication.bytes != bytes {
            return Err(CiError::Message(
                "owned native publication changed on retry".into(),
            ));
        }
        let path = if publication.renamed {
            &publication.published
        } else {
            &publication.staged
        };
        let named = fs::symlink_metadata(path)?;
        let held = publication.file.metadata()?;
        if !named.is_file()
            || named.uid() != 0
            || named.nlink() != 1
            || named.mode() & 0o7777 != 0o600
            || (named.dev(), named.ino()) != (held.dev(), held.ino())
        {
            return Err(CiError::Message(
                "owned native publication inode differs".into(),
            ));
        }
        if !publication.renamed {
            publication.file.seek(SeekFrom::Start(0))?;
            publication.file.write_all(bytes)?;
            publication.file.set_len(bytes.len() as u64)?;
            publication.file.sync_all()?;
            if crate::linux_consumer_readiness::measured(&publication.staged, 16 * 1024 * 1024)
                .map_err(CiError::Message)?
                != bytes
            {
                return Err(CiError::Message(
                    "owned native staging byte readback differs".into(),
                ));
            }
            let directory = self._ancestry.last().expect("held native output directory");
            rustix::fs::renameat_with(
                directory,
                staged_name.as_str(),
                directory,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(std::io::Error::from)?;
            publication.renamed = true;
        }
        let named = fs::symlink_metadata(&publication.published)?;
        let held = publication.file.metadata()?;
        if (named.dev(), named.ino()) != (held.dev(), held.ino())
            || held.nlink() != 1
            || crate::linux_consumer_readiness::measured(&publication.published, 16 * 1024 * 1024)
                .map_err(CiError::Message)?
                != bytes
        {
            return Err(CiError::Message(
                "owned native publication named readback differs".into(),
            ));
        }
        self._ancestry
            .last()
            .expect("held native output directory")
            .sync_all()?;
        publication.settled = true;
        Ok(())
    }
}

use std::os::unix::fs::OpenOptionsExt;

#[cfg(test)]
#[path = "../../tests/private/native_recipe_owner.rs"]
mod owner_tests;
