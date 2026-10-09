//! One outer installation lease for the measured predecessor and mixed cases.
use super::{
    installed_consumer::{MaterializedPayload, binary_path},
    linux_installed_consumer::{InstalledLeaseExtension, SelectedInstallOperation},
    linux_mixed_installed::{
        InstalledMixedDriver, InstalledMixedDriverInput, owned_fixture_recipes,
    },
    source,
};
use crate::{CiError, Result, command::CommandSpec, consumer_readiness_ledger::SourceIdentity};
use memcordon_readiness_verifier::{
    InstalledLifecycleEvent, InstalledLifecycleJournal, InstalledLifecycleReceipt, ProductKey,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PersistedLeaseOwner {
    pub format: String,
    pub revision: u32,
    pub identity: SourceIdentity,
    pub cell: ProductKey,
    pub admin_root: PathBuf,
    pub artifact_root: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub cleanup_agent: PathBuf,
    pub cleanup_agent_sha256: String,
    pub legacy: memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry,
    pub lease_id: String,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
}

pub struct ReadinessLinuxLease<'a> {
    pub identity: SourceIdentity,
    pub cell: ProductKey,
    pub workspace: &'a Path,
    pub artifact_root: &'a Path,
    pub predecessor: &'a MaterializedPayload,
    pub deadline: Instant,
    pub cleanup_deadline: Instant,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
    pub driver: InstalledMixedDriver,
    journal: InstalledLifecycleJournal,
    output: PathBuf,
    finalization_started: bool,
    failures: Vec<String>,
    admin_root: PathBuf,
    admin_owner: Option<std::fs::File>,
    admin_retired: bool,
}
impl<'a> ReadinessLinuxLease<'a> {
    pub fn new(
        identity: SourceIdentity,
        cell: ProductKey,
        workspace: &'a Path,
        artifact_root: &'a Path,
        predecessor: &'a MaterializedPayload,
        output: PathBuf,
        deadline: Instant,
        cleanup_deadline: Instant,
        cleanup_deadline_unix_millis: u64,
    ) -> Result<Self> {
        if deadline > cleanup_deadline
            || cleanup_deadline.saturating_duration_since(deadline) != Duration::from_secs(15 * 60)
        {
            return Err(CiError::Message(
                "installed lease requires original work and reserved cleanup cutoffs".into(),
            ));
        }
        if !rustix::process::geteuid().is_root() {
            return Err(CiError::Message(
                "installed native observer requires explicit local administrator controller".into(),
            ));
        }
        if predecessor.channel != crate::windows_causal_acceptance::InstalledChannel::CargoPackage
            || predecessor.source.version().to_string() != "0.5.7-rc.19"
            || predecessor.source.commit() != "a02e8f1e845349e27706c11d6d57acb27090223a"
            || predecessor.distribution.target != cell.target
            || predecessor.source.version() >= &semver::Version::parse(&identity.version)?
        {
            return Err(CiError::Message("readiness predecessor must be measured older rc19 Cargo runtime on the exact target".into()));
        }
        fs::create_dir(&output)?;
        let lease_id = format!("{}-{}-{}", identity.run_id, cell.target, cell.channel);
        let journal = InstalledLifecycleJournal {
            format: "memcordon.consumer-readiness.installed-journal".into(),
            revision: 1,
            run_id: identity.run_id.clone(),
            lease_id,
            key: cell.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            events: Vec::new(),
        };
        let admin_root = Path::new("/var/lib/memcordon-consumer-readiness").join(
            super::artifacts::checksum(&serde_json::to_vec(&(&identity, &cell))?),
        );
        let work_deadline_unix_millis = cleanup_deadline_unix_millis
            .checked_sub(15 * 60 * 1000)
            .ok_or_else(|| {
                CiError::Message("original wallclock cutoff lacks cleanup reservation".into())
            })?;
        let mut value = Self {
            work_deadline_unix_millis,
            cleanup_deadline_unix_millis,
            identity,
            cell,
            workspace,
            artifact_root,
            predecessor,
            deadline,
            cleanup_deadline,
            driver: InstalledMixedDriver::default(),
            journal,
            output,
            finalization_started: false,
            failures: Vec::new(),
            admin_root,
            admin_owner: None,
            admin_retired: false,
        };
        value.event("owned-before-mutation","selected-installation-owned",true,&serde_json::json!({"predecessor_source":value.predecessor.source,"predecessor_artifacts":value.predecessor.artifacts,"uninstall_required":true}))?;
        Ok(value)
    }
    fn event(
        &mut self,
        phase: &str,
        operation: &str,
        succeeded: bool,
        native: &serde_json::Value,
    ) -> Result<()> {
        let sequence = u64::try_from(self.journal.events.len())
            .map_err(|_| CiError::Message("installed lifecycle sequence overflow".into()))?
            + 1;
        let path = self.output.join(format!("operation-{sequence}.json"));
        source::write_json(&path, native)?;
        let relative = path
            .strip_prefix(self.artifact_root)
            .map_err(|_| CiError::Message("lifecycle receipt escapes artifact root".into()))?
            .to_str()
            .ok_or_else(|| CiError::Message("lifecycle receipt encoding differs".into()))?
            .to_owned();
        self.journal.events.push(InstalledLifecycleEvent {
            sequence,
            phase: phase.into(),
            operation: operation.into(),
            succeeded,
            native_receipt: relative,
        });
        source::write_json(&self.output.join("installed-journal.json"), &self.journal)
    }
    fn readback(&mut self, payload: &MaterializedPayload, phase: &str) -> Result<()> {
        let mut binaries = Vec::new();
        for binary in &payload.distribution.binaries {
            let expected = super::artifacts::read_file(&binary_path(
                &payload.directory,
                binary,
                &payload.distribution.target,
            ))?;
            let installed = super::artifacts::read_file(&Path::new("/usr/libexec").join(binary))?;
            if expected != installed {
                return Err(CiError::Message(
                    "installed native executable differs from selected measured payload".into(),
                ));
            }
            binaries.push(serde_json::json!({"binary":binary,"sha256":super::artifacts::checksum(&installed),"length":installed.len()}));
        }
        let observed = CommandSpec::new(
            "/usr/libexec/memcordon-sealed-agent",
            self.workspace,
            Duration::from_secs(60),
        )
        .args(["package", "verify", "--json"])
        .bounded_until(self.deadline)
        .output_quiet()?;
        let succeeded = observed.status.success();
        self.event(phase,"actual-installed-package-readback",succeeded,&serde_json::json!({"status":observed.status.code(),"stdout":observed.stdout,"stderr":observed.stderr,"source":payload.source,"binaries":binaries}))?;
        if succeeded {
            Ok(())
        } else {
            Err(CiError::Message(
                "installed package inspection failed".into(),
            ))
        }
    }
}
impl InstalledLeaseExtension for ReadinessLinuxLease<'_> {
    fn before_install(&mut self, selected: &MaterializedPayload, _: &Path) -> Result<()> {
        self.event(
            "owned-before-mutation",
            "administrative-staging-intent",
            true,
            &serde_json::json!({"path":self.admin_root,"source":self.identity,"cell":self.cell}),
        )?;
        self.admin_owner = Some(create_admin_directory(&self.admin_root)?);
        use std::os::unix::fs::MetadataExt;
        let metadata = self
            .admin_owner
            .as_ref()
            .expect("created admin owner")
            .metadata()?;
        self.event("owned-before-mutation","administrative-staging-created",true,&serde_json::json!({"path":self.admin_root,"device":metadata.dev(),"inode":metadata.ino()}))?;
        let cleanup_agent = self.admin_root.join("cleanup-agent");
        let bytes = super::artifacts::read_file(&binary_path(
            &selected.directory,
            "memcordon-sealed-agent",
            &selected.distribution.target,
        ))?;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut copied = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&cleanup_agent)?;
        copied.write_all(&bytes)?;
        copied.sync_all()?;
        self.admin_owner
            .as_ref()
            .expect("created admin owner")
            .sync_all()?;
        if super::artifacts::read_file(&cleanup_agent)? != bytes {
            return Err(CiError::Message(
                "retained native cleanup executable differs from measured selected agent".into(),
            ));
        }
        source::write_json(
            &self.output.join("lease-owner.json"),
            &PersistedLeaseOwner {
                format: "memcordon.consumer-readiness.linux-lease-owner".into(),
                revision: 1,
                identity: self.identity.clone(),
                cell: self.cell.clone(),
                admin_root: self.admin_root.clone(),
                artifact_root: self.artifact_root.to_owned(),
                device: metadata.dev(),
                inode: metadata.ino(),
                cleanup_agent,
                cleanup_agent_sha256: super::artifacts::checksum(&bytes),
                legacy: super::linux_installed_consumer::registry(selected)?,
                lease_id: self.journal.lease_id.clone(),
                work_deadline_unix_millis: self.work_deadline_unix_millis,
                cleanup_deadline_unix_millis: self.cleanup_deadline_unix_millis,
            },
        )?;
        let agent = binary_path(
            &self.predecessor.directory,
            "memcordon-sealed-agent",
            &self.predecessor.distribution.target,
        );
        let observed =
            CommandSpec::new(agent, &self.predecessor.directory, Duration::from_secs(300))
                .args(["package", "install"])
                .bounded_until(self.deadline)
                .output_quiet()?;
        let succeeded = observed.status.success();
        self.event("install","actual-older-cargo-runtime-install",succeeded,&serde_json::json!({"status":observed.status.code(),"stdout":observed.stdout,"stderr":observed.stderr,"source":self.predecessor.source}))?;
        if !succeeded {
            return Err(CiError::Message(
                "older Cargo runtime installation failed; outer uninstall remains required".into(),
            ));
        }
        self.readback(self.predecessor, "verify")
    }
    fn selected_installation_operation(&self) -> SelectedInstallOperation {
        SelectedInstallOperation::Upgrade
    }
    fn after_install(&mut self, payload: &MaterializedPayload, _: &Path) -> Result<()> {
        self.readback(payload, "upgrade")
    }
    fn execute_cases(&mut self, payload: &MaterializedPayload, _: &Path) -> Result<()> {
        let manifest = super::installed_consumer::measured_manifest(
            &payload.source,
            &payload.distribution,
            &payload.directory,
        )?;
        let bytes =
            super::artifacts::read_file(Path::new("/usr/libexec/memcordon-runtime-manifest.json"))?;
        if memcordon_core::runtime_manifest::RuntimeManifest::parse(&bytes)
            .map_err(CiError::Message)?
            != manifest
        {
            return Err(CiError::Message(
                "installed provider manifest differs from selected native bytes".into(),
            ));
        }
        let provider = manifest.public_binding(&bytes).map_err(CiError::Message)?;
        let output = self.output.join("mixed-cases");
        fs::create_dir(&output)?;
        self.event(
            "cases",
            "actual-installed-mixed-dispatch-start",
            true,
            &serde_json::json!({"provider":provider,"source":payload.source}),
        )?;
        self.driver.run_inside_installed_lease(
            InstalledMixedDriverInput {
                payload,
                provider: &provider,
                legacy: super::linux_installed_consumer::registry(payload)?,
                workspace: self.workspace,
                output: &output,
                artifact_root: self.artifact_root,
                admin_root: &self.admin_root,
                identity: self.identity.clone(),
                lease_id: self.journal.lease_id.clone(),
                cell: self.cell.clone(),
                deadline: self.deadline,
                cleanup_deadline: self.cleanup_deadline,
                work_deadline_unix_millis: self.work_deadline_unix_millis,
                cleanup_deadline_unix_millis: self.cleanup_deadline_unix_millis,
            },
            owned_fixture_recipes(&self.cell)?,
        )
    }
    fn finalize_before_uninstall(&mut self, payload: &MaterializedPayload, _: &Path) -> Result<()> {
        if self.finalization_started {
            return Err(CiError::Message(
                "outer installed finalization cannot be repeated as a new record".into(),
            ));
        }
        self.finalization_started = true;
        let result = (|| -> Result<()> {
            self.driver.finalize_owned_attempts(self.cleanup_deadline)?;
            self.driver.finalize_owned_resources(
                self.workspace,
                &self.output,
                &super::linux_installed_consumer::registry(payload)?,
                self.cleanup_deadline,
            )?;
            Ok(())
        })();
        if let Err(error) = &result {
            self.failures.push(error.to_string());
        }
        self.event("finalization","actual-owned-native-resource-finalization",result.is_ok(),&serde_json::json!({"active_attempts":self.driver.active.len(),"account_retained":self.driver.account.is_some(),"images_retained":self.driver.images.is_some(),"error":result.as_ref().err().map(ToString::to_string)}))?;
        result
    }
    fn after_uninstall(
        &mut self,
        payload: &MaterializedPayload,
        _: &Path,
        succeeded: bool,
    ) -> Result<()> {
        let mut absent = succeeded;
        for binary in &payload.distribution.binaries {
            match fs::symlink_metadata(Path::new("/usr/libexec").join(binary)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => absent = false,
            }
        }
        let mut remaining_paths = Vec::new();
        for path in [
            "/usr/libexec/memcordon-runtime-manifest.json",
            "/usr/libexec/memcordon-arm32-abi-helper",
            "/usr/lib/tmpfiles.d/memcordon.conf",
            "/run/memcordon",
            "/var/lib/memcordon/sealed",
            "/sys/fs/cgroup/memcordon-sealed",
        ] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    absent = false;
                    remaining_paths.push(path.to_owned());
                }
            }
        }
        let mut unit_observations = Vec::new();
        for unit in &payload.distribution.units {
            let path = Path::new("/usr/lib/systemd/system").join(unit);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    absent = false;
                    remaining_paths.push(path.display().to_string());
                }
            }
            if unit.ends_with(".service") || unit.ends_with(".socket") {
                let observed = CommandSpec::new(
                    "/usr/bin/systemctl",
                    self.workspace,
                    Duration::from_secs(30),
                )
                .args([
                    "show",
                    unit.as_str(),
                    "--property=ActiveState",
                    "--property=SubState",
                    "--property=MainPID",
                ])
                .bounded_until(self.cleanup_deadline)
                .output_quiet()?;
                let text = String::from_utf8(observed.stdout.clone()).map_err(|_| {
                    CiError::Message("final native systemd observation is not UTF-8".into())
                })?;
                if !observed.status.success()
                    || !text.lines().any(|line| line == "ActiveState=inactive")
                    || !text.lines().any(|line| line == "MainPID=0")
                {
                    absent = false;
                }
                unit_observations.push(serde_json::json!({"unit":unit,"status":observed.status.code(),"stdout":observed.stdout,"stderr":observed.stderr}));
            }
        }
        if absent
            && self.driver.active.is_empty()
            && self.driver.account.is_none()
            && self.driver.images.is_none()
        {
            use std::os::unix::fs::MetadataExt;
            let held=self.admin_owner.as_ref().ok_or_else(||CiError::Message("administrative allocation intent lacks held inode; exact absence/recovery must settle it".into()))?;
            let metadata = held.metadata()?;
            source::write_json(
                &self
                    .output
                    .join("package-absence-before-admin-retirement.json"),
                &serde_json::json!({"format":"memcordon.consumer-readiness.package-absence-before-admin-retirement","revision":1,"identity":self.identity,"cell":self.cell,"admin_root":self.admin_root,"device":metadata.dev(),"inode":metadata.ino(),"uninstall_succeeded":succeeded,"selected_paths_absent":absent,"units":unit_observations}),
            )?;
            let receipt = self.driver.retire_admin_sources(
                &self.admin_root,
                metadata.dev(),
                metadata.ino(),
                self.cleanup_deadline,
            )?;
            if held.metadata()?.nlink() != 0 {
                return Err(CiError::Message(
                    "retired administrative source owner remains linked".into(),
                ));
            }
            self.admin_retired = true;
            self.event(
                "finalization",
                "actual-administrative-source-retirement",
                true,
                &receipt,
            )?;
        }
        self.event("retired","actual-selected-package-absence",absent,&serde_json::json!({"uninstall_succeeded":succeeded,"selected_paths_absent":absent,"remaining_paths":remaining_paths,"units":unit_observations}))?;
        let native = self.driver.active.is_empty()
            && self.driver.account.is_none()
            && self.driver.images.is_none()
            && self.admin_retired;
        let journal = super::artifacts::read_file(&self.output.join("installed-journal.json"))?;
        let receipt = InstalledLifecycleReceipt {
            format: "memcordon.consumer-readiness.installed-retirement".into(),
            revision: 1,
            run_id: self.identity.run_id.clone(),
            lease_id: self.journal.lease_id.clone(),
            key: self.cell.clone(),
            journal_sha256: super::artifacts::checksum(&journal),
            final_sequence: self.journal.events.last().map_or(0, |event| event.sequence),
            explicit_finalization_count: u32::from(self.finalization_started),
            package_absent: absent,
            policy_retired: native && absent,
            native_resources_retired: native,
            cache_quiescent: native && absent,
            cleanup_failures: self.failures.clone(),
            outstanding: if native && absent {
                Vec::new()
            } else {
                vec!["owned installation or native resource retirement unresolved".into()]
            },
        };
        source::write_json(&self.output.join("installed-retirement.json"), &receipt)?;
        if native && absent && self.failures.is_empty() {
            Ok(())
        } else {
            Err(CiError::Message(
                "installed final state remains unresolved; receipt and exact obligations retained"
                    .into(),
            ))
        }
    }
}

pub(super) fn recover_installation(
    workspace: &Path,
    output: &Path,
    identity: &SourceIdentity,
    cell: &ProductKey,
    deadline: Instant,
) -> Result<()> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !rustix::process::geteuid().is_root() {
        return Err(CiError::Message(
            "interrupted installed cleanup requires local administrator ownership".into(),
        ));
    }
    let owner_path = output.join("lease-owner.json");
    let owner_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&owner_path)?;
    let before = owner_file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() > 16 * 1024 * 1024
    {
        return Err(CiError::Message(
            "persisted lease owner lacks protected regular-file custody".into(),
        ));
    }
    let mut owner_bytes = Vec::new();
    owner_file
        .try_clone()?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut owner_bytes)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&owner_bytes)
        .map_err(CiError::Message)?;
    let owner: PersistedLeaseOwner = serde_json::from_slice(&owner_bytes)?;
    let named = fs::symlink_metadata(&owner_path)?;
    let after = owner_file.metadata()?;
    if named.file_type().is_symlink()
        || (named.dev(), named.ino(), named.len()) != (before.dev(), before.ino(), before.len())
        || (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
        ) != (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
        )
    {
        return Err(CiError::Message(
            "persisted lease owner changed during held readback".into(),
        ));
    }
    let expected_admin = Path::new("/var/lib/memcordon-consumer-readiness").join(
        super::artifacts::checksum(&serde_json::to_vec(&(identity, cell))?),
    );
    if owner.format != "memcordon.consumer-readiness.linux-lease-owner"
        || owner.revision != 1
        || serde_json::to_value(&owner.identity)? != serde_json::to_value(identity)?
        || owner.cell != *cell
        || owner.admin_root != expected_admin
        || owner.cleanup_agent != expected_admin.join("cleanup-agent")
        || owner.lease_id != format!("{}-{}-{}", identity.run_id, cell.target, cell.channel)
        || owner.work_deadline_unix_millis == 0
        || owner
            .cleanup_deadline_unix_millis
            .checked_sub(15 * 60 * 1000)
            != Some(owner.work_deadline_unix_millis)
    {
        return Err(CiError::Message(
            "interrupted lease cannot reassociate cleanup ownership".into(),
        ));
    }
    super::linux_isolation_cases::recover_host_path_sockets(&output.join("mixed-cases"), deadline)?;
    let admin = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&owner.admin_root)
    {
        Ok(admin) => admin,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return finish_already_unlinked(workspace, output, &owner, deadline);
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = admin.metadata()?;
    if metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
        || (metadata.dev(), metadata.ino()) != (owner.device, owner.inode)
    {
        return Err(CiError::Message(
            "interrupted administrative owner differs from native allocation".into(),
        ));
    }
    let agent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&owner.cleanup_agent)?;
    let metadata = agent.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 256 * 1024 * 1024
    {
        return Err(CiError::Message(
            "retained cleanup executable custody differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    agent
        .try_clone()?
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if super::artifacts::checksum(&bytes) != owner.cleanup_agent_sha256 {
        return Err(CiError::Message(
            "retained cleanup executable bytes differ".into(),
        ));
    }
    verify_cleanup_agent_name(&owner.cleanup_agent, &agent, &bytes)?;
    let recovery = CommandSpec::new(&owner.cleanup_agent, workspace, Duration::from_secs(60))
        .args(["package", "policy", "recover", "--json"])
        .bounded_until(deadline)
        .output_quiet()?;
    source::write_json(
        &output.join("interrupted-native-recovery.json"),
        &serde_json::json!({"status":recovery.status.code(),"stdout":recovery.stdout,"stderr":recovery.stderr}),
    )?;
    if !recovery.status.success() {
        return Err(CiError::Message("native recovery retains unresolved attempt owners; resources and installation retained".into()));
    }
    let mixed = output.join("mixed-cases");
    let acquired = mixed.join("owned-resources-acquired.json");
    let images = mixed.join("owned-resources-images.json");
    let mut driver = if acquired.is_file() {
        InstalledMixedDriver::recover_owned_resources(
            &acquired,
            identity,
            cell,
            &owner.admin_root,
            owner.device,
            owner.inode,
            &owner.legacy,
        )?
    } else if images.is_file() {
        InstalledMixedDriver::recover_owned_resources(
            &images,
            identity,
            cell,
            &owner.admin_root,
            owner.device,
            owner.inode,
            &owner.legacy,
        )?
    } else {
        InstalledMixedDriver::recover_partial_acquisition(
            &mixed,
            identity,
            cell,
            &owner.admin_root,
        )?
    };
    driver.recover_image_case_intents(
        &mixed,
        identity,
        cell,
        &owner.admin_root,
        &owner.lease_id,
        owner.work_deadline_unix_millis,
        owner.cleanup_deadline_unix_millis,
        deadline,
        &owner.artifact_root,
    )?;
    driver.finalize_owned_resources(workspace, &mixed, &owner.legacy, deadline)?;
    verify_cleanup_agent_name(&owner.cleanup_agent, &agent, &bytes)?;
    let uninstall = CommandSpec::new(&owner.cleanup_agent, workspace, Duration::from_secs(120))
        .args(["package", "uninstall"])
        .bounded_until(deadline)
        .output_quiet()?;
    source::write_json(
        &output.join("interrupted-package-uninstall.json"),
        &serde_json::json!({"status":uninstall.status.code(),"stdout":uninstall.stdout,"stderr":uninstall.stderr}),
    )?;
    if !uninstall.status.success() {
        return Err(CiError::Message(
            "interrupted package uninstall failed; administrative owner retained".into(),
        ));
    }
    for path in [
        "/usr/libexec/memcordon",
        "/usr/libexec/memcordon-sealed-agent",
        "/usr/libexec/memcordon-runtime-manifest.json",
        "/usr/libexec/memcordon-arm32-abi-helper",
        "/run/memcordon",
        "/var/lib/memcordon/sealed",
        "/sys/fs/cgroup/memcordon-sealed",
    ] {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(CiError::Message(format!(
                    "interrupted cleanup retained native path {path}"
                )));
            }
        }
    }
    let selected = super::distribution::Distribution::read(workspace)?
        .consumer_readiness()?
        .native()?
        .clone();
    let mut units = Vec::new();
    for unit in &selected.units {
        match fs::symlink_metadata(Path::new("/usr/lib/systemd/system").join(unit)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(CiError::Message(format!(
                    "interrupted cleanup retained native unit {unit}"
                )));
            }
        }
        if unit.ends_with(".service") || unit.ends_with(".socket") {
            let observed =
                CommandSpec::new("/usr/bin/systemctl", workspace, Duration::from_secs(30))
                    .args([
                        "show",
                        unit.as_str(),
                        "--property=ActiveState",
                        "--property=SubState",
                        "--property=MainPID",
                    ])
                    .bounded_until(deadline)
                    .output_quiet()?;
            let text = std::str::from_utf8(&observed.stdout).map_err(|_| {
                CiError::Message("recovery systemd observation is not UTF-8".into())
            })?;
            if !observed.status.success()
                || !text.lines().any(|line| line == "ActiveState=inactive")
                || !text.lines().any(|line| line == "MainPID=0")
            {
                return Err(CiError::Message(format!(
                    "interrupted cleanup native unit {unit} remains active or uncertain"
                )));
            }
            units.push(serde_json::json!({"unit":unit,"status":observed.status.code(),"stdout":observed.stdout,"stderr":observed.stderr}));
        }
    }
    source::write_json(&output.join("interrupted-native-unit-absence.json"), &units)?;
    let receipt =
        driver.retire_admin_sources(&owner.admin_root, owner.device, owner.inode, deadline)?;
    if admin.metadata()?.nlink() != 0 {
        return Err(CiError::Message(
            "interrupted administrative source remains linked".into(),
        ));
    }
    source::write_json(
        &output.join("interrupted-administrative-retirement.json"),
        &receipt,
    )?;
    source::write_json(
        &output.join("interrupted-cleanup.json"),
        &serde_json::json!({"format":"memcordon.consumer-readiness.interrupted-cleanup","revision":1,"identity":identity,"cell":cell,"native_recovery":"interrupted-native-recovery.json","package_uninstall":"interrupted-package-uninstall.json","administrative_retirement":"interrupted-administrative-retirement.json"}),
    )
}

fn verify_cleanup_agent_name(path: &Path, held: &std::fs::File, expected: &[u8]) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let bytes = crate::linux_consumer_readiness::measured(path, 256 * 1024 * 1024)
        .map_err(CiError::Message)?;
    let native = held.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink()
        || (named.dev(), named.ino()) != (native.dev(), native.ino())
        || native.nlink() != 1
        || bytes != expected
    {
        return Err(CiError::Message(
            "retained cleanup executable named inode or exact readback changed".into(),
        ));
    }
    Ok(())
}

fn finish_already_unlinked(
    workspace: &Path,
    output: &Path,
    owner: &PersistedLeaseOwner,
    deadline: Instant,
) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, open, openat, statat};
    use std::os::unix::fs::MetadataExt;
    // A missing tree alone does not prove any prior resource retirement.
    InstalledMixedDriver::assess_retired_resources(
        &output.join("mixed-cases"),
        &owner.identity,
        &owner.cell,
        &owner.admin_root,
        owner.device,
        owner.inode,
        workspace,
        deadline,
    )?;
    let before_path = output.join("package-absence-before-admin-retirement.json");
    let prior = if before_path.exists() {
        let bytes = crate::linux_consumer_readiness::measured(&before_path, 4 * 1024 * 1024)
            .map_err(CiError::Message)?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
            .map_err(CiError::Message)?;
        let observed: serde_json::Value = serde_json::from_slice(&bytes)?;
        if observed["format"]
            != "memcordon.consumer-readiness.package-absence-before-admin-retirement"
            || observed["revision"] != 1
            || observed["identity"] != serde_json::to_value(&owner.identity)?
            || observed["cell"] != serde_json::to_value(&owner.cell)?
            || observed["admin_root"] != serde_json::to_value(&owner.admin_root)?
            || observed["device"] != owner.device
            || observed["inode"] != owner.inode
            || observed["uninstall_succeeded"] != true
            || observed["selected_paths_absent"] != true
        {
            return Err(CiError::Message(
                "prior native package absence receipt does not bind this owner".into(),
            ));
        }
        before_path
    } else {
        let path = output.join("interrupted-package-uninstall.json");
        let bytes = crate::linux_consumer_readiness::measured(&path, 4 * 1024 * 1024)
            .map_err(CiError::Message)?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
            .map_err(CiError::Message)?;
        let observed: serde_json::Value = serde_json::from_slice(&bytes)?;
        if observed["status"] != 0 {
            return Err(CiError::Message(
                "prior interrupted uninstall success was not retained".into(),
            ));
        }
        path
    };
    let selected = super::distribution::Distribution::read(workspace)?
        .consumer_readiness()?
        .native()?
        .clone();
    let mut paths = selected
        .binaries
        .iter()
        .map(|binary| Path::new("/usr/libexec").join(binary))
        .collect::<Vec<_>>();
    paths.extend(
        [
            "/usr/libexec/memcordon-runtime-manifest.json",
            "/usr/libexec/memcordon-arm32-abi-helper",
            "/usr/lib/tmpfiles.d/memcordon.conf",
            "/run/memcordon",
            "/var/lib/memcordon/sealed",
            "/sys/fs/cgroup/memcordon-sealed",
        ]
        .map(PathBuf::from),
    );
    let mut units = Vec::new();
    for unit in &selected.units {
        paths.push(Path::new("/usr/lib/systemd/system").join(unit));
        if unit.ends_with(".service") || unit.ends_with(".socket") {
            let observed =
                CommandSpec::new("/usr/bin/systemctl", workspace, Duration::from_secs(30))
                    .args([
                        "show",
                        unit.as_str(),
                        "--property=ActiveState",
                        "--property=SubState",
                        "--property=MainPID",
                    ])
                    .bounded_until(deadline)
                    .output_quiet()?;
            let text = std::str::from_utf8(&observed.stdout)
                .map_err(|_| CiError::Message("retirement retry unit state is not UTF-8".into()))?;
            if !observed.status.success()
                || !text.lines().any(|line| line == "ActiveState=inactive")
                || !text.lines().any(|line| line == "MainPID=0")
            {
                return Err(CiError::Message(
                    "retirement retry retains uncertain native unit".into(),
                ));
            }
            units.push(serde_json::json!({"unit":unit,"status":observed.status.code(),"stdout":observed.stdout,"stderr":observed.stderr}));
        }
    }
    for path in paths {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(CiError::Message(format!(
                    "retirement retry retains native path {}",
                    path.display()
                )));
            }
        }
    }
    let mut parent = std::fs::File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    for component in owner
        .admin_root
        .parent()
        .ok_or_else(|| CiError::Message("administrative owner parent absent".into()))?
        .components()
    {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(name) => {
                let metadata = parent.metadata()?;
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    return Err(CiError::Message(
                        "administrative absence retry lacks protected ancestry".into(),
                    ));
                }
                parent = std::fs::File::from(
                    openat(
                        &parent,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(std::io::Error::from)?,
                );
            }
            _ => {
                return Err(CiError::Message(
                    "administrative absence path is not normalized".into(),
                ));
            }
        }
    }
    let metadata = parent.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(CiError::Message(
            "administrative absence parent is not protected".into(),
        ));
    }
    match statat(
        &parent,
        owner
            .admin_root
            .file_name()
            .ok_or_else(|| CiError::Message("administrative owner leaf absent".into()))?,
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Err(error) => return Err(std::io::Error::from(error).into()),
        Ok(_) => {
            return Err(CiError::Message(
                "administrative owner reappeared during retry".into(),
            ));
        }
    }
    parent.sync_all()?;
    source::write_json(
        &output.join("interrupted-cleanup.json"),
        &serde_json::json!({"format":"memcordon.consumer-readiness.interrupted-cleanup","revision":1,"identity":owner.identity,"cell":owner.cell,"already_unlinked_administrative_owner":true,"prior_uninstall":prior,"native_unit_observations":units,"resource_retirement":"mixed-cases/owned-resources-retired.json"}),
    )
}

fn create_admin_directory(path: &Path) -> Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
    use std::os::unix::fs::MetadataExt;
    let mut held = std::fs::File::from(
        open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?,
    );
    let components = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    for (index, name) in components.iter().enumerate() {
        let metadata = held.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(CiError::Message(
                "administrative staging ancestor lacks protected root custody".into(),
            ));
        }
        let final_component = index + 1 == components.len();
        if index >= 2 {
            match mkdirat(&held, *name, Mode::from_bits_truncate(0o700)) {
                Ok(()) => held.sync_all()?,
                Err(error) if error == rustix::io::Errno::EXIST && !final_component => {}
                Err(error) => {
                    return Err(CiError::Message(format!(
                        "fresh administrative staging allocation: {error}"
                    )));
                }
            }
        }
        held = std::fs::File::from(
            openat(
                &held,
                *name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?,
        );
    }
    let metadata = held.metadata()?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(CiError::Message(
            "administrative staging final owner differs".into(),
        ));
    }
    held.sync_all()?;
    Ok(held)
}
