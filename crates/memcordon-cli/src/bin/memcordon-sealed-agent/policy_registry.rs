//! Provider-owned atomic policy activation and launch serialization.
use memcordon_core::BoundedVec;
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_contract::Nonce128;
use memcordon_core::workload_contract::{ContractVersionOne, ContractVersionTwo, PolicyEpoch};
use memcordon_core::workload_registry::PolicyRegistryV1;
use memcordon_core::workload_registry_v2::PolicyRegistryV2;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::{io::Write, num::NonZeroU64};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub schema_version: ContractVersionOne,
    pub registry: PolicyRegistryV1,
    pub registry_digest: DiagnosticSha256,
    pub epoch: PolicyEpoch,
    pub revoked_admissions: memcordon_core::diagnostics::BoundedVec<Nonce128, 256>,
}
impl Activation {
    pub(crate) fn inspection(
        &self,
    ) -> Result<memcordon_core::runtime_manifest::InstalledPolicyObservationV1, String> {
        if self.registry.canonical_digest()? != self.registry_digest {
            return Err("installed registry digest mismatch".into());
        }
        let mut enabled_profiles = memcordon_core::BoundedVec::default();
        for profile in self
            .registry
            .profiles
            .as_slice()
            .iter()
            .filter(|profile| profile.enabled)
        {
            enabled_profiles
                .try_push(profile.reference.clone())
                .map_err(|_| "installed profile limit exceeded")?;
        }
        Ok(
            memcordon_core::runtime_manifest::InstalledPolicyObservationV1::Active {
                epoch: self.epoch.clone(),
                registry_digest: self.registry_digest.clone(),
                enabled_profiles,
            },
        )
    }
    pub(crate) fn next_revocations(
        previous: Option<&Self>,
        disposition: memcordon_core::workload_registry::GrantChangeDisposition,
        live: &[(
            String,
            memcordon_core::workload_registry::ProviderAdmissionSnapshotV1,
        )],
    ) -> Result<memcordon_core::diagnostics::BoundedVec<Nonce128, 256>, String> {
        let mut revoked = memcordon_core::diagnostics::BoundedVec::default();
        for (_, snapshot) in live {
            let nonce = snapshot.admission_nonce;
            if (disposition
                == memcordon_core::workload_registry::GrantChangeDisposition::RevokeActive
                || previous
                    .is_some_and(|value| value.revoked_admissions.as_slice().contains(&nonce)))
                && !revoked.as_slice().contains(&nonce)
            {
                revoked
                    .try_push(nonce)
                    .map_err(|_| "revocation reference bound exceeded")?;
            }
        }
        Ok(revoked)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.registry.canonical_digest()? != self.registry_digest {
            return Err("policy activation digest differs".into());
        }
        Ok(())
    }
}

/// Linux V2 authority is stored as its own exact activation shape. Existing
/// V1 callers receive only its explicit preserve-caller baseline projection;
/// private/delegated grants cannot be laundered into V1 authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationV2 {
    pub schema_version: ContractVersionTwo,
    pub registry: PolicyRegistryV2,
    pub registry_digest: DiagnosticSha256,
    pub epoch: PolicyEpoch,
    pub revoked_admissions: BoundedVec<Nonce128, 256>,
}

impl ActivationV2 {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.registry.canonical_digest()? != self.registry_digest {
            return Err("V2 policy activation digest differs".into());
        }
        for (index, nonce) in self.revoked_admissions.as_slice().iter().enumerate() {
            if self.revoked_admissions.as_slice()[..index].contains(nonce) {
                return Err("duplicate V2 revoked admission".into());
            }
        }
        self.registry.baseline_v1_projection()?;
        Ok(())
    }

    pub(crate) fn baseline_projection(&self) -> Result<Activation, String> {
        let registry = self.registry.baseline_v1_projection()?;
        Ok(Activation {
            schema_version: ContractVersionOne::default(),
            registry_digest: registry.canonical_digest()?,
            registry,
            epoch: self.epoch.clone(),
            revoked_admissions: self.revoked_admissions.clone(),
        })
    }
}

pub enum VersionedActivation {
    V1(Activation),
    V2(ActivationV2),
}

impl VersionedActivation {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len()
            > memcordon_core::workload_limits::REGISTRY_BYTES
                + memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
        {
            return Err("policy activation exceeds bound".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        let version = schema_version(bytes)?;
        match version {
            1 => {
                let value: Activation =
                    serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
                value.validate()?;
                Ok(Self::V1(value))
            }
            2 => {
                let value: ActivationV2 =
                    serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
                value.validate()?;
                Ok(Self::V2(value))
            }
            _ => Err("unsupported policy activation schema version".into()),
        }
    }
}

pub(crate) enum RegistryConfiguration {
    V1(PolicyRegistryV1),
    V2(PolicyRegistryV2),
}

impl RegistryConfiguration {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        match schema_version(bytes)? {
            1 => PolicyRegistryV1::parse(bytes).map(Self::V1),
            2 => PolicyRegistryV2::parse(bytes).map(Self::V2),
            _ => Err("unsupported policy registry schema version".into()),
        }
    }
}

fn schema_version(bytes: &[u8]) -> Result<u64, String> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .map_err(|error| error.to_string())?
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "policy document has no numeric schema version".into())
}

pub fn read_configuration(path: &Path) -> Result<PolicyRegistryV1, String> {
    PolicyRegistryV1::parse(&read_configuration_bytes(path)?)
}

fn read_configuration_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("policy configuration is not regular".into());
    }
    let mut bytes = Vec::new();
    file.take(memcordon_core::workload_limits::REGISTRY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn read_configuration_any(path: &Path) -> Result<RegistryConfiguration, String> {
    let bytes = read_configuration_bytes(path)?;
    RegistryConfiguration::parse(&bytes)
}

#[cfg(target_os = "linux")]
pub fn inspect() -> Result<(), String> {
    let lease = native::Lease::acquire()?;
    match lease.read_any()? {
        None => println!("null"),
        Some(VersionedActivation::V1(activation)) => println!(
            "{}",
            serde_json::to_string(&activation).map_err(|error| error.to_string())?
        ),
        Some(VersionedActivation::V2(activation)) => println!(
            "{}",
            serde_json::to_string(&activation).map_err(|error| error.to_string())?
        ),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn apply(path: &Path) -> Result<(), String> {
    // Exclude package replacement while allowing policy changes during live launches.
    let _package = crate::linux::service::acquire_shared_package_lease()?;
    let registry = read_configuration_any(path)?;
    let lease = native::Lease::acquire()?;
    let revoke = match &registry {
        RegistryConfiguration::V1(registry) => registry.active_attempt_disposition,
        RegistryConfiguration::V2(registry) => registry.active_attempt_disposition,
    } == memcordon_core::workload_registry::GrantChangeDisposition::RevokeActive;
    let active = lease.live_bindings()?;
    let activation = match registry {
        RegistryConfiguration::V1(registry) => {
            serde_json::to_value(lease.activate(registry, None)?)
        }
        RegistryConfiguration::V2(registry) => {
            serde_json::to_value(lease.activate_v2(registry, None)?)
        }
    }
    .map_err(|error| error.to_string())?;
    drop(lease);
    if revoke {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let lease = native::Lease::acquire()?;
            let remaining = lease.live_bindings()?;
            if active
                .iter()
                .all(|(identity, _)| !remaining.iter().any(|(other, _)| other == identity))
            {
                break;
            }
            drop(lease);
            if std::time::Instant::now() >= deadline {
                return Err(
                    "policy revocation activated but retirement was not observed before deadline"
                        .into(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    println!(
        "{}",
        serde_json::to_string(&activation).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub mod native {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::time::{Duration, Instant};

    pub struct Lease {
        directory: File,
        lock: File,
    }
    impl Lease {
        pub fn retain_snapshot(&self, registry: &PolicyRegistryV1) -> Result<(), String> {
            let digest = registry.canonical_digest()?;
            let bytes = serde_json::to_vec(registry).map_err(|error| error.to_string())?;
            self.retain_snapshot_encoded(&digest, &bytes, 1)
        }

        fn retain_snapshot_v2(&self, registry: &PolicyRegistryV2) -> Result<(), String> {
            let digest = registry.canonical_digest()?;
            let bytes = serde_json::to_vec(registry).map_err(|error| error.to_string())?;
            self.retain_snapshot_encoded(&digest, &bytes, 2)
        }

        fn retain_snapshot_encoded(
            &self,
            digest: &DiagnosticSha256,
            bytes: &[u8],
            version: u32,
        ) -> Result<(), String> {
            self.check_capacity(digest)?;
            let mut retained = std::collections::BTreeSet::new();
            retained.insert(String::from(digest.clone()));
            for (_, binding) in self.live_bindings()? {
                retained.insert(String::from(binding.registry_digest));
            }
            if let Some(active) = self.read_any()? {
                let active_digest = match active {
                    VersionedActivation::V1(active) => active.registry_digest,
                    VersionedActivation::V2(active) => active.registry_digest,
                };
                retained.insert(String::from(active_digest));
            }
            for entry in
                std::fs::read_dir("/var/lib/memcordon/policy").map_err(|error| error.to_string())?
            {
                let entry = entry.map_err(|error| error.to_string())?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    return Err("nontext policy directory entry".into());
                };
                if let Some(digest) = name.strip_suffix(".snapshot") {
                    if !retained.contains(digest) {
                        let name =
                            std::ffi::CString::new(name).map_err(|error| error.to_string())?;
                        // SAFETY: exact child name and retained protected directory.
                        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) }
                            != 0
                        {
                            return Err(std::io::Error::last_os_error().to_string());
                        }
                    }
                }
            }
            let path =
                std::path::PathBuf::from(String::from(digest.clone())).with_extension("snapshot");
            use std::os::unix::ffi::OsStrExt;
            let name = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|error| error.to_string())?;
            if bytes.len() > memcordon_core::workload_limits::REGISTRY_BYTES {
                return Err("encoded registry exceeds limit".into());
            }
            match open_at(
                &self.directory,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            ) {
                Ok(mut file) => {
                    file.write_all(bytes)
                        .and_then(|()| file.sync_all())
                        .map_err(|error| error.to_string())?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let file = open_at(&self.directory, &name, libc::O_RDONLY)
                        .map_err(|error| error.to_string())?;
                    let mut existing = Vec::new();
                    file.take(memcordon_core::workload_limits::REGISTRY_BYTES as u64 + 1)
                        .read_to_end(&mut existing)
                        .map_err(|error| error.to_string())?;
                    let existing_digest = match version {
                        1 => PolicyRegistryV1::parse(&existing)?.canonical_digest()?,
                        2 => PolicyRegistryV2::parse(&existing)?.canonical_digest()?,
                        _ => return Err("unsupported policy snapshot version".into()),
                    };
                    if existing_digest != *digest {
                        return Err("immutable policy snapshot differs".into());
                    }
                }
                Err(error) => return Err(error.to_string()),
            }
            self.directory.sync_all().map_err(|error| error.to_string())
        }
        pub fn live_bindings(
            &self,
        ) -> Result<Vec<(String, crate::admission::FrozenAdmission)>, String> {
            let mut references = Vec::new();
            for entry in
                std::fs::read_dir(crate::linux::STATE_ROOT).map_err(|error| error.to_string())?
            {
                let entry = entry.map_err(|error| error.to_string())?;
                let name = entry.file_name();
                let Some(identity) = name
                    .to_str()
                    .filter(|value| crate::linux::cgroup::valid_attempt_identity(value))
                else {
                    continue;
                };
                let record = match crate::linux::recovery::read_record_no_follow(&entry.path()) {
                    Ok(record) => record,
                    Err(_) if !entry.path().exists() => continue,
                    Err(error) => return Err(error),
                };
                if let Some(binding) = crate::linux::attempt::parse_durable_policy(&record)? {
                    if references.len() == memcordon_core::workload_limits::LIVE_BINDINGS {
                        return Err("policy live reference capacity exceeded".into());
                    }
                    references.push((identity.into(), binding));
                }
            }
            Ok(references)
        }

        pub fn check_capacity(&self, candidate: &DiagnosticSha256) -> Result<(), String> {
            let references = self.live_bindings()?;
            let mut snapshots = std::collections::BTreeSet::new();
            snapshots.insert(*candidate.bytes());
            for (_, binding) in references {
                snapshots.insert(*binding.registry_digest.bytes());
            }
            if let Some(active) = self.read_any()? {
                let active_digest = match active {
                    VersionedActivation::V1(active) => active.registry_digest,
                    VersionedActivation::V2(active) => active.registry_digest,
                };
                snapshots.insert(*active_digest.bytes());
            }
            if snapshots.len() > memcordon_core::workload_limits::SNAPSHOTS {
                return Err("policy snapshot capacity exhausted".into());
            }
            Ok(())
        }
        pub fn acquire() -> Result<Self, String> {
            // SAFETY: geteuid has no pointer preconditions.
            if unsafe { libc::geteuid() } != 0 {
                return Err("policy registry requires authenticated root administration".into());
            }
            let root = Path::new("/var/lib/memcordon/policy");
            let mut walked = std::path::PathBuf::new();
            for component in root.components() {
                walked.push(component.as_os_str());
                if walked == root {
                    match std::fs::DirBuilder::new().mode(0o700).create(root) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error.to_string()),
                    }
                }
                let metadata =
                    std::fs::symlink_metadata(&walked).map_err(|error| error.to_string())?;
                if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    return Err("policy state ancestor ownership or mode differs".into());
                }
            }
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(root)
                .map_err(|error| error.to_string())?;
            let lock = open_at(&directory, c"policy.lock", libc::O_RDWR | libc::O_CREAT)
                .map_err(|error| error.to_string())?;
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                // SAFETY: lock is an owned open file; nonblocking flock only changes its advisory lock.
                if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EWOULDBLOCK) || Instant::now() >= deadline {
                    return Err(error.to_string());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(Self { directory, lock })
        }
        pub fn read(&self) -> Result<Option<Activation>, String> {
            match self.read_any()? {
                None => Ok(None),
                Some(VersionedActivation::V1(value)) => Ok(Some(value)),
                Some(VersionedActivation::V2(value)) => value.baseline_projection().map(Some),
            }
        }

        pub fn read_v2(&self) -> Result<Option<ActivationV2>, String> {
            match self.read_any()? {
                Some(VersionedActivation::V2(value)) => Ok(Some(value)),
                _ => Ok(None),
            }
        }

        pub fn read_any(&self) -> Result<Option<VersionedActivation>, String> {
            let file = match open_at(&self.directory, c"policy-activation.json", libc::O_RDONLY) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.to_string()),
            };
            let limit = memcordon_core::workload_limits::REGISTRY_BYTES
                + memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES;
            let mut bytes = Vec::new();
            file.take(limit as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            if bytes.len() > limit {
                return Err("policy activation exceeds bound".into());
            }
            VersionedActivation::parse(&bytes).map(Some)
        }
        pub fn activate(
            &self,
            registry: PolicyRegistryV1,
            instance: Option<Nonce128>,
        ) -> Result<Activation, String> {
            registry.validate()?;
            self.check_capacity(&registry.canonical_digest()?)?;
            self.retain_snapshot(&registry)?;
            let previous = self.read()?;
            let revoked_admissions = Activation::next_revocations(
                previous.as_ref(),
                registry.active_attempt_disposition,
                &self.live_bindings()?,
            )?;
            let epoch = match (instance, previous) {
                (Some(service_instance), _) => PolicyEpoch {
                    service_instance,
                    revision: NonZeroU64::MIN,
                },
                (None, Some(previous)) => PolicyEpoch {
                    service_instance: previous.epoch.service_instance,
                    revision: NonZeroU64::new(
                        previous
                            .epoch
                            .revision
                            .get()
                            .checked_add(1)
                            .ok_or("policy revision exhausted")?,
                    )
                    .ok_or("zero policy revision")?,
                },
                (None, None) => PolicyEpoch {
                    service_instance: random_nonce()?,
                    revision: NonZeroU64::MIN,
                },
            };
            let value = Activation {
                schema_version: ContractVersionOne::default(),
                registry_digest: registry.canonical_digest()?,
                registry,
                epoch,
                revoked_admissions,
            };
            self.write_activation(&value)?;
            Ok(value)
        }

        pub fn activate_v2(
            &self,
            registry: PolicyRegistryV2,
            instance: Option<Nonce128>,
        ) -> Result<ActivationV2, String> {
            registry.validate()?;
            self.check_capacity(&registry.canonical_digest()?)?;
            self.retain_snapshot_v2(&registry)?;
            let previous = self.read()?;
            let revoked_admissions = Activation::next_revocations(
                previous.as_ref(),
                registry.active_attempt_disposition,
                &self.live_bindings()?,
            )?;
            let epoch = match (instance, previous) {
                (Some(service_instance), _) => PolicyEpoch {
                    service_instance,
                    revision: NonZeroU64::MIN,
                },
                (None, Some(previous)) => PolicyEpoch {
                    service_instance: previous.epoch.service_instance,
                    revision: NonZeroU64::new(
                        previous
                            .epoch
                            .revision
                            .get()
                            .checked_add(1)
                            .ok_or("policy revision exhausted")?,
                    )
                    .ok_or("zero policy revision")?,
                },
                (None, None) => PolicyEpoch {
                    service_instance: random_nonce()?,
                    revision: NonZeroU64::MIN,
                },
            };
            let value = ActivationV2 {
                schema_version: ContractVersionTwo::default(),
                registry_digest: registry.canonical_digest()?,
                registry,
                epoch,
                revoked_admissions,
            };
            value.validate()?;
            self.write_activation(&value)?;
            Ok(value)
        }

        fn write_activation<T: Serialize>(&self, value: &T) -> Result<(), String> {
            let mut bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
            if bytes.len()
                > memcordon_core::workload_limits::REGISTRY_BYTES
                    + memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
            {
                return Err("encoded activation exceeds limit".into());
            }
            bytes.push(b'\n');
            // A fixed staging name is safe under the registry lease; prior uncommitted
            // staging files are never treated as activated authority.
            let mut staging = open_at(
                &self.directory,
                c"policy-activation.pending",
                libc::O_WRONLY | libc::O_CREAT,
            )
            .map_err(|error| error.to_string())?;
            staging.set_len(0).map_err(|error| error.to_string())?;
            staging
                .write_all(&bytes)
                .and_then(|()| staging.sync_all())
                .map_err(|error| error.to_string())?;
            // SAFETY: both names are fixed children of the retained protected directory.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    c"policy-activation.pending".as_ptr(),
                    self.directory.as_raw_fd(),
                    c"policy-activation.json".as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            self.directory
                .sync_all()
                .map_err(|error| error.to_string())?;
            Ok(())
        }
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            // SAFETY: the owned descriptor is valid until after this destructor.
            unsafe {
                libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
    fn open_at(directory: &File, name: &std::ffi::CStr, flags: i32) -> std::io::Result<File> {
        // SAFETY: path is a fixed terminated relative name and directory is retained.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful openat transferred an owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(std::io::Error::other(
                "policy file ownership, mode or link count differs",
            ));
        }
        Ok(file)
    }
    pub fn random_nonce() -> Result<Nonce128, String> {
        let mut bytes = [0_u8; 16];
        let mut filled = 0;
        while filled < bytes.len() {
            // SAFETY: the remaining slice is valid writable memory.
            let read = unsafe {
                libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
            };
            if read < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if read == 0 {
                return Err("random source made no progress".into());
            }
            filled += read as usize;
        }
        Ok(Nonce128(bytes))
    }
}

#[cfg(target_os = "linux")]
pub fn start_service_instance() -> Result<(), String> {
    let lease = native::Lease::acquire()?;
    let instance = native::random_nonce()?;
    match lease.read_any()? {
        Some(VersionedActivation::V2(previous)) => {
            lease.activate_v2(previous.registry, Some(instance))?;
        }
        previous => {
            let registry = match previous {
                Some(VersionedActivation::V1(previous)) => previous.registry,
                _ => PolicyRegistryV1 {
                    schema_version: ContractVersionOne::default(),
                    profiles: BoundedVec::default(),
                    grants: BoundedVec::default(),
                    active_attempt_disposition:
                        memcordon_core::workload_registry::GrantChangeDisposition::DrainExisting,
                },
            };
            lease.activate(registry, Some(instance))?;
        }
    }
    Ok(())
}
