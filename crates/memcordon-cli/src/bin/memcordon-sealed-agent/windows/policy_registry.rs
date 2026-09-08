//! Protected administrator policy, separate from private attempt records.
use super::pipe::OwnedHandle;
use super::security::SecurityDescriptor;
use crate::policy_registry::Activation;
use memcordon_core::workload_contract::{ContractVersionOne, Nonce128, PolicyEpoch};
use memcordon_core::workload_registry::PolicyRegistryV1;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroU64;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

pub fn root() -> PathBuf {
    super::package::state_root()
        .parent()
        .expect("sealed state has parent")
        .join("policy")
}
pub fn install() -> Result<(), String> {
    super::package::create_secure_directory(
        &root(),
        &SecurityDescriptor::from_sddl(&super::security::state_bootstrap_sddl()?)?,
        "policy registry directory",
    )
}

pub struct RetiredPolicySnapshot {
    entries: Vec<(std::ffi::OsString, Vec<u8>)>,
}

fn owned_policy_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    matches!(name, "policy-activation.json" | "policy-activation.pending")
        || name.strip_suffix(".snapshot").is_some_and(|digest| {
            digest.len() == std::mem::size_of::<[u8; 32]>() * 2
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

pub fn capture_retired() -> Result<Option<RetiredPolicySnapshot>, String> {
    match std::fs::symlink_metadata(root()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
        Ok(_) => {}
    }
    let lease = Lease::acquire()?;
    if !lease.live_bindings()?.is_empty() {
        return Err("policy snapshots still have active attempt references".into());
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(root()).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if !owned_policy_name(&entry.file_name())
            || entries.len() >= memcordon_core::workload_limits::SNAPSHOTS + 2
        {
            return Err("policy directory contains unknown or excessive entries".into());
        }
        let file = open_regular(&entry.path()).map_err(|error| error.to_string())?;
        let limit = memcordon_core::workload_limits::REGISTRY_BYTES
            + memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES;
        let mut bytes = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > limit {
            return Err("policy rollback snapshot exceeds limit".into());
        }
        entries.push((entry.file_name(), bytes));
    }
    Ok(Some(RetiredPolicySnapshot { entries }))
}

pub fn remove_retired() -> Result<(), String> {
    let Some(snapshot) = capture_retired()? else {
        return Ok(());
    };
    let lease = Lease::acquire()?;
    if !lease.live_bindings()?.is_empty() {
        return Err("policy references appeared during package removal".into());
    }
    for (name, _) in snapshot.entries {
        std::fs::remove_file(root().join(name)).map_err(|error| error.to_string())?;
    }
    drop(lease);
    std::fs::remove_dir(root()).map_err(|error| error.to_string())
}

pub fn restore_retired(snapshot: &RetiredPolicySnapshot) -> Result<(), String> {
    install()?;
    let lease = Lease::acquire()?;
    if !lease.live_bindings()?.is_empty() {
        return Err("cannot restore policy while attempts remain live".into());
    }
    for (name, bytes) in &snapshot.entries {
        let path = root().join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("policy rollback destination is not regular".into());
        }
        file.set_len(0)
            .and_then(|()| file.write_all(bytes))
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}
pub struct Lease {
    _directory: File,
    mutex: OwnedHandle,
}
impl Lease {
    pub fn live_bindings(
        &self,
    ) -> Result<
        Vec<(
            String,
            memcordon_core::workload_registry::ProviderAdmissionSnapshotV1,
        )>,
        String,
    > {
        let mut references = Vec::new();
        for entry in std::fs::read_dir(root()).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name();
            let Some(identity) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".reference"))
            else {
                continue;
            };
            super::record::validate_attempt_id(identity)?;
            if references.len() == memcordon_core::workload_limits::LIVE_BINDINGS {
                return Err("policy reference count exceeds limit".into());
            }
            let file = open_regular(&entry.path()).map_err(|error| error.to_string())?;
            let mut bytes = Vec::new();
            file.take(memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            if bytes.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
                return Err("policy reference exceeds limit".into());
            }
            let snapshot: memcordon_core::workload_registry::ProviderAdmissionSnapshotV1 =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            snapshot.validate()?;
            references.push((identity.into(), snapshot));
        }
        Ok(references)
    }
    pub fn retain_snapshot(&self, registry: &PolicyRegistryV1) -> Result<(), String> {
        let digest = registry.canonical_digest()?;
        let mut retained = std::collections::BTreeSet::new();
        retained.insert(String::from(digest.clone()));
        for (_, binding) in self.live_bindings()? {
            retained.insert(String::from(binding.registry_digest));
        }
        if retained.len() > memcordon_core::workload_limits::SNAPSHOTS {
            return Err("policy immutable snapshot capacity exhausted".into());
        }
        for entry in std::fs::read_dir(root()).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name();
            if let Some(digest) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".snapshot"))
            {
                if !retained.contains(digest) {
                    let file = open_regular(&entry.path()).map_err(|error| error.to_string())?;
                    drop(file);
                    std::fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
                }
            }
        }
        let destination = root().join(String::from(digest)).with_extension("snapshot");
        let bytes = serde_json::to_vec(registry).map_err(|error| error.to_string())?;
        if bytes.len() > memcordon_core::workload_limits::REGISTRY_BYTES {
            return Err("encoded registry exceeds bound".into());
        }
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&destination)
        {
            Ok(mut file) => file
                .write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| error.to_string())?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let file = open_regular(&destination).map_err(|error| error.to_string())?;
                let mut existing = Vec::new();
                file.take(memcordon_core::workload_limits::REGISTRY_BYTES as u64 + 1)
                    .read_to_end(&mut existing)
                    .map_err(|error| error.to_string())?;
                if PolicyRegistryV1::parse(&existing)?.canonical_digest()?
                    != registry.canonical_digest()?
                {
                    return Err("immutable registry snapshot differs".into());
                }
            }
            Err(error) => return Err(error.to_string()),
        }
        Ok(())
    }
    pub fn register_reference(
        &self,
        attempt_id: &str,
        snapshot: &memcordon_core::workload_registry::ProviderAdmissionSnapshotV1,
    ) -> Result<(), String> {
        super::record::validate_attempt_id(attempt_id)?;
        snapshot.validate()?;
        if self.live_bindings()?.len() >= memcordon_core::workload_limits::LIVE_BINDINGS {
            return Err("policy live reference capacity exhausted".into());
        }
        let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
        if bytes.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("policy reference exceeds limit".into());
        }
        let destination = root().join(attempt_id).with_extension("reference");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(destination)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())
    }
    pub fn acquire() -> Result<Self, String> {
        let root = root();
        super::package::reject_reparse_components(&root)?;
        SecurityDescriptor::from_sddl(&super::security::state_bootstrap_sddl()?)?
            .verify_path(&root)?;
        let directory = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS,
            )
            .open(&root)
            .map_err(|error| error.to_string())?;
        let control = super::security::service_sid(memcordon_core::WINDOWS_CONTROL_SERVICE_NAME)?;
        let launcher = super::security::service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)?;
        let security = SecurityDescriptor::from_sddl(&format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{control})(A;;GA;;;{launcher})"
        ))?;
        let attributes = security.attributes(false);
        let name = super::pipe::wide_null(r"Global\MemCordonWorkloadPolicyV1");
        // SAFETY: security attributes and terminated name remain live for creation.
        let mutex =
            OwnedHandle::new(unsafe { CreateMutexW(&raw const attributes, 0, name.as_ptr()) })?;
        security.verify_kernel_object(mutex.raw(), super::security::SecurityObjectKind::Mutex)?;
        // SAFETY: the owned mutex handle is valid; waiting is bounded.
        let wait = unsafe { WaitForSingleObject(mutex.raw(), 30_000) };
        if !matches!(wait, WAIT_OBJECT_0 | WAIT_ABANDONED) {
            return Err("policy activation mutex unavailable".into());
        }
        Ok(Self {
            _directory: directory,
            mutex,
        })
    }
    pub fn read(&self) -> Result<Option<Activation>, String> {
        let path = root().join("policy-activation.json");
        let file = match open_regular(&path) {
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
            return Err("policy activation exceeds limit".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
        let activation: Activation =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        activation.validate()?;
        Ok(Some(activation))
    }
    pub fn activate(
        &self,
        registry: PolicyRegistryV1,
        instance: Option<Nonce128>,
    ) -> Result<Activation, String> {
        registry.validate()?;
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
                        .ok_or("policy epoch exhausted")?,
                )
                .ok_or("zero policy epoch")?,
            },
            (None, None) => PolicyEpoch {
                service_instance: random_nonce()?,
                revision: NonZeroU64::MIN,
            },
        };
        let activation = Activation {
            schema_version: ContractVersionOne::default(),
            registry_digest: registry.canonical_digest()?,
            registry,
            epoch,
            revoked_admissions,
        };
        let mut bytes = serde_json::to_vec(&activation).map_err(|error| error.to_string())?;
        if bytes.len()
            > memcordon_core::workload_limits::REGISTRY_BYTES
                + memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
        {
            return Err("encoded activation exceeds limit".into());
        }
        bytes.push(b'\n');
        let staged = root().join("policy-activation.pending");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&staged)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("policy activation staging file is not regular".into());
        }
        file.set_len(0)
            .and_then(|()| file.write_all(&bytes))
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        drop(file);
        super::record::replace_atomically(&staged, &root().join("policy-activation.json"))?;
        Ok(activation)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        // SAFETY: this thread acquired the retained mutex handle.
        unsafe {
            ReleaseMutex(self.mutex.raw());
        }
    }
}
fn open_regular(path: &std::path::Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other("policy file is not regular"));
    }
    Ok(file)
}
pub fn random_nonce() -> Result<Nonce128, String> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut bytes = [0_u8; 16];
    // SAFETY: byte buffer is writable and its exact length is supplied.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err("policy service nonce generation failed".into());
    }
    Ok(Nonce128(bytes))
}

pub fn start_service_instance() -> Result<(), String> {
    let lease = Lease::acquire()?;
    let registry = match lease.read()? {
        Some(previous) => previous.registry,
        None => PolicyRegistryV1 {
            schema_version: ContractVersionOne::default(),
            profiles: memcordon_core::BoundedVec::default(),
            grants: memcordon_core::BoundedVec::default(),
            active_attempt_disposition:
                memcordon_core::workload_registry::GrantChangeDisposition::DrainExisting,
        },
    };
    lease.activate(registry, Some(random_nonce()?))?;
    Ok(())
}

pub fn inspect() -> Result<(), String> {
    let lease = Lease::acquire()?;
    println!(
        "{}",
        serde_json::to_string(&lease.read()?).map_err(|error| error.to_string())?
    );
    Ok(())
}

pub fn apply(path: &std::path::Path) -> Result<(), String> {
    let _package_lease = super::package::PackageLease::acquire()?;
    let registry = crate::policy_registry::read_configuration(path)?;
    let lease = Lease::acquire()?;
    let revoke = registry.active_attempt_disposition
        == memcordon_core::workload_registry::GrantChangeDisposition::RevokeActive;
    let active = lease.live_bindings()?;
    let activation = lease.activate(registry, None)?;
    drop(lease);
    if revoke {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let lease = Lease::acquire()?;
            let remaining = lease.live_bindings()?;
            if active
                .iter()
                .all(|(identity, _)| !remaining.iter().any(|(other, _)| other == identity))
            {
                break;
            }
            drop(lease);
            if std::time::Instant::now() >= deadline {
                return Err("policy revocation activated but retirement was not observed".into());
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

pub fn retire_reference(attempt_id: &str) -> Result<(), String> {
    super::record::validate_attempt_id(attempt_id)?;
    let _lease = Lease::acquire()?;
    let path = root().join(attempt_id).with_extension("reference");
    match open_regular(&path) {
        Ok(file) => {
            drop(file);
            std::fs::remove_file(path).map_err(|error| error.to_string())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}
