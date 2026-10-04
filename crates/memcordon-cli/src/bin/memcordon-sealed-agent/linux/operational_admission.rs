//! Live private admission owns authenticated kernel handles and local grants.
//! Durable metadata can describe this object but cannot reconstruct it.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use memcordon_core::workload_contract::{ExecutionIdentityRequestV2, Nonce128};
use memcordon_core::workload_registry::CallerSelector;
use memcordon_core::workload_registry_v2::{ProfileKindV2, resolve_v2};

use crate::policy_registry::ActivationV2;
use crate::request::NativePrivateLaunchInput;

use super::envelope::CapturedCallerEnvelopeV2;
use super::launch::{PrivatePrelaunchAuthority, pin_private_prelaunch_authority};
use super::private_attempt::ProcessIdentityV4;

/// This capacity remains charged after owner loss. Only verified native
/// retirement may unlink it; closing a file or parsing a journal is insufficient.
pub(crate) struct AccountReservation {
    directory: File,
    file: File,
    path: PathBuf,
}

impl AccountReservation {
    fn reserve(
        caller: &CapturedCallerEnvelopeV2,
        uid: u32,
        attempt: [u8; 16],
    ) -> Result<Self, String> {
        super::attempt::secure_state_root()?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(super::STATE_ROOT)
            .map_err(|error| error.to_string())?;
        let namespace = caller.envelope.user_namespace_identity;
        let name = format!(
            "account-{}-{}-{uid}.reservation",
            namespace.device, namespace.inode
        );
        let path = PathBuf::from(super::STATE_ROOT).join(&name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    "MCSEALED-PRIVATE-BUSY: target account remains reserved".into()
                } else {
                    error.to_string()
                }
            })?;
        let bytes = serde_json::to_vec(&serde_json::json!({
            "format": "memcordon.account-reservation", "revision": 1,
            "user_namespace_device": namespace.device,
            "user_namespace_inode": namespace.inode, "uid": uid, "attempt": attempt,
            "owner_pid": unsafe { libc::getpid() },
            "owner_birth": super::envelope::process_start_time(unsafe { libc::getpid() })?,
            "boot_identity": std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|error| error.to_string())?.trim(),
        }))
        .map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(Self {
            directory,
            file,
            path,
        })
    }

    pub(super) fn retire(self) -> Result<(), String> {
        let held = self.file.metadata().map_err(|error| error.to_string())?;
        let current = std::fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        if !current.is_file()
            || current.nlink() != 1
            || current.uid() != 0
            || current.mode() & 0o7777 != 0o600
            || (held.dev(), held.ino()) != (current.dev(), current.ino())
        {
            return Err("MCSEALED-PRIVATE-ACCOUNT: reservation identity changed".into());
        }
        std::fs::remove_file(&self.path).map_err(|error| error.to_string())?;
        self.directory.sync_all().map_err(|error| error.to_string())
    }
}

/// No Deserialize, Clone, or public constructor: the authenticated dispatcher
/// supplies native credentials and descriptors, then the resolver selects policy.
pub(crate) struct OperationalAdmission {
    pub(super) input: NativePrivateLaunchInput,
    pub(super) caller: CapturedCallerEnvelopeV2,
    pub(super) frontend_pidfd: OwnedFd,
    pub(super) frontend: ProcessIdentityV4,
    pub(super) activation: ActivationV2,
    pub(super) nonce: Nonce128,
    pub(super) attempt: [u8; 16],
    prelaunch: Option<PrivatePrelaunchAuthority>,
    reservation: Option<AccountReservation>,
    revoked: bool,
    released: bool,
}

pub(super) struct AdmissionFailure {
    pub detail: String,
    pub reservation_may_remain: bool,
}

impl OperationalAdmission {
    pub(super) fn authenticate(
        input: NativePrivateLaunchInput,
        caller: CapturedCallerEnvelopeV2,
        attempt: [u8; 16],
    ) -> Result<Self, AdmissionFailure> {
        let mut admitted =
            Self::authenticate_unreserved(input, caller, attempt).map_err(|detail| {
                AdmissionFailure {
                    detail,
                    reservation_may_remain: false,
                }
            })?;
        let reservation = AccountReservation::reserve(
            &admitted.caller,
            admitted
                .prelaunch
                .as_ref()
                .expect("authenticated held prelaunch")
                .target_identity()
                .uid(),
            attempt,
        )
        .map_err(|detail| AdmissionFailure {
            detail,
            reservation_may_remain: true,
        })?;
        admitted.reservation = Some(reservation);
        Ok(admitted)
    }

    fn authenticate_unreserved(
        input: NativePrivateLaunchInput,
        caller: CapturedCallerEnvelopeV2,
        attempt: [u8; 16],
    ) -> Result<Self, String> {
        if attempt == [0; 16] {
            return Err("MCSEALED-PRIVATE-ATTEMPT: empty identity".into());
        }
        for (name, _) in &input.launch.environment {
            if name.starts_with(b"LD_") || name == b"GLIBC_TUNABLES" || name.starts_with(b"DYLD_") {
                return Err("MCSEALED-PRIVATE-ENV: caller-controlled dynamic loader configuration is unsupported".into());
            }
        }
        super::envelope::verify_live(&caller.envelope)?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, caller.envelope.pid, 0) } as i32;
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: successful pidfd_open returns a uniquely owned descriptor.
        let frontend_pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let frontend = ProcessIdentityV4::observe(caller.envelope.pid, frontend_pidfd.as_fd())?;
        if frontend.start_time != caller.envelope.process_start_time {
            return Err("MCSEALED-PRIVATE-CALLER: native birth changed".into());
        }
        let lease = crate::policy_registry::native::Lease::acquire()?;
        let activation = lease
            .read_v2()?
            .ok_or("MCSEALED-PRIVATE-POLICY: active private registry absent")?;
        if lease.versioned_live_bindings()?.len() >= memcordon_core::workload_limits::LIVE_BINDINGS
        {
            return Err("MCSEALED-PRIVATE-BUSY: native attempt capacity exhausted".into());
        }
        let selector = CallerSelector::Linux {
            uid: caller.envelope.uid,
        };
        resolve_v2(
            &activation.registry,
            &activation.epoch,
            &input.contract,
            &selector,
            ProfileKindV2::LinuxTcp4PrivateV1,
        )
        .map_err(|error| format!("MCSEALED-PRIVATE-POLICY: {:?}", error.code))?;
        let identity = match &input.contract.execution_identity {
            ExecutionIdentityRequestV2::PreserveCaller => None,
            ExecutionIdentityRequestV2::AdministratorProfile { reference } => activation
                .registry
                .execution_identities
                .as_slice()
                .iter()
                .find(|value| value.reference == *reference),
        };
        let prelaunch = pin_private_prelaunch_authority(
            &input,
            identity,
            &caller.envelope,
            caller.root.as_fd(),
            0,
            0,
        )?;
        lease.retain_snapshot_v2(&activation.registry)?;
        let nonce = crate::policy_registry::native::random_nonce()?;
        drop(lease);
        Ok(Self {
            input,
            caller,
            frontend_pidfd,
            frontend,
            activation,
            nonce,
            attempt,
            prelaunch: Some(prelaunch),
            reservation: None,
            revoked: false,
            released: false,
        })
    }

    pub(super) fn take_prelaunch(&mut self) -> Result<PrivatePrelaunchAuthority, String> {
        self.prelaunch
            .take()
            .ok_or_else(|| "MCSEALED-PRIVATE-ENTRYPOINT: already consumed".into())
    }

    /// Slow native preparation happens before this short activation lock. The
    /// checked release operation runs while activation changes remain excluded.
    pub(super) fn release<T>(
        &mut self,
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        if self.released || self.revoked {
            return Err("MCSEALED-PRIVATE-RELEASE: already decided".into());
        }
        super::envelope::verify_live(&self.caller.envelope)?;
        if ProcessIdentityV4::observe(self.caller.envelope.pid, self.frontend_pidfd.as_fd())?
            != self.frontend
        {
            return Err("MCSEALED-PRIVATE-CALLER: frontend identity changed before release".into());
        }
        let lease = crate::policy_registry::native::Lease::acquire()?;
        let active = lease
            .read_v2()?
            .ok_or("MCSEALED-PRIVATE-POLICY: activation absent")?;
        if active.epoch != self.activation.epoch
            || active.registry_digest != self.activation.registry_digest
        {
            return Err("MCSEALED-POLICY-EPOCH-STALE: local policy changed before release".into());
        }
        if active.revoked_admissions.as_slice().contains(&self.nonce) {
            self.revoked = true;
            return Err("MCSEALED-PRIVATE-REVOKED: local cancellation latched".into());
        }
        resolve_v2(
            &active.registry,
            &active.epoch,
            &self.input.contract,
            &CallerSelector::Linux {
                uid: self.caller.envelope.uid,
            },
            ProfileKindV2::LinuxTcp4PrivateV1,
        )
        .map_err(|error| format!("MCSEALED-PRIVATE-POLICY: {:?}", error.code))?;
        // A failed write may have transferred bytes. Never retry this decision.
        self.released = true;
        operation()
    }

    pub(super) fn revoked(&mut self) -> Result<bool, String> {
        let lease = crate::policy_registry::native::Lease::acquire()?;
        let active = lease
            .read_v2()?
            .ok_or("MCSEALED-PRIVATE-POLICY: activation absent")?;
        self.revoked |= active.revoked_admissions.as_slice().contains(&self.nonce);
        Ok(self.revoked)
    }

    pub(super) fn metadata(
        &self,
    ) -> Result<memcordon_core::workload_admission_v2::RuntimePrivateAdmissionSnapshot, String>
    {
        let value = memcordon_core::workload_admission_v2::RuntimePrivateAdmissionSnapshot {
            format: "memcordon.private-admission-metadata".into(),
            revision: 1,
            request: self.input.contract.clone(),
            request_sha256: memcordon_core::workload_codec::contract_digest_v2(
                &self.input.contract,
            )?,
            invocation_sha256: memcordon_core::workload_codec::hash_bytes(
                &crate::request::encode_launch_request(&self.input.launch)
                    .map_err(|error| format!("private invocation codec: {error:?}"))?,
            ),
            caller: CallerSelector::Linux {
                uid: self.caller.envelope.uid,
            },
            registry_digest: self.activation.registry_digest.clone(),
            epoch: self.activation.epoch.clone(),
            admission_nonce: self.nonce,
            profile_id: self.input.contract.authorized_profile.clone(),
        };
        value.validate()?;
        Ok(value)
    }

    pub(super) fn retire_account(
        mut self,
        retired: &super::private_lifecycle::PrivateRetirementObservation,
    ) -> Result<(), String> {
        if retired.attempt_id()
            != self
                .attempt
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        {
            return Err(
                "MCSEALED-PRIVATE-ACCOUNT: verified retirement belongs to another attempt".into(),
            );
        }
        self.reservation
            .take()
            .ok_or("MCSEALED-PRIVATE-ACCOUNT: owner absent")?
            .retire()
    }
}
