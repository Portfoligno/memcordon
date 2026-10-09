//! Live mixed admission owns native account/image references; serialized metadata is descriptive.
use super::execution_identity::ResolvedTargetIdentity;
use super::operational_admission::AccountReservation;
use super::runtime_image::InstalledRuntimeImage;
use memcordon_core::BoundedText;
use memcordon_core::workload_admission_v3::RuntimeMixedAdmissionSnapshot;
use memcordon_core::workload_contract_v3::WorkloadContractV3;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

pub struct MixedOperationalAdmission {
    pub(super) contract: WorkloadContractV3,
    pub(super) launch: crate::request::LaunchRequestV2,
    pub(super) caller: super::envelope::CapturedCallerEnvelopeV2,
    pub(super) frontend_pidfd: OwnedFd,
    pub(super) frontend: super::private_attempt::ProcessIdentityV4,
    pub(super) identity: ResolvedTargetIdentity,
    pub(super) activation: crate::policy_registry::ActivationV3,
    pub(super) runtime: Option<InstalledRuntimeImage>,
    pub(super) input: Option<InstalledRuntimeImage>,
    metadata: RuntimeMixedAdmissionSnapshot,
    reservation: Option<AccountReservation>,
    reference: File,
    reference_directory: File,
    reference_path: PathBuf,
    reference_unlinked: bool,
    released: bool,
    revoked: bool,
}

/// Owns preallocation failure obligations rather than losing native handles on error.
pub(super) struct MixedAdmissionFailure {
    pub detail: String,
    pub reservation_may_remain: bool,
    pub reason: memcordon_core::result_v2::MixedAdmissionRejectionV2,
    reservation: Option<AccountReservation>,
    reference: Option<File>,
    directory: Option<File>,
    path: Option<PathBuf>,
}
/// A live release gate preserves its typed policy cause through native cleanup.
pub(crate) struct MixedReleaseFailure {
    pub reason: memcordon_core::result_v2::MixedAdmissionRejectionV2,
    pub detail: String,
}
impl From<String> for MixedReleaseFailure {
    fn from(detail: String) -> Self {
        Self {
            reason: memcordon_core::result_v2::MixedAdmissionRejectionV2::NativeSetupFailed,
            detail,
        }
    }
}
impl From<&str> for MixedReleaseFailure {
    fn from(detail: &str) -> Self {
        detail.to_owned().into()
    }
}
impl From<String> for MixedAdmissionFailure {
    fn from(detail: String) -> Self {
        Self {
            detail,
            reason:
                memcordon_core::result_v2::MixedAdmissionRejectionV2::HostPrerequisiteUnavailable,
            reservation_may_remain: false,
            reservation: None,
            reference: None,
            directory: None,
            path: None,
        }
    }
}
impl From<&str> for MixedAdmissionFailure {
    fn from(detail: &str) -> Self {
        detail.to_owned().into()
    }
}
impl MixedAdmissionFailure {
    fn because(
        reason: memcordon_core::result_v2::MixedAdmissionRejectionV2,
        detail: impl Into<String>,
    ) -> Self {
        let mut failure = Self::from(detail.into());
        failure.reason = reason;
        failure
    }
    pub(super) fn cleanup_before_allocation(&mut self) -> Result<(), String> {
        if self.reservation_may_remain && self.reservation.is_none() {
            return Err(
                "mixed reservation retirement remains unresolved without owned native custody"
                    .into(),
            );
        }
        if let (Some(reference), Some(path)) = (&self.reference, &self.path) {
            let held = reference.metadata().map_err(|error| error.to_string())?;
            let current = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
            if !current.is_file()
                || current.uid() != 0
                || current.nlink() != 1
                || current.mode() & 0o7777 != 0o600
                || (held.dev(), held.ino()) != (current.dev(), current.ino())
            {
                return Err("failed mixed admission reference changed native identity".into());
            }
            std::fs::remove_file(path).map_err(|error| error.to_string())?;
            self.directory
                .as_ref()
                .ok_or("mixed failure directory absent")?
                .sync_all()
                .map_err(|error| error.to_string())?;
            self.reference.take();
        }
        if let Some(reservation) = self.reservation.as_ref() {
            reservation.retire_observed()?;
            self.reservation.take();
        }
        self.reservation_may_remain = false;
        Ok(())
    }
}

/// Unknown/unreadable process credentials fail closed. Host numeric UIDs are
/// safe selectors only under the explicitly administrator-owned exclusive policy.
pub(super) fn require_account_quiescent(uid: u32, allowed: Option<u32>) -> Result<(), String> {
    for entry in std::fs::read_dir("/proc").map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let status = match std::fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
        };
        let ids = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .ok_or("process status omitted UID credentials")?
            .split_ascii_whitespace()
            .map(|id| id.parse::<u32>().map_err(|error| error.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() != 4 {
            return Err("process UID tuple length differs".into());
        }
        if ids.contains(&uid) && allowed != Some(pid) {
            return Err("exclusive target UID is occupied by another live process".into());
        }
    }
    Ok(())
}

impl MixedOperationalAdmission {
    #[cfg(test)]
    pub(crate) fn authenticate_component(
        contract: WorkloadContractV3,
        launch: crate::request::LaunchRequestV2,
        caller: super::envelope::CapturedCallerEnvelopeV2,
        attempt: [u8; 16],
        publish: impl FnOnce(&RuntimeMixedAdmissionSnapshot) -> Result<(), String>,
    ) -> Result<Self, String> {
        Self::authenticate(contract, launch, caller, attempt, publish).map_err(|mut failure| {
            let original = failure.detail.clone();
            match failure.cleanup_before_allocation() {
                Ok(()) => original,
                Err(error) => format!("{original}; original admission cleanup: {error}"),
            }
        })
    }
    #[cfg(test)]
    pub(crate) fn component_metadata(&self) -> &RuntimeMixedAdmissionSnapshot {
        self.metadata()
    }
    #[cfg(test)]
    pub(crate) fn component_effective_invocation(&self) -> Result<Vec<u8>, String> {
        crate::request::encode_launch_request(&self.launch).map_err(|error| format!("{error:?}"))
    }
    #[cfg(test)]
    pub(crate) fn component_target_uid(&self) -> u32 {
        self.identity.uid()
    }
    #[cfg(test)]
    pub(crate) fn component_reference_bytes(&self) -> Result<Vec<u8>, String> {
        self.reference_bytes()
    }
    #[cfg(test)]
    pub(crate) fn component_account_ownership(&self) -> Result<serde_json::Value, String> {
        let reservation = self
            .reservation
            .as_ref()
            .ok_or("component boundary lacks held reservation")?
            .component_observation()?;
        Ok(
            serde_json::json!({"attempt_id":self.metadata.attempt_id,"account_uid":self.identity.uid(),"reference_path":self.reference_path,
            "reference":self.component_reference_observation()?,"reservation":reservation}),
        )
    }
    #[cfg(test)]
    pub(crate) fn component_reference_observation(&self) -> Result<serde_json::Value, String> {
        let native = self.reference.metadata().map_err(|e| e.to_string())?;
        let absent = match std::fs::symlink_metadata(&self.reference_path) {
            Ok(current) => {
                if (current.dev(), current.ino()) != (native.dev(), native.ino()) {
                    return Err("component named reference changed".into());
                }
                false
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => return Err(e.to_string()),
        };
        if self.reference_unlinked {
            require_account_quiescent(self.identity.uid(), None)?;
            if native.nlink() != 0 || !absent || self.reservation.is_some() {
                return Err("component native account/reference remains".into());
            }
        }
        Ok(
            serde_json::json!({"device":native.dev(),"inode":native.ino(),"length":native.len(),"links":native.nlink(),"uid":native.uid(),"mode":native.mode(),"named_absent":absent,"account_uid":self.identity.uid(),"retired":self.reference_unlinked}),
        )
    }
    #[cfg(test)]
    pub(crate) fn component_release(
        &mut self,
        pid: u32,
        publish: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), MixedReleaseFailure> {
        self.release_with_native_gate(pid, publish)
    }
    /// Internal callback regressions never transfer either image into a root.
    /// This settles only their actual reservation/reference after native UID
    /// quiescence; it supplies no private-root or execution retirement proof.
    #[cfg(test)]
    pub(crate) fn retire_component_admission(&mut self) -> Result<(), String> {
        if self.runtime.is_none() || self.input.is_none() {
            return Err("component admission transferred native image ownership".into());
        }
        require_account_quiescent(self.identity.uid(), None)?;
        if self.reference_unlinked {
            if self
                .reference
                .metadata()
                .map_err(|error| error.to_string())?
                .nlink()
                != 0
            {
                return Err("component reference remains linked".into());
            }
            match std::fs::symlink_metadata(&self.reference_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err("component reference path reappeared".into()),
            }
            return self
                .reference_directory
                .sync_all()
                .map_err(|error| error.to_string());
        }
        self.verify_reference()?;
        if let Some(reservation) = self.reservation.as_ref() {
            reservation.retire_observed()?;
            self.reservation.take();
        }
        std::fs::remove_file(&self.reference_path).map_err(|error| error.to_string())?;
        self.reference_unlinked = true;
        if self
            .reference
            .metadata()
            .map_err(|error| error.to_string())?
            .nlink()
            != 0
        {
            return Err("component reference has native links after unlink".into());
        }
        self.reference_directory
            .sync_all()
            .map_err(|error| error.to_string())
    }
    pub(super) fn prepare_native_root_launch(
        &mut self,
        attempt: [u8; 16],
        staging: super::private_root::NativeRootStaging,
    ) -> Result<PreparedMixedLaunch, String> {
        let identity_text = attempt
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if identity_text != self.metadata.attempt_id.as_str() || self.released {
            return Err("mixed native preparation attempt/release differs".into());
        }
        let resolved = self
            .activation
            .registry
            .resolve(
                &self.contract,
                self.caller.envelope.uid,
                &self.activation.epoch,
            )
            .map_err(|reason| format!("mixed preparation registry binding: {reason:?}"))?;
        let layout = resolved.layout.clone();
        let declared = resolved
            .image
            .entrypoints
            .as_slice()
            .iter()
            .find(|entry| entry.id == self.contract.launch.entrypoint)
            .ok_or("mixed entrypoint disappeared")?;
        let entry = resolved
            .image
            .entries
            .as_slice()
            .iter()
            .find(|entry| entry.path() == &declared.path)
            .ok_or("mixed entrypoint member disappeared")?
            .clone();
        let runtime = self
            .runtime
            .as_ref()
            .ok_or("mixed runtime image already transferred")?;
        runtime.revalidate()?;
        super::image_elf_closure::validate(
            runtime,
            self.input
                .as_ref()
                .ok_or("mixed input image already transferred")?,
        )?;
        let file = File::from(
            runtime
                .object(entry.path())?
                .try_clone_to_owned()
                .map_err(|error| error.to_string())?,
        );
        let executable =
            super::entrypoint::VerifiedEntrypoint::from_private_root_image(file, &entry)?;
        let digest = memcordon_core::DiagnosticSha256::from_bytes(executable.identity().sha256);
        let abi = match (std::env::consts::ARCH, cfg!(target_env = "gnu")) {
            ("x86_64", true) => super::network_filter::NativeAbi::X86_64,
            ("aarch64", true) => super::network_filter::NativeAbi::Aarch64,
            _ => return Err("mixed runtime requires supported native GNU ABI".into()),
        };
        let filter = super::network_filter::filter_instruction_digest(
            &super::network_filter::compile_mixed_closed_filter(abi),
        )
        .map_err(str::to_owned)?;
        let command =
            super::private_target::PrivateExecArguments::from_native_launch(&self.launch)?;
        let mut prelaunch = super::launch::build_private_gated_prelaunch(
            self.identity.clone(),
            executable,
            digest,
            command,
            abi,
            filter,
        )?;
        prelaunch.target.mixed_root_filter = true;
        let (provider_root_channel, root_channel) = super::private_root::native_root_channel()?;
        let preparation = super::private_namespace_init::MixedNamespacePreparation {
            runtime: self.runtime.take().expect("checked runtime image"),
            input: self
                .input
                .take()
                .ok_or("mixed input image already transferred")?,
            layout,
            staging,
            entry,
            working_directory: self.contract.launch.working_directory.clone(),
            root_channel,
            nonce: self.metadata.admission_nonce.0,
            attempt,
            identity: self.contract.execution_identity.clone(),
        };
        Ok(PreparedMixedLaunch {
            prelaunch,
            preparation,
            provider_root_channel,
            abi,
            filter,
        })
    }
    pub(super) fn authenticate(
        contract: WorkloadContractV3,
        mut launch: crate::request::LaunchRequestV2,
        caller: super::envelope::CapturedCallerEnvelopeV2,
        attempt: [u8; 16],
        publish_ownership: impl FnOnce(&RuntimeMixedAdmissionSnapshot) -> Result<(), String>,
    ) -> Result<Self, MixedAdmissionFailure> {
        if !cfg!(feature = "private-tcp") || attempt == [0; 16] {
            return Err("mixed runtime unavailable or empty attempt".into());
        }
        contract.validate().map_err(|error| {
            MixedAdmissionFailure::because(
                memcordon_core::result_v2::MixedAdmissionRejectionV2::IncompatibleRequirement,
                error,
            )
        })?;
        super::envelope::verify_live(&caller.envelope)?;
        // Reservations name host accounts, so a caller in another user namespace
        // cannot establish a second reservation for the same native account.
        use std::os::unix::fs::MetadataExt;
        let provider_user_namespace =
            std::fs::metadata("/proc/self/ns/user").map_err(|error| error.to_string())?;
        if caller.envelope.user_namespace_identity.device != provider_user_namespace.dev()
            || caller.envelope.user_namespace_identity.inode != provider_user_namespace.ino()
        {
            return Err("mixed exclusive identity requires the provider user namespace".into());
        }
        // The image manifest is the sole trusted startup environment authority.
        // Free caller environment values never become loader/search-path input.
        if !launch.environment.is_empty() {
            return Err("image entrypoint requires an empty caller environment; trusted startup comes from administrator images".into());
        }
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, caller.envelope.pid, 0) } as i32;
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string().into());
        }
        let frontend_pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let frontend = super::private_attempt::ProcessIdentityV4::observe(
            caller.envelope.pid,
            frontend_pidfd.as_fd(),
        )?;
        if frontend.start_time != caller.envelope.process_start_time {
            return Err("mixed frontend native birth differs".into());
        }
        let lease = crate::policy_registry::native::Lease::acquire()?;
        let activation = lease.read_v3()?.ok_or("mixed local activation absent")?;
        if lease.versioned_live_bindings()?.len() >= memcordon_core::workload_limits::LIVE_BINDINGS
        {
            return Err("mixed native live capacity exhausted".into());
        }
        let resolved = activation
            .registry
            .resolve(&contract, caller.envelope.uid, &activation.epoch)
            .map_err(|code| {
                use memcordon_core::result_v2::MixedAdmissionRejectionV2 as R;
                use memcordon_core::workload_registry_v3::AdmissionCodeV3 as C;
                let reason = match code {
                    C::StaleEpoch => R::StaleEpoch,
                    C::UnauthorizedCaller => R::UnauthorizedCaller,
                    C::UnauthorizedPlan => R::UnauthorizedPlan,
                    C::UnauthorizedProfile => R::UnauthorizedProfile,
                    C::UnauthorizedImage => R::UnauthorizedImage,
                    C::UnauthorizedIdentity => R::UnauthorizedIdentity,
                    C::UnauthorizedRoot => R::UnauthorizedRoot,
                    C::DisabledGrant => R::DisabledGrant,
                    C::WrongGrantRevision => R::WrongGrantRevision,
                    C::IncompatibleRequirement => R::IncompatibleRequirement,
                };
                MixedAdmissionFailure::because(
                    reason,
                    format!("mixed admission rejected: {code:?}"),
                )
            })?;
        let identity = ResolvedTargetIdentity::exclusive(resolved.identity, caller.envelope.uid)?;
        let entrypoint = resolved
            .image
            .entrypoints
            .as_slice()
            .iter()
            .find(|entry| entry.id == contract.launch.entrypoint)
            .ok_or("image entrypoint absent")?;
        let expected_path = std::path::Path::new("/").join(entrypoint.path.as_str());
        use std::os::unix::ffi::OsStrExt;
        if launch.program.as_slice() != entrypoint.id.as_str().as_bytes() {
            return Err("native entrypoint selector differs from authorized image id".into());
        }
        launch.program = expected_path.as_os_str().as_bytes().to_vec();
        let mut names = std::collections::BTreeSet::new();
        for image in [resolved.image, resolved.input] {
            for variable in image.startup_environment.as_slice() {
                if !names.insert(&variable.name) {
                    return Err("trusted startup variables overlap images".into());
                }
                launch.environment.push((
                    variable.name.as_bytes().to_vec(),
                    variable.value.as_bytes().to_vec(),
                ));
            }
        }
        launch
            .environment
            .sort_by(|left, right| left.0.cmp(&right.0));
        let runtime = super::runtime_image::open_installed(resolved.image).map_err(|error| {
            MixedAdmissionFailure::because(
                memcordon_core::result_v2::MixedAdmissionRejectionV2::ImageCustodyMismatch,
                error,
            )
        })?;
        let input = super::runtime_image::open_installed(resolved.input).map_err(|error| {
            MixedAdmissionFailure::because(
                memcordon_core::result_v2::MixedAdmissionRejectionV2::ImageCustodyMismatch,
                error,
            )
        })?;
        if let Some(search) =
            super::image_elf_closure::validate(&runtime, &input).map_err(|error| {
                MixedAdmissionFailure::because(
                    memcordon_core::result_v2::MixedAdmissionRejectionV2::ImageCustodyMismatch,
                    error,
                )
            })?
        {
            launch
                .environment
                .push((b"LD_LIBRARY_PATH".to_vec(), search.into_bytes()));
            launch
                .environment
                .sort_by(|left, right| left.0.cmp(&right.0));
        }
        require_account_quiescent(identity.uid(), None).map_err(|error| {
            MixedAdmissionFailure::because(
                memcordon_core::result_v2::MixedAdmissionRejectionV2::ExclusiveAccountUnavailable,
                error,
            )
        })?;
        lease.retain_snapshot_v3(&activation.registry)?;
        let nonce = crate::policy_registry::native::random_nonce()?;
        let identity_text = attempt
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut invocation = crate::request::encode_launch_request(&launch)
            .map_err(|error| format!("mixed native invocation codec: {error:?}"))?;
        invocation.extend_from_slice(contract.digest()?.bytes());
        let metadata = RuntimeMixedAdmissionSnapshot {
            format: "memcordon.private-admission-metadata".into(),
            revision: 2,
            attempt_id: BoundedText::new(&identity_text).map_err(str::to_owned)?,
            request: contract.clone(),
            request_sha256: contract.digest()?,
            invocation_sha256: memcordon_core::workload_codec::hash_bytes(&invocation),
            caller_uid: caller.envelope.uid,
            registry_digest: activation.registry_digest.clone(),
            epoch: activation.epoch.clone(),
            admission_nonce: nonce,
            profile_id: contract.authorized_profile.clone(),
        };
        metadata.validate()?;
        // The original worker and exact prepared metadata must be durable
        // before either account reservation or reference allocation.
        publish_ownership(&metadata)?;
        let reference_directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(super::STATE_ROOT)
            .map_err(|error| error.to_string())?;
        let reference_path = PathBuf::from(super::STATE_ROOT)
            .join(&identity_text)
            .with_extension("mixed-admission");
        let reservation = match AccountReservation::reserve_owned(&caller, identity.uid(), attempt)
        {
            Ok(reservation) => reservation,
            Err(failure) => {
                let may_remain = failure.owned.is_some();
                return Err(MixedAdmissionFailure{detail:failure.detail,reason:memcordon_core::result_v2::MixedAdmissionRejectionV2::ExclusiveAccountUnavailable,reservation_may_remain:may_remain,reservation:failure.owned,reference:None,directory:None,path:None});
            }
        };
        let mut reference = None;
        let publication = (|| -> Result<(), String> {
            reference = Some(
                OpenOptions::new()
                    .write(true)
                    .read(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&reference_path)
                    .map_err(|error| error.to_string())?,
            );
            let file = reference.as_mut().expect("created owned reference");
            file.write_all(&serde_json::to_vec(&metadata).map_err(|error| error.to_string())?)
                .and_then(|()| file.sync_all())
                .and_then(|()| reference_directory.sync_all())
                .map_err(|error| error.to_string())
        })();
        if let Err(detail) = publication {
            return Err(MixedAdmissionFailure {
                detail,
                reason:
                    memcordon_core::result_v2::MixedAdmissionRejectionV2::InstallReadbackFailure,
                reservation_may_remain: true,
                reservation: Some(reservation),
                reference,
                directory: Some(reference_directory),
                path: Some(reference_path),
            });
        }
        let reference = reference.expect("publication created owned reference");
        drop(lease);
        Ok(Self {
            contract,
            launch,
            caller,
            frontend_pidfd,
            frontend,
            identity,
            activation,
            runtime: Some(runtime),
            input: Some(input),
            metadata,
            reservation: Some(reservation),
            reference,
            reference_directory,
            reference_path,
            reference_unlinked: false,
            released: false,
            revoked: false,
        })
    }
    pub(super) fn metadata(&self) -> &RuntimeMixedAdmissionSnapshot {
        &self.metadata
    }
    pub(super) fn release_with_native_gate(
        &mut self,
        target_pid: u32,
        publish: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), MixedReleaseFailure> {
        if self.released || self.revoked {
            return Err("mixed release is single-use and not revoked".into());
        }
        super::envelope::verify_live(&self.caller.envelope)?;
        let lease = crate::policy_registry::native::Lease::acquire()?;
        let current = lease.read_v3()?.ok_or("mixed activation disappeared")?;
        if current.epoch != self.activation.epoch
            || current.registry_digest != self.activation.registry_digest
            || current
                .revoked_admissions
                .as_slice()
                .contains(&self.metadata.admission_nonce)
        {
            return Err(MixedReleaseFailure {
                reason: memcordon_core::result_v2::MixedAdmissionRejectionV2::StaleEpoch,
                detail: "mixed epoch/grant changed before release".into(),
            });
        }
        current
            .registry
            .resolve(&self.contract, self.caller.envelope.uid, &current.epoch)
            .map_err(|code| {
                use memcordon_core::result_v2::MixedAdmissionRejectionV2 as R;
                use memcordon_core::workload_registry_v3::AdmissionCodeV3 as C;
                let reason = match code {
                    C::StaleEpoch => R::StaleEpoch,
                    C::UnauthorizedCaller => R::UnauthorizedCaller,
                    C::UnauthorizedPlan => R::UnauthorizedPlan,
                    C::UnauthorizedProfile => R::UnauthorizedProfile,
                    C::UnauthorizedImage => R::UnauthorizedImage,
                    C::UnauthorizedIdentity => R::UnauthorizedIdentity,
                    C::UnauthorizedRoot => R::UnauthorizedRoot,
                    C::DisabledGrant => R::DisabledGrant,
                    C::WrongGrantRevision => R::WrongGrantRevision,
                    C::IncompatibleRequirement => R::IncompatibleRequirement,
                };
                MixedReleaseFailure {
                    reason,
                    detail: format!("mixed live admission rejected: {code:?}"),
                }
            })?;
        self.verify_reference()?;
        require_account_quiescent(self.identity.uid(), Some(target_pid))?;
        self.released = true;
        let result = publish();
        drop(lease);
        result.map_err(MixedReleaseFailure::from)
    }
    pub(super) fn revoked(&mut self) -> Result<bool, String> {
        let lease = crate::policy_registry::native::Lease::acquire()?;
        let Some(current) = lease.read_v3()? else {
            self.revoked = true;
            return Ok(true);
        };
        self.revoked |= current.epoch.service_instance != self.activation.epoch.service_instance
            || current
                .revoked_admissions
                .as_slice()
                .contains(&self.metadata.admission_nonce);
        Ok(self.revoked)
    }
    fn verify_reference(&self) -> Result<(), String> {
        self.reference_bytes().map(|_| ())
    }
    fn reference_bytes(&self) -> Result<Vec<u8>, String> {
        let held = self
            .reference
            .metadata()
            .map_err(|error| error.to_string())?;
        let current =
            std::fs::symlink_metadata(&self.reference_path).map_err(|error| error.to_string())?;
        if !current.is_file()
            || current.uid() != 0
            || current.nlink() != 1
            || current.mode() & 0o7777 != 0o600
            || (held.dev(), held.ino()) != (current.dev(), current.ino())
        {
            return Err("mixed admission reference native custody differs".into());
        }
        let bound = memcordon_core::workload_limits::CONTRACT_ENVELOPE_BYTES as u64;
        if held.len() > bound {
            return Err("mixed admission reference exceeds bound".into());
        }
        let mut bytes = vec![
            0;
            usize::try_from(held.len())
                .map_err(|_| "reference size exceeds native range")?
                .checked_add(1)
                .ok_or("reference bound overflow")?
        ];
        let mut used = 0;
        while used < bytes.len() {
            let count = self
                .reference
                .read_at(&mut bytes[used..], used as u64)
                .map_err(|error| error.to_string())?;
            if count == 0 {
                break;
            }
            used += count;
        }
        bytes.truncate(used);
        let stamp = |value: &std::fs::Metadata| {
            (
                value.dev(),
                value.ino(),
                value.len(),
                value.ctime(),
                value.ctime_nsec(),
                value.nlink(),
                value.uid(),
                value.mode(),
            )
        };
        if bytes.len() as u64 != held.len()
            || stamp(&held)
                != stamp(
                    &self
                        .reference
                        .metadata()
                        .map_err(|error| error.to_string())?,
                )
        {
            return Err("held mixed reference changed while read".into());
        }
        let named =
            super::protected_read::read_protected_absolute(&self.reference_path, bound, None)?;
        if named != bytes
            || stamp(&held)
                != stamp(
                    &std::fs::symlink_metadata(&self.reference_path)
                        .map_err(|error| error.to_string())?,
                )
        {
            return Err("mixed reference named bytes or identity differ".into());
        }
        if RuntimeMixedAdmissionSnapshot::parse(&bytes)? != self.metadata {
            return Err("mixed admission reference content differs".into());
        }
        Ok(bytes)
    }
    pub(super) fn retire_after_native_root_and_account_quiescence(
        &mut self,
        retired: &super::private_lifecycle::PrivateRetirementObservation,
        root: &super::private_root::PrivateRootRetirement,
    ) -> Result<(), String> {
        if retired.attempt_id() != self.metadata.attempt_id.as_str() {
            return Err("mixed retirement attempt differs".into());
        }
        root.require_binding(
            self.metadata.attempt_id.as_str(),
            &self.contract.root_layout,
            &self.contract.execution_identity,
        )?;
        require_account_quiescent(self.identity.uid(), None)?;
        if self.reference_unlinked {
            if self
                .reference
                .metadata()
                .map_err(|error| error.to_string())?
                .nlink()
                != 0
            {
                return Err("retired mixed reference is still linked".into());
            }
            match std::fs::symlink_metadata(&self.reference_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err("retired mixed reference path reappeared or is unreadable".into()),
            }
            return self
                .reference_directory
                .sync_all()
                .map_err(|error| error.to_string());
        }
        self.verify_reference()?;
        if let Some(reservation) = self.reservation.as_ref() {
            reservation.retire_observed()?;
            self.reservation.take();
        }
        std::fs::remove_file(&self.reference_path).map_err(|error| error.to_string())?;
        self.reference_unlinked = true;
        if self
            .reference
            .metadata()
            .map_err(|error| error.to_string())?
            .nlink()
            != 0
        {
            return Err("unlinked mixed reference retains native links".into());
        }
        self.reference_directory
            .sync_all()
            .map_err(|error| error.to_string())
    }
}

pub(super) struct PreparedMixedLaunch {
    pub prelaunch: super::launch::PrivateGatedPrelaunch,
    pub preparation: super::private_namespace_init::MixedNamespacePreparation,
    pub provider_root_channel: std::os::unix::net::UnixStream,
    pub abi: super::network_filter::NativeAbi,
    pub filter: [u8; 32],
}
