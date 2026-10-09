//! Administrative test seam for one installed guardian, never a consumer RPC.
use serde::{Deserialize, Serialize};

use crate::{CiError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardianAssociationIdentity {
    pub service_name: String,
    pub process_id: u32,
    pub creation_time_100ns: u64,
    pub image_volume: u32,
    pub image_file_index: u64,
    pub image_sha256: String,
    pub generation_manifest_sha256: String,
}

pub fn guardian_slot_names() -> Vec<String> {
    (0..memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT)
        .map(|index| {
            format!(
                "{}{:03}",
                memcordon_core::WINDOWS_GUARDIAN_SERVICE_PREFIX,
                index
            )
        })
        .collect()
}

/// Used immediately before the native action. No PID-only perturbation exists.
pub fn validate_guardian_association(
    held: &GuardianAssociationIdentity,
    current: &GuardianAssociationIdentity,
) -> Result<()> {
    if held != current
        || held.process_id == 0
        || held.creation_time_100ns == 0
        || !guardian_slot_names().contains(&held.service_name)
        || [&held.image_sha256, &held.generation_manifest_sha256]
            .into_iter()
            .any(|digest| {
                digest.len() != std::mem::size_of::<[u8; 32]>() * 2
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    {
        return Err(CiError::Message(
            "owned guardian native association changed or is invalid".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod native {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom};
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};
    use std::ptr;

    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Foundation::{FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_SHARE_READ, GetFileInformationByHandle,
    };
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
        QueryServiceConfigW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
        SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_STATUS_PROCESS, SERVICE_STOPPED,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    };

    use super::*;

    struct ServiceHandle(SC_HANDLE);
    // SAFETY: SCM service handles have no thread affinity. This wrapper uniquely
    // owns its handle, is moved into one observer, and closes it exactly once.
    unsafe impl Send for ServiceHandle {}
    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            // SAFETY: each handle was acquired by this owner and is never copied.
            unsafe { CloseServiceHandle(self.0) };
        }
    }

    struct Slot {
        name: String,
        service: ServiceHandle,
        config_sha256: String,
    }

    pub struct GuardianBaseline {
        slots: Vec<Slot>,
        image: File,
        manifest: File,
        image_path: PathBuf,
        image_sha256: String,
        manifest_sha256: String,
    }

    pub struct HeldGuardian {
        slot: Slot,
        process: OwnedHandle,
        image: File,
        manifest: File,
        image_path: PathBuf,
        pub identity: GuardianAssociationIdentity,
    }

    fn native_failure(context: &str) -> CiError {
        CiError::Message(format!("{context}: {}", std::io::Error::last_os_error()))
    }

    fn locked_file(path: &Path) -> Result<File> {
        Ok(OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)?)
    }

    fn file_hash(file: &mut File) -> Result<String> {
        file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hash.update(&buffer[..read]);
        }
        Ok(hex::encode(hash.finalize()))
    }

    fn file_identity(file: &File) -> Result<(u32, u64)> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the file remains owned and the output structure is writable.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
            return Err(native_failure("cannot inspect held installed image"));
        }
        Ok((
            info.dwVolumeSerialNumber,
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }

    fn status(slot: &Slot) -> Result<SERVICE_STATUS_PROCESS> {
        let mut result = SERVICE_STATUS_PROCESS::default();
        let mut required = 0;
        // SAFETY: exact fixed output structure is writable; slot handle is held.
        if unsafe {
            QueryServiceStatusEx(
                slot.service.0,
                SC_STATUS_PROCESS_INFO,
                (&mut result as *mut SERVICE_STATUS_PROCESS).cast(),
                u32::try_from(std::mem::size_of_val(&result)).expect("service status size"),
                &mut required,
            )
        } == 0
        {
            return Err(native_failure("cannot inspect guardian slot status"));
        }
        Ok(result)
    }

    fn config_hash(service: &ServiceHandle) -> Result<String> {
        config_observation(service).map(|(digest, _)| digest)
    }

    fn config_observation(service: &ServiceHandle) -> Result<(String, serde_json::Value)> {
        let mut required = 0;
        // SAFETY: the first call queries the allocation size and no output is read.
        unsafe { QueryServiceConfigW(service.0, ptr::null_mut(), 0, &mut required) };
        if required == 0 || required > 64 * 1024 {
            return Err(CiError::Message(
                "guardian slot config size is invalid".to_owned(),
            ));
        }
        let units = usize::try_from(required)
            .expect("config bound fits usize")
            .div_ceil(std::mem::size_of::<usize>());
        let mut allocation = vec![0_usize; units];
        let pointer = allocation.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        // SAFETY: allocation is aligned and has at least required writable bytes.
        if unsafe { QueryServiceConfigW(service.0, pointer, required, &mut required) } == 0 {
            return Err(native_failure("cannot read guardian slot config"));
        }
        // Hash semantic values, never pointer addresses in the native structure.
        let config = unsafe { &*pointer };
        let mut hash = Sha256::new();
        let mut strings = Vec::new();
        for value in [
            config.dwServiceType,
            config.dwStartType,
            config.dwErrorControl,
        ] {
            hash.update(value.to_le_bytes());
        }
        for value in [config.lpBinaryPathName, config.lpServiceStartName] {
            let start = allocation.as_ptr() as usize;
            let end = start + allocation.len() * std::mem::size_of::<usize>();
            let pointer = value as usize;
            if pointer < start || pointer >= end || pointer % std::mem::align_of::<u16>() != 0 {
                return Err(CiError::Message(
                    "guardian config string pointer is invalid".to_owned(),
                ));
            }
            let remaining = (end - pointer) / std::mem::size_of::<u16>();
            // SAFETY: pointer and finite slice are within the held allocation.
            let text = unsafe { std::slice::from_raw_parts(value, remaining) };
            let length = text.iter().position(|unit| *unit == 0).ok_or_else(|| {
                CiError::Message("guardian config string is unterminated".to_owned())
            })?;
            hash.update(
                u64::try_from(length)
                    .expect("bounded config length")
                    .to_le_bytes(),
            );
            for unit in &text[..length] {
                hash.update(unit.to_le_bytes());
            }
            strings.push(text[..length].to_vec());
        }
        Ok((
            hex::encode(hash.finalize()),
            serde_json::json!({
                "service_type":config.dwServiceType,
                "start_type":config.dwStartType,
                "error_control":config.dwErrorControl,
                "binary_path_utf16":strings[0],
                "service_start_name_utf16":strings[1],
            }),
        ))
    }

    fn process_birth(process: HANDLE) -> Result<u64> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: process is held and all exact FILETIME outputs are writable.
        if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }
            == 0
        {
            return Err(native_failure("cannot inspect guardian creation identity"));
        }
        Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
    }

    fn process_image(process: HANDLE) -> Result<File> {
        let mut path = vec![0_u16; 32768];
        let mut length = u32::try_from(path.len()).expect("native path bound");
        // SAFETY: process is held and path/length outputs are writable.
        if unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut length) } == 0 {
            return Err(native_failure("cannot inspect guardian image"));
        }
        path.truncate(usize::try_from(length).expect("native path length"));
        locked_file(Path::new(&std::ffi::OsString::from_wide(&path)))
    }

    impl GuardianBaseline {
        /// Called after operational package verification and before starting a
        /// fixture. Locks the actual generation/image and rejects active slots.
        pub fn quiescent(
            image_path: &Path,
            manifest_path: &Path,
            expected_image_sha256: &str,
            expected_manifest_sha256: &str,
        ) -> Result<Self> {
            let mut image = locked_file(image_path)?;
            let mut manifest = locked_file(manifest_path)?;
            if file_hash(&mut image)? != expected_image_sha256
                || file_hash(&mut manifest)? != expected_manifest_sha256
            {
                return Err(CiError::Message(
                    "installed generation/image bytes differ".to_owned(),
                ));
            }
            // SAFETY: read-only local SCM connection with no optional machine/database.
            let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
            if manager.is_null() {
                return Err(native_failure("cannot open native SCM"));
            }
            let manager = ServiceHandle(manager);
            let mut slots = Vec::new();
            for name in guardian_slot_names() {
                let wide = name
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect::<Vec<_>>();
                // SAFETY: terminated name and held manager are valid; only query access.
                let raw = unsafe {
                    OpenServiceW(
                        manager.0,
                        wide.as_ptr(),
                        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
                    )
                };
                if raw.is_null() {
                    return Err(native_failure("cannot open installed guardian slot"));
                }
                let service = ServiceHandle(raw);
                let config_sha256 = config_hash(&service)?;
                let slot = Slot {
                    name,
                    service,
                    config_sha256,
                };
                let current = status(&slot)?;
                if current.dwCurrentState != SERVICE_STOPPED || current.dwProcessId != 0 {
                    return Err(CiError::Message(
                        "installed guardian pool was not quiescent".to_owned(),
                    ));
                }
                slots.push(slot);
            }
            Ok(Self {
                slots,
                image,
                manifest,
                image_path: image_path.to_owned(),
                image_sha256: expected_image_sha256.to_owned(),
                manifest_sha256: expected_manifest_sha256.to_owned(),
            })
        }

        pub fn hold_new_guardian(self) -> Result<HeldGuardian> {
            self.hold_new_guardian_excluding(&[])
        }

        /// Capture actual queried SCM values while exact image/manifest and
        /// every slot service handle remain held. No target/Job is invented.
        pub fn quiescence_receipt(&self) -> Result<Vec<u8>> {
            let mut image = self.image.try_clone()?;
            let mut manifest = self.manifest.try_clone()?;
            if file_hash(&mut image)? != self.image_sha256
                || file_hash(&mut manifest)? != self.manifest_sha256
            {
                return Err(CiError::Message(
                    "held quiescence generation bytes changed".into(),
                ));
            }
            let mut observations = Vec::with_capacity(self.slots.len());
            for slot in &self.slots {
                let (configuration, native_configuration) = config_observation(&slot.service)?;
                let current = status(slot)?;
                if configuration != slot.config_sha256
                    || current.dwCurrentState != SERVICE_STOPPED
                    || current.dwProcessId != 0
                {
                    return Err(CiError::Message(
                        "native guardian slot ceased to be quiescent".into(),
                    ));
                }
                observations.push(serde_json::json!({
                    "service_name":slot.name,
                    "configuration_sha256":configuration,
                    "configuration":native_configuration,
                    "service_type":current.dwServiceType,
                    "current_state":current.dwCurrentState,
                    "process_id":current.dwProcessId,
                    "controls_accepted":current.dwControlsAccepted,
                    "win32_exit_code":current.dwWin32ExitCode,
                    "service_specific_exit_code":current.dwServiceSpecificExitCode,
                    "checkpoint":current.dwCheckPoint,
                    "wait_hint":current.dwWaitHint,
                    "service_flags":current.dwServiceFlags,
                }));
            }
            Ok(serde_json::to_vec(&serde_json::json!({
                "format":"memcordon.windows-native-guardian-quiescence",
                "revision":1,
                "image_sha256":self.image_sha256,
                "runtime_manifest_sha256":self.manifest_sha256,
                "slots":observations,
            }))?)
        }

        /// Exclusions must remain held by the controller throughout selection.
        /// Native birth, image, and SCM identity are checked independently here.
        pub fn hold_new_guardian_excluding(
            self,
            exclusions: &[GuardianAssociationIdentity],
        ) -> Result<HeldGuardian> {
            let mut selected = None;
            for slot in self.slots {
                if config_hash(&slot.service)? != slot.config_sha256 {
                    return Err(CiError::Message(
                        "installed guardian service configuration changed".to_owned(),
                    ));
                }
                let current = status(&slot)?;
                if let Some(excluded) = exclusions
                    .iter()
                    .find(|identity| identity.service_name == slot.name)
                {
                    if current.dwCurrentState != SERVICE_RUNNING
                        || current.dwProcessId != excluded.process_id
                    {
                        return Err(CiError::Message(
                            "excluded held guardian lost its native SCM association".into(),
                        ));
                    }
                    // SAFETY: this is the observed PID of the exact held SCM slot;
                    // the returned handle is immediately owned and identity checked.
                    let raw = unsafe {
                        OpenProcess(
                            PROCESS_QUERY_LIMITED_INFORMATION | 0x0010_0000,
                            0,
                            current.dwProcessId,
                        )
                    };
                    if raw.is_null() {
                        return Err(native_failure("cannot revalidate excluded guardian"));
                    }
                    // SAFETY: OpenProcess returned this owner's non-null handle.
                    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
                    let image = process_image(process.as_raw_handle() as HANDLE)?;
                    if process_birth(raw)? != excluded.creation_time_100ns
                        || file_identity(&image)? != file_identity(&self.image)?
                        || (excluded.image_volume, excluded.image_file_index)
                            != file_identity(&image)?
                        || excluded.image_sha256 != self.image_sha256
                        || excluded.generation_manifest_sha256 != self.manifest_sha256
                        || unsafe { WaitForSingleObject(raw, 0) } != WAIT_TIMEOUT
                    {
                        return Err(CiError::Message(
                            "excluded guardian is not the exact live measured native identity"
                                .into(),
                        ));
                    }
                    continue;
                }
                match (current.dwCurrentState, current.dwProcessId) {
                    (SERVICE_STOPPED, 0) => {}
                    (SERVICE_RUNNING, pid) if pid != 0 && selected.is_none() => {
                        selected = Some((slot, pid))
                    }
                    _ => {
                        return Err(CiError::Message(
                            "newly active installed guardian slot is ambiguous".to_owned(),
                        ));
                    }
                }
            }
            let (slot, pid) = selected.ok_or_else(|| {
                CiError::Message("no newly active installed guardian slot".to_owned())
            })?;
            // SAFETY: PID is from exact held native SCM slot; identity is checked
            // on the returned handle before it can be used to terminate.
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | 0x0010_0000,
                    0,
                    pid,
                )
            };
            if raw.is_null() {
                return Err(native_failure("cannot hold newly active guardian"));
            }
            // SAFETY: OpenProcess returned this owner's non-null handle.
            let process = unsafe { OwnedHandle::from_raw_handle(raw) };
            let actual_image = process_image(raw)?;
            let (volume, index) = file_identity(&actual_image)?;
            if (volume, index) != file_identity(&self.image)? || status(&slot)?.dwProcessId != pid {
                return Err(CiError::Message(
                    "new guardian image or SCM association differs".to_owned(),
                ));
            }
            let identity = GuardianAssociationIdentity {
                service_name: slot.name.clone(),
                process_id: pid,
                creation_time_100ns: process_birth(raw)?,
                image_volume: volume,
                image_file_index: index,
                image_sha256: self.image_sha256,
                generation_manifest_sha256: self.manifest_sha256,
            };
            validate_guardian_association(&identity, &identity)?;
            Ok(HeldGuardian {
                slot,
                process,
                image: self.image,
                manifest: self.manifest,
                image_path: self.image_path,
                identity,
            })
        }
    }

    impl HeldGuardian {
        pub fn native_exit_status(&self) -> Result<Option<u32>> {
            if !self.has_retired()? {
                return Ok(None);
            }
            let mut status = 0;
            // SAFETY: this owner retains the exact retired process creation
            // handle, independently checked against its configured service.
            if unsafe {
                windows_sys::Win32::System::Threading::GetExitCodeProcess(
                    self.process.as_raw_handle() as HANDLE,
                    &mut status,
                )
            } == 0
            {
                return Err(native_failure(
                    "cannot read held guardian native exit status",
                ));
            }
            Ok(Some(status))
        }
        pub fn has_retired(&self) -> Result<bool> {
            if config_hash(&self.slot.service)? != self.slot.config_sha256 {
                return Err(CiError::Message(
                    "held guardian service configuration changed during retirement".into(),
                ));
            }
            let current = status(&self.slot)?;
            // SAFETY: this owner retains the process handle for the complete check.
            let wait = unsafe { WaitForSingleObject(self.process.as_raw_handle() as HANDLE, 0) };
            if wait != WAIT_TIMEOUT && wait != windows_sys::Win32::Foundation::WAIT_OBJECT_0 {
                return Err(native_failure("cannot observe held guardian retirement"));
            }
            Ok(wait == windows_sys::Win32::Foundation::WAIT_OBJECT_0
                && current.dwCurrentState == SERVICE_STOPPED
                && current.dwProcessId == 0)
        }

        pub fn terminate_owned(&mut self) -> Result<()> {
            let process = self.process.as_raw_handle() as HANDLE;
            let current = status(&self.slot)?;
            if current.dwCurrentState != SERVICE_RUNNING
                || config_hash(&self.slot.service)? != self.slot.config_sha256
                || unsafe { WaitForSingleObject(process, 0) } != WAIT_TIMEOUT
            {
                return Err(CiError::Message(
                    "held guardian ceased to be the live owned service".to_owned(),
                ));
            }
            let actual_image = process_image(process)?;
            let path_image = locked_file(&self.image_path)?;
            let (volume, index) = file_identity(&actual_image)?;
            if (volume, index) != file_identity(&self.image)?
                || (volume, index) != file_identity(&path_image)?
            {
                return Err(CiError::Message(
                    "installed guardian image identity changed".to_owned(),
                ));
            }
            let observed = GuardianAssociationIdentity {
                service_name: self.slot.name.clone(),
                process_id: current.dwProcessId,
                creation_time_100ns: process_birth(process)?,
                image_volume: volume,
                image_file_index: index,
                image_sha256: file_hash(&mut self.image)?,
                generation_manifest_sha256: file_hash(&mut self.manifest)?,
            };
            validate_guardian_association(&self.identity, &observed)?;
            // SAFETY: exact SCM/config/generation/image/creation association has
            // just been revalidated; only the already-held process is affected.
            if unsafe { TerminateProcess(process, 137) } == 0 {
                return Err(native_failure("cannot terminate held owned guardian"));
            }
            // SAFETY: held process has synchronize access; finite wait owns action.
            if unsafe { WaitForSingleObject(process, 10_000) } != WAIT_OBJECT_0 {
                return Err(CiError::Message(
                    "owned guardian did not retire after perturbation".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
pub use native::{GuardianBaseline, HeldGuardian};
