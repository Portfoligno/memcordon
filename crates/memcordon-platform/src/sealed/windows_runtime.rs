//! Independent verification of the installed package inventory before accepting
//! its authenticated provider's generation claim. Caller images are unrestricted.
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use memcordon_core::runtime_manifest::{RuntimeComponentRole, RuntimeManifest};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    OWNER_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
};

fn open_protected(path: &Path) -> Result<File, String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let mut units = current.as_os_str().encode_wide().collect::<Vec<_>>();
        if units.contains(&0) {
            return Err("installed runtime path contains a NUL".into());
        }
        units.push(0);
        // SAFETY: the path is NUL-terminated with no interior NUL. This API
        // reports the link's own attributes rather than following its target.
        let attributes = unsafe { GetFileAttributesW(units.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            let error = std::io::Error::last_os_error();
            return Err(format!(
                "GetFileAttributesW(runtime path {:?}): raw-os-error={:?}; {error}",
                current,
                error.raw_os_error()
            ));
        }
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("installed runtime path contains a reparse point".into());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            format!(
                "open protected runtime {:?}: raw-os-error={:?}; {error}",
                path,
                error.raw_os_error()
            )
        })?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "metadata(protected runtime {:?}): raw-os-error={:?}; {error}",
            path,
            error.raw_os_error()
        )
    })?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("installed runtime is not a regular file".into());
    }
    let mut owner = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: file remains open; outputs receive pointers into descriptor, freed below.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(format!(
            "GetSecurityInfo(protected runtime {:?}): raw-os-error={status}; {}",
            path,
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    let result = (|| {
        let admins =
            super::well_known_sid(windows_sys::Win32::Security::WinBuiltinAdministratorsSid)?;
        let system = super::well_known_sid(windows_sys::Win32::Security::WinLocalSystemSid)?;
        // SAFETY: queried SIDs and ACL are valid for the descriptor lifetime.
        let privileged = |sid| unsafe {
            EqualSid(sid, admins.as_ptr().cast_mut().cast()) != 0
                || EqualSid(sid, system.as_ptr().cast_mut().cast()) != 0
        };
        if owner.is_null() || !privileged(owner) || dacl.is_null() {
            return Err("installed runtime ownership or DACL is not protected".into());
        }
        // File write/append/attributes/delete/control rights, including generic write/all.
        const MUTATION: u32 = 0x0000_0156 | 0x000D_0000 | 0x5000_0000;
        // SAFETY: GetSecurityInfo supplied an ACL; GetAce validates each index.
        for index in 0..unsafe { (*dacl).AceCount } {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, u32::from(index), &raw mut ace) } == 0 {
                let error = std::io::Error::last_os_error();
                return Err(format!(
                    "GetAce(protected runtime {:?}, index={index}): raw-os-error={:?}; {error}",
                    path,
                    error.raw_os_error()
                ));
            }
            let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: inspect header first; only ordinary allowed ACE layout is used.
            if unsafe { (*ace).Header.AceType } != 0 {
                return Err("installed runtime DACL has an unreviewed ACE type".into());
            }
            let sid = unsafe { std::ptr::addr_of_mut!((*ace).SidStart).cast() };
            if !privileged(sid) && unsafe { (*ace).Mask } & MUTATION != 0 {
                return Err("installed runtime grants mutation to an unprivileged identity".into());
            }
        }
        Ok(())
    })();
    // SAFETY: GetSecurityInfo transfers this local allocation to the caller.
    unsafe {
        LocalFree(descriptor);
    }
    result?;
    Ok(file)
}

pub(super) fn verify_binding(
    expected: &memcordon_core::PublicProviderBindingV1,
) -> Result<(), String> {
    let root = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
        .join("MemCordon");
    let file = open_protected(&root.join("runtime-manifest.json"))?;
    let mut bytes = Vec::new();
    file.take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!(
                "read protected runtime manifest: raw-os-error={:?}; {error}",
                error.raw_os_error()
            )
        })?;
    let manifest = RuntimeManifest::parse(&bytes)?;
    let target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-pc-windows-msvc",
        "aarch64" => "aarch64-pc-windows-msvc",
        _ => return Err("unsupported Windows provider architecture".into()),
    };
    if manifest.version != env!("CARGO_PKG_VERSION")
        || manifest.components.len() != 4
        || manifest
            != RuntimeManifest::windows(
                manifest.version.clone(),
                manifest.source_commit.clone(),
                target.into(),
                manifest.components.clone(),
            )?
        || manifest.public_binding(&bytes)? != *expected
    {
        return Err("installed runtime binding differs from provider".into());
    }
    for (role, id, name) in [
        (
            RuntimeComponentRole::SealedAgent,
            "sealed-agent",
            "memcordon-sealed-agent.exe",
        ),
        (
            RuntimeComponentRole::DesktopBootstrap,
            "target-desktop-bootstrap",
            "memcordon-target-desktop-bootstrap.exe",
        ),
        (
            RuntimeComponentRole::SessionBroker,
            "session-broker",
            "memcordon-session-broker.exe",
        ),
    ] {
        let records: Vec<_> = manifest
            .components
            .iter()
            .filter(|record| record.role == role)
            .collect();
        if records.len() != 1 {
            return Err("installed runtime role inventory differs".into());
        }
        let record = records[0];
        let mut image = open_protected(&root.join(name))?;
        let size = image
            .metadata()
            .map_err(|error| {
                format!(
                    "metadata(protected runtime {name}): raw-os-error={:?}; {error}",
                    error.raw_os_error()
                )
            })?
            .len();
        let mut hash = Sha256::new();
        let mut chunk = [0_u8; 64 * 1024];
        loop {
            let read = image.read(&mut chunk).map_err(|error| {
                format!(
                    "read protected runtime {name}: raw-os-error={:?}; {error}",
                    error.raw_os_error()
                )
            })?;
            if read == 0 {
                break;
            }
            hash.update(&chunk[..read]);
        }
        let digest: String =
            memcordon_core::DiagnosticSha256::from_bytes(hash.finalize().into()).into();
        if record.id != id
            || record.path != name
            || record.mode != 0o755
            || record.size != size
            || record.sha256 != digest
        {
            return Err("installed runtime image differs from manifest".into());
        }
    }
    let public: Vec<_> = manifest
        .components
        .iter()
        .filter(|record| record.role == RuntimeComponentRole::PublicCli)
        .collect();
    if public.len() != 1 || public[0].id != "public-cli" || public[0].path != "memcordon.exe" {
        return Err("public runtime inventory differs".into());
    }
    Ok(())
}

/// Recovery reads the actual installed binding independently of live readiness.
pub(super) fn installed_binding() -> Result<memcordon_core::PublicProviderBindingV1, String> {
    let root = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
        .join("MemCordon");
    let file = open_protected(&root.join("runtime-manifest.json"))?;
    let mut bytes = Vec::new();
    file.take(128 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let binding = RuntimeManifest::parse(&bytes)?.public_binding(&bytes)?;
    verify_binding(&binding)?;
    Ok(binding)
}
pub(super) fn boot_identity() -> Result<String, String> {
    #[repr(C)]
    struct TimeOfDay {
        boot: i64,
        current: i64,
        bias: i64,
        zone: u32,
        reserved: u32,
        boot_bias: u64,
        sleep_bias: u64,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            class: u32,
            information: *mut std::ffi::c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut information = std::mem::MaybeUninit::<TimeOfDay>::zeroed();
    let mut returned = 0;
    // SAFETY: the buffer matches native SystemTimeOfDayInformation and the
    // returned size is checked before initialized fields are observed.
    let status = unsafe {
        NtQuerySystemInformation(
            3,
            information.as_mut_ptr().cast(),
            u32::try_from(std::mem::size_of::<TimeOfDay>()).expect("native time structure fits"),
            &raw mut returned,
        )
    };
    if status < 0 || usize::try_from(returned).ok() != Some(std::mem::size_of::<TimeOfDay>()) {
        return Err("native boot identity unavailable".into());
    }
    // SAFETY: successful native query returned the complete structure.
    Ok(unsafe { information.assume_init() }.boot.to_string())
}
