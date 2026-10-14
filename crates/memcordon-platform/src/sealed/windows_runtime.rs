//! Independent verification of the installed package inventory before accepting
//! its authenticated provider's generation claim. Caller images are unrestricted.
use std::fs::File;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};

use memcordon_core::runtime_manifest::{RuntimeComponentRole, RuntimeManifest};
use sha2::{Digest, Sha256};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE,
    RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidSecurityDescriptor, IsValidSid,
    OWNER_SECURITY_INFORMATION, SE_SELF_RELATIVE, SECURITY_DESCRIPTOR_RELATIVE, SID,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ,
};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySecurityObject(
        handle: HANDLE,
        information: u32,
        descriptor: *mut std::ffi::c_void,
        capacity: u32,
        returned_length: *mut u32,
    ) -> NTSTATUS;
    fn NtOpenSymbolicLinkObject(
        handle: *mut HANDLE,
        access: u32,
        attributes: *const OBJECT_ATTRIBUTES,
    ) -> NTSTATUS;
    fn NtQuerySymbolicLinkObject(
        handle: HANDLE,
        target: *mut UNICODE_STRING,
        returned_length: *mut u32,
    ) -> NTSTATUS;
}

const MAX_FILE_SECURITY_DESCRIPTOR_BYTES: usize = 64 * 1024;

fn bounded_sid_length(bytes: &[u8]) -> Result<usize, String> {
    let prefix = std::mem::offset_of!(SID, SubAuthority);
    if bytes.len() < prefix {
        return Err("runtime security SID header is truncated".into());
    }
    let count = usize::from(bytes[std::mem::offset_of!(SID, SubAuthorityCount)]);
    let length = count
        .checked_mul(std::mem::size_of::<u32>())
        .and_then(|length| prefix.checked_add(length))
        .ok_or("runtime security SID length overflows")?;
    if length > bytes.len() {
        return Err("runtime security SID exceeds its bounded container".into());
    }
    Ok(length)
}

fn validate_relative_descriptor_bounds(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < std::mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>() {
        return Err("runtime security descriptor header is truncated".into());
    }
    // SAFETY: full header extent checked; unaligned read does not borrow it.
    let header =
        unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<SECURITY_DESCRIPTOR_RELATIVE>()) };
    if header.Control & SE_SELF_RELATIVE == 0 {
        return Err("runtime security descriptor is not self-relative".into());
    }
    let suffix = |offset: u32| -> Result<&[u8], String> {
        let offset =
            usize::try_from(offset).map_err(|_| "runtime security offset is not representable")?;
        if offset < std::mem::size_of::<SECURITY_DESCRIPTOR_RELATIVE>()
            || offset % std::mem::align_of::<u32>() != 0
        {
            return Err("runtime security offset overlaps its header".into());
        }
        bytes
            .get(offset..)
            .ok_or_else(|| "runtime security offset exceeds returned descriptor".into())
    };
    for offset in [header.Owner, header.Group] {
        if offset == 0 {
            continue;
        }
        let sid = suffix(offset)?;
        bounded_sid_length(sid)?;
    }
    for offset in [header.Sacl, header.Dacl] {
        if offset == 0 {
            continue;
        }
        let bytes = suffix(offset)?;
        if bytes.len() < std::mem::size_of::<ACL>() {
            return Err("runtime security ACL header is truncated".into());
        }
        // SAFETY: header extent checked; unaligned native header copy.
        let acl = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<ACL>()) };
        if usize::from(acl.AclSize) < std::mem::size_of::<ACL>()
            || usize::from(acl.AclSize) > bytes.len()
        {
            return Err("runtime security ACL exceeds returned descriptor".into());
        }
        let acl_bytes = &bytes[..usize::from(acl.AclSize)];
        let mut cursor = std::mem::size_of::<ACL>();
        for _ in 0..acl.AceCount {
            let remaining = acl_bytes
                .get(cursor..)
                .ok_or("runtime security ACE offset exceeds ACL")?;
            if remaining.len() < std::mem::size_of::<ACE_HEADER>() {
                return Err("runtime security ACE header is truncated".into());
            }
            // SAFETY: complete ACE header extent checked before unaligned copy.
            let ace = unsafe { std::ptr::read_unaligned(remaining.as_ptr().cast::<ACE_HEADER>()) };
            let size = usize::from(ace.AceSize);
            if size < std::mem::size_of::<ACE_HEADER>()
                || size > remaining.len()
                || size % std::mem::align_of::<u32>() != 0
            {
                return Err("runtime security ACE exceeds its ACL".into());
            }
            if ace.AceType == 0 {
                let sid = remaining[..size]
                    .get(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart)..)
                    .ok_or("runtime allowed ACE lacks SID")?;
                bounded_sid_length(sid)?;
            }
            cursor = cursor
                .checked_add(size)
                .ok_or("runtime ACE offset overflow")?;
        }
    }
    Ok(())
}

fn protected_descriptor(file: &File, path: &Path) -> Result<Vec<usize>, String> {
    let words = MAX_FILE_SECURITY_DESCRIPTOR_BYTES.div_ceil(std::mem::size_of::<usize>());
    let mut descriptor = vec![0usize; words];
    let mut returned = 0u32;
    // SAFETY: aligned, initialized owned allocation covers the documented file
    // descriptor bound; the exact original file remains held throughout query.
    let status = unsafe {
        NtQuerySecurityObject(
            file.as_raw_handle(),
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
            u32::try_from(MAX_FILE_SECURITY_DESCRIPTOR_BYTES).expect("descriptor bound"),
            &raw mut returned,
        )
    };
    if status < 0 {
        // SAFETY: translation has no pointer or ownership operands.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(format!(
            "NtQuerySecurityObject(protected runtime {:?}): ntstatus={status:#x}; raw-os-error={code}; returned-bytes={returned}; capacity={MAX_FILE_SECURITY_DESCRIPTOR_BYTES}",
            path
        ));
    }
    let returned =
        usize::try_from(returned).map_err(|_| "runtime descriptor length is not representable")?;
    if returned == 0 || returned > MAX_FILE_SECURITY_DESCRIPTOR_BYTES {
        return Err("NtQuerySecurityObject returned an invalid descriptor length".into());
    }
    // SAFETY: the complete returned extent lies in the initialized allocation.
    let bytes = unsafe { std::slice::from_raw_parts(descriptor.as_ptr().cast::<u8>(), returned) };
    validate_relative_descriptor_bounds(bytes)?;
    // SAFETY: every self-relative SID/ACL extent was bounded above, and the
    // allocation stays live through all descriptor accessor use below.
    if unsafe { IsValidSecurityDescriptor(descriptor.as_ptr().cast_mut().cast()) } == 0 {
        return Err("NtQuerySecurityObject returned an invalid security descriptor".into());
    }
    Ok(descriptor)
}

#[cfg(feature = "test-support")]
pub(super) fn relative_descriptor_bounds_for_test(bytes: &[u8]) -> Result<(), String> {
    validate_relative_descriptor_bounds(bytes)
}

fn native_lookup_error(operation: &str, path: &Path, status: NTSTATUS) -> String {
    // SAFETY: status translation has no pointer or ownership operands.
    let code = unsafe { RtlNtStatusToDosError(status) };
    format!(
        "{operation}(runtime drive {:?}): ntstatus={status:#x}; raw-os-error={code}",
        path
    )
}

fn direct_volume_target(
    buffer: &[u16],
    length: u16,
    maximum_length: u16,
) -> Result<&[u16], String> {
    let unit_bytes = std::mem::size_of::<u16>();
    let length = usize::from(length);
    let maximum = usize::from(maximum_length);
    if length == 0
        || length % unit_bytes != 0
        || maximum % unit_bytes != 0
        || length > maximum
        || maximum / unit_bytes > buffer.len()
    {
        return Err("malformed counted runtime drive target".into());
    }
    let target = buffer
        .get(..length / unit_bytes)
        .ok_or("runtime drive target exceeds buffer")?;
    if target.contains(&0) {
        return Err("runtime drive target contains a NUL".into());
    }
    let prefix = "\\Device\\HarddiskVolume"
        .encode_utf16()
        .collect::<Vec<_>>();
    let number = target
        .strip_prefix(prefix.as_slice())
        .ok_or("runtime drive is not a direct disk volume")?;
    if number.is_empty()
        || !number
            .iter()
            .all(|unit| *unit >= u16::from(b'0') && *unit <= u16::from(b'9'))
    {
        return Err("runtime drive is not a numbered direct disk volume".into());
    }
    Ok(target)
}

fn resolve_drive(path: &Path, drive: u8) -> Result<Vec<u16>, String> {
    let mut alias = "\\??\\".encode_utf16().collect::<Vec<_>>();
    alias.extend([u16::from(drive), u16::from(b':')]);
    let bytes = alias
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or("runtime alias name exceeds UNICODE_STRING")?;
    let mut name = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: alias.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())
            .expect("native object attributes size"),
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &raw mut name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut handle = std::ptr::null_mut();
    // SYMBOLIC_LINK_QUERY requests only this named link's target. Deliberately
    // avoid opening/enumerating the enclosing caller device-map directory.
    // SAFETY: counted name and attributes remain live; output is owned here.
    let status = unsafe { NtOpenSymbolicLinkObject(&raw mut handle, 0x0001, &attributes) };
    let link = if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        // SAFETY: a returned native handle is owned exactly once, including
        // cleanup if the native operation also reports failure.
        Some(unsafe { OwnedHandle::from_raw_handle(handle) })
    } else {
        None
    };
    if status < 0 {
        return Err(native_lookup_error(
            "NtOpenSymbolicLinkObject",
            path,
            status,
        ));
    }
    let link = link.ok_or("NtOpenSymbolicLinkObject returned an invalid runtime alias handle")?;
    let capacity = usize::from(u16::MAX) / std::mem::size_of::<u16>();
    let mut buffer = vec![0u16; capacity];
    let maximum = u16::try_from(
        buffer
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .ok_or("runtime alias buffer overflow")?,
    )
    .map_err(|_| "runtime alias buffer exceeds UNICODE_STRING")?;
    let mut target = UNICODE_STRING {
        Length: 0,
        MaximumLength: maximum,
        Buffer: buffer.as_mut_ptr(),
    };
    let mut returned_length = 0u32;
    // SAFETY: the owned link and counted target buffer remain live. There is
    // no retry, impersonation override or alternate namespace fallback.
    let status = unsafe {
        NtQuerySymbolicLinkObject(
            link.as_raw_handle(),
            &raw mut target,
            &raw mut returned_length,
        )
    };
    if status < 0 {
        return Err(native_lookup_error(
            "NtQuerySymbolicLinkObject",
            path,
            status,
        ));
    }
    if target.Buffer != buffer.as_mut_ptr() || target.MaximumLength != maximum {
        return Err("NtQuerySymbolicLinkObject changed its supplied target buffer".into());
    }
    direct_volume_target(&buffer, target.Length, target.MaximumLength)
        .map(<[u16]>::to_vec)
        .map_err(|error| {
            format!(
                "NtQuerySymbolicLinkObject(runtime drive {:?}): {error}",
                path
            )
        })
}
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

fn local_drive_components(path: &Path) -> Result<(u8, Vec<Vec<u16>>), String> {
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err("installed runtime requires a fully qualified local drive path".into());
    };
    let drive = match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) if drive.is_ascii_alphabetic() => drive,
        _ => return Err("installed runtime requires a direct local drive path".into()),
    };
    if components.next() != Some(Component::RootDir) {
        return Err("installed runtime path lacks a drive root".into());
    }
    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    let prefix_units = prefix.as_os_str().encode_wide().collect::<Vec<_>>();
    let tail = units
        .strip_prefix(prefix_units.as_slice())
        .ok_or("runtime drive prefix mismatch")?;
    let separator = |unit: &u16| *unit == u16::from(b'\\') || *unit == u16::from(b'/');
    let Some((root, tail)) = tail.split_first() else {
        return Err("installed runtime path lacks a file leaf".into());
    };
    if !separator(root) || units.contains(&0) {
        return Err("installed runtime path has an invalid root or NUL".into());
    }
    let mut relative = Vec::new();
    for segment in tail.split(separator) {
        if segment.is_empty()
            || segment == [u16::from(b'.')]
            || segment == [u16::from(b'.'), u16::from(b'.')]
            || segment.contains(&u16::from(b':'))
        {
            return Err(
                "installed runtime path contains an invalid component or alternate stream".into(),
            );
        }
        relative.push(segment.to_vec());
    }
    Ok((drive, relative))
}

fn open_without_reparse(path: &Path) -> Result<File, String> {
    let (drive, components) = local_drive_components(path)?;
    let mut native = resolve_drive(path, drive)?;
    for component in components {
        native.push(u16::from(b'\\'));
        native.extend(component);
    }
    let byte_length = native
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or("native runtime name exceeds UNICODE_STRING")?;
    native.push(0);
    let maximum_length = native
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or("native runtime backing buffer exceeds UNICODE_STRING")?;
    let mut name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: maximum_length,
        Buffer: native.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())
            .expect("native object attributes size"),
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &raw mut name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut handle = std::ptr::null_mut();
    let mut status_block = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    // SAFETY: all native structures and name storage remain live through the
    // synchronous call. No inheritance, creation or reparse-following option is set.
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            FILE_GENERIC_READ,
            &attributes,
            status_block.as_mut_ptr(),
            std::ptr::null(),
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            // SAFETY: a returned owned handle is closed even on a failed call.
            unsafe { CloseHandle(handle) };
        }
        // SAFETY: translation has no pointer arguments or ownership effects.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(format!(
            "NtCreateFile(protected runtime {:?}): ntstatus={status:#x}; raw-os-error={code}; reparse-encountered={}",
            path,
            status == windows_sys::Win32::Foundation::STATUS_REPARSE_POINT_ENCOUNTERED
        ));
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err("NtCreateFile returned an invalid runtime handle".into());
    }
    // SAFETY: successful native open transfers its sole owned handle to File.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(feature = "test-support")]
pub(super) fn open_protected_for_test(path: &Path) -> Result<File, String> {
    open_protected(path)
}

#[cfg(feature = "test-support")]
pub(super) fn direct_volume_target_for_test(
    buffer: &[u16],
    length: u16,
    maximum: u16,
) -> Result<Vec<u16>, String> {
    direct_volume_target(buffer, length, maximum).map(<[u16]>::to_vec)
}

fn open_protected(path: &Path) -> Result<File, String> {
    let file = open_without_reparse(path)?;
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
    let descriptor = protected_descriptor(&file, path)?;
    validate_protected_descriptor(&descriptor, path)?;
    Ok(file)
}

fn validate_protected_descriptor(descriptor: &[usize], path: &Path) -> Result<(), String> {
    let raw = descriptor.as_ptr().cast_mut().cast();
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: validated self-relative descriptor remains owned throughout checks.
    if unsafe { GetSecurityDescriptorOwner(raw, &raw mut owner, &raw mut owner_defaulted) } == 0 {
        let error = std::io::Error::last_os_error();
        return Err(format!(
            "GetSecurityDescriptorOwner(protected runtime {:?}): raw-os-error={:?}; {error}",
            path,
            error.raw_os_error()
        ));
    }
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    // SAFETY: accessor returns interior pointers into the same owned descriptor.
    if unsafe {
        GetSecurityDescriptorDacl(raw, &raw mut present, &raw mut dacl, &raw mut defaulted)
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return Err(format!(
            "GetSecurityDescriptorDacl(protected runtime {:?}): raw-os-error={:?}; {error}",
            path,
            error.raw_os_error()
        ));
    }
    let admins = super::well_known_sid(windows_sys::Win32::Security::WinBuiltinAdministratorsSid)?;
    let system = super::well_known_sid(windows_sys::Win32::Security::WinLocalSystemSid)?;
    // SAFETY: queried SIDs and ACL are valid for the descriptor lifetime.
    let privileged = |sid| unsafe {
        EqualSid(sid, admins.as_ptr().cast_mut().cast()) != 0
            || EqualSid(sid, system.as_ptr().cast_mut().cast()) != 0
    };
    if owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || !privileged(owner)
        || present == 0
        || dacl.is_null()
    {
        return Err("installed runtime ownership or DACL is not protected".into());
    }
    // File write/append/attributes/delete/control rights, including generic write/all.
    const MUTATION: u32 = 0x0000_0156 | 0x000D_0000 | 0x5000_0000;
    // SAFETY: validated descriptor supplied the bounded ACL; GetAce checks each index.
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
        // SAFETY: inspect header first; only ordinary allowed ACE layout is used.
        if unsafe { (*ace.cast::<ACE_HEADER>()).AceType } != 0 {
            return Err("installed runtime DACL has an unreviewed ACE type".into());
        }
        let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
        let sid = unsafe { std::ptr::addr_of_mut!((*ace).SidStart).cast() };
        // SAFETY: the bounded ordinary ACE SID extent was checked before
        // any descriptor accessor; reject invalid SID revision/count too.
        if unsafe { IsValidSid(sid) } == 0 {
            return Err("installed runtime DACL has an invalid SID".into());
        }
        if !privileged(sid) && unsafe { (*ace).Mask } & MUTATION != 0 {
            return Err("installed runtime grants mutation to an unprivileged identity".into());
        }
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub(super) fn protected_descriptor_for_test(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_FILE_SECURITY_DESCRIPTOR_BYTES {
        return Err("invalid supplied security descriptor length".into());
    }
    validate_relative_descriptor_bounds(bytes)?;
    let mut aligned = vec![0usize; bytes.len().div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: initialized aligned allocation covers bytes.len(); copied bytes
    // encode a bounded self-relative descriptor, not owned pointers.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            aligned.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        )
    };
    // SAFETY: all descriptor-relative extents were bounded before validation.
    if unsafe { IsValidSecurityDescriptor(aligned.as_mut_ptr().cast()) } == 0 {
        return Err("invalid supplied security descriptor".into());
    }
    validate_protected_descriptor(&aligned, Path::new("native-descriptor-test"))
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
