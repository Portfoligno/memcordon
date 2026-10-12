//! Explicit standard system prerequisite for genuine readiness frontends.
//! This is fixture input, never an addition to the provider's caller environment.

#[cfg(windows)]
#[allow(unsafe_code)] // Bounded read-only native system-directory discovery.
pub fn entries() -> std::io::Result<Vec<memcordon_core::WindowsEnvironmentEntryV1>> {
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemInfo, GetSystemWindowsDirectoryW, SYSTEM_INFO,
    };
    let mut directory = [0u16; 2048];
    // SAFETY: fixed writable UTF-16 buffer with its exact advertised capacity.
    let length =
        unsafe { GetSystemWindowsDirectoryW(directory.as_mut_ptr(), directory.len() as u32) };
    if length == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if length as usize >= directory.len() || directory[length as usize] != 0 {
        return Err(std::io::Error::other(
            "native system Windows directory exceeds bound",
        ));
    }
    // SAFETY: zeroed SYSTEM_INFO is valid writable output for GetSystemInfo.
    let mut system: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: initialized structure has the native API's exact output layout.
    unsafe { GetSystemInfo(&mut system) };
    // SAFETY: GetSystemInfo initialized the architecture member of this union.
    let architecture = unsafe { system.Anonymous.Anonymous.wProcessorArchitecture };
    from_system(&directory[..length as usize], architecture)
}

pub fn from_system(
    directory: &[u16],
    architecture: u16,
) -> std::io::Result<Vec<memcordon_core::WindowsEnvironmentEntryV1>> {
    if directory.len() < 3
        || directory.len() >= 2048
        || !matches!(directory[0], 65..=90 | 97..=122)
        || directory[1] != b':' as u16
        || directory[2] != b'\\' as u16
        || directory.iter().any(|unit| matches!(*unit, 0 | 37 | 61))
    {
        return Err(std::io::Error::other(
            "native system Windows directory is not a bounded absolute drive path",
        ));
    }
    let architecture = match architecture {
        9 => "AMD64",
        12 => "ARM64",
        _ => {
            return Err(std::io::Error::other(
                "unsupported native frontend architecture",
            ));
        }
    };
    let drive = match directory[0] {
        lower @ 97..=122 => lower - 32,
        upper => upper,
    };
    Ok(vec![
        // Native drive-relative resolution defaults to the drive root when no
        // directory entry is supplied. Declare that exact fixture input rather
        // than inheriting ambient per-drive directories from the controller.
        memcordon_core::WindowsEnvironmentEntryV1 {
            name: vec![u16::from(b'='), drive, u16::from(b':')],
            value: vec![drive, u16::from(b':'), u16::from(b'\\')],
        },
        memcordon_core::WindowsEnvironmentEntryV1 {
            name: "PROCESSOR_ARCHITECTURE".encode_utf16().collect(),
            value: architecture.encode_utf16().collect(),
        },
        memcordon_core::WindowsEnvironmentEntryV1 {
            name: "SystemRoot".encode_utf16().collect(),
            value: directory.to_vec(),
        },
    ])
}
