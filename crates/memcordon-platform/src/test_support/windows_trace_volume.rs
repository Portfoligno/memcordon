//! Actual volume capacity and stable identity for bounded diagnostic exports.
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::{
    DISK_SPACE_INFORMATION, GetDiskSpaceInformationW, GetVolumeNameForVolumeMountPointW,
    GetVolumePathNameW,
};

/// Return the normalized volume GUID, actual volume capacity (ignoring quotas),
/// and caller-available bytes. A caller quota on a larger volume is not a hard
/// bound on exports performed by a different tracing principal.
pub fn windows_trace_volume(path: &Path) -> io::Result<(PathBuf, u64, u64)> {
    let path = path.canonicalize()?;
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.contains(&0) {
        return Err(io::Error::other("trace path contains NUL"));
    }
    encoded.push(0);
    // A mount-root input may omit its trailing separator. Leave space for the
    // separator as well as the terminator already included in `encoded`.
    let mut volume = vec![0_u16; encoded.len() + '\\'.len_utf16()];
    let length = u32::try_from(volume.len()).map_err(io::Error::other)?;
    // SAFETY: terminated input and sized output remain allocated for the calls.
    if unsafe { GetVolumePathNameW(encoded.as_ptr(), volume.as_mut_ptr(), length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = volume
        .iter()
        .position(|&c| c == 0)
        .ok_or_else(|| io::Error::other("unterminated volume path"))?;
    if !volume[..end].ends_with(&[u16::from(b'\\')]) {
        return Err(io::Error::other(
            "volume mount path has no trailing separator",
        ));
    }
    // The documented GUID path form defines the buffer size without a magic
    // character count. Mount aliases resolve to the same normalized volume key.
    let guid_capacity = r"\\?\Volume{00000000-0000-0000-0000-000000000000}\"
        .encode_utf16()
        .chain([0])
        .count();
    let mut guid = vec![0_u16; guid_capacity];
    let guid_length = u32::try_from(guid.len()).map_err(io::Error::other)?;
    // SAFETY: the mount path is terminated and `guid` has the advertised size.
    if unsafe { GetVolumeNameForVolumeMountPointW(volume.as_ptr(), guid.as_mut_ptr(), guid_length) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: every field in this Windows output structure is an integer; zero
    // initializes a valid value and the API receives a live mutable pointer.
    let mut space: DISK_SPACE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the normalized volume GUID is terminated and `space` is writable.
    let status = unsafe { GetDiskSpaceInformationW(guid.as_ptr(), &raw mut space) };
    if status < 0 {
        return Err(io::Error::other(format!(
            "GetDiskSpaceInformationW failed: {status:#x}"
        )));
    }
    let unit = u64::from(space.SectorsPerAllocationUnit)
        .checked_mul(u64::from(space.BytesPerSector))
        .filter(|unit| *unit != 0)
        .ok_or_else(|| io::Error::other("invalid volume allocation unit"))?;
    let total = space
        .ActualTotalAllocationUnits
        .checked_mul(unit)
        .ok_or_else(|| io::Error::other("volume capacity overflow"))?;
    let available = space
        .CallerAvailableAllocationUnits
        .checked_mul(unit)
        .ok_or_else(|| io::Error::other("available volume capacity overflow"))?;
    let end = guid
        .iter()
        .position(|&c| c == 0)
        .ok_or_else(|| io::Error::other("unterminated volume GUID"))?;
    Ok((
        PathBuf::from(std::ffi::OsString::from_wide(&guid[..end])),
        total,
        available,
    ))
}
