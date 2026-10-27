//! Read-only default-ACL fingerprint used only by the standalone experiment.
use sha2::{Digest, Sha256};
use std::{io, mem::size_of};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_DEFAULT_DACL, TokenDefaultDacl};

pub(super) struct DefaultAclObservation {
    pub bytes: Option<Vec<u8>>,
    pub sha256: String,
}

pub(super) fn collect(token: HANDLE) -> io::Result<DefaultAclObservation> {
    let mut required = 0;
    // SAFETY: sizing query on this retained query-only token.
    let sized = unsafe {
        GetTokenInformation(
            token,
            TokenDefaultDacl,
            std::ptr::null_mut(),
            0,
            &mut required,
        )
    };
    let error = io::Error::last_os_error();
    if sized != 0 || error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if required as usize > 64 * 1024 || (required as usize) < size_of::<TOKEN_DEFAULT_DACL>() {
        return Err(io::Error::other("experiment default ACL query bound"));
    }
    let mut storage = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
    let capacity = required;
    // SAFETY: aligned allocation covers the bounded capacity.
    if unsafe {
        GetTokenInformation(
            token,
            TokenDefaultDacl,
            storage.as_mut_ptr().cast(),
            capacity,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if required > capacity || (required as usize) < size_of::<TOKEN_DEFAULT_DACL>() {
        return Err(io::Error::other("experiment default ACL returned extent"));
    }
    // SAFETY: complete fixed native header fits returned extent.
    let pointer = unsafe {
        storage
            .as_ptr()
            .cast::<TOKEN_DEFAULT_DACL>()
            .read()
            .DefaultDacl
    };
    let acl = if pointer.is_null() {
        None
    } else {
        let offset = (pointer as usize)
            .checked_sub(storage.as_ptr() as usize)
            .ok_or_else(|| io::Error::other("experiment default ACL pointer"))?;
        if offset < size_of::<TOKEN_DEFAULT_DACL>()
            || offset
                .checked_add(8)
                .is_none_or(|end| end > required as usize)
        {
            return Err(io::Error::other("experiment default ACL header"));
        }
        // SAFETY: native ACL header admitted inside this retained query allocation.
        let header = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), 8) };
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if length < 8
            || offset
                .checked_add(length)
                .is_none_or(|end| end > required as usize)
        {
            return Err(io::Error::other("experiment default ACL extent"));
        }
        // SAFETY: complete ACL bytes admitted inside the same live query.
        Some(unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) }.to_vec())
    };
    let bytes = serde_json::to_vec(&acl).map_err(io::Error::other)?;
    let sha256 = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(DefaultAclObservation { bytes: acl, sha256 })
}
