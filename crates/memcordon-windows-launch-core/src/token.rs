use memcordon_core::WindowsCallerTokenEnvelopeV1;
use sha2::{Digest, Sha256};
use std::{ffi::c_void, io, ptr};
use windows_sys::Win32::{
    Foundation::{HANDLE, LocalFree},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, LUID_AND_ATTRIBUTES,
        SID_AND_ATTRIBUTES, SecurityAnonymous, SecurityDelegation, TOKEN_ELEVATION, TOKEN_GROUPS,
        TOKEN_MANDATORY_LABEL, TOKEN_MANDATORY_POLICY, TOKEN_OWNER, TOKEN_PRIMARY_GROUP,
        TOKEN_PRIVILEGES, TOKEN_STATISTICS, TokenElevation, TokenElevationType, TokenGroups,
        TokenImpersonation, TokenImpersonationLevel, TokenIntegrityLevel, TokenIsAppContainer,
        TokenMandatoryPolicy, TokenOwner, TokenPrimary, TokenPrimaryGroup, TokenPrivileges,
        TokenRestrictedSids, TokenSessionId, TokenStatistics, TokenUIAccess, TokenUser,
        TokenVirtualizationAllowed, TokenVirtualizationEnabled,
    },
};

/// Captures the canonical live token envelope used by both production and the
/// loader laboratory. The returned value is safe to serialize; it contains
/// only SIDs, flags, scalar identities, and digests of variable inventories.
pub fn query_token_envelope(token: HANDLE) -> Result<WindowsCallerTokenEnvelopeV1, String> {
    let statistics = scalar_struct::<TOKEN_STATISTICS>(token, TokenStatistics)?;
    let user = query(token, TokenUser)?;
    let owner = query(token, TokenOwner)?;
    let primary_group = query(token, TokenPrimaryGroup)?;
    let groups = query(token, TokenGroups)?;
    let privileges = query(token, TokenPrivileges)?;
    let restricted = query(token, TokenRestrictedSids)?;
    let integrity = query(token, TokenIntegrityLevel)?;
    let mandatory = query(token, TokenMandatoryPolicy)?;
    let user = read_fixed::<windows_sys::Win32::Security::TOKEN_USER>(&user)?;
    let owner = read_fixed::<TOKEN_OWNER>(&owner)?;
    let primary_group = read_fixed::<TOKEN_PRIMARY_GROUP>(&primary_group)?;
    let integrity = read_fixed::<TOKEN_MANDATORY_LABEL>(&integrity)?;
    let mandatory = read_fixed::<TOKEN_MANDATORY_POLICY>(&mandatory)?;
    let token_type = statistics.TokenType;
    let impersonation_level = if token_type == TokenPrimary {
        SecurityAnonymous as u32
    } else if token_type == TokenImpersonation {
        let level = scalar_i32(token, TokenImpersonationLevel)?;
        if !(SecurityAnonymous..=SecurityDelegation).contains(&level) {
            return Err(String::from("token impersonation level is invalid"));
        }
        level as u32
    } else {
        return Err(String::from("token type is invalid"));
    };
    Ok(WindowsCallerTokenEnvelopeV1 {
        user_sid: sid_string(user.User.Sid)?,
        owner_sid: sid_string(owner.Owner)?,
        primary_group_sid: sid_string(primary_group.PrimaryGroup)?,
        groups_sha256: groups_digest(groups.as_bytes())?,
        privileges_sha256: privileges_digest(privileges.as_bytes())?,
        restricted_sids_sha256: groups_digest(restricted.as_bytes())?,
        integrity_level: sid_string(integrity.Label.Sid)?,
        mandatory_policy: mandatory.Policy,
        session_id: scalar_u32(token, TokenSessionId)?,
        elevation_type: scalar_i32(token, TokenElevationType)? as u32,
        elevated: scalar_struct::<TOKEN_ELEVATION>(token, TokenElevation)?.TokenIsElevated != 0,
        virtualization_allowed: scalar_u32(token, TokenVirtualizationAllowed)? != 0,
        virtualization_enabled: scalar_u32(token, TokenVirtualizationEnabled)? != 0,
        ui_access: scalar_u32(token, TokenUIAccess)? != 0,
        appcontainer: scalar_u32(token, TokenIsAppContainer)? != 0,
        authentication_id: luid(&statistics.AuthenticationId),
        token_type: token_type as u32,
        impersonation_level,
    })
}

struct QueryBuffer {
    words: Vec<usize>,
    byte_length: usize,
}

impl QueryBuffer {
    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.byte_length) }
    }
}

fn query(token: HANDLE, class: i32) -> Result<QueryBuffer, String> {
    let mut length = 0_u32;
    unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &raw mut length) };
    if length == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let requested = length as usize;
    let mut words = vec![0_usize; requested.div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token,
            class,
            words.as_mut_ptr().cast(),
            length,
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(QueryBuffer {
        words,
        byte_length: length as usize,
    })
}

fn read_fixed<T: Copy>(buffer: &QueryBuffer) -> Result<T, String> {
    if buffer.byte_length < std::mem::size_of::<T>() {
        return Err(String::from("token information response is truncated"));
    }
    Ok(unsafe { ptr::read_unaligned(buffer.words.as_ptr().cast::<T>()) })
}

fn scalar_struct<T: Copy>(token: HANDLE, class: i32) -> Result<T, String> {
    read_fixed(&query(token, class)?)
}

fn scalar_u32(token: HANDLE, class: i32) -> Result<u32, String> {
    scalar_struct(token, class)
}

fn scalar_i32(token: HANDLE, class: i32) -> Result<i32, String> {
    scalar_u32(token, class).map(|value| value as i32)
}

fn groups_digest(buffer: &[u8]) -> Result<String, String> {
    let mut canonical =
        variable_entries::<SID_AND_ATTRIBUTES>(buffer, std::mem::offset_of!(TOKEN_GROUPS, Groups))?
            .iter()
            .map(|entry| Ok((sid_string(entry.Sid)?, entry.Attributes)))
            .collect::<Result<Vec<_>, String>>()?;
    canonical.sort();
    digest_records(canonical.into_iter().map(|(sid, attributes)| {
        let mut record = sid.into_bytes();
        record.extend_from_slice(&attributes.to_le_bytes());
        record
    }))
}

fn privileges_digest(buffer: &[u8]) -> Result<String, String> {
    let mut canonical = variable_entries::<LUID_AND_ATTRIBUTES>(
        buffer,
        std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges),
    )?
    .iter()
    .map(|entry| (entry.Luid.HighPart, entry.Luid.LowPart, entry.Attributes))
    .collect::<Vec<_>>();
    canonical.sort();
    digest_records(canonical.into_iter().map(|(high, low, attributes)| {
        let mut record = high.to_le_bytes().to_vec();
        record.extend_from_slice(&low.to_le_bytes());
        record.extend_from_slice(&attributes.to_le_bytes());
        record
    }))
}

fn variable_entries<T>(buffer: &[u8], fixed: usize) -> Result<&[T], String> {
    if buffer.len() < fixed || buffer.len() < std::mem::size_of::<u32>() {
        return Err(String::from("variable token response is truncated"));
    }
    let count = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    let bytes = count
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| fixed.checked_add(bytes))
        .ok_or_else(|| String::from("variable token response size overflow"))?;
    if bytes > buffer.len() {
        return Err(String::from("variable token response is truncated"));
    }
    let first = unsafe { buffer.as_ptr().add(fixed) }.cast::<T>();
    if first.align_offset(std::mem::align_of::<T>()) != 0 {
        return Err(String::from("variable token response is misaligned"));
    }
    Ok(unsafe { std::slice::from_raw_parts(first, count) })
}

fn digest_records(records: impl IntoIterator<Item = Vec<u8>>) -> Result<String, String> {
    let mut digest = Sha256::new();
    for record in records {
        let length = u32::try_from(record.len())
            .map_err(|_| String::from("token record length overflow"))?;
        digest.update(length.to_le_bytes());
        digest.update(record);
    }
    Ok(hex::encode(digest.finalize()))
}

fn sid_string(sid: *mut c_void) -> Result<String, String> {
    if sid.is_null() {
        return Err(String::from("token contains a null SID"));
    }
    let mut string = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &raw mut string) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut length = 0_usize;
    while unsafe { *string.add(length) } != 0 {
        length = length
            .checked_add(1)
            .ok_or_else(|| String::from("SID string length overflow"))?;
    }
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(string, length) })
        .map_err(|error| error.to_string());
    unsafe { LocalFree(string.cast()) };
    value
}

fn luid(value: &windows_sys::Win32::Foundation::LUID) -> u64 {
    (u64::from(value.HighPart as u32) << u32::BITS) | u64::from(value.LowPart)
}
