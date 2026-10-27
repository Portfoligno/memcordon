use crate::{
    ObservationUnavailable, PrivilegeAttributesV1, SidAttributesV1, TokenObservationV1,
    TokenStatisticsObservationV1, privilege_attributes_digest, sid_attributes_digest,
};
use memcordon_core::WindowsCallerTokenEnvelopeV1;
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
    envelope(
        token,
        &mut QueryMode {
            bounded: false,
            check: &mut || Ok(()),
        },
        false,
    )
    .map(|(envelope, _)| envelope)
}

/// Same canonical model, with finite diagnostic inventories and original-clock checks.
pub fn query_token_envelope_bounded(
    token: HANDLE,
    check: &mut dyn FnMut() -> Result<(), String>,
) -> Result<WindowsCallerTokenEnvelopeV1, String> {
    envelope(
        token,
        &mut QueryMode {
            bounded: true,
            check,
        },
        false,
    )
    .map(|(envelope, _)| envelope)
}

/// The same collection and canonical envelope, with optional owned diagnostics.
/// Diagnostic limits never change the envelope's native query/admission behavior.
pub fn query_token_envelope_with_observation(
    token: HANDLE,
) -> Result<
    (
        WindowsCallerTokenEnvelopeV1,
        Result<TokenObservationV1, ObservationUnavailable>,
    ),
    String,
> {
    envelope(
        token,
        &mut QueryMode {
            bounded: false,
            check: &mut || Ok(()),
        },
        true,
    )
}

struct QueryMode<'a> {
    bounded: bool,
    check: &'a mut dyn FnMut() -> Result<(), String>,
}

fn query_error(mode: &QueryMode<'_>, error: io::Error) -> String {
    if mode.bounded {
        format!(
            "bounded native token query failed: raw={:?}",
            error.raw_os_error()
        )
    } else {
        error.to_string()
    }
}

fn envelope(
    token: HANDLE,
    mode: &mut QueryMode<'_>,
    capture: bool,
) -> Result<
    (
        WindowsCallerTokenEnvelopeV1,
        Result<TokenObservationV1, ObservationUnavailable>,
    ),
    String,
> {
    let statistics = scalar_struct::<TOKEN_STATISTICS>(token, TokenStatistics, mode)?;
    let user = query(token, TokenUser, mode)?;
    let owner = query(token, TokenOwner, mode)?;
    let primary_group = query(token, TokenPrimaryGroup, mode)?;
    let groups = query(token, TokenGroups, mode)?;
    let privileges = query(token, TokenPrivileges, mode)?;
    let restricted = query(token, TokenRestrictedSids, mode)?;
    let integrity = query(token, TokenIntegrityLevel, mode)?;
    let mandatory = query(token, TokenMandatoryPolicy, mode)?;
    if mode.bounded {
        validate_sid(
            &user,
            read_fixed::<windows_sys::Win32::Security::TOKEN_USER>(&user)?
                .User
                .Sid,
        )?;
        validate_sid(&owner, read_fixed::<TOKEN_OWNER>(&owner)?.Owner)?;
        validate_sid(
            &primary_group,
            read_fixed::<TOKEN_PRIMARY_GROUP>(&primary_group)?.PrimaryGroup,
        )?;
        validate_sid(
            &integrity,
            read_fixed::<TOKEN_MANDATORY_LABEL>(&integrity)?.Label.Sid,
        )?;
    }
    let user_value = read_fixed::<windows_sys::Win32::Security::TOKEN_USER>(&user)?;
    let owner_value = read_fixed::<TOKEN_OWNER>(&owner)?;
    let primary_group_value = read_fixed::<TOKEN_PRIMARY_GROUP>(&primary_group)?;
    let integrity_value = read_fixed::<TOKEN_MANDATORY_LABEL>(&integrity)?;
    let mandatory = read_fixed::<TOKEN_MANDATORY_POLICY>(&mandatory)?;
    let token_type = statistics.TokenType;
    let impersonation_level = if token_type == TokenPrimary {
        SecurityAnonymous as u32
    } else if token_type == TokenImpersonation {
        let level = scalar_i32(token, TokenImpersonationLevel, mode)?;
        if !(SecurityAnonymous..=SecurityDelegation).contains(&level) {
            return Err(String::from("token impersonation level is invalid"));
        }
        level as u32
    } else {
        return Err(String::from("token type is invalid"));
    };
    // These checks govern only optional retention. Original native conversion
    // and envelope error behavior remain identical for every existing caller.
    let fixed_spans = !capture
        || [
            (
                &user,
                user_value.User.Sid,
                size_of::<windows_sys::Win32::Security::TOKEN_USER>(),
            ),
            (&owner, owner_value.Owner, size_of::<TOKEN_OWNER>()),
            (
                &primary_group,
                primary_group_value.PrimaryGroup,
                size_of::<TOKEN_PRIMARY_GROUP>(),
            ),
            (
                &integrity,
                integrity_value.Label.Sid,
                size_of::<TOKEN_MANDATORY_LABEL>(),
            ),
        ]
        .into_iter()
        .all(|(buffer, sid, minimum)| observation_sid(buffer.as_bytes(), sid, minimum));
    let user_sid = sid_string(user_value.User.Sid, mode)?;
    let owner_sid = sid_string(owner_value.Owner, mode)?;
    let primary_group_sid = sid_string(primary_group_value.PrimaryGroup, mode)?;
    let (normal_groups, normal_spans) = groups_records(groups.as_bytes(), mode, capture)?;
    let privileges = privilege_records(privileges.as_bytes(), mode)?;
    let (restricted_sids, restricted_spans) = groups_records(restricted.as_bytes(), mode, capture)?;
    let integrity_level = sid_string(integrity_value.Label.Sid, mode)?;
    let value = WindowsCallerTokenEnvelopeV1 {
        user_sid,
        owner_sid,
        primary_group_sid,
        groups_sha256: sid_attributes_digest(&normal_groups)?,
        privileges_sha256: privilege_attributes_digest(&privileges)?,
        restricted_sids_sha256: sid_attributes_digest(&restricted_sids)?,
        integrity_level,
        mandatory_policy: mandatory.Policy,
        session_id: scalar_u32(token, TokenSessionId, mode)?,
        elevation_type: scalar_i32(token, TokenElevationType, mode)? as u32,
        elevated: scalar_struct::<TOKEN_ELEVATION>(token, TokenElevation, mode)?.TokenIsElevated
            != 0,
        virtualization_allowed: scalar_u32(token, TokenVirtualizationAllowed, mode)? != 0,
        virtualization_enabled: scalar_u32(token, TokenVirtualizationEnabled, mode)? != 0,
        ui_access: scalar_u32(token, TokenUIAccess, mode)? != 0,
        appcontainer: scalar_u32(token, TokenIsAppContainer, mode)? != 0,
        authentication_id: luid(&statistics.AuthenticationId),
        token_type: token_type as u32,
        impersonation_level,
    };
    let observation = if !capture {
        Err(ObservationUnavailable::NotRequested)
    } else if !fixed_spans || !normal_spans || !restricted_spans {
        Err(ObservationUnavailable::NativeExtent)
    } else {
        TokenObservationV1::from_parts(
            value.clone(),
            user_value.User.Attributes,
            TokenStatisticsObservationV1 {
                token_id: luid(&statistics.TokenId),
                modified_id: luid(&statistics.ModifiedId),
                expiration_time: statistics.ExpirationTime,
                dynamic_charged: statistics.DynamicCharged,
                dynamic_available: statistics.DynamicAvailable,
                group_count: statistics.GroupCount,
                privilege_count: statistics.PrivilegeCount,
            },
            normal_groups,
            restricted_sids,
            privileges,
        )
    };
    Ok((value, observation))
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

fn query(token: HANDLE, class: i32, mode: &mut QueryMode<'_>) -> Result<QueryBuffer, String> {
    (mode.check)()?;
    let mut length = 0_u32;
    unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &raw mut length) };
    if length == 0 {
        let error = query_error(mode, io::Error::last_os_error());
        (mode.check)()?;
        return Err(error);
    }
    let requested = length as usize;
    (mode.check)()?;
    if mode.bounded && requested > 64 * 1024 {
        return Err("bounded token query exceeds byte cap".into());
    }
    let mut words = vec![0_usize; requested.div_ceil(std::mem::size_of::<usize>())];
    (mode.check)()?;
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
        let error = query_error(mode, io::Error::last_os_error());
        (mode.check)()?;
        return Err(error);
    }
    (mode.check)()?;
    if mode.bounded && length as usize > requested {
        return Err("bounded token query returned excessive length".into());
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

fn scalar_struct<T: Copy>(
    token: HANDLE,
    class: i32,
    mode: &mut QueryMode<'_>,
) -> Result<T, String> {
    read_fixed(&query(token, class, mode)?)
}

fn scalar_u32(token: HANDLE, class: i32, mode: &mut QueryMode<'_>) -> Result<u32, String> {
    scalar_struct(token, class, mode)
}

fn scalar_i32(token: HANDLE, class: i32, mode: &mut QueryMode<'_>) -> Result<i32, String> {
    scalar_u32(token, class, mode).map(|value| value as i32)
}

fn groups_records(
    buffer: &[u8],
    mode: &mut QueryMode<'_>,
    capture: bool,
) -> Result<(Vec<SidAttributesV1>, bool), String> {
    if mode.bounded
        && buffer.len() >= size_of::<u32>()
        && unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } == 0
    {
        return Ok((Vec::new(), true));
    }
    let entries =
        variable_entries::<SID_AND_ATTRIBUTES>(buffer, std::mem::offset_of!(TOKEN_GROUPS, Groups))?;
    if mode.bounded {
        if entries.len() > 256 {
            return Err("bounded token group inventory exceeds cap".into());
        }
        for entry in entries {
            validate_sid_bytes(buffer, entry.Sid)?;
        }
    }
    let minimum =
        std::mem::offset_of!(TOKEN_GROUPS, Groups).checked_add(std::mem::size_of_val(entries));
    let spans = !capture
        || minimum.is_some_and(|minimum| {
            entries
                .iter()
                .all(|entry| observation_sid(buffer, entry.Sid, minimum))
        });
    let mut canonical = entries
        .iter()
        .map(|entry| {
            Ok(SidAttributesV1 {
                sid: sid_string(entry.Sid, mode)?,
                attributes: entry.Attributes,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    canonical.sort();
    Ok((canonical, spans))
}

fn privilege_records(
    buffer: &[u8],
    mode: &mut QueryMode<'_>,
) -> Result<Vec<PrivilegeAttributesV1>, String> {
    let entries = variable_entries::<LUID_AND_ATTRIBUTES>(
        buffer,
        std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges),
    )?;
    if mode.bounded && entries.len() > 256 {
        return Err("bounded token privilege inventory exceeds cap".into());
    }
    let mut canonical = entries
        .iter()
        .map(|entry| PrivilegeAttributesV1 {
            luid_high: entry.Luid.HighPart,
            luid_low: entry.Luid.LowPart,
            attributes: entry.Attributes,
        })
        .collect::<Vec<_>>();
    canonical.sort();
    Ok(canonical)
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

fn validate_sid(buffer: &QueryBuffer, sid: *mut c_void) -> Result<(), String> {
    validate_sid_bytes(buffer.as_bytes(), sid)
}
fn observation_sid(buffer: &[u8], sid: *mut c_void, minimum: usize) -> bool {
    (sid as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .is_some_and(|offset| {
            offset >= minimum
                && offset % std::mem::align_of::<u32>() == 0
                && validate_sid_bytes(buffer, sid).is_ok()
        })
}
fn validate_sid_bytes(buffer: &[u8], sid: *mut c_void) -> Result<(), String> {
    let offset = (sid as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .ok_or("bounded token SID outside response")?;
    let tail = buffer
        .get(offset..)
        .ok_or("bounded token SID outside response")?;
    if tail.len() < 8
        || tail[0] != 1
        || tail[1] > 15
        || 8 + usize::from(tail[1]) * size_of::<u32>() > tail.len()
    {
        return Err("bounded token SID extent differs".into());
    }
    Ok(())
}
struct LocalSid(*mut u16);
impl Drop for LocalSid {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0.cast()) };
    }
}
fn sid_text_units_bound() -> usize {
    let authority_max = (1_u64 << 48) - 1;
    let subauthority_max = u32::MAX;
    let subauthorities = 15;
    "S-1-".encode_utf16().count()
        + authority_max.to_string().encode_utf16().count()
        + subauthorities
            * ("-".encode_utf16().count() + subauthority_max.to_string().encode_utf16().count())
        + [0_u16].len()
}
fn sid_string(sid: *mut c_void, mode: &mut QueryMode<'_>) -> Result<String, String> {
    if sid.is_null() {
        return Err(String::from("token contains a null SID"));
    }
    let mut string = ptr::null_mut();
    (mode.check)()?;
    if unsafe { ConvertSidToStringSidW(sid, &raw mut string) } == 0 {
        let error = query_error(mode, io::Error::last_os_error());
        (mode.check)()?;
        return Err(error);
    }
    let string = LocalSid(string);
    (mode.check)()?;
    let mut length = 0_usize;
    let text_bound = mode.bounded.then(sid_text_units_bound);
    loop {
        if text_bound.is_some_and(|bound| length >= bound) {
            return Err("bounded token SID text exceeds cap".into());
        }
        if unsafe { *string.0.add(length) } == 0 {
            break;
        }
        length = length
            .checked_add(1)
            .ok_or_else(|| String::from("SID string length overflow"))?;
    }
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(string.0, length) })
        .map_err(|error| {
            if mode.bounded {
                "bounded token SID text is invalid UTF16".to_owned()
            } else {
                error.to_string()
            }
        });
    let before_free = (mode.check)();
    drop(string);
    let after_free = (mode.check)();
    before_free?;
    after_free?;
    value
}

fn luid(value: &windows_sys::Win32::Foundation::LUID) -> u64 {
    (u64::from(value.HighPart as u32) << u32::BITS) | u64::from(value.LowPart)
}
