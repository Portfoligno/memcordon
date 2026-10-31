//! Default-object policy for the trusted fixture's own newly restricted token.
use std::io;
use std::mem::{offset_of, size_of};

use memcordon_core::WindowsCallerTokenEnvelopeV1;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE, LUID};
use windows_sys::Win32::Security::{
    ACL, GetTokenInformation, SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_DEFAULT_DACL,
    TOKEN_GROUPS, TOKEN_STATISTICS, TokenDefaultDacl, TokenPrimary, TokenRestrictedSids,
    TokenStatistics,
};
use windows_sys::Win32::System::SystemServices::{SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY};

use super::fixture_default_dacl::{self as policy, MAX_ACL_BYTES, RESTRICTED_CODE_SID};

const TOKEN_QUERY_BOUND: usize = 64 * 1024;

struct Query {
    words: Vec<usize>,
    length: usize,
}

struct NativeFailure {
    operation: &'static str,
    class: i32,
    cause: io::Error,
}

impl std::fmt::Display for NativeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "fixture default-DACL operation={}; class={}; kind={:?}; raw-os-error={:?}",
            self.operation,
            self.class,
            self.cause.kind(),
            self.cause.raw_os_error()
        )
    }
}

impl std::fmt::Debug for NativeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for NativeFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

fn native_failure(operation: &'static str, class: i32, cause: io::Error) -> io::Error {
    io::Error::new(
        cause.kind(),
        NativeFailure {
            operation,
            class,
            cause,
        },
    )
}

fn query(token: HANDLE, class: i32) -> io::Result<Query> {
    let mut required = 0;
    // SAFETY: sizing query only writes the returned length.
    let sized =
        unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut required) };
    if sized != 0 {
        return Err(io::Error::other(format!(
            "fixture default-DACL sizing unexpectedly succeeded: class={class}; required={required}"
        )));
    }
    let cause = io::Error::last_os_error();
    if cause.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(native_failure("GetTokenInformation-size", class, cause));
    }
    if required == 0 || required as usize > TOKEN_QUERY_BOUND {
        return Err(io::Error::other("fixture token query exceeds finite bound"));
    }
    let mut words = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
    let mut actual = required;
    // SAFETY: aligned storage covers the exact advertised native capacity.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            words.as_mut_ptr().cast(),
            required,
            &mut actual,
        )
    } == 0
    {
        return Err(native_failure(
            "GetTokenInformation-read",
            class,
            io::Error::last_os_error(),
        ));
    }
    if actual == 0 || actual > required {
        return Err(io::Error::other(
            "fixture token query returned an invalid extent",
        ));
    }
    Ok(Query {
        words,
        length: actual as usize,
    })
}

fn pointer_range(query: &Query, pointer: *const u8, length: usize) -> io::Result<usize> {
    let offset = (pointer as usize)
        .checked_sub(query.words.as_ptr() as usize)
        .ok_or_else(|| io::Error::other("fixture token pointer precedes native query"))?;
    if offset
        .checked_add(length)
        .is_none_or(|end| end > query.length)
    {
        return Err(io::Error::other(
            "fixture token pointer exceeds returned native extent",
        ));
    }
    Ok(offset)
}

fn default_acl(token: HANDLE) -> io::Result<Option<Vec<u8>>> {
    let captured = query(token, TokenDefaultDacl)?;
    if captured.length < size_of::<TOKEN_DEFAULT_DACL>() {
        return Err(io::Error::other("fixture default-DACL header is truncated"));
    }
    // SAFETY: the fixed header is inside the checked aligned query buffer.
    let header = unsafe {
        captured
            .words
            .as_ptr()
            .cast::<TOKEN_DEFAULT_DACL>()
            .read_unaligned()
    };
    if header.DefaultDacl.is_null() {
        return Ok(None);
    }
    pointer_range(&captured, header.DefaultDacl.cast(), size_of::<ACL>())?;
    // SAFETY: the complete ACL header was admitted inside the live query.
    let acl = unsafe { header.DefaultDacl.read_unaligned() };
    let length = usize::from(acl.AclSize);
    if !(size_of::<ACL>()..=MAX_ACL_BYTES).contains(&length) {
        return Err(io::Error::other(
            "fixture default-DACL exceeds supported finite extent",
        ));
    }
    pointer_range(&captured, header.DefaultDacl.cast(), length)?;
    // SAFETY: the entire admitted ACL remains owned by captured for this copy.
    Ok(Some(
        unsafe { std::slice::from_raw_parts(header.DefaultDacl.cast::<u8>(), length) }.to_vec(),
    ))
}

fn require_restricted_code(token: HANDLE) -> io::Result<()> {
    let captured = query(token, TokenRestrictedSids)?;
    let offset = offset_of!(TOKEN_GROUPS, Groups);
    if captured.length < offset + size_of::<SID_AND_ATTRIBUTES>() {
        return Err(io::Error::other(
            "fixture restricting SID inventory is truncated",
        ));
    }
    // SAFETY: the fixed count and sole entry are within the checked allocation.
    let count = unsafe { captured.words.as_ptr().cast::<u32>().read_unaligned() };
    if count != 1 {
        return Err(io::Error::other(
            "fixture requires exactly the RestrictedCode SID",
        ));
    }
    // SAFETY: the entry lies entirely within the returned native extent.
    let group = unsafe {
        captured
            .words
            .as_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<SID_AND_ATTRIBUTES>()
            .read_unaligned()
    };
    pointer_range(&captured, group.Sid.cast(), RESTRICTED_CODE_SID.len())?;
    // SAFETY: the canonical SID-sized range was admitted in this live query.
    let sid =
        unsafe { std::slice::from_raw_parts(group.Sid.cast::<u8>(), RESTRICTED_CODE_SID.len()) };
    if sid != RESTRICTED_CODE_SID
        || group.Attributes & SE_GROUP_ENABLED as u32 == 0
        || group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 != 0
    {
        return Err(io::Error::other(
            "fixture restricting SID is not enabled RestrictedCode",
        ));
    }
    Ok(())
}

fn luid(value: LUID) -> u64 {
    (u64::from(value.HighPart as u32) << 32) | u64::from(value.LowPart)
}

#[derive(Debug, Eq, PartialEq)]
struct StableToken {
    envelope: WindowsCallerTokenEnvelopeV1,
    token_id: u64,
    expiration: i64,
    group_count: u32,
    privilege_count: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    stable: StableToken,
    modified_id: u64,
    default_acl: Option<Vec<u8>>,
}

impl Snapshot {
    pub(super) fn envelope(&self) -> &WindowsCallerTokenEnvelopeV1 {
        &self.stable.envelope
    }

    pub(super) fn stable_eq(&self, other: &Self) -> bool {
        self.stable == other.stable && self.default_acl == other.default_acl
    }
}

pub(super) fn snapshot(token: HANDLE) -> io::Result<Snapshot> {
    let envelope =
        memcordon_windows_launch_core::query_token_envelope(token).map_err(io::Error::other)?;
    let captured = query(token, TokenStatistics)?;
    if captured.length < size_of::<TOKEN_STATISTICS>() {
        return Err(io::Error::other("fixture token statistics are truncated"));
    }
    // SAFETY: the complete statistics are covered by the checked query extent.
    let statistics = unsafe {
        captured
            .words
            .as_ptr()
            .cast::<TOKEN_STATISTICS>()
            .read_unaligned()
    };
    if statistics.TokenType != TokenPrimary
        || envelope.token_type != TokenPrimary as u32
        || envelope.authentication_id != luid(statistics.AuthenticationId)
    {
        return Err(io::Error::other(
            "fixture requires an actual matching primary token",
        ));
    }
    // Primary-token ImpersonationLevel is undefined and is intentionally not
    // observed; the canonical envelope already handles its applicable role.
    Ok(Snapshot {
        stable: StableToken {
            envelope,
            token_id: luid(statistics.TokenId),
            expiration: statistics.ExpirationTime,
            group_count: statistics.GroupCount,
            privilege_count: statistics.PrivilegeCount,
        },
        modified_id: luid(statistics.ModifiedId),
        default_acl: default_acl(token)?,
    })
}

pub(super) fn prepare(source: HANDLE, restricted: HANDLE) -> io::Result<()> {
    if source == restricted {
        return Err(io::Error::other(
            "fixture source and derived tokens must be distinct",
        ));
    }
    let source_before = snapshot(source)?;
    let before = snapshot(restricted)?;
    if source_before.stable.token_id == before.stable.token_id {
        return Err(io::Error::other(
            "fixture preparation cannot mutate the original token object",
        ));
    }
    require_restricted_code(restricted)?;
    let expected = policy::plan(before.default_acl.as_deref())?;
    let changed = before.default_acl.as_deref() != Some(expected.as_slice());
    if changed {
        // Native ACL storage must be aligned and live through synchronous copy.
        let mut storage = vec![0usize; expected.len().div_ceil(size_of::<usize>())];
        // SAFETY: checked planner bound fits the aligned backing allocation.
        unsafe {
            std::ptr::copy_nonoverlapping(
                expected.as_ptr(),
                storage.as_mut_ptr().cast::<u8>(),
                expected.len(),
            )
        };
        let selected = TOKEN_DEFAULT_DACL {
            DefaultDacl: storage.as_mut_ptr().cast(),
        };
        // SAFETY: only the newly derived fixture token is mutated, and both
        // native header and ACL storage remain live until this call returns.
        if unsafe {
            SetTokenInformation(
                restricted,
                TokenDefaultDacl,
                (&selected as *const TOKEN_DEFAULT_DACL).cast(),
                size_of::<TOKEN_DEFAULT_DACL>() as u32,
            )
        } == 0
        {
            return Err(native_failure(
                "SetTokenInformation-private-fixture",
                TokenDefaultDacl,
                io::Error::last_os_error(),
            ));
        }
    }
    let after = snapshot(restricted)?;
    let source_after = snapshot(source)?;
    if before.stable != after.stable
        || after.default_acl.as_deref() != Some(expected.as_slice())
        || (!changed && before.modified_id != after.modified_id)
    {
        return Err(io::Error::other(
            "fixture default-DACL readback or unchanged security differs",
        ));
    }
    if source_before != source_after {
        return Err(io::Error::other(
            "original fixture source token changed during private preparation",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/private/fixture_default_dacl_native.rs"]
mod native_tests;
