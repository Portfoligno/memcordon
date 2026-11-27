//! Native authority measurements for the fixture-only reduced compiler caller.
use super::descriptor::gate_precondition::{
    COMPILER_ADMINISTRATORS_SID, COMPILER_AUTHORITY_MEMBERS, CompilerAuthoritySnapshot,
    CompilerGroup, CompilerPrivilege, CompilerQualificationFailure, CompilerQualificationStage,
    validate_compiler_authority_reduction,
};
use CompilerQualificationStage::*;
use std::{
    io,
    mem::{offset_of, size_of, size_of_val},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr, slice,
};
use windows_sys::Win32::{
    Foundation::{HANDLE, LUID},
    Security::{
        CreateRestrictedToken, CreateWellKnownSid, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
        SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_GROUPS, TOKEN_PRIVILEGES, TOKEN_QUERY,
        TOKEN_STATISTICS, TokenGroups, TokenPrimary, TokenPrivileges, TokenSessionId,
        TokenStatistics, WinBuiltinAdministratorsSid,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

#[derive(Debug)]
struct QualificationError(CompilerQualificationFailure);

#[derive(Debug)]
struct TokenReadError {
    cause: io::Error,
    context: String,
}

impl std::fmt::Display for TokenReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.context)
    }
}

impl std::error::Error for TokenReadError {}

pub(super) fn token_read_error(cause: io::Error, context: String) -> io::Error {
    io::Error::new(cause.kind(), TokenReadError { cause, context })
}

impl std::fmt::Display for QualificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl std::error::Error for QualificationError {}

pub(super) fn qualification_failure(
    stage: CompilerQualificationStage,
    error: &io::Error,
) -> CompilerQualificationFailure {
    if let Some(typed) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<QualificationError>())
    {
        return typed.0.clone();
    }
    let token_read = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<TokenReadError>());
    CompilerQualificationFailure {
        stage,
        win32: error
            .raw_os_error()
            .or_else(|| token_read.and_then(|read| read.cause.raw_os_error())),
        premise: None,
    }
}

pub(super) fn qualification_stage(
    stage: CompilerQualificationStage,
    error: io::Error,
) -> io::Error {
    io::Error::other(QualificationError(qualification_failure(stage, &error)))
}

pub(super) fn qualification_premise(
    stage: CompilerQualificationStage,
    premise: &'static str,
) -> io::Error {
    io::Error::other(QualificationError(CompilerQualificationFailure {
        stage,
        win32: None,
        premise: Some(premise.into()),
    }))
}

fn invalid_inventory() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "compiler authority token inventory exceeds bound or differs",
    )
}

fn luid(value: LUID) -> [u32; 2] {
    [value.LowPart, value.HighPart as u32]
}

/// The information class and T are the matching Win32 layout at each call.
unsafe fn members<T>(buffer: &[usize], offset: usize) -> io::Result<&[T]> {
    let length = size_of_val(buffer);
    if length < size_of::<u32>() || length < offset {
        return Err(invalid_inventory());
    }
    let base = buffer.as_ptr().cast::<u8>();
    // SAFETY: Win32 initializes the group/privilege count at offset zero.
    let count = unsafe { base.cast::<u32>().read() } as usize;
    if count > COMPILER_AUTHORITY_MEMBERS || count > (length - offset) / size_of::<T>() {
        return Err(invalid_inventory());
    }
    // SAFETY: bounded count, matching C layout and native-aligned buffer.
    Ok(unsafe { slice::from_raw_parts(base.add(offset).cast::<T>(), count) })
}

fn observe(token: HANDLE) -> io::Result<CompilerAuthoritySnapshot> {
    let token_observation = serde_json::from_slice(&super::native::token_observation_from(token)?)
        .map_err(io::Error::other)?;
    let group_buffer = super::native::token_bytes(token, TokenGroups)?;
    let privilege_buffer = super::native::token_bytes(token, TokenPrivileges)?;
    let statistics = super::native::token_bytes(token, TokenStatistics)?;
    let session = super::native::token_bytes(token, TokenSessionId)?;
    if size_of_val(statistics.as_slice()) < size_of::<TOKEN_STATISTICS>()
        || size_of_val(session.as_slice()) < size_of::<u32>()
    {
        return Err(invalid_inventory());
    }
    // SAFETY: these bounded buffers were filled for their matching classes.
    let statistics = unsafe { &*statistics.as_ptr().cast::<TOKEN_STATISTICS>() };
    let session_id = unsafe { session.as_ptr().cast::<u32>().read() };
    // SAFETY: buffers use the matching Win32 variable-size layouts.
    let source_groups =
        unsafe { members::<SID_AND_ATTRIBUTES>(&group_buffer, offset_of!(TOKEN_GROUPS, Groups))? };
    let source_privileges = unsafe {
        members::<LUID_AND_ATTRIBUTES>(&privilege_buffer, offset_of!(TOKEN_PRIVILEGES, Privileges))?
    };
    // SAFETY: view only the owned native allocation, retaining it through each SID read.
    let group_bytes = unsafe {
        slice::from_raw_parts(
            group_buffer.as_ptr().cast::<u8>(),
            size_of_val(group_buffer.as_slice()),
        )
    };
    let groups: io::Result<Vec<_>> = source_groups
        .iter()
        .map(|group| {
            let offset = (group.Sid as usize)
                .checked_sub(group_bytes.as_ptr() as usize)
                .ok_or_else(invalid_inventory)?;
            let sid = group_bytes.get(offset..).ok_or_else(invalid_inventory)?;
            let Some([1, count, ..]) = sid.get(..8) else {
                return Err(invalid_inventory());
            };
            if *count > 15 {
                return Err(invalid_inventory());
            }
            let sid = sid
                .get(..8 + usize::from(*count) * size_of::<u32>())
                .ok_or_else(invalid_inventory)?;
            Ok(CompilerGroup {
                sid: sid.to_vec(),
                attributes: group.Attributes,
            })
        })
        .collect();
    let mut groups = groups?;
    groups.sort_by(|left, right| left.sid.cmp(&right.sid));
    let administrators_attributes = groups
        .iter()
        .find(|group| group.sid == COMPILER_ADMINISTRATORS_SID)
        .ok_or_else(|| io::Error::other("compiler authority token lacks Administrators group"))?
        .attributes;
    let mut privileges: Vec<_> = source_privileges
        .iter()
        .map(|entry| CompilerPrivilege {
            luid: luid(entry.Luid),
            attributes: entry.Attributes,
        })
        .collect();
    privileges.sort_by_key(|entry| entry.luid);
    let name: Vec<_> = "SeChangeNotifyPrivilege"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut traversal = LUID::default();
    // SAFETY: terminated privilege name and writable LUID on the local system.
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut traversal) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(CompilerAuthoritySnapshot {
        token: token_observation,
        authentication_id: luid(statistics.AuthenticationId),
        session_id,
        primary: statistics.TokenType == TokenPrimary,
        administrators_attributes,
        groups,
        privileges,
        traversal_luid: luid(traversal),
    })
}

pub(super) fn effective() -> io::Result<CompilerAuthoritySnapshot> {
    // GetCurrentThreadEffectiveToken pseudo-handle, borrowed for this query.
    observe(-6isize as HANDLE)
}

pub(super) fn process(process: &OwnedHandle) -> io::Result<CompilerAuthoritySnapshot> {
    let mut token = ptr::null_mut();
    // SAFETY: independently query the still-held suspended frontend.
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
    observe(token.as_raw_handle())
}

pub(super) fn select() -> io::Result<(OwnedHandle, OwnedHandle, CompilerAuthoritySnapshot)> {
    let mut primary = ptr::null_mut();
    // SAFETY: opens the original runner primary token into a new owner.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut primary) } == 0 {
        return Err(qualification_stage(SourceToken, io::Error::last_os_error()));
    }
    let primary = unsafe { OwnedHandle::from_raw_handle(primary.cast()) };
    let source =
        observe(primary.as_raw_handle()).map_err(|e| qualification_stage(SourceInventory, e))?;
    source
        .validate_source()
        .map_err(|reason| qualification_premise(SourceValidation, reason))?;
    if effective().map_err(|e| qualification_stage(SourceInventory, e))? != source {
        return Err(qualification_premise(
            SourceValidation,
            "reduced compiler source differs from its effective caller",
        ));
    }
    let mut sid = [0u32; 17];
    let mut sid_bytes = size_of_val(&sid) as u32;
    // SAFETY: correctly sized aligned storage for an OS-defined SID.
    if unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut sid_bytes,
        )
    } == 0
    {
        return Err(qualification_stage(
            AdministratorsSid,
            io::Error::last_os_error(),
        ));
    }
    let disabled = SID_AND_ATTRIBUTES {
        Sid: sid.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let deleted: Vec<_> = source
        .privileges
        .iter()
        .filter(|entry| entry.luid != source.traversal_luid)
        .map(|entry| LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: entry.luid[0],
                HighPart: entry.luid[1] as i32,
            },
            Attributes: 0,
        })
        .collect();
    let mut reduced = ptr::null_mut();
    // SAFETY: exact measured source plus live bounded deletion inputs. The zero
    // flags and empty restricting-SID list preserve the ordinary policy checks.
    if unsafe {
        CreateRestrictedToken(
            primary.as_raw_handle(),
            0,
            1,
            &disabled,
            deleted.len() as u32,
            deleted.as_ptr(),
            0,
            ptr::null(),
            &mut reduced,
        )
    } == 0
    {
        return Err(qualification_stage(
            CompilerQualificationStage::CreateRestrictedToken,
            io::Error::last_os_error(),
        ));
    }
    let reduced = unsafe { OwnedHandle::from_raw_handle(reduced.cast()) };
    // The elevated default DACL can rely on Administrators for access to
    // objects created without an explicit descriptor. That SID is now
    // deny-only. On the private derived token, grant the measured user access
    // to newly created objects without changing the owner or existing ACEs.
    super::native_fixture_default_dacl::prepare_reduced(
        primary.as_raw_handle(),
        reduced.as_raw_handle(),
        &source.token.user_sid,
    )
    .map_err(|e| qualification_stage(ReducedDefaultDacl, e))?;
    let selected =
        observe(reduced.as_raw_handle()).map_err(|e| qualification_stage(ReducedInventory, e))?;
    validate_compiler_authority_reduction(&source, &selected)
        .map_err(|reason| qualification_premise(AuthorityReduction, reason))?;
    Ok((primary, reduced, selected))
}
