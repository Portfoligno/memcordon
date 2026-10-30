//! Supplied-data Authz calculation only; never the actual named-open verdict.
use super::*;
use memcordon_windows_launch_core::{PrivilegeAttributesV1, SidAttributesV1};
use security_evidence::{AuthzObservation, Snapshot};
use std::ptr;

struct Manager(AUTHZ_RESOURCE_MANAGER_HANDLE);
impl Drop for Manager {
    fn drop(&mut self) {
        unsafe {
            AuthzFreeResourceManager(self.0);
        }
    }
}
struct Context(AUTHZ_CLIENT_CONTEXT_HANDLE);
impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            AuthzFreeContext(self.0);
        }
    }
}

struct Buffer {
    words: Vec<usize>,
    length: usize,
}
impl Buffer {
    fn contains(&self, pointer: *const u8, length: usize) -> bool {
        let start = self.words.as_ptr() as usize;
        (pointer as usize)
            .checked_sub(start)
            .and_then(|at| at.checked_add(length))
            .is_some_and(|end| end <= self.length)
    }
    fn read<T: Copy>(&self, pointer: *const T) -> io::Result<T> {
        if !self.contains(pointer.cast(), size_of::<T>()) {
            return Err(io::Error::other("context extent"));
        }
        Ok(unsafe { ptr::read_unaligned(pointer) })
    }
    fn sid(&self, pointer: PSID) -> io::Result<String> {
        let head = self.read::<[u8; 8]>(pointer.cast())?;
        let length = size_of::<[u8; 8]>() + usize::from(head[1]) * size_of::<u32>();
        if head[0] != 1 || head[1] > 15 || !self.contains(pointer.cast(), length) {
            return Err(io::Error::other("context SID extent"));
        }
        let mut authority = [0; 8];
        authority[2..].copy_from_slice(&head[2..]);
        let authority = u64::from_be_bytes(authority);
        let mut value = if authority > u64::from(u32::MAX) {
            format!("S-1-0x{authority:012x}")
        } else {
            format!("S-1-{authority}")
        };
        for at in 0..usize::from(head[1]) {
            let unit = self.read::<u32>(unsafe {
                pointer
                    .cast::<u8>()
                    .add(size_of::<[u8; 8]>() + at * size_of::<u32>())
                    .cast()
            })?;
            value.push('-');
            value.push_str(&unit.to_string());
        }
        Ok(value)
    }
}
fn query(
    context: &Context,
    class: AUTHZ_CONTEXT_INFORMATION_CLASS,
    deadline: Instant,
) -> io::Result<Buffer> {
    live(deadline)?;
    let mut needed = 0;
    let sized = unsafe {
        AuthzGetInformationFromContext(context.0, class, 0, &mut needed, ptr::null_mut())
    };
    let error = io::Error::last_os_error();
    if sized != 0
        || error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || needed == 0
        || needed > 8192
    {
        return Err(io::Error::other("bounded context sizing"));
    }
    live(deadline)?;
    let mut buffer = Buffer {
        words: vec![0; (needed as usize).div_ceil(size_of::<usize>())],
        length: needed as usize,
    };
    let capacity = needed;
    if unsafe {
        AuthzGetInformationFromContext(
            context.0,
            class,
            capacity,
            &mut needed,
            buffer.words.as_mut_ptr().cast(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if needed > capacity {
        return Err(io::Error::other("context grew beyond buffer"));
    }
    buffer.length = needed as usize;
    live(deadline)?;
    Ok(buffer)
}
fn groups(
    context: &Context,
    class: AUTHZ_CONTEXT_INFORMATION_CLASS,
    deadline: Instant,
) -> io::Result<Vec<SidAttributesV1>> {
    let buffer = query(context, class, deadline)?;
    let base = buffer.words.as_ptr().cast::<TOKEN_GROUPS>();
    let count = buffer.read::<u32>(base.cast())? as usize;
    if count > 256 {
        return Err(io::Error::other("context group bound"));
    }
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    let mut values = Vec::new();
    for index in 0..count {
        let entry = buffer.read::<SID_AND_ATTRIBUTES>({
            base.cast::<u8>()
                .wrapping_add(offset + index * size_of::<SID_AND_ATTRIBUTES>())
                .cast()
        })?;
        values.push(SidAttributesV1 {
            sid: buffer.sid(entry.Sid)?,
            attributes: entry.Attributes,
        });
    }
    values.sort();
    Ok(values)
}
fn privileges(context: &Context, deadline: Instant) -> io::Result<Vec<PrivilegeAttributesV1>> {
    let buffer = query(context, AuthzContextInfoPrivileges, deadline)?;
    let base = buffer.words.as_ptr().cast::<TOKEN_PRIVILEGES>();
    let count = buffer.read::<u32>(base.cast())? as usize;
    if count > 256 {
        return Err(io::Error::other("context privilege bound"));
    }
    let mut values = Vec::new();
    for index in 0..count {
        let entry = buffer.read::<LUID_AND_ATTRIBUTES>({
            base.cast::<u8>()
                .wrapping_add(
                    std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges)
                        + index * size_of::<LUID_AND_ATTRIBUTES>(),
                )
                .cast()
        })?;
        values.push(PrivilegeAttributesV1 {
            luid_high: entry.Luid.HighPart,
            luid_low: entry.Luid.LowPart,
            attributes: entry.Attributes,
        });
    }
    values.sort();
    Ok(values)
}

fn descriptor(snapshot: &Snapshot) -> io::Result<Vec<usize>> {
    let bytes = snapshot.bytes();
    let mut words = vec![0usize; bytes.len().div_ceil(size_of::<usize>())];
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), words.as_mut_ptr().cast(), bytes.len());
    }
    let buffer = Buffer {
        words,
        length: bytes.len(),
    };
    let sd: PSECURITY_DESCRIPTOR = buffer.words.as_ptr().cast_mut().cast();
    if bytes.len() < size_of::<SECURITY_DESCRIPTOR_RELATIVE>() {
        return Err(io::Error::other("invalid descriptor"));
    }
    let relative = buffer.read::<SECURITY_DESCRIPTOR_RELATIVE>(sd.cast())?;
    if relative.Control & SE_SELF_RELATIVE == 0
        || relative.Control & SE_DACL_PRESENT == 0
        || relative.Sacl != 0
        || relative.Dacl == 0
    {
        return Err(io::Error::other("unsupported descriptor"));
    }
    for offset in [relative.Owner, relative.Group] {
        if offset == 0 || offset as usize >= bytes.len() {
            return Err(io::Error::other("missing descriptor identity"));
        }
        buffer.sid(unsafe {
            buffer
                .words
                .as_ptr()
                .cast::<u8>()
                .add(offset as usize)
                .cast_mut()
                .cast()
        })?;
    }
    let acl = relative.Dacl as usize;
    if acl >= bytes.len() {
        return Err(io::Error::other("ACL offset"));
    }
    let header =
        buffer.read::<ACL>(unsafe { buffer.words.as_ptr().cast::<u8>().add(acl).cast() })?;
    if header.AclRevision != 2
        || header.AceCount > 256
        || usize::from(header.AclSize) < size_of::<ACL>()
        || acl
            .checked_add(header.AclSize as usize)
            .is_none_or(|end| end > bytes.len())
    {
        return Err(io::Error::other("unsupported ACL"));
    }
    let end = acl + header.AclSize as usize;
    let mut at = acl + size_of::<ACL>();
    for _ in 0..header.AceCount {
        let ace = bytes
            .get(at..at + size_of::<ACE_HEADER>())
            .ok_or_else(|| io::Error::other("ACE extent"))?;
        let length = u16::from_le_bytes([ace[2], ace[3]]) as usize;
        if !matches!(ace[0], 0 | 1)
            || ace[1] != 0
            || length < 16
            || at.checked_add(length).is_none_or(|n| n > end)
        {
            return Err(io::Error::other("unsupported ACE"));
        }
        let mask = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
        if mask & 0xf000_0000 != 0 {
            return Err(io::Error::other("generic ACE mask"));
        }
        let sid = bytes
            .get(at + 8..at + length)
            .ok_or_else(|| io::Error::other("ACE SID extent"))?;
        if sid.len() < 8
            || sid[0] != 1
            || sid[1] > 15
            || sid.len() != 8 + sid[1] as usize * size_of::<u32>()
        {
            return Err(io::Error::other("ACE SID grammar"));
        }
        at += length;
    }
    if unsafe { IsValidSecurityDescriptor(sd) } == 0 {
        return Err(io::Error::other("invalid descriptor"));
    }
    Ok(buffer.words)
}

pub(super) fn observe(
    token: &OwnedHandle,
    request: &Request,
    snapshot: &Snapshot,
    deadline: Instant,
) -> AuthzObservation {
    let mut stage = "descriptor";
    let result = (|| -> io::Result<AuthzObservation> {
        live(deadline)?;
        let descriptor = descriptor(snapshot)?;
        stage = "source-before";
        let (envelope, before) =
            memcordon_windows_launch_core::query_token_envelope_with_observation(
                token.as_raw_handle(),
            )
            .map_err(io::Error::other)?;
        let before = before.map_err(io::Error::other)?;
        if envelope != request.expected_token {
            return Err(io::Error::other("source binding changed"));
        }
        live(deadline)?;
        stage = "resource-manager";
        let mut manager = ptr::null_mut();
        if unsafe {
            AuthzInitializeResourceManager(
                AUTHZ_RM_FLAG_NO_AUDIT,
                None,
                None,
                None,
                ptr::null(),
                &mut manager,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let manager = Manager(manager);
        live(deadline)?;
        stage = "context";
        let mut context = ptr::null_mut();
        if unsafe {
            AuthzInitializeContextFromToken(
                0,
                token.as_raw_handle(),
                manager.0,
                ptr::null(),
                LUID::default(),
                ptr::null(),
                &mut context,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let context = Context(context);
        live(deadline)?;
        stage = "context-identities";
        let user = query(&context, AuthzContextInfoUserSid, deadline)?;
        let user_entry = user.read::<TOKEN_USER>(user.words.as_ptr().cast())?.User;
        let normal = groups(&context, AuthzContextInfoGroupsSids, deadline)?;
        let restricted = groups(&context, AuthzContextInfoRestrictedSids, deadline)?;
        let privileges = privileges(&context, deadline)?;
        let user_matches = user.sid(user_entry.Sid)? == before.envelope.user_sid
            && user_entry.Attributes == before.user_attributes;
        let groups_match = normal == before.normal_groups;
        let restricted_match = restricted == before.restricted_sids;
        let privileges_match = privileges == before.privileges;
        let context_matches = user_matches && groups_match && restricted_match && privileges_match;
        stage = "source-after";
        live(deadline)?;
        let (_, after) = memcordon_windows_launch_core::query_token_envelope_with_observation(
            token.as_raw_handle(),
        )
        .map_err(io::Error::other)?;
        let source_unchanged = after.map_err(io::Error::other)? == before;
        stage = "access-check";
        live(deadline)?;
        let query = AUTHZ_ACCESS_REQUEST {
            DesiredAccess: SYNCHRONIZATION_SYNCHRONIZE,
            ..Default::default()
        };
        let (mut granted, mut sacl, mut error) = (0, 0, 0);
        let mut reply = AUTHZ_ACCESS_REPLY {
            ResultListLength: 1,
            GrantedAccessMask: &mut granted,
            SaclEvaluationResults: &mut sacl,
            Error: &mut error,
        };
        let api = unsafe {
            AuthzAccessCheck(
                0,
                context.0,
                &query,
                ptr::null_mut(),
                descriptor.as_ptr().cast_mut().cast(),
                ptr::null(),
                0,
                &mut reply,
                ptr::null_mut(),
            )
        } != 0;
        let native = (!api)
            .then(|| io::Error::last_os_error().raw_os_error())
            .flatten();
        live(deadline)?;
        Ok(AuthzObservation::Evaluated {
            engine: "AuthzAccessCheck",
            scope: "controller-descriptor-and-token-derived-context",
            diagnostic_only: true,
            acceptance_authority: false,
            sampling: "sequential-non-atomic",
            descriptor_sha256: snapshot.sha256().to_owned(),
            desired_access: SYNCHRONIZATION_SYNCHRONIZE,
            source_token_id: before.statistics.token_id,
            source_modified_id: before.statistics.modified_id,
            context_matches,
            user_matches,
            groups_match,
            restricted_match,
            privileges_match,
            source_unchanged,
            api_success: api,
            native_error: native,
            reply_error: api.then_some(error),
            granted: api.then_some(granted),
            conclusion: AuthzObservation::conclusion(
                context_matches && source_unchanged,
                api,
                error,
                granted,
            ),
        })
    })();
    result.unwrap_or_else(|error| AuthzObservation::unavailable(stage, &error))
}

/// Directory-specific supplied-data calculation; the event validator and mask
/// above retain their original contract. No token/context is modified.
#[cfg(target_arch = "x86_64")]
pub(super) fn observe_directory(
    token: &OwnedHandle,
    bytes: &[u8],
    source: &memcordon_windows_launch_core::TokenObservationV1,
    deadline: Instant,
) -> serde_json::Value {
    let result = (|| -> io::Result<serde_json::Value> {
        live(deadline)?;
        if bytes.len() > 4096 || bytes.len() < size_of::<SECURITY_DESCRIPTOR_RELATIVE>() {
            return Err(io::Error::other("directory descriptor bound"));
        }
        let mut descriptor = vec![0usize; bytes.len().div_ceil(size_of::<usize>())];
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), descriptor.as_mut_ptr().cast(), bytes.len());
        }
        let sd = descriptor.as_mut_ptr().cast();
        if unsafe { IsValidSecurityDescriptor(sd) } == 0
            || unsafe { GetSecurityDescriptorLength(sd) } as usize != bytes.len()
        {
            return Err(io::Error::other("directory descriptor extent"));
        }
        let (_, before) = memcordon_windows_launch_core::query_token_envelope_with_observation(
            token.as_raw_handle(),
        )
        .map_err(io::Error::other)?;
        if before.map_err(io::Error::other)? != *source {
            return Err(io::Error::other("directory source changed before Authz"));
        }
        live(deadline)?;
        let mut manager = ptr::null_mut();
        if unsafe {
            AuthzInitializeResourceManager(
                AUTHZ_RM_FLAG_NO_AUDIT,
                None,
                None,
                None,
                ptr::null(),
                &mut manager,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let manager = Manager(manager);
        let mut context = ptr::null_mut();
        live(deadline)?;
        if unsafe {
            AuthzInitializeContextFromToken(
                0,
                token.as_raw_handle(),
                manager.0,
                ptr::null(),
                LUID::default(),
                ptr::null(),
                &mut context,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let context = Context(context);
        let user = query(&context, AuthzContextInfoUserSid, deadline)?;
        let entry = user.read::<TOKEN_USER>(user.words.as_ptr().cast())?.User;
        let user_matches = user.sid(entry.Sid)? == source.envelope.user_sid
            && entry.Attributes == source.user_attributes;
        let groups_match =
            groups(&context, AuthzContextInfoGroupsSids, deadline)? == source.normal_groups;
        let restricted_match =
            groups(&context, AuthzContextInfoRestrictedSids, deadline)? == source.restricted_sids;
        let privileges_match = privileges(&context, deadline)? == source.privileges;
        if !(user_matches && groups_match && restricted_match && privileges_match) {
            return Err(io::Error::other(
                "directory Authz context differs from actual token",
            ));
        }
        let mut checks = Vec::new();
        for desired in [0xf, 1, 2, 4, 8] {
            live(deadline)?;
            let request = AUTHZ_ACCESS_REQUEST {
                DesiredAccess: desired,
                ..Default::default()
            };
            let (mut granted, mut sacl, mut error) = (0, 0, 0);
            let mut reply = AUTHZ_ACCESS_REPLY {
                ResultListLength: 1,
                GrantedAccessMask: &mut granted,
                SaclEvaluationResults: &mut sacl,
                Error: &mut error,
            };
            let api = unsafe {
                AuthzAccessCheck(
                    0,
                    context.0,
                    &request,
                    ptr::null_mut(),
                    sd,
                    ptr::null(),
                    0,
                    &mut reply,
                    ptr::null_mut(),
                )
            } != 0;
            let native = (!api)
                .then(|| io::Error::last_os_error().raw_os_error())
                .flatten();
            checks.push(serde_json::json!({"desired":desired,"api_success":api,"native_error":native,"reply_error":api.then_some(error),"granted":api.then_some(granted)}));
        }
        live(deadline)?;
        let (_, after) = memcordon_windows_launch_core::query_token_envelope_with_observation(
            token.as_raw_handle(),
        )
        .map_err(io::Error::other)?;
        let stable = after.map_err(io::Error::other)? == *source;
        if !stable {
            return Err(io::Error::other("directory source changed after Authz"));
        }
        Ok(
            serde_json::json!({"engine":"AuthzAccessCheck","scope":"directory-descriptor/exact-token; MIC and other kernel policy separate","diagnostic_only":true,"acceptance_authority":false,"context_matches":true,"source_unchanged":true,"checks":checks}),
        )
    })();
    result.unwrap_or_else(|error|serde_json::json!({"unavailable":error.to_string(),"native_error":error.raw_os_error(),"diagnostic_only":true,"acceptance_authority":false}))
}
