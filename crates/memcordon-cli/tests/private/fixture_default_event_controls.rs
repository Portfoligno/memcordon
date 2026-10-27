//! Failure-only controls; none of these outcomes qualifies the original case.
use super::*;

#[derive(Debug, Clone, Copy)]
enum Stage {
    NotAttempted,
    Input,
    Descriptor,
    Create,
    Freshness,
    QuerySize,
    QueryDescriptor,
    ExtractAcl,
    CompareAcl,
    InitialState,
    Signal,
    SignaledState,
    Complete,
}

#[derive(Debug, Clone, Copy)]
enum StructuralRefusal {
    AbsentDacl,
    NullDacl,
    HeaderOutsideReturnedExtent,
    AclSizeOutsideBound,
    AclOutsideReturnedExtent,
}

pub(super) struct Outcome {
    stage: Stage,
    expired: bool,
    raw_error: Option<u32>,
    structural_refusal: Option<StructuralRefusal>,
    dacl_present: Option<bool>,
    dacl_defaulted: Option<bool>,
    dacl_null: Option<bool>,
    descriptor_bytes: Option<u32>,
    acl_bytes: Option<u16>,
    header_in_extent: Option<bool>,
    acl_in_extent: Option<bool>,
    created: bool,
    acl_matches: Option<bool>,
    sole_rc_grant: Option<bool>,
    self_use: bool,
    complete: bool,
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outcome")
            .field("stage", &self.stage)
            .field("expired", &self.expired)
            .field("raw_error", &self.raw_error)
            .field("structural_refusal", &self.structural_refusal)
            .field("dacl_present", &self.dacl_present)
            .field("dacl_defaulted", &self.dacl_defaulted)
            .field("dacl_null", &self.dacl_null)
            .field("descriptor_bytes", &self.descriptor_bytes)
            .field("acl_bytes", &self.acl_bytes)
            .field("header_in_extent", &self.header_in_extent)
            .field("acl_in_extent", &self.acl_in_extent)
            .field("created", &self.created)
            .field("acl_matches", &self.acl_matches)
            .field("sole_rc_grant", &self.sole_rc_grant)
            .field("self_use", &self.self_use)
            .field("complete", &self.complete)
            .finish()
    }
}

impl Outcome {
    fn new() -> Self {
        Self {
            stage: Stage::NotAttempted,
            expired: false,
            raw_error: None,
            structural_refusal: None,
            dacl_present: None,
            dacl_defaulted: None,
            dacl_null: None,
            descriptor_bytes: None,
            acl_bytes: None,
            header_in_extent: None,
            acl_in_extent: None,
            created: false,
            acl_matches: None,
            sole_rc_grant: None,
            self_use: false,
            complete: false,
        }
    }

    fn check(&mut self, stage: Stage, deadline: Instant) -> bool {
        self.stage = stage;
        if Instant::now() >= deadline {
            self.expired = true;
            return false;
        }
        true
    }

    fn native(&mut self, success: bool, code: u32, deadline: Instant) -> bool {
        if !success {
            self.raw_error = Some(code);
        }
        let live = self.check(self.stage, deadline);
        success && live
    }
}

pub(super) struct Controls {
    unnamed_default: Outcome,
    named_explicit: Outcome,
}

impl std::fmt::Debug for Controls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Controls")
            .field("unnamed_default", &self.unnamed_default)
            .field("named_explicit", &self.named_explicit)
            .finish()
    }
}

fn mapping() -> GENERIC_MAPPING {
    GENERIC_MAPPING {
        GenericRead: SYNCHRONIZATION_READ_CONTROL | SYNCHRONIZATION_SYNCHRONIZE,
        GenericWrite: SYNCHRONIZATION_READ_CONTROL | EVENT_MODIFY_STATE,
        GenericExecute: SYNCHRONIZATION_READ_CONTROL | SYNCHRONIZATION_SYNCHRONIZE,
        GenericAll: EVENT_ALL_ACCESS,
    }
}

// Closed revision-2 basic-ACE grammar, matching the prepared fixture policy.
// Compare every ACE byte after the event object's generic mapping, not only RC.
fn mapped_acl(raw: &[u8], event_readback: bool, deadline: Instant) -> Option<(Vec<u8>, usize)> {
    if Instant::now() >= deadline {
        return None;
    }
    if !(size_of::<ACL>()..=MAX_ACL_BYTES).contains(&raw.len())
        || raw[0] != 2
        || raw[1] != 0
        || raw[6..8] != [0, 0]
        || usize::from(u16::from_le_bytes([raw[2], raw[3]])) != raw.len()
    {
        return None;
    }
    let count = usize::from(u16::from_le_bytes([raw[4], raw[5]]));
    if count > policy::MAX_ACES {
        return None;
    }
    let mut mapped = raw.to_vec();
    let mut offset = size_of::<ACL>();
    let mut grants = 0;
    for _ in 0..count {
        let header = raw.get(offset..offset.checked_add(4)?)?;
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if length < 16 || length % size_of::<u32>() != 0 {
            return None;
        }
        let end = offset.checked_add(length)?;
        let ace = raw.get(offset..end)?;
        if !matches!(ace[0], 0 | 1) || ace[1] & 0x10 != 0 {
            return None;
        }
        let sid = ace.get(8..)?;
        if sid.len() < 8
            || sid[0] != 1
            || sid[1] > 15
            || sid.len() != 8 + usize::from(sid[1]) * size_of::<u32>()
        {
            return None;
        }
        let mut mask = u32::from_le_bytes(ace.get(4..8)?.try_into().ok()?);
        if Instant::now() >= deadline {
            return None;
        }
        // SAFETY: map a local integer using this object's fixed mapping.
        unsafe { MapGenericMask(&mut mask, &mapping()) };
        if Instant::now() >= deadline {
            return None;
        }
        mapped
            .get_mut(offset + 4..offset + 8)?
            .copy_from_slice(&mask.to_le_bytes());
        if sid == RESTRICTED_CODE_SID {
            if ace[0] != 0 || ace[1] != 0 || mask != EVENT_ALL_ACCESS {
                return None;
            }
            grants += 1;
        }
        offset = end;
    }
    if Instant::now() >= deadline || (!event_readback && offset != raw.len()) {
        return None;
    }
    // A native ACL's admitted AclSize can include unused allocation capacity.
    // All declared ACEs were parsed above; only that non-semantic tail is
    // excluded. Prepared token ACLs retain their packed representation rule.
    mapped.truncate(offset);
    mapped[2..4].copy_from_slice(&u16::try_from(offset).ok()?.to_le_bytes());
    Some((mapped, grants))
}

pub(super) fn event_acl_matches(actual: &[u8], expected: &[u8], deadline: Instant) -> bool {
    match (
        mapped_acl(actual, true, deadline),
        mapped_acl(expected, false, deadline),
    ) {
        (Some((actual, 1)), Some((expected, 1))) => actual == expected && Instant::now() < deadline,
        _ => false,
    }
}

fn read_acl(event: HANDLE, out: &mut Outcome, deadline: Instant) -> Option<Vec<u8>> {
    if !out.check(Stage::QuerySize, deadline) {
        return None;
    }
    let mut needed = 0;
    // SAFETY: sizing query only, using our owned event.
    let result = unsafe {
        GetKernelObjectSecurity(
            event,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    // SAFETY: capture this API's result immediately.
    let code = unsafe { GetLastError() };
    if !out.native(
        result == 0 && code == ERROR_INSUFFICIENT_BUFFER,
        code,
        deadline,
    ) || needed == 0
        || needed as usize > TOKEN_QUERY_BOUND
    {
        return None;
    }
    let mut words = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    let mut actual = needed;
    if !out.check(Stage::QueryDescriptor, deadline) {
        return None;
    }
    // SAFETY: aligned bounded output allocation covers the advertised size.
    let result = unsafe {
        GetKernelObjectSecurity(
            event,
            DACL_SECURITY_INFORMATION,
            words.as_mut_ptr().cast(),
            needed,
            &mut actual,
        )
    };
    // SAFETY: immediate error capture before any other native call.
    let code = unsafe { GetLastError() };
    if !out.native(result != 0, code, deadline) || actual == 0 || actual > needed {
        return None;
    }
    let query = Query {
        words,
        length: actual as usize,
    };
    out.descriptor_bytes = Some(actual);
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = std::ptr::null_mut();
    if !out.check(Stage::ExtractAcl, deadline) {
        return None;
    }
    // SAFETY: complete bounded descriptor remains owned by query.
    let result = unsafe {
        GetSecurityDescriptorDacl(
            query.words.as_ptr().cast_mut().cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    };
    // SAFETY: immediate error capture.
    let code = unsafe { GetLastError() };
    if !out.native(result != 0, code, deadline) {
        return None;
    }
    out.dacl_present = Some(present != 0);
    if present == 0 {
        // The other native outputs are invalid when no DACL is present.
        out.structural_refusal = Some(StructuralRefusal::AbsentDacl);
        return None;
    }
    out.dacl_defaulted = Some(defaulted != 0);
    out.dacl_null = Some(acl.is_null());
    if acl.is_null() {
        out.structural_refusal = Some(StructuralRefusal::NullDacl);
        return None;
    }
    let header_in_extent = pointer_range(&query, acl.cast(), size_of::<ACL>()).is_ok();
    out.header_in_extent = Some(header_in_extent);
    if !header_in_extent {
        out.structural_refusal = Some(StructuralRefusal::HeaderOutsideReturnedExtent);
        return None;
    }
    // SAFETY: the complete fixed header was checked inside query.
    let length = usize::from(unsafe { acl.read_unaligned() }.AclSize);
    out.acl_bytes = Some(length as u16);
    if !(size_of::<ACL>()..=MAX_ACL_BYTES).contains(&length) {
        out.structural_refusal = Some(StructuralRefusal::AclSizeOutsideBound);
        return None;
    }
    let acl_in_extent = pointer_range(&query, acl.cast(), length).is_ok();
    out.acl_in_extent = Some(acl_in_extent);
    if !acl_in_extent {
        out.structural_refusal = Some(StructuralRefusal::AclOutsideReturnedExtent);
        return None;
    }
    // SAFETY: the entire bounded ACL lies inside the retained descriptor.
    let bytes = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), length) }.to_vec();
    out.check(Stage::ExtractAcl, deadline).then_some(bytes)
}

fn control(
    name: *const u16,
    security: *const SECURITY_ATTRIBUTES,
    expected: &[u8],
    deadline: Instant,
) -> Outcome {
    let mut out = Outcome::new();
    if !out.check(Stage::Create, deadline) {
        return out;
    }
    // SAFETY: reset this thread's status immediately before the constructor.
    unsafe { SetLastError(0) };
    // SAFETY: pointers refer to caller-held validated name/descriptor storage.
    let handle = unsafe {
        CreateEventExW(
            security,
            name,
            CREATE_EVENT_MANUAL_RESET,
            EVENT_USE | SYNCHRONIZATION_READ_CONTROL,
        )
    };
    // SAFETY: capture before adoption or any other native call.
    let code = unsafe { GetLastError() };
    let event = match owned_event(handle, code) {
        Ok(event) => event,
        Err(code) => {
            out.native(false, code, deadline);
            return out;
        }
    };
    out.created = true;
    if !out.check(Stage::Freshness, deadline) {
        return out;
    }
    if code == ERROR_ALREADY_EXISTS {
        out.raw_error = Some(code);
        return out;
    }
    let Some(raw) = read_acl(event.as_raw_handle(), &mut out, deadline) else {
        return out;
    };
    if !out.check(Stage::CompareAcl, deadline) {
        return out;
    }
    let Some((actual, count)) = mapped_acl(&raw, true, deadline) else {
        out.check(Stage::CompareAcl, deadline);
        return out;
    };
    let Some((expected, _)) = mapped_acl(expected, false, deadline) else {
        out.check(Stage::CompareAcl, deadline);
        return out;
    };
    out.acl_matches = Some(actual == expected);
    out.sole_rc_grant = Some(count == 1);
    if !out.check(Stage::InitialState, deadline) {
        return out;
    }
    // SAFETY: zero-time observation of our retained handle; no waiting budget.
    let state = unsafe { WaitForSingleObject(event.as_raw_handle(), 0) };
    // SAFETY: immediate native error capture.
    let code = unsafe { GetLastError() };
    if state != WAIT_TIMEOUT {
        if state == windows_sys::Win32::Foundation::WAIT_FAILED {
            out.raw_error = Some(code);
        }
        out.check(Stage::InitialState, deadline);
        return out;
    }
    if !out.check(Stage::InitialState, deadline) {
        return out;
    }
    if !out.check(Stage::Signal, deadline) {
        return out;
    }
    // SAFETY: signal only this control's owned event.
    let result = unsafe { SetEvent(event.as_raw_handle()) };
    // SAFETY: immediate native error capture.
    let code = unsafe { GetLastError() };
    if !out.native(result != 0, code, deadline) {
        return out;
    }
    if !out.check(Stage::SignaledState, deadline) {
        return out;
    }
    // SAFETY: zero-time observation of the same control event.
    let state = unsafe { WaitForSingleObject(event.as_raw_handle(), 0) };
    // SAFETY: immediate native error capture.
    let code = unsafe { GetLastError() };
    if state != WAIT_OBJECT_0 {
        if state == windows_sys::Win32::Foundation::WAIT_FAILED {
            out.raw_error = Some(code);
        }
        out.check(Stage::SignaledState, deadline);
        return out;
    }
    if !out.check(Stage::SignaledState, deadline) {
        return out;
    }
    out.self_use = true;
    out.complete = out.check(Stage::Complete, deadline);
    // All return paths drop the successful owned event before returning facts.
    out
}

pub(super) fn observe(explicit_name: &[u16], prepared_acl: &[u8], deadline: Instant) -> Controls {
    let unnamed_default = control(std::ptr::null(), std::ptr::null(), prepared_acl, deadline);
    let mut named_explicit = Outcome::new();
    if !named_explicit.check(Stage::Input, deadline) {
        return Controls {
            unnamed_default,
            named_explicit,
        };
    }
    // The parent supplies a closed child in the retained private namespace.
    let body = explicit_name.strip_suffix(&[0]);
    let qualified = body
        .and_then(|body| {
            let separator = body.iter().position(|unit| *unit == u16::from(b'\\'))?;
            let (alias, rest) = body.split_at(separator);
            let child = rest.strip_prefix(&[u16::from(b'\\')])?;
            Some(
                !alias.is_empty()
                    && !body.contains(&0)
                    && !alias.iter().any(|unit| matches!(*unit, 47 | 58))
                    && !"Local".encode_utf16().eq(alias.iter().copied())
                    && !"Global".encode_utf16().eq(alias.iter().copied())
                    && "explicit-control".encode_utf16().eq(child.iter().copied()),
            )
        })
        .unwrap_or(false);
    if explicit_name.len() > windows_sys::Win32::Foundation::MAX_PATH as usize
        || !qualified
        || mapped_acl(prepared_acl, false, deadline).is_none()
    {
        named_explicit.check(Stage::Input, deadline);
        return Controls {
            unnamed_default,
            named_explicit,
        };
    }
    let mut storage = vec![0usize; prepared_acl.len().div_ceil(size_of::<usize>())];
    // SAFETY: aligned allocation covers the validated complete ACL bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            prepared_acl.as_ptr(),
            storage.as_mut_ptr().cast(),
            prepared_acl.len(),
        )
    };
    // SAFETY: zero initialization is valid before InitializeSecurityDescriptor.
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    if !named_explicit.check(Stage::Descriptor, deadline) {
        return Controls {
            unnamed_default,
            named_explicit,
        };
    }
    // SAFETY: fixed writable descriptor and documented revision.
    let result = unsafe {
        InitializeSecurityDescriptor((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(), 1)
    };
    // SAFETY: immediate native error capture.
    let code = unsafe { GetLastError() };
    if !named_explicit.native(result != 0, code, deadline) {
        return Controls {
            unnamed_default,
            named_explicit,
        };
    }
    if !named_explicit.check(Stage::Descriptor, deadline) {
        return Controls {
            unnamed_default,
            named_explicit,
        };
    }
    // SAFETY: descriptor and aligned complete ACL remain live through creation.
    let result = unsafe {
        SetSecurityDescriptorDacl(
            (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            1,
            storage.as_mut_ptr().cast(),
            0,
        )
    };
    // SAFETY: immediate native error capture.
    let code = unsafe { GetLastError() };
    if !named_explicit.native(result != 0, code, deadline) {
        return Controls {
            unnamed_default,
            named_explicit,
        };
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        bInheritHandle: 0,
    };
    named_explicit = control(explicit_name.as_ptr(), &attributes, prepared_acl, deadline);
    Controls {
        unnamed_default,
        named_explicit,
    }
}
