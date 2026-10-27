//! Dedicated owners for a test-created namespace and its user-only boundary.
use super::*;
use windows_sys::Win32::Security::{SE_DACL_PROTECTED, SetSecurityDescriptorControl};
use windows_sys::Win32::System::Threading::{
    AddSIDToBoundaryDescriptor, ClosePrivateNamespace, CreateBoundaryDescriptorW,
    CreatePrivateNamespaceW, DeleteBoundaryDescriptor, PRIVATE_NAMESPACE_FLAG_DESTROY,
};

#[path = "fixture_namespace_acl.rs"]
mod namespace_acl;

const NAME_BOUND: usize = windows_sys::Win32::Foundation::MAX_PATH as usize;

#[derive(Debug, Clone, Copy)]
pub(super) enum Operation {
    Deadline,
    Name,
    SourceUser,
    Acl,
    Descriptor,
    Boundary,
    BoundaryUser,
    Create,
    Collision,
    Close,
}

pub(super) struct ClosedError {
    operation: Operation,
    raw_error: Option<u32>,
}

impl std::fmt::Debug for ClosedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamespaceError")
            .field("operation", &self.operation)
            .field("raw_error", &self.raw_error)
            .finish()
    }
}

fn refusal(operation: Operation) -> ClosedError {
    ClosedError {
        operation,
        raw_error: None,
    }
}

fn native_error(operation: Operation, code: u32) -> ClosedError {
    ClosedError {
        operation,
        raw_error: Some(code),
    }
}

fn check(deadline: Instant) -> Result<(), ClosedError> {
    if Instant::now() >= deadline {
        Err(refusal(Operation::Deadline))
    } else {
        Ok(())
    }
}

struct Boundary(HANDLE);

impl Drop for Boundary {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this owner holds only a boundary descriptor, never a kernel handle.
            unsafe { DeleteBoundaryDescriptor(self.0) };
            self.0 = std::ptr::null_mut();
        }
    }
}

pub(super) struct EventNamespace {
    handle: HANDLE,
    boundary: Boundary,
    alias: Vec<u16>,
    deadline: Instant,
    owned: bool,
}

impl EventNamespace {
    pub(super) fn create(
        source: HANDLE,
        user_acl: &[u8],
        random: &tempfile::TempDir,
        deadline: Instant,
    ) -> Result<Self, ClosedError> {
        check(deadline)?;
        let base = random
            .path()
            .file_name()
            .ok_or_else(|| refusal(Operation::Name))?;
        let alias: Vec<u16> = base.encode_wide().take(NAME_BOUND + 1).collect();
        if alias.is_empty()
            || alias.len() > NAME_BOUND
            || alias.iter().any(|unit| matches!(*unit, 0 | 47 | 92 | 58))
            || base == std::ffi::OsStr::new(".")
            || base == std::ffi::OsStr::new("..")
        {
            return Err(refusal(Operation::Name));
        }
        // Admission includes the longest closed child, separator, and terminal NUL.
        let longest = "explicit-control".encode_utf16().count();
        if alias
            .len()
            .checked_add(longest)
            .and_then(|n| n.checked_add(2))
            .is_none_or(|n| n > NAME_BOUND)
        {
            return Err(refusal(Operation::Name));
        }
        let expected_user =
            namespace_acl::user_sid(user_acl).map_err(|_| refusal(Operation::Acl))?;
        let acl = namespace_acl::plan(user_acl).map_err(|_| refusal(Operation::Acl))?;
        check(deadline)?;
        let user = query(source, TokenUser).map_err(|error| ClosedError {
            operation: Operation::SourceUser,
            raw_error: error.raw_os_error().map(|code| code as u32),
        })?;
        check(deadline)?;
        if user.length < size_of::<TOKEN_USER>() {
            return Err(refusal(Operation::SourceUser));
        }
        // SAFETY: query contains the complete fixed native token-user header.
        let sid = unsafe { user.words.as_ptr().cast::<TOKEN_USER>().read_unaligned() }
            .User
            .Sid;
        pointer_range(&user, sid.cast(), 8).map_err(|_| refusal(Operation::SourceUser))?;
        // SAFETY: the SID header is admitted inside the retained aligned query.
        let header = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), 8) };
        if header[0] != 1 || header[1] > 15 {
            return Err(refusal(Operation::SourceUser));
        }
        let sid_length = 8 + usize::from(header[1]) * size_of::<u32>();
        pointer_range(&user, sid.cast(), sid_length).map_err(|_| refusal(Operation::SourceUser))?;
        // SAFETY: exact bounded SID bytes remain inside the retained native query.
        if unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_length) } != expected_user {
            return Err(refusal(Operation::SourceUser));
        }
        let mut native_name = alias.clone();
        native_name.push(0);
        check(deadline)?;
        // SAFETY: terminated bounded name and documented flags0.
        let handle = unsafe { CreateBoundaryDescriptorW(native_name.as_ptr(), 0) };
        // SAFETY: capture this operation's numeric error immediately.
        let code = unsafe { GetLastError() };
        if handle.is_null() {
            return Err(native_error(Operation::Boundary, code));
        }
        let mut boundary = Boundary(handle);
        check(deadline)?;
        // SAFETY: mutable owned descriptor updates in place immediately; exact source SID held.
        let result = unsafe { AddSIDToBoundaryDescriptor(&mut boundary.0, sid) };
        // SAFETY: immediate operation-specific status capture.
        let code = unsafe { GetLastError() };
        if result == 0 {
            return Err(native_error(Operation::BoundaryUser, code));
        }
        check(deadline)?;
        let mut storage = vec![0usize; acl.len().div_ceil(size_of::<usize>())];
        // SAFETY: aligned storage covers the complete validated namespace ACL.
        unsafe {
            std::ptr::copy_nonoverlapping(acl.as_ptr(), storage.as_mut_ptr().cast(), acl.len())
        };
        // SAFETY: descriptor initialization below accepts zeroed writable storage.
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        check(deadline)?;
        // SAFETY: fixed writable native descriptor with documented revision1.
        let result = unsafe {
            InitializeSecurityDescriptor((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(), 1)
        };
        // SAFETY: immediate native error capture.
        let code = unsafe { GetLastError() };
        if result == 0 {
            return Err(native_error(Operation::Descriptor, code));
        }
        check(deadline)?;
        // SAFETY: non-null validated ACL storage outlives native namespace creation.
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
        if result == 0 {
            return Err(native_error(Operation::Descriptor, code));
        }
        check(deadline)?;
        // SAFETY: protection prevents namespace inheritance; ACEs themselves all have flags0.
        let result = unsafe {
            SetSecurityDescriptorControl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        };
        // SAFETY: immediate native error capture.
        let code = unsafe { GetLastError() };
        if result == 0 {
            return Err(native_error(Operation::Descriptor, code));
        }
        check(deadline)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            bInheritHandle: 0,
        };
        // SAFETY: reset last error before the creation/collision distinction.
        unsafe { SetLastError(0) };
        // SAFETY: descriptor/boundary/name storage remain live for this synchronous constructor.
        let handle = unsafe {
            CreatePrivateNamespaceW(&attributes, boundary.0.cast_const(), native_name.as_ptr())
        };
        // SAFETY: immediate creation/collision status capture.
        let code = unsafe { GetLastError() };
        if handle.is_null() {
            return Err(native_error(Operation::Create, code));
        }
        let mut owner = Self {
            handle,
            boundary,
            alias,
            deadline,
            owned: code != ERROR_ALREADY_EXISTS,
        };
        if !owner.owned {
            // A returned collision handle is owned, but its namespace is NOT ours to destroy.
            owner.close_native()?;
            return Err(native_error(Operation::Collision, code));
        }
        check(deadline)?;
        Ok(owner)
    }

    pub(super) fn name(&self, child: &'static str) -> Result<Vec<u16>, ClosedError> {
        check(self.deadline)?;
        if !matches!(child, "self" | "external" | "explicit-control") || self.handle.is_null() {
            return Err(refusal(Operation::Name));
        }
        let mut result = self.alias.clone();
        result.push(u16::from(b'\\'));
        result.extend(child.encode_utf16());
        result.push(0);
        if result.len() > NAME_BOUND {
            return Err(refusal(Operation::Name));
        }
        Ok(result)
    }

    fn close_native(&mut self) -> Result<(), ClosedError> {
        if self.handle.is_null() {
            return Ok(());
        }
        let flags = if self.owned {
            PRIVATE_NAMESPACE_FLAG_DESTROY
        } else {
            0
        };
        // SAFETY: only this dedicated API owns namespace handles; collision never destroys.
        let result = unsafe { ClosePrivateNamespace(self.handle, flags) };
        // SAFETY: capture failed dedicated close immediately, retaining handle on failure.
        let code = unsafe { GetLastError() };
        if !result {
            return Err(native_error(Operation::Close, code));
        }
        self.handle = std::ptr::null_mut();
        Ok(())
    }

    pub(super) fn close(&mut self, deadline: Instant) -> Result<(), ClosedError> {
        let cutoff = self.deadline.min(deadline);
        // Cleanup remains obligatory even when the original budget has expired.
        let before = check(cutoff);
        self.close_native()?;
        before?;
        check(cutoff)
    }
}

impl Drop for EventNamespace {
    fn drop(&mut self) {
        // Best-effort unwind cleanup never panics or masks the initiating failure.
        let _ = self.close_native();
        // The dedicated boundary owner is dropped after this namespace close attempt.
        let _ = &self.boundary;
    }
}
