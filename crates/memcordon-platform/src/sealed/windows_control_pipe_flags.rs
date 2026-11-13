//! Fixed transport semantics for every authenticated control-pipe connection.
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, SECURITY_CONTEXT_TRACKING, SECURITY_IMPERSONATION, SECURITY_SQOS_PRESENT,
};

// Authenticate the effective writer dynamically, with disabled inventory
// available but without enabling any privilege. Do not select flags by route.
pub(super) const FLAGS: u32 = FILE_ATTRIBUTE_NORMAL
    | SECURITY_SQOS_PRESENT
    | SECURITY_IMPERSONATION
    | SECURITY_CONTEXT_TRACKING;
