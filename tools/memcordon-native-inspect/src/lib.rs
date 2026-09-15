//! Read-only native filesystem inspection authority for build tooling.
//!
//! Owned descriptors and kernel access checks provide observations to the CI
//! inventory. Callers retain admission and race policy; reparse bytes never
//! authorize target activation. This crate has no production supervision or
//! test-support dependency. Direct boundary tests live in `tests/`.
#![deny(unsafe_op_in_unsafe_fn)]

mod reparse_reply;
pub use reparse_reply::initialized_reparse_bytes;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native_access;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use native_access::{UnsearchableDirectory, unsearchable_directory};

#[cfg(target_os = "macos")]
mod system_input;
#[cfg(target_os = "macos")]
pub use system_input::macos_read_only_descriptor_path;

#[cfg(windows)]
mod windows_file_identity;
#[cfg(windows)]
pub use windows_file_identity::windows_file_identity;
#[cfg(windows)]
mod windows_reparse;
#[cfg(windows)]
pub use windows_reparse::windows_reparse_data;
