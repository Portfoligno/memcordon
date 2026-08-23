#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

//! Private provider machinery for certified sealed supervision.
//!
//! This package is deliberately unpublished. Its protocol is local, bounded,
//! versioned, and rejects unknown messages before any target can be created.

#[cfg(target_os = "linux")]
pub mod linux;
pub mod package;
pub mod protocol;
pub mod request;
pub mod state;
