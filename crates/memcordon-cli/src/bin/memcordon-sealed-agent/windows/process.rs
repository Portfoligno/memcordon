//! Thin production process facade.
//!
//! Native loader creation is owned by `memcordon-windows-launch-core`; the
//! remaining provider supervision implementation is isolated from callers so
//! its behavior modules can evolve without reopening the public boundary.

pub(crate) use super::process_impl::*;
