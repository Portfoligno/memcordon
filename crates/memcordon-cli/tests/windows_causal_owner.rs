//! Execute the actual portable journal owner, with native API cases left to Windows.
#![allow(dead_code)]
#![cfg(not(windows))]

#[path = "../src/bin/memcordon-sealed-agent/windows/diagnostics.rs"]
mod diagnostics;
