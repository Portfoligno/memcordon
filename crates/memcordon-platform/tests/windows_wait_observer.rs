#![cfg(all(windows, feature = "test-support"))]

use memcordon_platform::test_support::{
    ProcessIdentity, WindowsHeldFileMetadata, windows_held_file_metadata,
    windows_performance_counter,
};
#[path = "../src/windows_wait_observer.rs"]
pub mod observer;
