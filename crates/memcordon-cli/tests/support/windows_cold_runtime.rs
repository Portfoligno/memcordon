//! Test-owned cold-runtime protocol shared with the existing sealed fixture.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ColdRuntimeStage {
    NotEntered = 0,
    Entered = 1,
    RestrictedTokenConfirmed = 2,
    BeforeRuntimeOpen = 3,
    RuntimeOpened = 4,
    BytesVerified = 5,
    HashVerified = 6,
}

pub fn cold_runtime_stage_record(stage: ColdRuntimeStage) -> [u8; 2] {
    [1, stage as u8]
}

pub fn write_cold_runtime_stage(file: &mut std::fs::File, stage: ColdRuntimeStage) {
    use std::io::{Seek, Write};
    file.rewind().unwrap();
    file.write_all(&cold_runtime_stage_record(stage)).unwrap();
}

pub fn validate_cold_runtime_mode(arguments: &[std::ffi::OsString]) -> Result<(), &'static str> {
    match arguments {
        [mode] if mode == "cold-runtime-probe" => Ok(()),
        _ => Err("expected exactly the cold-runtime-probe fixture mode"),
    }
}

#[cfg(windows)]
pub fn run_child() -> ! {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{FILE_WRITE_DATA, SYNCHRONIZE};
    let root = std::env::current_dir().unwrap();
    let mut progress = std::fs::OpenOptions::new()
        .write(true)
        .access_mode(FILE_WRITE_DATA | SYNCHRONIZE)
        .open(root.join("cold-runtime.progress"))
        .unwrap();
    write_cold_runtime_stage(&mut progress, ColdRuntimeStage::Entered);
    // Query-only current-token pseudo handle never reopens the token DACL.
    assert_ne!(
        unsafe { windows_sys::Win32::Security::IsTokenRestricted((-4isize) as HANDLE) },
        0
    );
    write_cold_runtime_stage(&mut progress, ColdRuntimeStage::RestrictedTokenConfirmed);
    // No security-provider warm-up precedes this actual production open.
    write_cold_runtime_stage(&mut progress, ColdRuntimeStage::BeforeRuntimeOpen);
    let mut held =
        memcordon_platform::open_protected_runtime_for_test(&root.join("cold-runtime.bin"))
            .unwrap();
    write_cold_runtime_stage(&mut progress, ColdRuntimeStage::RuntimeOpened);
    let mut bytes = Vec::new();
    held.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"cold restricted runtime security descriptor");
    write_cold_runtime_stage(&mut progress, ColdRuntimeStage::BytesVerified);
    assert_eq!(
        Sha256::digest(&bytes),
        Sha256::digest(b"cold restricted runtime security descriptor")
    );
    write_cold_runtime_stage(&mut progress, ColdRuntimeStage::HashVerified);
    std::process::exit(37);
}
