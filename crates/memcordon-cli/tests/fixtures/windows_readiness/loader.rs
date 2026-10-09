use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(path: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let library = args.next().expect("DLL path");
    let directory = args.next().expect("output directory");
    assert!(args.next().is_none());
    assert!(Path::new(&library).is_absolute());
    let name: Vec<u16> = OsStr::new(&library).encode_wide().chain(Some(0)).collect();
    // SAFETY: input is a terminated absolute DLL path; load only its directory
    // and System32, excluding current directory and ambient PATH resolution.
    let module = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), 0x100 | 0x800) };
    if module.is_null() { return Err(std::io::Error::last_os_error()); }
    // SAFETY: fixed terminated symbol name and held loaded module.
    let address = unsafe { GetProcAddress(module, b"memcordon_readiness_byte\0".as_ptr()) };
    if address.is_null() { return Err(std::io::Error::last_os_error()); }
    // SAFETY: the owned DLL exports exactly this signature.
    let function: extern "C" fn(u32) -> u32 = unsafe { std::mem::transmute(address) };
    let mut bytes = Vec::new();
    for value in 0..=255 { assert_eq!(function(value), value); bytes.push(value as u8); }
    assert_eq!(function(256), u32::MAX);
    let directory = Path::new(&directory);
    std::fs::write(directory.join("dll-output.bin"), bytes)?;
    std::fs::write(directory.join("dll-empty.bin"), [])?;
    // SAFETY: releases this loader's module reference after the last function call.
    if unsafe { FreeLibrary(module) } == 0 { return Err(std::io::Error::last_os_error()); }
    Ok(())
}
