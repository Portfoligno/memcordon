pub fn run(pipe: &str, nonce: &str, desktop: &str) -> Result<(), String> {
    if pipe.is_empty() || nonce.is_empty() || desktop.is_empty() {
        return Err(String::from("pipe, nonce, and desktop must not be empty"));
    }
    #[cfg(windows)]
    {
        crate::target::windows::exchange_ready(pipe, nonce, desktop)
    }
    #[cfg(not(windows))]
    {
        let _ = (pipe, nonce, desktop);
        Err(String::from("the loader target role is Windows-only"))
    }
}

#[cfg(windows)]
mod windows {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING, ReadFile, WriteFile,
        },
    };

    const BOOTSTRAP_SCHEMA_VERSION: u32 =
        memcordon_windows_launch_core::PRODUCTION_LOADER_READY_SCHEMA_VERSION;

    pub fn exchange_ready(pipe: &str, nonce: &str, desktop: &str) -> Result<(), String> {
        let pipe = wide_null(OsStr::new(pipe));
        let handle = unsafe {
            CreateFileW(
                pipe.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(format!(
                "open loader-ready pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let ready = serde_json::json!({
            "kind": "loader-ready",
            "schema_version": BOOTSTRAP_SCHEMA_VERSION,
            "nonce": nonce,
            "expected_desktop": desktop,
        });
        let result = write_frame(handle, &ready)
            .and_then(|()| read_frame(handle))
            .and_then(|release| {
                if release.get("kind").and_then(serde_json::Value::as_str)
                    == Some("loader-control-release")
                    && release
                        .get("schema_version")
                        .and_then(serde_json::Value::as_u64)
                        == Some(u64::from(BOOTSTRAP_SCHEMA_VERSION))
                    && release.get("nonce").and_then(serde_json::Value::as_str) == Some(nonce)
                    && release
                        .get("expected_desktop")
                        .and_then(serde_json::Value::as_str)
                        == Some(desktop)
                {
                    Ok(())
                } else {
                    Err(String::from("loader-control release frame is invalid"))
                }
            });
        unsafe { CloseHandle(handle) };
        result
    }

    fn write_frame(handle: *mut std::ffi::c_void, value: &serde_json::Value) -> Result<(), String> {
        let payload = serde_json::to_vec(value)
            .map_err(|error| format!("encode loader-ready frame: {error}"))?;
        let length = u32::try_from(payload.len()).map_err(|_| String::from("frame too large"))?;
        write_all(handle, &length.to_le_bytes())?;
        write_all(handle, &payload)
    }

    fn read_frame(handle: *mut std::ffi::c_void) -> Result<serde_json::Value, String> {
        let mut length = [0_u8; std::mem::size_of::<u32>()];
        read_exact(handle, &mut length)?;
        let mut payload = vec![
            0_u8;
            usize::try_from(u32::from_le_bytes(length))
                .map_err(|_| String::from("release length overflow"))?
        ];
        read_exact(handle, &mut payload)?;
        serde_json::from_slice(&payload).map_err(|error| format!("decode release frame: {error}"))
    }

    fn write_all(handle: *mut std::ffi::c_void, mut source: &[u8]) -> Result<(), String> {
        while !source.is_empty() {
            let mut written = 0_u32;
            if unsafe {
                WriteFile(
                    handle,
                    source.as_ptr().cast(),
                    u32::try_from(source.len()).map_err(|_| String::from("frame too large"))?,
                    &raw mut written,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                let error = std::io::Error::last_os_error();
                return Err(format!("write loader-ready frame: {error}"));
            }
            source = &source
                [usize::try_from(written).map_err(|_| String::from("write length overflow"))?..];
        }
        Ok(())
    }

    fn read_exact(handle: *mut std::ffi::c_void, mut target: &mut [u8]) -> Result<(), String> {
        while !target.is_empty() {
            let mut read = 0_u32;
            if unsafe {
                ReadFile(
                    handle,
                    target.as_mut_ptr().cast(),
                    u32::try_from(target.len()).map_err(|_| String::from("frame too large"))?,
                    &raw mut read,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                let error = std::io::Error::last_os_error();
                return Err(format!("read loader-control release: {error}"));
            }
            let read = usize::try_from(read).map_err(|_| String::from("read length overflow"))?;
            if read == 0 {
                return Err(String::from("pipe closed before release completed"));
            }
            target = &mut target[read..];
        }
        Ok(())
    }

    fn wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }
}
