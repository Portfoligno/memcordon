use super::*;

#[test]
fn bootstrap_peer_exit_never_becomes_api_pipe_closure() {
    use memcordon_windows_launch_core::NativeStatusV1;
    for code in [0, 109, 232, 233, 0xc000_0142, 0xed14_0000] {
        let error = target_desktop_bootstrap_peer_exit_error(
            TargetDesktopBootstrapPipeOperation::LifetimeRead,
            "length",
            4,
            code,
        );
        assert_eq!(error.native_code(), None);
        assert_eq!(
            error.native_status(),
            Some(NativeStatusV1::TargetExit { code })
        );
        assert!(!error.is_lifetime_pipe_closure());
        assert!(
            error
                .to_string()
                .contains(&format!("child_exit_code_hex=0x{code:08X}"))
        );
    }
    for code in [109, 232, 233, 5] {
        let error = TargetDesktopBootstrapPipeError::native(
            TargetDesktopBootstrapPipeOperation::LifetimeRead,
            "length",
            &std::io::Error::from_raw_os_error(code),
        );
        assert_eq!(error.native_code(), Some(code));
        assert_eq!(
            error.native_status(),
            Some(NativeStatusV1::Win32 { code: code as u32 })
        );
        assert_eq!(error.is_lifetime_pipe_closure(), code != 5);
    }
    let protocol = TargetDesktopBootstrapPipeError::protocol(
        TargetDesktopBootstrapPipeOperation::LifetimeRead,
        "invalid frame",
    );
    assert_eq!(protocol.native_status(), None);
    assert!(!protocol.is_lifetime_pipe_closure());
}

#[test]
fn partial_writes_advance_without_replaying_the_frame() {
    let value = "native response";
    let payload = serde_json::to_vec(value).unwrap();
    let mut observed = Vec::new();
    write_frame_using(&value, |remaining| {
        observed.push(remaining[0]);
        Ok(1)
    })
    .unwrap();
    let mut expected = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
    expected.extend(payload);
    assert_eq!(observed, expected);
}

#[test]
fn native_loss_preserves_phase_progress_and_never_replays() {
    let mut calls = 0;
    let failure = write_frame_using(&"response", |remaining| {
        calls += 1;
        match calls {
            1 => Ok(remaining.len()),
            2 => Ok(2),
            3 => Err((Some(ERROR_NO_DATA), 0, "native loss".into())),
            _ => panic!("write replayed after native failure"),
        }
    })
    .unwrap_err();
    assert_eq!(calls, 3);
    assert_eq!(failure.phase, FrameWritePhase::Payload);
    assert_eq!(failure.transferred_bytes, 2);
    assert_eq!(failure.native_code, Some(ERROR_NO_DATA));
    assert!(failure.peer_closed);
}

#[test]
fn zero_progress_is_not_peer_loss() {
    let failure = write_frame_using(&"response", |_| Ok(0)).unwrap_err();
    assert_eq!(failure.phase, FrameWritePhase::Length);
    assert_eq!(failure.transferred_bytes, 0);
    assert_eq!(failure.native_code, None);
    assert!(!failure.peer_closed);
    for code in [ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED] {
        assert!(
            frame_write_error(FrameWritePhase::Length, 4, 0, Some(code), String::new()).peer_closed
        );
    }
    assert!(!frame_write_error(FrameWritePhase::Length, 4, 0, Some(5), String::new()).peer_closed);
}

#[test]
fn closed_native_pipe_retains_actual_write_error() {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    // SAFETY: both output pointers are valid; no handle is inherited.
    assert_ne!(
        unsafe {
            windows_sys::Win32::System::Pipes::CreatePipe(
                &raw mut read,
                &raw mut write,
                ptr::null(),
                0,
            )
        },
        0
    );
    let read = OwnedHandle::new(read).unwrap();
    let write = OwnedHandle::new(write).unwrap();
    drop(read);
    let failure = write_frame_detailed(write.raw(), &"response").unwrap_err();
    assert_eq!(failure.phase, FrameWritePhase::Length);
    assert!(matches!(
        failure.native_code,
        Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA)
    ));
    assert_eq!(failure.transferred_bytes, 0);
    assert!(failure.peer_closed);
}

#[cfg(feature = "test-support")]
fn pumped_frame_pipe_pair() -> (OwnedHandle, OwnedHandle) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let name = wide_null(&format!(
        r"\\.\pipe\memcordon-pumped-frame-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    // SAFETY: the finite unique local name and no-security-pointer arguments
    // remain valid for creation; returned handles are exclusively owned.
    let server = OwnedHandle::new(unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            256,
            256,
            0,
            ptr::null(),
        )
    })
    .unwrap();
    // SAFETY: the existing pipe name is live; no security attributes or
    // template handle are supplied, and the returned client is owned.
    let client = OwnedHandle::new(unsafe {
        CreateFileW(
            name.as_ptr(),
            windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    })
    .unwrap();
    // SAFETY: the current-process pseudo-handle is only borrowed by accept.
    let server = accept_target_desktop_bootstrap_pipe(
        server,
        unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() },
        std::time::Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    (server, client)
}

#[cfg(feature = "test-support")]
#[test]
fn pumped_pending_read_makes_progress_without_losing_frame_or_owner() {
    let (server, client) = pumped_frame_pipe_pair();
    let (start, ready) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        ready.recv().unwrap();
        write_frame(client.raw(), &"authenticated ready")
    });
    let mut calls = 0;
    let value = read_frame_bounded_pumped::<String>(
        server.raw(),
        None,
        std::time::Instant::now() + Duration::from_secs(2),
        TargetDesktopBootstrapPipeOperation::LoaderReadyRead,
        &mut || {
            calls += 1;
            if calls == 1 {
                start.send(()).map_err(|error| error.to_string())?;
            }
            Ok(())
        },
    );
    if value.is_err() {
        drop(server);
    }
    drop(start);
    writer.join().expect("writer settled").unwrap();
    let value = value.unwrap();
    assert_eq!(value, "authenticated ready");
    assert_ne!(calls, 0);
}

#[cfg(feature = "test-support")]
#[test]
fn failed_pump_cancels_pending_read_before_next_frame() {
    let (server, client) = pumped_frame_pipe_pair();
    let failure = read_frame_bounded_pumped::<String>(
        server.raw(),
        None,
        std::time::Instant::now() + Duration::from_secs(2),
        TargetDesktopBootstrapPipeOperation::LoaderReadyRead,
        &mut || Err("actual diagnostic pump failure".into()),
    )
    .unwrap_err();
    assert!(
        failure
            .to_string()
            .contains("actual diagnostic pump failure")
    );
    let writer = std::thread::spawn(move || write_frame(client.raw(), &"next intact frame"));
    let next = read_frame_bounded::<String>(
        server.raw(),
        None,
        std::time::Instant::now() + Duration::from_secs(2),
        TargetDesktopBootstrapPipeOperation::LoaderReadyRead,
    );
    if next.is_err() {
        drop(server);
    }
    writer.join().expect("writer settled").unwrap();
    let next = next.unwrap();
    assert_eq!(next, "next intact frame");
}

#[cfg(feature = "test-support")]
#[test]
fn pumped_pending_write_preserves_exact_frame_bytes() {
    let (server, client) = pumped_frame_pipe_pair();
    let value = "release".repeat(2048);
    let payload = serde_json::to_vec(&value).unwrap();
    let mut expected = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
    expected.extend(payload);
    let mut observed = Vec::new();
    let mut calls = 0;
    let mut receive = || -> Result<(), String> {
        calls += 1;
        let mut available = 0;
        // SAFETY: only the writable availability scalar is supplied, and the
        // client handle stays live throughout this callback.
        if unsafe {
            PeekNamedPipe(
                client.raw(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &raw mut available,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if available != 0 {
            let mut bytes = [0_u8; 512];
            let mut read = 0;
            // SAFETY: the requested byte count fits this live stack buffer;
            // the synchronous client has no outstanding operation.
            if unsafe {
                ReadFile(
                    client.raw(),
                    bytes.as_mut_ptr().cast(),
                    available.min(512),
                    &raw mut read,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
            observed.extend_from_slice(&bytes[..read as usize]);
        }
        Ok(())
    };
    write_frame_bounded_pumped(
        server.raw(),
        None,
        std::time::Instant::now() + Duration::from_secs(2),
        TargetDesktopBootstrapPipeOperation::LoaderControlReleaseWrite,
        &value,
        &mut receive,
    )
    .unwrap();
    // Any trailing buffered bytes remain readable after write completion.
    for _ in 0..64 {
        receive().unwrap();
    }
    assert_ne!(calls, 0);
    assert_eq!(observed, expected);
}
