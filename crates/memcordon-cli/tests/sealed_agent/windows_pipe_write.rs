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
