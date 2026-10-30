use std::{
    fs::File,
    io::{Read, Write},
    os::windows::io::FromRawHandle,
    time::{Duration, Instant},
};

#[allow(unsafe_code)] // A fresh anonymous kernel pipe gives this test exclusive native reader/writer ownership.
fn pair() -> (File, File) {
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            windows_sys::Win32::System::Pipes::CreatePipe(
                &mut read,
                &mut write,
                std::ptr::null(),
                0,
            )
        },
        0
    );
    unsafe {
        (
            File::from_raw_handle(read.cast()),
            File::from_raw_handle(write.cast()),
        )
    }
}

#[test]
fn partial_terminal_frame_cancels_only_original_synchronous_read() {
    let (mut read, mut write) = pair();
    write.write_all(&[0x11, 0x22]).unwrap();
    let started = Instant::now();
    let guard =
        crate::windows::pipe::SynchronousIoDeadline::start(started + Duration::from_millis(40))
            .unwrap();
    let mut header = [0u8; 4];
    let error = read.read_exact(&mut header).unwrap_err();
    assert_eq!(
        error.raw_os_error(),
        Some(windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED as i32)
    );
    assert!(guard.finish().is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    let (mut next_read, mut next_write) = pair();
    next_write.write_all(&[0x33]).unwrap();
    let mut next = [0u8; 1];
    next_read.read_exact(&mut next).unwrap();
    assert_eq!(next, [0x33]);
}

#[test]
fn completed_terminal_frame_stops_deadline_before_later_io() {
    let (mut read, mut write) = pair();
    write.write_all(&[1, 2, 3, 4]).unwrap();
    let guard =
        crate::windows::pipe::SynchronousIoDeadline::start(Instant::now() + Duration::from_secs(1))
            .unwrap();
    let mut frame = [0u8; 4];
    read.read_exact(&mut frame).unwrap();
    guard.finish().unwrap();
    assert_eq!(frame, [1, 2, 3, 4]);
    write.write_all(&[5]).unwrap();
    let mut next = [0u8; 1];
    read.read_exact(&mut next).unwrap();
    assert_eq!(next, [5]);
}

#[test]
fn partial_initial_request_uses_the_fixed_whole_frame_cutoff() {
    use std::os::windows::io::AsRawHandle;
    let (read, mut write) = pair();
    write.write_all(&[1, 0]).unwrap();
    let started = Instant::now();
    let error = crate::windows::pipe::read_frame_until::<serde_json::Value>(
        read.as_raw_handle().cast(),
        started + Duration::from_millis(40),
    )
    .unwrap_err();
    assert!(error.contains("MCSEALED-WINDOWS-PIPE-READ"));
    assert!(error.contains("phase=length-read"));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
#[allow(unsafe_code)] // Fresh test-only named pipe, with exact owned handles and no provider state.
fn withheld_response_drain_cannot_outlive_the_frame_write_cutoff() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    let name = format!(r"\\.\pipe\memcordon-frame-drain-{}", std::process::id());
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let raw = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            std::ptr::null(),
        )
    };
    assert_ne!(raw, windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
    let server = unsafe { File::from_raw_handle(raw.cast()) };
    let client = std::thread::spawn(move || crate::windows::pipe::connect(&name).unwrap());
    let connected = unsafe { ConnectNamedPipe(raw, std::ptr::null_mut()) };
    if connected == 0 {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(windows_sys::Win32::Foundation::ERROR_PIPE_CONNECTED as i32)
        );
    }
    let client = client.join().unwrap();
    let started = Instant::now();
    let error = crate::windows::pipe::write_frame_until(
        server.as_raw_handle().cast(),
        &serde_json::json!({"response":"retired"}),
        started + Duration::from_millis(40),
    )
    .unwrap_err();
    assert!(error.contains("phase=Drain"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(client);
}
