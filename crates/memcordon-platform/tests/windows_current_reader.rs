#![cfg(all(windows, feature = "test-support"))]
use std::{
    fs::File,
    io::Write,
    os::windows::io::FromRawHandle,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

#[allow(unsafe_code)] // The test owns both fresh kernel pipe references; neither is inherited or shared with another reader.
fn pair() -> (File, File) {
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    assert_ne!(
        unsafe {
            windows_sys::Win32::System::Pipes::CreatePipe(
                &mut read,
                &mut write,
                std::ptr::null(),
                256,
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
fn public_reader_partial_prefix_keeps_one_original_cutoff_and_pumps() {
    let (read, mut write) = pair();
    write.write_all(&[0x11, 0x22]).unwrap();
    let polls = AtomicUsize::new(0);
    let started = Instant::now();
    let error = memcordon_platform::test_support::read_windows_current_response_until(
        &read,
        Duration::from_millis(40),
        &mut || {
            polls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.contains("original whole provider-frame cutoff expired"));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(polls.load(Ordering::SeqCst) > 1);
}

#[test]
fn public_reader_streams_buffered_body_chunks_while_pumping() {
    let (read, mut write) = pair();
    let response = memcordon_core::WindowsProviderResponseV4::RecoveryAttemptUnavailable {
        schema_version: 4,
        challenge: "ab".repeat(32),
        attempt_id: "cd".repeat(32),
        detail: "x".repeat(4096),
    };
    let payload = serde_json::to_vec(&response).unwrap();
    let expected = payload.clone();
    let length = u32::try_from(payload.len()).unwrap();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        write.write_all(&length.to_le_bytes())?;
        for chunk in payload.chunks(31) {
            write.write_all(chunk)?;
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    });
    let polls = AtomicUsize::new(0);
    let observed = memcordon_platform::test_support::read_windows_current_response_until(
        &read,
        Duration::from_secs(5),
        &mut || {
            polls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .unwrap();
    writer.join().unwrap().unwrap();
    assert_eq!(serde_json::to_vec(&observed).unwrap(), expected);
    assert!(polls.load(Ordering::SeqCst) > 1);
}

#[test]
fn body_fragment_progress_cannot_renew_whole_frame_cutoff() {
    let (read, mut write) = pair();
    let response = memcordon_core::WindowsProviderResponseV4::RecoveryAttemptUnavailable {
        schema_version: 4,
        challenge: "ab".repeat(32),
        attempt_id: "cd".repeat(32),
        detail: "native current diagnostic".into(),
    };
    let payload = serde_json::to_vec(&response).unwrap();
    let length = u32::try_from(payload.len()).unwrap();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        write.write_all(&length.to_le_bytes())?;
        for byte in payload {
            write.write_all(&[byte])?;
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    });
    let started = Instant::now();
    let error = memcordon_platform::test_support::read_windows_current_response_until(
        &read,
        Duration::from_millis(40),
        &mut || Ok(()),
    )
    .unwrap_err();
    assert!(error.contains("original whole provider-frame cutoff expired"));
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(read);
    assert!(writer.join().unwrap().is_err());
}
