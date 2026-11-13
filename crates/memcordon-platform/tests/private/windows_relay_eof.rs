use super::*;
use std::io::{Read, Write};
use std::os::windows::io::FromRawHandle;

fn forward_and_read(source: std::fs::File) -> Vec<u8> {
    let mut reader = ptr::null_mut();
    let mut writer = ptr::null_mut();
    // SAFETY: two initialized out-pointers receive unique anonymous pipe handles.
    assert_ne!(
        unsafe {
            windows_sys::Win32::System::Pipes::CreatePipe(&mut reader, &mut writer, ptr::null(), 0)
        },
        0
    );
    let endpoint = OwnedHandle::new(writer).unwrap();
    // SAFETY: the successful pipe creation transfers the read endpoint once.
    let mut reader = unsafe { std::fs::File::from_raw_handle(reader.cast()) };
    let cutoff = Instant::now() + Duration::from_secs(5);
    let thread = std::thread::spawn(move || {
        let deadline = crate::windows_io_deadline::SynchronousIoDeadline::start(cutoff).unwrap();
        let destination = endpoint.raw();
        let result = relay_io(
            endpoint,
            source.as_raw_handle().cast(),
            destination,
            &AtomicBool::new(false),
        );
        let retirement = deadline.finish();
        result.and(retirement)
    });
    let deadline = crate::windows_io_deadline::SynchronousIoDeadline::start(cutoff).unwrap();
    let mut bytes = Vec::new();
    let read = reader.read_to_end(&mut bytes);
    let relay = thread.join().unwrap();
    let retirement = deadline.finish();
    read.unwrap();
    relay.unwrap();
    retirement.unwrap();
    bytes
}

#[test]
fn null_stdin_closes_the_only_remote_writer_at_eof() {
    assert!(forward_and_read(std::fs::File::open("NUL").unwrap()).is_empty());
}

#[test]
fn finite_stdin_preserves_exact_bytes_then_closes_the_remote_writer() {
    let mut source = tempfile::tempfile().unwrap();
    let expected = [0, 255, 128, 10, 0, 42].repeat(4096);
    source.write_all(&expected).unwrap();
    use std::io::{Seek, SeekFrom};
    source.seek(SeekFrom::Start(0)).unwrap();
    assert_eq!(forward_and_read(source), expected);
}
