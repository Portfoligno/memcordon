//! Failure-only filesystem context; the original native error remains the source.
use std::{error::Error, fmt, io, path::Path};
pub const PATH_BOUND: usize = 512;
pub const DISPLAY_BOUND: usize = PATH_BOUND * 8 + 512;
struct Context {
    operation: &'static str,
    operation_omitted: usize,
    path_head: Vec<u8>,
    path_tail: Vec<u8>,
    omitted: usize,
    original: io::Error,
}
fn hex(bytes: &[u8]) -> String {
    use fmt::Write;
    let mut text = String::new();
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("String formatting is infallible");
    }
    text
}
impl fmt::Display for Context {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = format!(
            "operation={}; kind={:?}; raw-os-error={:?}; path-head={:?}; path-head-hex={}; path-tail={:?}; path-tail-hex={}; omitted-path-bytes={}; omitted-operation-bytes={}",
            self.operation,
            self.original.kind(),
            self.original.raw_os_error(),
            String::from_utf8_lossy(&self.path_head),
            hex(&self.path_head),
            String::from_utf8_lossy(&self.path_tail),
            hex(&self.path_tail),
            self.omitted,
            self.operation_omitted
        );
        debug_assert!(text.len() <= DISPLAY_BOUND);
        out.write_str(&text)
    }
}
impl fmt::Debug for Context {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, out)
    }
}
impl Error for Context {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.original)
    }
}
pub fn context(operation: &'static str, path: &Path, original: io::Error) -> io::Error {
    const OPERATION_BOUND: usize = 96;
    let mut end = operation.len().min(OPERATION_BOUND);
    while !operation.is_char_boundary(end) {
        end -= 1;
    }
    let operation_omitted = operation.len() - end;
    let operation = &operation[..end];
    let bytes = path.as_os_str().as_encoded_bytes();
    let (head, tail) = if bytes.len() <= PATH_BOUND {
        (bytes, &[][..])
    } else {
        let half = PATH_BOUND / 2;
        (&bytes[..half], &bytes[bytes.len() - half..])
    };
    io::Error::new(
        original.kind(),
        Context {
            operation,
            operation_omitted,
            path_head: head.to_vec(),
            path_tail: tail.to_vec(),
            omitted: bytes.len() - head.len() - tail.len(),
            original,
        },
    )
}
