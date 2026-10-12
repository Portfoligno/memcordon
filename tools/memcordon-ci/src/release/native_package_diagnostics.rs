//! Bounded observations, separate from private native package owner records.
fn excerpt(bytes: &[u8]) -> String {
    const HALF: usize = 512;
    if bytes.len() <= HALF * 2 {
        format!("{:?}", String::from_utf8_lossy(bytes))
    } else {
        format!(
            "{:?} [truncated] {:?}",
            String::from_utf8_lossy(&bytes[..HALF]),
            String::from_utf8_lossy(&bytes[bytes.len() - HALF..]),
        )
    }
}

pub(crate) fn install_failure(status: Option<i32>, stdout: &[u8], stderr: &[u8]) -> String {
    // At most 1024 input bytes per stream, even for escaped control/invalid
    // bytes. Keep repeated failure observations within the bounded cell record.
    format!(
        "native component selected package install failed; owner retains finalization; status={status:?}; stdout={}; stderr={}",
        excerpt(stdout),
        excerpt(stderr),
    )
}
