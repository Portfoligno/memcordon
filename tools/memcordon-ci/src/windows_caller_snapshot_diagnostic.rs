pub fn failure(restricted: bool, status: Option<i32>, stdout: &[u8], stderr: &[u8]) -> String {
    fn excerpt(bytes: &[u8]) -> String {
        let prefix = &bytes[..bytes.len().min(4096)];
        format!(
            "{:?}; bytes={}; truncated={}",
            String::from_utf8_lossy(prefix),
            bytes.len(),
            prefix.len() != bytes.len()
        )
    }
    format!(
        "native caller-envelope provisioning failed; restricted={restricted}; status={status:?}; stdout={}; stderr={}",
        excerpt(stdout),
        excerpt(stderr)
    )
}
