use std::path::Path;

pub fn contextualize<T>(
    operation: &'static str,
    path: &Path,
    result: std::io::Result<T>,
) -> std::io::Result<T> {
    result.map_err(|cause| error(operation, path, cause))
}

pub fn error(operation: &'static str, path: &Path, error: std::io::Error) -> std::io::Error {
    let bytes = path.as_os_str().as_encoded_bytes();
    let prefix = &bytes[..bytes.len().min(512)];
    std::io::Error::new(
        error.kind(),
        format!(
            "public Cargo install verification {operation} failed; path={:?}; path-truncated={}; cause={error}",
            String::from_utf8_lossy(prefix),
            bytes.len() > prefix.len(),
        ),
    )
}
