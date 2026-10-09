use std::path::Path;

pub(crate) fn validate(
    source: &Path,
    regular: bool,
    links: u64,
    length: u64,
    limit: u64,
) -> Result<(), String> {
    if !regular || links != 1 || length > limit {
        let encoded = source.as_os_str().as_encoded_bytes();
        let path = String::from_utf8_lossy(&encoded[..encoded.len().min(512)]);
        return Err(format!(
            "original component source type/size differs; source={path:?}; path-truncated={}; regular={regular}; links={links}; length={length}; limit={limit}",
            encoded.len() > 512,
        ));
    }
    Ok(())
}
