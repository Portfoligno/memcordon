#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramedLineError {
    InvalidUtf8(std::str::Utf8Error),
    Missing,
    Duplicate,
    TooLarge,
}

pub fn unique_prefixed_line<'a>(
    output: &'a [u8],
    prefix: &str,
    maximum_payload_bytes: usize,
) -> Result<&'a str, FramedLineError> {
    let output = std::str::from_utf8(output).map_err(FramedLineError::InvalidUtf8)?;
    let mut payload = None;
    for candidate in output.lines().filter_map(|line| line.strip_prefix(prefix)) {
        if payload.replace(candidate).is_some() {
            return Err(FramedLineError::Duplicate);
        }
    }
    let payload = payload.ok_or(FramedLineError::Missing)?;
    if payload.len() > maximum_payload_bytes {
        Err(FramedLineError::TooLarge)
    } else {
        Ok(payload)
    }
}
