//! Standard GitHub output records are data, never command text.
use crate::{CiError, Result};
use std::io::Write;

pub fn write(values: &[(&str, String)]) -> Result<()> {
    let path = std::env::var_os("GITHUB_OUTPUT");
    write_to(path.as_deref().map(std::path::Path::new), values)
}

pub(crate) fn write_to(path: Option<&std::path::Path>, values: &[(&str, String)]) -> Result<()> {
    let mut records = String::new();
    for (key, value) in values {
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            || value.is_empty()
            || value.chars().any(char::is_control)
        {
            return Err(CiError::Message(
                "workflow output key/value is not a safe single line".into(),
            ));
        }
        records.push_str(key);
        records.push('=');
        records.push_str(value);
        records.push('\n');
    }
    if let Some(path) = path {
        let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
        // Serialize before appending: formatted writes can split a record into
        // key/value fragments that concurrent append handles interleave.
        file.write_all(records.as_bytes())?;
        file.flush()?;
    }
    Ok(())
}

pub fn quiescent(result: Result<()>) -> Result<()> {
    // An outer error can wrap native ownership uncertainty. Only a completed
    // successful operation proves every owner returned; failures keep reuse off.
    let observation = if result.is_ok() { "true" } else { "false" };
    if let Err(error) = write(&[("cache-quiescent", observation.into())]) {
        if result.is_ok() {
            return Err(error);
        }
        eprintln!("workflow output collection failed: {error}");
    }
    result
}
