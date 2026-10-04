//! Standard GitHub output records are data, never command text.
use crate::{CiError, Result};
use std::io::Write;

pub fn write(values: &[(&str, String)]) -> Result<()> {
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
    }
    if let Some(path) = std::env::var_os("GITHUB_OUTPUT") {
        let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
        for (key, value) in values {
            writeln!(&mut file, "{key}={value}")?;
        }
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
