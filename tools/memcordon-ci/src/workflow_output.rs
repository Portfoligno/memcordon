//! Standard GitHub output records are data, never command text.
use crate::{CiError, Result};
use std::io::Write;

pub fn write(values: &[(&str, String)]) -> Result<()> {
    let path = std::env::var_os("GITHUB_OUTPUT");
    write_to(path.as_deref().map(std::path::Path::new), values)
}

pub fn write_to(path: Option<&std::path::Path>, values: &[(&str, String)]) -> Result<()> {
    let mut records = String::new();
    for (key, value) in values {
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            || value.len() > 1024 * 1024
            || value
                .chars()
                .any(|character| character.is_control() && character != '\n')
        {
            return Err(CiError::Message(
                "workflow output key/value is not safe bounded text".into(),
            ));
        }
        records.push_str(key);
        if value.contains('\n') {
            let mut delimiter = String::from("MEMCORDON_CI_OUTPUT");
            while value.lines().any(|line| line == delimiter) {
                delimiter.push('_');
            }
            records.push_str("<<");
            records.push_str(&delimiter);
            records.push('\n');
            records.push_str(value);
            if !value.ends_with('\n') {
                records.push('\n');
            }
            records.push_str(&delimiter);
            records.push('\n');
        } else {
            records.push('=');
            records.push_str(value);
            records.push('\n');
        }
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
    fn settled(error: &CiError) -> bool {
        match error {
            CiError::SettledCommandFailure(_)
            | CiError::SettledCancellation(_)
            | CiError::NotStartedAfterFailure => true,
            CiError::LaneFailures { primary, secondary } => settled(primary) && settled(secondary),
            _ => false,
        }
    }
    // A real failed exit can retain useful compilation outputs after its sole
    // owner and readers settle. Unknown native cleanup remains ineligible.
    let observation = if result.as_ref().map_or_else(settled, |_| true) {
        "true"
    } else {
        "false"
    };
    if let Err(error) = write(&[("cache-quiescent", observation.into())]) {
        if result.is_ok() {
            return Err(error);
        }
        eprintln!("workflow output collection failed: {error}");
    }
    result
}
