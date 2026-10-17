//! Standard GitHub output records are data, never command text.
use crate::{CiError, Result};
use std::io::Write;
use std::sync::Mutex;

// Finite compiler observations only; this does not observe child ownership.
static COMPILATION: Mutex<std::collections::BTreeSet<&'static str>> =
    Mutex::new(std::collections::BTreeSet::new());

/// Actions cache inputs are glob patterns, not native filesystem paths. Keep
/// canonical paths internally, but remove Windows verbatim namespace syntax
/// when presenting an ordinary drive or UNC path to an action.
pub fn action_path(path: &std::path::Path) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| CiError::Message("action path is not UTF-8".into()))?;
    if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
        let mut components = unc.split('\\');
        if !components.next().is_some_and(|value| !value.is_empty())
            || !components.next().is_some_and(|value| !value.is_empty())
        {
            return Err(CiError::Message(
                "action UNC path lacks server or share".into(),
            ));
        }
        return Ok(["//", &unc.replace('\\', "/")].concat());
    }
    if let Some(drive) = value.strip_prefix(r"\\?\") {
        if matches!(drive.as_bytes(), [letter, b':', b'\\', ..] if letter.is_ascii_alphabetic()) {
            return Ok(drive.replace('\\', "/"));
        }
        return Err(CiError::Message(
            "unsupported Windows namespace in action path".into(),
        ));
    }
    Ok(value.to_owned())
}

pub fn action_paths(paths: &[std::path::PathBuf]) -> Result<String> {
    paths
        .iter()
        .map(|path| action_path(path))
        .collect::<Result<Vec<_>>>()
        .map(|paths| paths.join("\n"))
}

pub fn compiled_in_invocation(fact: &str) -> bool {
    COMPILATION
        .lock()
        .expect("compilation facts poisoned")
        .contains(fact)
}

pub fn revoke_compilation(fact: &'static str) -> Result<()> {
    COMPILATION
        .lock()
        .expect("compilation facts poisoned")
        .remove(fact);
    write(&[(fact, "false".into())])
}

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
        append_records(&mut file, records.as_bytes())?;
    }
    Ok(())
}

fn append_records(writer: &mut impl Write, records: &[u8]) -> Result<()> {
    writer.write_all(records)?;
    writer.flush()?;
    Ok(())
}

pub fn quiescent(result: Result<()>) -> Result<()> {
    finalize(crate::work_outcome::WorkOutcome::from_result(result))
}

pub fn finalize(outcome: crate::work_outcome::WorkOutcome<()>) -> Result<()> {
    finalize_with(outcome, crate::download_cache::flush, write)
}

fn finalize_with(
    outcome: crate::work_outcome::WorkOutcome<()>,
    population: impl FnOnce() -> Result<()>,
    mut emit: impl FnMut(&[(&str, String)]) -> Result<()>,
) -> Result<()> {
    let (mut result, writers, facts) = outcome.into_parts();
    // Each group is attempted even if a preceding append failed. Preserve work's
    // original failure; output errors are secondary and never imply population.
    for emission in [
        population(),
        emit(&[("cache-quiescent", writers.permits_reading().to_string())]),
        emit(&facts.outputs()),
    ] {
        if let Err(error) = emission {
            eprintln!("workflow fact emission failed: {error}");
            result = match result {
                Ok(()) => Err(error),
                Err(primary) => Err(CiError::LaneFailures {
                    primary: Box::new(primary),
                    secondary: Box::new(error),
                }),
            };
        }
    }
    result
}

/// Establish a genuine completed compilation boundary before later read-only
/// checks. Callers must revoke the fact before another writer to the same scope.
pub fn compilation_complete(fact: &'static str) -> Result<()> {
    assert!(matches!(
        fact,
        "compiled-native-complete"
            | "compiled-product-complete"
            | "compiled-recipe-complete"
            | "compiled-documentation-complete"
            | "compiled-compiler-complete"
            | "tool-cargo-audit-build-complete"
            | "tool-cargo-deny-build-complete"
            | "tool-cargo-fuzz-build-complete"
            | "tool-cargo-audit-ready"
            | "tool-cargo-deny-ready"
            | "tool-cargo-fuzz-ready"
    ));
    COMPILATION
        .lock()
        .expect("compilation facts poisoned")
        .insert(fact);
    crate::work_outcome::WorkOutcome::from_result(Ok(()))
        .fact(fact)
        .postcondition(write(&[(fact, "true".into())]))
        .into_result()
}

#[cfg(test)]
#[path = "../tests/private/workflow_finalization.rs"]
mod tests;
