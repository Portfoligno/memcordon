use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use crate::command::rustup_cargo;
use crate::{CiError, Result};

pub fn probe(root: &Path, stable: &str, target_dir: &Path, deadline: Duration) -> Result<Value> {
    let arguments = vec![
        OsString::from("run"),
        OsString::from("--target-dir"),
        target_dir.as_os_str().to_os_string(),
        OsString::from("--locked"),
        OsString::from("--package"),
        OsString::from("memcordon"),
        OsString::from("--bin"),
        OsString::from("memcordon"),
        OsString::from("--"),
        OsString::from("probe"),
        OsString::from("--json"),
    ];
    let output = rustup_cargo(root, stable, arguments, deadline).run()?;
    Ok(serde_json::from_slice(&output)?)
}

pub fn selected(probe: &Value) -> Option<&Value> {
    probe.get("selected").filter(|selected| !selected.is_null())
}

pub fn require_selected(probe: &Value) -> Result<&Value> {
    selected(probe).ok_or_else(|| {
        CiError::Message(format!(
            "stress requires a supported backend, but the capability probe reported: {probe}"
        ))
    })
}

pub fn require_single_test_success(output: &[u8], test_name: &str) -> Result<()> {
    let output = String::from_utf8_lossy(output);
    let passed_once = output.lines().any(|line| {
        line.starts_with("test result: ok.")
            && line.contains("1 passed; 0 failed; 0 ignored; 0 measured;")
    });
    if passed_once {
        Ok(())
    } else {
        Err(CiError::Message(format!(
            "exact certification test {test_name} did not report exactly one passing test: {output}"
        )))
    }
}
