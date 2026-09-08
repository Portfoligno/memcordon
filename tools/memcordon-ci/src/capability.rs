use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use memcordon_core::{DOCTOR_REPORT_SCHEMA_VERSION, DoctorReport};
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
        OsString::from("doctor"),
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
            "stress requires a supported backend, but doctor reported: {probe}"
        ))
    })
}

pub fn require_certified_hard_backend(probe: &Value, backend: &str) -> Result<()> {
    let report: DoctorReport = serde_json::from_value(probe.clone())?;
    let selected = report.selected.as_ref().ok_or_else(|| {
        CiError::Message(format!(
            "required backend capability is unavailable: {probe}"
        ))
    })?;
    let hard_memory = selected
        .memory
        .as_ref()
        .is_some_and(|memory| memory.supported && memory.class == "hard");
    if report.schema_version != DOCTOR_REPORT_SCHEMA_VERSION
        || selected.name != backend
        || !selected.containment.supported
        || !hard_memory
    {
        return Err(CiError::Message(format!(
            "required certified hard backend is not selected: {probe}"
        )));
    }
    Ok(())
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

pub fn require_certified_standard_backend(probe: &Value, backend: &str) -> Result<()> {
    require_certified_hard_backend(probe, backend)?;
    let report: DoctorReport = serde_json::from_value(probe.clone())?;
    let selected = report
        .selected
        .expect("hard backend validation requires selection");
    let (mechanism, metric) = match backend {
        "linux-cgroup-v2" => ("gated-cgroup-v2-v1", "linux-cgroup-memory"),
        "windows-job-object" => ("suspended-job-assignment-v1", "windows-job-commit"),
        _ => return Err(CiError::Message("unknown ordinary backend".into())),
    };
    if selected.boundary.class != memcordon_core::BoundaryClass::Standard
        || selected.boundary.mechanism != mechanism
        || !selected.boundary.target_gated
        || !selected.boundary.boundary_verified_before_authorization
        || !selected
            .memory
            .is_some_and(|memory| memory.metric == metric)
    {
        return Err(CiError::Message(
            "doctor did not select the required ordinary execution route".into(),
        ));
    }
    Ok(())
}

/// Strict libtest transcript parser. The caller must also require a successful process exit.
pub fn require_exact_standard_test_success(output: &[u8], test_name: &str) -> Result<()> {
    let invalid = || {
        CiError::Message(format!(
            "exact standard test {test_name} has an invalid libtest transcript"
        ))
    };
    if output.len() > 1024 * 1024 {
        return Err(invalid());
    }
    let output = std::str::from_utf8(output).map_err(|_| invalid())?;
    let mut lines = output.lines().filter(|line| !line.is_empty());
    if lines.next() != Some("running 1 test") {
        return Err(invalid());
    }
    let name = lines
        .next()
        .and_then(|line| line.strip_prefix("test "))
        .and_then(|line| line.strip_suffix(" ... ok"));
    if name != Some(test_name) {
        return Err(invalid());
    }
    let summary = lines
        .next()
        .and_then(|line| line.strip_prefix("test result: ok. "))
        .ok_or_else(invalid)?;
    let (counts, time) = summary.split_once("; finished in ").ok_or_else(invalid)?;
    let fields: Vec<_> = counts.split("; ").collect();
    let expected = [
        (" passed", Some(1_u64)),
        (" failed", Some(0)),
        (" ignored", Some(0)),
        (" measured", Some(0)),
        (" filtered out", None),
    ];
    if fields.len() != expected.len() {
        return Err(invalid());
    }
    for (field, (suffix, required)) in fields.into_iter().zip(expected) {
        let number: u64 = field
            .strip_suffix(suffix)
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        if required.is_some_and(|required| required != number) {
            return Err(invalid());
        }
    }
    let time = time.strip_suffix('s').ok_or_else(invalid)?;
    let seconds: f64 = time.parse().map_err(|_| invalid())?;
    if !seconds.is_finite() || seconds < 0.0 || lines.next().is_some() {
        return Err(invalid());
    }
    Ok(())
}
