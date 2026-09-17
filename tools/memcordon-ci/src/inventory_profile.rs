//! WPR capture on Windows with an isolated instance and bounded-capacity export volume.
use crate::inventory_benchmark::{ScanRequest, Variant, read_json, validate_request};
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePlan {
    pub schema: u32,
    pub scanner: Variant,
    pub wpr: Variant,
    pub request: ScanRequest,
    pub trace_directory: PathBuf,
    pub child_budget_seconds: u64,
}
pub fn validate(plan: &ProfilePlan) -> Result<()> {
    validate_request(&plan.request)?;
    if plan.schema != 1
        || !plan.trace_directory.is_absolute()
        || !plan.scanner.binary.is_absolute()
        || !plan.wpr.binary.is_absolute()
        || !(1..=1800).contains(&plan.child_budget_seconds)
    {
        return Err(CiError::Message("invalid inventory profiling plan".into()));
    }
    Ok(())
}
pub fn profile(plan: &Path, output: &Path, workspace: &Path) -> Result<()> {
    let plan: ProfilePlan = read_json(plan)?;
    validate(&plan)?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let output = parent.canonicalize()?.join(
        output
            .file_name()
            .ok_or_else(|| CiError::Message("profile output needs a directory name".into()))?,
    );
    for root in &plan.request.roots {
        if output.starts_with(root.canonicalize()?) {
            return Err(CiError::Message(
                "profile output must be outside measured roots".into(),
            ));
        }
    }
    std::fs::create_dir(&output)?;
    let result = capture(&plan, &output, workspace);
    let trace_saved = read_json::<serde_json::Value>(&output.join("trace.json")).is_ok();
    let report = serde_json::json!({"schema":1,"trace_saved":trace_saved,"scan_and_capture_succeeded":result.is_ok(),"runtime_qualified":false,"error":result.as_ref().err().map(ToString::to_string),"plan":plan});
    std::fs::write(
        output.join("profile-outcome.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    result
}
#[cfg(not(windows))]
fn capture(_plan: &ProfilePlan, _output: &Path, _workspace: &Path) -> Result<()> {
    Err(CiError::Message(
        "WPR capture requires Windows; no tracing session was started".into(),
    ))
}
#[cfg(windows)]
fn capture(plan: &ProfilePlan, output: &Path, workspace: &Path) -> Result<()> {
    use crate::inventory_benchmark::file_sha256;
    use sha2::{Digest, Sha256};
    use std::ffi::OsString;
    use std::fs;
    use std::process::Command;
    use std::time::Duration;
    for variant in [&plan.scanner, &plan.wpr] {
        if file_sha256(&variant.binary)? != variant.sha256 {
            return Err(CiError::Message(
                "profiling executable identity mismatch".into(),
            ));
        }
    }
    let profile = workspace.join("ci/inventory.wprp");
    if file_sha256(&profile)?
        != hex::encode(Sha256::digest(include_bytes!("../../../ci/inventory.wprp")))
    {
        return Err(CiError::Message(
            "WPR profile differs from compiled recording recipe".into(),
        ));
    }
    let (volume, capacity, available) =
        memcordon_testkit::windows_trace_volume(&plan.trace_directory)?;
    // A dedicated bounded-capacity volume enforces export+temporary storage even if
    // WPR is stalled. Monitoring file growth would not provide a hard bound.
    if capacity > 512 * 1024 * 1024 || available < 96 * 1024 * 1024 {
        return Err(CiError::Message(
            "WPR export requires a dedicated volume of actual capacity <=512 MiB with >=96 MiB available".into(),
        ));
    }
    let workspace_path = workspace.to_path_buf();
    for root in plan
        .request
        .roots
        .iter()
        .chain(std::iter::once(&workspace_path))
    {
        if memcordon_testkit::windows_trace_volume(root)?.0 == volume {
            return Err(CiError::Message(
                "trace export volume must be separate from measured inputs/workspace".into(),
            ));
        }
    }
    if fs::read_dir(&plan.trace_directory)?.next().is_some() {
        return Err(CiError::Message(
            "trace export directory must be empty".into(),
        ));
    }
    let reservations = workspace.join("target/ci/wpr-instances");
    fs::create_dir_all(&reservations)?;
    if fs::read_dir(&reservations)?.take(64).count() >= 64 {
        return Err(CiError::Message(
            "WPR instance reservation limit reached; inspect prior sessions before cleanup".into(),
        ));
    }
    let reservation = tempfile::Builder::new()
        .prefix("memcordon-inventory-")
        .tempdir_in(&reservations)?
        .keep();
    let instance = reservation
        .file_name()
        .expect("reserved instance has a filename")
        .to_os_string();
    fs::write(
        output.join("instance.json"),
        serde_json::to_vec(
            &serde_json::json!({"reservation":reservation,"instance":instance.to_string_lossy()}),
        )?,
    )?;
    let invoke = |args: Vec<OsString>| -> Result<memcordon_testkit::ObservedOutput> {
        let mut command = Command::new(&plan.wpr.binary);
        command
            .current_dir(workspace)
            .args(args)
            .arg("-instancename")
            .arg(&instance);
        Ok(memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            Duration::from_secs(30),
            65536,
        )?)
    };
    // A unique WPR instance cannot attach to or stop another investigation.
    let start = invoke(vec![
        "-start".into(),
        "ci/inventory.wprp!Inventory.Verbose".into(),
        "-recordtempto".into(),
        plan.trace_directory.clone().into_os_string(),
    ]);
    if !matches!(&start,Ok(result) if result.status.success()) {
        let cleanup = invoke(vec!["-cancel".into()]);
        return Err(CiError::Message(format!(
            "WPR start failed; own-instance cleanup observed={}: {:?}",
            cleanup.as_ref().is_ok_and(|result| result.status.success()),
            start.err()
        )));
    }
    let execution = (|| -> Result<bool> {
        fs::write(
            output.join("wpr-start.log"),
            &start.as_ref().expect("successful start").stdout,
        )?;
        let request = output.join("request.json");
        fs::write(&request, serde_json::to_vec(&plan.request)?)?;
        let scan = output.join("scan");
        fs::create_dir(&scan)?;
        let marker = invoke(vec!["-marker".into(), "inventory-start".into()])?;
        if !marker.status.success() {
            return Err(CiError::Message("WPR start marker failed".into()));
        }
        let mut command = Command::new(&plan.scanner.binary);
        command
            .current_dir(workspace)
            .arg("inventory-scan")
            .arg("--request")
            .arg(&request)
            .arg("--report-dir")
            .arg(&scan);
        let result = memcordon_testkit::run_with_deadline_output_limit(
            &mut command,
            Duration::from_secs(plan.child_budget_seconds),
            4 * 1024 * 1024,
        )?;
        fs::write(output.join("scanner-stderr.log"), &result.stderr)?;
        Ok(result.status.success())
    })();
    // Cleanup runs even if scan times out. Only our unique instance is addressed.
    let status = invoke(vec![
        "-status".into(),
        "collectors".into(),
        "-details".into(),
    ]);
    let trace = plan.trace_directory.join("inventory.etl");
    let stop = invoke(vec![
        "-stop".into(),
        trace.clone().into_os_string(),
        "-skipPdbGen".into(),
    ]);
    let saved = matches!(&stop,Ok(result) if result.status.success());
    if !saved {
        let cancel = invoke(vec!["-cancel".into()]);
        fs::write(
            output.join("wpr-cleanup.json"),
            serde_json::to_vec(
                &serde_json::json!({"stop_error":stop.as_ref().err().map(ToString::to_string),"cancel_observed":cancel.as_ref().is_ok_and(|result|result.status.success())}),
            )?,
        )?;
    }
    if !saved {
        return Err(CiError::Message(
            "WPR trace save failed; bounded export may be incomplete".into(),
        ));
    }
    if let Ok(status) = &status {
        fs::write(output.join("wpr-status.log"), &status.stdout)?;
    }
    let metadata = fs::metadata(&trace)?;
    if metadata.len() > 512 * 1024 * 1024 {
        return Err(CiError::Message(
            "WPR export exceeded declared volume budget".into(),
        ));
    }
    fs::write(
        output.join("trace.json"),
        serde_json::to_vec(
            &serde_json::json!({"path":trace,"sha256":file_sha256(&trace)?,"bytes":metadata.len(),"coverage":"rolling_memory_window","buffer_budget_bytes":48*1024*1024,"export_volume_capacity":capacity,"lost_events":"inspect retained wpr-status.log and ETL","profile_sha256":file_sha256(&profile)?}),
        )?,
    )?;
    if !execution? {
        return Err(CiError::Message(
            "inventory failed; WPR evidence retained".into(),
        ));
    }
    if !status?.status.success() {
        return Err(CiError::Message(
            "WPR status failed; trace retained but collector loss evidence is unavailable".into(),
        ));
    }
    Ok(())
}
