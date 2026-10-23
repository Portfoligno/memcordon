//! Separate actual-image experiment after settled original failure. Never acceptance authority.
#[path = "windows_sddl_text.rs"]
mod sddl_text;
use crate::windows_consumer_readiness::CaseInput;
use crate::windows_installed_cases::InstalledWindowsPayload;
use crate::{CiError, Result};
use memcordon_windows_loader_lab::workload::WorkloadDiagnosticRequestV1;
use std::{
    fs,
    os::windows::io::{AsRawHandle, OwnedHandle},
    path::Path,
    time::{Duration, Instant},
};

fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    drop(crate::windows_readiness_adapter::publish_receipt(
        path, bytes,
    )?);
    crate::windows_readiness_adapter::hold_artifact(
        path,
        Some(&crate::windows_causal_acceptance::sha256(bytes)),
        bytes.len() as u64,
    )?;
    Ok(())
}

pub(super) fn observe(
    config: &InstalledWindowsPayload,
    case: &CaseInput,
    report: &Path,
    public_report: &Path,
    gate_sddl: &str,
    work: Instant,
    cleanup: Instant,
) -> Result<serde_json::Value> {
    let original =
        crate::windows_readiness_adapter::hold_artifact(public_report, None, 4 * 1024 * 1024)?;
    let parsed =
        memcordon_core::result_v1::ResultV1::parse(&original.bytes).map_err(CiError::Message)?;
    if !super::released_target_loader_event_candidate(&parsed)
        || parsed
            .provider_association
            .as_ref()
            .map(|value| &value.provider)
            != Some(&config.provider)
        || case.key.family != "W-ENVELOPE"
        || case.key.scenario != "restricted"
    {
        return Err(CiError::Message(
            "actual-workload diagnostic selection differs".into(),
        ));
    }
    let terminal_path = public_report.with_extension("terminal-observation.json");
    let terminal_file = crate::windows_readiness_adapter::hold_artifact(
        &terminal_path,
        None,
        memcordon_platform::MAX_TERMINAL_OBSERVATION_BYTES as u64,
    )?;
    let terminal: memcordon_platform::AuthenticatedWindowsTerminalObservation =
        serde_json::from_slice(&terminal_file.bytes)?;
    let request: memcordon_core::WindowsLaunchRequestV1 =
        serde_json::from_slice(&terminal.provider_request)?;
    let fixture_path = std::path::absolute(&config.fixture.path)?;
    let image = crate::windows_readiness_adapter::hold_artifact(
        &fixture_path,
        Some(&config.fixture.sha256),
        64 * 1024 * 1024,
    )?;
    use std::os::windows::ffi::OsStrExt;
    if request.command.program != fixture_path.as_os_str().encode_wide().collect::<Vec<_>>()
        || request.command.arguments.get(1)
            != Some(
                &case
                    .descriptor_path
                    .as_os_str()
                    .encode_wide()
                    .collect::<Vec<_>>(),
            )
    {
        return Err(CiError::Message(
            "actual-workload original selected image/descriptor differs".into(),
        ));
    }
    let raw: serde_json::Value = serde_json::from_slice(&original.bytes)?;
    let plan = raw
        .pointer("/attempts/0/boundary_detail/loader_qualification/result/launch_plan_json")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CiError::Message("original object/token reference absent".into()))?;
    let reference_plan = serde_json::from_str(plan)?;
    let root = terminal
        .terminal
        .process_observation
        .root_identity
        .as_ref()
        .ok_or_else(|| CiError::Message("original native target birth absent".into()))?;
    let output = case
        .descriptor
        .output_root
        .with_file_name("restricted-workload-diagnostic");
    fs::create_dir(&output)?; // A new sibling inherits the same candidate-root access policy.
    let descriptor_path = output.join("input.json");
    let original_descriptor = serde_json::to_value(&case.descriptor)?;
    let mut descriptor = original_descriptor.clone();
    let diagnostic_id = crate::windows_causal_acceptance::sha256(&terminal.provider_request);
    descriptor["output_root"] = serde_json::to_value(&output)?;
    descriptor["transcript"] = serde_json::to_value(output.join("fixture-events.bin"))?;
    descriptor["start_gate"] = serde_json::json!(format!(
        "Local\\memcordon-workload-diagnostic-{diagnostic_id}"
    ));
    let descriptor_bytes = serde_json::to_vec(&descriptor)?;
    publish(&descriptor_path, &descriptor_bytes)?;
    let mut command = request.command.clone();
    command.arguments[1] = descriptor_path.as_os_str().encode_wide().collect();
    let now = Instant::now();
    let ticks = uptime();
    let work_remaining = work
        .saturating_duration_since(now)
        .min(Duration::from_secs(30));
    let cleanup_remaining = cleanup
        .saturating_duration_since(now)
        .min(Duration::from_secs(60));
    if work_remaining.is_zero() || cleanup_remaining <= work_remaining {
        return Err(CiError::Message(
            "original cutoff lacks diagnostic work/retirement room".into(),
        ));
    }
    let mut input = WorkloadDiagnosticRequestV1 {
        schema_version: 1,
        original_result_sha256: original.sha256.clone(),
        original_terminal_sha256: terminal_file.sha256.clone(),
        original_result_bytes: original.bytes.clone(),
        original_terminal_bytes: terminal_file.bytes.clone(),
        original_request_bytes: terminal.provider_request,
        original_pid: root.process_id,
        original_birth: root.creation_time_100ns,
        original_request: request,
        reference_plan,
        image_sha256: image.sha256.clone(),
        command,
        original_descriptor_sha256: crate::windows_causal_acceptance::sha256(&serde_json::to_vec(
            &original_descriptor,
        )?),
        descriptor_sha256: crate::windows_causal_acceptance::sha256(&descriptor_bytes),
        original_descriptor,
        descriptor,
        descriptor_path,
        output_directory: output,
        diagnostic_id,
        gate_security_descriptor_sddl: gate_sddl.into(),
        work_deadline_tick_ms: ticks
            .checked_add(work_remaining.as_millis() as u64)
            .ok_or_else(|| CiError::Message("diagnostic cutoff overflow".into()))?,
        cleanup_deadline_tick_ms: ticks
            .checked_add(cleanup_remaining.as_millis() as u64)
            .ok_or_else(|| CiError::Message("diagnostic cleanup cutoff overflow".into()))?,
    };
    input.validate().map_err(CiError::Message)?;
    let request_path = report.with_extension("workload-request.json");
    let workspace = std::env::current_dir()?;
    let source = crate::command::CommandSpec::new("git", &workspace, Duration::from_secs(5))
        .args(["rev-parse", "--verify", "HEAD"])
        .bounded_until(work)
        .defer_group_failure()
        .output_quiet()?;
    if !source.status.success()
        || String::from_utf8_lossy(&source.stdout).trim() != config.source_commit
    {
        return Err(CiError::Message(
            "diagnostic workspace source differs from selected provider".into(),
        ));
    }
    let toolchain = crate::config::toolchains(&workspace)?.stable;
    // Reuse the existing cached native release tree; introduce no separate
    // unvalidated cache or optimization profile for this diagnostic.
    let target = workspace.join("target/ci/native");
    crate::command::rustup_cargo(
        &workspace,
        &toolchain,
        [
            "build",
            "--release",
            "--locked",
            "--offline",
            "-p",
            "memcordon-windows-loader-lab",
            "--bin",
            "memcordon-windows-loader-lab",
            "--target-dir",
        ],
        Duration::from_secs(180),
    )
    .arg(target.as_os_str())
    .bounded_until(work)
    .defer_group_failure()
    .run()?;
    let (executable, held_executable) =
        crate::windows_readiness_adapter::prepare_workload_executable(&target, report)?;
    // Compilation and materialization consume original time; neither can
    // silently renew the caller's deadline or the experiment's finite slice.
    let now = Instant::now();
    let ticks = uptime();
    let work_remaining = work
        .saturating_duration_since(now)
        .min(Duration::from_secs(30));
    let cleanup_remaining = cleanup
        .saturating_duration_since(now)
        .min(Duration::from_secs(60));
    if work_remaining.is_zero() || cleanup_remaining <= work_remaining {
        return Err(CiError::Message(
            "original cutoff expired during diagnostic executable preparation".into(),
        ));
    }
    input.work_deadline_tick_ms = ticks
        .checked_add(work_remaining.as_millis() as u64)
        .ok_or_else(|| CiError::Message("diagnostic work cutoff overflow".into()))?;
    input.cleanup_deadline_tick_ms = ticks
        .checked_add(cleanup_remaining.as_millis() as u64)
        .ok_or_else(|| CiError::Message("diagnostic cleanup cutoff overflow".into()))?;
    input.validate().map_err(CiError::Message)?;
    publish(&request_path, &serde_json::to_vec(&input)?)?;
    let result_path = report.with_extension("workload-observation.json");
    let launched =
        crate::command::CommandSpec::new(&executable, &workspace, Duration::from_secs(60))
            .arg("run-workload")
            .arg("--request")
            .arg(request_path.as_os_str())
            .arg("--result")
            .arg(result_path.as_os_str())
            .bounded_until(cleanup)
            .defer_group_failure()
            .output_quiet();
    crate::windows_readiness_adapter::verify_named_artifact(&held_executable, &executable)?;
    crate::windows_readiness_adapter::verify_named_artifact(&image, &fixture_path)?;
    let observation =
        crate::windows_readiness_adapter::hold_artifact(&result_path, None, 32 * 1024 * 1024)
            .map(|record| serde_json::json!({"path":result_path,"sha256":record.sha256}))
            .map_err(|error| error.to_string());
    Ok(
        serde_json::json!({"authority":"diagnostic-only","original_failure_unchanged":true,
        "source_commit":config.source_commit,"executable_path":executable,"executable_sha256":held_executable.sha256,
        "request":request_path,"observation":observation,"command":launched.map(|output|serde_json::json!({"status":output.status.code()})).map_err(|error|error.to_string()),
        "equivalence":"startup policy with recorded fresh descriptor/objects and debugger/creator differences; never original authority"}),
    )
}

#[allow(unsafe_code)] // Query only the original held event; no name reopen or mutation.
pub(super) fn gate_sddl(gate: &OwnedHandle) -> Result<String> {
    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError},
        Security::{
            GetKernelObjectSecurity, GetSecurityDescriptorControl, GetSecurityDescriptorLength,
            IsValidSecurityDescriptor, SE_SELF_RELATIVE,
        },
    };
    let mut needed = 0;
    let success = unsafe {
        GetKernelObjectSecurity(
            gate.as_raw_handle(),
            0x17,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    let error = unsafe { GetLastError() };
    if success != 0 || error != ERROR_INSUFFICIENT_BUFFER || needed == 0 || needed > 64 * 1024 {
        return Err(CiError::Message(format!(
            "original event descriptor sizing failed: status={error} length={needed}"
        )));
    }
    let capacity = needed;
    let mut buffer = vec![0_u64; (capacity as usize).div_ceil(size_of::<u64>())];
    let pointer = buffer.as_mut_ptr().cast();
    if unsafe {
        GetKernelObjectSecurity(gate.as_raw_handle(), 0x17, pointer, capacity, &mut needed)
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if needed > capacity || unsafe { IsValidSecurityDescriptor(pointer) } == 0 {
        return Err(CiError::Message(
            "original event descriptor invalid or outside allocation".into(),
        ));
    }
    let actual = unsafe { GetSecurityDescriptorLength(pointer) };
    let mut control = 0;
    let mut revision = 0;
    if actual == 0
        || actual > capacity
        || (needed != 0 && actual > needed)
        || unsafe { GetSecurityDescriptorControl(pointer, &mut control, &mut revision) } == 0
        || control & SE_SELF_RELATIVE == 0
    {
        return Err(CiError::Message(
            "original event descriptor actual length differs".into(),
        ));
    }
    // SAFETY: the owned, validated self-relative descriptor remains live here.
    unsafe { sddl_text::from_descriptor(pointer, 0x17) }
        .map(|(text, _, _)| text)
        .map_err(CiError::Message)
}

#[allow(unsafe_code)] // Read only the machine-wide monotonic uptime clock.
fn uptime() -> u64 {
    unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }
}
