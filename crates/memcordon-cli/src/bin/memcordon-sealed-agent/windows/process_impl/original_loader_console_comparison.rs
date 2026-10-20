//! One support-only child; the original failed qualification is never replaced.
use super::*;
use crate::windows::support_loader_diagnostic::Execution;
use memcordon_core::{
    WindowsLoaderCleanupOutcomeV1, WindowsLoaderCleanupStatusV1,
    WindowsLoaderConsoleComparisonOutcomeV1 as Outcome,
    WindowsLoaderConsoleComparisonV1 as Comparison,
};

fn unavailable(baseline: &str, detail: &str) -> Comparison {
    Comparison {
        schema_version: 1,
        baseline_plan_sha256: baseline.into(),
        actual_creation_flags:
            memcordon_windows_launch_core::SupportDetachedConsolePlanV1::CREATION_FLAGS,
        diagnostic_plan_json: None,
        diagnostic_plan_json_sha256: None,
        outcome: Outcome::Unavailable {
            detail: bounded_utf8_detail(detail, 2048),
        },
        cleanup: WindowsLoaderCleanupOutcomeV1 {
            status: WindowsLoaderCleanupStatusV1::NotStarted,
            stable_code: None,
        },
        debug_observation: None,
    }
}

pub(super) fn compare_after_baseline(
    execution: &Execution,
    original: &mut TargetDesktopLeaseCreateError,
    run: impl FnOnce() -> Result<LoaderReadyQualificationV1, TargetDesktopLeaseCreateError>,
) {
    if execution.selection.kind != memcordon_core::WindowsLoaderDiagnosticKindV1::OriginalRestrictedBootstrapConsoleComparison {
        return;
    }
    let Some(memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(failure)) =
        &mut original.loader_qualification
    else {
        return;
    };
    let Some(baseline_debug) = failure.support_debug_observation.as_ref() else {
        return;
    };
    let baseline_digest = baseline_debug.launch_plan_sha256.clone();
    // V2 already selects the consoleless LoaderControl policy. Do not consume
    // the one-shot permit or create a child for an identical alternative.
    if let Some(plan) = failure
        .launch_plan_json
        .as_deref()
        .and_then(|json| {
            serde_json::from_str::<memcordon_windows_launch_core::ProductionLoaderPlanV2>(json).ok()
        })
        .filter(|plan| plan.launch_plan_sha256() == baseline_digest)
    {
        let mut comparison = unavailable(plan.launch_plan_sha256(), "consoleless baseline");
        comparison.outcome = Outcome::NotApplicable {
            baseline_schema_version: 2,
        };
        comparison.actual_creation_flags = 0;
        if let Some(debug) = failure.support_debug_observation.as_mut() {
            debug.console_comparison = Some(Box::new(comparison));
        }
        return;
    }
    let admission = (|| -> Result<(), String> {
        if !failure.admits_detached_console_comparison() {
            return Err("same-session complete 0142 baseline and retirement not proven".into());
        }
        if Instant::now() >= execution.work || Instant::now() >= execution.cleanup {
            return Err("original comparison cutoff expired".into());
        }
        if execution.comparison_started.replace(true) {
            return Err("console comparison already consumed".into());
        }
        let plan: memcordon_windows_launch_core::ProductionLoaderPlanV1 = serde_json::from_str(
            failure
                .launch_plan_json
                .as_deref()
                .ok_or("original baseline plan absent")?,
        )
        .map_err(|error| error.to_string())?;
        if plan.launch_plan_sha256() != baseline_digest {
            return Err("baseline plan binding differs".into());
        }
        *execution.baseline_plan.borrow_mut() = Some(plan);
        Ok(())
    })();
    let comparison = match admission {
        Err(detail) => unavailable(&baseline_digest, &detail),
        Ok(()) => {
            execution.detached_console.set(true);
            let result = run();
            execution.detached_console.set(false);
            execution.active_console_plan.borrow_mut().take();
            execution.comparison.borrow_mut().take().unwrap_or_else(|| {
                unavailable(
                    &baseline_digest,
                    &result.err().map_or_else(
                        || "diagnostic route produced no observation".into(),
                        |error| error.detail,
                    ),
                )
            })
        }
    };
    if let Some(debug) = failure.support_debug_observation.as_mut() {
        debug.console_comparison = Some(Box::new(comparison));
    }
}

pub(super) fn run_variant<const VERSION: u32>(
    execution: &Execution,
    plan: &memcordon_windows_launch_core::ProductionLoaderPlan<VERSION>,
    factory: &PackageLoaderFactory<'_>,
    attestor: &PackageLoaderAttestor<'_>,
    channel: &PackageLoaderChannel<'_>,
) {
    let baseline = execution.baseline_plan.borrow();
    let Some(baseline) = baseline.as_ref() else {
        return;
    };
    let mut observation = unavailable(baseline.launch_plan_sha256(), "comparison not admitted");
    let prepare =
        (|| -> Result<memcordon_windows_launch_core::SupportDetachedConsolePlanV1, String> {
            if !execution.detached_console.get()
                || !execution.comparison_started.get()
                || !channel.launch_context.target_token_restricted
                || channel.launch_context.target_token_write_restricted
                || Instant::now() >= execution.work
            {
                return Err("comparison token, one-shot permit or cutoff differs".into());
            }
            let selected = memcordon_windows_launch_core::SupportDetachedConsolePlanV1::new(
                serde_json::from_value(
                    serde_json::to_value(plan).map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?,
                baseline.launch_plan_sha256().into(),
                execution.selection.challenge.clone(),
            )?;
            selected.validate_baseline(baseline, &execution.selection.challenge)?;
            Ok(selected)
        })();
    let prepared = match prepare {
        Ok(plan) => plan,
        Err(detail) => {
            observation.outcome = Outcome::Unavailable {
                detail: bounded_utf8_detail(&detail, 2048),
            };
            *execution.comparison.borrow_mut() = Some(observation);
            return;
        }
    };
    let json = match serde_json::to_string(&prepared) {
        Ok(value) if value.len() <= 65536 => value,
        _ => {
            *execution.comparison.borrow_mut() = Some(observation);
            return;
        }
    };
    observation.diagnostic_plan_json_sha256 = Some(crate::windows::record::digest(json.as_bytes()));
    observation.diagnostic_plan_json = Some(json);
    // Publish a distinct diagnostic intent before the only native mutation.
    // Existing names are refused; this is not a production plan or authority.
    let intent = (|| -> Result<std::fs::File, String> {
        use std::io::Write;
        if Instant::now() >= execution.work {
            return Err("original comparison cutoff expired before intent".into());
        }
        // Package metadata is deliberately read-only to the restricted
        // launcher. Its existing mutable state root owns this support leaf.
        let path = crate::windows::package::support_console_comparison_intent_path(
            &crate::windows::package::state_root(),
        );
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let security = crate::windows::security::SecurityDescriptor::from_sddl(
            &crate::windows::security::support_console_comparison_intent_sddl()?,
        )?;
        let attributes = security.attributes(false);
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: the path and descriptor remain live for exclusive creation;
        // the returned handle is noninheritable and uniquely owned below.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(format!(
                "support console comparison intent create: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful CREATE_NEW transfers this one file handle to File.
        let mut file = unsafe { std::fs::File::from_raw_handle(handle.cast()) };
        security
            .verify_file_object(file.as_raw_handle().cast())
            .map_err(|error| format!("support console comparison intent security: {error}"))?;
        let bytes = serde_json::to_vec(&serde_json::json!({"diagnostic_only":true,
            "certification_authority":false,"selection":execution.selection,"descriptor":prepared,
            "provider":crate::windows::package::installed_public_provider_binding()
                .map_err(|error| format!("support console comparison intent provider binding: {error}"))?}))
        .map_err(|error| error.to_string())?;
        if bytes.len() > 128 * 1024 {
            return Err("console intent exceeds finite bound".into());
        }
        file.write_all(&bytes)
            .map_err(|error| format!("support console comparison intent write: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("support console comparison intent sync: {error}"))?;
        if Instant::now() >= execution.work {
            return Err("original comparison cutoff expired during intent".into());
        }
        Ok(file)
    })();
    let _intent = match intent {
        Ok(file) => file,
        Err(detail) => {
            observation.outcome = Outcome::Unavailable {
                detail: bounded_utf8_detail(&detail, 2048),
            };
            *execution.comparison.borrow_mut() = Some(observation);
            return;
        }
    };
    *execution.active_console_plan.borrow_mut() = Some(prepared);
    match factory.create(plan) {
        Err(error) => {
            observation.outcome = Outcome::CreationFailure {
                detail: bounded_utf8_detail(&error.detail, 2048),
            }
        }
        Ok(mut process) => {
            let result = (|| -> Result<Outcome, (String, ProcessCreateFailure)> {
                attestor
                    .attest(&process, plan)
                    .map_err(|error| ("suspended-attestation".into(), error))?;
                channel
                    .attest_containment(&process, plan)
                    .map_err(|error| ("containment".into(), error))?;
                channel
                    .resume(&mut process, plan)
                    .map_err(|error| ("resume".into(), error))?;
                match channel.await_ready(&mut process, plan) {
                    Err(error) if error.stable_code == "support-loader-diagnostic-only" => {
                        Ok(Outcome::ReachedHandshake)
                    }
                    Err(error) => Err(("handshake".into(), error)),
                    Ok(_) => Err((
                        "handshake".into(),
                        ProcessCreateFailure {
                            stable_code: "support-console-unexpected-success".into(),
                            native_status: None,
                            detail: "diagnostic channel must refuse production qualification"
                                .into(),
                        },
                    )),
                }
            })();
            // Unconditional cleanup precedes every publication/result path.
            let cleanup = <PackageLoaderFactory<'_> as SuspendedProcessFactory<VERSION>>::cleanup(
                factory,
                &mut process,
            );
            observation.cleanup = WindowsLoaderCleanupOutcomeV1 {
                status: match cleanup.status() {
                    memcordon_windows_launch_core::CleanupStatusV1::Complete => {
                        WindowsLoaderCleanupStatusV1::Complete
                    }
                    memcordon_windows_launch_core::CleanupStatusV1::Failed => {
                        WindowsLoaderCleanupStatusV1::Failed
                    }
                    memcordon_windows_launch_core::CleanupStatusV1::NotStarted => {
                        WindowsLoaderCleanupStatusV1::NotStarted
                    }
                },
                stable_code: cleanup.stable_code().map(str::to_owned),
            };
            observation.debug_observation =
                execution.variant_observation.borrow().clone().map(Box::new);
            observation.outcome = match result {
                Ok(value) => value,
                Err((stage, error)) => Outcome::NativeFailure {
                    stage,
                    detail: bounded_utf8_detail(
                        &format!(
                            "{}: {:?}: {}",
                            error.stable_code, error.native_status, error.detail
                        ),
                        2048,
                    ),
                },
            };
        }
    }
    *execution.comparison.borrow_mut() = Some(observation);
}
