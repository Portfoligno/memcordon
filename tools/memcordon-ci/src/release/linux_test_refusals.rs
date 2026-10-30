//! Actual current request preparation failures under the ordinary caller.
use super::{
    linux_request_fixture::{CallerRequestFixture, CallerSnapshot},
    linux_test_execution::TestInput,
};
use crate::{CiError, Result};
use memcordon_core::{BoundedVec, identifiers::LogicalId, workload_request::PrivateRootLayoutV1};
use std::{
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};
pub(super) fn allocations() -> Result<serde_json::Value> {
    let mut observations = Vec::new();
    for path in [
        "/var/lib/memcordon/workload-attempts",
        "/var/lib/memcordon/workload-inputs",
        "/var/lib/memcordon/workload-resources",
        "/sys/fs/cgroup/memcordon-sealed",
    ] {
        let observed = match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                serde_json::json!({"path":path,"absent":true})
            }
            Err(error) => return Err(error.into()),
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
                    return Err(CiError::Message(
                        "request refusal allocation root custody differs".into(),
                    ));
                }
                let held = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path)?;
                let pinned = held.metadata()?;
                let mut children = fs::read_dir(path)?
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                if children.len() > 1024 {
                    return Err(CiError::Message(
                        "refusal native inventory exceeds bound".into(),
                    ));
                }
                children.sort();
                let after = fs::symlink_metadata(path)?;
                if (pinned.dev(), pinned.ino()) != (after.dev(), after.ino()) {
                    return Err(CiError::Message("native inventory root changed".into()));
                }
                serde_json::json!({"path":path,"device":pinned.dev(),"inode":pinned.ino(),"children":children})
            }
        };
        observations.push(observed);
    }
    Ok(serde_json::Value::Array(observations))
}

pub fn run(mut input: TestInput<'_>) -> Result<()> {
    input.images = input.images.minimal();
    fs::create_dir(input.directory)?;
    fs::set_permissions(input.directory, fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(
        input.directory,
        Some(rustix::process::Uid::from_raw(input.caller.uid)),
        Some(rustix::process::Gid::from_raw(input.caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    let fixture = CallerRequestFixture::pack(
        input.caller,
        input.directory,
        CallerSnapshot {
            manifest: &input.images.runtime,
            manifest_path: &input.images.runtime_manifest,
            source_root: &input.images.runtime_source,
        },
        CallerSnapshot {
            manifest: &input.images.input,
            manifest_path: &input.images.input_manifest,
            source_root: &input.images.input_source,
        },
        LogicalId::new("owned-readiness".into()).map_err(CiError::Message)?,
        PrivateRootLayoutV1 {
            writable_roots: BoundedVec::default(),
            output_files: BoundedVec::default(),
        },
        BoundedVec::default(),
        input.work_cutoff,
    )?;
    let original = fs::read(&fixture.request)?;
    for (_family, scenario) in [
        ("C-ADMISSION", "unsupported-profile"),
        ("C-ADMISSION", "malformed-request"),
        ("C-ADMISSION", "unsupported-format"),
        ("C-ADMISSION", "identity-override-rejected"),
        ("L-VER-01", "unknown-request-variant"),
        ("L-VER-01", "duplicate-request"),
        ("L-VER-01", "result-format-mismatch"),
        ("L-VER-01", "unsupported-provider-version"),
        ("L-VER-01", "corrupted-binding"),
    ] {
        let mut request: serde_json::Value = serde_json::from_slice(&original)?;
        let request = match scenario {
            "unsupported-profile" => {
                request["runtime"]["profile"] = "unsupported-profile".into();
                serde_json::to_vec(&request)?
            }
            "malformed-request" | "duplicate-request" => {
                br#"{"format":"memcordon.workload-request","revision":1,"revision":1}"#.to_vec()
            }
            "unsupported-format" => br#"{"format":"unsupported-request","revision":255}"#.to_vec(),
            "identity-override-rejected" => {
                request["runtime"]["uid"] = 0.into();
                serde_json::to_vec(&request)?
            }
            "unknown-request-variant" => {
                request["runtime"]["kind"] = "unsupported-runtime".into();
                serde_json::to_vec(&request)?
            }
            "result-format-mismatch" | "unsupported-provider-version" | "corrupted-binding" => {
                original.clone()
            }
            _ => unreachable!(),
        };
        let request_path = input.directory.join(format!("{scenario}.request.json"));
        let mut request_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&request_path)?;
        use std::io::Write;
        request_file.write_all(&request)?;
        request_file.sync_all()?;
        let report = input.directory.join(format!("{scenario}.result.json"));
        let before = allocations()?;
        let report_format = if scenario == "result-format-mismatch" {
            "standard"
        } else {
            "result-v3"
        };
        let command = input
            .caller
            .command(input.directory, input.work_cutoff)?
            .args([
                "+128MiB",
                "+10s",
                "--sealed",
                "--report-format",
                report_format,
                "--workload-request",
            ])
            .arg(&request_path)
            .arg("--workload-input")
            .arg(&fixture.bundle)
            .arg("--report")
            .arg(&report)
            .args(["--image-entrypoint", "owned-readiness"])
            .args(["--", "bytes-argv-status", "refusal-no-target", "0"]);
        let provider_negative = matches!(
            scenario,
            "unsupported-provider-version" | "corrupted-binding"
        );
        let observed = if provider_negative {
            super::linux_current_provider_state::with(scenario, || command.output_quiet())?
        } else {
            command.output_quiet()?
        };
        let after = allocations()?;
        let report_absent = matches!(fs::symlink_metadata(&report),Err(error)if error.kind()==std::io::ErrorKind::NotFound);
        let expected_status = if provider_negative { 125 } else { 2 };
        let detail = std::str::from_utf8(&observed.stderr)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let diagnostic = if scenario == "result-format-mismatch" {
            "MCUSAGE-WORKLOAD-REPORT-FORMAT"
        } else {
            "MCUSAGE-WORKLOAD-REQUEST"
        };
        if observed.status.code() != Some(expected_status)
            || before != after
            || !observed.stdout.is_empty()
            || (!provider_negative && (!report_absent || !detail.contains(diagnostic)))
            || provider_negative
                && (detail.contains("MCUSAGE")
                    || !detail.contains(if scenario == "unsupported-provider-version" {
                        "manifest"
                    } else {
                        "component"
                    }))
        {
            return Err(CiError::Message(format!(
                "actual request refusal {scenario} has wrong status/diagnostic or changed native allocations"
            )));
        }
        if provider_negative && !report_absent {
            let result = memcordon_core::result_v3::ResultV3::parse(&fs::read(&report)?)
                .map_err(CiError::Message)?;
            let result = serde_json::to_value(result)?;
            if result["release"] != "not-released"
                || result["runtime"]["kind"] != "preparation-failed"
                || !result["outcome"]["native_termination"].is_null()
                || !result["workload_attempt"].is_null()
            {
                return Err(CiError::Message(
                    "provider descriptor refusal invented an allocated native workload".into(),
                ));
            }
        }
    }
    Ok(())
}
