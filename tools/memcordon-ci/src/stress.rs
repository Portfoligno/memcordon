use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{CiError, Result, capability, command::rustup_cargo};

pub const PACKAGES: &[&str] = &[
    "memcordon-core",
    "memcordon-windows-launch-core",
    "memcordon-platform",
    "memcordon",
    "memcordon-testkit",
    "memcordon-ci",
    "memcordon-windows-loader-lab",
];

#[derive(Debug, serde::Serialize)]
pub enum LifecycleDisposition {
    Passed,
    UnavailableOnLinux { probe: String },
}

fn evidence(root: &Path, phase: &str, value: &serde_json::Value) -> Result<()> {
    let directory = root.join("target/ci/reports/stress");
    fs::create_dir_all(&directory)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    let output = directory.join(phase).with_extension("json");
    temporary.persist(output).map_err(|error| error.error)?;
    Ok(())
}

fn state(
    root: &Path,
    target: &Path,
    phase: &str,
    completed: usize,
    started: Instant,
    result: &str,
    detail: serde_json::Value,
) -> Result<()> {
    let source_revision = String::from_utf8(crate::command::git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?;
    evidence(
        root,
        phase,
        &serde_json::json!({"schema_version": 1, "source_revision": source_revision.trim(), "platform": std::env::consts::OS, "architecture": std::env::consts::ARCH, "suite": phase, "target_path": target, "planned_package_ordinals": (0..if phase == "packages" { PACKAGES.len() } else { 0 }).collect::<Vec<_>>(), "completed_package_ordinals": (0..completed).collect::<Vec<_>>(), "elapsed_millis": started.elapsed().as_millis(), "disposition": result, "detail": detail}),
    )
}

pub fn packages(root: &Path, stable: &str, target: &Path) -> Result<()> {
    let started = Instant::now();
    state(
        root,
        target,
        "packages",
        0,
        started,
        "incomplete",
        serde_json::Value::Null,
    )?;
    let mut completed = 0;
    let result = (|| {
        for package in PACKAGES {
            fs::write(
                root.join("target/ci/reports/stress-active-target.txt"),
                format!("package={package}\n"),
            )?;
            rustup_cargo(
                root,
                stable,
                [
                    OsString::from("test"),
                    OsString::from("--target-dir"),
                    target.as_os_str().to_owned(),
                    OsString::from("--package"),
                    OsString::from(package),
                    OsString::from("--all-targets"),
                    OsString::from("--all-features"),
                    OsString::from("--locked"),
                    OsString::from("--release"),
                ],
                Duration::from_secs(900),
            )
            .run()?;
            completed += 1;
            state(
                root,
                target,
                "packages",
                completed,
                started,
                "incomplete",
                serde_json::Value::Null,
            )?;
        }
        fs::write(
            root.join("target/ci/reports/stress-active-target.txt"),
            "package-suite=complete\n",
        )?;
        Ok(())
    })();
    finish(root, target, "packages", completed, started, &result)?;
    result
}

fn finish<T>(
    root: &Path,
    target: &Path,
    phase: &str,
    completed: usize,
    started: Instant,
    result: &Result<T>,
) -> Result<()> {
    let detail = result
        .as_ref()
        .err()
        .map(|error| error.to_string().chars().take(8192).collect::<String>());
    let written = state(
        root,
        target,
        phase,
        completed,
        started,
        if result.is_ok() { "passed" } else { "failed" },
        serde_json::json!(detail),
    );
    if result.is_err() {
        if let Err(error) = written {
            eprintln!("stress evidence write failed: {error}");
        }
        Ok(())
    } else {
        written
    }
}

pub fn lifecycle(root: &Path, stable: &str, target: &Path) -> Result<LifecycleDisposition> {
    let started = Instant::now();
    state(
        root,
        target,
        "lifecycle",
        0,
        started,
        "incomplete",
        serde_json::Value::Null,
    )?;
    let reports = root.join("target/ci/reports");
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ u64::from(std::process::id());
    let result = (|| {
        fs::write(reports.join("stress-seed.txt"), format!("{seed}\n"))?;
        let probe = capability::probe(root, stable, target, Duration::from_secs(900))?;
        if cfg!(target_os = "linux") && capability::selected(&probe).is_none() {
            eprintln!(
                "deep backend-dependent stress is unavailable on this runner; mandatory protected backend certification remains authoritative: {probe}"
            );
            return Ok(LifecycleDisposition::UnavailableOnLinux {
                probe: probe.to_string(),
            });
        }
        capability::require_selected(&probe)?;
        rustup_cargo(
            root,
            stable,
            [
                OsString::from("test"),
                OsString::from("--target-dir"),
                target.as_os_str().to_owned(),
                OsString::from("--package"),
                OsString::from("memcordon"),
                OsString::from("--features"),
                OsString::from("test-fixtures"),
                OsString::from("--test"),
                OsString::from("stress"),
                OsString::from("--release"),
                OsString::from("--locked"),
                OsString::from("--"),
                OsString::from("deep_short_children_are_bounded_reaped_and_observed"),
                OsString::from("--ignored"),
                OsString::from("--nocapture"),
                OsString::from("--test-threads=1"),
            ],
            Duration::from_secs(35 * 60),
        )
        .run()?;
        let report: serde_json::Value = serde_json::from_slice(&fs::read(
            reports.join("stress-deep_short_child_iterations.json"),
        )?)?;
        if report.get("seed").and_then(serde_json::Value::as_u64) != Some(seed) {
            return Err(CiError::Message(
                "stress report did not preserve the selected seed".into(),
            ));
        }
        println!("stress seed: {seed} (recorded in the stress report)");
        Ok(LifecycleDisposition::Passed)
    })();
    match &result {
        Ok(disposition) => state(
            root,
            target,
            "lifecycle",
            0,
            started,
            match disposition {
                LifecycleDisposition::Passed => "passed",
                LifecycleDisposition::UnavailableOnLinux { .. } => "unavailable-on-linux",
            },
            serde_json::to_value(disposition)?,
        )?,
        Err(_) => finish(root, target, "lifecycle", 0, started, &result)?,
    }
    result
}

pub fn combined(root: &Path, stable: &str) -> Result<()> {
    let target = Path::new("target/ci/stress");
    packages(root, stable, target)?;
    lifecycle(root, stable, target)?;
    Ok(())
}
