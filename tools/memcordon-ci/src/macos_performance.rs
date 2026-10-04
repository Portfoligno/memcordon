//! Collection of the selected, actually executed macOS scheduling form.
use crate::{
    CiError, Result,
    native_results::{NativeTestOutcome, NativeTestReport},
    performance_plan::Layout,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, io::Read, path::Path};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosPhaseReport {
    pub format: String,
    pub revision: u32,
    pub host_os: String,
    pub host_arch: String,
    pub phase: String,
    pub native: NativeTestReport,
}

pub fn require_native_host(root: &Path, stable: &str) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Err(CiError::Message(
            "macOS phase requires a native macOS host".into(),
        ));
    }
    let target = crate::release::distribution::native_target()?;
    let output = crate::command::CommandSpec::toolchain_program(
        "rustup",
        root,
        stable,
        "rustc",
        std::time::Duration::from_secs(60),
    )
    .arg("-vV")
    .output_quiet()?;
    if !output.status.success()
        || !std::str::from_utf8(&output.stdout)
            .ok()
            .is_some_and(|text| {
                text.lines()
                    .any(|line| line.strip_prefix("host: ") == Some(target))
            })
    {
        return Err(CiError::Message(
            "macOS selected compiler host differs from actual native target".into(),
        ));
    }
    Ok(())
}

pub fn validate_phase(
    report: &MacosPhaseReport,
    commit: &str,
    architecture: &str,
    phase: &str,
) -> Result<()> {
    let expected = match phase {
        "native" => crate::native_acceptance_catalogue::MACOS_LIFECYCLE_SCENARIOS
            .iter()
            .chain(crate::native_acceptance_catalogue::MACOS_REMEDIATION_SCENARIOS)
            .copied()
            .collect::<Vec<_>>(),
        "acceptance" => vec![
            "installed_package_execution_probe_and_deadline",
            "installed_package_typed_external_consumer",
        ],
        _ => return Err(CiError::Message("unknown macOS execution phase".into())),
    };
    let native = &report.native;
    if report.format != "memcordon.macos-executed-phase"
        || report.revision != 1
        || report.host_os != "macos"
        || report.host_arch != architecture
        || report.phase != phase
        || native.schema_version != 1
        || native.backend != "macos-watchdog"
        || native.source_commit != commit
        || native.tests_run != expected.len()
        || native.tests_skipped != 0
        || native.tests.len() != expected.len()
        || native.tests.iter().zip(expected).any(|(actual, expected)| {
            actual.name != expected || actual.result != NativeTestOutcome::Passed
        })
    {
        return Err(CiError::Message(
            "macOS actual source, architecture, phase or coverage differs".into(),
        ));
    }
    Ok(())
}

fn read_phase(path: &Path) -> Result<MacosPhaseReport> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > crate::native_results::MAX_REPORT_BYTES {
        return Err(CiError::Message(
            "macOS phase is not a bounded regular report".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(crate::native_results::MAX_REPORT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > crate::native_results::MAX_REPORT_BYTES {
        return Err(CiError::Message("macOS phase exceeded byte bound".into()));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn aggregate(root: &Path, input: &Path, destination: &Path) -> Result<()> {
    let selected = crate::performance_plan::PerformancePlan::read(root)?
        .macos_release
        .selected;
    let expected: &[(&str, &str, &[&str])] = match selected {
        Layout::Serial => &[
            (
                "macos-combined-macos-x64",
                "x86_64",
                &["native", "acceptance"],
            ),
            (
                "macos-combined-macos-arm64",
                "aarch64",
                &["native", "acceptance"],
            ),
        ],
        Layout::Parallel => &[
            ("macos-native-macos-x64", "x86_64", &["native"]),
            ("macos-native-macos-arm64", "aarch64", &["native"]),
            ("macos-acceptance-macos-x64", "x86_64", &["acceptance"]),
            ("macos-acceptance-macos-arm64", "aarch64", &["acceptance"]),
        ],
    };
    let actual = fs::read_dir(input)?
        .map(|entry| {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Err(CiError::Message(
                    "macOS artifact inventory contains a non-directory".into(),
                ));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| CiError::Message("macOS artifact name is not Unicode".into()))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if actual
        != expected
            .iter()
            .map(|(name, _, _)| name.to_string())
            .collect()
    {
        return Err(CiError::Message(
            "macOS selected artifact inventory differs".into(),
        ));
    }
    let commit = crate::release::git::Git::new(root)?.text(["rev-parse", "--verify", "HEAD"])?;
    let mut reports = Vec::new();
    for (artifact, architecture, phases) in expected {
        let directory = input.join(artifact);
        for phase in *phases {
            let filename = match *phase {
                "native" => "release-macos-native.json",
                "acceptance" => "release-macos-acceptance.json",
                _ => unreachable!("finite selected phases"),
            };
            let report = read_phase(&directory.join(filename))?;
            validate_phase(&report, &commit, architecture, phase)?;
            reports.push(report);
        }
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    crate::release::source::write_json(destination, &reports)
}
