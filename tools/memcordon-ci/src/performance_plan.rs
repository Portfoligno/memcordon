//! Optional execution layouts selected from queue-inclusive measurements.
//! These records select performance only; they never authorize runtime work.
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

pub const STRESS_PLATFORMS: &[(&str, &str)] = &[
    ("linux-x64", "ubuntu-24.04"),
    ("macos-arm64", "macos-15"),
    ("macos-x64", "macos-15-intel"),
    ("windows-x64", "windows-2025"),
    ("windows-arm64", "windows-11-arm"),
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layout {
    Serial,
    Parallel,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Warmth {
    Cold,
    Warm,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub category: Warmth,
    pub layout: Layout,
    pub end_to_end_ms: u64,
    pub queue_ms: u64,
    pub bootstrap_ms: u64,
    pub duplicated_bootstrap_ms: u64,
    pub lost_incremental_reuse_ms: u64,
    pub coverage: Vec<String>,
    pub timeouts: u32,
    pub cleanup_failures: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Experiment {
    pub available_categories: Vec<Warmth>,
    pub samples: Vec<Sample>,
}

impl Experiment {
    pub fn supports_parallel(&self) -> Result<bool> {
        if self.available_categories.is_empty()
            || self.available_categories.len() > 2
            || self
                .available_categories
                .iter()
                .enumerate()
                .any(|(index, category)| self.available_categories[..index].contains(category))
        {
            return Err(CiError::Message(
                "measurement categories must be explicit and unique".into(),
            ));
        }
        let expected_count = self.available_categories.len() * 10;
        if self.samples.len() != expected_count {
            return Err(CiError::Message(
                "each available category needs five serial and five parallel runs".into(),
            ));
        }
        let coverage = &self.samples[0].coverage;
        if coverage.is_empty()
            || coverage.iter().collect::<BTreeSet<_>>().len() != coverage.len()
            || self.samples.iter().any(|sample| {
                sample.coverage != *coverage
                    || sample.end_to_end_ms == 0
                    || sample.queue_ms > sample.end_to_end_ms
                    || sample.bootstrap_ms > sample.end_to_end_ms
                    || sample.duplicated_bootstrap_ms > sample.end_to_end_ms
                    || sample.lost_incremental_reuse_ms > sample.end_to_end_ms
                    || !self.available_categories.contains(&sample.category)
            })
        {
            return Err(CiError::Message(
                "measurement coverage or actual timing dimensions differ".into(),
            ));
        }
        let mut improvement = true;
        for category in &self.available_categories {
            let mut durations = Vec::new();
            for layout in [Layout::Serial, Layout::Parallel] {
                let selected: Vec<_> = self
                    .samples
                    .iter()
                    .filter(|sample| sample.category == *category && sample.layout == layout)
                    .collect();
                if selected.len() != 5 {
                    return Err(CiError::Message(
                        "measurement layout cardinality differs".into(),
                    ));
                }
                let mut times: Vec<_> =
                    selected.iter().map(|sample| sample.end_to_end_ms).collect();
                times.sort_unstable();
                let failures = selected
                    .iter()
                    .map(|sample| {
                        (
                            u64::from(sample.timeouts),
                            u64::from(sample.cleanup_failures),
                        )
                    })
                    .fold((0_u64, 0_u64), |sum, next| (sum.0 + next.0, sum.1 + next.1));
                durations.push((
                    times[times.len() / 2],
                    *times.last().expect("five samples"),
                    failures,
                ));
            }
            let serial = durations[0];
            let parallel = durations[1];
            if u128::from(parallel.0) * 100 > u128::from(serial.0) * 90
                || parallel.1 > serial.1
                || parallel.2.0 > serial.2.0
                || parallel.2.1 > serial.2.1
            {
                improvement = false;
            }
        }
        Ok(improvement)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub selected: Layout,
    pub experiment: Option<Experiment>,
}
impl Selection {
    pub fn validate(&self) -> Result<()> {
        if let Some(experiment) = &self.experiment {
            let eligible = experiment.supports_parallel()?;
            if self.selected == Layout::Parallel && !eligible {
                return Err(CiError::Message(
                    "optional parallel layout lacks measured improvement without regressions"
                        .into(),
                ));
            }
        } else if self.selected != Layout::Serial {
            return Err(CiError::Message(
                "serial layout remains selected until comparable measurements exist".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StressSelection {
    pub platform: String,
    pub selected: Layout,
    pub experiment: Option<Experiment>,
}

impl StressSelection {
    /// Layout is a coverage decision; comparative speedup remains advisory.
    pub fn validate_layout(&self) -> Result<()> {
        if let Some(experiment) = &self.experiment {
            experiment.supports_parallel()?;
        }
        Ok(())
    }

    pub fn supports_parallel(&self) -> Result<bool> {
        self.experiment
            .as_ref()
            .map_or(Ok(false), Experiment::supports_parallel)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PerformancePlan {
    pub format: String,
    pub revision: u32,
    pub stress: Vec<StressSelection>,
    pub macos_release: Selection,
    pub preparation: Selection,
    pub quality: Selection,
}
impl PerformancePlan {
    pub fn read(root: &Path) -> Result<Self> {
        let bytes = crate::release::artifacts::read_file(&root.join("ci/performance.toml"))?;
        let plan: Self = toml::from_str(
            std::str::from_utf8(&bytes)
                .map_err(|_| CiError::Message("performance selection is not UTF-8".into()))?,
        )?;
        plan.validate()?;
        Ok(plan)
    }
    pub fn validate(&self) -> Result<()> {
        if self.format != "memcordon.performance-selection"
            || self.revision != 1
            || self.stress.len() != STRESS_PLATFORMS.len()
            || self
                .stress
                .iter()
                .map(|entry| entry.platform.as_str())
                .collect::<BTreeSet<_>>()
                != STRESS_PLATFORMS
                    .iter()
                    .map(|(platform, _)| *platform)
                    .collect()
        {
            return Err(CiError::Message(
                "performance namespace or exact stress platform inventory differs".into(),
            ));
        }
        for entry in &self.stress {
            entry.validate_layout()?;
        }
        for selection in [&self.macos_release, &self.preparation, &self.quality] {
            selection.validate()?;
        }
        Ok(())
    }
    pub fn stress_cells(&self, layout: Layout) -> Result<Vec<serde_json::Value>> {
        self.validate()?;
        Ok(self
            .stress
            .iter()
            .filter(|entry| entry.selected == layout)
            .map(|entry| {
                let runner = STRESS_PLATFORMS
                    .iter()
                    .find(|(platform, _)| *platform == entry.platform)
                    .expect("validated platform")
                    .1;
                serde_json::json!({"id":entry.platform,"runner":runner})
            })
            .collect())
    }
    pub fn emit(&self) -> Result<()> {
        self.validate()?;
        let combined = self.stress_cells(Layout::Serial)?;
        let split = self.stress_cells(Layout::Parallel)?;
        crate::workflow_output::write(&[
            ("stress-combined", serde_json::to_string(&combined)?),
            ("stress-split", serde_json::to_string(&split)?),
            ("stress-has-combined", (!combined.is_empty()).to_string()),
            ("stress-has-split", (!split.is_empty()).to_string()),
            (
                "macos-split",
                (self.macos_release.selected == Layout::Parallel).to_string(),
            ),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StressPhaseObservation {
    pub schema_version: u32,
    pub source_revision: String,
    pub platform: String,
    pub architecture: String,
    pub suite: String,
    pub target_path: String,
    pub planned_package_ordinals: Vec<usize>,
    pub attempted_package_ordinals: Vec<usize>,
    pub completed_package_ordinals: Vec<usize>,
    pub planned_iterations: u64,
    pub executed_iterations: u64,
    pub seed: Option<u64>,
    pub elapsed_millis: u64,
    pub disposition: String,
    pub detail: serde_json::Value,
}

/// An aggregation consumes exactly one completed observation for each selected
/// phase. A Linux capability skip remains an explicit unavailable observation.
pub fn validate_stress_results(
    plan: &PerformancePlan,
    platform: &str,
    source_commit: &str,
    reports: &[StressPhaseObservation],
) -> Result<()> {
    plan.validate()?;
    let selection = plan
        .stress
        .iter()
        .find(|entry| entry.platform == platform)
        .ok_or_else(|| CiError::Message("stress result platform is not selected".into()))?;
    if reports.len() != 2 {
        return Err(CiError::Message(
            "stress result aggregation requires exactly both phases".into(),
        ));
    }
    let (os, architecture) = match platform {
        "linux-x64" => ("linux", "x86_64"),
        "macos-x64" => ("macos", "x86_64"),
        "macos-arm64" => ("macos", "aarch64"),
        "windows-x64" => ("windows", "x86_64"),
        "windows-arm64" => ("windows", "aarch64"),
        _ => return Err(CiError::Message("unsupported stress result host".into())),
    };
    let mut phases = BTreeSet::new();
    for report in reports {
        let target = if selection.selected == Layout::Serial {
            "target/ci/stress"
        } else if report.suite == "packages" {
            "target/ci/stress-packages"
        } else {
            "target/ci/stress-lifecycle"
        };
        if report.schema_version != 1
            || report.source_revision != source_commit
            || report.platform != os
            || report.architecture != architecture
            || report.target_path != target
            || !matches!(report.suite.as_str(), "packages" | "lifecycle")
            || !phases.insert(report.suite.as_str())
        {
            return Err(CiError::Message(
                "stress phase source/host/root/cardinality differs".into(),
            ));
        }
        if report.suite == "packages" {
            let expected: Vec<_> = (0..crate::stress::PACKAGES.len()).collect();
            if report.disposition != "passed"
                || report.planned_package_ordinals != expected
                || report.attempted_package_ordinals != expected
                || report.completed_package_ordinals != expected
                || report.planned_iterations != 0
                || report.executed_iterations != 0
                || report.seed.is_some()
            {
                return Err(CiError::Message(
                    "stress packages did not complete exact coverage".into(),
                ));
            }
        } else {
            if !report.planned_package_ordinals.is_empty()
                || !report.attempted_package_ordinals.is_empty()
                || !report.completed_package_ordinals.is_empty()
                || report.planned_iterations != 4096
                || report.seed.is_none()
            {
                return Err(CiError::Message("stress lifecycle intent differs".into()));
            }
            match report.disposition.as_str() {
                "passed" if report.executed_iterations == report.planned_iterations => (),
                "unavailable-on-linux" if os == "linux" && report.executed_iterations == 0 => (),
                _ => {
                    return Err(CiError::Message(
                        "stress lifecycle incomplete/failed coverage".into(),
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn aggregate_stress(root: &Path, input: &Path, destination: &Path) -> Result<()> {
    let plan = PerformancePlan::read(root)?;
    let commit = crate::release::git::Git::new(root)?.text(["rev-parse", "--verify", "HEAD"])?;
    let expected_artifacts: BTreeSet<_> = plan
        .stress
        .iter()
        .flat_map(|selection| {
            let kinds = if selection.selected == Layout::Serial {
                vec!["combined"]
            } else {
                vec!["packages", "lifecycle"]
            };
            kinds
                .into_iter()
                .map(|kind| format!("stress-{kind}-{}", selection.platform))
                .collect::<Vec<_>>()
        })
        .collect();
    let actual_artifacts: BTreeSet<_> = std::fs::read_dir(input)?
        .map(|entry| {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Err(CiError::Message(
                    "stress artifact root must contain only selected directories".into(),
                ));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| CiError::Message("stress artifact name is not Unicode".into()))
        })
        .collect::<Result<_>>()?;
    if actual_artifacts != expected_artifacts {
        return Err(CiError::Message(
            "stress artifact inventory differs from selected phases".into(),
        ));
    }
    let mut collected = Vec::new();
    for platform in &plan.stress {
        let phase_artifacts: Vec<_> = if platform.selected == Layout::Serial {
            vec![("combined", vec!["packages", "lifecycle"])]
        } else {
            vec![
                ("packages", vec!["packages"]),
                ("lifecycle", vec!["lifecycle"]),
            ]
        };
        let mut reports = Vec::new();
        for (kind, phases) in phase_artifacts {
            let directory = input.join(format!("stress-{kind}-{}", platform.platform));
            if !directory.is_dir() {
                return Err(CiError::Message("selected stress artifact absent".into()));
            }
            let mut candidates =
                std::collections::BTreeMap::<String, Vec<std::path::PathBuf>>::new();
            for (ordinal, entry) in walkdir::WalkDir::new(&directory)
                .follow_links(false)
                .max_depth(8)
                .into_iter()
                .enumerate()
            {
                if ordinal >= 4096 {
                    return Err(CiError::Message(
                        "stress artifact entry bound exceeded".into(),
                    ));
                }
                let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
                if entry.file_type().is_symlink() {
                    return Err(CiError::Message("stress artifact symlink rejected".into()));
                }
                if entry.file_type().is_file() {
                    for phase in &phases {
                        if entry.file_name() == std::ffi::OsStr::new(&format!("{phase}.json")) {
                            candidates
                                .entry((*phase).into())
                                .or_default()
                                .push(entry.path().to_path_buf());
                        }
                    }
                }
            }
            for phase in phases {
                let paths = candidates
                    .get(phase)
                    .filter(|paths| paths.len() == 1)
                    .ok_or_else(|| {
                        CiError::Message("stress phase artifact absent or duplicated".into())
                    })?;
                if std::fs::symlink_metadata(&paths[0])?.len() > 1024 * 1024 {
                    return Err(CiError::Message("stress phase report exceeds bound".into()));
                }
                let bytes = crate::release::artifacts::read_file(&paths[0])?;
                if bytes.len() > 1024 * 1024 {
                    return Err(CiError::Message("stress phase report exceeds bound".into()));
                }
                memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                    .map_err(CiError::Message)?;
                reports.push(serde_json::from_slice::<StressPhaseObservation>(&bytes)?);
            }
        }
        validate_stress_results(&plan, &platform.platform, &commit, &reports)?;
        collected.push(serde_json::json!({"platform":platform.platform,"phases":reports}));
    }
    crate::release::source::write_json(
        destination,
        &serde_json::json!({"format":"memcordon.stress-assessment","revision":1,"source_commit":commit,"results":collected}),
    )
}
