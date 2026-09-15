//! PROV-05 evidence for the two still-active package inspection targets.
//! This route cannot authorize retirement: historical input discovery and native
//! acceptance are separate gates, explicitly retained in every report.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::command::{CommandSpec, git};
use crate::fuzz_targets::{
    Charter, CharterRegistry, CorpusEntry, merge_corpora, preserve_artifacts,
};
use crate::{CiError, Result};

pub const CANONICAL: &str = "agent-package-inspection";
pub const DUPLICATE: &str = "windows-package-inspection";

#[derive(Clone, Debug, Serialize)]
pub struct Inputs {
    pub corpus: Vec<CorpusEntry>,
    pub crashes: Vec<CorpusEntry>,
    pub searched_paths: Vec<PathBuf>,
}

/// Copy reachable inputs into fresh staging directories. Original corpora and
/// crash artifacts are never modified, including when cmin later fails.
pub fn prepare(root: &Path, staging: &Path, targets: [&Charter; 2]) -> Result<Inputs> {
    let bound = targets[0].max_input_bytes;
    if targets[1].max_input_bytes != bound {
        return Err(CiError::Message(
            "package migration input bounds disagree".into(),
        ));
    }
    let mut corpus_sources = Vec::new();
    let mut crash_sources = Vec::new();
    let mut searched_paths = Vec::new();
    for target in targets {
        for candidate in [
            root.join(&target.seed_directory),
            target.corpus_directory(root),
            root.join("fuzz/corpus").join(&target.bin),
        ] {
            searched_paths.push(candidate.clone());
            if candidate.exists() {
                corpus_sources.push(candidate);
            }
        }
        let legacy = root.join("fuzz/artifacts").join(&target.bin);
        searched_paths.push(legacy.clone());
        if legacy.exists() {
            crash_sources.push(legacy);
        }
        // Stable artifact directories also contain evidence.json. Only the
        // content-addressed entries are inputs; reports must not become seeds.
        let stable = target.artifact_directory(root);
        searched_paths.push(stable.clone());
        if stable.exists() {
            for entry in std::fs::read_dir(stable)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let digest_bytes = <sha2::Sha256 as sha2::Digest>::output_size();
                if name.len() == hex::encode(vec![0_u8; digest_bytes]).len()
                    && name.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    crash_sources.push(entry.path());
                }
            }
        }
    }
    let corpus = merge_corpora(&corpus_sources, &staging.join("original-corpus"), bound)?;
    let crashes = merge_corpora(&crash_sources, &staging.join("original-crashes"), bound)?;
    if corpus.is_empty() {
        return Err(CiError::Message(
            "package migration has no corpus inputs".into(),
        ));
    }
    merge_corpora(
        &[
            staging.join("original-corpus"),
            staging.join("original-crashes"),
        ],
        &staging.join("minimized"),
        bound,
    )?;
    Ok(Inputs {
        corpus,
        crashes,
        searched_paths,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct Invocation {
    pub phase: &'static str,
    pub arguments: Vec<OsString>,
    pub input_sha256: Option<String>,
}

pub fn replay(bin: &str, directory: &Path, entry: &CorpusEntry) -> Invocation {
    Invocation {
        phase: "replay",
        arguments: vec![
            "fuzz".into(),
            "run".into(),
            bin.into(),
            directory.join(&entry.sha256).into_os_string(),
            "--".into(),
            "-runs=1".into(),
        ],
        input_sha256: Some(entry.sha256.clone()),
    }
}

pub fn minimize(directory: &Path) -> Invocation {
    Invocation {
        phase: "cmin",
        arguments: vec![
            "fuzz".into(),
            "cmin".into(),
            CANONICAL.into(),
            directory.as_os_str().into(),
        ],
        input_sha256: None,
    }
}

/// Execute the ordered migration proof. The injected native executor lets
/// focused tests prove failure propagation without running a fuzzer locally.
pub fn verify(
    staging: &Path,
    inputs: &Inputs,
    bound: usize,
    mut invoke: impl FnMut(Invocation) -> Result<()>,
) -> Result<Vec<CorpusEntry>> {
    for bin in [CANONICAL, DUPLICATE] {
        invoke(Invocation {
            phase: "build",
            arguments: vec!["fuzz".into(), "build".into(), bin.into()],
            input_sha256: None,
        })?;
        for (directory, entries) in [
            ("original-corpus", &inputs.corpus),
            ("original-crashes", &inputs.crashes),
        ] {
            for entry in entries {
                invoke(replay(bin, &staging.join(directory), entry))?;
            }
        }
    }
    invoke(minimize(&staging.join("minimized")))?;
    let minimized = merge_corpora(
        &[staging.join("minimized")],
        &staging.join("minimized-snapshot"),
        bound,
    )?;
    if minimized.is_empty() {
        return Err(CiError::Message("cmin produced an empty corpus".into()));
    }
    for (directory, entries) in [
        ("minimized-snapshot", &minimized),
        ("original-crashes", &inputs.crashes),
    ] {
        for entry in entries {
            invoke(replay(CANONICAL, &staging.join(directory), entry))?;
        }
    }
    Ok(minimized)
}

#[derive(Serialize)]
struct Stage {
    invocation: Invocation,
    completed: bool,
    failure: Option<String>,
}

#[derive(Serialize)]
struct Evidence {
    schema: u32,
    source_commit: String,
    cargo_fuzz_version: String,
    nightly: String,
    host: String,
    historical_discovery_complete: bool,
    native_acceptance_complete: bool,
    retirement_authorized: bool,
    inputs: Option<Inputs>,
    minimized: Vec<CorpusEntry>,
    generated_artifacts: Vec<CorpusEntry>,
    stages: Vec<Stage>,
    failure: Option<String>,
}

fn write(path: &Path, evidence: &Evidence) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(evidence)?;
    bytes.push(b'\n');
    std::fs::write(path, bytes)?;
    Ok(())
}

fn execute(
    root: &Path,
    nightly: &str,
    executable: &Path,
    report: &Path,
    evidence: &mut Evidence,
    invocation: Invocation,
) -> Result<()> {
    evidence.stages.push(Stage {
        invocation,
        completed: false,
        failure: None,
    });
    write(report, evidence)?;
    let stage = evidence.stages.last_mut().expect("stage was just appended");
    let result = CommandSpec::toolchain_program(
        "rustup",
        root,
        nightly,
        executable,
        Duration::from_secs(5 * 60),
    )
    .args(stage.invocation.arguments.clone())
    .run();
    stage.completed = result.is_ok();
    stage.failure = result.as_ref().err().map(ToString::to_string);
    write(report, evidence)?;
    result.map(|_| ())
}

/// Native CI only. Each file is replayed explicitly: no random mutation run is
/// substituted for replay, and no minimized corpus replaces preserved inputs.
pub fn run(
    root: &Path,
    registry: &CharterRegistry,
    nightly: &str,
    executable: &Path,
    pinned_version: &str,
    host: &str,
) -> Result<()> {
    let find = |bin: &str| {
        registry
            .targets
            .iter()
            .find(|target| target.bin == bin)
            .ok_or_else(|| CiError::Message(format!("migration requires active target {bin}")))
    };
    let canonical = find(CANONICAL)?;
    let duplicate = find(DUPLICATE)?;
    if ![canonical, duplicate]
        .iter()
        .all(|target| target.hosts.iter().any(|value| value == host))
    {
        return Err(CiError::Message(
            "both migration targets must support this host".into(),
        ));
    }
    git(root, ["diff", "--quiet", "HEAD", "--"])?;
    let source_commit = String::from_utf8(git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
    let output = CommandSpec::new(executable, root, Duration::from_secs(30))
        .arg("--version")
        .run()?;
    let version = String::from_utf8(output).map_err(|error| CiError::Message(error.to_string()))?;
    if version.trim().strip_prefix("cargo-fuzz ") != Some(pinned_version) {
        return Err(CiError::Message(
            "measured cargo-fuzz version differs from pinned version".into(),
        ));
    }
    let parent = canonical.artifact_directory(root).join("migration");
    std::fs::create_dir_all(&parent)?;
    // Keep on both success and failure so the ordinary always-upload route
    // retains the exact copied inputs, minimized outputs, and partial evidence.
    let staging = tempfile::Builder::new()
        .prefix("replay-")
        .tempdir_in(parent)?
        .keep();
    let report = staging.join("migration.json");
    let mut evidence = Evidence {
        schema: 1,
        source_commit,
        cargo_fuzz_version: version.trim().into(),
        nightly: nightly.into(),
        host: host.into(),
        historical_discovery_complete: false,
        native_acceptance_complete: false,
        retirement_authorized: false,
        inputs: None,
        minimized: Vec::new(),
        generated_artifacts: Vec::new(),
        stages: Vec::new(),
        failure: None,
    };
    write(&report, &evidence)?;
    let result = (|| -> Result<()> {
        let inputs = prepare(root, &staging, [canonical, duplicate])?;
        evidence.inputs = Some(inputs.clone());
        write(&report, &evidence)?;
        evidence.minimized = verify(&staging, &inputs, canonical.max_input_bytes, |plan| {
            execute(root, nightly, executable, &report, &mut evidence, plan)
        })?;
        Ok(())
    })();
    evidence.failure = result.as_ref().err().map(ToString::to_string);
    let mut preservation_errors = Vec::new();
    for target in [canonical, duplicate] {
        match preserve_artifacts(root, target) {
            Ok(artifacts) => evidence.generated_artifacts.extend(artifacts),
            Err(error) => preservation_errors.push(error.to_string()),
        }
    }
    if !preservation_errors.is_empty() {
        evidence.failure = Some(format!(
            "migration failure: {:?}; artifact preservation failures: {:?}",
            evidence.failure, preservation_errors,
        ));
    }
    write(&report, &evidence)?;
    if !preservation_errors.is_empty() {
        return Err(CiError::Message(
            evidence.failure.expect("preservation failure recorded"),
        ));
    }
    result
}
