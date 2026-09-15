//! Measured subprocess observations. A successful command alone is not test coverage.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use memcordon_core::NativeArgument;
use memcordon_testkit::ObservedOutput;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CiError, Result};

static ACTIVE: Mutex<Option<Journal>> = Mutex::new(None);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub program: NativeArgument,
    pub arguments: Vec<NativeArgument>,
    pub current_directory: Option<NativeArgument>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub toolchain: Option<String>,
    pub invocation: Invocation,
    pub command_sha256: String,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub error: Option<String>,
    pub native_executions: Vec<super::native_runner::BoundExecution>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    commit: String,
    checkout_clean: bool,
    suite: String,
    workflow: Option<String>,
    run_id: Option<String>,
    #[serde(default)]
    run_attempt: Option<String>,
    job: Option<String>,
    runner: Option<String>,
    architecture: String,
    platform: String,
    execution_attested: bool,
    suite_success: bool,
    observations: Vec<Observation>,
    native_invocations: usize,
    #[serde(skip)]
    output: PathBuf,
    #[serde(skip)]
    root: PathBuf,
}

pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn begin(root: &Path, suite: &str) -> Result<()> {
    let checkout_clean =
        crate::command::git(root, ["status", "--porcelain", "--untracked-files=normal"])?
            .is_empty();
    let commit = String::from_utf8(crate::command::git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
    let mut active = ACTIVE
        .lock()
        .map_err(|_| CiError::Message("source observation lock poisoned".into()))?;
    if active.is_some() {
        return Err(CiError::Message(
            "source observation session already active".into(),
        ));
    }
    if suite.is_empty()
        || !suite
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(CiError::Message(
            "invalid source observation suite identity".into(),
        ));
    }
    let directory = root.join("target/ci/source-observations").join(suite);
    std::fs::create_dir_all(&directory)?;
    let session = tempfile::Builder::new()
        .prefix("run-")
        .tempdir_in(directory)?
        .keep();
    *active = Some(Journal {
        schema: 1,
        commit,
        checkout_clean,
        suite: suite.to_owned(),
        workflow: std::env::var("GITHUB_WORKFLOW").ok(),
        run_id: std::env::var("GITHUB_RUN_ID").ok(),
        run_attempt: std::env::var("GITHUB_RUN_ATTEMPT").ok(),
        job: std::env::var("GITHUB_JOB").ok(),
        runner: std::env::var("RUNNER_NAME").ok(),
        architecture: std::env::consts::ARCH.to_owned(),
        platform: std::env::consts::OS.to_owned(),
        execution_attested: false,
        suite_success: false,
        observations: Vec::new(),
        native_invocations: 0,
        root: root.to_owned(),
        output: session.join("source-command-observations-v1.json"),
    });
    Ok(())
}

pub fn native_configuration(
    deadline: std::time::Duration,
) -> Result<Option<super::native_runner::RunnerConfiguration>> {
    let mut active = ACTIVE
        .lock()
        .map_err(|_| CiError::Message("source observation lock poisoned".into()))?;
    let Some(journal) = active.as_mut() else {
        return Ok(None);
    };
    let directory = journal
        .output
        .parent()
        .expect("journal path has parent")
        .join("source-native")
        .join(std::process::id().to_string())
        .join(journal.native_invocations.to_string());
    journal.native_invocations += 1;
    super::native_runner::RunnerConfiguration::create(&journal.root, &directory, deadline).map(Some)
}

pub fn record(
    command: &Command,
    result: std::result::Result<&ObservedOutput, &str>,
    native_directory: Option<&Path>,
    toolchain: Option<&str>,
) -> Result<()> {
    let mut active = ACTIVE
        .lock()
        .map_err(|_| CiError::Message("source observation lock poisoned".into()))?;
    let Some(journal) = active.as_mut() else {
        return Ok(());
    };
    let invocation = Invocation {
        program: NativeArgument::from_os(command.get_program()),
        arguments: command.get_args().map(NativeArgument::from_os).collect(),
        current_directory: command
            .get_current_dir()
            .map(|path| NativeArgument::from_os(path.as_os_str())),
    };
    let command_sha256 = digest(&serde_json::to_vec(&invocation)?);
    let observation = match result {
        Ok(output) => Observation {
            toolchain: toolchain.map(str::to_owned),
            invocation,
            command_sha256,
            stdout_sha256: Some(digest(&output.stdout)),
            stderr_sha256: Some(digest(&output.stderr)),
            exit_code: output.status.code(),
            success: output.status.success(),
            error: None,
            native_executions: native_directory
                .map(|directory| {
                    super::native_runner::bind_artifacts(
                        directory,
                        &output.stdout,
                        output.status.success(),
                    )
                })
                .transpose()?
                .unwrap_or_default(),
        },
        Err(error) => Observation {
            toolchain: toolchain.map(str::to_owned),
            invocation,
            command_sha256,
            stdout_sha256: None,
            stderr_sha256: None,
            exit_code: None,
            success: false,
            error: Some(error.to_owned()),
            native_executions: Vec::new(),
        },
    };
    journal.observations.push(observation);
    persist(journal)
}

fn persist(journal: &Journal) -> Result<()> {
    std::fs::create_dir_all(journal.output.parent().expect("journal path has parent"))?;
    let mut bytes = serde_json::to_vec_pretty(journal)?;
    bytes.push(b'\n');
    std::fs::write(&journal.output, bytes)?;
    Ok(())
}

/// Called after the build-context audit, including on failed suite completion.
pub fn finish(success: bool) -> Result<()> {
    let mut active = ACTIVE
        .lock()
        .map_err(|_| CiError::Message("source observation lock poisoned".into()))?;
    if let Some(mut journal) = active.take() {
        drop(active);
        journal.suite_success = success;
        let unchanged =
            String::from_utf8(crate::command::git(&journal.root, ["rev-parse", "HEAD"])?)
                .map_err(|error| CiError::Message(error.to_string()))?;
        journal.checkout_clean &= unchanged.trim() == journal.commit
            && crate::command::git(
                &journal.root,
                ["status", "--porcelain", "--untracked-files=normal"],
            )?
            .is_empty();
        persist(&journal)?;
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedSource {
    pub source_id: String,
    pub coverage_sha256: String,
    pub tests: std::collections::BTreeSet<String>,
    pub command_sha256: Vec<String>,
    pub binary_sha256: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub schema: u32,
    pub commit: String,
    pub suite: String,
    pub workflow: String,
    pub run_id: String,
    pub run_attempt: String,
    pub job: String,
    pub runner: String,
    pub runner_name: String,
    pub journal_sha256: String,
    pub toolchains: std::collections::BTreeSet<String>,
    pub sources: Vec<AttestedSource>,
    pub conclusion: String,
}

pub fn attest_bytes(plan: &super::coverage::Plan, bytes: &[u8]) -> Result<Attestation> {
    use super::coverage::Evidence;
    let journal: Journal = serde_json::from_slice(bytes)?;
    if plan.schema != 1
        || journal.schema != 1
        || journal.commit != plan.commit
        || journal.suite != plan.suite
        || !journal.suite_success
        || !journal.checkout_clean
    {
        return Err(CiError::Message(
            "source attestation requires a successful matching commit and suite journal".into(),
        ));
    }
    let runner = match (journal.platform.as_str(), journal.architecture.as_str()) {
        ("linux", "x86_64") => "linux-x64",
        ("linux", "aarch64") => "linux-arm64",
        ("macos", "x86_64") => "macos-x64",
        ("macos", "aarch64") => "macos-arm64",
        ("windows", "x86_64") => "windows-x64",
        ("windows", "aarch64") => "windows-arm64",
        _ => {
            return Err(CiError::Message(
                "source attestation runner is unsupported".into(),
            ));
        }
    };
    let required = |value: Option<String>| {
        value.filter(|text| !text.trim().is_empty()).ok_or_else(|| {
            CiError::Message(
                "authoritative source evidence requires hosted workflow/run/job/runner identity"
                    .into(),
            )
        })
    };
    let mut sources = Vec::new();
    let mut toolchains = std::collections::BTreeSet::new();
    for source in &plan.sources {
        if !source
            .route
            .runner
            .iter()
            .any(|declared| declared == runner)
        {
            continue;
        }
        source.route.validate()?;
        if source.route.evidence != Evidence::Behavior {
            return Err(CiError::Message(
                "native execution cannot attest compile or fuzz routes".into(),
            ));
        }
        let (kind, name) =
            source.route.cargo_target.split_once(':').ok_or_else(|| {
                CiError::Message("coverage target must have kind:name form".into())
            })?;
        let mut tests = std::collections::BTreeSet::new();
        let mut listed = std::collections::BTreeSet::new();
        let mut commands = std::collections::BTreeSet::new();
        let mut binaries = std::collections::BTreeSet::new();
        for command in &journal.observations {
            if command.command_sha256 != digest(&serde_json::to_vec(&command.invocation)?) {
                return Err(CiError::Message(
                    "native command digest does not match argv".into(),
                ));
            }
            if !command.success {
                continue;
            }
            for execution in &command.native_executions {
                if execution.package_name != source.route.cargo_package
                    || execution.target_name != name
                    || source.route.test_binary != execution.target_name
                    || !execution
                        .target_kinds
                        .iter()
                        .any(|observed| observed == kind)
                {
                    continue;
                }
                if !execution.execution.success {
                    continue;
                }
                listed.extend(execution.execution.listed_tests.iter().cloned());
                tests.extend(execution.execution.executed_tests.iter().cloned());
                commands.insert(command.command_sha256.clone());
                toolchains.insert(
                    command
                        .toolchain
                        .clone()
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            CiError::Message(
                                "native test execution has no typed toolchain identity".into(),
                            )
                        })?,
                );
                binaries.insert(execution.execution.binary_sha256.clone());
            }
        }
        let expected = source.route.resolve(&listed)?;
        if !expected.is_subset(&tests) {
            return Err(CiError::Message(format!(
                "required native tests did not execute for source {}",
                source.source_id
            )));
        }
        sources.push(AttestedSource {
            source_id: source.source_id.clone(),
            coverage_sha256: digest(&serde_json::to_vec(&source.route)?),
            tests: expected,
            command_sha256: commands.into_iter().collect(),
            binary_sha256: binaries.into_iter().collect(),
        });
    }
    if sources.is_empty() {
        return Err(CiError::Message(
            "no declared source coverage applies to this native runner".into(),
        ));
    }
    Ok(Attestation {
        schema: 1,
        commit: journal.commit,
        suite: journal.suite,
        workflow: required(journal.workflow)?,
        run_id: required(journal.run_id)?,
        run_attempt: required(journal.run_attempt)?,
        job: required(journal.job)?,
        runner: runner.into(),
        runner_name: required(journal.runner)?,
        journal_sha256: digest(bytes),
        toolchains,
        sources,
        conclusion: "success".into(),
    })
}

pub fn write_attestation(plan: &Path, journal: &Path, output: &Path) -> Result<()> {
    let plan = serde_json::from_slice(&std::fs::read(plan)?)?;
    let attestation = attest_bytes(&plan, &std::fs::read(journal)?)?;
    let mut bytes = serde_json::to_vec_pretty(&attestation)?;
    bytes.push(b'\n');
    std::fs::write(output, bytes)?;
    Ok(())
}

/// Merge only the exact declared routes, suites and native runner identities.
pub fn validate_merge(
    commit: &str,
    plans: &[super::coverage::Plan],
    attestations: &[Attestation],
) -> Result<()> {
    use std::collections::BTreeSet;
    let mut required = BTreeSet::new();
    for plan in plans {
        if plan.schema != 1 || plan.commit != commit {
            return Err(CiError::Message(
                "coverage plan does not belong to the candidate commit".into(),
            ));
        }
        for source in &plan.sources {
            source.route.validate()?;
            let route_digest = digest(&serde_json::to_vec(&source.route)?);
            for runner in &source.route.runner {
                required.insert((
                    plan.suite.clone(),
                    runner.clone(),
                    source.source_id.clone(),
                    route_digest.clone(),
                ));
            }
        }
    }
    if required.is_empty() {
        return Err(CiError::Message(
            "coverage merge requires declared source routes".into(),
        ));
    }
    let mut observed = BTreeSet::new();
    for attestation in attestations {
        if attestation.schema != 1
            || attestation.commit != commit
            || attestation.conclusion != "success"
            || [
                &attestation.workflow,
                &attestation.run_id,
                &attestation.run_attempt,
                &attestation.job,
                &attestation.runner_name,
                &attestation.journal_sha256,
            ]
            .iter()
            .any(|value| value.trim().is_empty())
        {
            return Err(CiError::Message(
                "coverage attestation has wrong commit, conclusion or hosted identity".into(),
            ));
        }
        for source in &attestation.sources {
            let key = (
                attestation.suite.clone(),
                attestation.runner.clone(),
                source.source_id.clone(),
                source.coverage_sha256.clone(),
            );
            if !required.contains(&key)
                || source.tests.is_empty()
                || source.command_sha256.is_empty()
                || source.binary_sha256.is_empty()
            {
                return Err(CiError::Message(
                    "unexpected or empty source coverage in attestation".into(),
                ));
            }
            observed.insert(key);
        }
    }
    if observed != required {
        return Err(CiError::Message(
            "required source coverage or native runner attestation is missing".into(),
        ));
    }
    Ok(())
}

pub fn write_merge(
    root: &Path,
    plans: &[PathBuf],
    attestations: &[PathBuf],
    output: &Path,
) -> Result<()> {
    let commit = String::from_utf8(crate::command::git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
    let plans = plans
        .iter()
        .map(|path| Ok(serde_json::from_slice(&std::fs::read(path)?)?))
        .collect::<Result<Vec<super::coverage::Plan>>>()?;
    let attestations = attestations
        .iter()
        .map(|path| Ok(serde_json::from_slice(&std::fs::read(path)?)?))
        .collect::<Result<Vec<Attestation>>>()?;
    validate_merge(&commit, &plans, &attestations)?;
    #[derive(Serialize)]
    struct Merged<'a> {
        schema: u32,
        commit: &'a str,
        plans: &'a [super::coverage::Plan],
        attestations: &'a [Attestation],
        conclusion: &'a str,
    }
    let mut bytes = serde_json::to_vec_pretty(&Merged {
        schema: 1,
        commit: &commit,
        plans: &plans,
        attestations: &attestations,
        conclusion: "success",
    })?;
    bytes.push(b'\n');
    std::fs::write(output, bytes)?;
    Ok(())
}
