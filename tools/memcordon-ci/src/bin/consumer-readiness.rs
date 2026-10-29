use clap::{Parser, Subcommand};
use memcordon_ci::command::CommandSpec;
use memcordon_ci::consumer_readiness_current::{self as ledger, CellEvidenceV2 as CellEvidence};
use memcordon_ci::readiness_identity::SourceIdentity;
use memcordon_readiness_verifier::{JobOutcome, ProducerOrigin};
use std::{fs, path::PathBuf, process::ExitCode};

fn cleanup_failures(
    status: &memcordon_ci::Result<memcordon_testkit::ObservedOutput>,
    cell: &Result<CellEvidence, String>,
) -> Vec<String> {
    use memcordon_ci::command::bounded_excerpt;
    let mut failures = Vec::new();
    if !status.as_ref().is_ok_and(|output| output.status.success()) {
        failures.push(format!(
            "explicit cleanup command failed: {}",
            command_failure(status)
        ));
    }
    match cell {
        Ok(cell) if cell.cache_quiescent && cell.cleanup_failures.is_empty() => {}
        Ok(cell) => failures.push(format!(
            "selected cell is not settled: cache-quiescent={}; cleanup-failures={:?}",
            cell.cache_quiescent,
            bounded_excerpt(format!("{:?}", cell.cleanup_failures).as_bytes())
        )),
        Err(error) => failures.push(format!(
            "selected cleanup cell could not be read: {}",
            bounded_excerpt(error.as_bytes())
        )),
    }
    failures
}

fn command_failure(result: &memcordon_ci::Result<memcordon_testkit::ObservedOutput>) -> String {
    use memcordon_ci::command::bounded_excerpt;
    match result {
        Ok(output) => format!(
            "status={:?}; capture-complete=true; stdout-bytes={}; stdout={:?}; stderr-bytes={}; stderr={:?}",
            output.status,
            output.stdout.len(),
            bounded_excerpt(&output.stdout),
            output.stderr.len(),
            bounded_excerpt(&output.stderr)
        ),
        Err(error) => format!(
            "observation failed: {}",
            bounded_excerpt(error.to_string().as_bytes())
        ),
    }
}

#[derive(Parser)]
struct Arguments {
    #[command(subcommand)]
    command: Operation,
}
#[derive(Subcommand)]
enum Operation {
    SealProducer {
        #[arg(
            long,
            required_unless_present = "github_context",
            conflicts_with = "github_context"
        )]
        job: Option<String>,
        #[arg(long)]
        identity: PathBuf,
        #[arg(
            long,
            required_unless_present = "github_context",
            conflicts_with = "github_context"
        )]
        run_attempt: Option<u64>,
        #[arg(long)]
        github_context: bool,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        cell: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        acquisition_root: Option<PathBuf>,
        #[cfg(target_os = "linux")]
        #[arg(long, hide = true)]
        privileged_seal_context: Option<String>,
    },
    Identity {
        #[arg(long)]
        build_source: PathBuf,
        #[arg(
            long,
            required_unless_present = "github_context",
            conflicts_with = "github_context"
        )]
        run_id: Option<String>,
        #[arg(long)]
        github_context: bool,
        #[arg(long)]
        output: PathBuf,
    },
    Init {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value = "complete-profile")]
        scope: memcordon_readiness_verifier::VerificationScope,
    },
    Acquire {
        #[arg(long)]
        driver: PathBuf,
        #[arg(
            long,
            required_unless_present = "github_context",
            conflicts_with = "github_context"
        )]
        target: Option<String>,
        #[arg(
            long,
            required_unless_present = "github_context",
            conflicts_with = "github_context"
        )]
        channel: Option<String>,
        #[arg(long)]
        github_context: bool,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    Cleanup {
        #[arg(long)]
        driver: PathBuf,
        #[arg(
            long,
            required_unless_present = "github_context",
            conflicts_with = "github_context"
        )]
        target: Option<String>,
        #[arg(
            long,
            required_unless_present = "github_context",
            conflicts_with = "github_context"
        )]
        channel: Option<String>,
        #[arg(long)]
        github_context: bool,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    Merge {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        cells: Vec<PathBuf>,
        #[arg(long)]
        cells_root: Option<PathBuf>,
        #[arg(long)]
        artifact_root: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        jobs: PathBuf,
        #[arg(long)]
        origins: Vec<PathBuf>,
    },
    CaptureJobOutcomes {
        #[arg(long)]
        job_outcome: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    Gate {
        #[arg(long)]
        verifier: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        artifact_root: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_enum, default_value = "complete-profile")]
        scope: memcordon_readiness_verifier::VerificationScope,
    },
}
fn read<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T, String> {
    use std::io::Read;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    let maximum = 32 * 1024 * 1024;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err("typed readiness input is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err("typed readiness input changed/exceeded bound".into());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
    let value =
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| error.to_string())?;
    serde_json::from_value(value).map_err(|e| e.to_string())
}
fn github_positive_decimal(name: &str) -> Result<String, String> {
    let value =
        std::env::var(name).map_err(|_| format!("native GitHub context {name} absent/non-UTF8"))?;
    if value.len() > 20
        || value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.parse::<u64>().ok().is_none_or(|number| number == 0)
    {
        return Err(format!(
            "native GitHub context {name} must be positive decimal"
        ));
    }
    Ok(value)
}
fn github_producer_context() -> Result<(String, u64, String), String> {
    let run = github_positive_decimal("GITHUB_RUN_ID")?;
    let attempt = github_positive_decimal("GITHUB_RUN_ATTEMPT")?
        .parse::<u64>()
        .map_err(|error| error.to_string())?;
    let job =
        std::env::var("GITHUB_JOB").map_err(|_| "native GitHub job context absent/non-UTF8")?;
    ledger::parse_job_outcomes(&[format!("{job}=success")])?;
    Ok((run, attempt, job))
}
fn selected_cell(
    target: Option<String>,
    channel: Option<String>,
    github_context: bool,
) -> Result<(String, String), String> {
    if !github_context {
        return Ok((
            target.ok_or("selected target missing")?,
            channel.ok_or("selected channel missing")?,
        ));
    }
    let (_, _, job) = github_producer_context()?;
    for (label, target) in [
        ("linux-x64", "x86_64-unknown-linux-gnu"),
        ("linux-arm64", "aarch64-unknown-linux-gnu"),
        ("windows-x64", "x86_64-pc-windows-msvc"),
        ("windows-arm64", "aarch64-pc-windows-msvc"),
    ] {
        for source in ["candidate", "public"] {
            for route in ["native", "cargo"] {
                if job == format!("{source}-{label}-{route}") {
                    return Ok((target.into(), format!("{source}-{route}")));
                }
            }
        }
    }
    Err("native component job cannot acquire an installed product cell".into())
}
fn join_github_identity(path: &std::path::Path, enabled: bool) -> Result<(), String> {
    if enabled && read::<SourceIdentity>(path)?.run_id != github_positive_decimal("GITHUB_RUN_ID")?
    {
        return Err("persisted selected identity differs from native GitHub run".into());
    }
    Ok(())
}
fn acquisition_failed(root: Option<&std::path::Path>) -> Result<bool, String> {
    let Some(root) = root else {
        return Ok(false);
    };
    if !std::fs::symlink_metadata(root)
        .map_err(|error| error.to_string())?
        .is_dir()
    {
        return Err("selected acquisition root is not a real directory".into());
    }
    let acquisition = root
        .join("acquisition-failure.json")
        .try_exists()
        .map_err(|e| e.to_string())?;
    let cleanup = root
        .join("always-cleanup-failure.json")
        .try_exists()
        .map_err(|e| e.to_string())?;
    Ok(acquisition || cleanup)
}

#[cfg(test)]
#[path = "../../tests/private/readiness_seal_projection.rs"]
mod projection_tests;

fn run(operation: Operation) -> Result<(), String> {
    match operation {
        Operation::SealProducer {
            job,
            identity,
            run_attempt,
            github_context,
            manifest,
            cell,
            output,
            acquisition_root,
            #[cfg(target_os = "linux")]
            privileged_seal_context,
        } => {
            // Always-run publication gets one separate finite cutoff. It does
            // not renew acquisition/cleanup, including already expired work.
            #[cfg(target_os = "linux")]
            let parent_publication_deadline =
                if acquisition_root.is_some() && rustix::process::geteuid().as_raw() != 0 {
                    Some(
                        u64::try_from(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map_err(|e| e.to_string())?
                                .as_millis(),
                        )
                        .map_err(|e| e.to_string())?
                        .checked_add(60_000)
                        .ok_or("publication cutoff overflow")?,
                    )
                } else {
                    None
                };
            join_github_identity(&identity, github_context)?;
            let (job, run_attempt) = if github_context {
                let context = github_producer_context()?;
                (context.2, context.1)
            } else {
                (
                    job.ok_or("producer job missing")?,
                    run_attempt.ok_or("producer attempt missing")?,
                )
            };
            use sha2::{Digest, Sha256};
            use std::io::Write;
            ledger::parse_job_outcomes(&[format!("{job}=success")])?;
            if run_attempt == 0 {
                return Err("producer attempt must be positive".into());
            }
            #[cfg(target_os = "linux")]
            let scoped = if let Some(acquisition) = &acquisition_root {
                use memcordon_ci::{
                    preparation_tools as preparation, release::readiness_producer_seal as seal,
                };
                let workspace = std::env::current_dir().map_err(|e| e.to_string())?;
                let acquisition = std::path::absolute(acquisition).map_err(|e| e.to_string())?;
                let cell_path = std::path::absolute(&cell).map_err(|e| e.to_string())?;
                let output_path = std::path::absolute(&output).map_err(|e| e.to_string())?;
                seal::selected_paths(&workspace, &acquisition, &cell_path, &output_path)?;
                if std::path::absolute(&identity).map_err(|e| e.to_string())?
                    != workspace.join(".release/readiness-identity.json")
                    || std::path::absolute(&manifest).map_err(|e| e.to_string())?
                        != workspace.join("ci/consumer-readiness-v2.toml")
                {
                    return Err(
                        "privileged seal inputs differ from fixed selected workspace roles".into(),
                    );
                }
                let identity_bytes = seal::read_input(
                    &workspace,
                    std::path::Path::new(".release/readiness-identity.json"),
                )?;
                memcordon_core::canonical_json::reject_duplicate_json_keys(&identity_bytes)?;
                let selected_identity: SourceIdentity =
                    serde_json::from_slice(&identity_bytes).map_err(|e| e.to_string())?;
                let manifest_bytes = seal::read_input(
                    &workspace,
                    std::path::Path::new("ci/consumer-readiness-v2.toml"),
                )?;
                let context = if rustix::process::geteuid().as_raw() == 0 {
                    let bytes = privileged_seal_context.as_deref().ok_or(
                        "root projection sealing requires resolved original runner context",
                    )?;
                    if bytes.len() > 16 * 1024 {
                        return Err("privileged seal context exceeds bound".into());
                    }
                    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes.as_bytes())?;
                    serde_json::from_str::<seal::Context>(bytes).map_err(|e| e.to_string())?
                } else {
                    if privileged_seal_context.is_some() || !github_context {
                        return Err(
                            "privileged sealing requires original native GitHub context".into()
                        );
                    }
                    let publication_deadline_unix_millis = parent_publication_deadline
                        .ok_or("original runner publication cutoff absent")?;
                    let invocation = preparation::ReadinessHelperContext {
                        repository: std::env::var("GITHUB_REPOSITORY")
                            .map_err(|e| e.to_string())?,
                        workflow: std::env::var("GITHUB_WORKFLOW").map_err(|e| e.to_string())?,
                        run: selected_identity.run_id.clone(),
                        attempt: run_attempt,
                        source_commit: selected_identity.source_commit.clone(),
                        version: selected_identity.version.clone(),
                    };
                    let scope = seal::Scope::open(
                        &workspace,
                        &acquisition,
                        &cell_path,
                        &output_path,
                        rustix::process::geteuid().as_raw(),
                        seal::publication_cutoff(publication_deadline_unix_millis)?,
                    )?;
                    seal::Context {
                        invocation,
                        identity: selected_identity.clone(),
                        job: job.clone(),
                        runner_uid: rustix::process::geteuid().as_raw(),
                        helper_sha256: preparation::running_readiness_helper_digest(&workspace)
                            .map_err(|e| e.to_string())?,
                        cell_sha256: hex::encode(Sha256::digest(scope.cell_bytes())),
                        manifest_sha256: hex::encode(Sha256::digest(&manifest_bytes)),
                        publication_deadline_unix_millis,
                    }
                };
                let deadline = seal::publication_cutoff(context.publication_deadline_unix_millis)?;
                if context.job != job
                    || context.invocation.attempt != run_attempt
                    || context.invocation.run != selected_identity.run_id
                    || context.invocation.source_commit != selected_identity.source_commit
                    || context.invocation.version != selected_identity.version
                    || serde_json::to_value(&context.identity).map_err(|e| e.to_string())?
                        != serde_json::to_value(&selected_identity).map_err(|e| e.to_string())?
                    || context.manifest_sha256 != hex::encode(Sha256::digest(&manifest_bytes))
                {
                    return Err("resolved publication identity/job/manifest differs".into());
                }
                preparation::validate_readiness_helper(
                    &workspace,
                    &context.invocation,
                    &context.helper_sha256,
                )
                .map_err(|e| e.to_string())?;
                let scope = seal::Scope::open(
                    &workspace,
                    &acquisition,
                    &cell_path,
                    &output_path,
                    context.runner_uid,
                    deadline,
                )?;
                if context.cell_sha256 != hex::encode(Sha256::digest(scope.cell_bytes())) {
                    return Err("projected cell changed across privilege boundary".into());
                }
                if rustix::process::geteuid().as_raw() != 0 {
                    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
                    let status =
                        CommandSpec::new("sudo", &workspace, std::time::Duration::from_secs(60))
                            .bounded_until(deadline)
                            .args(["-n", "--"])
                            .arg(executable)
                            .arg("seal-producer")
                            .arg("--job")
                            .arg(&job)
                            .arg("--run-attempt")
                            .arg(run_attempt.to_string())
                            .arg("--identity")
                            .arg(&identity)
                            .arg("--manifest")
                            .arg(&manifest)
                            .arg("--cell")
                            .arg(&cell_path)
                            .arg("--output")
                            .arg(&output_path)
                            .arg("--acquisition-root")
                            .arg(&acquisition)
                            .arg("--privileged-seal-context")
                            .arg(serde_json::to_string(&context).map_err(|e| e.to_string())?)
                            .output();
                    return match status {
                        Ok(output) if output.status.success() => Ok(()),
                        other => Err(format!(
                            "scoped publication failed: {}",
                            command_failure(&other)
                        )),
                    };
                }
                Some((scope, selected_identity, manifest_bytes))
            } else {
                if privileged_seal_context.is_some() {
                    return Err(
                        "privileged publication context lacks acquisition projection".into(),
                    );
                }
                None
            };
            #[cfg(target_os = "linux")]
            let identity = if let Some((_, identity, _)) = &scoped {
                identity.clone()
            } else {
                read::<SourceIdentity>(&identity)?
            };
            #[cfg(not(target_os = "linux"))]
            let identity = read::<SourceIdentity>(&identity)?;
            #[cfg(target_os = "linux")]
            let mut cell = if let Some((scope, _, _)) = &scoped {
                serde_json::from_slice::<CellEvidence>(scope.cell_bytes())
                    .map_err(|e| e.to_string())?
            } else {
                read::<CellEvidence>(&cell)?
            };
            #[cfg(not(target_os = "linux"))]
            let mut cell = read::<CellEvidence>(&cell)?;
            #[cfg(target_os = "linux")]
            let failed = if let Some((scope, _, _)) = &scoped {
                scope.acquisition_failed()?
            } else {
                acquisition_failed(acquisition_root.as_deref())?
            };
            #[cfg(not(target_os = "linux"))]
            let failed = acquisition_failed(acquisition_root.as_deref())?;
            if failed {
                cell.cache_quiescent = false;
                cell.cleanup_failures
                    .push("acquisition wrapper recorded native runner/cleanup failure".into());
            }
            if cell.format != "memcordon.consumer-readiness.cell"
                || cell.revision != 2
                || serde_json::to_value(&cell.identity).map_err(|e| e.to_string())?
                    != serde_json::to_value(&identity).map_err(|e| e.to_string())?
            {
                return Err("producer cell source identity differs".into());
            }
            let target = match cell.key.target.as_str() {
                "x86_64-unknown-linux-gnu" => "linux-x64",
                "aarch64-unknown-linux-gnu" => "linux-arm64",
                "x86_64-pc-windows-msvc" => "windows-x64",
                "aarch64-pc-windows-msvc" => "windows-arm64",
                _ => return Err("unknown producer native target".into()),
            };
            let component = cell.component_build.is_some();
            let expected = if component {
                format!("native-{target}")
            } else {
                let (source, route) = cell
                    .key
                    .channel
                    .split_once('-')
                    .ok_or("producer channel lacks source/route")?;
                format!("{source}-{target}-{route}")
            };
            if expected != job
                || (component && cell.product.is_some())
                || cell.records.iter().any(|record| {
                    record.key.target != cell.key.target
                        || record.run_id != identity.run_id
                        || if component {
                            record.key.channel.is_some()
                        } else {
                            record.key.channel.as_deref() != Some(cell.key.channel.as_str())
                        }
                })
            {
                return Err("producer job mixes another job's product/component rows".into());
            }
            if !cell.cache_quiescent || !cell.cleanup_failures.is_empty() {
                for record in &mut cell.records {
                    record.state = memcordon_readiness_verifier::CaseState::Failed;
                    record.reason = Some(format!(
                        "cleanup/cache quiescence failed: {:?}",
                        cell.cleanup_failures
                    ));
                }
            }
            #[cfg(target_os = "linux")]
            let manifest_bytes = if let Some((_, _, bytes)) = &scoped {
                bytes.clone()
            } else {
                fs::read(&manifest).map_err(|e| e.to_string())?
            };
            #[cfg(not(target_os = "linux"))]
            let manifest_bytes = fs::read(&manifest).map_err(|e| e.to_string())?;
            let sealed = memcordon_readiness_verifier::current::ProducerManifestV2 {
                format: "memcordon.consumer-readiness.producer".into(),
                revision: 2,
                job,
                run_id: identity.run_id,
                run_attempt,
                source_commit: identity.source_commit,
                source_tree_sha256: identity.source_tree_sha256,
                version: identity.version,
                manifest_sha256: hex::encode(Sha256::digest(&manifest_bytes)),
                artifacts: cell.artifacts,
                products: cell.product.into_iter().collect(),
                component_builds: cell.component_build.into_iter().collect(),
                records: cell.records,
            };
            let bytes = serde_json::to_vec_pretty(&sealed).map_err(|e| e.to_string())?;
            #[cfg(target_os = "linux")]
            if let Some((scope, _, _)) = &scoped {
                return scope.publish_packed(&sealed);
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)
                .map_err(|e| e.to_string())?;
            file.write_all(&bytes)
                .and_then(|_| file.write_all(b"\n"))
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        Operation::Identity {
            build_source,
            run_id,
            github_context,
            output,
        } => {
            let run_id = if github_context {
                github_positive_decimal("GITHUB_RUN_ID")?
            } else {
                run_id.ok_or("workflow run id missing")?
            };
            use sha2::{Digest, Sha256};
            use std::io::Write;
            if run_id.parse::<u64>().ok().is_none_or(|value| value == 0)
                || !run_id.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err("selected workflow run id must be positive decimal".into());
            }
            let source = read::<memcordon_ci::release::source::BuildSourceIdentity>(&build_source)?;
            source.validate().map_err(|error| error.to_string())?;
            let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
            let head = CommandSpec::new("git", &cwd, std::time::Duration::from_secs(30))
                .args(["rev-parse", "--verify", "HEAD"])
                .run()
                .map_err(|error| error.to_string())?;
            if std::str::from_utf8(&head)
                .map_err(|error| error.to_string())?
                .trim()
                != source.commit()
            {
                return Err("actual selected Git HEAD differs from build source".into());
            }
            // Fixed tar encoding of the selected commit, not working-tree
            // files or a rewritten source identity. CommandSpec bounds bytes
            // and elapsed time independently of the caller's JSON claims.
            let archived = CommandSpec::new("git", &cwd, std::time::Duration::from_secs(60))
                .args(["archive", "--format=tar", source.commit()])
                .output_limit(memcordon_ci::release::source::MAX_SOURCE_ARCHIVE_BYTES)
                .output_quiet()
                .map_err(|error| error.to_string())?;
            if !archived.status.success() {
                return Err("bounded selected Git archive failed".into());
            }
            let archive = archived.stdout;
            let digest = hex::encode(Sha256::digest(&archive));
            let identity = SourceIdentity {
                run_id: run_id.clone(),
                source_commit: source.commit().into(),
                source_tree_sha256: digest.clone(),
                version: source.version().to_string(),
            };
            let receipt = serde_json::json!({"format":"memcordon.consumer-readiness.source-archive","revision":1,
                "run_id":run_id,"source_commit":source.commit(),"version":source.version(),
                "source_tree_sha256_encoding":"sha256-git-archive-format-tar-selected-commit",
                "source_tree_sha256":digest,"archive_bytes":archive.len()});
            for (path, bytes) in [
                (
                    output.with_extension("source-archive.json"),
                    serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?,
                ),
                (
                    output,
                    serde_json::to_vec_pretty(&identity).map_err(|error| error.to_string())?,
                ),
            ] {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|error| error.to_string())?;
                file.write_all(&bytes)
                    .and_then(|_| file.write_all(b"\n"))
                    .and_then(|_| file.sync_all())
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        }
        Operation::Init {
            manifest,
            identity,
            output,
            scope,
        } => {
            let mut index = ledger::initialize(&manifest, read::<SourceIdentity>(&identity)?)?;
            if scope == memcordon_readiness_verifier::VerificationScope::CandidateBeforePublication
            {
                for row in &mut index.records {
                    if row
                        .key
                        .channel
                        .as_ref()
                        .is_some_and(|c| c.starts_with("public-"))
                    {
                        row.reason = Some("publication-pending".into());
                    }
                }
            }
            ledger::persist(&index, &output)
        }
        Operation::Acquire {
            driver,
            target,
            channel,
            github_context,
            identity,
            destination,
        } => {
            memcordon_ci::workflow_output::write(&[("cache-quiescent", "false".into())])
                .map_err(|error| error.to_string())?;
            join_github_identity(&identity, github_context)?;
            let (target, channel) = selected_cell(target, channel, github_context)?;
            fs::create_dir(&destination).map_err(|e| e.to_string())?;
            let started = std::time::Instant::now();
            let cutoff = started
                .checked_add(std::time::Duration::from_secs(150 * 60))
                .ok_or("installed operation deadline overflow")?;
            let absolute = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .checked_add(std::time::Duration::from_secs(150 * 60))
                .ok_or("absolute installed deadline overflow")?
                .as_millis();
            let absolute = u64::try_from(absolute).map_err(|e| e.to_string())?;
            {
                use std::io::Write;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(destination.join("operation-deadline.json"))
                    .map_err(|e| e.to_string())?;
                file.write_all(&serde_json::to_vec(&absolute).map_err(|e| e.to_string())?)
                    .and_then(|_| file.write_all(b"\n"))
                    .and_then(|_| file.sync_all())
                    .map_err(|e| e.to_string())?;
            }
            let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
            // One driver owns acquisition, installed cases and durable evidence.
            // Its explicit cleanup runs even after spawn/exit failure.
            let acquisition =
                CommandSpec::new(&driver, &cwd, std::time::Duration::from_secs(150 * 60))
                    .bounded_until(cutoff)
                    .arg("consumer-readiness-cell")
                    .arg("--target")
                    .arg(&target)
                    .arg("--channel")
                    .arg(&channel)
                    .arg("--identity")
                    .arg(&identity)
                    .arg("--destination")
                    .arg(&destination)
                    .arg("--operation-deadline-unix-millis")
                    .arg(absolute.to_string())
                    .output();
            let acquisition_failed = !acquisition
                .as_ref()
                .is_ok_and(|observed| observed.status.success());
            let cleanup = CommandSpec::new(&driver, &cwd, std::time::Duration::from_secs(15 * 60))
                .bounded_until(cutoff)
                .arg("consumer-readiness-cleanup")
                .arg("--target")
                .arg(&target)
                .arg("--channel")
                .arg(&channel)
                .arg("--identity")
                .arg(&identity)
                .arg("--destination")
                .arg(&destination)
                .arg("--operation-deadline-unix-millis")
                .arg(absolute.to_string())
                .output();
            let cell: Result<CellEvidence, String> = read(
                &memcordon_ci::release::consumer_readiness_cell::cell_record_path(&destination),
            );
            let mut failures = Vec::new();
            if acquisition_failed {
                failures.push(format!(
                    "actual acquisition/installed runner failed: {}",
                    command_failure(&acquisition)
                ));
            }
            if !cleanup
                .as_ref()
                .is_ok_and(|observed| observed.status.success())
            {
                failures.push(format!(
                    "explicit native recovery/cleanup failed: {}",
                    command_failure(&cleanup)
                ));
            }
            match cell {
                Ok(cell) if cell.cache_quiescent && cell.cleanup_failures.is_empty() => {}
                Ok(_) => failures
                    .push("cell evidence or final cleanup/cache observation absent".to_owned()),
                Err(error) => failures.push(format!(
                    "cell evidence read failed: {}",
                    memcordon_ci::command::bounded_excerpt(error.as_bytes())
                )),
            }
            if failures.is_empty() {
                memcordon_ci::workflow_output::write(&[("cache-quiescent", "true".into())])
                    .map_err(|error| error.to_string())?;
                Ok(())
            } else {
                let original = failures.join("; ");
                fs::write(
                    destination.join("acquisition-failure.json"),
                    serde_json::to_vec(&failures).map_err(|e| e.to_string())?,
                )
                .map_err(|e| format!("{original}; acquisition failure retention failed: {e}"))?;
                Err(original)
            }
        }
        Operation::Cleanup {
            driver,
            target,
            channel,
            github_context,
            identity,
            destination,
        } => {
            memcordon_ci::workflow_output::write(&[("cache-quiescent", "false".into())])
                .map_err(|error| error.to_string())?;
            join_github_identity(&identity, github_context)?;
            let (target, channel) = selected_cell(target, channel, github_context)?;
            let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
            let absolute = read::<u64>(&destination.join("operation-deadline.json"))?;
            let now = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_millis(),
            )
            .map_err(|e| e.to_string())?;
            let remaining = absolute
                .checked_sub(now)
                .filter(|value| *value > 0)
                .ok_or("original installed cleanup deadline expired")?;
            let status = CommandSpec::new(
                driver,
                &cwd,
                std::time::Duration::from_millis(remaining)
                    .min(std::time::Duration::from_secs(15 * 60)),
            )
            .arg("consumer-readiness-cleanup")
            .arg("--target")
            .arg(target)
            .arg("--channel")
            .arg(channel)
            .arg("--identity")
            .arg(identity)
            .arg("--destination")
            .arg(&destination)
            .arg("--operation-deadline-unix-millis")
            .arg(absolute.to_string())
            .output();
            let cell = read::<CellEvidence>(
                &memcordon_ci::release::consumer_readiness_cell::cell_record_path(&destination),
            );
            let failures = cleanup_failures(&status, &cell);
            if failures.is_empty() {
                memcordon_ci::workflow_output::write(&[("cache-quiescent", "true".into())])
                    .map_err(|error| error.to_string())?;
                Ok(())
            } else {
                let failure = format!(
                    "always-run explicit recovery/cleanup failed: {}",
                    failures.join("; ")
                );
                if destination.is_dir() {
                    fs::write(
                        destination.join("always-cleanup-failure.json"),
                        b"{\"cleanup_failed\":true}\n",
                    )
                    .map_err(|error| {
                        format!("{failure}; retaining cleanup failure marker failed: {error}")
                    })?;
                }
                Err(failure)
            }
        }
        Operation::CaptureJobOutcomes {
            job_outcome,
            output,
        } => {
            let outcomes = ledger::parse_job_outcomes(&job_outcome)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .map_err(|error| error.to_string())?;
            use std::io::Write;
            file.write_all(
                &serde_json::to_vec_pretty(&outcomes).map_err(|error| error.to_string())?,
            )
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())
        }
        Operation::Merge {
            plan,
            mut cells,
            cells_root,
            artifact_root,
            output,
            jobs,
            origins,
        } => {
            let plan_value: serde_json::Value = read(&plan)?;
            let (mut index, _) = memcordon_readiness_verifier::current::storage::decode_evidence(
                &serde_json::to_vec(&plan_value).map_err(|e| e.to_string())?,
            )?;
            if !index.artifacts.is_empty() {
                return Err("merge requires an empty acquisition plan, not a previously retained evidence root".into());
            }
            let mut packed = ledger::PackedLedger::default();
            let mut failures = Vec::new();
            if let Err(error) = read::<Vec<JobOutcome>>(&jobs)
                .and_then(|observed| ledger::record_job_outcomes(&mut index, observed))
            {
                failures.push(format!("producer job outcomes: {error}"));
            }
            for origin in origins {
                if let Err(error) = read::<ProducerOrigin>(&origin)
                    .and_then(|observed| ledger::record_origin(&mut index, observed))
                {
                    failures.push(format!("{}: {error}", origin.display()));
                }
            }
            fs::create_dir(&artifact_root).map_err(|e| e.to_string())?;
            if let Some(root) = cells_root {
                match fs::read_dir(&root) {
                    Ok(entries) => {
                        for entry in entries {
                            match entry
                                .and_then(|entry| entry.file_type().map(|kind| (entry, kind)))
                            {
                                Ok((entry, kind)) if kind.is_dir() => cells.push(entry.path()),
                                Ok(_) => {}
                                Err(error) => failures.push(format!("{}: {error}", root.display())),
                            }
                        }
                    }
                    Err(error) => failures.push(format!("{}: {error}", root.display())),
                }
            }
            for directory in cells {
                let result =
                    read::<CellEvidence>(&directory.join("cell.json")).and_then(|mut cell| {
                        let producer_path = directory.join("producer-manifest.json");
                        let storage = match fs::symlink_metadata(&producer_path) {
                            Ok(_) => {
                                let value: serde_json::Value = read(&producer_path)?;
                                let (producer, storage) =
                                    memcordon_readiness_verifier::current::storage::decode_producer(
                                        &serde_json::to_vec(&value).map_err(|e| e.to_string())?,
                                    )?;
                                memcordon_readiness_verifier::current::storage::validate_cell(
                                    &producer,
                                    &serde_json::to_vec(&cell).map_err(|e| e.to_string())?,
                                )?;
                                storage
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                memcordon_readiness_verifier::storage::StoragePlan::direct(
                                    &cell.artifacts,
                                )?
                            }
                            Err(error) => return Err(error.to_string()),
                        };
                        if directory.join("acquisition-failure.json").exists()
                            || directory.join("always-cleanup-failure.json").exists()
                        {
                            cell.cleanup_failures.push(
                                "acquisition wrapper recorded native runner/cleanup failure".into(),
                            );
                        }
                        packed.ingest(&mut index, cell, &directory, &artifact_root, &storage)
                    });
                if let Err(error) = result {
                    failures.push(format!("{}: {error}", directory.display()));
                }
            }
            if failures.len() > 64 || failures.iter().any(|failure| failure.len() > 4096) {
                index
                    .assessment_failures
                    .push("aggregate inputs exceeded bounded failure observations".into());
            } else {
                index.assessment_failures.extend(failures.clone());
            }
            packed.persist(&index, &output, &artifact_root)?;
            if failures.is_empty() {
                Ok(())
            } else {
                Err(failures.join("; "))
            }
        }
        Operation::Gate {
            verifier,
            manifest,
            input,
            artifact_root,
            output,
            scope,
        } => {
            let scope = match scope {
                memcordon_readiness_verifier::VerificationScope::CompleteProfile => {
                    "complete-profile"
                }
                memcordon_readiness_verifier::VerificationScope::CandidateBeforePublication => {
                    "candidate-before-publication"
                }
            };
            let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
            let observed =
                CommandSpec::new(verifier, &cwd, std::time::Duration::from_secs(15 * 60))
                    .arg("verify")
                    .arg("--manifest")
                    .arg(manifest)
                    .arg("--input")
                    .arg(input)
                    .arg("--artifact-root")
                    .arg(artifact_root)
                    .arg("--output")
                    .arg(output)
                    .arg("--scope")
                    .arg(scope)
                    .output()
                    .map_err(|e| e.to_string())?;
            if observed.status.success() {
                Ok(())
            } else {
                Err("independent persisted evidence gate rejected readiness".into())
            }
        }
    }
}
fn main() -> ExitCode {
    match memcordon_ci::public_install_capture::run_if_wrapper() {
        Ok(Some(status)) => memcordon_ci::public_install_capture::exit_wrapper(status),
        Ok(None) => {}
        Err(error) => {
            eprintln!("memcordon-ci compiler capture: {error}");
            return ExitCode::FAILURE;
        }
    }
    match run(Arguments::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("consumer-readiness: {error}");
            ExitCode::FAILURE
        }
    }
}
