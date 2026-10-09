//! Independently gathered CI assessment of fixed original producer owners.
//! Publication and operational workload admission never consume this report.
use super::{artifacts, http, readiness_transport, source};
use crate::{
    CiError, Result,
    consumer_readiness_ledger::{self, SourceIdentity},
};
use clap::{Args, ValueEnum};
use memcordon_readiness_verifier::{Artifact, JobOutcome, JobResult};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Scope {
    CandidateBeforePublication,
    CompleteProfile,
}
#[derive(Clone, Debug, Args)]
pub struct ReportArguments {
    #[arg(long)]
    pub identity: PathBuf,
    #[arg(long)]
    pub verifier: PathBuf,
    #[arg(long, value_enum)]
    pub scope: Scope,
    #[arg(long)]
    pub destination: PathBuf,
}
const CANDIDATE: &[&str] = &[
    "native-linux-x64",
    "native-linux-arm64",
    "native-windows-x64",
    "native-windows-arm64",
    "candidate-linux-x64-native",
    "candidate-linux-x64-cargo",
    "candidate-linux-arm64-native",
    "candidate-linux-arm64-cargo",
    "candidate-windows-x64-native",
    "candidate-windows-x64-cargo",
    "candidate-windows-arm64-native",
    "candidate-windows-arm64-cargo",
];
const PUBLIC: &[&str] = &[
    "public-linux-x64-native",
    "public-linux-x64-cargo",
    "public-linux-arm64-native",
    "public-linux-arm64-cargo",
    "public-windows-x64-native",
    "public-windows-x64-cargo",
    "public-windows-arm64-native",
    "public-windows-arm64-cargo",
];
fn positive(name: &str) -> Result<u64> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| CiError::Message(format!("native {name} must be positive decimal")))
}
fn failure(index: &mut memcordon_readiness_verifier::EvidenceIndex, error: impl ToString) {
    if index.assessment_failures.len() < 64 {
        index
            .assessment_failures
            .push(error.to_string().chars().take(4096).collect());
    }
}

pub fn run(root: &Path, args: &ReportArguments) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15 * 60);
    let identity: SourceIdentity = source::read_json(&args.identity)?;
    let current_run = positive("GITHUB_RUN_ID")?;
    let current_attempt = positive("GITHUB_RUN_ATTEMPT")?;
    if identity.run_id != current_run.to_string() {
        return Err(CiError::Message(
            "assessment identity differs from actual current run".into(),
        ));
    }
    let repository = std::env::var("GITHUB_REPOSITORY")
        .map_err(|_| CiError::Message("native repository context absent".into()))?;
    let token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .map_err(|_| CiError::Message("read-only artifact credential absent".into()))?;
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(CiError::Message(
            "artifact read credential malformed".into(),
        ));
    }
    let headers = vec![
        ("Authorization".into(), format!("Bearer {token}")),
        ("User-Agent".into(), "memcordon-ci".into()),
        ("Accept".into(), "application/vnd.github+json".into()),
        ("X-GitHub-Api-Version".into(), "2022-11-28".into()),
    ];
    let manifest = root.join("ci/consumer-readiness-v1.toml");
    let mut index = consumer_readiness_ledger::initialize(&manifest, identity.clone())
        .map_err(CiError::Message)?;
    index.repository = Some(repository.clone());
    if matches!(args.scope, Scope::CandidateBeforePublication) {
        for row in &mut index.records {
            if row
                .key
                .channel
                .as_deref()
                .is_some_and(|channel| channel.starts_with("public-"))
            {
                row.reason = Some("publication-pending".into());
            }
        }
    }
    fs::create_dir(&args.destination)?;
    let custody = args.destination.join("artifacts");
    fs::create_dir(&custody)?;
    let budget = http::ReadBudget::new(deadline);
    let transport = http::HttpsTransport;
    let mut original = (current_run, current_attempt);
    if matches!(args.scope, Scope::CompleteProfile)
        && std::env::var("GITHUB_EVENT_NAME").ok().as_deref() == Some("workflow_dispatch")
    {
        let event = (|| -> Result<_> {
            let path = std::env::var_os("GITHUB_EVENT_PATH")
                .ok_or_else(|| CiError::Message("native event path absent".into()))?;
            let bytes = artifacts::read_file(Path::new(&path))?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                .map_err(CiError::Message)?;
            let document: serde_json::Value = serde_json::from_slice(&bytes)?;
            if document["inputs"]["recovery-mode"].as_str() != Some("publication-only") {
                return Ok(None);
            }
            super::recovery::parse_event(&bytes).map(Some)
        })();
        match event {
            Ok(Some(event)) => {
                if let Some(locator) = event.original {
                    let selected =
                        super::bundle::PreparedBundle::load(&root.join(".release/prepared"))?
                            .metadata
                            .source;
                    if selected.commit != identity.source_commit
                        || selected.version.to_string() != identity.version
                        || selected.repository != repository
                    {
                        return Err(CiError::Message(
                            "original prepared source differs from assessment".into(),
                        ));
                    }
                    match super::recovery::validate_original(
                        &transport, &budget, &headers, &selected, &locator,
                    )
                    .and_then(|()| {
                        readiness_transport::original_preparation_attempt(
                            &transport,
                            &budget,
                            &headers,
                            &repository,
                            locator.run_id,
                            locator.prepared_artifact_id,
                        )
                    }) {
                        Ok(attempt) => original = (locator.run_id, attempt),
                        Err(error) => failure(&mut index, error),
                    }
                }
            }
            Ok(None) => (),
            Err(error) => failure(&mut index, error),
        }
    }
    let groups = if matches!(args.scope, Scope::CompleteProfile) {
        vec![
            (CANDIDATE, original),
            (PUBLIC, (current_run, current_attempt)),
        ]
    } else {
        vec![(CANDIDATE, original)]
    };
    let mut outcomes = Vec::new();
    for (jobs, (run, attempt)) in groups {
        match readiness_transport::job_outcomes(
            &transport,
            &budget,
            &headers,
            &repository,
            run,
            attempt,
            jobs,
        ) {
            Ok(observed) => outcomes.extend(observed),
            Err(error) => {
                failure(&mut index, error);
                outcomes.extend(jobs.iter().map(|job| JobOutcome {
                    job: (*job).into(),
                    result: JobResult::Missing,
                }));
            }
        }
        for job in jobs {
            let acquired = (|| -> Result<_> {
                let id = readiness_transport::producer_artifact_id(
                    &transport,
                    &budget,
                    &headers,
                    &repository,
                    run,
                    attempt,
                    job,
                )?;
                let mut source = identity.clone();
                source.run_id = run.to_string();
                readiness_transport::download_producer(
                    &transport,
                    &budget,
                    &headers,
                    &repository,
                    run,
                    attempt,
                    id,
                    job,
                    &source,
                    &index.manifest_sha256,
                    &args.destination.join(format!("producer-{job}")),
                )
            })();
            match acquired {
                Err(error) => failure(&mut index, error),
                Ok(mut producer) => {
                    let result = (|| -> Result<()> {
                        consumer_readiness_ledger::ingest(
                            &mut index,
                            producer.cell,
                            &producer.directory,
                            &custody,
                        )
                        .map_err(CiError::Message)?;
                        let relative = format!("origins/{job}/{}", producer.archive.path);
                        let path = custody.join(&relative);
                        fs::create_dir_all(path.parent().expect("origin parent"))?;
                        let bytes =
                            artifacts::read_file(&producer.directory.join(&producer.archive.path))?;
                        let mut file = fs::OpenOptions::new()
                            .create_new(true)
                            .write(true)
                            .open(&path)?;
                        file.write_all(&bytes)?;
                        file.sync_all()?;
                        fs::File::open(path.parent().expect("origin parent"))?.sync_all()?;
                        producer.origin.bundle_artifact = relative.clone();
                        index.artifacts.push(Artifact {
                            path: relative,
                            ..producer.archive
                        });
                        consumer_readiness_ledger::record_origin(&mut index, producer.origin)
                            .map_err(CiError::Message)
                    })();
                    if let Err(error) = result {
                        failure(&mut index, error);
                    }
                }
            }
        }
    }
    consumer_readiness_ledger::record_job_outcomes(&mut index, outcomes)
        .map_err(CiError::Message)?;
    let evidence = args.destination.join("evidence.json");
    source::write_json(&evidence, &index)?;
    let scope = match args.scope {
        Scope::CandidateBeforePublication => "candidate-before-publication",
        Scope::CompleteProfile => "complete-profile",
    };
    crate::command::CommandSpec::new(&args.verifier, root, Duration::from_secs(15 * 60))
        .arg("verify")
        .arg("--manifest")
        .arg(manifest)
        .arg("--input")
        .arg(evidence)
        .arg("--artifact-root")
        .arg(custody)
        .arg("--scope")
        .arg(scope)
        .arg("--output")
        .arg(args.destination.join("verdict.json"))
        .bounded_until(deadline)
        .run()
        .map(|_| ())
}
