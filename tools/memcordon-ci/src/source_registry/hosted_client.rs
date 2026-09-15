//! Read-only GitHub collection. Metadata comes from the API, never the ZIP payload.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::coverage::Plan;
use super::hosted::{
    self, Admission, Artifact, ExpectedLane, ExpectedRun, HostedArchive, Job, WorkflowRun,
};
use super::observation::Attestation;
use crate::{CiError, Result};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lanes {
    schema: u32,
    lane: Vec<Lane>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lane {
    pub suite: String,
    pub workflow: String,
    pub job: String,
    pub matrix: String,
    pub runner: String,
}

pub struct LaneIdentity {
    pub job_name: String,
    pub runner_label: String,
    pub artifact_name: String,
}

pub fn validate_lane_coverage(lanes: &[Lane], sources: &[super::Source]) -> Result<()> {
    let mut declared = BTreeSet::new();
    for lane in lanes {
        let file = lane.workflow.strip_prefix(".github/workflows/");
        if file.is_none_or(|file| {
            file.is_empty() || file.contains('/') || file.contains('\\') || !file.ends_with(".yml")
        }) || lane.job.is_empty()
            || lane.matrix.is_empty()
            || !declared.insert((lane.suite.clone(), lane.runner.clone()))
        {
            return Err(CiError::Message(
                "source execution lanes are unsafe, empty or duplicated".into(),
            ));
        }
    }
    let required = sources
        .iter()
        .flat_map(|source| &source.coverage)
        .flat_map(|route| {
            route
                .runner
                .iter()
                .map(|runner| (route.suite.clone(), runner.clone()))
        })
        .collect::<BTreeSet<_>>();
    if required.is_empty() || declared != required {
        return Err(CiError::Message(
            "source execution lane inventory differs from declared coverage".into(),
        ));
    }
    Ok(())
}

/// Resolve the actual checked-in workflow matrix, including artifact index.
pub fn resolve_lane(lane: &Lane, workflow: &str) -> Result<LaneIdentity> {
    let fail = || CiError::Message("source lane does not match its workflow matrix".into());
    let value: serde_yaml::Value = serde_yaml::from_str(workflow)?;
    let job = &value["jobs"][lane.job.as_str()];
    let executes_suite = job["steps"].as_sequence().is_some_and(|steps| {
        steps.iter().any(|step| {
            step["run"].as_str().is_some_and(|run| {
                run.split_whitespace()
                    .collect::<Vec<_>>()
                    .windows(2)
                    .any(|pair| pair == ["suite", lane.suite.as_str()])
            })
        })
    });
    if !executes_suite {
        return Err(fail());
    }
    if job["runs-on"].as_str() != Some("${{ matrix.runner }}") {
        return Err(fail());
    }
    let matrix = job["strategy"]["matrix"]["include"]
        .as_sequence()
        .ok_or_else(fail)?;
    let matches = matrix
        .iter()
        .enumerate()
        .filter(|(_, row)| row["id"].as_str() == Some(lane.matrix.as_str()))
        .collect::<Vec<_>>();
    let [(index, row)] = matches.as_slice() else {
        return Err(fail());
    };
    let name = job["name"].as_str().ok_or_else(fail)?;
    let job_name = name.replace("${{ matrix.id }}", &lane.matrix);
    let runner_label = row["runner"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(fail)?
        .to_owned();
    if job_name.contains("${{") || runner_label.contains("${{") {
        return Err(fail());
    }
    Ok(LaneIdentity {
        job_name,
        runner_label,
        artifact_name: format!("source-observations-{}-{index}", lane.job),
    })
}

struct Client {
    agent: ureq::Agent,
    repository: String,
    api_version: String,
    token: String,
    maximum_bytes: u64,
}

impl Client {
    fn new(root: &Path) -> Result<Self> {
        let config = crate::config::release(root)?;
        let parts = config.repository.split('/').collect::<Vec<_>>();
        if parts.len() != 2
            || parts.iter().any(|part| {
                part.is_empty()
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
            })
        {
            return Err(CiError::Message(
                "invalid GitHub repository identity".into(),
            ));
        }
        let token = std::env::var("GITHUB_TOKEN")
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CiError::Message(
                    "source evidence collection requires GITHUB_TOKEN with actions:read".into(),
                )
            })?;
        Ok(Self {
            agent: ureq::Agent::config_builder()
                .https_only(true)
                .redirect_auth_headers(ureq::config::RedirectAuthHeaders::Never)
                .timeout_connect(Some(Duration::from_secs(15)))
                .timeout_recv_response(Some(Duration::from_secs(60)))
                .timeout_recv_body(Some(Duration::from_secs(60)))
                .build()
                .new_agent(),
            repository: config.repository,
            api_version: config.github_api_version,
            token,
            maximum_bytes: config.maximum_asset_bytes,
        })
    }

    fn bytes(&self, endpoint: &str) -> Result<Vec<u8>> {
        let url = format!(
            "https://api.github.com/repos/{}/actions/{endpoint}",
            self.repository
        );
        let mut response = self
            .agent
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", &self.api_version)
            .header("User-Agent", "memcordon-ci-source-evidence")
            .header("Authorization", format!("Bearer {}", self.token))
            .call()
            .map_err(Box::new)?;
        let mut bytes = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(
                self.maximum_bytes.checked_add(1).ok_or_else(|| {
                    CiError::Message("source evidence byte limit overflow".into())
                })?,
            )
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len())
            .ok()
            .is_none_or(|size| size > self.maximum_bytes)
        {
            return Err(CiError::Message(
                "source evidence response exceeds configured asset limit".into(),
            ));
        }
        Ok(bytes)
    }

    fn json<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
        Ok(serde_json::from_slice(&self.bytes(endpoint)?)?)
    }

    fn inventory<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        field: &str,
    ) -> Result<Vec<T>> {
        let mut values = Vec::new();
        let mut expected = None;
        let mut ids = BTreeSet::new();
        for page in 1..=100 {
            let value: serde_json::Value =
                self.json(&format!("{endpoint}?per_page=100&page={page}"))?;
            let total = value["total_count"]
                .as_u64()
                .ok_or_else(|| CiError::Message("GitHub inventory lacks total_count".into()))?;
            if expected.replace(total).is_some_and(|prior| prior != total) {
                return Err(CiError::Message(
                    "GitHub inventory changed during collection".into(),
                ));
            }
            let entries = value[field]
                .as_array()
                .ok_or_else(|| CiError::Message("GitHub inventory lacks entries".into()))?;
            for entry in entries {
                let id = entry["id"]
                    .as_u64()
                    .ok_or_else(|| CiError::Message("GitHub inventory entry lacks id".into()))?;
                if !ids.insert(id) {
                    return Err(CiError::Message("GitHub inventory repeats an entry".into()));
                }
                values.push(serde_json::from_value(entry.clone())?);
            }
            if u64::try_from(values.len()).ok() == Some(total) {
                return Ok(values);
            }
            if entries.is_empty() {
                break;
            }
        }
        Err(CiError::Message(
            "GitHub inventory was incomplete or exceeded its page limit".into(),
        ))
    }
}

#[derive(Serialize)]
struct Collected {
    schema: u32,
    commit: String,
    workflow: String,
    run: WorkflowRun,
    jobs: Vec<Job>,
    artifacts: Vec<Artifact>,
    plans: Vec<Plan>,
    attestations: Vec<Attestation>,
    conclusion: &'static str,
}

pub fn collect_current(root: &Path, workflow: &str, output: &Path) -> Result<()> {
    let commit = String::from_utf8(crate::command::git(root, ["rev-parse", "HEAD"])?)
        .map_err(|error| CiError::Message(error.to_string()))?
        .trim()
        .to_owned();
    let run_id: u64 = std::env::var("GITHUB_RUN_ID")
        .map_err(|error| CiError::Message(error.to_string()))?
        .parse()
        .map_err(|error| CiError::Message(format!("invalid GITHUB_RUN_ID: {error}")))?;
    let checkout =
        std::env::var("GITHUB_SHA").map_err(|error| CiError::Message(error.to_string()))?;
    if checkout != commit {
        return Err(CiError::Message(
            "source collector checkout differs from its hosted execution context".into(),
        ));
    }
    let client = Client::new(root)?;
    let run: WorkflowRun = client.json(&format!("runs/{run_id}"))?;
    let attempt =
        std::env::var("GITHUB_RUN_ATTEMPT").map_err(|error| CiError::Message(error.to_string()))?;
    if attempt != run.run_attempt.to_string() {
        return Err(CiError::Message(
            "source collector run attempt differs from GitHub".into(),
        ));
    }
    let expected = ExpectedRun {
        repository: &client.repository,
        workflow_path: workflow,
        admission: Admission::Current {
            run_id,
            checkout: &checkout,
        },
    };
    hosted::validate_run(
        &run,
        &client.repository,
        workflow,
        &commit,
        expected.admission,
    )?;
    let jobs = client.inventory::<Job>(
        &format!("runs/{run_id}/attempts/{}/jobs", run.run_attempt),
        "jobs",
    )?;
    let artifacts =
        client.inventory::<Artifact>(&format!("runs/{run_id}/artifacts"), "artifacts")?;
    let configured: Lanes = toml::from_str(&std::fs::read_to_string(
        root.join("ci/source-execution.toml"),
    )?)?;
    if configured.schema != 1 {
        return Err(CiError::Message(
            "unsupported source execution configuration".into(),
        ));
    }
    let sources = super::validate(root)?;
    validate_lane_coverage(&configured.lane, &sources)?;
    let lanes = configured
        .lane
        .iter()
        .filter(|lane| lane.workflow == workflow)
        .collect::<Vec<_>>();
    if lanes.is_empty() {
        return Err(CiError::Message(
            "workflow has no required source execution lanes".into(),
        ));
    }
    let suites = lanes
        .iter()
        .map(|lane| lane.suite.as_str())
        .collect::<BTreeSet<_>>();
    let plans = suites
        .into_iter()
        .map(|suite| Plan::from_sources(commit.clone(), suite.to_owned(), &sources))
        .collect::<Result<Vec<_>>>()?;
    let workflow_bytes = std::fs::read_to_string(root.join(workflow))?;
    let mut attestations = Vec::new();
    let mut used = BTreeSet::new();
    for lane in lanes {
        let identity = resolve_lane(lane, &workflow_bytes)?;
        let artifact_name = format!("{}-{}", identity.artifact_name, run.run_attempt);
        let matching = artifacts
            .iter()
            .filter(|artifact| artifact.name == artifact_name)
            .collect::<Vec<_>>();
        let [artifact] = matching.as_slice() else {
            return Err(CiError::Message(format!(
                "missing or ambiguous source artifact: {}",
                artifact_name
            )));
        };
        if !used.insert(artifact.id) {
            return Err(CiError::Message(
                "source lanes reuse the same artifact".into(),
            ));
        }
        let bytes = client.bytes(&format!("artifacts/{}/zip", artifact.id))?;
        let plan = plans
            .iter()
            .find(|plan| plan.suite == lane.suite)
            .ok_or_else(|| CiError::Message("source lane plan is absent".into()))?;
        attestations.push(hosted::attest_archive(
            plan,
            &expected,
            &ExpectedLane {
                job: &lane.job,
                job_name: &identity.job_name,
                runner: &lane.runner,
                runner_label: &identity.runner_label,
            },
            &HostedArchive {
                run: &run,
                jobs: &jobs,
                artifact,
                bytes: &bytes,
            },
            client.maximum_bytes,
        )?);
    }
    super::observation::validate_merge(&commit, &plans, &attestations)?;
    let result = Collected {
        schema: 1,
        commit,
        workflow: workflow.to_owned(),
        run,
        jobs,
        artifacts: artifacts
            .into_iter()
            .filter(|artifact| used.contains(&artifact.id))
            .collect(),
        plans,
        attestations,
        conclusion: "success",
    };
    let mut bytes = serde_json::to_vec_pretty(&result)?;
    bytes.push(b'\n');
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, bytes)?;
    Ok(())
}
