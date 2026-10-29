//! Descriptive selected-source identity and finite workflow observations.
use memcordon_readiness_verifier::{JobOutcome, JobResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub type LedgerResult<T> = Result<T, String>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
}

pub fn parse_job_outcomes(arguments: &[String]) -> LedgerResult<Vec<JobOutcome>> {
    if arguments.is_empty() || arguments.len() > 32 {
        return Err("finite job outcome input is empty/oversized".into());
    }
    let allowed = ["linux-x64", "linux-arm64", "windows-x64", "windows-arm64"]
        .into_iter()
        .flat_map(|label| {
            [
                format!("native-{label}"),
                format!("candidate-{label}-native"),
                format!("candidate-{label}-cargo"),
                format!("public-{label}-native"),
                format!("public-{label}-cargo"),
            ]
        })
        .collect::<BTreeSet<_>>();
    let mut keys = BTreeSet::new();
    arguments
        .iter()
        .map(|argument| {
            let (job, result) = argument
                .split_once('=')
                .ok_or("job outcome requires one name=value operand")?;
            if !allowed.contains(job) || !keys.insert(job.to_owned()) {
                return Err("duplicate/malformed producer job operand".into());
            }
            let result = match result {
                "success" => JobResult::Success,
                "failure" => JobResult::Failure,
                "cancelled" => JobResult::Cancelled,
                "skipped" => JobResult::Skipped,
                "missing" => JobResult::Missing,
                _ => return Err("unknown job outcome enum".into()),
            };
            Ok(JobOutcome {
                job: job.to_owned(),
                result,
            })
        })
        .collect()
}
