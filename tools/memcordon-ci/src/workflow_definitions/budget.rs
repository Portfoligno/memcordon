//! Planning ceilings, not benchmark claims. Production envelopes are preserved;
//! optional cache work and mutually exclusive platform branches are additional.
use crate::{CiError, Result};

pub const PLATFORM_LIMIT_MINUTES: u64 = 360;
const SETUP_TEARDOWN_SECONDS: u64 = 5 * 60;

/// Source-authored planning structure, never deserialized from workflow inputs.
/// A shared interval requires an actual inherited absolute operation deadline;
/// cache actions and unrelated operations belong outside that node.
#[derive(Clone, Debug)]
pub enum BudgetNode {
    Step {
        name: String,
        seconds: u64,
    },
    Sequence {
        name: String,
        steps: Vec<BudgetNode>,
    },
    Alternatives {
        name: String,
        branches: Vec<BudgetNode>,
    },
    SharedOperation {
        name: String,
        seconds: u64,
        steps: Vec<BudgetNode>,
    },
}

#[derive(Clone, Debug)]
pub struct BudgetEvaluation {
    pub name: String,
    pub seconds: u64,
    pub children: Vec<BudgetEvaluation>,
    pub selected_branch: Option<usize>,
}

fn overflow() -> CiError {
    CiError::Message("BudgetExceedsPlatformLimit: arithmetic overflow".into())
}

fn sum(values: &[BudgetEvaluation]) -> Result<u64> {
    values.iter().try_fold(0_u64, |total, value| {
        total.checked_add(value.seconds).ok_or_else(overflow)
    })
}

impl BudgetNode {
    pub fn minutes(name: impl Into<String>, minutes: u64) -> Result<Self> {
        Ok(Self::Step {
            name: name.into(),
            seconds: minutes.checked_mul(60).ok_or_else(overflow)?,
        })
    }

    fn evaluate(&self) -> Result<BudgetEvaluation> {
        let (name, seconds, children, selected_branch) = match self {
            Self::Step { name, seconds } => (name, *seconds, vec![], None),
            Self::Sequence { name, steps } => {
                let children = steps
                    .iter()
                    .map(Self::evaluate)
                    .collect::<Result<Vec<_>>>()?;
                (name, sum(&children)?, children, None)
            }
            Self::Alternatives { name, branches } => {
                let children = branches
                    .iter()
                    .map(Self::evaluate)
                    .collect::<Result<Vec<_>>>()?;
                let (selected, seconds) = children
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, value)| value.seconds)
                    .map(|(index, value)| (index, value.seconds))
                    .ok_or_else(|| {
                        CiError::Message("budget alternative has no reviewed branch".into())
                    })?;
                (name, seconds, children, Some(selected))
            }
            Self::SharedOperation {
                name,
                seconds,
                steps,
            } => {
                if *seconds == 0 || steps.is_empty() {
                    return Err(CiError::Message(
                        "shared operation needs its actual finite interval and steps".into(),
                    ));
                }
                let children = steps
                    .iter()
                    .map(Self::evaluate)
                    .collect::<Result<Vec<_>>>()?;
                (name, sum(&children)?.min(*seconds), children, None)
            }
        };
        if name.is_empty() || (seconds == 0 && !matches!(self, Self::Sequence { .. })) {
            return Err(CiError::Message(
                "every budget step needs a name and finite positive ceiling".into(),
            ));
        }
        Ok(BudgetEvaluation {
            name: name.clone(),
            seconds,
            children,
            selected_branch,
        })
    }
}

/// Finite reviewed branches of the emitted job, including every run and action.
#[derive(Clone, Debug)]
pub struct JobDefinition {
    pub steps: Vec<BudgetNode>,
}

impl JobDefinition {
    pub fn breakdown(&self) -> Result<BudgetEvaluation> {
        let summary = self.inventory_breakdown()?;
        let minutes = summary.seconds.checked_add(59).ok_or_else(overflow)? / 60;
        if minutes > PLATFORM_LIMIT_MINUTES {
            return Err(CiError::Message(format!(
                "BudgetExceedsPlatformLimit: {minutes} > {PLATFORM_LIMIT_MINUTES}; separate a real phase"
            )));
        }
        Ok(summary)
    }

    /// Source diagnostics may inspect a rejected finite inventory. This does
    /// not admit it: timeout_minutes/breakdown still reject the platform excess.
    pub(super) fn inventory_breakdown(&self) -> Result<BudgetEvaluation> {
        let mut children = self
            .steps
            .iter()
            .map(BudgetNode::evaluate)
            .collect::<Result<Vec<_>>>()?;
        children.push(BudgetEvaluation {
            name: "job setup/teardown slack".into(),
            seconds: SETUP_TEARDOWN_SECONDS,
            children: vec![],
            selected_branch: None,
        });
        let seconds = sum(&children)?;
        Ok(BudgetEvaluation {
            name: "job".into(),
            seconds,
            children,
            selected_branch: None,
        })
    }

    pub fn timeout_minutes(&self) -> Result<u64> {
        self.breakdown()?
            .seconds
            .checked_add(59)
            .map(|seconds| seconds / 60)
            .ok_or_else(overflow)
    }

    /// A conservative serial inventory adapter. Callers with reviewed exclusive
    /// branches or shared operation clocks construct the typed nodes above.
    /// Missing action bounds are errors just like missing run bounds.
    pub fn from_job(job: &serde_yaml::Value) -> Result<Self> {
        let steps = job["steps"]
            .as_sequence()
            .ok_or_else(|| CiError::Message("job budget has no step inventory".into()))?;
        let mut inventory = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            if !step["run"].is_string() && !step["uses"].is_string() {
                return Err(CiError::Message(
                    "job budget step has no executable/action".into(),
                ));
            }
            let name = step["id"]
                .as_str()
                .or_else(|| step["name"].as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("step-{index}"));
            let minutes = step["timeout-minutes"]
                .as_u64()
                .filter(|minutes| *minutes > 0)
                .ok_or_else(|| {
                    CiError::Message(format!("job budget step lacks finite ceiling: {name}"))
                })?;
            inventory.push(BudgetNode::minutes(name, minutes)?);
        }
        Ok(Self { steps: inventory })
    }
}

/// Evaluated source inventory for review/tests; no runtime or cache-service claim.
pub fn workflow_breakdown(file: &str) -> Result<Vec<(String, BudgetEvaluation)>> {
    let workflow = super::definition(file)?;
    workflow["jobs"]
        .as_mapping()
        .ok_or_else(|| CiError::Message("workflow jobs absent".into()))?
        .iter()
        .filter(|(_, job)| job["steps"].is_sequence())
        .map(|(name, job)| {
            let name = name
                .as_str()
                .ok_or_else(|| CiError::Message("job id is not text".into()))?;
            let budget = super::workflow_budget::job_budget_definition(job)
                .and_then(|definition| definition.breakdown())
                .map_err(|error| CiError::Message(format!("{file} job {name}: {error}")))?;
            Ok((name.to_owned(), budget))
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
pub struct JobBudget {
    pub production: u64,
    pub serial_cache: u64,
    pub cold_driver: u64,
    pub warm_driver: Option<u64>,
}
impl JobBudget {
    pub fn minutes(self) -> Result<u64> {
        let setup = self.cold_driver.max(self.warm_driver.unwrap_or(0));
        let total = self
            .production
            .checked_add(self.serial_cache)
            .and_then(|v| v.checked_add(setup))
            .and_then(|v| v.checked_add(5))
            .ok_or_else(|| {
                CiError::Message("BudgetExceedsPlatformLimit: arithmetic overflow".into())
            })?;
        if total > PLATFORM_LIMIT_MINUTES {
            return Err(CiError::Message(format!(
                "BudgetExceedsPlatformLimit: {total} > {PLATFORM_LIMIT_MINUTES}; separate a real phase"
            )));
        }
        Ok(total)
    }
}
