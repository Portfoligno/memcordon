//! Planning over current literal workflow steps and mutually exclusive paths.
use crate::{CiError, Result};
use serde_yaml::Value;
use std::collections::BTreeSet;
const RESTORE: &str = "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
const SAVE: &str = "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or("")
}
#[derive(Clone, PartialEq)]
enum BudgetScalar {
    Text(String),
    Bool(bool),
}
impl BudgetScalar {
    fn truthy(&self) -> bool {
        match self {
            Self::Text(value) => !value.is_empty(),
            Self::Bool(value) => *value,
        }
    }
}

/// Abstract source analysis only. Unknown statuses/outputs remain possible;
/// this never reads actual steps, event JSON or executable-facing environment.
fn budget_guard_value(
    expression: &crate::policy::cache_guard::Expr,
    known: &impl Fn(&str) -> Option<String>,
) -> Option<BudgetScalar> {
    use crate::policy::cache_guard::Expr as E;
    match expression {
        E::Value(name) => known(name).map(BudgetScalar::Text),
        E::Literal(value) => Some(BudgetScalar::Text(value.clone())),
        E::Bool(value) => Some(BudgetScalar::Bool(*value)),
        E::Status(_) => None,
        E::Not(value) => {
            budget_guard_value(value, known).map(|value| BudgetScalar::Bool(!value.truthy()))
        }
        E::Equal(a, b) | E::Unequal(a, b) => {
            let equal = budget_guard_value(a, known)?.eq(&budget_guard_value(b, known)?);
            Some(BudgetScalar::Bool(if matches!(expression, E::Equal(..)) {
                equal
            } else {
                !equal
            }))
        }
        E::And(a, b) | E::Or(a, b) => {
            let a = budget_guard_value(a, known).map(|value| value.truthy());
            let b = budget_guard_value(b, known).map(|value| value.truthy());
            let result = if matches!(expression, E::And(..)) {
                if a == Some(false) || b == Some(false) {
                    Some(false)
                } else if a == Some(true) && b == Some(true) {
                    Some(true)
                } else {
                    None
                }
            } else if a == Some(true) || b == Some(true) {
                Some(true)
            } else if a == Some(false) && b == Some(false) {
                Some(false)
            } else {
                None
            };
            result.map(BudgetScalar::Bool)
        }
    }
}

fn budget_matrix_rows(job: &Value) -> Result<Vec<std::collections::BTreeMap<String, String>>> {
    let mut rows = vec![std::collections::BTreeMap::new()];
    let scalar = |value: &Value| {
        value
            .as_str()
            .map(str::to_owned)
            .or_else(|| value.as_bool().map(|value| value.to_string()))
            .or_else(|| value.as_i64().map(|value| value.to_string()))
    };
    if let Some(matrix) = job["strategy"]["matrix"].as_mapping() {
        for (axis, values) in matrix {
            let Some(axis) = axis
                .as_str()
                .filter(|axis| !matches!(*axis, "include" | "exclude"))
            else {
                continue;
            };
            let Some(values) = values.as_sequence() else {
                continue;
            };
            let mut expanded = Vec::new();
            for row in &rows {
                for value in values {
                    let mut row = row.clone();
                    if let Some(value) = scalar(value) {
                        row.insert(format!("matrix.{axis}"), value);
                    }
                    expanded.push(row);
                }
            }
            rows = expanded;
            if rows.len() > 256 {
                return Err(CiError::Message(
                    "budget matrix exceeds reviewed finite rows".into(),
                ));
            }
        }
        if let Some(include) = job["strategy"]["matrix"]["include"].as_sequence() {
            let axes = rows.first().is_some_and(|row| !row.is_empty());
            if !axes {
                rows.clear();
            }
            for values in include {
                let mut row = std::collections::BTreeMap::new();
                if let Some(values) = values.as_mapping() {
                    for (axis, value) in values {
                        if let (Some(axis), Some(value)) = (axis.as_str(), scalar(value)) {
                            row.insert(format!("matrix.{axis}"), value);
                        }
                    }
                }
                rows.push(row);
            }
        }
    }
    if rows.is_empty() {
        rows.push(Default::default());
    }
    if rows.len() > 256 {
        return Err(CiError::Message(
            "budget matrix exceeds reviewed finite rows".into(),
        ));
    }
    Ok(rows)
}

fn budget_cache_class(step: &Value) -> Option<(String, usize)> {
    if field(step, "uses") != SAVE
        && !(field(step, "uses") == RESTORE && step["with"]["lookup-only"].as_bool() == Some(true))
    {
        return None;
    }
    let key = field(&step["with"], "key")
        .trim()
        .strip_prefix("${{")?
        .strip_suffix("}}")?
        .trim()
        .strip_prefix("steps.")?;
    let (owner, slot) = key.split_once(".outputs.")?;
    let slot = slot.strip_suffix("-key")?;
    if slot == "source-complete" {
        return Some((format!("{owner}:source-archives"), 0));
    }
    if slot == "archives-partial" {
        return Some((format!("{owner}:source-archives"), 1));
    }
    if let Some(slot) = slot.strip_suffix("-complete") {
        return Some((format!("{owner}:{slot}"), 0));
    }
    slot.strip_suffix("-partial")
        .map(|slot| (format!("{owner}:{slot}"), 1))
}

fn budget_producer_field(
    field_name: &str,
    base: &impl Fn(&str) -> Option<String>,
    producers: &std::collections::BTreeMap<&str, &Value>,
    ancestors: &BTreeSet<String>,
) -> Option<String> {
    if let Some(value) = base(field_name) {
        return Some(value);
    }
    let (owner, property) = field_name.strip_prefix("steps.")?.split_once('.')?;
    if (!property.starts_with("outputs.") && property != "outcome")
        || ancestors.len() >= 128
        || ancestors.contains(owner)
    {
        return None;
    }
    let producer = producers.get(owner)?;
    let guard = crate::policy::cache_guard::parse(field(producer, "if")).ok()?;
    let mut ancestors = ancestors.clone();
    ancestors.insert(owner.into());
    let known = |name: &str| budget_producer_field(name, base, producers, &ancestors);
    if budget_guard_value(&guard, &known).is_some_and(|value| !value.truthy()) {
        Some(if property == "outcome" {
            "skipped".into()
        } else {
            String::new()
        })
    } else {
        None
    }
}

fn budget_matrix_is_complete(job: &Value) -> bool {
    fn scalar(value: &Value) -> bool {
        value.as_str().is_some_and(|value| !value.contains("${{"))
            || value.is_bool()
            || value.is_number()
            || value.is_null()
    }
    job["strategy"]["matrix"]
        .as_mapping()
        .is_some_and(|matrix| {
            matrix.iter().all(|(name, value)| {
                let Some(name) = name.as_str() else {
                    return false;
                };
                value.as_sequence().is_some_and(|values| {
                    values.iter().all(|value| {
                        if matches!(name, "include" | "exclude") {
                            value.as_mapping().is_some_and(|row| {
                                row.iter()
                                    .all(|(key, value)| key.is_string() && scalar(value))
                            })
                        } else {
                            scalar(value)
                        }
                    })
                })
            })
        })
}

/// Every emitted run/action participates. Only reviewed matrix/host/driver and
/// complete/partial alternatives are reduced; unknown conditions overestimate.
pub(super) fn job_budget_definition(job: &Value) -> Result<super::budget::JobDefinition> {
    use super::budget::BudgetNode as N;
    let steps = job["steps"]
        .as_sequence()
        .ok_or_else(|| CiError::Message("job budget missing steps".into()))?;
    let has_driver = steps
        .iter()
        .any(|step| field(step, "run").contains(" ci driver-select"));
    let producers = steps
        .iter()
        .filter_map(|step| step["id"].as_str().map(|id| (id, step)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let complete_matrix = budget_matrix_is_complete(job);
    let mut branches = Vec::new();
    for (row_index, row) in budget_matrix_rows(job)?.into_iter().enumerate() {
        let runner = job["runs-on"].as_str().unwrap_or("");
        let declared = row
            .values()
            .find(|value| {
                value.starts_with("windows-")
                    || value.starts_with("ubuntu-")
                    || value.starts_with("macos-")
            })
            .map(String::as_str)
            .unwrap_or(runner);
        for host in ["Linux", "macOS", "Windows"] {
            if (declared.starts_with("windows-") && host != "Windows")
                || (declared.starts_with("ubuntu-") && host != "Linux")
                || (declared.starts_with("macos-") && host != "macOS")
            {
                continue;
            }
            for driver in if has_driver {
                &['c', 'm', 'r'][..]
            } else {
                &['c'][..]
            } {
                let base = |field: &str| -> Option<String> {
                    if field == "runner.os" {
                        return Some(host.into());
                    }
                    if let Some(value) = row.get(field) {
                        return (!value.contains("${{")).then(|| value.clone());
                    }
                    if field.starts_with("matrix.") && complete_matrix {
                        return Some(String::new());
                    }
                    if let Some((owner, _)) = field
                        .strip_prefix("steps.")
                        .and_then(|field| field.split_once('.'))
                        && !producers.contains_key(owner)
                    {
                        return None;
                    }
                    for suffix in ["", "-windows"] {
                        let prefix = |owner: &str| format!("steps.driver-{owner}{suffix}.");
                        let active_host = (suffix == "-windows") == (host == "Windows");
                        if !active_host {
                            for owner in [
                                "bootstrap",
                                "selection",
                                "managed-build",
                                "cold-build",
                                "cold-adopt",
                                "context",
                            ] {
                                if let Some(property) = field.strip_prefix(&prefix(owner)) {
                                    return Some(if property == "outcome" {
                                        "skipped".into()
                                    } else {
                                        String::new()
                                    });
                                }
                            }
                        }
                        if let Some(output) = field.strip_prefix(&prefix("bootstrap"))
                            && output == "outputs.bootstrap-ready"
                        {
                            return Some(if *driver == 'c' { "false" } else { "true" }.into());
                        }
                        if let Some(output) = field.strip_prefix(&prefix("selection")) {
                            return match output {
                                "outputs.build-required" => {
                                    Some(if *driver == 'm' { "true" } else { "false" }.into())
                                }
                                "outputs.current-ready" => {
                                    Some(if *driver == 'r' { "true" } else { "false" }.into())
                                }
                                _ => None,
                            };
                        }
                        for (owner, active) in [
                            ("managed-build", *driver == 'm'),
                            ("cold-build", *driver == 'c'),
                            ("cold-adopt", *driver == 'c'),
                            ("context", *driver != 'c'),
                        ] {
                            if let Some(tail) = field.strip_prefix(&prefix(owner)) {
                                if tail == "outcome" {
                                    return if active { None } else { Some("skipped".into()) };
                                }
                                if tail.starts_with("outputs.") && !active {
                                    return Some(String::new());
                                }
                            }
                        }
                    }
                    None
                };
                let known =
                    |name: &str| budget_producer_field(name, &base, &producers, &BTreeSet::new());
                let mut sequential = Vec::new();
                let mut classes = std::collections::BTreeMap::<String, [Vec<N>; 2]>::new();
                for (index, step) in steps.iter().enumerate() {
                    if let Ok(guard) = crate::policy::cache_guard::parse(field(step, "if"))
                        && budget_guard_value(&guard, &known).is_some_and(|value| !value.truthy())
                    {
                        continue;
                    }
                    let mut minutes = step["timeout-minutes"]
                        .as_u64()
                        .filter(|minutes| *minutes > 0)
                        .ok_or_else(|| {
                            CiError::Message(format!(
                                "budget step missing finite reviewed ceiling: {} {}",
                                field(step, "id"),
                                field(step, "run")
                            ))
                        })?;
                    let label = if field(step, "id").is_empty() {
                        format!("step-{index}")
                    } else {
                        field(step, "id").into()
                    };
                    let command = field(step, "run");
                    // A miss performs only selection. The continuation belongs
                    // to exactly one active-image/build/adoption route.
                    if *driver != 'r' && command.contains(" ci driver-select --feedback ") {
                        minutes = 4;
                    }
                    let node = N::minutes(label, minutes)?;
                    if let Some((group, class)) = budget_cache_class(step) {
                        classes.entry(group).or_default()[class].push(node);
                    } else {
                        sequential.push(node);
                    }
                }
                for (name, alternatives) in classes {
                    sequential.push(N::Alternatives {
                        name,
                        branches: alternatives
                            .into_iter()
                            .enumerate()
                            .map(|(class, steps)| N::Sequence {
                                name: if class == 0 { "complete" } else { "partial" }.into(),
                                steps,
                            })
                            .collect(),
                    });
                }
                branches.push(N::Sequence {
                    name: format!("matrix-row-{row_index}/{host}/driver-{driver}"),
                    steps: sequential,
                });
            }
        }
    }
    Ok(super::budget::JobDefinition {
        steps: vec![N::Alternatives {
            name: "reviewed emitted job paths".into(),
            branches,
        }],
    })
}
