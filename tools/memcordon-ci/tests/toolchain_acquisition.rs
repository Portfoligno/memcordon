use memcordon_ci::workflow_definitions::{self, toolchain_acquisition};
use serde_yaml::{Mapping, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

fn value(text: &str) -> Value {
    Value::String(text.into())
}
fn original(command: &str, minutes: u64) -> Value {
    let mut fields = Mapping::new();
    fields.insert(value("name"), value("Install exact toolchain"));
    fields.insert(value("run"), value(command));
    fields.insert(value("timeout-minutes"), Value::Number(minutes.into()));
    Value::Mapping(fields)
}
fn guard(previous: &str) -> String {
    format!("${{{{ !cancelled() && steps.{previous}.outcome == 'failure' }}}}")
}

#[test]
fn identical_acquisition_retains_original_context_and_partitions_only_its_budget() {
    for command in [
        "rustup toolchain install 1.97.1 --profile minimal",
        "rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt",
        "rustup toolchain install nightly-2026-07-31 --profile minimal",
    ] {
        for minutes in [3, 4, 5, 15, 16] {
            let mut input = original(command, minutes);
            input["if"] = value("${{ failure() && needs.selection.outputs.recovery == 'true' }}");
            input["working-directory"] = value("${{ github.workspace }}");
            let mut environment = Mapping::new();
            environment.insert(
                value("RUSTUP_HOME"),
                value("${{ runner.temp }}/existing-rustup"),
            );
            input["env"] = Value::Mapping(environment);
            let attempts = toolchain_acquisition::steps("pinned", input.clone());
            let mut total = 0;
            for (index, attempt) in attempts.iter().enumerate() {
                for field in ["run", "env", "working-directory"] {
                    assert_eq!(attempt[field], input[field]);
                }
                assert_eq!(attempt["id"], format!("pinned_{}", index + 1));
                let budget = attempt["timeout-minutes"].as_u64().unwrap();
                assert!(budget > 0);
                total += budget;
                if minutes == 15 {
                    assert_eq!(budget, 5);
                }
                if index == 0 {
                    assert_eq!(attempt["if"], input["if"]);
                } else {
                    assert_eq!(attempt["if"], guard(&format!("pinned_{index}")));
                }
                if index < 2 {
                    assert_eq!(attempt["continue-on-error"], true);
                } else {
                    assert!(attempt["continue-on-error"].is_null());
                }
            }
            assert_eq!(total, minutes);
        }
    }
    let mut input = original("rustup toolchain install 1.85.0 --profile minimal", 15);
    input.as_mapping_mut().unwrap().remove(value("name"));
    input["if"] = Value::Bool(false);
    let attempts = toolchain_acquisition::steps("msrv", input);
    assert_eq!(attempts[0]["if"], false);
    assert_eq!(
        attempts[0]["name"],
        "Install pinned toolchain (attempt 1/3)"
    );
    assert_eq!(attempts[1]["if"], guard("msrv_1"));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Success,
    Failure,
    Skipped,
}
fn simulate(
    attempts: &[Value; 3],
    admitted: bool,
    cancel_after: Option<usize>,
    actual: [Outcome; 3],
) -> ([Outcome; 3], bool) {
    let mut observed = [Outcome::Skipped; 3];
    let mut outcomes = BTreeMap::new();
    let mut fatal = false;
    for (index, attempt) in attempts.iter().enumerate() {
        let cancelled = cancel_after.is_some_and(|completed| index >= completed);
        let run = if index == 0 {
            admitted && !cancelled
        } else {
            let condition = attempt["if"].as_str().unwrap();
            let previous = condition
                .strip_prefix("${{ !cancelled() && steps.")
                .unwrap()
                .strip_suffix(".outcome == 'failure' }}")
                .unwrap();
            !cancelled && outcomes.get(previous) == Some(&Outcome::Failure)
        };
        if run {
            observed[index] = actual[index];
            fatal |= actual[index] == Outcome::Failure && attempt["continue-on-error"] != true;
        }
        outcomes.insert(attempt["id"].as_str().unwrap(), observed[index]);
    }
    (observed, fatal)
}
#[test]
fn outcome_retry_state_table_preserves_skip_cancel_success_and_fatal_exhaustion() {
    use Outcome::{Failure as F, Skipped as K, Success as S};
    let mut input = original(
        "rustup toolchain install 1.97.1 --profile minimal --component rustfmt",
        15,
    );
    input["if"] = value("failure()");
    let attempts = toolchain_acquisition::steps("acquire", input);
    for (admitted, cancelled, actual, expected, fatal) in [
        (true, None, [S, F, F], [S, K, K], false),
        (true, None, [F, S, F], [F, S, K], false),
        (true, None, [F, F, S], [F, F, S], false),
        (true, None, [F, F, F], [F, F, F], true),
        (false, None, [F, F, F], [K, K, K], false),
        (true, Some(1), [F, F, F], [F, K, K], false),
        (true, Some(2), [F, F, F], [F, F, K], false),
    ] {
        assert_eq!(
            simulate(&attempts, admitted, cancelled, actual),
            (expected, fatal)
        );
    }
    // A failed outcome remains failure despite continue-on-error's successful
    // conclusion. Only the outcome condition may admit a retry.
    assert!(!attempts[1]["if"].as_str().unwrap().contains("conclusion"));
    assert!(!attempts[2]["if"].as_str().unwrap().contains("failure()"));
}

#[test]
fn unsupported_metadata_commands_and_insufficient_budgets_are_rejected() {
    for command in [
        "rustup run 1.97.1 cargo test",
        "cargo build",
        "echo rustup toolchain install 1.97.1",
        "rustup toolchain install 1.97.1 --profile complete",
    ] {
        assert!(
            std::panic::catch_unwind(|| toolchain_acquisition::steps("pin", original(command, 15)))
                .is_err()
        );
    }
    for minutes in [0, 1, 2] {
        assert!(
            std::panic::catch_unwind(|| toolchain_acquisition::steps(
                "pin",
                original("rustup toolchain install 1.97.1 --profile minimal", minutes)
            ))
            .is_err()
        );
    }
    for field in ["id", "continue-on-error", "uses", "with", "shell"] {
        let mut input = original("rustup toolchain install 1.97.1 --profile minimal", 15);
        input[field] = value("unsupported");
        assert!(
            std::panic::catch_unwind(|| toolchain_acquisition::steps("pin", input)).is_err(),
            "{field}"
        );
    }
    for id in ["", "acquire-step", "${{ matrix.id }}"] {
        assert!(
            std::panic::catch_unwind(|| toolchain_acquisition::steps(
                id,
                original("rustup toolchain install 1.97.1 --profile minimal", 15)
            ))
            .is_err()
        );
    }
}

fn strings<'a>(node: &'a Value, result: &mut Vec<&'a str>) {
    match node {
        Value::String(text) => result.push(text),
        Value::Sequence(values) => {
            for value in values {
                strings(value, result);
            }
        }
        Value::Mapping(values) => {
            for value in values.values() {
                strings(value, result);
            }
        }
        _ => {}
    }
}
#[test]
fn all_four_authored_and_generated_workflows_expand_every_install_without_rebinding_consumers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for (file, expected_nodes) in [
        ("ci.yml", 18),
        ("deep-ci.yml", 12),
        ("backend-certification.yml", 21),
        ("release.yml", 64),
    ] {
        let authored = workflow_definitions::definition(file).unwrap();
        let checked_in: Value = serde_yaml::from_slice(
            &std::fs::read(root.join(".github/workflows").join(file)).unwrap(),
        )
        .unwrap();
        for document in [&authored, &checked_in] {
            let mut nodes = BTreeSet::new();
            let mut run_commands = 0;
            for (job_id, job) in document["jobs"].as_mapping().unwrap() {
                let Some(steps) = job["steps"].as_sequence() else {
                    continue;
                };
                let mut ids = BTreeSet::new();
                for step in steps {
                    if let Some(id) = step["id"].as_str() {
                        assert!(ids.insert(id), "{file}/{job_id:?}/{id}");
                    }
                }
                let mut permitted_refs = BTreeSet::new();
                let mut index = 0;
                while index < steps.len() {
                    let step = &steps[index];
                    let command = step["run"].as_str().unwrap_or_default();
                    if !command
                        .split_whitespace()
                        .take(3)
                        .eq(["rustup", "toolchain", "install"])
                    {
                        if command.starts_with("rustup run ") {
                            run_commands += 1;
                            assert!(
                                !step["id"]
                                    .as_str()
                                    .is_some_and(|id| id.starts_with("acquire_node_"))
                            );
                        }
                        index += 1;
                        continue;
                    }
                    let first_id = step["id"].as_str().unwrap();
                    let prefix = first_id.strip_suffix("_1").unwrap();
                    assert!(prefix.starts_with("acquire_node_"));
                    nodes.insert(prefix.to_owned());
                    assert!(index + 2 < steps.len());
                    let group = &steps[index..index + 3];
                    assert_eq!(
                        group
                            .iter()
                            .map(|step| step["timeout-minutes"].as_u64().unwrap())
                            .sum::<u64>(),
                        15
                    );
                    for (attempt, step) in group.iter().enumerate() {
                        assert_eq!(step["run"], group[0]["run"]);
                        assert_eq!(step["id"], format!("{prefix}_{}", attempt + 1));
                        for field in ["env", "working-directory"] {
                            assert_eq!(step[field], group[0][field]);
                        }
                        assert_eq!(step["timeout-minutes"], 5);
                        if attempt < 2 {
                            assert_eq!(step["continue-on-error"], true);
                        } else {
                            assert!(step["continue-on-error"].is_null());
                        }
                        if attempt > 0 {
                            let condition = guard(&format!("{prefix}_{attempt}"));
                            assert_eq!(step["if"], condition);
                            permitted_refs.insert(condition);
                        }
                    }
                    index += 3;
                }
                let mut values = Vec::new();
                strings(job, &mut values);
                for text in values {
                    if text.contains("steps.acquire_node_") {
                        assert!(
                            permitted_refs.contains(text),
                            "external/unsupported attempt consumer: {file}/{job_id:?}: {text}"
                        );
                    }
                }
            }
            assert_eq!(nodes.len(), expected_nodes, "{file}");
            assert!(
                run_commands > 0,
                "real rustup-run checks/builds remain in {file}"
            );
        }
    }
}
