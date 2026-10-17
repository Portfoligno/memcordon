use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use serde_yaml::{Mapping, Value};
use syn::visit::Visit;
use walkdir::WalkDir;

use crate::command;
use crate::config;
use crate::{CiError, Result};

#[path = "cache_guard.rs"]
pub(crate) mod cache_guard;

pub const MAXIMUM_YAML_BYTES: usize = 1_048_576;
pub const MAXIMUM_YAML_DEPTH: usize = 64;
const UPLOAD_ARTIFACT_ACTION: &str = "./.github/actions/upload-artifact";
const PINNED_UPLOAD_ARTIFACT_ACTION: &str =
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
const UPLOAD_ARTIFACT_ACTION_PATH: &str = ".github/actions/upload-artifact/action.yml";

fn failure(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}

fn inventory(root: &Path) -> Result<Vec<PathBuf>> {
    let output = command::git(root, ["ls-files", "-z"])?;
    let mut files = Vec::new();
    for bytes in output
        .split(|byte| *byte == 0)
        .filter(|item| !item.is_empty())
    {
        let text =
            std::str::from_utf8(bytes).map_err(|_| failure("a tracked path is not valid UTF-8"))?;
        let path = PathBuf::from(text);
        if path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::RootDir))
        {
            return Err(failure(format!(
                "tracked path escapes repository: {path:?}"
            )));
        }
        match fs::symlink_metadata(root.join(&path)) {
            Ok(_) => files.push(path),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                // `git ls-files` reports index entries. A pre-commit policy run must
                // tolerate an entry that the working tree intentionally deletes.
            }
            Err(error) => return Err(error.into()),
        }
    }
    files.sort();
    Ok(files)
}

fn check_files(root: &Path, files: &[PathBuf], policy: &config::Policy) -> Result<()> {
    let binary = config::binary_files(root)?;
    let binary_paths: BTreeSet<PathBuf> = binary.paths.iter().map(PathBuf::from).collect();
    if !binary.extensions.is_empty() {
        return Err(failure(
            "binary-file policy must enumerate exact paths, not extensions",
        ));
    }
    let shell_allowlist: BTreeSet<PathBuf> = policy
        .workflow
        .self_extracting_shell_allowlist
        .iter()
        .map(PathBuf::from)
        .collect();
    for path in files {
        let extension = path.extension().and_then(|value| value.to_str());
        if path.file_name().is_some_and(|name| name == ".env") {
            return Err(failure(format!("tracked .env file is forbidden: {path:?}")));
        }
        if matches!(extension, Some("sh" | "bash")) && !shell_allowlist.contains(path) {
            return Err(failure(format!(
                "tracked shell script is forbidden: {path:?}"
            )));
        }
        let is_binary = binary_paths.contains(path);
        if is_binary {
            continue;
        }
        let bytes = fs::read(root.join(path))?;
        if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
            return Err(failure(format!("UTF-16 text is forbidden: {path:?}")));
        }
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(failure(format!(
                "tracked text file lacks trailing newline: {path:?}"
            )));
        }
    }
    for path in binary_paths {
        if !files.contains(&path) {
            return Err(failure(format!("stale binary-file policy entry: {path:?}")));
        }
    }
    Ok(())
}

fn key(name: &str) -> Value {
    Value::String(name.to_owned())
}

fn mapping<'a>(value: &'a Value, context: &str) -> Result<&'a Mapping> {
    value
        .as_mapping()
        .ok_or_else(|| failure(format!("{context} must be a YAML mapping")))
}

fn scalar<'a>(mapping: &'a Mapping, name: &str) -> Option<&'a str> {
    mapping.get(key(name)).and_then(Value::as_str)
}

fn validate_yaml_depth(value: &Value, depth: usize) -> Result<()> {
    if depth > MAXIMUM_YAML_DEPTH {
        return Err(failure("YAML nesting exceeds configured depth policy"));
    }
    match value {
        Value::Sequence(sequence) => {
            for value in sequence {
                validate_yaml_depth(value, depth + 1)?;
            }
        }
        Value::Mapping(mapping) => {
            for (key, value) in mapping {
                validate_yaml_depth(key, depth + 1)?;
                validate_yaml_depth(value, depth + 1)?;
            }
        }
        Value::Tagged(tagged) => validate_yaml_depth(&tagged.value, depth + 1)?,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn parse_yaml(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAXIMUM_YAML_BYTES {
        return Err(failure("YAML input exceeds configured size policy"));
    }
    let document = serde_yaml::from_slice(bytes)?;
    validate_yaml_depth(&document, 1)?;
    Ok(document)
}

fn exact_mapping_keys(mapping: &Mapping, expected: &[&str], context: &str) -> Result<()> {
    let actual: BTreeSet<&str> = mapping
        .keys()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| failure(format!("{context} key must be a string")))
        })
        .collect::<Result<_>>()?;
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if actual != expected {
        return Err(failure(format!(
            "{context} keys differ: actual={actual:?} expected={expected:?}"
        )));
    }
    Ok(())
}

pub fn validate_upload_artifact_action_bytes(bytes: &[u8]) -> Result<()> {
    let action = parse_yaml(bytes)?;
    let action = mapping(&action, "artifact upload action")?;
    exact_mapping_keys(
        action,
        &["name", "description", "inputs", "outputs", "runs"],
        "artifact upload action",
    )?;
    if scalar(action, "name").is_none() || scalar(action, "description").is_none() {
        return Err(failure("artifact upload action metadata is incomplete"));
    }
    let outputs = mapping(
        action.get(key("outputs")).expect("exact keys"),
        "artifact upload outputs",
    )?;
    exact_mapping_keys(
        outputs,
        &["artifact-id", "artifact-digest"],
        "artifact upload outputs",
    )?;
    for name in ["artifact-id", "artifact-digest"] {
        let output = mapping(
            outputs.get(key(name)).expect("exact keys"),
            "artifact upload output",
        )?;
        exact_mapping_keys(output, &["description", "value"], "artifact upload output")?;
        let expected = format!(
            "${{{{ steps.retry-two.outputs.{name} || steps.retry-one.outputs.{name} || steps.initial.outputs.{name} }}}}"
        );
        if scalar(output, "value") != Some(&expected) {
            return Err(failure("artifact immutable output binding differs"));
        }
    }

    let inputs = mapping(
        action
            .get(key("inputs"))
            .ok_or_else(|| failure("artifact upload action inputs are absent"))?,
        "artifact upload action inputs",
    )?;
    exact_mapping_keys(
        inputs,
        &[
            "name",
            "path",
            "if-no-files-found",
            "retention-days",
            "compression-level",
            "include-hidden-files",
        ],
        "artifact upload action inputs",
    )?;
    for (name, default) in [
        ("name", "artifact"),
        ("if-no-files-found", "warn"),
        ("retention-days", "0"),
        ("compression-level", "6"),
        ("include-hidden-files", "false"),
    ] {
        let input = mapping(
            inputs
                .get(key(name))
                .ok_or_else(|| failure(format!("artifact upload action {name} input absent")))?,
            "artifact upload action input",
        )?;
        exact_mapping_keys(input, &["description", "default"], "artifact upload input")?;
        if scalar(input, "description").is_none() || scalar(input, "default") != Some(default) {
            return Err(failure(format!(
                "artifact upload action {name} input differs"
            )));
        }
    }
    let path = mapping(
        inputs
            .get(key("path"))
            .ok_or_else(|| failure("artifact upload action path input absent"))?,
        "artifact upload path input",
    )?;
    exact_mapping_keys(
        path,
        &["description", "required"],
        "artifact upload path input",
    )?;
    if scalar(path, "description").is_none()
        || path.get(key("required")).and_then(Value::as_bool) != Some(true)
    {
        return Err(failure("artifact upload action path must be required"));
    }

    let runs = mapping(
        action
            .get(key("runs"))
            .ok_or_else(|| failure("artifact upload action runs are absent"))?,
        "artifact upload action runs",
    )?;
    exact_mapping_keys(runs, &["using", "steps"], "artifact upload action runs")?;
    if scalar(runs, "using") != Some("composite") {
        return Err(failure("artifact upload action must be composite"));
    }
    let steps = runs
        .get(key("steps"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure("artifact upload action steps are absent"))?;
    if steps.len() != 3 {
        return Err(failure(
            "artifact upload action must make exactly three attempts",
        ));
    }
    let attempts = [
        ("initial", None, true, false),
        (
            "retry-one",
            Some("${{ steps.initial.outcome == 'failure' }}"),
            true,
            true,
        ),
        (
            "retry-two",
            Some(
                "${{ steps.initial.outcome == 'failure' && steps.retry-one.outcome == 'failure' }}",
            ),
            false,
            true,
        ),
    ];
    for (value, (id, condition, continue_on_error, overwrite)) in steps.iter().zip(attempts) {
        let step = mapping(value, "artifact upload attempt")?;
        let expected_keys = if condition.is_none() {
            &["id", "continue-on-error", "uses", "with"][..]
        } else if continue_on_error {
            &["id", "if", "continue-on-error", "uses", "with"][..]
        } else {
            &["id", "if", "uses", "with"][..]
        };
        exact_mapping_keys(step, expected_keys, "artifact upload attempt")?;
        if scalar(step, "id") != Some(id)
            || scalar(step, "if") != condition
            || scalar(step, "uses") != Some(PINNED_UPLOAD_ARTIFACT_ACTION)
            || step
                .get(key("continue-on-error"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
                != continue_on_error
        {
            return Err(failure(format!("artifact upload {id} attempt differs")));
        }
        let with = mapping(
            step.get(key("with"))
                .ok_or_else(|| failure("artifact upload attempt inputs absent"))?,
            "artifact upload attempt inputs",
        )?;
        exact_mapping_keys(
            with,
            &[
                "name",
                "path",
                "if-no-files-found",
                "retention-days",
                "compression-level",
                "include-hidden-files",
                "overwrite",
            ],
            "artifact upload attempt inputs",
        )?;
        for input in [
            "name",
            "path",
            "if-no-files-found",
            "retention-days",
            "compression-level",
            "include-hidden-files",
        ] {
            let expected = format!("${{{{ inputs.{input} }}}}");
            if scalar(with, input) != Some(expected.as_str()) {
                return Err(failure(format!(
                    "artifact upload {id} does not forward {input}"
                )));
            }
        }
        if with.get(key("overwrite")).and_then(Value::as_bool) != Some(overwrite) {
            return Err(failure(format!(
                "artifact upload {id} overwrite policy differs"
            )));
        }
    }
    Ok(())
}

fn check_upload_artifact_action(root: &Path) -> Result<()> {
    validate_upload_artifact_action_bytes(&fs::read(root.join(UPLOAD_ARTIFACT_ACTION_PATH))?)
}

fn local_step_references(steps: &[Value], context: &str) -> Result<BTreeSet<String>> {
    let mut references = BTreeSet::new();
    for step in steps {
        let step = mapping(step, context)?;
        if let Some(uses) = step.get(key("uses")) {
            let uses = uses
                .as_str()
                .ok_or_else(|| failure(format!("{context} uses must be a scalar string")))?;
            if uses.starts_with("./") {
                references.insert(uses.to_owned());
            }
        }
    }
    Ok(references)
}

/// Returns repository-local action references from workflow step positions.
pub fn workflow_local_action_references(bytes: &[u8]) -> Result<BTreeSet<String>> {
    let document = parse_yaml(bytes)?;
    let workflow = mapping(&document, "workflow provenance")?;
    let jobs = mapping(
        workflow
            .get(key("jobs"))
            .ok_or_else(|| failure("workflow provenance jobs are absent"))?,
        "workflow provenance jobs",
    )?;
    let mut references = BTreeSet::new();
    for job in jobs.values() {
        let job = mapping(job, "workflow provenance job")?;
        if scalar(job, "uses").is_some_and(|uses| uses.starts_with("./")) {
            return Err(failure(
                "repository-local reusable workflows are forbidden in release provenance",
            ));
        }
        if let Some(steps) = job.get(key("steps")) {
            let steps = steps
                .as_sequence()
                .ok_or_else(|| failure("workflow provenance steps must be a sequence"))?;
            references.extend(local_step_references(steps, "workflow provenance step")?);
        }
    }
    Ok(references)
}

/// Returns repository-local action references from composite-action step positions.
pub fn composite_local_action_references(bytes: &[u8]) -> Result<BTreeSet<String>> {
    let document = parse_yaml(bytes)?;
    let action = mapping(&document, "composite action provenance")?;
    let runs = mapping(
        action
            .get(key("runs"))
            .ok_or_else(|| failure("composite action provenance runs are absent"))?,
        "composite action provenance runs",
    )?;
    if scalar(runs, "using") != Some("composite") {
        return Err(failure(
            "workflow provenance supports only repository-local composite actions",
        ));
    }
    let steps = runs
        .get(key("steps"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure("composite action provenance steps are absent"))?;
    local_step_references(steps, "composite action provenance step")
}

fn exact_string_sequence(value: &Value, expected: &[&str], context: &str) -> Result<()> {
    let sequence = value
        .as_sequence()
        .ok_or_else(|| failure(format!("{context} must be a sequence")))?;
    let actual: Vec<&str> = sequence
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| failure(format!("{context} member must be a string")))
        })
        .collect::<Result<_>>()?;
    if actual != expected {
        return Err(failure(format!(
            "{context} differs: actual={actual:?} expected={expected:?}"
        )));
    }
    Ok(())
}

fn check_dependabot_update(
    value: &Value,
    ecosystem: &str,
    directory: &str,
    pull_request_limit: u64,
) -> Result<()> {
    let update = mapping(value, "Dependabot update")?;
    exact_mapping_keys(
        update,
        &[
            "package-ecosystem",
            "directory",
            "schedule",
            "open-pull-requests-limit",
        ],
        "Dependabot update",
    )?;
    if scalar(update, "package-ecosystem") != Some(ecosystem)
        || scalar(update, "directory") != Some(directory)
        || update
            .get(key("open-pull-requests-limit"))
            .and_then(Value::as_u64)
            != Some(pull_request_limit)
    {
        return Err(failure("Dependabot update target or limit differs"));
    }
    let schedule = mapping(
        update
            .get(key("schedule"))
            .ok_or_else(|| failure("Dependabot update schedule is absent"))?,
        "Dependabot update schedule",
    )?;
    exact_mapping_keys(schedule, &["interval"], "Dependabot update schedule")?;
    if scalar(schedule, "interval") != Some("weekly") {
        return Err(failure("Dependabot update schedule must be weekly"));
    }
    Ok(())
}

pub fn validate_dependabot_bytes(bytes: &[u8]) -> Result<()> {
    let document = parse_yaml(bytes)?;
    let dependabot = mapping(&document, "Dependabot configuration")?;
    exact_mapping_keys(
        dependabot,
        &["version", "updates"],
        "Dependabot configuration",
    )?;
    if dependabot.get(key("version")).and_then(Value::as_u64) != Some(2) {
        return Err(failure("Dependabot configuration version differs"));
    }
    let updates = dependabot
        .get(key("updates"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure("Dependabot updates must be a sequence"))?;
    let expected = [
        ("cargo", "/", 5),
        ("cargo", "/fuzz", 3),
        ("github-actions", "/", 3),
    ];
    if updates.len() != expected.len() {
        return Err(failure("Dependabot update count differs"));
    }
    for (update, (ecosystem, directory, pull_request_limit)) in updates.iter().zip(expected) {
        check_dependabot_update(update, ecosystem, directory, pull_request_limit)?;
    }
    Ok(())
}

fn check_top_level_permissions(workflow: &Mapping) -> Result<()> {
    let permissions = mapping(
        workflow
            .get(key("permissions"))
            .ok_or_else(|| failure("workflow has no permissions map"))?,
        "workflow permissions",
    )?;
    exact_mapping_keys(permissions, &["contents"], "workflow permissions")?;
    if scalar(permissions, "contents") != Some("read") {
        return Err(failure(
            "workflow default permissions must be contents: read",
        ));
    }
    Ok(())
}

fn check_push_and_dispatch_events(workflow: &Mapping, context: &str) -> Result<()> {
    let events = mapping(
        workflow
            .get(key("on"))
            .ok_or_else(|| failure(format!("{context} has no event map")))?,
        &format!("{context} events"),
    )?;
    exact_mapping_keys(
        events,
        &["push", "workflow_dispatch"],
        &format!("{context} events"),
    )?;
    for event in ["push", "workflow_dispatch"] {
        let configuration = events
            .get(key(event))
            .ok_or_else(|| failure(format!("{context} {event} is absent")))?;
        if event == "workflow_dispatch" && context == "deep CI" {
            let dispatch = mapping(configuration, "Deep dispatch")?;
            exact_mapping_keys(dispatch, &["inputs"], "Deep dispatch")?;
            let inputs = mapping(&dispatch["inputs"], "Deep dispatch inputs")?;
            exact_mapping_keys(inputs, &["failure-mode"], "Deep dispatch inputs")?;
            let mode = mapping(&inputs["failure-mode"], "Deep failure mode")?;
            exact_mapping_keys(
                mode,
                &["description", "type", "default", "options"],
                "Deep failure mode",
            )?;
            if mode["type"].as_str() != Some("choice")
                || mode["default"].as_str() != Some("collect-all")
            {
                return Err(failure(
                    "Deep manual diagnostics must preserve collect-all default",
                ));
            }
            exact_string_sequence(
                &mode["options"],
                &["stop-after-failure", "collect-all"],
                "Deep failure modes",
            )?;
            continue;
        }
        if !configuration.is_null()
            && configuration
                .as_mapping()
                .is_none_or(|mapping| !mapping.is_empty())
        {
            return Err(failure(format!(
                "{context} {event} must be unfiltered and have no inputs"
            )));
        }
    }
    Ok(())
}

const NATIVE_MATRIX: [(&str, &str); 6] = [
    ("linux-x64", "ubuntu-24.04"),
    ("linux-arm64", "ubuntu-24.04-arm"),
    ("macos-arm64", "macos-15"),
    ("macos-x64", "macos-15-intel"),
    ("windows-x64", "windows-2025"),
    ("windows-arm64", "windows-11-arm"),
];
// Work deadlines remain unchanged; these outer envelopes reserve bounded cache
// import/copy/transfer/cleanup time in addition to the established cold work.
const DEEP_CI_FUZZ_MINIMUM_TIMEOUT_MINUTES: u64 = 100;
const DEEP_CI_STRESS_TIMEOUT_MINUTES: u64 = 211;
const DEEP_CI_COMBINED_STRESS_TIMEOUT_MINUTES: u64 = 218;
fn check_runner_matrix(
    jobs: &Mapping,
    job_name: &str,
    expected: &[(&str, &str)],
    context: &str,
) -> Result<()> {
    let job = mapping(
        jobs.get(key(job_name))
            .ok_or_else(|| failure(format!("{context} job is absent")))?,
        context,
    )?;
    let strategy = mapping(
        job.get(key("strategy"))
            .ok_or_else(|| failure(format!("{context} strategy is absent")))?,
        context,
    )?;
    exact_mapping_keys(strategy, &["fail-fast", "matrix"], context)?;
    if strategy.get(key("fail-fast")).and_then(Value::as_bool) != Some(false) {
        return Err(failure(format!("{context} fail-fast policy differs")));
    }
    let matrix = mapping(
        strategy
            .get(key("matrix"))
            .ok_or_else(|| failure(format!("{context} matrix is absent")))?,
        context,
    )?;
    exact_mapping_keys(matrix, &["include"], context)?;
    let include = matrix
        .get(key("include"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure(format!("{context} matrix include is absent")))?;
    let actual: Vec<(&str, &str)> = include
        .iter()
        .map(|entry| {
            let entry = mapping(entry, context)?;
            exact_mapping_keys(entry, &["id", "runner"], context)?;
            Ok((
                scalar(entry, "id")
                    .ok_or_else(|| failure(format!("{context} matrix id is absent")))?,
                scalar(entry, "runner")
                    .ok_or_else(|| failure(format!("{context} matrix runner is absent")))?,
            ))
        })
        .collect::<Result<_>>()?;
    if actual != expected {
        return Err(failure(format!("{context} matrix entries differ")));
    }
    if scalar(job, "runs-on") != Some("${{ matrix.runner }}") {
        return Err(failure(format!("{context} runner selection differs")));
    }
    Ok(())
}

fn check_deep_ci_structure(workflow: &Mapping, jobs: &Mapping) -> Result<()> {
    check_push_and_dispatch_events(workflow, "deep CI")?;
    check_top_level_permissions(workflow)?;
    let concurrency = mapping(
        workflow
            .get(key("concurrency"))
            .ok_or_else(|| failure("deep CI lacks concurrency"))?,
        "deep CI concurrency",
    )?;
    exact_mapping_keys(
        concurrency,
        &["group", "cancel-in-progress"],
        "deep CI concurrency",
    )?;
    if scalar(concurrency, "group") != Some("deep-ci-${{ github.ref }}")
        || concurrency
            .get(key("cancel-in-progress"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(failure("deep CI concurrency differs"));
    }
    let fuzz = mapping(
        jobs.get(key("fuzz"))
            .ok_or_else(|| failure("deep CI fuzz job is absent"))?,
        "deep CI fuzz",
    )?;
    let fuzz_timeout = fuzz
        .get(key("timeout-minutes"))
        .and_then(Value::as_u64)
        .ok_or_else(|| failure("deep CI fuzz timeout is absent or nonnumeric"))?;
    if fuzz_timeout != DEEP_CI_FUZZ_MINIMUM_TIMEOUT_MINUTES {
        return Err(failure(
            "deep CI fuzz timeout differs from workload deadline",
        ));
    }
    check_deep_shards(
        fuzz,
        "fuzz",
        &[
            "quarter-one",
            "quarter-two",
            "quarter-three",
            "quarter-four",
        ],
        DEEP_CI_FUZZ_MINIMUM_TIMEOUT_MINUTES,
    )?;
    let miri = mapping(
        jobs.get(key("miri"))
            .ok_or_else(|| failure("deep CI Miri job is absent"))?,
        "deep CI Miri",
    )?;
    check_deep_shards(
        miri,
        "miri",
        &[
            "quarter-one",
            "quarter-two",
            "quarter-three",
            "quarter-four",
        ],
        113,
    )?;
    let planner = mapping(
        jobs.get(key("performance-plan"))
            .ok_or_else(|| failure("stress planner absent"))?,
        "stress planner",
    )?;
    let plan_steps = ordinary_steps(planner, "stress planner")?;
    check_scope_planner(planner, false)?;
    let plan_index = plan_steps
        .iter()
        .position(|step| {
            step.get(key("run")).and_then(Value::as_str)
                == Some("./target/ci/release/memcordon-ci ci performance-plan")
        })
        .ok_or_else(|| failure("actual stress plan command absent"))?;
    ordinary_driver_before_suite(plan_steps, plan_index)?;
    for (job_name, output, condition, suite, target) in [
        (
            "stress",
            "combined",
            "has-combined",
            "stress",
            "target/ci/stress",
        ),
        (
            "stress-packages",
            "split",
            "has-split",
            "stress-packages",
            "target/ci/stress-packages",
        ),
        (
            "stress-lifecycle",
            "split",
            "has-split",
            "stress-lifecycle",
            "target/ci/stress-lifecycle",
        ),
    ] {
        let job = mapping(
            jobs.get(key(job_name))
                .ok_or_else(|| failure("selected stress phase job absent"))?,
            "stress phase",
        )?;
        if scalar(job, "needs") != Some("performance-plan")
            || scalar(job, "if")
                != Some(format!("needs.performance-plan.outputs.{condition} == 'true'").as_str())
            || scalar(job, "runs-on") != Some("${{ matrix.runner }}")
            || job.get(key("timeout-minutes")).and_then(Value::as_u64)
                != Some(if job_name == "stress" {
                    DEEP_CI_COMBINED_STRESS_TIMEOUT_MINUTES
                } else {
                    DEEP_CI_STRESS_TIMEOUT_MINUTES
                })
        {
            return Err(failure(
                "deep CI stress timeout does not cover the complete cold workload",
            ));
        }
        let strategy = mapping(
            job.get(key("strategy"))
                .ok_or_else(|| failure("stress strategy absent"))?,
            "stress strategy",
        )?;
        let matrix = mapping(
            strategy
                .get(key("matrix"))
                .ok_or_else(|| failure("stress matrix absent"))?,
            "stress matrix",
        )?;
        exact_mapping_keys(matrix, &["include"], "selected stress matrix")?;
        if strategy.get(key("fail-fast")).and_then(Value::as_bool) != Some(false)
            || scalar(matrix, "include")
                != Some(
                    format!("${{{{ fromJSON(needs.performance-plan.outputs.{output}) }}}}")
                        .as_str(),
                )
        {
            return Err(failure("deep CI stress selected matrix differs"));
        }
        let steps = ordinary_steps(job, "stress phase")?;
        let index = steps
            .iter()
            .position(|step| {
                step.get(key("run")).and_then(Value::as_str)
                    == Some(format!("./target/ci/release/memcordon-ci suite {suite}").as_str())
            })
            .ok_or_else(|| failure("stress phase execution absent"))?;
        if steps[index].get(key("if")).is_some() {
            return Err(failure("selected stress execution cannot be conditional"));
        }
        ordinary_driver_before_suite(steps, index)?;
        let caches: Vec<_> = steps
            .iter()
            .filter(|step| {
                step.get(key("id")).and_then(Value::as_str) == Some("compiled")
                    || step.get(key("uses")).and_then(Value::as_str)
                        == Some("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9")
                        && step["with"]["key"].as_str()
                            == Some("${{ steps.compiled-context.outputs.product-key }}")
            })
            .collect();
        if caches.len() != 2
            || caches.iter().any(|step| {
                step.get(key("with"))
                    .and_then(|with| with.get(key("path")))
                    .and_then(Value::as_str)
                    .is_none_or(|path| {
                        path != target
                            && path != "${{ steps.compiled-context.outputs.product-paths }}"
                    })
            })
        {
            return Err(failure("stress phase compiled roots must remain isolated"));
        }
        let expected_context = format!(
            "./target/ci/release/memcordon-ci ci cache-context --purpose {suite} --shard complete"
        );
        if !steps[..index].iter().any(|step| {
            step["id"].as_str() == Some("compiled-context")
                && step["run"].as_str() == Some(&expected_context)
        }) {
            return Err(failure(
                "stress phase output mapping must match its actual recipe",
            ));
        }
        let expected_name = if job_name == "stress" {
            "stress-combined-${{ matrix.id }}"
        } else if job_name == "stress-packages" {
            "stress-packages-${{ matrix.id }}"
        } else {
            "stress-lifecycle-${{ matrix.id }}"
        };
        let uploads: Vec<_> = steps
            .iter()
            .filter(|step| {
                step.get(key("uses")).and_then(Value::as_str)
                    == Some("./.github/actions/upload-artifact")
            })
            .collect();
        if uploads.len() != 1
            || uploads[0].get(key("if")).and_then(Value::as_str) != Some("always()")
            || uploads[0]
                .get(key("with"))
                .and_then(|with| with.get(key("name")))
                .and_then(Value::as_str)
                != Some(expected_name)
            || uploads[0]
                .get(key("with"))
                .and_then(|with| with.get(key("include-hidden-files")))
                .and_then(Value::as_bool)
                != Some(true)
        {
            return Err(failure(
                "stress phase evidence must preserve phase, seed, active target and child reports on failure",
            ));
        }
    }
    let assessment = mapping(
        jobs.get(key("stress-assessment"))
            .ok_or_else(|| failure("stress aggregation absent"))?,
        "stress aggregation",
    )?;
    let required_needs = Value::Sequence(
        [
            "performance-plan",
            "stress",
            "stress-packages",
            "stress-lifecycle",
        ]
        .into_iter()
        .map(|name| Value::String(name.into()))
        .collect(),
    );
    if assessment.get(key("needs")) != Some(&required_needs)
        || scalar(assessment, "if") != Some("always() && github.event.deleted != true")
    {
        return Err(failure(
            "stress aggregation must collect all phase outcomes",
        ));
    }
    let assessment_steps = ordinary_steps(assessment, "stress aggregation")?;
    let assessment_index = assessment_steps
        .iter()
        .position(|step| {
            step.get(key("run")).and_then(Value::as_str)
                == Some("./target/ci/release/memcordon-ci ci aggregate-stress")
        })
        .ok_or_else(|| failure("actual stress aggregation command absent"))?;
    ordinary_driver_before_suite(assessment_steps, assessment_index)?;
    let stress = mapping(
        jobs.get(key("stress")).expect("validated stress job"),
        "deep CI stress",
    )?;
    if stress.get(key("timeout-minutes")).and_then(Value::as_u64)
        != Some(DEEP_CI_COMBINED_STRESS_TIMEOUT_MINUTES)
    {
        return Err(failure(
            "deep CI stress timeout does not cover the complete cold workload",
        ));
    }
    let stress_steps = ordinary_steps(stress, "deep CI stress")?;
    let mut phase_uploads = 0;
    for step in stress_steps.iter().filter_map(Value::as_mapping) {
        if scalar(step, "uses") != Some("./.github/actions/upload-artifact") {
            continue;
        }
        let with = mapping(
            step.get(key("with"))
                .ok_or_else(|| failure("stress phase upload settings absent"))?,
            "stress phase upload",
        )?;
        exact_mapping_keys(step, &["if", "uses", "with"], "stress phase upload")?;
        exact_mapping_keys(
            with,
            &["name", "path", "if-no-files-found", "include-hidden-files"],
            "stress phase upload settings",
        )?;
        if scalar(step, "if") != Some("always()")
            || scalar(with, "name") != Some("stress-combined-${{ matrix.id }}")
            || scalar(with, "if-no-files-found") != Some("warn")
            || with
                .get(key("include-hidden-files"))
                .and_then(Value::as_bool)
                != Some(true)
            || scalar(with, "path")
                != Some(
                    "target/ci/reports/stress\ntarget/ci/reports/stress-seed.txt\ntarget/ci/reports/stress-active-target.txt\ntarget/ci/reports/stress-deep_short_child_iterations.json\n",
                )
        {
            return Err(failure(
                "stress phase evidence must preserve phase, seed, active target and child reports on failure",
            ));
        }
        phase_uploads += 1;
    }
    if phase_uploads != 1 {
        return Err(failure(
            "deep stress requires exactly one phase evidence upload",
        ));
    }
    Ok(())
}

const ORDINARY_DRIVER_BUILD: &str = "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci";
const ORDINARY_SOURCE_PATHS: &str = "~/.cargo/registry/cache\n~/.cargo/git/db\n";

fn check_scope_planner(planner: &Mapping, conditional_plan: bool) -> Result<()> {
    if scalar(planner, "if") != Some("github.event.deleted != true") {
        return Err(failure("workflow scope planner must guard ref deletion"));
    }
    let outputs = mapping(
        planner
            .get(key("outputs"))
            .ok_or_else(|| failure("scope outputs absent"))?,
        "scope outputs",
    )?;
    if scalar(outputs, "standalone-common") != Some("${{ steps.scope.outputs.standalone-common }}")
    {
        return Err(failure("workflow scope output binding differs"));
    }
    let steps = ordinary_steps(planner, "scope planner")?;
    let scope = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step.get(key("run")).and_then(Value::as_str)
                == Some("./target/ci/release/memcordon-ci ci workflow-scope")
        })
        .collect::<Vec<_>>();
    if scope.len() != 1
        || scope[0].1.get(key("id")).and_then(Value::as_str) != Some("scope")
        || scope[0].1.get(key("if")).is_some()
    {
        return Err(failure(
            "actual unconditional workflow scope command absent",
        ));
    }
    ordinary_driver_before_suite(steps, scope[0].0)?;
    let plan = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step.get(key("run")).and_then(Value::as_str)
                == Some("./target/ci/release/memcordon-ci ci performance-plan")
        })
        .collect::<Vec<_>>();
    let condition = conditional_plan.then_some("steps.scope.outputs.standalone-common == 'true'");
    if plan.len() != 1
        || plan[0].0 <= scope[0].0
        || plan[0].1.get(key("if")).and_then(Value::as_str) != condition
    {
        return Err(failure(
            "performance plan must follow the actual workflow scope",
        ));
    }
    Ok(())
}

fn check_native_cache_role(job: &Mapping, purpose: &str) -> Result<()> {
    let steps = ordinary_steps(
        job,
        if purpose == "native-readiness" {
            "native readiness cache"
        } else {
            "native cache"
        },
    )?;
    if purpose == "native-readiness" {
        check_support_loader_diagnostic(steps)?;
    }
    let partition = " --partition native-tests";
    let expected = format!(
        "./target/ci/release/memcordon-ci ci cache-context --purpose {purpose} --shard complete{partition}"
    );
    let contexts = steps
        .iter()
        .filter_map(|step| step.get(key("run")).and_then(Value::as_str))
        .filter(|run| run.split_whitespace().any(|part| part == "cache-context"))
        .collect::<Vec<_>>();
    if contexts.iter().filter(|run| **run == expected).count() < 1
        || contexts
            .iter()
            .any(|run| !run.contains(&format!("--purpose {purpose} --shard complete"))
                && !(purpose == "native-debug" && matches!(*run, "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete" | "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --for-save" | "./target/ci/release/memcordon-ci ci cache-context --purpose native-auxiliary --shard complete --partition auxiliary-profiles")))
    {
        return Err(failure(format!("native debug/release cache role differs: purpose={purpose}; expected={expected}; contexts={contexts:?}")));
    }
    Ok(())
}

fn check_support_loader_diagnostic(steps: &[Value]) -> Result<()> {
    let unique = |id: &str| -> Result<usize> {
        let found = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| step["id"].as_str() == Some(id))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if found.len() != 1 {
            return Err(failure("support diagnostic role must be unique"));
        }
        Ok(found[0])
    };
    let original = unique("native_readiness_cleanup")?;
    let run = unique("support_loader_diagnostic")?;
    let cleanup = unique("support_loader_diagnostic_cleanup")?;
    let started = "always() && runner.os == 'Windows' && steps.support_loader_diagnostic.outputs.diagnostic-started == 'true'";
    let command = "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic";
    if original >= run
        || run >= cleanup
        || steps[run]["if"].as_str()
            != Some(
                "always() && runner.os == 'Windows' && steps.native_readiness_cleanup.outcome == 'success' && steps.native_readiness_cleanup.outputs.cache-quiescent == 'true'",
            )
        || steps[run]["run"].as_str() != Some(command)
        || steps[cleanup]["if"].as_str() != Some(started)
        || steps[cleanup]["run"].as_str() != Some(format!("{command} --cleanup").as_str())
        || steps[run]["continue-on-error"].as_bool() != Some(true)
        || steps[cleanup]["continue-on-error"].as_bool() != Some(true)
    {
        return Err(failure(
            "separate support diagnostic must preserve original settlement and cleanup",
        ));
    }
    let uploads = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step["with"]["path"].as_str()
                == Some(".release/support-loader-diagnostic/diagnostic-artifacts")
        })
        .collect::<Vec<_>>();
    if uploads.len() != 1 {
        return Err(failure(
            "separate support diagnostic artifact absent or duplicated",
        ));
    }
    let (index, upload) = uploads[0];
    if index <= cleanup
        || upload["uses"].as_str() != Some(PINNED_UPLOAD_ARTIFACT_ACTION)
        || upload["if"].as_str() != Some(started)
        || upload["continue-on-error"].as_bool() != Some(true)
        || upload["with"]["name"].as_str()
            != Some(
                "support-loader-diagnostic-${{ github.job }}-${{ github.run_id }}-${{ github.run_attempt }}",
            )
        || upload["with"]["if-no-files-found"].as_str() != Some("error")
        || upload["with"]["include-hidden-files"].as_bool() != Some(true)
        || upload["with"]["overwrite"].as_bool() != Some(false)
    {
        return Err(failure(
            "support diagnostic must retain its separate immutable bounded artifact namespace",
        ));
    }
    let guard = "(steps.support_loader_diagnostic.outputs.diagnostic-started != 'true' || steps.support_loader_diagnostic_cleanup.outputs.cache-quiescent == 'true')";
    for (ordinal, step) in steps.iter().enumerate() {
        if step["uses"].as_str()
            == Some("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9")
            && ordinal > cleanup
            && !step["if"]
                .as_str()
                .is_some_and(|condition| condition.contains(guard))
        {
            return Err(failure(
                "native cache save must retain diagnostic owner settlement",
            ));
        }
    }
    Ok(())
}

fn ordinary_steps<'a>(job: &'a Mapping, context: &str) -> Result<&'a [Value]> {
    let steps = job
        .get(key("steps"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure(format!("{context} steps absent")))?;
    for value in steps {
        let step = mapping(value, context)?;
        let diagnostic = step.get(key("uses")).and_then(Value::as_str)
            == Some(PINNED_UPLOAD_ARTIFACT_ACTION)
            && scalar(step, "if") == Some("always()")
            && step
                .get(key("with"))
                .and_then(|with| with.get(key("if-no-files-found")))
                .and_then(Value::as_str)
                == Some("warn");
        let optional_cache = (scalar(step, "uses")
            .is_some_and(|uses| uses.starts_with("actions/cache/"))
            || scalar(step, "run").is_some_and(|run| {
                run.contains(" ci download-cache-context ")
                    || run.ends_with(" ci bootstrap-cache-context")
                    || run.contains(" ci seed-context ")
                    || (run.contains(" ci cache-context ")
                        && step.get(key("timeout-minutes")).and_then(Value::as_u64) == Some(2))
            }))
            && step.get(key("continue-on-error")).and_then(Value::as_bool) == Some(true);
        let support_diagnostic = matches!(context, "native readiness cache" | "release native")
            && step.get(key("continue-on-error")).and_then(Value::as_bool) == Some(true)
            && match scalar(step, "id") {
                Some("support_loader_diagnostic") => {
                    scalar(step, "run")
                        == Some(
                            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic",
                        )
                }
                Some("support_loader_diagnostic_cleanup") => {
                    scalar(step, "run")
                        == Some(
                            "./target/ci/release/memcordon-ci consumer-readiness-loader-diagnostic --identity .release/native-readiness-identity.json --github-context --destination .release/support-loader-diagnostic --cleanup",
                        )
                }
                None => {
                    scalar(step, "uses") == Some(PINNED_UPLOAD_ARTIFACT_ACTION)
                        && value["with"]["path"].as_str()
                            == Some(".release/support-loader-diagnostic/diagnostic-artifacts")
                }
                _ => false,
            };
        if step.contains_key(key("continue-on-error"))
            && !diagnostic
            && !optional_cache
            && !support_diagnostic
            || context != "publisher" && step.contains_key(key("env"))
            || step.contains_key(key("shell"))
        {
            return Err(failure(
                "ordinary native controls may not ignore failure or override environment",
            ));
        }
    }
    Ok(steps)
}

fn ordinary_driver_before_suite(steps: &[Value], suite_index: usize) -> Result<()> {
    let builds: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            matches!(step.get(key("run")).and_then(Value::as_str),Some(run) if run==ORDINARY_DRIVER_BUILD
                ||run=="rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci --bin consumer-readiness")
        })
        .collect();
    if builds.len() != 1 || builds[0].0 >= suite_index || builds[0].1.get(key("if")).is_some() {
        let downloads = steps[..suite_index]
            .iter()
            .filter(|step| {
                step["uses"].as_str()
                    == Some("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c")
                    && step["with"]["artifact-ids"].as_str()
                        == Some("${{ needs.select.outputs.preparation-tool-artifact-id }}")
                    && step["with"]["path"].as_str() == Some(".release/tool")
                    && step["with"]["digest-mismatch"].as_str() == Some("error")
                    && step["if"].is_null()
            })
            .count();
        let extraction = steps[..suite_index]
            .iter()
            .filter(|step| {
                step["run"].as_str()
                    == Some(
                        "tar -xzf .release/tool/memcordon-publication-tool.tar.gz -C .release/tool",
                    )
                    && step["if"].is_null()
            })
            .count();
        if !builds.is_empty() || downloads != 1 || extraction != 1 {
            return Err(failure(
                "exactly one selected driver build or same-run immutable tool must precede work",
            ));
        }
    }
    Ok(())
}

fn cache_output_reference<'a>(value: &'a str, output: &str) -> Option<&'a str> {
    let (step, selected) = value
        .strip_prefix("${{ steps.")?
        .strip_suffix(" }}")?
        .split_once(".outputs.")?;
    (selected == output && !step.is_empty()).then_some(step)
}

fn ordinary_command(command: &str) -> Option<String> {
    for driver in [
        "./target/ci/release/memcordon-ci",
        "./.release/tool/memcordon-ci",
    ] {
        if let Some(arguments) = command
            .strip_prefix(driver)
            .filter(|arguments| arguments.starts_with(' '))
        {
            return Some(format!("./target/ci/release/memcordon-ci{arguments}"));
        }
    }
    None
}

fn check_compilation_checkpoint(
    steps: &[Value],
    compile: &str,
    execute: &str,
    selection: Option<&str>,
) -> Result<()> {
    let prefix = "./target/ci/release/memcordon-ci suite ";
    let compiles: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step["run"].as_str().and_then(ordinary_command).as_deref()
                == Some(format!("{prefix}{compile}").as_str())
        })
        .collect();
    let executions: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step["run"].as_str().and_then(ordinary_command).as_deref()
                == Some(format!("{prefix}{execute}").as_str())
        })
        .collect();
    if compiles.len() != 1
        || executions.len() != 1
        || compiles[0].0 >= executions[0].0
        || compiles[0].1["if"].as_str() != selection
        || selection.is_some() && executions[0].1["if"].as_str() != selection
    {
        return Err(failure(
            "required compilation must precede selected execution",
        ));
    }
    let owner = compiles[0].1["id"]
        .as_str()
        .ok_or_else(|| failure("compilation owner id absent"))?;
    let between = &steps[compiles[0].0 + 1..executions[0].0];
    let snapshots: Vec<_> = between
        .iter()
        .filter(|step| {
            step["run"].as_str().is_some_and(|run| {
                run.contains(" ci cache-snapshot --kind compiled ")
                    && compile.strip_prefix("fuzz-compile-").is_none_or(|shard| {
                        run.split_whitespace()
                            .collect::<Vec<_>>()
                            .windows(2)
                            .any(|pair| pair == ["--shard", shard])
                    })
            }) && step["if"].as_str().is_some_and(|guard| {
                guard.contains(&format!("steps.{owner}.outputs.cache-quiescent == 'true'"))
            })
        })
        .collect();
    if snapshots.len() != 1
        || !snapshots[0]["if"].as_str().is_some_and(|guard| {
            guard.contains(&format!("steps.{owner}.outputs.cache-quiescent == 'true'"))
                && guard.contains("always()")
        })
    {
        return Err(failure(
            "early checkpoint requires actual compilation settlement",
        ));
    }
    let snapshot = snapshots[0]["id"]
        .as_str()
        .ok_or_else(|| failure("compilation snapshot id absent"))?;
    if !between.iter().any(|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.contains(" ci cleanup-cache-snapshot --kind compiled "))
            && step["if"].as_str().is_some_and(|guard| {
                guard.contains("always()")
                    && (guard.contains(&format!("steps.{owner}.outputs.cache-quiescent == 'true'"))
                        || guard.contains(&format!("steps.{snapshot}.outcome == 'failure'")))
            })
    }) {
        return Err(failure(
            "closed compiled snapshot requires cleanup before execution",
        ));
    }
    let selected = format!("${{{{ steps.{snapshot}.outputs.snapshot-key }}}}");
    if between
        .iter()
        .filter(|step| {
            step["uses"].as_str()
                == Some("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9")
                && step["with"]["key"].as_str() == Some(selected.as_str())
        })
        .count()
        != 1
    {
        return Err(failure(
            "settled compilation must save before required execution",
        ));
    }
    Ok(())
}

/// Distinct snapshot identities are content keyed; they never save through a complete-entry key.
fn check_extended_cache(
    steps: &[Value],
    ordinal: usize,
    restore: bool,
    selected: &str,
    path: &str,
) -> Result<bool> {
    let step = &steps[ordinal];
    let find = |id: &str| -> Result<(usize, &Value)> {
        let found: Vec<_> = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| step["id"].as_str() == Some(id))
            .collect();
        if found.len() != 1 {
            return Err(failure("extended cache context must be unique"));
        }
        Ok(found[0])
    };
    let guard = step["if"].as_str().unwrap_or_default();
    let permitted_save = || {
        guard.contains("always()")
            && guard.contains("github.event_name == 'push'")
            && guard.contains("github.event_name == 'workflow_dispatch'")
    };
    if let Some(context) = cache_output_reference(selected, "seed-lookup-key") {
        let (before, producer) = find(context)?;
        let command = producer["run"]
            .as_str()
            .and_then(ordinary_command)
            .ok_or_else(|| failure("seed context command absent"))?;
        let args = command
            .strip_prefix("./target/ci/release/memcordon-ci ci seed-context ")
            .ok_or_else(|| failure("seed context command differs"))?;
        if ![
            "--kind compiled ",
            "--kind tool-build ",
            "--kind registry-archives",
            "--kind registry-index",
        ]
        .iter()
        .any(|kind| args.starts_with(kind))
            || !restore
            || before >= ordinal
            || step["with"]["restore-keys"].as_str()
                != Some(format!("${{{{ steps.{context}.outputs.seed-restore-prefix }}}}").as_str())
            || path != format!("${{{{ steps.{context}.outputs.seed-import-path }}}}")
            || !guard.contains(&format!("steps.{context}.outputs.seed-lookup-key != ''"))
        {
            return Err(failure("seed restore must use its actual bounded context"));
        }
        let id = step["id"]
            .as_str()
            .ok_or_else(|| failure("seed restore id absent"))?;
        let import = format!("./target/ci/release/memcordon-ci ci import-cache-snapshot {args}");
        if !steps.iter().skip(ordinal + 1).any(|candidate| {
            candidate["run"]
                .as_str()
                .and_then(ordinary_command)
                .as_deref()
                == Some(import.as_str())
                && candidate["if"].as_str().is_some_and(|guard| {
                    guard.contains(&format!("steps.{id}.outcome == 'success'"))
                        && guard.contains(&format!("steps.{id}.outputs.cache-matched-key != ''"))
                })
        }) {
            return Err(failure("seed restore requires actual validated import"));
        }
        return Ok(true);
    }
    if let Some(context) = cache_output_reference(selected, "snapshot-key") {
        let (before, producer) = find(context)?;
        let command = producer["run"]
            .as_str()
            .and_then(ordinary_command)
            .ok_or_else(|| failure("snapshot producer absent"))?;
        let owner_guard = producer["if"].as_str().unwrap_or_default();
        if !restore {
            let cleanup = command.replace(" ci cache-snapshot ", " ci cleanup-cache-snapshot ");
            let cleanup = cleanup
                .split_once(" --stage ")
                .map_or(cleanup.as_str(), |(command, _)| command);
            if !steps.iter().skip(ordinal + 1).any(|candidate| {
                candidate["run"]
                    .as_str()
                    .and_then(ordinary_command)
                    .as_deref()
                    == Some(cleanup)
                    && candidate["if"].as_str().is_some_and(|guard| {
                        guard.contains("always()")
                            && (guard.contains("quiescent == 'true'")
                                || guard.contains(&format!("steps.{context}.outcome == 'failure'")))
                    })
            }) {
                return Err(failure(
                    "snapshot transfer must finish before required staging cleanup",
                ));
            }
        }
        if !owner_guard.contains("always()")
            || !(owner_guard.contains("outputs.cache-quiescent == 'true'")
                || owner_guard.contains("outputs.miri-sysroot-quiescent == 'true'"))
        {
            return Err(failure("snapshot requires settled current writers"));
        }
        if before >= ordinal
            || !command.starts_with("./target/ci/release/memcordon-ci ci cache-snapshot --kind ")
            || !guard.contains(&format!("steps.{context}.outputs.snapshot-ready == 'true'"))
            || path != format!("${{{{ steps.{context}.outputs.snapshot-path }}}}")
        {
            return Err(failure(
                "snapshot save/probe requires current actual snapshot",
            ));
        }
        if command.contains("--kind compiled ")
            && !guard.contains(&format!("steps.{context}.outputs.input-key == steps."))
        {
            return Err(failure(
                "compiled checkpoint must recheck initial input identity",
            ));
        }
        if restore {
            if step["with"]["lookup-only"].as_bool() != Some(true)
                || !step["with"]["restore-keys"].is_null()
            {
                return Err(failure("snapshot probe must only look up exact content"));
            }
        } else {
            let probes: Vec<_> = steps
                .iter()
                .take(ordinal)
                .skip(before + 1)
                .filter(|candidate| {
                    candidate["with"]["key"].as_str() == Some(selected)
                        && candidate["with"]["path"].as_str() == Some(path)
                        && candidate["with"]["lookup-only"].as_bool() == Some(true)
                })
                .collect();
            if probes.len() != 1
                || !permitted_save()
                || !probes[0]["id"].as_str().is_some_and(|id| {
                    guard.contains(&format!("steps.{id}.outputs.cache-hit != 'true'"))
                })
            {
                return Err(failure(
                    "snapshot save needs exact probe and existing event policy",
                ));
            }
        }
        return Ok(true);
    }
    if let Some(context) = cache_output_reference(selected, "sysroot-key") {
        let (before, producer) = find(context)?;
        if before >= ordinal
            || producer["run"]
                .as_str()
                .and_then(ordinary_command)
                .as_deref()
                != Some("./target/ci/release/memcordon-ci ci miri-cache-context")
            || path != format!("${{{{ steps.{context}.outputs.sysroot-path }}}}")
        {
            return Err(failure("Miri sysroot cache context/path differs"));
        }
        let (setup, operation) = find("miri-sysroot-setup")?;
        let components: Vec<_> = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| {
                step["run"].as_str().and_then(ordinary_command).as_deref()
                    == Some("./target/ci/release/memcordon-ci ci prepare-miri-components")
            })
            .collect();
        if components.len() != 1 || components[0].0 >= before || !components[0].1["if"].is_null() {
            return Err(failure(
                "Miri components must precede generated sysroot context",
            ));
        }
        if operation["run"]
            .as_str()
            .and_then(ordinary_command)
            .as_deref()
            != Some("./target/ci/release/memcordon-ci ci prepare-miri-sysroot")
            || !operation["if"].is_null()
        {
            return Err(failure("Miri sysroot hit cannot skip actual pinned setup"));
        }
        if restore {
            if step["id"].as_str() != Some("miri-sysroot-cache")
                || setup <= ordinal
                || !guard.contains(&format!("steps.{context}.outputs.sysroot-key != ''"))
                || !step["with"]["restore-keys"].is_null()
            {
                return Err(failure(
                    "Miri sysroot restore must precede unconditional setup",
                ));
            }
        } else {
            let (recheck, probe) = find("miri-sysroot-save-context")?;
            if setup >= recheck || recheck >= ordinal || probe["run"].as_str().and_then(ordinary_command).as_deref() != Some("./target/ci/release/memcordon-ci ci miri-cache-context") || !permitted_save()
                || !guard.contains("steps.miri-sysroot-setup.outputs.miri-sysroot-ready == 'true'") || !guard.contains("steps.miri-sysroot-setup.outputs.miri-sysroot-quiescent == 'true'")
                || !guard.contains(&format!("steps.miri-sysroot-save-context.outputs.sysroot-key == steps.{context}.outputs.sysroot-key")) || !guard.contains("steps.miri-sysroot-cache.outputs.cache-hit != 'true'") { return Err(failure("Miri sysroot save requires current identity and setup settlement")); }
        }
        return Ok(true);
    }
    Ok(false)
}

fn cache_writer(step: &Value) -> bool {
    let run = step["run"].as_str().unwrap_or_default();
    run.contains(" cargo build ")
        || [
            " suite ",
            " ci fetch-downloads ",
            " ci prepare ",
            " ci prepare-miri-",
            " ci prepare-restored-cache ",
            " ci import-cache-snapshot ",
            " release build-target ",
            " release working-windows-prepare",
            " release installed-consumers ",
            " release working-windows-consumer ",
            " release packages ",
        ]
        .iter()
        .any(|part| run.contains(part))
}

fn cache_guard(source: &str) -> Result<cache_guard::Expr> {
    cache_guard::parse(source).map_err(|error| failure(format!("unsupported cache guard: {error}")))
}

fn require_cache_guard(guard: &cache_guard::Expr, required: &str) -> Result<()> {
    if !guard.requires(&cache_guard(required)?) {
        return Err(failure(format!("cache guard must require {required}")));
    }
    Ok(())
}

/// Validate retention against actual declared steps, before the separate suite
/// coverage pass folds normal and collect-all execution into one logical recipe.
fn check_cache_save_guards(steps: &[Value]) -> Result<()> {
    for snapshot in steps.iter().filter(|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.contains(" ci cache-snapshot --kind "))
    }) {
        let id = snapshot["id"]
            .as_str()
            .ok_or_else(|| failure("partial snapshot requires explicit id"))?;
        let key = format!("${{{{ steps.{id}.outputs.snapshot-key }}}}");
        let path = format!("${{{{ steps.{id}.outputs.snapshot-path }}}}");
        if !steps.iter().any(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                && step["with"]["key"].as_str() == Some(key.as_str())
                && step["with"]["path"].as_str() == Some(path.as_str())
        }) {
            return Err(failure(format!(
                "partial snapshot {id} requires its exact content-keyed save"
            )));
        }
    }
    if steps
        .iter()
        .any(|step| step["id"].as_str() == Some("workspace-fetch"))
    {
        for kind in ["registry-archives", "registry-index"] {
            let snapshots = steps
                .iter()
                .filter(|step| {
                    step["run"].as_str().is_some_and(|run| {
                        run.ends_with(&format!(" ci cache-snapshot --kind {kind}"))
                    })
                })
                .collect::<Vec<_>>();
            if snapshots.len() != 1 {
                return Err(failure(format!(
                    "workspace fetch requires one partial {kind} snapshot"
                )));
            }
            let id = snapshots[0]["id"].as_str().unwrap_or_default();
            let selected_key = format!("${{{{ steps.{id}.outputs.snapshot-key }}}}");
            if !steps.iter().any(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                    && step["with"]["key"].as_str() == Some(selected_key.as_str())
            }) {
                return Err(failure(format!(
                    "workspace fetch requires partial {kind} snapshot save"
                )));
            }
        }
    }
    let mut declared = BTreeMap::new();
    for (ordinal, step) in steps.iter().enumerate() {
        if let Some(id) = step["id"].as_str()
            && declared.insert(id, ordinal).is_some()
        {
            return Err(failure(format!("duplicate workflow step id {id}")));
        }
    }
    let find = |id: &str| -> Result<(usize, &Value)> {
        let ordinal = *declared
            .get(id)
            .ok_or_else(|| failure(format!("cache references unknown step {id}")))?;
        Ok((ordinal, &steps[ordinal]))
    };
    for (ordinal, step) in steps.iter().enumerate() {
        let run = step["run"].as_str().unwrap_or_default();
        let save = step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("actions/cache/save@"));
        let snapshot = run.contains(" ci cache-snapshot ");
        let recheck = step["id"]
            .as_str()
            .is_some_and(|id| id.contains("save-context"));
        let seed_consumer =
            run.contains(" ci seed-context ") || run.contains(" ci import-cache-snapshot ");
        if seed_consumer {
            ordinary_driver_before_suite(steps, ordinal)?;
            if let Some(condition) = step["if"].as_str() {
                for reference in cache_guard(condition)?.references() {
                    if let Some(id) = reference
                        .strip_prefix("steps.")
                        .and_then(|tail| tail.split('.').next())
                        && find(id)?.0 >= ordinal
                    {
                        return Err(failure(format!("seed consumer references later step {id}")));
                    }
                }
            }
            if run.contains(" ci import-cache-snapshot --kind compiled ") {
                let argument = |command: &str, flag: &str| {
                    command
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .windows(2)
                        .find(|pair| pair[0] == flag)
                        .map(|pair| pair[1].to_owned())
                };
                if steps.iter().enumerate().any(|(index, candidate)| {
                    candidate["run"].as_str().is_some_and(|candidate| {
                        candidate.contains(" ci prepare-restored-cache ")
                            && ["--purpose", "--shard", "--partition"]
                                .into_iter()
                                .all(|flag| argument(candidate, flag) == argument(run, flag))
                    }) && index >= ordinal
                }) {
                    return Err(failure(
                        "compiled seed import must follow complete-entry sanitation",
                    ));
                }
            }
        }
        if !save && !snapshot && !recheck {
            continue;
        }
        let guard = cache_guard(step["if"].as_str().unwrap_or_default())?;
        require_cache_guard(&guard, "always()")?;
        if guard.contains_status("success") {
            return Err(failure(
                "cache retention must not depend on aggregate success()",
            ));
        }
        for reference in guard.references() {
            if let Some(tail) = reference.strip_prefix("steps.") {
                let id = tail.split('.').next().expect("reference id");
                if find(id)?.0 >= ordinal {
                    return Err(failure(format!(
                        "cache producer {id} must precede retention"
                    )));
                }
            }
        }
        if save || snapshot {
            require_cache_guard(
                &guard,
                "github.event_name == 'push' || github.event_name == 'workflow_dispatch'",
            )?;
        }
        let key = step["with"]["key"].as_str().unwrap_or_default();
        // A closed immutable copy is independent of later live-root owners.
        if save
            && (cache_output_reference(key, "snapshot-key").is_some()
                || cache_output_reference(key, "sysroot-key").is_some())
        {
            continue;
        }
        // Source-only workspace acquisition has an explicit earlier boundary;
        // otherwise all declared writers preceding this live read participate.
        for owner in steps
            .iter()
            .take(ordinal)
            .filter(|owner| cache_writer(owner))
        {
            let id = owner["id"]
                .as_str()
                .ok_or_else(|| failure("cache writer lacks an explicit step id"))?;
            let owner_run = owner["run"].as_str().unwrap_or_default();
            let required = if owner_run.contains(" cargo build ") {
                format!("steps.{id}.outcome == 'skipped' || steps.{id}.outcome == 'success'")
            } else {
                format!(
                    "steps.{id}.outcome == 'skipped' || steps.{id}.outputs.cache-quiescent == 'true'"
                )
            };
            let fragment = cache_guard(&required)?;
            // Requiring success from a specific finished bootstrap build is a
            // stronger, valid form of that owner's nonstarted-or-settled gate.
            if owner_run.contains(" cargo build ")
                && guard.requires(&cache_guard(&format!("steps.{id}.outcome == 'success'"))?)
            {
                continue;
            }
            // A complete early fetch needs positive settlement, not a skipped arm.
            if guard.requires(&cache_guard(&format!(
                "steps.{id}.outputs.cache-quiescent == 'true'"
            ))?) {
                continue;
            }
            if !guard.requires(&fragment) {
                return Err(failure(format!(
                    "live cache read must cover skipped/settled writer {id}"
                )));
            }
            for (outcome, settled, permitted) in [
                ("skipped", "", true),
                ("failure", "true", true),
                ("failure", "false", false),
                ("cancelled", "", false),
                ("", "", false),
            ] {
                if owner_run.contains(" cargo build ") {
                    break;
                }
                let actual = guard.evaluate(
                    &|field| {
                        if field == format!("steps.{id}.outcome") {
                            return outcome.to_owned();
                        }
                        if field == format!("steps.{id}.outputs.cache-quiescent") {
                            return settled.to_owned();
                        }
                        if field == "github.event_name" {
                            "push"
                        } else if field == "matrix.shard" {
                            "quarter-one"
                        } else if field == "matrix.producer-job" {
                            ""
                        } else if field.ends_with(".outcome") {
                            "success"
                        } else if field.ends_with(".cache-hit") {
                            ""
                        } else if field.ends_with("-key") || field.ends_with("-compatibility") {
                            "same-key"
                        } else if field.ends_with("-paths") || field.ends_with("-path") {
                            "target/owned"
                        } else {
                            "true"
                        }
                        .to_owned()
                    },
                    &|status| status == "always",
                );
                // Positive cases can have additional recipe requirements. Every
                // unresolved scenario must remain false in the actual guard.
                if !permitted && actual {
                    return Err(failure("cache guard admits an unresolved writer scenario"));
                }
            }
        }
        if !save {
            continue;
        }
        let Some((context, field)) = ["product-key", "tool-build-key", "tool-key", "source-key"]
            .into_iter()
            .find_map(|field| cache_output_reference(key, field).map(|context| (context, field)))
        else {
            continue;
        };
        require_cache_guard(&guard, &format!("steps.{context}.outputs.{field} != ''"))?;
        let paths = match field {
            "product-key" => "product-paths",
            "tool-build-key" => "tool-build-path",
            "tool-key" => "tool-path",
            "source-key" => "source-paths",
            _ => unreachable!(),
        };
        require_cache_guard(&guard, &format!("steps.{context}.outputs.{paths} != ''"))?;
        let (context_ordinal, selected) = find(context)?;
        if context_ordinal >= ordinal {
            return Err(failure("initial cache context must precede save"));
        }
        let initial_command = selected["run"]
            .as_str()
            .and_then(ordinary_command)
            .ok_or_else(|| failure("selected cache context command absent"))?;
        let restores = steps
            .iter()
            .take(ordinal)
            .filter(|candidate| {
                candidate["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/cache/restore@"))
                    && candidate["with"]["key"].as_str() == Some(key)
            })
            .collect::<Vec<_>>();
        if restores.len() != 1 {
            return Err(failure(
                "completed cache requires one restore of its selected identity",
            ));
        }
        let restored = restores[0]["id"]
            .as_str()
            .ok_or_else(|| failure("complete restore id absent"))?;
        require_cache_guard(
            &guard,
            &format!(
                "!(steps.{restored}.outcome == 'success' && steps.{restored}.outputs.cache-hit == 'true')"
            ),
        )?;
        if field == "source-key" {
            if !initial_command.contains(" ci download-cache-context --family ") {
                return Err(failure(
                    "source cache identity must use source-only family context",
                ));
            }
            continue;
        }
        if field != "tool-key" {
            require_cache_guard(
                &guard,
                &format!("steps.{context}.outputs.compiled-cache-usable == 'true'"),
            )?;
        }
        let probes = steps
            .iter()
            .take(ordinal)
            .filter(|candidate| {
                candidate["id"]
                    .as_str()
                    .is_some_and(|id| id.contains("save-context"))
                    && candidate["run"]
                        .as_str()
                        .and_then(ordinary_command)
                        .is_some_and(|run| {
                            run.strip_suffix(" --for-save") == Some(initial_command.as_str())
                        })
            })
            .collect::<Vec<_>>();
        if probes.len() != 1 {
            return Err(failure(
                "completed cache requires one matching current save context",
            ));
        }
        let probe = probes[0]["id"].as_str().expect("matched context id");
        require_cache_guard(&guard, &format!("steps.{probe}.outcome == 'success'"))?;
        require_cache_guard(
            &guard,
            &format!("steps.{probe}.outputs.{field} == steps.{context}.outputs.{field}"),
        )?;
        if field != "tool-key" {
            require_cache_guard(
                &guard,
                &format!("steps.{probe}.outputs.payload-ready == 'true'"),
            )?;
        }
        let tool = initial_command
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .find(|pair| pair[0] == "--purpose")
            .map(|pair| pair[1].to_owned());
        let fact = match field {
            "tool-key" => format!("tool-{}-ready", tool.as_deref().unwrap_or_default()),
            "tool-build-key" => format!(
                "tool-{}-build-complete",
                tool.as_deref().unwrap_or_default()
            ),
            _ if initial_command.contains("--purpose private ") => {
                "compiled-recipe-complete".to_owned()
            }
            _ if initial_command.contains("--partition native-tests") => {
                "compiled-native-complete".to_owned()
            }
            _ if initial_command.contains("--partition product") => {
                "compiled-product-complete".to_owned()
            }
            _ => "compiled-recipe-complete".to_owned(),
        };
        let shard = initial_command
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .find(|pair| pair[0] == "--shard")
            .map(|pair| pair[1].to_owned())
            .unwrap_or_default();
        let producers = steps
            .iter()
            .take(ordinal)
            .filter(|owner| {
                let run = owner["run"].as_str().unwrap_or_default();
                if fact.starts_with("tool-") {
                    return run.contains(" suite supply-chain")
                        || run.contains(" ci prepare --profile fuzz");
                }
                if fact == "compiled-native-complete" {
                    return run.contains(" suite native-compile")
                        || run.contains(" release build-target ")
                        || run.contains(" release working-windows-prepare");
                }
                if fact == "compiled-product-complete" {
                    return run.contains(" release build-target ")
                        || run.contains(" release working-windows-prepare");
                }
                if tool.as_deref() == Some("miri") {
                    return run.contains(&format!(" suite miri-{shard} "))
                        || run.ends_with(&format!(" suite miri-{shard}"));
                }
                if tool.as_deref() == Some("fuzz") {
                    return run.contains(&format!(" suite fuzz-execute-{shard} "))
                        || run.ends_with(&format!(" suite fuzz-execute-{shard}"));
                }
                run.contains(" suite ")
                    && !run.contains(" suite fuzz-compile-")
                    && !run.contains(" suite native-compile")
                    || run.contains("--bin memcordon-release-rehearsal")
            })
            .filter_map(|owner| {
                owner["id"].as_str().map(|id| {
                    if owner["run"]
                        .as_str()
                        .is_some_and(|run| run.contains(" cargo build "))
                    {
                        format!("steps.{id}.outcome == 'success'")
                    } else {
                        format!("steps.{id}.outputs.{fact} == 'true'")
                    }
                })
            })
            .collect::<Vec<_>>();
        if producers.is_empty() {
            return Err(failure(
                "completed cache has no actual compilation producer",
            ));
        }
        require_cache_guard(&guard, &producers.join(" || "))?;
        if tool.as_deref() == Some("fuzz") {
            for owner in steps.iter().take(ordinal).filter(|owner| {
                owner["run"].as_str().is_some_and(|run| {
                    run.contains(" suite fuzz-compile-") || run.contains(" suite fuzz-execute-")
                })
            }) {
                let id = owner["id"].as_str().expect("validated fuzz writer id");
                require_cache_guard(
                    &guard,
                    &format!(
                        "steps.{id}.outcome == 'skipped' || steps.{id}.outputs.compiled-recipe-complete == 'true'"
                    ),
                )?;
            }
        }
        if fact == "compiled-native-complete" {
            for owner in steps.iter().take(ordinal).filter(|owner| {
                owner["run"].as_str().is_some_and(|run| {
                    run.contains(" suite native-execute")
                        || run.contains(" release build-target ")
                        || run.contains(" release working-windows-prepare")
                })
            }) {
                let id = owner["id"].as_str().expect("validated writer id");
                require_cache_guard(
                    &guard,
                    &format!(
                        "steps.{id}.outcome == 'skipped' || steps.{id}.outputs.compiled-native-complete == 'true'"
                    ),
                )?;
            }
        }
    }
    Ok(())
}

fn check_cache_lifecycle(steps: &[Value]) -> Result<()> {
    for step in steps {
        if let Some(shard) = step["run"]
            .as_str()
            .and_then(ordinary_command)
            .and_then(|run| {
                run.strip_prefix("./target/ci/release/memcordon-ci suite fuzz-compile-")
                    .map(str::to_owned)
            })
        {
            check_compilation_checkpoint(
                steps,
                &format!("fuzz-compile-{shard}"),
                &format!("fuzz-execute-{shard}"),
                step["if"].as_str(),
            )?;
        }
    }
    let mut restores = BTreeMap::new();
    let mut saves = BTreeMap::<String, Vec<(usize, &Value)>>::new();
    for (ordinal, step) in steps.iter().enumerate() {
        let uses = step["uses"].as_str().unwrap_or_default();
        if !uses.starts_with("actions/cache") {
            continue;
        }
        let restore = uses == "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
        if !restore && uses != "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9" {
            return Err(failure("cache must use pinned split restore/save"));
        }
        let path = step["with"]["path"]
            .as_str()
            .ok_or_else(|| failure("cache path absent"))?;
        let paths: Vec<_> = path
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        if paths.is_empty()
            || paths.iter().any(|path| {
                matches!(
                    *path,
                    "target"
                        | "target/ci-build"
                        | "target/ci-consumers"
                        | "target/ci-tools/bin"
                        | "target/ci-tools-build"
                ) || path.contains('*')
                    || [".release", "reports", "credentials", "installed"]
                        .iter()
                        .any(|excluded| path.contains(excluded))
            })
        {
            return Err(failure(
                "cache paths contain mixed ownership or runtime state",
            ));
        }
        let selected = step["with"]["key"]
            .as_str()
            .ok_or_else(|| failure("cache key absent"))?;
        if check_extended_cache(steps, ordinal, restore, selected, path)? {
            continue;
        }
        if restore {
            let id = step["id"]
                .as_str()
                .ok_or_else(|| failure("cache restore id absent"))?;
            if restores.insert(id.to_owned(), (ordinal, step)).is_some() {
                return Err(failure("duplicate cache restore id"));
            }
            if paths == ["~/.cargo/registry/cache", "~/.cargo/git/db"] {
                if !selected.starts_with("mc-download-bootstrap-v5-${{ runner.os }}-")
                    || selected.contains("runner.arch")
                    || selected.contains("github.sha")
                    || !step["if"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("hashFiles('Cargo.lock') != ''")
                    || !step["with"]["restore-keys"].as_str().is_some_and(|prefix| {
                        prefix.starts_with("mc-download-bootstrap-v5-${{ runner.os }}-")
                    })
                {
                    return Err(failure(
                        "download seed must use guarded partial bootstrap identity",
                    ));
                }
            } else if let Some(context) = cache_output_reference(selected, "product-key") {
                let input_command = steps
                    .iter()
                    .take(ordinal)
                    .find(|candidate| candidate["id"].as_str() == Some(context))
                    .and_then(|candidate| candidate["run"].as_str())
                    .ok_or_else(|| failure("compiled context must precede restore"))?;
                let argument = |command: &str, flag: &str| -> Option<String> {
                    let arguments: Vec<_> = command.split_whitespace().collect();
                    arguments
                        .windows(2)
                        .find(|pair| pair[0] == flag)
                        .map(|pair| pair[1].to_owned())
                };
                let prefix = format!("${{{{ steps.{context}.outputs.product-restore-prefix }}}}");
                if step["with"]["restore-keys"].as_str() != Some(prefix.as_str()) {
                    return Err(failure("compiled cache compatibility boundary differs"));
                }
                for mode in ["discard", "exact", "compatible"] {
                    if !steps.iter().skip(ordinal + 1).any(|candidate| {
                        candidate["run"].as_str().is_some_and(|run| {
                            run.contains(" ci prepare-restored-cache ")
                                && argument(run, "--mode").as_deref() == Some(mode)
                                && ["--purpose", "--shard", "--partition"].iter().all(|flag| {
                                    argument(run, flag) == argument(input_command, flag)
                                })
                        }) && candidate["if"]
                            .as_str()
                            .is_some_and(|condition| condition.contains(&format!("steps.{id}.")))
                    }) {
                        return Err(failure(
                            "compiled restore must sanitize transfer/exact/compatible outcomes",
                        ));
                    }
                }
            } else if let Some(context) = cache_output_reference(selected, "source-key") {
                if !steps.iter().take(ordinal).any(|candidate| {
                    candidate["id"].as_str() == Some(context)
                        && candidate["run"].as_str().is_some_and(|run| {
                            run.contains(" ci download-cache-context ")
                                || run.contains(" ci cache-context --purpose cargo-")
                        })
                }) {
                    return Err(failure("download context must precede every restore"));
                }
                let prefix = format!("${{{{ steps.{context}.outputs.source-restore-prefix }}}}");
                let paths = format!("${{{{ steps.{context}.outputs.source-paths }}}}");
                if step["with"]["restore-keys"].as_str() != Some(prefix.as_str()) || path != paths {
                    return Err(failure("download recipe context/path/prefix differ"));
                }
            } else if !["tool-key", "tool-build-key", "index-key"]
                .iter()
                .any(|output| cache_output_reference(selected, output).is_some())
            {
                return Err(failure("legacy or unprojected cache namespace"));
            }
        } else {
            let id = cache_output_reference(selected, "cache-primary-key")
                .or_else(|| {
                    restores
                        .iter()
                        .find_map(|(id, (_, restore)): (&String, &(usize, &Value))| {
                            (restore["with"]["key"].as_str() == Some(selected)
                                && restore["with"]["path"].as_str() == Some(path))
                            .then_some(id.as_str())
                        })
                })
                .ok_or_else(|| {
                    failure("cache save must use its originally selected exact context key")
                })?;
            saves
                .entry(id.to_owned())
                .or_default()
                .push((ordinal, step));
            let condition = step["if"].as_str().unwrap_or_default();
            if (path.contains(".outputs.product-paths")
                || path.contains(".outputs.tool-build-path"))
                && !(condition.contains("-complete == 'true'")
                    || condition.contains("steps.helper-build.outcome == 'success'"))
            {
                return Err(failure(
                    "complete compiled caches require actual successful compilation; failed settled output belongs only to snapshot seeds",
                ));
            }
            if paths == ["~/.cargo/registry/cache", "~/.cargo/git/db"] {
                if !condition
                    .contains("steps.bootstrap-home.outputs.bootstrap-home-matches == 'true'")
                {
                    return Err(failure(
                        "bootstrap seed save requires actual home association",
                    ));
                }
                let mut contexts = steps
                    .iter()
                    .enumerate()
                    .filter(|(_, candidate)| candidate["id"].as_str() == Some("bootstrap-home"));
                let (context_ordinal, context) = contexts.next().ok_or_else(|| {
                    failure("bootstrap seed save requires workspace home context")
                })?;
                if contexts.next().is_some()
                    || context_ordinal >= ordinal
                    || context["run"]
                        .as_str()
                        .and_then(ordinary_command)
                        .as_deref()
                        != Some("./target/ci/release/memcordon-ci ci bootstrap-cache-context")
                {
                    return Err(failure(
                        "bootstrap seed save requires one preceding workspace home context",
                    ));
                }
            }
            if !condition.contains("always()")
                || !condition.contains("github.event_name == 'push'")
                || !condition.contains("workflow_dispatch")
                || !(condition.contains("cache-primary-key != ''")
                    || ["source-key", "product-key", "tool-key", "tool-build-key"]
                        .iter()
                        .any(|field| condition.contains(&format!("{field} != ''"))))
                || (!condition.contains("cache-quiescent == 'true'")
                    && !condition.contains("outcome == 'success'")
                    && !(paths == ["~/.cargo/registry/cache", "~/.cargo/git/db"]
                        && condition.contains("success()")))
            {
                return Err(failure(
                    "cache save needs trusted context, nonempty key and settled owner",
                ));
            }
        }
    }
    for (id, (ordinal, restore)) in restores {
        let selected = match saves.remove(&id) {
            Some(selected) => selected,
            None if cache_output_reference(
                restore["with"]["key"].as_str().unwrap_or_default(),
                "source-key",
            )
            .is_some() =>
            {
                continue;
            }
            None => return Err(failure("cache restore/save pairing absent")),
        };
        for (save_ordinal, save) in selected {
            if save_ordinal <= ordinal || save["with"]["path"] != restore["with"]["path"] {
                return Err(failure("cache restore/save roots or ordering differ"));
            }
            if let Some(context) = cache_output_reference(
                restore["with"]["key"].as_str().unwrap_or_default(),
                "source-key",
            ) {
                let command = steps
                    .iter()
                    .take(ordinal)
                    .find(|step| step["id"].as_str() == Some(context))
                    .and_then(|step| step["run"].as_str())
                    .ok_or_else(|| failure("download context must precede restore"))?;
                let (population, population_key, producer_command) =
                    if command.ends_with("--family workspace") {
                        (
                            "workspace-downloads-populated",
                            "workspace-downloads-key",
                            " ci fetch-downloads --family workspace",
                        )
                    } else if command.ends_with("--family fuzz") {
                        (
                            "fuzz-downloads-populated",
                            "fuzz-downloads-key",
                            " ci prepare --profile fuzz",
                        )
                    } else if command.contains("--family tool-cargo-audit") {
                        (
                            "download-cargo-audit-populated",
                            "download-cargo-audit-key",
                            " suite supply-chain",
                        )
                    } else if command.contains("--family tool-cargo-deny") {
                        (
                            "download-cargo-deny-populated",
                            "download-cargo-deny-key",
                            " suite supply-chain",
                        )
                    } else if command.contains("--family tool-cargo-fuzz") {
                        (
                            "download-cargo-fuzz-populated",
                            "download-cargo-fuzz-key",
                            " ci prepare --profile fuzz",
                        )
                    } else {
                        return Err(failure("download recipe context unmodeled"));
                    };
                let save_context = context.strip_suffix("-context").map_or_else(
                    || format!("{context}-save-context"),
                    |base| format!("{base}-save-context"),
                );
                let save_probe = steps
                    .iter()
                    .take(save_ordinal)
                    .enumerate()
                    .find(|(_, step)| step["id"].as_str() == Some(&save_context))
                    .ok_or_else(|| failure("source save context absent"))?;
                if save_probe.0 <= ordinal
                    || save_probe.1["run"].as_str() != Some(command)
                    || save_probe.1["continue-on-error"].as_bool() != Some(true)
                {
                    return Err(failure(
                        "source save must recompute its exact recipe context",
                    ));
                }
                let condition = save["if"].as_str().unwrap_or_default();
                let producers = steps
                    .iter()
                    .take(save_probe.0)
                    .skip(ordinal + 1)
                    .filter(|step| {
                        step["run"]
                            .as_str()
                            .is_some_and(|run| run.contains(producer_command))
                    })
                    .filter_map(|step| step["id"].as_str())
                    .collect::<Vec<_>>();
                if !producers.iter().any(|owner| condition.contains(&format!("steps.{owner}.outputs.{population} == 'true'")) && condition.contains(&format!("steps.{save_context}.outputs.source-key == steps.{owner}.outputs.{population_key}")) && condition.contains(&format!("steps.{owner}.outputs.cache-quiescent == 'true'")))
                    || !condition.contains(&format!("steps.{save_context}.outputs.source-key == steps.{context}.outputs.source-key"))
                    || !condition.contains(&format!("steps.{save_context}.outcome == 'success'"))
                    || !(condition.contains(&format!("steps.{id}.outputs.cache-hit != 'true'"))
                        || cache_guard(condition)?.requires(&cache_guard(&format!("!(steps.{id}.outcome == 'success' && steps.{id}.outputs.cache-hit == 'true')"))?))
                    || (condition.contains("steps.deps.outputs.cache-hit")
                        || condition.contains("steps.supply-deps.outputs.cache-hit"))
                {
                    return Err(failure(
                        "complete downloads require actual recipe population and current source-key rechecks",
                    ));
                }
            }
            if cache_output_reference(
                restore["with"]["key"].as_str().unwrap_or_default(),
                "product-key",
            )
            .is_some()
                && !save["if"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("outputs.product-key == steps.")
            {
                return Err(failure(
                    "compiled cache save requires unchanged current inputs",
                ));
            }
        }
    }
    if !saves.is_empty() {
        return Err(failure("cache save references absent restore"));
    }
    Ok(())
}

fn check_deep_shards(job: &Mapping, family: &str, shards: &[&str], timeout: u64) -> Result<()> {
    exact_mapping_keys(
        job,
        &[
            "name",
            "needs",
            "if",
            "strategy",
            "runs-on",
            "timeout-minutes",
            "steps",
        ],
        "deep shard job",
    )?;
    if scalar(job, "needs") != Some("performance-plan")
        || scalar(job, "if") != Some("needs.performance-plan.outputs.standalone-common == 'true'")
    {
        return Err(failure("Deep common shard event selection differs"));
    }
    let strategy = mapping(
        job.get(key("strategy"))
            .ok_or_else(|| failure("shard strategy absent"))?,
        "shard strategy",
    )?;
    let fields = if family == "miri" {
        vec!["fail-fast", "max-parallel", "matrix"]
    } else {
        vec!["fail-fast", "matrix"]
    };
    exact_mapping_keys(strategy, &fields, "shard strategy")?;
    if family == "miri" && strategy["max-parallel"].as_u64() != Some(4) {
        return Err(failure(
            "Miri quarters require a four-cell concurrency bound",
        ));
    }
    let matrix = mapping(
        strategy
            .get(key("matrix"))
            .ok_or_else(|| failure("shard matrix absent"))?,
        "shard matrix",
    )?;
    exact_mapping_keys(matrix, &["shard"], "shard matrix")?;
    exact_string_sequence(
        matrix
            .get(key("shard"))
            .ok_or_else(|| failure("shard inventory absent"))?,
        shards,
        "complete shard inventory",
    )?;
    if scalar(strategy, "fail-fast")
        != Some(
            "${{ github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all' }}",
        )
        || scalar(job, "runs-on") != Some("ubuntu-24.04")
        || job.get(key("timeout-minutes")).and_then(Value::as_u64) != Some(timeout)
    {
        return Err(failure("deep shard runner or execution bounds differ"));
    }
    let steps = ordinary_steps(job, "deep shards")?;
    let checkout = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/checkout@"))
                && step["if"].is_null()
        })
        .ok_or_else(|| failure("deep shard checkout absent"))?;
    let toolchain = steps
        .iter()
        .position(|step| {
            step["run"].as_str() == Some("rustup toolchain install 1.97.1 --profile minimal")
                && step["if"].is_null()
        })
        .ok_or_else(|| failure("deep shard pinned toolchain absent"))?;
    let driver = steps
        .iter()
        .position(|step| step["run"].as_str() == Some(ORDINARY_DRIVER_BUILD))
        .ok_or_else(|| failure("deep shard driver build absent"))?;
    if checkout >= toolchain || toolchain >= driver {
        return Err(failure(
            "deep shard checkout and toolchain must precede driver build",
        ));
    }
    let workspace_fetches: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step["run"].as_str()
                == Some("./target/ci/release/memcordon-ci ci fetch-downloads --family workspace")
        })
        .collect();
    let first_work = steps
        .iter()
        .position(|step| {
            step["run"].as_str().is_some_and(|run| {
                run.split_whitespace().any(|part| part == "suite")
                    || run.ends_with("ci prepare --profile fuzz")
            })
        })
        .ok_or_else(|| failure("deep shard required work absent"))?;
    if workspace_fetches.len() != 1
        || workspace_fetches[0].0 <= driver
        || workspace_fetches[0].0 >= first_work
        || workspace_fetches[0].1["id"].as_str() != Some("workspace-fetch")
        || !workspace_fetches[0].1["if"].is_null()
    {
        return Err(failure(
            "deep shard workspace population must precede required work",
        ));
    }
    let mut invocations = Vec::new();
    let mut restores = 0;
    let mut saves = 0;
    let mut plans = 0;
    let mut compiled_restores = 0;
    let mut compiled_saves = 0;
    for (ordinal, value) in steps.iter().enumerate() {
        let step = mapping(value, "deep shard step")?;
        if let Some(run) = scalar(step, "run")
            && run.split_whitespace().any(|part| part == "suite")
        {
            ordinary_driver_before_suite(steps, ordinal)?;
            if !run.contains(" suite fuzz-compile-") {
                invocations.push((run, scalar(step, "if")));
            }
        }
        if let Some(uses) = scalar(step, "uses") {
            if uses.starts_with("actions/cache/") {
                let with = mapping(
                    step.get(key("with"))
                        .ok_or_else(|| failure("source cache inputs absent"))?,
                    "source cache",
                )?;
                let selected_key = scalar(with, "key").unwrap_or_default();
                let selected_path = scalar(with, "path").unwrap_or_default();
                if ["snapshot-key", "seed-lookup-key", "sysroot-key"]
                    .iter()
                    .any(|output| cache_output_reference(selected_key, output).is_some())
                {
                    continue;
                }
                if selected_key.starts_with("mc-download-bootstrap-v5-")
                    || selected_key.contains(".outputs.source-key")
                    || selected_key.contains(".outputs.product-key")
                    || selected_key.contains(".outputs.tool-key")
                    || selected_key.contains(".outputs.tool-build-key")
                    || selected_key.contains(".outputs.index-key")
                    || selected_key.contains(".outputs.cache-primary-key")
                {
                    let restore = uses.contains("/restore@");
                    if selected_path == ORDINARY_SOURCE_PATHS {
                        if restore {
                            let condition = scalar(step, "if").unwrap_or_default();
                            if !selected_key.contains("hashFiles('Cargo.lock',")
                                || !condition.contains("hashFiles('Cargo.lock') != ''")
                            {
                                return Err(failure(
                                    "workspace source cache must include its lockfile",
                                ));
                            }
                            if family == "fuzz"
                                && !condition.contains("hashFiles('fuzz/Cargo.lock') != ''")
                            {
                                return Err(failure("fuzz manifest must include its lockfile"));
                            }
                            restores += 1;
                        } else {
                            saves += 1;
                        }
                    } else if selected_key.contains(".outputs.product-key")
                        || selected_key.contains("steps.compiled")
                            && selected_key.contains(".outputs.cache-primary-key")
                    {
                        if restore {
                            compiled_restores += 1;
                        } else {
                            compiled_saves += 1;
                        }
                    }
                    continue;
                }
                return Err(failure("deep shard cache must use the V4 lifecycle"));
            }
            if uses == UPLOAD_ARTIFACT_ACTION {
                plans += 1;
                let with = mapping(
                    step.get(key("with"))
                        .ok_or_else(|| failure("shard plan upload absent"))?,
                    "shard plan upload",
                )?;
                let expected_path = match family {
                    "miri" => "target/ci/reports/miri",
                    "fuzz" => "target/ci/reports/fuzz",
                    _ => return Err(failure("unsupported shard family")),
                };
                if scalar(step, "if") != Some("always()")
                    || scalar(with, "path") != Some(expected_path)
                    || scalar(with, "if-no-files-found") != Some("warn")
                {
                    return Err(failure("shard plan failure evidence differs"));
                }
            }
        }
    }
    let mut expected: Vec<_> = shards
        .iter()
        .map(|shard| match (family, *shard) {
            ("miri", "quarter-one") => Ok((
                "./target/ci/release/memcordon-ci suite miri-quarter-one",
                Some("matrix.shard == 'quarter-one'"),
            )),
            ("miri", "quarter-two") => Ok((
                "./target/ci/release/memcordon-ci suite miri-quarter-two",
                Some("matrix.shard == 'quarter-two'"),
            )),
            ("miri", "quarter-three") => Ok((
                "./target/ci/release/memcordon-ci suite miri-quarter-three",
                Some("matrix.shard == 'quarter-three'"),
            )),
            ("miri", "quarter-four") => Ok((
                "./target/ci/release/memcordon-ci suite miri-quarter-four",
                Some("matrix.shard == 'quarter-four'"),
            )),
            ("fuzz", "quarter-one") => Ok((
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-one",
                Some("matrix.shard == 'quarter-one'"),
            )),
            ("fuzz", "quarter-two") => Ok((
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-two",
                Some("matrix.shard == 'quarter-two'"),
            )),
            ("fuzz", "quarter-three") => Ok((
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-three",
                Some("matrix.shard == 'quarter-three'"),
            )),
            ("fuzz", "quarter-four") => Ok((
                "./target/ci/release/memcordon-ci suite fuzz-execute-quarter-four",
                Some("matrix.shard == 'quarter-four'"),
            )),
            _ => Err(failure("unsupported shard")),
        })
        .collect::<Result<_>>()?;
    invocations.sort_unstable();
    expected.sort_unstable();
    if invocations != expected
        || restores != 1
        || saves != 1
        || plans != 1
        || compiled_restores != shards.len()
        || compiled_saves != shards.len()
    {
        return Err(failure(format!(
            "ordinary {family} shard invocation/cache/evidence coverage differs: invocations={invocations:?} expected={expected:?} source restores={restores} saves={saves} plans={plans} compiled restores={compiled_restores} saves={compiled_saves}"
        )));
    }
    check_cache_lifecycle(steps)?;
    for shard in shards {
        let partition = if family == "fuzz" {
            " --partition fuzz-targets"
        } else {
            ""
        };
        let recipe = format!(
            "./target/ci/release/memcordon-ci ci cache-context --purpose {family} --shard {shard}{partition}"
        );
        let context = format!("compiled-context-{shard}");
        let condition = format!("matrix.shard == '{shard}'");
        if !steps.iter().any(|step| {
            step["id"].as_str() == Some(context.as_str())
                && step["run"].as_str() == Some(recipe.as_str())
                && step["if"].as_str() == Some(condition.as_str())
        }) {
            return Err(failure("deep shard exact cache recipe differs"));
        }
    }
    if family == "fuzz" {
        for shard in shards {
            check_compilation_checkpoint(
                steps,
                &format!("fuzz-compile-{shard}"),
                &format!("fuzz-execute-{shard}"),
                Some(&format!("matrix.shard == '{shard}'")),
            )?;
        }
        let tool_context = steps
            .iter()
            .position(|step| {
                step["run"].as_str().is_some_and(|run| {
                    run.ends_with("ci cache-context --purpose cargo-fuzz --shard complete")
                })
            })
            .ok_or_else(|| failure("fuzz installed-tool context absent"))?;
        let prepare = steps
            .iter()
            .position(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.ends_with("ci prepare --profile fuzz"))
            })
            .ok_or_else(|| failure("fuzz pinned tool preparation absent"))?;
        if tool_context >= prepare {
            return Err(failure("fuzz tool restore must precede installation"));
        }
        let nightly = steps
            .iter()
            .position(|step| {
                step["run"].as_str()
                    == Some("rustup toolchain install nightly-2026-07-31 --profile minimal")
                    && step["if"].is_null()
            })
            .ok_or_else(|| failure("fuzz pinned nightly installation absent"))?;
        if nightly <= driver || nightly >= prepare {
            return Err(failure("fuzz pinned nightly must precede preparation"));
        }
    }
    Ok(())
}

fn check_selected_native_forms(jobs: &Mapping) -> Result<()> {
    let planner = mapping(
        jobs.get(key("macos-performance-plan"))
            .ok_or_else(|| failure("Mac performance selector absent"))?,
        "Mac selector",
    )?;
    let steps = ordinary_steps(planner, "Mac selector")?;
    check_scope_planner(planner, true)?;
    let selected = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step.get(key("run")).and_then(Value::as_str)
                == Some("./target/ci/release/memcordon-ci ci performance-plan")
        })
        .collect::<Vec<_>>();
    if selected.len() != 1
        || selected[0].1.get(key("if")).and_then(Value::as_str)
            != Some("steps.scope.outputs.standalone-common == 'true'")
        || selected[0].1.get(key("id")).and_then(Value::as_str) != Some("plan")
    {
        return Err(failure("Mac selector must run exactly once"));
    }
    ordinary_driver_before_suite(steps, selected[0].0)?;
    let outputs = mapping(
        planner
            .get(key("outputs"))
            .ok_or_else(|| failure("Mac selector output absent"))?,
        "Mac selector outputs",
    )?;
    if scalar(outputs, "split") != Some("${{ steps.plan.outputs.macos-split }}") {
        return Err(failure("Mac selector output differs"));
    }
    for (name, split, suite, phase) in [
        (
            "macos-combined",
            "false",
            "backend-macos-watchdog",
            "combined",
        ),
        ("macos-native", "true", "release-macos-native", "native"),
        (
            "macos-acceptance",
            "true",
            "release-macos-acceptance",
            "acceptance",
        ),
    ] {
        let job = mapping(
            jobs.get(key(name))
                .ok_or_else(|| failure("selected Mac phase absent"))?,
            name,
        )?;
        let condition = format!(
            "needs.macos-performance-plan.outputs.standalone-common == 'true' && needs.macos-performance-plan.outputs.split == '{split}'"
        );
        if scalar(job, "needs") != Some("macos-performance-plan")
            || scalar(job, "if") != Some(condition.as_str())
        {
            return Err(failure("Mac phase selection differs"));
        }
        check_native_runner_matrix(
            job,
            &[("macos-x64", "macos-15-intel"), ("macos-arm64", "macos-15")],
        )?;
        let steps = ordinary_steps(job, name)?;
        let run = format!("./target/ci/release/memcordon-ci suite {suite}");
        let operations = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| step.get(key("run")).and_then(Value::as_str) == Some(run.as_str()))
            .collect::<Vec<_>>();
        if operations.len() != 1 || operations[0].1.get(key("if")).is_some() {
            return Err(failure("selected Mac native phase cannot be skipped"));
        }
        ordinary_driver_before_suite(steps, operations[0].0)?;
        let context = format!(
            "./target/ci/release/memcordon-ci ci cache-context --purpose macos --shard {phase}"
        );
        if !steps
            .iter()
            .any(|step| step.get(key("run")).and_then(Value::as_str) == Some(context.as_str()))
        {
            return Err(failure("Mac phase cache identities must be separate"));
        }
        for (ordinal, step) in steps.iter().enumerate().filter(|(_, step)| {
            step.get(key("uses"))
                .and_then(Value::as_str)
                .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
        }) {
            if ordinal < operations[0].0
                || step["with"]["key"].as_str().is_some_and(|selected| {
                    cache_output_reference(selected, "snapshot-key").is_some()
                })
            {
                // Earlier acquisition and a closed immutable copy have their
                // own actual producer, independent of this later native phase.
                continue;
            }
            if !step
                .get(key("if"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .contains("steps.native.outputs.cache-quiescent == 'true'")
            {
                return Err(failure(
                    "Mac cache may save only after actual phase quiescence",
                ));
            }
        }
    }
    let assessment = mapping(
        jobs.get(key("macos-assessment"))
            .ok_or_else(|| failure("Mac selected assessment absent"))?,
        "Mac assessment",
    )?;
    if scalar(assessment, "if")
        != Some(
            "always() && github.event.deleted != true && needs.macos-performance-plan.result == 'success' && needs.macos-performance-plan.outputs.standalone-common == 'true'",
        )
    {
        return Err(failure("Mac selected assessment must run after failure"));
    }
    exact_string_sequence(
        assessment
            .get(key("needs"))
            .ok_or_else(|| failure("Mac assessment dependencies absent"))?,
        &[
            "macos-performance-plan",
            "macos-combined",
            "macos-native",
            "macos-acceptance",
        ],
        "Mac assessment dependencies",
    )?;
    let steps = ordinary_steps(assessment, "Mac assessment")?;
    if !steps.iter().any(|step| {
        step.get(key("run")).and_then(Value::as_str)
            == Some("./target/ci/release/memcordon-ci ci aggregate-macos")
            && step.get(key("if")).is_none()
    }) {
        return Err(failure("Mac actual report aggregation absent"));
    }
    for (architecture, runner) in [("x64", "windows-2025"), ("arm64", "windows-11-arm")] {
        for consumer in [false, true] {
            let name = format!(
                "windows-{}-{architecture}",
                if consumer { "installed" } else { "payload" }
            );
            let job = mapping(
                jobs.get(key(&name))
                    .ok_or_else(|| failure("selected Windows installed graph absent"))?,
                &name,
            )?;
            if scalar(job, "runs-on") != Some(runner)
                || scalar(job, "if") != Some("github.event.deleted != true")
                || (!consumer && job.get(key("needs")).is_some())
            {
                return Err(failure(
                    "selected Windows runner or unconditional graph differs",
                ));
            }
            let strategy = mapping(
                job.get(key("strategy"))
                    .ok_or_else(|| failure("Windows channel strategy absent"))?,
                "Windows strategy",
            )?;
            let matrix = mapping(
                strategy
                    .get(key("matrix"))
                    .ok_or_else(|| failure("Windows channel matrix absent"))?,
                "Windows matrix",
            )?;
            exact_mapping_keys(matrix, &["include"], "Windows exact matrix")?;
            let rows = matrix
                .get(key("include"))
                .and_then(Value::as_sequence)
                .ok_or_else(|| failure("Windows channel inventory absent"))?;
            if rows.len() != if consumer { 2 } else { 1 } {
                return Err(failure(
                    "Windows native and Cargo channel cardinality differs",
                ));
            }
            for (ordinal, row) in rows.iter().enumerate() {
                let row = mapping(row, "Windows row")?;
                exact_mapping_keys(
                    row,
                    if consumer {
                        &["id", "channel"]
                    } else {
                        &["id"]
                    },
                    "Windows row fields",
                )?;
                if scalar(row, "id") != Some(architecture)
                    || (consumer
                        && scalar(row, "channel")
                            != Some(if ordinal == 0 { "native" } else { "cargo" }))
                {
                    return Err(failure("Windows exact native and Cargo rows differ"));
                }
            }
            let steps = ordinary_steps(job, &name)?;
            if consumer {
                let producer = format!("windows-payload-{architecture}");
                if scalar(job, "needs") != Some(producer.as_str()) {
                    return Err(failure(
                        "Windows installed consumer must use its native producer",
                    ));
                }
                for channel in ["native", "cargo"] {
                    let run = format!(
                        "./target/ci/release/memcordon-ci release working-windows-consumer --channel {channel} --destination target/ci/windows-installed/{channel}"
                    );
                    let condition = format!("matrix.channel == '{channel}'");
                    let operations = steps
                        .iter()
                        .enumerate()
                        .filter(|(_, step)| {
                            step.get(key("run")).and_then(Value::as_str) == Some(run.as_str())
                        })
                        .collect::<Vec<_>>();
                    if operations.len() != 1
                        || operations[0].1.get(key("if")).and_then(Value::as_str)
                            != Some(condition.as_str())
                    {
                        return Err(failure("Windows literal channel execution differs"));
                    }
                    ordinary_driver_before_suite(steps, operations[0].0)?;
                }
            } else {
                let operations = steps
                    .iter()
                    .enumerate()
                    .filter(|(_, step)| {
                        step.get(key("run")).and_then(Value::as_str)
                            == Some(
                                "./target/ci/release/memcordon-ci release working-windows-prepare",
                            )
                    })
                    .collect::<Vec<_>>();
                if operations.len() != 1 || operations[0].1.get(key("if")).is_some() {
                    return Err(failure("Windows actual source producer absent"));
                }
                ordinary_driver_before_suite(steps, operations[0].0)?;
            }
        }
    }
    Ok(())
}

fn check_native_runner_matrix(job: &Mapping, rows: &[(&str, &str)]) -> Result<()> {
    if scalar(job, "runs-on") != Some("${{ matrix.runner }}") {
        return Err(failure("native matrix runner differs"));
    }
    let strategy = mapping(
        job.get(key("strategy"))
            .ok_or_else(|| failure("native strategy absent"))?,
        "native strategy",
    )?;
    let matrix = mapping(
        strategy
            .get(key("matrix"))
            .ok_or_else(|| failure("native matrix absent"))?,
        "native matrix",
    )?;
    exact_mapping_keys(matrix, &["include"], "native matrix fields")?;
    let actual = matrix
        .get(key("include"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure("native matrix include absent"))?;
    if actual.len() != rows.len() {
        return Err(failure("native architecture cardinality differs"));
    }
    for (row, (id, runner)) in actual.iter().zip(rows) {
        let row = mapping(row, "native architecture")?;
        exact_mapping_keys(row, &["id", "runner"], "native architecture fields")?;
        if scalar(row, "id") != Some(*id) || scalar(row, "runner") != Some(*runner) {
            return Err(failure("native exact architecture inventory differs"));
        }
    }
    Ok(())
}

fn check_standard_native_jobs(workflow: &Mapping, jobs: &Mapping) -> Result<()> {
    check_push_and_dispatch_events(workflow, "native backend")?;
    check_top_level_permissions(workflow)?;
    let concurrency = mapping(
        workflow
            .get(key("concurrency"))
            .ok_or_else(|| failure("native backend concurrency absent"))?,
        "native backend concurrency",
    )?;
    if scalar(concurrency, "group") != Some("backend-certification-${{ github.ref }}")
        || concurrency
            .get(key("cancel-in-progress"))
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(failure(
            "destructive native jobs may not cancel active cleanup",
        ));
    }
    for (name, runner, invocation) in [
        (
            "standard-linux",
            "ubuntu-24.04",
            "./target/ci/release/memcordon-ci suite backend-linux-cgroup",
        ),
        (
            "standard-windows",
            "windows-2025",
            "./target/ci/release/memcordon-ci suite backend-windows-job",
        ),
        (
            "standard-windows-arm64",
            "windows-11-arm",
            "./target/ci/release/memcordon-ci suite backend-windows-job",
        ),
    ] {
        let job = mapping(
            jobs.get(key(name))
                .ok_or_else(|| failure(format!("ordinary native job missing: {name}")))?,
            name,
        )?;
        if scalar(job, "runs-on") != Some(runner)
            || job.get(key("timeout-minutes")).and_then(Value::as_u64) != Some(173)
            || scalar(job, "needs") != Some("macos-performance-plan")
            || scalar(job, "if")
                != Some("needs.macos-performance-plan.outputs.standalone-common == 'true'")
        {
            return Err(failure("ordinary native runner or deadline differs"));
        }
        let steps = ordinary_steps(job, name)?;
        let suites: Vec<_> = steps
            .iter()
            .enumerate()
            .filter(|(_, value)| {
                value
                    .get(key("run"))
                    .and_then(Value::as_str)
                    .is_some_and(|run| run.split_whitespace().any(|part| part == "suite"))
            })
            .collect();
        if suites.len() != 1
            || suites[0].1.get(key("run")).and_then(Value::as_str) != Some(invocation)
            || suites[0].1.get(key("if")).is_some()
        {
            return Err(failure(
                "ordinary native suite is absent, substituted, or conditional",
            ));
        }
        ordinary_driver_before_suite(steps, suites[0].0)?;
    }
    check_selected_native_forms(jobs)?;
    let private = mapping(
        jobs.get(key("private-linux"))
            .ok_or_else(|| failure("private Linux job absent"))?,
        "private Linux",
    )?;
    if scalar(private, "if") != Some("github.event.deleted != true")
        || private.get(key("needs")).is_some()
    {
        return Err(failure(
            "optional private Linux work must remain independent",
        ));
    }
    Ok(())
}
pub fn check_deep_fuzz_shards(job: &Mapping) -> Result<()> {
    check_cache_save_guards(
        job["steps"]
            .as_sequence()
            .ok_or_else(|| failure("fuzz steps absent"))?,
    )?;
    let mut workflow = Mapping::new();
    let mut jobs = Mapping::new();
    jobs.insert(key("fuzz"), Value::Mapping(job.clone()));
    workflow.insert(key("jobs"), Value::Mapping(jobs));
    let normalized = normalize_failure_branches(&workflow)?;
    let job = normalized["jobs"]["fuzz"]
        .as_mapping()
        .expect("normalized fuzz job");
    check_deep_shards(
        job,
        "fuzz",
        &[
            "quarter-one",
            "quarter-two",
            "quarter-three",
            "quarter-four",
        ],
        DEEP_CI_FUZZ_MINIMUM_TIMEOUT_MINUTES,
    )
}

fn check_ci_structure(workflow: &Mapping, jobs: &Mapping, policy: &config::Policy) -> Result<()> {
    let events = mapping(
        workflow
            .get(key("on"))
            .ok_or_else(|| failure("CI workflow has no event map"))?,
        "CI events",
    )?;
    exact_mapping_keys(
        events,
        &["push", "pull_request", "merge_group", "workflow_dispatch"],
        "CI events",
    )?;
    for event in ["push", "pull_request"] {
        let event_map = mapping(
            events
                .get(key(event))
                .ok_or_else(|| failure(format!("CI lacks {event}")))?,
            event,
        )?;
        exact_mapping_keys(event_map, &["branches"], event)?;
        exact_string_sequence(
            event_map
                .get(key("branches"))
                .ok_or_else(|| failure(format!("{event} lacks branches")))?,
            &["**"],
            &format!("{event} branches"),
        )?;
    }
    let merge_group = mapping(
        events
            .get(key("merge_group"))
            .ok_or_else(|| failure("CI lacks merge_group"))?,
        "merge_group",
    )?;
    exact_mapping_keys(merge_group, &["types"], "merge_group")?;
    exact_string_sequence(
        merge_group
            .get(key("types"))
            .ok_or_else(|| failure("merge_group lacks types"))?,
        &["checks_requested"],
        "merge_group types",
    )?;
    check_top_level_permissions(workflow)?;
    let concurrency = mapping(
        workflow
            .get(key("concurrency"))
            .ok_or_else(|| failure("CI lacks concurrency"))?,
        "CI concurrency",
    )?;
    exact_mapping_keys(
        concurrency,
        &["group", "cancel-in-progress"],
        "CI concurrency",
    )?;
    if scalar(concurrency, "group")
        != Some("ci-${{ github.workflow }}-${{ github.event_name }}-${{ github.ref }}")
        || concurrency
            .get(key("cancel-in-progress"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(failure("CI concurrency policy differs"));
    }
    check_runner_matrix(jobs, "native", &NATIVE_MATRIX, "CI native")?;
    for name in [
        "policy",
        "quality",
        "msrv",
        "supply-chain",
        "macos-deadline",
    ] {
        let job = mapping(
            jobs.get(key(name))
                .ok_or_else(|| failure("CI common job absent"))?,
            name,
        )?;
        if scalar(job, "if") != Some("github.event_name != 'push'")
            || job.get(key("needs")).is_some()
        {
            return Err(failure(
                "CI common work must retain PR, merge-group and manual execution",
            ));
        }
    }
    let native = mapping(
        jobs.get(key("native")).expect("validated CI native"),
        "CI native",
    )?;
    if scalar(native, "if") != Some("github.event.deleted != true") {
        return Err(failure(
            "CI debug native must remain active on nondeleted events",
        ));
    }
    check_native_cache_role(native, "native-debug")?;
    for (name, suite) in [
        ("policy", "policy"),
        ("quality", "quality"),
        ("msrv", "msrv"),
        ("supply-chain", "supply-chain"),
        ("native", "native"),
        ("macos-deadline", "macos-deadline"),
    ] {
        let job = mapping(jobs.get(key(name)).expect("validated CI job"), name)?;
        let steps = ordinary_steps(job, name)?;
        let invocation = format!("./target/ci/release/memcordon-ci suite {suite}");
        let suites = steps
            .iter()
            .filter(|step| {
                step.get(key("run"))
                    .and_then(Value::as_str)
                    .is_some_and(|run| run.split_whitespace().any(|part| part == "suite"))
            })
            .collect::<Vec<_>>();
        if name == "native" {
            check_compilation_checkpoint(steps, "native-compile", "native-execute", None)?;
            if suites.len() != 3
                || suites[0]["run"].as_str()
                    != Some("./target/ci/release/memcordon-ci suite native-compile")
                || !suites[0]["if"].is_null()
                || suites[1]["run"].as_str()
                    != Some("./target/ci/release/memcordon-ci suite native-execute")
                || suites[1]["if"].as_str()
                    != Some(
                        "github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all'",
                    )
                || suites[2]["run"].as_str()
                    != Some(
                        "./target/ci/release/memcordon-ci suite native-execute --failure-mode collect-all",
                    )
                || suites[2]["if"].as_str()
                    != Some(
                        "github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all'",
                    )
            {
                return Err(failure(
                    "native stop and explicit manual diagnostic branches differ",
                ));
            }
        } else if suites.len() != 1
            || suites[0].get(key("run")).and_then(Value::as_str) != Some(invocation.as_str())
            || suites[0].get(key("if")).is_some()
        {
            return Err(failure("CI must execute its actual selected suite"));
        }
        for step in steps.iter().filter(|step| {
            step.get(key("uses"))
                .and_then(Value::as_str)
                .is_some_and(|uses| uses.starts_with("actions/checkout@"))
        }) {
            if step
                .get(key("with"))
                .is_some_and(|with| with.get(key("ref")).is_some())
            {
                return Err(failure(
                    "CI must preserve the event's PR/merge-group checkout source",
                ));
            }
        }
    }
    check_macos_deadline_job(jobs, "macos-deadline")?;
    let configured_matrix: Vec<&str> = policy
        .workflow
        .required_public_matrix
        .iter()
        .map(String::as_str)
        .collect();
    let expected_matrix: Vec<&str> = NATIVE_MATRIX.iter().map(|(id, _)| *id).collect();
    if configured_matrix != expected_matrix {
        return Err(failure("public native matrix policy differs"));
    }
    Ok(())
}

fn check_macos_deadline_job(jobs: &Mapping, name: &str) -> Result<()> {
    check_runner_matrix(
        jobs,
        name,
        &[("arm64", "macos-15"), ("x64", "macos-15-intel")],
        name,
    )?;
    let job = mapping(
        jobs.get(key(name))
            .ok_or_else(|| failure("missing macOS deadline job"))?,
        name,
    )?;
    let steps = job
        .get(key("steps"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure("macOS deadline steps missing"))?;
    let mut execution = false;
    let mut failure_artifact = false;
    for value in steps {
        let step = mapping(value, "macOS deadline step")?;
        if step.contains_key(key("env")) {
            return Err(failure(
                "macOS deadline configuration must use argv, not custom environment",
            ));
        }
        if scalar(step, "run").is_some_and(|value| value.ends_with("suite macos-deadline")) {
            execution = true;
        }
        if let Some(with) = step.get(key("with")).and_then(Value::as_mapping)
            && scalar(step, "uses") == Some(UPLOAD_ARTIFACT_ACTION)
            && scalar(with, "path") == Some("target/ci/deadline-evidence")
            && scalar(step, "if") == Some("always()")
        {
            failure_artifact = true;
        }
    }
    if !execution || !failure_artifact {
        return Err(failure(
            "macOS deadline execution or failure artifacts absent",
        ));
    }
    Ok(())
}

fn runner_selects_self_hosted(value: &Value) -> bool {
    match value {
        Value::String(runner) => runner == "self-hosted",
        Value::Sequence(runners) => runners
            .iter()
            .any(|runner| runner.as_str() == Some("self-hosted")),
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EnvironmentDefinition {
    file: String,
    step: String,
    variable: String,
    source: String,
}

fn static_run_command(command: &str) -> bool {
    !command.contains('\n')
        && !command.contains("${{")
        && !["&&", "&", ";", "|", "$(", "`", ">", "<"]
            .iter()
            .any(|operator| command.contains(operator))
}

fn check_release_row(
    job: &Mapping,
    target: &str,
    runner: &str,
    channel: Option<&str>,
) -> Result<()> {
    if scalar(job, "runs-on") != Some("${{ matrix.runner }}")
        || scalar(job, "if") != Some("needs.select.outputs.recovery-mode == 'reprepare'")
    {
        return Err(failure("release target host or selection differs"));
    }
    let rows = job
        .get(key("strategy"))
        .and_then(|strategy| strategy.get(key("matrix")))
        .and_then(|matrix| matrix.get(key("include")))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure("release target matrix absent"))?;
    if rows.len() != 1
        || rows[0].get(key("target")).and_then(Value::as_str) != Some(target)
        || rows[0].get(key("runner")).and_then(Value::as_str) != Some(runner)
        || rows[0].get(key("channel")).and_then(Value::as_str) != channel
    {
        return Err(failure("release exact target/channel/host row differs"));
    }
    Ok(())
}

const REHEARSAL_DRIVER_BUILD: &str = "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci";
const REHEARSAL_RUN: &str = "./.release/rehearsal-tool/memcordon-release-rehearsal run --publisher .release/tool/memcordon-ci --input .release/rehearsal-input --report-dir .release/rehearsal-results --jobs 2";
const RECOVERY_REHEARSAL_CONDITION: &str = "needs.select.outputs.preparation-kind == 'tagged' && needs.select.outputs.recovery-mode == 'publication-only' && github.event_name == 'workflow_dispatch' && inputs.preparation-mode == 'release' && startsWith(github.ref, 'refs/tags/')";

fn check_rehearsal_download(
    value: &Value,
    artifact: &str,
    path: &str,
    condition: Option<&str>,
    original: bool,
) -> Result<()> {
    let step = mapping(value, "rehearsal download")?;
    exact_mapping_keys(
        step,
        if condition.is_some() {
            &["if", "uses", "with"]
        } else {
            &["uses", "with"]
        },
        "rehearsal download",
    )?;
    if scalar(step, "uses")
        != Some("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c")
        || scalar(step, "if") != condition
    {
        return Err(failure("rehearsal download action/selection differs"));
    }
    let inputs = mapping(&value["with"], "rehearsal download inputs")?;
    exact_mapping_keys(
        inputs,
        if original {
            &[
                "artifact-ids",
                "path",
                "merge-multiple",
                "digest-mismatch",
                "run-id",
                "repository",
                "github-token",
            ]
        } else {
            &["artifact-ids", "path", "merge-multiple", "digest-mismatch"]
        },
        "rehearsal download inputs",
    )?;
    if scalar(inputs, "artifact-ids") != Some(artifact)
        || scalar(inputs, "path") != Some(path)
        || scalar(inputs, "digest-mismatch") != Some("error")
        || inputs.get(key("merge-multiple")).and_then(Value::as_bool) != Some(true)
        || original
            && (scalar(inputs, "run-id")
                != Some("${{ needs.recovery-inputs.outputs.original-run-id }}")
                || scalar(inputs, "repository") != Some("${{ github.repository }}")
                || scalar(inputs, "github-token") != Some("${{ github.token }}"))
    {
        return Err(failure(
            "rehearsal must download the exact current or original pair",
        ));
    }
    Ok(())
}

fn check_rehearsal_job(jobs: &Mapping, recovery: bool) -> Result<()> {
    let name = if recovery {
        "recovery-rehearse"
    } else {
        "rehearse"
    };
    let value = jobs
        .get(key(name))
        .ok_or_else(|| failure("required rehearsal absent"))?;
    let job = mapping(value, "rehearsal job")?;
    exact_mapping_keys(
        job,
        &[
            "name",
            "needs",
            "if",
            "runs-on",
            "timeout-minutes",
            "permissions",
            "steps",
        ],
        "rehearsal job",
    )?;
    if scalar(job, "name")
        != Some(if recovery {
            "Release recovery rehearsal"
        } else {
            "Release rehearsal"
        })
        || scalar(job, "if")
            != Some(if recovery {
                RECOVERY_REHEARSAL_CONDITION
            } else {
                "needs.select.outputs.recovery-mode == 'reprepare'"
            })
        || scalar(job, "runs-on") != Some("ubuntu-24.04")
        || job.get(key("timeout-minutes")).and_then(Value::as_u64) != Some(60)
    {
        return Err(failure("rehearsal name, mode, host or budget differs"));
    }
    exact_string_sequence(
        &value["needs"],
        if recovery {
            &["select", "recovery-inputs", "rehearsal-tool"]
        } else {
            &["select", "assemble-payload", "rehearsal-tool"]
        },
        "rehearsal successful prerequisites",
    )?;
    let permissions = mapping(&value["permissions"], "rehearsal permissions")?;
    exact_mapping_keys(
        permissions,
        if recovery {
            &["contents", "actions"]
        } else {
            &["contents"]
        },
        "rehearsal permissions",
    )?;
    if permissions
        .values()
        .any(|value| value.as_str() != Some("read"))
    {
        return Err(failure(
            "rehearsal may only read source and original artifacts",
        ));
    }
    let steps = ordinary_steps(job, "rehearsal steps")?;
    let download_count = 3;
    if steps.len() != download_count + 4 {
        return Err(failure(
            "rehearsal cannot compile, authenticate, cache or omit work",
        ));
    }
    check_rehearsal_download(
        &steps[0],
        "${{ needs.rehearsal-tool.outputs.artifact-id }}",
        ".release/rehearsal-tool",
        None,
        false,
    )?;
    if recovery {
        check_rehearsal_download(
            &steps[1],
            "${{ needs.recovery-inputs.outputs.tool-artifact-id }}",
            ".release/tool",
            None,
            true,
        )?;
        check_rehearsal_download(
            &steps[2],
            "${{ needs.recovery-inputs.outputs.prepared-artifact-id }}",
            ".release/rehearsal-input",
            None,
            true,
        )?;
    } else {
        for (index, artifact, path) in [
            (
                1,
                "${{ needs.select.outputs.preparation-tool-artifact-id }}",
                ".release/tool",
            ),
            (
                2,
                "${{ needs.assemble-payload.outputs.assembled-artifact-id }}",
                ".release/rehearsal-input",
            ),
        ] {
            check_rehearsal_download(&steps[index], artifact, path, None, false)?;
        }
    }
    for (offset, run) in [
        "tar -xzf .release/rehearsal-tool/memcordon-release-rehearsal.tar.gz -C .release/rehearsal-tool",
        "tar -xzf .release/tool/memcordon-publication-tool.tar.gz -C .release/tool",
        REHEARSAL_RUN,
    ].into_iter().enumerate() {
        let step = mapping(&steps[download_count + offset], "rehearsal invocation")?;
        exact_mapping_keys(step, if offset == 2 { &["id", "run"] } else { &["run"] }, "required rehearsal invocation")?;
        if scalar(step, "run") != Some(run) || offset == 2 && scalar(step, "id") != Some("rehearsal") {
            return Err(failure("rehearsal must execute downloaded helper and publisher unconditionally"));
        }
    }
    let diagnostic = &steps[download_count + 3];
    let expected: Value = serde_yaml::from_str(if recovery {
        "name: Retain recovery rehearsal diagnostics\nif: always()\ncontinue-on-error: true\nuses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\nwith:\n  name: recovery-rehearsal-${{ github.run_id }}-${{ github.run_attempt }}\n  path: .release/rehearsal-results\n  if-no-files-found: warn\n  retention-days: 7\n  include-hidden-files: true\n  overwrite: false\n"
    } else {
        "name: Retain rehearsal diagnostics\nif: always()\ncontinue-on-error: true\nuses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\nwith:\n  name: rehearsal-${{ github.run_id }}-${{ github.run_attempt }}\n  path: .release/rehearsal-results\n  if-no-files-found: warn\n  retention-days: 7\n  include-hidden-files: true\n  overwrite: false\n"
    }).map_err(|error| failure(format!("invalid rehearsal diagnostic contract: {error}")))?;
    if diagnostic != &expected {
        return Err(failure(
            "rehearsal diagnostics must be bounded, optional and nonauthoritative",
        ));
    }
    Ok(())
}

fn check_rehearsal_tool(jobs: &Mapping) -> Result<()> {
    let select = jobs
        .get(key("select"))
        .ok_or_else(|| failure("selection absent"))?;
    if !select["outputs"]["rehearsal-tool-artifact-id"].is_null() {
        return Err(failure(
            "selection cannot build the independent rehearsal helper",
        ));
    }
    let selection_steps = select["steps"]
        .as_sequence()
        .ok_or_else(|| failure("selection steps absent"))?;
    if selection_steps
        .iter()
        .filter(|step| step["run"].as_str() == Some(REHEARSAL_DRIVER_BUILD))
        .count()
        != 1
    {
        return Err(failure("selection must build only its current main driver"));
    }
    let format = selection_steps.iter().position(|step| step["run"].as_str() == Some("rustup run 1.97.1 cargo fmt --all -- --check")
        && step["if"].as_str() == Some("github.event_name != 'workflow_dispatch' || inputs.recovery-mode == 'reprepare'"))
        .ok_or_else(|| failure("reprepare formatting must precede main driver compilation"))?;
    let build = selection_steps
        .iter()
        .position(|step| step["run"].as_str() == Some(REHEARSAL_DRIVER_BUILD))
        .expect("driver checked");
    let selected = selection_steps
        .iter()
        .position(|step| step["id"].as_str() == Some("source"))
        .ok_or_else(|| failure("source selection absent"))?;
    let check = selection_steps.iter().position(|step| step["run"].as_str() == Some("./target/ci/release/memcordon-ci release check-preparation --build-source .release/build-source.json --consumer-readiness")
        && step["if"].as_str() == Some("steps.source.outputs.recovery-mode == 'reprepare'"))
        .ok_or_else(|| failure("selected preparation requires cheap policy/source checks"))?;
    if !(format < build && build < selected && selected < check) {
        return Err(failure("early preparation validation order differs"));
    }
    let selection_upload = selection_steps
        .iter()
        .find(|step| step["id"].as_str() == Some("selection"))
        .ok_or_else(|| failure("selection handoff absent"))?;
    if !selection_upload["if"].is_null() {
        return Err(failure(
            "recovery must also upload current selection metadata",
        ));
    }
    let helper = jobs
        .get(key("rehearsal-tool"))
        .ok_or_else(|| failure("independent helper absent"))?;
    if helper["needs"].as_str() != Some("select")
        || helper["outputs"]["artifact-id"].as_str()
            != Some("${{ steps.helper.outputs.artifact-id }}")
    {
        return Err(failure(
            "independent helper must depend only on selection and expose its upload",
        ));
    }
    let steps = helper["steps"]
        .as_sequence()
        .ok_or_else(|| failure("selection steps absent"))?;
    let build = steps
        .iter()
        .position(|step| step["run"].as_str() == Some("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/rehearsal-build -p memcordon-ci --bin memcordon-release-rehearsal"))
        .ok_or_else(|| failure("independent helper must build only the helper binary"))?;
    let pack = steps
        .iter()
        .position(|step| {
            step["run"].as_str() == Some("./.release/tool/memcordon-ci release rehearsal-tool --executable target/ci/rehearsal-build/release/memcordon-release-rehearsal")
        })
        .ok_or_else(|| failure("rehearsal helper packaging absent"))?;
    let upload = steps
        .iter()
        .position(|step| step["id"].as_str() == Some("helper"))
        .ok_or_else(|| failure("rehearsal helper upload absent"))?;
    if !(build < pack && pack < upload)
        || steps
            .iter()
            .filter(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.contains("cargo build"))
            })
            .count()
            != 1
        || [build, pack, upload].into_iter().any(|index| {
            !steps[index]["if"].is_null() || !steps[index]["continue-on-error"].is_null()
        })
    {
        return Err(failure(
            "helper build/pack/upload must succeed in both recovery modes",
        ));
    }
    let expected: Value = serde_yaml::from_str("id: helper\nuses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\nwith:\n  name: rehearsal-tool-${{ github.run_id }}-${{ github.run_attempt }}\n  path: .release/rehearsal-tool/memcordon-release-rehearsal.tar.gz\n  if-no-files-found: error\n  include-hidden-files: true\n  overwrite: false\n").map_err(|error| failure(format!("invalid helper upload contract: {error}")))?;
    if steps[upload] != expected {
        return Err(failure(
            "helper must be a separate immutable single-executable archive",
        ));
    }
    let assemble = jobs
        .get(key("assemble"))
        .ok_or_else(|| failure("assembly absent"))?;
    if assemble["outputs"]["candidate-artifact-id"].as_str()
        != Some("${{ steps.candidate.outputs.artifact-id }}")
    {
        return Err(failure(
            "assembly must expose the existing candidate artifact ID",
        ));
    }
    Ok(())
}

fn check_readiness_candidate_steps(
    job: &Mapping,
    steps: &[Value],
    name: &str,
    native_name: &str,
) -> Result<()> {
    if job.get(key("timeout-minutes")).and_then(Value::as_u64) != Some(241)
        || job
            .get(key("outputs"))
            .and_then(|outputs| outputs.get("artifact-id"))
            .and_then(Value::as_str)
            != Some("${{ steps.readiness-upload.outputs.artifact-id }}")
        || job
            .get(key("outputs"))
            .and_then(|outputs| outputs.get("artifact-digest"))
            .and_then(Value::as_str)
            != Some("${{ steps.readiness-upload.outputs.artifact-digest }}")
    {
        return Err(failure(
            "readiness owner deadline or immutable upload routing differs",
        ));
    }
    let rows = job
        .get(key("strategy"))
        .and_then(|strategy| strategy.get("matrix"))
        .and_then(|matrix| matrix.get("include"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure("readiness owner row absent"))?;
    if rows[0].get("producer-job").and_then(Value::as_str) != Some(name)
        || rows[0].get("native-job").and_then(Value::as_str) != Some(native_name)
    {
        return Err(failure(
            "readiness producer name or selected native artifact owner differs",
        ));
    }
    let operations = [
        (
            "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json",
            "matrix.producer-job != ''",
        ),
        (
            "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            "matrix.producer-job != ''",
        ),
        (
            "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
            "always() && matrix.producer-job != ''",
        ),
        (
            "./target/ci/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v1.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json",
            "always() && matrix.producer-job != ''",
        ),
    ];
    let mut previous = None;
    for (run, condition) in operations {
        let selected = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| step.get("run").and_then(Value::as_str) == Some(run))
            .collect::<Vec<_>>();
        if selected.len() != 1
            || selected[0].1.get("if").and_then(Value::as_str) != Some(condition)
            || selected[0].1.get("continue-on-error").is_some()
            || previous.is_some_and(|previous| previous >= selected[0].0)
        {
            return Err(failure(
                "readiness acquire/cleanup/seal order or failure propagation differs",
            ));
        }
        previous = Some(selected[0].0);
    }
    let upload = steps
        .iter()
        .filter(|step| step.get("id").and_then(Value::as_str) == Some("readiness-upload"))
        .collect::<Vec<_>>();
    if upload.len() != 1
        || upload[0].get("if").and_then(Value::as_str)
            != Some("always() && matrix.producer-job != ''")
        || upload[0]["with"]["overwrite"].as_bool() != Some(false)
        || upload[0]["with"]["include-hidden-files"].as_bool() != Some(true)
        || upload[0]["with"]["if-no-files-found"].as_str() != Some("error")
        || upload[0]["with"]["path"].as_str() != Some(".release/readiness-cell")
    {
        return Err(failure(
            "readiness original producer artifact custody differs",
        ));
    }
    Ok(())
}

fn check_release_structure(jobs: &Mapping) -> Result<()> {
    let select = jobs["select"]["steps"]
        .as_sequence()
        .ok_or_else(|| failure("Release selection steps absent"))?;
    if select.iter().any(|step| {
        matches!(
            step["id"].as_str(),
            Some("workspace-downloads" | "workspace-fetch")
        )
    }) {
        return Err(failure(
            "Release selection must not restore/fetch the complete Workspace family",
        ));
    }
    check_rehearsal_tool(jobs)?;
    check_rehearsal_job(jobs, false)?;
    check_rehearsal_job(jobs, true)?;
    let mut candidate_owners = vec![
        "select".to_owned(),
        "native-linux-x64".into(),
        "native-linux-arm64".into(),
        "native-windows-x64".into(),
        "native-windows-arm64".into(),
    ];
    let mut public_owners = Vec::new();
    for platform in ["linux-x64", "linux-arm64", "windows-x64", "windows-arm64"] {
        for channel in ["native", "cargo"] {
            candidate_owners.push(format!("candidate-{platform}-{channel}"));
            public_owners.push(format!("public-{platform}-{channel}"));
        }
    }
    for name in candidate_owners.iter().skip(1).chain(public_owners.iter()) {
        let job = jobs
            .get(name)
            .ok_or_else(|| failure("Release producer absent"))?;
        let matrix = job["strategy"]["matrix"]
            .as_mapping()
            .ok_or_else(|| failure("Release producer matrix absent"))?;
        exact_mapping_keys(matrix, &["include"], "Release producer matrix")?;
        let rows = matrix["include"]
            .as_sequence()
            .ok_or_else(|| failure("Release producer matrix rows absent"))?;
        if job["name"].as_str() != Some("${{ matrix.producer-job }}")
            || rows.len() != 1
            || rows[0]["producer-job"].as_str() != Some(name.as_str())
        {
            return Err(failure(
                "Release producer must have one uniquely named matrix row",
            ));
        }
    }
    for (name, scope, condition) in [
        (
            "readiness-candidate-report",
            "candidate-before-publication",
            "always() && needs.select.result == 'success' && needs.select.outputs.recovery-mode == 'reprepare'",
        ),
        (
            "readiness-complete-report",
            "complete-profile",
            "always() && (needs.publish.result == 'success' || needs.recovery-publish.result == 'success') && needs.select.outputs.preparation-kind == 'tagged'",
        ),
    ] {
        let job = jobs
            .get(key(name))
            .and_then(Value::as_mapping)
            .ok_or_else(|| failure("finite readiness reporting owner absent"))?;
        let mut expected = candidate_owners.clone();
        if scope == "complete-profile" {
            expected.extend(
                ["assemble", "publish", "recovery-inputs", "recovery-publish"].map(str::to_owned),
            );
            expected.extend(public_owners.clone());
        }
        let required = expected.iter().map(String::as_str).collect::<BTreeSet<_>>();
        let actual = job["needs"]
            .as_sequence()
            .ok_or_else(|| failure("finite report dependencies absent"))?;
        let actual_keys = actual
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        if actual.len() != required.len()
            || actual_keys != required
            || job["if"].as_str() != Some(condition)
            || job["timeout-minutes"].as_u64() != Some(20)
        {
            return Err(failure(
                "finite candidate/full report dependency set, condition or deadline differs",
            ));
        }
        let permissions = job
            .get(key("permissions"))
            .and_then(Value::as_mapping)
            .ok_or_else(|| failure("report read permissions absent"))?;
        exact_mapping_keys(
            permissions,
            &["contents", "actions"],
            "report read permissions",
        )?;
        if scalar(permissions, "contents") != Some("read")
            || scalar(permissions, "actions") != Some("read")
        {
            return Err(failure("report must remain read only"));
        }
        let steps = job["steps"]
            .as_sequence()
            .ok_or_else(|| failure("report steps absent"))?;
        let invocation = format!(
            "./target/ci/release/memcordon-ci release consumer-readiness-report --identity .release/readiness-identity.json --verifier ./target/ci/release/memcordon-readiness-verifier --scope {scope} --destination .release/readiness-report"
        );
        let reports = steps
            .iter()
            .filter(|step| step["run"].as_str() == Some(invocation.as_str()))
            .collect::<Vec<_>>();
        if reports.len()!=1||reports[0].get("continue-on-error").is_some()||reports[0].get("if").is_some()||!steps.iter().any(|step|step["run"].as_str()==Some("rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-readiness-verifier")){return Err(failure("independent finite verifier invocation/failure propagation absent"));}
        let uploads = steps
            .iter()
            .filter(|step| step["with"]["path"].as_str() == Some(".release/readiness-report"))
            .collect::<Vec<_>>();
        if uploads.len() != 1
            || uploads[0]["if"].as_str() != Some("always()")
            || uploads[0]["with"]["overwrite"].as_bool() != Some(false)
            || uploads[0]["with"]["include-hidden-files"].as_bool() != Some(true)
            || uploads[0]["with"]["if-no-files-found"].as_str() != Some("error")
        {
            return Err(failure(
                "report failure diagnostics must retain original custody",
            ));
        }
    }
    for (id, target, runner) in [
        ("linux-x64", "x86_64-unknown-linux-gnu", "ubuntu-24.04"),
        (
            "linux-arm64",
            "aarch64-unknown-linux-gnu",
            "ubuntu-24.04-arm",
        ),
        ("windows-x64", "x86_64-pc-windows-msvc", "windows-2022"),
        ("windows-arm64", "aarch64-pc-windows-msvc", "windows-11-arm"),
    ] {
        for channel in ["native", "cargo"] {
            let name = format!("public-{id}-{channel}");
            let job = jobs
                .get(key(&name))
                .and_then(Value::as_mapping)
                .ok_or_else(|| failure("mandatory public readiness owner absent"))?;
            exact_string_sequence(
                &job["needs"],
                &[
                    "select",
                    "assemble",
                    "publish",
                    "recovery-inputs",
                    "recovery-publish",
                ],
                "public selected original pair and publisher dependencies",
            )?;
            if job["if"].as_str()
                != Some(
                    "always() && (needs.publish.result == 'success' || needs.recovery-publish.result == 'success') && needs.select.outputs.preparation-kind == 'tagged'",
                )
                || job["name"].as_str() != Some("${{ matrix.producer-job }}")
                || job["outputs"]["artifact-id"].as_str()
                    != Some("${{ steps.readiness-upload.outputs.artifact-id }}")
                || job["outputs"]["artifact-digest"].as_str()
                    != Some("${{ steps.readiness-upload.outputs.artifact-digest }}")
            {
                return Err(failure(
                    "public readiness original publication condition or immutable routing differs",
                ));
            }
            let permissions = job
                .get(key("permissions"))
                .and_then(Value::as_mapping)
                .ok_or_else(|| failure("public readiness read permissions absent"))?;
            exact_mapping_keys(
                permissions,
                &["contents", "actions"],
                "public artifact read permissions",
            )?;
            if scalar(permissions, "contents") != Some("read")
                || scalar(permissions, "actions") != Some("read")
            {
                return Err(failure(
                    "public readiness must retain read-only permissions",
                ));
            }
            let rows = job
                .get(key("strategy"))
                .and_then(|strategy| strategy.get("matrix"))
                .and_then(|matrix| matrix.get("include"))
                .and_then(Value::as_sequence)
                .ok_or_else(|| failure("public readiness row absent"))?;
            if rows.len() != 1
                || rows[0]["target"].as_str() != Some(target)
                || rows[0]["runner"].as_str() != Some(runner)
                || rows[0]["channel"].as_str() != Some(format!("public-{channel}").as_str())
                || rows[0]["producer-job"].as_str() != Some(name.as_str())
                || job.get(key("timeout-minutes")).and_then(Value::as_u64) != Some(180)
            {
                return Err(failure(
                    "public readiness native target/channel/owner/deadline differs",
                ));
            }
            let steps = job
                .get(key("steps"))
                .and_then(Value::as_sequence)
                .ok_or_else(|| failure("public readiness steps absent"))?;
            let mut previous = None;
            for (run, condition) in [
                (
                    "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/readiness-identity.json",
                    None,
                ),
                (
                    "./target/ci/release/consumer-readiness acquire --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
                    None,
                ),
                (
                    "./target/ci/release/consumer-readiness cleanup --github-context --driver ./target/ci/release/memcordon-ci --identity .release/readiness-identity.json --destination .release/readiness-cell",
                    Some("always()"),
                ),
                (
                    "./target/ci/release/consumer-readiness seal-producer --github-context --identity .release/readiness-identity.json --manifest ci/consumer-readiness-v1.toml --cell .release/readiness-cell/cell.json --output .release/readiness-cell/producer-manifest.json",
                    Some("always()"),
                ),
            ] {
                let selected = steps
                    .iter()
                    .enumerate()
                    .filter(|(_, step)| step.get("run").and_then(Value::as_str) == Some(run))
                    .collect::<Vec<_>>();
                if selected.len() != 1
                    || selected[0].1.get("if").and_then(Value::as_str) != condition
                    || selected[0].1.get("continue-on-error").is_some()
                    || previous.is_some_and(|previous| previous >= selected[0].0)
                {
                    return Err(failure(
                        "public readiness operation order/always-cleanup/failure propagation differs",
                    ));
                }
                previous = Some(selected[0].0);
            }
            let upload = steps
                .iter()
                .filter(|step| step.get("id").and_then(Value::as_str) == Some("readiness-upload"))
                .collect::<Vec<_>>();
            if upload.len() != 1
                || upload[0]["if"].as_str() != Some("always()")
                || upload[0]["with"]["overwrite"].as_bool() != Some(false)
                || upload[0]["with"]["include-hidden-files"].as_bool() != Some(true)
                || upload[0]["with"]["if-no-files-found"].as_str() != Some("error")
                || upload[0]["with"]["name"].as_str()
                    != Some(
                        "readiness-${{ matrix.producer-job }}-${{ github.run_id }}-${{ github.run_attempt }}",
                    )
            {
                return Err(failure("public original producer artifact custody differs"));
            }
        }
    }
    for (name, value) in jobs {
        let name = name
            .as_str()
            .ok_or_else(|| failure("release job name is not a string"))?;
        let job = mapping(value, name)?;
        if job
            .get(key("timeout-minutes"))
            .and_then(Value::as_u64)
            .is_none_or(|minutes| {
                minutes == 0
                    || minutes
                        > if name.starts_with("native-") {
                            301
                        } else if name.starts_with("candidate-") {
                            241
                        } else if name.starts_with("installed-macos-") {
                            151
                        } else if name.starts_with("public-") {
                            180
                        } else {
                            match name {
                                "source-checks" | "msrv" | "miri" => 196,
                                "supply-chain" => 135,
                                "packages" => 121,
                                "rehearsal-tool" => 143,
                                "fuzz" => 93,
                                _ => 90,
                            }
                        }
            })
        {
            return Err(failure("release outer job envelope missing or excessive"));
        }
    }
    let mut required = vec![
        "select".to_owned(),
        "packages".into(),
        "source-checks".into(),
        "msrv".into(),
        "supply-chain".into(),
        "assemble-payload".into(),
        "rehearse".into(),
        "miri".into(),
        "fuzz".into(),
    ];
    for (id, target, runner) in [
        ("linux-x64", "x86_64-unknown-linux-gnu", "ubuntu-24.04"),
        (
            "linux-arm64",
            "aarch64-unknown-linux-gnu",
            "ubuntu-24.04-arm",
        ),
        ("macos-x64", "x86_64-apple-darwin", "macos-15-intel"),
        ("macos-arm64", "aarch64-apple-darwin", "macos-15"),
        ("windows-x64", "x86_64-pc-windows-msvc", "windows-2025"),
        ("windows-arm64", "aarch64-pc-windows-msvc", "windows-11-arm"),
    ] {
        let native_name = format!("native-{id}");
        required.push(native_name.clone());
        let native = mapping(
            jobs.get(key(&native_name))
                .ok_or_else(|| failure("release native target absent"))?,
            "release native",
        )?;
        if scalar(native, "needs") != Some("select") {
            return Err(failure(
                "native producer must not wait for packages or consumers",
            ));
        }
        check_release_row(native, target, runner, None)?;
        check_native_cache_role(native, "native-readiness")?;
        let steps = ordinary_steps(native, "release native")?;
        let build = steps
            .iter()
            .position(|step| {
                step.get(key("run")).and_then(Value::as_str)
                    == Some("./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness")
            })
            .ok_or_else(|| failure("actual native build absent"))?;
        if steps[build]["if"].as_str()
            != Some(
                "github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all'",
            )
        {
            return Err(failure("automated native build must retain stop mode"));
        }
        let diagnostics = steps.iter().enumerate().filter(|(_, step)| step["run"].as_str() == Some("./target/ci/release/memcordon-ci release build-target --build-source .release/build-source.json --consumer-readiness --failure-mode collect-all")).collect::<Vec<_>>();
        if diagnostics.len() != 1
            || diagnostics[0].0 <= build
            || diagnostics[0].1["if"].as_str()
                != Some(
                    "github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all'",
                )
        {
            return Err(failure(
                "native diagnostic branch must explicitly execute collect-all",
            ));
        }
        ordinary_driver_before_suite(steps, build)?;
        if !id.starts_with("macos") {
            let selected = "runner.os == 'Linux' || runner.os == 'Windows'";
            let always_selected = "always() && (runner.os == 'Linux' || runner.os == 'Windows')";
            let expected = [
                (
                    "./target/ci/release/consumer-readiness identity --github-context --build-source .release/build-source.json --output .release/native-readiness-identity.json",
                    selected,
                ),
                (
                    "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness",
                    selected,
                ),
                (
                    "./target/ci/release/memcordon-ci consumer-readiness-native-components --identity .release/native-readiness-identity.json --github-context --destination .release/native-readiness --cleanup",
                    always_selected,
                ),
            ];
            let mut previous = diagnostics[0].0;
            for (run, condition) in expected {
                let matching = steps
                    .iter()
                    .enumerate()
                    .filter(|(_, step)| step["run"].as_str() == Some(run))
                    .collect::<Vec<_>>();
                if matching.len() != 1
                    || matching[0].0 <= previous
                    || matching[0].1["if"].as_str() != Some(condition)
                {
                    return Err(failure(
                        "original native component source/execution/always-cleanup owner differs",
                    ));
                }
                previous = matching[0].0;
            }
            let uploads = steps
                .iter()
                .enumerate()
                .filter(|(_, step)| {
                    step["uses"].as_str() == Some(PINNED_UPLOAD_ARTIFACT_ACTION)
                        && step["with"]["path"].as_str() == Some(".release/native-readiness")
                })
                .collect::<Vec<_>>();
            if uploads.len() != 1
                || uploads[0].0 <= previous
                || uploads[0].1["if"].as_str() != Some(always_selected)
                || uploads[0].1["with"]["name"].as_str()
                    != Some(
                        "readiness-${{ github.job }}-${{ github.run_id }}-${{ github.run_attempt }}",
                    )
                || uploads[0].1["with"]["if-no-files-found"].as_str() != Some("error")
                || uploads[0].1["with"]["include-hidden-files"].as_bool() != Some(true)
                || uploads[0].1["with"]["overwrite"].as_bool() != Some(false)
            {
                return Err(failure(
                    "original native producer immutable evidence transport differs",
                ));
            }
        }
        let channels = ["native", "cargo"];
        for channel in channels {
            let name = if id.starts_with("macos") {
                format!("installed-{id}-{channel}")
            } else {
                format!("candidate-{id}-{channel}")
            };
            required.push(name.clone());
            let job = mapping(
                jobs.get(key(&name))
                    .ok_or_else(|| failure("release installed channel absent"))?,
                "installed channel",
            )?;
            exact_string_sequence(
                job.get(key("needs"))
                    .ok_or_else(|| failure("installed dependencies absent"))?,
                &["select", "packages", &native_name],
                "installed target-local dependencies",
            )?;
            let selected_channel = if id.starts_with("macos") {
                channel.to_owned()
            } else {
                format!("candidate-{channel}")
            };
            check_release_row(job, target, runner, Some(&selected_channel))?;
            let steps = ordinary_steps(job, "installed channel")?;
            if !id.starts_with("macos") {
                check_readiness_candidate_steps(job, steps, &name, &native_name)?;
                continue;
            }
            for (selected, condition) in [
                (
                    "native",
                    "matrix.producer-job == '' && matrix.channel != 'cargo'",
                ),
                (
                    "cargo",
                    "matrix.producer-job == '' && matrix.channel != 'native'",
                ),
            ] {
                let run = format!(
                    "./target/ci/release/memcordon-ci release installed-consumers --channel {selected} --destination .release/installed-results/{selected}"
                );
                let operations: Vec<_> = steps
                    .iter()
                    .enumerate()
                    .filter(|(_, step)| step.get(key("run")).and_then(Value::as_str) == Some(&run))
                    .collect();
                if operations.len() != 1
                    || operations[0].1.get(key("if")).and_then(Value::as_str) != Some(condition)
                {
                    return Err(failure("installed channel execution differs or is skipped"));
                }
                ordinary_driver_before_suite(steps, operations[0].0)?;
            }
            for (ordinal, step) in steps.iter().enumerate().filter(|(_, step)| {
                step.get(key("uses")).and_then(Value::as_str)
                    == Some("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9")
            }) {
                if steps
                    .iter()
                    .position(|candidate| candidate["id"].as_str() == Some("native"))
                    .is_some_and(|owner| ordinal < owner)
                    || step["with"]["key"].as_str().is_some_and(|selected| {
                        cache_output_reference(selected, "snapshot-key").is_some()
                    })
                {
                    // Acquisition saved before installed consumers and immutable
                    // copies use their own producer, not later channel cleanup.
                    continue;
                }
                let condition = step
                    .get(key("if"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if condition
                    == "always() && matrix.producer-job != '' && steps.readiness-cache.outputs.compiled-cache-usable == 'true' && steps.readiness-cleanup.outputs.cache-quiescent == 'true' && steps.readiness-consumers.outputs.cache-hit != 'true'"
                {
                    let with = mapping(
                        step.get(key("with"))
                            .ok_or_else(|| failure("readiness cache inputs absent"))?,
                        "readiness cache",
                    )?;
                    if scalar(with, "path") != Some("target/ci-consumers")
                        || scalar(with, "key")
                            != Some("${{ steps.readiness-consumers.outputs.cache-primary-key }}")
                    {
                        return Err(failure(
                            "readiness cache must retain only selected consumer products",
                        ));
                    }
                    continue;
                }
                if !condition.contains("(steps.native.conclusion == 'skipped' || steps.native.outputs.cache-quiescent == 'true') && (steps.cargo.conclusion == 'skipped' || steps.cargo.outputs.cache-quiescent == 'true')") {
                    return Err(failure("installed shared writer cache needs every started channel quiescent"));
                }
            }
        }
    }
    for name in [
        "packages",
        "source-checks",
        "msrv",
        "supply-chain",
        "miri",
        "fuzz",
    ] {
        let job = mapping(
            jobs.get(key(name))
                .ok_or_else(|| failure("release check descendant absent"))?,
            "release checks",
        )?;
        if scalar(job, "needs") != Some("select")
            || scalar(job, "if") != Some("needs.select.outputs.recovery-mode == 'reprepare'")
        {
            return Err(failure("release check fan-out dependency differs"));
        }
        let steps = ordinary_steps(job, "release checks")?;
        let verify = steps
            .iter()
            .position(|step| {
                step.get(key("run")).and_then(Value::as_str)
                    == Some("./.release/tool/memcordon-ci release verify-source --build-source .release/build-source.json")
            })
            .ok_or_else(|| failure("release source identity recheck absent"))?;
        ordinary_driver_before_suite(steps, verify)?;
        if name == "miri" || name == "fuzz" {
            if job
                .get(key("strategy"))
                .and_then(|strategy| strategy.get(key("fail-fast")))
                .and_then(Value::as_str)
                != Some(
                    "${{ github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all' }}",
                )
            {
                return Err(failure(
                    "only automated disposable shard matrices use fail-fast",
                ));
            }
            let shards = job
                .get(key("strategy"))
                .and_then(|strategy| strategy.get(key("matrix")))
                .and_then(|matrix| matrix.get(key("shard")))
                .ok_or_else(|| failure("release shard inventory absent"))?;
            exact_string_sequence(
                shards,
                &[
                    "quarter-one",
                    "quarter-two",
                    "quarter-three",
                    "quarter-four",
                ],
                "release complete quarters",
            )?;
            if job["strategy"]["max-parallel"].as_u64() != Some(4) {
                return Err(failure(
                    "Release quarters require a four-cell concurrency bound",
                ));
            }
            for shard in [
                "quarter-one",
                "quarter-two",
                "quarter-three",
                "quarter-four",
            ] {
                let selected = if name == "fuzz" {
                    format!("fuzz-execute-{shard}")
                } else {
                    format!("{name}-{shard}")
                };
                let run = format!("./.release/tool/memcordon-ci suite {selected}");
                let expected = format!("matrix.shard == '{shard}'");
                let matches: Vec<_> = steps
                    .iter()
                    .filter(|step| step.get(key("run")).and_then(Value::as_str) == Some(&run))
                    .collect();
                if matches.len() != 1
                    || matches[0].get(key("if")).and_then(Value::as_str) != Some(&expected)
                {
                    return Err(failure("release complete shard coverage differs"));
                }
            }
        } else if matches!(name, "source-checks" | "msrv" | "supply-chain") {
            let suite = if name == "source-checks" {
                "quality-compile"
            } else {
                name
            };
            {
                let run = format!("./.release/tool/memcordon-ci suite {suite}");
                let matches: Vec<_> = steps
                    .iter()
                    .filter(|step| step.get(key("run")).and_then(Value::as_str) == Some(&run))
                    .collect();
                if matches.len() != 1 || matches[0].get(key("if")).is_some() {
                    return Err(failure(
                        "release required source check absent or conditional",
                    ));
                }
            }
        }
    }
    let assemble = mapping(
        jobs.get(key("assemble"))
            .ok_or_else(|| failure("release assembly absent"))?,
        "release assembly",
    )?;
    let needs = assemble
        .get(key("needs"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure("assembly dependencies absent"))?;
    let actual: BTreeSet<_> = needs.iter().filter_map(Value::as_str).collect();
    let expected: BTreeSet<_> = required.iter().map(String::as_str).collect();
    if needs.len() != expected.len()
        || actual != expected
        || scalar(assemble, "if") != Some("needs.select.outputs.recovery-mode == 'reprepare'")
    {
        return Err(failure(
            "assembly requires every selected producer and installed/check leaf success",
        ));
    }
    for writer in ["publish", "recovery-publish"] {
        let publish = mapping(
            jobs.get(key(writer))
                .ok_or_else(|| failure("publisher absent"))?,
            "publisher",
        )?;
        let permissions = mapping(
            publish
                .get(key("permissions"))
                .ok_or_else(|| failure("publisher permissions absent"))?,
            "publisher permissions",
        )?;
        exact_mapping_keys(
            permissions,
            &["contents", "actions", "id-token"],
            "publisher permissions",
        )?;
        if scalar(permissions, "contents") != Some("write")
            || scalar(permissions, "actions") != Some("read")
            || scalar(permissions, "id-token") != Some("write")
        {
            return Err(failure("publisher permissions differ"));
        }
        let concurrency = mapping(
            publish
                .get(key("concurrency"))
                .ok_or_else(|| failure("publication serialization absent"))?,
            "publisher concurrency",
        )?;
        if scalar(concurrency, "group") != Some("memcordon-publication")
            || concurrency
                .get(key("cancel-in-progress"))
                .and_then(Value::as_bool)
                != Some(false)
        {
            return Err(failure("publication must serialize without cancellation"));
        }
        let publisher_steps = ordinary_steps(publish, "publisher")?;
        if publish.contains_key(key("continue-on-error")) || publisher_steps.len() != 5 {
            return Err(failure(
                "publisher cannot hide failure or add substitute execution",
            ));
        }
        for (index, path, current_id, original_id) in [
            (
                0,
                ".release/tool",
                "${{ needs.assemble.outputs.publication-tool-artifact-id }}",
                "${{ needs.recovery-inputs.outputs.tool-artifact-id }}",
            ),
            (
                1,
                ".release/prepared",
                "${{ needs.assemble.outputs.prepared-artifact-id }}",
                "${{ needs.recovery-inputs.outputs.prepared-artifact-id }}",
            ),
        ] {
            let value = &publisher_steps[index];
            let step = mapping(value, "publisher original-byte download")?;
            exact_mapping_keys(step, &["uses", "with"], "publisher download")?;
            let inputs = mapping(&value["with"], "publisher download inputs")?;
            exact_mapping_keys(
                inputs,
                if writer == "publish" {
                    &[
                        "artifact-ids",
                        "run-id",
                        "github-token",
                        "path",
                        "merge-multiple",
                        "digest-mismatch",
                    ]
                } else {
                    &[
                        "artifact-ids",
                        "run-id",
                        "repository",
                        "github-token",
                        "path",
                        "merge-multiple",
                        "digest-mismatch",
                    ]
                },
                "publisher download inputs",
            )?;
            if scalar(step, "uses")
                != Some("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c")
                || scalar(inputs, "artifact-ids")
                    != Some(if writer == "publish" {
                        current_id
                    } else {
                        original_id
                    })
                || scalar(inputs, "run-id")
                    != Some(if writer == "publish" {
                        "${{ github.run_id }}"
                    } else {
                        "${{ needs.recovery-inputs.outputs.original-run-id }}"
                    })
                || scalar(inputs, "path") != Some(path)
                || scalar(inputs, "github-token") != Some("${{ github.token }}")
                || scalar(inputs, "digest-mismatch") != Some("error")
                || inputs.get(key("merge-multiple")).and_then(Value::as_bool) != Some(true)
                || writer == "recovery-publish"
                    && scalar(inputs, "repository") != Some("${{ github.repository }}")
            {
                return Err(failure(
                    "publisher must use the same exact pair as its rehearsal",
                ));
            }
        }
        let mut writes = 0;
        for step in publisher_steps {
            if let Some(run) = step.get(key("run")).and_then(Value::as_str) {
                if run == "./.release/tool/memcordon-ci release publish" {
                    if step.get(key("if")).is_some() || step.get(key("continue-on-error")).is_some()
                    {
                        return Err(failure("actual publication cannot skip or ignore failure"));
                    }
                    writes += 1;
                } else if run
                    != "tar -xzf .release/tool/memcordon-publication-tool.tar.gz -C .release/tool"
                {
                    return Err(failure(
                        "publisher cannot build/test or invoke source tools",
                    ));
                }
            }
            if let Some(uses) = step.get(key("uses")).and_then(Value::as_str)
                && !uses.starts_with("actions/download-artifact@")
                && !uses.starts_with("rust-lang/crates-io-auth-action@")
            {
                return Err(failure(
                    "publisher cannot checkout/restore cache or run another action",
                ));
            }
        }
        if writes != 1 {
            return Err(failure("publisher needs one prepared-byte write operation"));
        }
        let expected_condition = if writer == "publish" {
            "needs.select.outputs.preparation-kind == 'tagged' && needs.select.outputs.recovery-mode == 'reprepare' && (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/') || github.event_name == 'workflow_dispatch' && inputs.preparation-mode == 'release' && startsWith(github.ref, 'refs/tags/'))"
        } else {
            "needs.select.outputs.preparation-kind == 'tagged' && needs.select.outputs.recovery-mode == 'publication-only' && github.event_name == 'workflow_dispatch' && inputs.preparation-mode == 'release' && startsWith(github.ref, 'refs/tags/')"
        };
        if scalar(publish, "if") != Some(expected_condition) {
            return Err(failure(
                "writer must retain exact tagged event and preparation mode guards",
            ));
        }
        exact_string_sequence(
            publish
                .get(key("needs"))
                .ok_or_else(|| failure("writer dependencies absent"))?,
            if writer == "publish" {
                &["select", "assemble", "rehearse"]
            } else {
                &["select", "recovery-inputs", "recovery-rehearse"]
            },
            "writer preparation dependencies",
        )?;
    }
    Ok(())
}

fn check_step_environment(
    file: &Path,
    step: &Mapping,
    policy: &config::Policy,
    definitions: &mut BTreeSet<EnvironmentDefinition>,
) -> Result<()> {
    let Some(environment) = step.get(key("env")) else {
        return Ok(());
    };
    let step_name =
        scalar(step, "name").ok_or_else(|| failure("an env-bearing step needs a name"))?;
    let environment = mapping(environment, "step env")?;
    for (variable, source) in environment {
        let variable = variable
            .as_str()
            .ok_or_else(|| failure("workflow environment key must be a string"))?;
        let source = source
            .as_str()
            .ok_or_else(|| failure("workflow environment source must be a string"))?;
        let allowance = policy
            .workflow
            .environment_allowlist
            .iter()
            .find(|entry| {
                Path::new(&entry.file) == file
                && entry.variable == variable
                && entry.source == source
                && entry.steps.iter().any(|name| name == step_name)
            })
            .ok_or_else(|| {
                failure(format!(
                    "workflow environment definition is not allowlisted: {file:?} {step_name:?} {variable:?}"
                ))
            })?;
        let definition = EnvironmentDefinition {
            file: allowance.file.clone(),
            step: step_name.to_owned(),
            variable: variable.to_owned(),
            source: source.to_owned(),
        };
        if !definitions.insert(definition) {
            return Err(failure("duplicate workflow environment definition"));
        }
    }
    Ok(())
}

fn validate_workflow_bytes_into(
    root: &Path,
    relative: &Path,
    bytes: &[u8],
    policy: &config::Policy,
    environment_definitions: &mut BTreeSet<EnvironmentDefinition>,
    used_actions: &mut BTreeSet<String>,
    authoritative_local_actions: Option<&BTreeMap<String, Vec<u8>>>,
) -> Result<()> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if text.contains("release-bootstrap") {
        return Err(failure(
            "release-bootstrap workflow and environment references are forbidden",
        ));
    }
    let document = parse_yaml(bytes)?;
    let workflow = mapping(&document, "workflow")?;
    let projection = crate::workflow_definitions::policy_projection(
        relative
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default(),
        &document,
    )?;
    let normalized = normalize_failure_branches(projection.as_ref().unwrap_or(workflow))?;
    if workflow.contains_key(key("shell")) || workflow.contains_key(key("env")) {
        return Err(failure(format!(
            "workflow-level shell/env is forbidden: {relative:?}"
        )));
    }
    let pins = config::action_pins(root)?;
    let allowed_actions: BTreeSet<&str> = pins.action.iter().map(|pin| pin.uses.as_str()).collect();
    if allowed_actions.len() != pins.action.len() {
        return Err(failure(
            "action pin manifest contains duplicate uses values",
        ));
    }
    for pin in &pins.action {
        let Some((repository, revision)) = pin.uses.split_once('@') else {
            return Err(failure("action pin manifest entry has no revision"));
        };
        if pin.name.trim().is_empty()
            || pin.release.trim().is_empty()
            || repository.trim().is_empty()
            || revision.is_empty()
            || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(failure("action pin manifest contains an incomplete entry"));
        }
    }
    if let Some(actions) = authoritative_local_actions {
        let bytes = actions.get(UPLOAD_ARTIFACT_ACTION_PATH).ok_or_else(|| {
            failure(format!(
                "authoritative local action is absent: {UPLOAD_ARTIFACT_ACTION_PATH}"
            ))
        })?;
        validate_upload_artifact_action_bytes(bytes)?;
    } else {
        check_upload_artifact_action(root)?;
    }
    if !allowed_actions.contains(PINNED_UPLOAD_ARTIFACT_ACTION) {
        return Err(failure(
            "artifact upload action pin is absent from the pin manifest",
        ));
    }
    let jobs = mapping(
        workflow
            .get(key("jobs"))
            .ok_or_else(|| failure("workflow has no jobs"))?,
        "jobs",
    )?;
    if matches!(
        relative.to_str(),
        Some(".github/workflows/ci.yml" | ".github/workflows/release.yml")
    ) {
        let mode = workflow
            .get(key("on"))
            .and_then(|events| events.get("workflow_dispatch"))
            .and_then(|dispatch| dispatch.get("inputs"))
            .and_then(|inputs| inputs.get("failure-mode"))
            .ok_or_else(|| failure("manual failure mode input absent"))?;
        if mode["type"].as_str() != Some("choice")
            || mode["default"].as_str() != Some("stop-after-failure")
        {
            return Err(failure(
                "automated failure mode cannot default to diagnostic collection",
            ));
        }
        exact_string_sequence(
            &mode["options"],
            &["stop-after-failure", "collect-all"],
            "manual failure modes",
        )?;
    }
    for (job_name, job_value) in jobs {
        let job_name = job_name
            .as_str()
            .ok_or_else(|| failure("job name must be a string"))?;
        let job = mapping(job_value, "job")?;
        if job.contains_key(key("shell")) || job.contains_key(key("env")) {
            return Err(failure(format!(
                "job-level shell/env is forbidden: {job_name}"
            )));
        }
        if job.contains_key(key("environment")) {
            return Err(failure(format!(
                "named GitHub environments are forbidden: {job_name}"
            )));
        }
        if job
            .get(key("runs-on"))
            .is_some_and(runner_selects_self_hosted)
        {
            return Err(failure("workflow may not select self-hosted runners"));
        }
        let Some(steps) = job.get(key("steps")).and_then(Value::as_sequence) else {
            continue;
        };
        if let Some(logical_steps) = normalized["jobs"][job_name]["steps"].as_sequence() {
            // Guard expressions refer to both original failure-mode branches;
            // lifecycle validation alone uses their normalized logical owner.
            let guard_steps = projection
                .as_ref()
                .and_then(|document| document["jobs"][job_name]["steps"].as_sequence())
                .unwrap_or(steps);
            check_cache_save_guards(guard_steps)?;
            check_cache_lifecycle(logical_steps)?;
        } else if projection.is_none() {
            return Err(failure("normalized steps absent"));
        }
        for step_value in steps {
            let step = mapping(step_value, "step")?;
            if step.contains_key(key("shell")) {
                return Err(failure(format!(
                    "workflow step defines shell: {relative:?}"
                )));
            }
            check_step_environment(relative, step, policy, environment_definitions)?;
            if scalar(step, "if").is_some_and(|condition| condition.contains("secrets.")) {
                return Err(failure("workflow conditions may not inspect secrets"));
            }
            if step.get(key("with")).is_some_and(|with| {
                serde_yaml::to_string(with).is_ok_and(|text| {
                    text.contains("CARGO_REGISTRY_TOKEN")
                        || text.contains("CARGO_REGISTRIES_CRATES_IO_TOKEN")
                        || text.contains("secrets.")
                })
            }) {
                return Err(failure(
                    "crates.io credentials may not be passed through action inputs",
                ));
            }
            let run_value = step.get(key("run"));
            let uses_value = step.get(key("uses"));
            if run_value.is_some() == uses_value.is_some() {
                return Err(failure(
                    "each workflow step must define exactly one of run or uses",
                ));
            }
            if let Some(value) = run_value {
                let run = value
                    .as_str()
                    .ok_or_else(|| failure("workflow run must be a scalar string"))?;
                if !static_run_command(run) {
                    return Err(failure(format!("workflow run is shell-shaped: {run:?}")));
                }
                if !policy
                    .workflow
                    .allowed_run_commands
                    .iter()
                    .any(|allowed| allowed == run)
                    && !(projection.is_some() && crate::workflow_definitions::known_run(run))
                {
                    return Err(failure(format!("workflow run is not allowlisted: {run:?}")));
                }
            }
            if let Some(value) = uses_value {
                let uses = value
                    .as_str()
                    .ok_or_else(|| failure("workflow uses must be a scalar string"))?;
                let local_upload = uses == UPLOAD_ARTIFACT_ACTION;
                if !local_upload && !allowed_actions.contains(uses) {
                    return Err(failure(format!(
                        "workflow action is not exactly pinned: {uses}"
                    )));
                }
                if let Some(with_value) = step.get(key("with")) {
                    let inputs = mapping(with_value, "action with")?;
                    for (input, value) in inputs {
                        let input = input.as_str().ok_or_else(|| {
                            failure("workflow action input name must be a string")
                        })?;
                        if value
                            .as_str()
                            .is_some_and(|source| source.contains("&&") || source.contains("||"))
                        {
                            return Err(failure(format!(
                                "workflow action input may not select values with Boolean operators: {uses} {input}"
                            )));
                        }
                    }
                }
                used_actions.insert(
                    if local_upload {
                        PINNED_UPLOAD_ARTIFACT_ACTION
                    } else {
                        uses
                    }
                    .to_owned(),
                );
                if uses.starts_with("actions/cache/") {
                    let Some(with) = step
                        .get(key("with"))
                        .map(|value| mapping(value, "cache with"))
                    else {
                        return Err(failure("cache action needs a with mapping"));
                    };
                    let with = with?;
                    let cache_path = scalar(with, "path")
                        .ok_or_else(|| failure("cache action needs a scalar path"))?;
                    let cache_key = scalar(with, "key")
                        .ok_or_else(|| failure("cache action needs a scalar key"))?;
                    if cache_key.contains("'**/Cargo.toml'") {
                        return Err(failure("cache keys may not use broad manifest globs"));
                    }
                    if cache_key.contains("'fuzz/Cargo.toml'")
                        && !cache_key.contains("'fuzz/Cargo.lock'")
                    {
                        return Err(failure(
                            "cache keys that include the fuzz manifest must include its lockfile",
                        ));
                    }
                    if [".ssh", ".gnupg", ".aws", ".config/gh", ".cargo/credentials"]
                        .iter()
                        .any(|secret_path| cache_path.contains(secret_path))
                    {
                        return Err(failure("cache path includes credential material"));
                    }
                    if cache_path.contains("target/ci-tools")
                        && cache_path.lines().any(|line| {
                            let trimmed = line.trim();
                            !trimmed.is_empty()
                                && !matches!(
                                    trimmed,
                                    "target/ci-tools/bin" | "target/ci-tools-build" | "fuzz/target"
                                )
                        })
                    {
                        return Err(failure(
                            "tool caches must contain only final binaries and tool compilation outputs",
                        ));
                    }
                }
                if uses.starts_with("actions/cache/save@") {
                    if projection.is_some()
                        && crate::workflow_definitions::validate_ready_save(step)?
                    {
                        continue;
                    }
                    let condition = scalar(step, "if").unwrap_or_default();
                    let cache_hit = condition.contains("outputs.cache-hit != 'true'")
                        || condition.contains("outputs.cache-hit == 'true'");
                    let with = mapping(
                        step.get(key("with"))
                            .ok_or_else(|| failure("cache save action needs with"))?,
                        "cache with",
                    )?;
                    let primary_key = scalar(with, "key").is_some_and(|value| {
                        value.contains("outputs.cache-primary-key")
                            || ["source-key", "product-key", "tool-key", "tool-build-key"]
                                .iter()
                                .any(|output| cache_output_reference(value, output).is_some())
                            || cache_output_reference(value, "snapshot-key").is_some()
                            || cache_output_reference(value, "sysroot-key").is_some()
                    });
                    if !condition.contains("always()") || !cache_hit || !primary_key {
                        return Err(failure(
                            "cache save must be guarded by always/cache-hit and reuse the primary key",
                        ));
                    }
                }
            }
        }
    }
    // Validate the literal two-branch mode routing and selected-step outputs before
    // presenting one logical operation to the existing source/cache validators.
    let workflow = &normalized;
    let jobs = mapping(&workflow["jobs"], "normalized jobs")?;
    if relative == Path::new(".github/workflows/ci.yml") {
        check_ci_structure(workflow, jobs, policy)?;
        if text.contains("paths:") || text.contains("paths-ignore:") {
            return Err(failure("CI workflow must not use path filters"));
        }
    }
    if relative == Path::new(".github/workflows/deep-ci.yml") {
        check_deep_ci_structure(workflow, jobs)?;
    }
    if relative == Path::new(".github/workflows/backend-certification.yml") {
        check_standard_native_jobs(workflow, jobs)?;
    }
    if relative == Path::new(".github/workflows/release-current.yml") {
        return Err(failure("duplicate release workflow identity is forbidden"));
    }
    if relative == Path::new(".github/workflows/release.yml") {
        check_release_structure(jobs)?;
        check_preparation_transport(workflow, jobs)?;
    }
    Ok(())
}

fn normalize_failure_branches(workflow: &Mapping) -> Result<Mapping> {
    const STOP: &str =
        "github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all'";
    const ALL: &str =
        "github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all'";
    fn routed(command: &str) -> bool {
        [
            " suite miri-",
            " suite fuzz-compile-",
            " suite fuzz-execute-",
            " suite supply-chain",
            " suite quality",
            " suite msrv",
            " ci prepare --profile ",
        ]
        .iter()
        .any(|token| command.contains(token))
    }
    fn rewrite(value: &mut Value, owners: &[String]) -> Result<()> {
        match value {
            Value::String(text) => {
                for owner in owners {
                    let mut replacements = Vec::new();
                    for field in ["outcome", "conclusion"] {
                        let original = format!("steps.{owner}.{field} == 'skipped'");
                        let selected = format!(
                            "({original} && steps.{owner}-diagnostic.{field} == 'skipped')"
                        );
                        let marker = format!("@logical-mode-{}@", replacements.len());
                        *text = text.replace(&selected, &marker);
                        if text.contains(&original) {
                            return Err(failure(
                                "skipped mode branch must include its diagnostic peer",
                            ));
                        }
                        replacements.push((marker, original));
                    }
                    let prefix = format!("(steps.{owner}.outputs.");
                    while let Some(start) = text.find(&prefix) {
                        let tail = &text[start + prefix.len()..];
                        let output: String = tail
                            .chars()
                            .take_while(|character| {
                                character.is_ascii_alphanumeric() || *character == '-'
                            })
                            .collect();
                        let original = format!("steps.{owner}.outputs.{output}");
                        let selected =
                            format!("({original} || steps.{owner}-diagnostic.outputs.{output})");
                        if !text[start..].starts_with(&selected) {
                            return Err(failure(
                                "mode outputs must select the same actual owner branch",
                            ));
                        }
                        let marker = format!("@logical-mode-{}@", replacements.len());
                        text.replace_range(start..start + selected.len(), &marker);
                        replacements.push((marker, original));
                    }
                    if text.contains(&format!("steps.{owner}-diagnostic."))
                        || text.contains(&format!("steps.{owner}.outputs."))
                    {
                        return Err(failure("mode output/settlement references are not paired"));
                    }
                    for (marker, original) in replacements {
                        *text = text.replace(&marker, &original);
                    }
                }
            }
            Value::Sequence(values) => {
                for value in values {
                    rewrite(value, owners)?;
                }
            }
            Value::Mapping(values) => {
                for value in values.values_mut() {
                    rewrite(value, owners)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut normalized = workflow.clone();
    let jobs = normalized
        .get_mut(key("jobs"))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| failure("jobs absent"))?;
    for job in jobs.values_mut() {
        let Some(steps) = job.get_mut("steps").and_then(Value::as_sequence_mut) else {
            continue;
        };
        let mut result = Vec::with_capacity(steps.len());
        let mut owners = Vec::new();
        let mut ordinal = 0;
        while ordinal < steps.len() {
            let step = &steps[ordinal];
            let command = step["run"].as_str().unwrap_or_default();
            if !routed(command) {
                result.push(step.clone());
                ordinal += 1;
                continue;
            }
            let base = command
                .strip_suffix(" --failure-mode stop-after-failure")
                .ok_or_else(|| {
                    failure("required suite must begin a literal stop/diagnostic pair")
                })?;
            let owner = step["id"]
                .as_str()
                .ok_or_else(|| failure("mode operation lacks id"))?;
            let condition = step["if"]
                .as_str()
                .ok_or_else(|| failure("mode selector absent"))?;
            let selection = if condition == STOP {
                None
            } else {
                Some(
                    condition
                        .strip_suffix(&format!(" && ({STOP})"))
                        .ok_or_else(|| failure("stop branch condition differs"))?,
                )
            };
            let diagnostic = steps
                .get(ordinal + 1)
                .ok_or_else(|| failure("diagnostic branch absent"))?;
            let expected_condition = selection.map_or_else(
                || ALL.to_owned(),
                |selection| format!("{selection} && ({ALL})"),
            );
            let mut expected = step.clone();
            expected["id"] = Value::String(format!("{owner}-diagnostic"));
            expected["run"] = Value::String(format!("{base} --failure-mode collect-all"));
            expected["if"] = Value::String(expected_condition);
            if diagnostic != &expected {
                return Err(failure(
                    "diagnostic branch must differ only in literal mode, id and selector",
                ));
            }
            let mut logical = step.clone();
            logical["run"] = Value::String(base.to_owned());
            if let Some(selection) = selection {
                logical["if"] = Value::String(selection.to_owned());
            } else {
                logical
                    .as_mapping_mut()
                    .expect("step map")
                    .remove(key("if"));
            }
            result.push(logical);
            owners.push(owner.to_owned());
            ordinal += 2;
        }
        *steps = result;
        for step in steps {
            let retention = step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/cache/"))
                || step["run"].as_str().is_some_and(|run| {
                    [
                        " ci cache-context ",
                        " ci download-cache-context ",
                        " ci cache-snapshot ",
                        " ci cleanup-cache-snapshot ",
                        " ci seed-context ",
                        " ci import-cache-snapshot ",
                    ]
                    .iter()
                    .any(|part| run.contains(part))
                });
            // Cache guards are validated against the real two declared owners,
            // before mode branches are collapsed for suite-coverage checks.
            if !retention {
                rewrite(step, &owners)?;
            }
        }
    }
    Ok(normalized)
}

fn check_preparation_transport(workflow: &Mapping, jobs: &Mapping) -> Result<()> {
    let permissions = mapping(
        workflow
            .get(key("permissions"))
            .ok_or_else(|| failure("workflow read permissions absent"))?,
        "preparation permissions",
    )?;
    exact_mapping_keys(permissions, &["contents"], "preparation permissions")?;
    if scalar(permissions, "contents") != Some("read") {
        return Err(failure("preparation workflow must be read-only"));
    }
    let events = workflow
        .get(key("on"))
        .ok_or_else(|| failure("preparation events absent"))?;
    let push = mapping(&events["push"], "preparation push")?;
    exact_mapping_keys(push, &["branches", "tags"], "preparation push")?;
    exact_string_sequence(
        &events["push"]["branches"],
        &["**"],
        "candidate branch coverage",
    )?;
    exact_string_sequence(
        &events["push"]["tags"],
        &[crate::workflow_scope::RELEASE_TAG_FILTER],
        "release tag coverage",
    )?;
    exact_string_sequence(
        &events["workflow_dispatch"]["inputs"]["preparation-mode"]["options"],
        &["candidate", "release"],
        "explicit preparation choices",
    )?;
    exact_string_sequence(
        &events["workflow_dispatch"]["inputs"]["recovery-mode"]["options"],
        &["reprepare", "publication-only"],
        "explicit recovery choices",
    )?;
    let concurrency = mapping(
        workflow
            .get(key("concurrency"))
            .ok_or_else(|| failure("preparation concurrency absent"))?,
        "preparation concurrency",
    )?;
    if scalar(concurrency, "group") != Some("memcordon-release-${{ github.ref }}")
        || scalar(concurrency, "cancel-in-progress")
            != Some("${{ github.event_name == 'push' && startsWith(github.ref, 'refs/heads/') }}")
    {
        return Err(failure(
            "preparation must serialize canonical refs and cancel only superseded branch pushes",
        ));
    }
    if !events["push"]["paths"].is_null() || !events["push"]["paths-ignore"].is_null() {
        return Err(failure("preparation cannot omit branch paths"));
    }
    if events["workflow_dispatch"]["inputs"]["preparation-mode"]["default"].as_str()
        != Some("release")
        || events["workflow_dispatch"]["inputs"]["tag"]["required"].as_bool() != Some(false)
    {
        return Err(failure("dispatch must distinguish candidate from release"));
    }
    for (name, job) in jobs {
        let name = name.as_str().ok_or_else(|| failure("job name invalid"))?;
        let job = mapping(job, "preparation job")?;
        let writer = matches!(name, "publish" | "recovery-publish");
        let preparation = !writer
            && name != "published-consumer"
            && !name.starts_with("public-")
            && !matches!(
                name,
                "readiness-candidate-report" | "readiness-complete-report"
            );
        if matches!(name, "recovery-inputs" | "rehearse" | "recovery-rehearse")
            && !job.contains_key(key("permissions"))
        {
            return Err(failure(
                "recovery validation requires explicit read-only artifact access",
            ));
        }
        if preparation && let Some(permissions) = job.get(key("permissions")) {
            let permissions = mapping(permissions, "preparation permissions")?;
            if !matches!(name, "recovery-inputs" | "rehearse" | "recovery-rehearse") {
                return Err(failure("preparation must inherit read-only permissions"));
            }
            exact_mapping_keys(
                permissions,
                if name == "rehearse" {
                    &["contents"]
                } else {
                    &["contents", "actions"]
                },
                "recovery read permissions",
            )?;
            if scalar(permissions, "contents") != Some("read")
                || name != "rehearse" && scalar(permissions, "actions") != Some("read")
            {
                return Err(failure(
                    "recovery validation requires only source and artifact read permissions",
                ));
            }
        }
        let steps = job
            .get(key("steps"))
            .and_then(Value::as_sequence)
            .ok_or_else(|| failure("preparation steps absent"))?;
        let mut diagnostic = false;
        if name.starts_with("native-")
            || name.starts_with("installed-")
            || name.starts_with("candidate-")
            || name == "select"
        {
            let checkout = steps
                .iter()
                .position(|step| {
                    step["uses"]
                        .as_str()
                        .is_some_and(|uses| uses.starts_with("actions/checkout@"))
                })
                .ok_or_else(|| failure("preparation checkout absent"))?;
            if !steps[..checkout].iter().any(|step| {
                step["run"].as_str() == Some("git config --global core.autocrlf false")
                    && step["if"].is_null()
                    && step["continue-on-error"].is_null()
            }) {
                return Err(failure("preparation must configure LF before checkout"));
            }
        }
        if name == "source-checks" {
            let quality = steps
                .iter()
                .position(|step| {
                    step["run"].as_str()
                        == Some("./.release/tool/memcordon-ci suite quality-compile")
                })
                .ok_or_else(|| failure("quality absent"))?;
            if !steps[..quality].iter().any(|step| step["run"].as_str() == Some("rustup toolchain install 1.97.1 --profile minimal --component clippy --component rustfmt") && step["if"].is_null() && step["continue-on-error"].is_null()) {
                return Err(failure("quality must provision pinned Clippy and rustfmt"));
            }
        }
        if name == "assemble-payload" {
            let assembly = steps.iter().position(|step| step["run"].as_str() == Some("./.release/tool/memcordon-ci release assemble --build-source .release/build-source.json --consumer-readiness --destination .release/assembled")).ok_or_else(|| failure("assembly absent"))?;
            if !steps[..assembly].iter().any(|step| {
                step["run"].as_str() == Some("rustup toolchain install 1.97.1 --profile minimal")
                    && step["if"].is_null()
                    && step["continue-on-error"].is_null()
            }) {
                return Err(failure(
                    "fresh assembly must provision the pinned metadata toolchain",
                ));
            }
        }
        for step in steps {
            let step = mapping(step, "preparation step")?;
            let uses = scalar(step, "uses").unwrap_or_default();
            let with = step.get(key("with"));
            if uses.starts_with("actions/checkout@") {
                let expected = if name == "select" {
                    "${{ github.sha }}"
                } else {
                    "${{ needs.select.outputs.selected-commit }}"
                };
                if with
                    .and_then(|with| with.get(key("ref")))
                    .and_then(Value::as_str)
                    != Some(expected)
                {
                    return Err(failure(
                        "preparation checkout must use exact selected event commit",
                    ));
                }
            }
            if uses == UPLOAD_ARTIFACT_ACTION && preparation {
                return Err(failure(
                    "required preparation artifacts cannot use destructive retry wrapper",
                ));
            }
            if uses == PINNED_UPLOAD_ARTIFACT_ACTION && preparation {
                let with = mapping(
                    with.ok_or_else(|| failure("upload inputs absent"))?,
                    "upload inputs",
                )?;
                if with.get(key("overwrite")).and_then(Value::as_bool) != Some(false)
                    || with
                        .get(key("include-hidden-files"))
                        .and_then(Value::as_bool)
                        != Some(true)
                    || !scalar(with, "name")
                        .is_some_and(|value| value.contains("github.run_attempt"))
                {
                    return Err(failure(
                        "preparation uploads must be immutable attempt-specific narrow hidden inventories",
                    ));
                }
                if scalar(with, "if-no-files-found") == Some("warn") {
                    diagnostic |= matches!(
                        scalar(step, "name"),
                        Some(
                            "Retain bounded preparation diagnostics"
                                | "Retain bounded helper diagnostics"
                                | "Retain rehearsal diagnostics"
                                | "Retain recovery rehearsal diagnostics"
                        )
                    );
                    if scalar(step, "if") != Some("always()")
                        || step.get(key("continue-on-error")).and_then(Value::as_bool) != Some(true)
                    {
                        return Err(failure("diagnostics must be nonfatal and always retained"));
                    }
                    if matches!(name, "miri" | "fuzz")
                        && !scalar(with, "name").is_some_and(|value| value.contains("matrix.shard"))
                    {
                        return Err(failure("matrix diagnostics require their actual shard"));
                    }
                } else if step.contains_key(key("continue-on-error")) {
                    if !matches!(
                        name,
                        "native-linux-x64"
                            | "native-linux-arm64"
                            | "native-macos-x64"
                            | "native-macos-arm64"
                            | "native-windows-x64"
                            | "native-windows-arm64"
                    ) || scalar(with, "path")
                        != Some(".release/support-loader-diagnostic/diagnostic-artifacts")
                    {
                        return Err(failure("required artifact failure cannot be ignored"));
                    }
                    check_support_loader_diagnostic(steps)?;
                }
            }
            if uses.starts_with("actions/download-artifact@") && preparation {
                let with = mapping(
                    with.ok_or_else(|| failure("download inputs absent"))?,
                    "download inputs",
                )?;
                if with.contains_key(key("name"))
                    || with.contains_key(key("pattern"))
                    || scalar(with, "artifact-ids").is_none()
                {
                    return Err(failure(
                        "preparation downloads must select immutable producer IDs",
                    ));
                }
                let destination = scalar(with, "path").unwrap_or_default();
                let expected = match destination {
                    ".release" => Some("${{ needs.select.outputs.selection-artifact-id }}"),
                    ".release/packages" => Some("${{ needs.packages.outputs.artifact-id }}"),
                    ".release/target" => {
                        Some("${{ needs[matrix.native-job].outputs.artifact-id }}")
                    }
                    ".release/tool"
                        if matches!(
                            name,
                            "assemble"
                                | "assemble-payload"
                                | "packages"
                                | "source-checks"
                                | "msrv"
                                | "supply-chain"
                                | "miri"
                                | "fuzz"
                                | "rehearsal-tool"
                                | "recovery-inputs"
                        ) =>
                    {
                        Some("${{ needs.select.outputs.preparation-tool-artifact-id }}")
                    }
                    _ => None,
                };
                if expected.is_some_and(|expected| scalar(with, "artifact-ids") != Some(expected)) {
                    return Err(failure(
                        "preparation download must use its exact producer output ID",
                    ));
                }
            }
            if uses.starts_with("actions/cache/") {
                let path = with
                    .and_then(|with| with.get(key("path")))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if path.lines().any(|path| {
                    [".release", "reports", "installed", "credentials"]
                        .iter()
                        .any(|excluded| path.contains(excluded))
                }) {
                    return Err(failure(
                        "cache paths include staging, diagnostics, installation or credentials",
                    ));
                }
            }
        }
        if preparation && !diagnostic {
            return Err(failure(
                "each preparation job must retain bounded diagnostics",
            ));
        }
        if name.starts_with("native-") {
            let diagnostics = steps
                .iter()
                .find(|step| {
                    step.get(key("name")).and_then(Value::as_str)
                        == Some("Retain bounded preparation diagnostics")
                })
                .ok_or_else(|| failure("native diagnostics absent"))?;
            let paths = diagnostics
                .get(key("with"))
                .and_then(|with| with.get(key("path")))
                .and_then(Value::as_str)
                .ok_or_else(|| failure("native diagnostic paths absent"))?;
            for required in [
                "target/ci/reports/release-macos-native.json",
                "target/ci/reports/release-macos-acceptance.json",
                "target/ci/reports/backend-macos-watchdog.json",
                "target/ci/reports/memcordon-macos-acceptance-*",
            ] {
                if !paths.lines().any(|path| path == required) {
                    return Err(failure(
                        "Release must preserve the actual macOS phase diagnostics",
                    ));
                }
            }
        }
        if name.starts_with("native-")
            && job.get(key("timeout-minutes")).and_then(Value::as_u64) != Some(301)
        {
            return Err(failure(
                "native serial phases and bounded cache finalization require the 301 minute planning envelope",
            ));
        }
        if name.starts_with("installed-") {
            let native = job
                .get(key("needs"))
                .and_then(Value::as_sequence)
                .and_then(|needs| needs.get(2))
                .and_then(Value::as_str)
                .ok_or_else(|| failure("installed native dependency absent"))?;
            if job
                .get(key("strategy"))
                .and_then(|value| value.get(key("matrix")))
                .and_then(|value| value.get(key("include")))
                .and_then(Value::as_sequence)
                .and_then(|rows| rows.first())
                .and_then(|row| row.get(key("native-job")))
                .and_then(Value::as_str)
                != Some(native)
            {
                return Err(failure(
                    "installed immutable artifact route must use its architecture-local producer",
                ));
            }
        }
    }
    let assemble = jobs
        .get(key("assemble"))
        .ok_or_else(|| failure("assembly absent"))?;
    let steps = assemble["steps"]
        .as_sequence()
        .ok_or_else(|| failure("assembly steps absent"))?;
    for (id, path, role) in [
        ("prepared", ".release/final/prepared", "prepared"),
        (
            "publication-tool",
            ".release/final/tool/memcordon-publication-tool.tar.gz",
            "publication-tool",
        ),
    ] {
        let expected_name =
            format!("{role}-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}");
        let matches: Vec<_> = steps
            .iter()
            .filter(|step| step["id"].as_str() == Some(id))
            .collect();
        if matches.len() != 1
            || matches[0]["with"]["path"].as_str() != Some(path)
            || matches[0]["with"]["name"].as_str() != Some(expected_name.as_str())
            || matches[0]["if"].as_str()
                != Some("needs.select.outputs.preparation-kind == 'tagged'")
        {
            return Err(failure(
                "tagged assembly must upload the prepared and unchanged tool archive final pair",
            ));
        }
    }
    let finalize = "./.release/tool/memcordon-ci release finalize-preparation --build-source .release/build-source.json --input .release/assembled --publisher-archive .release/tool/memcordon-publication-tool.tar.gz --destination .release/final";
    if steps
        .iter()
        .filter(|step| {
            step["run"].as_str() == Some(finalize)
                && step["if"].is_null()
                && step["continue-on-error"].is_null()
        })
        .count()
        != 1
        || steps.iter().any(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.contains("cargo ") || run.contains(" release assemble "))
        })
    {
        return Err(failure(
            "finalization must copy validated original bytes without rebuilding",
        ));
    }
    let finalize_index = steps
        .iter()
        .position(|step| {
            step["run"].as_str() == Some(finalize)
                && step["if"].is_null()
                && step["continue-on-error"].is_null()
        })
        .ok_or_else(|| failure("finalization command absent"))?;
    let inputs: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| step["with"]["path"].as_str() == Some(".release/assembled"))
        .collect();
    if inputs.len() != 1 || inputs[0].0 >= finalize_index {
        return Err(failure(
            "one immutable assembled input must precede finalization",
        ));
    }
    check_rehearsal_download(
        inputs[0].1,
        "${{ needs.assemble-payload.outputs.assembled-artifact-id }}",
        ".release/assembled",
        None,
        false,
    )?;
    let early = jobs
        .get(key("assemble-payload"))
        .ok_or_else(|| failure("early assembly absent"))?;
    exact_string_sequence(
        &early["needs"],
        &[
            "select",
            "packages",
            "native-linux-x64",
            "native-linux-arm64",
            "native-macos-x64",
            "native-macos-arm64",
            "native-windows-x64",
            "native-windows-arm64",
        ],
        "early assembly producer inputs",
    )?;
    if early["outputs"]["assembled-artifact-id"].as_str()
        != Some("${{ steps.assembled.outputs.artifact-id }}")
    {
        return Err(failure(
            "early assembly must expose only its intermediate artifact",
        ));
    }
    let steps = early["steps"]
        .as_sequence()
        .ok_or_else(|| failure("early assembly steps absent"))?;
    for platform in [
        "linux-x64",
        "linux-arm64",
        "macos-x64",
        "macos-arm64",
        "windows-x64",
        "windows-arm64",
    ] {
        let expected_id = format!("${{{{ needs.native-{platform}.outputs.artifact-id }}}}");
        let expected_path = format!(".release/targets/{platform}");
        if steps
            .iter()
            .filter(|step| {
                step["with"]["artifact-ids"].as_str() == Some(expected_id.as_str())
                    && step["with"]["path"].as_str() == Some(expected_path.as_str())
            })
            .count()
            != 1
        {
            return Err(failure(
                "assembly requires six exact immutable target downloads in separate roots",
            ));
        }
    }
    Ok(())
}

pub fn validate_workflow_bytes(
    root: &Path,
    relative: &Path,
    bytes: &[u8],
    policy: &config::Policy,
) -> Result<()> {
    validate_workflow_bytes_into(
        root,
        relative,
        bytes,
        policy,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        None,
    )
}

/// Validates exact-commit workflow bytes against exact-commit local action bytes.
pub fn validate_workflow_bytes_with_local_actions(
    root: &Path,
    relative: &Path,
    bytes: &[u8],
    policy: &config::Policy,
    local_actions: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    validate_workflow_bytes_into(
        root,
        relative,
        bytes,
        policy,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        Some(local_actions),
    )
}

fn check_workflow(
    root: &Path,
    relative: &Path,
    policy: &config::Policy,
    environment_definitions: &mut BTreeSet<EnvironmentDefinition>,
    used_actions: &mut BTreeSet<String>,
) -> Result<()> {
    validate_workflow_bytes_into(
        root,
        relative,
        &fs::read(root.join(relative))?,
        policy,
        environment_definitions,
        used_actions,
        None,
    )
}

fn driver_fixture_environment_slot(key: &str, value: &syn::Expr) -> Option<usize> {
    match (key, value) {
        ("GITHUB_EVENT_NAME", syn::Expr::Path(event)) if event.path.is_ident("event") => Some(0),
        (
            "GITHUB_REF",
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(reference),
                ..
            }),
        ) if reference.value() == "refs/heads/test" => Some(1),
        ("GITHUB_OUTPUT", syn::Expr::Reference(output)) if matches!(output.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("outputs")) => {
            Some(2)
        }
        ("CARGO_HOME", syn::Expr::MethodCall(home))
            if home.method == "join"
                && home.args.len() == 1
                && matches!(home.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(directory), .. })) if directory.value() == "cargo-home")
                && matches!(home.receiver.as_ref(), syn::Expr::MethodCall(unwrap) if unwrap.method == "unwrap" && unwrap.args.is_empty()
                    && matches!(unwrap.receiver.as_ref(), syn::Expr::MethodCall(canonical) if canonical.method == "canonicalize" && canonical.args.is_empty()
                        && matches!(canonical.receiver.as_ref(), syn::Expr::Path(root) if root.path.is_ident("root")))) =>
        {
            Some(3)
        }
        _ => None,
    }
}

#[derive(Default)]
struct RustPolicy {
    violations: Vec<String>,
    calls_current_exe: bool,
    names_proc_self_exe: bool,
    calls_env_remove: bool,
    subprocess_env_mutations: usize,
    standard_path_mutations: usize,
    standard_proxy_mutations: usize,
    standard_compiler_mutations: usize,
    cleared_environments: usize,
    cargo_home_mutations: usize,
    offline_download_fixture_mutations: usize,
    cargo_job_budget_mutations: usize,
    managed_miri_sysroot_mutations: usize,
    standard_output_mutations: usize,
    driver_fixture_mutations: [usize; 4],
    pre_exec_calls: usize,
    fork_calls: usize,
}

impl<'ast> Visit<'ast> for RustPolicy {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = expression.func.as_ref() {
            let segments: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            if segments.len() >= 2
                && segments[segments.len() - 2] == "env"
                && segments
                    .last()
                    .is_some_and(|segment| matches!(segment.as_str(), "set_var" | "remove_var"))
            {
                self.violations
                    .push("std::env environment mutation is forbidden".to_owned());
            }
            if segments.len() >= 2
                && segments[segments.len() - 2] == "libc"
                && segments.last().is_some_and(|segment| segment == "fork")
            {
                self.fork_calls += 1;
            }
            if segments
                .last()
                .is_some_and(|segment| segment == "current_exe")
            {
                self.calls_current_exe = true;
            }
            let constructs_shell = segments.last().is_some_and(|segment| segment == "new")
                && expression.args.first().is_some_and(|argument| {
                    let syn::Expr::Lit(literal) = argument else {
                        return false;
                    };
                    let syn::Lit::Str(program) = &literal.lit else {
                        return false;
                    };
                    [
                        "sh",
                        "bash",
                        "cmd",
                        "powershell",
                        "pwsh",
                        "/bin/sh",
                        "/bin/bash",
                    ]
                    .contains(&program.value().as_str())
                });
            if constructs_shell {
                self.violations
                    .push("shell process spawn is forbidden".to_owned());
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if expression.method == "env_clear" {
            self.cleared_environments += 1;
        }
        if expression.method == "env_remove" {
            self.calls_env_remove = true;
        }
        if expression.method == "pre_exec" {
            self.pre_exec_calls += 1;
        }
        if matches!(expression.method.to_string().as_str(), "env" | "envs") {
            self.subprocess_env_mutations += 1;
            if expression.method == "env"
                && expression.args.len() == 2
                && let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(key),
                    ..
                }) = &expression.args[0]
                && let Some(slot) =
                    driver_fixture_environment_slot(&key.value(), &expression.args[1])
            {
                self.driver_fixture_mutations[slot] += 1;
            }
            if expression.method == "env"
                && matches!(expression.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if key.value() == "PATH")
            {
                self.standard_path_mutations += 1;
            }
            if expression.method == "env"
                && matches!(expression.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if matches!(key.value().as_str(), "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "http_proxy" | "https_proxy" | "all_proxy" | "NO_PROXY" | "no_proxy"))
            {
                self.standard_proxy_mutations += 1;
            }
            if expression.method == "env"
                && matches!(expression.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if matches!(key.value().as_str(), "CARGO_HOME" | "RUSTC" | "TMPDIR"))
            {
                self.standard_compiler_mutations += 1;
            }
            if expression.method == "env"
                && matches!(expression.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if key.value() == "CARGO_HOME")
            {
                self.cargo_home_mutations += 1;
            }
            if expression.method == "env"
                && expression.args.len() == 2
                && matches!(expression.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if key.value() == "CARGO_NET_OFFLINE")
                && matches!(expression.args.iter().nth(1), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(value), .. })) if value.value() == "true")
            {
                self.offline_download_fixture_mutations += 1;
            }
            if expression.method == "env"
                && matches!(expression.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if key.value() == "CARGO_BUILD_JOBS")
                && matches!(expression.args.iter().nth(1), Some(syn::Expr::MethodCall(serialized)) if serialized.method == "to_string" && serialized.args.is_empty()
                    && matches!(&*serialized.receiver, syn::Expr::MethodCall(jobs) if jobs.method == "compiler_jobs" && jobs.args.is_empty()
                        && matches!(&*jobs.receiver, syn::Expr::Path(group) if group.path.is_ident("group"))))
            {
                self.cargo_job_budget_mutations += 1;
            }
            if expression.method == "env"
                && matches!(expression.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if key.value() == "MIRI_SYSROOT")
                && matches!(expression.args.iter().nth(1), Some(syn::Expr::Path(root)) if root.path.is_ident("root"))
            {
                self.managed_miri_sysroot_mutations += 1;
            }
            if expression.method == "env"
                && matches!(expression.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if key.value() == "GITHUB_OUTPUT")
            {
                self.standard_output_mutations += 1;
            }
        }
        syn::visit::visit_expr_method_call(self, expression);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path.segments.iter().any(|segment| segment.ident == "regex") {
            self.violations
                .push("regular-expression infrastructure is forbidden".to_owned());
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        if literal.value() == "/proc/self/exe" {
            self.names_proc_self_exe = true;
        }
        syn::visit::visit_lit_str(self, literal);
    }
}

/// Parses untrusted Rust source and applies the repository's semantic subprocess policy.
fn reviewed_environment_removal(relative: &Path, visitor: &RustPolicy) -> bool {
    !visitor.calls_env_remove
        || [
            Path::new("tools/memcordon-ci/src/command.rs"),
            Path::new("tools/memcordon-ci/src/release/git.rs"),
            Path::new("tools/memcordon-ci/src/rehearsal_support/coordinator.rs"),
            Path::new("tools/memcordon-ci/tests/release_rehearsal_http.rs"),
        ]
        .contains(&relative)
}

fn reviewed_git_environment(relative: &Path) -> bool {
    [
        Path::new("tools/memcordon-ci/src/release/git.rs"),
        Path::new("tools/memcordon-ci/src/release/tag.rs"),
    ]
    .contains(&relative)
}

fn reviewed_proxy_environment(relative: &Path, visitor: &RustPolicy) -> bool {
    relative == Path::new("tools/memcordon-ci/tests/release_rehearsal_transport.rs")
        && visitor.subprocess_env_mutations == visitor.standard_proxy_mutations
}

fn reviewed_compiler_environment(relative: &Path, visitor: &RustPolicy) -> bool {
    // The installed Linux joint fixture runs its selected, held compiler with
    // an empty inherited environment and explicit standard toolchain paths.
    relative == Path::new("crates/memcordon-cli/src/bin/consumer_readiness_linux/mod.rs")
        && visitor.subprocess_env_mutations == visitor.standard_compiler_mutations
        && visitor.standard_compiler_mutations == 3
        && visitor.cleared_environments == 1
}

fn reviewed_isolated_cargo_environment(relative: &Path, visitor: &RustPolicy) -> bool {
    // CommandSpec removes ambient Cargo/compiler overrides before selecting
    // the owned standard Cargo home, compiler allocation and managed Miri
    // sysroot. Each extra setter has one reviewed source/value shape.
    relative == Path::new("tools/memcordon-ci/src/command.rs")
        && visitor.cargo_job_budget_mutations <= 1
        && visitor.managed_miri_sysroot_mutations <= 1
        && visitor.subprocess_env_mutations
            == visitor.cargo_home_mutations
                + visitor.cargo_job_budget_mutations
                + visitor.managed_miri_sysroot_mutations
}

fn reviewed_download_fixture_environment(relative: &Path, visitor: &RustPolicy) -> bool {
    // The driver fixture must simulate both trusted push and untrusted PR
    // events, an owned output receipt, and its isolated standard Cargo home.
    // Every setter has one exact source/value shape; no ambient state changes.
    if relative == Path::new("tools/memcordon-ci/tests/driver_cache.rs") {
        return visitor.driver_fixture_mutations == [1; 4]
            && visitor.subprocess_env_mutations
                == visitor.driver_fixture_mutations.iter().sum::<usize>()
            && visitor.cleared_environments == 0;
    }
    // Only the authored-registry installation fixture forces Cargo offline;
    // other transport fixtures retain the existing home/output-only boundary.
    let offline = if relative == Path::new("tools/memcordon-ci/tests/tool_download_roundtrip.rs") {
        visitor.offline_download_fixture_mutations
    } else {
        0
    };
    [
        Path::new("tools/memcordon-ci/tests/cache_download_families.rs"),
        Path::new("tools/memcordon-ci/tests/cache_snapshot_transport.rs"),
        Path::new("tools/memcordon-ci/tests/tool_download_roundtrip.rs"),
    ]
    .contains(&relative)
        && visitor.subprocess_env_mutations
            == visitor.cargo_home_mutations + visitor.standard_output_mutations + offline
        && visitor.cleared_environments == 0
}

fn reviewed_macos_writer_image(relative: &Path) -> bool {
    [
        Path::new("crates/memcordon-platform/src/macos_watchdog.rs"),
        Path::new("crates/memcordon-platform/src/macos_launch_runtime.rs"),
        Path::new("crates/memcordon-platform/src/macos_result_delivery.rs"),
    ]
    .contains(&relative)
}

pub fn validate_rust_policy_bytes(relative: &Path, bytes: &[u8]) -> Result<()> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| failure(format!("Rust source is not UTF-8: {relative:?}")))?;
    let syntax = syn::parse_file(source).map_err(|error| {
        failure(format!(
            "Rust syntax parse failed for {relative:?}: {error}"
        ))
    })?;
    let mut visitor = RustPolicy::default();
    visitor.visit_file(&syntax);
    let test_support = Path::new("crates/memcordon-platform/src/test_support.rs");
    let sealed_launch =
        Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs");
    let native_path_fixture = [
        Path::new("crates/memcordon-cli/tests/macos_remediation.rs"),
        Path::new("crates/memcordon-cli/src/bin/memcordon-test-fixture.rs"),
    ]
    .contains(&relative)
        && visitor.subprocess_env_mutations == visitor.standard_path_mutations;
    if visitor.subprocess_env_mutations != 0
        && relative != sealed_launch
        && !native_path_fixture
        && !reviewed_proxy_environment(relative, &visitor)
        && !reviewed_compiler_environment(relative, &visitor)
        && !reviewed_isolated_cargo_environment(relative, &visitor)
        && !reviewed_download_fixture_environment(relative, &visitor)
        && !reviewed_git_environment(relative)
    {
        visitor
            .violations
            .push("subprocess environment mutation is forbidden".to_owned());
    }
    if visitor.pre_exec_calls != 0 && relative != test_support {
        visitor.violations.push(
            "pre_exec is allowed only at the exact reviewed process-test boundary".to_owned(),
        );
    }
    if visitor.fork_calls != 0 && !is_reviewed_raw_fork_boundary(relative) {
        visitor.violations.push("raw fork is forbidden".to_owned());
    }
    if relative.starts_with(Path::new("crates/memcordon-platform/src"))
        && (visitor.names_proc_self_exe
            || (visitor.calls_current_exe && !reviewed_macos_writer_image(relative)))
    {
        visitor
            .violations
            .push("platform helper self-execution is forbidden".to_owned());
    }
    if !reviewed_environment_removal(relative, &visitor) {
        visitor
            .violations
            .push("credential removal is allowed only in exact CI tooling".to_owned());
    }
    if visitor.violations.is_empty() {
        Ok(())
    } else {
        Err(failure(format!(
            "Rust policy failed for {relative:?}: {:?}",
            visitor.violations
        )))
    }
}

fn check_rust(root: &Path, files: &[PathBuf]) -> Result<()> {
    let mut candidates: BTreeSet<PathBuf> = files
        .iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .cloned()
        .collect();
    for base in [
        root.join("tools").join("memcordon-ci"),
        root.join("crates").join("memcordon-testkit"),
        root.join("crates")
            .join("memcordon-cli")
            .join("src")
            .join("bin"),
        root.join("crates").join("memcordon-cli").join("tests"),
        root.join("crates").join("memcordon-platform").join("src"),
    ] {
        for entry in WalkDir::new(base) {
            let entry = entry.map_err(|error| failure(error.to_string()))?;
            if entry.file_type().is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "rs")
            {
                candidates.insert(
                    entry
                        .path()
                        .strip_prefix(root)
                        .map_err(|error| failure(error.to_string()))?
                        .to_path_buf(),
                );
            }
        }
    }
    let mut test_boundary_pre_exec = 0_usize;
    for relative in &candidates {
        let source = fs::read_to_string(root.join(relative))?;
        let syntax = syn::parse_file(&source).map_err(|error| {
            failure(format!(
                "Rust syntax parse failed for {relative:?}: {error}"
            ))
        })?;
        let mut visitor = RustPolicy::default();
        visitor.visit_file(&syntax);
        let test_support = Path::new("crates/memcordon-platform/src/test_support.rs");
        let sealed_launch =
            Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs");
        let native_path_fixture = [
            Path::new("crates/memcordon-cli/tests/macos_remediation.rs"),
            Path::new("crates/memcordon-cli/src/bin/memcordon-test-fixture.rs"),
        ]
        .contains(&relative.as_path())
            && visitor.subprocess_env_mutations == visitor.standard_path_mutations;
        if visitor.subprocess_env_mutations != 0
            && relative != sealed_launch
            && !native_path_fixture
            && !reviewed_proxy_environment(relative, &visitor)
            && !reviewed_compiler_environment(relative, &visitor)
            && !reviewed_isolated_cargo_environment(relative, &visitor)
            && !reviewed_download_fixture_environment(relative, &visitor)
            && !reviewed_git_environment(relative)
        {
            visitor
                .violations
                .push("subprocess environment mutation is forbidden".to_owned());
        }
        if visitor.pre_exec_calls != 0 && relative != test_support {
            visitor
                .violations
                .push("pre_exec is allowed only at the reviewed process-test boundary".to_owned());
        }
        if visitor.fork_calls != 0 && !is_reviewed_raw_fork_boundary(relative) {
            visitor.violations.push("raw fork is forbidden".to_owned());
        }
        if relative == test_support {
            test_boundary_pre_exec = visitor.pre_exec_calls;
        }
        if relative.starts_with(Path::new("crates/memcordon-platform/src"))
            && (visitor.names_proc_self_exe
                || (visitor.calls_current_exe && !reviewed_macos_writer_image(relative)))
        {
            visitor
                .violations
                .push("platform helper self-execution is forbidden".to_owned());
        }
        if !reviewed_environment_removal(relative, &visitor) {
            visitor
                .violations
                .push("credential removal is allowed only in exact CI tooling".to_owned());
        }
        if !visitor.violations.is_empty() {
            return Err(failure(format!(
                "Rust policy failed for {relative:?}: {:?}",
                visitor.violations
            )));
        }
    }
    if test_boundary_pre_exec != 1 {
        return Err(failure(
            "reviewed process-test boundary must contain exactly one pre_exec hook",
        ));
    }
    Ok(())
}

fn is_reviewed_raw_fork_boundary(relative: &Path) -> bool {
    matches!(
        relative,
        path if path == Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs")
            || path == Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launcher.rs")
            || path == Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/namespace.rs")
            || path == Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/service.rs")
            // These isolated sealed workers require inherited namespace,
            // descriptor, or ABI custody; arbitrary private modules remain forbidden.
            || path == Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/private_guardian.rs")
            || path == Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/private_namespace_init.rs")
            || path
                == Path::new(
                    "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture.rs",
                )
            || path == Path::new("crates/memcordon-cli/tests/sealed_agent/linux_faults.rs")
            || path == Path::new("crates/memcordon-cli/tests/sealed_agent/linux_sealed.rs")
            || path == Path::new("crates/memcordon-cli/tests/sealed_agent/launcher_activation.rs")
            || path == Path::new("crates/memcordon-cli/tests/sealed_agent/native_descriptor_custody.rs")
            // Root-native fixture owns every child/pidfd and signals no external PID.
            || path == Path::new("crates/memcordon-cli/tests/release/native_private_owner_loss.rs")
    )
}

pub fn workspace_metadata_command(root: &Path) -> Result<command::CommandSpec> {
    let toolchains = config::toolchains(root)?;
    Ok(command::rustup_cargo(
        root,
        &toolchains.stable,
        [
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
        ],
        std::time::Duration::from_secs(120),
    ))
}

pub fn workspace_metadata(root: &Path) -> Result<cargo_metadata::Metadata> {
    let output = workspace_metadata_command(root)?.output_quiet()?;
    if !output.status.success() {
        return Err(failure(format!(
            "workspace metadata failed with {}; stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn check_manifests(root: &Path, policy: &config::Policy) -> Result<()> {
    let metadata = workspace_metadata(root)?;
    let release = config::release(root)?;
    if release.publish_packages != policy.workspace.publish_packages {
        return Err(failure(
            "release and workspace publish package orders differ",
        ));
    }
    let workspace_version = metadata
        .packages
        .iter()
        .find(|package| package.name.as_str() == "memcordon")
        .map(|package| package.version.clone())
        .ok_or_else(|| failure("workspace version is unavailable"))?;
    config::validate_registry_credentials(&release, &workspace_version)?;
    config::publish_order(&metadata, &release.publish_packages)?;
    let packages: BTreeMap<&str, &cargo_metadata::Package> = metadata
        .packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect();
    let production: BTreeSet<&str> = policy
        .workspace
        .production_packages
        .iter()
        .map(String::as_str)
        .collect();
    let ci: BTreeSet<&str> = policy
        .workspace
        .ci_packages
        .iter()
        .map(String::as_str)
        .collect();
    let publish: BTreeSet<&str> = policy
        .workspace
        .publish_packages
        .iter()
        .map(String::as_str)
        .collect();
    let non_publish: BTreeSet<&str> = policy
        .workspace
        .non_publish_packages
        .iter()
        .map(String::as_str)
        .collect();
    if !production.is_disjoint(&ci) || !publish.is_disjoint(&non_publish) {
        return Err(failure("workspace policy package lists overlap"));
    }
    let configured_workspace: BTreeSet<&str> = production.union(&ci).copied().collect();
    let configured_publication: BTreeSet<&str> = publish.union(&non_publish).copied().collect();
    let actual: BTreeSet<&str> = packages.keys().copied().collect();
    if configured_workspace != actual || configured_publication != actual {
        return Err(failure(format!(
            "workspace policy package lists are incomplete: actual={actual:?}"
        )));
    }
    let actual_rust_versions: BTreeMap<String, semver::Version> = packages
        .iter()
        .filter_map(|(name, package)| {
            package
                .rust_version
                .clone()
                .map(|version| ((*name).to_owned(), version))
        })
        .collect();
    let production_msrv = semver::Version::parse(&config::toolchains(root)?.msrv)?;
    validate_package_rust_versions(&actual_rust_versions, &policy.workspace, &production_msrv)?;
    for (name, package) in &packages {
        for dependency in &package.dependencies {
            if ["regex", "xshell", "duct", "shell-words"].contains(&dependency.name.as_str()) {
                return Err(failure(format!(
                    "forbidden regex or shell dependency (including aliases): {name} -> {}",
                    dependency.name
                )));
            }
            let internal = packages.contains_key(dependency.name.as_str());
            let exact = dependency.req.to_string() == format!("={}", package.version);
            let unpublished_dev_path = dependency.kind
                == cargo_metadata::DependencyKind::Development
                && non_publish.contains(dependency.name.as_str())
                && dependency.path.is_some();
            if internal && (dependency.path.is_none() || (!exact && !unpublished_dev_path)) {
                return Err(failure(format!(
                    "internal dependency must use an exact version and local path (except unpublished dev-only paths): {name} -> {}",
                    dependency.name
                )));
            }
        }
    }
    for name in policy
        .workspace
        .production_packages
        .iter()
        .chain(&policy.workspace.ci_packages)
    {
        if !packages.contains_key(name.as_str()) {
            return Err(failure(format!(
                "configured package does not exist: {name}"
            )));
        }
    }
    for name in &policy.workspace.publish_packages {
        let package = packages
            .get(name.as_str())
            .ok_or_else(|| failure(format!("publish package does not exist: {name}")))?;
        if package.publish.as_ref().is_none_or(|registries| {
            registries.len() != 1
                || registries
                    .first()
                    .is_none_or(|registry| registry != "crates-io")
        }) {
            return Err(failure(format!(
                "publish package is not crates.io-only: {name}"
            )));
        }
        if package.description.as_deref().is_none_or(str::is_empty)
            || package.repository.as_deref().is_none_or(str::is_empty)
            || package.readme.is_none()
            || package.license.as_deref().is_none_or(str::is_empty)
            || package.keywords.is_empty()
            || package.categories.is_empty()
        {
            return Err(failure(format!(
                "publish package metadata is incomplete: {name}"
            )));
        }
    }
    for name in &policy.workspace.non_publish_packages {
        let package = packages
            .get(name.as_str())
            .ok_or_else(|| failure(format!("non-publish package does not exist: {name}")))?;
        if package
            .publish
            .as_ref()
            .is_none_or(|registries| !registries.is_empty())
        {
            return Err(failure(format!(
                "package must declare publish=false: {name}"
            )));
        }
    }
    Ok(())
}

pub fn validate_package_rust_versions(
    actual: &BTreeMap<String, semver::Version>,
    workspace: &config::WorkspacePolicy,
    production_msrv: &semver::Version,
) -> Result<()> {
    let configured_ci: BTreeSet<&str> = workspace.ci_packages.iter().map(String::as_str).collect();
    let versioned_ci: BTreeSet<&str> = workspace
        .ci_package_rust_versions
        .keys()
        .map(String::as_str)
        .collect();
    if configured_ci != versioned_ci {
        return Err(failure(
            "CI package Rust-version policy does not match the configured CI package set",
        ));
    }
    for package in &workspace.production_packages {
        let version = actual
            .get(package)
            .ok_or_else(|| failure(format!("package lacks rust-version: {package}")))?;
        if version != production_msrv {
            return Err(failure(format!(
                "production package rust-version differs: {package} expected={production_msrv} actual={version}"
            )));
        }
    }
    for package in &workspace.ci_packages {
        let expected = workspace
            .ci_package_rust_versions
            .get(package)
            .ok_or_else(|| failure(format!("CI package lacks Rust-version policy: {package}")))?;
        let version = actual
            .get(package)
            .ok_or_else(|| failure(format!("package lacks rust-version: {package}")))?;
        if version != expected {
            return Err(failure(format!(
                "CI package rust-version differs: {package} expected={expected} actual={version}"
            )));
        }
    }
    Ok(())
}

fn check_cargo_configuration(root: &Path, files: &[PathBuf]) -> Result<()> {
    for relative in files {
        let file_name = relative.file_name().and_then(|name| name.to_str());
        if relative.starts_with(".cargo")
            && matches!(file_name, Some("credentials" | "credentials.toml"))
        {
            return Err(failure(format!(
                "tracked Cargo credentials are forbidden: {relative:?}"
            )));
        }
        let is_manifest = file_name == Some("Cargo.toml");
        let is_cargo_config =
            relative.starts_with(".cargo") && matches!(file_name, Some("config" | "config.toml"));
        if !is_manifest && !is_cargo_config {
            continue;
        }
        let document: toml::Value = toml::from_str(&fs::read_to_string(root.join(relative))?)?;
        if is_cargo_config && document.get("env").is_some() {
            return Err(failure(format!(
                "Cargo environment definitions are forbidden: {relative:?}"
            )));
        }
        if is_cargo_config
            && (document.get("credential-alias").is_some()
                || document
                    .get("registry")
                    .and_then(toml::Value::as_table)
                    .is_some_and(|registry| {
                        registry.contains_key("token")
                            || registry.contains_key("credential-provider")
                            || registry.contains_key("global-credential-providers")
                    })
                || document
                    .get("registries")
                    .and_then(toml::Value::as_table)
                    .is_some_and(|registries| {
                        registries.values().any(|registry| {
                            registry.as_table().is_some_and(|registry| {
                                registry.contains_key("token")
                                    || registry.contains_key("credential-provider")
                            })
                        })
                    }))
        {
            return Err(failure(format!(
                "tracked Cargo credential configuration is forbidden: {relative:?}"
            )));
        }
        if is_manifest {
            for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if document
                    .get(table_name)
                    .and_then(toml::Value::as_table)
                    .is_some_and(|table| table.contains_key("regex"))
                {
                    return Err(failure(format!(
                        "regular-expression dependency is forbidden: {relative:?} [{table_name}]"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn removal_only_legacy_token(source: &str) -> bool {
    let Ok(syntax) = syn::parse_file(source) else {
        return false;
    };
    let mut reviewed = 0;
    for item in syntax.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        if function.sig.ident != "sanitize_child" || function.sig.inputs.len() != 1 {
            continue;
        }
        let Some(syn::FnArg::Typed(argument)) = function.sig.inputs.first() else {
            continue;
        };
        let syn::Pat::Ident(parameter) = argument.pat.as_ref() else {
            continue;
        };
        let syn::Type::Reference(reference) = argument.ty.as_ref() else {
            continue;
        };
        let syn::Type::Path(argument_type) = reference.elem.as_ref() else {
            continue;
        };
        if reference.mutability.is_none() || !argument_type.path.is_ident("Command") {
            continue;
        }
        for statement in &function.block.stmts {
            let syn::Stmt::Expr(syn::Expr::ForLoop(loop_expression), _) = statement else {
                continue;
            };
            let syn::Pat::Ident(binding) = loop_expression.pat.as_ref() else {
                continue;
            };
            let syn::Expr::Array(names) = loop_expression.expr.as_ref() else {
                continue;
            };
            if !names.elems.iter().all(|name| {
                matches!(
                    name,
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(_),
                        ..
                    })
                )
            }) {
                continue;
            }
            let [syn::Stmt::Expr(syn::Expr::MethodCall(removal), _)] =
                loop_expression.body.stmts.as_slice()
            else {
                continue;
            };
            let syn::Expr::Path(receiver) = removal.receiver.as_ref() else {
                continue;
            };
            let Some(syn::Expr::Path(name)) = removal.args.first() else {
                continue;
            };
            if removal.method != "env_remove"
                || removal.args.len() != 1
                || !receiver.path.is_ident(&parameter.ident)
                || !name.path.is_ident(&binding.ident)
            {
                continue;
            }
            for name in &names.elems {
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(name),
                    ..
                }) = name
                    && name.value() == "CARGO_REGISTRY_TOKEN"
                {
                    reviewed += 1;
                }
            }
        }
    }
    reviewed != 0 && reviewed == source.matches("CARGO_REGISTRY_TOKEN").count()
}

fn trusted_workflow_definition_token(source: &str) -> bool {
    fn text_literal(expression: &syn::Expr) -> Option<String> {
        let syn::Expr::Call(call) = expression else {
            return None;
        };
        let syn::Expr::Path(function) = call.func.as_ref() else {
            return None;
        };
        if !function.path.is_ident("text") || call.args.len() != 1 {
            return None;
        }
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(value),
            ..
        }) = call.args.first()?
        else {
            return None;
        };
        Some(value.value())
    }
    struct Bindings(usize);
    impl<'ast> Visit<'ast> for Bindings {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "insert"
                && call.args.len() == 2
                && text_literal(&call.args[0]).as_deref() == Some("CARGO_REGISTRY_TOKEN")
                && text_literal(&call.args[1]).as_deref()
                    == Some("${{ steps.registry-auth.outputs.token }}")
            {
                self.0 += 1;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let Ok(syntax) = syn::parse_file(source) else {
        return false;
    };
    let mut bindings = Bindings(0);
    bindings.visit_file(&syntax);
    // Other reads, writes, literals and interfaces remain prohibited even in
    // the authoritative workflow source. Emitted auth flow is checked below.
    bindings.0 != 0 && bindings.0 == source.matches("CARGO_REGISTRY_TOKEN").count()
}

pub fn validate_legacy_registry_token_source(relative: &Path, source: &str) -> Result<()> {
    let legacy_secret_source = ["${{ secrets.", "CARGO_REGISTRY_TOKEN", " }}"].concat();
    if source.contains(legacy_secret_source.as_str()) {
        return Err(failure(format!(
            "legacy broad crates.io token source remains: {relative:?}"
        )));
    }
    if !source.contains("CARGO_REGISTRY_TOKEN") {
        return Ok(());
    }
    let established = [
        "tools/memcordon-ci/src/command.rs",
        "tools/memcordon-ci/src/policy.rs",
        "tools/memcordon-ci/tests/command.rs",
        "tools/memcordon-ci/tests/unit/policy.rs",
        "RELEASING.md",
        "MAINTAINERS.md",
        "ci/policy.toml",
        ".github/workflows/release.yml",
        "tools/memcordon-ci/src/release/publish.rs",
        "tools/memcordon-ci/src/release/git.rs",
    ]
    .iter()
    .any(|path| relative == Path::new(path));
    if established
        || relative == Path::new("tools/memcordon-ci/src/workflow_definitions/release.rs")
            && trusted_workflow_definition_token(source)
        || relative == Path::new("tools/memcordon-ci/src/rehearsal_support/coordinator.rs")
            && removal_only_legacy_token(source)
    {
        return Ok(());
    }
    Err(failure(format!(
        "legacy crates.io token interface remains outside negative policy assertions: {relative:?}"
    )))
}

pub fn run(root: &Path) -> Result<()> {
    let policy = config::policy(root)?;
    for command in &policy.workflow.allowed_run_commands {
        if !static_run_command(command) {
            return Err(failure(format!(
                "allowlisted workflow command is not static: {command:?}"
            )));
        }
    }
    let files = inventory(root)?;
    check_files(root, &files, &policy)?;
    validate_dependabot_bytes(&fs::read(root.join(".github/dependabot.yml"))?)?;
    let main_source = fs::read_to_string(root.join("tools/memcordon-ci/src/main.rs"))?;
    if main_source.contains("BootstrapCrates") || main_source.contains("bootstrap-crates") {
        return Err(failure("obsolete bootstrap-crates CLI path is forbidden"));
    }
    if root
        .join(".github/workflows/release-bootstrap.yml")
        .exists()
    {
        return Err(failure(
            "temporary release bootstrap workflow must be removed in steady state",
        ));
    }
    for relative in &files {
        let bytes = fs::read(root.join(relative))?;
        if let Ok(text) = std::str::from_utf8(&bytes) {
            validate_legacy_registry_token_source(relative, text)?;
        }
    }
    let mut environment_definitions = BTreeSet::new();
    let mut used_actions = BTreeSet::new();
    for entry in WalkDir::new(root.join(".github").join("workflows"))
        .min_depth(1)
        .max_depth(1)
    {
        let entry = entry.map_err(|error| failure(error.to_string()))?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "yml" || extension == "yaml")
        {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| failure(error.to_string()))?;
            check_workflow(
                root,
                relative,
                &policy,
                &mut environment_definitions,
                &mut used_actions,
            )?;
        }
    }
    let expected_environment: BTreeSet<EnvironmentDefinition> = policy
        .workflow
        .environment_allowlist
        .iter()
        .flat_map(|allowance| {
            allowance.steps.iter().map(|step| EnvironmentDefinition {
                file: allowance.file.clone(),
                step: step.clone(),
                variable: allowance.variable.clone(),
                source: allowance.source.clone(),
            })
        })
        .collect();
    if environment_definitions != expected_environment {
        return Err(failure(format!(
            "workflow environment definitions differ from the exact allowlist: observed={environment_definitions:?} expected={expected_environment:?}"
        )));
    }
    let configured_actions: BTreeSet<String> = config::action_pins(root)?
        .action
        .into_iter()
        .map(|pin| pin.uses)
        .collect();
    if used_actions != configured_actions {
        return Err(failure(format!(
            "action pin inventory differs from workflow uses: used={used_actions:?} configured={configured_actions:?}"
        )));
    }
    check_rust(root, &files)?;
    check_cargo_configuration(root, &files)?;
    check_manifests(root, &policy)?;
    if policy.test.fast_short_child_iterations != 128
        || policy.test.deep_short_child_iterations != 4_096
        || policy.test.release_short_child_iterations != 4_096
    {
        return Err(failure(
            "lifecycle iteration policy must remain 128 fast and 4096 deep/release",
        ));
    }
    println!("repository policy passed for {} tracked files", files.len());
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/policy.rs"]
mod tests;
