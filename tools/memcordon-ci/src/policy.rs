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
#[path = "policy_native_descriptor.rs"]
mod native_descriptor;
#[path = "policy_native_environment.rs"]
mod native_environment;

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
    check_top_level_permissions(workflow)?;
    let current_model = crate::workflow_definitions::validate_current_model(
        relative
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default(),
        &document,
    )?;
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
        let modeled_cargo_home = current_model
            && job_value["env"]
                .as_mapping()
                .is_some_and(|env| env.len() == 1)
            && job_value["env"]["CARGO_HOME"].as_str()
                == Some("${{ github.workspace }}/target/ci-cargo-home")
            && (matches!(
                job_name,
                "source-seed"
                    | "current-contracts"
                    | "tooling-contracts"
                    | "macos-administrative-contracts"
                    | "macos-startup-deadline-feedback"
                    | "windows-fixture-feedback"
                    | "windows-sealed-agent-contracts"
            ) || (relative == Path::new(".github/workflows/backend-certification.yml")
                && matches!(
                    job_name,
                    "private-linux-prepare-x64" | "private-linux-prepare-arm64"
                ))
                || job_value["steps"].as_sequence().is_some_and(|steps| {
                    steps.iter().any(|step| {
                        step["run"].as_str().is_some_and(|command| {
                            command.contains("--target-dir target/ci-driver-cold")
                        })
                    })
                }));
        if job.contains_key(key("shell")) || job.contains_key(key("env")) && !modeled_cargo_home {
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
                    && !(current_model && crate::workflow_definitions::known_run(run))
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
            }
        }
    }
    crate::workflow_definitions::validate_semantics(&document)?;
    if relative == Path::new(".github/workflows/release-current.yml") {
        return Err(failure("duplicate release workflow identity is forbidden"));
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

#[derive(Default)]
struct RustPolicy {
    violations: Vec<String>,
    calls_current_exe: bool,
    names_proc_self_exe: bool,
    calls_env_remove: bool,
    env_removal_calls: usize,
    subprocess_env_mutations: usize,
    standard_path_mutations: usize,
    standard_proxy_mutations: usize,
    standard_compiler_mutations: usize,
    cleared_environments: usize,
    cargo_home_mutations: usize,
    cargo_job_budget_mutations: usize,
    managed_miri_sysroot_mutations: usize,
    workload_loader_mutations: usize,
    owned_compiler_protocols: usize,
    compiler_protocol_removals: usize,
    compiler_protocol_setters: usize,
    command_sanitation_clears: usize,
    environment_sanitizations: usize,
    pre_exec_calls: usize,
    fork_calls: usize,
}

impl<'ast> Visit<'ast> for RustPolicy {
    fn visit_item_impl(&mut self, implementation: &'ast syn::ItemImpl) {
        if matches!(implementation.self_ty.as_ref(), syn::Type::Path(path) if path.path.is_ident("CommandSpec"))
            && implementation.trait_.is_none()
            && implementation.attrs.is_empty()
        {
            for item in &implementation.items {
                let syn::ImplItem::Fn(function) = item else {
                    continue;
                };
                if function.sig.ident == "materialize" && function.attrs.is_empty() {
                    let mut context = RustPolicy::default();
                    context.visit_block(&function.block);
                    if context.environment_sanitizations == 1 && context.env_removal_calls == 3 {
                        for statements in function.block.stmts.windows(2) {
                            if owned_compiler_protocol_branch(&statements[0], &statements[1]) {
                                self.owned_compiler_protocols += 1;
                            }
                        }
                    }
                }
                if function.sig.ident == "apply_environment" {
                    let mut sanitation = RustPolicy::default();
                    sanitation.visit_block(&function.block);
                    self.command_sanitation_clears += sanitation.cleared_environments;
                    self.workload_loader_mutations += function.block.stmts.iter().filter(|statement| {
                        matches!(statement, syn::Stmt::Expr(syn::Expr::If(branch), _) if reviewed_workload_loader_branch(branch))
                    }).count();
                }
            }
        }
        syn::visit::visit_item_impl(self, implementation);
    }

    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = expression.func.as_ref() {
            let segments: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            if segments.len() >= 2
                && matches!(
                    segments[segments.len() - 2].as_str(),
                    "Self" | "CommandSpec"
                )
                && segments
                    .last()
                    .is_some_and(|name| name == "apply_environment")
            {
                self.environment_sanitizations += 1;
            }
            if segments.len() >= 2
                && segments[segments.len() - 2] == "Command"
                && segments.last().is_some_and(|name| {
                    matches!(name.as_str(), "env" | "envs" | "env_remove" | "env_clear")
                })
            {
                self.violations.push(
                    "direct Command environment mutation bypasses reviewed method boundary"
                        .to_owned(),
                );
            }
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
        if expression.method == "apply_environment" {
            self.environment_sanitizations += 1;
        }
        if expression.method == "env_clear" {
            self.cleared_environments += 1;
        }
        if expression.method == "env_remove" {
            self.calls_env_remove = true;
            self.env_removal_calls += 1;
            if matches!(expression.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if matches!(key.value().as_str(), "MAKEFLAGS" | "MFLAGS" | "CARGO_BUILD_JOBS" | "CARGO_MAKEFLAGS"))
            {
                self.compiler_protocol_removals += 1;
            }
        }
        if expression.method == "pre_exec" {
            self.pre_exec_calls += 1;
        }
        if matches!(expression.method.to_string().as_str(), "env" | "envs") {
            self.subprocess_env_mutations += 1;
            if expression.method == "env"
                && matches!(expression.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if key.value() == "CARGO_MAKEFLAGS")
            {
                self.compiler_protocol_setters += 1;
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
        && visitor.workload_loader_mutations <= 1
        && reviewed_owned_compiler_protocol(relative, visitor)
        && visitor.subprocess_env_mutations
            == visitor.cargo_home_mutations
                + visitor.cargo_job_budget_mutations
                + visitor.managed_miri_sysroot_mutations
                + visitor.workload_loader_mutations
                + visitor.owned_compiler_protocols
}

fn reviewed_workload_loader_branch(branch: &syn::ExprIf) -> bool {
    if branch.attrs.len() != 1
        || branch.else_branch.is_some()
        || branch.then_branch.stmts.len() != 1
    {
        return false;
    }
    let attribute = &branch.attrs[0];
    if !attribute.path().is_ident("cfg")
        || !matches!(attribute.parse_args::<syn::Meta>(), Ok(syn::Meta::NameValue(value))
            if value.path.is_ident("target_os")
                && matches!(&value.value, syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(os), .. }) if os.value() == "linux"))
    {
        return false;
    }
    let syn::Expr::Let(binding) = branch.cond.as_ref() else {
        return false;
    };
    if !matches!(binding.pat.as_ref(), syn::Pat::TupleStruct(pattern)
        if pattern.path.is_ident("Some") && pattern.elems.len() == 1
            && matches!(pattern.elems.first(), Some(syn::Pat::Ident(name)) if name.ident == "path" && name.by_ref.is_none() && name.mutability.is_none() && name.subpat.is_none()))
        || !matches!(binding.expr.as_ref(), syn::Expr::Reference(reference)
            if reference.mutability.is_none()
                && matches!(reference.expr.as_ref(), syn::Expr::Field(field)
                    if matches!(&field.member, syn::Member::Named(name) if name == "workload_loader_path")
                        && matches!(field.base.as_ref(), syn::Expr::Path(base) if base.path.is_ident("self"))))
    {
        return false;
    }
    matches!(&branch.then_branch.stmts[0], syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_))
        if call.method == "env" && call.args.len() == 2
            && matches!(call.receiver.as_ref(), syn::Expr::Path(receiver) if receiver.path.is_ident("command"))
            && matches!(call.args.first(), Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(key), .. })) if key.value() == "LD_LIBRARY_PATH")
            && matches!(call.args.last(), Some(syn::Expr::Path(value)) if value.path.is_ident("path")))
}

/// Match the complete capability-consuming branch, not a variable-name allowlist.
fn owned_compiler_protocol_branch(previous: &syn::Stmt, statement: &syn::Stmt) -> bool {
    fn path(expression: &syn::Expr, name: &str) -> bool {
        matches!(expression, syn::Expr::Path(value) if value.path.is_ident(name))
    }
    fn field(expression: &syn::Expr, name: &str) -> bool {
        matches!(expression, syn::Expr::Field(value) if path(&value.base, "self") && matches!(&value.member, syn::Member::Named(member) if member == name))
    }
    fn literal(expression: &syn::Expr, expected: &str) -> bool {
        matches!(expression, syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(value), .. }) if value.value() == expected)
    }
    let syn::Stmt::Expr(syn::Expr::MethodCall(sanitize), Some(_)) = previous else {
        return false;
    };
    if sanitize.method != "apply_environment"
        || sanitize.turbofish.is_some()
        || !path(&sanitize.receiver, "self")
        || sanitize.args.len() != 1
        || !matches!(sanitize.args.first(), Some(syn::Expr::Reference(reference)) if reference.mutability.is_some() && path(&reference.expr, "command"))
    {
        return false;
    }
    let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else {
        return false;
    };
    if branch.else_branch.is_some()
        || branch.attrs.len() != 1
        || !branch.attrs[0].path().is_ident("cfg")
        || !branch.attrs[0]
            .parse_args::<syn::Path>()
            .is_ok_and(|condition| condition.is_ident("unix"))
    {
        return false;
    }
    let syn::Expr::Let(binding) = branch.cond.as_ref() else {
        return false;
    };
    if !matches!(binding.pat.as_ref(), syn::Pat::TupleStruct(pattern) if pattern.path.is_ident("Some") && pattern.elems.len() == 1 && matches!(pattern.elems.first(), Some(syn::Pat::Ident(owner)) if owner.ident == "owner" && owner.by_ref.is_none() && owner.mutability.is_none()))
        || !matches!(binding.expr.as_ref(), syn::Expr::Reference(reference) if reference.mutability.is_none() && field(&reference.expr, "compiler_owner"))
    {
        return false;
    }
    let [
        syn::Stmt::Local(protocol),
        syn::Stmt::Expr(syn::Expr::MethodCall(setter), Some(_)),
    ] = branch.then_branch.stmts.as_slice()
    else {
        return false;
    };
    if !matches!(&protocol.pat, syn::Pat::Ident(name) if name.ident == "protocol" && name.by_ref.is_none() && name.mutability.is_none())
    {
        return false;
    }
    let Some(initializer) = &protocol.init else {
        return false;
    };
    if initializer.diverge.is_some()
        || !matches!(initializer.expr.as_ref(), syn::Expr::Try(value) if matches!(value.expr.as_ref(), syn::Expr::MethodCall(admit) if admit.method == "admit" && admit.turbofish.is_none() && admit.args.is_empty() && path(&admit.receiver, "owner")))
    {
        return false;
    }
    if setter.method != "env"
        || setter.turbofish.is_some()
        || setter.args.len() != 2
        || !literal(&setter.args[0], "CARGO_MAKEFLAGS")
        || !matches!(&setter.args[1], syn::Expr::MethodCall(value) if value.method == "makeflags" && value.turbofish.is_none() && value.args.is_empty() && path(&value.receiver, "protocol"))
    {
        return false;
    }
    let mut receiver = setter.receiver.as_ref();
    for key in ["CARGO_BUILD_JOBS", "MFLAGS", "MAKEFLAGS"] {
        let syn::Expr::MethodCall(removal) = receiver else {
            return false;
        };
        if removal.method != "env_remove"
            || removal.turbofish.is_some()
            || removal.args.len() != 1
            || !literal(&removal.args[0], key)
        {
            return false;
        }
        receiver = removal.receiver.as_ref();
    }
    path(receiver, "command")
}

fn reviewed_owned_compiler_protocol(relative: &Path, visitor: &RustPolicy) -> bool {
    if visitor.owned_compiler_protocols == 0
        && visitor.compiler_protocol_removals == 0
        && visitor.compiler_protocol_setters == 0
    {
        return true;
    }
    relative == Path::new("tools/memcordon-ci/src/command.rs")
        && visitor.owned_compiler_protocols == 1
        && visitor.compiler_protocol_setters == 1
        && visitor.compiler_protocol_removals == 3
        && visitor.cleared_environments <= 1
        && visitor.cleared_environments == visitor.command_sanitation_clears
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
    if !reviewed_owned_compiler_protocol(relative, &visitor) {
        visitor
            .violations
            .push("owned compiler protocol capability boundary differs".to_owned());
    }
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
        && !reviewed_git_environment(relative)
        && !native_environment::reviewed(
            relative,
            &syntax,
            visitor.subprocess_env_mutations,
            visitor.cleared_environments,
        )
    {
        visitor
            .violations
            .push("subprocess environment mutation is forbidden".to_owned());
    }
    if visitor.pre_exec_calls != 0
        && relative != test_support
        && !native_descriptor::reviewed(relative, &syntax, visitor.pre_exec_calls)
    {
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
        if !reviewed_owned_compiler_protocol(relative, &visitor) {
            visitor
                .violations
                .push("owned compiler protocol capability boundary differs".to_owned());
        }
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
            && !reviewed_git_environment(relative)
            && !native_environment::reviewed(
                relative,
                &syntax,
                visitor.subprocess_env_mutations,
                visitor.cleared_environments,
            )
        {
            visitor
                .violations
                .push("subprocess environment mutation is forbidden".to_owned());
        }
        if visitor.pre_exec_calls != 0
            && relative != test_support
            && !native_descriptor::reviewed(relative, &syntax, visitor.pre_exec_calls)
        {
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
    crate::workflow_definitions::validate_public_source_model(root)?;
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
