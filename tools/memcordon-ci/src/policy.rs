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

pub const MAXIMUM_YAML_BYTES: usize = 1_048_576;
pub const MAXIMUM_YAML_DEPTH: usize = 64;

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

fn stored_token_source() -> String {
    ["${{ secrets.", "CARGO_REGISTRY_TOKEN", " }}"].concat()
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
const VERIFY_PUBLIC_MATRIX: [(&str, &str); 3] = [
    ("linux-x64", "ubuntu-24.04"),
    ("windows-x64", "windows-2025"),
    ("windows-arm64", "windows-11-arm"),
];

const STRESS_MATRIX: [(&str, &str); 5] = [
    ("linux-x64", "ubuntu-24.04"),
    ("macos-arm64", "macos-15"),
    ("macos-x64", "macos-15-intel"),
    ("windows-x64", "windows-2025"),
    ("windows-arm64", "windows-11-arm"),
];
const DEEP_CI_FUZZ_MINIMUM_TIMEOUT_MINUTES: u64 = 45;

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
    if fuzz_timeout < DEEP_CI_FUZZ_MINIMUM_TIMEOUT_MINUTES {
        return Err(failure("deep CI fuzz timeout is below workload minimum"));
    }
    check_runner_matrix(jobs, "stress", &STRESS_MATRIX, "deep CI stress")?;
    Ok(())
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

fn runner_selects_self_hosted(value: &Value) -> bool {
    match value {
        Value::String(runner) => runner == "self-hosted",
        Value::Sequence(runners) => runners
            .iter()
            .any(|runner| runner.as_str() == Some("self-hosted")),
        _ => false,
    }
}

fn certification_steps<'a>(job: &'a Mapping, context: &str) -> Result<&'a Vec<Value>> {
    job.get(key("steps"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure(format!("{context} steps are absent")))
}

fn action_steps<'a>(steps: &'a [Value], action: &str) -> Result<Vec<&'a Mapping>> {
    steps
        .iter()
        .filter_map(|value| {
            let step = value.as_mapping()?;
            (scalar(step, "uses") == Some(action)).then_some(Ok(step))
        })
        .collect()
}

fn step_with_id<'a>(steps: &'a [Value], id: &str, context: &str) -> Result<&'a Mapping> {
    let matches: Vec<&Mapping> = steps
        .iter()
        .filter_map(Value::as_mapping)
        .filter(|step| scalar(step, "id") == Some(id))
        .collect();
    if matches.len() != 1 {
        return Err(failure(format!(
            "{context} must contain exactly one {id} step"
        )));
    }
    Ok(matches[0])
}

fn check_certification_cache(
    steps: &[Value],
    restore_action: &str,
    save_action: &str,
    dependency_key: &str,
    target_key: &str,
    context: &str,
) -> Result<()> {
    const DEPENDENCY_PATHS: &str =
        "~/.cargo/registry/index\n~/.cargo/registry/cache\n~/.cargo/git/db\n";
    const TARGET_PATHS: &str = "target/ci/bootstrap\ntarget/ci/backend\n";
    const LINUX_TARGET_PATHS: &str =
        "target/ci/bootstrap\ntarget/ci/backend\ntarget/ci/sealed-agent\n";
    const WINDOWS_TARGET_PATHS: &str = "target/ci/bootstrap\ntarget/ci/backend\ntarget/ci/windows-sealed\ntarget/ci/windows-sealed-cargo\n";
    let target_paths = if context.contains("linux") {
        LINUX_TARGET_PATHS
    } else if context.contains("windows") {
        WINDOWS_TARGET_PATHS
    } else {
        TARGET_PATHS
    };

    let restores = action_steps(steps, restore_action)?;
    let saves = action_steps(steps, save_action)?;
    if restores.len() != 2 || saves.len() != 2 {
        return Err(failure(format!(
            "{context} must contain two split cache restores and saves"
        )));
    }

    for (id, path, expected_key) in [
        ("certification-deps", DEPENDENCY_PATHS, dependency_key),
        ("certification-target", target_paths, target_key),
    ] {
        let restore = step_with_id(steps, id, context)?;
        exact_mapping_keys(restore, &["id", "uses", "with"], context)?;
        if scalar(restore, "uses") != Some(restore_action) {
            return Err(failure(format!("{context} {id} must restore a cache")));
        }
        let inputs = mapping(
            restore
                .get(key("with"))
                .ok_or_else(|| failure(format!("{context} {id} lacks cache inputs")))?,
            context,
        )?;
        exact_mapping_keys(inputs, &["path", "key"], context)?;
        if scalar(inputs, "path") != Some(path) || scalar(inputs, "key") != Some(expected_key) {
            return Err(failure(format!("{context} {id} cache inputs differ")));
        }

        let expected_condition = format!("always() && steps.{id}.outputs.cache-hit != 'true'");
        let expected_primary_key = format!("${{{{ steps.{id}.outputs.cache-primary-key }}}}");
        let matching_saves: Vec<&Mapping> = saves
            .iter()
            .copied()
            .filter(|step| scalar(step, "if") == Some(expected_condition.as_str()))
            .collect();
        if matching_saves.len() != 1 {
            return Err(failure(format!(
                "{context} must contain exactly one save for {id}"
            )));
        }
        let save = matching_saves[0];
        exact_mapping_keys(save, &["if", "uses", "with"], context)?;
        let inputs = mapping(
            save.get(key("with"))
                .ok_or_else(|| failure(format!("{context} {id} save lacks inputs")))?,
            context,
        )?;
        exact_mapping_keys(inputs, &["path", "key"], context)?;
        if scalar(inputs, "path") != Some(path)
            || scalar(inputs, "key") != Some(expected_primary_key.as_str())
        {
            return Err(failure(format!("{context} {id} cache save inputs differ")));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_certification_job(
    job: &Mapping,
    expected_runner: &str,
    timeout_minutes: u64,
    checkout_count: usize,
    dependency_key: &str,
    target_key: &str,
    suite_command: &str,
    artifact_name: &str,
    artifact_path: &str,
    context: &str,
) -> Result<()> {
    if scalar(job, "runs-on") != Some(expected_runner) {
        return Err(failure(format!(
            "{context} must run on exact label {expected_runner}"
        )));
    }
    if job.get(key("timeout-minutes")).and_then(Value::as_u64) != Some(timeout_minutes) {
        return Err(failure(format!("{context} timeout differs")));
    }
    let steps = certification_steps(job, context)?;
    let windows = context.contains("windows");
    let release_windows = context == "release windows-certification job";
    if steps.len() != checkout_count + 7 + usize::from(windows) * 2 + usize::from(release_windows) {
        return Err(failure(format!("{context} step count differs")));
    }

    let checkout_action = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1";
    let restore_action = "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
    let save_action = "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
    let upload_action = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
    let download_action = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";

    let checkouts = action_steps(steps, checkout_action)?;
    if checkouts.len() != checkout_count {
        return Err(failure(format!("{context} checkout count differs")));
    }
    for checkout in checkouts {
        let inputs = mapping(
            checkout
                .get(key("with"))
                .ok_or_else(|| failure(format!("{context} checkout lacks inputs")))?,
            context,
        )?;
        if inputs
            .get(key("persist-credentials"))
            .and_then(Value::as_bool)
            != Some(false)
        {
            return Err(failure(format!(
                "{context} checkout must not persist credentials"
            )));
        }
    }
    let downloads = action_steps(steps, download_action)?;
    if release_windows {
        if downloads.len() != 1 {
            return Err(failure(format!(
                "{context} must download exactly one native archive"
            )));
        }
        let inputs = mapping(
            downloads[0]
                .get(key("with"))
                .ok_or_else(|| failure(format!("{context} native download lacks inputs")))?,
            context,
        )?;
        exact_mapping_keys(inputs, &["name", "path"], context)?;
        if scalar(inputs, "name") != Some("release-native-windows-${{ matrix.id }}")
            || scalar(inputs, "path") != Some("target/ci/release-input")
        {
            return Err(failure(format!(
                "{context} native archive download differs"
            )));
        }
    } else if !downloads.is_empty() {
        return Err(failure(format!(
            "{context} must not download a native archive"
        )));
    }

    let run_commands: Vec<&str> = steps
        .iter()
        .filter_map(Value::as_mapping)
        .filter_map(|step| scalar(step, "run"))
        .collect();
    let mut expected_run_commands = vec![
        "rustup toolchain install 1.97.1 --profile minimal",
        suite_command,
    ];
    if windows {
        expected_run_commands.extend([
            "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap --package memcordon-ci -- suite windows-provider-lifecycle",
            "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap --package memcordon-ci -- suite windows-package-channel",
        ]);
    }
    if run_commands != expected_run_commands {
        return Err(failure(format!("{context} run commands differ")));
    }

    check_certification_cache(
        steps,
        restore_action,
        save_action,
        dependency_key,
        target_key,
        context,
    )?;

    let uploads = action_steps(steps, upload_action)?;
    if uploads.len() != 1 {
        return Err(failure(format!("{context} artifact upload count differs")));
    }
    if (artifact_name.contains("linux") || artifact_name.contains("windows"))
        && scalar(uploads[0], "if") != Some("always()")
    {
        return Err(failure(format!(
            "{context} must retain sealed certification diagnostics under always()"
        )));
    }
    let inputs = mapping(
        uploads[0]
            .get(key("with"))
            .ok_or_else(|| failure(format!("{context} artifact lacks inputs")))?,
        context,
    )?;
    let is_linux_artifact = artifact_name.contains("linux");
    let expected_input_keys: &[&str] = if is_linux_artifact {
        &[
            "name",
            "path",
            "if-no-files-found",
            "retention-days",
            "compression-level",
            "include-hidden-files",
        ]
    } else {
        &[
            "name",
            "path",
            "if-no-files-found",
            "retention-days",
            "compression-level",
        ]
    };
    exact_mapping_keys(inputs, expected_input_keys, context)?;
    if scalar(inputs, "name") != Some(artifact_name)
        || scalar(inputs, "path") != Some(artifact_path)
        || scalar(inputs, "if-no-files-found") != Some("error")
        || inputs.get(key("retention-days")).and_then(Value::as_u64) != Some(14)
        || inputs.get(key("compression-level")).and_then(Value::as_u64) != Some(0)
        || (is_linux_artifact
            && inputs
                .get(key("include-hidden-files"))
                .and_then(Value::as_bool)
                != Some(true))
    {
        return Err(failure(format!("{context} artifact inputs differ")));
    }
    Ok(())
}

fn check_backend_certification_structure(workflow: &Mapping, jobs: &Mapping) -> Result<()> {
    check_push_and_dispatch_events(workflow, "backend certification")?;
    check_top_level_permissions(workflow)?;
    let concurrency = mapping(
        workflow
            .get(key("concurrency"))
            .ok_or_else(|| failure("backend certification lacks concurrency"))?,
        "backend certification concurrency",
    )?;
    exact_mapping_keys(
        concurrency,
        &["group", "cancel-in-progress"],
        "backend certification concurrency",
    )?;
    if scalar(concurrency, "group") != Some("backend-certification-${{ github.ref }}")
        || concurrency
            .get(key("cancel-in-progress"))
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(failure("backend certification concurrency differs"));
    }
    exact_mapping_keys(
        jobs,
        &[
            "linux",
            "windows-loader-production",
            "windows-provider-lifecycle",
            "windows-package-channel",
            "windows-loader-lab",
        ],
        "backend certification jobs",
    )?;

    let linux_dependency_key = "cargo-deps-backend-certification-v2-${{ runner.os }}-${{ runner.arch }}-1.97.1-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/**/Cargo.toml', 'tools/**/Cargo.toml', 'fuzz/Cargo.toml', 'fuzz/Cargo.lock', 'rust-toolchain.toml') }}";
    let linux_target_key = "cargo-target-backend-certification-v2-${{ runner.os }}-${{ runner.arch }}-1.97.1-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/**', 'tools/**', 'fuzz/**', 'ci/**', 'docs/**', 'spec/**', 'packaging/**', 'rust-toolchain.toml', '.github/workflows/backend-certification.yml', '.github/workflows/release.yml') }}";
    let linux = mapping(
        jobs.get(key("linux"))
            .ok_or_else(|| failure("backend certification linux job is absent"))?,
        "backend certification linux job",
    )?;
    exact_mapping_keys(
        linux,
        &["name", "runs-on", "timeout-minutes", "steps"],
        "backend certification linux job",
    )?;
    check_certification_job(
        linux,
        "ubuntu-24.04",
        45,
        1,
        linux_dependency_key,
        linux_target_key,
        "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap --package memcordon-ci -- suite backend-linux-sealed-v2",
        "backend-linux-sealed-v2",
        "target/ci/reports/linux-sealed-v2",
        "backend certification linux job",
    )?;

    for job_name in [
        "windows-loader-production",
        "windows-provider-lifecycle",
        "windows-package-channel",
        "windows-loader-lab",
    ] {
        check_runner_matrix(
            jobs,
            job_name,
            &[("x64", "windows-2025"), ("arm64", "windows-11-arm")],
            job_name,
        )?;
    }
    for (job_name, required_dependency) in [
        ("windows-provider-lifecycle", "windows-loader-production"),
        ("windows-package-channel", "windows-provider-lifecycle"),
        ("windows-loader-lab", "windows-loader-production"),
    ] {
        let job = mapping(
            jobs.get(key(job_name))
                .ok_or_else(|| failure(format!("{job_name} job is absent")))?,
            job_name,
        )?;
        if scalar(job, "needs") != Some(required_dependency) {
            return Err(failure(format!(
                "{job_name} does not depend on {required_dependency}"
            )));
        }
    }
    let lab = mapping(
        jobs.get(key("windows-loader-lab"))
            .ok_or_else(|| failure("windows-loader-lab job is absent"))?,
        "windows-loader-lab",
    )?;
    if scalar(lab, "if") != Some("always() && github.event_name == 'workflow_dispatch'") {
        return Err(failure(
            "Windows loader lab must remain dispatch-only and run after a failed production gate",
        ));
    }

    for contract in [
        SplitWindowsJobContract {
            name: "windows-loader-production",
            suite: concat!(
                "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap ",
                "--package memcordon-ci -- suite windows-loader-production"
            ),
            artifact_name: "windows-loader-production-${{ matrix.id }}",
            artifact_path: "target/ci/reports/windows-sealed-v2/loader-production",
            dependency: None,
            condition: None,
            downloads: &[],
            dependency_cache_id: "certification-deps",
            target_cache_id: "certification-target",
            target_cache_path: "target/ci/bootstrap\ntarget/ci/backend\ntarget/ci/windows-sealed\ntarget/ci/windows-sealed-cargo\n",
            checkout_count: 1,
            timeout_minutes: 45,
        },
        SplitWindowsJobContract {
            name: "windows-provider-lifecycle",
            suite: concat!(
                "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap ",
                "--package memcordon-ci -- suite windows-provider-lifecycle"
            ),
            artifact_name: "windows-provider-lifecycle-${{ matrix.id }}",
            artifact_path: "target/ci/reports/windows-sealed-v2",
            dependency: Some("windows-loader-production"),
            condition: None,
            downloads: &[(
                ("windows-loader-production-${{ matrix.id }}"),
                "target/ci/reports/windows-sealed-v2/loader-production",
            )],
            dependency_cache_id: "lifecycle-deps",
            target_cache_id: "lifecycle-target",
            target_cache_path: "target/ci/bootstrap\ntarget/ci/backend\ntarget/ci/windows-sealed\n",
            checkout_count: 1,
            timeout_minutes: 45,
        },
        SplitWindowsJobContract {
            name: "windows-package-channel",
            suite: concat!(
                "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap ",
                "--package memcordon-ci -- suite windows-package-channel"
            ),
            artifact_name: "windows-package-channel-${{ matrix.id }}",
            artifact_path: "target/ci/windows-sealed-cargo",
            dependency: Some("windows-provider-lifecycle"),
            condition: None,
            downloads: &[(
                "windows-provider-lifecycle-${{ matrix.id }}",
                "target/ci/reports/windows-sealed-v2",
            )],
            dependency_cache_id: "package-deps",
            target_cache_id: "package-target",
            target_cache_path: "target/ci/bootstrap\ntarget/ci/windows-sealed\ntarget/ci/windows-sealed-cargo\n",
            checkout_count: 1,
            timeout_minutes: 45,
        },
        SplitWindowsJobContract {
            name: "windows-loader-lab",
            suite: concat!(
                "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap ",
                "--package memcordon-ci -- suite windows-loader-lab"
            ),
            artifact_name: "windows-loader-lab-${{ matrix.id }}",
            artifact_path: "target/ci/reports/windows-sealed-v2/loader-lab",
            dependency: Some("windows-loader-production"),
            condition: Some("always() && github.event_name == 'workflow_dispatch'"),
            downloads: &[(
                ("windows-loader-production-${{ matrix.id }}"),
                "target/ci/reports/windows-sealed-v2/loader-production",
            )],
            dependency_cache_id: "lab-deps",
            target_cache_id: "lab-target",
            target_cache_path: "target/ci/bootstrap\ntarget/ci/windows-sealed\ntarget/ci/windows-loader-lab\n",
            checkout_count: 1,
            timeout_minutes: 45,
        },
    ] {
        let job = mapping(
            jobs.get(key(contract.name))
                .ok_or_else(|| failure(format!("{} job is absent", contract.name)))?,
            contract.name,
        )?;
        check_split_windows_job(job, contract)?;
    }
    Ok(())
}

struct SplitWindowsJobContract<'a> {
    name: &'a str,
    suite: &'a str,
    artifact_name: &'a str,
    artifact_path: &'a str,
    dependency: Option<&'a str>,
    condition: Option<&'a str>,
    downloads: &'a [(&'a str, &'a str)],
    dependency_cache_id: &'a str,
    target_cache_id: &'a str,
    target_cache_path: &'a str,
    checkout_count: usize,
    timeout_minutes: u64,
}

fn check_split_windows_job(job: &Mapping, contract: SplitWindowsJobContract<'_>) -> Result<()> {
    let context = contract.name;
    let expected_keys: &[&str] = match (contract.dependency, contract.condition) {
        (Some(_), Some(_)) => &[
            "name",
            "if",
            "needs",
            "strategy",
            "runs-on",
            "timeout-minutes",
            "steps",
        ],
        (Some(_), None) => &[
            "name",
            "needs",
            "strategy",
            "runs-on",
            "timeout-minutes",
            "steps",
        ],
        (None, None) => &["name", "strategy", "runs-on", "timeout-minutes", "steps"],
        (None, Some(_)) => return Err(failure(format!("{context} has an invalid contract"))),
    };
    exact_mapping_keys(job, expected_keys, context)?;
    if scalar(job, "needs") != contract.dependency
        || scalar(job, "if") != contract.condition
        || job.get(key("timeout-minutes")).and_then(Value::as_u64) != Some(contract.timeout_minutes)
    {
        return Err(failure(format!(
            "{context} dependency, condition, or timeout differs"
        )));
    }

    let steps = certification_steps(job, context)?;
    let checkout_action = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1";
    let restore_action = "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
    let save_action = "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
    let upload_action = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
    let download_action = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";
    if action_steps(steps, checkout_action)?.len() != contract.checkout_count
        || action_steps(steps, restore_action)?.len() != 2
        || action_steps(steps, save_action)?.len() != 2
        || action_steps(steps, upload_action)?.len() != 1
    {
        return Err(failure(format!("{context} action cardinality differs")));
    }
    const DEPENDENCY_CACHE_PATH: &str =
        "~/.cargo/registry/index\n~/.cargo/registry/cache\n~/.cargo/git/db\n";
    for (id, expected_path) in [
        (contract.dependency_cache_id, DEPENDENCY_CACHE_PATH),
        (contract.target_cache_id, contract.target_cache_path),
    ] {
        let restore = step_with_id(steps, id, context)?;
        let inputs = restore
            .get(key("with"))
            .and_then(Value::as_mapping)
            .ok_or_else(|| failure(format!("{context} {id} restore inputs are absent")))?;
        if scalar(restore, "uses") != Some(restore_action)
            || scalar(inputs, "path") != Some(expected_path)
            || scalar(inputs, "key").is_none()
        {
            return Err(failure(format!("{context} {id} restore differs")));
        }
        let expected_condition = format!("always() && steps.{id}.outputs.cache-hit != 'true'");
        let expected_key = format!("${{{{ steps.{id}.outputs.cache-primary-key }}}}");
        let matching_saves: Vec<&Mapping> = action_steps(steps, save_action)?
            .into_iter()
            .filter(|save| scalar(save, "if") == Some(expected_condition.as_str()))
            .collect();
        if matching_saves.len() != 1 {
            return Err(failure(format!("{context} {id} cache save differs")));
        }
        let save_inputs = matching_saves[0]
            .get(key("with"))
            .and_then(Value::as_mapping)
            .ok_or_else(|| failure(format!("{context} {id} save inputs are absent")))?;
        if scalar(save_inputs, "path") != Some(expected_path)
            || scalar(save_inputs, "key") != Some(expected_key.as_str())
        {
            return Err(failure(format!("{context} {id} save inputs differ")));
        }
    }
    for checkout in action_steps(steps, checkout_action)? {
        if checkout
            .get(key("with"))
            .and_then(Value::as_mapping)
            .and_then(|inputs| inputs.get(key("persist-credentials")))
            .and_then(Value::as_bool)
            != Some(false)
        {
            return Err(failure(format!(
                "{context} checkout must not persist credentials"
            )));
        }
    }

    let expected_runs = [
        "rustup toolchain install 1.97.1 --profile minimal",
        contract.suite,
    ];
    let actual_runs: Vec<&str> = steps
        .iter()
        .filter_map(Value::as_mapping)
        .filter_map(|step| scalar(step, "run"))
        .collect();
    if actual_runs != expected_runs {
        return Err(failure(format!("{context} run commands differ")));
    }

    let downloads = action_steps(steps, download_action)?;
    if downloads.len() != contract.downloads.len() {
        return Err(failure(format!("{context} download cardinality differs")));
    }
    for ((name, path), download) in contract.downloads.iter().zip(downloads) {
        let inputs = download
            .get(key("with"))
            .and_then(Value::as_mapping)
            .ok_or_else(|| failure(format!("{context} download inputs are absent")))?;
        exact_mapping_keys(inputs, &["name", "path"], context)?;
        if scalar(inputs, "name") != Some(*name) || scalar(inputs, "path") != Some(*path) {
            return Err(failure(format!("{context} download inputs differ")));
        }
    }

    for save in action_steps(steps, save_action)? {
        let condition = scalar(save, "if")
            .ok_or_else(|| failure(format!("{context} cache save condition is absent")))?;
        if !condition.starts_with("always() && steps.")
            || !condition.ends_with(".outputs.cache-hit != 'true'")
        {
            return Err(failure(format!("{context} cache save is not failure-safe")));
        }
    }

    let upload = action_steps(steps, upload_action)?[0];
    if scalar(upload, "if") != Some("always()") {
        return Err(failure(format!(
            "{context} artifact upload must run under always()"
        )));
    }
    let inputs = upload
        .get(key("with"))
        .and_then(Value::as_mapping)
        .ok_or_else(|| failure(format!("{context} artifact inputs are absent")))?;
    exact_mapping_keys(
        inputs,
        &[
            "name",
            "path",
            "if-no-files-found",
            "retention-days",
            "compression-level",
        ],
        context,
    )?;
    if scalar(inputs, "name") != Some(contract.artifact_name)
        || scalar(inputs, "path") != Some(contract.artifact_path)
        || scalar(inputs, "if-no-files-found") != Some("error")
        || inputs.get(key("retention-days")).and_then(Value::as_u64) != Some(14)
        || inputs.get(key("compression-level")).and_then(Value::as_u64) != Some(0)
    {
        return Err(failure(format!("{context} artifact inputs differ")));
    }
    Ok(())
}

fn named_steps<'a>(jobs: &'a Mapping, job_name: &str) -> Result<BTreeMap<&'a str, &'a Mapping>> {
    let job = mapping(
        jobs.get(key(job_name))
            .ok_or_else(|| failure(format!("{job_name} job is absent")))?,
        job_name,
    )?;
    let steps = job
        .get(key("steps"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure(format!("{job_name} steps are absent")))?;
    let mut named = BTreeMap::new();
    for step in steps {
        let step = mapping(step, "release step")?;
        if let Some(name) = scalar(step, "name")
            && named.insert(name, step).is_some()
        {
            return Err(failure(format!("duplicate release step name: {name}")));
        }
    }
    Ok(named)
}

fn require_publication_step(
    steps: &BTreeMap<&str, &Mapping>,
    name: &str,
    condition: Option<&str>,
    source: &str,
    cargo_home: &str,
) -> Result<()> {
    let step = steps
        .get(name)
        .ok_or_else(|| failure(format!("release publication step is absent: {name}")))?;
    let expected_keys = if condition.is_some() {
        &["name", "if", "env", "run"][..]
    } else {
        &["name", "env", "run"][..]
    };
    exact_mapping_keys(step, expected_keys, name)?;
    if scalar(step, "if") != condition
        || step.contains_key(key("continue-on-error"))
        || scalar(step, "run")
            != Some("target/ci/publish-bootstrap/debug/memcordon-ci release publish-next")
    {
        return Err(failure(format!(
            "release publication step shape differs: {name}"
        )));
    }
    let environment = mapping(
        step.get(key("env"))
            .ok_or_else(|| failure(format!("publication step has no credential: {name}")))?,
        "publication environment",
    )?;
    exact_mapping_keys(
        environment,
        &["CARGO_HOME", "CARGO_REGISTRIES_CRATES_IO_TOKEN"],
        name,
    )?;
    if scalar(environment, "CARGO_REGISTRIES_CRATES_IO_TOKEN") != Some(source)
        || scalar(environment, "CARGO_HOME") != Some(cargo_home)
    {
        return Err(failure(format!(
            "publication credential source differs: {name}"
        )));
    }
    Ok(())
}

fn require_oidc_step(
    steps: &BTreeMap<&str, &Mapping>,
    name: &str,
    condition: Option<&str>,
    id: &str,
    auth_action: &str,
) -> Result<()> {
    let step = steps
        .get(name)
        .ok_or_else(|| failure(format!("crates.io OIDC step is absent: {name}")))?;
    let expected_keys = if condition.is_some() {
        &["name", "if", "id", "uses"][..]
    } else {
        &["name", "id", "uses"][..]
    };
    exact_mapping_keys(step, expected_keys, name)?;
    if scalar(step, "if") != condition
        || scalar(step, "id") != Some(id)
        || scalar(step, "uses") != Some(auth_action)
        || step.contains_key(key("continue-on-error"))
    {
        return Err(failure(format!(
            "crates.io OIDC step shape differs: {name}"
        )));
    }
    Ok(())
}

fn require_github_step(steps: &BTreeMap<&str, &Mapping>, name: &str, run: &str) -> Result<()> {
    let step = steps
        .get(name)
        .ok_or_else(|| failure(format!("GitHub credential step is absent: {name}")))?;
    exact_mapping_keys(step, &["name", "env", "run"], name)?;
    if scalar(step, "run") != Some(run) {
        return Err(failure(format!("GitHub credential step differs: {name}")));
    }
    let environment = mapping(
        step.get(key("env"))
            .ok_or_else(|| failure(format!("GitHub credential step has no env: {name}")))?,
        "GitHub credential environment",
    )?;
    exact_mapping_keys(environment, &["GITHUB_TOKEN"], name)?;
    if scalar(environment, "GITHUB_TOKEN") != Some("${{ github.token }}") {
        return Err(failure(format!("GitHub credential source differs: {name}")));
    }
    Ok(())
}

fn check_release_credentials(
    jobs: &Mapping,
    release: &config::Release,
    auth_action: &str,
) -> Result<()> {
    let steps = named_steps(jobs, "publish")?;
    let publish_job = mapping(
        jobs.get(key("publish"))
            .ok_or_else(|| failure("publish job is absent"))?,
        "publish job",
    )?;
    let ordered_names: Vec<Option<&str>> = publish_job
        .get(key("steps"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure("publish steps are absent"))?
        .iter()
        .map(|step| step.as_mapping().and_then(|step| scalar(step, "name")))
        .collect();
    require_github_step(
        &steps,
        "Stage GitHub draft and assets",
        "rustup run 1.97.1 cargo run --locked --target-dir target/ci/publish-bootstrap --package memcordon-ci -- release stage-github",
    )?;
    require_github_step(
        &steps,
        "Finalize GitHub release",
        "rustup run 1.97.1 cargo run --locked --target-dir target/ci/publish-bootstrap --package memcordon-ci -- release finalize-github",
    )?;
    let mut previous_publish_position = None;
    for slot in 1..=release.publish_packages.len() {
        let acquire_name = format!("Acquire crates.io token for publication slot {slot}");
        let publish_name = format!("Publish next crate in slot {slot}");
        let acquire_position = ordered_names
            .iter()
            .position(|name| *name == Some(acquire_name.as_str()))
            .ok_or_else(|| failure(format!("crates.io OIDC step is absent: {acquire_name}")))?;
        if ordered_names.get(acquire_position + 1).copied() != Some(Some(publish_name.as_str())) {
            return Err(failure(format!(
                "crates.io publication slot {slot} is not an adjacent acquire/publish pair"
            )));
        }
        if previous_publish_position.is_some_and(|position| acquire_position <= position) {
            return Err(failure("crates.io publication slots are out of order"));
        }
        previous_publish_position = Some(acquire_position + 1);
        let action_id = format!("crates_auth_{slot}");
        require_oidc_step(&steps, &acquire_name, None, &action_id, auth_action)?;
        require_publication_step(
            &steps,
            &publish_name,
            None,
            &format!("${{{{ steps.{action_id}.outputs.token }}}}"),
            &format!("target/ci/cargo-publish-home/slot-{slot}"),
        )?;
    }
    let oidc_count = steps
        .values()
        .filter(|step| scalar(step, "uses") == Some(auth_action))
        .count();
    if oidc_count != release.publish_packages.len() {
        return Err(failure("crates.io OIDC action slot count differs"));
    }
    let github_credential_steps = ["Stage GitHub draft and assets", "Finalize GitHub release"];
    if steps
        .values()
        .filter(|step| step.contains_key(key("env")))
        .count()
        != release.publish_packages.len() + github_credential_steps.len()
    {
        return Err(failure(
            "publish job credential mapping count differs from profile",
        ));
    }
    Ok(())
}

fn check_release_structure(
    workflow: &Mapping,
    jobs: &Mapping,
    release: &config::Release,
    toolchains: &config::Toolchains,
    auth_action: &str,
) -> Result<()> {
    let events = mapping(
        workflow
            .get(key("on"))
            .ok_or_else(|| failure("release workflow has no event map"))?,
        "release events",
    )?;
    exact_mapping_keys(events, &["push", "workflow_dispatch"], "release events")?;
    let push = mapping(
        events
            .get(key("push"))
            .ok_or_else(|| failure("release lacks push"))?,
        "release push",
    )?;
    exact_mapping_keys(push, &["tags"], "release push")?;
    exact_string_sequence(
        push.get(key("tags"))
            .ok_or_else(|| failure("release push lacks tags"))?,
        &["[0-9]+.[0-9]+.[0-9]+*"],
        "release tags",
    )?;
    let dispatch = mapping(
        events
            .get(key("workflow_dispatch"))
            .ok_or_else(|| failure("release lacks workflow_dispatch"))?,
        "release dispatch",
    )?;
    let inputs = mapping(
        dispatch
            .get(key("inputs"))
            .ok_or_else(|| failure("release dispatch lacks inputs"))?,
        "release inputs",
    )?;
    exact_mapping_keys(inputs, &["tag"], "release inputs")?;
    let tag = mapping(
        inputs
            .get(key("tag"))
            .ok_or_else(|| failure("release input tag is absent"))?,
        "release tag input",
    )?;
    if tag.get(key("required")).and_then(Value::as_bool) != Some(true)
        || scalar(tag, "type") != Some("string")
    {
        return Err(failure("release tag input must be a required string"));
    }
    check_top_level_permissions(workflow)?;
    let concurrency = mapping(
        workflow
            .get(key("concurrency"))
            .ok_or_else(|| failure("release lacks concurrency"))?,
        "release concurrency",
    )?;
    if scalar(concurrency, "group") != Some("memcordon-release")
        || concurrency
            .get(key("cancel-in-progress"))
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(failure("release publication must be globally serialized"));
    }
    config::validate_release_configuration_identity(release)?;
    check_runner_matrix(jobs, "native", &NATIVE_MATRIX, "release native")?;
    let preflight = mapping(
        jobs.get(key("preflight"))
            .ok_or_else(|| failure("release preflight job is absent"))?,
        "release preflight job",
    )?;
    let preflight_steps = preflight
        .get(key("steps"))
        .and_then(Value::as_sequence)
        .ok_or_else(|| failure("release preflight steps are absent"))?;
    let actual_run_commands: Vec<&str> = preflight_steps
        .iter()
        .filter_map(Value::as_mapping)
        .filter_map(|step| scalar(step, "run"))
        .collect();
    let expected_run_commands = [
        format!(
            "rustup toolchain install {} --profile minimal --component clippy --component rustfmt",
            toolchains.stable
        ),
        format!(
            "rustup toolchain install {} --profile minimal",
            toolchains.msrv
        ),
        format!(
            "rustup run {} cargo run --locked --target-dir target/ci/bootstrap --package memcordon-ci -- suite release-preflight",
            toolchains.stable
        ),
    ];
    if actual_run_commands.len() != expected_run_commands.len()
        || !actual_run_commands
            .iter()
            .zip(&expected_run_commands)
            .all(|(actual, expected)| *actual == expected)
    {
        return Err(failure("release preflight toolchain provisioning differs"));
    }
    let preflight_target =
        step_with_id(preflight_steps, "preflight-target", "release preflight job")?;
    let preflight_target_inputs = mapping(
        preflight_target
            .get(key("with"))
            .ok_or_else(|| failure("release preflight target cache inputs are absent"))?,
        "release preflight target cache inputs",
    )?;
    let expected_preflight_target_key = format!(
        "cargo-target-release-v3-preflight-{}-msrv-{}-${{{{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/**', 'tools/**', 'fuzz/**', 'ci/**', 'docs/**', 'spec/**', 'packaging/**', 'README.md', 'LICENSE', 'CHANGELOG.md', 'RELEASING.md', 'rust-toolchain.toml', '.github/workflows/backend-certification.yml', '.github/workflows/release.yml') }}}}",
        toolchains.stable, toolchains.msrv
    );
    if scalar(preflight_target_inputs, "path") != Some("target/ci")
        || scalar(preflight_target_inputs, "key") != Some(expected_preflight_target_key.as_str())
    {
        return Err(failure("release preflight target cache identity differs"));
    }
    let linux_dependency_key = "cargo-deps-release-certification-v2-${{ runner.os }}-${{ runner.arch }}-1.97.1-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/**/Cargo.toml', 'tools/**/Cargo.toml', 'fuzz/Cargo.toml', 'fuzz/Cargo.lock', 'rust-toolchain.toml') }}";
    let linux_target_key = "cargo-target-release-certification-v2-${{ runner.os }}-${{ runner.arch }}-1.97.1-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/**', 'tools/**', 'fuzz/**', 'ci/**', 'docs/**', 'spec/**', 'packaging/**', 'rust-toolchain.toml', '.github/workflows/backend-certification.yml', '.github/workflows/release.yml') }}";
    let linux_job_name = "linux-certification";
    let linux_job = mapping(
        jobs.get(key(linux_job_name))
            .ok_or_else(|| failure(format!("release {linux_job_name} job is absent")))?,
        linux_job_name,
    )?;
    let linux_context = format!("release {linux_job_name} job");
    exact_mapping_keys(
        linux_job,
        &["name", "needs", "runs-on", "timeout-minutes", "steps"],
        &linux_context,
    )?;
    if scalar(linux_job, "needs") != Some("preflight") {
        return Err(failure(format!(
            "release {linux_job_name} must depend on preflight"
        )));
    }
    check_certification_job(
        linux_job,
        "ubuntu-24.04",
        75,
        2,
        linux_dependency_key,
        linux_target_key,
        "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap --package memcordon-ci -- suite backend-linux-sealed-v2",
        "release-certification-linux",
        "target/ci/reports/linux-sealed-v2",
        &linux_context,
    )?;
    for job_name in [
        "windows-loader-production",
        "windows-provider-lifecycle",
        "windows-package-channel",
    ] {
        check_runner_matrix(
            jobs,
            job_name,
            &[("x64", "windows-2025"), ("arm64", "windows-11-arm")],
            job_name,
        )?;
    }
    for contract in [
        SplitWindowsJobContract {
            name: "windows-loader-production",
            suite: "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap --package memcordon-ci -- suite windows-loader-production",
            artifact_name: "release-windows-loader-production-${{ matrix.id }}",
            artifact_path: "target/ci/reports/windows-sealed-v2/loader-production",
            dependency: Some("native"),
            condition: None,
            downloads: &[(
                "release-native-windows-${{ matrix.id }}",
                "target/ci/release-input",
            )],
            dependency_cache_id: "production-deps",
            target_cache_id: "production-target",
            target_cache_path: "target/ci/bootstrap\ntarget/ci/backend\ntarget/ci/windows-sealed\n",
            checkout_count: 2,
            timeout_minutes: 75,
        },
        SplitWindowsJobContract {
            name: "windows-provider-lifecycle",
            suite: "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap --package memcordon-ci -- suite windows-provider-lifecycle",
            artifact_name: "release-windows-provider-lifecycle-${{ matrix.id }}",
            artifact_path: "target/ci/reports/windows-sealed-v2/provider-lifecycle",
            dependency: Some("windows-loader-production"),
            condition: None,
            downloads: &[
                (
                    "release-native-windows-${{ matrix.id }}",
                    "target/ci/release-input",
                ),
                (
                    "release-windows-loader-production-${{ matrix.id }}",
                    "target/ci/reports/windows-sealed-v2/loader-production",
                ),
            ],
            dependency_cache_id: "lifecycle-deps",
            target_cache_id: "lifecycle-target",
            target_cache_path: "target/ci/bootstrap\ntarget/ci/backend\ntarget/ci/windows-sealed\n",
            checkout_count: 2,
            timeout_minutes: 75,
        },
        SplitWindowsJobContract {
            name: "windows-package-channel",
            suite: "rustup run 1.97.1 cargo run --locked --target-dir target/ci/bootstrap --package memcordon-ci -- suite windows-package-channel",
            artifact_name: "release-windows-package-channel-${{ matrix.id }}",
            artifact_path: "target/ci/windows-sealed-cargo",
            dependency: Some("windows-provider-lifecycle"),
            condition: None,
            downloads: &[
                (
                    "release-native-windows-${{ matrix.id }}",
                    "target/ci/release-input",
                ),
                (
                    "release-windows-provider-lifecycle-${{ matrix.id }}",
                    "target/ci/reports/windows-sealed-v2",
                ),
                (
                    "release-windows-loader-production-${{ matrix.id }}",
                    "target/ci/reports/windows-sealed-v2/loader-production",
                ),
            ],
            dependency_cache_id: "package-deps",
            target_cache_id: "package-target",
            target_cache_path: "target/ci/bootstrap\ntarget/ci/windows-sealed\ntarget/ci/windows-sealed-cargo\n",
            checkout_count: 2,
            timeout_minutes: 75,
        },
    ] {
        let job = mapping(
            jobs.get(key(contract.name))
                .ok_or_else(|| failure(format!("release {} job is absent", contract.name)))?,
            contract.name,
        )?;
        check_split_windows_job(job, contract)?;
    }
    let assemble = mapping(
        jobs.get(key("assemble"))
            .ok_or_else(|| failure("release assemble job is absent"))?,
        "assemble job",
    )?;
    exact_string_sequence(
        assemble
            .get(key("needs"))
            .ok_or_else(|| failure("release assemble dependencies are absent"))?,
        &[
            "native",
            "miri",
            "fuzz",
            "linux-certification",
            "windows-package-channel",
            "macos-acceptance",
        ],
        "release assemble dependencies",
    )?;
    let publish = mapping(
        jobs.get(key("publish"))
            .ok_or_else(|| failure("release publish job is absent"))?,
        "publish job",
    )?;
    if scalar(publish, "needs") != Some("assemble") || publish.contains_key(key("environment")) {
        return Err(failure(
            "publish job dependency differs or names a GitHub environment",
        ));
    }
    let permissions = mapping(
        publish
            .get(key("permissions"))
            .ok_or_else(|| failure("publish job permissions are absent"))?,
        "publish permissions",
    )?;
    exact_mapping_keys(
        permissions,
        &["actions", "contents", "id-token"],
        "publish permissions",
    )?;
    if scalar(permissions, "actions") != Some("read")
        || scalar(permissions, "contents") != Some("write")
        || scalar(permissions, "id-token") != Some("write")
    {
        return Err(failure("publish job permissions differ"));
    }
    let verify = mapping(
        jobs.get(key("verify-public"))
            .ok_or_else(|| failure("verify-public job is absent"))?,
        "verify-public job",
    )?;
    check_verify_public_job(jobs, verify, toolchains)?;
    check_release_credentials(jobs, release, auth_action)?;
    Ok(())
}

fn check_verify_public_job(
    jobs: &Mapping,
    job: &Mapping,
    toolchains: &config::Toolchains,
) -> Result<()> {
    let context = "verify-public job";
    exact_mapping_keys(
        job,
        &[
            "name",
            "needs",
            "strategy",
            "runs-on",
            "timeout-minutes",
            "permissions",
            "steps",
        ],
        context,
    )?;
    if scalar(job, "needs") != Some("publish") {
        return Err(failure("verify-public must depend on publish"));
    }
    check_runner_matrix(jobs, "verify-public", &VERIFY_PUBLIC_MATRIX, context)?;
    if job.get(key("timeout-minutes")).and_then(Value::as_u64) != Some(90) {
        return Err(failure("verify-public timeout differs"));
    }
    let permissions = mapping(
        job.get(key("permissions"))
            .ok_or_else(|| failure("verify-public permissions are absent"))?,
        context,
    )?;
    exact_mapping_keys(permissions, &["contents"], context)?;
    if scalar(permissions, "contents") != Some("read") {
        return Err(failure("verify-public permissions differ"));
    }
    let steps = certification_steps(job, context)?;
    if steps.len() != 10 {
        return Err(failure("verify-public step count differs"));
    }
    let checkout = action_steps(
        steps,
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    )?;
    let downloads = action_steps(
        steps,
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    )?;
    if checkout.len() != 2 || downloads.len() != 2 {
        return Err(failure(
            "verify-public checkout or release-bundle download count differs",
        ));
    }
    let run_commands = steps
        .iter()
        .filter_map(Value::as_mapping)
        .filter_map(|step| scalar(step, "run"))
        .collect::<Vec<_>>();
    let expected = [
        format!(
            "rustup toolchain install {} --profile minimal",
            toolchains.stable
        ),
        format!(
            "rustup run {} cargo run --locked --target-dir target/ci/verify-bootstrap --package memcordon-ci -- release verify-public",
            toolchains.stable
        ),
    ];
    if run_commands.len() != expected.len()
        || !run_commands
            .iter()
            .zip(&expected)
            .all(|(actual, expected)| *actual == expected)
    {
        return Err(failure("verify-public command inventory differs"));
    }
    let restore = "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
    let save = "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
    if action_steps(steps, restore)?.len() != 2 || action_steps(steps, save)?.len() != 2 {
        return Err(failure("verify-public split cache inventory differs"));
    }
    for (id, path, key_fragment) in [
        (
            "verify-public-deps",
            "~/.cargo/registry/index\n~/.cargo/registry/cache\n~/.cargo/git/db\n",
            "cargo-deps-release-verify-public-v2-",
        ),
        (
            "verify-public-target",
            "target/ci/verify-bootstrap",
            "cargo-target-release-verify-public-v2-",
        ),
    ] {
        let restore_step = step_with_id(steps, id, context)?;
        if scalar(restore_step, "uses") != Some(restore) {
            return Err(failure(format!(
                "verify-public {id} is not a cache restore"
            )));
        }
        let inputs = mapping(
            restore_step
                .get(key("with"))
                .ok_or_else(|| failure(format!("verify-public {id} inputs are absent")))?,
            context,
        )?;
        if scalar(inputs, "path") != Some(path)
            || !scalar(inputs, "key").is_some_and(|value| {
                value.starts_with(key_fragment)
                    && value.contains("${{ runner.os }}")
                    && value.contains("${{ runner.arch }}")
                    && value.contains("hashFiles(")
            })
        {
            return Err(failure(format!("verify-public {id} cache inputs differ")));
        }
        let condition = format!("always() && steps.{id}.outputs.cache-hit != 'true'");
        let primary_key = format!("${{{{ steps.{id}.outputs.cache-primary-key }}}}");
        let matching_saves = action_steps(steps, save)?
            .into_iter()
            .filter(|step| scalar(step, "if") == Some(condition.as_str()))
            .collect::<Vec<_>>();
        if matching_saves.len() != 1 {
            return Err(failure(format!("verify-public {id} cache save differs")));
        }
        let save_inputs = mapping(
            matching_saves[0]
                .get(key("with"))
                .ok_or_else(|| failure(format!("verify-public {id} save inputs are absent")))?,
            context,
        )?;
        if scalar(save_inputs, "path") != Some(path)
            || scalar(save_inputs, "key") != Some(primary_key.as_str())
        {
            return Err(failure(format!(
                "verify-public {id} cache save inputs differ"
            )));
        }
    }
    Ok(())
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
    let jobs = mapping(
        workflow
            .get(key("jobs"))
            .ok_or_else(|| failure("workflow has no jobs"))?,
        "jobs",
    )?;
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
        if let Some(runner) = job.get(key("runs-on"))
            && runner_selects_self_hosted(runner)
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
                        || text.contains(&stored_token_source())
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
                {
                    return Err(failure(format!("workflow run is not allowlisted: {run:?}")));
                }
            }
            if let Some(value) = uses_value {
                let uses = value
                    .as_str()
                    .ok_or_else(|| failure("workflow uses must be a scalar string"))?;
                if !allowed_actions.contains(uses) {
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
                used_actions.insert(uses.to_owned());
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
                            !trimmed.is_empty() && trimmed != "target/ci-tools"
                        })
                    {
                        return Err(failure(
                            "tool binaries must use a cache separate from build targets",
                        ));
                    }
                }
                if uses.starts_with("actions/cache/save@") {
                    let condition = scalar(step, "if").unwrap_or_default();
                    let cache_hit = condition.contains("outputs.cache-hit != 'true'");
                    let with = mapping(
                        step.get(key("with"))
                            .ok_or_else(|| failure("cache save action needs with"))?,
                        "cache with",
                    )?;
                    let primary_key = scalar(with, "key")
                        .is_some_and(|value| value.contains("outputs.cache-primary-key"));
                    if !condition.contains("always()") || !cache_hit || !primary_key {
                        return Err(failure(
                            "cache save must be guarded by always/cache-hit and reuse the primary key",
                        ));
                    }
                }
            }
        }
    }
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
        check_backend_certification_structure(workflow, jobs)?;
    }
    if relative == Path::new(".github/workflows/release.yml") {
        let release = config::release(root)?;
        let toolchains = config::toolchains(root)?;
        let auth_action = pins
            .action
            .iter()
            .find(|pin| pin.name == "crates-io-auth")
            .map(|pin| pin.uses.as_str())
            .ok_or_else(|| failure("crates.io authentication action pin is absent"))?;
        check_release_structure(workflow, jobs, &release, &toolchains, auth_action)?;
        if text.contains("release-bootstrap") || text.contains("bootstrap-crates") {
            return Err(failure("obsolete crates.io bootstrap path is forbidden"));
        }
        let publication_slots = release.publish_packages.len();
        if text.matches("CARGO_REGISTRIES_CRATES_IO_TOKEN").count() != publication_slots {
            return Err(failure(
                "release credential text occurs outside exact step-local mappings",
            ));
        }
        if text.contains("CARGO_REGISTRY_TOKEN")
            || text.contains(&stored_token_source())
            || text.matches("release publish-next").count() != publication_slots
            || text.matches("outputs.token").count() != publication_slots
            || text.contains("secrets.")
        {
            return Err(failure(
                "release publication or credential source occurs outside canonical slots",
            ));
        }
        if text.contains("stored-token") || text.contains("oidc-fallback") {
            return Err(failure(
                "steady-state workflow retains transition credential literals",
            ));
        }
    }
    Ok(())
}

/// Parses and validates untrusted workflow bytes through the production policy path.
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
    )
}

#[derive(Default)]
struct RustPolicy {
    violations: Vec<String>,
    calls_current_exe: bool,
    names_proc_self_exe: bool,
    calls_env_remove: bool,
    subprocess_env_mutations: usize,
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
        if expression.method == "env_remove" {
            self.calls_env_remove = true;
        }
        if expression.method == "pre_exec" {
            self.pre_exec_calls += 1;
        }
        if matches!(expression.method.to_string().as_str(), "env" | "envs") {
            self.subprocess_env_mutations += 1;
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
    let macos_watchdog = Path::new("crates/memcordon-platform/src/macos_watchdog.rs");
    let sealed_launch =
        Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs");
    if visitor.subprocess_env_mutations != 0 && relative != sealed_launch {
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
            || (visitor.calls_current_exe && relative != macos_watchdog))
    {
        visitor
            .violations
            .push("platform helper self-execution is forbidden".to_owned());
    }
    if visitor.calls_env_remove
        && relative != Path::new("tools/memcordon-ci/src/command.rs")
        && relative != Path::new("tools/memcordon-ci/src/release.rs")
    {
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
        let macos_watchdog = Path::new("crates/memcordon-platform/src/macos_watchdog.rs");
        let sealed_launch =
            Path::new("crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/launch.rs");
        if visitor.subprocess_env_mutations != 0 && relative != sealed_launch {
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
                || (visitor.calls_current_exe && relative != macos_watchdog))
        {
            visitor
                .violations
                .push("platform helper self-execution is forbidden".to_owned());
        }
        if visitor.calls_env_remove
            && relative != Path::new("tools/memcordon-ci/src/command.rs")
            && relative != Path::new("tools/memcordon-ci/src/release.rs")
        {
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
            || path
                == Path::new(
                    "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture.rs",
                )
            || path == Path::new("crates/memcordon-cli/tests/sealed_agent/linux_faults.rs")
            || path == Path::new("crates/memcordon-cli/tests/sealed_agent/linux_sealed.rs")
            || path == Path::new("crates/memcordon-cli/tests/sealed_agent/launcher_activation.rs")
    )
}

fn check_manifests(root: &Path, policy: &config::Policy) -> Result<()> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .current_dir(root)
        .no_deps()
        .exec()?;
    let release = config::release(root)?;
    if release.publish_packages != policy.workspace.publish_packages {
        return Err(failure(
            "release and workspace publish package orders differ",
        ));
    }
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

fn require_credential_transition_fragments(
    root: &Path,
    relative: &str,
    required: &[&str],
    forbidden: &[&str],
) -> Result<()> {
    let source = fs::read_to_string(root.join(relative))?;
    for fragment in required {
        if !source.contains(fragment) {
            return Err(failure(format!(
                "credential-transition v2 policy fragment is absent from {relative}: {fragment:?}"
            )));
        }
    }
    for fragment in forbidden {
        if source.contains(fragment) {
            return Err(failure(format!(
                "legacy credential-transition policy fragment remains in {relative}: {fragment:?}"
            )));
        }
    }
    Ok(())
}

fn check_credential_transition_redesign(root: &Path) -> Result<()> {
    require_credential_transition_fragments(
        root,
        "crates/memcordon-core/src/report.rs",
        &[
            "pub const EXECUTION_REPORT_SCHEMA_VERSION: u32 = 8;",
            "pub const PLAN_REPORT_SCHEMA_VERSION: u32 = 7;",
            "pub const DOCTOR_REPORT_SCHEMA_VERSION: u32 = 5;",
            "pub const CLEAN_REPORT_SCHEMA_VERSION: u32 = 2;",
        ],
        &[],
    )?;
    require_credential_transition_fragments(
        root,
        "crates/memcordon-core/src/supervision.rs",
        &[
            "CredentialTransitionDisposition",
            "PreserveCallerEnvelope",
            "LinuxSealedEvidenceV2",
            "WindowsSealedEvidenceV2",
            "LinuxPidNamespaceCgroupV2",
            "WindowsJobObjectV2",
        ],
        &["linux-pid-namespace-cgroup-v1"],
    )?;
    require_credential_transition_fragments(
        root,
        "crates/memcordon-cli/src/bin/memcordon-sealed-agent/protocol.rs",
        &["pub const PROTOCOL_VERSION: u16 = 2;"],
        &["linux-pid-namespace-cgroup-v1"],
    )?;
    require_credential_transition_fragments(
        root,
        "crates/memcordon-cli/src/bin/memcordon-sealed-agent/request.rs",
        &[
            "pub const LAUNCH_REQUEST_VERSION: u16 = 2;",
            "pub const LAUNCH_BROKER_REQUEST_VERSION: u16 = 2;",
            "CallerExecutionEnvelopeV2",
            "LaunchBrokerRequestV2",
            "request_digest",
            "control_process_start_time",
            "record_identity",
            "request_authentication_binding",
        ],
        &["linux-pid-namespace-cgroup-v1"],
    )?;
    require_credential_transition_fragments(
        root,
        "crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/qualification.rs",
        &[
            "schema_version: 2",
            "linux-pid-namespace-cgroup-v2",
            "preserve-caller-envelope",
            "setid_transition_certification_digest",
            "sudo_transition_certification_digest",
            "recursive_provider_request_rejected",
        ],
        &["linux-pid-namespace-cgroup-v1"],
    )?;
    let selectors = [
        "sealed_setid_transition_preserves_boundary",
        "sealed_sudo_transition_preserves_boundary",
        "sealed_file_capability_transition_preserves_boundary",
        "sealed_caller_no_new_privs_is_reproduced",
        "sealed_caller_capability_bounding_set_is_reproduced",
        "sealed_caller_mount_context_is_reproduced",
        "sealed_recursive_provider_request_is_rejected",
    ];
    require_credential_transition_fragments(
        root,
        "crates/memcordon-cli/tests/sealed_agent/linux_sealed.rs",
        &selectors,
        &[],
    )?;
    let artifacts = [
        "provider-package-verification.json",
        "provider-qualification-v2.json",
        "setid-transition.json",
        "sudo-transition.json",
        "file-capability-transition.json",
        "caller-envelope.json",
        "mount-context.json",
        "fault-injection.json",
        "cleanup-leak-check.json",
    ];
    let mut runner_fragments = vec![
        "linux-pid-namespace-cgroup-v2",
        "target/ci/reports/linux-sealed-v2",
    ];
    runner_fragments.extend(selectors);
    runner_fragments.extend(artifacts);
    require_credential_transition_fragments(
        root,
        "tools/memcordon-ci/src/sealed_linux.rs",
        &runner_fragments,
        &["linux-pid-namespace-cgroup-v1"],
    )?;
    let mut release_fragments = vec![
        "linux-pid-namespace-cgroup-v2",
        "LinuxPidNamespaceCgroupV2",
        "PreserveCallerEnvelope",
    ];
    release_fragments.extend(selectors);
    release_fragments.extend(artifacts);
    require_credential_transition_fragments(
        root,
        "tools/memcordon-ci/src/release_evidence.rs",
        &release_fragments,
        &["linux-pid-namespace-cgroup-v1"],
    )?;
    let fuzz_targets = [
        "caller-envelope-status",
        "capability-mask",
        "namespace-identity",
        "broker-protocol-v2",
        "qualification-receipt-v2",
        "terminal-receipt-v2",
        "linux-evidence-v2",
        "service-unit-policy",
        "provider-recursion-proof",
        "mount-context-manifest",
    ];
    require_credential_transition_fragments(root, "fuzz/Cargo.toml", &fuzz_targets, &[])?;
    require_credential_transition_fragments(
        root,
        "tools/memcordon-ci/src/suites.rs",
        &fuzz_targets,
        &[],
    )?;
    require_credential_transition_fragments(
        root,
        "docs/sealed-supervision.md",
        &[
            "linux-pid-namespace-cgroup-v2",
            "preserve-caller-envelope",
            "credential transitions",
        ],
        &[],
    )?;
    require_credential_transition_fragments(
        root,
        "docs/sealed-provider.md",
        &[
            "memcordon-sealed-launcher.service",
            "NoNewPrivileges=no",
            "provider protocol v2",
        ],
        &[],
    )?;
    require_credential_transition_fragments(
        root,
        "packaging/linux/memcordon.conf",
        &[
            "d /run/memcordon 0750 root memcordon -",
            "f /run/memcordon-sealed-package.lock 0600 root root -",
        ],
        &[],
    )?;
    require_credential_transition_fragments(root, "spec/sealed-linux-v2.md", &artifacts, &[])?;
    require_credential_transition_fragments(
        root,
        "spec/sealed-linux-v1.md",
        &["Historical specification", "reject this mechanism"],
        &[],
    )?;
    require_credential_transition_fragments(
        root,
        "spec/sealed-provider-protocol-v1.md",
        &["Historical specification", "reject protocol v1"],
        &[],
    )?;
    require_credential_transition_fragments(
        root,
        "tools/memcordon-ci/tests/release_evidence.rs",
        &[
            "required_credential_transition_mutants_fail_closed_and_map_to_named_tests",
            "retain-service-nnp-on-target",
            "force-target-nnp-regardless-of-caller",
            "ignore-caller-capability-bounding-set",
            "preserve-provider-capability",
            "inherit-control-service-mount-namespace",
            "authorize-before-mount-context-verification",
            "allow-recursive-provider-request",
            "accept-v1-provider",
            "hardcode-transition-compatibility",
            "skip-setid-certification-digest",
            "treat-credential-change-as-boundary-loss",
            "omit-cgroup-kill-after-credential-change",
            "restart-before-v2-retirement",
        ],
        &[],
    )?;
    Ok(())
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
    let stored_secret_source = ["secrets.", "CARGO_REGISTRY_TOKEN"].concat();
    for relative in &files {
        let bytes = fs::read(root.join(relative))?;
        if let Ok(text) = std::str::from_utf8(&bytes) {
            if text.contains(&stored_secret_source) {
                return Err(failure(format!(
                    "stored crates.io token source remains: {relative:?}"
                )));
            }
            if text.contains("CARGO_REGISTRY_TOKEN")
                && relative != Path::new("tools/memcordon-ci/src/command.rs")
                && relative != Path::new("tools/memcordon-ci/src/policy.rs")
                && relative != Path::new("tools/memcordon-ci/src/release.rs")
            {
                return Err(failure(format!(
                    "legacy crates.io token interface remains outside negative policy assertions: {relative:?}"
                )));
            }
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
    let release_environment: Vec<&EnvironmentDefinition> = environment_definitions
        .iter()
        .filter(|definition| definition.file == ".github/workflows/release.yml")
        .collect();
    let expected_release_environment_count = 3 + policy.workspace.publish_packages.len() * 2;
    if release_environment.len() != expected_release_environment_count {
        return Err(failure(
            "release workflow step-local environment mapping count does not match the publish package set",
        ));
    }
    for name in ["Stage GitHub draft and assets", "Finalize GitHub release"] {
        if !release_environment.iter().any(|definition| {
            definition.step == name
                && definition.variable == "GITHUB_TOKEN"
                && definition.source == "${{ github.token }}"
        }) {
            return Err(failure(format!(
                "release GitHub credential mapping is absent: {name}"
            )));
        }
    }
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
    check_credential_transition_redesign(root)?;
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
mod tests {
    use super::*;

    const AUTH_ACTION: &str =
        "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18";

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
    }

    fn steady_workflow_fixture() -> &'static str {
        r#"name: Release
on:
  push:
    tags:
      - "[0-9]+.[0-9]+.[0-9]+*"
  workflow_dispatch:
    inputs:
      tag:
        description: Existing protected SemVer tag to publish or reconcile
        required: true
        type: string
permissions:
  contents: read
concurrency:
  group: memcordon-release
  cancel-in-progress: false
jobs:
  publish:
    needs: assemble
    permissions:
      actions: read
      contents: write
      id-token: write
    steps:
      - name: Stage GitHub draft and assets
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: rustup run 1.97.1 cargo run --locked --target-dir target/ci/publish-bootstrap --package memcordon-ci -- release stage-github
      - name: Acquire crates.io token for publication slot 1
        id: crates_auth_1
        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Publish next crate in slot 1
        env:
          CARGO_HOME: target/ci/cargo-publish-home/slot-1
          CARGO_REGISTRIES_CRATES_IO_TOKEN: ${{ steps.crates_auth_1.outputs.token }}
        run: target/ci/publish-bootstrap/debug/memcordon-ci release publish-next
      - name: Acquire crates.io token for publication slot 2
        id: crates_auth_2
        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Publish next crate in slot 2
        env:
          CARGO_HOME: target/ci/cargo-publish-home/slot-2
          CARGO_REGISTRIES_CRATES_IO_TOKEN: ${{ steps.crates_auth_2.outputs.token }}
        run: target/ci/publish-bootstrap/debug/memcordon-ci release publish-next
      - name: Acquire crates.io token for publication slot 3
        id: crates_auth_3
        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Publish next crate in slot 3
        env:
          CARGO_HOME: target/ci/cargo-publish-home/slot-3
          CARGO_REGISTRIES_CRATES_IO_TOKEN: ${{ steps.crates_auth_3.outputs.token }}
        run: target/ci/publish-bootstrap/debug/memcordon-ci release publish-next
      - name: Acquire crates.io token for publication slot 4
        id: crates_auth_4
        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Publish next crate in slot 4
        env:
          CARGO_HOME: target/ci/cargo-publish-home/slot-4
          CARGO_REGISTRIES_CRATES_IO_TOKEN: ${{ steps.crates_auth_4.outputs.token }}
        run: target/ci/publish-bootstrap/debug/memcordon-ci release publish-next
      - name: Finalize GitHub release
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: rustup run 1.97.1 cargo run --locked --target-dir target/ci/publish-bootstrap --package memcordon-ci -- release finalize-github
  verify-public:
    needs: publish
"#
    }

    fn check_steady_fixture(text: &str) -> Result<()> {
        let root = repository_root();
        let fixture: Value = serde_yaml::from_str(text)?;
        let fixture_workflow = mapping(&fixture, "steady workflow")?;
        let fixture_jobs = mapping(
            fixture_workflow
                .get(key("jobs"))
                .ok_or_else(|| failure("steady fixture jobs are absent"))?,
            "steady jobs",
        )?;
        let mut document: Value =
            serde_yaml::from_slice(include_bytes!("../../../.github/workflows/release.yml"))?;
        {
            let workflow = document
                .as_mapping_mut()
                .ok_or_else(|| failure("release workflow must be a mapping"))?;
            workflow.insert(
                key("on"),
                fixture_workflow
                    .get(key("on"))
                    .ok_or_else(|| failure("steady fixture events are absent"))?
                    .clone(),
            );
            let jobs = workflow
                .get_mut(key("jobs"))
                .and_then(Value::as_mapping_mut)
                .ok_or_else(|| failure("release jobs are absent"))?;
            // The steady-state fixture exercises publication authentication.
            // Keep the production public-verification matrix intact so its
            // independently strict Windows x64/ARM64 structure is still
            // checked by check_release_structure.
            let job_name = "publish";
            jobs.insert(
                key(job_name),
                fixture_jobs
                    .get(key(job_name))
                    .ok_or_else(|| failure(format!("steady {job_name} job is absent")))?
                    .clone(),
            );
        }
        let workflow = mapping(&document, "release workflow")?;
        let jobs = mapping(
            workflow
                .get(key("jobs"))
                .ok_or_else(|| failure("release jobs are absent"))?,
            "release jobs",
        )?;
        let release = config::release(&root)?;
        let toolchains = config::toolchains(&root)?;
        check_release_structure(workflow, jobs, &release, &toolchains, AUTH_ACTION)
    }

    #[test]
    fn exact_oidc_only_workflow_profile_is_accepted() {
        let root = repository_root();
        let policy = config::policy(&root).expect("repository policy should parse");
        validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/release.yml"),
            include_bytes!("../../../.github/workflows/release.yml"),
            &policy,
        )
        .expect("OIDC-only workflow should satisfy production policy");
        check_steady_fixture(steady_workflow_fixture())
            .expect("cleanup steady-state workflow should satisfy structure policy");
    }

    #[test]
    fn steady_profile_rejects_noncanonical_oidc_slots_and_token_reintroduction() {
        let with_input = steady_workflow_fixture().replacen(
            "        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18\n",
            "        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18\n        with:\n          url: https://example.invalid\n",
            1,
        );
        assert!(check_steady_fixture(&with_input).is_err());

        let wrong_output = steady_workflow_fixture().replacen(
            "steps.crates_auth_1.outputs.token",
            "steps.crates_auth_2.outputs.token",
            1,
        );
        assert!(check_steady_fixture(&wrong_output).is_err());

        let separated_pair = steady_workflow_fixture().replacen(
            "        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18\n      - name: Publish next crate in slot 1\n",
            "        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18\n      - run: rustup toolchain install 1.97.1 --profile minimal\n      - name: Publish next crate in slot 1\n",
            1,
        );
        assert!(check_steady_fixture(&separated_pair).is_err());

        let stored = steady_workflow_fixture().replacen(
            "${{ steps.crates_auth_1.outputs.token }}",
            &stored_token_source(),
            1,
        );
        assert!(check_steady_fixture(&stored).is_err());

        let missing_github_mapping = steady_workflow_fixture().replacen(
            "      - name: Stage GitHub draft and assets\n",
            "      - name: Stage mapping removed\n",
            1,
        );
        assert!(check_steady_fixture(&missing_github_mapping).is_err());
    }

    #[test]
    fn oidc_only_profile_rejects_legacy_token_and_transition_input() {
        let root = repository_root();
        let policy = config::policy(&root).expect("repository policy should parse");
        let exact = std::str::from_utf8(include_bytes!("../../../.github/workflows/release.yml"))
            .expect("workflow should be UTF-8")
            .replace("\r\n", "\n");
        let legacy_environment = format!(
            "        env:\n          CARGO_REGISTRY_TOKEN: {}\n",
            stored_token_source()
        );
        let transition_input =
            "      registry_auth:\n        required: true\n        type: choice\n";
        for (case, invalid) in [
            (
                "legacy stored credential",
                exact.replacen(
                    "        env:\n          CARGO_HOME: target/ci/cargo-publish-home/slot-1\n          CARGO_REGISTRIES_CRATES_IO_TOKEN: ${{ steps.crates_auth_1.outputs.token }}\n",
                    &legacy_environment,
                    1,
                ),
            ),
            (
                "retired transition input",
                exact.replacen(
                    "  workflow_dispatch:\n    inputs:\n",
                    &format!("  workflow_dispatch:\n    inputs:\n{transition_input}"),
                    1,
                ),
            ),
        ] {
            assert_ne!(invalid, exact, "{case} fixture mutation must apply");
            assert!(
                validate_workflow_bytes(
                    &root,
                    Path::new(".github/workflows/release.yml"),
                    invalid.as_bytes(),
                    &policy,
                )
                .is_err(),
                "{case} fixture must be rejected"
            );
        }
    }

    #[test]
    fn malformed_policy_fixture_is_rejected() {
        let malformed = "[workspace]\nproduction_packages = \"not-a-list\"\n";
        assert!(toml::from_str::<config::Policy>(malformed).is_err());
    }

    #[test]
    fn malformed_workflow_fixture_non_scalar_run_is_rejected() {
        let document: Value = serde_yaml::from_str(
            "jobs:\n  check:\n    steps:\n      - run:\n          command: cargo check\n",
        )
        .expect("fixture YAML should parse");
        let jobs = mapping(
            mapping(&document, "workflow")
                .expect("workflow mapping")
                .get(key("jobs"))
                .expect("jobs"),
            "jobs",
        )
        .expect("jobs mapping");
        let step = jobs
            .get(key("check"))
            .and_then(Value::as_mapping)
            .and_then(|job| job.get(key("steps")))
            .and_then(Value::as_sequence)
            .and_then(|steps| steps.first())
            .and_then(Value::as_mapping)
            .expect("step mapping");
        assert!(step.get(key("run")).is_some());
        assert!(scalar(step, "run").is_none());
    }

    #[test]
    fn workflow_shell_operator_fixtures_are_rejected() {
        for command in [
            "cargo check && cargo test",
            "cargo check | tee out",
            "cargo &",
        ] {
            assert!(!static_run_command(command));
        }
        assert!(static_run_command("cargo check --locked"));
    }

    #[test]
    fn workflow_event_fixture_requires_exact_keys() {
        let mapping: Mapping = serde_yaml::from_str("push: {}\npull_request_target: {}\n")
            .expect("mapping should parse");
        assert!(exact_mapping_keys(&mapping, &["push", "pull_request"], "events").is_err());
    }
}
