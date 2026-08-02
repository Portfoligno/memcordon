use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_yaml::{Mapping, Value};
use syn::visit::Visit;
use walkdir::WalkDir;

use crate::command;
use crate::config;
use crate::{CiError, Result};

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
        files.push(path);
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
    if scalar(concurrency, "group") != Some("ci-${{ github.workflow }}-${{ github.ref }}")
        || concurrency
            .get(key("cancel-in-progress"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(failure("CI concurrency policy differs"));
    }
    let rendered = serde_yaml::to_string(jobs)?;
    for matrix in &policy.workflow.required_public_matrix {
        if !rendered.contains(matrix) {
            return Err(failure(format!("CI workflow lacks matrix member {matrix}")));
        }
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
        if let Some(name) = scalar(step, "name") {
            if named.insert(name, step).is_some() {
                return Err(failure(format!("duplicate release step name: {name}")));
            }
        }
    }
    Ok(named)
}

fn require_publication_step(
    steps: &BTreeMap<&str, &Mapping>,
    name: &str,
    condition: Option<&str>,
    source: &str,
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
            != Some(
                "rustup run 1.97.1 cargo run --locked --target-dir target/ci/publish-bootstrap --package memcordon-ci -- release publish-next",
            )
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
    exact_mapping_keys(environment, &["CARGO_REGISTRY_TOKEN"], name)?;
    if scalar(environment, "CARGO_REGISTRY_TOKEN") != Some(source) {
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
    if release.publish_packages.len() != 3 {
        return Err(failure(
            "release credential slot count must equal the three configured public packages",
        ));
    }
    let steps = named_steps(jobs, "publish")?;
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
    let transition_condition =
        "github.event_name == 'push' || inputs.registry_auth == 'stored-token'";
    let fallback_condition =
        "github.event_name == 'workflow_dispatch' && inputs.registry_auth == 'oidc-fallback'";
    for slot in 1..=release.publish_packages.len() {
        match release.registry_credentials.policy {
            config::RegistryCredentialPolicy::FirstReleaseTokenPrimary => {
                require_publication_step(
                    &steps,
                    &format!("Publish next crate in stored-token slot {slot}"),
                    Some(transition_condition),
                    &stored_token_source(),
                )?;
                let action_id = format!("crates_auth_fallback_{slot}");
                require_oidc_step(
                    &steps,
                    &format!("Acquire crates.io OIDC token for fallback slot {slot}"),
                    Some(fallback_condition),
                    &action_id,
                    auth_action,
                )?;
                require_publication_step(
                    &steps,
                    &format!("Publish next crate in OIDC fallback slot {slot}"),
                    Some(fallback_condition),
                    &format!("${{{{ steps.{action_id}.outputs.token }}}}"),
                )?;
            }
            config::RegistryCredentialPolicy::OidcOnly => {
                let action_id = format!("crates_auth_{slot}");
                require_oidc_step(
                    &steps,
                    &format!("Acquire crates.io token for publication slot {slot}"),
                    None,
                    &action_id,
                    auth_action,
                )?;
                require_publication_step(
                    &steps,
                    &format!("Publish next crate in slot {slot}"),
                    None,
                    &format!("${{{{ steps.{action_id}.outputs.token }}}}"),
                )?;
            }
        }
    }
    let oidc_count = steps
        .values()
        .filter(|step| scalar(step, "uses") == Some(auth_action))
        .count();
    if oidc_count != release.publish_packages.len() {
        return Err(failure("crates.io OIDC action slot count differs"));
    }
    let expected_environment_steps = match release.registry_credentials.policy {
        config::RegistryCredentialPolicy::FirstReleaseTokenPrimary => 8,
        config::RegistryCredentialPolicy::OidcOnly => 5,
    };
    if steps
        .values()
        .filter(|step| step.contains_key(key("env")))
        .count()
        != expected_environment_steps
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
    match release.registry_credentials.policy {
        config::RegistryCredentialPolicy::FirstReleaseTokenPrimary => {
            exact_mapping_keys(inputs, &["tag", "registry_auth"], "release inputs")?;
            let registry_auth = mapping(
                inputs
                    .get(key("registry_auth"))
                    .ok_or_else(|| failure("release registry_auth input is absent"))?,
                "release registry_auth input",
            )?;
            exact_mapping_keys(
                registry_auth,
                &["description", "required", "default", "type", "options"],
                "release registry_auth input",
            )?;
            if registry_auth.get(key("required")).and_then(Value::as_bool) != Some(true)
                || scalar(registry_auth, "default") != Some("stored-token")
                || scalar(registry_auth, "type") != Some("choice")
            {
                return Err(failure("release registry_auth input shape differs"));
            }
            exact_string_sequence(
                registry_auth
                    .get(key("options"))
                    .ok_or_else(|| failure("release registry_auth options are absent"))?,
                &["stored-token", "oidc-fallback"],
                "release registry_auth options",
            )?;
        }
        config::RegistryCredentialPolicy::OidcOnly => {
            exact_mapping_keys(inputs, &["tag"], "release inputs")?;
        }
    }
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
    if scalar(verify, "needs") != Some("publish") {
        return Err(failure("verify-public must depend on publish"));
    }
    check_release_credentials(jobs, release, auth_action)?;
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
    let document: Value = serde_yaml::from_slice(bytes)?;
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
        if relative == Path::new(".github/workflows/ci.yml") {
            if let Some(runner) = job.get(key("runs-on")) {
                if serde_yaml::to_string(runner)?.contains("self-hosted") {
                    return Err(failure("public CI may not select self-hosted runners"));
                }
            }
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
                    text.contains("CARGO_REGISTRY_TOKEN") || text.contains(&stored_token_source())
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
    if relative == Path::new(".github/workflows/release.yml") {
        let release = config::release(root)?;
        let auth_action = pins
            .action
            .iter()
            .find(|pin| pin.name == "crates-io-auth")
            .map(|pin| pin.uses.as_str())
            .ok_or_else(|| failure("crates.io authentication action pin is absent"))?;
        check_release_structure(workflow, jobs, &release, auth_action)?;
        if text.contains("release-bootstrap") || text.contains("bootstrap-crates") {
            return Err(failure("obsolete crates.io bootstrap path is forbidden"));
        }
        let expected_token_mentions = match release.registry_credentials.policy {
            config::RegistryCredentialPolicy::FirstReleaseTokenPrimary => 9,
            config::RegistryCredentialPolicy::OidcOnly => 3,
        };
        if text.matches("CARGO_REGISTRY_TOKEN").count() != expected_token_mentions {
            return Err(failure(
                "release credential text occurs outside exact step-local mappings",
            ));
        }
        let expected_stored_sources = match release.registry_credentials.policy {
            config::RegistryCredentialPolicy::FirstReleaseTokenPrimary => 3,
            config::RegistryCredentialPolicy::OidcOnly => 0,
        };
        if text.matches(&stored_token_source()).count() != expected_stored_sources {
            return Err(failure(
                "stored-token source count differs from credential profile",
            ));
        }
        let expected_publish_next = match release.registry_credentials.policy {
            config::RegistryCredentialPolicy::FirstReleaseTokenPrimary => 6,
            config::RegistryCredentialPolicy::OidcOnly => 3,
        };
        if text.matches("release publish-next").count() != expected_publish_next
            || text.matches("outputs.token").count() != 3
            || text.matches("secrets.").count() != expected_stored_sources
        {
            return Err(failure(
                "release publication or credential source occurs outside canonical slots",
            ));
        }
        if release.registry_credentials.policy == config::RegistryCredentialPolicy::OidcOnly
            && (text.contains("stored-token") || text.contains("oidc-fallback"))
        {
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
                && segments.last().is_some_and(|segment| segment == "set_var")
            {
                self.violations
                    .push("std::env::set_var is forbidden".to_owned());
            }
            if segments.len() >= 2
                && segments[segments.len() - 2] == "Command"
                && segments.last().is_some_and(|segment| segment == "new")
            {
                if let Some(syn::Expr::Lit(literal)) = expression.args.first() {
                    if let syn::Lit::Str(program) = &literal.lit {
                        if [
                            "sh",
                            "bash",
                            "cmd",
                            "powershell",
                            "pwsh",
                            "/bin/sh",
                            "/bin/bash",
                        ]
                        .contains(&program.value().as_str())
                        {
                            self.violations
                                .push("shell process spawn is forbidden".to_owned());
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if matches!(expression.method.to_string().as_str(), "env" | "envs") {
            self.violations
                .push("subprocess environment mutation is forbidden".to_owned());
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
    for relative in &candidates {
        let in_scope = relative.starts_with("tools/memcordon-ci")
            || relative.starts_with("crates/memcordon-testkit")
            || relative == Path::new("crates/memcordon-cli/src/bin/memcordon-test-fixture.rs")
            || relative
                .components()
                .any(|component| component.as_os_str() == "tests");
        if !in_scope {
            continue;
        }
        let source = fs::read_to_string(root.join(relative))?;
        let syntax = syn::parse_file(&source).map_err(|error| {
            failure(format!(
                "Rust syntax parse failed for {relative:?}: {error}"
            ))
        })?;
        let mut visitor = RustPolicy::default();
        visitor.visit_file(&syntax);
        if !visitor.violations.is_empty() {
            return Err(failure(format!(
                "Rust policy failed for {relative:?}: {:?}",
                visitor.violations
            )));
        }
    }
    Ok(())
}

fn check_manifests(root: &Path, policy: &config::Policy) -> Result<()> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .current_dir(root)
        .no_deps()
        .exec()?;
    let packages: BTreeMap<&str, &cargo_metadata::Package> = metadata
        .packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect();
    let workspace_version = packages
        .get("memcordon")
        .ok_or_else(|| failure("memcordon workspace package is absent"))?
        .version
        .clone();
    let release = config::release(root)?;
    config::validate_registry_credentials(&release.registry_credentials, &workspace_version)?;
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
    for (name, package) in &packages {
        for dependency in &package.dependencies {
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

fn check_cargo_configuration(root: &Path, files: &[PathBuf]) -> Result<()> {
    for relative in files {
        let file_name = relative.file_name().and_then(|name| name.to_str());
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
    let release = config::release(root)?;
    if release.registry_credentials.policy == config::RegistryCredentialPolicy::OidcOnly {
        let forbidden = ["secrets.", "CARGO_REGISTRY_TOKEN"].concat();
        for relative in &files {
            let bytes = fs::read(root.join(relative))?;
            if std::str::from_utf8(&bytes).is_ok_and(|text| text.contains(&forbidden)) {
                return Err(failure(format!(
                    "stored crates.io token source remains under oidc-only: {relative:?}"
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
    let release = config::release(root)?;
    let release_environment: Vec<&EnvironmentDefinition> = environment_definitions
        .iter()
        .filter(|definition| definition.file == ".github/workflows/release.yml")
        .collect();
    let expected_release_environment_count = match release.registry_credentials.policy {
        config::RegistryCredentialPolicy::FirstReleaseTokenPrimary => 8,
        config::RegistryCredentialPolicy::OidcOnly => 5,
    };
    if release_environment.len() != expected_release_environment_count {
        return Err(failure(format!(
            "release workflow must have exactly {expected_release_environment_count} credential mappings"
        )));
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
          CARGO_REGISTRY_TOKEN: ${{ steps.crates_auth_1.outputs.token }}
        run: rustup run 1.97.1 cargo run --locked --target-dir target/ci/publish-bootstrap --package memcordon-ci -- release publish-next
      - name: Acquire crates.io token for publication slot 2
        id: crates_auth_2
        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Publish next crate in slot 2
        env:
          CARGO_REGISTRY_TOKEN: ${{ steps.crates_auth_2.outputs.token }}
        run: rustup run 1.97.1 cargo run --locked --target-dir target/ci/publish-bootstrap --package memcordon-ci -- release publish-next
      - name: Acquire crates.io token for publication slot 3
        id: crates_auth_3
        uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18
      - name: Publish next crate in slot 3
        env:
          CARGO_REGISTRY_TOKEN: ${{ steps.crates_auth_3.outputs.token }}
        run: rustup run 1.97.1 cargo run --locked --target-dir target/ci/publish-bootstrap --package memcordon-ci -- release publish-next
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
        let document: Value = serde_yaml::from_str(text)?;
        let workflow = mapping(&document, "steady workflow")?;
        let jobs = mapping(
            workflow
                .get(key("jobs"))
                .ok_or_else(|| failure("steady fixture jobs are absent"))?,
            "steady jobs",
        )?;
        let mut release = config::release(&root)?;
        release.registry_credentials.policy = config::RegistryCredentialPolicy::OidcOnly;
        release.registry_credentials.first_release_version = None;
        check_release_structure(workflow, jobs, &release, AUTH_ACTION)
    }

    #[test]
    fn exact_transition_and_steady_workflow_profiles_are_accepted() {
        let root = repository_root();
        let policy = config::policy(&root).expect("repository policy should parse");
        validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/release.yml"),
            include_bytes!("../../../.github/workflows/release.yml"),
            &policy,
        )
        .expect("transition workflow should satisfy production policy");
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
    fn transition_profile_rejects_missing_condition_automatic_fallback_and_secret_if() {
        let root = repository_root();
        let policy = config::policy(&root).expect("repository policy should parse");
        let exact = std::str::from_utf8(include_bytes!("../../../.github/workflows/release.yml"))
            .expect("workflow should be UTF-8")
            .replace("\r\n", "\n");
        let stored_environment = format!(
            "        env:\n          CARGO_REGISTRY_TOKEN: {}\n",
            stored_token_source()
        );
        let automatic_fallback_environment = format!(
            "        continue-on-error: true\n        env:\n          CARGO_REGISTRY_TOKEN: {}\n",
            stored_token_source()
        );
        let secret_condition = format!("        if: {} != ''\n", stored_token_source());
        for (case, invalid) in [
            (
                "missing stored-token condition",
                exact.replacen(
                    "        if: github.event_name == 'push' || inputs.registry_auth == 'stored-token'\n",
                    "",
                    1,
                ),
            ),
            (
                "automatic stored-token fallback",
                exact.replacen(
                    &stored_environment,
                    &automatic_fallback_environment,
                    1,
                ),
            ),
            (
                "secret-backed step condition",
                exact.replacen(
                    "        if: github.event_name == 'push' || inputs.registry_auth == 'stored-token'\n",
                    &secret_condition,
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
