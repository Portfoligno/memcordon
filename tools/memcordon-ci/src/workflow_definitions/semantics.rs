//! Independent checks over actual YAML. No renderer equality or restored fact
//! can supply a required work operation or native checkpoint here.
use super::{adapters, text};
use crate::{CiError, Result};
use serde_yaml::Value;
use std::collections::BTreeMap;

fn reject(reason: &str) -> CiError {
    CiError::Message(reason.into())
}
fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or("")
}
fn required(step: &Value) -> Result<()> {
    if !step["continue-on-error"].is_null() && step["continue-on-error"].as_bool() != Some(false) {
        return Err(reject("required work became optional"));
    }
    Ok(())
}
fn recipe(command: &str) -> Option<&str> {
    command.split_once(" ci segment ").map(|(_, recipe)| recipe)
}

pub fn validate(document: &Value) -> Result<()> {
    if document["name"] == "Release" {
        let needs = document["jobs"]["assemble"]["needs"]
            .as_sequence()
            .ok_or_else(|| reject("assembly dependencies absent"))?;
        if !["format", "source-policy"]
            .iter()
            .all(|owner| needs.contains(&text(owner)))
            || !document["jobs"]["source-policy"].is_mapping()
            || !document["jobs"]["source-policy"]["needs"].is_null()
        {
            return Err(reject(
                "assembly requires independent source formatting and policy",
            ));
        }
    }
    super::source_seed::validate(document)?;
    super::concurrency::validate(document)?;
    super::windows_fixture_native::validate(document)?;
    if document["name"].as_str() == Some("Release") {
        super::release_fuzz::validate(document)?;
        super::host_preparation::validate(document)?;
    }
    if document["name"].as_str() == Some("Native backend tests") {
        super::backend_private::validate(document)?;
    }
    let jobs = document["jobs"]
        .as_mapping()
        .ok_or_else(|| reject("workflow jobs absent"))?;
    for (job_name, job) in jobs {
        let Some(steps) = job["steps"].as_sequence() else {
            continue;
        };
        let mut owners = BTreeMap::new();
        let writer = job["permissions"]
            .as_mapping()
            .is_some_and(|p| p.values().any(|v| v.as_str() == Some("write")));
        for (index, step) in steps.iter().enumerate() {
            let command = field(step, "run");
            if !command.is_empty() {
                if command.contains('\n')
                    || ["${{", "&&", ";", "|", "$(", "`"]
                        .iter()
                        .any(|s| command.contains(s))
                {
                    return Err(reject("run must be one literal native invocation"));
                }
                if command.contains(" ci segment ")
                    || command.contains(" release build-target ")
                    || command.ends_with(" release working-windows-prepare")
                    || command.ends_with(" ci driver-build")
                    || command.contains(" ci driver-build --feedback ")
                    || command.contains(" ci driver-select --feedback ")
                    || command.contains(" ci driver-adopt-cold --feedback ")
                    || command.contains("--target-dir target/ci-driver-cold")
                {
                    required(step)?;
                }
                if recipe(command) == Some("prepare-miri-components") {
                    let driver = command
                        .split_once(" ci segment ")
                        .expect("component command")
                        .0;
                    if !steps[..index].iter().any(|s| {
                        field(s, "run").strip_prefix(driver) == Some(" ci segment workspace-fetch")
                    }) {
                        return Err(reject(
                            "Miri components require the earlier actual workspace fetch",
                        ));
                    }
                }
            }
            if !step["shell"].is_null() {
                return Err(reject("workflow step may not supply a shell"));
            }
            if step["env"].as_mapping().is_some_and(|env| {
                env.keys().any(|key| {
                    key.as_str()
                        .is_some_and(|k| k == "CI_STEPS" || k.starts_with("INPUT_"))
                })
            }) {
                return Err(reject(
                    "custom step-context environment bridge is forbidden",
                ));
            }
            if field(step, "uses").starts_with("actions/cache/")
                && (writer
                    || matches!(
                        job_name.as_str(),
                        Some("rehearse" | "recovery-rehearse" | "publish" | "recovery-publish")
                    ))
            {
                return Err(reject(
                    "executable/cache transport is forbidden in publishers and rehearsal",
                ));
            }
            if !field(step, "id").is_empty() && owners.insert(field(step, "id"), index).is_some() {
                return Err(reject("duplicate workflow step id"));
            }
        }
        for (compile_index, compile) in steps.iter().enumerate() {
            let Some((driver, selected)) = field(compile, "run").split_once(" ci segment ") else {
                continue;
            };
            let execute = if selected == "native-compile" {
                "native-execute".to_owned()
            } else if let Some(shard) = selected.strip_prefix("fuzz-compile-") {
                format!("fuzz-execute-{shard}")
            } else {
                continue;
            };
            let Some(execute_index) = steps.iter().position(|step| {
                field(step, "run")
                    .strip_prefix(driver)
                    .is_some_and(|suffix| {
                        suffix.strip_prefix(" ci segment ") == Some(execute.as_str())
                    })
            }) else {
                return Err(reject(
                    "actual compilation lost its required execution phase",
                ));
            };
            if execute_index <= compile_index {
                return Err(reject("actual execution must follow compilation"));
            }
        }
    }
    if jobs.contains_key(text("fuzz-setup")) && document["name"].as_str() == Some("Deep CI") {
        validate_fuzz_split(document)?;
    }
    let file = match field(document, "name") {
        "CI" => "ci.yml",
        "Deep CI" => "deep-ci.yml",
        "Native backend tests" => "backend-certification.yml",
        "Release" => "release.yml",
        _ => return Err(reject("unknown source-defined workflow name")),
    };
    adapters::validate_budget(document, file)?;
    Ok(())
}

fn validate_fuzz_split(document: &Value) -> Result<()> {
    let setup = &document["jobs"]["fuzz-setup"];
    let shard = &document["jobs"]["fuzz"];
    if setup["needs"] != "performance-plan"
        || field(setup, "if") != "needs.performance-plan.outputs.standalone-common == 'true'"
        || shard["needs"]
            .as_sequence()
            .is_none_or(|needs| needs != &vec![text("performance-plan"), text("fuzz-setup")])
        || field(shard, "if")
            != "!cancelled() && needs.performance-plan.result == 'success' && (needs.performance-plan.outputs.standalone-common == 'true')"
        || setup["runs-on"] != "ubuntu-24.04"
        || !setup["strategy"].is_null()
    {
        return Err(reject(
            "fuzz setup/shards must preserve selected performance-plan edges",
        ));
    }
    if !shard["needs"]
        .as_sequence()
        .is_some_and(|needs| needs.iter().any(|n| n == "fuzz-setup"))
        || !field(shard, "if").starts_with("!cancelled()")
    {
        return Err(reject("fuzz shards require successful actual setup"));
    }
    if setup["outputs"]["artifact-id"] != "${{ steps.fuzz-setup-upload.outputs.artifact-id }}" {
        return Err(reject(
            "fuzz setup must expose its actual immutable artifact ID",
        ));
    }
    let early = setup["steps"]
        .as_sequence()
        .ok_or_else(|| reject("fuzz setup steps absent"))?;
    let late = shard["steps"]
        .as_sequence()
        .ok_or_else(|| reject("fuzz shard steps absent"))?;
    let admission = late
        .first()
        .ok_or_else(|| reject("fuzz setup failure must fail selected shards"))?;
    if field(admission, "id") != "fuzz-setup-required"
        || field(admission, "run") != "false"
        || field(admission, "if") != "needs.fuzz-setup.result != 'success'"
        || admission["continue-on-error"].as_bool().unwrap_or(false)
    {
        return Err(reject("fuzz setup failure must fail selected shards"));
    }
    let ready = early
        .iter()
        .position(|s| recipe(field(s, "run")) == Some("prepare-fuzz"))
        .ok_or_else(|| reject("fuzz setup must actually prepare the selected tool"))?;
    let pack=early.iter().position(|s|field(s,"run")=="tar -czf target/fuzz-setup.tar.gz target/ci-runtime/current target/ci-tools/bin/cargo-fuzz").ok_or_else(||reject("fuzz setup must package finite native images"))?;
    let upload = early
        .iter()
        .position(|s| field(s, "id") == "fuzz-setup-upload")
        .ok_or_else(|| reject("fuzz setup upload absent"))?;
    if !(ready < pack && pack < upload)
        || early[upload]["with"]["path"] != "target/fuzz-setup.tar.gz"
        || early[upload]["with"]["if-no-files-found"] != "error"
    {
        return Err(reject(
            "fuzz setup immutable upload must follow actual preparation",
        ));
    }
    required(&early[upload])?;
    let download = late
        .iter()
        .position(|s| field(s, "id") == "fuzz-setup-download")
        .ok_or_else(|| reject("fuzz setup download absent"))?;
    if late[download]["with"]["artifact-ids"] != "${{ needs.fuzz-setup.outputs.artifact-id }}"
        || late[download]["with"]["digest-mismatch"] != "error"
    {
        return Err(reject(
            "fuzz shards must consume the exact same-run immutable setup ID",
        ));
    }
    required(&late[download])?;
    let extract = late
        .iter()
        .position(|s| {
            field(s, "run") == "tar -xzf target/ci/fuzz-setup-download/fuzz-setup.tar.gz -C ."
        })
        .ok_or_else(|| reject("fuzz setup extraction absent"))?;
    let probe = late
        .iter()
        .position(|s| {
            field(s, "run") == "./target/ci-runtime/current/memcordon-ci ci driver-image-probe"
        })
        .ok_or_else(|| reject("fuzz current image requires an actual protocol probe"))?;
    required(&late[probe])?;
    let compile = late
        .iter()
        .position(|s| recipe(field(s, "run")).is_some_and(|r| r.starts_with("fuzz-compile-")))
        .ok_or_else(|| reject("fuzz compilation absent"))?;
    if !(download < extract && extract < probe && probe < compile) {
        return Err(reject(
            "fuzz setup validation must precede actual compilation",
        ));
    }
    for list in [early, late] {
        if !list.iter().any(|s| {
            field(s, "uses").starts_with("actions/checkout@")
                && s["with"]["persist-credentials"].as_bool() == Some(false)
                && s["with"]["ref"] == "${{ github.sha }}"
        }) {
            return Err(reject(
                "fuzz setup and shards require the same exact source checkout",
            ));
        }
    }
    for quarter in ["one", "two", "three", "four"] {
        for phase in ["compile", "execute"] {
            if !late.iter().any(|s| {
                recipe(field(s, "run")) == Some(format!("fuzz-{phase}-quarter-{quarter}").as_str())
            }) {
                return Err(reject(
                    "fuzz split must preserve all four complete compile/execute quarters",
                ));
            }
        }
    }
    Ok(())
}
