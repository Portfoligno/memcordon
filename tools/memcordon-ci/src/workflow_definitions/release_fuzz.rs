//! Release fuzz setup retains the original tool preparation on its own host.
use super::{adapters, text};
use crate::{CiError, Result};
use serde_yaml::{Mapping, Value};

const UPLOAD: &str = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
const DOWNLOAD: &str = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";

fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or("")
}
fn object(fields: &[(&str, Value)]) -> Value {
    Value::Mapping(
        fields
            .iter()
            .map(|(name, value)| (text(name), value.clone()))
            .collect(),
    )
}
fn set(value: &mut Value, name: &str, field: Value) {
    value
        .as_mapping_mut()
        .expect("source mapping")
        .insert(text(name), field);
}
fn run(id: &str, command: &str, minutes: u64) -> Value {
    object(&[
        ("id", text(id)),
        ("run", text(command)),
        ("timeout-minutes", Value::Number(minutes.into())),
    ])
}

pub(super) fn apply(workflow: &mut Value) -> Result<()> {
    let jobs = workflow["jobs"].as_mapping_mut().expect("source jobs");
    let mut shard = jobs
        .get(text("fuzz"))
        .ok_or_else(|| CiError::Message("release fuzz source job missing".into()))?
        .clone();
    let all = shard["steps"]
        .as_sequence()
        .expect("source fuzz steps")
        .clone();
    let boundary = all
        .iter()
        .position(|step| field(step, "run").contains(" ci cache-requests fuzz-compile-quarter-"))
        .ok_or_else(|| CiError::Message("release fuzz compiler boundary missing".into()))?;
    let prefix = &all[..boundary];
    let mut setup = shard.clone();
    setup
        .as_mapping_mut()
        .expect("setup mapping")
        .remove(text("strategy"));
    set(&mut setup, "name", text("Release fuzz setup"));
    let mut early = prefix.to_vec();
    early.push(run(
        "fuzz-setup-inputs",
        "./.release/tool/memcordon-ci ci preparation-tools package --kind release-fuzz",
        5,
    ));
    early.push(run("fuzz-setup-package","tar -czf target/release-fuzz-setup.tar.gz .release/tool/memcordon-ci target/ci-tools/bin/cargo-fuzz target/ci-preparation/release-fuzz.json",3));
    early.push(object(&[
        ("id", text("fuzz-setup-upload")),
        ("uses", text(UPLOAD)),
        ("timeout-minutes", Value::Number(5.into())),
        (
            "with",
            object(&[
                (
                    "name",
                    text("release-fuzz-setup-${{ github.run_id }}-${{ github.run_attempt }}"),
                ),
                ("path", text("target/release-fuzz-setup.tar.gz")),
                ("if-no-files-found", text("error")),
                ("overwrite", Value::Bool(false)),
            ]),
        ),
    ]));
    set(&mut setup, "steps", Value::Sequence(early));
    set(
        &mut setup,
        "outputs",
        object(&[(
            "artifact-id",
            text("${{ steps.fuzz-setup-upload.outputs.artifact-id }}"),
        )]),
    );

    set(
        &mut shard,
        "needs",
        Value::Sequence(vec![text("select"), text("fuzz-setup")]),
    );
    let condition = field(&shard, "if").to_owned();
    set(
        &mut shard,
        "if",
        text(&format!(
            "!cancelled() && needs.select.result == 'success' && ({condition})"
        )),
    );
    let mut late = vec![run("fuzz-setup-required", "false", 1)];
    set(
        &mut late[0],
        "if",
        text("needs.fuzz-setup.result != 'success'"),
    );
    // Keep the selected checkout and exact source-identity artifact. The setup
    // artifact supplies only the current tool and pinned native fuzz executable.
    late.extend(
        prefix
            .iter()
            .filter(|step| {
                field(step, "uses").starts_with("actions/checkout@")
                    || step["with"]["artifact-ids"].as_str()
                        == Some("${{ needs.select.outputs.selection-artifact-id }}")
                    || field(step, "run").starts_with("rustup toolchain install ")
            })
            .cloned(),
    );
    late.push(object(&[
        ("id", text("fuzz-setup-download")),
        ("uses", text(DOWNLOAD)),
        ("timeout-minutes", Value::Number(5.into())),
        (
            "with",
            object(&[
                (
                    "artifact-ids",
                    text("${{ needs.fuzz-setup.outputs.artifact-id }}"),
                ),
                ("path", text("target/ci/release-fuzz-download")),
                ("digest-mismatch", text("error")),
            ]),
        ),
    ]));
    late.push(run(
        "fuzz-setup-extract",
        "tar -xzf target/ci/release-fuzz-download/release-fuzz-setup.tar.gz -C .",
        3,
    ));
    late.push(run(
        "fuzz-setup-check",
        "./.release/tool/memcordon-ci ci preparation-tools check --kind release-fuzz",
        5,
    ));
    for (recipe, id) in [
        ("workspace-fetch", "shard-workspace-fetch"),
        ("fuzz-fetch", "shard-fuzz-fetch"),
    ] {
        late.extend(adapters::segment_steps(
            object(&[]),
            recipe,
            1,
            false,
            false,
            id,
        )?);
    }
    late.extend_from_slice(&all[boundary..]);
    set(&mut shard, "steps", Value::Sequence(late));
    jobs.insert(text("fuzz-setup"), setup);
    jobs.insert(text("fuzz"), shard);
    Ok(())
}

pub(super) fn validate(workflow: &Value) -> Result<()> {
    let jobs = &workflow["jobs"];
    let setup = &jobs["fuzz-setup"];
    let reject =
        || CiError::Message("release fuzz requires exact same-run selected-source setup".into());
    if setup["needs"] != text("select")
        || setup["runs-on"] != text("ubuntu-24.04")
        || setup["strategy"].is_mapping()
        || setup["outputs"]["artifact-id"]
            != text("${{ steps.fuzz-setup-upload.outputs.artifact-id }}")
    {
        return Err(reject());
    }
    let shard = &jobs["fuzz"];
    if shard["needs"] != Value::Sequence(vec![text("select"), text("fuzz-setup")])
        || !field(shard, "if").starts_with("!cancelled() && needs.select.result == 'success'")
    {
        return Err(reject());
    }
    for job in [setup, shard] {
        if job["permissions"]
            .as_mapping()
            .is_some_and(|fields| fields.values().any(|value| value.as_str() == Some("write")))
        {
            return Err(reject());
        }
        let steps = job["steps"].as_sequence().ok_or_else(reject)?;
        if !steps.iter().any(|step| {
            field(step, "uses").starts_with("actions/checkout@")
                && step["with"]["ref"] == text("${{ needs.select.outputs.selected-commit }}")
                && step["with"]["persist-credentials"] == Value::Bool(false)
        }) {
            return Err(reject());
        }
    }
    let early = setup["steps"].as_sequence().ok_or_else(reject)?;
    let prepare = early
        .iter()
        .position(|step| {
            field(step, "run") == "./.release/tool/memcordon-ci ci segment prepare-fuzz"
                && step["continue-on-error"].as_bool() != Some(true)
        })
        .ok_or_else(reject)?;
    let bind=early.iter().position(|step|field(step,"id")=="fuzz-setup-inputs" && field(step,"run")=="./.release/tool/memcordon-ci ci preparation-tools package --kind release-fuzz" && step["if"].is_null() && step["continue-on-error"].as_bool()!=Some(true)).ok_or_else(reject)?;
    let upload = early
        .iter()
        .position(|step| {
            field(step, "id") == "fuzz-setup-upload"
                && field(step, "uses") == UPLOAD
                && step["with"]["path"] == text("target/release-fuzz-setup.tar.gz")
                && step["with"]["if-no-files-found"] == text("error")
                && step["with"]["overwrite"] == Value::Bool(false)
                && step["if"].is_null()
                && step["continue-on-error"].as_bool() != Some(true)
        })
        .ok_or_else(reject)?;
    if !(prepare < bind && bind < upload) {
        return Err(reject());
    }
    let steps = shard["steps"].as_sequence().ok_or_else(reject)?;
    let check = steps
        .iter()
        .position(|step| {
            field(step, "id") == "fuzz-setup-check"
                && field(step, "run")
                    == "./.release/tool/memcordon-ci ci preparation-tools check --kind release-fuzz"
                && !step["continue-on-error"].as_bool().unwrap_or(false)
                && step["if"].is_null()
        })
        .ok_or_else(reject)?;
    let first = steps
        .iter()
        .position(|step| {
            let run = field(step, "run");
            run.ends_with(" ci segment workspace-fetch")
                || run.ends_with(" ci segment fuzz-fetch")
                || run.contains(" ci segment fuzz-compile-quarter-")
        })
        .ok_or_else(reject)?;
    if check >= first
        || !steps.iter().any(|step| {
            field(step, "id") == "fuzz-setup-download"
                && step["with"]["artifact-ids"]
                    == text("${{ needs.fuzz-setup.outputs.artifact-id }}")
                && step["with"]["digest-mismatch"] == text("error")
        })
        || !steps.iter().any(|step| {
            field(step, "id") == "fuzz-setup-required"
                && field(step, "run") == "false"
                && field(step, "if") == "needs.fuzz-setup.result != 'success'"
        })
    {
        return Err(reject());
    }
    Ok(())
}

pub(super) fn project(projected: &mut Mapping, expected: &Value, original: &Value) -> Result<()> {
    let Some(jobs) = projected
        .get_mut(text("jobs"))
        .and_then(Value::as_mapping_mut)
    else {
        return Ok(());
    };
    if !expected["jobs"]["fuzz-setup"].is_mapping() {
        return Ok(());
    }
    for name in ["fuzz", "fuzz-setup"] {
        if jobs.get(text(name)) != Some(&expected["jobs"][name]) {
            return Err(CiError::Message(
                "release fuzz phase differs from the reviewed generated job".into(),
            ));
        }
    }
    jobs.remove(text("fuzz-setup"));
    let mut legacy = original["jobs"]["fuzz"].clone();
    legacy["strategy"]["fail-fast"] = Value::Bool(false);
    jobs.insert(text("fuzz"), legacy);
    Ok(())
}
