//! Real private payload production and installed-runtime jobs. No native clock
//! or process-completion record crosses this provider boundary.
use super::text;
use crate::{CiError, Result};
use serde_yaml::Value;

fn node(fields: &[(&str, Value)]) -> Value {
    Value::Mapping(
        fields
            .iter()
            .map(|(key, value)| (text(key), value.clone()))
            .collect(),
    )
}
fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}
fn phase(mut step: Value, prepare: bool) -> Value {
    let command = match (field(&step, "run"), prepare) {
        (
            "./target/ci-runtime/current/memcordon-ci ci cache-requests backend-linux-private",
            true,
        ) => {
            "./target/ci-runtime/current/memcordon-ci ci cache-requests backend-linux-private-prepare"
        }
        ("./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private", true) => {
            "./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private-prepare"
        }
        (
            "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers backend-linux-private",
            true,
        ) => {
            "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers backend-linux-private-prepare"
        }
        (
            "./target/ci-runtime/current/memcordon-ci ci cache-requests backend-linux-private",
            false,
        ) => {
            "./target/ci-runtime/current/memcordon-ci ci cache-requests backend-linux-private-runtime"
        }
        ("./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private", false) => {
            "./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private-runtime"
        }
        (
            "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers backend-linux-private",
            false,
        ) => {
            "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers backend-linux-private-runtime"
        }
        _ => return step,
    };
    step["run"] = text(command);
    if command.contains(" ci segment ") {
        step.as_mapping_mut()
            .unwrap()
            .remove(text("timeout-minutes"));
    }
    step
}
fn includes_slot(step: &Value, slot: &str) -> bool {
    field(step, "id")
        .strip_prefix("private-run-")
        .is_some_and(|id| id.strip_prefix("request-").unwrap_or(id).starts_with(slot))
}

pub(super) fn apply(workflow: &mut Value) -> Result<()> {
    let jobs = workflow["jobs"]
        .as_mapping_mut()
        .ok_or_else(|| CiError::Message("private jobs absent".into()))?;
    let original = jobs
        .get(text("private-linux"))
        .cloned()
        .ok_or_else(|| CiError::Message("private source job absent".into()))?;
    let rows = original["strategy"]["matrix"]["include"]
        .as_sequence()
        .ok_or_else(|| CiError::Message("private source rows absent".into()))?;
    if rows.len() != 2 {
        return Err(CiError::Message("private source rows differ".into()));
    }
    for (index, row) in rows.iter().enumerate() {
        let (prepare_id, runtime_id, artifact_name, artifact_id) = match row["id"].as_str() {
            Some("linux-x64") => (
                "private-linux-prepare-x64",
                "private-linux",
                "private-prepared-linux-x64",
                "${{ needs.private-linux-prepare-x64.outputs.artifact-id }}",
            ),
            Some("linux-arm64") => (
                "private-linux-prepare-arm64",
                "private-linux-arm64",
                "private-prepared-linux-arm64",
                "${{ needs.private-linux-prepare-arm64.outputs.artifact-id }}",
            ),
            _ => return Err(CiError::Message("private source host differs".into())),
        };
        let source_steps = original["steps"].as_sequence().unwrap();
        let mut prepare = original.clone();
        prepare["name"] = text(if index == 0 {
            "Linux private preparation / linux-x64"
        } else {
            "Linux private preparation / linux-arm64"
        });
        prepare["strategy"]["matrix"]["include"] = Value::Sequence(vec![row.clone()]);
        prepare["outputs"] = node(&[(
            "artifact-id",
            text("${{ steps.private-prepared-upload.outputs.artifact-id }}"),
        )]);
        let mut prep_steps = Vec::new();
        for step in source_steps {
            let id = field(step, "id");
            if id.starts_with("workspace-fetch") || includes_slot(step, "private-native-tests-") {
                continue;
            }
            if field(step, "uses") == "./.github/actions/upload-artifact" {
                continue;
            }
            prep_steps.push(phase(step.clone(), true));
        }
        prep_steps.push(node(&[("run",text("./target/ci-runtime/current/memcordon-ci ci preparation-tools package --kind private")),("timeout-minutes",Value::Number(5.into()))]));
        prep_steps.push(node(&[("run",text("tar -cf target/ci/private-prepared.tar target/ci/private-prepared target/ci-runtime/current target/ci-preparation/private.json")),("timeout-minutes",Value::Number(15.into()))]));
        prep_steps.push(node(&[
            ("id", text("private-prepared-upload")),
            (
                "uses",
                text("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"),
            ),
            ("timeout-minutes", Value::Number(6.into())),
            (
                "with",
                node(&[
                    ("name", text(artifact_name)),
                    ("path", text("target/ci/private-prepared.tar")),
                    ("if-no-files-found", text("error")),
                    ("include-hidden-files", Value::Bool(true)),
                ]),
            ),
        ]));
        prepare["steps"] = Value::Sequence(prep_steps);

        let mut runtime = original.clone();
        runtime["needs"] = text(prepare_id);
        runtime["strategy"]["matrix"]["include"] = Value::Sequence(vec![row.clone()]);
        let mut runtime_steps = Vec::new();
        for step in source_steps {
            let id = field(step, "id");
            let command = field(step, "run");
            if id.starts_with("driver-")
                || command.contains("--target-dir target/ci-driver-cold")
                || includes_slot(step, "native-tests-")
                || includes_slot(step, "product-")
            {
                continue;
            }
            if command.starts_with("rustup toolchain install ") {
                runtime_steps.push(step.clone());
                runtime_steps.push(node(&[
                    (
                        "uses",
                        text("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"),
                    ),
                    ("timeout-minutes", Value::Number(6.into())),
                    (
                        "with",
                        node(&[
                            ("artifact-ids", text(artifact_id)),
                            ("path", text("target/ci/private-transfer")),
                            ("digest-mismatch", text("error")),
                        ]),
                    ),
                ]));
                runtime_steps.push(node(&[
                    (
                        "run",
                        text("tar -xf target/ci/private-transfer/private-prepared.tar"),
                    ),
                    ("timeout-minutes", Value::Number(15.into())),
                ]));
                runtime_steps.push(node(&[("run",text("./target/ci-runtime/current/memcordon-ci ci preparation-tools check --kind private")),("timeout-minutes",Value::Number(5.into()))]));
                continue;
            }
            runtime_steps.push(phase(step.clone(), false));
        }
        runtime["steps"] = Value::Sequence(runtime_steps);
        jobs.insert(text(prepare_id), prepare);
        jobs.insert(text(runtime_id), runtime);
    }
    Ok(())
}

/// Restore legacy vocabulary only after comparing the entire actual provider
/// boundary, including all authority, host, artifact and dependency fields.
pub(super) fn project(
    actual: &mut serde_yaml::Mapping,
    expected: &Value,
    original: &Value,
) -> Result<()> {
    let jobs = actual
        .get_mut(text("jobs"))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| CiError::Message("private jobs absent".into()))?;
    for name in [
        "private-linux-prepare-x64",
        "private-linux-prepare-arm64",
        "private-linux",
        "private-linux-arm64",
    ] {
        if jobs.get(text(name)) != expected["jobs"].get(name) {
            return Err(CiError::Message(format!(
                "private preparation graph differs: {name}"
            )));
        }
    }
    for name in [
        "private-linux-prepare-x64",
        "private-linux-prepare-arm64",
        "private-linux-arm64",
    ] {
        jobs.remove(text(name));
    }
    let mut legacy = original["jobs"]["private-linux"].clone();
    legacy["strategy"]["fail-fast"] = Value::Bool(false);
    jobs.insert(text("private-linux"), legacy);
    Ok(())
}

pub(super) fn validate(workflow: &Value) -> Result<()> {
    for (producer, consumer, artifact) in [
        (
            "private-linux-prepare-x64",
            "private-linux",
            "${{ needs.private-linux-prepare-x64.outputs.artifact-id }}",
        ),
        (
            "private-linux-prepare-arm64",
            "private-linux-arm64",
            "${{ needs.private-linux-prepare-arm64.outputs.artifact-id }}",
        ),
    ] {
        let prepared = &workflow["jobs"][producer];
        let runtime = &workflow["jobs"][consumer];
        if runtime["needs"].as_str() != Some(producer)
            || prepared["strategy"]["matrix"] != runtime["strategy"]["matrix"]
            || prepared["strategy"]["matrix"].is_null()
        {
            return Err(CiError::Message(
                "private exact host preparation dependency differs".into(),
            ));
        }
        for (job, recipe) in [
            (prepared, "backend-linux-private-prepare"),
            (runtime, "backend-linux-private-runtime"),
        ] {
            let steps = job["steps"]
                .as_sequence()
                .ok_or_else(|| CiError::Message("private required phase absent".into()))?;
            let work = steps
                .iter()
                .find(|step| {
                    field(step, "run")
                        .split_once(" ci segment ")
                        .map(|(_, operation)| operation)
                        == Some(recipe)
                })
                .ok_or_else(|| CiError::Message("private required operation absent".into()))?;
            if work["continue-on-error"].as_bool() == Some(true)
                || job["permissions"].as_mapping().is_some_and(|permissions| {
                    permissions
                        .values()
                        .any(|value| value.as_str() == Some("write"))
                })
            {
                return Err(CiError::Message(
                    "private phase authority/required status differs".into(),
                ));
            }
        }
        let source = prepared["steps"].as_sequence().unwrap();
        let package=source.iter().position(|step|field(step,"run")=="./target/ci-runtime/current/memcordon-ci ci preparation-tools package --kind private").ok_or_else(||CiError::Message("private source package binding absent".into()))?;
        let upload = source
            .iter()
            .position(|step| field(step, "id") == "private-prepared-upload")
            .ok_or_else(|| CiError::Message("private immutable artifact absent".into()))?;
        if package >= upload
            || !source[package]["if"].is_null()
            || source[package]["continue-on-error"].as_bool() == Some(true)
            || source[upload]["continue-on-error"].as_bool() == Some(true)
        {
            return Err(CiError::Message(
                "private producer binding must precede required upload".into(),
            ));
        }
        let steps = runtime["steps"].as_sequence().unwrap();
        let download = steps
            .iter()
            .position(|step| field(&step["with"], "artifact-ids") == artifact)
            .ok_or_else(|| CiError::Message("private exact artifact id absent".into()))?;
        let check=steps.iter().position(|step|field(step,"run")=="./target/ci-runtime/current/memcordon-ci ci preparation-tools check --kind private").ok_or_else(||CiError::Message("private source check absent".into()))?;
        if download >= check
            || field(&steps[download]["with"], "digest-mismatch") != "error"
            || steps[download]["continue-on-error"].as_bool() == Some(true)
            || !steps[check]["if"].is_null()
            || steps[check]["continue-on-error"].as_bool() == Some(true)
            || steps[..check].iter().any(|step| {
                field(step, "run").contains(" ci cache-requests ")
                    || field(step, "run").contains(" ci segment ")
            })
        {
            return Err(CiError::Message(
                "private source check must precede required runtime".into(),
            ));
        }
    }
    Ok(())
}
