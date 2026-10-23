//! One canonical native requirement, independently owned runners, one aggregate.
use super::{LiteralRun, Value, text};
use crate::{CiError, Result};
use serde_yaml::Mapping;

fn fail(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn fields(values: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Mapping(
        values
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
    )
}
fn put(value: &mut Value, key: &str, field: Value) -> Result<()> {
    value
        .as_mapping_mut()
        .ok_or_else(|| fail("native coverage workflow object absent"))?
        .insert(text(key), field);
    Ok(())
}
fn id(step: &Value) -> Option<&str> {
    step["id"].as_str()
}
fn position(steps: &[Value], selected: &str) -> Result<usize> {
    steps
        .iter()
        .position(|step| id(step) == Some(selected))
        .ok_or_else(|| fail("native coverage workflow phase absent"))
}
fn job(base: &Value, needs: &[&str], steps: Vec<Value>) -> Result<Value> {
    let mut job = base.clone();
    put(
        &mut job,
        "needs",
        Value::Sequence(needs.iter().map(|name| text(name)).collect()),
    )?;
    put(&mut job, "steps", Value::Sequence(steps))?;
    Ok(job)
}
fn download(template: &Value, settings: Value) -> Result<Value> {
    let mut step = template.clone();
    let map = step
        .as_mapping_mut()
        .ok_or_else(|| fail("native coverage download template absent"))?;
    map.remove(text("id"));
    map.remove(text("if"));
    map.remove(text("name"));
    put(&mut step, "with", settings)?;
    put(&mut step, "timeout-minutes", Value::Number(6.into()))?;
    Ok(step)
}
fn plan_download(template: &Value) -> Result<Value> {
    download(
        template,
        fields([
            (
                "artifact-ids",
                text("${{ needs.native-macos-x64-plan.outputs.artifact-id }}"),
            ),
            ("path", text(".release")),
            ("merge-multiple", Value::Bool(true)),
            ("digest-mismatch", text("error")),
        ]),
    )
}
fn upload(template: &Value, name: &str, path: &str) -> Result<Value> {
    let mut step = template.clone();
    put(
        &mut step,
        "with",
        fields([
            ("name", text(name)),
            ("path", text(path)),
            ("if-no-files-found", text("error")),
            ("include-hidden-files", Value::Bool(true)),
            ("overwrite", Value::Bool(false)),
        ]),
    )?;
    Ok(step)
}
fn run(name: &str, command: &str, minutes: u64) -> Value {
    fields([
        ("name", text(name)),
        ("run", text(command)),
        ("timeout-minutes", Value::Number(minutes.into())),
    ])
}

pub(super) fn apply(document: &mut Value, name: &str) -> Result<()> {
    if name != "release.yml" {
        return Ok(());
    }
    let jobs = document["jobs"]
        .as_mapping()
        .ok_or_else(|| fail("Release jobs absent"))?;
    let base = jobs
        .get(text("native-macos-x64"))
        .ok_or_else(|| fail("native macOS x64 producer absent"))?
        .clone();
    let steps = base["steps"]
        .as_sequence()
        .ok_or_else(|| fail("native macOS steps absent"))?;
    let request = position(steps, "build-request")?;
    let validation = position(steps, "build-validation")?;
    let payload = position(steps, "payload")?;
    let prefix = &steps[..request];
    let work = &steps[request..validation];
    let tail = &steps[payload..];
    let download_template = steps
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|value| value.starts_with("actions/download-artifact@"))
        })
        .ok_or_else(|| fail("native coverage source-bound transport absent"))?;
    let upload_template = &steps[payload];
    let mut plan_steps = prefix.to_vec();
    plan_steps.push(run(
        "Certify complete native coverage selection",
        LiteralRun::NativeCoveragePlan.command(),
        10,
    ));
    plan_steps.push(upload(
        upload_template,
        "native-coverage-plan-${{ github.run_id }}-${{ github.run_attempt }}",
        ".release/native-coverage-plan.json\n.release/native-coverage-deadline.json\n",
    )?);
    let plan = job(&base, &["select", "readiness-tools-macos-x64"], plan_steps)?;

    let mut product_steps = prefix.to_vec();
    product_steps.push(plan_download(download_template)?);
    for step in work
        .iter()
        .filter(|step| !id(step).is_some_and(|name| name.contains("native-tests-")))
    {
        let mut step = step.clone();
        if id(&step) == Some("build") {
            put(
                &mut step,
                "run",
                text(LiteralRun::NativeCoverageProduct.command()),
            )?;
        }
        product_steps.push(step);
    }
    product_steps.push(upload(
        upload_template,
        "native-product-${{ matrix.target }}-${{ github.run_id }}-${{ github.run_attempt }}",
        ".release/native-product",
    )?);
    product_steps.extend_from_slice(&tail[1..]);
    let product = job(
        &base,
        &[
            "select",
            "readiness-tools-macos-x64",
            "native-macos-x64-plan",
        ],
        product_steps,
    )?;

    let mut shard_jobs = Vec::new();
    for (owner, command, artifact, path) in [
        (
            "native-macos-x64-shard-0",
            LiteralRun::NativeCoverageShard0,
            "native-coverage-${{ matrix.target }}-0-${{ github.run_id }}-${{ github.run_attempt }}",
            ".release/native-coverage/0",
        ),
        (
            "native-macos-x64-shard-1",
            LiteralRun::NativeCoverageShard1,
            "native-coverage-${{ matrix.target }}-1-${{ github.run_id }}-${{ github.run_attempt }}",
            ".release/native-coverage/1",
        ),
        (
            "native-macos-x64-shard-2",
            LiteralRun::NativeCoverageShard2,
            "native-coverage-${{ matrix.target }}-2-${{ github.run_id }}-${{ github.run_attempt }}",
            ".release/native-coverage/2",
        ),
        (
            "native-macos-x64-shard-3",
            LiteralRun::NativeCoverageShard3,
            "native-coverage-${{ matrix.target }}-3-${{ github.run_id }}-${{ github.run_attempt }}",
            ".release/native-coverage/3",
        ),
    ] {
        let mut shard_steps = prefix.to_vec();
        shard_steps.push(plan_download(download_template)?);
        for step in work
            .iter()
            .filter(|step| !id(step).is_some_and(|name| name.contains("product-")))
        {
            let mut step = step.clone();
            if id(&step) == Some("build") {
                put(&mut step, "run", text(command.command()))?;
            }
            shard_steps.push(step);
        }
        shard_steps.push(upload(upload_template, artifact, path)?);
        for step in &tail[1..] {
            let mut step = step.clone();
            if let Some(with) = step
                .as_mapping_mut()
                .and_then(|map| map.get_mut(text("with")))
            {
                put(
                    with,
                    "name",
                    text(
                        "diagnostics-${{ github.job }}-${{ matrix.target }}-${{ github.run_id }}-${{ github.run_attempt }}",
                    ),
                )?;
            }
            shard_steps.push(step);
        }
        let mut shards = job(
            &base,
            &[
                "select",
                "readiness-tools-macos-x64",
                "native-macos-x64-plan",
            ],
            shard_steps,
        )?;
        shards
            .as_mapping_mut()
            .expect("source job mapping")
            .remove(text("outputs"));
        shard_jobs.push((owner, shards));
    }

    let mut aggregate_steps = prefix.to_vec();
    aggregate_steps.push(plan_download(download_template)?);
    aggregate_steps.push(download(
        download_template,
        fields([
            (
                "artifact-ids",
                text("${{ needs.native-macos-x64-product.outputs.artifact-id }}"),
            ),
            ("path", text(".release/native-product")),
            ("merge-multiple", Value::Bool(true)),
            ("digest-mismatch", text("error")),
        ]),
    )?);
    for (artifact, path) in [
        (
            "native-coverage-${{ matrix.target }}-0-${{ github.run_id }}-${{ github.run_attempt }}",
            ".release/native-coverage/0",
        ),
        (
            "native-coverage-${{ matrix.target }}-1-${{ github.run_id }}-${{ github.run_attempt }}",
            ".release/native-coverage/1",
        ),
        (
            "native-coverage-${{ matrix.target }}-2-${{ github.run_id }}-${{ github.run_attempt }}",
            ".release/native-coverage/2",
        ),
        (
            "native-coverage-${{ matrix.target }}-3-${{ github.run_id }}-${{ github.run_attempt }}",
            ".release/native-coverage/3",
        ),
    ] {
        aggregate_steps.push(download(
            download_template,
            fields([
                ("name", text(artifact)),
                ("path", text(path)),
                ("digest-mismatch", text("error")),
            ]),
        )?);
    }
    for step in &steps[validation..] {
        let mut step = step.clone();
        if id(&step) == Some("build-validation") {
            put(
                &mut step,
                "run",
                text(LiteralRun::NativeCoverageAggregate.command()),
            )?;
        }
        aggregate_steps.push(step);
    }
    let aggregate = job(
        &base,
        &[
            "select",
            "readiness-tools-macos-x64",
            "native-macos-x64-plan",
            "native-macos-x64-product",
            "native-macos-x64-shard-0",
            "native-macos-x64-shard-1",
            "native-macos-x64-shard-2",
            "native-macos-x64-shard-3",
        ],
        aggregate_steps,
    )?;
    let mut replacement = Mapping::new();
    for (key, value) in jobs {
        if key.as_str() == Some("native-macos-x64") {
            replacement.insert(text("native-macos-x64-plan"), plan.clone());
            replacement.insert(text("native-macos-x64-product"), product.clone());
            for (owner, shard) in &shard_jobs {
                replacement.insert(text(owner), shard.clone());
            }
            replacement.insert(key.clone(), aggregate.clone());
        } else {
            replacement.insert(key.clone(), value.clone());
        }
    }
    put(document, "jobs", Value::Mapping(replacement))
}
