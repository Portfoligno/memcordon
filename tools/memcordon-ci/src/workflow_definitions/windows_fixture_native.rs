//! An independent Windows fixture contract lane, preserving the broad native job.
use super::{LiteralRun, adapters, text};
use crate::{CiError, Result};
use serde_yaml::{Mapping, Value};

fn fail(message: &str) -> CiError {
    CiError::Message(message.into())
}

pub(super) fn apply(document: &mut Value, name: &str) -> Result<()> {
    if name != "ci.yml" {
        return Ok(());
    }
    let base = document["jobs"]["native"].clone();
    let steps = base["steps"]
        .as_sequence()
        .ok_or_else(|| fail("native fixture bootstrap template absent"))?;
    let first_fetch = steps
        .iter()
        .position(|step| step["id"] == "workspace-fetch-request")
        .ok_or_else(|| fail("broad workspace fetch boundary absent"))?;
    let mut selected_steps = steps[..first_fetch].to_vec();
    let work = Value::Mapping(Mapping::from_iter([
        (
            text("name"),
            text("Compile and execute the exact Windows fixture native contract"),
        ),
        (text("timeout-minutes"), Value::Number(70.into())),
        (
            text("run"),
            text(LiteralRun::WindowsFixtureNative.command()),
        ),
    ]));
    selected_steps.extend(adapters::segment_steps(
        work,
        "windows-fixture-native",
        0,
        true,
        false,
        "windows-fixture-native",
    )?);
    let rows = base["strategy"]["matrix"]["include"]
        .as_sequence()
        .ok_or_else(|| fail("native fixture Windows runner rows absent"))?;
    let selected_rows: Vec<_> = rows
        .iter()
        .filter(|row| matches!(row["id"].as_str(), Some("windows-x64" | "windows-arm64")))
        .cloned()
        .collect();
    if selected_rows.len() != 2 {
        return Err(fail(
            "native fixture requires exactly the two original Windows runners",
        ));
    }
    let mut lane = base;
    let fields = lane
        .as_mapping_mut()
        .ok_or_else(|| fail("native fixture job template invalid"))?;
    fields.remove(text("needs"));
    fields.remove(text("outputs"));
    fields.insert(
        text("name"),
        text("Windows fixture native / ${{ matrix.id }}"),
    );
    fields.insert(text("steps"), Value::Sequence(selected_steps));
    lane["strategy"]["matrix"]["include"] = Value::Sequence(selected_rows);
    let minutes = adapters::job_budget_definition(&lane)?.timeout_minutes()?;
    lane["timeout-minutes"] = Value::Number(minutes.into());
    document["jobs"]
        .as_mapping_mut()
        .ok_or_else(|| fail("CI jobs absent"))?
        .insert(text("windows-fixture-native"), lane);
    Ok(())
}

pub(super) fn validate(document: &Value) -> Result<()> {
    if document["name"] != "CI" {
        return Ok(());
    }
    let lane = &document["jobs"]["windows-fixture-native"];
    if !lane.is_mapping()
        || !lane["needs"].is_null()
        || lane["strategy"]["fail-fast"] != false
        || lane["if"] != "github.event.deleted != true"
    {
        return Err(fail(
            "Windows fixture lane must execute independently on both architectures",
        ));
    }
    let rows = lane["strategy"]["matrix"]["include"]
        .as_sequence()
        .ok_or_else(|| fail("Windows fixture runner matrix absent"))?;
    if rows.len() != 2
        || ![
            ("windows-x64", "windows-2025"),
            ("windows-arm64", "windows-11-arm"),
        ]
        .iter()
        .all(|(id, runner)| {
            rows.iter()
                .any(|row| row["id"] == *id && row["runner"] == *runner)
        })
    {
        return Err(fail(
            "Windows fixture lane must retain the original native runner identities",
        ));
    }
    let steps = lane["steps"]
        .as_sequence()
        .ok_or_else(|| fail("Windows fixture steps absent"))?;
    let mut runs = steps
        .iter()
        .filter(|step| step["run"] == LiteralRun::WindowsFixtureNative.command());
    let work = runs
        .next()
        .ok_or_else(|| fail("Windows fixture must execute its exact typed segment"))?;
    if runs.next().is_some()
        || work["continue-on-error"].as_bool().unwrap_or(false)
        || work["if"] != "runner.os == 'Windows'"
        || work["timeout-minutes"].as_u64() != Some(70)
        || steps.iter().any(|step| {
            step["run"].as_str().is_some_and(|command| {
                command.contains(" ci segment native-")
                    || command.ends_with(" ci segment workspace-fetch")
            })
        })
    {
        return Err(fail(
            "Windows fixture execution must be required and exclude broad native work",
        ));
    }
    Ok(())
}
