//! Current independent Windows fixture work and the native work it complements.
use super::{field, reject, required};
use crate::Result;
use serde_yaml::Value;
use std::collections::BTreeSet;

pub(super) fn validate(document: &Value) -> Result<()> {
    let job = &document["jobs"]["windows-fixture-native"];
    required(job)?;
    if !job.is_mapping()
        || !job["needs"].is_null()
        || field(job, "if") != "github.event.deleted != true"
        || job["runs-on"] != "${{ matrix.runner }}"
    {
        return Err(reject(
            "Windows fixture must remain an independent selected native job",
        ));
    }
    let matrix = &job["strategy"]["matrix"];
    let rows = matrix["include"]
        .as_sequence()
        .ok_or_else(|| reject("Windows fixture host rows absent"))?;
    let expected = BTreeSet::from([
        ("windows-x64", "windows-2025"),
        ("windows-arm64", "windows-11-arm"),
    ]);
    let actual = rows
        .iter()
        .map(|row| (field(row, "id"), field(row, "runner")))
        .collect::<BTreeSet<_>>();
    if matrix.as_mapping().is_none_or(|matrix| matrix.len() != 1)
        || rows.len() != 2
        || actual != expected
        || rows
            .iter()
            .any(|row| row.as_mapping().is_none_or(|row| row.len() != 2))
    {
        return Err(reject("Windows fixture requires both exact native hosts"));
    }
    let steps = job["steps"]
        .as_sequence()
        .ok_or_else(|| reject("Windows fixture steps absent"))?;
    let command = "./target/ci-runtime/current/memcordon-ci.exe ci segment windows-fixture-native";
    let work = steps
        .iter()
        .filter(|step| field(step, "run") == command)
        .collect::<Vec<_>>();
    if work.len() != 1
        || steps
            .iter()
            .filter(|step| field(step, "id") == "windows-fixture-native")
            .count()
            != 1
    {
        return Err(reject("Windows fixture execution missing or duplicated"));
    }
    required(work[0])?;
    if field(work[0], "id") != "windows-fixture-native"
        || field(work[0], "if") != "runner.os == 'Windows'"
        || work[0]["timeout-minutes"].as_u64() != Some(70)
        || steps.iter().any(|step| {
            let command = field(step, "run");
            command.ends_with(" ci segment workspace-fetch")
                || command.contains(" ci segment native-")
        })
    {
        return Err(reject(
            "Windows fixture must retain its narrow required native operation",
        ));
    }
    let native = document["jobs"]["native"]["steps"]
        .as_sequence()
        .ok_or_else(|| reject("workspace native execution absent"))?;
    for (driver, guard) in [
        (
            "./target/ci-runtime/current/memcordon-ci",
            "runner.os != 'Windows'",
        ),
        (
            "./target/ci-runtime/current/memcordon-ci.exe",
            "runner.os == 'Windows'",
        ),
    ] {
        let mut positions = Vec::new();
        for (phase, minutes) in [("native-compile", 35), ("native-execute", 40)] {
            let command = format!("{driver} ci segment {phase}");
            let matches = native
                .iter()
                .enumerate()
                .filter(|(_, step)| field(step, "run") == command)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(reject(
                    "Windows fixture cannot replace workspace native phases",
                ));
            }
            let (index, step) = matches[0];
            required(step)?;
            if field(step, "if") != guard || step["timeout-minutes"].as_u64() != Some(minutes) {
                return Err(reject("workspace native phase guard or cutoff changed"));
            }
            positions.push(index);
        }
        if positions[0] >= positions[1] {
            return Err(reject(
                "workspace native compilation must precede execution",
            ));
        }
    }
    Ok(())
}
