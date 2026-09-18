//! Validate the managed cache envelope before applying the existing per-suite
//! dependency, scenario, artifact and publication contracts to its payload.
use crate::{CiError, Result};
use serde_yaml::{Mapping, Value};

fn text<'a>(map: &'a Mapping, name: &str) -> Option<&'a str> {
    map.get(Value::from(name)).and_then(Value::as_str)
}
fn fail(message: &str) -> CiError {
    CiError::Message(message.into())
}

const TRACED_PREPARE: &str = "./ci-native-fingerprint.exe --output target/ci/native-inputs.bin --trace-inventory ${{ matrix.inventory-trace }}";
const QUALIFY_VOLUME: &str = "./ci-native-fingerprint.exe --qualify-trace-volume";

fn project_trace_configuration(job: &mut Value) -> Result<bool> {
    let traced = job
        .get("steps")
        .and_then(Value::as_sequence)
        .is_some_and(|steps| {
            steps
                .iter()
                .any(|step| step.get("run").and_then(Value::as_str) == Some(TRACED_PREPARE))
        });
    if !traced {
        return Ok(false);
    }
    let rows = job
        .get_mut("strategy")
        .and_then(|value| value.get_mut("matrix"))
        .and_then(|value| value.get_mut("include"))
        .and_then(Value::as_sequence_mut)
        .ok_or_else(|| {
            fail("inventory tracing requires the reviewed Windows architecture matrix")
        })?;
    if rows.len() != 2 {
        return Err(fail("inventory tracing matrix must contain x64 and arm64"));
    }
    let mut ids = std::collections::BTreeSet::new();
    for row in rows {
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !matches!(id.as_str(), "x64" | "arm64")
            || !ids.insert(id.clone())
            || row.get("inventory-trace").and_then(Value::as_bool) != Some(id == "arm64")
        {
            return Err(fail(
                "inventory tracing is enabled only for the ARM64 matrix entry",
            ));
        }
        row.as_mapping_mut()
            .expect("matrix entry has named fields")
            .remove(Value::from("inventory-trace"));
    }
    Ok(true)
}

pub fn validate_and_project(document: &mut Value) -> Result<()> {
    let Some(jobs) = document.get_mut("jobs").and_then(Value::as_mapping_mut) else {
        return Ok(());
    };
    for job in jobs.values_mut() {
        let traced = project_trace_configuration(job)?;
        let Some(steps) = job.get_mut("steps").and_then(Value::as_sequence_mut) else {
            continue;
        };
        let mut planned = false;
        let mut seed_compiled = false;
        let mut volume_qualified = false;
        let mut audited = false;
        let macos_gate = steps.iter().any(|value| {
            value.get("run").and_then(Value::as_str).is_some_and(|run| {
                run.ends_with("suite macos-deadline") || run.ends_with("suite release-macos")
            })
        });
        for value in steps.iter_mut() {
            let Some(step) = value.as_mapping_mut() else {
                continue;
            };
            if text(step, "run")
                == Some(
                    "rustup run 1.97.1 rustc --edition=2021 tools/ci-native-fingerprint.rs -o ci-native-fingerprint.exe",
                )
            {
                if step.len() != 1 {
                    return Err(fail(
                        "seed compilation must be unconditional and fail closed",
                    ));
                }
                seed_compiled = true;
            }
            if text(step, "run")
                == Some("./ci-native-fingerprint.exe --output target/ci/native-inputs.bin")
                || (traced && text(step, "run") == Some(TRACED_PREPARE))
            {
                if !seed_compiled
                    || (traced && !volume_qualified)
                    || step.len() != 2
                    || text(step, "id") != Some("build-context-prepare")
                {
                    return Err(fail(
                        "build context requires an unconditional freshly compiled seed",
                    ));
                }
                planned = true;
                step.remove(Value::from("id"));
                if traced {
                    step.insert(
                        Value::from("run"),
                        Value::from(
                            "./ci-native-fingerprint.exe --output target/ci/native-inputs.bin",
                        ),
                    );
                }
            }
            if text(step, "run") == Some(QUALIFY_VOLUME) {
                if !traced
                    || !seed_compiled
                    || planned
                    || volume_qualified
                    || step.len() != 3
                    || text(step, "id") != Some("trace-volume-qualification")
                    || text(step, "if") != Some("matrix.inventory-trace")
                {
                    return Err(fail(
                        "trace volume qualification must fail closed after seed compilation and before preparation",
                    ));
                }
                volume_qualified = true;
            }
            if text(step, "run")
                == Some(
                    "./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci audit-build-context --input target/ci/native-inputs.bin",
                )
            {
                if !planned
                    || text(step, "id") != Some("build-context-audit")
                    || text(step, "if")
                        != Some("always() && steps.build-context-prepare.outcome == 'success'")
                {
                    return Err(fail(
                        "managed cache audit must follow successful parent preparation",
                    ));
                }
                audited = true;
            }
            if text(step, "run").is_some_and(|run| {
                run.starts_with(
                    "./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci --build-context",
                )
            }) && text(step, "if").is_some_and(|condition| condition.contains("cache-hit"))
            {
                return Err(fail("cache hits must not skip fresh suite execution"));
            }
            let Some(action) = text(step, "uses").map(str::to_owned) else {
                continue;
            };
            if text(step, "id") == Some("inventory-observation") {
                let with = step
                    .get(Value::from("with"))
                    .and_then(Value::as_mapping)
                    .ok_or_else(|| fail("inventory observation upload settings missing"))?;
                if action != "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
                    || text(step, "if") != Some("always()")
                    || text(with, "path")
                        != Some(if traced {
                            "target/ci/reports/inventory-observation/v1/**/run-start.json\ntarget/ci/reports/inventory-observation/v1/**/phase-*.json\ntarget/ci/reports/inventory-observation/v1/**/inventory-*.json\ntarget/ci/reports/inventory-observation/v1/**/inventory-trace.etl\ntarget/ci/reports/inventory-observation/v1/**/inventory-wpr-*.log\n"
                        } else {
                            "target/ci/reports/inventory-observation/v1/**/run-start.json\ntarget/ci/reports/inventory-observation/v1/**/phase-*.json\ntarget/ci/reports/inventory-observation/v1/**/inventory-*.json\n"
                        })
                {
                    return Err(fail(
                        "inventory evidence upload must preserve bounded bootstrap records only",
                    ));
                }
                continue;
            }
            if !action.starts_with("actions/cache/") {
                continue;
            }
            let condition = text(step, "if").unwrap_or_default().to_owned();
            let Some(with) = step
                .get_mut(Value::from("with"))
                .and_then(Value::as_mapping_mut)
            else {
                continue;
            };
            let paths = text(with, "path").unwrap_or_default().to_owned();
            if paths
                .lines()
                .any(|path| path.starts_with("target/ci/source-home/"))
                && action.starts_with("actions/cache/restore@")
            {
                let key = text(with, "key").ok_or_else(|| fail("source cache key missing"))?;
                let payload = key
                    .strip_prefix("managed-sources-v2-")
                    .ok_or_else(|| fail("source cache requires the isolated-home namespace"))?
                    .to_owned();
                with.insert(Value::from("key"), Value::from(payload));
            }
            if !paths.lines().any(|path| {
                (path.starts_with("target/") || path.ends_with("/target"))
                    && !path.starts_with("target/ci/source-home/")
            }) {
                continue;
            }
            if !planned {
                return Err(fail(
                    "compiled cache requires a fresh controller and validated build context",
                ));
            }
            if paths.lines().any(|path| path == "target/ci")
                && !paths
                    .lines()
                    .any(|path| path == "!target/ci/control-bootstrap")
            {
                return Err(fail(
                    "compiled cache must exclude the running control bootstrap",
                ));
            }
            if paths.lines().any(|path| path == "target/ci")
                && !paths
                    .lines()
                    .any(|path| path == "!target/ci/native-inputs.admission.json")
            {
                return Err(fail("compiled cache must exclude parent admission"));
            }
            if paths
                .lines()
                .any(|path| path == "target/ci/native-inputs.admission.json")
            {
                return Err(fail("parent admission must never be cached"));
            }
            if paths.lines().any(|path| {
                path == "target/ci/control-bootstrap"
                    || path.starts_with("target/ci/control-bootstrap/")
            }) {
                return Err(fail("control bootstrap must never be restored or saved"));
            }
            if with.contains_key(Value::from("restore-keys")) {
                return Err(fail("managed compilation requires exact cache keys"));
            }
            if action.starts_with("actions/cache/restore@") {
                if condition!="steps.build-context-prepare.outcome == 'success'" {return Err(fail("compiled cache restore requires successful parent preparation"));}
                let key = text(with, "key").ok_or_else(|| fail("managed cache key missing"))?;
                let key = key
                    .strip_prefix("managed-v2-")
                    .ok_or_else(|| fail("old compiled cache namespace is forbidden"))?;
                if !key.contains("hashFiles('target/ci/native-inputs.bin'") {
                    return Err(fail("compiled cache must bind the full build context"));
                }
                let payload = if macos_gate {
                    key.to_owned()
                } else {
                    key.replace("hashFiles('target/ci/native-inputs.bin', ", "hashFiles(")
                };
                with.insert(Value::from("key"), Value::from(payload));
            } else if action.starts_with("actions/cache/save@")
                && (!audited || !condition.contains("steps.build-context-audit.outcome == 'success'")
                    || !condition.contains("steps.build-context-prepare.outcome == 'success'")
                    || !condition.contains(".outputs.cache-primary-key != ''")
                    || !condition.contains("github.ref == format('refs/heads/{0}', github.event.repository.default_branch)")) {
                    return Err(fail("compiled cache publication requires a successful audit, nonempty primary key and trusted default branch"));
            }
            if paths.lines().any(|path| path.starts_with('!')) {
                let mut payload = paths
                    .lines()
                    .filter(|path| !path.starts_with('!'))
                    .collect::<Vec<_>>()
                    .join("\n");
                if payload != "target/ci" {
                    payload.push('\n');
                }
                with.insert(Value::from("path"), Value::from(payload));
            }
            if action.starts_with("actions/cache/save@") {
                let payload = condition
                    .split(" && steps.build-context-audit.outcome")
                    .next()
                    .expect("split always has first");
                step.insert(Value::from("if"), Value::from(payload));
            } else if action.starts_with("actions/cache/restore@") {
                step.remove(Value::from("if"));
            }
        }
        // Existing suite policies describe the payload inside the independently
        // validated bootstrap envelope. Keep their exact inventory checks: the
        // only projected-away operations are the three fixed managed controls.
        steps.retain(|value| {
            if value.get("id").and_then(Value::as_str)==Some("inventory-observation") {return false;}
            let Some(run) = value.get("run").and_then(Value::as_str) else { return true; };
            run != QUALIFY_VOLUME && run != "./target/ci/control-bootstrap/ci-bootstrap/memcordon-ci audit-build-context --input target/ci/native-inputs.bin"
                && (macos_gate || !matches!(run,
                    "rustup run 1.97.1 rustc --edition=2021 tools/ci-native-fingerprint.rs -o ci-native-fingerprint.exe" |
                    "./ci-native-fingerprint.exe --output target/ci/native-inputs.bin"))
        });
        if planned && !macos_gate {
            let installers: Vec<_> = steps
                .iter()
                .filter(|value| {
                    value
                        .get("run")
                        .and_then(Value::as_str)
                        .is_some_and(|run| run.starts_with("rustup toolchain install "))
                })
                .cloned()
                .collect();
            steps.retain(|value| {
                !value
                    .get("run")
                    .and_then(Value::as_str)
                    .is_some_and(|run| run.starts_with("rustup toolchain install "))
            });
            let insertion = steps
                .iter()
                .rposition(|value| {
                    value
                        .get("uses")
                        .and_then(Value::as_str)
                        .is_some_and(|uses| uses.starts_with("actions/cache/restore@"))
                })
                .map_or_else(
                    || {
                        steps
                            .iter()
                            .position(|value| value.get("run").is_some())
                            .unwrap_or(steps.len())
                    },
                    |index| index + 1,
                );
            for (offset, installer) in installers.into_iter().enumerate() {
                steps.insert(insertion + offset, installer);
            }
        }
    }
    Ok(())
}
