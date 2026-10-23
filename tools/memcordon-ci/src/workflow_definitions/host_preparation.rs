//! Actual readiness-helper preparation, with its current-source driver, moves
//! before native work. Immutable same-run artifacts are not executable caches.
use super::{CiError, Result, text};
use serde_yaml::{Mapping, Value};

const HOSTS: [&str; 6] = [
    "linux-x64",
    "linux-arm64",
    "macos-x64",
    "macos-arm64",
    "windows-x64",
    "windows-arm64",
];
const UPLOAD: &str = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
const DOWNLOAD: &str = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";

fn object(fields: &[(&str, Value)]) -> Value {
    Value::Mapping(
        fields
            .iter()
            .map(|(key, value)| (text(key), value.clone()))
            .collect(),
    )
}
fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or("")
}
fn put(value: &mut Value, name: &str, data: Value) {
    value
        .as_mapping_mut()
        .expect("reviewed job")
        .insert(text(name), data);
}
fn needs(job: &mut Value, predecessor: &str) {
    let mut values = match &job["needs"] {
        Value::String(value) => vec![text(value)],
        Value::Sequence(values) => values.clone(),
        _ => vec![],
    };
    if !values
        .iter()
        .any(|value| value.as_str() == Some(predecessor))
    {
        values.push(text(predecessor));
    }
    put(job, "needs", Value::Sequence(values));
}
fn driver(step: &Value) -> bool {
    field(step, "id").starts_with("driver-")
}
fn tools_command(windows: bool, package: bool) -> &'static str {
    match (windows, package) {
        (false, true) => {
            "./target/ci-runtime/current/memcordon-ci ci preparation-tools package --kind readiness"
        }
        (true, true) => {
            "./target/ci-runtime/current/memcordon-ci.exe ci preparation-tools package --kind readiness"
        }
        (false, false) => {
            "./target/ci-runtime/current/memcordon-ci ci preparation-tools check --kind readiness"
        }
        (true, false) => {
            "./target/ci-runtime/current/memcordon-ci.exe ci preparation-tools check --kind readiness"
        }
    }
}
fn transport(preparation: &str, windows: bool) -> Vec<Value> {
    vec![
        object(&[
            ("id", text("readiness-tools-download")),
            ("uses", text(DOWNLOAD)),
            ("timeout-minutes", Value::from(6)),
            (
                "with",
                object(&[
                    (
                        "artifact-ids",
                        text(&format!(
                            "${{{{ needs.{preparation}.outputs.artifact-id }}}}"
                        )),
                    ),
                    ("path", text(".release/readiness-tools")),
                    ("merge-multiple", Value::Bool(false)),
                    ("digest-mismatch", text("error")),
                ]),
            ),
        ]),
        object(&[
            ("id", text("readiness-tools-extract")),
            ("timeout-minutes", Value::from(15)),
            (
                "run",
                text("tar -xzf .release/readiness-tools/readiness-tools.tar.gz"),
            ),
        ]),
        object(&[
            ("id", text("readiness-tools-check")),
            ("timeout-minutes", Value::from(5)),
            ("run", text(tools_command(windows, false))),
        ]),
    ]
}

pub(super) fn apply(workflow: &mut Value) -> Result<()> {
    let jobs = workflow["jobs"].as_mapping_mut().expect("source jobs");
    for host in HOSTS {
        let native = format!("native-{host}");
        let windows = host.starts_with("windows-");
        let preparation = format!("readiness-tools-{host}");
        let original = jobs
            .get(text(&native))
            .ok_or_else(|| CiError::Message("native helper preparation source missing".into()))?
            .clone();
        let all = original["steps"]
            .as_sequence()
            .expect("native source steps");
        let first = all
            .iter()
            .position(driver)
            .ok_or_else(|| CiError::Message("native helper build missing".into()))?;
        let end = all
            .iter()
            .rposition(|step| field(step, "id").starts_with("driver-workflows-check"))
            .ok_or_else(|| CiError::Message("native helper check missing".into()))?;
        let mut producer = original.clone();
        producer.as_mapping_mut().unwrap().remove(text("outputs"));
        put(
            &mut producer,
            "name",
            text(&format!("Readiness helper / {host}")),
        );
        put(&mut producer, "needs", text("select"));
        let mut early = all[..=end].to_vec();
        early.push(object(&[
            ("id", text("readiness-tools-bind")),
            ("timeout-minutes", Value::from(5)),
            ("run", text(tools_command(windows, true))),
        ]));
        let archive = if windows {
            "tar -czf target/readiness-tools.tar.gz target/ci-runtime/current target/ci-driver-cold/release/consumer-readiness.exe target/ci/release/consumer-readiness.exe target/ci-preparation/readiness.json"
        } else {
            "tar -czf target/readiness-tools.tar.gz target/ci-runtime/current target/ci-driver-cold/release/consumer-readiness target/ci/release/consumer-readiness target/ci-preparation/readiness.json"
        };
        early.push(object(&[
            ("id", text("readiness-tools-package")),
            ("timeout-minutes", Value::from(5)),
            ("run", text(archive)),
        ]));
        early.push(object(&[("id",text("readiness-tools-upload")),("uses",text(UPLOAD)),("timeout-minutes",Value::from(6)),("with",object(&[("name",text(&format!("readiness-tools-{host}-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}"))),("path",text("target/readiness-tools.tar.gz")),("if-no-files-found",text("error")),("overwrite",Value::Bool(false))]))]));
        put(&mut producer, "steps", Value::Sequence(early));
        put(
            &mut producer,
            "outputs",
            object(&[(
                "artifact-id",
                text("${{ steps.readiness-tools-upload.outputs.artifact-id }}"),
            )]),
        );
        jobs.insert(text(&preparation), producer);
        let consumers = jobs
            .keys()
            .filter_map(Value::as_str)
            .filter(|name| {
                *name == native
                    || name.starts_with(&format!("candidate-{host}-"))
                    || name.starts_with(&format!("installed-{host}-"))
            })
            .map(str::to_owned)
            .collect::<Vec<_>>();
        for consumer in consumers {
            let job = jobs.get_mut(text(&consumer)).expect("reviewed consumer");
            needs(job, &preparation);
            let steps = job["steps"].as_sequence().expect("consumer source");
            let insert = steps.iter().position(driver).unwrap_or(first);
            let mut transformed = Vec::new();
            let mut inserted = false;
            for (index, step) in steps.iter().enumerate() {
                if index == insert {
                    transformed.extend(transport(&preparation, windows));
                    inserted = true;
                }
                if driver(step) {
                    continue;
                }
                let command = field(step, "run");
                if command.starts_with("rustup ")
                    && command.contains(" cargo build ")
                    && command.ends_with("--bin consumer-readiness")
                {
                    continue;
                }
                transformed.push(step.clone());
            }
            if !inserted {
                return Err(CiError::Message("readiness tools insertion missing".into()));
            }
            put(job, "steps", Value::Sequence(transformed));
        }
    }
    Ok(())
}

/// Whole real jobs must equal the reviewed generated graph before legacy
/// policy vocabulary is restored; no dependency or artifact mutation is hidden.
pub(super) fn project(actual: &mut Mapping, expected: &Value, original: &Value) -> Result<()> {
    let jobs = actual
        .get_mut(text("jobs"))
        .and_then(Value::as_mapping_mut)
        .expect("jobs");
    for host in HOSTS {
        let prep = format!("readiness-tools-{host}");
        let native = format!("native-{host}");
        let names = expected["jobs"]
            .as_mapping()
            .expect("expected jobs")
            .keys()
            .filter_map(Value::as_str)
            .filter(|name| {
                *name == prep
                    || *name == native
                    || name.starts_with(&format!("candidate-{host}-"))
                    || name.starts_with(&format!("installed-{host}-"))
            })
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if !jobs.contains_key(text(&prep)) {
            return Err(CiError::Message(
                "required readiness helper preparation missing".into(),
            ));
        }
        for name in names {
            if jobs.get(text(&name)) != expected["jobs"].get(&name) {
                return Err(CiError::Message(format!(
                    "readiness preparation graph differs: {name}"
                )));
            }
            if name == prep {
                jobs.remove(text(&name));
            } else {
                let mut projected = original["jobs"][&name].clone();
                if projected["strategy"]["matrix"].is_mapping() {
                    projected["strategy"]["fail-fast"] = Value::Bool(false);
                }
                jobs.insert(text(&name), projected);
            }
        }
    }
    Ok(())
}

pub(super) fn projected_job(name: &str) -> bool {
    HOSTS.iter().any(|host| {
        name == format!("native-{host}")
            || name.starts_with(&format!("candidate-{host}-"))
            || name.starts_with(&format!("installed-{host}-"))
    })
}

pub(super) fn validate(workflow: &Value) -> Result<()> {
    let jobs = workflow["jobs"]
        .as_mapping()
        .ok_or_else(|| CiError::Message("jobs missing".into()))?;
    for host in HOSTS {
        let prep = format!("readiness-tools-{host}");
        let native = format!("native-{host}");
        if !jobs.contains_key(text(&native)) {
            return Err(CiError::Message("required native producer absent".into()));
        }
        let producer = jobs
            .get(text(&prep))
            .ok_or_else(|| CiError::Message("required helper preparation absent".into()))?;
        if producer["needs"].as_str() != Some("select")
            || producer["permissions"]
                .as_mapping()
                .is_some_and(|permissions| {
                    permissions
                        .values()
                        .any(|permission| permission.as_str() == Some("write"))
                })
        {
            return Err(CiError::Message(
                "helper preparation authority differs".into(),
            ));
        }
        if !producer["steps"].as_sequence().is_some_and(|steps| {
            steps.iter().any(|step| {
                field(step, "run").contains("--bin memcordon-ci --bin consumer-readiness")
                    && step["continue-on-error"].as_bool() != Some(true)
            })
        }) {
            return Err(CiError::Message(
                "actual required readiness helper compilation absent".into(),
            ));
        }
        let producer_steps = producer["steps"]
            .as_sequence()
            .expect("checked producer steps");
        let bind = producer_steps
            .iter()
            .position(|step| field(step, "id") == "readiness-tools-bind")
            .ok_or_else(|| CiError::Message("helper source binding absent".into()))?;
        let upload = producer_steps
            .iter()
            .position(|step| field(step, "id") == "readiness-tools-upload")
            .ok_or_else(|| CiError::Message("helper upload absent".into()))?;
        if bind >= upload
            || field(&producer_steps[bind], "run")
                != tools_command(host.starts_with("windows-"), true)
            || !producer_steps[bind]["if"].is_null()
            || producer_steps[bind]["continue-on-error"].as_bool() == Some(true)
        {
            return Err(CiError::Message(
                "helper source binding must succeed before upload".into(),
            ));
        }
        for (name, job) in jobs {
            let name = name.as_str().unwrap_or("");
            if name != native
                && !name.starts_with(&format!("candidate-{host}-"))
                && !name.starts_with(&format!("installed-{host}-"))
            {
                continue;
            }
            let required = job["needs"]
                .as_sequence()
                .ok_or_else(|| CiError::Message("helper consumer prerequisites absent".into()))?;
            if !required.iter().any(|need| need.as_str() == Some(&prep))
                || (name != native && !required.iter().any(|need| need.as_str() == Some(&native)))
            {
                return Err(CiError::Message(
                    "helper/native success prerequisite missing".into(),
                ));
            }
            let steps = job["steps"]
                .as_sequence()
                .ok_or_else(|| CiError::Message("helper consumer steps absent".into()))?;
            let download = steps
                .iter()
                .find(|step| field(step, "id") == "readiness-tools-download")
                .ok_or_else(|| CiError::Message("helper artifact download absent".into()))?;
            if field(&download["with"], "artifact-ids")
                != format!("${{{{ needs.{prep}.outputs.artifact-id }}}}")
                || field(download, "uses") != DOWNLOAD
                || download["continue-on-error"].as_bool() == Some(true)
            {
                return Err(CiError::Message(
                    "helper artifact must use exact required same-run producer".into(),
                ));
            }
            let check = steps
                .iter()
                .position(|step| field(step, "id") == "readiness-tools-check")
                .ok_or_else(|| CiError::Message("required helper source check absent".into()))?;
            if field(&steps[check], "run") != tools_command(host.starts_with("windows-"), false)
                || !steps[check]["if"].is_null()
                || steps[check]["continue-on-error"].as_bool() == Some(true)
                || steps[..check]
                    .iter()
                    .any(|step| field(step, "run").contains(" release compile-target "))
            {
                return Err(CiError::Message(
                    "helper source check must precede selected work".into(),
                ));
            }
        }
    }
    Ok(())
}
