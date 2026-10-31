//! Independent checks over actual YAML. No renderer equality or restored fact
//! can supply a required work operation or native checkpoint here.
use super::text;
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

fn dependencies(job: &Value) -> Vec<&str> {
    match &job["needs"] {
        Value::String(name) => vec![name],
        Value::Sequence(names) => names.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    }
}

fn requires(document: &Value, owner: &str, predecessors: &[&str]) -> Result<()> {
    let job = &document["jobs"][owner];
    if !job.is_mapping()
        || predecessors
            .iter()
            .any(|name| !dependencies(job).contains(name))
    {
        return Err(reject("required actual workflow dependency absent"));
    }
    Ok(())
}

fn operation<'a>(document: &'a Value, owner: &str, command: &str) -> Result<&'a Value> {
    let steps = document["jobs"][owner]["steps"]
        .as_sequence()
        .ok_or_else(|| reject("required actual operation steps absent"))?;
    let selected = steps
        .iter()
        .filter(|step| field(step, "run") == command)
        .collect::<Vec<_>>();
    if selected.len() != 1 {
        return Err(reject("required actual operation missing or duplicated"));
    }
    required(selected[0])?;
    if !selected[0]["if"].is_null() {
        return Err(reject(
            "required direct test must execute unconditionally after setup",
        ));
    }
    Ok(selected[0])
}

fn private_command_index(steps: &[Value], command: &str) -> Result<usize> {
    let matches = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| field(step, "run") == command)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(reject("private phase operation missing or duplicated"));
    }
    Ok(matches[0])
}

fn private_segment_index(steps: &[Value], command: &str, minutes: u64) -> Result<usize> {
    let index = private_command_index(steps, command)?;
    let step = &steps[index];
    required(step)?;
    if field(step, "if") != "runner.os != 'Windows'"
        || step["timeout-minutes"].as_u64() != Some(minutes)
    {
        return Err(reject(
            "private segment lost its required Linux guard or cutoff",
        ));
    }
    Ok(index)
}

fn validate_private_export(
    document: &Value,
    owner: &str,
    kind: &str,
    artifact: &str,
) -> Result<usize> {
    let (upload_id, tar, tar_command) = match kind {
        "private-driver" => (
            "private-driver-upload",
            "target/ci/private-driver.tar",
            "tar -cf target/ci/private-driver.tar target/ci-runtime/current target/ci-preparation/private-driver.json",
        ),
        "private" => (
            "private-prepared-upload",
            "target/ci/private-prepared.tar",
            "tar -cf target/ci/private-prepared.tar target/ci/private-prepared target/ci-runtime/current target/ci-preparation/private.json",
        ),
        _ => return Err(reject("unknown private executable transport")),
    };
    let job = &document["jobs"][owner];
    let steps = job["steps"]
        .as_sequence()
        .ok_or_else(|| reject("private producer steps absent"))?;
    let package = format!(
        "./target/ci-runtime/current/memcordon-ci ci preparation-tools package --kind {kind}"
    );
    operation(document, owner, &package)?;
    operation(document, owner, tar_command)?;
    let package_index = private_command_index(steps, &package)?;
    let tar_index = private_command_index(steps, tar_command)?;
    let uploads = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| field(step, "id") == upload_id)
        .collect::<Vec<_>>();
    if uploads.len() != 1 {
        return Err(reject("private producer upload missing or duplicated"));
    }
    let (upload_index, upload) = uploads[0];
    required(upload)?;
    if package_index >= tar_index
        || tar_index >= upload_index
        || !upload["if"].is_null()
        || !field(upload, "uses").starts_with("actions/upload-artifact@")
        || upload["with"]["name"] != artifact
        || upload["with"]["path"] != tar
        || upload["with"]["if-no-files-found"] != "error"
        || upload["with"]["include-hidden-files"] != true
        || job["outputs"]["artifact-id"]
            != format!("${{{{ steps.{upload_id}.outputs.artifact-id }}}}")
    {
        return Err(reject(
            "private producer must package and expose its exact native inputs",
        ));
    }
    Ok(package_index)
}

fn validate_private_input(
    document: &Value,
    owner: &str,
    predecessor: &str,
    kind: &str,
) -> Result<usize> {
    requires(document, owner, &[predecessor])?;
    let job = &document["jobs"][owner];
    if dependencies(job) != [predecessor] {
        return Err(reject(
            "private phase must depend only on its exact input producer",
        ));
    }
    let (destination, extraction, segment, minutes) = match kind {
        "private-driver" => (
            "target/ci/private-driver-transfer",
            "tar -xf target/ci/private-driver-transfer/private-driver.tar",
            "./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private-prepare",
            190,
        ),
        "private" => (
            "target/ci/private-transfer",
            "tar -xf target/ci/private-transfer/private-prepared.tar",
            "./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private-runtime",
            195,
        ),
        _ => return Err(reject("unknown private executable transport")),
    };
    let steps = job["steps"]
        .as_sequence()
        .ok_or_else(|| reject("private consumer steps absent"))?;
    let downloads = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| !step["with"]["artifact-ids"].is_null())
        .collect::<Vec<_>>();
    if downloads.len() != 1 {
        return Err(reject(
            "private phase exact artifact acquisition missing or duplicated",
        ));
    }
    let (download_index, download) = downloads[0];
    required(download)?;
    if !download["if"].is_null()
        || !field(download, "uses").starts_with("actions/download-artifact@")
        || download["with"]["artifact-ids"]
            != format!("${{{{ needs.{predecessor}.outputs.artifact-id }}}}")
        || download["with"]["path"] != destination
        || download["with"]["digest-mismatch"] != "error"
        || !download["with"]["name"].is_null()
    {
        return Err(reject(
            "private phase must acquire its exact same-host artifact",
        ));
    }
    let check = format!(
        "./target/ci-runtime/current/memcordon-ci ci preparation-tools check --kind {kind}"
    );
    operation(document, owner, extraction)?;
    operation(document, owner, &check)?;
    let extraction_index = private_command_index(steps, extraction)?;
    let check_index = private_command_index(steps, &check)?;
    let fetch_index = private_segment_index(
        steps,
        "./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch",
        25,
    )?;
    let segment_index = private_segment_index(steps, segment, minutes)?;
    if !(download_index < extraction_index
        && extraction_index < check_index
        && check_index < fetch_index
        && fetch_index < segment_index)
        || steps[..check_index]
            .iter()
            .any(|step| field(step, "run").contains("memcordon-ci"))
        || steps.iter().any(|step| {
            let command = field(step, "run");
            command.contains(" ci driver-")
                || command.contains("--target-dir target/ci-driver-cold")
        })
    {
        return Err(reject(
            "private consumer must validate transported inputs before real work",
        ));
    }
    Ok(segment_index)
}

fn validate_private_phases(document: &Value) -> Result<()> {
    for (arch, runner, runtime) in [
        ("x64", "ubuntu-24.04", "private-linux"),
        ("arm64", "ubuntu-24.04-arm", "private-linux-arm64"),
    ] {
        let host = format!("linux-{arch}");
        let tools = format!("private-linux-tools-{arch}");
        let prepare = format!("private-linux-prepare-{arch}");
        let mut row = serde_yaml::Mapping::new();
        row.insert(text("id"), text(&host));
        row.insert(text("runner"), text(runner));
        let expected = Value::Sequence(vec![Value::Mapping(row)]);
        for owner in [tools.as_str(), prepare.as_str(), runtime] {
            let job = &document["jobs"][owner];
            required(job)?;
            let matrix = &job["strategy"]["matrix"];
            if matrix.as_mapping().is_none_or(|matrix| matrix.len() != 1)
                || matrix["include"] != expected
                || job["runs-on"] != "${{ matrix.runner }}"
                || job["if"] != "github.event.deleted != true"
            {
                return Err(reject(
                    "private phases must retain their exact native host and source gate",
                ));
            }
        }
        if !document["jobs"][&tools]["needs"].is_null() {
            return Err(reject(
                "private tools must remain an independent prerequisite",
            ));
        }
        validate_private_export(
            document,
            &tools,
            "private-driver",
            &format!("private-driver-{host}"),
        )?;
        let prepared = validate_private_input(document, &prepare, &tools, "private-driver")?;
        let packaged = validate_private_export(
            document,
            &prepare,
            "private",
            &format!("private-prepared-{host}"),
        )?;
        if prepared >= packaged {
            return Err(reject("private payload must be prepared before packaging"));
        }
        validate_private_input(document, runtime, &prepare, "private")?;
    }
    Ok(())
}

fn validate_current_graph(document: &Value) -> Result<()> {
    let jobs = document["jobs"]
        .as_mapping()
        .ok_or_else(|| reject("workflow jobs absent"))?;
    for (name, job) in jobs {
        if job["strategy"]["matrix"].is_mapping()
            && job["strategy"]["fail-fast"].as_bool() != Some(false)
        {
            return Err(reject("matrix peers must retain independent execution"));
        }
        for predecessor in dependencies(job) {
            if !jobs.contains_key(text(predecessor)) || name.as_str() == Some(predecessor) {
                return Err(reject("dangling workflow dependency"));
            }
        }
        let steps = job["steps"]
            .as_sequence()
            .ok_or_else(|| reject("workflow steps absent"))?;
        let ids = steps
            .iter()
            .filter_map(|step| step["id"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if ids.len() != steps.iter().filter(|step| step["id"].is_string()).count() {
            return Err(reject("workflow step identifiers must be unique"));
        }
        for step in steps {
            let run = field(step, "run");
            if run.contains(" release compile-target ")
                || run.contains(" release validate-package ")
                || field(step, "id") == "test-tools-check"
            {
                required(step)?;
                let expected_guard = if run.contains("memcordon-ci.exe") {
                    "runner.os == 'Windows'"
                } else {
                    "runner.os != 'Windows'"
                };
                if if field(step, "id") == "test-tools-check" {
                    !step["if"].is_null()
                } else {
                    !step["if"].is_null() && field(step, "if") != expected_guard
                } {
                    return Err(reject(
                        "native validation must follow required setup success",
                    ));
                }
            }
        }
        if let Some(index) = steps
            .iter()
            .position(|step| field(step, "id") == "test-tools-download")
        {
            let initial = &steps[index];
            let retry = steps
                .get(index + 1)
                .ok_or_else(|| reject("native tools retry absent"))?;
            let extract = steps
                .get(index + 2)
                .ok_or_else(|| reject("native tools extraction absent"))?;
            if initial["timeout-minutes"].as_u64() != Some(3)
                || retry["timeout-minutes"].as_u64() != Some(3)
                || initial["continue-on-error"].as_bool() != Some(true)
                || !retry["continue-on-error"].is_null()
                || field(retry, "if")
                    != "!cancelled() && steps.test-tools-download.outcome == 'failure'"
                || initial["with"] != retry["with"]
                || initial["uses"] != retry["uses"]
                || field(extract, "id") != "test-tools-extract"
                || !extract["if"].is_null()
            {
                return Err(reject(
                    "native tools require one bounded terminal download retry",
                ));
            }
            if let Some(host) = name.as_str().and_then(|name| name.strip_prefix("native-")) {
                let host = host.strip_prefix("components-").unwrap_or(host);
                let host = host.split("-shard-").next().unwrap_or(host);
                let expected = format!("${{{{ needs.test-tools-{host}.outputs.artifact-id }}}}");
                if initial["with"]["artifact-ids"] != expected {
                    return Err(reject(
                        "native tools must come from the same-host preparation",
                    ));
                }
            }
        }
        let serialized = serde_yaml::to_string(job)?;
        for tail in serialized.split("steps.").skip(1) {
            let reference = tail.split('.').next().unwrap_or_default();
            if !ids.contains(reference) {
                return Err(CiError::Message(format!(
                    "dangling generated step reference in {}/{name:?}: steps.{reference}",
                    field(document, "name")
                )));
            }
        }
        if serialized.contains("consumer-readiness")
            || serialized.contains("readiness-upload")
            || serialized.contains("native-coverage-plan")
            || serialized.contains("native-coverage-shard")
            || serialized.contains("producer-manifest.json")
            || serialized.contains("aggregate-macos")
        {
            return Err(reject("retired CI evidence interface is forbidden"));
        }
        if job["timeout-minutes"]
            .as_u64()
            .is_none_or(|minutes| minutes == 0 || minutes > 360)
        {
            return Err(reject("job requires a finite hosted-runner timeout"));
        }
    }
    if matches!(document["name"].as_str(), Some("CI" | "Release")) {
        let release = document["name"] == "Release";
        for leaf in [
            if release {
                "source-docs"
            } else {
                "quality-docs"
            },
            "supply-chain-audit",
            "supply-chain-deny",
        ] {
            let job = &document["jobs"][leaf];
            if !job.is_mapping()
                || dependencies(job) != if release { vec!["select"] } else { vec![] }
            {
                return Err(reject(
                    "quality and security leaves must remain independent",
                ));
            }
        }
        if jobs.contains_key(text("supply-chain")) {
            return Err(reject(
                "combined security cannot replace required independent leaves",
            ));
        }
        if release {
            requires(
                document,
                "assemble",
                &["source-docs", "supply-chain-audit", "supply-chain-deny"],
            )?;
        }
    }
    if document["name"] == "Native backend tests" {
        validate_private_phases(document)?;
    }
    if document["name"] != "Release" {
        return Ok(());
    }
    for host in [
        "linux-x64",
        "linux-arm64",
        "macos-x64",
        "macos-arm64",
        "windows-x64",
        "windows-arm64",
    ] {
        let tools = format!("test-tools-{host}");
        let native = format!("native-{host}");
        requires(document, &tools, &["select"])?;
        requires(document, &native, &["select", &tools])?;
        if host != "macos-x64" {
            let steps = document["jobs"][&native]["steps"]
                .as_sequence()
                .ok_or_else(|| reject("native steps absent"))?;
            if steps
                .iter()
                .filter(|step| field(step, "run").contains(" release compile-target "))
                .count()
                != 1
            {
                return Err(reject("native target requires its actual compilation"));
            }
        }
        requires(document, "assemble-payload", &[&native])?;
        requires(document, "assemble", &[&native])?;
        let driver = if host.starts_with("windows-") {
            "./target/ci-runtime/current/memcordon-ci.exe"
        } else {
            "./target/ci-runtime/current/memcordon-ci"
        };
        operation(
            document,
            &tools,
            &format!(
                "{driver} release prepare-test-tools --build-source .release/build-source.json"
            ),
        )?;
        if host.starts_with("linux-") || host.starts_with("windows-") {
            let components = format!("native-components-{host}");
            requires(document, &components, &["select", &tools, &native])?;
            let phase = &document["jobs"][&components];
            let producer = &document["jobs"][&native];
            if phase["strategy"] != producer["strategy"]
                || phase["runs-on"] != producer["runs-on"]
                || phase["if"] != producer["if"]
            {
                return Err(reject(
                    "component phase must select its exact payload host and source",
                ));
            }
            let steps = phase["steps"]
                .as_sequence()
                .ok_or_else(|| reject("component phase steps absent"))?;
            let downloads = steps
                .iter()
                .enumerate()
                .filter(|(_, step)| field(step, "id") == "native-payload-download")
                .collect::<Vec<_>>();
            if downloads.len() != 1 {
                return Err(reject(
                    "component native payload acquisition absent or duplicated",
                ));
            }
            let (index, first) = downloads[0];
            let retry = steps
                .get(index + 1)
                .ok_or_else(|| reject("component native payload retry absent"))?;
            let execution = steps
                .iter()
                .position(|step| field(step, "id") == "native-components")
                .ok_or_else(|| reject("component native execution absent"))?;
            if first["with"]["artifact-ids"]
                != format!("${{{{ needs.{native}.outputs.artifact-id }}}}")
                || first["with"]["path"] != ".release/target"
                || first["with"]["digest-mismatch"] != "error"
                || first["with"]["merge-multiple"] != false
                || first["timeout-minutes"].as_u64() != Some(3)
                || first["continue-on-error"].as_bool() != Some(true)
                || !first["if"].is_null()
                || first["with"] != retry["with"]
                || first["uses"] != retry["uses"]
                || retry["timeout-minutes"].as_u64() != Some(3)
                || !retry["continue-on-error"].is_null()
                || field(retry, "id") != "native-payload-download-retry"
                || field(retry, "if")
                    != "!cancelled() && steps.native-payload-download.outcome == 'failure'"
                || execution <= index + 1
            {
                return Err(reject(
                    "component phase requires bounded exact native payload acquisition",
                ));
            }
            for (owner, job) in jobs {
                let Some(owner) = owner.as_str() else {
                    continue;
                };
                if owner != components && dependencies(job).contains(&native.as_str()) {
                    requires(document, owner, &[&components])?;
                }
            }
            operation(
                document,
                &components,
                &format!(
                    "{driver} release test-components --diagnostics target/ci/reports/components"
                ),
            )?;
        } else if document["jobs"][&native]["steps"]
            .as_sequence()
            .is_some_and(|steps| {
                steps
                    .iter()
                    .any(|step| field(step, "run").contains(" release test-components "))
            })
        {
            return Err(reject(
                "macOS cannot select the Linux or Windows component operation",
            ));
        }
        for channel in ["native", "cargo"] {
            let candidate = if host.starts_with("macos-") {
                format!("installed-{host}-{channel}")
            } else {
                format!("candidate-{host}-{channel}")
            };
            requires(
                document,
                &candidate,
                &["select", "packages", &native, &tools],
            )?;
            requires(document, "assemble", &[&candidate])?;
            operation(
                document,
                &candidate,
                &format!(
                    "{driver} release test-installed --delivery candidate-{channel} --target .release/target --packages .release/packages --diagnostics target/ci/reports/installed"
                ),
            )?;
            if !document["jobs"][&candidate]["outputs"].is_null() {
                return Err(reject("installed tests do not export success artifacts"));
            }
            if !host.starts_with("macos-") {
                let public = format!("public-{host}-{channel}");
                requires(
                    document,
                    &public,
                    &[
                        "select",
                        "assemble",
                        "publish",
                        "recovery-inputs",
                        "recovery-publish",
                        &tools,
                    ],
                )?;
                if field(&document["jobs"][&public], "if")
                    != "!cancelled() && (needs.publish.result == 'success' || needs.recovery-publish.result == 'success') && needs.select.outputs.preparation-kind == 'tagged'"
                {
                    return Err(reject(
                        "public delivery requires the successful selected writer",
                    ));
                }
                operation(
                    document,
                    &public,
                    &format!(
                        "{driver} release test-installed --delivery public-{channel} --prepared .release/prepared --diagnostics target/ci/reports/installed"
                    ),
                )?;
            }
        }
    }
    for index in 0..4 {
        let shard = format!("native-macos-x64-shard-{index}");
        requires(document, &shard, &["select", "test-tools-macos-x64"])?;
        requires(document, "assemble", &[&shard])?;
        operation(
            document,
            &shard,
            &format!(
                "./target/ci-runtime/current/memcordon-ci suite native-shard --index {index} --count 4 --profile release"
            ),
        )?;
        if dependencies(&document["jobs"]["assemble-payload"]).contains(&shard.as_str()) {
            return Err(reject(
                "early payload cannot wait for unrelated native shards",
            ));
        }
    }
    operation(
        document,
        "native-macos-x64",
        "./target/ci-runtime/current/memcordon-ci release build-native-payload --build-source .release/build-source.json --runtime-components",
    )?;
    requires(
        document,
        "rehearse",
        &["select", "assemble-payload", "rehearsal-tool"],
    )?;
    requires(document, "assemble", &["assemble-payload", "rehearse"])?;
    requires(
        document,
        "recovery-rehearse",
        &["select", "recovery-inputs", "rehearsal-tool"],
    )?;
    requires(document, "publish", &["select", "assemble", "rehearse"])?;
    requires(
        document,
        "recovery-publish",
        &["select", "recovery-inputs", "recovery-rehearse"],
    )?;
    for writer in ["publish", "recovery-publish"] {
        let condition = field(&document["jobs"][writer], "if");
        if condition.contains("always()")
            || !condition.contains("startsWith(github.ref, 'refs/tags/')")
            || !condition.contains("needs.select.outputs.preparation-kind == 'tagged'")
        {
            return Err(reject("publisher must retain successful tag-only routing"));
        }
        operation(
            document,
            writer,
            "./.release/tool/memcordon-ci release publish",
        )?;
    }
    Ok(())
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
    validate_current_graph(document)?;
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
