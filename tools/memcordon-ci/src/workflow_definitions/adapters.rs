//! Closed platform adapters. These functions author Actions data; they do not
//! execute a workflow, inspect step outcomes, or interpret executable recipes.
use super::{LiteralRun, invocations::invocation, literal, number, text, translations::translate};
use crate::{CiError, Result};
use serde_yaml::Value;
use std::collections::BTreeSet;

const RESTORE: &str = "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
const SAVE: &str = "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
const NORMAL: &str =
    "github.event_name != 'workflow_dispatch' || inputs.failure-mode != 'collect-all'";
const DIAGNOSTIC: &str =
    "github.event_name == 'workflow_dispatch' && inputs.failure-mode == 'collect-all'";

fn object(fields: &[(&str, Value)]) -> Value {
    Value::Mapping(fields.iter().map(|(k, v)| (text(k), v.clone())).collect())
}
fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or("")
}
fn set(value: &mut Value, name: &str, data: Value) {
    value
        .as_mapping_mut()
        .expect("source step map")
        .insert(text(name), data);
}
fn remove(value: &mut Value, name: &str) {
    value
        .as_mapping_mut()
        .expect("source step map")
        .remove(text(name));
}
fn output(owner: &str, slot: &str, suffix: &str) -> Value {
    text(&format!("${{{{ steps.{owner}.outputs.{slot}-{suffix} }}}}"))
}
fn action(id: &str, restore: bool, condition: String, inputs: Value, timeout: u64) -> Value {
    object(&[
        ("id", text(id)),
        ("if", text(&condition)),
        ("continue-on-error", Value::Bool(true)),
        ("timeout-minutes", Value::Number(timeout.into())),
        ("uses", text(if restore { RESTORE } else { SAVE })),
        ("with", inputs),
    ])
}

/// A class has one producer. Complete and partial classes never share keys.
struct CacheSlot<'a> {
    owner: &'a str,
    name: &'a str,
}
impl CacheSlot<'_> {
    fn restore(&self) -> Value {
        action(
            &format!("{}-{}-restore", self.owner, self.name),
            true,
            format!(
                "steps.{}.outputs.{}-restore == 'true'",
                self.owner, self.name
            ),
            object(&[
                ("key", output(self.owner, self.name, "key")),
                ("path", output(self.owner, self.name, "path")),
                ("restore-keys", output(self.owner, self.name, "prefix")),
            ]),
            2,
        )
    }
    fn retain(&self) -> Vec<Value> {
        let probe = format!("{}-{}-probe", self.owner, self.name);
        let ready = format!(
            "always() && steps.{}.outputs.{}-save == 'true'",
            self.owner, self.name
        );
        let inputs = object(&[
            ("key", output(self.owner, self.name, "key")),
            ("path", output(self.owner, self.name, "path")),
        ]);
        if self.name.ends_with("partial") {
            return vec![action(
                &format!("{}-{}-save", self.owner, self.name),
                false,
                ready,
                inputs,
                2,
            )];
        }
        let mut lookup = inputs.clone();
        set(&mut lookup, "lookup-only", Value::Bool(true));
        vec![
            action(
                &probe,
                true,
                format!(
                    "!cancelled() && steps.{}.outputs.{}-save == 'true'",
                    self.owner, self.name
                ),
                lookup,
                1,
            ),
            action(
                &format!("{}-{}-save", self.owner, self.name),
                false,
                format!("{ready} && steps.{probe}.outputs.cache-hit != 'true'"),
                inputs,
                2,
            ),
        ]
    }
}

fn source_slots() -> Vec<&'static str> {
    vec!["source", "archives-partial", "index-partial"]
}
fn acquires_sources(recipe: &str) -> bool {
    matches!(
        recipe,
        "workspace-fetch"
            | "fuzz-fetch"
            | "prepare-fuzz"
            | "prepare-tools"
            | "miri-setup"
            | "supply-chain"
            | "supply-audit-prepare"
            | "supply-deny-prepare"
            | "supply-audit"
            | "supply-deny"
    )
}
fn tools(recipe: &str) -> &'static [&'static str] {
    match recipe {
        "supply-chain" | "prepare-tools" => &["cargo-audit", "cargo-deny"],
        "supply-audit-prepare" | "supply-audit" => &["cargo-audit"],
        "supply-deny-prepare" | "supply-deny" => &["cargo-deny"],
        "prepare-fuzz" => &["cargo-fuzz"],
        _ => &[],
    }
}
fn compiled_slots(recipe: &str) -> Vec<&'static str> {
    match recipe {
        "native" | "native-compile" => vec!["native-tests"],
        "native-execute" => vec!["auxiliary-profiles"],
        "backend-linux-private" => vec!["native-tests", "product", "private-native-tests"],
        "backend-linux-private-prepare" => vec!["native-tests", "product"],
        "backend-linux-private-runtime" => vec!["private-native-tests"],
        "release-build" | "release-readiness" | "working-windows-prepare" => {
            vec!["native-tests", "product"]
        }
        "policy"
        | "workspace-fetch"
        | "fuzz-fetch"
        | "prepare-miri-components"
        | "miri-setup"
        | "prepare-tools"
        | "prepare-fuzz"
        | "supply-chain"
        | "supply-audit-prepare"
        | "supply-deny-prepare"
        | "supply-audit"
        | "supply-deny"
        | "supply-audit-check"
        | "supply-deny-check"
        | "release-validate-package" => vec![],
        _ => vec!["compiled"],
    }
}
fn segment_recipe(command: &str) -> Option<(&str, u8)> {
    if command
        == "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci/rehearsal-build -p memcordon-ci --bin memcordon-release-rehearsal"
    {
        return Some(("rehearsal-tool-build", 1));
    }
    let (driver, args) = command.split_once(' ')?;
    let path = match driver {
        "./target/ci/release/memcordon-ci" => 0,
        "./.release/tool/memcordon-ci" => 1,
        _ => return None,
    };
    if let Some(suite) = args.strip_prefix("suite ") {
        return Some((suite.split_whitespace().next()?, path));
    }
    if args.starts_with("release build-target ") {
        return Some((
            if args.split_whitespace().any(|s| s == "--consumer-readiness") {
                "release-readiness"
            } else {
                "release-build"
            },
            path,
        ));
    }
    if args == "release working-windows-prepare" {
        return Some(("working-windows-prepare", path));
    }
    match args {
        "ci fetch-downloads --family workspace" => Some(("workspace-fetch", path)),
        "ci fetch-downloads --family fuzz" => Some(("fuzz-fetch", path)),
        "ci prepare-miri-components" => Some(("prepare-miri-components", path)),
        "ci prepare-miri-sysroot" => Some(("miri-setup", path)),
        "ci prepare --profile fuzz --failure-mode stop-after-failure"
        | "ci prepare --profile fuzz --failure-mode collect-all" => Some(("prepare-fuzz", path)),
        "ci prepare --profile tools --failure-mode stop-after-failure"
        | "ci prepare --profile tools --failure-mode collect-all" => Some(("prepare-tools", path)),
        _ => None,
    }
}
fn outer_condition(condition: &str) -> String {
    let condition = condition
        .strip_prefix("${{ ")
        .and_then(|s| s.strip_suffix(" }}"))
        .unwrap_or(condition);
    if condition == NORMAL || condition == DIAGNOSTIC {
        return String::new();
    }
    for suffix in [
        format!(" && ({NORMAL})"),
        format!(" && ({DIAGNOSTIC})"),
        format!(" && {NORMAL}"),
        format!(" && {DIAGNOSTIC}"),
    ] {
        if let Some(outer) = condition.strip_suffix(&suffix) {
            return outer.to_owned();
        }
    }
    condition.to_owned()
}
fn security_invocation(recipe: &str, path: u8, operation: u8) -> Option<Value> {
    let commands = match (recipe, path) {
        ("supply-audit", 0) => [
            "./target/ci-runtime/current/memcordon-ci ci segment supply-audit",
            "./target/ci-runtime/current/memcordon-ci ci cache-requests supply-audit",
            "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers supply-audit",
        ],
        ("supply-audit", 1) => [
            "./.release/tool/memcordon-ci ci segment supply-audit",
            "./.release/tool/memcordon-ci ci cache-requests supply-audit",
            "./.release/tool/memcordon-ci ci cleanup-transfers supply-audit",
        ],
        ("supply-audit", 2) => [
            "./target/ci-runtime/current/memcordon-ci.exe ci segment supply-audit",
            "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests supply-audit",
            "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers supply-audit",
        ],
        ("supply-deny", 0) => [
            "./target/ci-runtime/current/memcordon-ci ci segment supply-deny",
            "./target/ci-runtime/current/memcordon-ci ci cache-requests supply-deny",
            "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers supply-deny",
        ],
        ("supply-deny", 1) => [
            "./.release/tool/memcordon-ci ci segment supply-deny",
            "./.release/tool/memcordon-ci ci cache-requests supply-deny",
            "./.release/tool/memcordon-ci ci cleanup-transfers supply-deny",
        ],
        ("supply-deny", 2) => [
            "./target/ci-runtime/current/memcordon-ci.exe ci segment supply-deny",
            "./target/ci-runtime/current/memcordon-ci.exe ci cache-requests supply-deny",
            "./target/ci-runtime/current/memcordon-ci.exe ci cleanup-transfers supply-deny",
        ],
        _ => return None,
    };
    commands
        .get(usize::from(operation))
        .map(|command| text(command))
}
fn host_guard(outer: &str, windows: bool) -> String {
    let host = if windows {
        "runner.os == 'Windows'"
    } else {
        "runner.os != 'Windows'"
    };
    if outer.is_empty() {
        host.to_owned()
    } else {
        format!("({outer}) && {host}")
    }
}
pub(super) fn segment_steps(
    mut old: Value,
    recipe: &str,
    path: u8,
    windows: bool,
    mixed: bool,
    id: &str,
) -> Result<Vec<Value>> {
    let outer = outer_condition(field(&old, "if"));
    if matches!(recipe, "supply-audit" | "supply-deny") {
        set(&mut old, "timeout-minutes", number("130"));
    }
    let selected_path = if windows { 2 } else { path };
    let suffix = if windows && mixed { "-windows" } else { "" };
    let owner = format!("{id}{suffix}");
    let request = format!("{owner}-request");
    let run = |op| {
        security_invocation(recipe, selected_path, op)
            .or_else(|| invocation(recipe, selected_path, op).map(literal))
            .ok_or_else(|| CiError::Message(format!("unsupported literal segment: {recipe}")))
    };
    let condition = if path == 1 {
        outer
    } else {
        host_guard(&outer, windows)
    };
    if matches!(recipe, "policy" | "prepare-miri-components") {
        set(&mut old, "id", text(&owner));
        set(&mut old, "run", run(0)?);
        remove(&mut old, "if");
        if !condition.is_empty() {
            set(&mut old, "if", text(&condition));
        }
        return Ok(vec![old]);
    }
    let mut ask = object(&[
        ("id", text(&request)),
        ("timeout-minutes", number("5")),
        ("run", run(1)?),
    ]);
    if !condition.is_empty() {
        set(&mut ask, "if", text(&condition));
    }
    let execute_only = recipe.starts_with("fuzz-execute-");
    let mut steps = if execute_only { Vec::new() } else { vec![ask] };
    if acquires_sources(recipe) {
        for slot in source_slots() {
            steps.push(
                CacheSlot {
                    owner: &request,
                    name: slot,
                }
                .restore(),
            );
        }
    }
    for partition in compiled_slots(recipe) {
        if execute_only {
            continue;
        }
        for class in ["complete", "partial"] {
            steps.push(
                CacheSlot {
                    owner: &request,
                    name: &format!("{partition}-{class}"),
                }
                .restore(),
            );
        }
    }
    for tool in tools(recipe) {
        for class in ["image", "source", "complete", "partial"] {
            steps.push(
                CacheSlot {
                    owner: &request,
                    name: &format!("{tool}-{class}"),
                }
                .restore(),
            );
        }
    }
    if recipe == "miri-setup" {
        steps.push(
            CacheSlot {
                owner: &request,
                name: "sysroot",
            }
            .restore(),
        );
    }
    let native_build = matches!(recipe, "release-build" | "release-readiness");
    let translated_native = native_build.then(|| {
        translate(field(&old, "run"), if windows { 1 } else { 0 }).expect("reviewed native build")
    });
    let validation = translated_native.map(|command| {
        super::native_invocations::phase(command.command(), false)
            .expect("reviewed native validation")
    });
    let work_run = if let Some(command) = translated_native {
        set(&mut old, "timeout-minutes", number("115"));
        literal(
            super::native_invocations::phase(command.command(), true)
                .expect("reviewed native compile"),
        )
    } else if matches!(
        recipe,
        "release-build" | "release-readiness" | "working-windows-prepare"
    ) {
        literal(
            translate(field(&old, "run"), if windows { 1 } else { 0 })
                .expect("reviewed source-aware release operation"),
        )
    } else {
        run(0)?
    };
    set(&mut old, "id", text(&owner));
    set(&mut old, "run", work_run);
    remove(&mut old, "if");
    if !condition.is_empty() {
        set(&mut old, "if", text(&condition));
    }
    steps.push(old);
    if acquires_sources(recipe) {
        for slot in ["source-complete", "archives-partial", "index-partial"] {
            steps.extend(
                CacheSlot {
                    owner: &owner,
                    name: slot,
                }
                .retain(),
            );
        }
    }
    for partition in compiled_slots(recipe) {
        for class in ["complete", "partial"] {
            steps.extend(
                CacheSlot {
                    owner: &owner,
                    name: &format!("{partition}-{class}"),
                }
                .retain(),
            );
        }
    }
    for tool in tools(recipe) {
        for class in ["image", "source-complete", "complete", "partial"] {
            steps.extend(
                CacheSlot {
                    owner: &owner,
                    name: &format!("{tool}-{class}"),
                }
                .retain(),
            );
        }
    }
    if recipe == "miri-setup" {
        steps.extend(
            CacheSlot {
                owner: &owner,
                name: "sysroot",
            }
            .retain(),
        );
    }
    let mut cleanup = object(&[
        ("id", text(&format!("{owner}-cleanup"))),
        (
            "if",
            text(&format!("always() && steps.{owner}.outcome != 'skipped'")),
        ),
        ("timeout-minutes", number("2")),
        ("run", run(2)?),
    ]);
    // Missing outcomes must not activate cleanup on the other native host.
    set(
        &mut cleanup,
        "if",
        text(&format!(
            "always() && (steps.{owner}.outcome == 'success' || steps.{owner}.outcome == 'failure')"
        )),
    );
    steps.push(cleanup);
    if let Some(validation) = validation {
        let mut step = object(&[
            ("id", text(&format!("{owner}-validation"))),
            ("timeout-minutes", number("100")),
            ("run", literal(validation)),
        ]);
        // Default success is mandatory even after always() cache/cleanup steps.
        if !condition.is_empty() {
            set(&mut step, "if", text(&condition));
        }
        steps.push(step);
    }
    Ok(steps)
}

fn obsolete_cache_step(step: &Value) -> bool {
    let command = field(step, "run");
    if [
        " ci cache-context ",
        " ci download-cache-context ",
        " ci seed-context ",
        " ci import-cache-snapshot ",
        " ci prepare-restored-cache ",
        " ci cache-snapshot ",
        " ci cleanup-cache-snapshot ",
        " ci miri-cache-context",
        " ci bootstrap-cache-context",
    ]
    .iter()
    .any(|s| command.contains(s))
    {
        return true;
    }
    let uses = field(step, "uses");
    if uses == SAVE {
        return true;
    }
    uses == RESTORE
}

#[derive(Clone, Copy)]
enum DriverOperation {
    Probe,
    ColdBuild,
    Adopt,
    Context,
    Select,
    Build,
    Check,
    CleanupBootstrap,
    CleanupCurrent,
    ImageProbe,
}
fn driver_literal(op: DriverOperation, windows: bool) -> &'static str {
    match (op, windows) {
        (DriverOperation::Probe, false) => {
            "./target/ci-bootstrap-in/memcordon-ci ci driver-bootstrap"
        }
        (DriverOperation::Probe, true) => {
            "./target/ci-bootstrap-in/memcordon-ci.exe ci driver-bootstrap"
        }
        (DriverOperation::ColdBuild, _) => {
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci-driver-cold -p memcordon-ci --bin memcordon-ci"
        }
        (DriverOperation::Adopt, false) => {
            "./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold"
        }
        (DriverOperation::Adopt, true) => {
            "./target/ci-driver-cold/release/memcordon-ci.exe ci driver-adopt-cold"
        }
        (DriverOperation::Context, false) => {
            "./target/ci-runtime/bootstrap/memcordon-ci ci driver-context"
        }
        (DriverOperation::Context, true) => {
            "./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-context"
        }
        (DriverOperation::Select, false) => {
            "./target/ci-runtime/bootstrap/memcordon-ci ci driver-select"
        }
        (DriverOperation::Select, true) => {
            "./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-select"
        }
        (DriverOperation::Build, false) => {
            "./target/ci-runtime/bootstrap/memcordon-ci ci driver-build"
        }
        (DriverOperation::Build, true) => {
            "./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-build"
        }
        (DriverOperation::Check, false) => {
            "./target/ci-runtime/current/memcordon-ci ci workflows --check"
        }
        (DriverOperation::Check, true) => {
            "./target/ci-runtime/current/memcordon-ci.exe ci workflows --check"
        }
        (DriverOperation::CleanupBootstrap, false) => {
            "./target/ci-runtime/bootstrap/memcordon-ci ci driver-cleanup"
        }
        (DriverOperation::CleanupBootstrap, true) => {
            "./target/ci-runtime/bootstrap/memcordon-ci.exe ci driver-cleanup"
        }
        (DriverOperation::CleanupCurrent, false) => {
            "./target/ci-runtime/current/memcordon-ci ci driver-cleanup"
        }
        (DriverOperation::CleanupCurrent, true) => {
            "./target/ci-runtime/current/memcordon-ci.exe ci driver-cleanup"
        }
        (DriverOperation::ImageProbe, false) => {
            "./target/ci-runtime/current/memcordon-ci ci driver-image-probe"
        }
        (DriverOperation::ImageProbe, true) => {
            "./target/ci-runtime/current/memcordon-ci.exe ci driver-image-probe"
        }
    }
}
fn driver_step(
    id: &str,
    op: DriverOperation,
    windows: bool,
    guard: String,
    timeout: u64,
    optional: bool,
) -> Value {
    let mut step = object(&[
        ("id", text(id)),
        ("if", text(&guard)),
        ("timeout-minutes", Value::Number(timeout.into())),
        ("run", text(driver_literal(op, windows))),
    ]);
    if guard.is_empty() {
        remove(&mut step, "if");
    }
    if optional {
        set(&mut step, "continue-on-error", Value::Bool(true));
    }
    step
}
fn driver_retention(owner: &str, cold: bool) -> Vec<Value> {
    let slots: &[&str] = if cold {
        &[
            "bootstrap",
            "source-complete",
            "archives-partial",
            "index-partial",
        ]
    } else {
        &[
            "bootstrap",
            "image",
            "compiled-complete",
            "compiled-partial",
            "source-complete",
            "archives-partial",
            "index-partial",
        ]
    };
    slots
        .iter()
        .flat_map(|name| CacheSlot { owner, name }.retain())
        .collect()
}
fn bootstrap_steps(windows: bool, source_build: Option<&str>) -> Result<Vec<Value>> {
    let suffix = if windows { "-windows" } else { "" };
    let id = |name: &str| format!("driver-{name}{suffix}");
    let probe = id("bootstrap");
    let cold = id("cold-build");
    let adopt = id("cold-adopt");
    let context = id("context");
    let select = id("selection");
    let build = id("managed-build");
    let host = host_guard("", windows);
    let mut steps = Vec::new();
    if source_build.is_none() {
        let cache = id("bootstrap-cache");
        steps.push(action(&cache,true,host.clone(),object(&[("path",text("target/ci-bootstrap-in")),
            ("key",text("mc-ci-bootstrap-v2-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-lookup")),
            ("restore-keys",text("mc-ci-bootstrap-v2-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/driver-bootstrap.toml', 'ci/toolchains.toml') }}-"))]),2));
        steps.push(driver_step(&probe,DriverOperation::Probe,windows,format!("{host} && steps.{cache}.outcome == 'success' && steps.{cache}.outputs.cache-matched-key != ''"),2,true));
        steps.push(driver_step(
            &context,
            DriverOperation::Context,
            windows,
            format!("steps.{probe}.outputs.bootstrap-ready == 'true'"),
            5,
            false,
        ));
        steps.push(
            CacheSlot {
                owner: &context,
                name: "image",
            }
            .restore(),
        );
        steps.push(driver_step(
            &select,
            DriverOperation::Select,
            windows,
            format!("steps.{probe}.outputs.bootstrap-ready == 'true'"),
            4,
            false,
        ));
        for name in [
            "source",
            "archives-partial",
            "index-partial",
            "compiled-complete",
            "compiled-partial",
        ] {
            let mut restore = CacheSlot {
                owner: &context,
                name,
            }
            .restore();
            set(
                &mut restore,
                "if",
                text(&format!(
                    "steps.{select}.outputs.build-required == 'true' && steps.{context}.outputs.{name}-restore == 'true'"
                )),
            );
            steps.push(restore);
        }
        steps.push(driver_step(
            &build,
            DriverOperation::Build,
            windows,
            format!("steps.{select}.outputs.build-required == 'true'"),
            50,
            false,
        ));
        steps.extend(driver_retention(&build, false));
        steps.push(driver_step(&id("managed-cleanup"),DriverOperation::CleanupBootstrap,windows,format!("always() && (steps.{build}.outcome == 'success' || steps.{build}.outcome == 'failure')"),2,false));
    }
    let guard = if source_build.is_some() {
        host.clone()
    } else {
        format!("{host} && steps.{probe}.outputs.bootstrap-ready != 'true'")
    };
    let mut cold_step = driver_step(&cold, DriverOperation::ColdBuild, windows, guard, 30, false);
    if let Some(command) = source_build {
        let literal = translate(command, 2)
            .ok_or_else(|| CiError::Message("unreviewed cold source build".into()))?;
        set(&mut cold_step, "run", super::literal(literal));
    }
    steps.push(cold_step);
    steps.push(driver_step(
        &adopt,
        DriverOperation::Adopt,
        windows,
        format!("steps.{cold}.outcome == 'success'"),
        15,
        false,
    ));
    steps.extend(driver_retention(&adopt, true));
    steps.push(driver_step(
        &id("cold-cleanup"),
        DriverOperation::CleanupCurrent,
        windows,
        format!("always() && steps.{adopt}.outcome == 'success'"),
        2,
        false,
    ));
    steps.push(driver_step(
        &id("workflows-check"),
        DriverOperation::Check,
        windows,
        host,
        2,
        false,
    ));
    Ok(steps)
}

fn selected_hosts(job: &Value) -> Result<Vec<bool>> {
    fn visit(value: &Value, hosts: &mut BTreeSet<bool>) {
        match value {
            Value::String(value) if value.starts_with("windows-") => {
                hosts.insert(true);
            }
            Value::String(value) if value.starts_with("ubuntu-") || value.starts_with("macos-") => {
                hosts.insert(false);
            }
            Value::Sequence(items) => {
                for v in items {
                    visit(v, hosts);
                }
            }
            Value::Mapping(items) => {
                for (_, v) in items {
                    visit(v, hosts);
                }
            }
            _ => (),
        }
    }
    let mut hosts = BTreeSet::new();
    visit(&job["runs-on"], &mut hosts);
    visit(&job["strategy"]["matrix"], &mut hosts);
    if hosts.is_empty() {
        return Err(CiError::Message(
            "unrecognized native runner selection".into(),
        ));
    }
    Ok(hosts.into_iter().collect())
}

fn early_source_checks(workflow: &mut Value, name: &str) -> Result<()> {
    if name != "release.yml" {
        return Ok(());
    }
    for (_, job) in workflow["jobs"].as_mapping_mut().expect("release jobs") {
        let Some(steps) = job["steps"].as_sequence_mut() else {
            continue;
        };
        let verify = steps.iter().position(|step| field(step,"run") == "./.release/tool/memcordon-ci release verify-source --build-source .release/build-source.json");
        if let Some(verify) = verify
            && let Some(fetch) = steps.iter().position(|step| {
                field(step, "run")
                    == "./.release/tool/memcordon-ci ci cache-requests workspace-fetch"
            })
            && verify > fetch
        {
            let check = steps.remove(verify);
            steps.insert(fetch, check);
        }
    }
    let steps = workflow["jobs"]["select"]["steps"]
        .as_sequence_mut()
        .expect("selection steps");
    let mut retention = Vec::new();
    let mut work = Vec::new();
    for mut step in std::mem::take(steps) {
        let id = field(&step, "id");
        if id == "driver-cold-adopt"
            || id.starts_with("driver-cold-adopt-")
            || id == "driver-cold-cleanup"
        {
            if id == "driver-cold-adopt" {
                set(
                    &mut step,
                    "if",
                    text(
                        "!cancelled() && runner.os != 'Windows' && steps.driver-cold-build.outcome == 'success'",
                    ),
                );
            }
            retention.push(step);
            continue;
        }
        let replacement = match field(&step, "run") {
            "./target/ci-runtime/current/memcordon-ci ci workflows --check" => {
                Some("./target/ci-driver-cold/release/memcordon-ci ci workflows --check")
            }
            "./target/ci-runtime/current/memcordon-ci release select-preparation" => {
                Some("./target/ci-driver-cold/release/memcordon-ci release select-preparation")
            }
            "./target/ci-runtime/current/memcordon-ci release check-preparation --build-source .release/build-source.json --consumer-readiness" => {
                Some(
                    "./target/ci-driver-cold/release/memcordon-ci release check-selected-inputs --build-source .release/build-source.json --consumer-readiness",
                )
            }
            "./target/ci-runtime/current/memcordon-ci release publication-tool" => {
                Some("./target/ci-driver-cold/release/memcordon-ci release publication-tool")
            }
            _ => None,
        };
        if let Some(command) = replacement {
            set(&mut step, "run", text(command));
            let minutes = match command {
                "./target/ci-driver-cold/release/memcordon-ci ci workflows --check" => "2",
                "./target/ci-driver-cold/release/memcordon-ci release select-preparation" => "15",
                "./target/ci-driver-cold/release/memcordon-ci release check-selected-inputs --build-source .release/build-source.json --consumer-readiness" => {
                    "20"
                }
                "./target/ci-driver-cold/release/memcordon-ci release publication-tool" => "10",
                _ => unreachable!("finite fresh-source operation"),
            };
            set(&mut step, "timeout-minutes", number(minutes));
        }
        work.push(step);
    }
    let after = work
        .iter()
        .position(|step| field(step, "id") == "tool")
        .ok_or_else(|| CiError::Message("selection tool upload absent".into()))?;
    work.splice(after + 1..after + 1, retention);
    *steps = work;
    Ok(())
}

fn apply_feedback(workflow: &mut Value, name: &str) -> Result<()> {
    let selected = match name {
        "ci.yml" => Some(("policy", "repository-policy", 62)),
        "deep-ci.yml" => Some(("performance-plan", "deep-plan", 12)),
        "backend-certification.yml" => Some(("macos-performance-plan", "backend-plan", 12)),
        _ => None,
    };
    if let Some((owner, feedback, allowance)) = selected {
        let job = &mut workflow["jobs"][owner];
        let steps = job["steps"]
            .as_sequence_mut()
            .expect("feedback owner steps");
        steps.retain(|step| {
            let command = field(step, "run");
            ![
                " ci workflows --check",
                " ci check-workflows",
                " suite policy",
                " ci segment policy",
                " ci cache-requests policy",
                " ci cleanup-transfers policy",
                " ci workflow-scope",
                " ci performance-plan",
            ]
            .iter()
            .any(|suffix| command.ends_with(suffix))
        });
        for step in steps {
            let operation = match field(step, "id") {
                "driver-selection" => "select",
                "driver-managed-build" => "build",
                "driver-cold-adopt" => "adopt",
                _ => continue,
            };
            let command = match (feedback, operation) {
                ("repository-policy", "select") => {
                    "./target/ci-runtime/bootstrap/memcordon-ci ci driver-select --feedback repository-policy"
                }
                ("repository-policy", "build") => {
                    "./target/ci-runtime/bootstrap/memcordon-ci ci driver-build --feedback repository-policy"
                }
                ("repository-policy", "adopt") => {
                    "./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold --feedback repository-policy"
                }
                ("deep-plan", "select") => {
                    "./target/ci-runtime/bootstrap/memcordon-ci ci driver-select --feedback deep-plan"
                }
                ("deep-plan", "build") => {
                    "./target/ci-runtime/bootstrap/memcordon-ci ci driver-build --feedback deep-plan"
                }
                ("deep-plan", "adopt") => {
                    "./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold --feedback deep-plan"
                }
                ("backend-plan", "select") => {
                    "./target/ci-runtime/bootstrap/memcordon-ci ci driver-select --feedback backend-plan"
                }
                ("backend-plan", "build") => {
                    "./target/ci-runtime/bootstrap/memcordon-ci ci driver-build --feedback backend-plan"
                }
                ("backend-plan", "adopt") => {
                    "./target/ci-driver-cold/release/memcordon-ci ci driver-adopt-cold --feedback backend-plan"
                }
                _ => unreachable!("closed feedback route"),
            };
            let original = step["timeout-minutes"].as_u64().expect("driver ceiling");
            set(step, "run", text(command));
            set(
                step,
                "timeout-minutes",
                Value::Number((original + allowance).into()),
            );
        }
        let outputs: &[(&str, &str)] = match feedback {
            "deep-plan" => &[
                ("combined", "stress-combined"),
                ("split", "stress-split"),
                ("has-combined", "stress-has-combined"),
                ("has-split", "stress-has-split"),
                ("standalone-common", "standalone-common"),
            ],
            "backend-plan" => &[
                ("split", "macos-split"),
                ("standalone-common", "standalone-common"),
            ],
            _ => &[],
        };
        for (name, output) in outputs {
            set(
                &mut job["outputs"],
                name,
                text(&format!(
                    "${{{{ steps.driver-selection.outputs.{output} || steps.driver-managed-build.outputs.{output} || steps.driver-cold-adopt.outputs.{output} }}}}"
                )),
            );
        }
    }
    if name == "release.yml" {
        let mut ci = super::original("ci.yml").expect("source CI definition");
        apply(&mut ci, "ci.yml")?;
        let mut policy = ci["jobs"]["policy"].clone();
        policy["steps"]
            .as_sequence_mut()
            .expect("policy steps")
            .retain(|step| field(step, "id") != "public-source-seed-restore");
        set(&mut policy, "name", text("Release source policy"));
        set(
            &mut policy,
            "if",
            text(
                "github.event.deleted != true && (github.event_name != 'workflow_dispatch' || inputs.recovery-mode == 'reprepare')",
            ),
        );
        set(
            &mut policy,
            "permissions",
            object(&[("contents", text("read"))]),
        );
        for step in policy["steps"].as_sequence_mut().expect("policy steps") {
            if field(step, "uses").starts_with("actions/checkout@") {
                set(&mut step["with"], "ref", text("${{ github.sha }}"));
            }
        }
        set(&mut workflow["jobs"], "source-policy", policy);
        let needs = workflow["jobs"]["assemble"]["needs"]
            .as_sequence_mut()
            .expect("assembly dependencies");
        for required in ["source-policy"] {
            if !needs.iter().any(|value| value.as_str() == Some(required)) {
                needs.push(text(required));
            }
        }
    }
    Ok(())
}

pub(super) fn apply(workflow: &mut Value, name: &str) -> Result<()> {
    super::concurrency::apply(workflow, name)?;
    let jobs = workflow["jobs"].as_mapping_mut().expect("source jobs");
    for (job_name, job) in jobs {
        let Some(original_steps) = job["steps"].as_sequence().cloned() else {
            continue;
        };
        // Credential-bearing writers and actual rehearsal execute only immutable
        // prepared artifacts. No executable-cache adapter is admitted there.
        if matches!(
            job_name.as_str(),
            Some(
                "publish"
                    | "recovery-publish"
                    | "rehearse"
                    | "recovery-rehearse"
                    | "recovery-inputs"
                    | "assemble"
                    | "assemble-payload"
                    | "published-consumer"
            )
        ) {
            continue;
        }
        let mut steps = Vec::new();
        let mut seen = BTreeSet::new();
        let hosts = match selected_hosts(job) {
            Ok(hosts) => hosts,
            Err(_)
                if matches!(
                    job_name.as_str(),
                    Some("stress" | "stress-packages" | "stress-lifecycle")
                ) =>
            {
                vec![false, true]
            }
            Err(_)
                if matches!(
                    job_name.as_str(),
                    Some("macos-combined" | "macos-native" | "macos-acceptance")
                ) =>
            {
                vec![false]
            }
            Err(error) => {
                return Err(CiError::Message(format!(
                    "unrecognized runner: {name}/{}: {error:?}",
                    job_name.as_str().unwrap_or("?")
                )));
            }
        };
        let has_multi_bin = original_steps
            .iter()
            .any(|step| field(step, "run").contains("--bin memcordon-ci --bin consumer-readiness"));
        for (index, mut step) in original_steps.iter().cloned().enumerate() {
            if obsolete_cache_step(&step) {
                continue;
            }
            let command = field(&step, "run").to_owned();
            if name == "ci.yml"
                && job_name.as_str() == Some("policy")
                && segment_recipe(&command).is_some_and(|(recipe, _)| recipe == "workspace-fetch")
            {
                continue;
            }
            if field(&step, "uses") == RESTORE {
                set(&mut step, "timeout-minutes", number("2"));
            }
            if command.starts_with("rustup ")
                && command.contains(" cargo build ")
                && command.contains("--bin memcordon-ci")
            {
                let force_source = job_name.as_str() == Some("select")
                    || command.contains("--bin consumer-readiness")
                    || command.contains("--bin memcordon-release-rehearsal");
                for &windows in &hosts {
                    steps.extend(bootstrap_steps(
                        windows,
                        force_source.then_some(command.as_str()),
                    )?);
                }
                continue;
            }
            if let Some((recipe, path)) = segment_recipe(&command) {
                let recipe =
                    super::concurrency::recipe(job_name.as_str().expect("job name"), recipe);
                let recipe = match recipe {
                    "supply-audit-prepare" => "supply-audit",
                    "supply-deny-prepare" => "supply-deny",
                    other => other,
                };
                let outer = outer_condition(field(&step, "if"));
                if !seen.insert((recipe.to_owned(), outer)) {
                    continue;
                }
                let id = if field(&step, "id").is_empty() {
                    format!("segment-{index}")
                } else {
                    field(&step, "id")
                        .trim_end_matches("-diagnostic")
                        .to_owned()
                };
                if path == 1 {
                    steps.extend(segment_steps(step, recipe, path, false, false, &id)?);
                } else {
                    for &windows in &hosts {
                        steps.extend(segment_steps(
                            step.clone(),
                            recipe,
                            path,
                            windows,
                            hosts.len() > 1,
                            &id,
                        )?);
                    }
                }
            } else {
                if command.contains("./target/ci/release/memcordon-ci")
                    || (has_multi_bin
                        && command.starts_with("./target/ci/release/consumer-readiness "))
                {
                    let outer = field(&step, "if").to_owned();
                    let mut windows = step.clone();
                    let readiness = has_multi_bin
                        && command.starts_with("./target/ci/release/consumer-readiness ");
                    set(
                        &mut step,
                        "run",
                        literal(
                            translate(&command, if readiness { 4 } else { 0 })
                                .expect("reviewed current invocation"),
                        ),
                    );
                    set(
                        &mut windows,
                        "run",
                        literal(
                            translate(&command, if readiness { 5 } else { 1 })
                                .expect("reviewed Windows invocation"),
                        ),
                    );
                    set(&mut step, "if", text(&host_guard(&outer, false)));
                    set(&mut windows, "if", text(&host_guard(&outer, true)));
                    if hosts.len() > 1 && !field(&windows, "id").is_empty() {
                        let id = format!("{}-windows", field(&windows, "id"));
                        set(&mut windows, "id", text(&id));
                    }
                    if hosts.contains(&false) {
                        steps.push(step);
                    }
                    if hosts.contains(&true) {
                        steps.push(windows);
                    }
                    continue;
                }
                steps.push(step);
            }
        }
        set(job, "steps", Value::Sequence(steps));
    }
    if name == "deep-ci.yml" {
        split_fuzz(workflow)?;
    }
    if name == "backend-certification.yml" {
        for job_name in ["windows-installed-x64", "windows-installed-arm64"] {
            let steps = workflow["jobs"][job_name]["steps"]
                .as_sequence_mut()
                .expect("installed steps");
            let upload = steps
                .iter()
                .position(|step| field(&step["with"], "path") == "target/ci/windows-installed")
                .ok_or_else(|| CiError::Message("installed diagnostic upload absent".into()))?;
            for (offset, (id, condition, command)) in [
                (
                    "loader-cleanup-native",
                    "always() && matrix.channel == 'native' && runner.os == 'Windows'",
                    LiteralRun::InstalledLoaderCleanupNative,
                ),
                (
                    "loader-cleanup-cargo",
                    "always() && matrix.channel == 'cargo' && runner.os == 'Windows'",
                    LiteralRun::InstalledLoaderCleanupCargo,
                ),
            ]
            .into_iter()
            .enumerate()
            {
                steps.insert(
                    upload + offset,
                    object(&[
                        ("id", text(id)),
                        ("if", text(condition)),
                        ("run", literal(command)),
                    ]),
                );
            }
        }
    }
    if name == "release.yml" {
        super::release_fuzz::apply(workflow)?;
    }
    if name == "release.yml" {
        super::host_preparation::apply(workflow)?;
        // Public Linux producers upload only selected readable copies, never
        // administrative owners or caller-private native execution directories.
        for (job_name, job) in workflow["jobs"].as_mapping_mut().expect("source jobs") {
            if !job_name.as_str().is_some_and(|id| {
                id.starts_with("candidate-linux-") || id.starts_with("public-linux-")
            }) {
                continue;
            }
            let mut sealed = false;
            let mut uploaded = false;
            for step in job["steps"].as_sequence_mut().expect("producer steps") {
                let command = field(step, "run");
                let replacement = if command == LiteralRun::R535.command() {
                    Some(LiteralRun::LinuxProjectedProducerSeal)
                } else if command == LiteralRun::R567.command() {
                    Some(LiteralRun::LinuxProjectedProducerColdSeal)
                } else {
                    None
                };
                if let Some(command) = replacement {
                    set(step, "run", literal(command));
                    sealed = true;
                }
                if field(step, "id") == "readiness-upload" {
                    if field(&step["with"], "path") != ".release/readiness-cell" {
                        return Err(CiError::Message(
                            "Linux producer upload root differs".into(),
                        ));
                    }
                    set(
                        &mut step["with"],
                        "path",
                        text(".release/readiness-cell/producer-packed"),
                    );
                    uploaded = true;
                }
            }
            if !sealed || !uploaded {
                return Err(CiError::Message(
                    "Linux producer projection seal/upload pair absent".into(),
                ));
            }
        }
        // Installed macOS consumers use the consumer branch of the shared
        // readiness steps, whose producer guard requires an explicit empty key.
        for (job_name, job) in workflow["jobs"].as_mapping_mut().expect("source jobs") {
            if job_name
                .as_str()
                .is_some_and(|name| name.starts_with("installed-macos-"))
            {
                for row in job["strategy"]["matrix"]["include"]
                    .as_sequence_mut()
                    .expect("installed macOS matrix")
                {
                    set(row, "producer-job", text(""));
                }
            }
        }
    }
    if name == "backend-certification.yml" {
        super::backend_private::apply(workflow)?;
    }
    early_source_checks(workflow, name)?;
    apply_feedback(workflow, name)?;
    super::source_seed::apply(workflow, name)?;
    apply_budgets(workflow, name)?;
    Ok(())
}

/// A genuine provider boundary: setup finishes before any shard's compilation.
/// This keeps all original workload deadlines within the hosted job ceiling.
fn split_fuzz(workflow: &mut Value) -> Result<()> {
    let jobs = workflow["jobs"].as_mapping_mut().expect("source jobs");
    let mut shard = jobs.get(text("fuzz")).expect("source fuzz job").clone();
    let all = shard["steps"]
        .as_sequence()
        .expect("source fuzz steps")
        .clone();
    let split = all
        .iter()
        .position(|s| field(s, "run").contains(" ci cache-requests fuzz-compile-quarter-"))
        .ok_or_else(|| CiError::Message("fuzz compile boundary missing".into()))?;
    let mut setup = shard.clone();
    remove(&mut setup, "strategy");
    set(&mut setup, "name", text("fuzz setup"));
    let mut early = all[..split].to_vec();
    for step in &mut early {
        if field(step, "uses").starts_with("actions/checkout@") {
            set(&mut step["with"], "ref", text("${{ github.sha }}"));
        }
    }
    // Preparation owns these exact pinned installs inside its original45min
    // envelope; do not repeat the same install as an extra platform phase.
    early.retain(|step| {
        field(step, "run") != "rustup toolchain install nightly-2026-07-31 --profile minimal"
    });
    early.push(object(&[("id",text("fuzz-setup-package")),("timeout-minutes",number("3")),("run",text("tar -czf target/fuzz-setup.tar.gz target/ci-runtime/current target/ci-tools/bin/cargo-fuzz"))]));
    early.push(object(&[
        ("id", text("fuzz-setup-upload")),
        ("timeout-minutes", number("5")),
        (
            "uses",
            text("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"),
        ),
        (
            "with",
            object(&[
                (
                    "name",
                    text("fuzz-setup-${{ github.run_id }}-${{ github.run_attempt }}"),
                ),
                ("path", text("target/fuzz-setup.tar.gz")),
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
    let mut needs = match &shard["needs"] {
        Value::String(name) => vec![text(name)],
        Value::Sequence(values) => values.clone(),
        _ => vec![],
    };
    needs.push(text("fuzz-setup"));
    set(&mut shard, "needs", Value::Sequence(needs));
    let condition = field(&shard, "if").to_owned();
    set(
        &mut shard,
        "if",
        text(&format!(
            "always() && needs.performance-plan.result == 'success' && ({condition})"
        )),
    );
    let mut checkout = all
        .iter()
        .find(|s| field(s, "uses").starts_with("actions/checkout@"))
        .expect("fuzz checkout")
        .clone();
    set(&mut checkout["with"], "ref", text("${{ github.sha }}"));
    let install = all
        .iter()
        .find(|s| field(s, "run") == "rustup toolchain install 1.97.1 --profile minimal")
        .expect("fuzz pinned Rust")
        .clone();
    let mut late = vec![
        object(&[
            ("id", text("fuzz-setup-required")),
            ("if", text("needs.fuzz-setup.result != 'success'")),
            ("timeout-minutes", number("1")),
            ("run", text("false")),
        ]),
        checkout,
        install,
        object(&[
            ("id", text("fuzz-setup-download")),
            ("timeout-minutes", number("5")),
            (
                "uses",
                text("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"),
            ),
            (
                "with",
                object(&[
                    (
                        "artifact-ids",
                        text("${{ needs.fuzz-setup.outputs.artifact-id }}"),
                    ),
                    ("path", text("target/ci/fuzz-setup-download")),
                    ("digest-mismatch", text("error")),
                ]),
            ),
        ]),
        object(&[
            ("id", text("fuzz-setup-extract")),
            ("timeout-minutes", number("3")),
            (
                "run",
                text("tar -xzf target/ci/fuzz-setup-download/fuzz-setup.tar.gz -C ."),
            ),
        ]),
        driver_step(
            "fuzz-current-probe",
            DriverOperation::ImageProbe,
            false,
            String::new(),
            2,
            false,
        ),
        driver_step(
            "fuzz-current-workflows",
            DriverOperation::Check,
            false,
            String::new(),
            2,
            false,
        ),
    ];
    for (recipe, id) in [
        ("workspace-fetch", "shard-workspace-fetch"),
        ("fuzz-fetch", "shard-fuzz-fetch"),
    ] {
        late.extend(segment_steps(
            object(&[("run", text("./target/ci/release/memcordon-ci"))]),
            recipe,
            0,
            false,
            false,
            id,
        )?);
    }
    late.extend_from_slice(&all[split..]);
    set(&mut shard, "steps", Value::Sequence(late));
    jobs.insert(text("fuzz-setup"), setup);
    jobs.insert(text("fuzz"), shard);
    Ok(())
}

pub(super) fn operation_recipe(command: &str) -> Option<&str> {
    if [
        LiteralRun::NativeCoverageShard0,
        LiteralRun::NativeCoverageShard1,
        LiteralRun::NativeCoverageShard2,
        LiteralRun::NativeCoverageShard3,
    ]
    .into_iter()
    .any(|run| run.command() == command)
    {
        return Some("release-readiness");
    }
    if let Some((_, recipe)) = command.split_once(" ci segment ") {
        return Some(recipe);
    }
    if command.contains(" release build-target ") || command.contains(" release compile-target ") {
        return Some(
            if command
                .split_whitespace()
                .any(|s| s == "--consumer-readiness")
            {
                "release-readiness"
            } else {
                "release-build"
            },
        );
    }
    if command.ends_with(" release working-windows-prepare") {
        return Some("working-windows-prepare");
    }
    None
}
/// Only missing bounds with an existing reviewed native/tool counterpart are
/// supplied here. Unknown commands fail generation instead of inheriting an
/// unrelated whole-job planning envelope.
fn reviewed_step_minutes(step: &Value) -> Option<u64> {
    if let Some(minutes) = step["timeout-minutes"]
        .as_u64()
        .filter(|minutes| *minutes > 0)
    {
        return Some(minutes);
    }
    let command = field(step, "run");
    if step["uses"].is_string() {
        return Some(6);
    } // finite action/transport ceiling
    if command.starts_with("rustup toolchain install ") {
        return Some(15);
    } // preparation.rs toolchain owner
    if command == "git config --global core.autocrlf false" || command == "false" {
        return Some(1);
    }
    if command
        == "rustup run 1.97.1 cargo clean --locked --package memcordon-ci --target-dir target"
    {
        return Some(2); // cache_restore.rs selected-package Cargo clean owner:120s
    }
    if command.starts_with("./.release/rehearsal-tool/memcordon-release-rehearsal run ") {
        return Some(60); // retained actual rehearsal-job Actions ceiling; no case deadline changed
    }
    match operation_recipe(command) {
        // Same policy::run inventory/check path as `ci policy`; retain the
        // previously accepted complete policy-job60 ceiling for this sole leaf.
        Some("policy") => Some(60),
        Some("quality-compiler" | "release-quality-compiler" | "quality-documentation") => {
            Some(100)
        } // required90 + optional10
        Some(
            "supply-audit-prepare"
            | "supply-deny-prepare"
            | "supply-audit-check"
            | "supply-deny-check",
        ) => Some(70), // each actual60 + optional10
        Some("workspace-fetch" | "fuzz-fetch") => Some(25), // actual fetch15 + optional10
        Some("rehearsal-tool-build") => Some(40),           // actual compiler30 + optional10
        Some("prepare-miri-components") => Some(45),
        Some("msrv") => Some(100), // suites::run_result original90 + optional10
        Some(recipe @ ("native-compile" | "native-execute" | "native")) => {
            // The shared POSIX command can run on macOS or other native hosts.
            // Its ceiling must cover both modeled allocations.
            // Derive Actions work ceilings from the same finite runtime plan;
            // cache work retains its separate, unchanged10-minute allocation.
            use crate::native_test_plan::{NativePlatform, commands_for_platform};
            let platforms = if command
                .split_whitespace()
                .next()
                .is_some_and(|executable| executable.ends_with(".exe"))
            {
                vec![NativePlatform::Windows]
            } else {
                vec![NativePlatform::MacOs, NativePlatform::Other]
            };
            let work = platforms
                .into_iter()
                .map(|platform| {
                    let plan = commands_for_platform(
                        false,
                        crate::failure_mode::FailureMode::StopAfterFailure,
                        platform,
                    );
                    match recipe {
                        "native-compile" => plan[0].deadline,
                        "native-execute" => plan[1].deadline,
                        _ => plan.iter().map(|command| command.deadline).sum(),
                    }
                })
                .max()
                .expect("native command has at least one supported platform");
            Some(work.as_secs().div_ceil(60) + 10)
        }
        Some("miri-setup") => Some(25), // miri_cache::prepare original15 + optional10
        Some("prepare-tools" | "prepare-fuzz") => Some(55), // preparation original45 + optional10
        Some("stress" | "stress-packages" | "stress-lifecycle") => Some(110), // actual original100 + optional10
        // Newly enforced Actions planning guards from the accepted source
        // estimates, NOT preexisting Rust clocks or a claim that every serial
        // child fits at its maximum. Native child deadlines/scenarios stay.
        Some("macos-deadline") => Some(75),
        Some("backend-macos-watchdog" | "release-macos-native" | "release-macos-acceptance") => {
            Some(120)
        }
        Some("backend-linux-private") => Some(195),
        // New Actions planning guards for actual separate payload production
        // (package30 + native work/cleanup155 + source/IO room) and runtime.
        // Neither introduces a Rust shared clock or changes child deadlines.
        Some("backend-linux-private-prepare") => Some(190),
        Some("backend-linux-private-runtime") => Some(195),
        Some("working-windows-prepare" | "backend-windows-sealed") => Some(150),
        Some("backend-linux-cgroup" | "backend-windows-job") => Some(105),
        Some("quality" | "quality-compile") => Some(100), // actual root90 + optional10
        Some("supply-chain") => Some(70),                 // actual combined root60 + optional10
        Some(recipe)
            if recipe == "miri"
                || recipe.starts_with("miri-")
                || recipe == "fuzz"
                || recipe.starts_with("fuzz-") =>
        {
            Some(70)
        } // suites::run_result original60 + optional10
        _ => super::budget_legacy::reviewed_legacy_minutes(command),
    }
}

#[derive(Clone, PartialEq)]
enum BudgetScalar {
    Text(String),
    Bool(bool),
}
impl BudgetScalar {
    fn truthy(&self) -> bool {
        match self {
            Self::Text(value) => !value.is_empty(),
            Self::Bool(value) => *value,
        }
    }
}

/// Abstract source analysis only. Unknown statuses/outputs remain possible;
/// this never reads actual steps, event JSON or executable-facing environment.
fn budget_guard_value(
    expression: &crate::policy::cache_guard::Expr,
    known: &impl Fn(&str) -> Option<String>,
) -> Option<BudgetScalar> {
    use crate::policy::cache_guard::Expr as E;
    match expression {
        E::Value(name) => known(name).map(BudgetScalar::Text),
        E::Literal(value) => Some(BudgetScalar::Text(value.clone())),
        E::Bool(value) => Some(BudgetScalar::Bool(*value)),
        E::Status(_) => None,
        E::Not(value) => {
            budget_guard_value(value, known).map(|value| BudgetScalar::Bool(!value.truthy()))
        }
        E::Equal(a, b) | E::Unequal(a, b) => {
            let equal = budget_guard_value(a, known)?.eq(&budget_guard_value(b, known)?);
            Some(BudgetScalar::Bool(if matches!(expression, E::Equal(..)) {
                equal
            } else {
                !equal
            }))
        }
        E::And(a, b) | E::Or(a, b) => {
            let a = budget_guard_value(a, known).map(|value| value.truthy());
            let b = budget_guard_value(b, known).map(|value| value.truthy());
            let result = if matches!(expression, E::And(..)) {
                if a == Some(false) || b == Some(false) {
                    Some(false)
                } else if a == Some(true) && b == Some(true) {
                    Some(true)
                } else {
                    None
                }
            } else if a == Some(true) || b == Some(true) {
                Some(true)
            } else if a == Some(false) && b == Some(false) {
                Some(false)
            } else {
                None
            };
            result.map(BudgetScalar::Bool)
        }
    }
}

fn budget_matrix_rows(job: &Value) -> Result<Vec<std::collections::BTreeMap<String, String>>> {
    let mut rows = vec![std::collections::BTreeMap::new()];
    let scalar = |value: &Value| {
        value
            .as_str()
            .map(str::to_owned)
            .or_else(|| value.as_bool().map(|value| value.to_string()))
            .or_else(|| value.as_i64().map(|value| value.to_string()))
    };
    if let Some(matrix) = job["strategy"]["matrix"].as_mapping() {
        for (axis, values) in matrix {
            let Some(axis) = axis
                .as_str()
                .filter(|axis| !matches!(*axis, "include" | "exclude"))
            else {
                continue;
            };
            let Some(values) = values.as_sequence() else {
                continue;
            };
            let mut expanded = Vec::new();
            for row in &rows {
                for value in values {
                    let mut row = row.clone();
                    if let Some(value) = scalar(value) {
                        row.insert(format!("matrix.{axis}"), value);
                    }
                    expanded.push(row);
                }
            }
            rows = expanded;
            if rows.len() > 256 {
                return Err(CiError::Message(
                    "budget matrix exceeds reviewed finite rows".into(),
                ));
            }
        }
        if let Some(include) = job["strategy"]["matrix"]["include"].as_sequence() {
            let axes = rows.first().is_some_and(|row| !row.is_empty());
            if !axes {
                rows.clear();
            }
            for values in include {
                let mut row = std::collections::BTreeMap::new();
                if let Some(values) = values.as_mapping() {
                    for (axis, value) in values {
                        if let (Some(axis), Some(value)) = (axis.as_str(), scalar(value)) {
                            row.insert(format!("matrix.{axis}"), value);
                        }
                    }
                }
                rows.push(row);
            }
        }
    }
    if rows.is_empty() {
        rows.push(Default::default());
    }
    if rows.len() > 256 {
        return Err(CiError::Message(
            "budget matrix exceeds reviewed finite rows".into(),
        ));
    }
    Ok(rows)
}

fn budget_cache_class(step: &Value) -> Option<(String, usize)> {
    if field(step, "uses") != SAVE
        && !(field(step, "uses") == RESTORE && step["with"]["lookup-only"].as_bool() == Some(true))
    {
        return None;
    }
    let key = field(&step["with"], "key")
        .trim()
        .strip_prefix("${{")?
        .strip_suffix("}}")?
        .trim()
        .strip_prefix("steps.")?;
    let (owner, slot) = key.split_once(".outputs.")?;
    let slot = slot.strip_suffix("-key")?;
    if slot == "source-complete" {
        return Some((format!("{owner}:source-archives"), 0));
    }
    if slot == "archives-partial" {
        return Some((format!("{owner}:source-archives"), 1));
    }
    if let Some(slot) = slot.strip_suffix("-complete") {
        return Some((format!("{owner}:{slot}"), 0));
    }
    slot.strip_suffix("-partial")
        .map(|slot| (format!("{owner}:{slot}"), 1))
}

fn budget_producer_field(
    field_name: &str,
    base: &impl Fn(&str) -> Option<String>,
    producers: &std::collections::BTreeMap<&str, &Value>,
    ancestors: &BTreeSet<String>,
) -> Option<String> {
    if let Some(value) = base(field_name) {
        return Some(value);
    }
    let (owner, property) = field_name.strip_prefix("steps.")?.split_once('.')?;
    if (!property.starts_with("outputs.") && property != "outcome")
        || ancestors.len() >= 128
        || ancestors.contains(owner)
    {
        return None;
    }
    let producer = producers.get(owner)?;
    let guard = crate::policy::cache_guard::parse(field(producer, "if")).ok()?;
    let mut ancestors = ancestors.clone();
    ancestors.insert(owner.into());
    let known = |name: &str| budget_producer_field(name, base, producers, &ancestors);
    if budget_guard_value(&guard, &known).is_some_and(|value| !value.truthy()) {
        Some(if property == "outcome" {
            "skipped".into()
        } else {
            String::new()
        })
    } else {
        None
    }
}

fn budget_matrix_is_complete(job: &Value) -> bool {
    fn scalar(value: &Value) -> bool {
        value.as_str().is_some_and(|value| !value.contains("${{"))
            || value.is_bool()
            || value.is_number()
            || value.is_null()
    }
    job["strategy"]["matrix"]
        .as_mapping()
        .is_some_and(|matrix| {
            matrix.iter().all(|(name, value)| {
                let Some(name) = name.as_str() else {
                    return false;
                };
                value.as_sequence().is_some_and(|values| {
                    values.iter().all(|value| {
                        if matches!(name, "include" | "exclude") {
                            value.as_mapping().is_some_and(|row| {
                                row.iter()
                                    .all(|(key, value)| key.is_string() && scalar(value))
                            })
                        } else {
                            scalar(value)
                        }
                    })
                })
            })
        })
}

/// Every emitted run/action participates. Only reviewed matrix/host/driver and
/// complete/partial alternatives are reduced; unknown conditions overestimate.
pub(super) fn job_budget_definition(job: &Value) -> Result<super::budget::JobDefinition> {
    use super::budget::BudgetNode as N;
    let steps = job["steps"]
        .as_sequence()
        .ok_or_else(|| CiError::Message("job budget missing steps".into()))?;
    let has_driver = steps
        .iter()
        .any(|step| field(step, "run").contains(" ci driver-select"));
    let has_native_clock = steps
        .iter()
        .any(|step| field(step, "run").contains(" release compile-target "));
    let producers = steps
        .iter()
        .filter_map(|step| step["id"].as_str().map(|id| (id, step)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let complete_matrix = budget_matrix_is_complete(job);
    let mut branches = Vec::new();
    for (row_index, row) in budget_matrix_rows(job)?.into_iter().enumerate() {
        let runner = job["runs-on"].as_str().unwrap_or("");
        let declared = row
            .values()
            .find(|value| {
                value.starts_with("windows-")
                    || value.starts_with("ubuntu-")
                    || value.starts_with("macos-")
            })
            .map(String::as_str)
            .unwrap_or(runner);
        for host in ["Linux", "macOS", "Windows"] {
            if (declared.starts_with("windows-") && host != "Windows")
                || (declared.starts_with("ubuntu-") && host != "Linux")
                || (declared.starts_with("macos-") && host != "macOS")
            {
                continue;
            }
            for driver in if has_driver {
                &['c', 'm', 'r'][..]
            } else {
                &['c'][..]
            } {
                let base = |field: &str| -> Option<String> {
                    if field == "runner.os" {
                        return Some(host.into());
                    }
                    if let Some(value) = row.get(field) {
                        return (!value.contains("${{")).then(|| value.clone());
                    }
                    if field.starts_with("matrix.") && complete_matrix {
                        return Some(String::new());
                    }
                    if let Some((owner, _)) = field
                        .strip_prefix("steps.")
                        .and_then(|field| field.split_once('.'))
                        && !producers.contains_key(owner)
                    {
                        return None;
                    }
                    for suffix in ["", "-windows"] {
                        let prefix = |owner: &str| format!("steps.driver-{owner}{suffix}.");
                        let active_host = (suffix == "-windows") == (host == "Windows");
                        if !active_host {
                            for owner in [
                                "bootstrap",
                                "selection",
                                "managed-build",
                                "cold-build",
                                "cold-adopt",
                                "context",
                            ] {
                                if let Some(property) = field.strip_prefix(&prefix(owner)) {
                                    return Some(if property == "outcome" {
                                        "skipped".into()
                                    } else {
                                        String::new()
                                    });
                                }
                            }
                        }
                        if let Some(output) = field.strip_prefix(&prefix("bootstrap"))
                            && output == "outputs.bootstrap-ready"
                        {
                            return Some(if *driver == 'c' { "false" } else { "true" }.into());
                        }
                        if let Some(output) = field.strip_prefix(&prefix("selection")) {
                            return match output {
                                "outputs.build-required" => {
                                    Some(if *driver == 'm' { "true" } else { "false" }.into())
                                }
                                "outputs.current-ready" => {
                                    Some(if *driver == 'r' { "true" } else { "false" }.into())
                                }
                                _ => None,
                            };
                        }
                        for (owner, active) in [
                            ("managed-build", *driver == 'm'),
                            ("cold-build", *driver == 'c'),
                            ("cold-adopt", *driver == 'c'),
                            ("context", *driver != 'c'),
                        ] {
                            if let Some(tail) = field.strip_prefix(&prefix(owner)) {
                                if tail == "outcome" {
                                    return if active { None } else { Some("skipped".into()) };
                                }
                                if tail.starts_with("outputs.") && !active {
                                    return Some(String::new());
                                }
                            }
                        }
                    }
                    None
                };
                let known =
                    |name: &str| budget_producer_field(name, &base, &producers, &BTreeSet::new());
                let mut sequential = Vec::new();
                let mut native = Vec::new();
                let mut installed_readiness = Vec::new();
                let mut classes = std::collections::BTreeMap::<String, [Vec<N>; 2]>::new();
                for (index, step) in steps.iter().enumerate() {
                    if let Ok(guard) = crate::policy::cache_guard::parse(field(step, "if"))
                        && budget_guard_value(&guard, &known).is_some_and(|value| !value.truthy())
                    {
                        continue;
                    }
                    let mut minutes = step["timeout-minutes"]
                        .as_u64()
                        .filter(|minutes| *minutes > 0)
                        .ok_or_else(|| {
                            CiError::Message(format!(
                                "budget step missing finite reviewed ceiling: {} {}",
                                field(step, "id"),
                                field(step, "run")
                            ))
                        })?;
                    let label = if field(step, "id").is_empty() {
                        format!("step-{index}")
                    } else {
                        field(step, "id").into()
                    };
                    let command = field(step, "run");
                    // A miss performs only selection. The continuation belongs
                    // to exactly one active-image/build/adoption route.
                    if *driver != 'r' && command.contains(" ci driver-select --feedback ") {
                        minutes = 4;
                    }
                    let node = N::minutes(label, minutes)?;
                    if has_native_clock
                        && (command.contains(" release compile-target ")
                            || command.contains(" release validate-package ")
                            || command.contains(" consumer-readiness-native-components "))
                    {
                        native.push(node);
                        if command.contains(" release compile-target ") {
                            sequential.push(N::minutes(
                                "compiler optional finalization outside original clock",
                                10,
                            )?);
                        }
                    } else if [
                        "/consumer-readiness acquire ",
                        "/consumer-readiness cleanup ",
                        "/consumer-readiness.exe acquire ",
                        "/consumer-readiness.exe cleanup ",
                    ]
                    .iter()
                    .any(|part| command.contains(part))
                    {
                        installed_readiness.push(node);
                    } else if let Some((group, class)) = budget_cache_class(step) {
                        classes.entry(group).or_default()[class].push(node);
                    } else {
                        sequential.push(node);
                    }
                }
                if !native.is_empty() {
                    sequential.push(N::SharedOperation {
                        name: "original native work/cleanup deadline".into(),
                        seconds: 155 * 60,
                        steps: native,
                    });
                }
                if !installed_readiness.is_empty() {
                    sequential.push(N::SharedOperation {
                        name: "original installed acquisition/cleanup deadline".into(),
                        seconds: 150 * 60,
                        steps: installed_readiness,
                    });
                    sequential.push(N::minutes(
                        "installed readiness local input/readback overhead",
                        10,
                    )?);
                }
                for (name, alternatives) in classes {
                    sequential.push(N::Alternatives {
                        name,
                        branches: alternatives
                            .into_iter()
                            .enumerate()
                            .map(|(class, steps)| N::Sequence {
                                name: if class == 0 { "complete" } else { "partial" }.into(),
                                steps,
                            })
                            .collect(),
                    });
                }
                branches.push(N::Sequence {
                    name: format!("matrix-row-{row_index}/{host}/driver-{driver}"),
                    steps: sequential,
                });
            }
        }
    }
    Ok(super::budget::JobDefinition {
        steps: vec![N::Alternatives {
            name: "reviewed emitted job paths".into(),
            branches,
        }],
    })
}

fn apply_budgets(workflow: &mut Value, file: &str) -> Result<()> {
    let mut failures = Vec::new();
    for (name, job) in workflow["jobs"].as_mapping_mut().expect("source jobs") {
        let Some(steps) = job["steps"].as_sequence_mut() else {
            continue;
        };
        for step in steps {
            if !step["timeout-minutes"].is_null() {
                if step["timeout-minutes"]
                    .as_u64()
                    .filter(|minutes| *minutes > 0)
                    .is_none()
                {
                    failures.push(format!(
                        "{file}/{name:?}: invalid finite step ceiling: {} {}",
                        field(step, "id"),
                        field(step, "run")
                    ));
                }
                continue;
            }
            let Some(minutes) = reviewed_step_minutes(step) else {
                failures.push(format!(
                    "{file}/{name:?}: missing reviewed step ceiling: {} {}",
                    field(step, "id"),
                    field(step, "run")
                ));
                continue;
            };
            set(step, "timeout-minutes", Value::Number(minutes.into()));
        }
    }
    // Finish the finite inventory before rejecting; one execution names all
    // unreviewed steps rather than requiring a rebuild for every first miss.
    for (name, job) in workflow["jobs"].as_mapping_mut().expect("source jobs") {
        let Some(steps) = job["steps"].as_sequence() else {
            continue;
        };
        if steps.iter().any(|step| {
            step["timeout-minutes"]
                .as_u64()
                .filter(|minutes| *minutes > 0)
                .is_none()
        }) {
            continue;
        }
        match job_budget_definition(job) {
            Ok(definition) => match definition.timeout_minutes() {
                Ok(minutes) => set(job, "timeout-minutes", Value::Number(minutes.into())),
                Err(error) => {
                    let detail=definition.inventory_breakdown().ok().map(|summary| {
                        let paths=&summary.children[0];
                        let selected=&paths.children[paths.selected_branch.expect("finite alternatives")];
                        let contributions=selected.children.iter().take(128).map(|node|format!("{}={}s",node.name,node.seconds)).collect::<Vec<_>>().join(", ");
                        format!("; selected={} total={}s (+300s slack); {contributions}; omitted-contributions={}",selected.name,summary.seconds,selected.children.len().saturating_sub(128))
                    }).unwrap_or_default();
                    failures.push(format!("{file}/{name:?}: {error}{detail}"));
                }
            },
            Err(error) => failures.push(format!("{file}/{name:?}: {error}")),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CiError::Message(failures.join("\n")))
    }
}

pub(super) fn validate_budget(workflow: &Value, file: &str) -> Result<()> {
    for (name, job) in workflow["jobs"].as_mapping().expect("source jobs") {
        if !job["steps"].is_sequence() {
            continue;
        }
        let actual = job["timeout-minutes"]
            .as_u64()
            .ok_or_else(|| CiError::Message("job timeout must be finite".into()))?;
        let required = job_budget_definition(job)?.timeout_minutes()?;
        if actual < required || actual > super::budget::PLATFORM_LIMIT_MINUTES {
            return Err(CiError::Message(format!(
                "{file}/{name:?}: job budget {actual} does not cover emitted branch {required}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/private/concurrency_budget_inventory.rs"]
mod budget_inventory_tests;
