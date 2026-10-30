//! Public source bytes, independently acquired before a driver exists.
use super::{number, text};
use crate::{CiError, Result};
use serde_yaml::{Mapping, Value};

pub const CARGO_HOME_VALUE: &str = "${{ github.workspace }}/target/ci-cargo-home";
const RESTORE: &str = "actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
const SAVE: &str = "actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
const PATHS: &str = "target/ci-cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/*.crate\ntarget/ci-cargo-home/registry/cache/index.crates.io-6f17d22bba15001f/*.crate\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/.cache\ntarget/ci-cargo-home/registry/index/index.crates.io-1949cf8c6b5b557f/config.json";
const KEY: &str = "mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-${{ hashFiles('Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}";
const PREFIX: &str =
    "mc-ci-public-source-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml') }}-";
const WRITE: &str = "((github.event_name == 'push' && ((startsWith(github.ref, 'refs/heads/') && github.ref != 'refs/heads/') || (startsWith(github.ref, 'refs/tags/') && github.ref != 'refs/tags/'))) || (github.event_name == 'workflow_dispatch' && startsWith(github.ref, 'refs/heads/') && github.ref != 'refs/heads/'))";
const NORMALIZE: &str = "git config --global core.autocrlf false";
const FORMAT: &str = "rustup run 1.97.1 cargo fmt --all -- --check";
const FETCH: &str = "rustup run 1.97.1 cargo fetch --locked";

fn object(fields: &[(&str, Value)]) -> Value {
    Value::Mapping(fields.iter().map(|(k, v)| (text(k), v.clone())).collect())
}
fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}
fn invocation(name: &str, run: &str, minutes: &str) -> Value {
    object(&[
        ("name", text(name)),
        ("run", text(run)),
        ("timeout-minutes", number(minutes)),
    ])
}
pub fn consumer_restore() -> Value {
    object(&[
        ("id", text("public-source-seed-restore")),
        ("uses", text(RESTORE)),
        ("continue-on-error", Value::Bool(true)),
        ("timeout-minutes", number("2")),
        (
            "with",
            object(&[
                ("path", text(PATHS)),
                ("key", text(KEY)),
                ("restore-keys", text(PREFIX)),
            ]),
        ),
    ])
}
fn owner_condition(workflow: &str) -> String {
    let manual = if workflow == "release.yml" {
        "github.event_name == 'workflow_dispatch' && startsWith(github.ref, 'refs/heads/') && github.ref != 'refs/heads/' && inputs.recovery-mode == 'reprepare'"
    } else {
        "github.event_name == 'workflow_dispatch' && startsWith(github.ref, 'refs/heads/') && github.ref != 'refs/heads/'"
    };
    let push = match workflow {
        "release.yml" => Some(
            "github.event_name == 'push' && startsWith(github.ref, 'refs/heads/') && github.ref != 'refs/heads/'",
        ),
        "deep-ci.yml" => Some(
            "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/') && github.ref != 'refs/tags/'",
        ),
        _ => None,
    };
    match push {
        Some(push) => format!("github.event.deleted != true && (({push}) || ({manual}))"),
        None => format!("github.event.deleted != true && ({manual})"),
    }
}
pub fn producer_job(workflow: &str) -> Value {
    let mut fetch = invocation("Acquire locked public workspace sources", FETCH, "25");
    fetch["id"] = text("public-source-fetch");
    object(&[
        (
            "name",
            text("Public Cargo source seed / ${{ matrix.runner }}"),
        ),
        ("if", text(&owner_condition(workflow))),
        ("permissions", object(&[("contents", text("read"))])),
        (
            "strategy",
            object(&[
                ("fail-fast", Value::Bool(false)),
                (
                    "matrix",
                    object(&[(
                        "runner",
                        Value::Sequence(
                            ["ubuntu-24.04", "macos-15", "windows-2025"]
                                .map(text)
                                .into(),
                        ),
                    )]),
                ),
            ]),
        ),
        ("runs-on", text("${{ matrix.runner }}")),
        ("timeout-minutes", number("56")),
        ("continue-on-error", Value::Bool(true)),
        ("env", object(&[("CARGO_HOME", text(CARGO_HOME_VALUE))])),
        (
            "steps",
            Value::Sequence(vec![
                invocation("Configure checkout line endings", NORMALIZE, "1"),
                object(&[
                    (
                        "uses",
                        text("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"),
                    ),
                    (
                        "with",
                        object(&[("persist-credentials", Value::Bool(false))]),
                    ),
                    ("timeout-minutes", number("6")),
                ]),
                invocation(
                    "Install pinned Cargo toolchain",
                    "rustup toolchain install 1.97.1 --profile minimal",
                    "15",
                ),
                consumer_restore(),
                fetch,
                object(&[
                    ("id", text("public-source-seed-save")),
                    (
                        "if",
                        text(&format!(
                            "always() && steps.public-source-fetch.outcome == 'success' && steps.public-source-seed-restore.outputs.cache-primary-key != '' && steps.public-source-seed-restore.outputs.cache-hit != 'true' && {WRITE}"
                        )),
                    ),
                    ("uses", text(SAVE)),
                    ("continue-on-error", Value::Bool(true)),
                    ("timeout-minutes", number("2")),
                    (
                        "with",
                        object(&[
                            ("path", text(PATHS)),
                            (
                                "key",
                                text(
                                    "${{ steps.public-source-seed-restore.outputs.cache-primary-key }}",
                                ),
                            ),
                        ]),
                    ),
                ]),
            ]),
        ),
    ])
}

pub fn apply(document: &mut Value, workflow: &str) -> Result<()> {
    let jobs = document["jobs"].as_mapping_mut().expect("jobs");
    for (_, job) in jobs.iter_mut() {
        let Some(steps) = job["steps"].as_sequence_mut() else {
            continue;
        };
        if !steps
            .iter()
            .any(|step| field(step, "run").contains("--target-dir target/ci-driver-cold"))
        {
            continue;
        }
        let normalize = steps
            .iter()
            .position(|step| field(step, "run") == NORMALIZE)
            .map(|index| steps.remove(index))
            .unwrap_or_else(|| invocation("Configure checkout line endings", NORMALIZE, "1"));
        let checkout = steps
            .iter()
            .position(|step| field(step, "uses").starts_with("actions/checkout@"))
            .ok_or_else(|| CiError::Message("source driver checkout absent".into()))?;
        steps.insert(checkout, normalize);
        let first_driver = steps
            .iter()
            .position(|step| field(step, "id").starts_with("driver-"))
            .expect("driver steps");
        steps.insert(first_driver, consumer_restore());
        if job["env"].is_null() {
            job["env"] = Value::Mapping(Mapping::new());
        }
        job["env"]["CARGO_HOME"] = text(CARGO_HOME_VALUE);
    }
    jobs.insert(text("source-seed"), producer_job(workflow));
    if matches!(workflow, "ci.yml" | "release.yml") {
        for (_, job) in jobs.iter_mut() {
            if let Some(steps) = job["steps"].as_sequence_mut() {
                steps.retain(|step| field(step, "run") != FORMAT);
            }
        }
        let owner = if workflow == "release.yml" {
            "select"
        } else {
            "policy"
        };
        let checkout = jobs[text(owner)]["steps"]
            .as_sequence()
            .expect("owner steps")
            .iter()
            .find(|step| field(step, "uses").starts_with("actions/checkout@"))
            .expect("owner checkout")
            .clone();
        let release = workflow == "release.yml";
        jobs.insert(text("format"), object(&[
            ("name", text(if release { "Release source formatting" } else { "CI source formatting" })),
            ("if", text(if release { "github.event.deleted != true && (github.event_name != 'workflow_dispatch' || inputs.recovery-mode == 'reprepare')" } else { "github.event_name != 'push'" })),
            ("permissions", object(&[("contents", text("read"))])),
            ("runs-on", text("ubuntu-24.04")),
            ("timeout-minutes", number("42")),
            ("steps", Value::Sequence(vec![invocation("Configure checkout line endings", NORMALIZE, "1"), checkout, invocation("Install formatter", "rustup toolchain install 1.97.1 --profile minimal --component rustfmt", "15"), invocation("Check formatting", FORMAT, "15")])),
        ]));
        if release {
            jobs[text("assemble")]["needs"]
                .as_sequence_mut()
                .expect("assembly needs")
                .push(text("format"));
        }
    }
    if matches!(
        workflow,
        "ci.yml" | "release.yml" | "deep-ci.yml" | "backend-certification.yml"
    ) {
        jobs.insert(text("current-contracts"), current_contracts_job(workflow));
        jobs.insert(text("tooling-contracts"), tooling_contracts_job(workflow));
        jobs.insert(
            text("macos-administrative-contracts"),
            platform_contracts_job(workflow, PlatformFeedback::MacosAdministration),
        );
        if workflow == "ci.yml" {
            jobs.insert(
                text("macos-startup-deadline-feedback"),
                platform_contracts_job(workflow, PlatformFeedback::MacosStartupDeadline),
            );
            jobs.insert(
                text("windows-fixture-feedback"),
                platform_contracts_job(workflow, PlatformFeedback::WindowsFixture),
            );
            jobs.insert(
                text("windows-sealed-agent-contracts"),
                platform_contracts_job(workflow, PlatformFeedback::WindowsNativeContracts),
            );
        }
    }
    Ok(())
}

/// Portable wire/help feedback owns its own target directory and never waits
/// for selection, a CI driver, or the complete native test inventory.
fn current_contracts_job(workflow: &str) -> Value {
    let mut job = producer_job("ci.yml");
    let mapping = job.as_mapping_mut().expect("contract job");
    for key in ["strategy", "continue-on-error"] {
        mapping.remove(text(key));
    }
    job["name"] = text("Current portable contracts");
    job["if"] = text(if workflow == "release.yml" {
        "github.event.deleted != true && (github.event_name != 'workflow_dispatch' || inputs.recovery-mode == 'reprepare')"
    } else {
        "github.event.deleted != true"
    });
    job["runs-on"] = text("ubuntu-24.04");
    job["timeout-minutes"] = number("40");
    let steps = job["steps"].as_sequence_mut().expect("contract steps");
    steps.retain(|step| {
        field(step, "id") != "public-source-fetch" && field(step, "id") != "public-source-seed-save"
    });
    let key = "mc-current-contracts-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}";
    let prefix = "mc-current-contracts-v1-${{ runner.os }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-";
    steps.push(object(&[
        ("id", text("current-contracts-restore")),
        ("uses", text(RESTORE)),
        ("continue-on-error", Value::Bool(true)),
        ("timeout-minutes", number("3")),
        (
            "with",
            object(&[
                ("path", text("target/ci-current-contracts")),
                ("key", text(key)),
                ("restore-keys", text(prefix)),
            ]),
        ),
    ]));
    for (name, command) in [
        (
            "Current core wire contracts",
            "rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon-core --test diagnostics --test current_formats --test windows_guardian_observation",
        ),
        (
            "Current public help",
            "rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test documentation",
        ),
        (
            "Retired native package routes refuse before authorization",
            "rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test native_package_recovery_dispatch",
        ),
        (
            "Current Linux package inspection",
            "rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test sealed_agent_distribution",
        ),
        (
            "Current fail-closed CLI reports",
            "rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test cli sealed_execution_plan_and_doctor_fail_closed -- --exact",
        ),
        (
            "Current doctor presentation",
            "rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test cli doctor_text_and_json_have_distinct_complete_shapes -- --exact",
        ),
    ] {
        steps.push(invocation(name, command, "10"));
    }
    steps.push(object(&[
        ("id", text("current-contracts-save")), ("uses", text(SAVE)),
        ("if", text("always() && steps.current-contracts-restore.outcome != 'skipped' && steps.current-contracts-restore.outputs.cache-hit != 'true'")),
        ("continue-on-error", Value::Bool(true)), ("timeout-minutes", number("3")),
        ("with", object(&[("path", text("target/ci-current-contracts")), ("key", text(key))])),
    ]));
    steps.push(object(&[
        ("id", text("current-contracts-source-save")), ("uses", text(SAVE)),
        ("if", text("always() && steps.public-source-seed-restore.outputs.cache-primary-key != '' && steps.public-source-seed-restore.outputs.cache-hit != 'true'")),
        ("continue-on-error", Value::Bool(true)), ("timeout-minutes", number("2")),
        ("with", object(&[("path", text(PATHS)), ("key", text("${{ steps.public-source-seed-restore.outputs.cache-primary-key }}"))])),
    ]));
    job
}

/// Tooling contracts compile only their package and never bootstrap a CI driver.
fn tooling_contracts_job(workflow: &str) -> Value {
    let mut job = current_contracts_job(workflow);
    job["name"] = text("Current tooling contracts");
    let steps = job["steps"]
        .as_sequence_mut()
        .expect("tooling contract steps");
    steps.retain(|step| {
        !matches!(
            field(step, "id"),
            "current-contracts-restore" | "current-contracts-save"
        ) && step["run"]
            .as_str()
            .is_none_or(|run| !run.starts_with("rustup run 1.97.1 cargo test "))
    });
    let key = "mc-tooling-contracts-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('tools/memcordon-ci/**/*.rs', 'crates/**/*.rs', 'fuzz/Cargo.toml', 'fuzz/corpus/**', '.github/workflows/deep-ci.yml') }}";
    let prefix = "mc-tooling-contracts-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', 'tools/*/Cargo.toml', '.cargo/**') }}-";
    let source_save = steps.pop().expect("independent source save");
    steps.push(object(&[
        ("id", text("tooling-contracts-restore")),
        ("uses", text(RESTORE)),
        ("continue-on-error", Value::Bool(true)),
        ("timeout-minutes", number("3")),
        (
            "with",
            object(&[
                ("path", text("target/ci-tooling-contracts")),
                ("key", text(key)),
                ("restore-keys", text(prefix)),
            ]),
        ),
    ]));
    steps.push(invocation("Current external consumer contracts", "rustup run 1.97.1 cargo test --locked --target-dir target/ci-tooling-contracts -p memcordon-ci --test external_consumer --test windows_installed_paths --test target_shard --test fuzz_targets --test msrv_source --test original_native_roles --test workflow_policy", "10"));
    steps.push(object(&[
        ("id", text("tooling-contracts-save")), ("uses", text(SAVE)),
        ("if", text("always() && steps.tooling-contracts-restore.outcome != 'skipped' && steps.tooling-contracts-restore.outputs.cache-hit != 'true'")),
        ("continue-on-error", Value::Bool(true)), ("timeout-minutes", number("3")),
        ("with", object(&[("path", text("target/ci-tooling-contracts")), ("key", text(key))])),
    ]));
    steps.push(source_save);
    job
}

enum PlatformFeedback {
    MacosAdministration,
    MacosStartupDeadline,
    WindowsFixture,
    WindowsNativeContracts,
}

/// Feedback starts with the actual selected Cargo prerequisites. Windows
/// acceptance still requires the existing exact one-test verified native lane.
fn platform_contracts_job(workflow: &str, feedback: PlatformFeedback) -> Value {
    let mut job = current_contracts_job(workflow);
    let (name, runner, command, key, prefix) = match feedback {
        PlatformFeedback::MacosAdministration => (
            "macOS administrative contracts",
            "macos-15",
            "rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test sealed_agent_distribution",
            "mc-macos-administrative-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}",
            "mc-macos-administrative-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-",
        ),
        PlatformFeedback::MacosStartupDeadline => (
            "macOS x64 startup deadline feedback",
            "macos-15-intel",
            "rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test macos_remediation requested_deadline_expires_during_unacknowledged_startup -- --exact --nocapture",
            "mc-macos-startup-deadline-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}",
            "mc-macos-startup-deadline-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-",
        ),
        PlatformFeedback::WindowsFixture => (
            "Windows fixture feedback / ${{ matrix.id }}",
            "${{ matrix.runner }}",
            "rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test windows_namespace_primary fresh_restricted_primary_namespace_access_is_observed_without_inherited_gate_capabilities -- --exact --nocapture",
            "mc-windows-fixture-feedback-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}",
            "mc-windows-fixture-feedback-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-",
        ),
        PlatformFeedback::WindowsNativeContracts => (
            "Windows sealed-agent contracts / ${{ matrix.id }}",
            "${{ matrix.runner }}",
            "rustup run 1.97.1 cargo test --locked --all-features --target-dir target/ci-current-contracts -p memcordon --test sealed_agent -- --exact --nocapture windows_security::exact_predecessor_delete_child_grant_is_refused_unchanged_and_current_policy_denies windows_security::certification_marker_security_accepts_only_current_policy_and_preserves_refused_descriptors windows_security::server_response_completion_waits_for_small_and_large_frames_to_be_consumed windows_security::support_control_release_reads_only_complete_bounded_frames_before_original_cutoff windows_guardian_startup::structured_bootstrap_rejection_is_preserved_while_guardian_is_live windows_security::frame_read_diagnostics_distinguish_length_payload_decode_and_peer_close windows_terminal_transport::partial_initial_request_uses_the_fixed_whole_frame_cutoff",
            "mc-windows-sealed-agent-feedback-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs') }}",
            "mc-windows-sealed-agent-feedback-v1-${{ runner.os }}-${{ runner.arch }}-${{ hashFiles('ci/toolchains.toml', 'Cargo.lock', 'Cargo.toml', 'crates/*/Cargo.toml', '.cargo/**') }}-",
        ),
    };
    job["name"] = text(name);
    job["runs-on"] = text(runner);
    if matches!(
        feedback,
        PlatformFeedback::WindowsFixture | PlatformFeedback::WindowsNativeContracts
    ) {
        job["strategy"] = object(&[
            ("fail-fast", Value::Bool(false)),
            (
                "matrix",
                object(&[(
                    "include",
                    Value::Sequence(vec![
                        object(&[
                            ("id", text("windows-x64")),
                            ("runner", text("windows-2025")),
                        ]),
                        object(&[
                            ("id", text("windows-arm64")),
                            ("runner", text("windows-11-arm")),
                        ]),
                    ]),
                )]),
            ),
        ]);
    }
    let steps = job["steps"]
        .as_sequence_mut()
        .expect("platform feedback steps");
    let first = steps
        .iter()
        .position(|step| field(step, "run").starts_with("rustup run 1.97.1 cargo test "))
        .expect("portable contract boundary");
    steps.retain(|step| !field(step, "run").starts_with("rustup run 1.97.1 cargo test "));
    steps.insert(first, invocation(name, command, "10"));
    for step in steps {
        match field(step, "id") {
            "current-contracts-restore" => {
                step["with"]["key"] = text(key);
                step["with"]["restore-keys"] = text(prefix);
            }
            "current-contracts-save" => {
                step["with"]["key"] = text(key);
            }
            _ => {}
        }
    }
    job
}

pub fn validate(document: &Value) -> Result<()> {
    let fail = |message: &str| CiError::Message(message.into());
    let jobs = document["jobs"]
        .as_mapping()
        .ok_or_else(|| fail("source jobs absent"))?;
    for (name, job) in jobs {
        if job["needs"]
            .as_sequence()
            .is_some_and(|needs| needs.contains(&text("source-seed")))
            || job["needs"] == text("source-seed")
        {
            return Err(fail("checks must not wait for source seed"));
        }
        let Some(steps) = job["steps"].as_sequence() else {
            continue;
        };
        let source_driver = steps
            .iter()
            .any(|step| field(step, "run").contains("--target-dir target/ci-driver-cold"));
        if source_driver || name.as_str() == Some("source-seed") {
            let normalize = steps.iter().position(|s| field(s, "run") == NORMALIZE);
            let checkout = steps
                .iter()
                .position(|s| field(s, "uses").starts_with("actions/checkout@"));
            if !matches!((normalize,checkout),(Some(n),Some(c)) if n < c) {
                return Err(fail("source checkout must normalize before preparation"));
            }
        }
        if matches!(
            name.as_str(),
            Some("publish" | "recovery-publish" | "rehearse" | "recovery-rehearse")
        ) && steps
            .iter()
            .any(|step| field(step, "uses").starts_with("actions/cache/"))
        {
            return Err(fail(
                "source cache cannot enter immutable publisher/rehearsal",
            ));
        }
        if matches!(name.as_str(), Some("policy" | "source-policy"))
            && steps
                .iter()
                .any(|s| field(s, "run").ends_with(" ci segment workspace-fetch"))
        {
            return Err(fail("policy must not wait for workspace fetch"));
        }
    }
    if matches!(document["name"].as_str(), Some("CI" | "Release")) {
        let format = &document["jobs"]["format"];
        let steps = format["steps"]
            .as_sequence()
            .ok_or_else(|| fail("independent formatter absent"))?;
        if !format["needs"].is_null()
            || !steps.iter().any(|s| {
                field(s, "run") == FORMAT && s["continue-on-error"].is_null() && s["if"].is_null()
            })
            || steps.iter().any(|s| {
                field(s, "run").contains("memcordon-ci") || field(s, "run").contains("cargo fetch")
            })
        {
            return Err(fail(
                "required formatting must complete independently of source preparation",
            ));
        }
    }
    Ok(())
}

/// The raw predriver transport models only the checked-in public registry.
pub fn validate_source_model(root: &std::path::Path) -> Result<()> {
    let invalid = || {
        CiError::Message(
            "public source seed requires the explicit crates.io-only source model".into(),
        )
    };
    for name in ["config", "config.toml"] {
        if root.join(".cargo").join(name).try_exists()? {
            return Err(invalid());
        }
    }
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(root.join("Cargo.lock"))?)?;
    let packages = lock["package"].as_array().ok_or_else(invalid)?;
    for package in packages {
        if let Some(source) = package.get("source")
            && source.as_str() != Some("registry+https://github.com/rust-lang/crates.io-index")
        {
            return Err(invalid());
        }
    }
    Ok(())
}
