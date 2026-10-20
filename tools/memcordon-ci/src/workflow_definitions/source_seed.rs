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
    for (name, job) in jobs.iter_mut() {
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
        if workflow == "ci.yml" && name.as_str() == Some("quality") {
            let toolchain = steps
                .iter()
                .position(|step| field(step, "run").starts_with("rustup toolchain install "))
                .ok_or_else(|| CiError::Message("format toolchain absent".into()))?;
            let toolchain = steps.remove(toolchain);
            let checkout = steps
                .iter()
                .position(|step| field(step, "uses").starts_with("actions/checkout@"))
                .expect("checkout");
            steps.insert(checkout + 1, toolchain);
            let mut format = invocation("Check Rust formatting", FORMAT, "15");
            format["id"] = text("early-format");
            steps.insert(checkout + 2, format);
        }
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
    Ok(())
}

pub fn validate(document: &Value) -> Result<()> {
    let fail = |message: &str| CiError::Message(message.into());
    let jobs = document["jobs"]
        .as_mapping()
        .ok_or_else(|| fail("source jobs absent"))?;
    let producer = &document["jobs"]["source-seed"];
    let workflow = match document["name"].as_str() {
        Some("Release") => "release.yml",
        Some("Native backend tests") => "backend-certification.yml",
        Some("Deep CI") => "deep-ci.yml",
        _ => "ci.yml",
    };
    if producer != &producer_job(workflow) {
        return Err(fail(
            "source acquisition must be independent with finite event ownership",
        ));
    }
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
        let restores = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| field(step, "id") == "public-source-seed-restore")
            .collect::<Vec<_>>();
        if source_driver || name.as_str() == Some("source-seed") {
            if restores.len() != 1
                || restores[0].1 != &consumer_restore()
                || job["env"] != object(&[("CARGO_HOME", text(CARGO_HOME_VALUE))])
            {
                return Err(fail("public source reader path/key/home contract changed"));
            }
            let normalize = steps.iter().position(|s| field(s, "run") == NORMALIZE);
            let checkout = steps
                .iter()
                .position(|s| field(s, "uses").starts_with("actions/checkout@"));
            if !matches!((normalize,checkout),(Some(n),Some(c)) if n < c) {
                return Err(fail("source checkout must normalize before hashing"));
            }
            if source_driver
                && steps
                    .iter()
                    .position(|s| field(s, "id").starts_with("driver-"))
                    .is_some_and(|driver| restores[0].0 >= driver)
            {
                return Err(fail("source restore must precede driver identity/build"));
            }
        } else if !restores.is_empty() {
            return Err(fail(
                "source cache cannot enter immutable publisher/rehearsal",
            ));
        }
        if steps
            .iter()
            .any(|s| field(&s["with"], "key").starts_with("mc-download-bootstrap-"))
        {
            return Err(fail("orphan bootstrap source reader retained"));
        }
        if name.as_str() == Some("source-seed") {
            let expected = producer_job(workflow);
            if job["steps"] != expected["steps"] {
                return Err(fail("source producer fetch/save contract changed"));
            }
        }
        if document["name"].as_str() == Some("CI")
            && name.as_str() == Some("policy")
            && steps
                .iter()
                .any(|s| field(s, "run").ends_with(" ci segment workspace-fetch"))
        {
            return Err(fail("policy must not wait for workspace fetch"));
        }
        if source_driver
            && name.as_str() == Some("quality")
            && document["name"].as_str() == Some("CI")
        {
            let format = steps.iter().position(|s| {
                field(s, "run") == FORMAT && s["continue-on-error"].is_null() && s["if"].is_null()
            });
            if !format.is_some_and(|index| index < restores[0].0) {
                return Err(fail(
                    "required formatting must precede source/driver preparation",
                ));
            }
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
        if let Some(source) = package.get("source") {
            if source.as_str() != Some("registry+https://github.com/rust-lang/crates.io-index") {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
