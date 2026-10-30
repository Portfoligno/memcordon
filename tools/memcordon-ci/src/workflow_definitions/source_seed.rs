//! Independent source-supply and formatting checks over the current graph.
use super::text;
use crate::{CiError, Result};
use serde_yaml::Value;
const NORMALIZE: &str = "git config --global core.autocrlf false";
const FORMAT: &str = "rustup run 1.97.1 cargo fmt --all -- --check";
fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
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
