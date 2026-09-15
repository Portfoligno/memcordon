#![cfg(feature = "test-support")]

use serde::Deserialize;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    argument_parser: String,
    owner: String,
    platform_cfg: String,
    #[serde(default)]
    available: Option<bool>,
    owning_suites: Vec<String>,
    privilege_needs: String,
    expected_side_effects: String,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned()
}

fn inventories() -> [(&'static str, Vec<Entry>); 2] {
    [
        env!("CARGO_BIN_EXE_memcordon-test-fixture"),
        env!("CARGO_BIN_EXE_memcordon-sealed-test-fixture"),
    ]
    .map(|image| {
        let output = Command::new(image)
            .args(["--fixture-inventory-json"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{image}: {:?}", output.stderr);
        (
            image,
            serde_json::from_slice(&output.stdout).expect("strict command inventory"),
        )
    })
}

#[test]
fn fixture_inventory_preserves_every_command_and_native_parser_owner() {
    let mut general: BTreeSet<&str> = [
        "exit",
        "hold",
        "wait-for-signal",
        "spin",
        "allocate",
        "burst",
        "spawn-background",
        "fork-continually",
        "monitor-failure",
        "spawn-tree",
        "print-pid-and-hold",
        "new-session-and-hold",
        "assert-native-containment",
        "record-argv",
        "assert-no-memcordon-environment",
        "gate-marker",
        "gate-wait",
        "tcp-loopback",
        "tcp-client",
        "gate-failure",
        "attempt-job-breakaway",
    ]
    .into_iter()
    .collect();
    if cfg!(target_os = "macos") {
        general.extend([
            "macos-signal-parent",
            "macos-signal-target",
            "__macos-guardian",
            "__macos-guardian-envelope-v1",
            "macos-gated-group-change",
            "macos-envelope-caller",
            "macos-envelope-parent",
            "macos-envelope-target",
            "macos-accounting-backend",
            "macos-envelope-transfer",
            "macos-guardian-inspector-wrapper",
            "macos-custody-wrapper",
            "macos-closed-stdio",
            "macos-ignore-term",
        ]);
    }
    let sealed: BTreeSet<&str> = [
        "exit",
        "exit-17",
        "exit-126",
        "exit-127",
        "mark",
        "fault-ready",
        "frontend-hold",
        "frontend-exit-before-ready",
        "child",
        "retained-stream",
        "concurrency-gate",
        "double-fork",
        "setsid",
        "fork-storm",
        "deny-cgroup",
        "deny-setns",
        "deny-cgroup-mount",
        "assert-credential-transition-root",
        "assert-effective-uid",
        "assert-file-capability-transition",
        "assert-bounding-capability-absent",
        "elevated-transition-descendant",
        "assert-mount-marker",
        "assert-recursive-provider-rejected",
        "identity",
    ]
    .into_iter()
    .collect();
    for ((image, entries), expected) in inventories().into_iter().zip([general, sealed]) {
        let names: BTreeSet<_> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names.len(), entries.len(), "duplicate command in {image}");
        assert_eq!(names, expected, "command preservation for {image}");
        for entry in entries {
            let owner = root().join(&entry.owner);
            assert!(owner.is_file(), "missing owner {}", entry.owner);
            let parser = entry.argument_parser.split("::").last().unwrap().trim();
            let source = std::fs::read_to_string(owner).unwrap();
            assert!(
                source.contains(&format!("fn {parser}(")),
                "unowned parser {}",
                entry.argument_parser
            );
            assert!(!entry.platform_cfg.is_empty());
            assert!(!entry.privilege_needs.is_empty());
            assert!(!entry.expected_side_effects.is_empty());
            assert!(!entry.owning_suites.is_empty());
            for suite in entry.owning_suites {
                let target = suite.split("::").next().unwrap();
                assert!(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests")
                        .join(target)
                        .with_extension("rs")
                        .is_file(),
                    "missing suite {suite}"
                );
            }
            if let Some(available) = entry.available {
                assert_eq!(available, cfg!(target_os = "linux"));
            }
        }
    }
}

#[test]
fn fixture_registry_owners_are_declared_source_boundaries() {
    let mut sources = BTreeSet::new();
    for domain in [
        "core",
        "platform",
        "cli",
        "sealed-provider",
        "ci",
        "loader-lab",
        "tests",
        "fuzz",
    ] {
        let path = root()
            .join("ci/source-presence")
            .join(domain)
            .with_extension("toml");
        let document: toml::Value =
            toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for entry in document["source"].as_array().unwrap() {
            sources.insert(entry["path"].as_str().unwrap().to_owned());
        }
    }
    for (_, entries) in inventories() {
        for entry in entries {
            assert!(
                sources.contains(&entry.owner),
                "unregistered fixture owner {}",
                entry.owner
            );
        }
    }
}

#[test]
fn fixture_dispatch_preserves_exit_codes_and_rejects_unknown_commands() {
    let fixture = env!("CARGO_BIN_EXE_memcordon-test-fixture");
    assert_eq!(
        Command::new(fixture)
            .args(["exit", "--code", "17"])
            .status()
            .unwrap()
            .code(),
        Some(17)
    );
    assert_eq!(
        Command::new(fixture)
            .args(["exit", "--code", "256"])
            .status()
            .unwrap()
            .code(),
        Some(2)
    );
    assert_eq!(
        Command::new(fixture)
            .args(["unknown-command"])
            .status()
            .unwrap()
            .code(),
        Some(2)
    );
    assert_eq!(
        Command::new(fixture)
            .args(["--fixture-inventory-json", "extra"])
            .status()
            .unwrap()
            .code(),
        Some(2)
    );
    let sealed = env!("CARGO_BIN_EXE_memcordon-sealed-test-fixture");
    assert_eq!(
        Command::new(sealed)
            .args(["unknown-command"])
            .status()
            .unwrap()
            .code(),
        Some(if cfg!(target_os = "linux") { 2 } else { 125 })
    );
    assert_eq!(
        Command::new(sealed).status().unwrap().code(),
        Some(if cfg!(target_os = "linux") { 0 } else { 125 })
    );
    assert_eq!(
        Command::new(sealed)
            .args(["exit-17"])
            .status()
            .unwrap()
            .code(),
        Some(if cfg!(target_os = "linux") { 17 } else { 125 })
    );
}

#[test]
fn fixture_feature_gates_preserve_default_install_exclusion() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    for (name, feature) in [
        ("memcordon-test-fixture", "test-fixtures"),
        ("memcordon-sealed-test-fixture", "test-support"),
    ] {
        let target = manifest["bin"]
            .as_array()
            .unwrap()
            .iter()
            .find(|target| target["name"].as_str() == Some(name))
            .unwrap();
        assert_eq!(
            target["required-features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>(),
            [feature]
        );
    }
}
