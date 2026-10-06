use std::path::{Path, PathBuf};

use memcordon_ci::{config, policy};
use serde_yaml::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workflow() -> Value {
    serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap()
}

fn validate(value: &Value) -> memcordon_ci::Result<()> {
    policy::validate_workflow_bytes(
        &root(),
        Path::new(".github/workflows/release.yml"),
        serde_yaml::to_string(value)?.as_bytes(),
        &config::policy(&root())?,
    )
}

#[test]
fn actual_release_graph_requires_successful_rehearsal_for_each_writer() {
    let baseline = workflow();
    validate(&baseline).unwrap();
    for (writer, gate) in [
        ("publish", "rehearse"),
        ("recovery-publish", "recovery-rehearse"),
    ] {
        assert!(
            baseline["jobs"][writer]["needs"]
                .as_sequence()
                .unwrap()
                .iter()
                .any(|need| need.as_str() == Some(gate))
        );
        let mut missing = baseline.clone();
        missing["jobs"][writer]["needs"]
            .as_sequence_mut()
            .unwrap()
            .retain(|need| need.as_str() != Some(gate));
        assert!(validate(&missing).is_err(), "{writer} cannot omit its gate");
        for condition in [
            "always()",
            "failure()",
            "cancelled()",
            "needs.rehearse.result != 'failure'",
        ] {
            let mut bypass = baseline.clone();
            bypass["jobs"][writer]["if"] = condition.into();
            assert!(validate(&bypass).is_err(), "{writer}: {condition}");
        }
    }
}

#[test]
fn rehearsal_mode_truth_table_and_failed_prerequisites_preserve_the_actual_graph() {
    let baseline = workflow();
    let normal_condition = baseline["jobs"]["rehearse"]["if"].as_str().unwrap();
    assert_eq!(
        normal_condition,
        "needs.select.outputs.recovery-mode == 'reprepare'"
    );
    let recovery_condition = baseline["jobs"]["recovery-rehearse"]["if"]
        .as_str()
        .unwrap();
    assert_eq!(
        recovery_condition,
        baseline["jobs"]["recovery-publish"]["if"].as_str().unwrap()
    );
    for (kind, mode, event, tag, expected) in [
        ("candidate", "reprepare", "push", false, (true, false)),
        (
            "candidate",
            "reprepare",
            "workflow_dispatch",
            false,
            (true, false),
        ),
        ("tagged", "reprepare", "push", true, (true, false)),
        (
            "tagged",
            "reprepare",
            "workflow_dispatch",
            true,
            (true, false),
        ),
        (
            "tagged",
            "publication-only",
            "workflow_dispatch",
            true,
            (false, true),
        ),
    ] {
        let normal = mode == "reprepare";
        let recovery =
            kind == "tagged" && mode == "publication-only" && event == "workflow_dispatch" && tag;
        assert_eq!((normal, recovery), expected);
        assert_ne!(normal, recovery, "exactly one applicable rehearsal");
        let active = if normal {
            "rehearse"
        } else {
            "recovery-rehearse"
        };
        assert!(
            !baseline["jobs"][active]["if"]
                .as_str()
                .unwrap()
                .contains("always()")
        );
        assert!(baseline["jobs"][active]["continue-on-error"].is_null());
        let predecessor = if normal {
            "assemble"
        } else {
            "recovery-inputs"
        };
        assert_eq!(
            baseline["jobs"][active]["needs"],
            serde_yaml::from_str::<Value>(&format!("[select, {predecessor}]")).unwrap()
        );
    }
    assert!(
        !baseline["jobs"]["recovery-rehearse"]["needs"]
            .as_sequence()
            .unwrap()
            .iter()
            .any(|need| need.as_str() == Some("assemble"))
    );
}

#[test]
fn downloaded_tools_inputs_and_credentials_cannot_be_substituted_or_bypassed() {
    let baseline = workflow();
    for job in ["rehearse", "recovery-rehearse"] {
        for case in [
            "optional",
            "public-consumer",
            "write-permission",
            "token-env",
            "checkout",
            "cargo",
            "cache",
            "compound",
            "shell",
            "unpinned",
            "diagnostic-input",
            "missing-helper",
            "wildcard",
            "changed-input",
            "changed-publisher",
            "ignored-run",
        ] {
            let mut changed = baseline.clone();
            let value = &mut changed["jobs"][job];
            let count = value["steps"].as_sequence().unwrap().len();
            match case {
                "optional" => value["continue-on-error"] = true.into(),
                "public-consumer" => {
                    value["if"] = "needs.select.outputs.public-consumer == 'true'".into()
                }
                "write-permission" => value["permissions"]["id-token"] = "write".into(),
                "token-env" => {
                    value["steps"][count - 2]["env"]["GH_TOKEN"] = "${{ github.token }}".into()
                }
                "checkout" | "cargo" | "cache" => {
                    let injected = match case {
                        "checkout" => {
                            "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
                        }
                        "cargo" => {
                            "run: rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-ci --bin memcordon-ci\n"
                        }
                        _ => {
                            "uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\nwith:\n  path: .release/rehearsal-results\n  key: fixture\n"
                        }
                    };
                    value["steps"]
                        .as_sequence_mut()
                        .unwrap()
                        .push(serde_yaml::from_str(injected).unwrap());
                }
                "compound" => value["steps"][count - 2]["run"] = "true && true".into(),
                "shell" => value["steps"][count - 2]["shell"] = "sh".into(),
                "unpinned" => value["steps"][0]["uses"] = "actions/download-artifact@main".into(),
                "diagnostic-input" => {
                    value["steps"][0]["with"]["artifact-ids"] =
                        "${{ needs.rehearse.outputs.report }}".into()
                }
                "missing-helper" => {
                    value["steps"].as_sequence_mut().unwrap().remove(0);
                }
                "wildcard" => value["steps"][1]["with"]["pattern"] = "publication-tool-*".into(),
                "changed-input" => {
                    value["steps"][if job == "rehearse" { 3 } else { 2 }]["with"]["artifact-ids"] =
                        "${{ needs.select.outputs.selection-artifact-id }}".into()
                }
                "changed-publisher" => {
                    value["steps"][1]["with"]["artifact-ids"] =
                        "${{ needs.select.outputs.rehearsal-tool-artifact-id }}".into()
                }
                "ignored-run" => value["steps"][count - 2]["continue-on-error"] = true.into(),
                _ => unreachable!(),
            }
            assert!(validate(&changed).is_err(), "{job}: {case}");
        }
    }
}

#[test]
fn recovery_routes_original_pair_and_helper_packing_is_required_in_both_modes() {
    let baseline = workflow();
    for case in [
        "new-publisher",
        "new-input",
        "wrong-run",
        "assemble",
        "helper-kind-gate",
        "helper-ignored",
        "helper-shared-archive",
        "missing-candidate-output",
    ] {
        let mut changed = baseline.clone();
        match case {
            "new-publisher" => {
                changed["jobs"]["recovery-rehearse"]["steps"][1]["with"]["artifact-ids"] =
                    "${{ needs.select.outputs.preparation-tool-artifact-id }}".into()
            }
            "new-input" => {
                changed["jobs"]["recovery-rehearse"]["steps"][2]["with"]["artifact-ids"] =
                    "${{ needs.assemble.outputs.prepared-artifact-id }}".into()
            }
            "wrong-run" => {
                changed["jobs"]["recovery-rehearse"]["steps"][1]["with"]["run-id"] =
                    "${{ github.run_id }}".into()
            }
            "assemble" => changed["jobs"]["recovery-rehearse"]["needs"]
                .as_sequence_mut()
                .unwrap()
                .push("assemble".into()),
            "missing-candidate-output" => {
                changed["jobs"]["assemble"]["outputs"]
                    .as_mapping_mut()
                    .unwrap()
                    .remove(Value::String("candidate-artifact-id".into()));
            }
            other => {
                let step = changed["jobs"]["select"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| step["id"].as_str() == Some("rehearsal-tool"))
                    .unwrap();
                match other {
                    "helper-kind-gate" => {
                        step["if"] = "steps.source.outputs.recovery-mode == 'reprepare'".into()
                    }
                    "helper-ignored" => step["continue-on-error"] = true.into(),
                    "helper-shared-archive" => {
                        step["with"]["path"] =
                            ".release/tool/memcordon-publication-tool.tar.gz".into()
                    }
                    _ => unreachable!(),
                }
            }
        }
        assert!(validate(&changed).is_err(), "{case}");
    }
}

#[test]
fn actual_writers_cannot_publish_candidates_or_substitute_the_rehearsed_original_pair() {
    let baseline = workflow();
    for writer in ["publish", "recovery-publish"] {
        for (index, replacement) in [
            (
                0,
                "${{ needs.select.outputs.preparation-tool-artifact-id }}",
            ),
            (1, "${{ needs.assemble.outputs.candidate-artifact-id }}"),
            (1, "${{ needs.rehearse.outputs.report }}"),
        ] {
            let mut changed = baseline.clone();
            changed["jobs"][writer]["steps"][index]["with"]["artifact-ids"] = replacement.into();
            assert!(validate(&changed).is_err(), "{writer}: {replacement}");
        }
        let mut ignored = baseline.clone();
        ignored["jobs"][writer]["steps"][4]["continue-on-error"] = true.into();
        assert!(validate(&ignored).is_err());
    }
}

#[test]
fn child_credential_removal_is_narrow_and_does_not_allow_environment_configuration() {
    let remove = br#"fn sanitize_child(command: &mut std::process::Command) { command.env_remove("GH_TOKEN"); }"#;
    policy::validate_rust_policy_bytes(
        Path::new("tools/memcordon-ci/src/rehearsal_support/coordinator.rs"),
        remove,
    )
    .unwrap();
    policy::validate_rust_policy_bytes(
        Path::new("tools/memcordon-ci/tests/release_rehearsal_http.rs"),
        remove,
    )
    .unwrap();
    for path in [
        "tools/memcordon-ci/src/rehearsal_support/server.rs",
        "tools/memcordon-ci/src/release/rehearsal.rs",
        "crates/example/src/lib.rs",
    ] {
        assert!(policy::validate_rust_policy_bytes(Path::new(path), remove).is_err());
    }
    let set = br#"fn run(command: &mut std::process::Command) { command.env("CUSTOM_REHEARSAL", "fixture"); }"#;
    assert!(
        policy::validate_rust_policy_bytes(
            Path::new("tools/memcordon-ci/src/rehearsal_support/coordinator.rs"),
            set
        )
        .is_err()
    );
}

#[test]
fn actual_new_rehearsal_sources_follow_policy_before_git_staging() {
    for relative in [
        "tools/memcordon-ci/src/bin/memcordon-release-rehearsal.rs",
        "tools/memcordon-ci/src/release/rehearsal.rs",
        "tools/memcordon-ci/src/release/rehearsal_input.rs",
        "tools/memcordon-ci/src/release/rehearsal_tool.rs",
        "tools/memcordon-ci/src/rehearsal_support/cases.rs",
        "tools/memcordon-ci/src/rehearsal_support/coordinator.rs",
        "tools/memcordon-ci/src/rehearsal_support/mod.rs",
        "tools/memcordon-ci/src/rehearsal_support/protocol.rs",
        "tools/memcordon-ci/src/rehearsal_support/server.rs",
        "tools/memcordon-ci/src/rehearsal_support/wire.rs",
        "tools/memcordon-ci/tests/release_rehearsal_http.rs",
        "tools/memcordon-ci/tests/release_rehearsal_tool.rs",
        "tools/memcordon-ci/tests/release_rehearsal_transport.rs",
        "tools/memcordon-ci/tests/release_rehearsal_workflow.rs",
    ] {
        let bytes = std::fs::read(root().join(relative)).unwrap();
        policy::validate_rust_policy_bytes(Path::new(relative), &bytes)
            .unwrap_or_else(|error| panic!("{relative}: {error}"));
    }
}

#[test]
fn isolated_proxy_fixture_accepts_only_literal_standard_proxy_keys() {
    let path = Path::new("tools/memcordon-ci/tests/release_rehearsal_transport.rs");
    let standard = br#"fn trap(command: &mut std::process::Command) { command.env("HTTP_PROXY", "http://127.0.0.1:12345").env("https_proxy", "http://127.0.0.1:12345").env("NO_PROXY", ""); }"#;
    policy::validate_rust_policy_bytes(path, standard).unwrap();
    for invalid in [
        br#"fn trap(command: &mut std::process::Command) { command.env("REHEARSAL_URL", "http://127.0.0.1:12345"); }"#.as_slice(),
        br#"fn trap(command: &mut std::process::Command, key: &str) { command.env(key, "value"); }"#,
        br#"fn trap(command: &mut std::process::Command) { command.envs([("HTTP_PROXY", "trap")]); }"#,
    ] { assert!(policy::validate_rust_policy_bytes(path, invalid).is_err()); }
    assert!(
        policy::validate_rust_policy_bytes(
            Path::new("tools/memcordon-ci/tests/release_rehearsal_process.rs"),
            standard
        )
        .is_err()
    );
}
