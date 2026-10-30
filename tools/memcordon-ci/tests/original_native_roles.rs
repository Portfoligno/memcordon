use memcordon_ci::release::native_role_contract::{
    NativeRole, original_roles, validate_original_roles,
};

#[test]
fn current_producer_roles_are_the_only_admitted_consumer_pair() {
    for target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    ] {
        let roles = original_roles(target).unwrap();
        assert_eq!(
            roles[0],
            NativeRole {
                role: "operational",
                package: "memcordon",
                test: "sealed_agent",
                features: Some(if target.contains("windows") {
                    "windows-sealed-runtime,test-support"
                } else {
                    "private-tcp,test-support"
                })
            }
        );
        assert_eq!(
            roles[1],
            NativeRole {
                role: "parser",
                package: "memcordon-readiness-verifier",
                test: "current_parser_receipts",
                features: None
            }
        );
        validate_original_roles(target, roles.into_iter()).unwrap();
        validate_original_roles(target, roles.into_iter().rev()).unwrap();
        for changed in [
            NativeRole {
                test: "contract",
                ..roles[1]
            },
            NativeRole {
                package: "memcordon",
                ..roles[1]
            },
            NativeRole {
                role: "operational",
                ..roles[1]
            },
            NativeRole {
                features: Some("test-support"),
                ..roles[1]
            },
            NativeRole {
                features: Some(""),
                ..roles[1]
            },
        ] {
            assert!(validate_original_roles(target, [roles[0], changed].into_iter()).is_err());
        }
        let other_features = if target.contains("windows") {
            "private-tcp,test-support"
        } else {
            "windows-sealed-runtime,test-support"
        };
        assert!(
            validate_original_roles(
                target,
                [
                    NativeRole {
                        features: Some(other_features),
                        ..roles[0]
                    },
                    roles[1]
                ]
                .into_iter()
            )
            .is_err()
        );
        for invalid in [
            vec![],
            vec![roles[0]],
            vec![roles[0], roles[0]],
            vec![roles[1], roles[1]],
            vec![roles[0], roles[1], roles[1]],
        ] {
            assert!(validate_original_roles(target, invalid.into_iter()).is_err());
        }
    }
    assert!(original_roles("unsupported").is_err());
}

#[test]
fn rejected_role_details_are_bounded_and_keep_the_current_expected_tuple() {
    let roles = original_roles("aarch64-unknown-linux-gnu").unwrap();
    let enormous = "x".repeat(1024 * 1024);
    let invalid = NativeRole {
        role: &enormous,
        ..roles[1]
    };
    let error =
        validate_original_roles("aarch64-unknown-linux-gnu", [roles[0], invalid].into_iter())
            .unwrap_err()
            .to_string();
    assert!(error.len() < 4096);
    assert!(error.contains("current_parser_receipts"));
    assert!(error.contains("observed_count=2"));
    assert!(error.contains("failing_role=parser"));
    assert!(!error.contains(&enormous));
}

#[test]
fn acquisition_records_survive_failure_as_diagnostics_not_readiness_products() {
    let workflow = memcordon_ci::workflow_definitions::definition("release.yml").unwrap();
    for name in [
        "native-linux-x64",
        "native-linux-arm64",
        "native-windows-x64",
        "native-windows-arm64",
    ] {
        let step = workflow["jobs"][name]["steps"]
            .as_sequence()
            .unwrap()
            .iter()
            .find(|step| {
                step["with"]["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("diagnostics-"))
            })
            .unwrap();
        // Existing branch cancellation normalization still permits failure retention.
        assert_eq!(step["if"], "!cancelled()");
        assert_eq!(step["continue-on-error"], true);
        let paths: Vec<_> = step["with"]["path"].as_str().unwrap().lines().collect();
        for record in [
            ".release/native-components/measured-harnesses.json",
            ".release/native-components/acquisition-origin.json",
            ".release/native-components/native-host.json",
            ".release/native-operation-deadline.json",
            ".release/native-readiness-identity.json",
        ] {
            assert!(paths.contains(&record), "{name}: missing {record}");
        }
        assert!(!paths.contains(&".release/native-readiness"));
    }
}
