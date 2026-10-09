use memcordon_readiness_verifier::*;
use serde_json::json;

#[path = "support/operational_parser_receipts.rs"]
mod operational_parser_receipts;

const MANIFEST: &str = include_str!("../../../ci/consumer-readiness-v1.toml");

/// Explicit native component invocation only. The controller supplies a fresh
/// owned directory through bounded stdin, never ambient CI configuration.
#[test]
#[ignore = "requires an explicitly owned native component receipt directory"]
fn native_index_mutations_emit_actual_parser_receipts() {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        run_id: String,
        recipe_id: String,
        native_target: String,
        artifact_root: std::path::PathBuf,
        artifact_prefix: String,
        challenge: Vec<u8>,
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 64 * 1024);
    let input: Input = serde_json::from_value(validate_json_document(&bytes).unwrap()).unwrap();
    assert!(!input.run_id.is_empty() && !input.recipe_id.is_empty() && input.challenge.len() == 32);
    assert!(input.artifact_root.is_absolute() && input.artifact_root.is_dir());
    assert!(
        !input.artifact_prefix.is_empty()
            && input
                .artifact_prefix
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && !input.artifact_prefix.contains(['\\', ':'])
    );
    let target = match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "windows") => "x86_64-pc-windows-msvc",
        ("aarch64", "windows") => "aarch64-pc-windows-msvc",
        _ => panic!("unsupported native component target"),
    };
    assert_eq!(input.native_target, target);
    let executable = std::env::current_exe().unwrap();
    let mut executable_bytes = Vec::new();
    std::fs::File::open(executable)
        .unwrap()
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut executable_bytes)
        .unwrap();
    assert!(executable_bytes.len() <= 512 * 1024 * 1024);
    let write = |name: &str, bytes: &[u8]| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(input.artifact_root.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        format!("{}/{}", input.artifact_prefix, name)
    };
    let manifest = write("manifest.toml", MANIFEST.as_bytes());
    let base = structural_index();
    let base_bytes = serde_json::to_vec(&base).unwrap();
    let base_path = write("base-index.json", &base_bytes);
    let mut observations = Vec::new();
    for scenario in ["omitted-case", "duplicate-case", "wrong-product"] {
        let mut changed = base.clone();
        match scenario {
            "omitted-case" => {
                changed.records.pop();
            }
            "duplicate-case" => changed.records.push(changed.records[0].clone()),
            _ => {
                changed
                    .records
                    .iter_mut()
                    .find(|row| row.key.evidence_class == EvidenceClass::InstalledProduct)
                    .unwrap()
                    .key
                    .channel = Some("unselected-product".into())
            }
        }
        let path = write(
            &format!("{scenario}-index.json"),
            &serde_json::to_vec(&changed).unwrap(),
        );
        let refusal = verify(
            &input.artifact_root.join("manifest.toml"),
            &input.artifact_root.join(format!("{scenario}-index.json")),
            &input.artifact_root,
        )
        .unwrap_err();
        assert!(refusal.contains("missing/duplicate/unexpected/reclassified"));
        observations.push(json!({"scenario":scenario,"base_input":base_path,"mutated_input":path,"operation":"independent-evidence-index-frozen-inventory","actual_refusal":refusal,"baseline_profile_ready":false}));
    }
    let receipt = json!({"format":"memcordon.native-parser-mutation-receipt","revision":1,"run_id":input.run_id,"recipe_id":input.recipe_id,"test_name":"native_index_mutations_emit_actual_parser_receipts","native_target":target,
        "executable_sha256":hex::encode(Sha256::digest(executable_bytes)),"challenge_sha256":hex::encode(Sha256::digest(input.challenge)),"manifest":manifest,"observations":observations});
    write(
        "native-receipt.json",
        &serde_json::to_vec(&receipt).unwrap(),
    );
}

#[test]
fn immutable_downloaded_archive_rejects_attempt_relabel_and_raw_member_substitution() {
    use std::io::Write;
    for mutation in 0..4 {
        let temp = tempfile::tempdir().unwrap();
        let mut index = structural_index();
        index.job_outcomes = ["linux-x64", "linux-arm64", "windows-x64", "windows-arm64"]
            .into_iter()
            .flat_map(|target| {
                [
                    format!("native-{target}"),
                    format!("candidate-{target}-native"),
                    format!("candidate-{target}-cargo"),
                    format!("public-{target}-native"),
                    format!("public-{target}-cargo"),
                ]
            })
            .map(|job| JobOutcome {
                job,
                result: JobResult::Missing,
            })
            .collect();
        let raw = Artifact {
            path: "raw.bin".into(),
            length: 3,
            sha256: sha256(b"old"),
        };
        let payload = ProducerManifest {
            format: "memcordon.consumer-readiness.producer".into(),
            revision: 1,
            job: "candidate-linux-x64-native".into(),
            run_id: "original-run".into(),
            run_attempt: 1,
            source_commit: index.source_commit.clone(),
            source_tree_sha256: index.source_tree_sha256.clone(),
            version: index.version.clone(),
            manifest_sha256: index.manifest_sha256.clone(),
            artifacts: vec![raw.clone()],
            products: vec![],
            component_builds: vec![],
            records: vec![],
        };
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        writer
            .start_file("producer-manifest.json", options)
            .unwrap();
        writer
            .write_all(&serde_json::to_vec(&payload).unwrap())
            .unwrap();
        writer.start_file("raw.bin", options).unwrap();
        writer
            .write_all(if mutation == 2 { b"new" } else { b"old" })
            .unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        std::fs::write(temp.path().join("original.zip"), &bytes).unwrap();
        std::fs::write(temp.path().join("raw.bin"), b"old").unwrap();
        index.artifacts = vec![
            raw,
            Artifact {
                path: "original.zip".into(),
                length: bytes.len() as u64,
                sha256: sha256(&bytes),
            },
        ];
        index.producer_origins = vec![ProducerOrigin {
            job: payload.job,
            run_id: payload.run_id,
            run_attempt: if mutation == 1 { 2 } else { 1 },
            artifact_id: "17".into(),
            artifact_sha256: if mutation == 3 {
                "3".repeat(64)
            } else {
                sha256(&bytes)
            },
            bundle_artifact: "original.zip".into(),
            source_commit: index.source_commit.clone(),
            source_tree_sha256: index.source_tree_sha256.clone(),
            version: index.version.clone(),
            manifest_sha256: index.manifest_sha256.clone(),
            repository: None,
        }];
        let manifest = temp.path().join("manifest.toml");
        let input = temp.path().join("index.json");
        std::fs::write(&manifest, MANIFEST).unwrap();
        std::fs::write(&input, serde_json::to_vec(&index).unwrap()).unwrap();
        let observed = verify(&manifest, &input, temp.path());
        match mutation {
            // This deliberately incomplete vector tests archive custody only;
            // it supplies no products, native executions or successful rows.
            0 => assert!(observed.is_err() || !observed.unwrap().profile_ready),
            1 => assert!(
                observed
                    .unwrap_err()
                    .contains("original producer ZIP run/attempt/source/profile")
            ),
            2 => assert!(observed.unwrap_err().contains("raw evidence bytes differ")),
            _ => assert!(
                observed
                    .unwrap_err()
                    .contains("downloaded producer archive digest differs")
            ),
        }
    }
}

fn linux_joint() -> CaseKey {
    CaseKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: Some("candidate-native".into()),
        evidence_class: EvidenceClass::InstalledProduct,
        family: "L-MIX-01".into(),
        scenario: "joint-build-tcp-unix-http".into(),
    }
}

fn structural_index() -> EvidenceIndex {
    let cases = validate_manifest(MANIFEST.as_bytes())
        .expect("checked-in manifest matches independent anchors");
    EvidenceIndex {
        format: "memcordon.consumer-readiness.evidence".into(),
        revision: 1,
        profile: PROFILE.into(),
        run_id: "mutation-run".into(),
        source_commit: "1".repeat(40),
        source_tree_sha256: "2".repeat(64),
        version: "0.5.8-dev".into(),
        manifest_sha256: sha256(MANIFEST.as_bytes()),
        repository: None,
        products: Vec::new(),
        component_builds: Vec::new(),
        producer_origins: Vec::new(),
        job_outcomes: Vec::new(),
        assessment_failures: Vec::new(),
        workflow_cells: [
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
        ]
        .into_iter()
        .flat_map(|target| {
            [
                "candidate-native",
                "candidate-cargo",
                "public-native",
                "public-cargo",
            ]
            .into_iter()
            .map(move |channel| ProductKey {
                target: target.into(),
                channel: channel.into(),
            })
        })
        .collect(),
        fixture_cases: cases.iter().cloned().collect(),
        artifacts: Vec::new(),
        records: cases
            .into_iter()
            .map(|key| CaseRecord {
                key,
                run_id: "mutation-run".into(),
                state: CaseState::NotRun,
                reason: None,
                evidence: None,
            })
            .collect(),
    }
}

#[test]
fn frozen_semantic_anchors_include_joint_churn_all_native_channels_and_channel_free_regressions() {
    let cases = validate_manifest(MANIFEST.as_bytes()).unwrap();
    assert!(cases.contains(&linux_joint()));
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        for channel in [
            "candidate-native",
            "candidate-cargo",
            "public-native",
            "public-cargo",
        ] {
            assert!(cases.contains(&CaseKey {
                target: target.into(),
                channel: Some(channel.into()),
                evidence_class: EvidenceClass::InstalledProduct,
                family: "W-CHURN".into(),
                scenario: "natural-4096-three-generations".into()
            }));
        }
        assert!(cases.contains(&CaseKey {
            target: target.into(),
            channel: None,
            evidence_class: EvidenceClass::NativeComponentRegression,
            family: "W-WRITER".into(),
            scenario: "readback-error".into()
        }));
    }
    assert!(!cases.iter().any(|case| case.evidence_class
        == EvidenceClass::NativeComponentRegression
        && case.channel.is_some()));
}

#[test]
fn coordinated_manifest_and_result_deletion_cannot_narrow_required_semantics() {
    let temp = tempfile::tempdir().unwrap();
    let mut manifest: Manifest = toml::from_str(MANIFEST).unwrap();
    manifest.cases.retain(|case| case.family != "L-MIX-01");
    let modified = toml::to_string(&manifest).unwrap();
    let mut report = structural_index();
    report.records.retain(|row| row.key.family != "L-MIX-01");
    report.fixture_cases.retain(|row| row.family != "L-MIX-01");
    report.manifest_sha256 = sha256(modified.as_bytes());
    let manifest_path = temp.path().join("manifest.toml");
    let report_path = temp.path().join("evidence-index.json");
    std::fs::write(&manifest_path, modified).unwrap();
    std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
    let error = verify(&manifest_path, &report_path, temp.path()).unwrap_err();
    assert!(
        error.contains("omits independently pinned semantic group"),
        "{error}"
    );
}

#[test]
fn scenario_class_parameters_and_crosswalk_cannot_be_changed_to_observed_results() {
    for mutate in 0..5 {
        let mut manifest: Manifest = toml::from_str(MANIFEST).unwrap();
        match mutate {
            0 => manifest.windows_churn_creations = 64,
            1 => manifest.channels.retain(|c| c != "public-cargo"),
            2 => {
                manifest
                    .cases
                    .iter_mut()
                    .find(|c| c.family == "W-CHURN")
                    .unwrap()
                    .evidence_class = EvidenceClass::NativeComponentRegression
            }
            3 => manifest
                .cases
                .iter_mut()
                .find(|c| c.family == "L-MIX-01")
                .unwrap()
                .requirements
                .clear(),
            _ => manifest
                .cases
                .iter_mut()
                .find(|c| c.family == "W-IO")
                .unwrap()
                .scenarios
                .retain(|s| s != "embedded-nul"),
        }
        assert!(validate_manifest(toml::to_string(&manifest).unwrap().as_bytes()).is_err());
    }
}

#[test]
fn omitted_duplicate_unknown_and_reclassified_rows_are_rejected_before_product_assessment() {
    for mutation in 0..4 {
        let temp = tempfile::tempdir().unwrap();
        let mut report = structural_index();
        match mutation {
            0 => {
                report.records.pop();
            }
            1 => report.records.push(report.records[0].clone()),
            2 => report.records[0].key.scenario = "invented-success".into(),
            _ => {
                report
                    .records
                    .iter_mut()
                    .find(|row| row.key.evidence_class == EvidenceClass::InstalledProduct)
                    .unwrap()
                    .key
                    .evidence_class = EvidenceClass::NativeComponentRegression
            }
        }
        let manifest = temp.path().join("manifest.toml");
        let input = temp.path().join("index.json");
        std::fs::write(&manifest, MANIFEST).unwrap();
        std::fs::write(&input, serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(
            verify(&manifest, &input, temp.path())
                .unwrap_err()
                .contains("missing/duplicate/unexpected/reclassified")
        );
    }
}

#[test]
fn duplicate_json_keys_at_any_depth_and_trailing_or_float_values_are_rejected() {
    for value in [
        r#"{"a":1,"a":2}"#,
        r#"{"nested":{"x":1,"x":1}}"#,
        r#"{"a":[{"kind":"old","kind":"forged"}]}"#,
        "{}{}",
        r#"{"revision":1.0}"#,
    ] {
        assert!(validate_json_document(value.as_bytes()).is_err(), "{value}");
    }
    assert_eq!(
        validate_json_document(br#"{"empty":[],"nul":"\u0000"}"#).unwrap(),
        json!({"empty": [], "nul": "\0"})
    );
}

#[test]
fn candidate_scope_does_not_delete_public_inventory_or_accept_missing_observations() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("manifest.toml");
    let input = temp.path().join("index.json");
    std::fs::write(&manifest, MANIFEST).unwrap();
    let mut report = structural_index();
    for row in &mut report.records {
        if row
            .key
            .channel
            .as_ref()
            .is_some_and(|c| c.starts_with("public-"))
        {
            row.reason = Some("publication-pending".into());
        }
    }
    std::fs::write(&input, serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(
        verify_scoped(
            &manifest,
            &input,
            temp.path(),
            VerificationScope::CandidateBeforePublication
        )
        .is_err()
    );
    report.records.retain(|row| {
        !row.key
            .channel
            .as_ref()
            .is_some_and(|c| c.starts_with("public-"))
    });
    report.fixture_cases.retain(|row| {
        !row.channel
            .as_ref()
            .is_some_and(|c| c.starts_with("public-"))
    });
    std::fs::write(&input, serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(
        verify_scoped(
            &manifest,
            &input,
            temp.path(),
            VerificationScope::CandidateBeforePublication
        )
        .unwrap_err()
        .contains("fixture inventory")
    );
}

#[test]
fn required_job_outcomes_cannot_be_discovered_from_uploaded_successes() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("manifest.toml");
    let input = temp.path().join("index.json");
    std::fs::write(&manifest, MANIFEST).unwrap();
    let mut report = structural_index();
    // These are test-side literal source obligations, not runner enumeration.
    for label in ["linux-x64", "linux-arm64", "windows-x64", "windows-arm64"] {
        for (stage, kind) in [
            ("candidate", "native"),
            ("candidate", "cargo"),
            ("public", "native"),
            ("public", "cargo"),
        ] {
            report.job_outcomes.push(JobOutcome {
                job: format!("{stage}-{label}-{kind}"),
                result: JobResult::Success,
            });
        }
        report.job_outcomes.push(JobOutcome {
            job: format!("native-{label}"),
            result: JobResult::Success,
        });
    }
    for mutation in ["missing", "duplicate", "unexpected"] {
        let mut mutated = report.clone();
        match mutation {
            "missing" => {
                mutated.job_outcomes.pop();
            }
            "duplicate" => {
                mutated.job_outcomes.push(mutated.job_outcomes[0].clone());
            }
            _ => {
                mutated.job_outcomes[0].job = "unselected-component".into();
            }
        }
        std::fs::write(&input, serde_json::to_vec(&mutated).unwrap()).unwrap();
        assert!(
            verify(&manifest, &input, temp.path())
                .unwrap_err()
                .contains("producer job outcomes"),
            "{mutation}"
        );
    }
    for failures in [
        vec![String::new()],
        vec!["x".repeat(4097)],
        vec!["failure".into(); 65],
    ] {
        let mut failed = report.clone();
        failed.assessment_failures = failures;
        std::fs::write(&input, serde_json::to_vec(&failed).unwrap()).unwrap();
        assert!(
            verify(&manifest, &input, temp.path())
                .unwrap_err()
                .contains("assessment failure observation")
        );
    }
    let mut reassociated = report;
    reassociated.producer_origins.push(ProducerOrigin {
        job: "candidate-linux-x64-native".into(),
        run_id: "original-run".into(),
        run_attempt: 1,
        artifact_id: "17".into(),
        artifact_sha256: "5".repeat(64),
        source_commit: "9".repeat(40),
        bundle_artifact: "origin-archives/candidate-linux-x64-native.zip".into(),
        source_tree_sha256: reassociated.source_tree_sha256.clone(),
        version: reassociated.version.clone(),
        manifest_sha256: reassociated.manifest_sha256.clone(),
        repository: None,
    });
    std::fs::write(&input, serde_json::to_vec(&reassociated).unwrap()).unwrap();
    assert!(
        verify(&manifest, &input, temp.path())
            .unwrap_err()
            .contains("immutable origin/source/profile")
    );
}

#[test]
fn artifact_digest_length_duplicate_and_escape_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("bytes.bin"), [0, 255, 128]).unwrap();
    let artifact = Artifact {
        path: "bytes.bin".into(),
        length: 3,
        sha256: sha256(&[0, 255, 128]),
    };
    validate_artifact_custody(temp.path(), std::slice::from_ref(&artifact)).unwrap();
    assert!(validate_artifact_custody(temp.path(), &[artifact.clone(), artifact.clone()]).is_err());
    for path in [
        "../bytes.bin",
        "nested/../bytes.bin",
        "/bytes.bin",
        "nested\\bytes.bin",
        "C:bytes.bin",
        "./bytes.bin",
        "a//bytes.bin",
    ] {
        let bad = Artifact {
            path: path.into(),
            ..artifact.clone()
        };
        assert!(
            validate_artifact_custody(temp.path(), &[bad]).is_err(),
            "{path}"
        );
    }
    std::fs::write(temp.path().join("bytes.bin"), [1, 255, 128]).unwrap();
    assert!(
        validate_artifact_custody(temp.path(), &[artifact])
            .unwrap_err()
            .contains("custody differs")
    );
}

#[cfg(unix)]
#[test]
fn artifact_symlinks_ancestor_links_and_hardlinks_do_not_establish_custody() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("real")).unwrap();
    std::fs::write(temp.path().join("real/bytes.bin"), b"fresh").unwrap();
    symlink("real/bytes.bin", temp.path().join("link.bin")).unwrap();
    symlink("real", temp.path().join("alias")).unwrap();
    for path in ["link.bin", "alias/bytes.bin"] {
        assert!(
            validate_artifact_custody(
                temp.path(),
                &[Artifact {
                    path: path.into(),
                    length: 5,
                    sha256: sha256(b"fresh")
                }]
            )
            .is_err()
        );
    }
    std::fs::hard_link(
        temp.path().join("real/bytes.bin"),
        temp.path().join("hard.bin"),
    )
    .unwrap();
    assert!(
        validate_artifact_custody(
            temp.path(),
            &[Artifact {
                path: "hard.bin".into(),
                length: 5,
                sha256: sha256(b"fresh")
            }]
        )
        .is_err()
    );
}

#[test]
fn native_invocation_reconstruction_preserves_empty_and_raw_native_units() {
    let mut invocation = NativeInvocation {
        format: "memcordon.consumer-readiness.invocation".into(),
        revision: 1,
        arguments: NativeArguments::UnixBytes(vec![
            b"fixture".to_vec(),
            Vec::new(),
            vec![0xff, b'\\', b'"'],
        ]),
        executable_sha256: "1".repeat(64),
        environment: "env.json".into(),
        environment_sha256: "2".repeat(64),
        association_sha256: "3".repeat(64),
        budget_tokens: vec![BudgetToken {
            kind: "time".into(),
            token: "+1s".into(),
        }],
        memory_token: None,
        deadline_token: Some("+1s".into()),
    };
    let first = reconstruct_invocation_sha256(&invocation).unwrap();
    invocation.arguments =
        NativeArguments::UnixBytes(vec![b"fixture".to_vec(), vec![0xff, b'\\', b'"']]);
    assert_ne!(first, reconstruct_invocation_sha256(&invocation).unwrap());
    invocation.arguments = NativeArguments::WindowsUtf16(vec![vec![0xd800], Vec::new()]);
    let raw = reconstruct_invocation_sha256(&invocation).unwrap();
    invocation.arguments = NativeArguments::WindowsUtf16(vec![vec![0xfffd], Vec::new()]);
    assert_ne!(raw, reconstruct_invocation_sha256(&invocation).unwrap());
    invocation.budget_tokens.push(BudgetToken {
        kind: "time".into(),
        token: "+1s".into(),
    });
    assert!(reconstruct_invocation_sha256(&invocation).is_err());
}
