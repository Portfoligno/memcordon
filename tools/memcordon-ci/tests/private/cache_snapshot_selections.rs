use super::*;

#[test]
fn failed_snapshot_keeps_the_disjoint_completed_copy() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let mut first = fixture(directory.path(), SnapshotKind::Compiled);
    first.stage = root.join("first-stage");
    let mut second = fixture(directory.path(), SnapshotKind::Compiled);
    second.stage = root.join("second-stage");
    second.roots = vec![root.join("second-source")];
    fs::create_dir(&second.roots[0]).unwrap();
    fs::write(
        second.roots[0].join("dependency.rlib"),
        b"real completed output\n",
    )
    .unwrap();
    let (failed, observed) = std::sync::mpsc::sync_channel(1);
    let outcomes = finalize_copies(
        Instant::now() + Duration::from_secs(10),
        || {
            let result = create(&first, SnapshotKind::Compiled);
            assert!(result.is_err());
            failed.send(()).unwrap();
            result
        },
        move || {
            observed.recv_timeout(Duration::from_secs(5)).unwrap();
            create(&second, SnapshotKind::Compiled)
        },
    );
    assert!(outcomes[0].is_err());
    assert!(outcomes[1].is_ok(), "{:?}", outcomes[1]);
    assert!(directory.path().join("second-stage/index.json").is_file());
}

#[test]
fn growth_beyond_the_reserved_copy_budget_fails_before_staging() {
    let directory = tempfile::tempdir().unwrap();
    let selected = fixture(directory.path(), SnapshotKind::Compiled);
    fs::create_dir(&selected.roots[0]).unwrap();
    fs::write(selected.roots[0].join("dependency.rlib"), b"initial\n").unwrap();
    let reserved = reservation(&selected, SnapshotKind::Compiled).unwrap();
    fs::write(selected.roots[0].join("new.rlib"), b"additional\n").unwrap();
    COPY_RESERVATION.with(|slot| slot.set(Some(reserved)));
    let result = create(&selected, SnapshotKind::Compiled);
    COPY_RESERVATION.with(|slot| slot.set(None));
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("aggregate reservation")
    );
    assert!(!selected.stage.exists());
}

#[test]
fn new_staging_selections_are_finite_and_separate_from_v6_slots() {
    for (purpose, shard) in [
        ("quality", "complete"),
        ("msrv", "complete"),
        ("miri", "quarter-one"),
        ("deadline", "complete"),
        ("backend", "complete"),
        ("stress", "complete"),
    ] {
        assert_eq!(
            stage_relative(SnapshotKind::Compiled, purpose, shard, None).unwrap(),
            Path::new("target/ci-cache-export/recipe")
                .join(purpose)
                .join(shard)
        );
    }
    for tool in ["cargo-audit", "cargo-deny", "cargo-fuzz"] {
        assert_eq!(
            stage_relative(SnapshotKind::ToolBuild, tool, "complete", None).unwrap(),
            Path::new("target/ci-cache-export/tool-build").join(tool)
        );
        assert_eq!(
            cache_restore::tool_build_layout(tool, "complete")
                .unwrap()
                .directories,
            [Path::new("target/ci-tools-build").join(tool)]
        );
    }
    assert!(stage_relative(SnapshotKind::ToolBuild, "cargo-audit", "../complete", None).is_err());
    assert!(stage_relative(SnapshotKind::Compiled, "../quality", "complete", None).is_err());
    assert!(
        stage_relative(
            SnapshotKind::ToolBuild,
            "cargo-audit",
            "complete",
            Some(CompiledPartition::Product)
        )
        .is_err()
    );
    assert_eq!(
        stage_relative(
            SnapshotKind::Compiled,
            "native-debug",
            "complete",
            Some(CompiledPartition::NativeTests)
        )
        .unwrap(),
        Path::new("target/ci-cache-export/native-tests")
    );
    let miri = cache_restore::partition_layout(
        "miri",
        "quarter-one",
        Some(CompiledPartition::MiriTargets),
    )
    .unwrap();
    assert_eq!(
        miri.directories,
        [PathBuf::from("target/ci/miri-quarter-one")]
    );
    assert!(
        !miri
            .directories
            .iter()
            .any(|path| path.starts_with("target/ci-miri-sysroot"))
    );
}

fn fixture(root: &Path, kind: SnapshotKind) -> Selection {
    let root = root.canonicalize().unwrap();
    Selection {
        transfer: None,
        revision: 7,
        stage: root.join("stage"),
        roots: vec![root.join("first"), root.join("absent")],
        compatibility: "same-native-inputs".into(),
        input: "same-recipe".into(),
        family: if kind == SnapshotKind::ToolBuild {
            "tool-build-seed"
        } else {
            "compiled-seed"
        },
        count: 100,
        bytes: 1024 * 1024,
        metadata: 64 * 1024,
    }
}

#[test]
fn partial_compilation_and_tool_build_round_trip_a_populated_subset() {
    for kind in [SnapshotKind::Compiled, SnapshotKind::ToolBuild] {
        let directory = tempfile::tempdir().unwrap();
        let selected = fixture(directory.path(), kind);
        fs::create_dir(&selected.roots[0]).unwrap();
        fs::write(
            selected.roots[0].join("CACHEDIR.TAG"),
            b"Signature: 8a477f597d28d172789f06886806bc55\n",
        )
        .unwrap();
        fs::write(
            selected.roots[0].join("dependency.rlib"),
            b"real partial output",
        )
        .unwrap();
        create(&selected, kind).unwrap();
        fs::remove_dir_all(&selected.roots[0]).unwrap();
        import_selected(&selected, kind).unwrap();
        assert_eq!(
            fs::read(selected.roots[0].join("dependency.rlib")).unwrap(),
            b"real partial output"
        );
        assert!(!selected.roots[1].exists());
        fs::remove_dir_all(&selected.roots[0]).unwrap();
        assert!(
            import_selected(
                &selected,
                if kind == SnapshotKind::Compiled {
                    SnapshotKind::ToolBuild
                } else {
                    SnapshotKind::Compiled
                }
            )
            .is_err()
        );
        assert!(
            !selected.roots[0].exists(),
            "wrong snapshot class mutated live roots"
        );
    }
}

#[test]
fn empty_and_marker_only_payloads_are_unavailable() {
    let directory = tempfile::tempdir().unwrap();
    let selected = fixture(directory.path(), SnapshotKind::Compiled);
    assert!(create(&selected, SnapshotKind::Compiled).is_err());
    fs::create_dir(&selected.roots[0]).unwrap();
    fs::write(selected.roots[0].join("CACHEDIR.TAG"), b"marker alone").unwrap();
    assert!(create(&selected, SnapshotKind::Compiled).is_err());
    fs::write(selected.roots[0].join(".cargo-lock"), b"").unwrap();
    assert!(create(&selected, SnapshotKind::Compiled).is_err());
}

#[test]
fn completed_transfer_and_partial_seed_reject_each_others_manifest_before_mutation() {
    for complete in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let mut selected = fixture(directory.path(), SnapshotKind::Compiled);
        selected.revision = 8;
        selected.family = if complete {
            "compiled-transfer"
        } else {
            "compiled-transfer-seed"
        };
        selected.transfer = Some(TransferIdentity {
            complete,
            input: selected.input.clone(),
        });
        fs::create_dir(&selected.roots[0]).unwrap();
        fs::write(
            selected.roots[0].join("dependency.rlib"),
            b"real compiler cache bytes\n",
        )
        .unwrap();
        let key = create(&selected, SnapshotKind::Compiled).unwrap();
        assert!(key.contains(if complete {
            "compiled-transfer-"
        } else {
            "compiled-transfer-seed-"
        }));
        fs::remove_dir_all(&selected.roots[0]).unwrap();
        selected.transfer.as_mut().unwrap().complete = !complete;
        assert!(import_selected(&selected, SnapshotKind::Compiled).is_err());
        assert!(!selected.roots[0].exists());
        selected.transfer.as_mut().unwrap().complete = complete;
        let mode = import_selected(&selected, SnapshotKind::Compiled).unwrap();
        assert!(matches!(
            (complete, mode),
            (true, cache_restore::RestoreMode::Exact)
                | (false, cache_restore::RestoreMode::Compatible)
        ));
        assert_eq!(
            fs::read(selected.roots[0].join("dependency.rlib")).unwrap(),
            b"real compiler cache bytes\n"
        );
    }
}
