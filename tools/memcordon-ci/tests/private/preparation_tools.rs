use super::*;

fn selected() -> Inputs {
    Inputs {
        kind: Kind::Private,
        source: BuildSourceIdentity::Working {
            version: semver::Version::new(1, 2, 3),
            commit: "a".repeat(40),
        },
        host: "x86_64-unknown-linux-gnu".into(),
        toolchains: "b".repeat(64),
        invocation: Invocation {
            repository: "owner/repo".into(),
            workflow: "Native backend tests".into(),
            run: "12".into(),
            attempt: "3".into(),
        },
        producer: "private-linux-prepare-x64".into(),
    }
}

#[test]
fn preparation_rejects_wrong_source_host_invocation_or_kind_before_reading_members() {
    let expected = selected();
    for field in [
        "source",
        "host",
        "run",
        "attempt",
        "repository",
        "workflow",
        "producer",
        "toolchains",
        "kind",
        "protocol",
    ] {
        let mut record: Record = serde_json::from_value(
            serde_json::json!({"format":FORMAT,"inputs":selected(),"files":[]}),
        )
        .unwrap();
        match field {
            "source" => {
                record.inputs.source = BuildSourceIdentity::Working {
                    version: semver::Version::new(1, 2, 3),
                    commit: "c".repeat(40),
                }
            }
            "host" => record.inputs.host = "aarch64-unknown-linux-gnu".into(),
            "run" => record.inputs.invocation.run = "13".into(),
            "attempt" => record.inputs.invocation.attempt = "4".into(),
            "repository" => record.inputs.invocation.repository = "other/repo".into(),
            "workflow" => record.inputs.invocation.workflow = "Release".into(),
            "producer" => record.inputs.producer = "private-linux-prepare-arm64".into(),
            "toolchains" => record.inputs.toolchains = "d".repeat(64),
            "kind" => record.inputs.kind = Kind::Readiness,
            "protocol" => record.format = FORMAT + 1,
            _ => unreachable!(),
        }
        let error = validate(
            Path::new("/definitely-absent-preparation-root"),
            &record,
            &expected,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("source, host, protocol or invocation differs"),
            "{field}: {error}"
        );
    }
}

#[test]
fn producer_hosts_are_closed_and_records_do_not_accept_test_certificates() {
    assert_eq!(
        producer(Kind::Private, "aarch64-unknown-linux-gnu").unwrap(),
        "private-linux-prepare-arm64"
    );
    assert_eq!(
        producer(Kind::Readiness, "aarch64-pc-windows-msvc").unwrap(),
        "readiness-tools-windows-arm64"
    );
    assert!(producer(Kind::Private, "x86_64-pc-windows-msvc").is_err());
    assert!(producer(Kind::ReleaseFuzz, "aarch64-unknown-linux-gnu").is_err());
    let mut record = serde_json::json!({"format":FORMAT,"inputs":selected(),"files":[]});
    record["tests-passed"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<Record>(record).is_err());
}

#[test]
fn byte_inventory_detects_changed_members_and_refuses_symlinks_and_size_growth() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("image.json"), b"first").unwrap();
    let paths = [PathBuf::from("image.json")];
    let initial = records(temp.path(), &paths).unwrap();
    std::fs::write(temp.path().join("image.json"), b"other").unwrap();
    assert_ne!(initial, records(temp.path(), &paths).unwrap());
    assert!(read(temp.path(), Path::new("image.json"), 2).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(temp.path().join("image.json"), temp.path().join("linked"))
            .unwrap();
        assert!(read(temp.path(), Path::new("linked"), 100).is_err());
    }
}
