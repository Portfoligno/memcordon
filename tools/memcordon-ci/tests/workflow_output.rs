use memcordon_ci::workflow_output::write_to;

#[test]
fn concurrent_output_batches_remain_complete_single_line_records() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("output");
    std::fs::write(&path, b"original=preserved\n").unwrap();
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let path = &path;
            scope.spawn(move || {
                for sequence in 0..128 {
                    write_to(
                        Some(path),
                        &[("release-notes", format!("unavailable-{worker}-{sequence}"))],
                    )
                    .unwrap();
                }
            });
        }
    });
    let output = std::fs::read_to_string(&path).unwrap();
    assert!(output.starts_with("original=preserved\n"));
    assert!(output.ends_with('\n'));
    let actual: std::collections::BTreeSet<_> = output.lines().skip(1).collect();
    let expected: std::collections::BTreeSet<_> = (0..8)
        .flat_map(|worker| {
            (0..128).map(move |sequence| format!("release-notes=unavailable-{worker}-{sequence}"))
        })
        .collect();
    assert_eq!(output.lines().count(), expected.len() + 1);
    assert_eq!(actual, expected.iter().map(String::as_str).collect());
}

#[test]
fn invalid_batch_never_opens_or_partially_changes_output() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("output");
    let values = [("valid", "first".into()), ("invalid", "line\rbreak".into())];
    let error = write_to(Some(&path), &values).unwrap_err();
    assert!(error.to_string().contains("safe bounded text"));
    assert!(!path.exists());
    std::fs::write(&path, b"original=preserved\n").unwrap();
    assert!(write_to(Some(&path), &values).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"original=preserved\n");
}

#[test]
fn multiline_delimiter_collision_and_invalid_control_are_handled_before_append() {
    let file = tempfile::NamedTempFile::new().unwrap();
    write_to(
        Some(file.path()),
        &[("paths", "MEMCORDON_CI_OUTPUT\nsecond".into())],
    )
    .unwrap();
    let before = std::fs::read(file.path()).unwrap();
    assert!(
        String::from_utf8(before.clone())
            .unwrap()
            .contains("paths<<MEMCORDON_CI_OUTPUT_\n")
    );
    for value in ["bad\rvalue", "bad\0value", "bad\u{1b}value"] {
        assert!(
            write_to(
                Some(file.path()),
                &[("safe", "would be valid".into()), ("unsafe", value.into())]
            )
            .is_err()
        );
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }
}
