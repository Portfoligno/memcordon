#[path = "../src/release/linux_image_custody_completion.rs"]
mod completion;

#[test]
fn failed_diagnostics_and_normalization_or_merge_never_skip_native_settlement() {
    for normalized in [
        "normalization failed before image loop",
        "artifact merge conflict",
    ] {
        let calls = std::cell::Cell::new(0);
        let error = completion::finish(
            Ok(()),
            Err("diagnostic capture failed"),
            Err(normalized),
            || {
                calls.set(calls.get() + 1);
                Err("native custody retirement incomplete")
            },
        )
        .unwrap_err();
        assert_eq!(calls.get(), 1);
        assert!(error.starts_with("diagnostic capture failed"));
        assert!(error.contains(normalized));
        assert!(error.contains("native custody retirement incomplete"));
    }
}

#[test]
fn original_work_failure_stays_first_and_success_requires_settled_owners() {
    let calls = std::cell::Cell::new(0);
    let error = completion::finish(
        Err("original EMFILE"),
        Err("diagnostic failure"),
        Err("normalization failure"),
        || {
            calls.set(calls.get() + 1);
            Err("native cleanup failure")
        },
    )
    .unwrap_err();
    assert_eq!(calls.get(), 1);
    assert!(error.starts_with("original EMFILE"));
    assert!(error.contains("diagnostic failure"));
    assert!(error.contains("normalization failure"));
    assert!(error.contains("native cleanup failure"));
    assert_eq!(
        completion::finish(Ok(()), Ok(()), Ok(()), || Err("native cleanup failure")),
        Err("native cleanup failure".to_owned())
    );
    assert_eq!(
        completion::finish::<&str>(Ok(()), Ok(()), Ok(()), || Ok(())),
        Ok(())
    );
    assert!(
        completion::finish(Ok(()), Ok(()), Err("merge failed"), || Ok(()))
            .unwrap_err()
            .starts_with("merge failed")
    );
}
