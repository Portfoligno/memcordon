use memcordon_ci::diagnostic_projection::{
    Limit, MAX_BYTES, MAX_DEPTH, MAX_ENTRIES, MAX_FILE_BYTES, Projection,
};

#[test]
fn admission_preserves_exact_existing_bounds() {
    use memcordon_ci::diagnostic_projection::{entry_limit, extent_limit};
    assert_eq!(entry_limit(127), None);
    assert_eq!(entry_limit(128), Some(Limit::Entries));
    assert_eq!(
        extent_limit(8, MAX_BYTES - MAX_FILE_BYTES, MAX_FILE_BYTES),
        None
    );
    assert_eq!(extent_limit(9, 0, 0), Some(Limit::Depth));
    assert_eq!(
        extent_limit(0, 0, MAX_FILE_BYTES + 1),
        Some(Limit::FileBytes)
    );
    assert_eq!(extent_limit(0, MAX_BYTES, 1), Some(Limit::AggregateBytes));
    assert_eq!(extent_limit(0, u64::MAX, 1), Some(Limit::AggregateBytes));
}

#[test]
fn diagnostic_completeness_cannot_replace_primary_outcome() {
    use memcordon_ci::{
        CiError,
        work_outcome::{WorkOutcome, join_completed},
    };
    let mut incomplete = Projection::Complete;
    incomplete.record_limit(Limit::Entries);
    let projection: memcordon_ci::Result<Projection> = Ok(incomplete);
    assert!(
        join_completed(
            WorkOutcome::from_result(Ok(())),
            WorkOutcome::from_result(projection.map(|_| ()))
        )
        .into_result()
        .is_ok()
    );
    let primary = Err(CiError::Message("original child exit 2".into()));
    let error = join_completed(
        WorkOutcome::from_result(primary),
        WorkOutcome::from_result(Ok(())),
    )
    .into_result()
    .unwrap_err();
    assert!(error.to_string().contains("original child exit 2"));
    assert!(
        join_completed(
            WorkOutcome::from_result(Ok(())),
            WorkOutcome::from_result(Err(CiError::Message(
                "destination publication failed".into()
            )))
        )
        .into_result()
        .is_err()
    );
}

#[test]
fn bounded_diagnostic_loss_is_explicit_without_fabricated_remaining_count() {
    let mut projection = Projection::Complete;
    assert_eq!(
        serde_json::to_value(&projection).unwrap()["status"],
        "complete"
    );
    for limit in [
        Limit::Entries,
        Limit::Depth,
        Limit::FileBytes,
        Limit::AggregateBytes,
    ] {
        projection.record_limit(limit);
        projection.record_limit(limit);
    }
    let value = serde_json::to_value(projection).unwrap();
    assert_eq!(value["status"], "incomplete");
    assert_eq!(value["limits"].as_array().unwrap().len(), 4);
    assert!(value["remaining_entries"].is_null());
    assert_eq!(
        (MAX_ENTRIES, MAX_BYTES, MAX_FILE_BYTES, MAX_DEPTH),
        (128, 64 * 1024 * 1024, 16 * 1024 * 1024, 8)
    );
}
