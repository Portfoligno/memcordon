use super::*;

#[test]
fn unresolved_source_admission_prevents_work_even_after_optional_budget_exhaustion() {
    let root = tempfile::tempdir().unwrap();
    let source = SourceSession {
        family: DownloadFamily::Workspace,
        before: WorkOutcome::observed(
            Err(CiError::Message("actual source owner unresolved".into())),
            WriterSettlement::Unknown,
        )
        .into_result(),
        slot: "source",
        partial: true,
    };
    assert!(source.blocks_work());
    let session = Session {
        scopes: Vec::new(),
        source: Some(source),
        tool_sources: Vec::new(),
        images: Vec::new(),
        setup_error: None,
        source_not_started: true,
        cache_remaining: Duration::ZERO,
        scope_writers: Default::default(),
    };
    let mut started = false;
    let failure = session
        .execute(root.path(), || {
            started = true;
            Ok(())
        })
        .unwrap_err();
    assert!(
        !started,
        "unsafe source admission must prevent actual mutation"
    );
    assert!(crate::work_outcome::has_unresolved_owner(&failure));
    assert!(
        failure
            .to_string()
            .contains("actual source owner unresolved")
    );
    assert!(
        root.path().read_dir().unwrap().next().is_none(),
        "blocked finalization must not create native probe or transfer state"
    );
}
