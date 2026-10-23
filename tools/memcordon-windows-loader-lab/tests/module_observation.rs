use memcordon_windows_loader_lab::module_observation::{
    EventKind, LoadOutcome, MappedName, MappedNameOutcome, ModuleTable, UnloadOutcome,
    classify_mapped_name,
};

#[test]
fn native_event_names_do_not_confuse_unload_and_debug_string() {
    let expected = [
        EventKind::Exception,
        EventKind::CreateThread,
        EventKind::CreateProcess,
        EventKind::ExitThread,
        EventKind::ExitProcess,
        EventKind::LoadDll,
        EventKind::UnloadDll,
        EventKind::OutputDebugString,
        EventKind::Rip,
    ];
    for (index, kind) in expected.into_iter().enumerate() {
        assert_eq!(EventKind::from_code(index as u32 + 1), kind);
    }
    assert_eq!(EventKind::from_code(0), EventKind::Unknown(0));
    assert_eq!(EventKind::from_code(u32::MAX), EventKind::Unknown(u32::MAX));
}

#[test]
fn module_generations_preserve_unknown_duplicate_unload_and_reuse() {
    let mut table = ModuleTable::new(2);
    assert_eq!(table.unload(10, 1).outcome, UnloadOutcome::UnknownBase);
    let first = table.load(10, 2);
    assert_eq!(first.outcome, LoadOutcome::FirstLoad);
    assert_eq!(first.generation, Some(1));
    let duplicate = table.load(10, 3);
    assert_eq!(duplicate.outcome, LoadOutcome::DuplicateLive);
    assert_eq!(duplicate.previous_load_sequence, Some(2));
    assert_eq!(duplicate.generation, Some(2));
    let unloaded = table.unload(10, 4);
    assert_eq!(unloaded.outcome, UnloadOutcome::Matched);
    assert_eq!(unloaded.load_sequence, Some(3));
    assert_eq!(unloaded.generation, Some(2));
    let again = table.unload(10, 5);
    assert_eq!(again.outcome, UnloadOutcome::AlreadyUnloaded);
    assert_eq!(again.previous_unload_sequence, Some(4));
    let reused = table.load(10, 6);
    assert_eq!(reused.outcome, LoadOutcome::ReusedBase);
    assert_eq!(reused.previous_generation, Some(2));
    assert_eq!(reused.generation, Some(3));
    assert_eq!(table.load(20, 7).outcome, LoadOutcome::FirstLoad);
    assert_eq!(table.load(30, 8).outcome, LoadOutcome::TableExhausted);
    table.unload(20, 9);
    assert_eq!(
        table.load(30, 10).outcome,
        LoadOutcome::TableExhausted,
        "unloaded tombstones must not lose generation history"
    );
    assert_eq!(table.unload(30, 11).outcome, UnloadOutcome::UnknownBase);
}

#[test]
fn mapped_names_report_observation_limits_and_ignore_stale_errors_on_success() {
    let text: Vec<u16> = "\\Device\\HarddiskVolume1\\known.dll"
        .encode_utf16()
        .collect();
    let mut buffer = text.clone();
    buffer.extend([0, 123]);
    let complete = classify_mapped_name(&buffer, text.len() as u32, Some(122));
    assert_eq!(complete.outcome, MappedNameOutcome::Complete);
    assert_eq!(complete.native_error, None);
    assert_eq!(
        complete.path.as_deref(),
        Some("\\Device\\HarddiskVolume1\\known.dll")
    );
    assert_eq!(complete.source, "held-process-mapped-section-path");
    let truncated = classify_mapped_name(&text, text.len() as u32, Some(122));
    assert_eq!(truncated.outcome, MappedNameOutcome::Truncated);
    assert!(truncated.truncated);
    assert_eq!(truncated.native_error, None);
    let failed = classify_mapped_name(&buffer, 0, Some(5));
    assert_eq!(failed.outcome, MappedNameOutcome::NativeFailure);
    assert_eq!(failed.native_error, Some(5));
    assert!(failed.path.is_none());
    assert_eq!(
        classify_mapped_name(&[0xd800, 0], 1, None).outcome,
        MappedNameOutcome::InvalidUtf16
    );
    let split_surrogate = classify_mapped_name(&[0xd800], 1, None);
    assert_eq!(split_surrogate.outcome, MappedNameOutcome::InvalidUtf16);
    assert!(split_surrogate.truncated);
    assert!(split_surrogate.path.is_none());
    assert_eq!(
        classify_mapped_name(&[65, 0, 66, 0], 3, None).outcome,
        MappedNameOutcome::InvalidText
    );
    assert_eq!(
        MappedName::skipped_deadline(4096).outcome,
        MappedNameOutcome::SkippedDeadline
    );
}
