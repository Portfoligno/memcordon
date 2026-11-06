#[path = "../src/bin/memcordon-sealed-agent/windows/writer_lifecycle.rs"]
mod lifecycle;
use lifecycle::*;

fn owner() -> Owner {
    Owner {
        pid: 123,
        birth: 456,
    }
}
fn binding(seed: u64) -> Binding {
    Binding {
        attempt_id: String::from(memcordon_core::hash_bytes(&seed.to_le_bytes())),
        request_sha256: String::from(memcordon_core::hash_bytes(b"original request")),
        owner: Some(owner()),
        generation: seed + 1,
    }
}
fn row(history: History) -> WriterSnapshot {
    WriterSnapshot {
        history: history.snapshot(),
        registry_present: Some(true),
        pending: Some(3),
        quarantined: Some(false),
        publisher_native_code: None,
        thread: ThreadObservation::Running { tid: 7, birth: 789 },
        changed: false,
    }
}
fn snapshot(records: Vec<WriterSnapshot>) -> Snapshot {
    let present = records
        .iter()
        .filter(|row| row.registry_present == Some(true))
        .collect::<Vec<_>>();
    Snapshot {
        registry: Availability::Available,
        history: Availability::Available,
        current_owner: Some(owner()),
        total_lanes: Some(present.len()),
        total_pending: Some(present.iter().filter_map(|row| row.pending).sum()),
        total_quarantined: Some(
            present
                .iter()
                .filter(|row| row.quarantined == Some(true))
                .count(),
        ),
        records,
        evicted: 0,
        dropped: 0,
        changed: false,
        completed_before_cutoff: true,
    }
}
fn registered() -> History {
    let mut value = History::new(binding(1));
    value.transition(Stage::ReservationPublished, None);
    value.transition(Stage::WorkerCreateRequested, None);
    value.transition(Stage::WorkerCreated, None);
    value.transition(Stage::Registered, None);
    value
}

#[test]
fn healthy_pending_and_removed_lifecycle_are_distinct_and_never_retirement_authority() {
    let live = snapshot(vec![row(registered())]);
    let token = live.records[0].history.binding.attempt_id.clone();
    let value = diagnostic(&live, std::slice::from_ref(&token));
    assert_eq!(
        value["names"][0]["classification"],
        "current-local-lane-observed"
    );
    assert_eq!(value["records"][0]["pending"], 3);
    assert_eq!(value["total_pending"], 3);
    assert_eq!(value["total_quarantined"], 0);
    assert_eq!(diagnostic(&snapshot(Vec::new()), &[])["total_pending"], 0);
    let mut unavailable_history = live.clone();
    unavailable_history.history = Availability::Busy;
    assert_eq!(diagnostic(&unavailable_history, &[])["total_pending"], 3);
    unavailable_history.registry = Availability::Busy;
    assert!(diagnostic(&unavailable_history, &[])["total_pending"].is_null());
    assert_eq!(value["records"][0]["quarantined"], false);
    let mut publisher_failed = live.clone();
    publisher_failed.records[0].publisher_native_code = Some(5);
    assert_eq!(
        diagnostic(&publisher_failed, std::slice::from_ref(&token))["records"][0]["publisher_native_code"],
        5
    );
    assert_eq!(value["retirement_proof"], false);
    assert_eq!(value["native_error_domain"], "Win32");
    assert_eq!(value["current_file_binding"], false);
    let mut history = registered();
    history.transition(Stage::CloseRequested, None);
    history.transition(Stage::CloseSucceeded, None);
    history.transition(Stage::RegistryRemoved, None);
    history.transition(Stage::AdmissionRetireRequested, None);
    history.transition(Stage::AdmissionRetireFailed, Some(5));
    let mut removed = row(history);
    removed.registry_present = Some(false);
    removed.pending = None;
    removed.thread = ThreadObservation::Exited { tid: 7, birth: 789 };
    let value = diagnostic(&snapshot(vec![removed]), &[token]);
    assert_eq!(
        value["names"][0]["classification"],
        "retained-local-lifecycle-observed"
    );
    assert_eq!(value["records"][0]["last_native_error"], 5);
    assert_eq!(value["records"][0]["registry_removed"], true);
    assert_eq!(
        value["records"][0]["admission_retirement_returned_ok"],
        false
    );
    assert_eq!(value["records"][0]["thread"]["state"], "exited");
    assert_eq!(value["records"][0]["retirement_proof"], false);
}

#[test]
fn reservation_then_spawn_failure_survives_without_inventing_a_live_lane() {
    let mut initial = binding(2);
    initial.owner = None;
    let mut history = History::new(initial);
    history.bind_owner(owner());
    history.transition(Stage::ReservationPublished, None);
    history.transition(Stage::WorkerCreateRequested, None);
    history.transition(Stage::WorkerCreateFailed, Some(8));
    let mut writer = row(history);
    writer.registry_present = Some(false);
    writer.pending = None;
    writer.quarantined = None;
    writer.thread = ThreadObservation::NoHandle;
    let token = writer.history.binding.attempt_id.clone();
    let value = diagnostic(&snapshot(vec![writer]), &[token]);
    assert_eq!(value["records"][0]["reservation_published"], true);
    assert_eq!(value["records"][0]["registered"], false);
    assert_eq!(value["records"][0]["stage"], "worker-create-failed");
    assert_eq!(value["records"][0]["thread"]["state"], "no-handle");
    assert_eq!(
        value["names"][0]["classification"],
        "retained-local-lifecycle-observed"
    );
}

#[test]
fn missing_changed_contended_cutoff_and_other_incarnations_remain_unbound() {
    let original = snapshot(vec![row(registered())]);
    let token = original.records[0].history.binding.attempt_id.clone();
    for state in [
        Availability::Busy,
        Availability::Poisoned,
        Availability::Cutoff,
        Availability::Unsupported,
    ] {
        let mut changed = original.clone();
        changed.history = state;
        assert_eq!(
            diagnostic(&changed, std::slice::from_ref(&token))["names"][0]["classification"],
            "unbound-history-unavailable"
        );
    }
    for mutation in 0..7 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.changed = true,
            1 => changed.records[0].changed = true,
            2 => changed.completed_before_cutoff = false,
            3 => {
                changed.current_owner = Some(Owner {
                    pid: 999,
                    birth: 456,
                })
            }
            4 => changed.records[0].history.binding.owner = None,
            5 => changed.records.push(changed.records[0].clone()),
            6 => changed.dropped = 1,
            _ => unreachable!(),
        }
        let value = diagnostic(&changed, std::slice::from_ref(&token));
        assert!(
            value["names"][0]["classification"]
                .as_str()
                .unwrap()
                .starts_with("unbound-")
        );
        assert_eq!(value["foreign_owner_binding"], "unavailable");
        assert_eq!(value["retirement_proof"], false);
    }
    let unknown = binding(99).attempt_id;
    let mut evicted = original;
    evicted.evicted = 1;
    assert_eq!(
        diagnostic(&evicted, &[unknown])["names"][0]["classification"],
        "unbound-no-producer-history"
    );
}

#[test]
fn first_failed_transition_and_last_native_code_survive_later_stages_and_event_eviction() {
    let mut history = registered();
    history.transition(Stage::PublicationFailed, None);
    history.transition(Stage::SubmissionAccepted, None);
    history.transition(Stage::CloseFailed, Some(5));
    history.transition(Stage::CloseFailed, None);
    for _ in 0..100 {
        history.transition(Stage::PublicationCompleted, None);
    }
    let record = history.snapshot();
    assert_eq!(
        record.first_failure_event.as_ref().unwrap().stage,
        Stage::PublicationFailed
    );
    assert_eq!(
        record.first_failure_event.as_ref().unwrap().native_code,
        None
    );
    assert_eq!(record.last_native_error, Some(5));
    assert_eq!(record.last_native_error_stage, Some(Stage::CloseFailed));
    let value = diagnostic(&snapshot(vec![row(history)]), &[]);
    assert_eq!(
        value["records"][0]["first_failed_transition"]["stage"],
        "publication-failed"
    );
    assert_eq!(value["records"][0]["last_native_error"], 5);
    assert_eq!(value["records"][0]["stage"], "publication-completed");
    assert_eq!(value["retirement_proof"], false);
}

#[test]
fn bounded_projection_prioritizes_the_observed_name_over_old_terminal_rows() {
    let mut records = Vec::new();
    for index in 0..JOURNAL_RECORDS as u64 {
        let mut history = History::new(binding(index));
        history.transition(Stage::ReservationPublished, None);
        history.transition(Stage::WorkerCreateRequested, None);
        history.transition(Stage::WorkerCreated, None);
        history.transition(Stage::Registered, None);
        let current = index + 1 == JOURNAL_RECORDS as u64;
        if !current {
            history.transition(Stage::CloseRequested, None);
            history.transition(Stage::CloseSucceeded, None);
            history.transition(Stage::RegistryRemoved, None);
            history.transition(Stage::AdmissionRetireRequested, None);
            history.transition(Stage::AdmissionRetired, None);
        }
        let mut writer = row(history);
        writer.registry_present = Some(current);
        if !current {
            writer.thread = ThreadObservation::NotObserved;
            writer.pending = None;
            writer.quarantined = None;
        }
        records.push(writer);
    }
    let selected = records.last().unwrap().history.binding.attempt_id.clone();
    let value = diagnostic(&snapshot(records), std::slice::from_ref(&selected));
    assert_eq!(value["records"][0]["binding"]["attempt_id"], selected);
    assert_eq!(
        value["names"][0]["classification"],
        "current-local-lane-observed"
    );
    assert!(value["records_omitted"].as_u64().unwrap() > 0);
    assert!(serde_json::to_vec(&value).unwrap().len() <= RECORD_BYTES);
}

#[test]
fn bounded_events_keep_cumulative_facts_and_output_loss_is_explicit() {
    let mut history = registered();
    for stage in [
        Stage::SubmissionAccepted,
        Stage::SubmissionRefused,
        Stage::PublicationStarted,
        Stage::PublicationCompleted,
        Stage::PublicationFailed,
        Stage::CloseRequested,
        Stage::CloseFailed,
        Stage::RegistryRemoved,
        Stage::AdmissionRetireRequested,
        Stage::AdmissionRetired,
        Stage::AdmissionRetireFailed,
        Stage::ReservationFailed,
    ] {
        history.transition(stage, None);
    }
    for _ in 0..100 {
        history.transition(Stage::PublicationCompleted, None);
    }
    let record = history.snapshot();
    assert_eq!(record.events.len(), HISTORY_EVENTS);
    assert!(record.omitted_events > 0);
    assert!(
        record.reservation_published
            && record.registered
            && record.removed
            && record.admission_retired
    );
    history.bind_owner(Owner {
        pid: 999,
        birth: 888,
    });
    assert!(history.snapshot().binding_changed);
    let mut records = Vec::new();
    let mut names = Vec::new();
    for index in 0..JOURNAL_RECORDS as u64 + 4 {
        let history = History::new(binding(index));
        names.push(history.snapshot().binding.attempt_id.clone());
        records.push(row(history));
    }
    let mut sampled = snapshot(records);
    sampled.records[0].thread = ThreadObservation::Unavailable {
        native_code: Some(5),
    };
    sampled.records[1].thread = ThreadObservation::NotObserved;
    sampled.records[2].thread = ThreadObservation::NoHandle;
    sampled.records[3].thread = ThreadObservation::Cutoff;
    sampled.records[4].thread = ThreadObservation::Unavailable { native_code: None };
    let value = diagnostic(&sampled, &names);
    assert!(serde_json::to_vec(&value).unwrap().len() <= RECORD_BYTES);
    assert!(value["records"].as_array().unwrap().len() <= OUTPUT_ROWS);
    assert_eq!(value["names"].as_array().unwrap().len(), NAME_TOKENS);
    assert!(value["records_omitted"].as_u64().unwrap() > 0);
    assert!(value["names_omitted"].as_u64().unwrap() > 0);
    assert_eq!(value["acceptance_authority"], false);
}
