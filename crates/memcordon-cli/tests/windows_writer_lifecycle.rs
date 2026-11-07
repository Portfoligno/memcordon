#[path = "../src/bin/memcordon-sealed-agent/windows/frame_write.rs"]
pub mod frame_write;
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
        publisher_failure: None,
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
        sampled_at: Some(std::time::Instant::now()),
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

fn publisher_event(redacted: bool) -> memcordon_core::CausalEventV1 {
    memcordon_core::CausalEventV1 {
        sequence: 1,
        origin: memcordon_core::DiagnosticOriginV1::RecordWriter,
        category: memcordon_core::FailureCategoryV1::Persistence,
        operation: memcordon_core::FailureOperationV1::StoreRecord,
        code: memcordon_core::FailureCodeV1::UnexpectedProviderFailure,
        native_code: Some(memcordon_core::NativeFailureCodeV1::Win32(5)),
        observed_phase: memcordon_core::AttemptObservationPhaseV1::Terminalizing,
        safe_detail: memcordon_core::SafeDiagnosticDetailV1::ProviderMessage {
            id: memcordon_core::SafeMessageIdV1::CommitNotConfirmed,
        },
        detail_redacted: redacted,
        detail_truncated: false,
        terminalization_reference: None,
    }
}

#[test]
fn publisher_error_is_exact_tuple_bound_redacted_and_never_changes_writer_state() {
    let mut history = registered();
    history.transition(Stage::PublicationFailed, Some(5));
    let mut failed = row(history);
    failed.quarantined = Some(true);
    failed.pending = Some(0);
    failed.publisher_failure = Some(PublisherFailureSnapshot::retained(
        failed.history.binding.clone(),
        &publisher_event(true),
        "private-user-path-must-not-be-published",
        false,
    ));
    let observed = snapshot(vec![failed]);
    let before = &observed.records[0];
    let value = publisher_diagnostic(&observed, before);
    assert_eq!(value["event"], serde_json::json!(publisher_event(true)));
    assert!(value["detail"].is_null());
    assert!(
        !serde_json::to_string(&value)
            .unwrap()
            .contains("private-user-path")
    );
    assert_eq!(value["state"], "first-retained-publisher-error-observed");
    assert_eq!(value["current_file_binding"], false);
    assert_eq!(value["retirement_proof"], false);
    assert_eq!(value["later_persistence_errors_substituted"], false);
    for field in ["attempt", "request", "generation", "owner"] {
        let mut changed = observed.clone();
        let source = &mut changed.records[0]
            .publisher_failure
            .as_mut()
            .unwrap()
            .binding;
        match field {
            "attempt" => {
                source.attempt_id = String::from(memcordon_core::hash_bytes(b"other-attempt"))
            }
            "request" => {
                source.request_sha256 = String::from(memcordon_core::hash_bytes(b"other-request"))
            }
            "generation" => source.generation += 1,
            "owner" => source.owner.as_mut().unwrap().birth += 1,
            _ => unreachable!(),
        }
        let value = publisher_diagnostic(&changed, &changed.records[0]);
        assert_eq!(value["state"], "unavailable-tuple-mismatch", "{field}");
        assert!(value["event"].is_null());
        assert!(value["detail"].is_null());
    }
    for state in [
        Availability::Busy,
        Availability::Poisoned,
        Availability::Cutoff,
    ] {
        let mut unavailable = observed.clone();
        unavailable.registry = state;
        assert_eq!(
            publisher_diagnostic(&unavailable, &unavailable.records[0])["state"],
            "unavailable-registry"
        );
    }
    let mut late = observed.clone();
    late.completed_before_cutoff = false;
    assert_eq!(
        publisher_diagnostic(&late, &late.records[0])["state"],
        "unavailable-original-cutoff"
    );
    let mut removed = observed.clone();
    removed.records[0].registry_present = Some(false);
    assert_eq!(
        publisher_diagnostic(&removed, &removed.records[0])["state"],
        "unavailable-local-lane-not-retained"
    );
    let mut absent = observed.clone();
    absent.records[0].publisher_failure = None;
    assert_eq!(
        publisher_diagnostic(&absent, &absent.records[0])["state"],
        "not-observed-for-local-lane"
    );
    assert_eq!(observed.records[0].quarantined, Some(true));
    assert_eq!(observed.records[0].pending, Some(0));
    assert_eq!(observed.records[0].history.stage, Stage::PublicationFailed);
    assert_eq!(observed.records[0].history.last_native_error, Some(5));
}

#[test]
fn publisher_detail_truncation_and_outer_omissions_preserve_fixed_report_bound() {
    let mut failed = row(registered());
    failed.publisher_failure = Some(PublisherFailureSnapshot::retained(
        failed.history.binding.clone(),
        &publisher_event(false),
        &"界".repeat(2000),
        false,
    ));
    let failure = failed.publisher_failure.as_ref().unwrap();
    assert!(failure.detail.len() <= PUBLISHER_DETAIL_BYTES);
    assert!(failure.truncated);
    assert!(failure.detail.is_char_boundary(failure.detail.len()));
    let observed = snapshot(vec![failed.clone()]);
    let value = publisher_diagnostic(&observed, &observed.records[0]);
    assert_eq!(value["detail"], failure.detail);
    assert_eq!(value["detail_truncated"], true);
    assert!(value["original_detail_total_bytes"].is_null());
    let value = diagnostic(&snapshot(vec![failed; OUTPUT_ROWS]), &[]);
    assert!(serde_json::to_vec(&value).unwrap().len() <= RECORD_BYTES);
    assert!(value["records_omitted"].as_u64().unwrap() > 0);
    let mut source_truncated = row(registered());
    source_truncated.publisher_failure = Some(PublisherFailureSnapshot::retained(
        source_truncated.history.binding.clone(),
        &publisher_event(false),
        "already shortened",
        true,
    ));
    let value = publisher_diagnostic(&snapshot(vec![source_truncated.clone()]), &source_truncated);
    assert_eq!(value["detail_truncated"], true);
}

#[test]
fn transport_substage_is_last_observed_for_exact_tuple_and_keeps_outer_driver_and_cutoffs() {
    use frame_write::{ProgressOutcome, ProgressPhase, WriteProgress};
    use std::time::{Duration, Instant};
    let sampled = Instant::now();
    let outer = sampled + Duration::from_secs(10);
    let inner = sampled + Duration::from_secs(20);
    let mut history = registered();
    history.transition(Stage::PublicationCompleted, None);
    history.driver_transition(DriverPhase::TerminalDelivery, DriverOutcome::Attempted);
    let source = history.snapshot().binding;
    let before = history.snapshot();
    let attempted = WriteProgress {
        phase: ProgressPhase::PayloadWrite,
        outcome: ProgressOutcome::Attempted,
        expected_bytes: Some(20),
        transferred_bytes: 5,
        native_code: None,
        observed_write_count: None,
        native_call_succeeded: None,
    };
    assert!(history.transport_transition(
        &source,
        TransportUpdate {
            progress: attempted,
            outer_cutoff: outer,
            inner_cutoff: inner
        }
    ));
    let after = history.snapshot();
    assert_eq!(after.stage, before.stage);
    assert_eq!(
        after.last_driver_event.as_ref().unwrap().outcome,
        DriverOutcome::Attempted
    );
    assert!(!after.admission_retired);
    assert!(!after.removed);
    let mut observed = snapshot(vec![row(history)]);
    observed.sampled_at = Some(sampled);
    let value = transport_diagnostic(&observed, &observed.records[0]);
    assert_eq!(value["last_observed"]["progress"]["outcome"], "attempted");
    assert_eq!(value["last_observed"]["progress"]["transferred_bytes"], 5);
    assert!(value["last_observed"]["progress"]["observed_write_count"].is_null());
    assert_eq!(
        value["last_observed"]["selected_outer_cutoff_remaining_millis_at_sample"],
        10000
    );
    assert_eq!(
        value["last_observed"]["selected_inner_cutoff_remaining_millis_at_sample"],
        20000
    );
    assert!(value["last_observed"]["stage_qpc"].is_null());
    assert_eq!(value["current_blocking_api_proved"], false);
    assert_eq!(value["retained_worker_thread_is_context_only"], true);
    assert!(value["executing_io_thread_identity"].is_null());
    observed.sampled_at = Some(inner + Duration::from_secs(1));
    observed.completed_before_cutoff = false;
    let value = transport_diagnostic(&observed, &observed.records[0]);
    assert_eq!(
        value["last_observed"]["outer_cutoff_expired_at_sample"],
        true
    );
    assert_eq!(
        value["last_observed"]["inner_cutoff_expired_at_sample"],
        true
    );
    assert_eq!(value["sample_completed_before_original_cutoff"], false);
    observed.sampled_at = None;
    assert!(transport_diagnostic(&observed,&observed.records[0])["last_observed"]["inner_cutoff_expired_at_sample"].is_null());
}

#[test]
fn transport_partial_failure_and_foreign_or_dropped_updates_never_mint_completion() {
    use frame_write::{ProgressOutcome, ProgressPhase, WriteProgress};
    use std::time::{Duration, Instant};
    let cutoff = Instant::now() + Duration::from_secs(2);
    let mut history = registered();
    let source = history.snapshot().binding;
    let failure = WriteProgress {
        phase: ProgressPhase::HeaderWrite,
        outcome: ProgressOutcome::ReturnedError,
        expected_bytes: Some(4),
        transferred_bytes: 2,
        native_code: Some(232),
        observed_write_count: Some(1),
        native_call_succeeded: Some(false),
    };
    let update = TransportUpdate {
        progress: failure,
        outer_cutoff: cutoff,
        inner_cutoff: cutoff,
    };
    assert!(history.transport_transition(&source, update));
    for field in ["request", "attempt", "generation", "owner"] {
        let mut foreign = source.clone();
        match field {
            "request" => {
                foreign.request_sha256 =
                    String::from(memcordon_core::hash_bytes(b"foreign request"))
            }
            "attempt" => {
                foreign.attempt_id = String::from(memcordon_core::hash_bytes(b"foreign attempt"))
            }
            "generation" => foreign.generation += 1,
            "owner" => foreign.owner.as_mut().unwrap().birth += 1,
            _ => unreachable!(),
        }
        assert!(!history.transport_transition(&foreign, update));
    }
    let finish = WriteProgress {
        phase: ProgressPhase::WatcherFinish,
        outcome: ProgressOutcome::ReturnedOk,
        expected_bytes: None,
        transferred_bytes: 0,
        native_code: None,
        observed_write_count: None,
        native_call_succeeded: None,
    };
    assert!(history.transport_transition(
        &source,
        TransportUpdate {
            progress: finish,
            ..update
        }
    ));
    let mut observed = snapshot(vec![row(history)]);
    observed.dropped = 3;
    observed.changed = true;
    let value = transport_diagnostic(&observed, &observed.records[0]);
    assert_eq!(value["first_failure"]["progress"]["native_code"], 232);
    assert_eq!(value["first_failure"]["progress"]["transferred_bytes"], 2);
    assert_eq!(
        value["last_observed"]["progress"]["phase"],
        "watcher-finish"
    );
    assert_eq!(value["updates_rejected"], 4);
    assert_eq!(value["global_diagnostic_updates_dropped"], 3);
    assert_eq!(value["updates_complete"], false);
    assert_eq!(value["retirement_proof"], false);
    assert!(!observed.records[0].history.admission_retired);
    assert!(observed.records[0].history.last_driver_event.is_none());
    let mut rebound = registered();
    let source = rebound.snapshot().binding;
    assert!(rebound.transport_transition(&source, update));
    rebound.bind_owner(Owner {
        birth: owner().birth + 1,
        ..owner()
    });
    let rebound = snapshot(vec![row(rebound)]);
    assert!(rebound.records[0].history.binding_changed);
    assert_eq!(
        transport_diagnostic(&rebound, &rebound.records[0])["state"],
        "unavailable-producer-tuple"
    );
    let rendered = diagnostic(&observed, &[]);
    assert!(serde_json::to_vec(&rendered).unwrap().len() <= RECORD_BYTES);
}

#[test]
fn driver_progress_preserves_writer_state_and_first_failure() {
    let mut history = registered();
    history.transition(Stage::PublicationCompleted, None);
    let before = history.snapshot();
    history.driver_transition(DriverPhase::TerminalAckWait, DriverOutcome::Attempted);
    history.driver_transition(DriverPhase::TerminalAckWait, DriverOutcome::Failed);
    history.driver_transition(DriverPhase::AckValidation, DriverOutcome::Failed);
    history.driver_transition(DriverPhase::WriterRetire, DriverOutcome::Succeeded);
    let after = history.snapshot();
    assert_eq!(after.stage, before.stage);
    assert_eq!(after.registered, before.registered);
    assert!(!after.removed);
    assert!(!after.admission_retired);
    assert!(after.first_failure_event.is_none());
    assert_eq!(after.sequence, before.sequence + 4);
    assert_eq!(
        after.first_driver_failure.unwrap().phase,
        DriverPhase::TerminalAckWait
    );
    assert_eq!(
        after.last_driver_event.unwrap().outcome,
        DriverOutcome::Succeeded
    );
    let mut all_phases = registered();
    for phase in [
        DriverPhase::RecordRetire,
        DriverPhase::CleanupCompletion,
        DriverPhase::TerminalOutboxStage,
        DriverPhase::TerminalDelivery,
        DriverPhase::TerminalAckWait,
        DriverPhase::AckValidation,
        DriverPhase::AckCommit,
        DriverPhase::AckTombstoneStage,
        DriverPhase::JobAdmissionRetire,
        DriverPhase::GuardianReceiptRemove,
        DriverPhase::WriterRetire,
        DriverPhase::PublicationGuardAcquire,
        DriverPhase::AttemptRecordRemove,
        DriverPhase::AckTombstoneComplete,
        DriverPhase::RetirementReceiptDelivery,
    ] {
        all_phases.driver_transition(phase, DriverOutcome::Attempted);
        all_phases.driver_transition(phase, DriverOutcome::Succeeded);
        let record = all_phases.snapshot();
        assert_eq!(record.last_driver_event.as_ref().unwrap().phase, phase);
        assert_eq!(record.stage, Stage::Registered);
        assert!(!record.removed && !record.admission_retired);
        assert!(record.first_driver_failure.is_none());
        assert!(serde_json::to_value(&record.last_driver_event).unwrap()["phase"].is_string());
    }
    let value = diagnostic(&snapshot(vec![row(history)]), &[]);
    assert_eq!(value["records"][0]["stage"], "publication-completed");
    assert_eq!(
        value["records"][0]["last_driver_event"]["phase"],
        "writer-retire"
    );
    assert_eq!(value["retirement_proof"], false);
}

#[test]
fn temporal_progress_requires_exact_generation_binding_and_retained_thread() {
    let mut history = registered();
    let first = snapshot(vec![row(registered())]);
    history.driver_transition(DriverPhase::AckCommit, DriverOutcome::Attempted);
    history.driver_transition(DriverPhase::AckCommit, DriverOutcome::Failed);
    let mut later_row = row(history);
    later_row.thread = ThreadObservation::Exited { tid: 7, birth: 789 };
    let later = snapshot(vec![later_row]);
    let value = temporal_comparison(&first, &later);
    assert_eq!(
        value["records"][0]["classification"],
        "same-generation-and-retained-thread-observed"
    );
    assert_eq!(
        value["records"][0]["later_driver_event"]["phase"],
        "ack-commit"
    );
    assert_eq!(
        value["records"][0]["first_driver_failure"]["outcome"],
        "failed"
    );
    assert_eq!(
        value["records"][0]["continuous_thread_liveness_proved"],
        false
    );
    assert_eq!(value["current_file_binding"], false);
    assert_eq!(value["retirement_proof"], false);

    let mut changed = later.clone();
    changed.records[0].thread = ThreadObservation::Exited { tid: 7, birth: 790 };
    assert_eq!(
        temporal_comparison(&first, &changed)["records"][0]["classification"],
        "unbound-retained-thread-identity"
    );
    changed = later.clone();
    changed.records[0].history.binding.request_sha256 =
        memcordon_core::hash_bytes(b"different request").into();
    assert_eq!(
        temporal_comparison(&first, &changed)["records"][0]["same_generation_tuple_observed"],
        false
    );
    changed = later.clone();
    changed.records[0].history.generation += 1;
    changed.records[0].history.binding.generation += 1;
    assert_eq!(
        temporal_comparison(&first, &changed)["records"][0]["classification"],
        "different-generation-observed"
    );
    changed = later.clone();
    changed.records[0].history.binding.owner = Some(Owner {
        pid: 123,
        birth: 457,
    });
    assert_eq!(
        temporal_comparison(&first, &changed)["records"][0]["same_generation_tuple_observed"],
        false
    );
}

#[test]
fn temporal_missing_loss_cutoff_and_contention_never_become_absence_proof() {
    let first = snapshot(vec![row(registered())]);
    let mut later = snapshot(Vec::new());
    assert_eq!(
        temporal_comparison(&first, &later)["records"][0]["classification"],
        "unavailable-source-not-retained"
    );
    later.evicted = 1;
    assert_eq!(
        temporal_comparison(&first, &later)["records"][0]["classification"],
        "unavailable-source-not-retained-after-eviction"
    );
    later = first.clone();
    later.dropped = 1;
    let value = temporal_comparison(&first, &later);
    assert_eq!(
        value["records"][0]["classification"],
        "unbound-diagnostic-loss"
    );
    assert_eq!(value["records"][0]["same_generation_tuple_observed"], true);
    later.dropped = 0;
    later.history = Availability::Busy;
    assert_eq!(
        temporal_comparison(&first, &later)["records"][0]["classification"],
        "unbound-history-unavailable"
    );
    later.completed_before_cutoff = false;
    assert_eq!(
        temporal_comparison(&first, &later)["records"][0]["classification"],
        "unbound-original-cutoff"
    );
    let many = snapshot(
        (0..100)
            .map(|seed| row(History::new(binding(seed))))
            .collect(),
    );
    let value = temporal_comparison(&many, &many);
    assert!(value["records"].as_array().unwrap().len() <= OUTPUT_ROWS);
    assert!(serde_json::to_vec(&value).unwrap().len() <= RECORD_BYTES);
    assert!(value["records_omitted"].as_u64().unwrap() >= 92);
    let mut retained = (0..16)
        .map(|seed| row(History::new(binding(seed))))
        .collect::<Vec<_>>();
    for row in retained.iter_mut().take(15) {
        row.registry_present = Some(false);
    }
    let prioritized = snapshot(retained);
    let value = temporal_comparison(&prioritized, &prioritized);
    assert_eq!(value["records"][0]["binding"]["generation"], 16);
    let tokens = vec![binding(15).attempt_id; 100];
    let names = filename_correlations(&prioritized, &tokens);
    assert_eq!(names["names"].as_array().unwrap().len(), NAME_TOKENS);
    assert_eq!(names["names_omitted"], 100 - NAME_TOKENS);
    assert_eq!(
        names["names"][0]["classification"],
        "unbound-local-state-unavailable"
    );
    assert_eq!(names["name_sample_order_relative_to_later_unproved"], true);
    assert_eq!(names["current_file_binding"], false);
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
