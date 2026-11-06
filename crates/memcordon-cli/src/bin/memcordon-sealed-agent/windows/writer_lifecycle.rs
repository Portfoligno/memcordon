//! Bounded historical producer observations. No value grants settlement authority.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::VecDeque;

pub const HISTORY_EVENTS: usize = 16;
pub const JOURNAL_RECORDS: usize = 16;
pub const OUTPUT_ROWS: usize = 8;
pub const NAME_TOKENS: usize = 8;
pub const RECORD_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Owner {
    pub pid: u32,
    pub birth: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Binding {
    pub attempt_id: String,
    pub request_sha256: String,
    pub owner: Option<Owner>,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    ReservationRequested,
    ReservationPublished,
    ReservationFailed,
    WorkerCreateRequested,
    WorkerCreated,
    WorkerCreateFailed,
    Registered,
    SubmissionAccepted,
    SubmissionRefused,
    PublicationStarted,
    PublicationCompleted,
    PublicationFailed,
    CloseRequested,
    CloseSucceeded,
    CloseFailed,
    RegistryRemoved,
    AdmissionRetireRequested,
    AdmissionRetired,
    AdmissionRetireFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriverPhase {
    RecordRetire,
    CleanupCompletion,
    TerminalOutboxStage,
    TerminalDelivery,
    TerminalAckWait,
    AckValidation,
    AckCommit,
    AckTombstoneStage,
    JobAdmissionRetire,
    GuardianReceiptRemove,
    WriterRetire,
    PublicationGuardAcquire,
    AttemptRecordRemove,
    AckTombstoneComplete,
    RetirementReceiptDelivery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriverOutcome {
    Attempted,
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct DriverEvent {
    pub sequence: u64,
    pub phase: DriverPhase,
    pub outcome: DriverOutcome,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub sequence: u64,
    pub stage: Stage,
    pub native_code: Option<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct HistoryRecord {
    pub binding: Binding,
    pub generation: u64,
    pub sequence: u64,
    pub stage: Stage,
    pub events: Vec<Event>,
    pub omitted_events: u64,
    pub binding_changed: bool,
    pub first_failure_event: Option<Event>,
    pub last_native_error: Option<u32>,
    pub last_native_error_stage: Option<Stage>,
    pub reservation_published: bool,
    pub registered: bool,
    pub removed: bool,
    pub admission_retired: bool,
    pub last_driver_event: Option<DriverEvent>,
    pub first_driver_failure: Option<DriverEvent>,
}
pub struct History {
    record: HistoryRecord,
    events: VecDeque<Event>,
}
impl History {
    pub fn new(binding: Binding) -> Self {
        let generation = binding.generation;
        let mut value = Self {
            record: HistoryRecord {
                binding,
                generation,
                sequence: 0,
                stage: Stage::ReservationRequested,
                events: Vec::new(),
                omitted_events: 0,
                binding_changed: false,
                first_failure_event: None,
                last_native_error: None,
                last_native_error_stage: None,
                reservation_published: false,
                registered: false,
                removed: false,
                admission_retired: false,
                last_driver_event: None,
                first_driver_failure: None,
            },
            events: VecDeque::new(),
        };
        value.transition(Stage::ReservationRequested, None);
        value
    }
    pub fn bind_owner(&mut self, owner: Owner) {
        match self.record.binding.owner {
            None => self.record.binding.owner = Some(owner),
            Some(previous) if previous != owner => self.record.binding_changed = true,
            Some(_) => {}
        }
        self.bump();
    }
    fn bump(&mut self) {
        if let Some(sequence) = self.record.sequence.checked_add(1) {
            self.record.sequence = sequence;
        } else {
            self.record.binding_changed = true;
            self.record.omitted_events = self.record.omitted_events.saturating_add(1);
        }
    }
    pub fn transition(&mut self, stage: Stage, native_error: Option<u32>) {
        self.bump();
        self.record.stage = stage;
        if native_error.is_some() {
            self.record.last_native_error = native_error;
            self.record.last_native_error_stage = Some(stage);
        }
        let event = Event {
            sequence: self.record.sequence,
            stage,
            native_code: native_error,
        };
        if self.record.first_failure_event.is_none()
            && matches!(
                stage,
                Stage::ReservationFailed
                    | Stage::WorkerCreateFailed
                    | Stage::SubmissionRefused
                    | Stage::PublicationFailed
                    | Stage::CloseFailed
                    | Stage::AdmissionRetireFailed
            )
        {
            self.record.first_failure_event = Some(event.clone());
        }
        match stage {
            Stage::ReservationPublished => self.record.reservation_published = true,
            Stage::Registered => self.record.registered = true,
            Stage::RegistryRemoved => self.record.removed = true,
            Stage::AdmissionRetired => self.record.admission_retired = true,
            _ => {}
        }
        if self.events.len() == HISTORY_EVENTS {
            self.events.pop_front();
            self.record.omitted_events = self.record.omitted_events.saturating_add(1);
        }
        self.events.push_back(event);
    }
    pub fn snapshot(&self) -> HistoryRecord {
        let mut record = self.record.clone();
        record.events = self.events.iter().cloned().collect();
        record
    }

    pub fn driver_transition(&mut self, phase: DriverPhase, outcome: DriverOutcome) {
        self.bump();
        let event = DriverEvent {
            sequence: self.record.sequence,
            phase,
            outcome,
        };
        if outcome == DriverOutcome::Failed && self.record.first_driver_failure.is_none() {
            self.record.first_driver_failure = Some(event.clone());
        }
        self.record.last_driver_event = Some(event);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Availability {
    Available,
    Busy,
    Poisoned,
    Cutoff,
    #[default]
    Unsupported,
}
#[derive(Clone, Debug, Default, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum ThreadObservation {
    #[default]
    NotObserved,
    NoHandle,
    Running {
        tid: u32,
        birth: u64,
    },
    Exited {
        tid: u32,
        birth: u64,
    },
    Unavailable {
        native_code: Option<u32>,
    },
    Cutoff,
}
#[derive(Clone, Debug)]
pub struct WriterSnapshot {
    pub history: HistoryRecord,
    pub registry_present: Option<bool>,
    pub pending: Option<usize>,
    pub quarantined: Option<bool>,
    pub publisher_native_code: Option<u32>,
    pub thread: ThreadObservation,
    pub changed: bool,
}
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub registry: Availability,
    pub history: Availability,
    pub current_owner: Option<Owner>,
    pub total_lanes: Option<usize>,
    pub total_pending: Option<usize>,
    pub total_quarantined: Option<usize>,
    pub records: Vec<WriterSnapshot>,
    pub evicted: u64,
    pub dropped: u64,
    pub changed: bool,
    pub completed_before_cutoff: bool,
}
fn digest(value: &str) -> bool {
    value.len() == String::from(memcordon_core::hash_bytes(&[])).len()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid(record: &HistoryRecord) -> bool {
    digest(&record.binding.attempt_id)
        && digest(&record.binding.request_sha256)
        && record.generation > 0
        && record.generation == record.binding.generation
        && record.sequence > 0
        && record
            .binding
            .owner
            .is_none_or(|owner| owner.pid > 0 && owner.birth > 0)
        && record.events.len() <= HISTORY_EVENTS
        && record
            .events
            .iter()
            .all(|event| event.sequence > 0 && event.sequence <= record.sequence)
        && record
            .events
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
}
fn correlation(snapshot: &Snapshot, token: &str) -> Value {
    let records = snapshot
        .records
        .iter()
        .take(JOURNAL_RECORDS)
        .filter(|row| row.history.binding.attempt_id == token)
        .collect::<Vec<_>>();
    let reason = if !digest(token) {
        "unbound-invalid-token"
    } else if !snapshot.completed_before_cutoff {
        "unbound-original-cutoff"
    } else if snapshot.dropped > 0 {
        "unbound-diagnostic-loss"
    } else if snapshot.history != Availability::Available {
        "unbound-history-unavailable"
    } else if snapshot.changed {
        "unbound-sample-changed"
    } else if records.len() != 1 {
        if records.is_empty() {
            "unbound-no-producer-history"
        } else {
            "unbound-ambiguous-history"
        }
    } else {
        let row = records[0];
        let history = &row.history;
        if !valid(history) || history.binding_changed || row.changed {
            "unbound-record-changed-or-invalid"
        } else if history.binding.owner.is_none() || history.binding.owner != snapshot.current_owner
        {
            "unbound-producer-incarnation"
        } else if snapshot.registry != Availability::Available {
            "historical-local-publication-registry-unavailable"
        } else if row.registry_present == Some(true)
            && history.registered
            && history.reservation_published
            && !history.removed
        {
            "current-local-lane-observed"
        } else if row.registry_present == Some(false) && history.reservation_published {
            "retained-local-lifecycle-observed"
        } else {
            "unbound-local-state-unavailable"
        }
    };
    json!({"filename_token":digest(token).then_some(token),"classification":reason,
        "historical_filename_correlation_only":true,"current_file_binding":false,"retirement_proof":false})
}

/// Filename text is historical correlation, never current object identity.
pub fn filename_correlations(snapshot: &Snapshot, tokens: &[String]) -> Value {
    json!({"name_sample":"last-successful-admission-name-sample",
        "name_sample_order_relative_to_later_unproved":true,
        "diagnostic_only":true,"current_file_binding":false,"retirement_proof":false,
        "later_history_state":snapshot.history,"later_evicted":snapshot.evicted,"later_dropped":snapshot.dropped,
        "later_sample_changed":snapshot.changed,"later_completed_before_original_cutoff":snapshot.completed_before_cutoff,
        "names":tokens.iter().take(NAME_TOKENS).map(|token|correlation(snapshot,token)).collect::<Vec<_>>(),
        "names_omitted":tokens.len().saturating_sub(NAME_TOKENS)})
}

/// Inputs are primitive copies from a bounded nonblocking observation, never lanes or handles.
pub fn diagnostic(snapshot: &Snapshot, writer_tokens: &[String]) -> Value {
    let mut rows = Vec::new();
    let mut selected = Vec::new();
    for priority in 0..4 {
        for (index, row) in snapshot.records.iter().take(JOURNAL_RECORDS).enumerate() {
            let named = writer_tokens
                .iter()
                .take(NAME_TOKENS)
                .any(|token| token == &row.history.binding.attempt_id);
            let current = row.registry_present == Some(true);
            let rank = match (named, current) {
                (true, true) => 0,
                (true, false) => 1,
                (false, true) => 2,
                (false, false) => 3,
            };
            if rank == priority && selected.len() < OUTPUT_ROWS {
                selected.push(index);
            }
        }
    }
    for index in selected {
        let row = &snapshot.records[index];
        let history = &row.history;
        rows.push(if valid(history) {
            json!({"binding":history.binding,"generation":history.generation,"sequence":history.sequence,
                "stage":history.stage,"last_native_error":history.last_native_error,"last_native_error_stage":history.last_native_error_stage,
                "first_failed_transition":history.first_failure_event,
                "last_driver_event":history.last_driver_event,"first_driver_failure":history.first_driver_failure,
                "reservation_published":history.reservation_published,"registered":history.registered,
                "registry_removed":history.removed,"admission_retirement_returned_ok":history.admission_retired,
                "events_omitted":history.omitted_events.saturating_add(history.events.len() as u64),
                "binding_changed":history.binding_changed,"registry_present":row.registry_present,
                "pending":row.pending,"quarantined":row.quarantined,"publisher_native_code":row.publisher_native_code,"thread":row.thread,"changed":row.changed,
                "current_file_binding":false,"retirement_proof":false})
        } else {json!({"invalid_record":true,"binding_omitted":true,"retirement_proof":false})});
    }
    let names = writer_tokens
        .iter()
        .take(NAME_TOKENS)
        .map(|token| correlation(snapshot, token))
        .collect::<Vec<_>>();
    let mut value = json!({"format":"memcordon.writer-lifecycle-observation","revision":1,
        "diagnostic_only":true,"acceptance_authority":false,"retirement_proof":false,
        "native_error_domain":"Win32",
        "current_file_binding":false,"foreign_owner_binding":"unavailable","filename_inventory_complete":false,
        "registry_state":snapshot.registry,"history_state":snapshot.history,"current_owner":snapshot.current_owner,
        "total_local_lanes":snapshot.total_lanes.filter(|_|snapshot.registry==Availability::Available),
        "total_pending":snapshot.total_pending.filter(|_|snapshot.registry==Availability::Available),
        "total_quarantined":snapshot.total_quarantined.filter(|_|snapshot.registry==Availability::Available),
        "registry_counts_are_sampled_not_admission_or_thread_absence":true,"evicted":snapshot.evicted,"dropped":snapshot.dropped,
        "sample_changed":snapshot.changed,"completed_before_original_cutoff":snapshot.completed_before_cutoff,
        "independent_samples_not_atomic":true,"records":rows,"names":names,
        "records_omitted":snapshot.records.len().saturating_sub(OUTPUT_ROWS),
        "names_omitted":writer_tokens.len().saturating_sub(NAME_TOKENS)});
    while serde_json::to_vec(&value)
        .expect("fixed diagnostic JSON")
        .len()
        > RECORD_BYTES
    {
        let rows = value["records"].as_array_mut().expect("fixed record list");
        if rows.pop().is_none() {
            break;
        }
        let omitted = value["records_omitted"]
            .as_u64()
            .expect("fixed omission count");
        value["records_omitted"] = json!(omitted.saturating_add(1));
    }
    value
}

/// Compare copied historical observations only; missing rows never prove absence.
pub fn temporal_comparison(first: &Snapshot, later: &Snapshot) -> Value {
    fn thread_identity(thread: &ThreadObservation) -> Option<(u32, u64)> {
        match thread {
            ThreadObservation::Running { tid, birth }
            | ThreadObservation::Exited { tid, birth }
                if *tid > 0 && *birth > 0 =>
            {
                Some((*tid, *birth))
            }
            _ => None,
        }
    }
    let mut rows = Vec::new();
    let bounded = &first.records[..first.records.len().min(JOURNAL_RECORDS)];
    let prioritized = bounded
        .iter()
        .filter(|row| row.registry_present == Some(true))
        .chain(
            bounded
                .iter()
                .filter(|row| row.registry_present != Some(true)),
        );
    for row in prioritized.take(OUTPUT_ROWS) {
        let history = &row.history;
        if !valid(history) {
            rows.push(json!({"classification":"unbound-invalid-first-record"}));
            continue;
        }
        let matches = later
            .records
            .iter()
            .take(JOURNAL_RECORDS)
            .filter(|candidate| {
                candidate.history.binding == history.binding
                    && candidate.history.generation == history.generation
            })
            .collect::<Vec<_>>();
        let matching = (matches.len() == 1).then(|| matches[0]);
        let same_thread = matching.is_some_and(|candidate| {
            thread_identity(&row.thread).is_some()
                && thread_identity(&row.thread) == thread_identity(&candidate.thread)
        });
        let reason = if !first.completed_before_cutoff || !later.completed_before_cutoff {
            "unbound-original-cutoff"
        } else if first.history != Availability::Available
            || later.history != Availability::Available
        {
            "unbound-history-unavailable"
        } else if first.dropped > 0 || later.dropped > 0 {
            "unbound-diagnostic-loss"
        } else if first.changed || later.changed || row.changed || history.binding_changed {
            "unbound-sample-changed"
        } else if matches.len() > 1 {
            "unbound-ambiguous-generation"
        } else if let Some(candidate) = matching {
            if !valid(&candidate.history) || candidate.changed || candidate.history.binding_changed
            {
                "unbound-later-record-changed-or-invalid"
            } else if history.binding.owner.is_none() {
                "unbound-producer-incarnation"
            } else if candidate.history.sequence < history.sequence {
                "unbound-sequence-regressed"
            } else if !same_thread {
                "unbound-retained-thread-identity"
            } else {
                "same-generation-and-retained-thread-observed"
            }
        } else if later.records.iter().take(JOURNAL_RECORDS).any(|candidate| {
            candidate.history.binding.attempt_id == history.binding.attempt_id
                && candidate.history.generation != history.generation
        }) {
            "different-generation-observed"
        } else if later.evicted > first.evicted {
            "unavailable-source-not-retained-after-eviction"
        } else {
            "unavailable-source-not-retained"
        };
        rows.push(json!({"binding":history.binding,"classification":reason,
            "same_generation_tuple_observed":matching.is_some(),"same_retained_thread_identity_observed":same_thread,
            "first_sequence":history.sequence,"later_sequence":matching.map(|candidate|candidate.history.sequence),
            "first_writer_stage":history.stage,"later_writer_stage":matching.map(|candidate|candidate.history.stage),
            "first_driver_event":history.last_driver_event,
            "later_driver_event":matching.and_then(|candidate|candidate.history.last_driver_event.as_ref()),
            "first_driver_failure":matching.and_then(|candidate|candidate.history.first_driver_failure.as_ref()),
            "continuous_thread_liveness_proved":false,"current_file_binding":false,"retirement_proof":false}));
    }
    let mut value = json!({"format":"memcordon.writer-lifecycle-temporal-observation","revision":1,
        "diagnostic_only":true,"acceptance_authority":false,"retirement_proof":false,"current_file_binding":false,
        "independent_samples_not_atomic":true,"first_evicted":first.evicted,"later_evicted":later.evicted,
        "first_dropped":first.dropped,"later_dropped":later.dropped,"records":rows,
        "records_omitted":first.records.len().saturating_sub(OUTPUT_ROWS)});
    while serde_json::to_vec(&value)
        .expect("fixed temporal JSON")
        .len()
        > RECORD_BYTES
    {
        if value["records"]
            .as_array_mut()
            .expect("fixed rows")
            .pop()
            .is_none()
        {
            break;
        }
        let omitted = value["records_omitted"].as_u64().expect("fixed count");
        value["records_omitted"] = json!(omitted.saturating_add(1));
    }
    value
}
