//! Private measured-fixture input; it never grants provider administration.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[path = "../../../memcordon-core/src/canonical_json.rs"]
mod canonical_json;

pub const INPUT_BOUND: usize = 65_536;
pub const RECORD_BOUND: u64 = 16 * 1024 * 1024;
pub const RESULT_LEAF: &str = "original-native-recovery-result.json";
pub const FAILURE_LEAF: &str = "original-native-recovery-failure.json";
pub const FAILURE_BOUND: usize = 65_536;

/// Anchor the remaining wall-clock allowance to a monotonic sample taken
/// BEFORE the wall sample. Reusing the result never renews the original budget.
pub fn monotonic_cleanup_cutoff(
    original_wall_ms: u64,
    sampled_monotonic_ns: u64,
    sampled_wall_ms: u64,
) -> Result<u64, String> {
    // The wall sample is floor-rounded to milliseconds. Discard its uncertain
    // final millisecond; this is a conservative reduction, never added grace.
    let remaining = original_wall_ms
        .checked_sub(sampled_wall_ms)
        .and_then(|remaining| remaining.checked_sub(1))
        .filter(|remaining| *remaining != 0)
        .ok_or_else(|| "original recovery cleanup cutoff exhausted".to_owned())?;
    remaining
        .checked_mul(1_000_000)
        .and_then(|remaining| sampled_monotonic_ns.checked_add(remaining))
        .ok_or_else(|| "original recovery cleanup cutoff conversion overflow".to_owned())
}
pub const TEST_NAME: &str =
    "native_original_recovery::native_original_recovery_emit_actual_receipt";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub path: PathBuf,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Context {
    Component {
        recipe_id: String,
        native_input: Record,
        boundary: Record,
        ownership: Record,
        journal: Record,
        reference: Record,
    },
    Lifecycle {
        lease_owner: Record,
        prepared: Record,
        allocation_journal: Record,
        phase_journal: Record,
        controller_intent: Record,
        controller_action: Record,
    },
    Export {
        lease_owner: Record,
        prepared: Record,
        original_journal: Option<Record>,
        original_reservation: Option<Record>,
    },
    Delivery {
        lease_owner: Record,
        prepared: Record,
        allocation_journal: Record,
        frontend_invocation: Record,
        original_contract: Record,
        report_destination: Record,
        report_delivery_failure: Record,
    },
    InterruptedLease {
        lease_owner: Record,
        resources_acquired: Option<Record>,
    },
}

impl Context {
    pub fn records_mut(&mut self) -> Vec<(&'static str, &mut Record)> {
        match self {
            Self::Delivery {
                lease_owner,
                prepared,
                allocation_journal,
                frontend_invocation,
                original_contract,
                report_destination,
                report_delivery_failure,
            } => vec![
                ("lease_owner", lease_owner),
                ("prepared", prepared),
                ("allocation_journal", allocation_journal),
                ("frontend_invocation", frontend_invocation),
                ("original_contract", original_contract),
                ("report_destination", report_destination),
                ("report_delivery_failure", report_delivery_failure),
            ],
            Self::Component {
                native_input,
                boundary,
                ownership,
                journal,
                reference,
                ..
            } => vec![
                ("native_input", native_input),
                ("boundary", boundary),
                ("ownership", ownership),
                ("journal", journal),
                ("reference", reference),
            ],
            Self::Lifecycle {
                lease_owner,
                prepared,
                allocation_journal,
                phase_journal,
                controller_intent,
                controller_action,
            } => vec![
                ("lease_owner", lease_owner),
                ("prepared", prepared),
                ("allocation_journal", allocation_journal),
                ("phase_journal", phase_journal),
                ("controller_intent", controller_intent),
                ("controller_action", controller_action),
            ],
            Self::Export {
                lease_owner,
                prepared,
                original_journal,
                original_reservation,
            } => {
                let mut records = vec![("lease_owner", lease_owner), ("prepared", prepared)];
                records.extend(
                    original_journal
                        .as_mut()
                        .map(|record| ("original_journal", record)),
                );
                records.extend(
                    original_reservation
                        .as_mut()
                        .map(|record| ("original_reservation", record)),
                );
                records
            }
            Self::InterruptedLease {
                lease_owner,
                resources_acquired,
            } => {
                let mut records = vec![("lease_owner", lease_owner)];
                records.extend(
                    resources_acquired
                        .as_mut()
                        .map(|record| ("resources_acquired", record)),
                );
                records
            }
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Component { .. } => "Component",
            Self::Lifecycle { .. } => "Lifecycle",
            Self::Delivery { .. } => "Delivery",
            Self::Export { .. } => "Export",
            Self::InterruptedLease { .. } => "InterruptedLease",
        }
    }
    pub fn records(&self) -> Vec<(&'static str, &Record)> {
        match self {
            Self::Delivery {
                lease_owner,
                prepared,
                allocation_journal,
                frontend_invocation,
                original_contract,
                report_destination,
                report_delivery_failure,
            } => vec![
                ("lease_owner", lease_owner),
                ("prepared", prepared),
                ("allocation_journal", allocation_journal),
                ("frontend_invocation", frontend_invocation),
                ("original_contract", original_contract),
                ("report_destination", report_destination),
                ("report_delivery_failure", report_delivery_failure),
            ],
            Self::Component {
                native_input,
                boundary,
                ownership,
                journal,
                reference,
                ..
            } => vec![
                ("native_input", native_input),
                ("boundary", boundary),
                ("ownership", ownership),
                ("journal", journal),
                ("reference", reference),
            ],
            Self::Lifecycle {
                lease_owner,
                prepared,
                allocation_journal,
                phase_journal,
                controller_intent,
                controller_action,
            } => vec![
                ("lease_owner", lease_owner),
                ("prepared", prepared),
                ("allocation_journal", allocation_journal),
                ("phase_journal", phase_journal),
                ("controller_intent", controller_intent),
                ("controller_action", controller_action),
            ],
            Self::Export {
                lease_owner,
                prepared,
                original_journal,
                original_reservation,
            } => {
                let mut records = vec![("lease_owner", lease_owner), ("prepared", prepared)];
                records.extend(
                    original_journal
                        .as_ref()
                        .map(|record| ("original_journal", record)),
                );
                records.extend(
                    original_reservation
                        .as_ref()
                        .map(|record| ("original_reservation", record)),
                );
                records
            }
            Self::InterruptedLease {
                lease_owner,
                resources_acquired,
            } => {
                let mut records = vec![("lease_owner", lease_owner)];
                records.extend(
                    resources_acquired
                        .as_ref()
                        .map(|record| ("resources_acquired", record)),
                );
                records
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub format: String,
    pub revision: u32,
    pub identity: Identity,
    pub native_target: String,
    pub scope_id: String,
    pub artifact_root: PathBuf,
    pub original_artifact_root: PathBuf,
    pub origin_sha256: String,
    pub work_deadline_unix_millis: u64,
    pub cleanup_deadline_unix_millis: u64,
    pub recovery_harness_owner_sha256: String,
    pub context: Context,
}

pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Input {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > INPUT_BOUND {
            return Err("original recovery fixture input exceeds finite bound".into());
        }
        canonical_json::reject_duplicate_json_keys(bytes)?;
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }
    pub fn validate(&self, cwd: &std::path::Path, now: u64) -> Result<(), String> {
        let normal = |path: &std::path::Path| {
            let bytes = path.as_os_str().as_encoded_bytes();
            bytes.starts_with(b"/")
                && !bytes.contains(&0)
                && bytes[1..]
                    .split(|byte| *byte == b'/')
                    .all(|part| !part.is_empty() && part != b"." && part != b"..")
        };
        if self.format != "memcordon.original-native-recovery-input"
            || self.revision != 1
            || self.identity.run_id.is_empty()
            || self.identity.run_id.len() > 256
            || self.identity.source_commit.len() != 40
            || !self
                .identity
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || !digest(&self.identity.source_tree_sha256)
            || self.identity.version.is_empty()
            || !matches!(
                self.native_target.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
            || self.scope_id.is_empty()
            || self.scope_id.len() > 512
            || !normal(&self.artifact_root)
            || self.artifact_root.as_os_str().as_encoded_bytes()
                != cwd.as_os_str().as_encoded_bytes()
            || !normal(&self.original_artifact_root)
            || !digest(&self.origin_sha256)
            || self.work_deadline_unix_millis == 0
            || self.work_deadline_unix_millis >= self.cleanup_deadline_unix_millis
            || now >= self.cleanup_deadline_unix_millis
            || !digest(&self.recovery_harness_owner_sha256)
            || self.context.records().iter().any(|(_, record)| {
                !normal(&record.path)
                    || record.length == 0
                    || record.length > RECORD_BOUND
                    || !digest(&record.sha256)
            })
        {
            return Err("original recovery fixture input scope/source/cutoffs differ".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryResult {
    pub format: String,
    pub revision: u32,
    pub input_sha256: String,
    pub context: String,
    pub identity: Identity,
    pub native_target: String,
    pub scope_id: String,
    pub recovery_harness_owner_sha256: String,
    pub original_records: Vec<(String, String)>,
    pub completed_unix_millis: u64,
    pub within_original_cleanup: bool,
    pub outstanding: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseObservation {
    pub started_monotonic_nanos: Option<u64>,
    pub finished_monotonic_nanos: Option<u64>,
    pub contention_count: u64,
    pub lock_acquired: bool,
    pub validated_acquisition: bool,
    pub held_device: Option<u64>,
    pub held_inode: Option<u64>,
    pub native_error: Option<i32>,
    pub operation: String,
}

/// Failed-operation evidence only; this is deliberately not a RecoveryResult.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryFailure {
    pub format: String,
    pub revision: u32,
    pub input_sha256: String,
    pub context: String,
    pub identity: Identity,
    pub native_target: String,
    pub scope_id: String,
    pub recovery_harness_owner_sha256: String,
    pub original_records: Vec<(String, String)>,
    pub original_cleanup_deadline_unix_millis: u64,
    pub monotonic_cutoff_nanos: Option<u64>,
    pub observed_unix_millis: u64,
    pub stage: String,
    pub recovery_entered: bool,
    pub error: String,
    pub lease: LeaseObservation,
}
