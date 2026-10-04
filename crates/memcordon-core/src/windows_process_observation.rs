//! Bounded, explicitly partial observations of members of a Windows Job.
//!
//! Native Job accounting and retirement proofs have separate owners.  A sample
//! can never establish that every process associated with a Job was observed.

use std::mem::size_of;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::WindowsProcessIdentityV1;

pub const WINDOWS_PROCESS_OBSERVATION_SCHEMA_VERSION: u32 = 2;
pub const WINDOWS_PROCESS_SNAPSHOT_STORAGE_BYTES: usize = 256 * 1024;
pub const WINDOWS_PROCESS_SAMPLE_STORAGE_BYTES: usize = 24 * 1024;
pub const WINDOWS_PROCESS_OBSERVATION_WIRE_BYTES: usize = 128 * 1024;
pub const WINDOWS_PROCESS_SNAPSHOT_QUERIES_PER_TICK: u32 = 2;
pub const WINDOWS_PROCESS_IDENTITY_QUERIES_PER_TICK: u32 = 64;
pub const WINDOWS_PROCESS_SAMPLE_INTERVAL_MILLIS: u64 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservationPolicyV1 {
    pub snapshot_storage_bytes: usize,
    pub sample_storage_bytes: usize,
    pub serialized_field_bytes: usize,
    pub snapshot_queries_per_tick: u32,
    pub identity_queries_per_tick: u32,
    pub sample_interval_millis: u64,
}

impl ProcessObservationPolicyV1 {
    pub const SERVICE: Self = Self {
        snapshot_storage_bytes: WINDOWS_PROCESS_SNAPSHOT_STORAGE_BYTES,
        sample_storage_bytes: WINDOWS_PROCESS_SAMPLE_STORAGE_BYTES,
        serialized_field_bytes: WINDOWS_PROCESS_OBSERVATION_WIRE_BYTES,
        snapshot_queries_per_tick: WINDOWS_PROCESS_SNAPSHOT_QUERIES_PER_TICK,
        identity_queries_per_tick: WINDOWS_PROCESS_IDENTITY_QUERIES_PER_TICK,
        sample_interval_millis: WINDOWS_PROCESS_SAMPLE_INTERVAL_MILLIS,
    };

    pub fn sample_slots(self) -> usize {
        self.sample_storage_bytes / size_of::<ProcessSampleEntryV1>()
    }

    pub fn is_valid(self) -> bool {
        self == Self::SERVICE && self.sample_slots() > 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservationCountersV1 {
    pub polls_attempted: u64,
    pub snapshots_obtained: u64,
    pub identity_queries_attempted: u64,
    pub identity_observations_verified: u64,
    pub vanished_or_not_member: u64,
    pub sample_evictions: u64,
    pub counter_saturated: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservationOmissionsV1 {
    pub snapshot_byte_budget: u64,
    pub snapshot_race_or_retry_budget: u64,
    pub per_tick_query_budget: u64,
    pub allocation_unavailable: u64,
    pub sample_eviction: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSampleEntryV1 {
    pub identity: WindowsProcessIdentityV1,
    pub last_observation_sequence: u64,
}

/// This decoder refuses element K+1 before allocating for it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedProcessIdentitySample(pub Vec<ProcessSampleEntryV1>);

impl<'de> Deserialize<'de> for BoundedProcessIdentitySample {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedVisitor;

        impl<'de> Visitor<'de> for BoundedVisitor {
            type Value = BoundedProcessIdentitySample;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(
                    formatter,
                    "at most {} process sample entries",
                    ProcessObservationPolicyV1::SERVICE.sample_slots()
                )
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let capacity = ProcessObservationPolicyV1::SERVICE.sample_slots();
                let mut entries = Vec::new();
                while entries.len() < capacity {
                    let Some(entry) = sequence.next_element()? else {
                        return Ok(BoundedProcessIdentitySample(entries));
                    };
                    entries.push(entry);
                }
                if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("process sample capacity exceeded"));
                }
                Ok(BoundedProcessIdentitySample(entries))
            }
        }

        deserializer.deserialize_seq(BoundedVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessObservationUnavailableReasonV1 {
    WorkerLostBeforeFreeze,
    LegacyObservationUnavailable,
    TargetNotCreated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "coverage", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProcessObservationCoverageV1 {
    Sampled {
        policy: ProcessObservationPolicyV1,
        counters: ProcessObservationCountersV1,
        omissions: ProcessObservationOmissionsV1,
        sample: BoundedProcessIdentitySample,
    },
    Unavailable {
        reason: ProcessObservationUnavailableReasonV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsJobAccountingObservationV1 {
    pub total_processes_native_u32: u32,
    pub active_processes_native_u32: u32,
    pub observed_after_target_retirement: bool,
    pub counter_regression_observed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsQualificationWitnessRoleV1 {
    NestedAlternateToken,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsQualificationMembershipWitnessV1 {
    pub schema_version: u32,
    pub role: WindowsQualificationWitnessRoleV1,
    pub child_identity: WindowsProcessIdentityV1,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub qualification_lease: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProcessObservationV2 {
    pub schema_version: u32,
    pub coverage: ProcessObservationCoverageV1,
    pub root_identity: Option<WindowsProcessIdentityV1>,
    pub final_accounting: Option<WindowsJobAccountingObservationV1>,
    pub required_witness: Option<WindowsQualificationMembershipWitnessV1>,
}

fn valid_identity(identity: &WindowsProcessIdentityV1) -> bool {
    identity.process_id != 0 && identity.creation_time_100ns != 0
}

impl WindowsProcessObservationV2 {
    pub fn unavailable(reason: ProcessObservationUnavailableReasonV1) -> Self {
        Self {
            schema_version: WINDOWS_PROCESS_OBSERVATION_SCHEMA_VERSION,
            coverage: ProcessObservationCoverageV1::Unavailable { reason },
            root_identity: None,
            final_accounting: None,
            required_witness: None,
        }
    }

    pub fn validate(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
    ) -> Result<(), &'static str> {
        if self.schema_version != WINDOWS_PROCESS_OBSERVATION_SCHEMA_VERSION {
            return Err("process_observation.schema_version");
        }
        if self
            .root_identity
            .as_ref()
            .is_some_and(|identity| !valid_identity(identity))
        {
            return Err("process_observation.root_identity");
        }
        if let Some(witness) = &self.required_witness {
            if witness.schema_version != 1
                || !valid_identity(&witness.child_identity)
                || witness.attempt_id != attempt_id
                || witness.nonce != nonce
                || witness.request_sha256 != request_sha256
                || witness.qualification_lease.is_empty()
                || self.root_identity.as_ref() == Some(&witness.child_identity)
            {
                return Err("process_observation.required_witness");
            }
        }
        if let ProcessObservationCoverageV1::Unavailable { reason } = &self.coverage {
            if self.required_witness.is_some()
                || (*reason == ProcessObservationUnavailableReasonV1::TargetNotCreated
                    && (self.root_identity.is_some() || self.final_accounting.is_some()))
            {
                return Err("process_observation.unavailable");
            }
        }
        if let ProcessObservationCoverageV1::Sampled {
            policy,
            counters,
            omissions,
            sample,
        } = &self.coverage
        {
            if !policy.is_valid() || sample.0.len() > policy.sample_slots() {
                return Err("process_observation.policy_or_capacity");
            }
            if counters.snapshots_obtained > counters.polls_attempted
                || counters.identity_observations_verified > counters.identity_queries_attempted
                || counters.vanished_or_not_member > counters.identity_queries_attempted
                || omissions.sample_eviction != counters.sample_evictions
            {
                return Err("process_observation.counters");
            }
            for (index, entry) in sample.0.iter().enumerate() {
                if !valid_identity(&entry.identity)
                    || entry.last_observation_sequence == 0
                    || !sample.0[..index]
                        .iter()
                        .all(|prior| prior.identity != entry.identity)
                {
                    return Err("process_observation.sample");
                }
            }
            let wire = crate::bounded_json_bytes(self, policy.serialized_field_bytes, false)
                .map_err(|_| "process_observation.wire_budget")?;
            if wire.len() > policy.serialized_field_bytes {
                return Err("process_observation.wire_budget");
            }
        }
        Ok(())
    }
}

fn increment(counter: &mut u64, saturated: &mut bool) {
    if let Some(next) = counter.checked_add(1) {
        *counter = next;
    } else {
        *saturated = true;
    }
}

#[derive(Debug)]
pub struct ProcessObserver {
    policy: ProcessObservationPolicyV1,
    counters: ProcessObservationCountersV1,
    omissions: ProcessObservationOmissionsV1,
    sample: Vec<ProcessSampleEntryV1>,
    sample_storage_available: bool,
    sequence: u64,
    final_accounting: Option<WindowsJobAccountingObservationV1>,
    last_total: Option<u32>,
}

impl ProcessObserver {
    pub fn new(policy: ProcessObservationPolicyV1) -> Result<Self, &'static str> {
        if !policy.is_valid() {
            return Err("invalid process observation policy");
        }
        let mut sample = Vec::new();
        sample
            .try_reserve_exact(policy.sample_slots())
            .map_err(|_| "process sample allocation unavailable")?;
        Ok(Self {
            policy,
            counters: ProcessObservationCountersV1::default(),
            omissions: ProcessObservationOmissionsV1::default(),
            sample,
            sample_storage_available: true,
            sequence: 0,
            final_accounting: None,
            last_total: None,
        })
    }

    /// Continue native supervision when optional sample storage cannot be reserved.
    /// The resulting receipt remains `Sampled` with an explicit omission.
    pub fn without_sample_storage() -> Self {
        Self {
            policy: ProcessObservationPolicyV1::SERVICE,
            counters: ProcessObservationCountersV1::default(),
            omissions: ProcessObservationOmissionsV1 {
                allocation_unavailable: 1,
                ..ProcessObservationOmissionsV1::default()
            },
            sample: Vec::new(),
            sample_storage_available: false,
            sequence: 0,
            final_accounting: None,
            last_total: None,
        }
    }

    pub fn attempt_poll(&mut self) {
        increment(
            &mut self.counters.polls_attempted,
            &mut self.counters.counter_saturated,
        );
    }

    pub fn snapshot_obtained(&mut self) {
        increment(
            &mut self.counters.snapshots_obtained,
            &mut self.counters.counter_saturated,
        );
    }

    pub fn identity_query_attempted(&mut self) {
        increment(
            &mut self.counters.identity_queries_attempted,
            &mut self.counters.counter_saturated,
        );
    }

    pub fn vanished_or_not_member(&mut self) {
        increment(
            &mut self.counters.vanished_or_not_member,
            &mut self.counters.counter_saturated,
        );
    }

    pub fn observe_identity(
        &mut self,
        identity: WindowsProcessIdentityV1,
    ) -> Result<(), &'static str> {
        if !valid_identity(&identity) {
            return Err("invalid verified process identity");
        }
        increment(
            &mut self.counters.identity_observations_verified,
            &mut self.counters.counter_saturated,
        );
        increment(&mut self.sequence, &mut self.counters.counter_saturated);
        if !self.sample_storage_available {
            return Ok(());
        }
        if let Some(entry) = self
            .sample
            .iter_mut()
            .find(|entry| entry.identity == identity)
        {
            entry.last_observation_sequence = self.sequence;
            return Ok(());
        }
        if self.sample.len() == self.policy.sample_slots() {
            self.sample.remove(0);
            increment(
                &mut self.counters.sample_evictions,
                &mut self.counters.counter_saturated,
            );
            increment(
                &mut self.omissions.sample_eviction,
                &mut self.counters.counter_saturated,
            );
        }
        self.sample.push(ProcessSampleEntryV1 {
            identity,
            last_observation_sequence: self.sequence,
        });
        Ok(())
    }

    pub fn omit_snapshot_byte_budget(&mut self) {
        increment(
            &mut self.omissions.snapshot_byte_budget,
            &mut self.counters.counter_saturated,
        );
    }

    pub fn omit_snapshot_race_or_retry_budget(&mut self) {
        increment(
            &mut self.omissions.snapshot_race_or_retry_budget,
            &mut self.counters.counter_saturated,
        );
    }

    pub fn omit_per_tick_query_budget(&mut self) {
        increment(
            &mut self.omissions.per_tick_query_budget,
            &mut self.counters.counter_saturated,
        );
    }

    pub fn omit_allocation_unavailable(&mut self) {
        increment(
            &mut self.omissions.allocation_unavailable,
            &mut self.counters.counter_saturated,
        );
    }

    pub fn observe_accounting(&mut self, total: u32, active: u32, after_retirement: bool) {
        let regression = self.last_total.is_some_and(|prior| total < prior)
            || self
                .final_accounting
                .is_some_and(|prior| prior.counter_regression_observed);
        self.last_total = Some(total);
        self.final_accounting = Some(WindowsJobAccountingObservationV1 {
            total_processes_native_u32: total,
            active_processes_native_u32: active,
            observed_after_target_retirement: after_retirement,
            counter_regression_observed: regression,
        });
    }

    pub fn freeze(
        self,
        root_identity: Option<WindowsProcessIdentityV1>,
        required_witness: Option<WindowsQualificationMembershipWitnessV1>,
    ) -> WindowsProcessObservationV2 {
        WindowsProcessObservationV2 {
            schema_version: WINDOWS_PROCESS_OBSERVATION_SCHEMA_VERSION,
            coverage: ProcessObservationCoverageV1::Sampled {
                policy: self.policy,
                counters: self.counters,
                omissions: self.omissions,
                sample: BoundedProcessIdentitySample(self.sample),
            },
            root_identity,
            final_accounting: self.final_accounting,
            required_witness,
        }
    }
}
