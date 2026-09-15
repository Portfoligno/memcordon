//! Versioned runtime observations. Unknown evidence never certifies retirement.

use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

pub const MAX_RETIREMENT_OBLIGATIONS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "domain", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ClockDomain {
    DarwinContinuousTicksV1 {
        boot_identity: String,
        ticks_per_second: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ReleaseEvidence {
    NotIssued,
    Issued { at: u64, exec_confirmed: bool },
    Unknown,
}

impl<'de> Deserialize<'de> for ReleaseEvidence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Empty struct variants enforce unknown-field rejection, unlike serde's
        // internally tagged unit variants. The public representation and all
        // valid serialized bytes remain unchanged.
        #[derive(Deserialize)]
        #[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
        enum Wire {
            NotIssued {},
            Issued { at: u64, exec_confirmed: bool },
            Unknown {},
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::NotIssued {} => Self::NotIssued,
            Wire::Issued { at, exec_confirmed } => Self::Issued { at, exec_confirmed },
            Wire::Unknown {} => Self::Unknown,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerIdentity {
    pub pid: NonZeroU32,
    pub start_identity: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetirementObligation {
    PendingCreation,
    RootExit,
    RootReap,
    GroupReconciliation,
    DetachedIdentity,
    InspectorReap,
    GuardianReap,
    ControlTransport,
    WorkloadPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RetirementEvidence {
    Complete {
        at: u64,
        target_reaped_or_absent: bool,
        group_reconciled: bool,
        detached_identities_discharged: bool,
        native_obligations_settled: bool,
        policy_retired: bool,
    },
    Pending {
        owner: OwnerIdentity,
        #[serde(deserialize_with = "bounded_obligations")]
        obligations: Vec<RetirementObligation>,
    },
    Unconfirmed {
        last_owner: Option<OwnerIdentity>,
    },
}

fn bounded_obligations<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<RetirementObligation>, D::Error> {
    let bounded = crate::diagnostics::BoundedVec::<RetirementObligation, MAX_RETIREMENT_OBLIGATIONS>::deserialize(deserializer)?;
    Ok(bounded.as_slice().to_vec())
}

impl RetirementEvidence {
    pub fn is_complete(&self) -> bool {
        matches!(
            self,
            Self::Complete {
                target_reaped_or_absent: true,
                group_reconciled: true,
                detached_identities_discharged: true,
                native_obligations_settled: true,
                policy_retired: true,
                ..
            }
        )
    }
}

/// Describes preparation only: an execution report cannot certify its own write.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum DeliveryEvidence {
    NotSubmitted,
    Prepared,
    PreparedBy { writer_pid: NonZeroU32 },
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeEvidenceV1 {
    pub schema_version: u32,
    pub clock: ClockDomain,
    pub run_origin: u64,
    pub attempt_origin: u64,
    pub work_expires: Option<u64>,
    pub startup_expires: u64,
    pub release: ReleaseEvidence,
    pub target_pid: Option<NonZeroU32>,
    pub terminal_observed: Option<u64>,
    pub force_requested: Option<u64>,
    pub force_expires: Option<u64>,
    pub retirement_expires: Option<u64>,
    pub delivery_expires: Option<u64>,
    pub retirement: RetirementEvidence,
    pub delivery: DeliveryEvidence,
}

impl RuntimeEvidenceV1 {
    pub fn is_consistent(&self) -> bool {
        let clock_valid = match &self.clock {
            ClockDomain::DarwinContinuousTicksV1 {
                boot_identity,
                ticks_per_second,
            } => !boot_identity.is_empty() && boot_identity.len() <= 128 && *ticks_per_second > 0,
        };
        let release_valid = match self.release {
            ReleaseEvidence::Issued { at, .. } => {
                self.target_pid.is_some()
                    && self.attempt_origin <= at
                    && at < self.startup_expires
                    && self.work_expires.is_none_or(|expiry| at < expiry)
            }
            ReleaseEvidence::NotIssued => true,
            ReleaseEvidence::Unknown => !self.retirement.is_complete(),
        };
        let retirement_valid = match &self.retirement {
            RetirementEvidence::Complete { at, .. } => {
                self.retirement.is_complete()
                    && self
                        .terminal_observed
                        .is_some_and(|terminal| terminal <= *at)
                    && self.retirement_expires.is_some_and(|expiry| *at <= expiry)
            }
            RetirementEvidence::Pending { obligations, .. } => {
                !obligations.is_empty() && obligations.len() <= MAX_RETIREMENT_OBLIGATIONS
            }
            RetirementEvidence::Unconfirmed { .. } => true,
        };
        let boundaries_valid = match (
            self.force_expires,
            self.retirement_expires,
            self.delivery_expires,
        ) {
            (None, None, None) => self.terminal_observed.is_none(),
            (Some(force), Some(retire), Some(deliver)) => force <= retire && retire <= deliver,
            _ => false,
        };
        self.schema_version == 1
            && clock_valid
            && release_valid
            && retirement_valid
            && boundaries_valid
            && self.run_origin <= self.attempt_origin
            && self.attempt_origin <= self.startup_expires
            && self
                .work_expires
                .is_none_or(|expiry| self.startup_expires <= expiry)
            && self
                .terminal_observed
                .is_none_or(|at| self.attempt_origin <= at)
            && self.force_requested.is_none_or(|at| {
                self.terminal_observed
                    .is_some_and(|terminal| terminal <= at)
            })
    }
}

impl<'de> Deserialize<'de> for RuntimeEvidenceV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: u32,
            clock: ClockDomain,
            run_origin: u64,
            attempt_origin: u64,
            work_expires: Option<u64>,
            startup_expires: u64,
            release: ReleaseEvidence,
            target_pid: Option<NonZeroU32>,
            terminal_observed: Option<u64>,
            force_requested: Option<u64>,
            force_expires: Option<u64>,
            retirement_expires: Option<u64>,
            delivery_expires: Option<u64>,
            retirement: RetirementEvidence,
            delivery: DeliveryEvidence,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            clock: wire.clock,
            run_origin: wire.run_origin,
            attempt_origin: wire.attempt_origin,
            work_expires: wire.work_expires,
            startup_expires: wire.startup_expires,
            release: wire.release,
            target_pid: wire.target_pid,
            terminal_observed: wire.terminal_observed,
            force_requested: wire.force_requested,
            force_expires: wire.force_expires,
            retirement_expires: wire.retirement_expires,
            delivery_expires: wire.delivery_expires,
            retirement: wire.retirement,
            delivery: wire.delivery,
        };
        if !value.is_consistent() {
            return Err(serde::de::Error::custom("inconsistent runtime evidence"));
        }
        Ok(value)
    }
}
