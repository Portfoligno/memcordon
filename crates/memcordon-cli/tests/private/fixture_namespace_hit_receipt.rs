use super::profile::{
    DebugRegisters, Expectation, HitRejection, Observation, Planner, Site, State, Stop,
};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Metadata {
    pub event_ordinal: usize,
    pub flags: u32,
    pub first_chance: u32,
    pub received_qpc: Option<u64>,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptStage {
    PlannerLookup,
    Validation,
    EntryArguments,
    HelperOperands,
    SetRegisters,
    Readback,
    Complete,
}

#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    pub raw: Stop,
    pub metadata: Metadata,
    pub expected: Option<Expectation>,
    pub observation: Option<Observation>,
    pub initializer_planned: Option<InitializerFacts>,
    pub state_after: Option<State>,
    pub registers_after: Option<DebugRegisters>,
    pub readback: Option<DebugRegisters>,
    pub rejection: Option<HitRejection>,
    pub stage: ReceiptStage,
    pub admitted: bool,
    pub transition_attempted: bool,
    pub transition_verified: bool,
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct InitializerFacts {
    pub source: Option<&'static str>,
    pub status: Option<i32>,
    pub thread_token_cleared: bool,
}
impl Receipt {
    pub fn capture(metadata: Metadata, stop: Stop, planner: Option<&Planner>) -> Self {
        let expected = planner.map(|planner| planner.snapshot(stop.registers));
        Self {
            raw: stop,
            metadata,
            expected,
            observation: None,
            initializer_planned: None,
            state_after: expected.map(|expected| expected.state),
            registers_after: expected.map(|expected| expected.registers),
            readback: None,
            rejection: None,
            stage: ReceiptStage::PlannerLookup,
            admitted: false,
            transition_attempted: false,
            transition_verified: false,
            failed: false,
        }
    }
}

pub const ACCEPTED_STAGE_LIMIT: usize = Site::ALL.len() + 2;

/// Fixed receipts never replace the first failure during later cleanup.
#[derive(Default, Serialize)]
pub struct Receipts {
    pub first_observed: Option<Receipt>,
    pub first_rejected: Option<Receipt>,
    pub accepted_stages: Vec<Receipt>,
    pub observed: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub omitted: usize,
}
impl Receipts {
    pub fn record(&mut self, receipt: Receipt) {
        self.record_helper(receipt, false);
    }
    pub fn record_helper(&mut self, receipt: Receipt, helper_retained: bool) {
        self.observed = self.observed.saturating_add(1);
        let first = self.first_observed.is_none();
        let rejection = receipt.failed && self.first_rejected.is_none();
        let accepted = !helper_retained
            && receipt.transition_verified
            && self.accepted_stages.len() < ACCEPTED_STAGE_LIMIT;
        if first {
            self.first_observed = Some(receipt.clone());
        }
        if receipt.transition_verified {
            self.accepted = self.accepted.saturating_add(1);
        }
        if accepted {
            self.accepted_stages.push(receipt.clone());
        }
        if receipt.failed {
            self.rejected = self.rejected.saturating_add(1);
        }
        if rejection {
            self.first_rejected = Some(receipt);
        }
        if !first && !rejection && !accepted && !helper_retained {
            self.omitted = self.omitted.saturating_add(1);
        }
    }
}
