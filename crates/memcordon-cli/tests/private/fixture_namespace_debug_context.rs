use serde::Serialize;

pub const CALL_LIMIT: usize = 16;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    PreCallArm,
    PostCallCoverage,
    Hit,
    Restore,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    GetContext,
    SetRegisters,
    GetReadback,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Call {
    pub purpose: Purpose,
    pub stage: Stage,
    pub flags: u32,
    pub size: usize,
    pub alignment: usize,
    pub address_mod_16: usize,
    pub success: bool,
    pub raw_error: Option<i32>,
}

/// Native-call receipts only: successful writes do not imply verified readback.
#[derive(Default, Serialize)]
pub struct Trace {
    pub calls: Vec<Call>,
    pub omitted: usize,
    pub first_failure: Option<Call>,
    pub write_attempted: usize,
    pub set_succeeded: usize,
    pub verified: usize,
}

impl Trace {
    pub fn record(&mut self, call: Call) {
        if matches!(call.stage, Stage::SetRegisters) {
            self.write_attempted = self.write_attempted.saturating_add(1);
            if call.success {
                self.set_succeeded = self.set_succeeded.saturating_add(1);
            }
        }
        if !call.success && self.first_failure.is_none() {
            self.first_failure = Some(call);
        }
        if self.calls.len() < CALL_LIMIT {
            self.calls.push(call);
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }

    /// Called only after the caller's actual register comparison succeeds.
    pub fn verified(&mut self) {
        self.verified = self.verified.saturating_add(1);
    }
}
