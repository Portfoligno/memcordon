//! ResumeThread returns a prior suspension count; only DWORD_MAX is failure.
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Outcome {
    Released,
    AlreadyUnsuspended,
    StillSuspended { previous_count: u32 },
    NativeFailure { code: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ResumeResult {
    pub raw_return: u32,
    pub outcome: Outcome,
    pub native_error: Option<u32>,
}

pub fn classify(raw: u32, last_error: impl FnOnce() -> u32) -> ResumeResult {
    let (outcome, native_error) = match raw {
        0 => (Outcome::AlreadyUnsuspended, None),
        1 => (Outcome::Released, None),
        u32::MAX => {
            let code = last_error();
            (Outcome::NativeFailure { code }, Some(code))
        }
        previous_count => (Outcome::StillSuspended { previous_count }, None),
    };
    ResumeResult {
        raw_return: raw,
        outcome,
        native_error,
    }
}

impl ResumeResult {
    pub fn require_exact_one(&self) -> Result<(), String> {
        match self.outcome {
            Outcome::Released => Ok(()),
            Outcome::NativeFailure { code } => Err(format!(
                "ResumeThread native failure: raw_return={} native_code={code}",
                self.raw_return
            )),
            Outcome::AlreadyUnsuspended | Outcome::StillSuspended { .. } => Err(format!(
                "ResumeThread prior suspend count mismatch: expected=1 actual={}; native API succeeded",
                self.raw_return
            )),
        }
    }
}
