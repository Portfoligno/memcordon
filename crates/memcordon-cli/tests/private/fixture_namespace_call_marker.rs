use serde::Serialize;
use std::io;

#[path = "fixture_namespace_call_packet.rs"]
pub mod packet;
pub use packet::{CODE, PARAMETERS, Packet};

use packet::{PHASE_POST, PHASE_PRE};

// EXCEPTION_RECORD documents this system-reserved flag; pinned windows-sys
// 0.61.2 defines it as 128. It is compatible with a continuable marker, but
// supplies no authentication or execution evidence.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record
pub const EXCEPTION_SOFTWARE_ORIGINATE: u32 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rejection {
    Code,
    Flags,
    FirstChance,
    OwnerPid,
    OwnerTid,
    ParameterCount,
    ResultRange,
    PhaseOrder,
    Version,
    Nonce,
    ApiNonzero,
    PreResultZero,
    PostApiMatch,
    PostResultConsistency,
    CanonicalPacketMismatch,
}
impl std::fmt::Display for Rejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid replay call marker")
    }
}
impl std::error::Error for Rejection {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Pre,
    Post,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    AwaitPre,
    AwaitPost,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CallResult {
    pub opened: bool,
    pub raw_error: u32,
}

pub struct Window {
    pid: u32,
    tid: u32,
    nonce: String,
    pub state: State,
    pub api: Option<u64>,
    pub result: Option<CallResult>,
}

impl Window {
    pub fn new(pid: u32, tid: u32, replay_nonce: &str) -> io::Result<Self> {
        Ok(Self {
            pid,
            tid,
            nonce: {
                Packet::pre(replay_nonce, 1)?;
                replay_nonce.to_owned()
            },
            state: State::AwaitPre,
            api: None,
            result: None,
        })
    }

    pub fn accept(
        &mut self,
        code: u32,
        flags: u32,
        first_chance: bool,
        pid: u32,
        tid: u32,
        parameters: &[u64],
    ) -> Result<Phase, Rejection> {
        if code != CODE {
            return Err(Rejection::Code);
        }
        if flags != 0 && flags != EXCEPTION_SOFTWARE_ORIGINATE {
            return Err(Rejection::Flags);
        }
        if !first_chance {
            return Err(Rejection::FirstChance);
        }
        if pid != self.pid {
            return Err(Rejection::OwnerPid);
        }
        if tid != self.tid {
            return Err(Rejection::OwnerTid);
        }
        if parameters.len() != PARAMETERS {
            return Err(Rejection::ParameterCount);
        }
        let p = parameters;
        if p[5] > 1 || p[6] > u64::from(u32::MAX) {
            return Err(Rejection::ResultRange);
        }
        let phase = match (self.state, p[1]) {
            (State::AwaitPre, PHASE_PRE) => Phase::Pre,
            (State::AwaitPost, PHASE_POST) => Phase::Post,
            _ => return Err(Rejection::PhaseOrder),
        };
        let expected = match phase {
            Phase::Pre => {
                if p[5] != 0 || p[6] != 0 {
                    return Err(Rejection::PreResultZero);
                }
                if p[4] == 0 {
                    return Err(Rejection::ApiNonzero);
                }
                Packet::pre(&self.nonce, p[4])
            }
            Phase::Post => {
                if self.api != Some(p[4]) {
                    return Err(Rejection::PostApiMatch);
                }
                if p[5] == 1 && p[6] != 0 {
                    return Err(Rejection::PostResultConsistency);
                }
                Packet::post(&self.nonce, p[4], p[5] == 1, p[6] as u32)
            }
        }
        .map_err(|_| Rejection::CanonicalPacketMismatch)?;
        if p[0] != expected[0] {
            return Err(Rejection::Version);
        }
        if p[2..4] != expected[2..4] {
            return Err(Rejection::Nonce);
        }
        if p != expected {
            return Err(Rejection::CanonicalPacketMismatch);
        }
        match phase {
            Phase::Pre => {
                self.api = Some(p[4]);
                self.state = State::AwaitPost;
                Ok(Phase::Pre)
            }
            Phase::Post => {
                self.result = Some(CallResult {
                    opened: p[5] == 1,
                    raw_error: p[6] as u32,
                });
                self.state = State::Complete;
                Ok(Phase::Post)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    IncompleteWindow,
    ObservedProfiledHit,
    NoHostHitWithIntactPostState,
    #[serde(rename = "coverage-drift-observed")]
    DriftObserved,
}

pub fn classify(post_observed: bool, post_intact: bool, profiled_hit: bool) -> Coverage {
    if !post_observed {
        Coverage::IncompleteWindow
    } else if !post_intact {
        Coverage::DriftObserved
    } else if profiled_hit {
        Coverage::ObservedProfiledHit
    } else {
        Coverage::NoHostHitWithIntactPostState
    }
}
