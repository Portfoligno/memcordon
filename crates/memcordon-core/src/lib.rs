#![forbid(unsafe_code)]

mod error;
mod outcome;
mod policy;
mod report;
mod state_machine;

pub use error::{Error, ErrorCategory};
pub use outcome::{
    ChildTermination, CleanupErrorRecord, CleanupSummary, Interruption, LimitEvidence, RunOutcome,
};
pub use policy::{
    ByteSize, CommandSpec, Enforcement, Lifetime, Metric, Policy, ReportMode, ResolvedPolicy,
    SwapPolicy,
};
pub use report::{
    BackendReport, CommandReport, MemcordonReport, PolicyReport, ResultReport, ToolReport,
    write_report_atomic,
};
pub use state_machine::{RunState, StateMachine, StateTransitionError};
