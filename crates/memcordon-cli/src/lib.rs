#![forbid(unsafe_code)]

pub use memcordon_core::{
    ByteSize, ChildTermination, CleanupSummary, CommandSpec, Enforcement, Error, Lifetime, Metric,
    Policy, RunOutcome,
};
pub use memcordon_platform::{BackendInfo, ProbeReport, probe};

pub struct Limiter {
    policy: Policy,
    command: Option<CommandSpec>,
}

impl Limiter {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            command: None,
        }
    }

    pub fn command(mut self, command: CommandSpec) -> Self {
        self.command = Some(command);
        self
    }

    pub fn run(self) -> Result<RunOutcome, Error> {
        let command = self.command.ok_or_else(|| {
            Error::new(
                memcordon_core::ErrorCategory::Usage,
                "MCUSAGE-COMMAND",
                "no command was configured",
            )
        })?;
        memcordon_platform::run(self.policy, &command).map(|execution| execution.outcome)
    }
}
