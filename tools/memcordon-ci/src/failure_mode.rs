/// Scheduling policy; a diagnostic run still fails when any operation fails.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub enum FailureMode {
    #[default]
    StopAfterFailure,
    CollectAll,
}
