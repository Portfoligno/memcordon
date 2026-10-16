/// Scheduling policy inherited by nested operations under one absolute deadline.
/// CollectAll continues independent settled failures and still returns failure;
/// deadline exhaustion and unsafe ownership always close admission.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub enum FailureMode {
    #[default]
    StopAfterFailure,
    CollectAll,
}
