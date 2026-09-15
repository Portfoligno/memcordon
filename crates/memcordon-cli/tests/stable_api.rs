//! Downstream facade consumer; building a request never executes its command.
use memcordon::{
    ByteSize, CommandSpec, Error, Limiter, MemcordonExecutable, Policy, RunOutcome,
    SupervisionExecution, Supervisor,
};

#[test]
fn stable_facade_builders_and_result_types_remain_source_compatible() {
    let path = std::env::current_exe().unwrap();
    let executable = MemcordonExecutable::new(&path).unwrap();
    assert_eq!(executable.as_path(), path);
    let policy = Policy::new(ByteSize::gib(1));
    let _limiter = Limiter::new(policy.clone())
        .memcordon_executable(executable.clone())
        .command(CommandSpec::new("consumer-command").args(["a b"]));
    let _supervisor = Supervisor::new(policy)
        .memcordon_executable(executable)
        .command(CommandSpec::new("consumer-command"));
    let _: fn(Limiter) -> Result<RunOutcome, Error> = Limiter::run;
    let _: fn(Supervisor) -> Result<SupervisionExecution, Error> = Supervisor::run;
    assert_eq!(
        memcordon::parse_duration("0.001s").unwrap(),
        std::time::Duration::from_millis(1)
    );
}
