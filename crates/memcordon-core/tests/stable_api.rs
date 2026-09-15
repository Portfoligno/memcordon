//! Downstream consumer crate: only stable root exports are imported.
use memcordon_core::{BoundaryRequirement, ByteSize, CommandSpec, DeadlineScope, Policy};

#[test]
fn root_policy_and_typed_arguments_remain_source_compatible() {
    let bytes = ByteSize::from_bytes(4096);
    let policy = Policy::new(bytes)
        .with_boundary(BoundaryRequirement::Sealed)
        .with_deadline(std::time::Duration::from_secs(2))
        .unwrap();
    assert_eq!(policy.boundary(), BoundaryRequirement::Sealed);
    assert_eq!(policy.deadline.unwrap().scope(), DeadlineScope::Attempt);
    let arguments = [
        std::ffi::OsString::from("a b"),
        std::ffi::OsString::from("--literal=$x"),
    ];
    let command = CommandSpec::new("consumer-command").args(arguments.clone());
    assert_eq!(command.program(), std::ffi::OsStr::new("consumer-command"));
    assert_eq!(command.arguments(), &arguments);
    assert_eq!(bytes.bytes(), 4096);
}
