//! Sealed fixture command/argument-parser authority and side-effect inventory.
#[derive(serde::Serialize)]
pub(super) struct FixtureCommand {
    pub name: &'static str,
    pub argument_parser: &'static str,
    pub owner: &'static str,
    pub platform_cfg: &'static str,
    pub available: bool,
    pub owning_suites: &'static [&'static str],
    pub privilege_needs: &'static str,
    pub expected_side_effects: &'static str,
    #[serde(skip)]
    #[cfg(target_os = "linux")]
    pub handler: fn(),
}
macro_rules! command {
    ($name:literal, $handler:path, $owner:literal, $privileges:literal, $effects:literal) => {
        FixtureCommand {
            name: $name,
            argument_parser: stringify!($handler),
            owner: $owner,
            platform_cfg: "target_os = linux",
            available: cfg!(target_os = "linux"),
            owning_suites: &["sealed_agent::linux_sealed", "sealed_agent::linux_provider"],
            privilege_needs: $privileges,
            expected_side_effects: $effects,
            #[cfg(target_os = "linux")]
            handler: $handler,
        }
    };
}
pub(super) const COMMANDS: &[FixtureCommand] = &[
    command!(
        "exit",
        super::process::command_exit,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "returns successfully without creating a target descendant"
    ),
    command!(
        "exit-17",
        super::process::command_exit_17,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "exits with status 17"
    ),
    command!(
        "exit-126",
        super::process::command_exit_126,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "exits with status 126"
    ),
    command!(
        "exit-127",
        super::process::command_exit_127,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "exits with status 127"
    ),
    command!(
        "mark",
        super::process::command_mark,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "writes /tmp/memcordon-sealed-preauthorization-marker"
    ),
    command!(
        "fault-ready",
        super::process::command_fault_ready,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "writes the supplied authorization marker, then waits for external termination"
    ),
    command!(
        "frontend-hold",
        super::process::command_frontend_hold,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "creates and syncs a private no-follow readiness file, then waits for external termination"
    ),
    command!(
        "frontend-exit-before-ready",
        super::process::command_frontend_exit_before_ready,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "exits with status 121 before readiness"
    ),
    command!(
        "child",
        super::process::command_child,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "forks one sleeping descendant"
    ),
    command!(
        "retained-stream",
        super::process::command_retained_stream,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "forks a descendant that retains and writes stdout/stderr before exit"
    ),
    command!(
        "concurrency-gate",
        super::process::command_concurrency_gate,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "writes readiness to stdout, waits for a release file, then writes release evidence"
    ),
    command!(
        "double-fork",
        super::process::command_double_fork,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "creates a double-forked sleeping descendant"
    ),
    command!(
        "setsid",
        super::process::command_setsid,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "forks a descendant that creates a new session and sleeps"
    ),
    command!(
        "fork-storm",
        super::process::command_fork_storm,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/process.rs",
        "native sealed fixture caller authority",
        "forks the fixed certification workload of sleeping descendants"
    ),
    command!(
        "deny-cgroup",
        super::namespace::command_deny_cgroup,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/namespace.rs",
        "native sealed fixture caller authority",
        "attempts opening the ancestor cgroup membership file for writing and requires denial"
    ),
    command!(
        "deny-setns",
        super::namespace::command_deny_setns,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/namespace.rs",
        "native sealed fixture caller authority",
        "attempts entry into the parent pid namespace and requires denial"
    ),
    command!(
        "deny-cgroup-mount",
        super::namespace::command_deny_cgroup_mount,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/namespace.rs",
        "native sealed fixture caller authority",
        "attempts a cgroup2 mount, unmounts if unexpectedly successful, then fails"
    ),
    command!(
        "assert-credential-transition-root",
        super::credentials::command_assert_credential_transition_root,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/credentials.rs",
        "caller credentials or installed setid/file-capability certification image",
        "requires effective root and creates a retained double-fork descendant"
    ),
    command!(
        "assert-effective-uid",
        super::credentials::command_assert_effective_uid,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/credentials.rs",
        "caller credentials or installed setid/file-capability certification image",
        "compares the current effective uid with the supplied uid"
    ),
    command!(
        "assert-file-capability-transition",
        super::credentials::command_assert_file_capability_transition,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/credentials.rs",
        "caller credentials or installed setid/file-capability certification image",
        "uses the certified file capability to become root and creates a retained descendant"
    ),
    command!(
        "assert-bounding-capability-absent",
        super::credentials::command_assert_bounding_capability_absent,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/credentials.rs",
        "caller credentials or installed setid/file-capability certification image",
        "requires effective root with the supplied bounding capability absent, then creates a retained descendant"
    ),
    command!(
        "elevated-transition-descendant",
        super::credentials::command_elevated_transition_descendant,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/credentials.rs",
        "caller credentials or installed setid/file-capability certification image",
        "verifies effective root and cgroup write denial, signals readiness through its inherited fd, then waits"
    ),
    command!(
        "assert-mount-marker",
        super::namespace::command_assert_mount_marker,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/namespace.rs",
        "native sealed fixture caller authority",
        "reads the supplied marker and verifies caller mount context bytes"
    ),
    command!(
        "assert-recursive-provider-rejected",
        super::namespace::command_assert_recursive_provider_rejected,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/namespace.rs",
        "native sealed fixture caller authority",
        "invokes memcordon recursively and validates exact preauthorization rejection/report fields"
    ),
    command!(
        "identity",
        super::credentials::command_identity,
        "crates/memcordon-cli/src/bin/memcordon-sealed-test-fixture/credentials.rs",
        "caller credentials or installed setid/file-capability certification image",
        "checks zero effective capabilities and the inherited descriptor count"
    ),
];
