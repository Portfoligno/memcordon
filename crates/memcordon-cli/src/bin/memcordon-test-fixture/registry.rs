//! Declarative command authority and argument-parser inventory.
use super::*;

#[derive(serde::Serialize)]
pub(super) struct FixtureCommand {
    pub name: &'static str,
    pub argument_parser: &'static str,
    pub owner: &'static str,
    pub platform_cfg: &'static str,
    pub owning_suites: &'static [&'static str],
    pub privilege_needs: &'static str,
    pub expected_side_effects: &'static str,
    #[serde(skip)]
    pub handler: fn(std::env::ArgsOs) -> i32,
}

macro_rules! command {
    ($name:literal, $handler:path, $owner:literal, $platform:literal, [$($suite:literal),+], $effects:literal) => {
        FixtureCommand { name: $name, argument_parser: stringify!($handler), owner: $owner,
            platform_cfg: $platform, owning_suites: &[$($suite),+], privilege_needs: "current disposable fixture process authority",
            expected_side_effects: $effects, handler: $handler }
    };
}
pub(super) const COMMANDS: &[FixtureCommand] = &[
    #[cfg(target_os = "macos")]
    command!(
        "macos-signal-parent",
        macos::command_macos_signal_parent,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "sets signal disposition and mask, then execs the direct or supervised target"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-signal-target",
        macos::command_macos_signal_target,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "verifies inherited signal state, writes readiness/completion markers, and raises the selected signal"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "__macos-guardian",
        macos::command_macos_guardian,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "parks the disposable guardian process until externally terminated"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "__macos-guardian-envelope-v1",
        macos::command_macos_guardian,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "parks the disposable guardian process until externally terminated"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-gated-group-change",
        macos::command_macos_gated_group_change,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "waits for a marker, changes its session with setsid, and writes a transition marker"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-envelope-caller",
        macos::command_macos_envelope_caller,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "creates an inherited descriptor and starts the envelope parent"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-envelope-parent",
        macos::command_macos_envelope_parent,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "sets caller descriptors, signal state, umask, rlimit, cwd and PATH before supervising a target"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-envelope-target",
        macos::command_macos_envelope_target,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "inspects inherited native process state and creates a file to verify the caller umask"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-accounting-backend",
        macos::command_macos_accounting_backend,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "starts a bounded memory workload and validates native limit and retirement evidence"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-envelope-transfer",
        macos::command_macos_envelope_transfer,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "runs the native descriptor/envelope transfer fixture in the requested directory"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-guardian-inspector-wrapper",
        macos::command_macos_guardian_inspector_wrapper,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "starts the native guardian/inspector fixture and writes identity evidence"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-custody-wrapper",
        macos::command_macos_custody_wrapper,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "starts a native custody fixture and records descendant and guardian markers"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-closed-stdio",
        macos::command_macos_closed_stdio,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "closes descriptors 0, 1, and 2, then execs the requested native image"
    ),
    command!(
        "exit",
        process::command_exit,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "optionally writes a pid marker and exits with the requested code"
    ),
    #[cfg(target_os = "macos")]
    command!(
        "macos-ignore-term",
        macos::command_macos_ignore_term,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/macos.rs",
        "target_os = macos",
        ["macos_remediation", "backend_contract"],
        "ignores SIGTERM, writes readiness, and parks until externally terminated"
    ),
    command!(
        "hold",
        process::command_hold,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "optionally writes pid/completion markers and waits for the requested duration"
    ),
    command!(
        "wait-for-signal",
        process::command_hold,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "optionally writes pid/completion markers and waits for the requested duration"
    ),
    command!(
        "spin",
        process::command_spin,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "optionally writes a pid marker and consumes CPU until externally terminated"
    ),
    command!(
        "allocate",
        memory::command_allocate,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/memory.rs",
        "all",
        ["backend_contract", "stress"],
        "touches the requested allocation and retains it for the requested duration"
    ),
    command!(
        "burst",
        memory::command_burst,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/memory.rs",
        "all",
        ["backend_contract", "stress"],
        "touches and releases the requested allocation before the hold interval"
    ),
    command!(
        "spawn-background",
        process::command_spawn_background,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "starts a detached-duration child and records requested process markers"
    ),
    command!(
        "fork-continually",
        process::command_fork_continually,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "repeatedly starts disposable children until the requested deadline"
    ),
    command!(
        "monitor-failure",
        process::command_monitor_failure,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "waits with optional pid/completion markers for monitor-failure tests"
    ),
    command!(
        "spawn-tree",
        process::command_spawn_tree,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "starts a tree of disposable children and waits for the requested duration"
    ),
    command!(
        "print-pid-and-hold",
        process::command_print_pid_and_hold,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "prints and flushes its pid, then waits with optional completion markers"
    ),
    command!(
        "new-session-and-hold",
        process::command_new_session_and_hold,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "creates a new session on Unix and holds until externally terminated"
    ),
    command!(
        "assert-native-containment",
        process::command_assert_native_containment,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/process.rs",
        "all",
        ["lifecycle", "stress"],
        "inspects the native containment boundary against the requested memory limit"
    ),
    command!(
        "record-argv",
        io::command_record_argv,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/io.rs",
        "all",
        [
            "backend_contract",
            "sealed_agent::native_workload_admission"
        ],
        "writes the exact native argument representation to the requested file"
    ),
    command!(
        "assert-no-memcordon-environment",
        io::command_assert_no_memcordon_environment,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/io.rs",
        "all",
        [
            "backend_contract",
            "sealed_agent::native_workload_admission"
        ],
        "checks the disposable process environment for leaked internal variables"
    ),
    command!(
        "gate-marker",
        io::command_gate_marker,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/io.rs",
        "all",
        [
            "backend_contract",
            "sealed_agent::native_workload_admission"
        ],
        "writes the requested authorization marker"
    ),
    command!(
        "gate-wait",
        io::command_gate_wait,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/io.rs",
        "all",
        [
            "backend_contract",
            "sealed_agent::native_workload_admission"
        ],
        "writes readiness and waits for the requested finish gate file"
    ),
    command!(
        "tcp-loopback",
        network::command_tcp_loopback,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/network.rs",
        "all",
        [
            "sealed_agent::native_workload_admission",
            "fixture_inventory"
        ],
        "opens a loopback echo listener/client pair and writes a completion marker"
    ),
    command!(
        "tcp-client",
        network::command_tcp_client,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/network.rs",
        "all",
        [
            "sealed_agent::native_workload_admission",
            "fixture_inventory"
        ],
        "connects to the requested loopback port, verifies an echo, and writes a completion marker"
    ),
    command!(
        "gate-failure",
        io::command_gate_failure,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/io.rs",
        "all",
        [
            "backend_contract",
            "sealed_agent::native_workload_admission"
        ],
        "validates phase/marker arguments and writes a target-executed marker"
    ),
    command!(
        "attempt-job-breakaway",
        windows::command_attempt_job_breakaway,
        "crates/memcordon-cli/src/bin/memcordon-test-fixture/windows.rs",
        "all",
        ["backend_contract"],
        "attempts creation of a child outside its Windows Job Object"
    ),
];
