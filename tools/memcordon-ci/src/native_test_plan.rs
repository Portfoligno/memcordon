use std::time::Duration;

const STANDARD_DEADLINE: Duration = Duration::from_secs(15 * 60);
// A cold Windows all-targets release build includes the native service and
// fixture graphs as well as the workspace tests. Keep compilation finite,
// independently of the shorter execution deadline and enclosing lane budget.
const BUILD_DEADLINE: Duration = Duration::from_secs(25 * 60);
const WINDOWS_RELEASE_BUILD_DEADLINE: Duration = Duration::from_secs(40 * 60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTestCommand {
    pub arguments: Vec<&'static str>,
    pub deadline: Duration,
}

pub fn commands(release_mode: bool) -> Vec<NativeTestCommand> {
    let mut arguments = vec![
        "--target-dir",
        "target/ci/native",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--locked",
    ];
    if release_mode {
        arguments.push("--release");
    }

    let mut build_arguments = arguments.clone();
    build_arguments.push("--no-run");
    // Bound cold compilation separately from execution on every native lane.
    // Both phases select the same targets, features, profile, and lockfile.
    // Execute every selected test binary after a failure, but retain Cargo's
    // nonzero final status and the existing whole-execution deadline.
    arguments.push("--no-fail-fast");
    vec![
        NativeTestCommand {
            arguments: build_arguments,
            deadline: if cfg!(windows) && release_mode {
                WINDOWS_RELEASE_BUILD_DEADLINE
            } else {
                BUILD_DEADLINE
            },
        },
        NativeTestCommand {
            arguments,
            deadline: STANDARD_DEADLINE,
        },
    ]
}
