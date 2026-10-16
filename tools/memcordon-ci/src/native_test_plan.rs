use std::time::Duration;

const STANDARD_DEADLINE: Duration = Duration::from_secs(15 * 60);
// Cold Windows and macOS all-targets release builds include the native service and
// fixture graphs as well as the workspace tests. Keep compilation finite,
// independently of the shorter execution deadline and enclosing lane budget.
const BUILD_DEADLINE: Duration = Duration::from_secs(25 * 60);
const MACOS_RELEASE_BUILD_DEADLINE: Duration = Duration::from_secs(40 * 60);
// A cold Windows x64 workspace/test graph exceeded forty minutes while
// actively compiling with three workers. Leave finite cold-build headroom;
// the enclosing identity-bound operation deadline still limits every command.
const WINDOWS_RELEASE_BUILD_DEADLINE: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePlatform {
    Windows,
    MacOs,
    Other,
}

impl NativePlatform {
    fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAllocation {
    pub layout: crate::performance_plan::Layout,
    pub product_jobs: usize,
    pub native_jobs: usize,
}

/// Reserve one worker for the selected product while prioritizing the broader
/// native test graph, within the existing four-worker admission cap.
pub fn build_allocation(available: usize) -> BuildAllocation {
    let workers = available.clamp(1, 4);
    BuildAllocation {
        layout: if workers == 1 {
            crate::performance_plan::Layout::Serial
        } else {
            crate::performance_plan::Layout::Parallel
        },
        product_jobs: 1,
        native_jobs: workers.saturating_sub(1).max(1),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTestCommand {
    pub arguments: Vec<&'static str>,
    pub deadline: Duration,
}

pub fn commands(release_mode: bool) -> Vec<NativeTestCommand> {
    commands_with_failure(
        release_mode,
        crate::failure_mode::FailureMode::StopAfterFailure,
    )
}

pub fn commands_with_failure(
    release_mode: bool,
    mode: crate::failure_mode::FailureMode,
) -> Vec<NativeTestCommand> {
    commands_for_platform(release_mode, mode, NativePlatform::current())
}

pub fn commands_for_platform(
    release_mode: bool,
    mode: crate::failure_mode::FailureMode,
    platform: NativePlatform,
) -> Vec<NativeTestCommand> {
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
    if mode == crate::failure_mode::FailureMode::CollectAll {
        arguments.push("--no-fail-fast");
    }
    vec![
        NativeTestCommand {
            arguments: build_arguments,
            deadline: match (release_mode, platform) {
                (true, NativePlatform::Windows) => WINDOWS_RELEASE_BUILD_DEADLINE,
                (true, NativePlatform::MacOs) => MACOS_RELEASE_BUILD_DEADLINE,
                _ => BUILD_DEADLINE,
            },
        },
        NativeTestCommand {
            arguments,
            deadline: STANDARD_DEADLINE,
        },
    ]
}
