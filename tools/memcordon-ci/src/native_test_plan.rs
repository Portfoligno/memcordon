use std::time::Duration;

const STANDARD_DEADLINE: Duration = Duration::from_secs(15 * 60);
const RELEASE_BUILD_DEADLINE: Duration = Duration::from_secs(25 * 60);

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
    if !release_mode {
        return vec![NativeTestCommand {
            arguments,
            deadline: STANDARD_DEADLINE,
        }];
    }

    arguments.push("--release");
    let mut build_arguments = arguments.clone();
    build_arguments.push("--no-run");
    vec![
        NativeTestCommand {
            arguments: build_arguments,
            deadline: RELEASE_BUILD_DEADLINE,
        },
        NativeTestCommand {
            arguments,
            deadline: STANDARD_DEADLINE,
        },
    ]
}
