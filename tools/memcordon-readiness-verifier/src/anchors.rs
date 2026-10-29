//! Independently reviewed semantic anchors, not imported from the runner.
//! Changing these is a change to the readiness contract, not discovery.

pub const TARGETS: [&str; 4] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];
pub const CHANNELS: [&str; 4] = [
    "candidate-native",
    "candidate-cargo",
    "public-native",
    "public-cargo",
];
pub const PRODUCER_JOBS: [(&str, &str); 4] = [
    ("x86_64-unknown-linux-gnu", "linux-x64"),
    ("aarch64-unknown-linux-gnu", "linux-arm64"),
    ("x86_64-pc-windows-msvc", "windows-x64"),
    ("aarch64-pc-windows-msvc", "windows-arm64"),
];
pub const REQUIREMENTS: [&str; 14] = [
    "CR-01", "CR-02", "CR-03", "CR-04", "CR-05", "CR-06", "CR-07", "CR-08", "CR-09", "CR-10",
    "CR-11", "CR-12", "CR-13", "CR-14",
];
