use memcordon_ci::config::{self, Release};

type ReleaseMutation = (&'static str, fn(&mut Release));

fn canonical_release() -> Release {
    toml::from_str(include_str!("../../../ci/release.toml"))
        .expect("canonical release configuration should parse")
}

#[test]
fn canonical_release_identity_accepts_only_supported_values() {
    let canonical = canonical_release();
    config::validate_release_configuration_identity(&canonical)
        .expect("canonical release configuration identity should be valid");

    let mutations: [ReleaseMutation; 11] = [
        ("stale schema", |release| release.schema_version = 1),
        ("wrong registry", |release| {
            release.registry = "other".to_owned();
        }),
        ("wrong workflow", |release| {
            release.workflow = "other.yml".to_owned();
        }),
        ("empty GitHub API version", |release| {
            release.github_api_version.clear();
        }),
        ("zero package limit", |release| {
            release.maximum_package_bytes = 0;
        }),
        ("zero asset limit", |release| {
            release.maximum_asset_bytes = 0;
        }),
        ("zero registry wait", |release| {
            release.registry_wait.initial_milliseconds = 0;
        }),
        ("inverted registry wait", |release| {
            release.registry_wait.maximum_milliseconds =
                release.registry_wait.initial_milliseconds - 1;
        }),
        ("zero network retry", |release| {
            release.network_retry.initial_milliseconds = 0;
        }),
        ("inverted network retry", |release| {
            release.network_retry.maximum_milliseconds =
                release.network_retry.initial_milliseconds - 1;
        }),
        ("missing native target", |release| {
            release.assets.target.pop();
        }),
    ];

    for (case, mutate) in mutations {
        let mut invalid = canonical.clone();
        mutate(&mut invalid);
        let error = config::validate_release_configuration_identity(&invalid)
            .expect_err("mutated release configuration identity should be rejected");
        assert_eq!(
            error.to_string(),
            "release configuration identity is invalid",
            "{case}"
        );
    }
}

#[test]
fn canonical_release_targets_match_native_hosts() {
    let release = canonical_release();
    let actual: Vec<(&str, &str, &str, &str)> = release
        .assets
        .target
        .iter()
        .map(|target| {
            (
                target.id.as_str(),
                target.rust_target.as_str(),
                target.archive.as_str(),
                target.executable.as_str(),
            )
        })
        .collect();
    assert_eq!(
        actual,
        [
            (
                "linux-x64",
                "x86_64-unknown-linux-gnu",
                "tar-gz",
                "memcordon",
            ),
            (
                "linux-arm64",
                "aarch64-unknown-linux-gnu",
                "tar-gz",
                "memcordon",
            ),
            ("macos-arm64", "aarch64-apple-darwin", "tar-gz", "memcordon",),
            ("macos-x64", "x86_64-apple-darwin", "tar-gz", "memcordon",),
            (
                "windows-x64",
                "x86_64-pc-windows-msvc",
                "zip",
                "memcordon.exe",
            ),
            (
                "windows-arm64",
                "aarch64-pc-windows-msvc",
                "zip",
                "memcordon.exe",
            ),
        ]
    );
}

#[test]
fn native_hosts_select_their_release_targets() {
    for (os, arch, expected) in [
        ("linux", "x86_64", "linux-x64"),
        ("linux", "aarch64", "linux-arm64"),
        ("macos", "aarch64", "macos-arm64"),
        ("macos", "x86_64", "macos-x64"),
        ("windows", "x86_64", "windows-x64"),
        ("windows", "aarch64", "windows-arm64"),
    ] {
        assert_eq!(
            config::release_target_id_for_host(os, arch)
                .expect("native host should map to a release target"),
            expected
        );
    }
    assert!(config::release_target_id_for_host("windows", "x86").is_err());
}
