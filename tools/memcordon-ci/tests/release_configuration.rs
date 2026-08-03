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

    let mutations: [ReleaseMutation; 10] = [
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
