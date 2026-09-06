use memcordon_ci::config::{self, RegistryCredentials, Release, SealedAssetPolicy};

type ReleaseMutation = (&'static str, fn(&mut Release));

#[test]
fn workspace_publication_order_matches_the_dependency_graph() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let metadata = cargo_metadata::MetadataCommand::new()
        .current_dir(&root)
        .no_deps()
        .other_options(vec!["--locked".to_owned(), "--offline".to_owned()])
        .exec()
        .expect("workspace metadata should be available");
    let release = canonical_release();
    let policy = config::policy(&root).expect("workspace policy should parse");
    assert_eq!(release.publish_packages, policy.workspace.publish_packages);
    config::publish_order(&metadata, &release.publish_packages)
        .expect("configured publication order should match the actual workspace graph");

    let mut previous_order = release.publish_packages.clone();
    let platform = previous_order
        .iter()
        .position(|name| name == "memcordon-platform")
        .unwrap();
    let launch_core = previous_order
        .iter()
        .position(|name| name == "memcordon-windows-launch-core")
        .unwrap();
    previous_order.swap(platform, launch_core);
    let error = config::publish_order(&metadata, &previous_order)
        .expect_err("the previous sibling order must fail before tagging");
    assert!(error.to_string().contains("does not match derived DAG"));

    let mut reversed_dependencies = release.publish_packages.clone();
    reversed_dependencies.reverse();
    assert!(config::publish_order(&metadata, &reversed_dependencies).is_err());
}

fn canonical_release() -> Release {
    toml::from_str(include_str!("../../../ci/release.toml"))
        .expect("canonical release configuration should parse")
}

#[test]
fn canonical_fallback_configuration_is_bounded_to_the_exact_release() {
    let release = canonical_release();
    let development = semver::Version::parse("0.5.2-dev").unwrap();
    config::validate_registry_credentials(&release, &development)
        .expect("the current development version should match fallback 0.5.2");
    let stable = semver::Version::parse("0.5.2").unwrap();
    config::validate_registry_credentials(&release, &stable)
        .expect("the release commit should match fallback 0.5.2");
    assert_eq!(release.schema_version, 3);
    assert_eq!(
        release.registry_credentials.policy,
        config::RegistryCredentialPolicy::OidcFirstNewCrateFallback
    );
    assert_eq!(
        release.publish_packages,
        [
            "memcordon-core",
            "memcordon-platform",
            "memcordon-windows-launch-core",
            "memcordon"
        ]
    );

    let mutations: [ReleaseMutation; 8] = [
        ("missing fallback version", |release| {
            release.registry_credentials.fallback_version = None;
        }),
        ("development fallback version", |release| {
            release.registry_credentials.fallback_version =
                Some(semver::Version::parse("0.5.2-dev").unwrap());
        }),
        ("build-metadata fallback version", |release| {
            release.registry_credentials.fallback_version =
                Some(semver::Version::parse("0.5.2+build").unwrap());
        }),
        ("missing fallback secret", |release| {
            release.registry_credentials.fallback_token_secret = None;
        }),
        ("wrong fallback secret", |release| {
            release.registry_credentials.fallback_token_secret =
                Some("BROAD_REGISTRY_TOKEN".to_owned());
        }),
        ("empty publication list", |release| {
            release.publish_packages.clear();
        }),
        ("duplicate publication names", |release| {
            let last = release.publish_packages.last().cloned().unwrap();
            release.publish_packages.push(last);
        }),
        ("wrong numeric workspace version", |release| {
            release.registry_credentials.fallback_version =
                Some(semver::Version::parse("0.5.3").unwrap());
        }),
    ];
    for (case, mutate) in mutations {
        let mut invalid = release.clone();
        mutate(&mut invalid);
        assert!(
            config::validate_registry_credentials(&invalid, &development).is_err(),
            "{case} must fail before tagging"
        );
    }
}

#[test]
fn registry_credential_profiles_parse_only_their_exact_fields() {
    let fallback = "policy = \"oidc-first-new-crate-fallback\"\nfallback_version = \"0.5.2\"\nfallback_token_secret = \"MEMCORDON_CRATES_IO_NEW_CRATE_FALLBACK\"\n";
    toml::from_str::<RegistryCredentials>(fallback)
        .expect("the exact fallback profile should parse");
    toml::from_str::<RegistryCredentials>("policy = \"oidc-only\"\n")
        .expect("the exact OIDC-only profile should parse");
    for invalid in [
        "policy = \"arbitrary-provider\"\n",
        "policy = \"new-crate-token-bridge\"\nbridge_version = \"0.5.2\"\nbridge_package = \"memcordon-windows-launch-core\"\nstored_token_secret = \"MEMCORDON_WINDOWS_LAUNCH_FIRST_PUBLISH\"\n",
    ] {
        assert!(
            toml::from_str::<RegistryCredentials>(invalid).is_err(),
            "credential profile should remain closed: {invalid}"
        );
    }
}

#[test]
fn normal_prerelease_fallback_versions_are_bounded_but_acceptable() {
    let mut release = canonical_release();
    release.registry_credentials.fallback_version =
        Some(semver::Version::parse("0.5.2-dev").unwrap());
    let development = semver::Version::parse("0.5.2-dev").unwrap();
    config::validate_registry_credentials(&release, &development)
        .expect_err("the dev pre-release identifier remains forbidden in the fallback version");
    release.registry_credentials.fallback_version =
        Some(semver::Version::parse("0.5.2-rc.12").unwrap());
    let candidate = semver::Version::parse("0.5.2-rc.12").unwrap();
    release.registry_credentials.fallback_version = Some(candidate.clone());
    config::validate_registry_credentials(&release, &candidate)
        .expect("a normal prerelease may bound one immutable recovery release");
    let mismatched = semver::Version::parse("0.5.3").unwrap();
    assert!(
        config::validate_registry_credentials(&release, &mismatched).is_err(),
        "a numerically different workspace version must fail before tagging"
    );
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
    let actual: Vec<(&str, &str, &str, bool, Vec<&str>)> = release
        .assets
        .target
        .iter()
        .map(|target| {
            (
                target.id.as_str(),
                target.rust_target.as_str(),
                target.archive.as_str(),
                target.sealed == SealedAssetPolicy::Included,
                target
                    .executable
                    .iter()
                    .map(|component| component.archive_path.as_str())
                    .collect(),
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
                true,
                vec!["memcordon", "memcordon-sealed-agent"],
            ),
            (
                "linux-arm64",
                "aarch64-unknown-linux-gnu",
                "tar-gz",
                true,
                vec!["memcordon", "memcordon-sealed-agent"],
            ),
            (
                "macos-arm64",
                "aarch64-apple-darwin",
                "tar-gz",
                false,
                vec!["memcordon"],
            ),
            (
                "macos-x64",
                "x86_64-apple-darwin",
                "tar-gz",
                false,
                vec!["memcordon"],
            ),
            (
                "windows-x64",
                "x86_64-pc-windows-msvc",
                "zip",
                true,
                vec![
                    "memcordon.exe",
                    "memcordon-sealed-agent.exe",
                    "memcordon-target-desktop-bootstrap.exe",
                    "memcordon-session-broker.exe",
                ],
            ),
            (
                "windows-arm64",
                "aarch64-pc-windows-msvc",
                "zip",
                true,
                vec![
                    "memcordon.exe",
                    "memcordon-sealed-agent.exe",
                    "memcordon-target-desktop-bootstrap.exe",
                    "memcordon-session-broker.exe",
                ],
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
