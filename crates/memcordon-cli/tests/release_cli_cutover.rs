#[path = "../src/bin/memcordon-sealed-agent/release_cli_cutover.rs"]
mod release_cli_cutover;

use std::ffi::OsString;

use release_cli_cutover::{ReleasePlatform, retired_release_command};

fn denied(platform: ReleasePlatform, arguments: &[&str]) -> bool {
    let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
    retired_release_command(platform, &arguments)
}

#[test]
fn linux_protected_image_install_reaches_its_existing_operational_dispatch() {
    let arguments = [
        "package",
        "policy",
        "entrypoint",
        "install",
        "--definition",
        "/usr/libexec/selected image.json",
        "--source",
        "/tmp/selected image",
    ];
    assert!(!denied(ReleasePlatform::Linux, &arguments));
    assert!(denied(ReleasePlatform::Windows, &arguments));
    assert!(denied(ReleasePlatform::Other, &arguments));

    for index in [1, 2, 3, 4, 6] {
        let mut changed = arguments;
        changed[index] = "unsupported";
        assert!(denied(ReleasePlatform::Linux, &changed), "{changed:?}");
    }
    for length in 1..arguments.len() {
        assert!(denied(ReleasePlatform::Linux, &arguments[..length]));
    }
    let mut extra = arguments.to_vec();
    extra.push("--ephemeral-ci");
    assert!(denied(ReleasePlatform::Linux, &extra));
    let mut qualification = arguments;
    qualification[4] = "--qualification-artifact-directory";
    assert!(denied(ReleasePlatform::Linux, &qualification));
    let mut reordered = arguments;
    reordered.swap(4, 6);
    assert!(denied(ReleasePlatform::Linux, &reordered));
}

#[cfg(unix)]
#[test]
fn linux_image_install_preserves_native_path_arguments_for_protected_validation() {
    use std::os::unix::ffi::OsStringExt;

    let mut arguments = [
        "package",
        "policy",
        "entrypoint",
        "install",
        "--definition",
        "definition",
        "--source",
        "source",
    ]
    .map(OsString::from);
    arguments[5] = OsString::from_vec(b"/usr/libexec/definition\xff.json".to_vec());
    arguments[7] = OsString::from_vec(b"/tmp/source\xff".to_vec());
    assert!(!retired_release_command(ReleasePlatform::Linux, &arguments));
    assert!(retired_release_command(
        ReleasePlatform::Windows,
        &arguments
    ));
    assert!(retired_release_command(ReleasePlatform::Other, &arguments));
}

#[test]
fn retired_release_entrypoints_close_without_blocking_operational_packages() {
    let expected_platform = if cfg!(target_os = "linux") {
        ReleasePlatform::Linux
    } else if cfg!(target_os = "windows") {
        ReleasePlatform::Windows
    } else {
        ReleasePlatform::Other
    };
    assert_eq!(ReleasePlatform::current(), expected_platform);
    assert!(denied(ReleasePlatform::Other, &["package", "inspect"]));
    for command in [
        "release-case-reuse-source",
        "release-hosted-facility-controls",
        "public-release-fixture",
        "public-abi-filtered-target",
        "private-release-fixture",
        "private-release-unix-intent",
        "policy-decision-peer",
    ] {
        assert!(denied(ReleasePlatform::Linux, &[command]), "{command}");
        assert!(denied(ReleasePlatform::Windows, &[command]), "{command}");
    }
    for command in ["serve", "launch-broker", "probe", "private-probe-fixture"] {
        assert!(!denied(ReleasePlatform::Linux, &[command]), "{command}");
        assert!(!denied(ReleasePlatform::Windows, &[command]), "{command}");
    }
    assert!(!retired_release_command(ReleasePlatform::Windows, &[]));
    for operation in ["inspect", "verify", "install", "upgrade", "uninstall"] {
        assert!(!denied(ReleasePlatform::Windows, &["package", operation]));
        assert!(!denied(ReleasePlatform::Linux, &["package", operation]));
    }
    for operation in ["inspect", "verify"] {
        assert!(!denied(
            ReleasePlatform::Windows,
            &["package", operation, "--json"]
        ));
    }
    for operation in ["install", "upgrade", "uninstall"] {
        assert!(denied(
            ReleasePlatform::Windows,
            &["package", operation, "--ephemeral-ci"]
        ));
        assert!(denied(
            ReleasePlatform::Linux,
            &["package", operation, "--ephemeral-ci"]
        ));
    }
    assert!(!denied(
        ReleasePlatform::Windows,
        &["package", "policy", "inspect", "--json"]
    ));
    assert!(!denied(
        ReleasePlatform::Windows,
        &["package", "policy", "apply", "--file", "policy.json"]
    ));
    for arguments in [
        &[
            "package",
            "install",
            "--qualification-artifact-directory",
            "proofs",
        ][..],
        &[
            "package",
            "install",
            "--ephemeral-ci",
            "--qualification-artifact-directory",
            "proofs",
        ],
        &["package", "install", "--archive-path", "archive.zip"],
        &["package", "fault-inject"],
        &["package", "verify-private-host"],
        &[
            "package",
            "policy",
            "apply",
            "--file",
            "policy.json",
            "extra",
        ],
    ] {
        assert!(denied(ReleasePlatform::Windows, arguments), "{arguments:?}");
    }
    let source = include_str!("../src/bin/memcordon-sealed-agent/main.rs");
    assert!(!source.contains("let retired = false"));
    assert!(!source.contains("#[cfg(target_os = \"linux\")]\nmod release_cli_cutover"));
    for removed_dispatch in [
        "package::run_with_archive(",
        "--archive-certificate",
        "--qualification-artifact-directory",
    ] {
        assert!(
            !source.contains(removed_dispatch),
            "retired package dispatch remains: {removed_dispatch}"
        );
    }
    assert!(source.contains("windows::policy_registry::apply("));
    assert!(source.contains("windows::policy_registry::inspect("));
    assert!(
        source.find("let retired =").unwrap() < source.find("match arguments.as_slice()").unwrap()
    );
}

#[test]
fn sealed_agent_dispatch_no_longer_calls_old_release_producers() {
    let source = include_str!("../src/bin/memcordon-sealed-agent/main.rs");
    let linux_modules = include_str!("../src/bin/memcordon-sealed-agent/linux/mod.rs");
    assert!(!linux_modules.contains("mod private_policy_decision_peer;"));
    for forbidden in [
        "linux::private_release_case::",
        "linux::private_release_run::",
        "linux::private_public_provider::",
        "linux::hosted_public_provider::",
        "linux::private_policy_decision_peer::",
    ] {
        assert!(
            !source.contains(forbidden),
            "retired dispatch remains: {forbidden}"
        );
    }
    for required in ["linux::service::serve()", "linux::launcher::serve()"] {
        assert!(
            source.contains(required),
            "product entrypoint lost: {required}"
        );
    }
}
