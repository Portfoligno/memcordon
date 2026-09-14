use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;
use std::process::Command;

use memcordon_ci::build_context::{BuildInputSnapshot, ValidatedBuildContext, environment};

fn ambient() -> BTreeMap<OsString, OsString> {
    let mut environment = BTreeMap::new();
    environment.insert(
        "PATH".into(),
        std::env::join_paths([std::env::temp_dir()]).unwrap(),
    );
    environment
}

#[test]
fn compiler_wrapper_flags_and_configuration_families_are_rejected() {
    for name in [
        "RUSTC",
        "RUSTDOC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC",
        "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
        "CARGO_PROFILE_RELEASE_LTO",
        "RUSTFLAGS",
        "CFLAGS",
        "CARGO_SOURCE_CRATES_IO_REPLACE_WITH",
    ] {
        for value in ["", "<absent>", "unapproved"] {
            let mut env = ambient();
            env.insert(name.into(), value.into());
            assert!(
                environment::closed_environment(&env).is_err(),
                "{name}={value:?} must not silently change the compiler"
            );
        }
    }
}

#[test]
fn unknown_variables_and_credentials_do_not_reach_builds() {
    let mut env = ambient();
    for name in [
        "TERM",
        "RUST_LOG",
        "GITHUB_TOKEN",
        "CARGO_REGISTRIES_CRATES_IO_TOKEN",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
    ] {
        env.insert(name.into(), "untrusted".into());
    }
    let closed = environment::closed_environment(&env).unwrap();
    for name in [
        "TERM",
        "RUST_LOG",
        "GITHUB_TOKEN",
        "CARGO_REGISTRIES_CRATES_IO_TOKEN",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
    ] {
        assert!(!closed.contains_key(OsStr::new(name)));
    }
}

#[test]
fn empty_absent_and_literal_absence_are_distinct() {
    let absent = environment::closed_environment(&ambient()).unwrap();
    let mut env = ambient();
    env.insert("SDKROOT".into(), "".into());
    let empty = environment::closed_environment(&env).unwrap();
    env.insert("SDKROOT".into(), "<absent>".into());
    let literal = environment::closed_environment(&env).unwrap();
    assert_ne!(absent, empty);
    assert_ne!(empty, literal);
    assert_ne!(absent, literal);
}

#[cfg(unix)]
#[test]
fn native_environment_bytes_are_never_lossily_encoded() {
    use std::os::unix::ffi::OsStringExt;
    let mut env = ambient();
    let value = OsString::from_vec(vec![b'/', 0xff]);
    env.insert("SDKROOT".into(), value.clone());
    assert_eq!(
        environment::closed_environment(&env)
            .unwrap()
            .get(OsStr::new("SDKROOT")),
        Some(&value)
    );
}

#[test]
fn both_legacy_and_toml_ancestor_and_home_configuration_are_rejected() {
    for file in ["config", "config.toml"] {
        let root = tempfile::tempdir().unwrap();
        let work = root.path().join("checkout/nested");
        let home = root.path().join("home");
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&home).unwrap();
        environment::reject_cargo_configuration(&work, &home).unwrap();
        fs::create_dir(root.path().join(".cargo")).unwrap();
        fs::write(
            root.path().join(".cargo").join(file),
            "[build]\nrustc = 'other'\n",
        )
        .unwrap();
        assert!(environment::reject_cargo_configuration(&work, &home).is_err());
        let isolated = tempfile::tempdir().unwrap();
        fs::write(home.join(file), "[env]\nRUSTC = 'other'\n").unwrap();
        assert!(environment::reject_cargo_configuration(isolated.path(), &home).is_err());
    }
}

#[test]
fn unchanged_version_output_cannot_hide_compiler_or_sdk_content_drift() {
    let root = tempfile::tempdir().unwrap();
    for name in ["compiler", "sdk-header", "generated-source", "Cargo.toml"] {
        fs::write(root.path().join(name), b"version stays the same\n").unwrap();
    }
    for name in ["compiler", "sdk-header", "generated-source", "Cargo.toml"] {
        let before = BuildInputSnapshot::capture(root.path()).unwrap();
        fs::write(
            root.path().join(name),
            b"changed content; version stays the same\n",
        )
        .unwrap();
        assert!(before.audit().is_err());
        assert_ne!(
            before.digest().unwrap(),
            BuildInputSnapshot::capture(root.path())
                .unwrap()
                .digest()
                .unwrap()
        );
    }
}

#[cfg(unix)]
#[test]
fn executable_modes_and_symlink_targets_enter_identity() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("tool");
    fs::write(&executable, b"bytes\n").unwrap();
    let original = BuildInputSnapshot::capture(root.path()).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(original.audit().is_err());
    let original = BuildInputSnapshot::capture(root.path()).unwrap();
    symlink(&executable, root.path().join("selected-tool")).unwrap();
    assert!(original.audit().is_err());
}

#[test]
fn failed_test_with_unchanged_inputs_remains_auditable_without_a_cached_pass() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("source"), b"source\n").unwrap();
    let before = BuildInputSnapshot::capture(root.path()).unwrap();
    let failed_outcome: Result<(), &str> = Err("candidate test failed");
    assert!(failed_outcome.is_err());
    before.audit().unwrap();
    assert_eq!(
        before.digest().unwrap(),
        BuildInputSnapshot::capture(root.path())
            .unwrap()
            .digest()
            .unwrap()
    );
}

#[test]
fn missing_empty_and_future_contexts_cannot_authorize_restore() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("context.json");
    assert!(ValidatedBuildContext::read(&path).is_err());
    for bytes in [b"".as_slice(), b"{}", b"{\"schema_version\":999}"] {
        fs::write(&path, bytes).unwrap();
        assert!(ValidatedBuildContext::read(&path).is_err());
    }
}

#[test]
fn external_sdk_and_native_path_lists_are_content_inputs() {
    use memcordon_ci::build_context::native_environment_roots;
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("sdk");
    let second = root.path().join("libraries");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    let header = first.join("header.h");
    fs::write(&header, b"original\n").unwrap();
    for name in [
        "SDKROOT",
        "DEVELOPER_DIR",
        "VCToolsInstallDir",
        "WindowsSdkDir",
    ] {
        let env = BTreeMap::from([(OsString::from(name), first.clone().into_os_string())]);
        assert_eq!(
            native_environment_roots(&env).unwrap(),
            vec![first.canonicalize().unwrap()]
        );
    }
    for name in ["INCLUDE", "LIB", "LIBPATH"] {
        let env = BTreeMap::from([(
            OsString::from(name),
            std::env::join_paths([&first, &second]).unwrap(),
        )]);
        assert_eq!(native_environment_roots(&env).unwrap().len(), 2);
    }
    let before = BuildInputSnapshot::capture(&first).unwrap();
    fs::write(header, b"changed external header\n").unwrap();
    assert!(before.audit().is_err());
    let env = BTreeMap::from([(OsString::from("SDKROOT"), OsString::from("relative"))]);
    assert!(native_environment_roots(&env).is_err());
}

#[test]
fn cold_seed_compiles_without_cargo_dependencies_and_rejects_override_before_bootstrap() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = tempfile::tempdir().unwrap();
    let executable = output
        .path()
        .join(if cfg!(windows) { "seed.exe" } else { "seed" });
    let status = Command::new("rustup")
        .args(["run", "1.97.1", "rustc", "--edition=2021"])
        .arg(root.join("tools/ci-native-fingerprint.rs"))
        .arg("-o")
        .arg(&executable)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "the seed must compile freshly using only std"
    );
    let result = Command::new(&executable)
        .args(["--output"])
        .arg(output.path().join("manifest"))
        .env("RUSTC_WRAPPER", "unapproved")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("rejects ambient override")
    );
    assert!(!output.path().join("manifest").exists());
}

#[test]
fn generated_package_builds_use_fresh_uncached_outputs_and_reject_configuration_overrides() {
    use memcordon_ci::build_context::run_isolated_cargo;
    use std::time::Duration;
    let source = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("src")).unwrap();
    fs::write(
        source.path().join("Cargo.toml"),
        "[package]\nname = \"isolated-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(source.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    let deadline = Duration::from_secs(30);
    run_isolated_cargo(
        source.path(),
        "1.97.1",
        ["generate-lockfile"],
        deadline,
        None,
    )
    .unwrap();
    let cached = source.path().join("must-not-be-a-cached-target");
    run_isolated_cargo(
        source.path(),
        "1.97.1",
        [
            OsString::from("check"),
            OsString::from("--locked"),
            OsString::from("--target-dir"),
            cached.clone().into_os_string(),
        ],
        deadline,
        None,
    )
    .unwrap();
    assert!(!cached.exists());
    assert!(!source.path().join("target").exists());
    for args in [
        vec!["check", "--config", "build.rustc-wrapper=other"],
        vec!["install", "--root=../escape"],
        vec!["install", "--root", "../escape"],
    ] {
        assert!(run_isolated_cargo(source.path(), "1.97.1", args, deadline, None).is_err());
    }
    fs::create_dir(source.path().join(".cargo")).unwrap();
    fs::write(
        source.path().join(".cargo/config.toml"),
        "[build]\nrustc-wrapper = \"other\"\n",
    )
    .unwrap();
    assert!(run_isolated_cargo(source.path(), "1.97.1", ["check"], deadline, None).is_err());
    fs::write(
        source.path().join(".cargo/config.toml"),
        "[patch.crates-io]\n",
    )
    .unwrap();
    run_isolated_cargo(
        source.path(),
        "1.97.1",
        ["check", "--locked"],
        deadline,
        None,
    )
    .unwrap();
}
