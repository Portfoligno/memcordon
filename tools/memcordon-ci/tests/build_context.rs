use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
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

#[cfg(unix)]
#[test]
fn dangling_native_links_are_stable_until_the_target_appears() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let target = external.path().join("optional-library");
    symlink(&target, root.path().join("library")).unwrap();
    let missing = BuildInputSnapshot::capture(root.path()).unwrap();
    missing.audit().unwrap();
    fs::write(&target, b"installed library\n").unwrap();
    assert!(missing.audit().is_err());
    let present = BuildInputSnapshot::capture(root.path()).unwrap();
    present.audit().unwrap();
    fs::write(&target, b"updated library\n").unwrap();
    assert!(present.audit().is_err());
}

#[cfg(unix)]
#[test]
fn dangling_native_link_retargeting_changes_identity() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let link = root.path().join("library");
    symlink("missing-first", &link).unwrap();
    let before = BuildInputSnapshot::capture(root.path()).unwrap();
    fs::remove_file(&link).unwrap();
    symlink("missing-second", &link).unwrap();
    assert!(before.audit().is_err());
}

#[cfg(unix)]
#[test]
fn overlapping_native_aliases_and_ancestor_cycles_remain_auditable() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let sdk = root.path().join("sdk");
    fs::create_dir(&sdk).unwrap();
    let header = sdk.join("header.h");
    fs::write(&header, b"header\n").unwrap();
    symlink(root.path(), sdk.join("parent")).unwrap();
    symlink(&sdk, root.path().join("alias-a")).unwrap();
    symlink(&sdk, root.path().join("alias-b")).unwrap();
    let before = BuildInputSnapshot::capture(root.path()).unwrap();
    before.audit().unwrap();
    fs::write(header, b"changed header\n").unwrap();
    assert!(before.audit().is_err());
}

#[cfg(unix)]
#[test]
fn unresolvable_native_links_report_the_path_and_operation() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let link = root.path().join("self-reference");
    symlink("self-reference", &link).unwrap();
    let error = BuildInputSnapshot::capture(root.path())
        .unwrap_err()
        .to_string();
    assert!(error.contains("self-reference"), "{error}");
    assert!(error.contains("resolving symlink"), "{error}");
}

#[test]
fn missing_declared_native_root_is_an_error_with_path_context() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("required-sdk");
    let error = BuildInputSnapshot::capture(&missing)
        .unwrap_err()
        .to_string();
    assert!(error.contains("required-sdk"), "{error}");
    assert!(error.contains("resolving build input root"), "{error}");
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
    for name in ["SDKROOT", "DEVELOPER_DIR"] {
        let env = BTreeMap::from([(OsString::from(name), first.clone().into_os_string())]);
        assert_eq!(
            native_environment_roots(&env).unwrap(),
            vec![first.canonicalize().unwrap()]
        );
    }
    for name in [
        "VCToolsInstallDir",
        "WindowsSdkDir",
        "VCINSTALLDIR",
        "VSINSTALLDIR",
    ] {
        let env = BTreeMap::from([(OsString::from(name), first.clone().into_os_string())]);
        assert!(native_environment_roots(&env).unwrap().is_empty());
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
fn windows_native_discovery_uses_all_canonical_environment_names() {
    use environment::{EnvironmentNames, closed_environment_with_names};
    use memcordon_ci::build_context::{
        native_environment_roots, validate_windows_native_root_scope, windows_native_roots,
    };

    let root = tempfile::tempdir().unwrap();
    let windows = root.path().join("Windows");
    let selected_sdk = root.path().join("SelectedSdk");
    let selected_compiler = root.path().join("SelectedCompiler");
    let selected_include = selected_compiler.join("include");
    let selected_library = selected_compiler.join("lib");
    fs::create_dir(&selected_sdk).unwrap();
    fs::create_dir_all(&selected_include).unwrap();
    fs::create_dir(&selected_library).unwrap();
    let mut env = BTreeMap::from([
        (OsString::from("pAtH"), root.path().as_os_str().to_owned()),
        (
            OsString::from("sYsTeMrOoT"),
            windows.clone().into_os_string(),
        ),
        (
            OsString::from("wInDoWsSdKdIr"),
            selected_sdk.clone().into_os_string(),
        ),
        (
            OsString::from("vCtOoLsInStAlLdIr"),
            selected_compiler.clone().into_os_string(),
        ),
        (
            OsString::from("iNcLuDe"),
            selected_include.clone().into_os_string(),
        ),
        (
            OsString::from("lIb"),
            selected_library.clone().into_os_string(),
        ),
    ]);
    let mut expected = Vec::new();
    for name in ["pRoGrAmFiLeS", "pRoGrAmFiLeS(x86)", "pRoGrAmW6432"] {
        let base = root.path().join(name);
        for child in ["Windows Kits", "Microsoft Visual Studio"] {
            let directory = base.join(child);
            fs::create_dir_all(&directory).unwrap();
        }
        env.insert(name.into(), base.into_os_string());
    }
    for library in ["kernel32.dll", "ntdll.dll", "ucrtbase.dll", "msvcp_win.dll"] {
        expected.push(windows.join("System32").join(library));
    }
    let closed = closed_environment_with_names(&env, EnvironmentNames::Windows).unwrap();
    let mut actual = windows_native_roots(&closed).unwrap();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
    let selected = native_environment_roots(&closed).unwrap();
    assert_eq!(
        selected,
        [
            selected_include.canonicalize().unwrap(),
            selected_library.canonicalize().unwrap(),
        ]
    );
    assert!(!selected.contains(&selected_sdk.canonicalize().unwrap()));
    assert!(!selected.contains(&selected_compiler.canonicalize().unwrap()));
    validate_windows_native_root_scope(&closed, &selected).unwrap();
}

#[test]
fn windows_native_baseline_requires_only_the_system_root() {
    use memcordon_ci::build_context::windows_native_roots;
    let root = tempfile::tempdir().unwrap();
    let mut env = BTreeMap::from([(
        OsString::from("ProgramFiles"),
        root.path().as_os_str().to_owned(),
    )]);
    assert!(windows_native_roots(&env).is_err());
    env.insert(
        "SystemRoot".into(),
        root.path().join("Windows").into_os_string(),
    );
    assert!(windows_native_roots(&env).is_ok());
}

#[test]
fn windows_native_scope_rejects_discovery_ancestors_but_accepts_selected_descendants() {
    use memcordon_ci::build_context::validate_windows_native_root_scope;
    let root = tempfile::tempdir().unwrap();
    let program_files = root.path().join("Program Files");
    let installation = program_files.join("Microsoft Visual Studio").join("2022");
    let vc = installation.join("VC");
    let toolset = vc.join("Tools/MSVC/selected");
    let sdk = root.path().join("Windows Kits").join("10");
    fs::create_dir_all(&toolset).unwrap();
    fs::create_dir_all(&sdk).unwrap();
    let environment = BTreeMap::from([
        (
            "ProgramFiles".into(),
            program_files.clone().into_os_string(),
        ),
        ("VSINSTALLDIR".into(), installation.clone().into_os_string()),
        ("VCINSTALLDIR".into(), vc.clone().into_os_string()),
        ("VCToolsInstallDir".into(), toolset.clone().into_os_string()),
        ("WindowsSdkDir".into(), sdk.clone().into_os_string()),
    ]);
    for broad in [
        program_files.clone(),
        program_files.join("Microsoft Visual Studio"),
        installation,
        vc.clone(),
        toolset.clone(),
        sdk.clone(),
    ] {
        assert!(
            validate_windows_native_root_scope(&environment, &[broad.canonicalize().unwrap()])
                .is_err()
        );
    }
    validate_windows_native_root_scope(
        &environment,
        &[toolset.join("include"), sdk.join("Include/selected/um")],
    )
    .unwrap();
}

#[test]
fn native_roots_drop_covered_descendants_without_admitting_siblings() {
    use memcordon_ci::build_context::minimal_native_roots;
    let root = PathBuf::from("root");
    assert_eq!(
        minimal_native_roots(vec![
            root.join("selected/include"),
            root.join("selected"),
            root.join("selected/lib"),
            root.join("sibling"),
            root.join("selected"),
        ]),
        [root.join("selected"), root.join("sibling")]
    );
}

#[test]
fn inactive_windows_selection_siblings_do_not_change_selected_input_identity() {
    use memcordon_ci::build_context::native_environment_roots;
    let root = tempfile::tempdir().unwrap();
    let selected = root.path().join("selected");
    let include = selected.join("include");
    let library = selected.join("lib");
    let inactive = root.path().join("inactive-sdk");
    fs::create_dir_all(&include).unwrap();
    fs::create_dir(&library).unwrap();
    fs::create_dir(&inactive).unwrap();
    let header = include.join("selected.h");
    fs::write(&header, b"selected header\n").unwrap();
    fs::write(library.join("selected.lib"), b"selected library\n").unwrap();
    let inactive_file = inactive.join("other-version.lib");
    fs::write(&inactive_file, b"inactive version\n").unwrap();
    let environment = BTreeMap::from([
        (
            OsString::from("INCLUDE"),
            std::env::join_paths([&include]).unwrap(),
        ),
        (
            OsString::from("LIB"),
            std::env::join_paths([&library]).unwrap(),
        ),
        (
            OsString::from("WindowsSdkDir"),
            inactive.clone().into_os_string(),
        ),
    ]);
    let roots = native_environment_roots(&environment).unwrap();
    assert_eq!(
        roots,
        [
            include.canonicalize().unwrap(),
            library.canonicalize().unwrap(),
        ]
    );
    let snapshots = roots
        .iter()
        .map(|root| BuildInputSnapshot::capture(root).unwrap())
        .collect::<Vec<_>>();
    fs::write(inactive_file, b"changed inactive version\n").unwrap();
    assert!(snapshots.iter().all(|snapshot| snapshot.audit().is_ok()));
    fs::write(header, b"changed selected header\n").unwrap();
    assert!(snapshots.iter().any(|snapshot| snapshot.audit().is_err()));
}

#[test]
fn cold_seed_compiles_without_cargo_dependencies_and_rejects_override_before_bootstrap() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = tempfile::tempdir().unwrap();
    let source_journals =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/ci/reports/inventory-observation/v1");
    let source_entries = || match std::fs::read_dir(&source_journals) {
        Ok(entries) => {
            let mut paths = entries
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            paths.sort();
            Some(paths)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("reading source journal directory: {error}"),
    };
    let before = source_entries();
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
        .current_dir(output.path())
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
    assert!(!output.path().join("manifest.admission.json").exists());
    let journals = std::fs::read_dir(
        output
            .path()
            .join("target/ci/reports/inventory-observation/v1"),
    )
    .unwrap()
    .map(|entry| entry.unwrap().path())
    .collect::<Vec<_>>();
    assert_eq!(
        journals.len(),
        1,
        "retain the isolated early-failure journal"
    );
    let start: serde_json::Value =
        serde_json::from_slice(&std::fs::read(journals[0].join("run-start.json")).unwrap())
            .unwrap();
    assert_eq!(start["schema"], 1);
    assert_eq!(start["outcome"], "incomplete_unknown_termination");
    assert_eq!(
        source_entries(),
        before,
        "the test must not mutate measured source"
    );
}

#[test]
fn isolated_install_child_uses_the_canonical_source_namespace() {
    // This fixture exercises the unmanaged API. Cargo's managed parent may
    // supply compiler routing, but its in-process context is not inherited.
    let mut child = generated_fixture_child("generated_package_unmanaged_child");
    let output =
        memcordon_testkit::run_with_deadline(&mut child, std::time::Duration::from_secs(90))
            .unwrap();
    assert!(
        output.status.success(),
        "generated-package child failed: stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("1 passed;")
    );
}

#[test]
fn isolated_source_child_output_requires_exact_single_root_argument() {
    use memcordon_ci::build_context::{IsolatedOutputScope, run_isolated_cargo_with_output_scope};

    let source = tempfile::tempdir().unwrap();
    let install = source.path().join("install");
    let sibling = source.path().with_file_name("install-other");
    let deadline = std::time::Duration::from_secs(1);
    let run = |arguments: Vec<OsString>, declared: Option<&Path>| {
        run_isolated_cargo_with_output_scope(
            source.path(),
            "1.97.1",
            arguments,
            deadline,
            declared,
            IsolatedOutputScope::SourceChild,
        )
    };

    assert!(run(vec![OsString::from("install")], Some(&install)).is_err());
    assert!(run(vec![OsString::from("install")], Some(&sibling)).is_err());
    assert!(run(vec![OsString::from("install")], Some(source.path())).is_err());
    assert!(
        run(
            vec![OsString::from("install")],
            Some(&source.path().join("candidate/install")),
        )
        .is_err()
    );
    assert!(
        run(
            vec![
                OsString::from("install"),
                OsString::from("--root"),
                install.as_os_str().to_os_string(),
            ],
            None,
        )
        .is_err()
    );
    assert!(
        run(
            vec![
                OsString::from("install"),
                OsString::from("--root"),
                sibling.into_os_string(),
            ],
            Some(&install),
        )
        .is_err()
    );
    assert!(
        run(
            vec![
                OsString::from("install"),
                OsString::from("--root"),
                install.as_os_str().to_os_string(),
                OsString::from("--root"),
                install.as_os_str().to_os_string(),
            ],
            Some(&install),
        )
        .is_err()
    );
}

#[test]
fn isolated_external_output_cannot_hide_measured_source() {
    let source = tempfile::tempdir().unwrap();
    let deadline = std::time::Duration::from_secs(1);
    for output in [source.path().to_path_buf(), source.path().join("install")] {
        let error = memcordon_ci::build_context::run_isolated_cargo(
            source.path(),
            "1.97.1",
            [
                OsString::from("install"),
                OsString::from("--root"),
                output.as_os_str().to_os_string(),
            ],
            deadline,
            Some(&output),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("overlaps source"),
            "unexpected error: {error}"
        );
    }
}

fn generated_fixture_child(name: &str) -> Command {
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", name, "--ignored", "--nocapture"])
        .env_remove("RUSTC")
        .env_remove("RUSTDOC");
    child
}

#[test]
fn unmanaged_generated_packages_reject_each_ambient_compiler_override() {
    for variable in ["RUSTC", "RUSTDOC"] {
        let mut child = generated_fixture_child("generated_package_rejected_override_child");
        child.env(variable, "unapproved-compiler-fixture");
        let output =
            memcordon_testkit::run_with_deadline(&mut child, std::time::Duration::from_secs(10))
                .unwrap();
        assert!(
            output.status.success(),
            "override {variable} was not rejected: stdout={:?} stderr={:?}",
            output.stdout,
            output.stderr
        );
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("1 passed;")
        );
    }
}

#[test]
fn generated_package_regression_isolated_from_parent_compiler_routing() {
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "isolated_install_child_uses_the_canonical_source_namespace",
            "--nocapture",
        ])
        .env("RUSTC", "parent-compiler-routing-fixture")
        .env("RUSTDOC", "parent-rustdoc-routing-fixture");
    let output =
        memcordon_testkit::run_with_deadline(&mut child, std::time::Duration::from_secs(100))
            .unwrap();
    assert!(
        output.status.success(),
        "inherited compiler routing contaminated the unmanaged fixture: stdout={:?} stderr={:?}",
        output.stdout,
        output.stderr
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("1 passed;")
    );
}

#[test]
#[ignore = "invoked explicitly by the generated-package environment boundary regression"]
fn generated_package_rejected_override_child() {
    let source = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("src")).unwrap();
    fs::write(source.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    fs::write(
        source.path().join("Cargo.toml"),
        "[package]\nname = \"rejected-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    let error = memcordon_ci::build_context::run_isolated_cargo(
        source.path(),
        "1.97.1",
        ["generate-lockfile"],
        std::time::Duration::from_secs(5),
        None,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("rejects ambient override"),
        "{error}"
    );
    assert!(!source.path().join("Cargo.lock").exists());
}

#[test]
#[ignore = "invoked explicitly in a child with unmanaged compiler environment"]
fn generated_package_unmanaged_child() {
    use memcordon_ci::build_context::{
        IsolatedOutputScope, run_isolated_cargo, run_isolated_cargo_with_output_scope,
    };
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
    let install = source.path().join("install");
    run_isolated_cargo_with_output_scope(
        source.path(),
        "1.97.1",
        [
            OsString::from("install"),
            OsString::from("--locked"),
            OsString::from("--root"),
            install.clone().into_os_string(),
            OsString::from("--path"),
            source.path().as_os_str().to_os_string(),
        ],
        deadline,
        Some(&install),
        IsolatedOutputScope::SourceChild,
    )
    .unwrap();
    assert!(
        install
            .join("bin")
            .join(if cfg!(windows) {
                "isolated-fixture.exe"
            } else {
                "isolated-fixture"
            })
            .exists()
    );
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
        "[patch.crates-io]\nisolated-local-dependency = { path = 'local-dependency' }\n",
    )
    .unwrap();
    let dependency = source.path().join("local-dependency");
    fs::create_dir_all(dependency.join("src")).unwrap();
    fs::write(
        dependency.join("Cargo.toml"),
        "[package]\nname = 'isolated-local-dependency'\nversion = '0.0.0'\nedition = '2021'\n",
    )
    .unwrap();
    fs::write(
        dependency.join("src/lib.rs"),
        "pub fn value() -> u32 { 7 }\n",
    )
    .unwrap();
    fs::write(source.path().join("Cargo.toml"), "[package]\nname = 'isolated-fixture'\nversion = '0.0.0'\nedition = '2021'\n[dependencies]\nisolated-local-dependency = '=0.0.0'\n").unwrap();
    fs::write(
        source.path().join("src/main.rs"),
        "fn main() { assert_eq!(isolated_local_dependency::value(), 7); }\n",
    )
    .unwrap();
    run_isolated_cargo(
        source.path(),
        "1.97.1",
        ["generate-lockfile", "--offline"],
        deadline,
        None,
    )
    .unwrap();
    run_isolated_cargo(
        source.path(),
        "1.97.1",
        ["check", "--locked", "--offline"],
        deadline,
        None,
    )
    .unwrap();
}
