use memcordon_ci::build_context::environment::command_path;
use std::fs;

#[test]
fn command_path_preserves_existing_identity_and_native_names() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().join("native 日本語 path with spaces");
    fs::create_dir(&directory).unwrap();
    let canonical = directory.canonicalize().unwrap();
    let command = command_path(&canonical).unwrap();
    assert_eq!(command.canonicalize().unwrap(), canonical);
    assert_eq!(command.file_name(), directory.file_name());
    assert_eq!(command_path(&command).unwrap(), command);
    assert!(command_path(&directory.join("missing-input")).is_err());
}

#[cfg(windows)]
#[test]
fn windows_disk_and_unc_spellings_preserve_components() {
    use memcordon_ci::build_context::environment::paths::windows_command_spelling;
    use std::path::Path;

    for (input, expected) in [
        (
            r"\\?\C:\native 日本語\file name",
            r"C:\native 日本語\file name",
        ),
        (
            r"\\?\UNC\server\share\native 日本語\file name",
            r"\\server\share\native 日本語\file name",
        ),
        (r"C:\normal\file name", r"C:\normal\file name"),
        (r"\\server\share\file name", r"\\server\share\file name"),
    ] {
        assert_eq!(
            windows_command_spelling(Path::new(input)).unwrap(),
            Path::new(expected)
        );
    }
}

#[cfg(windows)]
#[test]
fn unsupported_namespaces_cannot_become_command_paths() {
    use memcordon_ci::build_context::environment::paths::windows_command_spelling;
    use std::path::Path;

    for input in [
        r"\\.\PhysicalDrive0",
        r"\\?\GLOBALROOT\Device\HarddiskVolume1\input",
        r"relative\input",
        r"C:relative\input",
        r"\\?\C:\name.",
        r"\\?\C:\name ",
    ] {
        assert!(
            windows_command_spelling(Path::new(input)).is_err(),
            "unsupported namespace accepted: {input}"
        );
    }
}

#[test]
fn command_outputs_validate_existing_ancestor_and_preserve_future_names() {
    use memcordon_ci::build_context::environment::paths::command_output_path;
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let output = root.join("future target").join("日本語 output");
    let command = command_output_path(&output).unwrap();
    assert_eq!(
        command,
        command_path(&root)
            .unwrap()
            .join("future target")
            .join("日本語 output")
    );
    assert!(!output.exists());
    fs::create_dir_all(&output).unwrap();
    assert_eq!(
        command.canonicalize().unwrap(),
        output.canonicalize().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn native_program_spelling_preserves_multicall_alias_name() {
    use memcordon_ci::build_context::environment::paths::command_program;
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("multicall");
    let alias = temporary.path().join("rustup");
    fs::write(&target, b"fixture\n").unwrap();
    symlink(&target, &alias).unwrap();
    assert_eq!(command_program(&alias).unwrap(), alias);
}

#[cfg(windows)]
#[test]
fn windows_spelling_preserves_non_unicode_native_units() {
    use memcordon_ci::build_context::environment::paths::windows_command_spelling;
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::Path;

    let mut input: Vec<_> = r"\\?\C:\native ".encode_utf16().collect();
    input.push(0xd800);
    let mut expected: Vec<_> = r"C:\native ".encode_utf16().collect();
    expected.push(0xd800);
    let input = OsString::from_wide(&input);
    let output = windows_command_spelling(Path::new(&input)).unwrap();
    assert_eq!(
        output.as_os_str().encode_wide().collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn managed_commands_keep_canonical_authorization_and_native_tool_paths() {
    use memcordon_ci::build_context::ValidatedBuildContext;
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};
    use std::path::Path;

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let bin = root.join("toolchain with spaces/bin");
    fs::create_dir_all(&bin).unwrap();
    let tool = |name| {
        bin.join(name)
            .with_extension(std::env::consts::EXE_EXTENSION)
    };
    let cargo = tool("cargo");
    let rustc = tool("rustc");
    let rustdoc = tool("rustdoc");
    for file in [&cargo, &rustc, &rustdoc] {
        fs::write(file, b"measured fixture\n").unwrap();
    }
    let home = root.join("source home");
    fs::create_dir(&home).unwrap();
    let command_home = command_path(&home).unwrap();
    let encoded = |value: &OsStr| hex::encode(value.as_encoded_bytes());
    let manifest = root.join("context.json");
    fs::write(&manifest, serde_json::to_vec(&serde_json::json!({
        "schema_version": 4, "profile": "stable", "root": root,
        "environment": [
            [encoded(OsStr::new("PATH")), encoded(command_path(&bin).unwrap().as_os_str())],
            [encoded(OsStr::new("CARGO_HOME")), encoded(command_home.as_os_str())]
        ],
        "toolchains": {"nightly": cargo}, "input_roots": [root], "discovery_roots": [],
        "inputs": [{"path": encoded(cargo.as_os_str()), "kind": "file", "mode": 0, "digest": "fixture"}],
        "worker": {}
    })).unwrap()).unwrap();
    let context = ValidatedBuildContext::read(&manifest).unwrap();
    let arguments = [
        OsString::from("test"),
        OsString::from("literal $() ; & argument"),
    ];
    let command = context.cargo_command("nightly", &arguments, &root).unwrap();
    assert_eq!(command.get_program(), command_path(&cargo).unwrap());
    assert_eq!(
        command.get_current_dir(),
        Some(command_path(&root).unwrap().as_path())
    );
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        arguments
            .iter()
            .map(OsString::as_os_str)
            .collect::<Vec<_>>()
    );
    let environment: BTreeMap<_, _> = command
        .get_envs()
        .filter_map(|(name, value)| value.map(|value| (name, value)))
        .collect();
    for (name, path) in [
        ("RUSTC", &rustc),
        ("RUSTDOC", &rustdoc),
        ("CARGO_HOME", &home),
    ] {
        let actual = Path::new(environment.get(OsStr::new(name)).unwrap());
        assert_eq!(actual, command_path(path).unwrap());
        assert_eq!(actual.canonicalize().unwrap(), path.canonicalize().unwrap());
    }
    assert_eq!(
        std::env::split_paths(environment.get(OsStr::new("PATH")).unwrap()).next(),
        Some(command_path(&bin).unwrap())
    );
    let unauthorized = tempfile::tempdir().unwrap();
    assert!(
        context
            .cargo_command("nightly", &arguments, unauthorized.path())
            .is_err()
    );
}
