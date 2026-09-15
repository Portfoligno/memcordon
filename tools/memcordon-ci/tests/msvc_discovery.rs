#[allow(dead_code)]
#[path = "../../ci-native-fingerprint.rs"]
mod bootstrap;

use memcordon_ci::build_context::environment::{
    EnvironmentNames, closed_environment_with_names, windows_discovery_environment,
};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

fn ambient() -> BTreeMap<OsString, OsString> {
    let mut environment = BTreeMap::new();
    for name in [
        "PATH",
        "SystemRoot",
        "HOME",
        "USERPROFILE",
        "TMP",
        "TEMP",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            environment.insert(name.into(), value);
        }
    }
    environment
}

#[test]
fn installer_context_is_preserved_only_for_discovery() {
    let mut input = ambient();
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("installer context with spaces");
    let names = [
        "ProgramData",
        "ALLUSERSPROFILE",
        "SystemDrive",
        "APPDATA",
        "LOCALAPPDATA",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "CommonProgramW6432",
    ];
    for name in names {
        let value = if name == "SystemDrive" {
            OsStr::new("C:")
        } else {
            profile.as_os_str()
        };
        input.insert(name.to_ascii_lowercase().into(), value.to_owned());
    }
    input.insert("GITHUB_TOKEN".into(), "not admitted".into());
    let discovery = windows_discovery_environment(&input).unwrap();
    let compilation = closed_environment_with_names(&input, EnvironmentNames::Windows).unwrap();
    for name in names {
        let expected = if name == "SystemDrive" {
            OsStr::new("C:")
        } else {
            profile.as_os_str()
        };
        assert_eq!(
            discovery.get(OsStr::new(name)).map(OsString::as_os_str),
            Some(expected)
        );
        assert!(
            !compilation.contains_key(OsStr::new(name)),
            "discovery-only selector leaked to compilation: {name}"
        );
    }
    assert!(!discovery.contains_key(OsStr::new("GITHUB_TOKEN")));
    assert!(!compilation.contains_key(OsStr::new("GITHUB_TOKEN")));
}

#[test]
fn discovery_rejects_conflicting_profile_aliases_and_compiler_overrides() {
    let mut input = ambient();
    input.insert("ProgramData".into(), "first".into());
    input.insert("PROGRAMDATA".into(), "different".into());
    assert!(
        windows_discovery_environment(&input)
            .unwrap_err()
            .to_string()
            .contains("conflicting environment aliases")
    );

    let mut input = ambient();
    input.insert("rustflags".into(), "unapproved".into());
    assert!(
        windows_discovery_environment(&input)
            .unwrap_err()
            .to_string()
            .contains("rejects ambient override")
    );
    assert!(closed_environment_with_names(&input, EnvironmentNames::Windows).is_err());
}

#[test]
fn capture_uses_the_supplied_discovery_map_and_literal_arguments() {
    use std::fs;
    use std::process::Command;
    use std::time::Duration;

    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("discovery_fixture.rs");
    let executable = directory.path().join("discovery_fixture.exe");
    fs::write(
        &source,
        r#"fn main() {
    println!("{}", std::env::var("ProgramData").unwrap_or_else(|_| "missing".into()));
    println!("{}", std::env::var("GITHUB_TOKEN").unwrap_or_else(|_| "absent".into()));
    for argument in std::env::args().skip(1) { println!("{argument}"); }
}
"#,
    )
    .unwrap();
    let mut compile = Command::new("rustup");
    compile
        .args(["run", "1.97.1", "rustc", "--edition=2021"])
        .arg(&source)
        .arg("-o")
        .arg(&executable);
    let compiled =
        memcordon_testkit::run_with_deadline(&mut compile, Duration::from_secs(20)).unwrap();
    assert!(
        compiled.status.success(),
        "native fixture compilation failed: {:?}",
        compiled.stderr
    );

    let mut input = ambient();
    let program_data = directory.path().join("selected installer profile");
    input.insert("ProgramData".into(), program_data.as_os_str().to_owned());
    input.insert("GITHUB_TOKEN".into(), "not admitted".into());
    let discovery = windows_discovery_environment(&input).unwrap();
    let literal = "literal $() ; & argument";
    let output = bootstrap::capture(executable.to_str().unwrap(), &[literal], &discovery).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert_eq!(
        output.lines().collect::<Vec<_>>(),
        [program_data.to_str().unwrap(), "absent", literal]
    );

    let compilation = closed_environment_with_names(&input, EnvironmentNames::Windows).unwrap();
    let output =
        bootstrap::capture(executable.to_str().unwrap(), &[literal], &compilation).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert_eq!(
        output.lines().collect::<Vec<_>>(),
        ["missing", "absent", literal]
    );
}
