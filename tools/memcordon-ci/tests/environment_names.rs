use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use memcordon_ci::build_context::environment::{
    EnvironmentNames, closed_environment, closed_environment_with_names,
};

fn ambient(path_name: &str) -> BTreeMap<OsString, OsString> {
    BTreeMap::from([(
        path_name.into(),
        std::env::join_paths([std::env::temp_dir()]).unwrap(),
    )])
}

#[test]
fn windows_names_produce_one_canonical_environment() {
    let mut mixed = ambient("Path");
    let mut canonical = ambient("PATH");
    for (input, output) in [
        ("userprofile", "USERPROFILE"),
        ("systemroot", "SystemRoot"),
        ("ComSpec", "COMSPEC"),
        ("pathext", "PATHEXT"),
        ("programfiles", "ProgramFiles"),
        ("PROGRAMFILES(X86)", "ProgramFiles(x86)"),
        ("programw6432", "ProgramW6432"),
        ("vctoolsinstalldir", "VCToolsInstallDir"),
        ("windowssdkdir", "WindowsSdkDir"),
        ("Include", "INCLUDE"),
        ("Lib", "LIB"),
        ("LibPath", "LIBPATH"),
    ] {
        let value = OsString::from("preserved value");
        mixed.insert(input.into(), value.clone());
        canonical.insert(output.into(), value);
    }
    let closed = closed_environment_with_names(&mixed, EnvironmentNames::Windows).unwrap();
    assert_eq!(
        closed,
        closed_environment_with_names(&canonical, EnvironmentNames::Windows).unwrap()
    );
    for key in canonical.keys() {
        assert_eq!(closed.get(key), canonical.get(key));
    }
    assert!(!closed.contains_key(OsStr::new("SYSTEMROOT")));
}

#[test]
fn windows_case_aliases_cannot_hide_compiler_overrides() {
    for name in [
        "Rustc",
        "RustDoc",
        "rustc_wrapper",
        "Rustc_Workspace_Wrapper",
        "rustflags",
        "Cargo_Home",
        "cargo_build_rustc",
        "Cargo_Target_X86_64_PC_WINDOWS_MSVC_Linker",
        "Cargo_Profile_Release_Lto",
        "Cargo_Encoded_Rustflags",
        "Cargo_Source_Crates_Io_Replace_With",
        "Cargo_Registries_Crates_Io_Index",
        "cflags",
        "cc",
    ] {
        let mut input = ambient("Path");
        input.insert(name.into(), "override".into());
        let error = closed_environment_with_names(&input, EnvironmentNames::Windows).unwrap_err();
        assert!(
            error.to_string().contains("rejects ambient override"),
            "{name}: {error}"
        );
    }
}

#[test]
fn windows_case_aliases_preserve_credential_filtering() {
    let mut input = ambient("Path");
    input.insert("Cargo_Registries_Crates_Io_Token".into(), "secret".into());
    input.insert("Github_Token".into(), "secret".into());
    let closed = closed_environment_with_names(&input, EnvironmentNames::Windows).unwrap();
    assert!(!closed.values().any(|value| value == "secret"));
}

#[test]
fn windows_conflicting_aliases_fail_and_equal_aliases_collapse() {
    let mut input = ambient("Path");
    let path = input[OsStr::new("Path")].clone();
    input.insert("PATH".into(), path.clone());
    assert_eq!(
        closed_environment_with_names(&input, EnvironmentNames::Windows).unwrap(),
        closed_environment_with_names(&ambient("Path"), EnvironmentNames::Windows).unwrap()
    );
    input.insert("PATH".into(), "conflicting path".into());
    let error = closed_environment_with_names(&input, EnvironmentNames::Windows).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("conflicting environment aliases")
    );
    let mut input = ambient("Path");
    input.insert("SystemRoot".into(), "first root".into());
    input.insert("SYSTEMROOT".into(), "second root".into());
    assert!(closed_environment_with_names(&input, EnvironmentNames::Windows).is_err());
}

#[test]
fn case_sensitive_names_keep_unix_policy() {
    assert!(
        closed_environment_with_names(&ambient("Path"), EnvironmentNames::CaseSensitive).is_err()
    );
    let mut input = ambient("PATH");
    input.insert("Path".into(), "unselected path".into());
    input.insert("rustflags".into(), "unselected flags".into());
    let closed = closed_environment_with_names(&input, EnvironmentNames::CaseSensitive).unwrap();
    assert_eq!(
        closed.get(OsStr::new("PATH")),
        input.get(OsStr::new("PATH"))
    );
    assert!(!closed.contains_key(OsStr::new("Path")));
    assert!(!closed.contains_key(OsStr::new("rustflags")));
}

#[test]
fn mixed_case_windows_path_still_requires_absolute_components() {
    let mut input = ambient("Path");
    input.insert("Path".into(), "relative-directory".into());
    let error = closed_environment_with_names(&input, EnvironmentNames::Windows).unwrap_err();
    assert!(error.to_string().contains("absolute, nonempty components"));
}

#[test]
fn native_name_policy_matches_the_platform() {
    let mixed = ambient("Path");
    assert_eq!(closed_environment(&mixed).is_ok(), cfg!(windows));
}
