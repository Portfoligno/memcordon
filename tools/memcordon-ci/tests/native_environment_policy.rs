use std::path::Path;

#[path = "../src/policy_native_environment.rs"]
mod boundary;

const CONTROL: &str = include_str!("../src/windows_current_control_cases.rs");
const SERVICE: &str = include_str!("../src/windows_current_service_restart.rs");
const PROVIDER: &str = include_str!(
    "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/fixture_environment.rs"
);

fn accepts(path: &str, source: &str, setters: usize, clears: usize) -> bool {
    syn::parse_file(source)
        .is_ok_and(|syntax| boundary::reviewed(Path::new(path), &syntax, setters, clears))
}

#[test]
fn native_fixture_copies_require_exact_inventory_clear_and_setter_provenance() {
    let control = "tools/memcordon-ci/src/windows_current_control_cases.rs";
    let service = "tools/memcordon-ci/src/windows_current_service_restart.rs";
    assert!(boundary::provider_matches(PROVIDER), "provider shape");
    assert!(accepts(control, CONTROL, 4, 4), "control copies");
    assert!(accepts(service, SERVICE, 1, 1), "service copy");
    assert!(accepts(
        control,
        &CONTROL.replace(
            "        command.env(",
            "        /* formatting */ command . env ("
        ),
        4,
        4
    ));
    assert!(!accepts("crates/example/src/lib.rs", CONTROL, 4, 4));
    for (before, after) in [
        ("fixture_environment::entries()?", "arbitrary::entries()?"),
        (
            "let frontend_environment =",
            "let mut frontend_environment =",
        ),
        (
            ".filter(|entry| entry.name.first() != Some(&u16::from(b'=')))",
            ".filter(|entry| entry.name.first() == Some(&u16::from(b'=')))",
        ),
        (
            "std::ffi::OsString::from_wide(&entry.value)",
            "std::ffi::OsString::from_wide(&entry.name)",
        ),
        (
            "    command.env_clear()",
            "    different_command.env_clear()",
        ),
        (
            "command.current_dir(&directory).env_clear()",
            "command.current_dir(&directory)",
        ),
        (
            "mod fixture_environment;",
            "mod fixture_environment { fn entries() {} }",
        ),
        (
            "for entry in &frontend_environment",
            "for entry in &arbitrary_environment",
        ),
        (
            "for entry in &frontend_environment",
            "frontend_environment.push(arbitrary); for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "let frontend_environment = arbitrary; for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "let (frontend_environment, _) = arbitrary; for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "command = std::process::Command::new(arbitrary); for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "let change = |frontend_environment| { for entry in &frontend_environment {} }; for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "{ command = std::process::Command::new(arbitrary); } for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "{ mutate(&mut command); } for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "{ mutate(&mut command); let command = arbitrary; } for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "{ mutate(&mut command); let command = arbitrary; command.env_clear(); } for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "(command, _) = arbitrary; for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "for frontend_environment in arbitrary { } for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "if let Some(frontend_environment) = arbitrary {} for entry in &frontend_environment",
        ),
        (
            "for entry in &frontend_environment",
            "match arbitrary { Some(frontend_environment) => {}, _ => {} } for entry in &frontend_environment",
        ),
    ] {
        assert!(
            CONTROL.contains(before),
            "missing mutation operand: {before}"
        );
        assert!(
            syn::parse_file(&CONTROL.replace(before, after)).is_ok(),
            "invalid mutation: {before}"
        );
        assert!(
            !accepts(control, &CONTROL.replace(before, after), 4, 4),
            "accepted mutation: {before} -> {after}"
        );
    }
    let extra = format!(
        "{CONTROL}\nfn extra(command: &mut std::process::Command) {{ command.env(\"CUSTOM_CI\", \"value\"); }}"
    );
    assert!(
        memcordon_ci::policy::validate_rust_policy_bytes(Path::new(control), extra.as_bytes())
            .is_err()
    );
}

#[test]
fn provider_contract_rejects_ambient_and_arbitrary_keys_or_native_values() {
    assert!(boundary::provider_matches(PROVIDER));
    for (before, after) in [
        ("\"SystemRoot\"", "\"CUSTOM_CI\""),
        ("directory.to_vec()", "std::env::vars().collect()"),
        (
            "GetSystemWindowsDirectoryW(directory.as_mut_ptr(), directory.len() as u32)",
            "arbitrary_directory(directory.as_mut_ptr(), directory.len() as u32)",
        ),
        ("9 => \"AMD64\"", "9 => \"arbitrary\""),
    ] {
        assert!(PROVIDER.contains(before));
        assert!(!boundary::provider_matches(
            &PROVIDER.replace(before, after)
        ));
    }
}
