use memcordon_ci::build_context::{environment, installed_toolchains_command};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;

#[test]
fn installed_query_scopes_the_pinned_selector_without_changing_the_caller_environment() {
    let temporary = tempfile::tempdir().unwrap();
    let cwd = temporary.path().canonicalize().unwrap();
    let env = BTreeMap::from([(
        OsString::from("PATH"),
        std::env::join_paths([&cwd]).unwrap(),
    )]);
    let original = env.clone();
    let command = installed_toolchains_command(Path::new("rustup"), "1.97.1", &env, &cwd).unwrap();
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [OsStr::new("toolchain"), OsStr::new("list")]
    );
    let child: BTreeMap<_, _> = command.get_envs().collect();
    assert_eq!(
        child.get(OsStr::new("RUSTUP_TOOLCHAIN")),
        Some(&Some(OsStr::new("1.97.1")))
    );
    assert_eq!(
        child.get(OsStr::new("RUSTUP_AUTO_INSTALL")),
        Some(&Some(OsStr::new("0")))
    );
    assert_eq!(env, original);
    assert!(!env.contains_key(OsStr::new("RUSTUP_TOOLCHAIN")));
}

#[test]
fn ambient_toolchain_override_is_still_rejected_before_identity_planning() {
    for value in ["hostile-toolchain", "1.97.1", ""] {
        let env = BTreeMap::from([
            (
                OsString::from("PATH"),
                std::env::join_paths([std::env::temp_dir()]).unwrap(),
            ),
            (OsString::from("RUSTUP_TOOLCHAIN"), OsString::from(value)),
        ]);
        assert!(
            environment::closed_environment(&env).is_err(),
            "ambient override {value:?} must remain rejected"
        );
    }
}

#[test]
fn identity_query_child_receives_literal_argv_pinned_selector_and_repository_cwd() {
    use std::fs;
    use std::process::Command;
    use std::time::Duration;
    let temporary = tempfile::tempdir().unwrap();
    let cwd = temporary.path().join("repository with spaces");
    fs::create_dir(&cwd).unwrap();
    fs::write(cwd.join("rust-toolchain.toml"), "[toolchain]\nchannel = \"uninstalled-override\"\ncomponents = [\"unavailable-component\"]\n").unwrap();
    let source = temporary.path().join("identity_probe.rs");
    let executable = temporary.path().join("identity_probe.exe");
    fs::write(
        &source,
        r#"fn main() {
    assert_eq!(std::env::args().skip(1).collect::<Vec<_>>(), ["toolchain", "list"]);
    assert_eq!(std::env::var("RUSTUP_TOOLCHAIN").unwrap(), "1.97.1");
    assert!(std::env::current_dir().unwrap().join("rust-toolchain.toml").is_file());
    assert_eq!(std::env::var("RUSTUP_AUTO_INSTALL").unwrap(), "0");
    println!("1.97.1-fixture-host (active)");
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
    let built =
        memcordon_testkit::run_with_deadline(&mut compile, Duration::from_secs(20)).unwrap();
    assert!(built.status.success(), "{:?}", built.stderr);
    let env = BTreeMap::from([(
        OsString::from("PATH"),
        std::env::join_paths([temporary.path()]).unwrap(),
    )]);
    let mut command = installed_toolchains_command(&executable, "1.97.1", &env, &cwd).unwrap();
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(5),
        8192,
    )
    .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(output.stdout, b"1.97.1-fixture-host (active)\n");
    assert!(output.stderr.is_empty());
}
