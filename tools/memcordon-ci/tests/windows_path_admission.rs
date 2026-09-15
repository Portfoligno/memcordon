use environment::msvc::Architecture;
use memcordon_ci::build_context::{BuildInputSnapshot, environment};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

fn tool(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, b"selected native tool\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    env: BTreeMap<OsString, OsString>,
    linker: PathBuf,
    git: PathBuf,
    llvm: PathBuf,
    rustup: PathBuf,
    sdk_bin: PathBuf,
    ambient: PathBuf,
    system: PathBuf,
}

impl Fixture {
    fn new(arch: &str) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let git = root.join("Git installation");
        let llvm = root.join("LLVM installation");
        let rustup = root.join("rustup bin").join("rustup.exe");
        let linker = root.join("MSVC bin").join("link.exe");
        let sdk = root.join("Windows SDK");
        let sdk_bin = sdk.join("bin").join("10.0.26100.0").join(arch);
        let ambient = root.join("unselected applications");
        let windows = root.join("Windows");
        let system = windows.join("System32");
        for executable in [
            rustup.clone(),
            linker.clone(),
            linker.with_file_name("cl.exe"),
            linker.with_file_name("lib.exe"),
            git.join("cmd/git.exe"),
            llvm.join("bin/clang.exe"),
            sdk_bin.join("rc.exe"),
            sdk_bin.join("mt.exe"),
            system.join("ping.exe"),
            system.join("cmd.exe"),
            ambient.join("unselected.exe"),
        ] {
            tool(&executable);
        }
        let git_arch = if arch == "arm64" {
            "clangarm64"
        } else {
            "mingw64"
        };
        fs::create_dir_all(git.join(git_arch).join("libexec/git-core")).unwrap();
        fs::create_dir_all(llvm.join("lib/clang")).unwrap();
        let env = BTreeMap::from([
            (
                "PATH".into(),
                std::env::join_paths([
                    ambient.clone(),
                    rustup.parent().unwrap().to_path_buf(),
                    git.join("cmd"),
                    llvm.join("bin"),
                ])
                .unwrap(),
            ),
            ("WindowsSdkDir".into(), sdk.into_os_string()),
            ("WindowsSDKVersion".into(), "10.0.26100.0".into()),
            ("SystemRoot".into(), windows.into_os_string()),
        ]);
        Self {
            _temporary: temporary,
            env,
            linker,
            git,
            llvm,
            rustup,
            sdk_bin,
            ambient,
            system,
        }
    }
}

#[test]
fn positive_paths_are_complete_repeatable_and_exclude_unselected_directories() {
    for (name, arch) in [("x64", Architecture::X64), ("arm64", Architecture::Arm64)] {
        let mut fixture = Fixture::new(name);
        let selection =
            environment::windows_compiler::admit(&mut fixture.env, &fixture.linker, arch).unwrap();
        let paths: Vec<_> =
            std::env::split_paths(fixture.env.get(OsStr::new("PATH")).unwrap()).collect();
        assert_eq!(
            paths,
            [
                fixture.linker.parent().unwrap().to_path_buf(),
                fixture.rustup.parent().unwrap().to_path_buf(),
                fixture.git.join("cmd"),
                fixture.llvm.join("bin"),
                fixture.sdk_bin.clone(),
            ]
            .map(|path| environment::command_path(&path).unwrap())
        );
        assert!(!paths.contains(&environment::command_path(&fixture.ambient).unwrap()));
        assert_eq!(
            selection.rustup,
            environment::paths::command_program(&fixture.rustup).unwrap()
        );
        let root_identities: Vec<_> = selection
            .input_roots
            .iter()
            .map(|path| path.canonicalize().unwrap())
            .collect();
        for required in [
            &fixture.git,
            &fixture.llvm,
            &fixture.system.join("ping.exe"),
            &fixture.system.join("cmd.exe"),
        ] {
            assert!(
                root_identities.contains(&required.canonicalize().unwrap()),
                "missing measured root {required:?}: {:?}",
                selection.input_roots
            );
        }
        let frozen = fixture.env.clone();
        let repeated =
            environment::windows_compiler::admit(&mut fixture.env, &fixture.linker, arch).unwrap();
        assert_eq!(fixture.env, frozen);
        assert_eq!(repeated.rustup, selection.rustup);
        assert_eq!(repeated.input_roots, selection.input_roots);
    }
}

#[test]
fn missing_selected_sdk_helper_fails_without_ambient_fallback_or_partial_mutation() {
    let mut fixture = Fixture::new("arm64");
    fs::remove_file(fixture.sdk_bin.join("rc.exe")).unwrap();
    tool(&fixture.ambient.join("rc.exe"));
    let original = fixture.env.clone();
    assert!(
        environment::windows_compiler::admit(
            &mut fixture.env,
            &fixture.linker,
            Architecture::Arm64
        )
        .is_err()
    );
    assert_eq!(fixture.env, original);
}

#[test]
fn missing_enrolled_executables_fail_without_freezing_a_partial_recipe() {
    for name in ["rustup", "git", "clang", "ping"] {
        let mut fixture = Fixture::new("arm64");
        let missing = match name {
            "rustup" => fixture.rustup.clone(),
            "git" => fixture.git.join("cmd/git.exe"),
            "clang" => fixture.llvm.join("bin/clang.exe"),
            "ping" => fixture.system.join("ping.exe"),
            _ => unreachable!(),
        };
        fs::remove_file(missing).unwrap();
        let original = fixture.env.clone();
        assert!(
            environment::windows_compiler::admit(
                &mut fixture.env,
                &fixture.linker,
                Architecture::Arm64,
            )
            .is_err(),
            "missing {name} must reject admission"
        );
        assert_eq!(fixture.env, original);
    }
}

#[test]
fn missing_git_or_llvm_support_roots_fail_before_freezing_paths() {
    for support in ["git", "llvm"] {
        let mut fixture = Fixture::new("x64");
        let path = if support == "git" {
            fixture.git.join("mingw64/libexec/git-core")
        } else {
            fixture.llvm.join("lib/clang")
        };
        fs::remove_dir(path).unwrap();
        let original = fixture.env.clone();
        assert!(
            environment::windows_compiler::admit(
                &mut fixture.env,
                &fixture.linker,
                Architecture::X64
            )
            .is_err()
        );
        assert_eq!(fixture.env, original);
    }
}

#[test]
fn enrolled_support_content_remains_subject_to_full_snapshot_audit() {
    let mut fixture = Fixture::new("x64");
    let library = fixture.llvm.join("lib/clang/resource.lib");
    fs::write(&library, b"original resource\n").unwrap();
    let selection =
        environment::windows_compiler::admit(&mut fixture.env, &fixture.linker, Architecture::X64)
            .unwrap();
    let llvm_identity = fixture.llvm.canonicalize().unwrap();
    let selected_llvm = selection
        .input_roots
        .iter()
        .find(|path| path.canonicalize().unwrap() == llvm_identity)
        .expect("LLVM support root must be enrolled by filesystem identity");
    let snapshot = BuildInputSnapshot::capture(selected_llvm).unwrap();
    snapshot.audit().unwrap();
    fs::write(library, b"changed resource\n").unwrap();
    assert!(snapshot.audit().is_err());
}
