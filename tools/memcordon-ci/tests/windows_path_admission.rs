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

    fn installation(&self, host: &str, target: &str) -> PathBuf {
        let installation = self.linker.parent().unwrap().join("Visual Studio");
        let defaults = installation.join("VC/Auxiliary/Build");
        fs::create_dir_all(&defaults).unwrap();
        fs::write(
            defaults.join("Microsoft.VCToolsVersion.default.txt"),
            b"14.40.12345\n",
        )
        .unwrap();
        let vc = installation.join("VC/Tools/MSVC/14.40.12345");
        fs::create_dir_all(vc.join("include")).unwrap();
        fs::create_dir_all(vc.join("lib").join(target)).unwrap();
        for name in ["link.exe", "cl.exe", "lib.exe"] {
            tool(&vc.join("bin").join(host).join(target).join(name));
        }
        let sdk = Path::new(self.env.get(OsStr::new("WindowsSdkDir")).unwrap());
        for category in ["ucrt", "um", "shared"] {
            fs::create_dir_all(sdk.join("Include/10.0.26100.0").join(category)).unwrap();
        }
        for (category, name) in [("ucrt", "ucrt.lib"), ("um", "kernel32.lib")] {
            tool(
                &sdk.join("Lib/10.0.26100.0")
                    .join(category)
                    .join(target)
                    .join(name),
            );
        }
        installation
    }
}

#[test]
fn fresh_workflow_step_and_bootstrap_selection_enroll_the_same_compiler_and_selector() {
    for (target, host, arch) in [
        ("x64", "Hostx64", Architecture::X64),
        ("arm64", "Hostarm64", Architecture::Arm64),
    ] {
        let fixture = Fixture::new(target);
        let installation = fixture.installation(host, target);
        let program_files = fixture.linker.parent().unwrap().join("Program Files");
        let query = program_files.join("Microsoft Visual Studio/Installer/vswhere.exe");
        tool(&query);
        let mut fresh = fixture.env.clone();
        fresh.insert("ProgramFiles(x86)".into(), program_files.into_os_string());
        assert!(
            environment::msvc::selected_installation(&fresh)
                .unwrap()
                .is_none()
        );
        let discovery = BTreeMap::from([("ProgramData".into(), "installer-state".into())]);
        let mut bootstrap = fresh.clone();
        let bootstrap_selection = environment::windows_compiler::configure(
            &mut bootstrap,
            &discovery,
            arch,
            |selected, arguments, actual_discovery| {
                assert_eq!(
                    selected.canonicalize().unwrap(),
                    query.canonicalize().unwrap()
                );
                assert_eq!(arguments, arch.discovery_arguments());
                assert_eq!(actual_discovery, &discovery);
                Ok(installation.to_str().unwrap().as_bytes().to_vec())
            },
        )
        .unwrap();
        let prepared_selection = environment::windows_compiler::configure(
            &mut bootstrap,
            &discovery,
            arch,
            |_, _, _| panic!("bootstrap child already has the selected installation"),
        )
        .unwrap();
        let prepared_environment = bootstrap.clone();
        let audited_selection =
            environment::windows_compiler::configure(&mut fresh, &discovery, arch, |_, _, _| {
                Ok(installation.to_str().unwrap().as_bytes().to_vec())
            })
            .unwrap();
        assert_eq!(fresh, prepared_environment);
        assert_eq!(
            bootstrap_selection.input_roots,
            prepared_selection.input_roots
        );
        assert_eq!(
            audited_selection.input_roots,
            prepared_selection.input_roots
        );
        let selector = prepared_selection
            .input_roots
            .iter()
            .find(|path| path.canonicalize().unwrap() == query.canonicalize().unwrap())
            .expect("selector must be enrolled even when prepare did not execute it");
        let snapshot = BuildInputSnapshot::capture(selector).unwrap();
        fs::write(&query, b"changed discovery executable\n").unwrap();
        assert!(snapshot.audit().is_err(), "selector drift must be measured");
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
