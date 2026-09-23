use memcordon_ci::build_context::environment::msvc::{Architecture, configure};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

struct Installation {
    _temporary: tempfile::TempDir,
    visual_studio: PathBuf,
    sdk: PathBuf,
    decoy: PathBuf,
}

impl Installation {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let visual_studio = temporary.path().join("Visual Studio With Spaces");
        let sdk = temporary.path().join("Windows Kits").join("10");
        let decoy = temporary.path().join("unrelated tools");
        fs::create_dir_all(&decoy).unwrap();
        fs::write(decoy.join("link.exe"), b"not the MSVC linker\n").unwrap();
        let version = visual_studio.join("VC/Auxiliary/Build");
        fs::create_dir_all(&version).unwrap();
        fs::write(
            version.join("Microsoft.VCToolsVersion.default.txt"),
            b"14.40.12345\n",
        )
        .unwrap();
        let vc = visual_studio.join("VC/Tools/MSVC/14.40.12345");
        fs::create_dir_all(vc.join("include")).unwrap();
        for (host, target) in [("Hostx64", "x64"), ("Hostarm64", "arm64")] {
            let bin = vc.join("bin").join(host).join(target);
            fs::create_dir_all(&bin).unwrap();
            for tool in ["link.exe", "cl.exe", "lib.exe"] {
                fs::write(bin.join(tool), b"native tool fixture\n").unwrap();
            }
            fs::create_dir_all(vc.join("lib").join(target)).unwrap();
            for category in ["ucrt", "um"] {
                let library = sdk.join("Lib/10.0.26100.0").join(category).join(target);
                fs::create_dir_all(&library).unwrap();
                fs::write(
                    library.join(if category == "ucrt" {
                        "ucrt.lib"
                    } else {
                        "kernel32.lib"
                    }),
                    b"native library fixture\n",
                )
                .unwrap();
            }
        }
        for category in ["ucrt", "um", "shared"] {
            fs::create_dir_all(sdk.join("Include/10.0.26100.0").join(category)).unwrap();
        }
        Self {
            _temporary: temporary,
            visual_studio,
            sdk,
            decoy,
        }
    }

    fn environment(&self) -> BTreeMap<OsString, OsString> {
        BTreeMap::from([
            ("PATH".into(), std::env::join_paths([&self.decoy]).unwrap()),
            ("WindowsSdkDir".into(), self.sdk.as_os_str().to_owned()),
        ])
    }

    fn binary_directory(&self, host: &str, target: &str) -> PathBuf {
        self.visual_studio
            .join("VC/Tools/MSVC/14.40.12345/bin")
            .join(host)
            .join(target)
    }
}

fn paths(environment: &BTreeMap<OsString, OsString>, name: &str) -> Vec<PathBuf> {
    std::env::split_paths(environment.get(OsStr::new(name)).unwrap()).collect()
}

#[test]
fn selected_msvc_tools_precede_decoys_for_each_native_architecture() {
    let installation = Installation::new();
    for (architecture, host, target) in [
        (Architecture::X64, "Hostx64", "x64"),
        (Architecture::Arm64, "Hostarm64", "arm64"),
    ] {
        let mut environment = installation.environment();
        let selected =
            configure(&mut environment, &installation.visual_studio, architecture).unwrap();
        let bin = installation.binary_directory(host, target);
        assert_eq!(selected, bin.join("link.exe"));
        assert!(selected.is_absolute());
        assert_eq!(paths(&environment, "PATH").first(), Some(&bin));
        assert!(paths(&environment, "PATH").contains(&installation.decoy));
        assert_eq!(environment[OsStr::new("VSCMD_ARG_TGT_ARCH")], target);
        assert!(
            paths(&environment, "LIB")
                .contains(&installation.sdk.join("Lib/10.0.26100.0/um").join(target))
        );
        assert!(
            paths(&environment, "INCLUDE")
                .contains(&installation.sdk.join("Include/10.0.26100.0/shared"))
        );
    }
}

#[test]
fn selecting_the_same_toolchain_is_idempotent() {
    let installation = Installation::new();
    let mut environment = installation.environment();
    let first = configure(
        &mut environment,
        &installation.visual_studio,
        Architecture::X64,
    )
    .unwrap();
    let first_environment = environment.clone();
    assert_eq!(
        configure(
            &mut environment,
            &installation.visual_studio,
            Architecture::X64
        )
        .unwrap(),
        first
    );
    assert_eq!(environment, first_environment);
}

#[test]
fn missing_selected_tool_or_sdk_library_cannot_fall_back_to_path() {
    for missing in [
        Path::new("VC/Tools/MSVC/14.40.12345/bin/Hostx64/x64/link.exe"),
        Path::new("VC/Tools/MSVC/14.40.12345/bin/Hostx64/x64/cl.exe"),
        Path::new("VC/Tools/MSVC/14.40.12345/bin/Hostx64/x64/lib.exe"),
    ] {
        let installation = Installation::new();
        fs::remove_file(installation.visual_studio.join(missing)).unwrap();
        let mut environment = installation.environment();
        assert!(
            configure(
                &mut environment,
                &installation.visual_studio,
                Architecture::X64
            )
            .is_err()
        );
    }
    let installation = Installation::new();
    fs::remove_file(
        installation
            .sdk
            .join("Lib/10.0.26100.0/um/x64/kernel32.lib"),
    )
    .unwrap();
    assert!(
        configure(
            &mut installation.environment(),
            &installation.visual_studio,
            Architecture::X64
        )
        .is_err()
    );
}

#[test]
fn selected_compiler_environment_survives_closure_and_has_required_input_roots() {
    use memcordon_ci::build_context::{environment, native_environment_roots};

    let installation = Installation::new();
    let mut selected = installation.environment();
    configure(
        &mut selected,
        &installation.visual_studio,
        Architecture::Arm64,
    )
    .unwrap();
    let closed = environment::closed_environment_with_names(
        &selected,
        environment::EnvironmentNames::Windows,
    )
    .unwrap();
    for name in [
        "VCINSTALLDIR",
        "VSINSTALLDIR",
        "VCToolsInstallDir",
        "VCToolsVersion",
        "VSCMD_ARG_HOST_ARCH",
        "VSCMD_ARG_TGT_ARCH",
        "WindowsSdkDir",
        "WindowsSDKVersion",
        "PATH",
        "LIB",
        "INCLUDE",
    ] {
        let value = selected
            .get(OsStr::new(name))
            .expect("configured selection is complete");
        assert!(!value.is_empty(), "selector {name} is empty");
        assert_eq!(
            closed.get(OsStr::new(name)),
            Some(value),
            "closure changed selector {name}"
        );
    }
    let roots = native_environment_roots(&closed).unwrap();
    for name in ["INCLUDE", "LIB", "LIBPATH"] {
        if let Some(value) = closed.get(OsStr::new(name)) {
            for required in std::env::split_paths(value) {
                assert!(
                    roots.contains(&required.canonicalize().unwrap()),
                    "missing required selected native root {required:?}"
                );
            }
        }
    }
    for discovery_selector in [
        &installation.visual_studio,
        &installation.visual_studio.join("VC"),
        &installation.visual_studio.join("VC/Tools/MSVC/14.40.12345"),
        &installation.sdk,
    ] {
        assert!(
            !roots.contains(&discovery_selector.canonicalize().unwrap()),
            "broad discovery selector became a recursive root {discovery_selector:?}"
        );
    }
}

#[test]
fn explicit_sdk_version_never_falls_back_to_another_installed_version() {
    let installation = Installation::new();
    let mut environment = installation.environment();
    environment.insert("WindowsSDKVersion".into(), "10.0.99999.0".into());
    let before = environment.clone();
    assert!(
        configure(
            &mut environment,
            &installation.visual_studio,
            Architecture::X64
        )
        .is_err()
    );
    assert_eq!(
        environment, before,
        "failed selection must not partially reconfigure the build"
    );
}

#[test]
fn missing_arm64_tools_cannot_fall_back_to_x64_tools() {
    let installation = Installation::new();
    fs::remove_file(
        installation
            .binary_directory("Hostarm64", "arm64")
            .join("link.exe"),
    )
    .unwrap();
    let mut environment = installation.environment();
    assert!(
        configure(
            &mut environment,
            &installation.visual_studio,
            Architecture::Arm64
        )
        .is_err()
    );
    assert!(
        installation
            .binary_directory("Hostx64", "x64")
            .join("link.exe")
            .is_file()
    );
}
