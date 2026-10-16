#![cfg(windows)]

use memcordon_ci::{command::CommandSpec, windows_cache_identity};
use std::{
    ffi::{OsStr, OsString},
    path::Path,
    time::{Duration, Instant},
};

#[test]
fn resolver_effective_path_selects_native_tools_before_ambient_decoys() {
    struct NativeDefaults {
        path: OsString,
    }
    impl find_msvc_tools::EnvGetter for NativeDefaults {
        fn get_env(&self, name: &'static str) -> Option<find_msvc_tools::Env> {
            match name {
                "PATH" => Some(find_msvc_tools::Env::Owned(self.path.clone())),
                "INCLUDE" | "LIB" | "VCINSTALLDIR" | "VSTEL_MSBuildProjectFullPath" => None,
                _ => std::env::var_os(name).map(find_msvc_tools::Env::Owned),
            }
        }
    }
    let fixture = tempfile::tempdir().unwrap();
    for name in ["link.exe", "cl.exe", "lib.exe"] {
        std::fs::write(fixture.path().join(name), b"ambient decoy, never executed").unwrap();
    }
    let ambient = std::env::var_os("PATH").unwrap_or_default();
    let selector = NativeDefaults {
        path: std::env::join_paths(
            std::iter::once(fixture.path().to_path_buf()).chain(std::env::split_paths(&ambient)),
        )
        .unwrap(),
    };
    let target = if std::env::consts::ARCH == "aarch64" {
        "aarch64"
    } else {
        "x86_64"
    };
    for name in ["link.exe", "cl.exe", "lib.exe"] {
        let tool = find_msvc_tools::find_tool_with_env(target, name, &selector).unwrap();
        assert!(tool.path().is_absolute());
        assert!(
            !windows_cache_identity::native_tool_path_matches(
                &fixture.path().join(name),
                tool.path()
            )
            .unwrap()
        );
        let effective = find_msvc_tools::Tool::env(&tool)
            .into_iter()
            .find(|(key, _)| key == "PATH")
            .unwrap()
            .1
            .as_os_str();
        let candidate = std::env::split_paths(effective)
            .map(|directory| directory.join(name))
            .find(|path| path.is_file())
            .unwrap();
        assert!(windows_cache_identity::native_tool_path_matches(&candidate, tool.path()).unwrap());
    }
}

#[test]
fn native_tool_identity_accepts_aliases_but_rejects_distinct_or_relative_files() {
    let fixture = tempfile::tempdir().unwrap();
    let selected = fixture.path().join("selected.exe");
    let distinct = fixture.path().join("distinct.exe");
    std::fs::write(
        &selected,
        b"same bytes do not establish native path identity",
    )
    .unwrap();
    std::fs::copy(&selected, &distinct).unwrap();
    assert!(
        windows_cache_identity::native_tool_path_matches(
            &selected.with_file_name("SELECTED.EXE"),
            &selected
        )
        .unwrap()
    );
    assert!(!windows_cache_identity::native_tool_path_matches(&distinct, &selected).unwrap());
    for relative in [
        Path::new("selected.exe"),
        Path::new(r"C:selected.exe"),
        Path::new(r"\selected.exe"),
    ] {
        assert!(windows_cache_identity::native_tool_path_matches(relative, &selected).is_err());
        assert!(windows_cache_identity::native_tool_path_matches(&selected, relative).is_err());
    }
    assert!(windows_cache_identity::native_tool_path_matches(fixture.path(), &selected).is_err());
}

#[test]
fn pinned_resolver_adds_one_empty_tail_when_search_selectors_are_absent() {
    struct NativeDefaults;
    impl find_msvc_tools::EnvGetter for NativeDefaults {
        fn get_env(&self, name: &'static str) -> Option<find_msvc_tools::Env> {
            match name {
                "INCLUDE" | "LIB" | "VCINSTALLDIR" | "VSTEL_MSBuildProjectFullPath" => None,
                _ => std::env::var_os(name).map(find_msvc_tools::Env::Owned),
            }
        }
    }
    let target = if std::env::consts::ARCH == "aarch64" {
        "aarch64"
    } else {
        "x86_64"
    };
    let tool = find_msvc_tools::find_tool_with_env(target, "link.exe", &NativeDefaults).unwrap();
    assert!(tool.path().is_absolute());
    for name in ["INCLUDE", "LIB"] {
        let value = find_msvc_tools::Tool::env(&tool)
            .into_iter()
            .find(|(key, _)| key == name)
            .unwrap()
            .1
            .as_os_str();
        let observed: Vec<_> = std::env::split_paths(value).collect();
        let (tail, directories) = observed.split_last().unwrap();
        assert!(tail.as_os_str().is_empty());
        assert!(!directories.is_empty());
        assert!(directories.iter().all(|path| path.is_absolute()));
        assert_eq!(
            windows_cache_identity::native_search_paths(value, false).unwrap(),
            directories
        );
        assert!(windows_cache_identity::native_search_paths(value, true).is_err());
    }
}

#[test]
fn native_search_paths_preserve_order_and_reject_user_relative_or_empty_entries() {
    let selected = OsStr::new(r"C:\native\include;C:\sdk\include");
    let expected = vec![
        Path::new(r"C:\native\include").to_path_buf(),
        Path::new(r"C:\sdk\include").to_path_buf(),
    ];
    for ambient_present in [false, true] {
        assert_eq!(
            windows_cache_identity::native_search_paths(selected, ambient_present).unwrap(),
            expected
        );
        for invalid in [
            "",
            ";",
            r"relative",
            r"C:relative",
            r"\rooted-without-drive",
            r".",
            r"C:\native\include;relative",
            r";C:\native\include",
            r"C:\native\include;;C:\sdk\include",
            r"C:\native\include;;",
        ] {
            assert!(
                windows_cache_identity::native_search_paths(OsStr::new(invalid), ambient_present)
                    .is_err(),
                "accepted {invalid:?}, ambient_present={ambient_present}"
            );
        }
    }
    let generated_tail = OsStr::new(r"C:\native\include;C:\sdk\include;");
    assert_eq!(
        windows_cache_identity::native_search_paths(generated_tail, false).unwrap(),
        expected
    );
    assert!(windows_cache_identity::native_search_paths(generated_tail, true).is_err());
}

#[test]
fn ordinary_native_rust_link_matches_observed_msvc_selection() {
    let target = memcordon_ci::release::distribution::native_target().unwrap();
    let identity =
        windows_cache_identity::discover_native(target, Instant::now() + Duration::from_secs(30))
            .unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let stable = memcordon_ci::config::toolchains(&root).unwrap().stable;
    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(
        fixture.path().join("probe.rs"),
        "fn main() { println!(\"native selection probe\"); }\n",
    )
    .unwrap();
    let output = CommandSpec::toolchain_program(
        "rustup",
        fixture.path(),
        &stable,
        "rustc",
        Duration::from_secs(120),
    )
    .args(["probe.rs", "--print", "link-args", "--target", target])
    .output_quiet()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = String::from_utf8(output.stdout)
        .unwrap()
        .to_ascii_lowercase();
    let selected = identity["windows-tool-link.exe-path"].to_ascii_lowercase();
    // Compiler diagnostic text is used only by this pinned native regression,
    // never parsed to identify production cache inputs.
    assert!(
        actual.contains(&selected) || actual.contains(&selected.replace('\\', "\\\\")),
        "actual linker differs; selected={selected}, observed={actual}"
    );
    for name in ["cl.exe", "lib.exe", "link.exe"] {
        let actual = find_msvc_tools::find_tool(target, name).unwrap();
        assert_eq!(
            actual.path().to_str().unwrap(),
            identity[&format!("windows-tool-{name}-path")]
        );
    }
    assert!(fixture.path().join("probe.exe").is_file());
    for cpp in [false, true] {
        let source = fixture
            .path()
            .join(if cpp { "probe.cpp" } else { "probe.c" });
        std::fs::write(
            &source,
            "#include <windows.h>\nint native_probe(void) { return sizeof(DWORD); }\n",
        )
        .unwrap();
        let mut build = cc::Build::new();
        build
            .target(target)
            .host(target)
            .cpp(cpp)
            .file(&source)
            .out_dir(fixture.path())
            .opt_level(0)
            .debug(false)
            .cargo_metadata(false);
        let compiler = build.try_get_compiler().unwrap();
        assert_eq!(
            compiler.path().to_str().unwrap(),
            identity["windows-tool-cl.exe-path"]
        );
        let librarian = build.get_archiver();
        assert_eq!(
            librarian.get_program().to_str().unwrap(),
            identity["windows-tool-lib.exe-path"]
        );
        build
            .try_compile(if cpp {
                "native_probe_cpp"
            } else {
                "native_probe_c"
            })
            .unwrap();
    }
}

#[test]
fn wrong_native_architecture_cannot_be_enabled_by_version_strings() {
    let other = if std::env::consts::ARCH == "x86_64" {
        "aarch64-pc-windows-msvc"
    } else {
        "x86_64-pc-windows-msvc"
    };
    assert!(
        windows_cache_identity::discover_native(other, Instant::now() + Duration::from_secs(30))
            .is_err()
    );
}
