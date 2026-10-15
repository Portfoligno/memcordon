#![cfg(windows)]

use memcordon_ci::{command::CommandSpec, windows_cache_identity};
use std::{
    path::Path,
    time::{Duration, Instant},
};

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
