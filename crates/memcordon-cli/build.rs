use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[path = "build_support/source_identity.rs"]
mod source_identity;

fn packaged_commit(manifest: &Path) -> Option<String> {
    let bytes = fs::read(manifest.join(".cargo_vcs_info.json")).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("git")?
        .get("sha1")?
        .as_str()
        .filter(|commit| valid_commit(commit))
        .map(str::to_owned)
}

fn git_directory(manifest: &Path) -> Option<PathBuf> {
    for ancestor in manifest.ancestors() {
        let candidate = ancestor.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if candidate.is_file() {
            let value = fs::read_to_string(&candidate).ok()?;
            let relative = value.trim().strip_prefix("gitdir: ")?;
            return Some(ancestor.join(relative));
        }
    }
    None
}

fn workspace_commit(manifest: &Path) -> Option<String> {
    let git = git_directory(manifest)?;
    let head = fs::read_to_string(git.join("HEAD")).ok()?;
    let head = head.trim();
    if valid_commit(head) {
        return Some(head.to_owned());
    }
    let reference = head.strip_prefix("ref: ")?;
    if let Ok(value) = fs::read_to_string(git.join(reference)) {
        let commit = value.trim();
        if valid_commit(commit) {
            return Some(commit.to_owned());
        }
    }
    let packed = fs::read_to_string(git.join("packed-refs")).ok()?;
    packed.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let commit = fields.next()?;
        let name = fields.next()?;
        (name == reference && valid_commit(commit)).then(|| commit.to_owned())
    })
}

fn valid_commit(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn watch_git_identity(manifest: &Path, output_root: Option<&Path>) {
    let Some(git) = git_directory(manifest) else {
        return;
    };
    let head_path = git.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());
    if let Ok(head) = fs::read_to_string(&head_path) {
        if let Some(reference) = head.trim().strip_prefix("ref: ") {
            println!(
                "cargo:rerun-if-changed={}",
                source_identity::watch_path(&git.join(reference), output_root).display()
            );
            println!(
                "cargo:rerun-if-changed={}",
                source_identity::watch_path(&git.join("packed-refs"), output_root).display()
            );
        }
    }
}

fn main() {
    static_vcruntime::metabuild();
    #[cfg(feature = "test-fixtures")]
    build_gate_call_trace();
    println!("cargo::rustc-check-cfg=cfg(memcordon_static_vcruntime)");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo::rustc-cfg=memcordon_static_vcruntime");
    }
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output_directory = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let output = output_directory.join("source_commit.rs");
    let commit = packaged_commit(&manifest)
        .or_else(|| workspace_commit(&manifest))
        .unwrap_or_else(|| "unknown".to_owned());
    let mut file = fs::File::create(output).unwrap();
    writeln!(file, "pub const SOURCE_COMMIT: &str = {commit:?};").unwrap();
    let output_root = source_identity::output_root(&output_directory);
    println!(
        "cargo:rerun-if-changed={}",
        source_identity::watch_path(
            &manifest.join(".cargo_vcs_info.json"),
            output_root.as_deref()
        )
        .display()
    );
    println!("cargo:rerun-if-changed=build_support/source_identity.rs");
    watch_git_identity(&manifest, output_root.as_deref());
}

#[cfg(feature = "test-fixtures")]
fn build_gate_call_trace() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    assert_eq!(
        std::env::var("CARGO_CFG_TARGET_ENV").as_deref(),
        Ok("msvc"),
        "fixture call tracing requires the supported MSVC target"
    );
    let vendor = Path::new("vendor/detours/src");
    let mut detours = cc::Build::new();
    detours
        .cpp(true)
        .static_crt(true)
        .warnings(false)
        .include(vendor)
        .define("WIN32_LEAN_AND_MEAN", None)
        .define("_WIN32_WINNT", "0x0A00");
    for name in [
        "detours.cpp",
        "modules.cpp",
        "disasm.cpp",
        "image.cpp",
        "creatwth.cpp",
        "disolx86.cpp",
        "disolx64.cpp",
        "disolia64.cpp",
        "disolarm.cpp",
        "disolarm64.cpp",
    ] {
        let path = vendor.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        detours.file(path);
    }
    for name in ["detours.h", "detver.h", "uimports.cpp"] {
        println!("cargo:rerun-if-changed={}", vendor.join(name).display());
    }
    detours.compile("memcordon_fixture_detours");
    println!("cargo:rerun-if-changed=native/gate_call_trace.cpp");
    println!("cargo:rerun-if-changed=native/gate_call_trace.h");
    println!("cargo:rerun-if-changed=native/winsock_call_trace.cpp");
    println!("cargo:rerun-if-changed=native/winsock_call_trace.h");
    println!("cargo:rerun-if-changed=native/native_file_request_trace.h");
    println!("cargo:rerun-if-changed=native/native_file_request_trace.inc");
    cc::Build::new()
        .cpp(true)
        .static_crt(true)
        .std("c++17")
        .flag("/guard:cf")
        .include(vendor)
        .define("_WIN32_WINNT", "0x0A00")
        .file("native/gate_call_trace.cpp")
        .file("native/winsock_call_trace.cpp")
        .compile("memcordon_fixture_gate_call_trace");
    println!("cargo:rustc-link-arg-bin=memcordon-test-fixture=/guard:cf");
    println!("cargo:rustc-link-arg-bin=memcordon-test-fixture=/DYNAMICBASE");
    println!("cargo:rustc-link-lib=kernel32");
    println!("cargo:rustc-link-lib=ntdll");
}
