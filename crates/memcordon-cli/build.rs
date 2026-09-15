mod build_support;

use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    static_vcruntime::metabuild();
    println!("cargo::rustc-check-cfg=cfg(memcordon_static_vcruntime)");
    if build_support::runtime::static_msvc(
        &std::env::var("CARGO_CFG_TARGET_OS").expect("Cargo target OS"),
        &std::env::var("CARGO_CFG_TARGET_ENV").expect("Cargo target environment"),
    ) {
        println!("cargo::rustc-cfg=memcordon_static_vcruntime");
    }
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest"));
    let identity = build_support::load(&manifest).expect("valid build source identity");
    let output =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo output")).join("source_commit.rs");
    let mut file = fs::File::create(output).expect("source identity output");
    writeln!(
        file,
        "pub const SOURCE_COMMIT: &str = {:?};",
        identity.commit
    )
    .expect("write source identity");
    for input in identity.inputs {
        println!("cargo:rerun-if-changed={}", input.display());
    }
}
