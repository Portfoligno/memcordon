//! Closed fixture linker layout and actual argument construction, without shell text.
use super::{LinkerMode, Toolchain};
use std::{
    path::{Component, Path},
    process::Command,
};

pub fn linker_argument(input: &Toolchain) -> Result<&'static str, String> {
    let (target, argument) = match (input.linker_mode, input.target.as_str()) {
        (LinkerMode::BundledLldLink, "x86_64-pc-windows-msvc") => (
            "x86_64-pc-windows-msvc",
            "linker=./toolchain/lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe",
        ),
        (LinkerMode::BundledLldLink, "aarch64-pc-windows-msvc") => (
            "aarch64-pc-windows-msvc",
            "linker=./toolchain/lib/rustlib/aarch64-pc-windows-msvc/bin/rust-lld.exe",
        ),
        _ => return Err("fixture linker target is not a supported native MSVC target".into()),
    };
    let root = &input.input_root;
    if !root.is_absolute()
        || root.file_name() != Some(std::ffi::OsStr::new("locked-inputs"))
        || root
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || input.rustc != root.join("toolchain").join("bin").join("rustc.exe")
        || input.native_linker
            != root
                .join("toolchain")
                .join("lib")
                .join("rustlib")
                .join(target)
                .join("bin")
                .join("rust-lld.exe")
        || input.native_library_directories
            != [
                root.join("msvc-lib"),
                root.join("sdk-ucrt"),
                root.join("sdk-um"),
            ]
    {
        return Err("fixture linker mode does not match the exact qualified input layout".into());
    }
    Ok(argument)
}

pub fn compile_command(
    input: &Toolchain,
    source: &Path,
    output: &Path,
    flags: &[&str],
) -> Result<Command, String> {
    input.validate_selected_images()?;
    if !source.is_absolute() || !output.is_absolute() {
        return Err("native compiler source/output must remain absolute".into());
    }
    let mut command = Command::new(&input.rustc);
    command
        .current_dir(&input.input_root)
        .arg(source)
        .args(flags)
        .arg("--edition=2021")
        .arg("--target")
        .arg(&input.target)
        .args([
            "-C",
            linker_argument(input)?,
            "-C",
            "linker-flavor=lld-link",
        ])
        .arg("-o")
        .arg(output)
        .args([
            "-L",
            "native=./msvc-lib",
            "-L",
            "native=./sdk-ucrt",
            "-L",
            "native=./sdk-um",
        ]);
    Ok(command)
}
