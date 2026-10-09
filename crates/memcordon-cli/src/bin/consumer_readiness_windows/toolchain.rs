use super::{Descriptor, Transcript};
use std::fs;
use std::io;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn observed_output(
    command: &mut Command,
    root: &Path,
    role: &str,
    challenge: &[u8],
) -> io::Result<Output> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    };
    let image = fs::OpenOptions::new()
        .read(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(command.get_program())?;
    let metadata = image.metadata()?;
    if !metadata.is_file()
        || metadata.len() > 512 * 1024 * 1024
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    {
        return Err(io::Error::other(
            "owned toolchain image is not bounded regular code",
        ));
    }
    let mut code = Vec::new();
    (&image)
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut code)?;
    if code.len() > 512 * 1024 * 1024 {
        return Err(io::Error::other("owned toolchain code exceeds bound"));
    }
    let image_sha256 = String::from(memcordon_core::DiagnosticSha256::from_bytes(
        Sha256::digest(&code).into(),
    ));
    let parent = super::native::current_identity()?;
    let program: Vec<_> = command.get_program().encode_wide().collect();
    let arguments: Vec<Vec<u16>> = command
        .get_args()
        .map(|argument| argument.encode_wide().collect())
        .collect();
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let held = match super::native::retain_child_handle(&child) {
        Ok(held) => held,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    if let Err(error) = super::native::verify_child_image(&child, &image) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let identity = match super::native::child_identity(&child) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let (parent_pid, live_before_wait) = match super::native::child_parent_and_liveness(&child) {
        Ok(observed) => observed,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    if parent_pid != parent.process_id || parent.creation_time_100ns > identity.creation_time_100ns
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other(
            "owned child native ancestry differs from creator root",
        ));
    }
    let created = serde_json::json!({"format":"memcordon.windows-fixture-owned-child-created","revision":1,
        "role":role,"challenge":challenge,"parent":parent,"child":identity,
        "program_utf16":program,"argv_utf16":arguments,"image_sha256":image_sha256,
        "held_from_process_creation":true,"held_live_before_wait":live_before_wait,"native_parent_edge_observed":true});
    let created_bytes = match serde_json::to_vec(&created) {
        Ok(bytes) => bytes,
        Err(original) => {
            let cleanup = super::native::retire_failed_child(&held);
            if cleanup.is_ok() {
                let _ = child.wait();
            }
            return Err(io::Error::other(match cleanup {
                Ok(()) => original.to_string(),
                Err(cleanup) => format!(
                    "child creation receipt serialization failed: {original}; native retirement unresolved: {cleanup}"
                ),
            }));
        }
    };
    if let Err(error) = fs::write(
        root.join(format!("native-child-{role}.created.json")),
        created_bytes,
    ) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(original) => {
            return match super::native::retire_failed_child(&held) {
                Ok(()) => Err(original),
                Err(cleanup) => Err(io::Error::other(format!(
                    "owned child output wait failed: {original}; native retirement unresolved: {cleanup}"
                ))),
            };
        }
    };
    let retired = serde_json::json!({"format":"memcordon.windows-fixture-owned-child-retired","revision":1,
        "role":role,"challenge":challenge,"parent":parent,"child":identity,
        "image_sha256":image_sha256,"held_from_process_creation":true,
        "held_live_before_wait":live_before_wait,"native_parent_edge_observed":true,
        "native_wait_completed":true,"native_status":output.status.code()});
    fs::write(
        root.join(format!("native-child-{role}.retired.json")),
        serde_json::to_vec(&retired).map_err(io::Error::other)?,
    )?;
    Ok(output)
}

fn checked(command: &mut Command, root: &Path, role: &str, challenge: &[u8]) -> io::Result<()> {
    let output = observed_output(command, root, role, challenge)?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "owned toolchain command failed with native status {:?}, stderr bytes {:?}",
            output.status.code(),
            output.stderr
        )));
    }
    if !output.stdout.is_empty() {
        return Err(io::Error::other("unexpected toolchain stdout"));
    }
    Ok(())
}

fn compile(
    inputs: &super::descriptor::Toolchain,
    source: &Path,
    output: &Path,
    flags: &[&str],
    challenge: &[u8],
) -> io::Result<()> {
    let mut linker = std::ffi::OsString::from("linker=");
    linker.push(&inputs.native_linker);
    let mut command = Command::new(&inputs.rustc);
    command
        .arg(source)
        .args(flags)
        .arg("--edition=2021")
        .arg("--target")
        .arg(&inputs.target)
        .arg("-C")
        .arg(linker)
        .arg("-o")
        .arg(output);
    for directory in &inputs.native_library_directories {
        let mut argument = std::ffi::OsString::from("native=");
        argument.push(directory);
        command.arg("-L").arg(argument);
    }
    checked(
        &mut command,
        output
            .parent()
            .ok_or_else(|| io::Error::other("owned compiler output parent missing"))?,
        output
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::other("owned compiler output role invalid"))?,
        challenge,
    )
}

pub(super) fn execute(descriptor: &Descriptor, transcript: &mut Transcript) -> io::Result<()> {
    let start = descriptor
        .start_gate
        .as_ref()
        .ok_or_else(|| io::Error::other("owned toolchain execution lacks native observer gate"))?;
    transcript.event(
        "toolchain-ready-for-native-observer",
        None,
        &descriptor.challenge,
    )?;
    super::native::wait_controller_gate(
        std::ffi::OsStr::new(&format!("{start}-toolchain-observer")),
        || Ok(()),
    )?;
    let inputs = descriptor
        .toolchain
        .as_ref()
        .ok_or_else(|| io::Error::other("toolchain inputs missing"))?;
    let root = descriptor.output_root.join("compiled");
    fs::create_dir(&root)?;
    for (input, name) in [
        (&inputs.library_source, "library.rs"),
        (&inputs.test_source, "tests.rs"),
        (&inputs.child_source, "child.rs"),
        (&inputs.dll_source, "dll.rs"),
        (&inputs.loader_source, "loader.rs"),
    ] {
        fs::copy(input, root.join(name))?;
    }
    let library = root.join("readiness.rlib");
    compile(
        inputs,
        &root.join("library.rs"),
        &library,
        &["--crate-type=rlib"],
        &descriptor.challenge,
    )?;
    let child = root.join("child.exe");
    compile(
        inputs,
        &root.join("child.rs"),
        &child,
        &[],
        &descriptor.challenge,
    )?;
    let tests = root.join("tests.exe");
    compile(
        inputs,
        &root.join("tests.rs"),
        &tests,
        &["--test"],
        &descriptor.challenge,
    )?;
    let dll = root.join("readiness.dll");
    compile(
        inputs,
        &root.join("dll.rs"),
        &dll,
        &["--crate-type=cdylib"],
        &descriptor.challenge,
    )?;
    let loader = root.join("loader.exe");
    compile(
        inputs,
        &root.join("loader.rs"),
        &loader,
        &[],
        &descriptor.challenge,
    )?;
    transcript.event("toolchain-compiled", None, &descriptor.challenge)?;
    let result = observed_output(
        Command::new(&tests).arg("--test-threads=1"),
        &root,
        "run-tests",
        &descriptor.challenge,
    )?;
    if !result.status.success() {
        return Err(io::Error::other("owned compiled test driver failed"));
    }
    // libtest output is independently retained, never used as a semantic parser.
    fs::write(root.join("test-stdout.bin"), result.stdout)?;
    fs::write(root.join("test-stderr.bin"), result.stderr)?;
    let challenge = root.join("challenge-input.bin");
    fs::write(&challenge, &descriptor.challenge)?;
    let product = root.join("child-output.bin");
    checked(
        Command::new(&child).arg(&challenge).arg(&product),
        &root,
        "run-child",
        &descriptor.challenge,
    )?;
    if fs::read(&product)? != descriptor.challenge {
        return Err(io::Error::other("compiled child bytes differ"));
    }
    checked(
        Command::new(&loader).arg(&dll).arg(&root),
        &root,
        "run-loader",
        &descriptor.challenge,
    )?;
    if fs::read(root.join("dll-output.bin"))? != (0..=255).collect::<Vec<u8>>()
        || !fs::read(root.join("dll-empty.bin"))?.is_empty()
    {
        return Err(io::Error::other("loaded DLL products differ"));
    }
    transcript.event(
        "toolchain-test-child-dll-complete",
        None,
        &descriptor.challenge,
    )
}
