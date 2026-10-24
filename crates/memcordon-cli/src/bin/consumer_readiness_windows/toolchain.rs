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
    creation: Option<&super::descriptor::Toolchain>,
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
        .open(command.get_program())
        .map_err(|error| {
            super::toolchain_debug::operation_error("original-image-open", None, error)
        })?;
    let metadata = image.metadata().map_err(|error| {
        super::toolchain_debug::operation_error("original-image-metadata", None, error)
    })?;
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
        .read_to_end(&mut code)
        .map_err(|error| {
            super::toolchain_debug::operation_error("original-image-read", None, error)
        })?;
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
    if let Some(inputs) = creation {
        return creation_output(
            command,
            CreationInput {
                root,
                role,
                challenge,
                inputs,
                image: &image,
                image_sha256: &image_sha256,
                parent,
                program: &program,
                arguments: &arguments,
            },
        );
    }
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

struct CreationInput<'a> {
    root: &'a Path,
    role: &'a str,
    challenge: &'a [u8],
    inputs: &'a super::descriptor::Toolchain,
    image: &'a fs::File,
    image_sha256: &'a str,
    parent: memcordon_core::WindowsProcessIdentityV1,
    program: &'a [u16],
    arguments: &'a [Vec<u16>],
}

fn unselected_creation_error(
    created: &super::toolchain_debug::Created,
    inputs: &super::descriptor::Toolchain,
    original_rustc_sha256: &str,
) -> io::Error {
    use std::os::windows::ffi::OsStrExt;
    let path_context = |path: &Path| {
        let total = path.as_os_str().encode_wide().count();
        let prefix: Vec<_> = path
            .as_os_str()
            .encode_wide()
            .take(
                memcordon_core::workload_limits::ENTRYPOINT_PATH_BYTES / std::mem::size_of::<u16>(),
            )
            .collect();
        serde_json::json!({
            "display_prefix":String::from_utf16_lossy(&prefix),
            "utf16_units_total":total,"truncated":prefix.len() < total,
            "utf16_prefix":prefix,
        })
    };
    let context = serde_json::json!({
        "format":"memcordon.windows-unselected-compiler-creation","revision":1,
        "diagnostic_only":true,"child":created.identity,
        "parent_pid":created.parent_pid,"parent_birth":created.parent_birth,
        "held_created_image":{"path":path_context(&created.image),"sha256":created.image_sha256},
        "selected_rustc":{"path":path_context(&inputs.rustc),"original_held_sha256":original_rustc_sha256},
        "selected_linker":{"path":path_context(&inputs.native_linker),"held_sha256":null,
            "digest_observation":"selected linker digest is not retained in this creation callback"},
    });
    match serde_json::to_string(&context) {
        Ok(context) => io::Error::other(format!(
            "unselected real compiler descendant image; context={context}"
        )),
        Err(_) => io::Error::other(
            "unselected real compiler descendant image; diagnostic serialization failed",
        ),
    }
}

fn creation_output(command: &mut Command, input: CreationInput<'_>) -> io::Result<Output> {
    let CreationInput {
        root,
        role,
        challenge,
        inputs,
        image,
        image_sha256,
        parent,
        program,
        arguments,
    } = input;
    use std::io::Read;
    use std::os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    };
    super::toolchain_debug::validate_clock(
        inputs.native_work_cutoff_ticks,
        inputs.native_work_frequency,
    )?;
    let output_root = root
        .parent()
        .ok_or_else(|| io::Error::other("compiler acknowledgment root absent"))?;
    command
        .creation_flags(windows_sys::Win32::System::Threading::DEBUG_PROCESS)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let mut debug_started = false;
    let operation = (|| {
        let capture = |pipe: Box<dyn Read + Send>| {
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            std::thread::Builder::new().spawn(move || {
                let mut bytes = Vec::new();
                let result = pipe
                    .take(16 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .and_then(|_| {
                        if bytes.len() <= 16 * 1024 * 1024 {
                            Ok(bytes)
                        } else {
                            Err(io::Error::other("compiler output exceeds bound"))
                        }
                    });
                let _ = send.send(result);
            })?;
            Ok::<_, io::Error>(receive)
        };
        let stdout =
            capture(Box::new(child.stdout.take().ok_or_else(|| {
                io::Error::other("compiler stdout pipe absent")
            })?))?;
        let stderr =
            capture(Box::new(child.stderr.take().ok_or_else(|| {
                io::Error::other("compiler stderr pipe absent")
            })?))?;
        let held = super::native::retain_child_handle(&child)?;
        let mut original = None;
        debug_started = true;
        super::toolchain_debug::run(
            inputs.native_work_cutoff_ticks,
            inputs.native_work_frequency,
            &parent,
            &child,
            |created| {
                if original.is_none() {
                    super::native::verify_child_image(&child, image).map_err(|error| {
                        super::toolchain_debug::operation_error(
                            "original-child-image-verify",
                            Some(child.id()),
                            error,
                        )
                    })?;
                    let identity = super::native::child_identity(&child)?;
                    let (parent_pid, live) = super::native::child_parent_and_liveness(&child)?;
                    if created.identity != identity
                        || parent_pid != parent.process_id
                        || created.parent_pid != parent.process_id
                        || created.parent_birth != parent.creation_time_100ns
                        || created.image != inputs.rustc
                        || created.image_sha256 != image_sha256
                        || !live
                    {
                        return Err(io::Error::other(
                            "compiler creation event differs from held original child",
                        ));
                    }
                    let receipt = serde_json::json!({"format":"memcordon.windows-fixture-owned-child-created","revision":1,
                        "role":role,"challenge":challenge,"parent":parent,"child":identity,
                        "program_utf16":program,"argv_utf16":arguments,"image_sha256":image_sha256,
                        "held_from_process_creation":true,"held_live_before_wait":live,"native_parent_edge_observed":true});
                    fs::write(
                        root.join(format!("native-child-{role}.created.json")),
                        serde_json::to_vec(&receipt).map_err(io::Error::other)?,
                    )
                    .map_err(|error| {
                        super::toolchain_debug::operation_error(
                            "original-child-created-receipt-write",
                            Some(child.id()),
                            error,
                        )
                    })?;
                    original = Some((identity, live));
                }
                if created.image != inputs.rustc && created.image != inputs.native_linker {
                    return Err(unselected_creation_error(created, inputs, image_sha256));
                }
                let path = output_root.join(format!(
                    "native-toolchain-{}-{}.ack.json",
                    created.identity.process_id, created.identity.creation_time_100ns
                ));
                let published_path = path.with_extension("published");
                loop {
                    super::toolchain_debug::remaining(
                        inputs.native_work_cutoff_ticks,
                        inputs.native_work_frequency,
                    )?;
                    // This hint only sequences the strict ACK open after the
                    // publisher has finished persistence and final readback.
                    // It supplies no authority: the complete ACK is still checked.
                    if !published_path.try_exists().map_err(|error| {
                        super::toolchain_debug::operation_error(
                            "creation-ack-publication-hint",
                            Some(created.identity.process_id),
                            error,
                        )
                    })? {
                        std::thread::yield_now();
                        continue;
                    }
                    match fs::OpenOptions::new()
                        .read(true)
                        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
                        .custom_flags(
                            windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
                        )
                        .open(&path)
                    {
                        Ok(file) => {
                            let metadata = file.metadata().map_err(|error| {
                                super::toolchain_debug::operation_error(
                                    "creation-ack-held-metadata",
                                    Some(created.identity.process_id),
                                    error,
                                )
                            })?;
                            if !metadata.is_file() || metadata.len() > 16 * 1024
                                || metadata.file_attributes() & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                                return Err(io::Error::other("compiler acknowledgment is not bounded ordinary evidence"));
                            }
                            let mut bytes = Vec::new();
                            file.take(16 * 1024 + 1)
                                .read_to_end(&mut bytes)
                                .map_err(|error| {
                                    super::toolchain_debug::operation_error(
                                        "creation-ack-held-read",
                                        Some(created.identity.process_id),
                                        error,
                                    )
                                })?;
                            if bytes.len() > 16 * 1024 || bytes.len() as u64 != metadata.len() {
                                return Err(io::Error::other(
                                    "compiler acknowledgment length changed",
                                ));
                            }
                            memcordon::toolchain_creation_ack::validate(
                                &bytes,
                                memcordon::toolchain_creation_ack::Expected {
                                    challenge,
                                    root_pid: parent.process_id,
                                    child: &created.identity,
                                    parent: &memcordon_core::WindowsProcessIdentityV1 {
                                        process_id: created.parent_pid,
                                        creation_time_100ns: created.parent_birth,
                                    },
                                    image_sha256: &created.image_sha256,
                                },
                            )
                            .map_err(io::Error::other)?;
                            return Ok(());
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            std::thread::yield_now()
                        }
                        Err(error) => {
                            return Err(super::toolchain_debug::operation_error(
                                "creation-ack-open",
                                Some(created.identity.process_id),
                                error,
                            ));
                        }
                    }
                }
            },
        )?;
        super::toolchain_debug::wait_retired(
            &held,
            super::toolchain_debug::remaining(
                inputs.native_work_cutoff_ticks,
                inputs.native_work_frequency,
            )?,
        )?;
        super::toolchain_debug::remaining(
            inputs.native_work_cutoff_ticks,
            inputs.native_work_frequency,
        )?;
        let status = child.wait()?;
        let receive = |capture: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>| {
            let milliseconds = super::toolchain_debug::remaining(
                inputs.native_work_cutoff_ticks,
                inputs.native_work_frequency,
            )?;
            capture
                .recv_timeout(std::time::Duration::from_millis(u64::from(milliseconds)))
                .map_err(io::Error::other)?
        };
        let output = Output {
            status,
            stdout: receive(stdout)?,
            stderr: receive(stderr)?,
        };
        let (identity, live) =
            original.ok_or_else(|| io::Error::other("compiler creation receipt absent"))?;
        let retired = serde_json::json!({"format":"memcordon.windows-fixture-owned-child-retired","revision":1,
            "role":role,"challenge":challenge,"parent":parent,"child":identity,"image_sha256":image_sha256,
            "held_from_process_creation":true,"held_live_before_wait":live,"native_parent_edge_observed":true,
            "native_wait_completed":true,"native_status":output.status.code()});
        fs::write(
            root.join(format!("native-child-{role}.retired.json")),
            serde_json::to_vec(&retired).map_err(io::Error::other)?,
        )?;
        Ok(output)
    })();
    match operation {
        Err(original) if !debug_started => {
            let cleanup = super::toolchain_debug::run(
                inputs.native_work_cutoff_ticks,
                inputs.native_work_frequency,
                &parent,
                &child,
                |_| Err(io::Error::other("compiler setup failed before release")),
            );
            Err(io::Error::other(format!(
                "{original}; creation-owner cleanup={cleanup:?}"
            )))
        }
        other => other,
    }
}

fn checked(
    command: &mut Command,
    root: &Path,
    role: &str,
    challenge: &[u8],
    creation: Option<&super::descriptor::Toolchain>,
) -> io::Result<()> {
    let output = observed_output(command, root, role, challenge, creation)?;
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
        Some(inputs),
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
        None,
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
        None,
    )?;
    if fs::read(&product)? != descriptor.challenge {
        return Err(io::Error::other("compiled child bytes differ"));
    }
    checked(
        Command::new(&loader).arg(&dll).arg(&root),
        &root,
        "run-loader",
        &descriptor.challenge,
        None,
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
