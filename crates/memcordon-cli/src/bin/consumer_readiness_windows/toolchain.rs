use super::{
    Descriptor, Transcript,
    operation_context::{
        CompilerOperation as CompilerStage, compiler_context, compiler_error, with_secondary,
    },
    toolchain_process_wait::{terminate_failed_child, wait_retired},
};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
#[path = "toolchain_direct_baseline.rs"]
pub(super) mod direct_baseline;
#[path = "toolchain_inputs.rs"]
mod qualified_inputs;
#[path = "toolchain_source_staging.rs"]
mod source_staging;

#[derive(Clone, Copy)]
struct Compilation<'a> {
    inputs: &'a super::descriptor::Toolchain,
    publication: &'a super::toolchain_diagnostics::PublicationOwner,
    input_root: Option<&'a qualified_inputs::HeldRoot>,
    compare_spawn: bool,
    spawn_trace: Option<&'a (
        super::descriptor::controller_start::Binding,
        super::descriptor::ControlClock,
    )>,
}

fn observed_output(
    command: &mut Command,
    root: &Path,
    role: &str,
    challenge: &[u8],
    creation: Option<Compilation<'_>>,
) -> io::Result<Output> {
    let qualified = creation
        .map(|creation| {
            qualified_inputs::Qualified::new(creation.inputs, command, creation.input_root)
        })
        .transpose()?;
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    };
    let image = compiler_context(
        CompilerStage::CompilerOpen,
        fs::OpenOptions::new()
            .read(true)
            .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(command.get_program()),
    )?;
    let metadata = compiler_context(CompilerStage::CompilerMetadata, image.metadata())?;
    if !metadata.is_file()
        || metadata.len() > 512 * 1024 * 1024
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    {
        return compiler_context(
            CompilerStage::CompilerMetadata,
            Err(io::Error::other(
                "owned toolchain image is not bounded regular code",
            )),
        );
    }
    let mut code = Vec::new();
    compiler_context(
        CompilerStage::CompilerRead,
        (&image).take(512 * 1024 * 1024 + 1).read_to_end(&mut code),
    )?;
    if code.len() > 512 * 1024 * 1024 {
        return compiler_context(
            CompilerStage::CompilerRead,
            Err(io::Error::other("owned toolchain code exceeds bound")),
        );
    }
    let image_sha256 = String::from(memcordon_core::DiagnosticSha256::from_bytes(
        Sha256::digest(&code).into(),
    ));
    let parent = compiler_context(
        CompilerStage::ParentIdentity,
        super::native::current_identity(),
    )?;
    let program: Vec<_> = command.get_program().encode_wide().collect();
    let arguments: Vec<Vec<u16>> = command
        .get_args()
        .map(|argument| argument.encode_wide().collect())
        .collect();
    if let Some(Compilation {
        inputs,
        publication,
        compare_spawn,
        spawn_trace,
        ..
    }) = creation
    {
        let qualified = qualified
            .as_ref()
            .expect("compiler inputs qualified before native launch");
        qualified.verify(inputs, command)?;
        return creation_output(
            command,
            CreationInput {
                root,
                role,
                challenge,
                inputs,
                publication,
                image: &image,
                image_sha256: &image_sha256,
                parent,
                program: &program,
                arguments: &arguments,
                qualified,
                compare_spawn,
                spawn_trace,
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
    publication: &'a super::toolchain_diagnostics::PublicationOwner,
    image: &'a fs::File,
    image_sha256: &'a str,
    parent: memcordon_core::WindowsProcessIdentityV1,
    program: &'a [u16],
    arguments: &'a [Vec<u16>],
    qualified: &'a qualified_inputs::Qualified<'a>,
    compare_spawn: bool,
    spawn_trace: Option<&'a (
        super::descriptor::controller_start::Binding,
        super::descriptor::ControlClock,
    )>,
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
    let selected_digest = |path: &Path| {
        inputs
            .selected_images
            .iter()
            .find(|image| image.path == path)
            .map(|image| image.sha256.as_str())
    };
    let context = serde_json::json!({
        "format":"memcordon.windows-unselected-compiler-creation","revision":1,
        "diagnostic_only":true,"child":created.identity,
        "parent_pid":created.parent_pid,"parent_birth":created.parent_birth,
        "held_created_image":{"path":path_context(&created.image),"sha256":created.image_sha256},
        "selected_rustc":{"path":path_context(&inputs.rustc),"original_held_sha256":original_rustc_sha256,
            "frozen_selected_sha256":selected_digest(&inputs.rustc)},
        "selected_linker":{"path":path_context(&inputs.native_linker),"held_sha256":null,
            "frozen_selected_sha256":selected_digest(&inputs.native_linker),
            "digest_observation":"a selected linker file handle is not retained in this creation callback"},
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

type Capture = std::sync::mpsc::Receiver<io::Result<Vec<u8>>>;

fn capture_compiler_pipe(pipe: impl Read + Send + 'static) -> io::Result<Capture> {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    compiler_context(
        CompilerStage::CaptureStart,
        std::thread::Builder::new().spawn(move || {
            const LIMIT: usize = 16 * 1024 * 1024;
            let mut bytes = Vec::new();
            let result = pipe
                .take((LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .and_then(|_| {
                    if bytes.len() <= LIMIT {
                        Ok(bytes)
                    } else {
                        Err(io::Error::other("compiler output exceeds bound"))
                    }
                });
            let _ = send.send(result);
        }),
    )?;
    Ok(receive)
}

fn capture_compiler_pipes(child: &mut Child) -> io::Result<(Capture, Capture)> {
    let stdout = capture_compiler_pipe(
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("compiler stdout pipe absent"))?,
    )?;
    let stderr = capture_compiler_pipe(
        child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("compiler stderr pipe absent"))?,
    )?;
    Ok((stdout, stderr))
}

fn native_x64() -> bool {
    use windows_sys::Win32::System::SystemInformation::{
        IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_UNKNOWN,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, IsWow64Process2};
    if !cfg!(target_arch = "x86_64") {
        return false;
    }
    let mut process = 0;
    let mut native = 0;
    // SAFETY: pseudo process handle and writable machine types.
    (unsafe { IsWow64Process2(GetCurrentProcess(), &mut process, &mut native) }) != 0
        && process == IMAGE_FILE_MACHINE_UNKNOWN
        && native == IMAGE_FILE_MACHINE_AMD64
}

fn compare_compiler_creation(
    command: &mut Command,
    input: &CreationInput<'_>,
    binding: &super::descriptor::controller_start::Binding,
    clock: &super::descriptor::ControlClock,
    compiler_inputs: &serde_json::Value,
    original_native_flags: u32,
) -> String {
    use serde_json::json;
    use windows_sys::Win32::System::Threading::DEBUG_PROCESS;
    let digest = super::descriptor::controller_start::descriptor_digest;
    let remaining =
        || super::toolchain_debug::remaining(clock.work_cutoff_qpc, clock.qpc_frequency);
    let product = input.root.join(input.role);
    let prepare = || -> io::Result<()> {
        super::toolchain_debug::validate_clock(clock.work_cutoff_qpc, clock.qpc_frequency)?;
        input.qualified.verify(input.inputs, command)?;
        if input.parent.process_id != binding.pid
            || input.parent.creation_time_100ns != binding.birth
            || !input.inputs.selected_images.iter().any(|selected| {
                selected.path == input.inputs.rustc && selected.sha256 == input.image_sha256
            })
        {
            return Err(io::Error::other("comparison compiler binding differs"));
        }
        match product.symlink_metadata() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::other(
                    "comparison requires a fresh compiler output",
                ));
            }
        }
        remaining()?;
        let mut hint = fs::OpenOptions::new().write(true).create_new(true).open(
            input
                .root
                .join("native-compiler-no-debug-comparison.started"),
        )?;
        hint.write_all(&binding.descriptor_sha256)?;
        hint.sync_all()?;
        remaining()?;
        Ok(())
    };
    let outcome = match prepare() {
        Err(error) => json!({"state":"preparation-error","raw_os_error":error.raw_os_error()}),
        Ok(()) => {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0);
            let (result, route) = super::spawn_trace::comparison_compiler_spawn(command, clock);
            let returned = route.map_or_else(
                || json!({"state":"unobserved","win32_error":null}),
                |row| match row.win32_error {
                    Some(code) => json!({
                        "state":"failure","win32_error":code,"native_flags":row.flags,
                    }),
                    None => json!({
                        "state":"success","win32_error":null,"native_flags":row.flags,
                        "process_id":row.process_id,
                    }),
                },
            );
            match result {
                Err(error) => json!({
                    "state":"spawn-error","raw_os_error":error.raw_os_error(),"returned":returned,
                }),
                Ok(mut child) => {
                    // The Child is the original creation handle owner, including
                    // on setup failure. Use it directly without duplicating rights.
                    let mut identity = None;
                    let mut retired = false;
                    let mut native_status = None;
                    let operation = (|| -> io::Result<()> {
                        use std::os::windows::io::AsRawHandle;
                        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
                        let mut in_job = 0;
                        // SAFETY: the creation handle and output scalar are retained.
                        if unsafe {
                            IsProcessInJob(child.as_raw_handle(), std::ptr::null_mut(), &mut in_job)
                        } == 0
                        {
                            return Err(io::Error::last_os_error());
                        }
                        if in_job == 0 {
                            return Err(io::Error::other(
                                "comparison compiler Job membership absent",
                            ));
                        }
                        super::native::verify_child_image(&child, input.image)?;
                        let child_identity = super::native::child_identity(&child)?;
                        let (parent, _) = super::native::child_parent_and_liveness(&child)?;
                        if parent != input.parent.process_id
                            || child_identity.process_id == 0
                            || child_identity.process_id == parent
                            || child_identity.creation_time_100ns < input.parent.creation_time_100ns
                        {
                            return Err(io::Error::other(
                                "comparison compiler parent identity differs",
                            ));
                        }
                        identity = Some(child_identity);
                        let (stdout, stderr) = capture_compiler_pipes(&mut child)?;
                        wait_retired(&child, remaining()?)?;
                        retired = true;
                        native_status = child.wait()?.code();
                        for capture in [stdout, stderr] {
                            capture
                                .recv_timeout(std::time::Duration::from_millis(u64::from(
                                    remaining()?,
                                )))
                                .map_err(io::Error::other)??;
                        }
                        input.qualified.verify(input.inputs, command)?;
                        remaining()?;
                        Ok(())
                    })();
                    let cleanup = if retired {
                        Ok(())
                    } else {
                        let (signaled, status) = terminate_failed_child(&mut child, remaining);
                        retired = signaled;
                        status.map(|status| native_status = status)
                    };
                    let state = if operation.is_ok() {
                        "child-complete"
                    } else {
                        "child-incomplete"
                    };
                    json!({
                        "state":state,"returned":returned,"identity":identity,"retired":retired,
                        "native_status":native_status,"operation_failed":operation.is_err(),
                        "cleanup_failed":cleanup.is_err(),
                    })
                }
            }
        }
    };
    let marker = json!({
        "pid":binding.pid,"birth":binding.birth,"descriptor_sha256":binding.descriptor_sha256,
        "challenge_sha256":digest(&binding.challenge),
        "cutoff_qpc":clock.work_cutoff_qpc,"frequency":clock.qpc_frequency,
        "compiler_sha256":input.image_sha256,"role":input.role,
        "linker_sha256":compiler_inputs["selected_linker_sha256"],
        "original_ordinal":1,"original_flags":DEBUG_PROCESS,
        "original_native_flags":original_native_flags,
        "comparison_ordinal":2,"comparison_flags":0,
        "outcome":outcome,
    });
    format!("\ncompiler-no-debug-comparison-v1 {marker}\n")
}

fn creation_output(command: &mut Command, input: CreationInput<'_>) -> io::Result<Output> {
    use std::os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    };
    compiler_context(
        CompilerStage::QualifyClock,
        super::toolchain_debug::validate_clock(
            input.inputs.native_work_cutoff_ticks,
            input.inputs.native_work_frequency,
        ),
    )?;
    let output_root = input
        .root
        .parent()
        .ok_or_else(|| io::Error::other("compiler acknowledgment root absent"))?;
    command
        .creation_flags(windows_sys::Win32::System::Threading::DEBUG_PROCESS)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    input.qualified.verify(input.inputs, command)?;
    let compiler_inputs = input.qualified.receipt(input.inputs)?;
    let spawned = match input.spawn_trace {
        Some((binding, clock)) => {
            let compare = input.compare_spawn && input.role == "readiness.rlib" && native_x64();
            let witness = compare.then(|| {
                direct_baseline::retain_pre_creation(
                    command,
                    &input,
                    binding,
                    clock,
                    &compiler_inputs,
                )
            });
            let (result, denied_at_flags) =
                super::spawn_trace::compiler_spawn(command, binding, clock);
            result.map_err(|original| {
                if let Some(flags) = denied_at_flags.filter(|flags| {
                    flags & windows_sys::Win32::System::Threading::DEBUG_PROCESS != 0 && compare
                }) {
                    let detail = compare_compiler_creation(
                        command,
                        &input,
                        binding,
                        clock,
                        &compiler_inputs,
                        flags,
                    );
                    let detail = match witness {
                        Some(Ok(digest)) => {
                            format!("{detail}compiler-pre-creation-v1 {digest}\n")
                        }
                        Some(Err(stage)) => {
                            format!("{detail}compiler-pre-creation-v1 unavailable {stage}\n")
                        }
                        None => detail,
                    };
                    with_secondary(original, detail)
                } else {
                    original
                }
            })
        }
        None => command.spawn(),
    };
    let mut child = compiler_context(CompilerStage::CompilerSpawn, spawned)?;
    let CreationInput {
        root,
        role,
        challenge,
        inputs,
        publication,
        image,
        image_sha256,
        parent,
        program,
        arguments,
        qualified,
        compare_spawn: _,
        spawn_trace: _,
    } = input;
    let mut debug_started = false;
    let operation = (|| {
        let (stdout, stderr) = capture_compiler_pipes(&mut child)?;
        let held = compiler_context(
            CompilerStage::ChildRetain,
            super::native::retain_child_handle(&child),
        )?;
        let original_identity = compiler_context(
            CompilerStage::ChildIdentity,
            super::native::child_identity(&child),
        )?;
        let diagnostics = compiler_context(
            CompilerStage::CheckpointInitialize,
            super::toolchain_diagnostics::Publisher::new(
                publication,
                serde_json::json!({
                    "role":role,"challenge":challenge,"parent":parent,"original_child":original_identity,
                    "selected_image_sha256":image_sha256,
                    "native_work_cutoff_ticks":inputs.native_work_cutoff_ticks,
                    "native_work_frequency":inputs.native_work_frequency
                    ,"compiler_inputs":compiler_inputs
                }),
            ),
        )?;
        compiler_context(
            CompilerStage::CheckpointPublish,
            diagnostics.publish(
                false,
                "before-debug-run",
                &serde_json::json!({"original_process_owner_retained":true}),
            ),
        )?;
        let mut original = None;
        let mut original_loads = (role == "readiness.rlib"
            && !inputs.compiler_import_siblings.is_empty())
        .then(super::descriptor::OriginalCompilerLoads::default);
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
                        "compiler_inputs":compiler_inputs,
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
                if !inputs.admits_created_image(&created.image, &created.image_sha256) {
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
                            diagnostics.publish(false, "creation-ack-received-before-validation", &serde_json::json!({
                                "child":created.identity,"parent_pid":created.parent_pid,
                                "parent_birth":created.parent_birth,"image_sha256":created.image_sha256,
                                "ack_bytes":bytes.len(),"ack_validated":false,"continued":false
                            }))?;
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
            |phase, state| diagnostics.publish(true, phase, &state),
            original_loads.as_mut().map(|loads| (inputs.compiler_import_siblings.as_slice(), loads)),
        )
        .map_err(|error| compiler_error(CompilerStage::DebugObservation, error))?;
        diagnostics.publish(
            false,
            "after-debug-run-before-wait-retired",
            &serde_json::json!({"debug_active_inventory_empty":true}),
        )?;
        compiler_context(
            CompilerStage::ChildRetirement,
            wait_retired(
                &held,
                super::toolchain_debug::remaining(
                    inputs.native_work_cutoff_ticks,
                    inputs.native_work_frequency,
                )?,
            ),
        )?;
        diagnostics.publish(
            false,
            "after-wait-retired-before-child-wait",
            &serde_json::json!({"original_native_retirement_signaled":true}),
        )?;
        super::toolchain_debug::remaining(
            inputs.native_work_cutoff_ticks,
            inputs.native_work_frequency,
        )?;
        let status = compiler_context(CompilerStage::ChildWait, child.wait())?;
        diagnostics.publish(
            false,
            "after-child-wait",
            &serde_json::json!({"native_status":status.code()}),
        )?;
        let receive = |capture: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>, phase| {
            diagnostics.publish(false, phase, &serde_json::json!({"native_status":status.code(),"original_native_retirement_signaled":true}))?;
            let milliseconds = super::toolchain_debug::remaining(
                inputs.native_work_cutoff_ticks,
                inputs.native_work_frequency,
            )?;
            compiler_context(CompilerStage::CaptureReceive, capture
                .recv_timeout(std::time::Duration::from_millis(u64::from(milliseconds)))
                .map_err(|error| {
                    io::Error::other(format!(
                        "{error}; toolchain-operation={phase}; original-child={original_identity:?}"
                    ))
                })
                .and_then(|result| result))
        };
        let output = Output {
            status,
            stdout: receive(stdout, "before-stdout-capture-receive")?,
            stderr: receive(stderr, "before-stderr-capture-receive")?,
        };
        diagnostics.publish(false, "output-capture-complete", &serde_json::json!({"stdout_bytes":output.stdout.len(),"stderr_bytes":output.stderr.len(),"native_status":output.status.code()}))?;
        let (identity, live) =
            original.ok_or_else(|| io::Error::other("compiler creation receipt absent"))?;
        let mut retired = serde_json::json!({"format":"memcordon.windows-fixture-owned-child-retired","revision":1,
            "role":role,"challenge":challenge,"parent":parent,"child":identity,"image_sha256":image_sha256,
            "compiler_inputs":compiler_inputs,
            "held_from_process_creation":true,"held_live_before_wait":live,"native_parent_edge_observed":true,
            "native_wait_completed":true,"native_status":output.status.code()});
        if let Some(loads) = original_loads.filter(|_| !output.status.success()) {
            retired["original_compiler_loads"] = serde_json::json!({
                "loads": loads,
                "compiler_stderr_bytes": output.stderr.len(),
            });
        }
        compiler_context(
            CompilerStage::RetirementReceipt,
            fs::write(
                root.join(format!("native-child-{role}.retired.json")),
                serde_json::to_vec(&retired).map_err(io::Error::other)?,
            ),
        )?;
        Ok(output)
    })();
    let operation = match operation {
        Err(original) if !debug_started => {
            let cleanup = super::toolchain_debug::run(
                inputs.native_work_cutoff_ticks,
                inputs.native_work_frequency,
                &parent,
                &child,
                |_| Err(io::Error::other("compiler setup failed before release")),
                |_, _| Ok(()),
                None,
            );
            Err(with_secondary(
                original,
                format!("creation-owner cleanup={cleanup:?}"),
            ))
        }
        other => other,
    };
    let named = qualified.verify(inputs, command);
    match (operation, named) {
        (Err(original), Err(secondary)) => Err(with_secondary(
            original,
            format!("secondary compiler input custody={secondary}"),
        )),
        (Err(original), _) => Err(original),
        (Ok(_), Err(error)) => Err(error),
        (Ok(output), Ok(())) => Ok(output),
    }
}

fn checked(
    command: &mut Command,
    root: &Path,
    role: &str,
    challenge: &[u8],
    creation: Option<Compilation<'_>>,
) -> io::Result<()> {
    let output = observed_output(command, root, role, challenge, creation)?;
    if !output.status.success() {
        return compiler_context(
            CompilerStage::ChildStatus,
            Err(io::Error::other(format!(
                "owned toolchain command failed with native status {:?}, stderr bytes {:?}",
                output.status.code(),
                output.stderr
            ))),
        );
    }
    if !output.stdout.is_empty() {
        return Err(io::Error::other("unexpected toolchain stdout"));
    }
    Ok(())
}

fn compile(
    creation: Compilation<'_>,
    source: &Path,
    output: &Path,
    flags: &[&str],
    challenge: &[u8],
) -> io::Result<()> {
    let mut command = compiler_context(
        CompilerStage::QualifyCommand,
        super::descriptor::toolchain_command::compile_command(
            creation.inputs,
            source,
            output,
            flags,
        )
        .map_err(io::Error::other),
    )?;
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
        Some(creation),
    )
}

struct CompilerConsole(bool);

impl CompilerConsole {
    fn allocate_if_detached() -> io::Result<Self> {
        use super::console_calibration::parent_console;
        use super::operation_context::{ConsoleApi, console_error};
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Console::{
            AllocConsole, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };

        if parent_console()
            .map_err(|error| console_error(ConsoleApi::ProcessListBefore, error))?
            .is_some()
        {
            return Ok(Self(false));
        }
        let streams = || {
            // SAFETY: these are the three supported standard-handle selectors.
            [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
                .map(|kind| unsafe { GetStdHandle(kind) })
        };
        let before = streams();
        if before
            .iter()
            .any(|h| h.is_null() || *h == INVALID_HANDLE_VALUE)
        {
            return Err(io::Error::other("compiler fixture standard handle absent"));
        }
        // SAFETY: this fixture has no attached console; no caller memory is passed.
        if unsafe { AllocConsole() } == 0 {
            return Err(console_error(
                ConsoleApi::Allocate,
                io::Error::last_os_error(),
            ));
        }
        let owner = Self(true);
        if parent_console()
            .map_err(|error| console_error(ConsoleApi::ProcessListAfter, error))?
            .is_none()
            || streams() != before
        {
            return Err(io::Error::other(
                "compiler fixture console attachment or original standard handles differ",
            ));
        }
        Ok(owner)
    }

    fn release(&mut self) -> io::Result<()> {
        use super::operation_context::{ConsoleApi, console_error};
        use windows_sys::Win32::System::Console::FreeConsole;
        // SAFETY: release only this process's newly acquired attachment.
        if self.0 && unsafe { FreeConsole() } == 0 {
            return Err(console_error(ConsoleApi::Free, io::Error::last_os_error()));
        }
        self.0 = false;
        Ok(())
    }
}

impl Drop for CompilerConsole {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

/// Use the real fixture path and refuse to count an already attached child.
pub(super) fn detached_console_probe() -> serde_json::Value {
    let result = match CompilerConsole::allocate_if_detached() {
        Ok(mut console) if console.0 => console.release(),
        Ok(_) => return serde_json::json!({"state":"unexpected-inherited-console"}),
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => {
            serde_json::json!({"state":"allocated-and-released","stdio_unchanged_at_attach":true})
        }
        Err(error) => {
            let detail = super::operation_context::console_failure_detail(&error);
            serde_json::json!({"state":"failed","api":detail.map(|(api, _)| api),
                "raw_os_error":detail.and_then(|(_, raw)| raw)})
        }
    }
}

pub(super) fn execute(
    descriptor: &Descriptor,
    transcript: &mut Transcript,
    control: Option<&mut super::controller_start_input::Session>,
) -> io::Result<()> {
    use super::operation_context::{
        Operation::Toolchain as Stage, SourceRole, ToolchainOperation as Op, context, wrap,
    };
    let start = descriptor
        .start_gate
        .as_ref()
        .ok_or_else(|| io::Error::other("owned toolchain execution lacks native observer gate"))?;
    let inputs = descriptor
        .toolchain
        .as_ref()
        .ok_or_else(|| io::Error::other("toolchain inputs missing"))?;
    let candidate_root = match inputs.controller_input_root {
        Some(expected) => {
            let session = control.as_deref().ok_or_else(|| {
                io::Error::other("compiler root custody lacks original stdin session")
            })?;
            if std::time::Instant::now() >= session.original_deadline() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original compiler root custody cutoff expired",
                ));
            }
            let token: serde_json::Value =
                serde_json::from_slice(&super::native::token_observation()?)
                    .map_err(io::Error::other)?;
            if token["restricted"].as_bool() != Some(true) {
                return Err(io::Error::other(
                    "compiler root custody requires the original restricted fixture token",
                ));
            }
            Some(qualified_inputs::HeldRoot::acquire(inputs, expected)?)
        }
        None => None,
    };
    let bound_ready = candidate_root
        .as_ref()
        .map(|root| {
            let session = control
                .as_deref()
                .expect("root observation requires the original session");
            serde_json::to_vec(&super::descriptor::ToolchainRootReady::from_start(
                root.identity,
                session.original_binding(),
            ))
            .map_err(io::Error::other)
        })
        .transpose()?;
    transcript.event(
        "toolchain-ready-for-native-observer",
        None,
        bound_ready.as_deref().unwrap_or(&descriptor.challenge),
    )?;
    let spawn_trace = candidate_root.as_ref().and_then(|_| {
        let session = control.as_deref()?;
        let mut clock = descriptor.control_clock.clone()?;
        if clock.qpc_frequency != inputs.native_work_frequency {
            return None;
        }
        clock.work_cutoff_qpc = clock.work_cutoff_qpc.min(inputs.native_work_cutoff_ticks);
        Some((session.original_binding().clone(), clock))
    });
    match descriptor.start_transport {
        super::descriptor::StartTransport::ControllerStdin { .. } => {
            control
                .ok_or_else(|| {
                    wrap(
                        Stage(Op::ObserverSession),
                        io::Error::other("original toolchain control session unavailable"),
                    )
                })?
                .receive(super::descriptor::controller_start::Phase::ToolchainObserverRelease)?;
        }
        super::descriptor::StartTransport::NamedEvent => {
            if candidate_root.is_some() {
                return Err(io::Error::other(
                    "compiler root custody requires bound stdin observer release",
                ));
            }
            let observer_name = format!("{start}-toolchain-observer");
            super::native::wait_controller_gate(std::ffi::OsStr::new(&observer_name), || Ok(()))
                .map_err(|error| {
                    super::toolchain_diagnostics::observer_gate_error(&observer_name, error)
                })?;
        }
    }
    // Only the original second stdin frame enables use of the independently
    // observed root in place of reopening controller-owned ambient ancestors.
    if let Some(root) = &candidate_root {
        root.verify(inputs)?;
    }
    let root = descriptor.output_root.join("compiled");
    context(Stage(Op::CreateCompiledDirectory), fs::create_dir(&root))?;
    context(
        Stage(Op::ValidateClock),
        super::toolchain_debug::validate_clock(
            inputs.native_work_cutoff_ticks,
            inputs.native_work_frequency,
        ),
    )?;
    // Convert the original absolute QPC deadline once, conservatively. Sampling
    // Instant before QPC prevents conversion work from extending the budget.
    let sampled = std::time::Instant::now();
    let remaining = context(
        Stage(Op::SampleDeadline),
        super::toolchain_debug::remaining(
            inputs.native_work_cutoff_ticks,
            inputs.native_work_frequency,
        ),
    )?;
    let deadline = sampled
        .checked_add(std::time::Duration::from_millis(u64::from(remaining)))
        .ok_or_else(|| {
            wrap(
                Stage(Op::PublicationDeadline),
                io::Error::other("toolchain publication cutoff overflow"),
            )
        })?;
    let publication = context(
        Stage(Op::RetainPublicationParent),
        super::toolchain_diagnostics::PublicationOwner::new(&root, deadline),
    )?;
    for (input, name, role) in [
        (&inputs.library_source, "library.rs", SourceRole::Library),
        (&inputs.test_source, "tests.rs", SourceRole::Tests),
        (&inputs.child_source, "child.rs", SourceRole::Child),
        (&inputs.dll_source, "dll.rs", SourceRole::Dll),
        (&inputs.loader_source, "loader.rs", SourceRole::Loader),
    ] {
        context(
            Stage(Op::CopySource(role)),
            source_staging::stage(input, &root.join(name), deadline),
        )?;
    }
    let library = root.join("readiness.rlib");
    let creation = Compilation {
        inputs,
        publication: &publication,
        input_root: candidate_root.as_ref(),
        compare_spawn: descriptor.case == super::descriptor::Case::Toolchain
            && !descriptor.provider_input_experiment
            && descriptor.matched_control.is_none()
            && inputs.target == "x86_64-pc-windows-msvc",
        spawn_trace: None,
    };
    // Allocate in the fixture, outside the debug family. Rustc and the bundled
    // linker can both inherit; DEBUG_PROCESS still observes their entire family.
    let mut compiler_console = context(
        Stage(Op::CompilerConsole),
        CompilerConsole::allocate_if_detached(),
    )?;
    context(
        Stage(Op::CompileLibrary),
        compile(
            Compilation {
                spawn_trace: spawn_trace.as_ref(),
                ..creation
            },
            &root.join("library.rs"),
            &library,
            &["--crate-type=rlib"],
            &descriptor.challenge,
        ),
    )?;
    let child = root.join("child.exe");
    compile(
        creation,
        &root.join("child.rs"),
        &child,
        &[],
        &descriptor.challenge,
    )?;
    let tests = root.join("tests.exe");
    compile(
        creation,
        &root.join("tests.rs"),
        &tests,
        &["--test"],
        &descriptor.challenge,
    )?;
    let dll = root.join("readiness.dll");
    compile(
        creation,
        &root.join("dll.rs"),
        &dll,
        &["--crate-type=cdylib"],
        &descriptor.challenge,
    )?;
    let loader = root.join("loader.exe");
    compile(
        creation,
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
    context(Stage(Op::CompilerConsole), compiler_console.release())?;
    transcript.event(
        "toolchain-test-child-dll-complete",
        None,
        &descriptor.challenge,
    )
}
