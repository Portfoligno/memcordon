//! Read-only comparison of the first compiler launch outside the provider.
use super::{capture_compiler_pipes, qualified_inputs, wait_retired};
use crate::consumer_readiness_windows as fixture;
use fixture::{descriptor, native, toolchain_debug};
use serde_json::{Value, json};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

const CASE_TARGET: &str = "aarch64-pc-windows-msvc";
const X64_TARGET: &str = "x86_64-pc-windows-msvc";
pub(super) const PRE_CREATION: &str = "native-first-compiler-pre-creation.json";

#[derive(Debug)]
struct RunFailure(io::Error);

impl std::fmt::Display for RunFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for RunFailure {}

pub(in crate::consumer_readiness_windows) fn failure_record(error: &io::Error) -> Value {
    let run = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<RunFailure>());
    let (stage, error) = run.map_or(("input-validation", error), |run| {
        ("compiler-capture-or-retirement", &run.0)
    });
    json!({"format":"memcordon.windows-direct-compiler-helper-failure","revision":1,
        "stage":stage,"raw_os_error":error.raw_os_error()})
}

fn bounded_file(path: &Path, limit: u64) -> io::Result<(File, Vec<u8>)> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let meta = memcordon_platform::test_support::windows_held_file_metadata(&file)?;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    if meta.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || meta.links != 1
        || meta.length > limit
    {
        return Err(io::Error::other(
            "baseline input is not a bounded single-link file",
        ));
    }
    let mut bytes = Vec::new();
    (&file).take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != meta.length {
        return Err(io::Error::other("baseline input length changed"));
    }
    Ok((file, bytes))
}

fn wide(arg: &OsStr) -> Vec<u16> {
    arg.encode_wide().collect()
}

fn environment_digest() -> io::Result<String> {
    let environment = memcordon_core::encode_windows_environment_block(
        &fixture::matched_control_readback::environment()?,
    )
    .map_err(io::Error::other)?;
    let bytes: Vec<_> = environment
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    Ok(descriptor::gate_precondition::sha256(&bytes))
}

pub(super) fn retain_pre_creation(
    command: &std::process::Command,
    input: &super::CreationInput<'_>,
    binding: &descriptor::controller_start::Binding,
    clock: &descriptor::ControlClock,
    custody: &Value,
) -> Result<String, &'static str> {
    use descriptor::gate_precondition::sha256;
    let live = || {
        toolchain_debug::remaining(clock.work_cutoff_qpc, clock.qpc_frequency)
            .map_err(|_| "original-clock")
    };
    live()?;
    let (_, source) =
        bounded_file(&input.root.join("library.rs"), 1024 * 1024).map_err(|_| "source-read")?;
    let environment_sha256 = environment_digest().map_err(|_| "environment-read")?;
    let bytes = serde_json::to_vec(&json!({
        "pid":binding.pid,"birth":binding.birth,
        "descriptor_sha256":String::from(memcordon_core::DiagnosticSha256::from_bytes(binding.descriptor_sha256)),
        "challenge_sha256":sha256(&binding.challenge),"role":input.role,
        "cutoff_qpc":clock.work_cutoff_qpc,"frequency":clock.qpc_frequency,
        "image_sha256":input.image_sha256,"source_sha256":sha256(&source),
        "program_utf16":wide(command.get_program()),
        "argv_utf16":command.get_args().map(wide).collect::<Vec<_>>(),
        "environment_sha256":environment_sha256,"compiler_inputs":custody,
    })).map_err(|_| "encode")?;
    live()?;
    if bytes.len() > 16 * 1024 {
        return Err("byte-bound");
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(input.root.join(PRE_CREATION))
        .map_err(|_| "exclusive-open")?;
    file.write_all(&bytes).map_err(|_| "write")?;
    file.sync_all().map_err(|_| "sync")?;
    live()?;
    Ok(sha256(&bytes))
}

pub(in crate::consumer_readiness_windows) fn execute(
    mut args: impl Iterator<Item = OsString>,
) -> io::Result<()> {
    use descriptor::gate_precondition::{TokenObservation, sha256};
    use windows_sys::Win32::System::Threading::DEBUG_PROCESS;
    let descriptor_path = args
        .next()
        .ok_or_else(|| io::Error::other("missing baseline descriptor"))?;
    let scratch = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::other("missing baseline output directory"))?,
    );
    let text = |arg: Option<OsString>| {
        arg.and_then(|arg| arg.into_string().ok())
            .filter(|arg| !arg.is_empty())
            .ok_or_else(|| io::Error::other("missing baseline binding"))
    };
    let expected_descriptor = text(args.next())?;
    let expected_receipt = text(args.next())?;
    let expected_token = text(args.next())?;
    let cutoff = text(args.next())?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    let frequency = text(args.next())?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    let x64 = cfg!(target_arch = "x86_64") && super::native_x64();
    if args.next().is_some() || !(cfg!(target_arch = "aarch64") || x64) {
        return Err(io::Error::other(
            "invalid baseline architecture or arguments",
        ));
    }
    toolchain_debug::validate_clock(cutoff, frequency)?;
    let remaining = || toolchain_debug::remaining(cutoff, frequency);
    let (descriptor, digest) = fixture::read_descriptor_with_digest(Path::new(&descriptor_path))?;
    let x64_precreation = x64;
    let descriptor_sha256 = String::from(memcordon_core::DiagnosticSha256::from_bytes(digest));
    if descriptor_sha256 != expected_descriptor
        || descriptor.case != descriptor::Case::Toolchain
        || !matches!(
            descriptor.start_transport,
            descriptor::StartTransport::ControllerStdin { .. }
        )
        || descriptor.provider_input_experiment
        || descriptor.matched_control.is_some()
        || descriptor.reduced_compiler_sentinel().is_some()
    {
        return Err(io::Error::other("baseline descriptor binding differs"));
    }
    if scratch.parent() != Some(descriptor.output_root.as_path())
        || !scratch
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| {
                name.starts_with(if x64 {
                    "direct-x64-compiler-baseline-"
                } else {
                    "direct-arm64-compiler-baseline-"
                })
            })
    {
        return Err(io::Error::other("baseline output directory differs"));
    }
    let token_bytes = native::token_observation()?;
    let token: TokenObservation = serde_json::from_slice(&token_bytes).map_err(io::Error::other)?;
    if !token.restricted
        || token.restricting_sids != vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]]
        || sha256(&serde_json::to_vec(&token).map_err(io::Error::other)?) != expected_token
    {
        return Err(io::Error::other(
            "baseline restricted token profile differs",
        ));
    }
    let mut inputs = descriptor
        .toolchain
        .ok_or_else(|| io::Error::other("baseline compiler inputs absent"))?;
    if inputs.target != if x64 { X64_TARGET } else { CASE_TARGET }
        || frequency != inputs.native_work_frequency
        || cutoff > inputs.native_work_cutoff_ticks
    {
        return Err(io::Error::other(
            "baseline target or compiler deadline differs",
        ));
    }
    inputs.native_work_cutoff_ticks = cutoff;
    let compiled = descriptor.output_root.join("compiled");
    let (_, receipt) = bounded_file(
        &compiled.join(if x64_precreation {
            PRE_CREATION
        } else {
            "native-child-readiness.rlib.created.json"
        }),
        16 * 1024,
    )?;
    if sha256(&receipt) != expected_receipt {
        return Err(io::Error::other(
            "baseline original creation receipt differs",
        ));
    }
    let receipt: Value = serde_json::from_slice(&receipt).map_err(io::Error::other)?;
    let source = compiled.join("library.rs");
    let (_, selected_source) = bounded_file(&inputs.library_source, 1024 * 1024)?;
    let (_held_source, source_bytes) = bounded_file(&source, 1024 * 1024)?;
    if source_bytes != selected_source {
        return Err(io::Error::other(
            "baseline original source differs from selected bytes",
        ));
    }
    if x64_precreation
        && (receipt["descriptor_sha256"] != descriptor_sha256
            || receipt["challenge_sha256"] != sha256(&descriptor.challenge)
            || receipt["role"] != "readiness.rlib"
            || receipt["frequency"] != frequency
            || receipt["cutoff_qpc"]
                .as_u64()
                .is_none_or(|original_cutoff| original_cutoff < cutoff)
            || receipt["source_sha256"] != sha256(&source_bytes)
            || receipt["environment_sha256"] != environment_digest()?)
    {
        return Err(io::Error::other(
            "baseline compiler pre-creation witness differs",
        ));
    }
    let flags = ["--crate-type=rlib"];
    let original = descriptor::toolchain_command::compile_command(
        &inputs,
        &source,
        &compiled.join("readiness.rlib"),
        &flags,
    )
    .map_err(io::Error::other)?;
    let argv: Vec<_> = original.get_args().map(wide).collect();
    if receipt["program_utf16"] != json!(wide(original.get_program()))
        || receipt["argv_utf16"] != json!(argv)
    {
        return Err(io::Error::other("baseline original command differs"));
    }
    let product = scratch.join("readiness.rlib");
    let metadata = scratch.symlink_metadata()?;
    if !metadata.is_dir()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        || scratch.read_dir()?.next().is_some()
    {
        return Err(io::Error::other("baseline output directory is not empty"));
    }
    let mut command =
        descriptor::toolchain_command::compile_command(&inputs, &source, &product, &flags)
            .map_err(io::Error::other)?;
    if inputs.controller_input_root.is_none() {
        return Err(io::Error::other("baseline cwd identity absent"));
    }
    let held_root = inputs
        .controller_input_root
        .map(|identity| qualified_inputs::HeldRoot::acquire(&inputs, identity))
        .transpose()?;
    let qualified = qualified_inputs::Qualified::new(&inputs, &command, held_root.as_ref())?;
    let custody = qualified.receipt(&inputs)?;
    for key in [
        "cwd_native_identity",
        "selected_linker_native_identity",
        "selected_linker_sha256",
    ] {
        if custody[key].is_null() || custody[key] != receipt["compiler_inputs"][key] {
            return Err(io::Error::other(
                "baseline original cwd or linker identity differs",
            ));
        }
    }
    let (held_image, image) = bounded_file(&inputs.rustc, 2 * 1024 * 1024)?;
    let compiler_sha256 = sha256(&image);
    if receipt["image_sha256"] != compiler_sha256
        || !inputs.admits_created_image(&inputs.rustc, &compiler_sha256)
    {
        return Err(io::Error::other(
            "baseline original compiler digest differs",
        ));
    }
    let environment =
        memcordon_core::encode_windows_environment_block(&fixture::fixture_environment::entries()?)
            .map_err(io::Error::other)?;
    let observed_entries = fixture::matched_control_readback::environment()?;
    let observed_environment = memcordon_core::encode_windows_environment_block(&observed_entries)
        .map_err(io::Error::other)?;
    if observed_environment != environment {
        return Err(io::Error::other("baseline inherited environment differs"));
    }
    let environment_bytes: Vec<_> = environment
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let parent = native::current_identity()?;
    remaining()?;
    let run = |command: &mut std::process::Command| -> io::Result<Value> {
        qualified.verify(&inputs, command)?;
        remaining()?;
        command
            .creation_flags(DEBUG_PROCESS)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (spawn, returned) = if x64 {
            let clock = descriptor::ControlClock {
                revision: 1,
                work_cutoff_qpc: cutoff,
                qpc_frequency: frequency,
            };
            fixture::spawn_trace::comparison_compiler_spawn(command, &clock)
        } else {
            (command.spawn(), None)
        };
        let returned_create_process = returned.map(|row| {
            json!({
                "native_flags":row.flags,"win32_error":row.win32_error,"pid":row.process_id,
            })
        });
        let mut child = match spawn {
            Ok(child) => child,
            Err(error) => {
                return Ok(
                    json!({"state":"spawn-error","raw_os_error":error.raw_os_error(),
                    "returned_create_process":returned_create_process}),
                );
            }
        };
        let captures = capture_compiler_pipes(&mut child);
        let mut seen = false;
        // Always consume the original debugger job even if pipe setup failed.
        toolchain_debug::run(
            cutoff,
            frequency,
            &parent,
            &child,
            |created| {
                if !seen {
                    native::verify_child_image(&child, &held_image)?;
                    if created.identity != native::child_identity(&child)?
                        || created.parent_pid != parent.process_id
                        || created.parent_birth != parent.creation_time_100ns
                        || created.image_sha256 != compiler_sha256
                    {
                        return Err(io::Error::other("baseline debug creation identity differs"));
                    }
                    seen = true;
                }
                if !inputs.admits_created_image(&created.image, &created.image_sha256) {
                    return Err(io::Error::other("unmeasured baseline compiler descendant"));
                }
                Ok(())
            },
            |_, _| Ok(()),
            None,
        )?;
        wait_retired(&child, remaining()?)?;
        let status = child
            .wait()?
            .code()
            .ok_or_else(|| io::Error::other("baseline native status absent"))?
            as u32;
        let (stdout, stderr) = captures?;
        let capture_len = |stream: super::Capture| -> io::Result<usize> {
            Ok(stream
                .recv_timeout(Duration::from_millis(u64::from(remaining()?)))
                .map_err(io::Error::other)??
                .len())
        };
        let (stdout_bytes, stderr_bytes) = (capture_len(stdout)?, capture_len(stderr)?);
        let product = if status == 0 {
            let (_, bytes) = bounded_file(&product, 16 * 1024 * 1024)?;
            if !bytes.starts_with(b"!<arch>\n") || bytes.len() <= b"!<arch>\n".len() {
                return Err(io::Error::other(
                    "baseline compiler did not produce a nonempty rlib",
                ));
            }
            json!({"sha256":sha256(&bytes),"bytes":bytes.len()})
        } else {
            Value::Null
        };
        qualified.verify(&inputs, command)?;
        if !seen {
            return Err(io::Error::other("baseline original child creation absent"));
        }
        let outcome = json!({"state":"retired","native_status":status,"stdout_bytes":stdout_bytes,
            "child_pid":child.id(),"returned_create_process":returned_create_process,
            "stderr_bytes":stderr_bytes,"product":product});
        Ok(outcome)
    };
    let outcome =
        run(&mut command).map_err(|error| io::Error::new(error.kind(), RunFailure(error)))?;
    let record = json!({
        "format":if x64 {"memcordon.windows-direct-x64-compiler-baseline"} else {"memcordon.windows-direct-arm64-compiler-baseline"},"revision":1,
        "descriptor_sha256":descriptor_sha256,"original_witness_sha256":expected_receipt,
        "token_profile_sha256":expected_token,"environment_sha256":sha256(&environment_bytes),
        "source_sha256":sha256(&source_bytes),"compiler_sha256":compiler_sha256,
        "linker_sha256":custody["selected_linker_sha256"],"cwd_native_identity":custody["cwd_native_identity"],
        "requested_creation_flags":DEBUG_PROCESS,"role":"readiness.rlib","outcome":outcome,
    });
    io::stdout().write_all(&serde_json::to_vec(&record).map_err(io::Error::other)?)
}
