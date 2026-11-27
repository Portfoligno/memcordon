//! Bounded fixture-only console comparison of the fixed token snapshot entry.
use super::{
    compiler_authority,
    console_calibration_desktop::{Desktop, failure as desktop_failure},
    console_calibration_token::{evidence as token_evidence, vary},
    descriptor::gate_precondition::{CompilerAuthoritySnapshot, RECORD_BYTES, sha256},
    fixture_environment,
    matched_control_broker::hold_image,
    matched_control_io::Pipe,
    matched_control_process::{Caller, ConsolePolicy, Image, Job, Launch, Process, live},
    native_fixture_default_dacl::snapshot,
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read, Write},
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    sync::Arc,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::ERROR_INVALID_HANDLE,
    System::{
        Console::GetConsoleProcessList, Pipes::PeekNamedPipe, SystemInformation::GetTickCount64,
    },
};

fn take_ascii(args: &mut impl Iterator<Item = OsString>) -> io::Result<String> {
    args.next()
        .and_then(|value| value.into_string().ok())
        .filter(|value| value.is_ascii())
        .ok_or_else(|| io::Error::other("calibration argument absent or invalid"))
}

fn hash_arg(args: &mut impl Iterator<Item = OsString>) -> io::Result<String> {
    let hash = take_ascii(args)?;
    if !super::console_calibration_desktop::valid_digest(&hash) {
        return Err(io::Error::other("calibration digest differs"));
    }
    Ok(hash)
}

fn drain(pipe: &mut File, capture: &mut Vec<u8>, cutoff: Instant) -> io::Result<()> {
    let mut buffer = [0u8; 4096];
    loop {
        live(cutoff)?;
        let mut available = 0;
        // SAFETY: the owned pipe is readable and this is its only reader.
        if unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if available == 0 {
            return Ok(());
        }
        let count = (available as usize).min(buffer.len());
        if count > RECORD_BYTES - capture.len() {
            return Err(io::Error::other("calibration capture exceeds bound"));
        }
        pipe.read_exact(&mut buffer[..count])?;
        capture.extend_from_slice(&buffer[..count]);
    }
}

pub(super) fn parent_console() -> io::Result<Option<u32>> {
    let mut processes = [0u32; 64];
    // SAFETY: this is a live writable array for a bounded console observation.
    let count = unsafe { GetConsoleProcessList(processes.as_mut_ptr(), processes.len() as u32) };
    if count == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if count as usize > processes.len()
        || !processes[..count as usize].contains(&std::process::id())
    {
        return Err(io::Error::other(
            "parent console process list is truncated or differs",
        ));
    }
    Ok(Some(count))
}

fn leg(
    process: &mut Process,
    stdout: &mut File,
    stderr: &mut File,
    selected: &CompilerAuthoritySnapshot,
    work: Instant,
    runtime: bool,
) -> io::Result<Value> {
    live(work)?;
    if &process.with_live_process(work, compiler_authority::process)? != selected {
        return Err(io::Error::other("suspended child authority differs"));
    }
    process.resume(work)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    while process.status(work)?.is_none() {
        drain(stdout, &mut out, work)?;
        drain(stderr, &mut err, work)?;
        std::thread::sleep(Duration::from_millis(1));
    }
    let status = process.settle(work)?;
    drain(stdout, &mut out, work)?;
    drain(stderr, &mut err, work)?;
    let snapshot_matches = !runtime
        && status == 0
        && err.is_empty()
        && serde_json::from_slice::<CompilerAuthoritySnapshot>(&out)
            .is_ok_and(|snapshot| &snapshot == selected);
    let mut result = json!({
        "flags":process.creation_flags, "pid":process.pid, "birth":process.birth,
        "native_status":status,"snapshot_matches":snapshot_matches,
        "stdout_bytes":out.len(),"stdout_sha256":sha256(&out),
        "stderr_bytes":err.len(),"stderr_sha256":sha256(&err),
        "creation_returned_child":true,"resume_previous_suspend_count":1,
        "suspended_token_and_image_verified":true,"natural_exit":true,"job_empty_verified":true,
    });
    if runtime {
        result
            .as_object_mut()
            .expect("leg evidence")
            .remove("snapshot_matches");
        result["probe"] = if status == 0 && err.is_empty() {
            serde_json::from_slice::<Value>(&out).unwrap_or(Value::Null)
        } else {
            Value::Null
        };
    }
    Ok(result)
}

pub(super) fn run(mut args: impl Iterator<Item = OsString>, runtime: bool) -> io::Result<i32> {
    let image_sha256 = hash_arg(&mut args)?;
    let source_sha256 = hash_arg(&mut args)?;
    let selected_sha256 = hash_arg(&mut args)?;
    let challenge_sha256 = hash_arg(&mut args)?;
    let work_tick = take_ascii(&mut args)?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    let cleanup_tick = take_ascii(&mut args)?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    if args.next().is_some() {
        return Err(io::Error::other("unexpected calibration argument"));
    }
    let started = Instant::now();
    // SAFETY: native uptime counter has no preconditions.
    let tick = unsafe { GetTickCount64() };
    let remaining = cleanup_tick.saturating_sub(tick);
    let mut evidence = json!({
        "format": if runtime {"memcordon.windows-fixture-runtime-console-calibration"}
            else {"memcordon.windows-fixture-console-calibration"},"revision":1,
        "challenge_sha256":challenge_sha256,"fixture_sha256":image_sha256,
        "selected_sha256":selected_sha256,"source_sha256":source_sha256,
        "state":"unavailable","stage":"deadline","diagnostic_only":true,
    });
    let result = (|| -> io::Result<()> {
        if !(work_tick > tick && cleanup_tick > work_tick && remaining <= 8_000) {
            return Err(io::Error::other(
                "calibration budget exhausted or exceeds bound",
            ));
        }
        let work = started + Duration::from_millis(work_tick - tick);
        let cleanup = started + Duration::from_millis(remaining);
        evidence["stage"] = json!("image");
        let image = std::env::current_exe()?;
        let cwd = std::env::current_dir()?;
        let held = hold_image(&image, &image_sha256, work)?;
        let variant_image = runtime.then(|| held.try_clone()).transpose()?;
        let file = memcordon_platform::test_support::windows_held_file_metadata(&held)?;
        evidence["fixture_identity"] =
            json!({"volume_serial":file.volume_serial,"file_index":file.file_index});
        evidence["stage"] = json!("caller");
        let source = compiler_authority::effective()?;
        if sha256(&serde_json::to_vec(&source).map_err(io::Error::other)?) != source_sha256 {
            return Err(io::Error::other("calibration source snapshot differs"));
        }
        let mut selected = None;
        let mut source_token = None;
        let caller = Caller::select(true, vec![held], work, |_| {
            let (source, derived, measured) = compiler_authority::select()?;
            if sha256(&serde_json::to_vec(&measured).map_err(io::Error::other)?) != selected_sha256
            {
                return Err(io::Error::other("calibration reduced snapshot differs"));
            }
            if runtime {
                source_token = Some(snapshot(source.as_raw_handle())?);
            }
            selected = Some(measured);
            Ok((source, derived))
        })?;
        let selected = selected.expect("selected caller is captured before returning owners");
        let mut logon = selected
            .groups
            .iter()
            .filter(|group| group.attributes & 0xc000_0000 == 0xc000_0000);
        let sid = logon
            .next()
            .ok_or_else(|| io::Error::other("calibration logon SID absent"))?;
        if logon.next().is_some() {
            return Err(io::Error::other("calibration logon SID is ambiguous"));
        }
        evidence["stage"] = json!("prepared-inputs");
        let stdin = Pipe::create(caller.default_acl()?, true, work)?;
        drop(stdin.write);
        let mut stdout = Pipe::create(caller.default_acl()?, false, work)?;
        let mut stderr = Pipe::create(caller.default_acl()?, false, work)?;
        let stdio = [
            stdin.read.as_raw_handle(),
            stdout.write.as_raw_handle(),
            stderr.write.as_raw_handle(),
        ];
        let job = Job::create(work)?;
        let argv = [
            image.clone().into_os_string(),
            "consumer-readiness-windows".into(),
            if runtime {
                "reduced-compiler-detached-console-probe"
            } else {
                "reduced-compiler-snapshot"
            }
            .into(),
        ];
        let environment = fixture_environment::entries()?;
        let encode = |value: &std::ffi::OsStr| {
            value
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        };
        evidence["cwd_sha256"] = json!(sha256(&encode(cwd.as_os_str())));
        evidence["argv_sha256"] = json!(sha256(
            &serde_json::to_vec(
                &argv
                    .iter()
                    .map(|arg| arg.encode_wide().collect::<Vec<_>>())
                    .collect::<Vec<_>>()
            )
            .map_err(io::Error::other)?
        ));
        evidence["environment_sha256"] = json!(sha256(
            &memcordon_core::encode_windows_environment_block(&environment)
                .map_err(io::Error::other)?
                .into_iter()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        ));
        evidence["parent_pid"] = json!(std::process::id());
        evidence["parent_session"] = json!(source.session_id);
        evidence["stage"] = json!("parent-console");
        let console = parent_console()?;
        evidence["parent_console"] =
            json!({"attached":console.is_some(),"observed_process_count":console});
        evidence["stage"] = json!("desktop");
        let desktop = Desktop::create(&challenge_sha256, &sid.sid, caller.token())?;
        evidence["desktop"] = desktop.evidence().clone();
        let pair = (|| -> io::Result<()> {
            let held_token = if runtime {
                Some(snapshot(caller.token())?)
            } else {
                None
            };
            let legs: &[_] = if runtime {
                &[
                    ("reduced", ConsolePolicy::Detached, false, false),
                    ("source", ConsolePolicy::Detached, false, false),
                    ("dacl_only", ConsolePolicy::Detached, true, false),
                    ("owner_only", ConsolePolicy::Detached, false, true),
                    ("dacl_and_owner", ConsolePolicy::Detached, true, true),
                ]
            } else {
                &[
                    ("baseline", ConsolePolicy::Inherit, false, false),
                    ("detached", ConsolePolicy::Detached, false, false),
                    ("new_console", ConsolePolicy::NewConsole, false, false),
                ]
            };
            for (index, &(name, policy, dacl, owner)) in legs.iter().enumerate() {
                // Share one absolute cutoff without letting an earlier child
                // consume a later child's allowance.
                let remaining = u32::try_from(legs.len() - index).unwrap_or(u32::MAX);
                let leg_work = if remaining == 1 {
                    work
                } else {
                    Instant::now() + work.saturating_duration_since(Instant::now()) / remaining
                };
                evidence["stage"] = json!(format!("{name}-create"));
                caller.verify_unchanged(leg_work)?;
                if parent_console()?.is_some() != console.is_some() {
                    return Err(io::Error::other("parent console attachment changed"));
                }
                if job.active(leg_work)? != 0 {
                    return Err(io::Error::other(
                        "calibration Job is not empty before creation",
                    ));
                }
                let source_leg = name == "source";
                let selected_caller = if runtime && (source_leg || dacl || owner) {
                    let variant = (|| {
                        let held = variant_image
                            .as_ref()
                            .expect("held runtime calibration image")
                            .try_clone()?;
                        Caller::select(!source_leg, vec![held], leg_work, |_| {
                            let (original, derived, measured) = compiler_authority::select()?;
                            if measured != selected
                                || !snapshot(original.as_raw_handle())?
                                    .stable_eq(source_token.as_ref().expect("held source security"))
                            {
                                return Err(io::Error::other(
                                    "calibration variant authority differs",
                                ));
                            }
                            if !source_leg {
                                vary(
                                    original.as_raw_handle(),
                                    derived.as_raw_handle(),
                                    held_token.as_ref().expect("held reduced security"),
                                    &selected.token.user_sid,
                                    dacl,
                                    owner,
                                )?;
                            }
                            Ok((original, derived))
                        })
                    })();
                    match variant {
                        Ok(variant) => variant,
                        Err(error) => {
                            evidence[name] = json!({"state":"variant-unavailable",
                                "raw_os_error":error.raw_os_error(),
                                "detail":error.to_string()});
                            continue;
                        }
                    }
                } else {
                    Arc::clone(&caller)
                };
                if runtime {
                    evidence[name] = json!({"token_security": token_evidence(&snapshot(selected_caller.token())?)});
                }
                let created = Process::create_with_console(
                    selected_caller,
                    Launch {
                        image_role: Image::Fixture,
                        image: &image,
                        argv: &argv,
                        environment: &environment,
                        cwd: &cwd,
                        stdio,
                        job: Some(Arc::clone(&job)),
                        work: leg_work,
                        cleanup,
                    },
                    Some((desktop.name(), policy)),
                );
                let mut process = match created {
                    Ok(process) => process,
                    Err(error) if runtime && job.active(leg_work)? == 0 => {
                        evidence[name]["state"] = json!("creation-unavailable");
                        evidence[name]["raw_os_error"] = json!(error.raw_os_error());
                        evidence[name]["detail"] = json!(error.to_string());
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                evidence["stage"] = json!(format!("{name}-run"));
                let leg = leg(
                    &mut process,
                    &mut stdout.read,
                    &mut stderr.read,
                    if source_leg { &source } else { &selected },
                    leg_work,
                    runtime,
                );
                match leg {
                    Ok(mut value) => {
                        if runtime {
                            value["token_security"] = evidence[name]["token_security"].take();
                        }
                        evidence[name] = value;
                    }
                    Err(error) if process.needs_settlement() => {
                        return Err(process.fail(error, cleanup));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })();
        let desktop_cleanup = desktop.close();
        evidence["desktop_closed"] = json!(desktop_cleanup.is_ok());
        pair?;
        evidence["stage"] = json!("desktop-retirement");
        desktop_cleanup?;
        live(cleanup)?;
        evidence["same_held_inputs"] = json!({
            "reduced_primary":!runtime,"desktop":true,"stdio_endpoints":true,"creation_job":true,
        });
        Ok(())
    })();
    if let Err(error) = result {
        let native_code = if let Some((substage, code)) = desktop_failure(&error) {
            evidence["desktop_substage"] = json!(substage);
            code
        } else {
            error.raw_os_error()
        };
        evidence["raw_os_error"] = json!(native_code);
    } else {
        evidence["state"] = json!("complete");
        evidence
            .as_object_mut()
            .expect("calibration evidence object")
            .remove("stage");
    }
    io::stdout().write_all(&serde_json::to_vec(&evidence).map_err(io::Error::other)?)?;
    Ok(0)
}
