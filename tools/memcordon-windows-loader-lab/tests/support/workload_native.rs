#![cfg(windows)]

use super as native;

use std::{
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    Storage::FileSystem::WriteFile,
    System::{
        Pipes::CreatePipe,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

#[test]
fn only_initial_first_chance_breakpoint_is_handled() {
    let mut initial = false;
    assert_eq!(
        native::exception_disposition(0xC0000142, true, &mut initial),
        DBG_EXCEPTION_NOT_HANDLED as u32
    );
    assert!(!initial);
    assert_eq!(
        native::exception_disposition(0x80000003, false, &mut initial),
        DBG_EXCEPTION_NOT_HANDLED as u32
    );
    assert!(!initial);
    assert_eq!(
        native::exception_disposition(0x80000003, true, &mut initial),
        DBG_CONTINUE as u32
    );
    assert!(initial);
    assert_eq!(
        native::exception_disposition(0x80000003, true, &mut initial),
        DBG_EXCEPTION_NOT_HANDLED as u32
    );
    assert_eq!(
        native::exception_disposition(0xC0000005, false, &mut initial),
        DBG_EXCEPTION_NOT_HANDLED as u32
    );
}

#[test]
fn actual_pipe_capture_is_nonblocking_bounded_and_preserves_omitted_bytes() {
    let (mut reader, mut writer) = (ptr::null_mut(), ptr::null_mut());
    assert_ne!(
        unsafe { CreatePipe(&mut reader, &mut writer, ptr::null(), 65536) },
        0
    );
    let mut bytes = vec![0_u8; 256 * 1024 - 3];
    let mut omitted = 0;
    native::drain(reader, &mut bytes, &mut omitted).unwrap();
    assert_eq!(bytes.len(), 256 * 1024 - 3);
    let data = b"bounded-output";
    let mut written = 0;
    assert_ne!(
        unsafe {
            WriteFile(
                writer,
                data.as_ptr(),
                data.len() as u32,
                &mut written,
                ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(written as usize, data.len());
    native::drain(reader, &mut bytes, &mut omitted).unwrap();
    assert_eq!(bytes.len(), 256 * 1024);
    assert_eq!(&bytes[bytes.len() - 3..], &data[..3]);
    assert_eq!(omitted, data.len() as u64 - 3);
    assert_ne!(unsafe { CloseHandle(writer) }, 0);
    native::drain(reader, &mut bytes, &mut omitted).unwrap();
    assert_ne!(unsafe { CloseHandle(reader) }, 0);
}

#[test]
fn actual_owned_job_can_terminate_and_prove_empty_under_finite_cutoff() {
    let mut token = ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let envelope = memcordon_windows_launch_core::query_token_envelope(token).unwrap();
    assert_ne!(unsafe { CloseHandle(token) }, 0);
    let job = memcordon_windows_launch_core::ProductionJobV1::create(&format!(
        "O:{}D:P(A;;GA;;;{})",
        envelope.user_sid, envelope.user_sid
    ))
    .unwrap();
    job.terminate(0x4d430d01).unwrap();
    assert!(
        job.wait_empty(Instant::now() + Duration::from_secs(1))
            .unwrap()
    );
}

#[test]
fn invalid_source_identity_cannot_start_an_scm_diagnostic() {
    assert!(
        native::run_as_service(
            "invalid",
            std::path::Path::new("absent"),
            std::path::Path::new("absent-result"),
            0,
            0,
            0
        )
        .is_err()
    );
}

fn retained_spawn_resume_fixture(
    debug: bool,
    fault: Option<native::CreationCheckpoint>,
    modules: bool,
) {
    use std::os::windows::ffi::OsStrExt;
    let started = Instant::now();
    let work = started + Duration::from_secs(5);
    let cleanup = started + Duration::from_secs(10);
    let mut raw_token = ptr::null_mut();
    assert_ne!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                &mut raw_token,
            )
        },
        0
    );
    let token = native::Handle::new(raw_token).unwrap();
    let envelope = memcordon_windows_launch_core::query_token_envelope(token.0).unwrap();
    let job = native::Job::create(&format!(
        "O:{}D:P(A;;GA;;;{})",
        envelope.user_sid, envelope.user_sid
    ))
    .unwrap();
    let (stdin_read, stdin_write) = native::pipe().unwrap();
    let (stdout_read, stdout_write) = native::pipe().unwrap();
    let (stderr_read, stderr_write) = native::pipe().unwrap();
    for handle in [&stdin_write, &stdout_read, &stderr_read] {
        native::clear(handle.0).unwrap();
    }
    let command = memcordon_core::NativeWindowsCommandV1 {
        program: std::env::current_exe()
            .unwrap()
            .as_os_str()
            .encode_wide()
            .collect(),
        arguments: if modules {
            [
                "--exact",
                "workload_native::tests::mapped_module_child_role",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ]
            .into_iter()
            .map(|argument| argument.encode_utf16().collect())
            .collect()
        } else {
            vec!["--list".encode_utf16().collect()]
        },
    };
    let cwd: Vec<u16> = std::env::current_dir()
        .unwrap()
        .as_os_str()
        .encode_wide()
        .collect();
    let output = std::env::temp_dir().join(format!(
        "memcordon-resume-{}-{debug}-{fault:?}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&output).unwrap();
    let mut process = None;
    let mut owner = None;
    let mut resume_observation = None;
    let mut native_exit = None;
    let mut mapped_queries = Vec::new();
    let mut invalid_mapping = None;
    let mut module_base = None;
    let mut actual_creation_flags = None;
    let observation = (|| -> Result<(), String> {
        process = Some(native::spawn_checked(
            native::SpawnSpec {
                token: token.0,
                command: &command,
                environment: &[],
                cwd: &cwd,
                desktop: None,
                job: &job,
                handles: &[stdin_read.0, stdout_write.0, stderr_write.0],
                standard: true,
                descriptors: None,
                cleanup,
                debug: if debug {
                    native::DebugCreation::OnlyThisProcess(&output)
                } else {
                    native::DebugCreation::None
                },
            },
            |checkpoint| {
                if fault == Some(checkpoint) {
                    Err(format!("injected post-create checkpoint {checkpoint:?}"))
                } else {
                    Ok(())
                }
            },
        )?);
        let process = process.as_mut().expect("held fixture process");
        owner = process.debugger.take();
        actual_creation_flags = Some(process.creation_flags);
        if Instant::now() >= work {
            return Err("fixture work cutoff before resume".into());
        }
        unsafe {
            SetLastError(122);
        }
        resume_observation = Some(native::resume(
            process,
            "native-api-fixture",
            if debug {
                "debug-at-creation"
            } else {
                "without-debugger"
            },
            debug,
        )?);
        eprintln!("native-resume-measured-before-policy: {resume_observation:?}");
        resume_observation
            .as_ref()
            .unwrap()
            .result
            .require_exact_one()?;
        let (mut out, mut err, mut out_omitted, mut err_omitted) = (Vec::new(), Vec::new(), 0, 0);
        loop {
            if Instant::now() >= work {
                return Err("fixture work deadline before natural completion".into());
            }
            native::drain(stdout_read.0, &mut out, &mut out_omitted)?;
            native::drain(stderr_read.0, &mut err, &mut err_omitted)?;
            if let Some(owner) = owner.as_mut() {
                if modules {
                    owner.poll_checked(process.process.0, work, native::DebugPhase::Work, |owner,event| {
                        if event.dwDebugEventCode == windows_sys::Win32::System::Diagnostics::Debug::LOAD_DLL_DEBUG_EVENT {
                            if mapped_queries.len() >= 32 {return Err("native module fixture query bound exceeded".into());}
                            let pending = owner.pending;
                            let base = unsafe{event.u.LoadDll.lpBaseOfDll} as usize as u64;
                            let query = owner.observe_module_identity(process.process.0,base,ptr::null_mut(),work);
                            mapped_queries.push((base,query));
                            if invalid_mapping.is_none() {
                                invalid_mapping = Some(owner.observe_module_identity(process.process.0,0,ptr::null_mut(),work));
                            }
                            if pending.is_none() || owner.pending != pending {
                                return Err("optional mapped query changed pending debug ownership".into());
                            }
                        }
                        Ok(())
                    })?;
                    if owner.pending.is_some() {
                        return Err("mapped query event was not continued".into());
                    }
                } else {
                    owner.poll(process.process.0, work, native::DebugPhase::Work)?;
                }
                if let Some(exit) = owner.exit {
                    native_exit = Some(exit);
                    break;
                }
            } else if unsafe {
                windows_sys::Win32::System::Threading::WaitForSingleObject(process.process.0, 0)
            } == WAIT_OBJECT_0
            {
                native_exit = Some(
                    unsafe {
                        memcordon_windows_loader_lab::holder_protocol::query_exit(process.process.0)
                    }
                    .map_err(|error| error.to_string())?,
                );
                break;
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        native::drain(stdout_read.0, &mut out, &mut out_omitted)?;
        if out.is_empty() {
            return Err("actual fixture entry produced no libtest list output".into());
        }
        if modules {
            module_base = std::str::from_utf8(&out)
                .map_err(|error| error.to_string())?
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find(|row| row["format"] == "memcordon.mapped-module-native-fixture")
                .and_then(|row| row["base"].as_u64());
            if module_base.is_none() {
                return Err("known DLL fixture supplied no bound module base".into());
            }
        }
        eprintln!(
            "native-resume-work exit={native_exit:?} stdout-bytes={} stderr-bytes={} omitted={out_omitted}/{err_omitted}",
            out.len(),
            err.len()
        );
        Ok(())
    })();
    // Preserve the raw result before interpretation, then settle every owned
    // native obligation before any assertion can unwind the debugger owner.
    eprintln!("native-resume-observation debug={debug}: {observation:?}");
    let termination_request =
        serde_json::json!({"requested":true,"phase":"cleanup","code":native::FAILURE});
    eprintln!("native-resume-fixture termination={termination_request}");
    let terminated = job.terminate(native::FAILURE);
    let debug_settled = match (owner.as_mut(), process.as_ref()) {
        (Some(owner), Some(process)) => owner.settle(process.process.0, cleanup),
        _ => Ok(()),
    };
    let waited = process
        .as_ref()
        .map(|process| native::wait(process.process.0, cleanup));
    let empty = job.wait_empty(cleanup);
    let rollback = fault.map(|_| {
        std::fs::read(output.join("post-create-rollback.json"))
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                serde_json::from_slice::<serde_json::Value>(&bytes)
                    .map_err(|error| error.to_string())
            })
    });
    // Keep the emergency-publication parent if debugger settlement failed.
    let removed_output = if debug_settled.is_ok() {
        std::fs::remove_dir_all(&output)
    } else {
        Ok(())
    };
    if let Some(owner) = owner.as_ref() {
        eprintln!(
            "native-resume-fixture cleanup event_count={} exit={:?} observation_phase={:?}",
            owner.events.len(),
            owner.exit,
            owner.exit_phase
        );
    }
    assert!(
        terminated.is_ok()
            && debug_settled.is_ok()
            && waited.as_ref().is_none_or(Result::is_ok)
            && matches!(empty, Ok(true)),
        "cleanup terminate={terminated:?} debug={debug_settled:?} wait={waited:?} empty={empty:?}"
    );
    removed_output.unwrap();
    if let Some(checkpoint) = fault {
        assert!(
            resume_observation.is_none(),
            "early failure must precede any resume"
        );
        let error = observation.unwrap_err();
        assert!(
            error.contains(&format!("injected post-create checkpoint {checkpoint:?}")),
            "{error}"
        );
        let rollback = rollback.unwrap().unwrap();
        assert_eq!(rollback["debug_creation"], "only-this-process");
        assert_eq!(rollback["debug_settlement"], "Ok(())");
        assert_eq!(rollback["held_process_settlement"], "Ok(())");
        assert_eq!(rollback["exit_phase"], "cleanup");
        assert_eq!(rollback["termination_request"]["code"], native::FAILURE);
        assert_eq!(rollback["termination_request"]["succeeded"], true);
        assert_eq!(rollback["exit"], native::FAILURE);
        assert_ne!(
            rollback["creation_flags"].as_u64().unwrap()
                & u64::from(windows_sys::Win32::System::Threading::DEBUG_ONLY_THIS_PROCESS),
            0
        );
        assert!(!rollback["events"].as_array().unwrap().is_empty());
        assert!(
            rollback["events"]
                .as_array()
                .unwrap()
                .iter()
                .all(|event| event["observation_phase"] == "cleanup")
        );
        assert!(rollback["pid"].as_u64().unwrap() > 0 && rollback["tid"].as_u64().unwrap() > 0);
        match checkpoint {
            native::CreationCheckpoint::Created => assert!(rollback["birth"].is_null()),
            native::CreationCheckpoint::Validated => {
                assert!(rollback["birth"].as_u64().unwrap() > 0)
            }
        }
        return;
    }
    observation.unwrap();
    let flags = actual_creation_flags.unwrap();
    assert_eq!(
        flags & windows_sys::Win32::System::Threading::DEBUG_ONLY_THIS_PROCESS,
        if debug {
            windows_sys::Win32::System::Threading::DEBUG_ONLY_THIS_PROCESS
        } else {
            0
        }
    );
    assert_ne!(
        flags & windows_sys::Win32::System::Threading::CREATE_SUSPENDED,
        0
    );
    assert_eq!(
        native_exit,
        Some(0),
        "fixture must finish naturally before cleanup"
    );
    if let Some(owner) = owner.as_ref() {
        assert!(matches!(owner.exit_phase, Some(native::DebugPhase::Work)));
        assert!(
            owner
                .events
                .iter()
                .any(|event| event["observation_phase"] == "work")
        );
        assert!(owner.events.iter().any(|event| event["event"]
            == windows_sys::Win32::System::Diagnostics::Debug::CREATE_PROCESS_DEBUG_EVENT));
        if modules {
            let base = module_base.unwrap();
            let loaded = owner
                .events
                .iter()
                .find(|event| {
                    event["event"]
                        == windows_sys::Win32::System::Diagnostics::Debug::LOAD_DLL_DEBUG_EVENT
                        && event["base"] == base
                })
                .expect("actual known DLL load event");
            let unloaded = owner
                .events
                .iter()
                .find(|event| {
                    event["event"]
                        == windows_sys::Win32::System::Diagnostics::Debug::UNLOAD_DLL_DEBUG_EVENT
                        && event["base"] == base
                })
                .expect("actual known DLL unload event");
            assert_eq!(loaded["observation_phase"], "work");
            assert_eq!(unloaded["observation_phase"], "work");
            assert_eq!(unloaded["module_unload"]["outcome"], "Matched");
            assert_eq!(
                unloaded["module_unload"]["generation"],
                loaded["module"]["association"]["generation"]
            );
            assert_eq!(
                unloaded["module_unload"]["load_sequence"],
                loaded["module"]["association"]["load_sequence"]
            );
            let (_, query) = mapped_queries
                .iter()
                .find(|(address, _)| *address == base)
                .expect("same collector simulated-null query at actual known DLL base");
            eprintln!("native mapped module simulated-null input: {query}");
            assert_eq!(query["event_file_handle"], "absent");
            assert_eq!(query["mapped_name"]["status"], "queried");
            assert_eq!(query["mapped_name"]["name"]["outcome"], "Complete");
            assert!(
                query["mapped_name"]["name"]["path"]
                    .as_str()
                    .unwrap()
                    .to_ascii_lowercase()
                    .ends_with("\\version.dll")
            );
            let invalid = invalid_mapping.unwrap();
            assert_eq!(invalid["mapped_name"]["name"]["outcome"], "NativeFailure");
            assert!(
                invalid["mapped_name"]["name"]["native_error"]
                    .as_u64()
                    .is_some()
            );
            assert!(owner.pending.is_none());
        }
    }
    let observation = resume_observation.unwrap();
    assert_eq!(observation.call_ordinal, 1);
    assert_eq!(observation.expected_previous_count, 1);
    assert_eq!(observation.debugger_attached, debug);
    assert!(observation.pid > 0 && observation.birth > 0 && observation.tid > 0);
    assert_eq!(
        observation.result.require_exact_one().is_ok(),
        observation.result.raw_return == 1
    );
    if observation.result.raw_return != u32::MAX {
        assert_eq!(observation.result.native_error, None);
    }
    observation.result.require_exact_one().unwrap();
}

#[test]
fn actual_suspended_spawn_single_resume_without_debugger() {
    retained_spawn_resume_fixture(false, None, false);
}

#[test]
fn actual_debug_at_creation_single_resume_reaches_natural_work_exit() {
    retained_spawn_resume_fixture(true, None, false);
}

#[test]
fn actual_debug_creation_rollback_before_birth_drains_and_retires() {
    retained_spawn_resume_fixture(true, Some(native::CreationCheckpoint::Created), false);
}

#[test]
fn actual_debug_creation_rollback_after_validation_drains_and_retires() {
    retained_spawn_resume_fixture(true, Some(native::CreationCheckpoint::Validated), false);
}

#[test]
fn actual_mapped_dll_name_null_handle_query_and_unload_lineage_continue_pending_events() {
    retained_spawn_resume_fixture(true, None, true);
}

#[test]
#[ignore = "native mapped-module child role invoked only by the owned debug fixture"]
fn mapped_module_child_role() {
    use std::io::Write;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::System::{LibraryLoader::*, SystemInformation::GetSystemDirectoryW};
    let mut directory = [0_u16; 4096];
    let length = unsafe { GetSystemDirectoryW(directory.as_mut_ptr(), directory.len() as u32) };
    assert!(length > 0 && (length as usize) < directory.len());
    let path =
        std::path::PathBuf::from(std::ffi::OsString::from_wide(&directory[..length as usize]))
            .join("version.dll");
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    assert!(
        unsafe { GetModuleHandleW(wide.as_ptr()) }.is_null(),
        "known DLL fixture must begin unloaded"
    );
    let module = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    assert!(!module.is_null());
    println!(
        "\n{}",
        serde_json::json!({"format":"memcordon.mapped-module-native-fixture","base":module as usize as u64})
    );
    std::io::stdout().flush().unwrap();
    assert_ne!(unsafe { FreeLibrary(module) }, 0);
}
