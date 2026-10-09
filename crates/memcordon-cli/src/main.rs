mod commands;
mod presentation;

use memcordon::invocation::{
    CLEAN_USAGE, DOCTOR_USAGE, HelpKind, Invocation, PLAN_USAGE, ROOT_USAGE, route,
};
use presentation::Presentation;

fn main() {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    #[cfg(all(target_os = "windows", feature = "test-support"))]
    if argv
        .first()
        .is_some_and(|argument| argument == "__windows-certification")
    {
        std::process::exit(execute_windows_certification(&argv));
    }
    #[cfg(all(target_os = "macos", feature = "test-fixtures"))]
    let argv = if argv
        .first()
        .is_some_and(|arg| arg == "__delivery-observed-v1")
    {
        let descriptor = argv
            .get(1)
            .and_then(|value| value.to_str())
            .and_then(|value| value.parse().ok());
        if descriptor
            .and_then(|fd| commands::observe_failures(fd).ok())
            .is_none()
        {
            std::process::exit(126);
        }
        argv.into_iter().skip(2).collect()
    } else {
        argv
    };
    #[cfg(target_os = "windows")]
    if let [command, pid, birth] = argv.as_slice() {
        if command == "__observe-windows-guardian" {
            std::process::exit(commands::windows_guardian_observation(pid, birth));
        }
    }
    if let Some(internal) = commands::route_internal(&argv) {
        let code = match internal {
            Ok(internal) => commands::execute_internal(internal),
            Err(message) => {
                eprintln!("error[MCCLI-INTERNAL-PROTOCOL]: {message}");
                2
            }
        };
        std::process::exit(code);
    }
    let presentation = Presentation::automatic();
    let code = match route(&argv) {
        Ok(Invocation::Execute(args)) => execute_with_terminal_observation(args, &presentation),
        Ok(Invocation::WindowsRecovery(args)) => commands::windows_recovery(args),
        Ok(Invocation::Doctor(args)) => commands::doctor(args, &presentation),
        Ok(Invocation::Plan(args)) => commands::plan(args, &presentation),
        Ok(Invocation::Clean(args)) => commands::clean(args, &presentation),
        Ok(Invocation::Version) => {
            let mut out = presentation.stdout();
            presentation::write_version(&mut out, env!("CARGO_PKG_VERSION"))
                .expect("version output should be writable");
            0
        }
        Ok(Invocation::Help(kind)) => {
            let help = match kind {
                HelpKind::Root => ROOT_USAGE,
                HelpKind::Doctor => DOCTOR_USAGE,
                HelpKind::Plan => PLAN_USAGE,
                HelpKind::Clean => CLEAN_USAGE,
            };
            let mut out = presentation.stdout();
            presentation::write_help(&mut out, help).expect("help output should be writable");
            0
        }
        Err(error) if error.code == "MCCLI-HELP" => {
            let mut out = presentation.stdout();
            presentation::write_help(&mut out, &error.message)
                .expect("topic help output should be writable");
            0
        }
        Err(error) => {
            let mut out = presentation.stderr();
            presentation::write_usage_error(&mut out, error.code, &error.message)
                .expect("usage diagnostic should be writable");
            if let Some(help) = error.help {
                presentation::write_help(&mut out, help).expect("usage help should be writable");
            }
            2
        }
    };
    std::process::exit(code);
}

#[cfg(all(target_os = "windows", feature = "test-support"))]
fn execute_windows_certification(argv: &[std::ffi::OsString]) -> i32 {
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let operation = (|| -> Result<i32, String> {
        let selection_path = argv.get(1).ok_or("certification selection path missing")?;
        let observation_path = argv
            .get(2)
            .ok_or("certification observation path missing")?;
        let mut input = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(selection_path)
            .map_err(|error| error.to_string())?;
        let mut selection = Vec::new();
        std::io::Read::by_ref(&mut input)
            .take(4097)
            .read_to_end(&mut selection)
            .map_err(|error| error.to_string())?;
        if selection.len() > 4096 {
            return Err("certification selection exceeds bound".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(&selection)?;
        let scope = memcordon_platform::WindowsCertificationScope::begin_persisted(
            serde_json::from_slice(&selection).map_err(|error| error.to_string())?,
            std::path::Path::new(observation_path),
        )?;
        let execution = if argv
            .get(3)
            .is_some_and(|argument| argument == "--controller-start-gate")
        {
            use std::os::windows::{
                ffi::OsStrExt,
                io::{AsRawHandle, FromRawHandle},
            };
            use windows_sys::Win32::System::Threading::{OpenEventW, WaitForSingleObject};
            let name = argv
                .get(4)
                .ok_or("component controller gate name missing")?;
            let wide: Vec<_> = name.encode_wide().collect();
            if wide.is_empty() || wide.len() > 240 || wide.contains(&0) {
                return Err("component controller gate name invalid".into());
            }
            let wide: Vec<_> = wide.into_iter().chain(Some(0)).collect();
            // SAFETY: bounded terminated native name; synchronization-only owned event.
            let raw = unsafe { OpenEventW(0x00100000, 0, wide.as_ptr()) };
            if raw.is_null() {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let gate = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
            if unsafe { WaitForSingleObject(gate.as_raw_handle(), 90000) }
                != windows_sys::Win32::Foundation::WAIT_OBJECT_0
            {
                return Err(
                    "component controller did not release held frontend before deadline".into(),
                );
            }
            argv.get(5..).ok_or("component execution argv missing")?
        } else {
            argv.get(3..)
                .ok_or("certification execution argv missing")?
        };
        let presentation = Presentation::automatic();
        let code = match route(execution) {
            Ok(Invocation::Execute(args)) => commands::execute(args, &presentation),
            _ => return Err("certification requires typed execution argv".into()),
        };
        let observation = scope.finish()?;
        let bytes = serde_json::to_vec(&observation).map_err(|error| error.to_string())?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err("certification observation exceeds bound".into());
        }
        memcordon_core::write_report_bytes_atomic(std::path::Path::new(observation_path), &bytes)
            .map_err(|error| error.to_string())?;
        let mut named = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(observation_path)
            .map_err(|error| error.to_string())?;
        let mut readback = Vec::new();
        named
            .take((bytes.len() + 1) as u64)
            .read_to_end(&mut readback)
            .map_err(|error| error.to_string())?;
        if readback != bytes {
            return Err("certification named observation readback differs".into());
        }
        Ok(code)
    })();
    match operation {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error[MCCLI-WINDOWS-CERTIFICATION]: {error}");
            126
        }
    }
}

fn execute_with_terminal_observation(
    args: memcordon::invocation::ExecutionArgs,
    presentation: &Presentation,
) -> i32 {
    #[cfg(target_os = "linux")]
    let _mixed_observation_scope = match args.output.mixed_observation_directory.as_deref() {
        Some(directory) => match memcordon_platform::MixedObservationScope::install(directory) {
            Ok(scope) => Some(scope),
            Err(error) => {
                eprintln!("error[MCCLI-MIXED-OBSERVATION]: {error}");
                return 126;
            }
        },
        None => None,
    };
    #[cfg(windows)]
    if let Some(path) = &args.output.windows_request_observation {
        let path = match std::path::absolute(path) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("error[MCCLI-WINDOWS-OBSERVATION]: {error}");
                return 126;
            }
        };
        let scope =
            match memcordon_platform::WindowsTerminalObservationScope::begin_with_request_path(
                &path,
            ) {
                Ok(scope) => scope,
                Err(error) => {
                    eprintln!("error[MCCLI-WINDOWS-OBSERVATION]: {error}");
                    return 126;
                }
            };
        let status = commands::execute(args, presentation);
        if let Err(error) = scope.finish_request() {
            eprintln!("error[MCCLI-WINDOWS-OBSERVATION]: {error}");
            return 126;
        }
        return status;
    }
    #[cfg(windows)]
    if let Some(path) = &args.output.windows_terminal_observation {
        use std::io::{Read, Write};
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT, GetFileInformationByHandle,
        };
        let destination = path.clone();
        // Reserve the output before launch. It cannot overwrite a prior attempt
        // and the open handle is excluded from the provider's target handle list.
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(file) => file,
            Err(error) => {
                eprintln!("error[MCCLI-WINDOWS-OBSERVATION]: {error}");
                return 126;
            }
        };
        let request_path = match std::path::absolute(path)
            .map(|path| path.with_extension("provider-request.bin"))
        {
            Ok(path) => path,
            Err(error) => {
                eprintln!("error[MCCLI-WINDOWS-OBSERVATION]: {error}");
                return 126;
            }
        };
        let scope =
            match memcordon_platform::WindowsTerminalObservationScope::begin_with_request_path(
                &request_path,
            ) {
                Ok(scope) => scope,
                Err(error) => {
                    eprintln!("error[MCCLI-WINDOWS-OBSERVATION]: {error}");
                    return 126;
                }
            };
        let status = commands::execute(args, presentation);
        let write = scope.finish().and_then(|observation| {
            memcordon_core::bounded_json_bytes(&observation, memcordon_platform::MAX_TERMINAL_OBSERVATION_BYTES, true)
                .map_err(|error| error.to_string())
        }).and_then(|bytes| {
            file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(|error| error.to_string())?;
            let mut named = std::fs::OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&destination).map_err(|error| error.to_string())?;
            let mut held_identity = BY_HANDLE_FILE_INFORMATION::default();
            let mut named_identity = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: both files are independently held native handles; each
            // writable identity buffer has the exact API structure layout.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut held_identity) } == 0
                || unsafe { GetFileInformationByHandle(named.as_raw_handle(), &mut named_identity) } == 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if (held_identity.dwVolumeSerialNumber, held_identity.nFileIndexHigh, held_identity.nFileIndexLow)
                != (named_identity.dwVolumeSerialNumber, named_identity.nFileIndexHigh, named_identity.nFileIndexLow)
                || named_identity.dwFileAttributes & 0x400 != 0 {
                return Err("terminal observation destination no longer names the reserved ordinary file".into());
            }
            let mut persisted = Vec::new();
            std::io::Read::by_ref(&mut named).take(memcordon_platform::MAX_TERMINAL_OBSERVATION_BYTES as u64 + 1)
                .read_to_end(&mut persisted).map_err(|error| error.to_string())?;
            if persisted != bytes { return Err("terminal observation named-file readback differs".into()); }
            Ok(())
        });
        if let Err(error) = write {
            eprintln!("error[MCCLI-WINDOWS-OBSERVATION]: {error}");
            return 126;
        }
        return status;
    }
    commands::execute(args, presentation)
}
