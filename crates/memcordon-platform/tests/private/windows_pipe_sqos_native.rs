//! Native fixture only. No production connection flags or protocol are changed.
#![allow(unsafe_code)]
use super::{client_input, client_input_native, record};
use sha2::{Digest, Sha256};
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::RevertToSelf;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx, GetTokenInformation,
    SecurityImpersonation, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_STATISTICS,
    TokenImpersonation, TokenStatistics,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, ReadFile, WriteFile};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    SetThreadToken, WaitForSingleObject,
};

fn raw(handle: &OwnedHandle) -> windows_sys::Win32::Foundation::HANDLE {
    handle.as_raw_handle().cast()
}
fn live(cutoff: Instant) -> Result<(), String> {
    if Instant::now() < cutoff {
        Ok(())
    } else {
        Err("original SQOS fixture cutoff exhausted".into())
    }
}
fn last(stage: &str) -> String {
    format!("SQOS fixture {stage}: {}", io::Error::last_os_error())
}
fn join_owned<T>(worker: std::thread::JoinHandle<T>, cutoff: Instant) -> Result<T, String> {
    loop {
        let expired = Instant::now() >= cutoff;
        let wait = unsafe { WaitForSingleObject(worker.as_raw_handle().cast(), 0) };
        if wait == 0 {
            let value = worker.join().map_err(|_| "SQOS owned worker panicked")?;
            if expired {
                return Err("SQOS worker retirement observed after original cutoff".into());
            }
            live(cutoff)?;
            return Ok(value);
        }
        if expired || wait != 258 {
            unsafe {
                CancelSynchronousIo(worker.as_raw_handle().cast());
            }
            std::mem::forget(worker);
            return Err("SQOS worker retirement unproved; cancellation attempted and original native owner retained".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn fresh_pipe(label: &str, cutoff: Instant) -> Result<(OwnedHandle, Vec<u16>), String> {
    live(cutoff)?;
    let name: Vec<u16> = format!(
        "\\\\.\\pipe\\memcordon-sqos-fixture-{}-{label}-{}",
        unsafe { GetCurrentProcessId() },
        unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let pipe = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            3 | 0x80000,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            std::ptr::null(),
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(last("negative CreateNamedPipeW"));
    }
    Ok((unsafe { OwnedHandle::from_raw_handle(pipe.cast()) }, name))
}
fn connected_negative(label: &str, cutoff: Instant) -> Result<(OwnedHandle, OwnedHandle), String> {
    let (pipe, name) = fresh_pipe(label, cutoff)?;
    let deadline = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)?;
    let client = unsafe {
        CreateFileW(
            name.as_ptr(),
            record::DESIRED_ACCESS,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0x80,
            std::ptr::null_mut(),
        )
    };
    let error = if client == INVALID_HANDLE_VALUE {
        Some(last("negative CreateFileW"))
    } else {
        None
    };
    let stopped = deadline.finish();
    if let Some(error) = error {
        return Err(format!("{error}; deadline={stopped:?}"));
    }
    let client = unsafe { OwnedHandle::from_raw_handle(client.cast()) };
    stopped?;
    live(cutoff)?;
    if unsafe { ConnectNamedPipe(raw(&pipe), std::ptr::null_mut()) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
            return Err(format!("negative ConnectNamedPipe: {error}"));
        }
    }
    Ok((pipe, client))
}
fn negative_checks(cutoff: Instant) -> Result<record::NegativeChecks, String> {
    let (pipe, _) = fresh_pipe("authentication", cutoff)?;
    let authentication_worker = std::thread::spawn(move || -> Result<u32, String> {
        live(cutoff)?;
        let impersonated = unsafe { ImpersonateNamedPipeClient(raw(&pipe)) };
        if impersonated == 0 {
            Ok(io::Error::last_os_error()
                .raw_os_error()
                .ok_or("missing native authentication error")? as u32)
        } else {
            Revert(true).finish()?;
            Err("SQOS unconnected authentication unexpectedly succeeded".into())
        }
    });
    let authentication_rejected = join_owned(authentication_worker, cutoff)??;
    let (pipe, client) = connected_negative("disconnect", cutoff)?;
    drop(client);
    let deadline = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)?;
    let mut byte = 0;
    let mut read = 0;
    let result = unsafe { ReadFile(raw(&pipe), &mut byte, 1, &mut read, std::ptr::null_mut()) };
    let error = if result == 0 {
        io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    deadline.finish()?;
    let early_disconnect_rejected = error.ok_or("SQOS early disconnect was not rejected")? as u32;
    drop(pipe);
    let (pipe, client) = connected_negative("cancel", cutoff)?;
    let worker = std::thread::spawn(move || -> Result<u32, String> {
        let deadline = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)?;
        let mut byte = 0;
        let mut read = 0;
        let result = unsafe { ReadFile(raw(&pipe), &mut byte, 1, &mut read, std::ptr::null_mut()) };
        let error = if result == 0 {
            io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        deadline.finish()?;
        Ok(error.ok_or("SQOS pending read unexpectedly succeeded")? as u32)
    });
    // Cancel while the original budget is live; ERROR_NOT_FOUND before the
    // worker enters ReadFile is not mistaken for retirement or cancellation.
    loop {
        let wait = unsafe { WaitForSingleObject(worker.as_raw_handle().cast(), 0) };
        if wait == 0 {
            break;
        }
        if Instant::now() >= cutoff || wait != 258 {
            break;
        }
        unsafe {
            CancelSynchronousIo(worker.as_raw_handle().cast());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let pending_read_cancelled = join_owned(worker, cutoff)??;
    drop(client);
    if pending_read_cancelled != 995 {
        return Err(format!(
            "SQOS pending read cancellation returned native {pending_read_cancelled}"
        ));
    }
    Ok(record::NegativeChecks {
        authentication_rejected,
        early_disconnect_rejected,
        pending_read_cancelled,
    })
}
fn summary(sample: client_input::Sample, server: bool) -> Result<record::Summary, String> {
    match &sample {
        client_input::Sample::Missing {} => return Err("SQOS sample missing".into()),
        client_input::Sample::Unavailable {
            stage,
            native_win32_error,
        }
        | client_input::Sample::Observed {
            token:
                client_input::Token::Unavailable {
                    stage,
                    native_win32_error,
                },
            ..
        } => {
            return Err(format!(
                "SQOS sample unavailable stage={stage:?} native_win32_error={native_win32_error:?}"
            ));
        }
        _ => {}
    }
    let client_input::Sample::Observed {
        process,
        thread_id,
        token: client_input::Token::Observed { facts },
        ..
    } = sample
    else {
        return Err("SQOS token observation unavailable".into());
    };
    if server && facts.source != client_input::Source::ThreadToken {
        return Err(
            "SQOS server impersonation token missing; process fallback is not authentication"
                .into(),
        );
    }
    Ok(record::Summary {
        process_id: process.process_id,
        process_birth: process.creation_time_100ns,
        thread_id,
        token_id: facts.token_id,
        modified_id: facts.modified_id,
        authentication_id: facts.authentication_id,
        token_type: facts.token_type,
        impersonation_level: facts.impersonation_level,
        total: facts.privileges.total_count,
        enabled: facts.privileges.enabled_count,
        all_sha256: facts.privileges.all_sha256,
        enabled_sha256: facts.privileges.enabled_sha256,
    })
}
struct Revert(bool);
impl Revert {
    fn finish(mut self) -> Result<(), String> {
        if unsafe { RevertToSelf() } == 0 {
            return Err(last("RevertToSelf"));
        }
        self.0 = false;
        Ok(())
    }
}
impl Drop for Revert {
    fn drop(&mut self) {
        if self.0 {
            unsafe {
                RevertToSelf();
            }
        }
    }
}

fn server(
    pipe: OwnedHandle,
    message: [u8; 32],
    pid: u32,
    cutoff: Instant,
) -> Result<record::Summary, String> {
    let deadline = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)?;
    let result = (|| {
        live(cutoff)?;
        if unsafe { ConnectNamedPipe(raw(&pipe), std::ptr::null_mut()) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                return Err(format!("SQOS ConnectNamedPipe: {error}"));
            }
        }
        let mut actual_pid = 0;
        if unsafe { GetNamedPipeClientProcessId(raw(&pipe), &mut actual_pid) } == 0 {
            return Err(last("GetNamedPipeClientProcessId"));
        }
        if actual_pid != pid {
            return Err("SQOS pipe client identity mismatch".into());
        }
        let mut bytes = [0u8; 32];
        let mut read = 0;
        live(cutoff)?;
        if unsafe {
            ReadFile(
                raw(&pipe),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(last("ReadFile"));
        }
        if read as usize != message.len() || bytes != message {
            return Err("SQOS message mismatch before impersonation".into());
        }
        live(cutoff)?;
        if unsafe { ImpersonateNamedPipeClient(raw(&pipe)) } == 0 {
            return Err(last("ImpersonateNamedPipeClient"));
        }
        let revert = Revert(true);
        let measured = summary(client_input_native::capture(cutoff), true);
        let restored = revert.finish();
        match (measured, restored) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(a), Err(b)) => Err(format!("{a}; {b}")),
            (Err(a), _) => Err(a),
            (_, Err(b)) => Err(b),
        }
    })();
    let stopped = deadline.finish();
    match (result, stopped) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(a), Err(b)) => Err(format!("{a}; {b}")),
        (Err(a), _) => Err(a),
        (_, Err(b)) => Err(b),
    }
}

pub fn run() -> Result<(), String> {
    let result = run_inner();
    if let Err(error) = &result {
        // Fixed redacted errors above contain no raw token, endpoint, SID or
        // environment. Publication failure must not replace the native error.
        let detail = if error.len() <= 1024 {
            error.as_str()
        } else {
            "bounded native fixture diagnostic overflow"
        };
        let gap = serde_json::json!({"revision":1,"state":"unavailable","detail":detail});
        use std::io::Write;
        let _ = writeln!(std::io::stdout(), "{}{gap}", record::GAP_MARKER);
    }
    result
}
fn run_inner() -> Result<(), String> {
    let cutoff = Instant::now()
        .checked_add(Duration::from_secs(10))
        .ok_or("SQOS cutoff overflow")?;
    let pid = unsafe { GetCurrentProcessId() };
    let negative_checks = negative_checks(cutoff)?;
    // Retain the exact effective caller token for the entire five-row fixture.
    live(cutoff)?;
    let mut token = std::ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(1008) {
            return Err(format!("SQOS held caller thread token: {error}"));
        }
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(last("held process token"));
        }
    }
    let held_token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
    let mut statistics: TOKEN_STATISTICS = unsafe { std::mem::zeroed() };
    let mut returned = 0;
    live(cutoff)?;
    if unsafe {
        GetTokenInformation(
            raw(&held_token),
            TokenStatistics,
            (&mut statistics as *mut TOKEN_STATISTICS).cast(),
            size_of::<TOKEN_STATISTICS>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(last("held token statistics"));
    }
    if returned as usize != size_of::<TOKEN_STATISTICS>() {
        return Err("SQOS held token statistics extent mismatch".into());
    }
    live(cutoff)?;
    let held_token_id =
        ((statistics.TokenId.HighPart as u32 as u64) << 32) | u64::from(statistics.TokenId.LowPart);
    let mut held_caller = None;
    for (ordinal, case) in record::Case::ALL.into_iter().enumerate() {
        live(cutoff)?;
        let name: Vec<u16> = format!(
            "\\\\.\\pipe\\memcordon-sqos-fixture-{pid}-{ordinal}-{}",
            unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                3 | 0x80000,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last("CreateNamedPipeW"));
        }
        let pipe = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
        let before_connect = summary(client_input_native::capture(cutoff), false)?;
        if before_connect.token_id != held_token_id {
            return Err("SQOS effective caller differs from held token".into());
        }
        if let Some(expected) = &held_caller {
            if expected != &before_connect {
                return Err("SQOS caller changed between rows".into());
            }
        } else {
            held_caller = Some(before_connect.clone());
        }
        let deadline = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)?;
        let client_handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                record::DESIRED_ACCESS, // Exact existing production PIPE_CLIENT_READ_WRITE request.
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                case.flags(),
                std::ptr::null_mut(),
            )
        };
        if client_handle == INVALID_HANDLE_VALUE {
            let error = last("CreateFileW");
            let stopped = deadline.finish();
            return Err(format!("{error}; deadline={stopped:?}"));
        }
        let client = unsafe { OwnedHandle::from_raw_handle(client_handle.cast()) };
        let before_write = summary(client_input_native::capture(cutoff), false)?;
        let message: [u8; 32] = Sha256::digest(
            name.iter()
                .flat_map(|unit| unit.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .into();
        let mut written = 0;
        live(cutoff)?;
        let write = unsafe {
            WriteFile(
                raw(&client),
                message.as_ptr(),
                message.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        let write_error = if write == 0 {
            Some(last("WriteFile"))
        } else {
            None
        };
        let after_write = summary(client_input_native::capture(cutoff), false);
        let stopped = deadline.finish();
        if let Some(error) = write_error {
            return Err(format!("{error}; deadline={stopped:?}"));
        }
        stopped?;
        if written as usize != message.len() {
            return Err("SQOS incomplete fixture write".into());
        }
        let after_write = after_write?;
        let worker = std::thread::spawn(move || server(pipe, message, pid, cutoff));
        let server = join_owned(worker, cutoff)??;
        live(cutoff)?;
        drop(client);
        let row = record::Row {
            desired_access: record::DESIRED_ACCESS,
            share_mode: 0,
            open_disposition: OPEN_EXISTING,
            negative_checks,
            revision: 1,
            case,
            flags: case.flags(),
            digest_kind: "length-prefixed-le-luid-attributes-v1".into(),
            tracking: "unmeasured-stationary-context".into(),
            inventory: record::classify(&before_write, &server),
            before_connect,
            before_write,
            after_write,
            server,
            message_sha256: Sha256::digest(message).into(),
            message_read: true,
            server_thread_token: true,
            reverted: true,
            worker_retired: true,
        };
        let json = record::encode(&row).map_err(|error| error.to_string())?;
        println!("{}{json}", record::MARKER);
        // The CI owner forwards all five measurements before verify_rows
        // asserts preservation. Actual I/O/cleanup failures still fail here.
    }
    for case in record::TrackingCase::ALL {
        live(cutoff)?;
        let worker = std::thread::spawn(move || tracking_client(case, held_token_id, cutoff));
        let mut row = join_owned(worker, cutoff)??;
        row.worker_retired = true;
        let json = record::encode_tracking(&row).map_err(|error| error.to_string())?;
        println!("{}{json}", record::TRACKING_MARKER);
    }
    live(cutoff)
}

fn primary_context(cutoff: Instant) -> Result<record::Summary, String> {
    let sample = client_input_native::capture(cutoff);
    if matches!(&sample,client_input::Sample::Observed{token:client_input::Token::Observed{facts},..} if facts.source==client_input::Source::ThreadToken)
    {
        // Never clear a pre-existing thread token to manufacture the baseline.
        return Err("SQOS tracking C0 requires observed ERROR_NO_TOKEN/process-primary; initial context preserved".into());
    }
    summary(sample, false)
}

fn tracking_client(
    case: record::TrackingCase,
    held_primary_id: u64,
    cutoff: Instant,
) -> Result<record::TrackingRow, String> {
    let initial = primary_context(cutoff)?;
    live(cutoff)?;
    let mut handle = std::ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut handle,
        )
    } == 0
    {
        return Err(last("tracking explicit primary duplication rights"));
    }
    let source = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
    let mut statistics: TOKEN_STATISTICS = unsafe { std::mem::zeroed() };
    let mut returned = 0;
    live(cutoff)?;
    if unsafe {
        GetTokenInformation(
            raw(&source),
            TokenStatistics,
            (&mut statistics as *mut TOKEN_STATISTICS).cast(),
            size_of::<TOKEN_STATISTICS>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(last("tracking source statistics"));
    }
    let identity =
        ((statistics.TokenId.HighPart as u32 as u64) << 32) | u64::from(statistics.TokenId.LowPart);
    if returned as usize != size_of::<TOKEN_STATISTICS>()
        || identity != initial.token_id
        || identity != held_primary_id
    {
        return Err("SQOS tracking duplicate source differs from exact held C0".into());
    }
    let mut reduced = std::ptr::null_mut();
    live(cutoff)?;
    if unsafe {
        CreateRestrictedToken(
            raw(&source),
            DISABLE_MAX_PRIVILEGE,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut reduced,
        )
    } == 0
    {
        return Err(last("tracking reduced token"));
    }
    let reduced = unsafe { OwnedHandle::from_raw_handle(reduced.cast()) };
    let mut impersonation = std::ptr::null_mut();
    live(cutoff)?;
    if unsafe {
        DuplicateTokenEx(
            raw(&reduced),
            TOKEN_QUERY | TOKEN_IMPERSONATE,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut impersonation,
        )
    } == 0
    {
        return Err(last("tracking owned reduced impersonation token"));
    }
    let writer = unsafe { OwnedHandle::from_raw_handle(impersonation.cast()) };
    let (pipe, name) = fresh_pipe(&format!("tracking-{case:?}"), cutoff)?;
    let connect = primary_context(cutoff)?;
    if connect != initial {
        return Err("SQOS tracking primary changed before connection".into());
    }
    let deadline = memcordon_platform::WindowsSynchronousIoDeadline::start(cutoff)?;
    live(cutoff)?;
    let client = unsafe {
        CreateFileW(
            name.as_ptr(),
            record::DESIRED_ACCESS,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            case.flags(),
            std::ptr::null_mut(),
        )
    };
    if client == INVALID_HANDLE_VALUE {
        let error = last("tracking CreateFileW");
        let stopped = deadline.finish();
        return Err(format!("{error}; deadline={stopped:?}"));
    }
    let client = unsafe { OwnedHandle::from_raw_handle(client.cast()) };
    if primary_context(cutoff)? != connect {
        return Err("SQOS tracking primary changed at connection".into());
    }
    live(cutoff)?;
    if unsafe { SetThreadToken(std::ptr::null(), raw(&writer)) } == 0 {
        return Err(last("tracking install reduced writer context"));
    }
    let restore = Revert(true);
    let operation = (|| {
        let write = summary(client_input_native::capture(cutoff), true)?;
        if write.enabled_sha256 == connect.enabled_sha256 {
            return Err("SQOS tracking enabled contexts indistinguishable".into());
        }
        let message: [u8; 32] = Sha256::digest(
            name.iter()
                .flat_map(|unit| unit.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .into();
        let mut written = 0;
        live(cutoff)?;
        let written_ok = unsafe {
            WriteFile(
                raw(&client),
                message.as_ptr(),
                message.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        let write_error = if written_ok == 0 {
            Some(last("tracking WriteFile"))
        } else {
            None
        };
        let post_write = summary(client_input_native::capture(cutoff), true);
        let stopped = deadline.finish();
        if let Some(error) = write_error {
            return Err(format!("{error}; deadline={stopped:?}"));
        }
        stopped?;
        if written as usize != message.len() {
            return Err("SQOS tracking incomplete message write".into());
        }
        let post_write = post_write?;
        let pid = connect.process_id;
        let worker = std::thread::spawn(move || server(pipe, message, pid, cutoff));
        // C1 remains installed until this exact server has read, impersonated,
        // captured and reverted, and its original worker has actually retired.
        let server = join_owned(worker, cutoff)??;
        Ok((write, post_write, server, Sha256::digest(message).into()))
    })();
    let restoration = (|| {
        restore.finish()?;
        let restored = primary_context(cutoff)?;
        if restored != connect {
            return Err("SQOS tracking restoration changed original primary".into());
        }
        Ok(restored)
    })();
    let ((write, post_write, server, message_sha256), restored) = match (operation, restoration) {
        (Ok(value), Ok(restored)) => (value, restored),
        (Err(primary), Err(secondary)) => {
            return Err(format!("{primary}; restoration: {secondary}"));
        }
        (Err(primary), _) => return Err(primary),
        (_, Err(secondary)) => return Err(secondary),
    };
    drop(client);
    live(cutoff)?;
    Ok(record::TrackingRow {
        revision: 1,
        case,
        flags: case.flags(),
        desired_access: record::DESIRED_ACCESS,
        share_mode: 0,
        open_disposition: OPEN_EXISTING,
        experiment: "thread-context-replacement".into(),
        digest_kind: "length-prefixed-le-luid-attributes-v1".into(),
        inventory: record::classify_tracking(&connect, &write, &server),
        connect,
        write,
        post_write,
        restored,
        server,
        message_sha256,
        connect_no_thread_token: true,
        restored_no_thread_token: true,
        writer_context_held_through_server_snapshot: true,
        message_read: true,
        server_thread_token: true,
        reverted: true,
        worker_retired: false,
    })
}
