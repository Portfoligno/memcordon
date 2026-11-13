//! Query-only snapshots on the thread that actually connects and writes.
use super::client_input::*;
use memcordon_core::WindowsProcessIdentityV1;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::{io, ptr, time::Instant};
use windows_sys::Win32::{
    Foundation::{FILETIME, GetLastError, INVALID_HANDLE_VALUE, SetLastError},
    Security::{
        GetTokenInformation, LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_STATISTICS,
        TokenPrivileges, TokenStatistics,
    },
    System::{
        SystemInformation::GetTickCount64,
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId,
            GetProcessTimes, OpenProcessToken, OpenThreadToken,
        },
    },
};

type Failure = (Stage, Option<i32>);
fn guard(cutoff: Instant) -> Result<(), Failure> {
    if Instant::now() >= cutoff {
        Err((Stage::Cutoff, None))
    } else {
        Ok(())
    }
}
fn failed(stage: Stage) -> Failure {
    (stage, io::Error::last_os_error().raw_os_error())
}
fn luid(value: windows_sys::Win32::Foundation::LUID) -> u64 {
    u64::from(value.LowPart) | (u64::from(value.HighPart as u32) << 32)
}
fn token(cutoff: Instant) -> Result<TokenFacts, Failure> {
    guard(cutoff)?;
    let mut raw = ptr::null_mut();
    // SAFETY: this pseudo handle identifies this actual calling thread. Query
    // only, OpenAsSelf=false; no impersonation, duplication or adjustment.
    let source = if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut raw) } == 0 {
        let error = failed(Stage::ThreadTokenOpen);
        if !permits_process_fallback(error.1) {
            return Err(error);
        }
        guard(cutoff)?;
        // SAFETY: process primary is a separately labelled fallback only for
        // native ERROR_NO_TOKEN, never for an access denial or missing query.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(failed(Stage::ProcessTokenOpen));
        }
        Source::ProcessPrimaryAfterNoThreadToken
    } else {
        Source::ThreadToken
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err((Stage::Extent, None));
    }
    // SAFETY: successful native query-open transfers this sole token owner.
    let held = unsafe { OwnedHandle::from_raw_handle(raw) };
    guard(cutoff)?;
    let mut statistics = TOKEN_STATISTICS::default();
    let mut returned = 0;
    // SAFETY: fixed native statistics output is initialized and SDK-sized.
    if unsafe {
        GetTokenInformation(
            held.as_raw_handle(),
            TokenStatistics,
            (&mut statistics as *mut TOKEN_STATISTICS).cast(),
            size_of::<TOKEN_STATISTICS>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(failed(Stage::Statistics));
    }
    guard(cutoff)?;
    if returned as usize != size_of::<TOKEN_STATISTICS>() {
        return Err((Stage::Extent, None));
    }
    let token_type = statistics.TokenType as u32;
    let impersonation_level = match token_type {
        1 => None,
        2 if (0..=3).contains(&statistics.ImpersonationLevel) => {
            Some(statistics.ImpersonationLevel as u32)
        }
        _ => return Err((Stage::Statistics, None)),
    };
    // Aligned initialized storage is fixed and bounded. Returned length, not
    // capacity, bounds every typed entry copied from the native allocation.
    let mut words = [0usize; 8192 / size_of::<usize>()];
    returned = 0;
    guard(cutoff)?;
    // SAFETY: owned aligned words cover the stated writable capacity.
    if unsafe {
        GetTokenInformation(
            held.as_raw_handle(),
            TokenPrivileges,
            words.as_mut_ptr().cast(),
            size_of_val(&words) as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(failed(Stage::PrivilegesQuery));
    }
    guard(cutoff)?;
    let bytes = returned as usize;
    let offset = std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
    if bytes < offset || bytes > size_of_val(&words) {
        return Err((Stage::Extent, None));
    }
    let pointer = words.as_ptr().cast::<u8>();
    // SAFETY: the checked native prefix contains PrivilegeCount. No reference
    // to the variable-tail TOKEN_PRIVILEGES structure is constructed.
    let count = unsafe { ptr::read_unaligned(pointer.cast::<u32>()) } as usize;
    if count > MAX_PRIVILEGES {
        return Err((Stage::CountBound, None));
    }
    let end = count
        .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
        .and_then(|size| offset.checked_add(size))
        .ok_or((Stage::Extent, None))?;
    if end > bytes {
        return Err((Stage::Extent, None));
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| (Stage::Allocation, None))?;
    for index in 0..count {
        guard(cutoff)?;
        // SAFETY: the entire checked native entry range fits returned bytes.
        let entry = unsafe {
            ptr::read_unaligned(
                pointer
                    .add(offset + index * size_of::<LUID_AND_ATTRIBUTES>())
                    .cast::<LUID_AND_ATTRIBUTES>(),
            )
        };
        values.push(PrivilegeTuple {
            high: entry.Luid.HighPart,
            low: entry.Luid.LowPart,
            attributes: entry.Attributes,
        });
    }
    let privileges = summarize(&values).map_err(|stage| (stage, None))?;
    guard(cutoff)?;
    Ok(TokenFacts {
        source,
        token_id: luid(statistics.TokenId),
        modified_id: luid(statistics.ModifiedId),
        authentication_id: luid(statistics.AuthenticationId),
        token_type,
        impersonation_level,
        statistics_group_count: statistics.GroupCount,
        statistics_privilege_count: statistics.PrivilegeCount,
        privileges,
    })
}

fn capture_inner(cutoff: Instant) -> Sample {
    let captured = (|| -> Result<Sample, Failure> {
        guard(cutoff)?;
        // SAFETY: current native thread/process pseudo handles never move the
        // query to the deadline watcher and no PID is reopened.
        let started_tick_ms = unsafe { GetTickCount64() };
        let thread_id = unsafe { GetCurrentThreadId() };
        let (mut birth, mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        guard(cutoff)?;
        // SAFETY: current process and four distinct initialized native outputs.
        if unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut birth,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(failed(Stage::ProcessIdentity));
        }
        guard(cutoff)?;
        let process = WindowsProcessIdentityV1 {
            process_id: unsafe { GetCurrentProcessId() },
            creation_time_100ns: u64::from(birth.dwLowDateTime)
                | (u64::from(birth.dwHighDateTime) << 32),
        };
        let facts = token(cutoff);
        if Instant::now() >= cutoff {
            return Err(facts.err().unwrap_or((Stage::Cutoff, None)));
        }
        let token = match facts {
            Ok(facts) => Token::Observed {
                facts: Box::new(facts),
            },
            Err((stage, error)) => Token::Unavailable {
                stage,
                native_win32_error: error,
            },
        };
        Ok(Sample::Observed {
            process,
            thread_id,
            started_tick_ms,
            finished_tick_ms: unsafe { GetTickCount64() },
            token,
        })
    })();
    match captured {
        Ok(sample) => sample,
        Err((stage, error)) => Sample::Unavailable {
            stage,
            native_win32_error: error,
        },
    }
}

pub(super) fn capture(cutoff: Instant) -> Sample {
    // SAFETY: preserve the invoking I/O thread's native last-error state.
    let saved = unsafe { GetLastError() };
    let sample = capture_inner(cutoff);
    unsafe { SetLastError(saved) };
    sample
}
