//! Native CI regression in a separate fixture process, never a workload gate.
use super::gate_call_trace;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::{
    Foundation::{CompareObjectHandles, GetLastError},
    System::{
        Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
        Threading::{CreateEventW, GetCurrentThreadId, OpenEventW},
    },
};

fn peer_calls(
    name: &[u16],
    missing: &[u16],
    original: &OwnedHandle,
    missing_error: u32,
    cutoff: u64,
    frequency: i64,
) -> io::Result<()> {
    for (selected, expected) in [(name, true), (missing, false)] {
        remaining(cutoff, frequency)?;
        // SAFETY: exact owned test names remain NUL-terminated and live.
        let raw = unsafe { OpenEventW(0x0010_0000, 0, selected.as_ptr()) };
        let error = unsafe { GetLastError() };
        let reference = (!raw.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(raw) });
        if let Some(reference) = reference {
            if !expected
                || unsafe {
                    CompareObjectHandles(original.as_raw_handle(), reference.as_raw_handle())
                } == 0
            {
                return Err(io::Error::other("ambient peer returned a different event"));
            }
        } else if expected || error != missing_error {
            return Err(io::Error::other(
                "ambient peer original named-open result/error changed",
            ));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct ObservationAndCleanup {
    primary: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for ObservationAndCleanup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; ambient peer cleanup: {}",
            self.primary, self.secondary
        )
    }
}
impl std::error::Error for ObservationAndCleanup {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
fn combined(primary: io::Result<()>, secondary: io::Result<()>) -> io::Result<()> {
    match (primary, secondary) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(secondary)) => Err(io::Error::new(
            primary.kind(),
            ObservationAndCleanup { primary, secondary },
        )),
    }
}

pub(super) fn run() -> io::Result<i32> {
    let mut now = 0;
    let mut frequency = 0;
    // SAFETY: writable clock scalars; this CI self-check has its own fixed
    // original deadline. Installed case work/cleanup budgets are untouched.
    assert_ne!(unsafe { QueryPerformanceCounter(&mut now) }, 0);
    assert_ne!(unsafe { QueryPerformanceFrequency(&mut frequency) }, 0);
    let cutoff = u64::try_from(now + frequency * 5).unwrap();
    assert!(gate_call_trace::mock_forwarding());
    remaining(cutoff, frequency)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!(
        "Local\\memcordon-control-trace-{}-{nonce}",
        std::process::id()
    );
    let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    // SAFETY: fresh bounded test name and no inherited/substituted handle.
    let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
    let error = unsafe { GetLastError() };
    assert!(!handle.is_null() && error != 183);
    let owner = unsafe { OwnedHandle::from_raw_handle(handle) };
    let missing = format!("{name}-missing")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: the exact missing-name baseline precedes any hook installation.
    // Save the original error before any further native or diagnostic call.
    let baseline = unsafe { OpenEventW(0x0010_0000, 0, missing.as_ptr()) };
    let baseline_error = unsafe { GetLastError() };
    let baseline_owner =
        (!baseline.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(baseline) });
    assert!(baseline_owner.is_none());
    assert_ne!(baseline_error, 0);
    std::thread::scope(|scope| -> io::Result<()> {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let peer_name = &wide;
        let peer_missing = &missing;
        let peer_owner = &owner;
        let peer = scope.spawn(move || -> io::Result<()> {
            let calls = || -> io::Result<()> {
                remaining(cutoff, frequency)?;
                let observed = peer_calls(
                    peer_name,
                    peer_missing,
                    peer_owner,
                    baseline_error,
                    cutoff,
                    frequency,
                );
                combined(observed, remaining(cutoff, frequency).map(|_| ()))
            };
            let before = calls();
            let identity = unsafe { GetCurrentThreadId() };
            if let Err(error) = ready_tx.send(before.map(|()| identity)) {
                return combined(
                    error.0.map(|_| ()),
                    Err(io::Error::other("ambient peer ready receiver lost")),
                );
            }
            release_rx
                .recv_timeout(remaining(cutoff, frequency)?)
                .map_err(io::Error::other)?;
            calls()
        });
        let observation =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
                let peer_id = ready_rx
                    .recv_timeout(remaining(cutoff, frequency)?)
                    .map_err(io::Error::other)??;
                let original_id = unsafe { GetCurrentThreadId() };
                assert_ne!(peer_id, original_id);
                for (selected, should_open) in [(&wide, true), (&missing, false)] {
                    let mut prepared = gate_call_trace::Prepared::new(cutoff, frequency as u64);
                    let call = prepared.call(selected)?;
                    let returned_error = unsafe { GetLastError() };
                    // Adopt the successful reference before any assertion can unwind.
                    let returned_owner = (!call.handle.is_null())
                        .then(|| unsafe { OwnedHandle::from_raw_handle(call.handle) });
                    assert_eq!(returned_error, call.native_error);
                    assert_eq!(!call.handle.is_null(), should_open);
                    if call.handle.is_null() {
                        assert_eq!(call.native_error, baseline_error);
                    } else {
                        // SAFETY: both references are live and owned within this self-check.
                        // This test-local comparison never grants workload identity authority.
                        assert_ne!(
                            unsafe {
                                CompareObjectHandles(
                                    owner.as_raw_handle(),
                                    returned_owner
                                        .as_ref()
                                        .expect("returned event owned")
                                        .as_raw_handle(),
                                )
                            },
                            0
                        );
                    }
                    let trace = prepared.diagnostic();
                    assert_eq!(
                        trace["setup_stage"],
                        1,
                        "case={}; bounded_trace={trace}",
                        if should_open {
                            "owned-event"
                        } else {
                            "missing-event"
                        }
                    );
                    assert_eq!(trace["attached_directory"], 1);
                    assert_eq!(trace["attached_event"], 1);
                    assert_eq!(trace["coverage_inconclusive"], true);
                    assert_eq!(trace["observed_entries_complete"], true);
                    assert_eq!(trace["all_native_routes_observed"], false);
                    assert_eq!(trace["absence_is_not_evidence"], true);
                    assert_eq!(trace["iat"]["strategy"], 1);
                    assert_eq!(trace["iat"]["owner_pinned"], 1);
                    assert_eq!(trace["iat"]["discovery_complete"], 1);
                    assert_eq!(trace["iat"]["directory_matches"], 1);
                    assert_eq!(trace["iat"]["event_matches"], 1);
                    assert_eq!(trace["iat"]["published_directory"], 1);
                    assert_eq!(trace["iat"]["published_event"], 1);
                    assert_eq!(trace["iat"]["protections_restored"], 1);
                    assert_eq!(trace["iat"]["rollback_error"], 0);
                    assert_eq!(trace["iat"]["protection_error"], 0);
                    assert_eq!(trace["iat"]["callback_error"], 0);
                    assert_eq!(trace["route"]["node_limit"], 2);
                    assert_eq!(trace["route"]["original_owner_export_equal"], 1);
                    assert_eq!(trace["route"]["route_revalidated"], 1);
                    let nodes = trace["route"]["nodes"].as_array().unwrap();
                    assert!(!nodes.is_empty() && nodes.len() <= 2);
                    assert_eq!(nodes[0]["entry"], trace["iat"]["original_open_event"]);
                    assert_eq!(
                        nodes.last().unwrap()["owner_base"],
                        trace["iat"]["owner_base"]
                    );
                    assert_eq!(trace["invalid_record"], false);
                    assert_eq!(trace["overflow"], 0);
                    assert_eq!(trace["incomplete"], 0);
                    assert_eq!(trace["clock_live"], 1);
                    assert_eq!(trace["armed_call_count"], 1);
                    assert_eq!(trace["called"], 1);
                    assert_eq!(trace["outer_opened"], u32::from(should_open));
                    assert_eq!(trace["outer_error"], call.native_error);
                    assert_eq!(trace["acceptance_authority"], false);
                    assert_eq!(trace["target_identity_proved"], false);
                    assert!(
                        trace["entries"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|entry| entry["thread_id"] == original_id
                                && entry["thread_id"] != peer_id)
                    );
                    assert!(trace["entries"].as_array().unwrap().iter().any(|entry| {
                        entry["operation_code"] == 2
                            && entry["entered"] == 1
                            && entry["returned"] == 1
                            && entry["desired_access"] == 0x0010_0000
                            && entry["native_status"]
                                .as_i64()
                                .is_some_and(|status| (status >= 0) == should_open)
                            && entry["output_handle_returned"] == u32::from(should_open)
                    }));
                    assert!(prepared.call(selected).is_err());
                    assert_eq!(
                        prepared.diagnostic(),
                        trace,
                        "refused second call changed original trace"
                    );
                }
                Ok(())
            }));
        let released = release_tx
            .send(())
            .map_err(|_| io::Error::other("ambient peer release receiver lost"));
        drop(release_tx);
        let joined = peer
            .join()
            .map_err(|_| io::Error::other("ambient peer panicked"))
            .and_then(|result| result);
        let cleanup = combined(released, joined);
        match observation {
            Ok(primary) => {
                combined(primary, cleanup)?;
                remaining(cutoff, frequency)?;
                Ok(())
            }
            Err(panic) => {
                if let Err(error) = cleanup {
                    use std::io::Write;
                    let _ = writeln!(
                        std::io::stderr(),
                        "original gate trace self-check peer cleanup after unwind: {error}"
                    );
                }
                std::panic::resume_unwind(panic)
            }
        }
    })?;
    // The original start tick is now expired; no sleep, new budget, or native
    // event attempt is needed to exercise the actual bridge refusal boundary.
    let mut expired = gate_call_trace::Prepared::new(u64::try_from(now).unwrap(), frequency as u64);
    let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let error = expired.call(&name).err().expect("expired call must refuse");
    assert_eq!(error.raw_os_error(), Some(1460));
    let trace = expired.diagnostic();
    assert_eq!(trace["setup_stage"], 2);
    assert_eq!(trace["setup_error"], 1460);
    assert_eq!(trace["called"], 0);
    assert_eq!(trace["armed_call_count"], 0);
    assert_eq!(trace["reported_count"], 0);
    assert_eq!(trace["clock_live"], 0);
    assert_eq!(trace["coverage_inconclusive"], true);
    assert_eq!(trace["acceptance_authority"], false);
    assert_eq!(trace["target_identity_proved"], false);
    Ok(0)
}

fn remaining(cutoff: u64, frequency: i64) -> io::Result<std::time::Duration> {
    let mut now = 0;
    // SAFETY: writable scalar observes the same original test clock.
    if unsafe { QueryPerformanceCounter(&mut now) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let ticks = cutoff
        .checked_sub(u64::try_from(now).map_err(io::Error::other)?)
        .filter(|ticks| *ticks > 0)
        .ok_or_else(|| io::Error::other("original self-check cutoff exhausted"))?;
    Ok(std::time::Duration::from_secs_f64(
        ticks as f64 / frequency as f64,
    ))
}
