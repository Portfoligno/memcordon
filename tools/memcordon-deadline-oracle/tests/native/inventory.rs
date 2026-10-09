use super::super::inventory::*;
use std::cell::Cell;
use std::io;
use std::time::{Duration, Instant};

fn observation(pid: i32, birth: u64, session: i32) -> ProcessObservation {
    ProcessObservation {
        identity: ProcessIdentity {
            pid,
            birth_seconds: birth,
            birth_microseconds: 0,
        },
        state: 2,
        parent_pid: 1,
        process_group: pid,
        session_id: session,
    }
}

#[test]
fn pid_counts_one_two_three_are_not_divided_again() {
    for count in 1..=3 {
        let pids = enumerate_pids(8, |buffer| {
            for (offset, slot) in buffer.iter_mut().take(count).enumerate() {
                *slot = i32::try_from(offset + 1).unwrap();
            }
            Ok(count)
        })
        .unwrap();
        assert_eq!(
            pids,
            (1..=i32::try_from(count).unwrap()).collect::<Vec<_>>()
        );
        assert_ne!(
            count / std::mem::size_of::<i32>(),
            pids.len(),
            "old byte division must fail this regression"
        );
    }
}

#[test]
fn full_buffer_retries_and_zero_or_cap_fails_closed() {
    let mut attempts = 0;
    let pids = enumerate_pids(2, |buffer| {
        attempts += 1;
        buffer[0] = 9;
        buffer[1] = 3;
        Ok(if attempts == 1 { buffer.len() } else { 2 })
    })
    .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(pids, [3, 9]);
    assert!(enumerate_pids(2, |_| Ok(0)).is_err());
    assert!(enumerate_pids(MAX_PID_CAPACITY, |buffer| Ok(buffer.len())).is_err());
    assert!(enumerate_pids(2, |_| Err(io::Error::other("unavailable"))).is_err());
}

struct Fake {
    mode: u8,
    calls: Cell<usize>,
}
impl ProcessApi for Fake {
    fn all_pids(&self) -> io::Result<Vec<i32>> {
        Ok(vec![3, 2, 1])
    }
    fn session_id(&self, _: i32) -> io::Result<Option<i32>> {
        if self.mode == 4 {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        Ok(Some(7))
    }
    fn observation(&self, pid: i32) -> io::Result<Option<ProcessObservation>> {
        let call = self.calls.get();
        self.calls.set(call + 1);
        Ok(match self.mode {
            1 => None,
            2 => Some(observation(pid, u64::try_from(call).unwrap(), 7)),
            3 => Some(observation(pid, 0, if call % 2 == 0 { 7 } else { 8 })),
            _ => Some(observation(pid, 0, 7)),
        })
    }
}

#[test]
fn session_selection_rejects_exit_reuse_session_races_and_errors() {
    for mode in 1..=3 {
        let snapshot = session_snapshot(
            &Fake {
                mode,
                calls: Cell::new(0),
            },
            7,
        )
        .unwrap();
        assert!(snapshot.members.is_empty());
        assert_eq!(snapshot.raced_pids, 3);
    }
    assert!(
        session_snapshot(
            &Fake {
                mode: 4,
                calls: Cell::new(0)
            },
            7
        )
        .is_err()
    );
    let snapshot = session_snapshot(
        &Fake {
            mode: 0,
            calls: Cell::new(0),
        },
        7,
    )
    .unwrap();
    assert_eq!(
        snapshot
            .members
            .iter()
            .map(|value| value.identity.pid)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
}

#[test]
fn stable_empty_requires_three_spaced_complete_snapshots_and_resets() {
    let mut proof = StableEmpty::default();
    let mut snapshot = SessionSnapshot {
        complete: true,
        members: vec![],
        raced_pids: 0,
    };
    let now = Instant::now();
    assert!(!proof.observe(&snapshot, now));
    assert!(!proof.observe(&snapshot, now + Duration::from_millis(1)));
    assert_eq!(proof.count, 1);
    assert!(!proof.observe(&snapshot, now + Duration::from_millis(20)));
    assert!(proof.observe(&snapshot, now + Duration::from_millis(40)));
    snapshot.complete = false;
    assert!(!proof.observe(&snapshot, now + Duration::from_millis(60)));
    assert_eq!(proof.count, 0);
    snapshot.complete = true;
    assert!(!proof.observe(&snapshot, now + Duration::from_millis(80)));
    snapshot.members.push(observation(1, 0, 7));
    assert!(!proof.observe(&snapshot, now + Duration::from_millis(100)));
    assert_eq!(proof.count, 0);
}

#[test]
fn known_identities_use_birth_time_and_remain_live_outside_session() {
    let api = Fake {
        mode: 3,
        calls: Cell::new(1),
    };
    let identity = observation(3, 0, 7).identity;
    assert!(
        same_identity(&api, identity).unwrap(),
        "session escape must not remove known identity"
    );
    let reused = ProcessIdentity {
        birth_seconds: 1,
        ..identity
    };
    assert!(!same_identity(&api, reused).unwrap());
    let set = std::collections::BTreeSet::from([identity, reused]);
    assert_eq!(set.len(), 2, "PID reuse is a distinct identity");
}
