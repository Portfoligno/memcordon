use memcordon_ci::standard_runner::{
    CONTEXT_BYTE_LIMIT, DelegatedUnitLease, UnitControl, publish_candidate, read_bounded_regular,
    read_bounded_regular_owned,
};
use memcordon_ci::{CiError, Result};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::rc::Rc;

const UNIT: &str = "memcordon-standard-test.service";
const ACTIVE: &[u8] = b"LoadState=loaded\nActiveState=active\n";
const RETIRED: &[u8] = b"LoadState=loaded\nActiveState=inactive\n";

#[test]
fn delegation_result_preserves_exact_primary_error_when_cleanup_succeeds() {
    let primary = CiError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "child denied",
    ));
    let result =
        memcordon_ci::standard_runner::finish_delegation::<()>(Err(primary), Ok(()), Ok(()));
    let CiError::Io(error) = result.unwrap_err() else {
        panic!("primary error variant was replaced");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "child denied");
}

#[test]
fn delegation_success_requires_all_three_results_and_retains_every_failure() {
    // Deliberately lacks Debug: successful child values do not enter diagnostics.
    struct ChildValue(u32);
    for child_fails in [false, true] {
        for retirement_fails in [false, true] {
            for context_fails in [false, true] {
                let execution = if child_fails {
                    Err(CiError::Message("original child failure".into()))
                } else {
                    Ok(ChildValue(42))
                };
                let retirement = if retirement_fails {
                    Err(CiError::Message("retirement failure".into()))
                } else {
                    Ok(())
                };
                let cleanup = if context_fails {
                    Err(std::io::Error::other("context close failure"))
                } else {
                    Ok(())
                };
                let result = memcordon_ci::standard_runner::finish_delegation(
                    execution, retirement, cleanup,
                );
                if !(child_fails || retirement_fails || context_fails) {
                    let Ok(value) = result else {
                        panic!("complete delegation failed");
                    };
                    assert_eq!(value.0, 42);
                    continue;
                }
                let Err(error) = result else {
                    panic!("failure was promoted to success");
                };
                let message = error.to_string();
                for (failed, expected) in [
                    (child_fails, "original child failure"),
                    (retirement_fails, "retirement failure"),
                    (context_fails, "context close failure"),
                ] {
                    if failed {
                        assert!(message.contains(expected), "missing {expected}: {message}");
                    }
                }
            }
        }
    }
}

enum Reply {
    Query(std::result::Result<&'static [u8], &'static str>),
    Stop(std::result::Result<(), &'static str>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Query,
    Stop,
}

#[derive(Default)]
struct Observations {
    replies: VecDeque<Reply>,
    calls: Vec<(Operation, PathBuf, OsString)>,
}

#[derive(Clone, Default)]
struct ControlledNative(Rc<RefCell<Observations>>);

impl ControlledNative {
    fn new(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self(Rc::new(RefCell::new(Observations {
            replies: replies.into_iter().collect(),
            calls: Vec::new(),
        })))
    }

    fn next(&self, operation: Operation, root: &Path, unit: &OsStr) -> Option<Reply> {
        let mut observations = self.0.borrow_mut();
        observations
            .calls
            .push((operation, root.to_owned(), unit.to_owned()));
        observations.replies.pop_front()
    }

    fn assert_calls(&self, expected: &[Operation]) {
        let observations = self.0.borrow();
        assert!(observations.replies.is_empty(), "unused native outcomes");
        assert_eq!(
            observations
                .calls
                .iter()
                .map(|call| call.0)
                .collect::<Vec<_>>(),
            expected
        );
        for (_, root, unit) in &observations.calls {
            assert_eq!(root, Path::new("owned-checkout"));
            assert_eq!(unit, OsStr::new(UNIT));
        }
    }
}

impl UnitControl for ControlledNative {
    fn query(&self, root: &Path, unit: &OsStr) -> Result<Vec<u8>> {
        match self.next(Operation::Query, root, unit) {
            Some(Reply::Query(result)) => result
                .map(<[u8]>::to_vec)
                .map_err(|error| CiError::Message(error.into())),
            _ => Err(CiError::Message("unexpected native query".into())),
        }
    }

    fn stop(&self, root: &Path, unit: &OsStr) -> Result<()> {
        match self.next(Operation::Stop, root, unit) {
            Some(Reply::Stop(result)) => result.map_err(|error| CiError::Message(error.into())),
            _ => Err(CiError::Message("unexpected native stop".into())),
        }
    }
}

fn lease(control: &ControlledNative) -> DelegatedUnitLease<ControlledNative> {
    DelegatedUnitLease::with_control(Path::new("owned-checkout"), UNIT.into(), control.clone())
        .unwrap()
}

#[test]
fn query_error_or_malformed_reply_still_stops_and_observes_retirement() {
    for initial in [
        Err("native query unavailable"),
        Ok(b"LoadState=loaded\nActiveState=inactive\nActiveState=inactive\n".as_slice()),
        Ok(b"LoadState=loaded\n".as_slice()),
    ] {
        let control = ControlledNative::new([
            Reply::Query(initial),
            Reply::Stop(Ok(())),
            Reply::Query(Ok(RETIRED)),
        ]);
        let mut lease = lease(&control);
        lease.retire().unwrap();
        drop(lease);
        control.assert_calls(&[Operation::Query, Operation::Stop, Operation::Query]);
    }
}

#[test]
fn stop_failure_preserves_error_and_leaves_drop_cleanup_armed() {
    let control = ControlledNative::new([
        Reply::Query(Ok(ACTIVE)),
        Reply::Stop(Err("native stop denied")),
        Reply::Stop(Ok(())),
    ]);
    let mut lease = lease(&control);
    assert!(
        lease
            .retire()
            .unwrap_err()
            .to_string()
            .contains("native stop denied")
    );
    drop(lease);
    control.assert_calls(&[Operation::Query, Operation::Stop, Operation::Stop]);
}

#[test]
fn unconfirmed_retirement_is_an_error_and_keeps_emergency_cleanup() {
    for final_query in [Ok(ACTIVE), Err("retirement observation lost")] {
        let control = ControlledNative::new([
            Reply::Query(Ok(ACTIVE)),
            Reply::Stop(Ok(())),
            Reply::Query(final_query),
            Reply::Stop(Ok(())),
        ]);
        let mut lease = lease(&control);
        let error = lease.retire().unwrap_err().to_string();
        assert!(error.contains("remains active") || error.contains("retirement observation lost"));
        drop(lease);
        control.assert_calls(&[
            Operation::Query,
            Operation::Stop,
            Operation::Query,
            Operation::Stop,
        ]);
    }
}

#[test]
fn already_retired_unit_does_not_receive_a_stop_including_on_drop() {
    for observed in [
        RETIRED,
        b"LoadState=not-found\nActiveState=inactive\n".as_slice(),
        b"LoadState=loaded\nActiveState=failed\n".as_slice(),
    ] {
        let control = ControlledNative::new([Reply::Query(Ok(observed))]);
        let mut lease = lease(&control);
        lease.retire().unwrap();
        drop(lease);
        control.assert_calls(&[Operation::Query]);
    }
}

#[test]
fn early_return_drop_attempts_cleanup_even_if_native_stop_fails() {
    for outcome in [Ok(()), Err("emergency stop unavailable")] {
        let control = ControlledNative::new([Reply::Stop(outcome)]);
        drop(lease(&control));
        control.assert_calls(&[Operation::Stop]);
    }
}

#[test]
fn invalid_unit_names_never_reach_native_control() {
    for name in [
        "other.service",
        "memcordon-standard-test.socket",
        "memcordon-standard-../test.service",
        "memcordon-standard-test;other.service",
    ] {
        let control = ControlledNative::default();
        assert!(
            DelegatedUnitLease::with_control(
                Path::new("owned-checkout"),
                name.into(),
                control.clone()
            )
            .is_err()
        );
        control.assert_calls(&[]);
    }
}

#[test]
fn failed_candidate_cleanup_never_publishes_and_stale_destination_is_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let candidate = directory.path().join("candidate.json");
    let final_path = directory.path().join("report.json");
    std::fs::create_dir(&candidate).unwrap();
    assert!(publish_candidate(&candidate, &final_path, b"validated\n").is_err());
    assert!(!final_path.exists());
    let valid_candidate = directory.path().join("valid.json");
    std::fs::write(&valid_candidate, b"current\n").unwrap();
    std::fs::write(&final_path, b"stale\n").unwrap();
    assert!(publish_candidate(&valid_candidate, &final_path, b"current\n").is_err());
    assert_eq!(std::fs::read(&final_path).unwrap(), b"stale\n");
}

#[test]
fn bounded_evidence_accepts_exact_limit_and_rejects_one_more_byte() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("evidence.json");
    let mut data = vec![b' '; usize::try_from(CONTEXT_BYTE_LIMIT).unwrap()];
    *data.last_mut().unwrap() = b'\n';
    std::fs::write(&path, &data).unwrap();
    assert_eq!(read_bounded_regular(&path).unwrap(), data);
    data.push(b'\n');
    std::fs::write(&path, &data).unwrap();
    assert!(read_bounded_regular(&path).is_err());
}

#[cfg(unix)]
#[test]
fn evidence_symlinks_and_wrong_owner_reject_without_changing_target() {
    use std::os::unix::fs::{MetadataExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("actual.json");
    let link = directory.path().join("candidate.json");
    std::fs::write(&target, b"actual\n").unwrap();
    symlink(&target, &link).unwrap();
    assert!(read_bounded_regular(&link).is_err());
    let actual_uid = std::fs::metadata(&target).unwrap().uid();
    assert!(read_bounded_regular_owned(&target, Some(actual_uid ^ 1)).is_err());
    assert_eq!(
        read_bounded_regular_owned(&target, Some(actual_uid)).unwrap(),
        b"actual\n"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"actual\n");
}
