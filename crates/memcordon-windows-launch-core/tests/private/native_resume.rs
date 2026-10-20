// Registered privately by the Windows native module. These contracts do not
// start a process or change a thread's suspension count.
use super::{NativeCreateErrorV1, interpret_resume_count};

#[test]
fn resume_requires_exact_selected_count_without_reading_stale_last_error() {
    for count in [0, 2, 17, u32::MAX - 1] {
        let error = interpret_resume_count(count, || {
            panic!("a successful native count must not consult GetLastError")
        })
        .unwrap_err();
        assert_eq!(error.stable_code, "resume-thread-count");
        assert_eq!(error.win32_error, None);
        assert!(error.detail.contains(&count.to_string()));
        assert!(error.detail.contains("required=1"));
    }
    interpret_resume_count(1, || panic!("sole-suspension success has no last error")).unwrap();
}

#[test]
fn native_resume_failure_preserves_actual_error_and_native_return() {
    let calls = std::cell::Cell::new(0);
    let error = interpret_resume_count(u32::MAX, || {
        calls.set(calls.get() + 1);
        NativeCreateErrorV1 {
            stable_code: "resume-thread",
            win32_error: Some(5),
            detail: "actual native access denial".into(),
        }
    })
    .unwrap_err();
    assert_eq!(calls.get(), 1);
    assert_eq!(error.stable_code, "resume-thread");
    assert_eq!(error.win32_error, Some(5));
    assert!(error.detail.contains(&u32::MAX.to_string()));
    assert!(error.detail.contains("actual native access denial"));
}
