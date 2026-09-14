#![cfg(all(target_os = "macos", feature = "test-fixtures"))]

use memcordon_core::{CommandSpec, NativeStartupCleanupStateV1, ReleaseEvidence};
use memcordon_platform::test_support::{MacosLaunchFault, macos_cancellation_fault};
use std::path::Path;

#[test]
fn cancellation_at_native_release_boundaries_never_reopens_admission() {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        for fault in [
            MacosLaunchFault::CancelBeforeCommit(signal),
            MacosLaunchFault::CancelAfterCommit(signal),
            MacosLaunchFault::CancelReleasePrefix(signal),
            MacosLaunchFault::CancelAfterIssue(signal),
            MacosLaunchFault::CancelAfterSend(signal),
            MacosLaunchFault::CancelAfterExec(signal),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("target-started");
            let command = CommandSpec::new(Path::new(env!("CARGO_BIN_EXE_memcordon-test-fixture")))
                .args([
                    std::ffi::OsString::from("record-argv"),
                    marker.as_os_str().to_owned(),
                ]);
            let started = std::time::Instant::now();
            let (release, diagnostic) = macos_cancellation_fault(
                &command,
                Path::new(env!("CARGO_BIN_EXE_memcordon")),
                fault,
            )
            .unwrap();
            assert!(started.elapsed() < std::time::Duration::from_secs(6));
            assert!(diagnostic.guardian_ready);
            assert!(diagnostic.launcher_pid.is_some());
            assert_eq!(
                diagnostic.cleanup.state,
                NativeStartupCleanupStateV1::Complete,
                "{fault:?}: {diagnostic:?}"
            );
            match fault {
                MacosLaunchFault::CancelBeforeCommit(_)
                | MacosLaunchFault::CancelAfterCommit(_) => {
                    assert!(!marker.exists());
                    assert_eq!(release, ReleaseEvidence::NotIssued);
                    assert!(!diagnostic.release_sent);
                }
                MacosLaunchFault::CancelReleasePrefix(_) => {
                    assert!(!marker.exists());
                    assert_eq!(release, ReleaseEvidence::Unknown);
                    assert!(!diagnostic.release_sent);
                }
                MacosLaunchFault::CancelAfterIssue(_) => {
                    assert!(matches!(release, ReleaseEvidence::Issued { .. }));
                    assert!(diagnostic.release_sent);
                }
                MacosLaunchFault::CancelAfterSend(_) => {
                    assert!(!matches!(release, ReleaseEvidence::NotIssued));
                }
                MacosLaunchFault::CancelAfterExec(_) => {
                    assert!(matches!(
                        release,
                        ReleaseEvidence::Issued {
                            exec_confirmed: true,
                            ..
                        }
                    ));
                    assert!(diagnostic.release_sent && diagnostic.exec_confirmed);
                }
                _ => unreachable!(),
            }
        }
    }
}
