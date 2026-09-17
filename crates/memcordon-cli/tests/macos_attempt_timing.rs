#![cfg(all(target_os = "macos", feature = "test-fixtures"))]

use memcordon_core::{CommandSpec, Policy, ReleaseEvidence};
use memcordon_platform::{
    CallerSignalSnapshot, CancellationHandle, MacosExecutionContext, macos_continuous_nanos,
};
use std::path::Path;
use std::time::Duration;

#[test]
fn authorization_offsets_exclude_preparation_before_the_attempt() {
    for target in [
        env!("CARGO_BIN_EXE_memcordon-test-fixture"),
        "/nonexistent-memcordon-timing-target",
    ] {
        // Model a caller that captured its deadline origin before preparing the
        // request. This offset is deterministic and remains within startup time.
        let preparation = u64::try_from(Duration::from_secs(1).as_nanos()).unwrap();
        let origin = macos_continuous_nanos()
            .unwrap()
            .checked_sub(preparation)
            .unwrap();
        let context = MacosExecutionContext::host_managed(
            origin,
            CallerSignalSnapshot::capture().unwrap(),
            CancellationHandle::new(),
        )
        .unwrap();
        let before_attempt = macos_continuous_nanos().unwrap();
        let command = CommandSpec::new(target).args(["exit", "--code", "0"]);
        let result = context.run(
            Policy::unbounded(),
            &command,
            Path::new(env!("CARGO_BIN_EXE_memcordon")),
        );
        let (offset, runtime) = if target == env!("CARGO_BIN_EXE_memcordon-test-fixture") {
            let execution = result.expect("immediate target should complete");
            assert!(execution.authorization_offset.unwrap() <= execution.duration);
            (execution.authorization_offset, execution.runtime)
        } else {
            let error = result.expect_err("missing target should retain startup evidence");
            assert_eq!(error.code, "MCSPAWN-NOT-FOUND");
            (error.authorization_offset, error.runtime)
        };
        let runtime = runtime.expect("native runtime evidence");
        let ReleaseEvidence::Issued { at, .. } = runtime.release else {
            panic!("target launch must have been authorized");
        };
        assert_eq!(runtime.run_origin, origin);
        assert_eq!(runtime.attempt_origin, origin);
        assert!(runtime.is_consistent());
        assert!(
            offset.expect("attempt authorization offset")
                <= Duration::from_nanos(at.checked_sub(before_attempt).unwrap()),
            "authorization must be relative to this attempt, not the earlier deadline origin"
        );
    }
}
