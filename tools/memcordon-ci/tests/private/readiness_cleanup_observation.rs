use super::*;

fn settled_cell() -> CellEvidence {
    CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 1,
        identity: SourceIdentity {
            run_id: "1".into(),
            source_commit: "a".repeat(40),
            source_tree_sha256: "b".repeat(64),
            version: "0.5.8-dev".into(),
        },
        key: memcordon_readiness_verifier::ProductKey {
            target: "x86_64-unknown-linux-gnu".into(),
            channel: "candidate-native".into(),
        },
        product: None,
        component_build: None,
        records: vec![],
        artifacts: vec![],
        cleanup_failures: vec![],
        cache_quiescent: true,
    }
}

fn output(success: bool) -> memcordon_ci::Result<memcordon_testkit::ObservedOutput> {
    #[cfg(unix)]
    let status = {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(if success { 0 } else { 256 })
    };
    #[cfg(windows)]
    let status = {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(if success { 0 } else { 1 })
    };
    Ok(memcordon_testkit::ObservedOutput {
        status,
        stdout: vec![],
        stderr: b"retained inner recovery failure".to_vec(),
        elapsed: std::time::Duration::ZERO,
    })
}

#[test]
fn cleanup_requires_both_command_and_settled_cell_and_retains_each_failure() {
    assert!(cleanup_failures(&output(true), &Ok(settled_cell())).is_empty());
    let failed_command = cleanup_failures(&output(false), &Ok(settled_cell())).join("; ");
    assert!(failed_command.contains("retained inner recovery failure"));
    assert!(failed_command.contains("status="));

    let missing_cell =
        cleanup_failures(&output(true), &Err("cell access denied".into())).join("; ");
    assert!(missing_cell.contains("cell access denied"));
    let mut cell = settled_cell();
    cell.cleanup_failures.push("native owner still held".into());
    let unsettled = cleanup_failures(&output(true), &Ok(cell)).join("; ");
    assert!(unsettled.contains("native owner still held"));

    let failed_observation = Err(memcordon_ci::CiError::Message(
        "spawn observation unavailable".into(),
    ));
    let combined = cleanup_failures(&failed_observation, &Err("cell absent".into()));
    assert_eq!(combined.len(), 2);
    assert!(combined[0].contains("spawn observation unavailable"));
    assert!(combined[1].contains("cell absent"));
}
