use memcordon_ci::{CiError, Result};

#[path = "../src/workflow_output.rs"]
mod workflow_output;

// Keep the environment-backed entry point compiled while exercising explicit
// file custody below, without modifying the test process's runner channels.
const _: fn(Result<()>) -> Result<()> = workflow_output::quiescent;

#[test]
fn concurrent_output_batches_remain_complete_single_line_records() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("output");
    std::fs::write(&path, b"original=preserved\n").unwrap();
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let path = &path;
            scope.spawn(move || {
                for sequence in 0..128 {
                    workflow_output::write_to(
                        Some(path),
                        &[("release-notes", format!("unavailable-{worker}-{sequence}"))],
                    )
                    .unwrap();
                }
            });
        }
    });
    let output = std::fs::read_to_string(&path).unwrap();
    assert!(output.starts_with("original=preserved\n"));
    assert!(output.ends_with('\n'));
    let actual: std::collections::BTreeSet<_> = output.lines().skip(1).collect();
    let expected: std::collections::BTreeSet<_> = (0..8)
        .flat_map(|worker| {
            (0..128).map(move |sequence| format!("release-notes=unavailable-{worker}-{sequence}"))
        })
        .collect();
    assert_eq!(output.lines().count(), expected.len() + 1);
    assert_eq!(actual, expected.iter().map(String::as_str).collect());
}

#[test]
fn invalid_batch_never_opens_or_partially_changes_output() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("output");
    let values = [("valid", "first".into()), ("invalid", "line\nbreak".into())];
    let error = workflow_output::write_to(Some(&path), &values).unwrap_err();
    assert!(error.to_string().contains("safe single line"));
    assert!(!path.exists());
    std::fs::write(&path, b"original=preserved\n").unwrap();
    assert!(workflow_output::write_to(Some(&path), &values).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"original=preserved\n");
}
