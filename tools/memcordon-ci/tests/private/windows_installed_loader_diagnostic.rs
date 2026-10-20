use super::*;

#[test]
fn expired_original_cutoff_refuses_before_launching_diagnostic() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("diagnostic-must-never-be-launched");
    assert!(!missing.exists());
    let spec = crate::command::CommandSpec::new(&missing, root.path(), Duration::from_secs(30));
    let cutoff = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    let observed: Result<memcordon_testkit::ObservedOutput> = execute(spec, cutoff);
    let error = observed.unwrap_err().to_string();
    assert_eq!(error, "installed diagnostic original work cutoff exhausted");
    assert!(!missing.exists());
}
