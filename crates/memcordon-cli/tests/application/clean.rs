#[test]
fn clean_failure_json_uses_current_schema_and_is_machine_readable() {
    let error = memcordon_core::Error::new(
        memcordon_core::ErrorCategory::Cleanup,
        "MCCLEANUP-TEST",
        "fixture failure",
    );
    let value = super::clean_failure_report(true, &error);
    assert_eq!(
        value["schema_version"],
        memcordon_core::CLEAN_REPORT_SCHEMA_VERSION
    );
    assert_eq!(value["dry_run"], true);
    assert_eq!(value["errors"][0]["code"], "MCCLEANUP-TEST");
}
