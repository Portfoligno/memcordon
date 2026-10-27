#[path = "../src/release/linux_image_custody_plan.rs"]
mod plan;

#[test]
fn unique_sources_copies_and_directories_cost_channels_not_local_descriptors() {
    let small = plan::Plan::new(40, 1, 10, 20, 1024).unwrap();
    let many = plan::Plan::new(40, 1200, 1500, 20, 1024).unwrap();
    assert_eq!(many.remote_files, 1200 * (plan::IMPORT_CASES + 1) + 1);
    assert!(many.remote_files + many.directory_owners > 1024);
    assert!(many.maximum_parent_descriptors < 1024);
    assert_eq!(
        many.maximum_parent_descriptors - small.maximum_parent_descriptors,
        (many.channels - small.channels) * 2
    );
    assert_eq!(many.directory_owners, 1500);
}

#[test]
fn complete_parent_budget_includes_unpooled_owners_and_rejects_before_materialization() {
    let baseline = plan::Plan::new(30, 200, 300, 40, u64::MAX).unwrap();
    assert_eq!(
        baseline.maximum_parent_descriptors,
        30 + baseline.channels * 2
            + 40
            + baseline.artifact_owners
            + plan::PARTIAL_WRITERS
            + plan::TRANSIENT_OWNERS
            + plan::JOURNAL_OWNERS
            + plan::CLEANUP_RESERVE_OWNERS
            + plan::NATIVE_FAMILY_OWNERS
    );
    assert!(plan::Plan::new(30, 200, 300, 40, baseline.maximum_parent_descriptors as u64).is_err());
    assert!(
        plan::Plan::new(
            30,
            200,
            300,
            40,
            baseline.maximum_parent_descriptors as u64 + 1
        )
        .is_ok()
    );
    assert!(plan::Plan::new(30, 200, 300, 1000, 1024).is_err());
    assert!(plan::Plan::new(30, 200, 300, 40, 128).is_err());
}

#[test]
fn slot_boundary_and_impossible_manifest_arithmetic_fail_closed() {
    let a = plan::Plan::new(
        0,
        1,
        plan::FILES_PER_SHARD - (plan::IMPORT_CASES + 2),
        0,
        4096,
    )
    .unwrap();
    let b = plan::Plan::new(0, 1, a.directory_owners + 1, 0, 4096).unwrap();
    assert_eq!(a.channels, 1);
    assert_eq!(b.channels, 2);
    assert!(plan::Plan::new(0, 0, 0, 0, 4096).is_err());
    assert!(plan::Plan::new(0, usize::MAX, 0, 0, u64::MAX).is_err());
    assert!(plan::Plan::new(usize::MAX, 1, 0, 0, u64::MAX).is_err());
    assert!(plan::Plan::new(0, 1, usize::MAX, 0, u64::MAX).is_err());
}
