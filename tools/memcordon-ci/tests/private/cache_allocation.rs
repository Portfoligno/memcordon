use super::*;

#[test]
fn tool_keys_distinguish_actual_leaf_supply_and_preparation_job_counts() {
    for workers in 1..=4 {
        for tool in ["cargo-audit", "cargo-deny", "cargo-fuzz"] {
            assert_eq!(
                tool_jobs_for_scope(workers, true, false, tool, "complete"),
                workers
            );
            let auxiliary = if workers == 1 {
                1
            } else {
                workers - workers / 2
            };
            assert_eq!(
                tool_jobs_for_scope(workers, true, false, tool, "preparation-pair-v1"),
                auxiliary
            );
            assert_eq!(
                tool_jobs_for_scope(workers, false, false, tool, "preparation-pair-v1"),
                workers
            );
            assert_eq!(
                tool_jobs_for_scope(workers, true, true, tool, "preparation-pair-v1"),
                workers
            );
        }
        let audit = tool_jobs_for_scope(workers, true, false, "cargo-audit", "supply-pair-v1");
        let deny = tool_jobs_for_scope(workers, true, false, "cargo-deny", "supply-pair-v1");
        assert_eq!(audit, workers.div_ceil(2));
        assert_eq!(deny, (workers / 2).max(1));
    }
    assert_eq!(
        tool_jobs_for_scope(3, true, false, "cargo-deny", "preparation-pair-v1"),
        2
    );
    assert_eq!(
        tool_jobs_for_scope(3, true, false, "cargo-deny", "supply-pair-v1"),
        1
    );
}

#[test]
fn tool_compiler_namespaces_are_closed_and_share_only_the_declared_live_root() {
    for shard in ["complete", "supply-pair-v1", "preparation-pair-v1"] {
        let layout = crate::cache_restore::tool_build_layout("cargo-audit", shard).unwrap();
        assert_eq!(
            layout.directories,
            [std::path::PathBuf::from(
                "target/ci-tools-build/cargo-audit"
            )]
        );
    }
    assert!(crate::cache_restore::tool_build_layout("cargo-fuzz", "supply-pair-v1").is_err());
    assert!(crate::cache_restore::tool_build_layout("cargo-audit", "invented").is_err());
}
