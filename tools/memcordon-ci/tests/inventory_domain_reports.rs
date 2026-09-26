use memcordon_ci::inventory_progress::{
    DomainSummary, InventoryProgress, ReportDomain, finish_domains, set_report_directory,
};

#[test]
fn concurrent_domains_keep_their_own_bounded_slots_and_joined_summary() {
    let directory = tempfile::tempdir().unwrap();
    set_report_directory(Some(directory.path().to_path_buf())).unwrap();
    std::thread::scope(|scope| {
        for domain in [ReportDomain::Source, ReportDomain::Native] {
            scope.spawn(move || {
                for root in 0..3 {
                    let mut progress = InventoryProgress::for_domain(
                        std::path::Path::new("fixture"),
                        domain,
                        root,
                        [16, 8, 8],
                    );
                    progress.file_validated(17);
                    progress.file_committed(17);
                    progress.finish(true);
                }
            });
        }
    });
    finish_domains(&[
        DomainSummary {
            domain: ReportDomain::Source,
            roots: 3,
            elapsed_ns: 20,
            files: 3,
            bytes: 51,
            complete: true,
        },
        DomainSummary {
            domain: ReportDomain::Native,
            roots: 3,
            elapsed_ns: 25,
            files: 3,
            bytes: 51,
            complete: false,
        },
    ]);
    set_report_directory(None).unwrap();
    let mut names = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        [
            "inventory-domains.json",
            "inventory-native-0.json",
            "inventory-native-1.json",
            "inventory-source-0.json",
            "inventory-source-1.json"
        ]
    );
    for domain in ["source", "native"] {
        for slot in 0..2 {
            let bytes = std::fs::read(
                directory
                    .path()
                    .join(format!("inventory-{domain}-{slot}.json")),
            )
            .unwrap();
            assert_eq!(bytes.last(), Some(&b'\n'));
            let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(record["domain"], domain);
            assert_eq!(record["root_complete"], true);
            assert_eq!(
                record["limits"],
                serde_json::json!({"outstanding":16,"files":8,"preparations":8})
            );
            assert_eq!(record["manifest_bytes_committed"], 17);
        }
    }
    let summary: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.path().join("inventory-domains.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        summary["aggregate_limits"],
        serde_json::json!({"outstanding":32,"files":16,"preparations":16})
    );
    assert_eq!(summary["domains"][0]["complete"], true);
    assert_eq!(summary["domains"][1]["complete"], false);
}
