#[path = "../src/release/native_toolchain_search.rs"]
mod search;

#[test]
fn original_wrapper_and_compiler_searches_stay_in_copied_toolchain() {
    assert_eq!(
        search::directory(
            "toolchain/lib/rustlib/aarch64-unknown-linux-gnu/bin/gcc-ld/ld.lld",
            "$ORIGIN/../lib"
        )
        .unwrap(),
        "toolchain/lib/rustlib/aarch64-unknown-linux-gnu/bin/lib"
    );
    assert_eq!(
        search::directory("toolchain/bin/rustc", "${ORIGIN}/../lib").unwrap(),
        "toolchain/lib"
    );
    for value in [
        "/usr/lib",
        "$LIB",
        "$ORIGIN/../../usr/lib",
        "$ORIGIN/../../../toolchain/lib",
        "$ORIGIN/$OTHER",
    ] {
        assert!(
            search::directory("toolchain/bin/rustc", value).is_err(),
            "{value}"
        );
    }
    assert!(search::directory("host/bin/rustc", "$ORIGIN/../lib").is_err());
}

#[test]
fn declarations_preserve_the_existing_finite_catalogue() {
    let mut directories = (0..32)
        .map(|index| format!("toolchain/lib/{index}"))
        .collect::<Vec<_>>();
    search::declare(&mut directories, "toolchain/lib/0".into()).unwrap();
    assert_eq!(directories.len(), 32);
    assert!(search::declare(&mut directories, "toolchain/new".into()).is_err());
}

fn path(value: &str) -> memcordon_core::workload_files::RootRelativePath {
    memcordon_core::workload_files::RootRelativePath::new(value.into()).unwrap()
}
fn regular(value: &str) -> memcordon_core::workload_files::ImageEntryV1 {
    memcordon_core::workload_files::ImageEntryV1::Regular {
        path: path(value),
        sha256: memcordon_core::DiagnosticSha256::from_bytes([7; 32]),
        size: 1,
        executable: true,
    }
}
fn measured(
    member: &str,
    original: &str,
) -> (
    memcordon_core::workload_files::RootRelativePath,
    String,
    String,
) {
    (
        path(member),
        original.into(),
        search::directory(member, original).unwrap(),
    )
}

#[test]
fn final_definition_keeps_measured_absent_origin_search_but_prunes_unmeasured_host_candidates() {
    let wrapper = "toolchain/lib/rustlib/aarch64-unknown-linux-gnu/bin/gcc-ld/ld.lld";
    let compiler = "toolchain/bin/rustc";
    let searches = vec![
        measured(wrapper, "$ORIGIN/../lib"),
        measured(compiler, "$ORIGIN/../lib"),
        measured(wrapper, "$ORIGIN/../lib"),
    ];
    let output = search::definition(
        "aarch64-unknown-linux-gnu",
        vec![
            regular(wrapper),
            regular(compiler),
            regular("toolchain/lib/libactual.so"),
        ],
        vec![],
        vec![path("toolchain/lib"), path("usr/lib"), path("opt/unused")],
        &searches,
    )
    .unwrap();
    output.validate().unwrap();
    let catalogue = output
        .library_directories
        .as_slice()
        .iter()
        .map(|entry| entry.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        catalogue,
        [
            "toolchain/lib",
            "toolchain/lib/rustlib/aarch64-unknown-linux-gnu/bin/lib"
        ]
    );
    for (_, _, directory) in searches {
        assert!(catalogue.contains(&directory.as_str()));
    }
    assert!(!output.entries.as_slice().iter().any(|entry| {
        entry
            .path()
            .as_str()
            .starts_with("toolchain/lib/rustlib/aarch64-unknown-linux-gnu/bin/lib/")
    }));
}

#[test]
fn final_definition_requires_real_original_member_normalization_and_finite_stable_catalogue() {
    let member = "toolchain/bin/rustc";
    let searches = (0..32)
        .map(|index| measured(member, &format!("$ORIGIN/../lib/s{index}")))
        .collect::<Vec<_>>();
    let output = search::definition(
        "aarch64-unknown-linux-gnu",
        vec![regular(member)],
        vec![],
        vec![path("usr/lib")],
        &searches,
    )
    .unwrap();
    assert_eq!(output.library_directories.as_slice().len(), 32);
    for (actual, (_, _, expected)) in output.library_directories.as_slice().iter().zip(&searches) {
        assert_eq!(actual.as_str(), expected);
    }
    let mut excessive = searches;
    excessive.push(measured(member, "$ORIGIN/../lib/excess"));
    assert!(
        search::definition(
            "aarch64-unknown-linux-gnu",
            vec![regular(member)],
            vec![],
            vec![],
            &excessive
        )
        .is_err()
    );
    let measured = vec![measured(member, "$ORIGIN/../lib")];
    assert!(
        search::definition(
            "aarch64-unknown-linux-gnu",
            vec![regular("toolchain/bin/other")],
            vec![],
            vec![],
            &measured
        )
        .is_err()
    );
    let mut forged = measured;
    forged[0].2 = "toolchain/undeclared".into();
    assert!(
        search::definition(
            "aarch64-unknown-linux-gnu",
            vec![regular(member)],
            vec![],
            vec![],
            &forged
        )
        .is_err()
    );
}
