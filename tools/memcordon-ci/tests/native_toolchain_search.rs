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
