use memcordon_ci::release::source;

#[test]
fn unavailable_metadata_toolchain_retains_native_error_and_selected_toolchain() {
    let directory = if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    std::fs::create_dir(directory.path().join("ci")).unwrap();
    std::fs::write(
        directory.path().join("ci").join("toolchains.toml"),
        "stable = \"memcordon-ci-absent-metadata-regression\"\nmsrv = \"1.85.0\"\nmiri = \"nightly-2026-07-31\"\n",
    ).unwrap();
    let error = source::metadata(directory.path()).unwrap_err().to_string();
    assert!(error.contains("Cargo metadata failed with"), "{error}");
    assert!(
        error.contains("using toolchain memcordon-ci-absent-metadata-regression"),
        "{error}"
    );
    assert!(
        error.contains("not installed"),
        "native rustup stderr must survive: {error}"
    );
}
