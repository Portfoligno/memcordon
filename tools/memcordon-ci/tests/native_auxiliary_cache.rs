use memcordon_ci::{
    cache_restore::{self, RestoreMode},
    command::rustup_cargo,
};
use std::{fs, path::Path, time::Duration};

#[test]
fn default_profile_cleanup_preserves_ci_driver_and_report_siblings() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    fs::create_dir_all(root.join("local/src")).unwrap();
    fs::create_dir(root.join("ci")).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/toolchains.toml"),
        root.join("ci/toolchains.toml"),
    )
    .unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers=[\"local\"]\nresolver=\"2\"\n",
    )
    .unwrap();
    fs::write(
        root.join("local/Cargo.toml"),
        "[package]\nname=\"memcordon\"\nversion=\"0.0.0\"\nedition=\"2021\"\n",
    )
    .unwrap();
    fs::write(
        root.join("local/src/lib.rs"),
        "pub fn current() -> bool { true }\n",
    )
    .unwrap();
    let stable = memcordon_ci::config::toolchains(root).unwrap().stable;
    fs::create_dir_all(root.join("target/ci/release")).unwrap();
    fs::create_dir_all(root.join("target/ci/reports")).unwrap();
    // Preserve the real executing test driver's bytes under the sibling CI
    // layout, alongside report state. Neither belongs to the two cache roots.
    let driver = fs::read(std::env::current_exe().unwrap()).unwrap();
    fs::write(
        root.join("target/ci/release/running-driver-sentinel"),
        &driver,
    )
    .unwrap();
    fs::write(root.join("target/ci/reports/sentinel"), "current report\n").unwrap();
    for mode in [RestoreMode::Exact, RestoreMode::Compatible] {
        for release in [false, true] {
            let mut command = rustup_cargo(
                root,
                &stable,
                ["build", "--offline", "--package", "memcordon"],
                Duration::from_secs(120),
            );
            if release {
                command = command.arg("--release");
            }
            command.run().unwrap();
        }
        assert!(root.join("target/debug/libmemcordon.rlib").exists());
        assert!(root.join("target/release/libmemcordon.rlib").exists());
        cache_restore::prepare(root, "native-auxiliary", "complete", mode).unwrap();
        assert!(!root.join("target/debug/libmemcordon.rlib").exists());
        assert!(!root.join("target/release/libmemcordon.rlib").exists());
        assert_eq!(
            fs::read(root.join("target/ci/release/running-driver-sentinel")).unwrap(),
            driver
        );
        assert!(root.join("target/ci/reports/sentinel").exists());
    }
    cache_restore::prepare(root, "native-auxiliary", "complete", RestoreMode::Discard).unwrap();
    assert!(!root.join("target/debug").exists());
    assert!(!root.join("target/release").exists());
    assert!(
        root.join("target/ci/release/running-driver-sentinel")
            .exists()
    );
    assert!(root.join("target/ci/reports/sentinel").exists());
}
