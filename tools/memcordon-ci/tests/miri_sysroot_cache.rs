//! Real pinned-nightly acceptance. Run explicitly; ordinary portable tests do not
//! pretend that parser fixtures prove generated standard-library reuse.
use memcordon_ci::{command::CommandSpec, release::artifacts};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

fn libraries(root: &Path) -> BTreeMap<PathBuf, (u64, String, SystemTime)> {
    let mut result = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.unwrap();
        let metadata = fs::symlink_metadata(entry.path()).unwrap();
        assert!(
            !metadata.file_type().is_symlink(),
            "generated sysroot must have an ordinary transport layout"
        );
        if metadata.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "rlib")
        {
            result.insert(
                entry.path().strip_prefix(root).unwrap().to_owned(),
                (
                    metadata.len(),
                    artifacts::checksum(&fs::read(entry.path()).unwrap()),
                    metadata.modified().unwrap(),
                ),
            );
        }
    }
    assert!(
        !result.is_empty(),
        "actual setup must produce generated standard libraries"
    );
    result
}

fn setup(root: &Path, nightly: &str, sysroot: &Path) -> String {
    let before = memcordon_ci::miri_cache::identity(root)
        .unwrap()
        .expect("production Miri identity must be eligible");
    assert_eq!(before.1, sysroot);
    assert_eq!(
        memcordon_ci::miri_cache::ensure(
            root,
            nightly,
            std::time::Instant::now() + Duration::from_secs(900)
        )
        .unwrap()
        .as_deref(),
        Some(sysroot)
    );
    assert_eq!(
        memcordon_ci::miri_cache::identity(root).unwrap().as_ref(),
        Some(&before)
    );
    let output = CommandSpec::new("rustup", root, Duration::from_secs(900))
        .args(["run", nightly, "cargo", "miri", "setup", "--print-sysroot"])
        .miri_sysroot(sysroot)
        .output_quiet()
        .unwrap();
    assert!(
        output.status.success(),
        "actual pinned setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let selected = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        Path::new(selected.trim()).canonicalize().unwrap(),
        sysroot.canonicalize().unwrap(),
        "pinned setup must honor the managed root"
    );
    String::from_utf8(output.stderr).unwrap()
}

#[test]
#[ignore = "required native acceptance: builds pinned Miri sysroot, transports it, then interprets a real test"]
fn actual_pinned_sysroot_round_trip_reuses_generated_libraries_and_interprets() {
    for name in [
        "MIRI_SYSROOT",
        "MIRI_LIB_SRC",
        "MIRI_NO_STD",
        "MIRIFLAGS",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
    ] {
        assert!(
            std::env::var_os(name).is_none(),
            "acceptance requires the selected ordinary setup environment: {name}"
        );
    }
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let nightly = memcordon_ci::config::toolchains(checkout).unwrap().miri;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir(root.join("tests")).unwrap();
    fs::create_dir(root.join("ci")).unwrap();
    fs::copy(
        checkout.join("ci/toolchains.toml"),
        root.join("ci/toolchains.toml"),
    )
    .unwrap();
    memcordon_ci::miri_cache::components_only(
        &root,
        std::time::Instant::now() + Duration::from_secs(900),
    )
    .unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='miri-cache-acceptance'\nversion='0.0.0'\nedition='2021'\n[workspace]\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
    fs::write(root.join("tests/smoke.rs"), "#[test]\nfn actual_interpretation() { assert_eq!(miri_cache_acceptance::answer(), 42); }\n").unwrap();
    let sysroot = memcordon_ci::miri_cache::managed_root(&root)
        .unwrap()
        .expect("ordinary native setup remains enabled");
    let first = setup(&root, &nightly, &sysroot);
    let produced = libraries(&sysroot);
    let archive_path = root.join("sysroot.tar");
    let mut builder = tar::Builder::new(fs::File::create(&archive_path).unwrap());
    builder.append_dir_all("ci-miri-sysroot", &sysroot).unwrap();
    builder.finish().unwrap();
    drop(builder);
    fs::remove_dir_all(&sysroot).unwrap();
    tar::Archive::new(fs::File::open(&archive_path).unwrap())
        .unpack(sysroot.parent().unwrap())
        .unwrap();
    let restored = libraries(&sysroot);
    assert_eq!(
        produced
            .iter()
            .map(|(path, (size, hash, _))| (path, (*size, hash)))
            .collect::<BTreeMap<_, _>>(),
        restored
            .iter()
            .map(|(path, (size, hash, _))| (path, (*size, hash)))
            .collect::<BTreeMap<_, _>>()
    );
    let second = setup(&root, &nightly, &sysroot);
    assert_eq!(
        restored,
        libraries(&sysroot),
        "actual setup must retain transported generated libraries, including their restored modification times"
    );
    let output = CommandSpec::new("rustup", &root, Duration::from_secs(300))
        .args([
            "run",
            nightly.as_str(),
            "cargo",
            "miri",
            "test",
            "--test",
            "smoke",
            "--target-dir",
        ])
        .arg(root.join("target/interpretation"))
        .miri_sysroot(&sysroot)
        .output_quiet()
        .unwrap();
    assert!(
        output.status.success(),
        "actual interpretation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!(
        "Pinned nightly: {nightly}; generated libraries: {}; first setup: {first}; restored setup: {second}; interpretation: {}",
        restored.len(),
        String::from_utf8_lossy(&output.stdout)
    );
}
