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
        "[package]\nname=\"memcordon\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[dependencies]\nhex=\"=0.4.3\"\n",
    )
    .unwrap();
    fs::write(
        root.join("local/src/lib.rs"),
        "pub fn current() -> String { hex::encode([1_u8]) }\n",
    )
    .unwrap();
    let stable = memcordon_ci::config::toolchains(root).unwrap().stable;
    // A package-scoped clean initializes a genuine Cargo target before the
    // nested driver bootstrap creates its parent. It compiles nothing.
    rustup_cargo(
        root,
        &stable,
        [
            "clean",
            "--offline",
            "--package",
            "memcordon",
            "--target-dir",
            "target",
        ],
        Duration::from_secs(120),
    )
    .run()
    .unwrap();
    assert!(root.join("target/CACHEDIR.TAG").is_file());
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
        let mut external = Vec::new();
        for release in [false, true] {
            let mut command = rustup_cargo(
                root,
                &stable,
                [
                    "build",
                    "--offline",
                    "--package",
                    "memcordon",
                    "--message-format=json",
                ],
                Duration::from_secs(120),
            );
            if release {
                command = command.arg("--release");
            }
            let output = command.output_quiet().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            for line in output
                .stdout
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
            {
                let message: serde_json::Value = serde_json::from_slice(line).unwrap();
                if message["reason"] == "compiler-artifact" && message["target"]["name"] == "hex" {
                    for filename in message["filenames"].as_array().unwrap() {
                        let path = std::path::PathBuf::from(filename.as_str().unwrap());
                        external.push((path.clone(), fs::read(path).unwrap()));
                    }
                }
            }
        }
        assert!(!external.is_empty(), "real registry artifact required");
        assert!(root.join("target/debug/libmemcordon.rlib").exists());
        assert!(root.join("target/release/libmemcordon.rlib").exists());
        let layout = cache_restore::layout("native-auxiliary", "complete").unwrap();
        assert_eq!(
            layout.required_files,
            [std::path::PathBuf::from("target/CACHEDIR.TAG")]
        );
        assert!(
            cache_restore::payload_ready(root, "native-auxiliary", "complete").unwrap(),
            "marker: {:?}",
            fs::read(root.join("target/CACHEDIR.TAG"))
        );
        let mut archive = tar::Builder::new(Vec::new());
        for path in layout.archive_members() {
            if root.join(&path).is_dir() {
                archive.append_dir_all(&path, root.join(&path)).unwrap();
            } else {
                archive
                    .append_path_with_name(root.join(&path), &path)
                    .unwrap();
            }
        }
        let archive = archive.into_inner().unwrap();
        for path in &layout.directories {
            fs::remove_dir_all(root.join(path)).unwrap();
        }
        fs::remove_file(root.join("target/CACHEDIR.TAG")).unwrap();
        tar::Archive::new(archive.as_slice()).unpack(root).unwrap();
        assert!(root.join("target/CACHEDIR.TAG").is_file());
        if matches!(mode, RestoreMode::Compatible) {
            fs::write(
                root.join("local/src/lib.rs"),
                "pub fn current() -> String { hex::encode([2_u8]) }\n",
            )
            .unwrap();
        }
        cache_restore::prepare(root, "native-auxiliary", "complete", mode).unwrap();
        for (path, bytes) in &external {
            assert_eq!(fs::read(path).unwrap(), *bytes);
        }
        assert!(!root.join("target/debug/libmemcordon.rlib").exists());
        assert!(!root.join("target/release/libmemcordon.rlib").exists());
        assert_eq!(
            fs::read(root.join("target/ci/release/running-driver-sentinel")).unwrap(),
            driver
        );
        assert!(root.join("target/ci/reports/sentinel").exists());
        for release in [false, true] {
            let mut command = rustup_cargo(
                root,
                &stable,
                [
                    "build",
                    "--offline",
                    "--package",
                    "memcordon",
                    "--message-format=json",
                ],
                Duration::from_secs(120),
            );
            if release {
                command = command.arg("--release");
            }
            let output = command.output_quiet().unwrap();
            assert!(output.status.success());
            let messages = output
                .stdout
                .split(|byte| *byte == b'\n')
                .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
                .collect::<Vec<_>>();
            assert!(
                messages
                    .iter()
                    .any(|message| message["reason"] == "compiler-artifact"
                        && message["target"]["name"] == "hex"
                        && message["fresh"] == true),
                "Cargo must reuse the transported external artifact"
            );
        }
    }
    fs::remove_dir_all(root.join("target/release")).unwrap();
    assert!(
        !cache_restore::payload_ready(root, "native-auxiliary", "complete").unwrap(),
        "a single populated profile belongs only to a partial seed"
    );
    fs::remove_dir_all(root.join("target/debug")).unwrap();
    fs::create_dir(root.join("target/debug")).unwrap();
    assert!(
        !cache_restore::payload_ready(root, "native-auxiliary", "complete").unwrap(),
        "empty profile is not a payload"
    );
    cache_restore::prepare(root, "native-auxiliary", "complete", RestoreMode::Discard).unwrap();
    assert!(!root.join("target/debug").exists());
    assert!(!root.join("target/release").exists());
    assert!(
        root.join("target/ci/release/running-driver-sentinel")
            .exists()
    );
    assert!(root.join("target/ci/reports/sentinel").exists());
}

#[test]
fn auxiliary_layout_changes_exact_and_compatible_identity_only_for_its_family() {
    use memcordon_ci::cache_inputs::{KeyInputs, keys};
    use std::collections::BTreeMap;
    let mut inputs = KeyInputs {
        family: "workspace".into(),
        layout_revision: 4,
        compatibility: BTreeMap::from([("purpose".into(), "native-auxiliary".into())]),
        content: BTreeMap::from([("source".into(), "unchanged".into())]),
    };
    let old = keys(&inputs).unwrap();
    inputs.layout_revision = cache_restore::layout("native-auxiliary", "complete")
        .unwrap()
        .revision;
    let revised = keys(&inputs).unwrap();
    assert_ne!(old.0, revised.0);
    assert_ne!(old.1, revised.1);
    assert_eq!(
        cache_restore::layout("native-debug", "complete")
            .unwrap()
            .revision,
        4
    );
    assert_eq!(
        cache_restore::roots("native-auxiliary", "complete").unwrap(),
        [
            std::path::PathBuf::from("target/debug"),
            std::path::PathBuf::from("target/release")
        ]
    );
}
