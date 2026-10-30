use memcordon_ci::windows_consumer_readiness::descriptor::{self, LinkerMode, Toolchain};
use std::{ffi::OsString, path::PathBuf};

fn input(target: &str) -> Toolchain {
    let root = std::env::temp_dir()
        .join("native-linker-command")
        .join("locked-inputs");
    let rustc = root.join("toolchain").join("bin").join("rustc.exe");
    let linker = root
        .join("toolchain")
        .join("lib")
        .join("rustlib")
        .join(target)
        .join("bin")
        .join("rust-lld.exe");
    // This is selection/argv data, never a PE or filesystem qualification fixture.
    let images = descriptor::project_toolchain_images(
        [rustc.clone(), linker.clone()].into_iter().map(|path| {
            (
                path,
                memcordon_ci::windows_causal_acceptance::sha256(b"frozen selected-image fixture"),
            )
        }),
    )
    .unwrap();
    Toolchain {
        native_work_cutoff_ticks: 1,
        native_work_frequency: 1,
        linker_mode: LinkerMode::BundledLldLink,
        input_root: root.clone(),
        rustc,
        native_linker: linker,
        selected_images: images,
        native_library_directories: ["msvc-lib", "sdk-ucrt", "sdk-um"]
            .map(|name| root.join(name))
            .to_vec(),
        library_source: root.join("library.rs"),
        test_source: root.join("tests.rs"),
        child_source: root.join("child.rs"),
        dll_source: root.join("dll.rs"),
        loader_source: root.join("loader.rs"),
        target: target.into(),
    }
}

#[test]
fn both_targets_use_exact_static_linker_flavor_libraries_and_qualified_cwd() {
    for (target, linker) in [
        (
            "x86_64-pc-windows-msvc",
            "linker=./toolchain/lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe",
        ),
        (
            "aarch64-pc-windows-msvc",
            "linker=./toolchain/lib/rustlib/aarch64-pc-windows-msvc/bin/rust-lld.exe",
        ),
    ] {
        let input = input(target);
        let output = input
            .input_root
            .parent()
            .unwrap()
            .join("compiled")
            .join("product.exe");
        for flags in [
            vec!["--crate-type=rlib"],
            vec![],
            vec!["--test"],
            vec!["--crate-type=cdylib"],
        ] {
            let command = descriptor::toolchain_command::compile_command(
                &input,
                &input.child_source,
                &output,
                &flags,
            )
            .unwrap();
            assert_eq!(command.get_program(), input.rustc.as_os_str());
            assert_eq!(command.get_current_dir(), Some(input.input_root.as_path()));
            let mut expected = vec![input.child_source.as_os_str().to_owned()];
            expected.extend(flags.iter().map(|flag| OsString::from(*flag)));
            expected.extend(
                [
                    "--edition=2021",
                    "--target",
                    target,
                    "-C",
                    linker,
                    "-C",
                    "linker-flavor=lld-link",
                    "-o",
                ]
                .map(OsString::from),
            );
            expected.push(output.as_os_str().to_owned());
            expected.extend(
                [
                    "-L",
                    "native=./msvc-lib",
                    "-L",
                    "native=./sdk-ucrt",
                    "-L",
                    "native=./sdk-um",
                ]
                .map(OsString::from),
            );
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                expected.iter().map(OsString::as_os_str).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn malformed_layout_or_selection_never_falls_back_to_another_linker() {
    let valid = input("x86_64-pc-windows-msvc");
    let mut candidates = Vec::new();
    let mut changed = valid.clone();
    changed.target = "aarch64-pc-windows-msvc".into();
    candidates.push(changed);
    let mut changed = valid.clone();
    changed.target = "x86_64-unknown-linux-gnu".into();
    candidates.push(changed);
    let mut changed = valid.clone();
    changed.native_linker = changed.input_root.join("link.exe");
    candidates.push(changed);
    let mut changed = valid.clone();
    changed.input_root = PathBuf::from("locked-inputs");
    candidates.push(changed);
    let mut changed = valid.clone();
    changed.native_library_directories.swap(0, 1);
    candidates.push(changed);
    let mut changed = valid.clone();
    changed
        .native_library_directories
        .push(changed.input_root.join("ambient"));
    candidates.push(changed);
    let mut changed = valid.clone();
    changed
        .selected_images
        .retain(|image| image.path != changed.native_linker);
    candidates.push(changed);
    let mut changed = valid.clone();
    changed.selected_images[0].sha256 = "invalid".into();
    candidates.push(changed);
    for input in candidates {
        assert!(
            descriptor::toolchain_command::compile_command(
                &input,
                &input.child_source,
                &input.loader_source,
                &[]
            )
            .is_err()
        );
    }
    assert!(
        descriptor::toolchain_command::compile_command(
            &valid,
            std::path::Path::new("relative.rs"),
            &valid.loader_source,
            &[]
        )
        .is_err()
    );
    assert!(
        descriptor::toolchain_command::compile_command(
            &valid,
            &valid.child_source,
            std::path::Path::new("relative.exe"),
            &[]
        )
        .is_err()
    );
    let mut encoded = serde_json::to_value(&valid).unwrap();
    encoded.as_object_mut().unwrap().remove("linker_mode");
    assert!(serde_json::from_value::<Toolchain>(encoded).is_err());
    let mut encoded = serde_json::to_value(&valid).unwrap();
    encoded["linker_mode"] = "ambient-linker".into();
    assert!(serde_json::from_value::<Toolchain>(encoded).is_err());
}
