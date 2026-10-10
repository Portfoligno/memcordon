use memcordon_ci::public_install_capture::{Descriptor, selected_output};
use std::ffi::OsString;

fn fixture() -> (tempfile::TempDir, Descriptor, Vec<OsString>) {
    let root = tempfile::tempdir().unwrap();
    let registry = root.path().join("registry");
    let source = registry.join("memcordon-0.1.0/src/bin");
    std::fs::create_dir_all(&source).unwrap();
    let source = source.join("some-tool.rs");
    std::fs::write(&source, b"fn main() {}\n").unwrap();
    let descriptor = Descriptor {
        format: "memcordon.public-install-capture".into(),
        revision: 1,
        compiler: root.path().join("rustc"),
        compiler_sha256: "0".repeat(64),
        wrapper_sha256: "1".repeat(64),
        target: "aarch64-pc-windows-msvc".into(),
        registry_source: registry,
        target_directory: root.path().join("target"),
        capture_directory: root.path().join("capture"),
        package: "memcordon".into(),
        version: "0.1.0".into(),
        binaries: vec!["some-tool".into()],
        deadline_unix_millis: 1,
    };
    let args = vec![
        "--crate-name".into(),
        "some_tool".into(),
        source.into_os_string(),
        "--crate-type=bin".into(),
        "--target=aarch64-pc-windows-msvc".into(),
        "--out-dir".into(),
        descriptor
            .target_directory
            .join(&descriptor.target)
            .join("release/deps")
            .into_os_string(),
        "--emit=dep-info,link".into(),
        "-Cextra-filename=-0123456789abcdef".into(),
    ];
    (root, descriptor, args)
}

#[test]
fn maps_actual_compiler_output_to_cargo_uplift_with_distinct_bin_spelling() {
    let (_root, descriptor, args) = fixture();
    assert!(selected_output(&descriptor, &[OsString::from("x".repeat(128 * 1024 + 1))]).is_err());
    let (binary, source, original, cargo) = selected_output(&descriptor, &args).unwrap().unwrap();
    assert_eq!(binary, "some-tool");
    assert!(source.ends_with("some-tool.rs"));
    assert_eq!(
        original,
        descriptor
            .target_directory
            .join(&descriptor.target)
            .join("release/deps/some_tool-0123456789abcdef.exe")
    );
    assert_eq!(
        cargo,
        descriptor
            .target_directory
            .join(&descriptor.target)
            .join("release/some-tool.exe")
    );
    assert!(
        selected_output(&descriptor, &["-vV".into()])
            .unwrap()
            .is_none()
    );
}

#[test]
fn refuses_ambiguous_foreign_and_output_redirected_invocations() {
    let (_root, descriptor, args) = fixture();
    for addition in [
        vec!["--target=foreign"],
        vec!["@arguments"],
        vec!["-o", "elsewhere"],
        vec!["-C", "extra-filename=-abc"],
        vec!["--emit=link=elsewhere"],
    ] {
        let mut hostile = args.clone();
        hostile.extend(addition.into_iter().map(OsString::from));
        assert!(selected_output(&descriptor, &hostile).is_err());
    }
    let mut collision = descriptor.clone();
    collision.binaries.push("some_tool".into());
    assert!(selected_output(&collision, &args).is_err());
    let mut foreign = descriptor.clone();
    foreign.registry_source = foreign.target_directory.clone();
    std::fs::create_dir_all(&foreign.registry_source).unwrap();
    assert!(selected_output(&foreign, &args).is_err());
}

#[test]
fn synchronous_wrapper_retains_real_compiler_bytes_before_cargo_consumes_output() {
    use sha2::{Digest, Sha256};
    let (root, mut descriptor, args) = fixture();
    let compiler = std::process::Command::new("rustup")
        .args(["which", "rustc"])
        .output()
        .unwrap();
    assert!(compiler.status.success());
    descriptor.compiler = std::fs::canonicalize(std::path::PathBuf::from(
        String::from_utf8(compiler.stdout).unwrap().trim(),
    ))
    .unwrap();
    let version = std::process::Command::new(&descriptor.compiler)
        .arg("-vV")
        .output()
        .unwrap();
    assert!(version.status.success());
    descriptor.target = String::from_utf8(version.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap()
        .to_owned();
    std::fs::create_dir(&descriptor.target_directory).unwrap();
    descriptor.target_directory = std::fs::canonicalize(&descriptor.target_directory).unwrap();
    std::fs::create_dir(&descriptor.capture_directory).unwrap();
    let wrapper = root.path().join(format!(
        "{}{}",
        memcordon_ci::public_install_capture::WRAPPER_NAME,
        std::env::consts::EXE_SUFFIX
    ));
    std::fs::copy(env!("CARGO_BIN_EXE_memcordon-ci"), &wrapper).unwrap();
    // Exercise the actual driver without carrying its unrelated debug sections
    // into the bounded executable fixture. Never modify Cargo's original image.
    #[cfg(target_os = "linux")]
    {
        let stripped = std::process::Command::new("strip")
            .arg("--strip-debug")
            .arg(&wrapper)
            .output()
            .unwrap();
        assert!(
            stripped.status.success(),
            "{}",
            String::from_utf8_lossy(&stripped.stderr)
        );
    }
    descriptor.wrapper_sha256 = hex::encode(Sha256::digest(std::fs::read(&wrapper).unwrap()));
    descriptor.compiler_sha256 =
        hex::encode(Sha256::digest(std::fs::read(&descriptor.compiler).unwrap()));
    descriptor.deadline_unix_millis = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 60_000;
    let source = std::path::PathBuf::from(&args[2]);
    let manifest = source
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("Cargo.toml");
    std::fs::write(
        &manifest,
        b"[package]\nname='memcordon'\nversion='0.1.0'\nedition='2021'\n[workspace]\n",
    )
    .unwrap();
    let cargo_config = root.path().join("capture-cargo.toml");
    std::fs::write(
        &cargo_config,
        toml::to_string(&serde_json::json!({"build": {
            "rustc": descriptor.compiler,
            "rustc-wrapper": wrapper,
        }}))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.path()
            .join(memcordon_ci::public_install_capture::DESCRIPTOR_NAME),
        serde_json::to_vec(&descriptor).unwrap(),
    )
    .unwrap();
    let execute = || {
        std::process::Command::new(env!("CARGO"))
            .current_dir(manifest.parent().unwrap())
            .args(["build", "--offline", "--release", "--target"])
            .arg(&descriptor.target)
            .arg("--target-dir")
            .arg(&descriptor.target_directory)
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--config")
            .arg(&cargo_config)
            .output()
            .unwrap()
    };
    let observed = execute();
    assert!(
        observed.status.success(),
        "{}",
        String::from_utf8_lossy(&observed.stderr)
    );
    let receipt =
        memcordon_ci::public_install_capture::load_receipt(&descriptor, "some-tool").unwrap();
    let installed = root.path().join("installed");
    // Cargo has already uplifted the actual compiler output. Consume both
    // paths to prove verification does not depend on their later lifetime.
    std::fs::remove_file(&receipt.original_output).unwrap();
    std::fs::rename(&receipt.cargo_output, &installed).unwrap();
    assert!(!receipt.original_output.exists());
    let retained =
        memcordon_ci::public_install_capture::load_receipt(&descriptor, "some-tool").unwrap();
    assert_eq!(
        std::fs::read(retained.retained_output).unwrap(),
        std::fs::read(installed).unwrap()
    );
    assert!(!execute().status.success(), "duplicate capture must refuse");
    for probe in ["-vV", "--not-a-real-compiler-option"] {
        let direct = std::process::Command::new(&descriptor.compiler)
            .arg(probe)
            .output()
            .unwrap();
        let wrapped = std::process::Command::new(&wrapper)
            .arg(&descriptor.compiler)
            .arg(probe)
            .output()
            .unwrap();
        assert_eq!(wrapped.status.code(), direct.status.code());
        assert_eq!(wrapped.stdout, direct.stdout);
        assert_eq!(wrapped.stderr, direct.stderr);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let signal_source = root.path().join("aborting_compiler.rs");
        std::fs::write(&signal_source, b"fn main() { std::process::abort(); }\n").unwrap();
        let compiled = std::process::Command::new(&descriptor.compiler)
            .args(["--crate-name", "aborting_compiler"])
            .arg(&signal_source)
            .arg("--out-dir")
            .arg(root.path())
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        descriptor.compiler = std::fs::canonicalize(root.path().join("aborting_compiler")).unwrap();
        descriptor.compiler_sha256 =
            hex::encode(Sha256::digest(std::fs::read(&descriptor.compiler).unwrap()));
        std::fs::write(
            wrapper
                .parent()
                .unwrap()
                .join(memcordon_ci::public_install_capture::DESCRIPTOR_NAME),
            serde_json::to_vec(&descriptor).unwrap(),
        )
        .unwrap();
        let terminated = std::process::Command::new(&wrapper)
            .arg(&descriptor.compiler)
            .output()
            .unwrap();
        assert_eq!(terminated.status.signal(), Some(libc::SIGABRT));
    }
}
