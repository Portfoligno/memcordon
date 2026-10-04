use memcordon_ci::command::PackageOutput;
use std::{ffi::OsStr, fs, path::Path};

#[test]
fn package_producer_and_consumer_share_explicit_target() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let absolute = temporary.path().join("absolute output with spaces");
    let mut targets = vec![
        None,
        Some(Path::new("target/channel output")),
        Some(absolute.as_path()),
    ];
    #[cfg(unix)]
    let non_unicode = {
        use std::os::unix::ffi::OsStringExt;
        std::path::PathBuf::from(std::ffi::OsString::from_vec(
            b"target/channel-\xff".to_vec(),
        ))
    };
    #[cfg(unix)]
    targets.push(Some(non_unicode.as_path()));
    for target in targets {
        let output = PackageOutput::new(&root, target).unwrap();
        let expected = target.map_or_else(
            || root.join("target"),
            |path| {
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    root.join(path)
                }
            },
        );
        assert_eq!(output.archive_directory(), expected.join("package"));
        // macOS rejects invalid UTF-8 file names; native argv must still preserve them.
        if expected.to_str().is_some() || !cfg!(target_os = "macos") {
            fs::create_dir_all(output.archive_directory()).unwrap();
            let archive = output.archive_directory().join("fixture-one-1.0.0.crate");
            fs::write(&archive, b"archive bytes\n").unwrap();
            assert_eq!(
                fs::read_dir(output.archive_directory())
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path(),
                archive
            );
        }
        let command = output
            .command(
                &root,
                "1.97.1",
                &["fixture-one".into(), "fixture-two".into()],
            )
            .materialize()
            .unwrap();
        assert_eq!(command.get_program(), "rustup");
        let args = command.get_args().collect::<Vec<_>>();
        assert_eq!(&args[..3], ["run", "1.97.1", "cargo"]);
        let index = args.iter().position(|arg| *arg == "--target-dir").unwrap();
        assert_eq!(args[index + 1], expected);
        assert!(args.contains(&OsStr::new("--locked")));
        assert!(args.contains(&OsStr::new("--no-verify")));
        assert_eq!(args.iter().filter(|arg| **arg == "--package").count(), 2);
        assert!(!command.get_envs().any(|(key, _)| key == "CARGO_TARGET_DIR"));
        assert_eq!(command.get_current_dir(), Some(root.as_path()));
    }
}
