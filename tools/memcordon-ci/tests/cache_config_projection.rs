use memcordon_ci::cache_inputs::{self, KeyInputs};
use std::collections::BTreeMap;

#[test]
fn actual_config_layers_use_nearest_scalars_extensionless_precedence_and_explicit_home() {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path().canonicalize().unwrap();
    let root = base.join("workspace");
    let home = base.join("isolated-home");
    for path in [base.join(".cargo"), root.join(".cargo"), home.clone()] {
        std::fs::create_dir_all(path).unwrap();
    }
    std::fs::write(
        base.join(".cargo/config.toml"),
        "profile.release.opt-level=1\nprofile.release.codegen-units=4\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".cargo/config"),
        "profile.release.opt-level=3\nbuild.jobs=2\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".cargo/config.toml"),
        "registry.token='ignored-secret'\n",
    )
    .unwrap();
    std::fs::write(
        home.join("config.toml"),
        "profile.release.opt-level=0\nbuild.incremental=true\n",
    )
    .unwrap();
    let projection = cache_inputs::cargo_configs_with_home(&root, &home, None).unwrap();
    assert_eq!(projection["profile.release.opt-level"], "3");
    assert_eq!(projection["profile.release.codegen-units"], "4");
    assert_eq!(projection["build.incremental"], "true");
    assert!(!projection.contains_key("build.jobs"));
    std::fs::write(
        root.join(".cargo/config"),
        "# include rustflags @ token\nprofile.release.opt-level=3\nbuild.jobs=8\n",
    )
    .unwrap();
    assert_eq!(
        projection,
        cache_inputs::cargo_configs_with_home(&root, &home, None).unwrap()
    );
}

#[test]
fn comments_operational_settings_and_equivalent_toml_shapes_do_not_change_identity() {
    let first = cache_inputs::project_cargo_config(
        "# token include rustflags @\n[build]\njobs=2\nincremental=true\n[profile.release]\nopt-level=3\n",
        None,
        false,
    ).unwrap();
    let second = cache_inputs::project_cargo_config(
        "build={jobs=8,incremental=true}\nprofile.release.opt-level=3\nnet.retry=2\nhttp.timeout=30\n",
        None,
        false,
    ).unwrap();
    assert_eq!(first, second);
    let changed = cache_inputs::project_cargo_config(
        "build.incremental=false\nprofile.release.opt-level=3\n",
        None,
        false,
    )
    .unwrap();
    assert_ne!(first, changed);
}

#[test]
fn unknown_semantics_secrets_and_invalid_scalar_values_fail_closed() {
    for text in [
        "build.rustflags=['-C','opt-level=3']",
        "build.rustc-wrapper='wrapper'",
        "include='other.toml'",
        "registry.token='secret'",
        "source.crates-io.replace-with='private'",
        "registries.private.index='https://user:secret@example.invalid'",
        "profile.release.lto=true",
        "profile.release.package.example.opt-level=3",
        "profile.release.build-override.opt-level=3",
        "profile.custom.inherits='release'",
        "build.incremental=1",
        "profile.release.codegen-units=0",
        "profile.release.debug=4",
        "net.retry='2'",
        "http.proxy='https://user:secret@example.invalid'",
        "build.target=['x86_64-unknown-linux-gnu']",
    ] {
        let error =
            cache_inputs::project_cargo_config(text, Some("x86_64-unknown-linux-gnu"), false)
                .unwrap_err();
        assert!(!error.to_string().contains("secret"));
    }
    assert!(
        cache_inputs::project_cargo_config("build.target='x86_64-unknown-linux-gnu'", None, false)
            .is_err()
    );
    assert!(
        cache_inputs::project_cargo_config(
            "build.target='aarch64-unknown-linux-gnu'",
            Some("x86_64-unknown-linux-gnu"),
            false
        )
        .is_err()
    );
    assert!(
        cache_inputs::project_cargo_config(
            "build.target='x86_64-unknown-linux-gnu'",
            Some("x86_64-unknown-linux-gnu"),
            false
        )
        .is_ok()
    );
}

#[test]
fn encoded_flags_preserve_order_and_duplicates_without_a_shell_parser() {
    let flags = "-C\u{1f}opt-level=2\u{1f}-C\u{1f}opt-level=3";
    let tokens = cache_inputs::encoded_rustflags(flags).unwrap();
    assert_eq!(tokens, ["-C", "opt-level=2", "-C", "opt-level=3"]);
    assert_ne!(
        tokens,
        cache_inputs::encoded_rustflags("-C\u{1f}opt-level=3\u{1f}-C\u{1f}opt-level=2").unwrap()
    );
    for flags in [
        "-Copt-level=3",
        "-C opt-level=3",
        "-C\u{1f}linker=other",
        "-L\u{1f}native=/tmp",
        "-C\u{1f}codegen-units=0",
        "-C\u{1f}panic=unknown",
        "-C\u{1f}opt-level=3\u{1f}",
    ] {
        assert!(cache_inputs::encoded_rustflags(flags).is_err());
    }
    assert!(cache_inputs::incremental_setting("0").is_ok());
    assert!(cache_inputs::incremental_setting("1").is_ok());
    assert!(cache_inputs::incremental_setting("true").is_err());
}

#[test]
fn finite_seed_families_and_layouts_never_share_legacy_prefixes() {
    for family in [
        "compiled-seed",
        "registry-archive-seed",
        "registry-index-snapshot",
        "miri-sysroot",
    ] {
        let mut input = KeyInputs {
            family: family.into(),
            layout_revision: 6,
            compatibility: BTreeMap::new(),
            content: BTreeMap::new(),
        };
        let current = cache_inputs::keys(&input).unwrap();
        input.layout_revision = 5;
        assert_ne!(current.1, cache_inputs::keys(&input).unwrap().1);
    }
}
