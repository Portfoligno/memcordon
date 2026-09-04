use std::ffi::OsString;

use memcordon_ci::windows_package_staging::{
    ExternalWindowsPackageSources, WINDOWS_PACKAGE_NAMES, WindowsPackageSourceLayout,
    validate_staging_outside_repository,
};
use tempfile::TempDir;

#[test]
fn execution_staging_is_owned_external_and_retired_on_drop() {
    let repository = TempDir::new().unwrap();
    std::fs::write(repository.path().join("Cargo.toml"), "[workspace]\n").unwrap();

    let staging = ExternalWindowsPackageSources::new(repository.path()).unwrap();
    let staging_root = staging.temporary_root().to_path_buf();
    assert!(!staging_root.starts_with(repository.path()));
    assert!(staging.layout().root().starts_with(&staging_root));
    assert!(staging.layout().root().is_dir());
    drop(staging);
    assert!(!staging_root.exists());
}

#[test]
fn repository_descendant_staging_is_rejected() {
    let repository = TempDir::new().unwrap();
    let staging = repository.path().join("target").join("packaged-sources");
    std::fs::create_dir_all(&staging).unwrap();

    let error = validate_staging_outside_repository(repository.path(), &staging).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("outside the repository workspace")
    );
}

#[test]
fn layout_keeps_all_package_sources_and_configuration_under_staging() {
    let staging = TempDir::new().unwrap();
    let sources = staging.path().join("packaged-sources");
    let layout = WindowsPackageSourceLayout::new(sources.clone());

    assert_eq!(layout.root(), sources);
    assert_eq!(
        layout.package_destinations().map(|(package, _)| package),
        WINDOWS_PACKAGE_NAMES
    );
    for (_, destination) in layout.package_destinations() {
        assert!(destination.starts_with(staging.path()));
    }
    assert!(layout.cargo_config().starts_with(staging.path()));
    assert!(layout.cli().starts_with(staging.path()));
}

#[test]
fn configuration_and_install_arguments_bind_the_isolated_layout() {
    let staging = TempDir::new().unwrap();
    let layout = WindowsPackageSourceLayout::new(staging.path().join("packaged-sources"));
    std::fs::create_dir_all(layout.root()).unwrap();
    layout.write_cargo_configuration().unwrap();

    let configuration: toml::Value =
        toml::from_str(&std::fs::read_to_string(layout.cargo_config()).unwrap()).unwrap();
    let patches = configuration["patch"]["crates-io"].as_table().unwrap();
    for (package, destination) in layout.package_destinations().into_iter().take(3) {
        assert_eq!(
            patches[package]["path"].as_str().unwrap(),
            destination.to_string_lossy()
        );
    }
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        assert_eq!(
            configuration["target"][target]["rustflags"],
            toml::Value::Array(vec![
                toml::Value::String("-C".to_owned()),
                toml::Value::String("target-feature=+crt-static".to_owned()),
            ])
        );
    }

    let install_root = staging.path().join("durable-install");
    let target_root = staging.path().join("durable-target");
    assert_eq!(
        layout.cargo_install_arguments(&install_root, &target_root),
        vec![
            OsString::from("--config"),
            layout.cargo_config().as_os_str().to_os_string(),
            OsString::from("install"),
            OsString::from("--locked"),
            OsString::from("--path"),
            layout.cli().as_os_str().to_os_string(),
            OsString::from("--root"),
            install_root.into_os_string(),
            OsString::from("--target-dir"),
            target_root.into_os_string(),
            OsString::from("--force"),
        ]
    );
}
