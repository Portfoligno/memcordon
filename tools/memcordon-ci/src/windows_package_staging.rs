use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use crate::{CiError, Result};

pub const WINDOWS_PACKAGE_NAMES: [&str; 4] = [
    "memcordon-core",
    "memcordon-platform",
    "memcordon-windows-launch-core",
    "memcordon",
];

#[derive(Debug, Eq, PartialEq)]
pub struct WindowsPackageSourceLayout {
    root: PathBuf,
    core: PathBuf,
    platform: PathBuf,
    launch_core: PathBuf,
    cli: PathBuf,
    cargo_config: PathBuf,
}

impl WindowsPackageSourceLayout {
    pub fn new(root: PathBuf) -> Self {
        Self {
            core: root.join("memcordon-core"),
            platform: root.join("memcordon-platform"),
            launch_core: root.join("memcordon-windows-launch-core"),
            cli: root.join("memcordon"),
            cargo_config: root.join(".cargo").join("config.toml"),
            root,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn cli(&self) -> &Path {
        &self.cli
    }

    pub fn cargo_config(&self) -> &Path {
        &self.cargo_config
    }

    pub fn package_destinations(&self) -> [(&'static str, &Path); 4] {
        [
            (WINDOWS_PACKAGE_NAMES[0], &self.core),
            (WINDOWS_PACKAGE_NAMES[1], &self.platform),
            (WINDOWS_PACKAGE_NAMES[2], &self.launch_core),
            (WINDOWS_PACKAGE_NAMES[3], &self.cli),
        ]
    }

    pub fn write_cargo_configuration(&self) -> Result<()> {
        let cargo_configuration = self.cargo_config.parent().ok_or_else(|| {
            CiError::Message("packaged-source Cargo configuration has no parent".to_owned())
        })?;
        fs::create_dir_all(cargo_configuration)?;

        let mut crates_io = toml::Table::new();
        for (name, path) in [
            (WINDOWS_PACKAGE_NAMES[0], &self.core),
            (WINDOWS_PACKAGE_NAMES[1], &self.platform),
            (WINDOWS_PACKAGE_NAMES[2], &self.launch_core),
        ] {
            let mut specification = toml::Table::new();
            specification.insert(
                "path".to_owned(),
                toml::Value::String(path.to_string_lossy().into_owned()),
            );
            crates_io.insert(name.to_owned(), toml::Value::Table(specification));
        }

        let mut patch_table = toml::Table::new();
        patch_table.insert("crates-io".to_owned(), toml::Value::Table(crates_io));
        let mut configuration = toml::Table::new();
        configuration.insert("patch".to_owned(), toml::Value::Table(patch_table));
        configuration.insert(
            "target".to_owned(),
            windows_static_crt_target_configuration(),
        );
        let encoded = toml::to_string(&toml::Value::Table(configuration)).map_err(|error| {
            CiError::Message(format!(
                "packaged-source Cargo configuration serialization failed: {error}"
            ))
        })?;
        fs::write(&self.cargo_config, encoded)?;
        Ok(())
    }

    pub fn cargo_install_arguments(
        &self,
        install_root: &Path,
        target_root: &Path,
    ) -> Vec<OsString> {
        vec![
            OsString::from("--config"),
            self.cargo_config.clone().into_os_string(),
            OsString::from("install"),
            OsString::from("--locked"),
            OsString::from("--path"),
            self.cli.clone().into_os_string(),
            OsString::from("--root"),
            install_root.as_os_str().to_os_string(),
            OsString::from("--target-dir"),
            target_root.as_os_str().to_os_string(),
            OsString::from("--force"),
        ]
    }
}

pub struct ExternalWindowsPackageSources {
    temporary: TempDir,
    layout: WindowsPackageSourceLayout,
}

impl ExternalWindowsPackageSources {
    pub fn new(repository_root: &Path) -> Result<Self> {
        let temporary = tempfile::Builder::new()
            .prefix("memcordon-windows-package-sources-")
            .tempdir()?;
        validate_staging_outside_repository(repository_root, temporary.path())?;
        let layout = WindowsPackageSourceLayout::new(temporary.path().join("packaged-sources"));
        fs::create_dir_all(layout.root())?;
        Ok(Self { temporary, layout })
    }

    pub fn layout(&self) -> &WindowsPackageSourceLayout {
        &self.layout
    }

    pub fn temporary_root(&self) -> &Path {
        self.temporary.path()
    }
}

pub fn validate_staging_outside_repository(
    repository_root: &Path,
    staging_root: &Path,
) -> Result<()> {
    let repository_root = fs::canonicalize(repository_root)?;
    let staging_root = fs::canonicalize(staging_root)?;
    if staging_root.starts_with(&repository_root) {
        return Err(CiError::Message(format!(
            "packaged-source execution staging must be outside the repository workspace: repository={} staging={}",
            repository_root.display(),
            staging_root.display()
        )));
    }
    Ok(())
}

fn windows_static_crt_target_configuration() -> toml::Value {
    let rustflags = || {
        toml::Value::Array(vec![
            toml::Value::String("-C".to_owned()),
            toml::Value::String("target-feature=+crt-static".to_owned()),
        ])
    };
    let mut targets = toml::Table::new();
    for target in ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"] {
        let mut specification = toml::Table::new();
        specification.insert("rustflags".to_owned(), rustflags());
        targets.insert(target.to_owned(), toml::Value::Table(specification));
    }
    toml::Value::Table(targets)
}
