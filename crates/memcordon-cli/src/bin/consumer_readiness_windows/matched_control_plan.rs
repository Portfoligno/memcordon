//! Closed launch plan for the additional two-lane owned-file measurement.
use super::{
    ControlClock, Descriptor,
    matched::{Binding, Lane, Scope},
};
use memcordon_core::WindowsEnvironmentEntryV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[cfg(windows)]
#[path = "matched_control_directory.rs"]
mod native;
#[cfg(windows)]
pub use native::{hold_chain, observe_directory, remove_empty_directory};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DirectoryRole {
    Cwd,
    DirectOutput,
    InstalledOutput,
    DriverParent,
    ProviderParent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub role: DirectoryRole,
    pub path: PathBuf,
    pub volume_serial: u64,
    pub file_index: u64,
    pub attributes: u32,
    pub security_information: u32,
    pub security_bytes: u32,
    pub security_sha256: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub revision: u32,
    pub pair_sha256: [u8; 32],
    pub input_sha256: [u8; 32],
    pub scope: Scope,
    pub restricted: bool,
    pub fixture_sha256: String,
    pub cli_sha256: String,
    pub direct_descriptor: PathBuf,
    pub installed_descriptor: PathBuf,
    pub cwd: PathBuf,
    pub work_clock: ControlClock,
    pub cleanup_cutoff_qpc: u64,
    pub record: PathBuf,
    pub environment: Vec<WindowsEnvironmentEntryV1>,
    pub directories: Vec<Directory>,
}
impl Plan {
    pub fn direct_descriptor_for(&self, installed: &Descriptor) -> Result<Descriptor, String> {
        let mut direct = installed.clone();
        direct.output_root = self
            .directories
            .iter()
            .find(|directory| directory.role == DirectoryRole::DirectOutput)
            .ok_or("matched direct output directory role absent")?
            .path
            .clone();
        direct.transcript = direct.output_root.join("fixture-events.bin");
        let binding = direct
            .matched_control
            .as_mut()
            .ok_or("matched installed descriptor binding absent")?;
        if binding.lane != Lane::Installed
            || binding.pair_sha256 != self.pair_sha256
            || binding.scope != self.scope
            || binding.input_sha256 != self.input_sha256
        {
            return Err("matched source descriptor differs from the installed plan lane".into());
        }
        binding.lane = Lane::Direct;
        self.directory_inputs(&direct)?;
        if self.directories[2].path != installed.output_root {
            return Err("matched installed output directory role differs".into());
        }
        Ok(direct)
    }

    fn directory_inputs(&self, direct: &Descriptor) -> Result<(), String> {
        use DirectoryRole::*;
        let protected = self.restricted && self.scope == Scope::Envelope;
        let roles: &[DirectoryRole] = if protected {
            &[
                Cwd,
                DirectOutput,
                InstalledOutput,
                DriverParent,
                ProviderParent,
            ]
        } else {
            &[Cwd, DirectOutput, InstalledOutput]
        };
        if self.directories.len() != roles.len()
            || self.directories.iter().zip(roles).any(|(directory, role)| {
                directory.role != *role
                    || !directory.path.is_absolute()
                    || directory
                        .path
                        .components()
                        .any(|part| matches!(part, std::path::Component::ParentDir))
                    || directory.path.as_os_str().to_string_lossy().contains('\0')
                    || directory.attributes & 0x10 == 0
                    || directory.attributes & (0x400 | 0x40) != 0
                    || directory.security_information != 23
                    || directory.security_bytes == 0
                    || directory.security_bytes > 8192
            })
        {
            return Err("matched directory role/order/native security declaration differs".into());
        }
        let cwd = &self.directories[0];
        let direct_output = &self.directories[1];
        let installed_output = &self.directories[2];
        if cwd.path != self.cwd
            || direct_output.path != direct.output_root
            || (direct_output.volume_serial, direct_output.file_index)
                == (installed_output.volume_serial, installed_output.file_index)
            || direct_output.security_bytes != installed_output.security_bytes
            || direct_output.security_sha256 != installed_output.security_sha256
            || direct_output.attributes != installed_output.attributes
        {
            return Err("matched owned directory allocation or output security differs".into());
        }
        if direct.denied_write_paths.len() != if protected { 2 } else { 0 } {
            return Err("matched protected operation count differs".into());
        }
        if protected {
            let driver = &self.directories[3];
            let provider = &self.directories[4];
            if (driver.volume_serial, driver.file_index)
                == (provider.volume_serial, provider.file_index)
                || direct
                    .denied_write_paths
                    .iter()
                    .zip([driver, provider])
                    .any(|(leaf, parent)| {
                        leaf.parent() != Some(parent.path.as_path())
                            || leaf.file_name().is_none()
                            || !leaf.is_absolute()
                            || leaf
                                .components()
                                .any(|part| matches!(part, std::path::Component::ParentDir))
                            || leaf.as_os_str().to_string_lossy().contains('\0')
                    })
            {
                return Err(
                    "matched protected leaves do not name the distinct declared parents".into(),
                );
            }
        }
        Ok(())
    }

    pub fn input_digest(&self, direct: &Descriptor) -> Result<[u8; 32], String> {
        self.directory_inputs(direct)?;
        if self.environment.is_empty() || self.environment.len() > 128 {
            return Err("matched environment count differs".into());
        }
        let environment = memcordon_core::encode_windows_environment_block(&self.environment)
            .map_err(str::to_owned)?;
        for hash in [&self.fixture_sha256, &self.cli_sha256] {
            if hash.len() != Sha256::output_size() * 2
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("matched image digest malformed".into());
            }
        }
        #[derive(Serialize)]
        struct Inputs<'a> {
            scope: Scope,
            restricted: bool,
            fixture_sha256: &'a str,
            cli_sha256: &'a str,
            challenge: &'a [u8],
            arguments: &'a [String],
            stdout: &'a [u8],
            stderr: &'a [u8],
            environment: &'a [u16],
            protected_paths: &'a [PathBuf],
            directories: &'a [Directory],
        }
        let bytes = serde_json::to_vec(&Inputs {
            scope: self.scope,
            restricted: self.restricted,
            fixture_sha256: &self.fixture_sha256,
            cli_sha256: &self.cli_sha256,
            challenge: &direct.challenge,
            arguments: &direct.arguments,
            stdout: &direct.stdout,
            stderr: &direct.stderr,
            environment: &environment,
            protected_paths: &direct.denied_write_paths,
            directories: &self.directories,
        })
        .map_err(|error| error.to_string())?;
        if bytes.len() > 64 * 1024 {
            return Err("matched logical input declaration exceeds64KiB".into());
        }
        Ok(Sha256::digest(&bytes).into())
    }

    pub fn validate(&self, direct: &Descriptor, installed: &Descriptor) -> Result<(), String> {
        for path in [
            &self.direct_descriptor,
            &self.installed_descriptor,
            &self.cwd,
            &self.record,
        ] {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || path.as_os_str().to_string_lossy().contains('\0')
            {
                return Err("matched plan path is not bounded absolute input".into());
            }
        }
        if self.revision != 1
            || self.pair_sha256 == [0; 32]
            || self.input_sha256 == [0; 32]
            || self.cleanup_cutoff_qpc <= self.work_clock.work_cutoff_qpc
            || self.direct_descriptor == self.installed_descriptor
            || direct.output_root == installed.output_root
        {
            return Err("matched plan revision/binding/deadline/allocations differ".into());
        }
        self.work_clock.validate()?;
        if self
            .directories
            .get(2)
            .is_none_or(|directory| directory.path != installed.output_root)
            || self.input_digest(direct)? != self.input_sha256
            || serde_json::to_vec(self)
                .map_err(|error| error.to_string())?
                .len()
                > 64 * 1024
        {
            return Err("matched final directory inputs or computed input digest differ".into());
        }
        for (descriptor, lane) in [(direct, Lane::Direct), (installed, Lane::Installed)] {
            descriptor.validate()?;
            if descriptor.matched_control.as_ref()
                != Some(&Binding {
                    pair_sha256: self.pair_sha256,
                    lane,
                    scope: self.scope,
                    input_sha256: self.input_sha256,
                })
                || descriptor.control_clock.as_ref() != Some(&self.work_clock)
                || descriptor.denied_write_paths.len()
                    != if self.restricted && self.scope == Scope::Envelope {
                        2
                    } else {
                        0
                    }
            {
                return Err("matched lane descriptor/binding/clock/protected roles differ".into());
            }
        }
        if direct.arguments != installed.arguments
            || direct.challenge != installed.challenge
            || direct.stdout != installed.stdout
            || direct.stderr != installed.stderr
            || direct.denied_write_paths != installed.denied_write_paths
            || direct.application_status != 0
            || installed.application_status != 0
        {
            return Err("matched logical application inputs differ".into());
        }
        Ok(())
    }
}
