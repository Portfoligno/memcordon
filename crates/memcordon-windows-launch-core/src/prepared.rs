use crate::{LoaderReadyEndpointV1, PreparedEnvironmentIdentityV1};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedLoaderCommandV1 {
    pub(crate) units: Vec<u16>,
    semantic_sha256: String,
}

impl PreparedLoaderCommandV1 {
    pub fn loader_control(
        executable: &[u16],
        endpoint: &LoaderReadyEndpointV1,
        desktop: &[u16],
    ) -> Result<Self, &'static str> {
        if executable.is_empty()
            || desktop.is_empty()
            || [executable, desktop].iter().any(|value| value.contains(&0))
        {
            return Err("loader command inputs must be nonempty and NUL-free");
        }
        let pipe_endpoint = endpoint.name().encode_utf16().collect::<Vec<_>>();
        let nonce = endpoint.nonce().encode_utf16().collect::<Vec<_>>();
        let action = "loader-control".encode_utf16().collect::<Vec<_>>();
        let mut units = memcordon_core::encode_windows_command_line(&[
            executable.to_vec(),
            action.clone(),
            pipe_endpoint,
            nonce,
            desktop.to_vec(),
        ]);
        units.push(0);
        let mut semantics = b"memcordon-production-loader-command-v1\0".to_vec();
        append_utf16(&mut semantics, executable);
        append_utf16(&mut semantics, &action);
        semantics.extend_from_slice(b"authenticated-private-pipe\0");
        semantics.extend_from_slice(b"one-time-secret-nonce\0");
        append_utf16(&mut semantics, desktop);
        Ok(Self {
            units,
            semantic_sha256: hex::encode(Sha256::digest(semantics)),
        })
    }

    #[must_use]
    pub fn semantic_sha256(&self) -> &str {
        &self.semantic_sha256
    }

    #[must_use]
    pub fn units(&self) -> &[u16] {
        &self.units
    }

    pub(crate) fn units_mut(&mut self) -> &mut [u16] {
        &mut self.units
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedLoaderEnvironmentV1 {
    pub(crate) units: Vec<u16>,
    identity: PreparedEnvironmentIdentityV1,
}

impl PreparedLoaderEnvironmentV1 {
    pub fn new(units: Vec<u16>) -> Result<Self, &'static str> {
        if units.len() < 2 || !units.ends_with(&[0, 0]) {
            return Err("loader environment must be double-NUL terminated");
        }
        let byte_len = units
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or("loader environment byte length overflow")?;
        let sha256 = sha256_utf16(&units);
        Ok(Self {
            units,
            identity: PreparedEnvironmentIdentityV1 {
                encoding: String::from("utf-16le-double-nul"),
                byte_len,
                sha256,
            },
        })
    }

    pub fn canonical_minimal_system(values: [Vec<u16>; 3]) -> Result<Self, &'static str> {
        let names = ["SystemDrive", "SystemRoot", "windir"];
        let entries = names
            .into_iter()
            .zip(values)
            .map(|(name, value)| memcordon_core::WindowsEnvironmentEntryV1 {
                name: name.encode_utf16().collect(),
                value,
            })
            .collect::<Vec<_>>();
        Self::new(memcordon_core::encode_windows_environment_block(&entries)?)
    }

    #[must_use]
    pub fn identity(&self) -> &PreparedEnvironmentIdentityV1 {
        &self.identity
    }

    #[must_use]
    pub fn units(&self) -> &[u16] {
        &self.units
    }

    pub(crate) fn units_mut(&mut self) -> &mut [u16] {
        &mut self.units
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCurrentDirectoryV1 {
    units: Vec<u16>,
    sha256: String,
}

impl PreparedCurrentDirectoryV1 {
    pub fn new(mut units: Vec<u16>) -> Result<Self, &'static str> {
        if units.is_empty() || units.contains(&0) {
            return Err("current directory must be nonempty and NUL-free");
        }
        units.push(0);
        let sha256 = sha256_utf16(&units);
        Ok(Self { units, sha256 })
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn units(&self) -> &[u16] {
        &self.units
    }
}

fn append_utf16(target: &mut Vec<u8>, value: &[u16]) {
    target.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    target.extend(value.iter().flat_map(|unit| unit.to_le_bytes()));
}

fn sha256_utf16(value: &[u16]) -> String {
    hex::encode(Sha256::digest(
        value
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>(),
    ))
}
