use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_STABLE_CODE_BYTES: usize = 128;

/// Version of the production target-desktop bootstrap ready/release frame.
pub const PRODUCTION_LOADER_READY_SCHEMA_VERSION: u32 = 19;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandshakeOutcomeV1 {
    NotStarted,
    Authenticated { protocol_version: u32 },
    Failed { stable_code: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoaderReadyEndpointV1 {
    name: String,
    nonce: String,
}

impl LoaderReadyEndpointV1 {
    pub fn new(nonce: String) -> Result<Self, &'static str> {
        if nonce.len() != Sha256::output_size() * 2
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("loader-ready nonce must be a lowercase SHA-256-width value");
        }
        let mut name = String::from(r"\\.\pipe\memcordon-target-desktop-bootstrap-v2-");
        name.push_str(&nonce);
        Ok(Self { name, nonce })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum HandshakeOutcomeWireV1 {
    NotStarted,
    Authenticated { protocol_version: u32 },
    Failed { stable_code: String },
}

impl<'de> Deserialize<'de> for HandshakeOutcomeV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match HandshakeOutcomeWireV1::deserialize(deserializer)? {
            HandshakeOutcomeWireV1::NotStarted => Ok(Self::NotStarted),
            HandshakeOutcomeWireV1::Authenticated { protocol_version } => {
                Ok(Self::Authenticated { protocol_version })
            }
            HandshakeOutcomeWireV1::Failed { stable_code }
                if !stable_code.is_empty() && stable_code.len() <= MAX_STABLE_CODE_BYTES =>
            {
                Ok(Self::Failed { stable_code })
            }
            HandshakeOutcomeWireV1::Failed { .. } => {
                Err(serde::de::Error::custom("invalid handshake stable code"))
            }
        }
    }
}
