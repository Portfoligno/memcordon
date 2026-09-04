use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RedactionClassV1 {
    Public,
    RedactedSummary,
    RestrictedTrace,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactRefV1 {
    relative_path: String,
    sha256: String,
    byte_length: u64,
    media_type: String,
    redaction: RedactionClassV1,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ArtifactRefError {
    #[error("artifact path must be relative and traversal-free")]
    UnsafePath,
    #[error("artifact digest must be lowercase SHA-256")]
    InvalidDigest,
    #[error("artifact media type must not be empty")]
    EmptyMediaType,
}

impl ArtifactRefV1 {
    pub fn new(
        relative_path: String,
        sha256: String,
        byte_length: u64,
        media_type: String,
        redaction: RedactionClassV1,
    ) -> Result<Self, ArtifactRefError> {
        let path = Path::new(&relative_path);
        if path.is_absolute()
            || relative_path.is_empty()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(ArtifactRefError::UnsafePath);
        }
        if sha256.len() != Sha256::output_size() * 2
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ArtifactRefError::InvalidDigest);
        }
        if media_type.is_empty() {
            return Err(ArtifactRefError::EmptyMediaType);
        }
        Ok(Self {
            relative_path,
            sha256,
            byte_length,
            media_type,
            redaction,
        })
    }

    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    #[must_use]
    pub const fn redaction(&self) -> &RedactionClassV1 {
        &self.redaction
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRefWireV1 {
    relative_path: String,
    sha256: String,
    byte_length: u64,
    media_type: String,
    redaction: RedactionClassV1,
}

impl<'de> Deserialize<'de> for ArtifactRefV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ArtifactRefWireV1::deserialize(deserializer)?;
        Self::new(
            wire.relative_path,
            wire.sha256,
            wire.byte_length,
            wire.media_type,
            wire.redaction,
        )
        .map_err(serde::de::Error::custom)
    }
}
