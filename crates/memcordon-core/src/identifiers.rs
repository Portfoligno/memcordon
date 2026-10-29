//! Bounded identifiers for current requests and native attempt associations.
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LogicalId(String);

impl LogicalId {
    pub fn new(value: String) -> Result<Self, String> {
        if value.is_empty()
            || value.len() > crate::workload_limits::IDENTIFIER_BYTES
            || value.starts_with('-')
            || value.ends_with('-')
            || value.contains("--")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("invalid logical identifier".into());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for LogicalId {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let value =
            crate::BoundedText::<{ crate::workload_limits::IDENTIFIER_BYTES }>::deserialize(
                decoder,
            )?;
        Self::new(value.as_str().to_owned()).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce128(pub [u8; 16]);
