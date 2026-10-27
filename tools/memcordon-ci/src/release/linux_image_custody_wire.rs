//! Data-only wire format shared by the actual custodian endpoints.
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(super) const FRAME_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Role {
    AdministrativeFile,
    AdministrativeDirectory,
    EvidenceDirectory,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub nonce: String,
    pub sequence: u64,
    pub slot: usize,
    pub path: PathBuf,
    pub identity: Identity,
    pub role: Role,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub(super) enum Frame {
    Hello {
        nonce: String,
        pid: u32,
        #[serde(with = "birth_decimal")]
        birth: u128,
    },
    Admit {
        binding: Binding,
    },
    Borrow {
        binding: Binding,
    },
    Ack {
        binding: Binding,
    },
    Finish {
        nonce: String,
        sequence: u64,
        count: usize,
    },
    Finished {
        nonce: String,
        sequence: u64,
        count: usize,
    },
}

// Internally tagged serde enum buffering does not support native u128 numbers.
// The wire identity is canonical decimal text; the native identity stays u128.
mod birth_decimal {
    use serde::{Deserializer, Serializer, de};
    use std::fmt;

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        struct Decimal;
        impl de::Visitor<'_> for Decimal {
            type Value = u128;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded canonical unsigned 128-bit decimal string")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<u128, E> {
                if value.is_empty()
                    || value.len() > u128::MAX.to_string().len()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || (value.starts_with('0') && value != "0")
                {
                    return Err(E::custom("noncanonical process birth"));
                }
                let parsed = value.parse::<u128>().map_err(E::custom)?;
                if parsed.to_string() != value {
                    return Err(E::custom("noncanonical process birth"));
                }
                Ok(parsed)
            }
        }
        deserializer.deserialize_str(Decimal)
    }
}

pub(super) fn encode(frame: &Frame) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    if bytes.len() > FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "custody frame exceeds finite bound",
        ));
    }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> io::Result<Frame> {
    if bytes.len() > FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "custody frame exceeds finite bound",
        ));
    }
    serde_json::from_slice(bytes).map_err(io::Error::other)
}
