//! Current native-source retirement receipt; native custody and NOENT remain
//! mandatory in the caller, independently of this exact byte/schema binding.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSourceRetirement {
    format: String,
    revision: u32,
    path: PathBuf,
    device: u64,
    inode: u64,
    absent: bool,
}
impl NativeSourceRetirement {
    /// Publish only after the existing held/inode/cutoff retirement succeeds.
    pub fn observed(path: PathBuf, device: u64, inode: u64) -> Self {
        Self {
            format: "memcordon.native-source-retirement".into(),
            revision: 1,
            path,
            device,
            inode,
            absent: true,
        }
    }
    pub fn decode_bound(
        bytes: &[u8],
        path: &Path,
        device: u64,
        inode: u64,
    ) -> Result<Self, String> {
        if bytes.len() > 65536 {
            return Err("native-source retirement receipt exceeds byte bound".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
        let receipt: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("native-source retirement receipt schema: {error}"))?;
        if receipt != Self::observed(path.to_path_buf(), device, inode) {
            return Err(
                "native-source retirement receipt original root association/absence differs".into(),
            );
        }
        Ok(receipt)
    }
}
