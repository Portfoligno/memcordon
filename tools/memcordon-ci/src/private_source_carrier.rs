//! Canonical bounded representation of already acknowledged source leaves.
//! Decoding retains bytes only; it cannot authenticate their origin or qualify
//! a case. The custodian's repack operation checks original byte equality.
use crate::private_observer_session::{canonical_bytes, strict_json, valid_relative_path};
use crate::{CiError, Result};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAGIC: &[u8] = b"MCSC\x01\0\0\0";
pub const MAX_SOURCE_CARRIER_BYTES: usize = 8 * 1024 * 1024;
const MAX_INDEX_BYTES: usize = 128 * 1024;
const MAX_LEAVES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceLeafV1 {
    path: String,
    size: u64,
    sha256: DiagnosticSha256,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceIndexV1 {
    schema_version: u8,
    leaves: Vec<SourceLeafV1>,
}

pub fn is_source_carrier(path: &str) -> bool {
    path.ends_with("/source-carrier.v1.bin")
}
fn source_path(path: &str) -> bool {
    valid_relative_path(path)
        && !is_source_carrier(path)
        && !path.ends_with("/replay-bundle.v1.bin")
        && !matches!(
            path.rsplit('/').next(),
            Some(
                "origin-index.v1.json"
                    | "origin-commitment.v1.json"
                    | "origin-receipt.v1.json"
                    | "candidate-c-v3.json"
                    | "public-index-v3.json"
                    | "qualification.json"
            )
        )
}
fn empty_stream(path: &str) -> bool {
    matches!(path.rsplit('/').next(), Some("stdout.raw" | "stderr.raw"))
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}

pub fn encode_source_carrier(leaves: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    if leaves.is_empty() || leaves.len() > MAX_LEAVES {
        return fail("source carrier inventory count differs");
    }
    let mut index = SourceIndexV1 {
        schema_version: 1,
        leaves: Vec::with_capacity(leaves.len()),
    };
    let mut data_size = 0_usize;
    for (path, bytes) in leaves {
        if !source_path(path) || bytes.is_empty() && !empty_stream(path) {
            return fail("source carrier path/empty evidence differs");
        }
        data_size = data_size
            .checked_add(bytes.len())
            .ok_or_else(|| CiError::Message("source carrier byte count overflow".into()))?;
        if data_size > MAX_SOURCE_CARRIER_BYTES {
            return fail("source carrier exceeds reviewed byte budget");
        }
        index.leaves.push(SourceLeafV1 {
            path: path.clone(),
            size: bytes.len() as u64,
            sha256: hash_bytes(bytes),
        });
    }
    let inventory = canonical_bytes(&index)?;
    let total = MAGIC
        .len()
        .checked_add(std::mem::size_of::<u32>())
        .and_then(|n| n.checked_add(inventory.len()))
        .and_then(|n| n.checked_add(data_size))
        .ok_or_else(|| CiError::Message("source carrier total overflow".into()))?;
    if inventory.len() > MAX_INDEX_BYTES || total > MAX_SOURCE_CARRIER_BYTES {
        return fail("source carrier index/aggregate exceeds reviewed bound");
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(
        &u32::try_from(inventory.len())
            .map_err(|_| CiError::Message("source inventory length exceeds u32".into()))?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&inventory);
    for leaf in leaves.values() {
        bytes.extend_from_slice(leaf);
    }
    Ok(bytes)
}

pub fn parse_source_carrier(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    if bytes.len() > MAX_SOURCE_CARRIER_BYTES {
        return fail("source carrier exceeds reviewed byte bound");
    }
    let bytes = bytes
        .strip_prefix(MAGIC)
        .ok_or_else(|| CiError::Message("source carrier version/domain differs".into()))?;
    let width = std::mem::size_of::<u32>();
    let size = u32::from_be_bytes(
        bytes
            .get(..width)
            .ok_or_else(|| CiError::Message("source carrier truncated index length".into()))?
            .try_into()
            .expect("bounded u32"),
    ) as usize;
    if size > MAX_INDEX_BYTES {
        return fail("source carrier index bound differs");
    }
    let bytes = &bytes[width..];
    let raw = bytes
        .get(..size)
        .ok_or_else(|| CiError::Message("source carrier truncated inventory".into()))?;
    let index: SourceIndexV1 = strict_json(raw, MAX_INDEX_BYTES)?;
    if index.schema_version != 1
        || index.leaves.is_empty()
        || index.leaves.len() > MAX_LEAVES
        || canonical_bytes(&index)? != raw
    {
        return fail("source carrier noncanonical inventory/version differs");
    }
    let mut data = &bytes[size..];
    let mut leaves = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for leaf in &index.leaves {
        let size = usize::try_from(leaf.size)
            .map_err(|_| CiError::Message("source carrier leaf size overflow".into()))?;
        if !source_path(&leaf.path)
            || size == 0 && !empty_stream(&leaf.path)
            || previous.is_some_and(|path| path >= leaf.path.as_str())
        {
            return fail("source carrier duplicate/unsorted/cyclic path differs");
        }
        let raw = data
            .get(..size)
            .ok_or_else(|| CiError::Message("source carrier truncated exact leaf".into()))?;
        if hash_bytes(raw) != leaf.sha256 {
            return fail("source carrier exact leaf digest differs");
        }
        leaves.insert(leaf.path.clone(), raw.to_vec());
        data = &data[size..];
        previous = Some(&leaf.path);
    }
    if !data.is_empty() {
        return fail("source carrier undeclared trailing bytes");
    }
    Ok(leaves)
}

const HELD_MAGIC: &[u8] = b"MCHS\x01\0\0\0";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeldSourceEnvelopeV1 {
    schema_version: u8,
    sample: crate::private_public_live::HeldPublicTargetSamplesV1,
    image_path: String,
}

/// Raw proc bytes use binary leaves rather than JSON byte arrays. The held
/// ELF has one exact origin leaf, independently hashed for every sample.
pub fn encode_held_source(
    sample: &crate::private_public_live::HeldPublicTargetSamplesV1,
    image_path: String,
) -> Result<Vec<u8>> {
    if !source_path(&image_path)
        || sample.leaves.get("image.raw").map(|raw| hash_bytes(raw))
            != Some(sample.executable_sha256.clone())
    {
        return fail("held source image reference differs from original held bytes");
    }
    let mut metadata = sample.clone();
    let mut leaves = std::mem::take(&mut metadata.leaves);
    leaves.remove("image.raw");
    let envelope = canonical_bytes(&HeldSourceEnvelopeV1 {
        schema_version: 1,
        sample: metadata,
        image_path,
    })?;
    if envelope.len() > MAX_INDEX_BYTES {
        return fail("held source metadata exceeds reviewed index bound");
    }
    let raw = encode_source_carrier(&leaves)?;
    let mut bytes = HELD_MAGIC.to_vec();
    bytes.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&envelope);
    bytes.extend_from_slice(&raw);
    if bytes.len() > MAX_SOURCE_CARRIER_BYTES {
        return fail("held source exceeds reviewed member bound");
    }
    Ok(bytes)
}

pub fn decode_held_source(
    bytes: &[u8],
    image: impl FnOnce(&str) -> Result<Vec<u8>>,
) -> Result<crate::private_public_live::HeldPublicTargetSamplesV1> {
    let Some(raw) = bytes.strip_prefix(HELD_MAGIC) else {
        return strict_json(bytes, MAX_SOURCE_CARRIER_BYTES);
    };
    if bytes.len() > MAX_SOURCE_CARRIER_BYTES {
        return fail("held source exceeds reviewed member bound");
    }
    let width = std::mem::size_of::<u32>();
    let size = u32::from_be_bytes(
        raw.get(..width)
            .ok_or_else(|| CiError::Message("held source length truncated".into()))?
            .try_into()
            .expect("bounded u32"),
    ) as usize;
    if size > MAX_INDEX_BYTES {
        return fail("held source metadata bound differs");
    }
    let raw = &raw[width..];
    let metadata = raw
        .get(..size)
        .ok_or_else(|| CiError::Message("held source metadata truncated".into()))?;
    let mut envelope: HeldSourceEnvelopeV1 = strict_json(metadata, MAX_INDEX_BYTES)?;
    if envelope.schema_version != 1
        || !envelope.sample.leaves.is_empty()
        || !source_path(&envelope.image_path)
        || canonical_bytes(&envelope)? != metadata
    {
        return fail("held source canonical image/metadata mapping differs");
    }
    let mut leaves = parse_source_carrier(&raw[size..])?;
    if leaves.contains_key("image.raw") {
        return fail("held source image aliases binary proc inventory");
    }
    let image = image(&envelope.image_path)?;
    if image.is_empty() || hash_bytes(&image) != envelope.sample.executable_sha256 {
        return fail("held source origin image hash differs");
    }
    leaves.insert("image.raw".into(), image);
    envelope.sample.leaves = leaves;
    Ok(envelope.sample)
}

pub(crate) fn expand_source_payload(
    payload: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut views = payload.clone();
    for (path, bytes) in payload {
        if !is_source_carrier(path) {
            continue;
        }
        for (source, raw) in parse_source_carrier(bytes)? {
            if views.insert(source, raw).is_some() {
                return fail("source carrier aliases another literal or mapped leaf");
            }
        }
    }
    Ok(views)
}
