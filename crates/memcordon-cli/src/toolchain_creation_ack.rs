//! Strict acknowledgment decoding for independently held fixture toolchain children.
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descendant {
    format: String,
    revision: u32,
    ordinal: u32,
    root_pid: u32,
    pid: u32,
    birth: u64,
    parent_pid: u32,
    parent_birth: u64,
    image_sha256: String,
    native_parent_edge_observed: bool,
    parent_and_child_held_live: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgment {
    format: String,
    revision: u32,
    challenge: Vec<u8>,
    descendant: Descendant,
}

/// Actual native facts from a still-held creation event, never derived from the ACK.
pub struct Expected<'a> {
    pub challenge: &'a [u8],
    pub root_pid: u32,
    pub child: &'a memcordon_core::WindowsProcessIdentityV1,
    pub parent: &'a memcordon_core::WindowsProcessIdentityV1,
    pub image_sha256: &'a str,
}

/// Decode bounded original bytes and join every authority-bearing identity field.
/// This does not establish process custody; the caller must still hold real native owners.
pub fn validate(bytes: &[u8], expected: Expected<'_>) -> Result<(), String> {
    if bytes.len() > 16 * 1024 {
        return Err("compiler acknowledgment exceeds bound".into());
    }
    let ack: Acknowledgment = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let child = ack.descendant;
    if ack.format != "memcordon.windows-toolchain-creation-ack"
        || ack.revision != 1
        || ack.challenge != expected.challenge
        || child.format != "memcordon.windows-native-toolchain-descendant"
        || child.revision != 1
        || child.ordinal == 0
        || child.ordinal > 4096
        || expected.root_pid == 0
        || child.root_pid != expected.root_pid
        || expected.child.process_id == 0
        || expected.child.creation_time_100ns == 0
        || expected.parent.process_id == 0
        || expected.parent.creation_time_100ns == 0
        || expected.child.process_id == expected.parent.process_id
        || expected.parent.creation_time_100ns > expected.child.creation_time_100ns
        || child.pid != expected.child.process_id
        || child.birth != expected.child.creation_time_100ns
        || child.parent_pid != expected.parent.process_id
        || child.parent_birth != expected.parent.creation_time_100ns
        || child.image_sha256 != expected.image_sha256
        || expected.image_sha256.len() != 64
        || !expected
            .image_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !child.native_parent_edge_observed
        || !child.parent_and_child_held_live
    {
        return Err("compiler acknowledgment differs from actual creation-held identity".into());
    }
    Ok(())
}
