//! Independent, structural installed-agent ancestor observation for CI.
//!
//! Unlike the native owner, this crate forbids unsafe openat. We open each
//! fixed component with O_NOFOLLOW and compare exact before/after metadata,
//! but this alone is not equivalent to native pinned-descriptor custody or Q.

use serde::{Deserialize, Serialize};

use crate::{CiError, Result};

pub const AGENT_PATH_SELECTOR: &str = "private_tcp::elf_ancestor_and_identity_pinned";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPathNodeV1 {
    component: String,
    device: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPathSnapshotV1 {
    schema_version: u8,
    nodes: Vec<AgentPathNodeV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPathPreservationV1 {
    schema_version: u8,
    before: AgentPathSnapshotV1,
    after: AgentPathSnapshotV1,
}

impl AgentPathSnapshotV1 {
    fn validate(&self) -> Result<()> {
        let expected = ["/", "usr", "libexec", "memcordon-sealed-agent"];
        if self.schema_version != 1
            || self.nodes.len() != expected.len()
            || self
                .nodes
                .iter()
                .zip(expected)
                .enumerate()
                .any(|(index, (node, component))| {
                    let expected_kind = if index + 1 == expected.len() {
                        libc::S_IFREG as u32
                    } else {
                        libc::S_IFDIR as u32
                    };
                    node.component != component
                        || node.device == 0
                        || node.inode == 0
                        || node.owner_uid != 0
                        || node.mode & libc::S_IFMT as u32 != expected_kind
                        || node.mode & 0o022 != 0
                        || index + 1 == expected.len() && node.mode & 0o111 == 0
                })
        {
            return Err(CiError::Message(
                "CI installed agent ancestor chain differs".into(),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn capture(expected_agent_bytes: &[u8]) -> Result<Self> {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let paths = [
            "/",
            "/usr",
            "/usr/libexec",
            "/usr/libexec/memcordon-sealed-agent",
        ];
        let names = ["/", "usr", "libexec", "memcordon-sealed-agent"];
        let mut nodes = Vec::with_capacity(paths.len());
        for (index, (path, component)) in paths.into_iter().zip(names).enumerate() {
            let directory = index + 1 != paths.len();
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(
                    libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | if directory { libc::O_DIRECTORY } else { 0 },
                )
                .open(path)?;
            let metadata = file.metadata()?;
            let path_metadata = std::fs::symlink_metadata(path)?;
            if (directory && !metadata.is_dir())
                || (!directory && !metadata.is_file())
                || (metadata.dev(), metadata.ino()) != (path_metadata.dev(), path_metadata.ino())
                || (!directory && metadata.nlink() != 1)
            {
                return Err(CiError::Message(
                    "CI installed agent path changed during readback".into(),
                ));
            }
            nodes.push(AgentPathNodeV1 {
                component: component.into(),
                device: metadata.dev(),
                inode: metadata.ino(),
                owner_uid: metadata.uid(),
                mode: metadata.mode(),
            });
        }
        let image = crate::private_installed_h0::read_fixed_agent_identity(expected_agent_bytes)?;
        if nodes.last().map(|node| (node.device, node.inode)) != Some(image) {
            return Err(CiError::Message(
                "CI installed image differs from ancestor leaf".into(),
            ));
        }
        let snapshot = Self {
            schema_version: 1,
            nodes,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn capture(_expected_agent_bytes: &[u8]) -> Result<Self> {
        Err(CiError::Message(
            "CI agent path observation requires Linux".into(),
        ))
    }
}

/// The observer field is selector-only; its before/after state must equal
/// independent CI snapshots, including a fresh post-readback capture.
pub fn validate_agent_path_observer(
    selector: &str,
    observer: &[u8],
    before: Option<&AgentPathSnapshotV1>,
    after: Option<&AgentPathSnapshotV1>,
    current: Option<&AgentPathSnapshotV1>,
) -> Result<()> {
    memcordon_core::workload_contract::reject_duplicate_json_keys(observer)
        .map_err(CiError::Message)?;
    let value: serde_json::Value = serde_json::from_slice(observer)?;
    let claim = value.get("agent_path_preservation");
    if selector != AGENT_PATH_SELECTOR {
        if claim.is_some_and(|value| !value.is_null())
            || before.is_some()
            || after.is_some()
            || current.is_some()
        {
            return Err(CiError::Message("unexpected agent path claim".into()));
        }
        return Ok(());
    }
    let proof: AgentPathPreservationV1 = serde_json::from_value(
        claim
            .filter(|value| !value.is_null())
            .ok_or_else(|| CiError::Message("agent path claim absent".into()))?
            .clone(),
    )?;
    let (Some(before), Some(after), Some(current)) = (before, after, current) else {
        return Err(CiError::Message(
            "independent agent path snapshots absent".into(),
        ));
    };
    for snapshot in [before, after, current, &proof.before, &proof.after] {
        snapshot.validate()?;
    }
    if proof.schema_version != 1
        || proof.before != *before
        || proof.after != *after
        || before != after
        || after != current
    {
        return Err(CiError::Message(
            "agent path claim differs from CI snapshots".into(),
        ));
    }
    Ok(())
}
