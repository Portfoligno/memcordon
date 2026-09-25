//! Native host-preservation witness for a distinct release-matrix attempt.
//! This records bounded kernel bytes before boundary creation and after full
//! retirement; detached readback independently compares the current host.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use serde::{Deserialize, Serialize};

pub(crate) const SELECTOR: &str = "private_tcp::host_namespace_and_sysctl_unchanged";
const MAX_SYSCTL_BYTES: u64 = 4096;
const PORT_START: &str = "/proc/sys/net/ipv4/ip_unprivileged_port_start";
const PORT_RANGE: &str = "/proc/sys/net/ipv4/ip_local_port_range";
const RESERVED: &str = "/proc/sys/net/ipv4/ip_local_reserved_ports";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostNetworkStateV1 {
    schema_version: u8,
    namespace_device: u64,
    namespace_inode: u64,
    unprivileged_port_start: String,
    local_port_range: String,
    local_reserved_ports: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostNetworkPreservationV1 {
    schema_version: u8,
    before: HostNetworkStateV1,
    after: HostNetworkStateV1,
}

impl HostNetworkStateV1 {
    pub(crate) fn capture() -> Result<Self, String> {
        let namespace = File::open("/proc/self/ns/net")
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: host netns: {error}"))?;
        let metadata = namespace.metadata().map_err(|error| error.to_string())?;
        let state = Self {
            schema_version: 1,
            namespace_device: metadata.dev(),
            namespace_inode: metadata.ino(),
            unprivileged_port_start: read_sysctl(PORT_START)?,
            local_port_range: read_sysctl(PORT_RANGE)?,
            local_reserved_ports: read_sysctl(RESERVED)?,
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.namespace_device == 0
            || self.namespace_inode == 0
            || self.unprivileged_port_start.is_empty()
            || self.local_port_range.is_empty()
            || [
                &self.unprivileged_port_start,
                &self.local_port_range,
                &self.local_reserved_ports,
            ]
            .into_iter()
            .any(|value| value.len() as u64 > MAX_SYSCTL_BYTES)
        {
            return Err("MCSEALED-PRIVATE-RELEASE: host network state differs".into());
        }
        Ok(())
    }
}

impl HostNetworkPreservationV1 {
    pub(crate) fn complete(
        before: HostNetworkStateV1,
        after: HostNetworkStateV1,
    ) -> Result<Self, String> {
        let proof = Self {
            schema_version: 1,
            before,
            after,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        self.before.validate()?;
        self.after.validate()?;
        if self.schema_version != 1 || self.before != self.after {
            return Err("MCSEALED-PRIVATE-RELEASE: host network state changed".into());
        }
        Ok(())
    }

    pub(crate) fn verify_current(&self) -> Result<(), String> {
        self.validate()?;
        if HostNetworkStateV1::capture()? != self.after {
            return Err("MCSEALED-PRIVATE-RELEASE: current host network state changed".into());
        }
        Ok(())
    }
}

pub(crate) fn expected_private_projection() -> [u8; 7] {
    let mut bytes = [0_u8; 7];
    bytes[..2].copy_from_slice(&0_u16.to_le_bytes());
    bytes[2..4].copy_from_slice(&32768_u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&60999_u16.to_le_bytes());
    bytes[6] = 0;
    bytes
}

pub(crate) fn observe_target_private_projection() -> Result<[u8; 7], String> {
    let start: u16 = read_sysctl(PORT_START)?
        .trim()
        .parse()
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE-FIXTURE: private port start differs")?;
    let range = read_sysctl(PORT_RANGE)?;
    let mut bounds = range.split_whitespace();
    let low: u16 = bounds
        .next()
        .ok_or("MCSEALED-PRIVATE-RELEASE-FIXTURE: private port range absent")?
        .parse()
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE-FIXTURE: private port range differs")?;
    let high: u16 = bounds
        .next()
        .ok_or("MCSEALED-PRIVATE-RELEASE-FIXTURE: private port range absent")?
        .parse()
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE-FIXTURE: private port range differs")?;
    if bounds.next().is_some()
        || (start, low, high) != (0, 32768, 60999)
        || !read_sysctl(RESERVED)?.trim().is_empty()
    {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: private sysctl policy differs".into());
    }
    Ok(expected_private_projection())
}

fn read_sysctl(path: &str) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: sysctl {path}: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_SYSCTL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: sysctl {path}: {error}"))?;
    if bytes.len() as u64 > MAX_SYSCTL_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: sysctl byte bound differs".into());
    }
    String::from_utf8(bytes).map_err(|_| "MCSEALED-PRIVATE-RELEASE: sysctl is not UTF-8".into())
}
