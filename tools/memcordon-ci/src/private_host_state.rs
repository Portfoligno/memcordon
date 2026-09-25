//! Independent CI host-network observation around a native case invocation.
//! The native observer remains owner-produced; matching it to these direct
//! `/proc` reads is necessary but not sufficient to qualify a release run.

use serde::{Deserialize, Serialize};

use crate::{CiError, Result};

pub const HOST_PRESERVATION_SELECTOR: &str = "private_tcp::host_namespace_and_sysctl_unchanged";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostNetworkStateV1 {
    schema_version: u8,
    namespace_device: u64,
    namespace_inode: u64,
    unprivileged_port_start: String,
    local_port_range: String,
    local_reserved_ports: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostNetworkPreservationV1 {
    schema_version: u8,
    before: HostNetworkStateV1,
    after: HostNetworkStateV1,
}

impl HostNetworkStateV1 {
    fn validate(&self) -> Result<()> {
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
            .any(|value| value.len() > 4096)
        {
            return Err(CiError::Message("CI host network state differs".into()));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn capture() -> Result<Self> {
        use std::fs::{File, OpenOptions};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        // nsfs exposes the current namespace through a proc symlink. The
        // opened fd pins the kernel object while metadata is sampled.
        let namespace = File::open("/proc/self/ns/net")?;
        let metadata = namespace.metadata()?;
        let read_sysctl = |path| -> Result<String> {
            use std::io::Read;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            let mut bytes = Vec::new();
            file.take(4097).read_to_end(&mut bytes)?;
            if bytes.len() > 4096 {
                return Err(CiError::Message("CI host sysctl exceeds bound".into()));
            }
            String::from_utf8(bytes)
                .map_err(|_| CiError::Message("CI host sysctl is not UTF-8".into()))
        };
        let state = Self {
            schema_version: 1,
            namespace_device: metadata.dev(),
            namespace_inode: metadata.ino(),
            unprivileged_port_start: read_sysctl("/proc/sys/net/ipv4/ip_unprivileged_port_start")?,
            local_port_range: read_sysctl("/proc/sys/net/ipv4/ip_local_port_range")?,
            local_reserved_ports: read_sysctl("/proc/sys/net/ipv4/ip_local_reserved_ports")?,
        };
        state.validate()?;
        Ok(state)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn capture() -> Result<Self> {
        Err(CiError::Message(
            "CI host network capture requires Linux".into(),
        ))
    }
}

pub fn validate_host_preservation_observer(
    selector: &str,
    observer: &[u8],
    before: Option<&HostNetworkStateV1>,
    after: Option<&HostNetworkStateV1>,
) -> Result<()> {
    memcordon_core::workload_contract::reject_duplicate_json_keys(observer)
        .map_err(CiError::Message)?;
    let value: serde_json::Value = serde_json::from_slice(observer)?;
    let preservation = value.get("host_network_preservation");
    if selector != HOST_PRESERVATION_SELECTOR {
        if preservation.is_some_and(|value| !value.is_null()) || before.is_some() || after.is_some()
        {
            return Err(CiError::Message(
                "unexpected host-preservation observation".into(),
            ));
        }
        return Ok(());
    }
    let proof: HostNetworkPreservationV1 = serde_json::from_value(
        preservation
            .filter(|value| !value.is_null())
            .ok_or_else(|| CiError::Message("host-preservation observation absent".into()))?
            .clone(),
    )?;
    let (Some(before), Some(after)) = (before, after) else {
        return Err(CiError::Message(
            "independent CI host snapshots absent".into(),
        ));
    };
    before.validate()?;
    after.validate()?;
    proof.before.validate()?;
    proof.after.validate()?;
    if proof.schema_version != 1
        || before != after
        || proof.before != *before
        || proof.after != *after
        || HostNetworkStateV1::capture()? != *after
    {
        return Err(CiError::Message(
            "native host preservation differs from CI snapshots".into(),
        ));
    }
    Ok(())
}
