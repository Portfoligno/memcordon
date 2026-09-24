//! Native setup primitives for the disabled private IPv4 TCP profile.
//!
//! This module does not make the profile available. In particular, a port
//! policy readback is not a substitute for loopback/topology verification,
//! descriptor custody, a target filter, or installed native qualification.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

use crate::request::NamespaceIdentity;

use super::network_netlink::{
    DumpKind, RouteNetlink, loopback_index, verify_loopback_addresses, verify_loopback_routes,
};

const UNPRIVILEGED_PORT_START: &str = "/proc/sys/net/ipv4/ip_unprivileged_port_start";
const LOCAL_PORT_RANGE: &str = "/proc/sys/net/ipv4/ip_local_port_range";
const LOCAL_RESERVED_PORTS: &str = "/proc/sys/net/ipv4/ip_local_reserved_ports";
const IPV6_ALL_DISABLED: &str = "/proc/sys/net/ipv6/conf/all/disable_ipv6";
const IPV6_DEFAULT_DISABLED: &str = "/proc/sys/net/ipv6/conf/default/disable_ipv6";
const IPV6_LOOPBACK_DISABLED: &str = "/proc/sys/net/ipv6/conf/lo/disable_ipv6";
const MAX_SYSCTL_READ: u64 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivatePortPolicy {
    pub unprivileged_port_start: u16,
    pub local_port_range: (u16, u16),
    pub reserved_ports_empty: bool,
}

impl PrivatePortPolicy {
    pub const REQUIRED: Self = Self {
        unprivileged_port_start: 0,
        local_port_range: (32768, 60999),
        reserved_ports_empty: true,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivateNetworkSetup {
    pub port_policy: PrivatePortPolicy,
    pub loopback_index: i32,
    pub address_count: usize,
    pub route_count: usize,
}

/// Prepare loopback, verify bounded link/address/route dumps, then set the
/// namespace-local port policy. This is only one preauthorization step: no
/// target may be released merely because this function returned successfully.
pub fn prepare_private_ipv4_network(
    caller_namespace: NamespaceIdentity,
    provider_namespace: NamespaceIdentity,
) -> Result<PrivateNetworkSetup, String> {
    let target_namespace = require_fresh_network_namespace(caller_namespace, provider_namespace)?;
    for path in [
        IPV6_ALL_DISABLED,
        IPV6_DEFAULT_DISABLED,
        IPV6_LOOPBACK_DISABLED,
    ] {
        write_sysctl(path, b"1\n")?;
        if read_sysctl(path)?.trim() != "1" {
            return Err(format!(
                "MCSEALED-PRIVATE-NETWORK: IPv6 disable readback mismatch {path}"
            ));
        }
    }

    let mut route = RouteNetlink::open()?;
    let index = loopback_index(&route.dump(DumpKind::Links)?, false)?;
    route.set_loopback_up(index)?;
    if loopback_index(&route.dump(DumpKind::Links)?, true)? != index {
        return Err("MCSEALED-PRIVATE-NETWORK: loopback identity changed".into());
    }
    if !verify_loopback_addresses(&route.dump(DumpKind::Addresses)?, index)? {
        route.add_loopback_address(index)?;
    }
    let addresses = route.dump(DumpKind::Addresses)?;
    if !verify_loopback_addresses(&addresses, index)? {
        return Err("MCSEALED-PRIVATE-NETWORK: loopback address absent".into());
    }
    let routes = route.dump(DumpKind::Routes)?;
    verify_loopback_routes(&routes, index)?;
    drop(route);

    let port_policy = configure_private_port_policy(caller_namespace, provider_namespace)?;
    for path in [
        IPV6_ALL_DISABLED,
        IPV6_DEFAULT_DISABLED,
        IPV6_LOOPBACK_DISABLED,
    ] {
        if read_sysctl(path)?.trim() != "1" {
            return Err(format!(
                "MCSEALED-PRIVATE-NETWORK: IPv6 changed after setup {path}"
            ));
        }
    }
    if current_network_namespace()? != target_namespace {
        return Err("MCSEALED-PRIVATE-NETWORK: network namespace changed after setup".into());
    }
    Ok(PrivateNetworkSetup {
        port_policy,
        loopback_index: index,
        address_count: addresses.len(),
        route_count: routes.len(),
    })
}

/// Applies the immutable port policy only after checking that the process is
/// in a fresh namespace distinct from both authenticated caller and provider.
/// The dedicated setup process must be single-threaded and must not call
/// `setns` while this function runs. Failure requires destruction of this
/// namespace; callers must never resume a target with partial setup.
pub fn configure_private_port_policy(
    caller_namespace: NamespaceIdentity,
    provider_namespace: NamespaceIdentity,
) -> Result<PrivatePortPolicy, String> {
    let target_namespace = require_fresh_network_namespace(caller_namespace, provider_namespace)?;
    write_sysctl(UNPRIVILEGED_PORT_START, b"0\n")?;
    write_sysctl(LOCAL_PORT_RANGE, b"32768 60999\n")?;
    write_sysctl(LOCAL_RESERVED_PORTS, b"\n")?;
    let policy = read_private_port_policy()?;
    if policy != PrivatePortPolicy::REQUIRED {
        return Err(
            "MCSEALED-PRIVATE-NETWORK: namespace-local port policy readback mismatch".into(),
        );
    }
    if current_network_namespace()? != target_namespace {
        return Err("MCSEALED-PRIVATE-NETWORK: network namespace changed during setup".into());
    }
    Ok(policy)
}

fn require_fresh_network_namespace(
    caller_namespace: NamespaceIdentity,
    provider_namespace: NamespaceIdentity,
) -> Result<NamespaceIdentity, String> {
    let target_namespace = current_network_namespace()?;
    if target_namespace == caller_namespace || target_namespace == provider_namespace {
        return Err(
            "MCSEALED-PRIVATE-NETWORK: target did not enter a fresh network namespace".into(),
        );
    }
    Ok(target_namespace)
}

pub fn read_private_port_policy() -> Result<PrivatePortPolicy, String> {
    let unprivileged = read_sysctl(UNPRIVILEGED_PORT_START)?;
    let range = read_sysctl(LOCAL_PORT_RANGE)?;
    let reserved = read_sysctl(LOCAL_RESERVED_PORTS)?;
    parse_private_port_policy(&unprivileged, &range, &reserved)
}

pub fn parse_private_port_policy(
    unprivileged: &str,
    range: &str,
    reserved: &str,
) -> Result<PrivatePortPolicy, String> {
    let unprivileged_port_start = unprivileged
        .trim()
        .parse::<u16>()
        .map_err(|_| "MCSEALED-PRIVATE-NETWORK: invalid unprivileged port start")?;
    let mut range_tokens = range.split_ascii_whitespace();
    let low = range_tokens
        .next()
        .ok_or("MCSEALED-PRIVATE-NETWORK: missing local port range start")?
        .parse::<u16>()
        .map_err(|_| "MCSEALED-PRIVATE-NETWORK: invalid local port range start")?;
    let high = range_tokens
        .next()
        .ok_or("MCSEALED-PRIVATE-NETWORK: missing local port range end")?
        .parse::<u16>()
        .map_err(|_| "MCSEALED-PRIVATE-NETWORK: invalid local port range end")?;
    if range_tokens.next().is_some() || low == 0 || low > high {
        return Err("MCSEALED-PRIVATE-NETWORK: malformed local port range".into());
    }
    Ok(PrivatePortPolicy {
        unprivileged_port_start,
        local_port_range: (low, high),
        reserved_ports_empty: reserved.trim().is_empty(),
    })
}

pub(crate) fn current_network_namespace() -> Result<NamespaceIdentity, String> {
    let metadata = fs::metadata("/proc/self/ns/net")
        .map_err(|error| format!("MCSEALED-PRIVATE-NETWORK: netns identity: {error}"))?;
    Ok(NamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn read_sysctl(path: &str) -> Result<String, String> {
    let file = fs::File::open(path)
        .map_err(|error| format!("MCSEALED-PRIVATE-NETWORK: sysctl open {path}: {error}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_SYSCTL_READ + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("MCSEALED-PRIVATE-NETWORK: sysctl read {path}: {error}"))?;
    if bytes.len() as u64 > MAX_SYSCTL_READ {
        return Err(format!("MCSEALED-PRIVATE-NETWORK: sysctl overlong {path}"));
    }
    String::from_utf8(bytes)
        .map_err(|_| format!("MCSEALED-PRIVATE-NETWORK: sysctl not UTF-8 {path}"))
}

fn write_sysctl(path: &str, value: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| format!("MCSEALED-PRIVATE-NETWORK: sysctl open {path}: {error}"))?;
    file.write_all(value)
        .map_err(|error| format!("MCSEALED-PRIVATE-NETWORK: sysctl write {path}: {error}"))
}
