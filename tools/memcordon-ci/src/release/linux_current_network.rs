//! Actual host-network observations for the current installed lifetime.
use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use sha2::Digest;

/// Read host configuration without entering or changing any namespace.
#[cfg(target_os = "linux")]
pub fn snapshot() -> Result<serde_json::Value> {
    use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt, path::Path};
    let namespace = fs::metadata("/proc/self/ns/net")?;
    let mut facts = BTreeMap::new();
    for path in [
        "/proc/sys/net/ipv4/ip_local_port_range",
        "/proc/sys/net/ipv4/ip_local_reserved_ports",
        "/proc/sys/net/ipv4/ip_nonlocal_bind",
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        "/proc/net/route",
        "/proc/net/ipv6_route",
    ] {
        let bytes = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        facts.insert(path, bytes);
    }
    let mut links = BTreeMap::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CiError::Message("host link name is not UTF-8".into()))?;
        let observed = observe_link(Path::new("/sys/class/net"), &name)?;
        links.insert(name, observed);
    }
    Ok(
        serde_json::json!({"namespace_device":namespace.dev(),"namespace_inode":namespace.ino(),"facts":facts,"links":links}),
    )
}
fn ipv6_route_configuration(bytes: &[u8]) -> Result<Vec<[String; 9]>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CiError::Message("IPv6 route snapshot is not UTF-8".into()))?;
    let hex = |field: &str, bits: u32| -> Result<u128> {
        if field.len() != usize::try_from(bits / 4).expect("native hexadecimal width")
            || !field.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CiError::Message(
                "malformed IPv6 route hexadecimal field".into(),
            ));
        }
        u128::from_str_radix(field, 16)
            .map_err(|_| CiError::Message("invalid IPv6 route hexadecimal value".into()))
    };
    text.lines()
        .map(|line| {
            let fields: [&str; 10] = line
                .split_ascii_whitespace()
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| CiError::Message("malformed IPv6 route field count".into()))?;
            let [
                destination,
                prefix,
                source,
                source_prefix,
                next_hop,
                metric,
                references,
                uses,
                flags,
                interface,
            ] = fields;
            for address in [destination, source, next_hop] {
                hex(address, u128::BITS)?;
            }
            for prefix in [prefix, source_prefix] {
                if hex(prefix, u8::BITS)? > u128::from(u128::BITS) {
                    return Err(CiError::Message("invalid IPv6 route prefix length".into()));
                }
            }
            for value in [metric, references, uses, flags] {
                hex(value, u32::BITS)?;
            }
            // fib6_ref is an observational reference count, not configuration.
            // Preserve every other field, including usage, flags and interface.
            Ok([
                destination.into(),
                prefix.into(),
                source.into(),
                source_prefix.into(),
                next_hop.into(),
                metric.into(),
                uses.into(),
                flags.into(),
                interface.into(),
            ])
        })
        .collect()
}

fn network_configuration(snapshot: &serde_json::Value) -> Result<serde_json::Value> {
    let mut configuration = snapshot.clone();
    let routes = configuration
        .get_mut("facts")
        .and_then(|facts| facts.get_mut("/proc/net/ipv6_route"))
        .ok_or_else(|| CiError::Message("network snapshot omits IPv6 route observation".into()))?;
    if !routes.is_null() {
        let bytes: Vec<u8> = serde_json::from_value(routes.clone())?;
        *routes = serde_json::to_value(ipv6_route_configuration(&bytes)?)?;
    }
    Ok(configuration)
}

/// Compare captured configuration while retaining raw snapshots separately.
pub fn host_network_configuration_unchanged(
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> Result<bool> {
    Ok(host_network_comparison(before, after)?["unchanged"] == true)
}

/// Preserve the raw captures while explaining the exact semantic comparison.
pub fn host_network_comparison(
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> Result<serde_json::Value> {
    let before = network_configuration(before)?;
    let after = network_configuration(after)?;
    let acceleration_churn: Vec<serde_json::Value> = Vec::new();
    let mut changes = Vec::new();
    let mut omitted = 0_usize;
    let summarize = |value: Option<&serde_json::Value>| -> Result<serde_json::Value> {
        let Some(value) = value else {
            return Ok(serde_json::json!({"present":false}));
        };
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() <= 4096 {
            return Ok(serde_json::json!({"present":true,"value":value}));
        }
        Ok(
            serde_json::json!({"present":true,"bytes":bytes.len(),"sha256":DiagnosticSha256::from_bytes(sha2::Sha256::digest(&bytes).into()),"value_omitted":true}),
        )
    };
    let keys = before
        .as_object()
        .into_iter()
        .flat_map(|map| map.keys())
        .chain(after.as_object().into_iter().flat_map(|map| map.keys()))
        .collect::<std::collections::BTreeSet<_>>();
    for key in keys {
        if before.get(key) == after.get(key) {
            continue;
        }
        if matches!(key.as_str(), "facts" | "links")
            && before.get(key).is_some_and(serde_json::Value::is_object)
            && after.get(key).is_some_and(serde_json::Value::is_object)
        {
            let members = before
                .get(key)
                .and_then(serde_json::Value::as_object)
                .into_iter()
                .flat_map(|map| map.keys())
                .chain(
                    after
                        .get(key)
                        .and_then(serde_json::Value::as_object)
                        .into_iter()
                        .flat_map(|map| map.keys()),
                )
                .collect::<std::collections::BTreeSet<_>>();
            for member in members {
                let left = before.get(key).and_then(|map| map.get(member));
                let right = after.get(key).and_then(|map| map.get(member));
                if left == right {
                    continue;
                }
                if changes.len() < 128 {
                    changes.push(serde_json::json!({"path":[key,member],"before":summarize(left)?,"after":summarize(right)?}));
                } else {
                    omitted += 1;
                }
            }
        } else if changes.len() < 128 {
            changes.push(serde_json::json!({"path":[key],"before":summarize(before.get(key))?,"after":summarize(after.get(key))?}));
        } else {
            omitted += 1;
        }
    }
    Ok(
        serde_json::json!({"format":"memcordon.host-network-comparison","revision":1,
        "unchanged":before==after,"acceleration_churn":acceleration_churn,"changes":changes,"omitted_changes":omitted}),
    )
}
#[cfg(unix)]
mod link_observation {
    use crate::{CiError, Result};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    fn leaf(path: &Path) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(1025).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 {
            return Err(CiError::Message("sysfs network leaf exceeds bound".into()));
        }
        Ok(bytes)
    }

    fn identity(path: &Path) -> Result<Value> {
        let first = fs::metadata(path)?;
        let canonical = fs::canonicalize(path)?;
        let index = leaf(&path.join("ifindex"))?;
        let index = std::str::from_utf8(&index)
            .map_err(|error| CiError::Message(error.to_string()))?
            .trim()
            .parse::<u32>()
            .map_err(|error| CiError::Message(error.to_string()))?;
        let last = fs::metadata(path)?;
        if !first.is_dir()
            || index == 0
            || first.dev() != last.dev()
            || first.ino() != last.ino()
            || fs::canonicalize(path)? != canonical
        {
            return Err(CiError::Message(
                "sysfs network identity changed during observation".into(),
            ));
        }
        Ok(json!({"path":canonical,"device":first.dev(),"inode":first.ino(),"ifindex":index}))
    }

    fn optional_path(path: &Path) -> Result<Option<PathBuf>> {
        match fs::canonicalize(path) {
            Ok(path) => Ok(Some(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn relation(root: &Path, path: &Path, name: &str) -> Result<Value> {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(CiError::Message(
                "sysfs network relation name differs".into(),
            ));
        }
        if fs::canonicalize(root.join(name))? != fs::canonicalize(path)? {
            return Err(CiError::Message(
                "sysfs network relation does not join named identity".into(),
            ));
        }
        identity(path)
    }

    fn leaves(path: &Path) -> Result<BTreeMap<&'static str, Vec<u8>>> {
        ["ifindex", "address", "flags", "operstate"]
            .into_iter()
            .map(|name| Ok((name, leaf(&path.join(name))?)))
            .collect()
    }

    pub fn observe_link(root: &Path, name: &str) -> Result<Value> {
        let path = root.join(name);
        let initial = identity(&path)?;
        let values = leaves(&path)?;
        let provenance = (|| -> Result<Value> {
            let mut sampled = None;
            // Two proof samples detect churn; this is not a retry or a new baseline.
            for _ in 0..2 {
            let device = if let Some(device) = optional_path(&path.join("device"))? {
                Some(json!({"path":device,"subsystem":optional_path(&device.join("subsystem"))?,
                    "driver":optional_path(&device.join("driver"))?,"physfn":optional_path(&device.join("physfn"))?}))
            } else { None };
            let master = if let Some(master) = optional_path(&path.join("master"))? {
                let name = master.file_name().and_then(|name| name.to_str())
                    .ok_or_else(|| CiError::Message("sysfs master name is not UTF-8".into()))?;
                Some(json!({"name":name,"identity":relation(root, &master, name)?}))
            } else { None };
            let mut uppers = BTreeMap::new();
            let mut lowers = BTreeMap::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_str().ok_or_else(|| CiError::Message("sysfs relation name is not UTF-8".into()))?;
                let selected = name.strip_prefix("upper_").map(|name| (&mut uppers, name))
                    .or_else(|| name.strip_prefix("lower_").map(|name| (&mut lowers, name)));
                if let Some((relations, name)) = selected {
                    if !entry.file_type()?.is_symlink() {
                        return Err(CiError::Message("sysfs network relation is not a kernel symlink".into()));
                    }
                    relations.insert(name.to_owned(), relation(root, &entry.path(), name)?);
                }
            }
                let current = json!({"revision":1,"state":"observed","identity":initial,
                    "device":device,"master":master,"uppers":uppers,"lowers":lowers});
                if sampled.as_ref().is_some_and(|previous| previous != &current) {
                    return Err(CiError::Message("sysfs network topology changed during observation".into()));
                }
                sampled = Some(current);
            }
            if identity(&path)? != initial || leaves(&path)? != values {
                return Err(CiError::Message("sysfs network configuration changed during observation".into()));
            }
            Ok(sampled.expect("two native topology samples were collected"))
        })().unwrap_or_else(|error| json!({"revision":1,"state":"unavailable",
            "error":error.to_string().chars().take(1024).collect::<String>()}));
        let mut observed = serde_json::to_value(values)?;
        observed
            .as_object_mut()
            .expect("network leaves serialize as a map")
            .insert("provenance".into(), provenance);
        Ok(observed)
    }
}

#[cfg(unix)]
pub use link_observation::observe_link;
