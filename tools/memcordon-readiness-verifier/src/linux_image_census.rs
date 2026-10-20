//! Independent acceptance of a complete native installed-image observation.
use crate::VerificationResult;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field))
    }) {
        return Err("installed image census schema differs".into());
    }
    Ok(())
}

pub(crate) fn identity(value: &Value) -> VerificationResult<(u64, u64)> {
    closed(
        value,
        &["device", "inode", "uid", "gid", "mode", "nlink", "length"],
    )?;
    for field in ["device", "inode", "uid", "gid", "mode", "nlink", "length"] {
        value[field]
            .as_u64()
            .ok_or("installed census numeric field absent")?;
    }
    if value["uid"] != 0
        || value["inode"] == 0
        || value["nlink"] == 0
        || value["gid"]
            .as_u64()
            .is_none_or(|value| value > u64::from(u32::MAX))
        || value["mode"]
            .as_u64()
            .is_none_or(|value| value > u64::from(u32::MAX))
    {
        return Err("installed census object lacks protected native custody".into());
    }
    Ok((
        value["device"].as_u64().unwrap(),
        value["inode"].as_u64().unwrap(),
    ))
}

fn directory(value: &Value) -> VerificationResult<(u64, u64)> {
    let identity = identity(value)?;
    let mode = value["mode"]
        .as_u64()
        .ok_or("installed census mode absent")?;
    if mode & 0o170000 != 0o040000 || mode & 0o022 != 0 {
        return Err("installed census directory is writable or not a directory".into());
    }
    Ok(identity)
}

/// Checks observation contents only. Native command provenance, original cutoff
/// and freshness against the held source are separately mandatory joins.
pub fn validate_linux_installed_image_census(
    census: &Value,
    definition: &Value,
    definition_sha256: &str,
    target: &str,
) -> VerificationResult<()> {
    crate::digest(definition_sha256)?;
    closed(
        census,
        &[
            "format",
            "revision",
            "reference",
            "target",
            "definition_sha256",
            "cutoff_unix_millis",
            "store",
            "root",
            "members",
        ],
    )?;
    if census["format"] != "memcordon.runtime-image-census"
        || census["revision"] != 1
        || census["reference"] != crate::linux_build::linux_image_reference(definition, target)?
        || census["target"] != target
        || census["definition_sha256"] != definition_sha256
        || census["cutoff_unix_millis"]
            .as_u64()
            .is_none_or(|value| value == 0)
    {
        return Err("installed census selected reference/target/definition differs".into());
    }
    let store = directory(&census["store"])?;
    let root = directory(&census["root"])?;
    if store == root || store.0 != root.0 {
        return Err("installed census selected root/store association differs".into());
    }
    let mut expected: BTreeMap<String, Option<&Value>> = BTreeMap::new();
    expected.insert(".memcordon-image.json".into(), None);
    for entry in definition["entries"]
        .as_array()
        .filter(|entries| !entries.is_empty() && entries.len() <= 4096)
        .ok_or("installed census approved members absent/over bound")?
    {
        let path = entry["path"]
            .as_str()
            .ok_or("installed census approved path absent")?;
        let components: Vec<_> = path.split('/').collect();
        for count in 1..components.len() {
            let parent = components[..count].join("/");
            if parent == ".memcordon-image.json"
                || expected
                    .insert(parent, None)
                    .is_some_and(|prior| prior.is_some())
            {
                return Err("installed census manifest/member used as parent".into());
            }
        }
        if expected.insert(path.to_owned(), Some(entry)).is_some() {
            return Err("installed census approved paths overlap".into());
        }
    }
    let members = census["members"]
        .as_array()
        .filter(|members| members.len() == expected.len())
        .ok_or("installed census complete population differs")?;
    let mut identities = BTreeSet::from([store, root]);
    for ((path, expected), member) in expected.iter().zip(members) {
        closed(member, &["path", "identity", "object"])?;
        let native = identity(&member["identity"])?;
        if member["path"] != *path || native.0 != root.0 || !identities.insert(native) {
            return Err("installed census member order/device/inode alias differs".into());
        }
        let object = &member["object"];
        let mode = member["identity"]["mode"]
            .as_u64()
            .ok_or("census member mode absent")?;
        if path == ".memcordon-image.json"
            || expected.is_some_and(|entry| entry["kind"] == "regular")
        {
            closed(object, &["kind", "sha256", "capability_absent"])?;
            let expected_hash = expected.map_or(Value::String(definition_sha256.into()), |entry| {
                entry["sha256"].clone()
            });
            let executable = expected.is_some_and(|entry| entry["executable"] == true);
            if object["kind"] != "regular"
                || object["sha256"] != expected_hash
                || object["capability_absent"] != true
                || member["identity"]["nlink"] != 1
                || mode != if executable { 0o100555 } else { 0o100444 }
                || expected.is_some_and(|entry| member["identity"]["length"] != entry["size"])
            {
                return Err("installed census protected approved bytes differ".into());
            }
        } else if let Some(entry) = expected {
            closed(object, &["kind", "target"])?;
            let mut link = vec![".."; path.split('/').count().saturating_sub(1)];
            link.extend(
                entry["target"]
                    .as_str()
                    .ok_or("declared census link target absent")?
                    .split('/'),
            );
            if entry["kind"] != "symlink"
                || object["kind"] != "symlink"
                || object["target"] != link.join("/")
                || mode != 0o120777
                || member["identity"]["nlink"] != 1
            {
                return Err("installed census reconstructed declared link differs".into());
            }
        } else {
            closed(object, &["kind"])?;
            directory(&member["identity"])?;
            if object["kind"] != "directory" {
                return Err("installed census implicit directory type differs".into());
            }
        }
    }
    Ok(())
}
