//! Pairwise exclusion of positively observed hardware acceleration link lifecycle.
use serde_json::{Value, json};

fn closed(value: &Value, fields: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
    })
}

fn path(value: &Value) -> Option<&str> {
    let value = value.as_str()?;
    (value.starts_with("/sys/")
        && !value.contains(['\\', '\0'])
        && value.strip_prefix('/').is_some_and(|rest| {
            rest.split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
        }))
    .then_some(value)
}

fn identity(value: &Value, name: &str) -> bool {
    !name.is_empty()
        && !name.contains(['/', '\\', '\0'])
        && closed(value, &["path", "device", "inode", "ifindex"])
        && path(&value["path"]).is_some_and(|path| {
            path.starts_with("/sys/devices/")
                && path
                    .strip_suffix(name)
                    .is_some_and(|parent| parent.ends_with("/net/"))
        })
        && value["device"].as_u64().is_some()
        && value["inode"].as_u64().is_some_and(|value| value > 0)
        && value["ifindex"]
            .as_u64()
            .is_some_and(|value| value > 0 && u32::try_from(value).is_ok())
}

fn bytes(value: &Value) -> Option<String> {
    String::from_utf8(serde_json::from_value::<Vec<u8>>(value.clone()).ok()?).ok()
}

fn link(value: &Value, name: &str) -> bool {
    let proof = &value["provenance"];
    closed(
        value,
        &["ifindex", "address", "flags", "operstate", "provenance"],
    ) && closed(
        proof,
        &[
            "revision", "state", "identity", "device", "master", "uppers", "lowers",
        ],
    ) && proof["revision"] == 1
        && proof["state"] == "observed"
        && identity(&proof["identity"], name)
        && bytes(&value["ifindex"])
            .and_then(|value| value.trim().parse::<u32>().ok())
            .map(u64::from)
            == proof["identity"]["ifindex"].as_u64()
        && ["address", "flags", "operstate"]
            .iter()
            .all(|field| bytes(&value[*field]).is_some())
        && proof["uppers"].as_object().is_some()
        && proof["lowers"].as_object().is_some()
        && (proof["device"].is_null()
            || path(&proof["identity"]["path"]).is_some_and(|native| {
                path(&proof["device"]["path"]).is_some_and(|device| {
                    native
                        .strip_prefix(device)
                        .is_some_and(|rest| rest.strip_prefix("/net/") == Some(name))
                })
            }))
}

fn device(value: &Value, bus: &str, driver: Option<&str>) -> bool {
    if !closed(value, &["path", "subsystem", "driver", "physfn"])
        || !path(&value["path"]).is_some_and(|value| value.starts_with("/sys/devices/"))
        || value["subsystem"] != bus
        || !(value["physfn"].is_null()
            || path(&value["physfn"]).is_some_and(|value| value.starts_with("/sys/devices/")))
    {
        return false;
    }
    let Some(actual) = path(&value["driver"]) else {
        return false;
    };
    if let Some(driver) = driver {
        actual == driver
    } else {
        actual
            .strip_prefix("/sys/bus/pci/drivers/")
            .is_some_and(|child| !child.is_empty() && !child.contains('/'))
    }
}

fn qualified(present: &Value, absent: &Value, name: &str) -> Option<String> {
    let links = present["links"].as_object()?;
    let other = absent["links"].as_object()?;
    let candidate = links.get(name)?;
    if other.contains_key(name) || !link(candidate, name) {
        return None;
    }
    let proof = &candidate["provenance"];
    let flags = bytes(&candidate["flags"])?;
    let flags = u32::from_str_radix(flags.trim().strip_prefix("0x")?, 16).ok()?;
    let master = &proof["master"];
    let master_name = master["name"].as_str()?;
    if !closed(master, &["name", "identity"])
        || master_name == name
        || flags & 0x800 == 0
        || !device(&proof["device"], "/sys/bus/pci", None)
        || !proof["lowers"].as_object()?.is_empty()
        || proof["uppers"].as_object()?.len() != 1
        || proof["uppers"][master_name] != master["identity"]
    {
        return None;
    }
    let current_master = links.get(master_name)?;
    let other_master = other.get(master_name)?;
    if !link(current_master, master_name)
        || !link(other_master, master_name)
        || current_master["provenance"]["identity"] != master["identity"]
        || !device(
            &current_master["provenance"]["device"],
            "/sys/bus/vmbus",
            Some("/sys/bus/vmbus/drivers/hv_netvsc"),
        )
        || current_master["provenance"]["lowers"][name] != proof["identity"]
        || other_master["provenance"]["lowers"]
            .as_object()?
            .contains_key(name)
        || bytes(&candidate["address"])?.trim().is_empty()
        || candidate["address"] != current_master["address"]
    {
        return None;
    }
    let mut stripped = current_master.clone();
    stripped["provenance"]["lowers"]
        .as_object_mut()?
        .remove(name);
    (stripped == *other_master).then(|| master_name.to_owned())
}

/// Mutate only comparison clones; unknown provenance never earns an exclusion.
pub fn project_acceleration_churn(before: &mut Value, after: &mut Value) -> Vec<Value> {
    let original_before = before.clone();
    let original_after = after.clone();
    let mut decisions = Vec::new();
    for (present, absent, addition) in [
        (&original_after, &original_before, true),
        (&original_before, &original_after, false),
    ] {
        let Some(links) = present["links"].as_object() else {
            continue;
        };
        for name in links.keys() {
            let Some(master) = qualified(present, absent, name) else {
                continue;
            };
            let target = if addition { &mut *after } else { &mut *before };
            target["links"]
                .as_object_mut()
                .expect("qualified link population")
                .remove(name);
            target["links"][&master]["provenance"]["lowers"]
                .as_object_mut()
                .expect("qualified master lowers")
                .remove(name);
            decisions.push(json!({"link":name,"master":master,"change":if addition {"added"} else {"removed"},"basis":"observed-pci-slave-of-unchanged-hv-netvsc"}));
        }
    }
    decisions
}
