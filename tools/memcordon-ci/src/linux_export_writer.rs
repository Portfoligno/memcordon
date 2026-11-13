//! Immediate checks of an already-held export writer; no process discovery occurs here.
use memcordon_core::workload_request::RootRelativePath;
use serde_json::Value;

fn integer(value: &Value, field: &str) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or_else(|| format!("export writer {field} is not a native unsigned integer"))
}
fn pid(value: &Value, field: &str) -> Result<u32, String> {
    u32::try_from(integer(value, field)?)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| format!("export writer {field} is not a nonzero native PID"))
}
fn unique<'a>(values: &'a [Value], operation: &str) -> Result<&'a Value, String> {
    let mut found = values
        .iter()
        .filter(|value| value["operation"] == operation);
    let result = found
        .next()
        .ok_or_else(|| format!("export writer required {operation} is absent"))?;
    if found.next().is_some() {
        return Err(format!("export writer required {operation} is duplicated"));
    }
    Ok(result)
}
fn bytes(value: &Value, field: &str) -> Result<Vec<u8>, String> {
    serde_json::from_value(value.clone())
        .map_err(|_| format!("export writer {field} bytes are missing or malformed"))
}

pub fn validate(
    controller: &Value,
    retirement: &Value,
    rows: &[Value],
    native: &Value,
    outputs: &[(RootRelativePath, Vec<u8>)],
) -> Result<(), String> {
    let writer = &controller["export_writer_native"];
    let host = pid(&writer["writer"]["pid"], "host PID")?;
    let local = pid(&writer["writer"]["namespace_pid"], "namespace PID")?;
    let birth = integer(&writer["writer"]["birth"], "birth")?;
    let context = format!("host={host}; namespace={local}; birth={birth}");
    let stages = controller["held_stages"]
        .as_array()
        .ok_or("export writer held stages absent")?;
    let stage = unique(stages, "export-writer-held")?;
    let children = stage["children"]
        .as_array()
        .ok_or("export writer held child array absent")?;
    if children.len() != 1 {
        return Err(format!(
            "export writer held child count differs; {context}; count={}",
            children.len()
        ));
    }
    let child = &children[0];
    let snapshot = &child["snapshot"];
    let identity = &child["identity"];
    if pid(&snapshot["process_id"], "snapshot host PID")? != host
        || integer(&snapshot["birth"], "snapshot birth")? != birth
        || pid(&identity["pid"], "held identity PID")? != host
        || integer(&identity["birth"], "held identity birth")? != birth
        || pid(&child["namespace_pid"], "held namespace PID")? != local
    {
        return Err(format!(
            "export writer original held identity binding differs; {context}"
        ));
    }
    let parent = pid(&native["target"]["pid"], "target PID")?;
    let parent_birth = integer(&native["target"]["birth"], "target birth")?;
    if pid(&identity["parent_pid"], "verified parent PID")? != parent
        || integer(&identity["parent_birth"], "verified parent birth")? != parent_birth
        || parent_birth > birth
        || identity["retirement_observed"] != false
    {
        return Err(format!(
            "export writer original live parent binding differs; {context}; parent={parent}; parent-birth={parent_birth}"
        ));
    }
    let mapping = snapshot["namespace_pids"]
        .as_array()
        .ok_or("export writer original NSpid mapping absent")?;
    let mapping: Vec<_> = mapping
        .iter()
        .map(|value| pid(value, "NSpid entry"))
        .collect::<Result<_, _>>()?;
    if mapping.first() != Some(&host)
        || mapping.last() != Some(&local)
        || snapshot["pid"] != native["pid_namespace"]
        || native["pid_namespace"]["inode"]
            .as_u64()
            .is_none_or(|inode| inode == 0)
        || !native["pid_namespace"]["device"].is_u64()
    {
        return Err(format!(
            "export writer native namespace mapping differs; {context}; mapping-count={}",
            mapping.len()
        ));
    }
    let held = unique(rows, "export-writer-held")?;
    if held["sequence"] != stage["sequence"]
        || !held["sequence"].as_u64().is_some_and(|value| value > 0)
        || pid(&held["observation"]["pid"], "announced namespace PID")? != local
        || integer(&held["observation"]["birth"], "announced birth")? != birth
    {
        return Err(format!(
            "export writer original authenticated announcement differs; {context}"
        ));
    }
    let retired = &unique(rows, "export-writer-retired")?["observation"];
    if pid(&retired["pid"], "retired namespace PID")? != local
        || retired["native_wait_completed"] != true
        || retired["raw_wait_status"] != 0
        || retired["before_root_release"] != true
    {
        return Err(format!(
            "export writer original namespace-local wait differs; {context}"
        ));
    }
    let records = retirement["held_processes"]
        .as_array()
        .ok_or("export writer original host retirement array absent")?;
    let mut matched = records
        .iter()
        .filter(|record| record["pid"].as_u64() == Some(u64::from(host)));
    let original = matched
        .next()
        .ok_or("export writer original host retirement absent")?;
    if matched.next().is_some()
        || integer(&original["birth"], "retired host birth")? != birth
        || original["pidfd_readable"] != true
        || writer["pidfd_readable_after_stop"] != true
    {
        return Err(format!(
            "export writer original pidfd retirement differs; {context}"
        ));
    }
    if writer["target_alive_after_writer"] != true {
        return Err(format!("export writer target lifetime differs; {context}"));
    }
    let first = bytes(&writer["first"]["bytes"], "first live sample")?;
    let second = bytes(&writer["second"]["bytes"], "second live sample")?;
    let final_bytes = bytes(&writer["final"]["bytes"], "post-retirement sample")?;
    if first == second {
        return Err(format!(
            "export writer live mutation absent; {context}; first-length={}; second-length={}",
            first.len(),
            second.len()
        ));
    }
    let inode = integer(&writer["first"]["inode"], "first inode")?;
    let device = integer(&writer["first"]["device"], "first device")?;
    if inode == 0
        || [
            &writer["second"],
            &writer["final"],
            &controller["export_candidate"],
        ]
        .into_iter()
        .any(|sample| {
            sample["inode"].as_u64() != Some(inode) || sample["device"].as_u64() != Some(device)
        })
    {
        return Err(format!(
            "export writer original file identity differs; {context}; device={device}; inode={inode}"
        ));
    }
    if outputs.len() != 1 {
        return Err(format!(
            "export writer caller output count differs; {context}; count={}",
            outputs.len()
        ));
    }
    let actual = &outputs[0].1;
    if actual != &final_bytes {
        let first_difference = actual
            .iter()
            .zip(&final_bytes)
            .position(|(actual, expected)| actual != expected)
            .unwrap_or(actual.len().min(final_bytes.len()));
        return Err(format!(
            "export writer exact final byte product differs; {context}; actual-length={}; expected-length={}; first-difference={first_difference}",
            actual.len(),
            final_bytes.len()
        ));
    }
    Ok(())
}
