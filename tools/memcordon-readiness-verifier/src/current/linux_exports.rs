//! Independent native object and returned byte checks for current exports.
use super::CaseEvidenceV2;
use crate::VerificationResult;
use serde_json::Value;

fn bytes(value: &Value) -> VerificationResult<Vec<u8>> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}

pub fn verify(
    evidence: &CaseEvidenceV2,
    result: &Value,
    native: &Value,
    rows: &[Value],
    controller: &Value,
    resolver: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let scenario = evidence.key.scenario.as_str();
    let (kind, component, label) = match scenario {
        "export-symlink" => (0o120000, "work/exported.bin", "symlink"),
        "export-fifo" => (0o010000, "work/exported.bin", "controller-fifo-required"),
        "export-device" => (0o020000, "work/exported.bin", "controller-device-required"),
        "export-socket" => (0o140000, "work/exported.bin", "socket"),
        "export-traversal" => (0o120000, "work/parent", "parent-symlink"),
        "export-concurrent-writer" => (0o100000, "work/exported.bin", "regular-with-held-writer"),
        _ => return Err("unknown current export scenario".into()),
    };
    let node = &controller["export_candidate"];
    let ready = super::linux::operation(rows, "export-object-ready")?;
    if node["format"] != "memcordon.linux-current-export-node"
        || node["revision"] != 1
        || node["scenario"] != scenario
        || node["root"]["device"] != native["root_device"]
        || node["root"]["inode"] != native["root_inode"]
        || node["component"] != component
        || node["mode"]
            .as_u64()
            .is_none_or(|mode| mode & 0o170000 != kind)
        || node["inode"].as_u64().is_none_or(|inode| inode == 0)
        || node["links"] != 1
        || node["output_empty_before_release"] != true
        || ready["kind"] != label
        || result["outcome"]["native_termination"]["kind"] != "exit-code"
        || result["outcome"]["native_termination"]["code"] != 0
        || native["native_wait_status"] != 0
    {
        return Err("native export object, original root, release or direct wait differs".into());
    }
    if matches!(scenario, "export-fifo" | "export-device") {
        let injected = &controller["export_injection"];
        for field in ["device", "inode", "mode", "uid", "gid", "rdev", "component"] {
            if injected[field] != node[field] {
                return Err("held pre-release export injection was replaced".into());
            }
        }
        if node["uid"] != 0 || scenario == "export-device" && node["rdev"] != 259 {
            return Err("native injected object credentials/device differ".into());
        }
    } else if node["uid"] != native["target_uid"] {
        return Err("export object was not created by actual sandbox credential".into());
    }
    if matches!(scenario, "export-symlink" | "export-traversal") {
        let expected = if scenario == "export-symlink" {
            b"/owned-source/Cargo.toml".as_slice()
        } else {
            b"/work/other".as_slice()
        };
        if bytes(&node["symlink_target"])? != expected {
            return Err("native export symlink target differs".into());
        }
    }
    super::linux::operation(rows, "export-object-controller-release")?;
    if scenario != "export-concurrent-writer" {
        if result["output_delivery"] != "incomplete"
            || result["outcome"]["wrapper_status"] != 125
            || !evidence.outputs.is_empty()
            || controller["rejected_export_output_empty"] != true
        {
            return Err(
                "unsafe export was materialized or refusal/delivery outcome differs".into(),
            );
        }
        return Ok(());
    }
    let writer = &controller["export_writer_native"];
    let retired = super::linux::operation(rows, "export-writer-retired")?;
    let announced = super::linux::operation(rows, "export-writer-held")?;
    let stages = controller["held_stages"]
        .as_array()
        .ok_or("export writer native phase absent")?;
    let phases: Vec<_> = stages
        .iter()
        .filter(|stage| stage["operation"] == "export-writer-held")
        .collect();
    if phases.len() != 1 {
        return Err("original export writer phase duplicated/absent".into());
    }
    let children = phases[0]["children"]
        .as_array()
        .ok_or("export writer native child absent")?;
    if children.len() != 1 {
        return Err("export writer is not one independently held child".into());
    }
    let child = &children[0];
    if child["identity"]["pid"] != writer["writer"]["pid"]
        || child["identity"]["birth"] != writer["writer"]["birth"]
        || child["identity"]["parent_pid"] != native["target"]["pid"]
        || child["identity"]["parent_birth"] != native["target"]["birth"]
        || child["namespace_pid"] != announced["pid"]
        || retired["pid"] != announced["pid"]
        || child["credentials"]["uid"] != native["target_uid"]
    {
        return Err("writer original parent/namespace/credential association differs".into());
    }
    for (observed, expected) in [
        ("mount", "mount_namespace"),
        ("pid", "pid_namespace"),
        ("network", "network_namespace"),
        ("ipc", "ipc_namespace"),
    ] {
        if child["snapshot"][observed] != native[expected] {
            return Err("writer native namespace differs".into());
        }
    }
    if writer["pidfd_readable_after_stop"] != true
        || writer["target_alive_after_writer"] != true
        || retired["native_wait_completed"] != true
        || retired["raw_wait_status"] != 0
        || retired["native_exit_code"] != 0
        || retired["native_signal"] != Value::Null
        || retired["before_root_release"] != true
        || result["outcome"]["wrapper_status"] != 0
        || result["output_delivery"] != "complete"
        || evidence.outputs.len() != 1
    {
        return Err("actual writer retirement before root release is unproven".into());
    }
    let mut counters = Vec::new();
    for field in ["first", "second", "final"] {
        let sample = &writer[field];
        let value = bytes(&sample["bytes"])?;
        if sample["device"] != node["device"]
            || sample["inode"] != node["inode"]
            || sample["before_length"] != 14
            || sample["after_length"] != 14
            || value.len() != 14
            || &value[8..] != b"nitial"
        {
            return Err("native writer samples lost original file identity or finite bytes".into());
        }
        counters.push(u64::from_le_bytes(
            value[..8].try_into().map_err(|_| "writer counter absent")?,
        ));
    }
    if counters[0] == 0
        || counters[0] == counters[1]
        || counters[2] < counters[0].max(counters[1])
        || writer["final"]["before_mtime"] != writer["final"]["after_mtime"]
        || resolver(&evidence.outputs[0])? != bytes(&writer["final"]["bytes"])?
    {
        return Err("export copied a live writer or changed final settled bytes".into());
    }
    Ok(())
}
