//! Decode the finite native frontend descriptor handoff without changing its receipt.
use serde_json::Value;
use sha2::{Digest, Sha256};

fn closed(value: &Value, fields: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("frontend access object absent")?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err("frontend access fields differ".into());
    }
    Ok(())
}

fn bytes(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}

fn path(value: &Value) -> Result<Vec<u8>, String> {
    let result = bytes(value)?;
    if !result.starts_with(b"/")
        || result.len() > 4096
        || result.contains(&0)
        || result[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err("frontend access path is not an original absolute path".into());
    }
    Ok(result)
}

fn number(value: &Value) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or_else(|| "frontend access native integer absent".into())
}

/// Historical direct-path receipts remain strict at their existing consumers.
/// Descriptor receipts are resolved only after the complete fixed map is checked.
pub fn resolve(command: &Value, contract_bytes: Option<&[u8]>) -> Result<Value, String> {
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    if let Some(endpoint) = command.get("endpoint_access") {
        let gid = endpoint_group(endpoint)?;
        let argument = format!("--groups={gid}").into_bytes();
        if arguments.get(4) != Some(&argument) {
            return Err("frontend supplementary group differs from held public endpoint".into());
        }
    } else if arguments.get(4).map(Vec::as_slice) != Some(b"--clear-groups") {
        return Err("frontend supplementary group lacks original endpoint access receipt".into());
    }
    let mut command = command.clone();
    command
        .as_object_mut()
        .ok_or("frontend command object absent")?
        .remove("endpoint_access");
    let command = &command;
    let Some(access) = command.get("file_access") else {
        let arguments: Vec<Vec<u8>> = serde_json::from_value(command["arguments"].clone())
            .map_err(|error| error.to_string())?;
        if arguments.windows(2).any(|pair| {
            [
                b"--workload-contract".as_slice(),
                b"--report",
                b"--mixed-observation-directory",
            ]
            .contains(&pair[0].as_slice())
                && pair[1].starts_with(b"/proc/self/fd/")
        }) {
            return Err("frontend descriptor operands lack original native access receipt".into());
        }
        return Ok(command.clone());
    };
    closed(
        access,
        &["format", "revision", "contract", "output_directory"],
    )?;
    if access["format"] != "memcordon.linux-frontend-file-access" || access["revision"] != 1 {
        return Err("frontend access codec differs".into());
    }
    let source = &access["contract"];
    let runtime = &source["runtime"];
    let directory = &access["output_directory"];
    closed(
        source,
        &[
            "descriptor",
            "path",
            "device",
            "inode",
            "uid",
            "gid",
            "mode",
            "links",
            "length",
            "sha256",
            "runtime",
        ],
    )?;
    closed(
        runtime,
        &[
            "path", "device", "inode", "uid", "gid", "mode", "links", "length", "sha256",
        ],
    )?;
    closed(
        directory,
        &[
            "descriptor",
            "path",
            "device",
            "inode",
            "uid",
            "gid",
            "mode",
        ],
    )?;
    let source_path = path(&source["path"])?;
    let directory_path = path(&directory["path"])?;
    let mut runtime_path = directory_path.clone();
    runtime_path.extend_from_slice(b"/workload-contract.json");
    for file in [source, runtime] {
        let mode = number(&file["mode"])?;
        if number(&file["inode"])? == 0
            || number(&file["uid"])? != 0
            || number(&file["links"])? != 1
            || mode & 0o170000 != 0o100000
            || mode > u64::from(u32::MAX)
            || number(&file["gid"])? > u64::from(u32::MAX)
            || mode & 0o022 != 0
            || number(&file["length"])? == 0
            || number(&file["length"])? > 4 * 1024 * 1024
        {
            return Err("frontend contract native custody differs".into());
        }
        number(&file["device"])?;
        number(&file["gid"])?;
    }
    let digest = source["sha256"]
        .as_str()
        .ok_or("frontend source digest absent")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || runtime["sha256"] != source["sha256"]
        || runtime["length"] != source["length"]
        || path(&runtime["path"])? != runtime_path
        || number(&runtime["mode"])? & 0o7777 != 0o444
        || source_path == runtime_path
        || (source["device"] == runtime["device"] && source["inode"] == runtime["inode"])
        || source["descriptor"] != 129
        || directory["descriptor"] != 130
        || number(&directory["inode"])? == 0
        || number(&directory["mode"])? & 0o177777 != 0o40700
        || number(&directory["mode"])? > u64::from(u32::MAX)
        || !(1..=u64::from(u32::MAX)).contains(&number(&directory["uid"])?)
        || !(1..=u64::from(u32::MAX)).contains(&number(&directory["gid"])?)
        || directory["uid"] != command["caller_uid"]
        || directory["gid"] != command["caller_gid"]
    {
        return Err("frontend descriptor map differs from exact source/output authority".into());
    }
    number(&directory["device"])?;
    match contract_bytes {
        Some(original)
            if original.len() as u64 != number(&source["length"])?
                || hex::encode(Sha256::digest(original)) != digest =>
        {
            return Err("frontend descriptor contract differs from retained original bytes".into());
        }
        _ => {}
    }
    let mut arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    for (flag, actual, resolved) in [
        (
            b"--workload-contract".as_slice(),
            b"/proc/self/fd/129".as_slice(),
            source_path,
        ),
        (
            b"--report".as_slice(),
            b"/proc/self/fd/130/result.json".as_slice(),
            [directory_path.as_slice(), b"/result.json"].concat(),
        ),
        (
            b"--mixed-observation-directory".as_slice(),
            b"/proc/self/fd/130/observations".as_slice(),
            [directory_path.as_slice(), b"/observations"].concat(),
        ),
    ] {
        let positions: Vec<_> = arguments
            .iter()
            .enumerate()
            .filter_map(|(index, value)| (value == flag).then_some(index))
            .collect();
        if positions.len() != 1
            || arguments.get(positions[0] + 1).map(Vec::as_slice) != Some(actual)
        {
            return Err("frontend descriptor operand differs from fixed native handoff".into());
        }
        arguments[positions[0] + 1] = resolved;
    }
    let mut resolved = command.clone();
    resolved
        .as_object_mut()
        .ok_or("frontend command object absent")?
        .remove("file_access");
    resolved["arguments"] = serde_json::to_value(arguments).map_err(|error| error.to_string())?;
    Ok(resolved)
}

/// Decode the same finite original endpoint observation used by the frontend
/// invocation and the independent control-intervention receipt.
pub(crate) fn endpoint_group(endpoint: &Value) -> Result<u32, String> {
    closed(
        endpoint,
        &[
            "format",
            "revision",
            "path",
            "device",
            "inode",
            "uid",
            "gid",
            "mode",
            "links",
            "supplementary_groups",
            "group_argument",
        ],
    )?;
    let gid = number(&endpoint["gid"])?;
    let argument = format!("--groups={gid}").into_bytes();
    if endpoint["format"] != "memcordon.linux-owned-frontend-endpoint-access"
        || endpoint["revision"] != 1
        || path(&endpoint["path"])? != b"/run/memcordon/sealed-agent.sock"
        || number(&endpoint["device"])? == 0
        || number(&endpoint["inode"])? == 0
        || endpoint["uid"] != 0
        || gid == 0
        || gid > u64::from(u32::MAX)
        || endpoint["mode"] != 0o140660
        || endpoint["links"] != 1
        || endpoint["supplementary_groups"] != serde_json::json!([gid])
        || bytes(&endpoint["group_argument"])? != argument
    {
        return Err("frontend supplementary group differs from held public endpoint".into());
    }
    Ok(gid as u32)
}
