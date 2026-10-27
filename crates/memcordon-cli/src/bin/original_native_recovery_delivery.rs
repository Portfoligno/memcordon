//! Original measured delivery association; never resolves a live /proc table.
#[path = "../../../../tools/memcordon-readiness-verifier/src/linux_frontend_access.rs"]
mod frontend_access;

use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn validate_contract(
    bytes: &[u8],
    prepared: &memcordon_core::mixed_observation::MixedPreparedObservationV2,
    source_commit: &str,
) -> Result<(), String> {
    prepared.validate()?;
    let contract = memcordon_core::workload_contract_v3::WorkloadContractV3::parse(bytes)?;
    if contract != prepared.admission.request
        || !prepared.provider.is_consistent()
        || prepared.provider.source_commit.as_str() != source_commit
    {
        return Err(
            "original recovery delivery contract/provider substitutes prepared admission".into(),
        );
    }
    Ok(())
}

fn closed(value: &Value, fields: &[&str]) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("original recovery delivery object absent")?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err("original recovery delivery fields differ".into());
    }
    Ok(())
}

pub fn validate(
    invocation: &Value,
    contract: &[u8],
    destination: &Value,
    failure: &Value,
    caller_pid: u32,
    caller_uid: u32,
) -> Result<(), String> {
    let raw: Vec<Vec<u8>> = serde_json::from_value(invocation["arguments"].clone())
        .map_err(|error| error.to_string())?;
    let resolved = frontend_access::resolve(invocation, Some(contract))?;
    closed(
        &resolved,
        &[
            "format",
            "revision",
            "program",
            "arguments",
            "environment_cleared",
            "caller_uid",
            "caller_gid",
            "selected_cli_sha256",
        ],
    )?;
    let args: Vec<Vec<u8>> =
        serde_json::from_value(resolved["arguments"].clone()).map_err(|error| error.to_string())?;
    let program: Vec<u8> =
        serde_json::from_value(resolved["program"].clone()).map_err(|error| error.to_string())?;
    let digest = resolved["selected_cli_sha256"]
        .as_str()
        .ok_or("original recovery frontend source digest absent")?;
    let digest_width = hex::encode(Sha256::digest([])).len();
    if caller_pid == 0
        || caller_uid != 65534
        || raw.len() != 26
        || args.len() != raw.len()
        || resolved["format"] != "memcordon.linux-owned-frontend-invocation"
        || resolved["revision"] != 1
        || program != b"/usr/bin/setpriv"
        || resolved["environment_cleared"] != true
        || resolved["caller_uid"] != caller_uid
        || resolved["caller_gid"] != caller_uid
        || digest.len() != digest_width
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("original recovery delivery frontend identity/source differs".into());
    }
    for (index, expected) in [
        (0, "--reuid"),
        (1, "65534"),
        (2, "--regid"),
        (3, "65534"),
        (5, "--"),
        (6, "/usr/libexec/memcordon"),
        (9, "--sealed"),
        (10, "--workload-contract"),
        (12, "--report-format"),
        (13, "result-v2"),
        (14, "--report"),
        (16, "--mixed-observation-directory"),
        (18, "--image-entrypoint"),
        (19, "owned-readiness"),
        (20, "--wait-for"),
        (21, "command"),
        (22, "--"),
        (23, "bytes-argv-status"),
        (25, "0"),
    ] {
        if args[index] != expected.as_bytes() {
            return Err("original recovery delivery frontend argument association differs".into());
        }
    }
    closed(
        destination,
        &[
            "format",
            "revision",
            "path",
            "device",
            "inode",
            "uid",
            "gid",
            "mode",
            "is_directory",
        ],
    )?;
    closed(
        failure,
        &[
            "format",
            "revision",
            "report_path",
            "submitted_report",
            "native_errno",
            "native_error_code",
            "destination",
            "frontend_pid",
        ],
    )?;
    closed(
        &failure["destination"],
        &["device", "inode", "uid", "gid", "mode", "is_directory"],
    )?;
    if destination["format"] != "memcordon.linux-report-destination"
        || destination["revision"] != 1
        || failure["format"] != "memcordon.linux-native-report-delivery-failure"
        || failure["revision"] != 1
        || failure["report_path"]
            != serde_json::to_value(&raw[15]).map_err(|error| error.to_string())?
        || destination["path"]
            != serde_json::to_value(&args[15]).map_err(|error| error.to_string())?
        || failure["frontend_pid"] != caller_pid
        || failure["native_errno"] != 21
        || failure["native_error_code"] != "MCREPORT-WRITE"
        || destination["is_directory"] != true
        || destination["uid"] != caller_uid
        || destination["gid"] != caller_uid
        || destination["mode"]
            .as_u64()
            .is_none_or(|mode| mode & 0o170000 != 0o040000 || mode & 0o7777 != 0o700)
        || ["device", "inode"]
            .iter()
            .any(|field| destination[*field].as_u64().is_none_or(|value| value == 0))
    {
        return Err("original recovery report delivery association differs".into());
    }
    for field in ["device", "inode", "uid", "gid", "mode", "is_directory"] {
        if failure["destination"][field] != destination[field] {
            return Err("original recovery report destination native identity differs".into());
        }
    }
    let submitted: Vec<u8> = serde_json::from_value(failure["submitted_report"].clone())
        .map_err(|error| error.to_string())?;
    if submitted.is_empty() || submitted.len() > 16 * 1024 * 1024 {
        return Err("original recovery submitted report exceeds native bound".into());
    }
    Ok(())
}
