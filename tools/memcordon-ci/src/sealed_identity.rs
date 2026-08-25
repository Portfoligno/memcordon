use std::ffi::OsString;
use std::path::Path;

use serde::Serialize;

use crate::{CiError, Result};

pub const SETPRIV_PATH: &str = "/usr/bin/setpriv";
pub const PROVIDER_GROUP: &str = "memcordon";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontendIdentity {
    pub username: String,
    pub uid: u32,
    pub provider_gid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FrontendCredentialReadback {
    pub schema_version: u32,
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups: Vec<u32>,
    pub no_new_privs: bool,
    pub capability_inheritable: u64,
    pub capability_permitted: u64,
    pub capability_effective: u64,
    pub capability_ambient: u64,
}

pub fn parse_frontend_identity(
    username_output: &[u8],
    uid_output: &[u8],
    provider_group_output: &[u8],
) -> Result<FrontendIdentity> {
    let username = single_line("frontend username", username_output)?;
    if username == "root"
        || username
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b':')
    {
        return Err(CiError::Message(
            "Linux sealed certification frontend identity is unsafe".to_owned(),
        ));
    }
    let uid = parse_id("frontend uid", single_line("frontend uid", uid_output)?)?;
    if uid == 0 {
        return Err(CiError::Message(
            "Linux sealed certification frontend must begin as non-root".to_owned(),
        ));
    }

    let group = single_line("provider group", provider_group_output)?;
    let fields = group.split(':').collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != PROVIDER_GROUP {
        return Err(CiError::Message(
            "provider group database record is malformed".to_owned(),
        ));
    }
    let provider_gid = parse_id("provider gid", fields[2])?;
    if provider_gid == 0 {
        return Err(CiError::Message(
            "provider access group must not be root".to_owned(),
        ));
    }

    Ok(FrontendIdentity {
        username: username.to_owned(),
        uid,
        provider_gid,
    })
}

pub fn setpriv_sudo_arguments(
    identity: &FrontendIdentity,
    program: &Path,
    arguments: &[OsString],
) -> Result<Vec<OsString>> {
    if identity.uid == 0 || identity.provider_gid == 0 {
        return Err(CiError::Message(
            "setpriv identity must use non-root numeric ids".to_owned(),
        ));
    }
    if !program.is_absolute() {
        return Err(CiError::Message(
            "setpriv target program must be absolute".to_owned(),
        ));
    }
    let mut result = vec![
        OsString::from("--non-interactive"),
        OsString::from("--"),
        OsString::from(SETPRIV_PATH),
        OsString::from("--reuid"),
        OsString::from(identity.uid.to_string()),
        OsString::from("--regid"),
        OsString::from(identity.provider_gid.to_string()),
        OsString::from("--clear-groups"),
        OsString::from("--inh-caps=-all"),
        OsString::from("--ambient-caps=-all"),
        OsString::from("--no-new-privs"),
        OsString::from("--"),
        program.as_os_str().to_os_string(),
    ];
    result.extend_from_slice(arguments);
    Ok(result)
}

pub fn parse_credential_readback(
    identity: &FrontendIdentity,
    status_output: &[u8],
) -> Result<FrontendCredentialReadback> {
    let status = std::str::from_utf8(status_output)
        .map_err(|error| CiError::Message(format!("frontend status is not UTF-8: {error}")))?;
    let uid = parse_status_ids(status, "Uid", identity.uid)?;
    let gid = parse_status_ids(status, "Gid", identity.provider_gid)?;
    let supplementary_groups = parse_status_values(status, "Groups")?
        .into_iter()
        .map(|value| parse_id("supplementary gid", value))
        .collect::<Result<Vec<_>>>()?;
    if !supplementary_groups.is_empty() {
        return Err(CiError::Message(format!(
            "setpriv retained supplementary groups: {supplementary_groups:?}"
        )));
    }
    let no_new_privs = parse_status_values(status, "NoNewPrivs")?;
    if no_new_privs.as_slice() != ["1"] {
        return Err(CiError::Message(
            "setpriv did not enable no_new_privs".to_owned(),
        ));
    }
    let capability_inheritable = parse_inactive_capability_mask(status, "CapInh")?;
    let capability_permitted = parse_inactive_capability_mask(status, "CapPrm")?;
    let capability_effective = parse_inactive_capability_mask(status, "CapEff")?;
    let capability_ambient = parse_inactive_capability_mask(status, "CapAmb")?;
    Ok(FrontendCredentialReadback {
        schema_version: 2,
        username: identity.username.clone(),
        uid,
        gid,
        supplementary_groups,
        no_new_privs: true,
        capability_inheritable,
        capability_permitted,
        capability_effective,
        capability_ambient,
    })
}

fn single_line<'a>(label: &str, output: &'a [u8]) -> Result<&'a str> {
    let output = std::str::from_utf8(output)
        .map_err(|error| CiError::Message(format!("{label} is not UTF-8: {error}")))?;
    let line = output
        .strip_suffix('\n')
        .ok_or_else(|| CiError::Message(format!("{label} lacks one terminator")))?;
    if line.is_empty() || line.contains('\n') || line.contains('\r') {
        return Err(CiError::Message(format!("{label} is not one line")));
    }
    Ok(line)
}

fn parse_id(label: &str, value: &str) -> Result<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CiError::Message(format!("{label} is not a decimal id")));
    }
    value
        .parse()
        .map_err(|error| CiError::Message(format!("{label} is out of range: {error}")))
}

fn parse_status_ids(status: &str, field: &str, expected: u32) -> Result<u32> {
    let values = parse_status_values(status, field)?;
    if values.len() != 4 {
        return Err(CiError::Message(format!(
            "frontend {field} readback does not contain four ids"
        )));
    }
    let ids = values
        .into_iter()
        .map(|value| parse_id(field, value))
        .collect::<Result<Vec<_>>>()?;
    if ids.iter().any(|value| *value != expected) {
        return Err(CiError::Message(format!(
            "frontend {field} readback differs: expected {expected}, observed {ids:?}"
        )));
    }
    Ok(expected)
}

fn parse_inactive_capability_mask(status: &str, field: &str) -> Result<u64> {
    let values = parse_status_values(status, field)?;
    if values.len() != 1
        || values[0].is_empty()
        || !values[0].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CiError::Message(format!(
            "frontend {field} readback is not one hexadecimal mask"
        )));
    }
    let value = u64::from_str_radix(values[0], 16).map_err(|error| {
        CiError::Message(format!("frontend {field} readback is invalid: {error}"))
    })?;
    if value != 0 {
        return Err(CiError::Message(format!(
            "setpriv retained active {field} capability mask {value:#x}"
        )));
    }
    Ok(value)
}

fn parse_status_values<'a>(status: &'a str, field: &str) -> Result<Vec<&'a str>> {
    let prefix = format!("{field}:");
    let mut matches = status.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = matches
        .next()
        .ok_or_else(|| CiError::Message(format!("frontend status omitted {field}")))?;
    if matches.next().is_some() {
        return Err(CiError::Message(format!(
            "frontend status duplicated {field}"
        )));
    }
    Ok(value.split_whitespace().collect())
}
