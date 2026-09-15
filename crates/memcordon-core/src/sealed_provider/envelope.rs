//! Pure Linux proc status and namespace contracts, independent of the host OS.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerStatusV2 {
    pub uids: [u32; 4],
    pub gids: [u32; 4],
    pub supplementary_groups: Vec<u32>,
    pub no_new_privs: bool,
    pub capability_inheritable_set: u64,
    pub capability_permitted_set: u64,
    pub capability_effective_set: u64,
    pub capability_bounding_set: u64,
    pub capability_ambient_set: u64,
}

pub fn parse_capability_mask(value: &str) -> Result<u64, String> {
    if value.is_empty() || value.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err("capability mask is not hexadecimal".to_owned());
    }
    u64::from_str_radix(value, 16).map_err(|_| "capability mask exceeds 64 bits".to_owned())
}

pub fn parse_namespace_identity(value: &str, expected_kind: &str) -> Result<u64, String> {
    let (kind, inode) = value
        .split_once(":[")
        .ok_or_else(|| "namespace identity is malformed".to_owned())?;
    let inode = inode
        .strip_suffix(']')
        .ok_or_else(|| "namespace identity is malformed".to_owned())?;
    if kind != expected_kind || inode.is_empty() {
        return Err("namespace identity kind or inode is invalid".to_owned());
    }
    inode
        .parse()
        .map_err(|_| "namespace inode is invalid".to_owned())
}

pub fn parse_proc_status(status: &str) -> Result<CallerStatusV2, String> {
    fn field<'a>(status: &'a str, name: &str) -> Result<&'a str, String> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| format!("process status field {name:?} is missing"))
    }

    fn identity_columns(value: &str, name: &str) -> Result<[u32; 4], String> {
        let values = value
            .split_ascii_whitespace()
            .map(|value| {
                value
                    .parse::<u32>()
                    .map_err(|_| format!("process status field {name:?} is invalid"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        values
            .try_into()
            .map_err(|_| format!("process status field {name:?} has the wrong column count"))
    }

    let no_new_privs = match field(status, "NoNewPrivs:")?.trim() {
        "0" => false,
        "1" => true,
        _ => return Err("process status NoNewPrivs value is invalid".to_owned()),
    };
    let supplementary_groups = field(status, "Groups:")?
        .split_ascii_whitespace()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "process status supplementary group is invalid".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CallerStatusV2 {
        uids: identity_columns(field(status, "Uid:")?, "Uid")?,
        gids: identity_columns(field(status, "Gid:")?, "Gid")?,
        supplementary_groups,
        no_new_privs,
        capability_inheritable_set: parse_capability_mask(field(status, "CapInh:")?.trim())?,
        capability_permitted_set: parse_capability_mask(field(status, "CapPrm:")?.trim())?,
        capability_effective_set: parse_capability_mask(field(status, "CapEff:")?.trim())?,
        capability_bounding_set: parse_capability_mask(field(status, "CapBnd:")?.trim())?,
        capability_ambient_set: parse_capability_mask(field(status, "CapAmb:")?.trim())?,
    })
}
