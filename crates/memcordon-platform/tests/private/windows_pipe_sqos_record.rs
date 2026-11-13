//! Closed, redacted fixture measurements; never a production connection policy.
use serde::{Deserialize, Serialize};
use std::io;

pub const MARKER: &str = "[windows-pipe-sqos-v1] ";
pub const GAP_MARKER: &str = "[windows-pipe-sqos-gap-v1] ";
pub const MAX_ROW_BYTES: usize = 8192;
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const DESIRED_ACCESS: u32 = 0x0012_019b;
pub const TRACKING_MARKER: &str = "[windows-pipe-sqos-tracking-v1] ";
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    Baseline,
    StaticFull,
    StaticEffective,
    DynamicFull,
    DynamicEffective,
}
impl Case {
    pub const ALL: [Self; 5] = [
        Self::Baseline,
        Self::StaticFull,
        Self::StaticEffective,
        Self::DynamicFull,
        Self::DynamicEffective,
    ];
    pub fn flags(self) -> u32 {
        let normal = 0x80;
        let present_impersonation = 0x100000 | 0x20000;
        match self {
            Self::Baseline => normal,
            Self::StaticFull => normal | present_impersonation,
            Self::StaticEffective => normal | present_impersonation | 0x80000,
            Self::DynamicFull => normal | present_impersonation | 0x40000,
            Self::DynamicEffective => normal | present_impersonation | 0xc0000,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub process_id: u32,
    pub process_birth: u64,
    pub thread_id: u32,
    pub token_id: u64,
    pub modified_id: u64,
    pub authentication_id: u64,
    pub token_type: u32,
    pub impersonation_level: Option<u32>,
    pub total: u32,
    pub enabled: u32,
    pub all_sha256: [u8; 32],
    pub enabled_sha256: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Inventory {
    All,
    Enabled,
    Both,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeChecks {
    pub authentication_rejected: u32,
    pub early_disconnect_rejected: u32,
    pub pending_read_cancelled: u32,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub desired_access: u32,
    pub share_mode: u32,
    pub open_disposition: u32,
    pub negative_checks: NegativeChecks,
    pub revision: u32,
    pub case: Case,
    pub flags: u32,
    pub digest_kind: String,
    pub tracking: String,
    pub before_connect: Summary,
    pub before_write: Summary,
    pub after_write: Summary,
    pub server: Summary,
    pub inventory: Inventory,
    pub message_sha256: [u8; 32],
    pub message_read: bool,
    pub server_thread_token: bool,
    pub reverted: bool,
    pub worker_retired: bool,
}
pub fn classify(client: &Summary, server: &Summary) -> Inventory {
    let all = server.total == client.total && server.all_sha256 == client.all_sha256;
    let enabled = server.total == client.enabled && server.all_sha256 == client.enabled_sha256;
    match (all, enabled) {
        (true, true) => Inventory::Both,
        (true, false) => Inventory::All,
        (false, true) => Inventory::Enabled,
        _ => Inventory::Other,
    }
}
pub fn validate(row: &Row) -> io::Result<()> {
    validate_structure(row)?;
    let reject = || io::Error::other("invalid bounded SQOS fixture row");
    if row.revision != 1
        || row.desired_access != DESIRED_ACCESS
        || row.share_mode != 0
        || row.open_disposition != 3
        || row.negative_checks.authentication_rejected == 0
        || row.negative_checks.early_disconnect_rejected == 0
        || row.negative_checks.pending_read_cancelled != 995
        || row.flags != row.case.flags()
        || row.digest_kind != "length-prefixed-le-luid-attributes-v1"
        || row.tracking != "unmeasured-stationary-context"
        || !row.message_read
        || !row.server_thread_token
        || !row.reverted
        || !row.worker_retired
        || row.server.token_type != 2
        || row.server.impersonation_level != Some(2)
        || row.inventory != classify(&row.before_write, &row.server)
    {
        return Err(reject());
    }
    for sample in [
        &row.before_connect,
        &row.before_write,
        &row.after_write,
        &row.server,
    ] {
        if sample.process_id == 0
            || sample.process_birth == 0
            || sample.thread_id == 0
            || sample.enabled > sample.total
            || sample.total > 256
        {
            return Err(reject());
        }
    }
    if row.before_connect != row.before_write
        || row.before_write != row.after_write
        || row.server.process_id != row.before_write.process_id
        || row.server.process_birth != row.before_write.process_birth
    {
        return Err(reject());
    }
    Ok(())
}
pub fn encode(row: &Row) -> io::Result<String> {
    // Serialization retains genuine failed measurements too; it is not a pass.
    let json = serde_json::to_string(row).map_err(io::Error::other)?;
    if json.len() > MAX_ROW_BYTES {
        return Err(io::Error::other("SQOS row exceeds fixed bound"));
    }
    Ok(json)
}
fn validate_structure(row: &Row) -> io::Result<()> {
    if row.revision != 1
        || row.flags != row.case.flags()
        || row.digest_kind != "length-prefixed-le-luid-attributes-v1"
        || row.tracking != "unmeasured-stationary-context"
        || row.inventory != classify(&row.before_write, &row.server)
        || [
            &row.before_connect,
            &row.before_write,
            &row.after_write,
            &row.server,
        ]
        .iter()
        .any(|sample| sample.enabled > sample.total || sample.total > 256)
    {
        return Err(io::Error::other("invalid SQOS diagnostic structure"));
    }
    Ok(())
}
pub fn verify_rows(rows: &[String]) -> io::Result<()> {
    if rows.len() != Case::ALL.len() {
        return Err(io::Error::other("SQOS measurement set incomplete"));
    }
    let mut original = None;
    for (index, json) in rows.iter().enumerate() {
        let row: Row = serde_json::from_str(json).map_err(io::Error::other)?;
        validate(&row)?;
        if row.case != Case::ALL[index]
            || original.as_ref().is_some_and(|(caller, checks)| {
                caller != &row.before_connect || checks != &row.negative_checks
            })
        {
            return Err(io::Error::other(
                "SQOS caller or negative checks changed between rows",
            ));
        }
        if matches!(row.case, Case::StaticFull | Case::DynamicFull)
            && !matches!(row.inventory, Inventory::All | Inventory::Both)
        {
            return Err(io::Error::other(
                "explicit full SQOS inventory preservation failed",
            ));
        }
        if original.is_none() {
            original = Some((row.before_connect, row.negative_checks));
        }
    }
    Ok(())
}
pub fn extract(stdout: &[u8]) -> io::Result<Vec<String>> {
    if stdout.len() > MAX_OUTPUT_BYTES {
        return Err(io::Error::other("SQOS output exceeds fixed bound"));
    }
    let text = std::str::from_utf8(stdout).map_err(io::Error::other)?;
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.contains(GAP_MARKER) {
            return Err(io::Error::other(
                "SQOS fixture contains an explicit unavailable measurement",
            ));
        }
        let inline = line.strip_prefix(
            "test owned_pipe_sqos_rows_measure_authenticated_inventory_without_policy_changes ... ",
        );
        let Some(json) = line
            .strip_prefix(MARKER)
            .or_else(|| inline.and_then(|line| line.strip_prefix(MARKER)))
        else {
            continue;
        };
        if json.len() > MAX_ROW_BYTES || rows.len() >= Case::ALL.len() {
            return Err(io::Error::other("SQOS marker exceeds fixed bounds"));
        }
        let row: Row = serde_json::from_str(json).map_err(io::Error::other)?;
        validate_structure(&row)?;
        if row.case != Case::ALL[rows.len()] {
            return Err(io::Error::other(
                "SQOS rows omitted, duplicated or reordered",
            ));
        }
        rows.push(json.to_owned());
    }
    if rows.len() != Case::ALL.len() {
        return Err(io::Error::other(
            "SQOS fixture requires all five measured rows",
        ));
    }
    Ok(rows)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrackingCase {
    Baseline,
    StaticFull,
    DynamicFull,
}
impl TrackingCase {
    pub const ALL: [Self; 3] = [Self::Baseline, Self::StaticFull, Self::DynamicFull];
    pub fn flags(self) -> u32 {
        match self {
            Self::Baseline => Case::Baseline.flags(),
            Self::StaticFull => Case::StaticFull.flags(),
            Self::DynamicFull => Case::DynamicFull.flags(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrackingInventory {
    ConnectAll,
    ConnectEnabled,
    ConnectBoth,
    WriteAll,
    WriteEnabled,
    WriteBoth,
    Ambiguous,
    Other,
}
pub fn classify_tracking(
    connect: &Summary,
    write: &Summary,
    server: &Summary,
) -> TrackingInventory {
    let matches = [
        (
            server.total == connect.total && server.all_sha256 == connect.all_sha256,
            TrackingInventory::ConnectAll,
        ),
        (
            server.total == connect.enabled && server.all_sha256 == connect.enabled_sha256,
            TrackingInventory::ConnectEnabled,
        ),
        (
            server.total == write.total && server.all_sha256 == write.all_sha256,
            TrackingInventory::WriteAll,
        ),
        (
            server.total == write.enabled && server.all_sha256 == write.enabled_sha256,
            TrackingInventory::WriteEnabled,
        ),
    ];
    if matches[0].0 && matches[1].0 && !matches[2].0 && !matches[3].0 {
        return TrackingInventory::ConnectBoth;
    }
    if matches[2].0 && matches[3].0 && !matches[0].0 && !matches[1].0 {
        return TrackingInventory::WriteBoth;
    }
    let mut values = matches
        .into_iter()
        .filter_map(|(yes, kind)| yes.then_some(kind));
    match (values.next(), values.next()) {
        (Some(kind), None) => kind,
        (None, _) => TrackingInventory::Other,
        _ => TrackingInventory::Ambiguous,
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackingRow {
    pub revision: u32,
    pub case: TrackingCase,
    pub flags: u32,
    pub desired_access: u32,
    pub share_mode: u32,
    pub open_disposition: u32,
    pub experiment: String,
    pub digest_kind: String,
    pub connect: Summary,
    pub write: Summary,
    pub post_write: Summary,
    pub restored: Summary,
    pub server: Summary,
    pub inventory: TrackingInventory,
    pub message_sha256: [u8; 32],
    pub connect_no_thread_token: bool,
    pub restored_no_thread_token: bool,
    pub writer_context_held_through_server_snapshot: bool,
    pub message_read: bool,
    pub server_thread_token: bool,
    pub reverted: bool,
    pub worker_retired: bool,
}
fn tracking_structure(row: &TrackingRow) -> io::Result<()> {
    if row.revision != 1
        || row.flags != row.case.flags()
        || row.desired_access != DESIRED_ACCESS
        || row.share_mode != 0
        || row.open_disposition != 3
        || row.experiment != "thread-context-replacement"
        || row.digest_kind != "length-prefixed-le-luid-attributes-v1"
        || row.inventory != classify_tracking(&row.connect, &row.write, &row.server)
        || [
            &row.connect,
            &row.write,
            &row.post_write,
            &row.restored,
            &row.server,
        ]
        .iter()
        .any(|sample| sample.total > 256 || sample.enabled > sample.total)
    {
        return Err(io::Error::other("invalid bounded SQOS tracking structure"));
    }
    Ok(())
}
pub fn encode_tracking(row: &TrackingRow) -> io::Result<String> {
    let json = serde_json::to_string(row).map_err(io::Error::other)?;
    if json.len() > MAX_ROW_BYTES {
        return Err(io::Error::other("SQOS tracking row exceeds fixed bound"));
    }
    Ok(json)
}
pub fn extract_tracking(stdout: &[u8]) -> io::Result<Vec<String>> {
    if stdout.len() > MAX_OUTPUT_BYTES {
        return Err(io::Error::other("SQOS tracking output exceeds fixed bound"));
    }
    let text = std::str::from_utf8(stdout).map_err(io::Error::other)?;
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.contains(GAP_MARKER) {
            return Err(io::Error::other("SQOS tracking observation unavailable"));
        }
        let Some(json) = line.strip_prefix(TRACKING_MARKER) else {
            continue;
        };
        if json.len() > MAX_ROW_BYTES || rows.len() >= TrackingCase::ALL.len() {
            return Err(io::Error::other(
                "SQOS tracking marker exceeds fixed bounds",
            ));
        }
        let row: TrackingRow = serde_json::from_str(json).map_err(io::Error::other)?;
        tracking_structure(&row)?;
        if row.case != TrackingCase::ALL[rows.len()] {
            return Err(io::Error::other(
                "SQOS tracking rows omitted, duplicated or reordered",
            ));
        }
        rows.push(json.to_owned());
    }
    if rows.len() != TrackingCase::ALL.len() {
        return Err(io::Error::other(
            "SQOS tracking requires all three measured rows",
        ));
    }
    Ok(rows)
}
pub fn verify_tracking_rows(rows: &[String]) -> io::Result<()> {
    if rows.len() != TrackingCase::ALL.len() {
        return Err(io::Error::other("SQOS tracking set incomplete"));
    }
    for (index, json) in rows.iter().enumerate() {
        let row: TrackingRow = serde_json::from_str(json).map_err(io::Error::other)?;
        tracking_structure(&row)?;
        let all = [
            &row.connect,
            &row.write,
            &row.post_write,
            &row.restored,
            &row.server,
        ];
        if row.case != TrackingCase::ALL[index]
            || !row.connect_no_thread_token
            || !row.restored_no_thread_token
            || !row.writer_context_held_through_server_snapshot
            || !row.message_read
            || !row.server_thread_token
            || !row.reverted
            || !row.worker_retired
            || all.iter().any(|sample| {
                sample.process_id == 0
                    || sample.process_birth == 0
                    || sample.thread_id == 0
                    || sample.process_id != row.connect.process_id
                    || sample.process_birth != row.connect.process_birth
            })
            || row.connect != row.restored
            || row.write != row.post_write
            || row.connect.thread_id != row.write.thread_id
            || row.connect.token_type != 1
            || row.connect.impersonation_level.is_some()
            || row.write.token_type != 2
            || row.write.impersonation_level != Some(2)
            || row.server.token_type != 2
            || row.server.impersonation_level != Some(2)
            || row.connect.enabled_sha256 == row.write.enabled_sha256
            || row.connect.authentication_id != row.write.authentication_id
            || row.connect.authentication_id != row.server.authentication_id
            || (row.case == TrackingCase::StaticFull
                && (row.server.total != row.connect.total
                    || row.server.all_sha256 != row.connect.all_sha256))
            || (row.case == TrackingCase::DynamicFull
                && (row.server.total != row.write.total
                    || row.server.all_sha256 != row.write.all_sha256))
        {
            return Err(io::Error::other(
                "SQOS tracking context, restoration or explicit-row contract failed",
            ));
        }
    }
    Ok(())
}
