use super::inventory::ProcessObservation;
use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};

pub(super) const TARGET_MARKER_SCHEMA: u32 = 2;
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct TargetMarker {
    pub(super) schema_version: u32,
    pub(super) target: ProcessObservation,
    pub(super) guardian: ProcessObservation,
}
#[derive(Debug)]
pub(super) enum MarkerState {
    Missing,
    Valid(TargetMarker),
    Malformed(String),
}
pub(super) fn read_marker(path: &Path) -> io::Result<MarkerState> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(MarkerState::Missing),
        Err(error) => return Err(error),
    };
    Ok(match serde_json::from_slice::<TargetMarker>(&bytes) {
        Ok(marker) if marker.schema_version == TARGET_MARKER_SCHEMA => MarkerState::Valid(marker),
        Ok(_) => MarkerState::Malformed("unsupported marker schema".into()),
        Err(error) => MarkerState::Malformed(error.to_string().chars().take(512).collect()),
    })
}
pub(super) fn validate_marker(
    marker: &TargetMarker,
    session: i32,
) -> std::result::Result<(), String> {
    if marker.schema_version != TARGET_MARKER_SCHEMA {
        return Err("unsupported marker schema".into());
    }
    if marker.target.identity.pid <= 0
        || marker.guardian.identity.pid <= 0
        || marker.target.identity.pid == marker.guardian.identity.pid
    {
        return Err("marker target and guardian must be distinct positive identities".into());
    }
    if marker.target.parent_pid != marker.guardian.identity.pid {
        return Err("marker guardian is not the target parent".into());
    }
    if marker.target.session_id != session || marker.guardian.session_id != session {
        return Err("marker identities do not belong to the oracle session".into());
    }
    if marker.target.identity.birth_microseconds >= 1_000_000
        || marker.guardian.identity.birth_microseconds >= 1_000_000
    {
        return Err("invalid marker birth identity".into());
    }
    Ok(())
}
pub(super) fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> super::Result<()> {
    let temporary = path.with_extension("tmp");
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}
