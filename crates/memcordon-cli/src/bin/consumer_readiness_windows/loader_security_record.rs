//! Selection of an observed loader name, never authority over the original file.
use super::{listener_trace_record as listener, winsock_trace_record as dependency};
use serde_json::{Value, json};

pub const RECORD_BYTES: usize = 8192;
#[derive(Debug, PartialEq, Eq)]
pub struct SelectedPath {
    pub path: Vec<u16>,
    pub loader_dependency_sequence: u64,
    pub dependency_sequence: u64,
    pub parent_listener_sequence: u64,
    pub thread_id: u32,
}
fn same_entry(a: &dependency::Entry, b: &dependency::Entry) -> bool {
    a.sequence == b.sequence
        && a.raw_root == b.raw_root
        && a.raw_output == b.raw_output
        && a.requested_size == b.requested_size
        && a.secondary_size == b.secondary_size
        && a.operation == b.operation
        && a.thread_id == b.thread_id
        && a.desired_access == b.desired_access
        && a.flags == b.flags
        && a.entered == b.entered
        && a.returned == b.returned
        && a.native_status == b.native_status
        && a.incoming_error == b.incoming_error
        && a.outgoing_error == b.outgoing_error
        && a.reported_name_bytes == b.reported_name_bytes
        && a.copied_name_units == b.copied_name_units
        && a.name_flags == b.name_flags
        && a.output_flags == b.output_flags
        && a.scalar_flags == b.scalar_flags
        && a.name == b.name
}
fn entry(packet: &dependency::Packet, sequence: u64) -> Result<&dependency::Entry, String> {
    let mut entries = packet.entries[..(packet.record_count as usize).min(16)]
        .iter()
        .filter(|entry| entry.sequence == sequence)
        .collect::<Vec<_>>();
    if packet.first_failure_present == 1 && packet.first_failure.sequence == sequence {
        entries.push(&packet.first_failure);
    }
    let first = *entries.first().ok_or("observed loader entry unavailable")?;
    if entries.iter().any(|entry| !same_entry(first, entry)) {
        return Err("conflicting observed loader entry carriers".into());
    }
    Ok(first)
}
fn name(entry: &dependency::Entry) -> Result<Vec<u16>, String> {
    let count = entry.copied_name_units as usize;
    if entry.name_flags != 1
        || count == 0
        || count > 256
        || entry.reported_name_bytes != entry.copied_name_units * 2
        || entry.name[..count].contains(&0)
        || entry.name[count..].iter().any(|unit| *unit != 0)
    {
        return Err("original loader name is not fully copied".into());
    }
    let name = entry.name[..count].to_vec();
    String::from_utf16(&name).map_err(|_| "original loader name is malformed UTF16")?;
    Ok(name)
}
fn absolute(path: &[u16]) -> bool {
    path.len() > 3
        && matches!(path[0],65..=90|97..=122)
        && path[1] == 58
        && path[2] == 92
        && !path[3..]
            .iter()
            .any(|unit| *unit < 32 || matches!(*unit, 34 | 42 | 47 | 58 | 60 | 62 | 63 | 124))
        && path[3..].split(|unit| *unit == 92).all(|part| {
            !part.is_empty()
                && part != [46]
                && part != [46, 46]
                && !matches!(part.last(), Some(32 | 46))
        })
}
pub fn select(packet: &listener::Packet) -> Result<SelectedPath, String> {
    let validity = listener::diagnostic(packet);
    let timing = &validity["loader_owner"];
    if validity["invalid_packet"] != false
        || timing["invalid_scope"] != false
        || timing["invalid_windows"] != false
        || timing["windows_observation_incomplete"] != false
        || packet.called != 1
        || packet.original_thread == 0
        || packet.loader_owner.first_failure_window_present != 1
        || packet.dropped != 0
        || packet.dependencies.dropped != 0
        || packet.loader_owner.dependencies.dropped != 0
    {
        return Err("original loader packet/link/window unavailable or incomplete".into());
    }
    let scope = &packet.loader_owner;
    let mut windows = Vec::new();
    for window in std::iter::once(&scope.first_failure_window)
        .chain(scope.windows[..(scope.window_count as usize).min(16)].iter())
    {
        if let Some(previous) = windows.iter().find(|previous: &&listener::LoaderWindow| {
            previous.dependency_sequence == window.dependency_sequence
        }) {
            if *previous != *window {
                return Err("conflicting original loader windows".into());
            }
        } else {
            windows.push(*window);
        }
    }
    let mut selected = None;
    for window in windows {
        let loaded = entry(&scope.dependencies, window.dependency_sequence)?;
        if loaded.operation != 4
            || loaded.entered != 1
            || loaded.returned != 1
            || loaded.thread_id != packet.original_thread
        {
            return Err("original LdrLoadDll entry differs".into());
        }
        if loaded.native_status >= 0 {
            continue;
        }
        let mut parents = packet.entries[..(packet.record_count as usize).min(16)]
            .iter()
            .filter(|entry| entry.sequence == window.parent_listener_sequence)
            .collect::<Vec<_>>();
        if packet.first_failure_present == 1
            && packet.first_failure.sequence == window.parent_listener_sequence
        {
            parents.push(&packet.first_failure);
        }
        let socket = *parents
            .first()
            .ok_or("original listener parent unavailable")?;
        if socket.operation != 2
            || socket.entered != 1
            || socket.returned != 1
            || socket.thread_id != packet.original_thread
            || parents.iter().any(|other| *other != socket)
        {
            return Err("original listener parent is ambiguous or differs".into());
        }
        let links = scope.links[..(scope.link_count as usize).min(16)]
            .iter()
            .chain(
                (scope.dependencies.first_failure_present == 1)
                    .then_some(&scope.first_failure_link),
            );
        let linked = links
            .filter(|link| link.dependency_sequence == window.dependency_sequence)
            .collect::<Vec<_>>();
        let link = *linked
            .first()
            .ok_or("original LdrLoadDll link unavailable")?;
        if linked.iter().any(|other| *other != link)
            || link.loader_dependency_sequence != window.loader_dependency_sequence
            || link.parent_listener_sequence != window.parent_listener_sequence
        {
            return Err("original LdrLoadDll parent link differs".into());
        }
        let parent = entry(&packet.dependencies, window.loader_dependency_sequence)?;
        if parent.operation != 12
            || parent.entered != 1
            || parent.returned != 1
            || parent.thread_id != packet.original_thread
            || parent.native_status != 1
            || parent.raw_output != 0
            || parent.output_flags != 1
            || parent.raw_root != 0
            || parent.scalar_flags & 4 == 0
        {
            return Err("original LoadLibraryExW failure is unavailable".into());
        }
        let path = name(parent)?;
        if !absolute(&path) || name(loaded)? != path {
            return Err("original loader path is unsupported or uncorroborated".into());
        }
        let candidate = SelectedPath {
            path,
            loader_dependency_sequence: window.loader_dependency_sequence,
            dependency_sequence: window.dependency_sequence,
            parent_listener_sequence: window.parent_listener_sequence,
            thread_id: packet.original_thread,
        };
        if selected
            .as_ref()
            .is_some_and(|previous| previous != &candidate)
        {
            return Err("multiple original failed loader selections".into());
        }
        selected = Some(candidate);
    }
    selected.ok_or_else(|| "no fully bound original failed loader path".into())
}

fn fits(value: &Value, bound: usize) -> bool {
    serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= bound)
}
fn small(value: Option<&Value>, bound: usize) -> Value {
    value
        .filter(|value| fits(value, bound))
        .cloned()
        .unwrap_or_else(|| json!({"unavailable_or_omitted_for_bound":true}))
}
pub fn bounded(mut value: Value) -> Value {
    if !value.is_object() {
        value = json!({"state":"unavailable","stage":"invalid-diagnostic-record"});
    }
    value["diagnostic_only"] = json!(true);
    value["acceptance_authority"] = json!(false);
    value["denied_object_proved"] = json!(false);
    value["original_desired_access"] = Value::Null;
    value["original_desired_access_unavailable"] = json!(true);
    value["continuous_token_equality_proved"] = json!(false);
    value["original_file_identity_proved"] = json!(false);
    value["checks_are_hypotheses"] = json!(true);
    if fits(&value, RECORD_BYTES) {
        return value;
    }
    let mut summary = json!({"format":"memcordon.post-original-loader-security","revision":1,"diagnostic_only":true,"acceptance_authority":false,"denied_object_proved":false,"original_desired_access":null,"original_desired_access_unavailable":true,"continuous_token_equality_proved":false,"original_file_identity_proved":false,"checks_are_hypotheses":true,"record_omitted_for_bound":true});
    for key in [
        "state",
        "stage",
        "reason",
        "observation_timing",
        "file_observation_timing",
        "hypothetical_checks_unavailable",
        "access_check_scope",
        "unmodeled_inputs",
    ] {
        summary[key] = small(value.get(key), 256);
    }
    for (key, bound) in [
        ("unavailable", 512),
        ("token", 1024),
        ("effective_token_endpoint", 1024),
        ("later_file_identity", 256),
        ("security_descriptor", 512),
        ("generic_mapping", 256),
        ("hypothetical_checks", 2048),
        ("later_file_open_request", 256),
        ("later_ancestor_open_request", 256),
        ("token_source_requested_access", 64),
        ("access_check_duplicate_requested_access", 64),
    ] {
        summary[key] = small(value.get(key), bound);
    }
    let mut selection = json!({"path_utf16_omitted_for_bound":true});
    for key in [
        "path_sha256",
        "thread_id",
        "dependency_sequence",
        "loader_dependency_sequence",
        "parent_listener_sequence",
    ] {
        selection[key] = small(
            value
                .get("selection")
                .and_then(|selection| selection.get(key)),
            160,
        );
    }
    summary["selection"] = selection;
    if !fits(&summary, RECORD_BYTES) {
        summary["hypothetical_checks"] = json!({"omitted_for_bound":true});
    }
    if fits(&summary, RECORD_BYTES) {
        return summary;
    }
    // This final fixed reservation is below 8KiB even when every retained node
    // reaches its individual limit. Never hand an oversized fallback to I/O.
    let mut compact = json!({"format":"memcordon.post-original-loader-security","revision":1,"diagnostic_only":true,"acceptance_authority":false,"denied_object_proved":false,"original_desired_access":null,"original_desired_access_unavailable":true,"continuous_token_equality_proved":false,"original_file_identity_proved":false,"checks_are_hypotheses":true,"record_omitted_for_bound":true});
    for (key, limit) in [
        ("state", 128),
        ("stage", 128),
        ("unavailable", 512),
        ("effective_token_endpoint", 1024),
        ("token", 1024),
        ("selection", 1024),
        ("access_check_scope", 256),
        ("unmodeled_inputs", 512),
        ("later_file_open_request", 256),
        ("later_ancestor_open_request", 256),
        ("token_source_requested_access", 64),
        ("access_check_duplicate_requested_access", 64),
    ] {
        compact[key] = small(summary.get(key), limit);
    }
    compact
}
