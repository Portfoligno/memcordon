//! Bounded observations of the current thread's existing activation context.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub const BUFFER_BYTES: usize = 8192;
pub const RECORD_BYTES: usize = 8192;
pub const PATH_UNITS: usize = 256;
pub const DETAILS_BYTES: usize = 64;

#[derive(Default)]
pub struct Observation {
    pub attempted: bool,
    pub started_qpc: Option<u64>,
    pub finished_qpc: Option<u64>,
    pub success: Option<bool>,
    pub native_error: Option<u32>,
    pub required_bytes: Option<usize>,
    pub available_bytes: usize,
    pub clock_error: Option<u32>,
    pub cutoff_reached: bool,
    pub cutoff_qpc: u64,
    pub qpc_frequency: u64,
    pub details: Option<Value>,
}

fn path(buffer: &[u8], base: usize, pointer: u64, characters: u32, kind: u32) -> Value {
    let mut value = json!({"path_type":kind,"reported_characters":characters,
        "state":"malformed","utf16_prefix":null,"captured_units":0,
        "prefix_truncated":false,"reported_span_sha256":null,
        "zero_unit_in_reported_span":null,"identity_authority":false});
    if pointer == 0 {
        value["state"] = json!(if characters == 0 {
            "absent"
        } else {
            "null-nonempty"
        });
        return value;
    }
    let Some((start, end)) = usize::try_from(pointer).ok().and_then(|pointer| {
        if pointer % std::mem::size_of::<u16>() != 0 {
            return None;
        }
        let start = pointer.checked_sub(base)?;
        let bytes = usize::try_from(characters)
            .ok()?
            .checked_mul(std::mem::size_of::<u16>())?;
        let end = start.checked_add(bytes)?;
        base.checked_add(buffer.len())?;
        (end <= buffer.len()).then_some((start, end))
    }) else {
        value["state"] = json!("invalid-pointer-or-extent");
        return value;
    };
    let span = &buffer[start..end];
    let mut zero = false;
    let mut prefix = Vec::with_capacity(PATH_UNITS.min(characters as usize));
    for (index, bytes) in span.chunks_exact(std::mem::size_of::<u16>()).enumerate() {
        let unit = u16::from_le_bytes([bytes[0], bytes[1]]);
        zero |= unit == 0;
        if index < PATH_UNITS {
            prefix.push(unit);
        }
    }
    let hash = Sha256::digest(span)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    value["state"] = json!(if characters == 0 {
        "known-empty"
    } else {
        "observed"
    });
    value["captured_units"] = json!(prefix.len());
    value["utf16_prefix"] = json!(prefix);
    value["prefix_truncated"] = json!(characters as usize > PATH_UNITS);
    value["reported_span_sha256"] = json!(hash);
    value["zero_unit_in_reported_span"] = json!(zero);
    value
}

/// Decode the documented 64-bit SDK layout using only the supplied byte slice.
/// Pointer values are offsets into this slice, never dereferenced addresses.
pub fn decode_details(buffer: &[u8], base: usize, returned_bytes: usize) -> Value {
    let unavailable = |state| {
        json!({"state":state,"details_usable":false,
        "returned_bytes":returned_bytes,"allocation_bytes":buffer.len(),
        "raw_flags":null,"format_version":null,"assembly_count":null,"paths":null})
    };
    if buffer.len() > BUFFER_BYTES || returned_bytes > BUFFER_BYTES || returned_bytes > buffer.len()
    {
        return unavailable("oversize-or-invalid-extent");
    }
    if returned_bytes < DETAILS_BYTES {
        return unavailable("short-header");
    }
    let allocation_bytes = buffer.len();
    let buffer = &buffer[..returned_bytes];
    let word = |offset| {
        u32::from_le_bytes(
            buffer[offset..offset + 4]
                .try_into()
                .expect("validated SDK header"),
        )
    };
    let pointer = |offset| {
        u64::from_le_bytes(
            buffer[offset..offset + 8]
                .try_into()
                .expect("validated SDK header"),
        )
    };
    let flags = word(0);
    let format = word(4);
    let paths = [
        path(buffer, base, pointer(40), word(16), word(12)),
        path(buffer, base, pointer(48), word(24), word(20)),
        path(buffer, base, pointer(56), word(32), word(28)),
    ];
    let malformed = paths.iter().any(|path| {
        !matches!(
            path["state"].as_str(),
            Some("observed" | "known-empty" | "absent")
        )
    });
    let state = if flags != 0 {
        "unexpected-header-flags"
    } else if format != 1 {
        "unsupported-format"
    } else if malformed {
        "malformed-path"
    } else {
        "complete"
    };
    json!({"state":state,"details_usable":state=="complete","returned_bytes":returned_bytes,
        "allocation_bytes":allocation_bytes,"raw_flags":flags,"format_version":format,"assembly_count":word(8),
        "paths":{"root_manifest":paths[0],"root_configuration":paths[1],"application_directory":paths[2]},
        "path_length_unit":"reported UTF-16 code units; no terminator scan",
        "path_hash_encoding":"exact reported UTF-16LE span",
        "no_active_context_separately_measured":false,"acceptance_authority":false})
}

pub fn diagnostic(observation: &Observation) -> Value {
    let clock_regressed = observation
        .started_qpc
        .zip(observation.finished_qpc)
        .map(|(start, finish)| finish < start);
    let cutoff_reached = (observation.qpc_frequency != 0
        && observation.clock_error.is_none()
        && clock_regressed != Some(true)
        && observation.started_qpc.is_some_and(|start| start != 0))
    .then_some(observation.cutoff_reached);
    let extent = observation.available_bytes <= BUFFER_BYTES
        && observation.required_bytes.is_some_and(|required| {
            required >= DETAILS_BYTES && required <= observation.available_bytes
        });
    let timed = observation
        .started_qpc
        .zip(observation.finished_qpc)
        .is_some_and(|(start, finish)| {
            start != 0 && finish >= start && finish < observation.cutoff_qpc
        })
        && observation.qpc_frequency != 0
        && observation.clock_error.is_none()
        && !observation.cutoff_reached;
    let state = if cutoff_reached == Some(true) {
        "original-cutoff-reached"
    } else if observation.qpc_frequency == 0
        || observation.clock_error.is_some()
        || clock_regressed == Some(true)
        || (observation.attempted && !timed)
    {
        "clock-or-time-unavailable"
    } else if !observation.attempted {
        "not-attempted"
    } else if observation
        .required_bytes
        .is_some_and(|bytes| bytes > BUFFER_BYTES)
    {
        "oversize"
    } else if observation.success == Some(false) {
        if matches!(observation.native_error, Some(50 | 120 | 127)) {
            "unsupported"
        } else {
            "query-error"
        }
    } else if observation.success != Some(true) {
        "incomplete"
    } else if extent
        && observation
            .details
            .as_ref()
            .is_some_and(|details| details["details_usable"] == true)
    {
        "observed"
    } else {
        "malformed-or-unsupported-details"
    };
    json!({"api":"QueryActCtxW","query_flags":"QUERY_ACTCTX_FLAG_USE_ACTIVE_ACTCTX",
        "information_class":"ActivationContextDetailedInformation","state":state,
        "attempted":observation.attempted,"query_succeeded":observation.success,"native_error":observation.native_error,
        "required_bytes":observation.required_bytes,"available_bytes":observation.available_bytes,
        "started_qpc":observation.started_qpc,"finished_qpc":observation.finished_qpc,
        "cutoff_qpc":observation.cutoff_qpc,"qpc_frequency":observation.qpc_frequency,
        "clock_error":observation.clock_error,"clock_regressed":clock_regressed,"original_cutoff_reached":cutoff_reached,
        "available_before_original_cutoff":state=="observed","details":observation.details,
        "no_active_context_separately_measured":false,"active_context_presence":"unmeasured",
        "scope":"active context on this thread at query time; process default and loader use unproved",
        "acceptance_authority":false,"loader_context_causation_proved":false})
}

pub fn bind(mut snapshot: Value, pid: u32, birth: u64) -> Value {
    snapshot["matches_authenticated_original_identity"] = json!(
        snapshot["actual_self"]["available_before_original_cutoff"] == true
            && snapshot["actual_self"]["pid"] == pid
            && snapshot["actual_self"]["creation_time_100ns"] == birth
    );
    snapshot
}

struct Capped(Vec<u8>);
impl Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > RECORD_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("provider loader context exceeds 8 KiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn bounded(value: Value) -> io::Result<Vec<u8>> {
    let mut bytes = Capped(Vec::new());
    serde_json::to_writer(&mut bytes, &value).map_err(io::Error::other)?;
    Ok(bytes.0)
}
