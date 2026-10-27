//! A selected diagnostic line is evidence only, never command or acceptance input.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub const CAPTURE_PREFIX_BYTES: usize = 8 * 1024;
const CAPTURE_FIELDS: usize = 6;
const METADATA_BYTES: usize = 32 * 1024;
pub const RECORD_BOUND: usize = CAPTURE_FIELDS * CAPTURE_PREFIX_BYTES * 2 + METADATA_BYTES;
pub const MARKER: &[u8] = b"export-original-producer-failure ";

#[derive(Debug, Default, Serialize)]
pub struct Counts {
    pub capture_available: bool,
    pub matching_records: usize,
    pub incomplete_records: usize,
    pub oversized_records: usize,
    pub invalid_records: usize,
    pub omitted_valid_records: usize,
}

pub struct Forwarding<'a> {
    pub counts: Counts,
    pub record: Option<&'a [u8]>,
}

pub fn inspect(stderr: Option<&[u8]>) -> Forwarding<'_> {
    let mut forwarding = Forwarding {
        counts: Counts::default(),
        record: None,
    };
    let Some(stderr) = stderr else {
        return forwarding;
    };
    forwarding.counts.capture_available = true;
    for segment in stderr.split_inclusive(|byte| *byte == b'\n') {
        let Some(payload) = segment.strip_prefix(MARKER) else {
            continue;
        };
        forwarding.counts.matching_records += 1;
        if segment.len() > RECORD_BOUND {
            forwarding.counts.oversized_records += 1;
            continue;
        }
        let Some(payload) = payload.strip_suffix(b"\n") else {
            forwarding.counts.incomplete_records += 1;
            continue;
        };
        let valid = memcordon_core::canonical_json::reject_duplicate_json_keys(payload).is_ok()
            && serde_json::from_slice::<serde_json::Value>(payload).is_ok_and(|value| {
                value["diagnostic_only"] == true
                    && ((value["format"] == "memcordon.original-export-producer-failure"
                        && value["revision"] == 1)
                        || (value["state"] == "unavailable" && value.get("format").is_none()))
            });
        if !valid {
            forwarding.counts.invalid_records += 1;
            continue;
        }
        if forwarding.record.is_some() {
            forwarding.counts.omitted_valid_records += 1;
            continue;
        }
        forwarding.record = Some(segment);
    }
    forwarding
}

impl Forwarding<'_> {
    pub fn write_to(&self, output: &mut impl Write) -> io::Result<()> {
        // A completion claim is earned only after the entire original line is written.
        if let Some(record) = self.record {
            output.write_all(record)?;
        }
        let summary = serde_json::json!({"diagnostic_only":true,"counts":self.counts,"multiple_records":self.counts.matching_records>1,
            "forwarded_records":usize::from(self.record.is_some()),"omitted_records":self.counts.matching_records-usize::from(self.record.is_some()),
            "selection":"first complete valid bounded producer record only; never runtime authority",
            "forwarded_bytes":self.record.map(|record|record.len()),"forwarded_sha256":self.record.map(|record|hex::encode(Sha256::digest(record))),
            "state":if self.record.is_some(){"complete-record-forwarded"}else{"unavailable"}});
        output.write_all(b"export-producer-forwarding ")?;
        serde_json::to_writer(&mut *output, &summary).map_err(io::Error::other)?;
        output.write_all(b"\n")?;
        Ok(())
    }
}
