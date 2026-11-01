//! Validate only the bounded original-call handoff, never native identity.
use serde_json::Value;

pub struct Relative {
    pub sequence: u32,
    pub flags: u32,
    pub name: Vec<u16>,
}
pub struct Parent {
    pub sequence: u32,
    pub raw_handle: u64,
    pub flags: u32,
    pub children: Vec<Relative>,
}

pub fn plan(trace: &Value) -> Result<Vec<Parent>, &'static str> {
    if trace["observed_entries_complete"] != true
        || trace["called"] != 1
        || trace["source_before_setup_validated"] != true
        || trace["source_after_setup_validated"] != true
        || trace["source_after_call_validated"] != true
    {
        return Err("original call entries unavailable or incomplete");
    }
    let entries = trace["entries"].as_array().ok_or("entries absent")?;
    let retained = &trace["retained_directories"];
    let handles = retained["handles"]
        .as_array()
        .ok_or("retained handles absent")?;
    let errors = retained["errors"]
        .as_array()
        .ok_or("retained errors absent")?;
    if entries.len() > 8
        || handles.len() != 8
        || errors.len() != 8
        || retained["raw_handles_are_authority"] != false
    {
        return Err("retained reference bounds or authority declaration differ");
    }
    if errors
        .iter()
        .any(|error| error.as_u64().is_none_or(|v| u32::try_from(v).is_err()))
    {
        return Err("retained reference error type differs");
    }
    let mut result = Vec::new();
    let thread = trace["original_current_thread_id"]
        .as_u64()
        .filter(|v| *v != 0 && u32::try_from(*v).is_ok())
        .ok_or("original caller thread absent")?;
    for (index, entry) in entries.iter().enumerate() {
        if entry["sequence"].as_u64() != Some(index as u64 + 1)
            || entry["entered"] != 1
            || entry["returned"] != 1
            || entry["invalid_record"] != false
            || entry["coverage_inconclusive"] != false
            || entry["thread_id"].as_u64() != Some(thread)
        {
            return Err("original entry sequence or completeness differs");
        }
    }
    for (index, entry) in entries.iter().enumerate() {
        let handle = handles[index]
            .as_u64()
            .ok_or("retained handle type differs")?;
        if handle == 0 {
            continue;
        }
        if errors[index] != 0
            || entry["operation_code"] != 1
            || entry["native_status"].as_i64().is_none_or(|v| v < 0)
            || entry["output_handle_readable"] != 1
            || entry["output_handle_returned"] != 1
        {
            return Err("retained handle lacks successful original directory output");
        }
        if entry["attributes_length"] != 48 || entry["attributes_flags"] != 64 {
            return Err("original parent attributes differ");
        }
        let output = entry["opaque_raw_output"]
            .as_u64()
            .filter(|v| *v != 0)
            .ok_or("original directory output absent")?;
        let mut children = Vec::new();
        for failed in entries.iter().skip(index + 1) {
            // Stop at reuse of the numeric output; retained references are not
            // reconstructed from a later reused handle-table number.
            if failed["native_status"].as_i64().is_some_and(|v| v >= 0)
                && failed["opaque_raw_output"].as_u64() == Some(output)
            {
                break;
            }
            if failed["operation_code"] != 1
                || failed["opaque_raw_root"].as_u64() != Some(output)
                || failed["native_status"].as_i64().is_none_or(|v| v >= 0)
                || failed["desired_access"] != 15
            {
                continue;
            }
            if failed["root_is_null"] != 0
                || failed["attributes_length"] != 48
                || failed["attributes_flags"] != 64
                || failed["arguments_readable"] != 1
                || failed["name_readable"] != 1
                || failed["name_malformed"] != 0
                || failed["name_truncated"] != 0
            {
                return Err("relative directory arguments differ");
            }
            let name: Option<Vec<u16>> = failed["name_utf16"].as_array().and_then(|v| {
                v.iter()
                    .map(|v| v.as_u64().and_then(|v| u16::try_from(v).ok()))
                    .collect()
            });
            let name = name
                .filter(|v| {
                    !v.is_empty()
                        && v.len() <= 256
                        && !v.contains(&0)
                        && !v.contains(&(b'\\' as u16))
                })
                .ok_or("relative directory name differs")?;
            if failed["reported_name_bytes"].as_u64() != Some(name.len() as u64 * 2)
                || failed["copied_name_units"].as_u64() != Some(name.len() as u64)
            {
                return Err("relative directory name extent differs");
            }
            children.push(Relative {
                sequence: failed["sequence"]
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("relative sequence differs")?,
                flags: 64,
                name,
            });
        }
        result.push(Parent {
            sequence: index as u32 + 1,
            raw_handle: handle,
            flags: 64,
            children,
        });
    }
    Ok(result)
}
