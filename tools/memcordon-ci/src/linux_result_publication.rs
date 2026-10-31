//! Publication facts checked against the original held frontend and its sole wait.
use memcordon_core::{execution_facts::NativeProcessV2, result_v3::DeliveryStateV3};

pub fn writer(
    delivery: DeliveryStateV3,
    caller: &NativeProcessV2,
    original: (u32, u64),
) -> Result<(), String> {
    if original.0 == 0 || (caller.pid, caller.birth) != original {
        return Err("result native caller differs from original held frontend".into());
    }
    match delivery {
        DeliveryStateV3::PreparedBy { writer_pid } if writer_pid.get() == original.0 => Ok(()),
        _ => Err(format!(
            "persisted result delivery differs: expected prepared-by original writer {}; observed {delivery:?}",
            original.0
        )),
    }
}

pub fn wrapper_status(observed: Option<i32>, reported: i32) -> Result<(), String> {
    match observed {
        Some(status) if status == reported => Ok(()),
        _ => Err(format!(
            "original frontend wrapper status differs: observed={observed:?}; reported={reported}"
        )),
    }
}

pub fn stderr_detail(bytes: &[u8]) -> String {
    let limit = 2048;
    let (head, tail, omitted) = if bytes.len() <= limit {
        (bytes, &[][..], 0)
    } else {
        let section = limit / 2;
        (
            &bytes[..section],
            &bytes[bytes.len() - section..],
            bytes.len() - limit,
        )
    };
    format!(
        "bytes={}; omitted={omitted}; head={:?}; tail={:?}",
        bytes.len(),
        String::from_utf8_lossy(head),
        String::from_utf8_lossy(tail)
    )
}
