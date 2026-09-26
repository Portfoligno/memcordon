//! Explicit feature64 kernel source shape, not origin or completion authority.
use super::KernelEventRecordV2;
use crate::{CiError, Result};
const NAME_SLOT_BYTES: usize = size_of::<[u64; 6]>() / 2;
fn fail() -> CiError {
    CiError::Message("reuse checked native source records differ".into())
}
fn same(left: &KernelEventRecordV2, right: &KernelEventRecordV2) -> bool {
    left.task == right.task
        && left.syscall_occurrence == right.syscall_occurrence
        && left.syscall_arch == right.syscall_arch
        && left.syscall_nr == right.syscall_nr
}
fn role(arch: u32, nr: i64) -> Option<u32> {
    match (arch, nr) {
        (0xc000003e, 257) | (0xc00000b7, 56) => Some(1),
        (0xc000003e, 263) | (0xc00000b7, 35) => Some(2),
        (0xc000003e, 316) | (0xc00000b7, 276) => Some(3),
        _ => None,
    }
}
fn name(slot: &[u8], expected: &[u8]) -> Result<()> {
    let Some(end) = slot.iter().position(|byte| *byte == 0) else {
        return Err(fail());
    };
    if &slot[..end] != expected || slot[end..].iter().any(|byte| *byte != 0) {
        return Err(fail());
    }
    Ok(())
}
pub(crate) fn validate_reuse_records(events: &[KernelEventRecordV2]) -> Result<()> {
    let entries = events
        .iter()
        .filter(|event| event.kind == 17)
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return Err(fail());
    }
    for entry in &entries {
        let Some(kind) = role(entry.syscall_arch, entry.syscall_nr) else {
            return Err(fail());
        };
        if entry.other_tid != kind
            || entry.image_dev == 0
            || entry.image_inode == 0
            || entry.args[1] == 0
            || entry.seccomp_action != 0
            || entry.syscall_result != 0
        {
            return Err(fail());
        }
        let returned = events
            .iter()
            .filter(|event| event.kind == 5 && same(entry, event))
            .collect::<Vec<_>>();
        let [returned] = returned.as_slice() else {
            return Err(fail());
        };
        let paths = events
            .iter()
            .filter(|event| event.kind == 18 && same(entry, event))
            .collect::<Vec<_>>();
        let [paths] = paths.as_slice() else {
            return Err(fail());
        };
        let bytes = paths
            .args
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        name(&bytes[..NAME_SLOT_BYTES], b"attempt.json.new")?;
        let second = if kind == 3 {
            b"attempt.json".as_slice()
        } else {
            b"".as_slice()
        };
        name(&bytes[NAME_SLOT_BYTES..NAME_SLOT_BYTES * 2], second)?;
        let encoded_lengths = ((b"attempt.json.new".len() + 1) as i64)
            | (((if kind == 3 { second.len() + 1 } else { 0 }) as i64) << 32);
        if bytes[NAME_SLOT_BYTES * 2..].iter().any(|byte| *byte != 0)
            || paths.other_tid != kind
            || paths.seccomp_action != 0
            || (paths.image_dev, paths.image_inode) != (entry.image_dev, entry.image_inode)
            || paths.sequence <= entry.sequence
            || paths.sequence >= returned.sequence
            || paths.syscall_result != encoded_lengths
        {
            return Err(fail());
        }
        let objects = events
            .iter()
            .filter(|event| event.kind == 19 && same(entry, event))
            .collect::<Vec<_>>();
        if objects.len() > 1 || (kind != 1 && returned.syscall_result == 0 && objects.len() != 1) {
            return Err(fail());
        }
        for objects in objects {
            if kind == 1
                || objects.other_tid != kind
                || objects.seccomp_action != 0
                || objects.syscall_result != 0
                || objects.sequence <= paths.sequence
                || objects.sequence >= returned.sequence
                || (objects.image_dev, objects.image_inode) != (entry.image_dev, entry.image_inode)
                || objects.args[0] == 0
                || objects.args[1] == 0
                || (kind == 2 && objects.args[2..].iter().any(|word| *word != 0))
                || (kind == 3
                    && (objects.args[2] == 0
                        || objects.args[3] == 0
                        || (objects.args[4], objects.args[5])
                            != (entry.image_dev, entry.image_inode)))
            {
                return Err(fail());
            }
        }
    }
    for metadata in events.iter().filter(|event| matches!(event.kind, 18 | 19)) {
        if !entries.iter().any(|entry| same(entry, metadata)) {
            return Err(fail());
        }
    }
    Ok(())
}
