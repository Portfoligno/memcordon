//! Explicit feature32 scalar protocol only. These records do not establish
//! host approval, custody, observation endpoints or preservation by themselves.
use super::KernelEventRecordV2;
use crate::{CiError, Result};

pub(crate) fn validate_host_records(events: &[KernelEventRecordV2]) -> Result<()> {
    let fail = || CiError::Message("host sysctl kernel source identities differ".into());
    let mut pins = [None; 4];
    for event in events.iter().filter(|event| event.kind == 15) {
        let slot = usize::try_from(event.other_tid)
            .map_err(|_| fail())?
            .checked_sub(1)
            .ok_or_else(fail)?;
        if slot >= pins.len() || pins[slot].is_some() {
            return Err(fail());
        }
        pins[slot] = Some(event);
    }
    let pins = pins
        .map(|pin| pin.ok_or_else(fail))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    for (slot, pin) in pins.iter().enumerate() {
        if pins[..slot].iter().any(|previous| {
            previous.args[0] == pin.args[0]
                || previous.args[1] == pin.args[1]
                || (previous.image_dev, previous.image_inode) == (pin.image_dev, pin.image_inode)
        }) || pin.args[4] != pin.args[3]
            || pin.args[3] != pins[0].args[3]
            || pin.task.tgid != pins[0].task.tgid
        {
            return Err(fail());
        }
    }
    for event in events.iter().filter(|event| matches!(event.kind, 15 | 16)) {
        let slot = usize::try_from(event.other_tid)
            .map_err(|_| fail())?
            .checked_sub(1)
            .ok_or_else(fail)?;
        if slot >= pins.len()
            || event.syscall_nr != 0
            || event.syscall_arch != 0
            || event.seccomp_action != 0
            || event.syscall_occurrence != 0
            || event.syscall_result <= 0
            || event.image_dev == 0
            || event.image_inode == 0
            || event.args.contains(&0)
            || event.args[5] > event.monotonic_ns
            || event.args[2] > event.monotonic_ns
            || event.args[1] != pins[slot].args[1]
            || event.args[2] != pins[slot].args[2]
            || event.args[3] != pins[slot].args[3]
        {
            return Err(fail());
        }
        if event.kind == 15
            && (event.args[0] != pins[slot].args[0]
                || (event.image_dev, event.image_inode)
                    != (pins[slot].image_dev, pins[slot].image_inode))
        {
            return Err(fail());
        }
    }
    Ok(())
}
