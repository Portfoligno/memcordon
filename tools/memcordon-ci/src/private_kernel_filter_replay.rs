//! Explicit feature16 kernel-retained original cBPF and filter identity.
use super::KernelEventRecordV2;
use crate::{CiError, Result};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct InstalledKernelFilterV1 {
    pub(crate) task: super::KernelTaskIdentityV2,
    pub(crate) occurrence: u64,
    pub(crate) install_sequence: u64,
    pub(crate) installed_sequence: u64,
    pub(crate) filter_identity: u64,
    pub(crate) previous_filter_identity: u64,
    pub(crate) count_before: u32,
    pub(crate) count_after: u32,
    pub(crate) instructions: Vec<u8>,
    pub(crate) instructions_sha256: DiagnosticSha256,
}
pub(crate) fn is_filter_install(arch: u32, nr: i64, args: &[u64; 6]) -> bool {
    matches!((arch, nr), (0xc000003e, 317) | (0xc00000b7, 277))
        && args[0] == 1
        && args[1] & !1 == 0
        && args[2] != 0
        || matches!((arch, nr), (0xc000003e, 157) | (0xc00000b7, 167))
            && args[0] == 22
            && args[1] == 2
            && args[2] != 0
}
fn fail<T>(message: &str) -> Result<T> {
    Err(CiError::Message(message.into()))
}
pub(crate) fn installed_kernel_filters(
    events: &[KernelEventRecordV2],
) -> Result<Vec<InstalledKernelFilterV1>> {
    let entries = events
        .iter()
        .filter(|e| matches!(e.kind, 4 | 11))
        .map(|e| (e.syscall_occurrence, e))
        .collect::<BTreeMap<_, _>>();
    let returns = events
        .iter()
        .filter(|e| e.kind == 5)
        .map(|e| (e.syscall_occurrence, e))
        .collect::<BTreeMap<_, _>>();
    let mut descriptors = BTreeMap::new();
    let mut rows: BTreeMap<u64, Vec<&KernelEventRecordV2>> = BTreeMap::new();
    let mut installed = BTreeMap::new();
    let mut decisions = BTreeSet::new();
    for event in events {
        if event.kind == 14 {
            let entry = entries
                .get(&event.syscall_occurrence)
                .ok_or_else(|| CiError::Message("filter descriptor install entry absent".into()))?;
            if !is_filter_install(event.syscall_arch, event.syscall_nr, &event.args)
                || event.task != entry.task
                || event.args != entry.args
                || event.syscall_arch != entry.syscall_arch
                || event.syscall_nr != entry.syscall_nr
                || event.sequence <= entry.sequence
                || event.syscall_result != 0
                || event.seccomp_action != 0
                || !(1..=4096).contains(&event.image_dev)
                || event.image_inode == 0
                || descriptors
                    .insert(event.syscall_occurrence, event)
                    .is_some()
            {
                return fail("checked filter descriptor differs or duplicated");
            }
        } else if event.kind == 12 {
            if event.seccomp_action != 0
                || event.image_dev == 0
                || !(1..=4096).contains(&event.other_tid)
                || event.syscall_result < 0
            {
                return fail("installed kernel instruction header differs");
            }
            rows.entry(event.syscall_occurrence)
                .or_default()
                .push(event);
        } else if event.kind == 13 {
            if event.image_dev == 0
                || event.syscall_result != 2
                || !(1..=4).contains(&event.seccomp_action)
            {
                return fail("kernel filter identity header differs");
            }
            match event.seccomp_action {
                1 | 2 => {
                    let entry = entries.get(&event.syscall_occurrence).ok_or_else(|| {
                        CiError::Message("kernel filter identity syscall absent".into())
                    })?;
                    if event.seccomp_action == 2 && event.other_tid != 0
                        || event.task != entry.task
                        || event.args != entry.args
                        || event.syscall_arch != entry.syscall_arch
                        || event.syscall_nr != entry.syscall_nr
                        || event.seccomp_action == 2
                            && (entry.kind != 4
                                || event.sequence >= entry.sequence
                                || !decisions.insert(event.syscall_occurrence)
                                || events
                                    .iter()
                                    .find(|e| e.task == event.task && e.sequence > event.sequence)
                                    .map(|e| e.sequence)
                                    != Some(entry.sequence))
                        || event.seccomp_action == 1
                            && installed.insert(event.syscall_occurrence, event).is_some()
                    {
                        return fail("kernel filter identity syscall role differs");
                    }
                }
                3 | 4 => {
                    if event.syscall_occurrence != 0
                        || event.syscall_arch != 0
                        || event.syscall_nr != 0
                        || event.args != [0; 6]
                        || event.seccomp_action == 3
                            && (event.other_tid != 0
                                || !events
                                    .iter()
                                    .rev()
                                    .find(|e| e.task == event.task && e.sequence < event.sequence)
                                    .is_some_and(|e| e.kind == 6))
                        || event.seccomp_action == 4
                            && (event.other_tid == 0
                                || !events
                                    .iter()
                                    .rev()
                                    .find(|e| e.task == event.task && e.sequence < event.sequence)
                                    .is_some_and(|e| e.kind == 7 && e.other_tid == event.other_tid))
                    {
                        return fail("kernel filter identity exec/fork role differs");
                    }
                }
                _ => unreachable!("closed filter identity role"),
            }
        }
    }
    let mut result = Vec::new();
    for (occurrence, descriptor) in &descriptors {
        let entry = entries[occurrence];
        let returned = returns
            .get(occurrence)
            .ok_or_else(|| CiError::Message("filter install return absent".into()))?;
        if returned.sequence <= descriptor.sequence
            || returned.task != entry.task
            || returned.args != entry.args
        {
            return fail("filter descriptor/return order differs");
        }
        if returned.syscall_result != 0 {
            if rows.contains_key(occurrence) || installed.contains_key(occurrence) {
                return fail("failed filter install claims kernel installed program");
            }
            continue;
        }
        let program = rows.remove(occurrence).ok_or_else(|| {
            CiError::Message("successful filter has no kernel instruction snapshot".into())
        })?;
        let identity = installed.remove(occurrence).ok_or_else(|| {
            CiError::Message("successful filter has no installed identity".into())
        })?;
        if program.len() != descriptor.image_dev as usize
            || identity.sequence <= returned.sequence
            || identity.task != entry.task
            || !is_filter_install(identity.syscall_arch, identity.syscall_nr, &identity.args)
            || descriptor.other_tid.checked_add(1) != Some(identity.other_tid)
        {
            return fail("installed kernel program length/identity differs");
        }
        let mut instructions = Vec::with_capacity(program.len() * 8);
        let mut previous = returned.sequence;
        for (index, row) in program.iter().enumerate() {
            if row.task != entry.task
                || row.args != entry.args
                || row.syscall_arch != entry.syscall_arch
                || row.syscall_nr != entry.syscall_nr
                || row.other_tid as u64 != descriptor.image_dev
                || row.image_dev != identity.image_dev
                || row.syscall_result != index as i64
                || row.sequence <= previous
                || row.sequence >= identity.sequence
            {
                return fail("partial/substituted kernel instruction snapshot");
            }
            instructions.extend_from_slice(&row.image_inode.to_le_bytes());
            previous = row.sequence;
        }
        let instructions_sha256 = hash_bytes(&instructions);
        result.push(InstalledKernelFilterV1 {
            task: entry.task,
            occurrence: *occurrence,
            install_sequence: entry.sequence,
            installed_sequence: identity.sequence,
            filter_identity: identity.image_dev,
            previous_filter_identity: identity.image_inode,
            count_before: descriptor.other_tid,
            count_after: identity.other_tid,
            instructions,
            instructions_sha256,
        });
    }
    if !rows.is_empty() || !installed.is_empty() {
        return fail("orphan installed kernel filter snapshot");
    }
    Ok(result)
}
