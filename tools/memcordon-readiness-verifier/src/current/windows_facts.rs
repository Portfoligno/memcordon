//! Current Windows factual process and aggregate settlement joins.
use crate::{HeldProcessIdentity, VerificationResult};
use std::collections::BTreeSet;

pub(super) fn verify_retirement(
    retired: &crate::RetirementObservation,
    native: &crate::NativeObservation,
    owned_overlap: bool,
) -> VerificationResult<()> {
    crate::header(
        &retired.format,
        retired.revision,
        "memcordon.consumer-readiness.retirement",
    )?;
    if !native.target.ends_with("windows-msvc")
        || retired.run_id != native.run_id
        || retired.attempt_id != native.attempt_id
        || retired.root_pid != native.root_pid
        || retired.root_birth != native.root_birth
        || !retired.target_reaped_or_absent
        || !retired.aggregate_empty
        || !retired.relays_retired
        || !retired.guardian_retired
        || !retired.native_handles_closed
        || retired.independently_observed == owned_overlap
        || !retired.outstanding.is_empty()
        || !retired.failed_operations.is_empty()
        || retired.namespace_init_reaped.is_some()
        || retired.private_root_closed.is_some()
        || retired.exports_finalized.is_some()
        || retired.final_job_handles_closed != Some(true)
        || retired.active_processes_zero != Some(true)
        || native.root_pid.is_none_or(|pid| pid == 0)
        || native.root_birth.is_none_or(|birth| birth == 0)
        || native.attempt_id.as_deref().is_none_or(str::is_empty)
    {
        return Err("current Windows native aggregate retirement or binding incomplete".into());
    }
    Ok(())
}

pub fn validate_windows_capacity_exclusions(
    raw: &serde_json::Value,
    live: &serde_json::Value,
    expected_live: &serde_json::Value,
    expected: &[(u32, u64); 2],
    own: &[HeldProcessIdentity],
) -> VerificationResult<()> {
    if live != expected_live
        || expected[0] == expected[1]
        || expected.iter().any(|(pid, birth)| *pid == 0 || *birth == 0)
    {
        return Err(
            "capacity exclusion live association or expected first native owners differ".into(),
        );
    }
    let excluded = raw.as_array().ok_or("capacity held exclusions absent")?;
    if excluded.len() != 2 {
        return Err("capacity excludes exactly first root and held TCP peer".into());
    }
    let mut identities = BTreeSet::new();
    for process in excluded {
        if process.as_object().is_none_or(|object| {
            object.len() != 4
                || object.keys().any(|key| {
                    ![
                        "pid",
                        "birth",
                        "held_live_before_overlap",
                        "still_live_at_own_retirement",
                    ]
                    .contains(&key.as_str())
                })
        }) || process["held_live_before_overlap"] != true
            || process["still_live_at_own_retirement"] != true
        {
            return Err(
                "capacity raw exclusions lack actual before-and-after live ownership".into(),
            );
        }
        let pid = u32::try_from(
            process["pid"]
                .as_u64()
                .ok_or("capacity excluded PID absent")?,
        )
        .map_err(|_| "capacity excluded PID out of range")?;
        let birth = process["birth"]
            .as_u64()
            .ok_or("capacity excluded birth absent")?;
        if !identities.insert((pid, birth))
            || own
                .iter()
                .any(|held| held.pid == pid && held.birth == birth)
        {
            return Err("capacity exclusion duplicates or hides its own retired family".into());
        }
    }
    if identities != expected.iter().copied().collect() {
        return Err(
            "capacity excluded identities differ from actual first held root and TCP peer".into(),
        );
    }
    Ok(())
}
