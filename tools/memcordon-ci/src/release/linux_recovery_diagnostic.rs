//! Bound receipt diagnostics. No result from this module authorizes recovery.
#[path = "../../../../crates/memcordon-cli/src/bin/original_native_recovery_contract.rs"]
pub mod contract;

pub fn receipt(bytes: &[u8], input_bytes: &[u8]) -> Result<serde_json::Value, String> {
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
        return Err("recovery diagnostic receipt missing or exceeds bound".into());
    }
    let input = contract::Input::decode(input_bytes)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
    let result: contract::RecoveryResult =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if result.format != "memcordon.original-native-recovery-result"
        || result.revision != 1
        || result.input_sha256 != super::artifacts::checksum(input_bytes)
        || result.context != input.context.kind()
        || result.identity != input.identity
        || result.native_target != input.native_target
        || result.scope_id != input.scope_id
        || result.recovery_harness_owner_sha256 != input.recovery_harness_owner_sha256
        || result.original_records
            != input
                .context
                .records()
                .iter()
                .map(|(role, record)| ((*role).to_owned(), record.sha256.clone()))
                .collect::<Vec<_>>()
        || result.within_original_cleanup
            != (result.completed_unix_millis < input.cleanup_deadline_unix_millis)
    {
        return Err("recovery diagnostic receipt differs from original input bindings".into());
    }
    let outstanding: Vec<String> = result
        .outstanding
        .iter()
        .take(8)
        .map(|item| item.chars().take(256).collect())
        .collect();
    Ok(
        serde_json::json!({"diagnostic_only":true,"bound_to_original_input":true,
        "receipt_sha256":super::artifacts::checksum(bytes),
        "outstanding_count":result.outstanding.len(),"outstanding_first":outstanding,
        "completed_unix_millis":result.completed_unix_millis,
        "cleanup_deadline_unix_millis":input.cleanup_deadline_unix_millis,
        "within_original_cleanup":result.within_original_cleanup,
        "post_persistence_cutoff_state":"not established by receipt; native status remains authoritative"}),
    )
}

pub fn failure(bytes: &[u8], input_bytes: &[u8]) -> Result<serde_json::Value, String> {
    if bytes.is_empty() || bytes.len() > contract::FAILURE_BOUND {
        return Err("recovery failure diagnostic missing or exceeds bound".into());
    }
    let input = contract::Input::decode(input_bytes)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
    let result: contract::RecoveryFailure =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let lease = &result.lease;
    let lease_not_started = lease.started_monotonic_nanos.is_none()
        && lease.finished_monotonic_nanos.is_none()
        && lease.contention_count == 0
        && !lease.lock_acquired
        && !lease.validated_acquisition
        && lease.held_device.is_none()
        && lease.held_inode.is_none()
        && lease.native_error.is_none()
        && lease.operation == "not-started";
    let stage_consistent = match result.stage.as_str() {
        "cleanup-cutoff-conversion" => {
            result.monotonic_cutoff_nanos.is_none() && !result.recovery_entered && lease_not_started
        }
        "root-authentication" => {
            result
                .monotonic_cutoff_nanos
                .is_some_and(|cutoff| cutoff != 0)
                && !result.recovery_entered
                && lease_not_started
        }
        "package-lease-acquisition" => {
            result
                .monotonic_cutoff_nanos
                .is_some_and(|cutoff| cutoff != 0)
                && !result.recovery_entered
                && !lease.validated_acquisition
        }
        "persisted-recovery" => {
            result
                .monotonic_cutoff_nanos
                .is_some_and(|cutoff| cutoff != 0)
                && result.recovery_entered
                && lease.validated_acquisition
        }
        _ => false,
    };
    if result.format != "memcordon.original-native-recovery-failure"
        || result.revision != 1
        || result.input_sha256 != super::artifacts::checksum(input_bytes)
        || result.context != input.context.kind()
        || result.identity != input.identity
        || result.native_target != input.native_target
        || result.scope_id != input.scope_id
        || result.recovery_harness_owner_sha256 != input.recovery_harness_owner_sha256
        || result.original_records
            != input
                .context
                .records()
                .iter()
                .map(|(role, record)| ((*role).to_owned(), record.sha256.clone()))
                .collect::<Vec<_>>()
        || result.original_cleanup_deadline_unix_millis != input.cleanup_deadline_unix_millis
        || result.observed_unix_millis == 0
        || result.error.is_empty()
        || result.error.len() > 4096
        || lease.operation.is_empty()
        || lease.operation.len() > 128
        || !stage_consistent
        || (lease.validated_acquisition && !lease.lock_acquired)
        || (lease.lock_acquired
            && (lease.held_device.is_none()
                || lease.held_inode.is_none()
                || lease.started_monotonic_nanos.is_none()))
        || matches!((lease.started_monotonic_nanos, lease.finished_monotonic_nanos), (Some(start), Some(end)) if end < start)
    {
        return Err(
            "recovery failure diagnostic differs from original bindings or stage facts".into(),
        );
    }
    Ok(
        serde_json::json!({"diagnostic_only":true,"bound_to_original_input":true,
        "operation_failed":true,"recovery_entered":result.recovery_entered,"stage":result.stage,
        "error":result.error,"lease":lease,"observed_unix_millis":result.observed_unix_millis,
        "original_cleanup_deadline_unix_millis":result.original_cleanup_deadline_unix_millis,
        "monotonic_cutoff_nanos":result.monotonic_cutoff_nanos,
        "failure_sha256":super::artifacts::checksum(bytes),
        "within_original_cleanup":result.observed_unix_millis < input.cleanup_deadline_unix_millis}),
    )
}
