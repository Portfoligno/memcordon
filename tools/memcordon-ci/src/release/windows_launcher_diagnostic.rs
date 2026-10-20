//! Historical startup-file telemetry. Never SCM, process or recovery authority.
use crate::{
    CiError, Result, ci_operation_time::ClockReading, consumer_readiness_ledger::SourceIdentity,
};
use memcordon_core::{PublicProviderBindingV1, WindowsLauncherStartupDiagnosticV1};
use serde::{Deserialize, Serialize};
const EPOCH_BYTES: usize = 16 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WindowsOriginalOwner {
    pub format: String,
    pub revision: u32,
    pub identity: SourceIdentity,
    pub job: String,
    pub run_attempt: u64,
    pub config: crate::windows_installed_cases::InstalledWindowsPayload,
    pub removal: crate::windows_readiness_adapter::WindowsRemovalPlan,
    pub original_work_unix_millis: u64,
    pub original_cleanup_unix_millis: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_clock: Option<WindowsDiagnosticClock>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WindowsDiagnosticClock {
    pub domain: String,
    pub millis: u64,
}

pub(super) fn launcher_diagnostic_binding(owner: &WindowsOriginalOwner) -> Result<Binding> {
    let clock = owner.diagnostic_clock.as_ref().ok_or_else(|| {
        CiError::Message("original owner has no pre-mutation diagnostic clock".into())
    })?;
    Ok(Binding {
        owner_sha256: super::artifacts::checksum(&serde_json::to_vec(owner)?),
        identity: owner.identity.clone(),
        job: owner.job.clone(),
        run_attempt: owner.run_attempt,
        provider: owner.config.provider.clone(),
        work_unix_millis: owner.original_work_unix_millis,
        cleanup_unix_millis: owner.original_cleanup_unix_millis,
        clock_domain: clock.domain.clone(),
        minimum_tick: clock.millis,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub owner_sha256: String,
    pub identity: SourceIdentity,
    pub job: String,
    pub run_attempt: u64,
    pub provider: PublicProviderBindingV1,
    pub work_unix_millis: u64,
    pub cleanup_unix_millis: u64,
    pub clock_domain: String,
    pub minimum_tick: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Epoch {
    pub format: String,
    pub revision: u32,
    pub binding: Binding,
    pub clock_domain: String,
    pub minimum_tick: u64,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", content = "observation", rename_all = "kebab-case")]
pub(super) enum Observation {
    Uncorroborated(WindowsLauncherStartupDiagnosticV1),
    Unavailable(String),
}

fn boot(domain: &str) -> Result<&str> {
    let boot = domain
        .strip_prefix("windows-gettickcount64:")
        .ok_or_else(|| CiError::Message("startup diagnostic clock domain differs".into()))?;
    if boot
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .is_none_or(|value| value.to_string() != boot)
    {
        return Err(CiError::Message(
            "startup diagnostic boot identity invalid".into(),
        ));
    }
    Ok(boot)
}

impl Epoch {
    pub(super) fn acquire(binding: Binding, clock: ClockReading) -> Result<Self> {
        boot(&clock.domain)?;
        if clock.domain != binding.clock_domain
            || clock.millis != binding.minimum_tick
            || binding.owner_sha256.len() != 64
            || !binding
                .owner_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || binding.identity.run_id.is_empty()
            || binding.identity.source_commit.is_empty()
            || binding.identity.source_tree_sha256.is_empty()
            || binding.identity.version.is_empty()
            || binding.job.is_empty()
            || binding.run_attempt == 0
            || !binding.provider.is_consistent()
            || binding.work_unix_millis >= binding.cleanup_unix_millis
        {
            return Err(CiError::Message(
                "startup diagnostic owner binding invalid".into(),
            ));
        }
        let epoch = Self {
            format: "memcordon.original-launcher-diagnostic-epoch".into(),
            revision: 1,
            binding,
            clock_domain: clock.domain,
            minimum_tick: clock.millis,
        };
        if serde_json::to_vec(&epoch)?.len() > EPOCH_BYTES {
            return Err(CiError::Message(
                "startup diagnostic epoch exceeds byte bound".into(),
            ));
        }
        Ok(epoch)
    }
}

fn validate_epoch<'a>(epoch: &Epoch, expected: &Binding, now: &'a ClockReading) -> Result<&'a str> {
    if epoch.format != "memcordon.original-launcher-diagnostic-epoch"
        || epoch.revision != 1
        || serde_json::to_vec(&epoch.binding)? != serde_json::to_vec(expected)?
        || epoch.clock_domain != now.domain
        || epoch.clock_domain != expected.clock_domain
        || epoch.minimum_tick != expected.minimum_tick
        || now.millis < epoch.minimum_tick
    {
        return Err(CiError::Message(
            "startup diagnostic epoch cannot be reassociated or renewed".into(),
        ));
    }
    let current_boot = boot(&now.domain)?;
    // Validate the expected binding too; no serialized record supplies it.
    Epoch::acquire(
        expected.clone(),
        ClockReading {
            domain: now.domain.clone(),
            millis: epoch.minimum_tick,
        },
    )?;
    Ok(current_boot)
}

pub(super) fn launcher_service_snapshot(
    epoch: &Epoch,
    expected: &Binding,
    before: &ClockReading,
    after: &ClockReading,
    reported: std::result::Result<
        crate::windows_owned_guardian::LauncherServiceStatus,
        crate::windows_owned_guardian::LauncherServiceQueryError,
    >,
) -> Result<serde_json::Value> {
    validate_epoch(epoch, expected, before)?;
    validate_epoch(epoch, expected, after)?;
    if after.millis < before.millis {
        return Err(CiError::Message(
            "launcher service observation clock regressed".into(),
        ));
    }
    let pid_field_defined = reported
        .as_ref()
        .ok()
        .map(|status| matches!(status.current_state, 4..=7));
    Ok(serde_json::json!({
        "format":"memcordon.original-launcher-scm-observation", "revision":1,
        "diagnostic_only":true, "certification_authority":false,
        "owner_sha256":expected.owner_sha256,
        "service_name":memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME,
        "reported_state_source":"most-recently-reported-to-scm-may-lag",
        "process_join":"unavailable", "listener_join":"unavailable",
        "clock_domain":before.domain, "before_tick":before.millis, "after_tick":after.millis,
        "pid_field_defined_for_reported_state":pid_field_defined,
        "query_result":reported,
    }))
}

pub(super) fn classify(
    epoch: &Epoch,
    expected: &Binding,
    now: &ClockReading,
    bytes: &[u8],
) -> Result<Observation> {
    let current_boot = validate_epoch(epoch, expected, now)?;
    let unavailable = |reason: &str| Ok(Observation::Unavailable(reason.into()));
    if bytes.len() > memcordon_core::WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES {
        return unavailable("record exceeds startup byte bound");
    }
    if memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).is_err() {
        return unavailable("record encoding has duplicate or invalid JSON keys");
    }
    let record: WindowsLauncherStartupDiagnosticV1 = match serde_json::from_slice(bytes) {
        Ok(record) => record,
        Err(_) => return unavailable("record schema unavailable or invalid"),
    };
    if let Err(error) = record.validate_since(epoch.minimum_tick) {
        return unavailable(error);
    }
    if record.provider != expected.provider {
        return unavailable("record provider differs from original owner");
    }
    if record.boot_identity != current_boot {
        return unavailable("record boot differs from observed native boot");
    }
    let Some(age) = now.millis.checked_sub(record.recorded_tick_millis) else {
        return unavailable("record tick is in the future");
    };
    if age > memcordon_core::WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_MAX_AGE_MILLIS {
        return unavailable("record is stale");
    }
    // No SCM exit or held startup-process identity was observed here. Do not
    // call validate_for/from_json_for with fields taken from this same file.
    Ok(Observation::Uncorroborated(record))
}

#[cfg(windows)]
pub(super) fn publish_epoch(
    binding: Binding,
    path: &std::path::Path,
    cutoff: std::time::Instant,
) -> Result<()> {
    if std::time::Instant::now() >= cutoff {
        return Err(CiError::Message(
            "original startup epoch cutoff exhausted".into(),
        ));
    }
    let clock = ClockReading {
        domain: binding.clock_domain.clone(),
        millis: binding.minimum_tick,
    };
    let epoch = Epoch::acquire(binding, clock)?;
    let _held =
        crate::windows_readiness_adapter::publish_receipt(path, &serde_json::to_vec(&epoch)?)?;
    if std::time::Instant::now() >= cutoff {
        return Err(CiError::Message(
            "original startup epoch publication exceeded cutoff".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn retain(
    expected: &Binding,
    epoch_path: &std::path::Path,
    policy_root: &std::path::Path,
    directory: &std::path::Path,
    cutoff: std::time::Instant,
) -> Result<()> {
    use crate::windows_readiness_adapter::{hold_artifact, publish_receipt};
    if std::time::Instant::now() >= cutoff {
        return Err(CiError::Message(
            "original startup retention cutoff exhausted".into(),
        ));
    }
    std::fs::create_dir_all(directory)?;
    let destination = directory.join("launcher-startup-record");
    std::fs::create_dir(&destination)?;
    let observed_clock = crate::ci_operation_time::clock_reading()?;
    let epoch = hold_artifact(epoch_path, None, EPOCH_BYTES as u64).and_then(|held| {
        memcordon_core::canonical_json::reject_duplicate_json_keys(&held.bytes)
            .map_err(CiError::Message)?;
        Ok(serde_json::from_slice::<Epoch>(&held.bytes)?)
    });
    let source = policy_root.join("launcher-startup-failure.json");
    let held = hold_artifact(
        &source,
        None,
        memcordon_core::WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES as u64,
    );
    let mut raw_digest = None;
    let observation = match (&epoch, &held) {
        (Ok(epoch), Ok(held)) => classify(epoch, expected, &observed_clock, &held.bytes)
            .unwrap_or_else(|error| Observation::Unavailable(error.to_string())),
        (Err(error), _) => Observation::Unavailable(format!("epoch unavailable: {error}")),
        (_, Err(error)) => {
            Observation::Unavailable(format!("startup record absent or unreadable: {error}"))
        }
    };
    if let Ok(held) = &held {
        let _copy = publish_receipt(&destination.join("startup-record.bin"), &held.bytes)?;
        raw_digest = Some(held.sha256.clone());
    }
    // This is a genuinely additional read-only launcher status query. It uses
    // the existing owner context, never adds rights or changes guard results.
    let service_observation = (|| -> Result<serde_json::Value> {
        let epoch = epoch
            .as_ref()
            .map_err(|error| CiError::Message(format!("epoch unavailable: {error}")))?;
        validate_epoch(epoch, expected, &observed_clock)?;
        if std::time::Instant::now() >= cutoff {
            return Err(CiError::Message(
                "launcher service observation cutoff exhausted".into(),
            ));
        }
        let before = crate::ci_operation_time::clock_reading()?;
        let reported = crate::windows_owned_guardian::launcher_service_status();
        let after = crate::ci_operation_time::clock_reading()?;
        if std::time::Instant::now() >= cutoff {
            return Err(CiError::Message(
                "launcher service observation exceeded cutoff".into(),
            ));
        }
        launcher_service_snapshot(epoch, expected, &before, &after, reported)
    })()
    .unwrap_or_else(|error| {
        serde_json::json!({
            "diagnostic_only":true,"certification_authority":false,
            "status":"unavailable","error":error.to_string(),
            "process_join":"unavailable","listener_join":"unavailable",
        })
    });
    let receipt = serde_json::json!({
        "format":"memcordon.original-launcher-startup-file-observation", "revision":1,
        "diagnostic_only":true,"certification_authority":false,
        "scm_join":"unavailable","process_join":"unavailable",
        "owner_binding":expected,"source_path":source,"raw_sha256":raw_digest,
        "observed_clock_domain":observed_clock.domain,"observed_tick":observed_clock.millis,
        "observation":observation,
        "launcher_service_observation":service_observation,
    });
    let _receipt = publish_receipt(
        &destination.join("observation.json"),
        &serde_json::to_vec(&receipt)?,
    )?;
    if std::time::Instant::now() >= cutoff {
        return Err(CiError::Message(
            "original startup retention exceeded cutoff".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/private/windows_launcher_diagnostic.rs"]
mod tests;
