//! Bounded failure evidence only; never a neighboring import observation.
use memcordon_readiness_verifier::Artifact;
use serde_json::{Value, json};

pub const RECORD_BOUND: usize = 128 * 1024;
const FIRST_ERROR_BOUND: usize = 8 * 1024;
const OTHER_ERROR_BOUND: usize = 1024;
const ERROR_COUNT_BOUND: usize = 8;

pub fn validate_artifact(expected: &Artifact, actual: &Artifact) -> Result<(), String> {
    let path = std::path::Path::new(&expected.path);
    if expected.length == 0
        || expected.length > RECORD_BOUND as u64
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        || actual.path != expected.path
        || actual.length != expected.length
        || actual.sha256 != expected.sha256
    {
        return Err(
            "image failure diagnostic path/extent/hash differs from original retained artifact"
                .into(),
        );
    }
    Ok(())
}

#[cfg(unix)]
pub fn validate_registration(
    expected: &Artifact,
    actual: &Artifact,
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
    named: &std::fs::Metadata,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    validate_artifact(expected, actual)?;
    let stamp = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if !before.is_file()
        || before.nlink() != 1
        || stamp(before) != stamp(named)
        || stamp(before) != stamp(after)
    {
        return Err("original image failure diagnostic held/named custody differs".into());
    }
    Ok(())
}

fn text(value: &str, bound: usize) -> (&str, bool) {
    let mut end = value.len().min(bound);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (&value[..end], end != value.len())
}

pub fn primary(
    phase: &str,
    scenario: Option<&str>,
    errors: &[String],
    retention_error: Option<&str>,
) -> Option<String> {
    let original = errors.first()?;
    let (error, truncated) = text(original, FIRST_ERROR_BOUND);
    let suffix = if truncated {
        format!(" [truncated; original_bytes={}]", original.len())
    } else {
        String::new()
    };
    let retention = retention_error.map(|error| {
        let (value, truncated) = text(error, OTHER_ERROR_BOUND);
        json!({"error":value,"truncated":truncated,"original_bytes":error.len()})
    });
    Some(format!(
        "image-first-failure phase={phase} scenario={scenario:?}: {error}{suffix}; diagnostic-retention-error={retention:?}"
    ))
}

pub fn encode(
    binding: Value,
    phase: &str,
    scenario: Option<&str>,
    errors: &[String],
    neighbor_observed: bool,
) -> Result<Vec<u8>, String> {
    if errors.is_empty() {
        return Err("image failure record requires an actual failure".into());
    }
    let failures = errors
        .iter()
        .take(ERROR_COUNT_BOUND)
        .enumerate()
        .map(|(index, error)| {
            let (retained, truncated) = text(
                error,
                if index == 0 {
                    FIRST_ERROR_BOUND
                } else {
                    OTHER_ERROR_BOUND
                },
            );
            json!({"error":retained,"original_bytes":error.len(),"truncated":truncated})
        })
        .collect::<Vec<_>>();
    let record = json!({"format":"memcordon.linux-image-case-failures","revision":1,"diagnostic_only":true,
        "binding":binding,"first_failure_phase":phase,"first_failure_scenario":scenario,
        "neighbor_observation_created":neighbor_observed,"failures":failures,"failure_count":errors.len(),
        "omitted_failure_count":errors.len().saturating_sub(ERROR_COUNT_BOUND)});
    let bytes = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
    if bytes.len() > RECORD_BOUND {
        return Err("image failure record exceeds finite encoded bound".into());
    }
    Ok(bytes)
}
