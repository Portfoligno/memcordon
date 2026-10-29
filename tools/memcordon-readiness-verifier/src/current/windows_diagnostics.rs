//! Independent encoding of the unchanged diagnostic-v1 commitment. Diagnostic
//! observations do not grant launch, replay, or cleanup authority.
use crate::VerificationResult;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn shape(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    let object = value.as_object().ok_or("diagnostic object absent")?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err("diagnostic missing/unknown fields".into());
    }
    Ok(())
}
fn number(value: &Value) -> VerificationResult<u64> {
    value
        .as_u64()
        .ok_or("diagnostic unsigned integer absent".into())
}
fn flag(value: &Value) -> VerificationResult<u8> {
    value
        .as_bool()
        .map(u8::from)
        .ok_or("diagnostic boolean absent".into())
}
fn tag(value: &Value, vocabulary: &str) -> VerificationResult<u16> {
    let value = value
        .as_str()
        .ok_or("diagnostic vocabulary string absent")?;
    u16::try_from(
        vocabulary
            .split_whitespace()
            .position(|known| known == value)
            .ok_or("unknown diagnostic vocabulary")?,
    )
    .map_err(|error| error.to_string())
}
fn hash_text(hash: &mut Sha256, value: &Value) -> VerificationResult<()> {
    let text = value
        .as_str()
        .filter(|text| !text.is_empty() && !text.contains('\0'))
        .ok_or("diagnostic text identity absent")?;
    if text.len() > 256 {
        return Err("diagnostic identity exceeds bound".into());
    }
    hash.update(
        u64::try_from(text.len())
            .map_err(|error| error.to_string())?
            .to_be_bytes(),
    );
    hash.update(text.as_bytes());
    Ok(())
}
fn hash_digest(hash: &mut Sha256, value: &Value) -> VerificationResult<()> {
    let text = value.as_str().ok_or("diagnostic digest absent")?;
    crate::digest(text)?;
    let bytes: [u8; 32] = hex::decode(text)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "diagnostic digest byte width differs")?;
    hash.update(bytes);
    Ok(())
}

fn event(hash: &mut Sha256, value: &Value) -> VerificationResult<u64> {
    shape(
        value,
        &[
            "sequence",
            "origin",
            "category",
            "operation",
            "code",
            "native_code",
            "observed_phase",
            "safe_detail",
            "detail_redacted",
            "detail_truncated",
            "terminalization_reference",
        ],
    )?;
    let sequence = number(&value["sequence"])?;
    if sequence == 0 {
        return Err("diagnostic event sequence is zero".into());
    }
    hash.update(sequence.to_be_bytes());
    for (field, vocabulary) in [
        (
            "origin",
            "launcher control-relay guardian-recovery startup-recovery record-writer client-transport",
        ),
        (
            "category",
            "admission launch monitor cleanup terminalization transport persistence recovery",
        ),
        (
            "operation",
            "authenticate-caller validate-request configure-job verify-job start-guardian create-target verify-suspended-target authorize-target resume-target query-job-process-ids observe-process-identity accumulate-process-inventory read-job-notification query-peak-memory poll-target read-target-exit check-guardian check-desktop-authority read-control-frame terminate-job wait-job-empty retire-guardian close-final-handles build-rejection validate-terminal-response serialize-terminal-response store-record deliver-response acknowledge-terminal retire-outbox inspect-recovery-record unexpected-unwind unclassified-provider-operation query-job-accounting",
        ),
        (
            "code",
            "process-inventory-observation process-inventory-capacity job-query guardian-loss target-create target-resume target-query control-transport job-configuration-readback terminal-binding record-io record-authentication unexpected-provider-failure",
        ),
    ] {
        let ordinal = tag(&value[field], vocabulary)?;
        let native_tag = if field == "code" && ordinal >= 8 {
            ordinal + 1
        } else {
            ordinal
        };
        hash.update(native_tag.to_be_bytes());
    }
    if value["native_code"].is_null() {
        hash.update([0]);
    } else {
        let codes = value["native_code"]
            .as_object()
            .filter(|object| object.len() == 1)
            .ok_or("diagnostic native code is ambiguous")?;
        let (domain, code) = codes.iter().next().ok_or("diagnostic native code absent")?;
        let index = match domain.as_str() {
            "win32" => 1,
            "nt-status" => 2,
            "h-result" => 3,
            "winsock" => 4,
            "errno" => 5,
            "unclassified" => 6,
            _ => return Err("diagnostic native code domain unknown".into()),
        };
        hash.update([index]);
        let raw = code
            .as_i64()
            .ok_or("diagnostic native code is not integer")?;
        let bytes = if index <= 3 {
            u32::try_from(raw)
                .map_err(|error| error.to_string())?
                .to_be_bytes()
        } else {
            i32::try_from(raw)
                .map_err(|error| error.to_string())?
                .to_be_bytes()
        };
        hash.update(bytes);
    }
    hash.update(tag(&value["observed_phase"],"before-authorization authorized-before-resume resume-attempted monitoring target-exit-observed cleaning terminalizing recovery")?.to_be_bytes());
    let detail = &value["safe_detail"];
    if detail == "no-additional-detail" {
        hash.update([0]);
    } else {
        let object = detail
            .as_object()
            .filter(|object| object.len() == 1)
            .ok_or("diagnostic safe detail ambiguous")?;
        let (kind, body) = object
            .iter()
            .next()
            .ok_or("diagnostic safe detail absent")?;
        match kind.as_str() {
            "count-and-limit" => {
                shape(body, &["observed", "limit"])?;
                hash.update([1]);
                for field in ["observed", "limit"] {
                    hash.update(
                        u32::try_from(number(&body[field])?)
                            .map_err(|error| error.to_string())?
                            .to_be_bytes(),
                    );
                }
            }
            "provider-message" => {
                shape(body, &["id"])?;
                hash.update([2]);
                hash.update(tag(&body["id"],"original-failure-captured receipt-required-for-posttarget peer-disconnected commit-not-confirmed observation-unavailable-after-owner-loss")?.to_be_bytes());
            }
            "injected-windows-fault" => {
                shape(body, &["fault"])?;
                let fault = &body["fault"];
                tag(
                    fault,
                    "public-pipe-create caller-pid-lookup caller-token-impersonation primary-token-duplicate private-pipe-connect launcher-peer-verify token-handle-duplicate job-create job-configure completion-port guardian-create guardian-killed-before-authorization guardian-killed-after-authorization frontend-disconnected-after-authorization frontend-killed-after-authorization control-worker-killed-after-authorization control-service-killed-after-authorization launcher-worker-killed-after-authorization launcher-service-killed-after-authorization all-job-owners-closed-after-authorization stream-create relay-handle-duplicate relay-ready attribute-list job-list handle-list create-process-as-user target-token-readback job-membership-readback before-resume resume terminate-job active-process-query relay-retire guardian-reap final-handle-close record-retire",
                )?;
                hash.update([3]);
                let bytes = serde_json::to_vec(fault).map_err(|error| error.to_string())?;
                hash.update(
                    u32::try_from(bytes.len())
                        .map_err(|error| error.to_string())?
                        .to_be_bytes(),
                );
                hash.update(bytes);
            }
            _ => return Err("diagnostic safe detail domain unknown".into()),
        }
    }
    hash.update([
        flag(&value["detail_redacted"])?,
        flag(&value["detail_truncated"])?,
    ]);
    let reference = &value["terminalization_reference"];
    if reference.is_null() {
        hash.update([0]);
    } else if reference == "first-error" {
        hash.update([1]);
    } else {
        shape(reference, &["secondary-error"])?;
        shape(&reference["secondary-error"], &["index"])?;
        if number(&reference["secondary-error"]["index"])? >= 4 {
            return Err("diagnostic reference exceeds actual terminal secondary bound".into());
        }
        hash.update([
            2,
            u8::try_from(number(&reference["secondary-error"]["index"])?)
                .map_err(|error| error.to_string())?,
        ]);
    }
    Ok(sequence)
}

pub fn validate_projection(value: &Value) -> VerificationResult<()> {
    shape(
        value,
        &[
            "schema_version",
            "provider_binding",
            "attempt_id",
            "request_sha256",
            "diagnostic_sequence",
            "durable_through_sequence",
            "original",
            "secondary",
            "loss",
            "projection_sha256",
        ],
    )?;
    if value["schema_version"] != 1
        || serde_json::to_vec(value)
            .map_err(|error| error.to_string())?
            .len()
            > 16 * 1024
    {
        return Err("diagnostic projection version/byte bound differs".into());
    }
    shape(
        &value["provider_binding"],
        &["generation", "source_commit", "runtime_manifest_sha256"],
    )?;
    let generation = value["provider_binding"]["generation"]
        .as_str()
        .ok_or("diagnostic provider generation absent")?;
    let commit = value["provider_binding"]["source_commit"]
        .as_str()
        .ok_or("diagnostic provider source absent")?;
    if generation.is_empty()
        || !generation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
        || ![
            std::mem::size_of::<[u8; 20]>() * 2,
            std::mem::size_of::<[u8; 32]>() * 2,
        ]
        .contains(&commit.len())
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("diagnostic provider identity is malformed".into());
    }
    let mut hash = Sha256::new();
    hash.update(b"memcordon:causal-diagnostic:v1\0");
    hash.update(1u32.to_be_bytes());
    for field in ["generation", "source_commit"] {
        hash_text(&mut hash, &value["provider_binding"][field])?;
    }
    hash_digest(
        &mut hash,
        &value["provider_binding"]["runtime_manifest_sha256"],
    )?;
    hash_digest(&mut hash, &value["attempt_id"])?;
    hash_digest(&mut hash, &value["request_sha256"])?;
    let sequence = number(&value["diagnostic_sequence"])?;
    hash.update(sequence.to_be_bytes());
    if value["durable_through_sequence"].is_null() {
        hash.update([0]);
    } else {
        let durable = number(&value["durable_through_sequence"])?;
        if durable > sequence {
            return Err("diagnostic durability exceeds actual observation sequence".into());
        }
        hash.update([1]);
        hash.update(durable.to_be_bytes());
    }
    let original = value["original"]
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or("diagnostic original cause ambiguous")?;
    let mut prior = if let Some(observed) = original.get("observed") {
        shape(observed, &["event"])?;
        hash.update([0]);
        event(&mut hash, &observed["event"])?
    } else if let Some(unavailable) = original.get("unavailable") {
        shape(unavailable, &["reason"])?;
        hash.update([1]);
        let ordinal = tag(
            &unavailable["reason"],
            "no-earlier-error-observed worker-lost-before-observation observation-not-durable-before-service-loss record-unavailable record-authentication-failed retention-expired",
        )?;
        hash.update((if ordinal == 5 { 6 } else { ordinal }).to_be_bytes());
        0
    } else {
        return Err("diagnostic original domain unknown".into());
    };
    if prior > sequence || (prior != 0 && prior != 1) {
        return Err("diagnostic original event exceeds final sequence".into());
    }
    let secondary = value["secondary"]
        .as_array()
        .filter(|events| events.len() <= 8)
        .ok_or("diagnostic secondary expansion exceeds bound")?;
    hash.update(
        u64::try_from(secondary.len())
            .map_err(|error| error.to_string())?
            .to_be_bytes(),
    );
    for observed in secondary {
        let current = event(&mut hash, observed)?;
        if current != prior.checked_add(1).ok_or("diagnostic sequence overflow")?
            || current > sequence
        {
            return Err("diagnostic secondary ordering changes original cause".into());
        }
        prior = current;
    }
    shape(
        &value["loss"],
        &[
            "secondary_events_omitted",
            "secondary_count_saturated",
            "persistence_failure_observed",
            "writer_unavailable",
        ],
    )?;
    let omitted = number(&value["loss"]["secondary_events_omitted"])?;
    let saturated = value["loss"]["secondary_count_saturated"]
        .as_bool()
        .ok_or("diagnostic saturation flag absent")?;
    if (omitted > 0 && secondary.len() != 8)
        || if saturated {
            omitted != u64::from(u32::MAX)
                || sequence
                    <= prior
                        .checked_add(omitted)
                        .ok_or("diagnostic sequence overflow")?
        } else {
            sequence
                != prior
                    .checked_add(omitted)
                    .ok_or("diagnostic sequence overflow")?
        }
    {
        return Err("diagnostic omitted observations disagree with native sequence".into());
    }
    hash.update(
        u32::try_from(number(&value["loss"]["secondary_events_omitted"])?)
            .map_err(|error| error.to_string())?
            .to_be_bytes(),
    );
    hash.update([
        flag(&value["loss"]["secondary_count_saturated"])?,
        flag(&value["loss"]["persistence_failure_observed"])?,
        flag(&value["loss"]["writer_unavailable"])?,
    ]);
    if value["projection_sha256"] != hex::encode(hash.finalize()) {
        return Err(
            "diagnostic projection commitment differs from actual retained causal bytes".into(),
        );
    }
    Ok(())
}
