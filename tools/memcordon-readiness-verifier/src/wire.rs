use crate::*;
use base64::Engine;
use serde::Deserializer;
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded duplicate-free JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Strict, E> {
                Err(E::custom("floating-point evidence is unsupported"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Strict, E> {
                if v.len() > 1024 * 1024 {
                    return Err(E::custom("JSON string exceeds bound"));
                }
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Strict, E> {
                self.visit_str(&v)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Strict, E> {
                self.visit_unit()
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(v)) = access.next_element()? {
                    if values.len() >= 131_072 {
                        return Err(serde::de::Error::custom("JSON collection exceeds bound"));
                    }
                    values.push(v);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if key.len() > 256 || values.len() >= 256 {
                        return Err(serde::de::Error::custom("JSON object exceeds bound"));
                    }
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let Strict(value) = access.next_value()?;
                    values.insert(key, value);
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        decoder.deserialize_any(StrictVisitor)
    }
}

pub(crate) fn json(bytes: &[u8]) -> VerificationResult<Value> {
    if bytes.is_empty() || bytes.len() > MAX_INDEX_BYTES {
        return Err("JSON byte bound exceeded".into());
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Strict::deserialize(&mut decoder).map_err(|e| e.to_string())?;
    decoder.end().map_err(|e| e.to_string())?;
    Ok(value.0)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> VerificationResult<T> {
    serde_json::from_value(json(bytes)?).map_err(|e| e.to_string())
}

pub(crate) fn validate_arguments(args: &NativeArguments, target: &str) -> VerificationResult<()> {
    let lengths: Vec<usize> = match args {
        NativeArguments::UnixBytes(values) if target.ends_with("linux-gnu") => {
            if values.iter().any(|v| v.contains(&0)) {
                return Err("native argv contains NUL".into());
            }
            values.iter().map(Vec::len).collect()
        }
        NativeArguments::WindowsUtf16(values) if target.ends_with("windows-msvc") => {
            if values.iter().any(|v| v.contains(&0)) {
                return Err("native argv contains NUL".into());
            }
            values.iter().map(Vec::len).collect()
        }
        _ => return Err("native argv encoding differs from target".into()),
    };
    if lengths.len() > 4096
        || lengths.iter().any(|length| *length > 131_072)
        || lengths.iter().sum::<usize>() > 1024 * 1024
    {
        return Err("native argv exceeds bounds".into());
    }
    Ok(())
}

#[derive(Serialize)]
struct PublicInvocation<'a> {
    syntax: &'static str,
    budget_tokens: &'a [BudgetToken],
    memory_token: &'a Option<String>,
    deadline_token: &'a Option<String>,
    argv: Vec<PublicArgument>,
}
#[derive(Serialize)]
struct PublicArgument {
    display: String,
    raw: Option<RawArgument>,
}
#[derive(Serialize)]
struct RawArgument {
    encoding: &'static str,
    data: String,
}

pub(crate) fn invocation_digest(invocation: &NativeInvocation) -> VerificationResult<String> {
    invocation_digest_parts(
        &invocation.arguments,
        &invocation.budget_tokens,
        &invocation.memory_token,
        &invocation.deadline_token,
    )
}

pub(crate) fn invocation_digest_parts(
    arguments: &NativeArguments,
    budget_tokens: &[BudgetToken],
    memory_token: &Option<String>,
    deadline_token: &Option<String>,
) -> VerificationResult<String> {
    if budget_tokens.len() > 2 {
        return Err("invocation budget count exceeds bound".into());
    }
    let mut kinds = BTreeSet::new();
    for token in budget_tokens {
        if !["memory", "time"].contains(&token.kind.as_str())
            || !kinds.insert(token.kind.as_str())
            || token.token.len() > 256
            || token.token.is_empty()
        {
            return Err("unknown/duplicate/invalid native budget token".into());
        }
        let selected = if token.kind == "memory" {
            memory_token
        } else {
            deadline_token
        };
        if selected.as_deref() != Some(token.token.as_str()) {
            return Err("budget token projection differs".into());
        }
    }
    if memory_token.is_some() != kinds.contains("memory")
        || deadline_token.is_some() != kinds.contains("time")
    {
        return Err("budget token omitted from ordered invocation".into());
    }
    let argv = match arguments {
        NativeArguments::UnixBytes(values) => values
            .iter()
            .map(|bytes| match std::str::from_utf8(bytes) {
                Ok(text) => PublicArgument {
                    display: text.to_owned(),
                    raw: None,
                },
                Err(_) => PublicArgument {
                    display: String::from_utf8_lossy(bytes).into_owned(),
                    raw: Some(RawArgument {
                        encoding: "unix-bytes-base64",
                        data: base64::engine::general_purpose::STANDARD.encode(bytes),
                    }),
                },
            })
            .collect(),
        NativeArguments::WindowsUtf16(values) => values
            .iter()
            .map(|units| match String::from_utf16(units) {
                Ok(text) => PublicArgument {
                    display: text,
                    raw: None,
                },
                Err(_) => PublicArgument {
                    display: String::from_utf16_lossy(units),
                    raw: Some(RawArgument {
                        encoding: "windows-u16le-base64",
                        data: base64::engine::general_purpose::STANDARD.encode(
                            units
                                .iter()
                                .flat_map(|unit| unit.to_le_bytes())
                                .collect::<Vec<_>>(),
                        ),
                    }),
                },
            })
            .collect(),
    };
    let public = PublicInvocation {
        syntax: "plus-budgets-v1",
        budget_tokens,
        memory_token,
        deadline_token,
        argv,
    };
    Ok(sha256(
        &serde_json::to_vec(&public).map_err(|e| e.to_string())?,
    ))
}

fn object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> VerificationResult<&'a Map<String, Value>> {
    let map = value.as_object().ok_or("expected JSON object")?;
    if required.iter().any(|field| !map.contains_key(*field))
        || map
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err("missing/unknown authority-bearing wire field".into());
    }
    Ok(map)
}
fn text<'a>(value: &'a Value, field: &str) -> VerificationResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {field}"))
}
fn number(value: &Value, field: &str) -> VerificationResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing unsigned field {field}"))
}

pub(crate) fn validate_original_failure(original: &Value) -> VerificationResult<()> {
    let variants = original
        .as_object()
        .ok_or("original failure is not a closed variant")?;
    if variants.len() != 1 {
        return Err("ambiguous original failure variant".into());
    }
    if let Some(unavailable) = variants.get("unavailable") {
        object(unavailable, &["reason"], &[])?;
        if ![
            "no-earlier-error-observed",
            "worker-lost-before-observation",
            "observation-not-durable-before-service-loss",
            "record-unavailable",
            "record-authentication-failed",
            "retention-expired",
        ]
        .contains(&text(unavailable, "reason")?)
        {
            return Err("unknown original failure unavailability reason".into());
        }
        return Ok(());
    }
    let observed = variants
        .get("observed")
        .ok_or("unknown original failure variant")?;
    object(observed, &["event"], &[])?;
    let event = observed.get("event").ok_or("original event missing")?;
    object(
        event,
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
        &[],
    )?;
    if number(event, "sequence")? == 0 {
        return Err("original causal event sequence absent".into());
    }
    for (field, variants) in [
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
            "authenticate-caller validate-request configure-job verify-job start-guardian create-target verify-suspended-target authorize-target resume-target query-job-process-ids observe-process-identity accumulate-process-inventory read-job-notification read-control-frame query-peak-memory poll-target read-target-exit check-guardian check-desktop-authority terminate-job wait-job-empty retire-guardian close-final-handles build-rejection validate-terminal-response serialize-terminal-response store-record deliver-response acknowledge-terminal retire-outbox inspect-recovery-record unexpected-unwind unclassified-provider-operation query-job-accounting",
        ),
        (
            "code",
            "process-inventory-observation process-inventory-capacity job-query guardian-loss target-create target-resume target-query control-transport job-configuration-readback terminal-binding record-io record-authentication unexpected-provider-failure",
        ),
        (
            "observed_phase",
            "before-authorization authorized-before-resume resume-attempted monitoring target-exit-observed cleaning terminalizing recovery",
        ),
    ] {
        if !variants
            .split_whitespace()
            .any(|variant| Some(variant) == event.get(field).and_then(Value::as_str))
        {
            return Err("unknown original failure authority vocabulary".into());
        }
    }
    if let Some(code) = event.get("native_code").filter(|value| !value.is_null()) {
        let code = code
            .as_object()
            .ok_or("native original code is not typed")?;
        if code.len() != 1
            || code.iter().any(|(kind, value)| {
                ![
                    "win32",
                    "nt-status",
                    "h-result",
                    "winsock",
                    "errno",
                    "unclassified",
                ]
                .contains(&kind.as_str())
                    || value.as_i64().is_none()
            })
        {
            return Err("unknown native original code domain/value".into());
        }
        for (kind, value) in code {
            let number = value.as_i64().ok_or("native code not integer")?;
            if if ["win32", "nt-status", "h-result"].contains(&kind.as_str()) {
                !(0..=i64::from(u32::MAX)).contains(&number)
            } else {
                !(i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&number)
            } {
                return Err("native original code exceeds its frozen native width".into());
            }
        }
    }
    let detail = event
        .get("safe_detail")
        .ok_or("safe diagnostic detail missing")?;
    if detail != "no-additional-detail" {
        let variants = detail
            .as_object()
            .ok_or("unknown safe diagnostic detail variant")?;
        if variants.len() != 1 {
            return Err("ambiguous safe diagnostic detail".into());
        }
        if let Some(counts) = variants.get("count-and-limit") {
            object(counts, &["observed", "limit"], &[])?;
            if number(counts, "observed")? > u64::from(u32::MAX)
                || number(counts, "limit")? > u64::from(u32::MAX)
            {
                return Err("diagnostic count out of bounds".into());
            }
        } else if let Some(message) = variants.get("provider-message") {
            object(message, &["id"], &[])?;
            if ![
                "original-failure-captured",
                "receipt-required-for-posttarget",
                "peer-disconnected",
                "commit-not-confirmed",
                "observation-unavailable-after-owner-loss",
            ]
            .contains(&text(message, "id")?)
            {
                return Err("unknown safe diagnostic message".into());
            }
        } else {
            return Err("unknown safe diagnostic detail authority variant".into());
        }
    }
    if !event.get("detail_redacted").is_some_and(Value::is_boolean)
        || !event.get("detail_truncated").is_some_and(Value::is_boolean)
    {
        return Err("diagnostic flags are not boolean".into());
    }
    if let Some(reference) = event
        .get("terminalization_reference")
        .filter(|value| !value.is_null())
        && reference != "first-error"
    {
        object(reference, &["secondary-error"], &[])?;
        let secondary = reference
            .get("secondary-error")
            .ok_or("unknown terminalization reference")?;
        object(secondary, &["index"], &[])?;
        if number(secondary, "index")? > u64::from(u8::MAX) {
            return Err("terminalization reference index out of bounds".into());
        }
    }
    Ok(())
}
