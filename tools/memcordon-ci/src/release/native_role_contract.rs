//! Closed acquisition recipes; these identify inputs, never successful execution.
use crate::{CiError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct NativeRole<'a> {
    pub role: &'a str,
    pub package: &'a str,
    pub test: &'a str,
    pub features: Option<&'a str>,
}

pub fn original_roles(target: &str) -> Result<[NativeRole<'static>; 2]> {
    let features = match target {
        "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu" => "private-tcp,test-support",
        "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc" => {
            "windows-sealed-runtime,test-support"
        }
        _ => {
            return Err(CiError::Message(
                "unsupported original native role target".into(),
            ));
        }
    };
    Ok([
        NativeRole {
            role: "operational",
            package: "memcordon",
            test: "sealed_agent",
            features: Some(features),
        },
        NativeRole {
            role: "parser",
            package: "memcordon-readiness-verifier",
            test: "current_parser_receipts",
            features: None,
        },
    ])
}

pub fn validate_original_roles<'a>(
    target: &str,
    roles: impl ExactSizeIterator<Item = NativeRole<'a>>,
) -> Result<()> {
    let expected = original_roles(target)?;
    let count = roles.len();
    let observed: Vec<_> = roles.take(expected.len() + 1).collect();
    if count == expected.len()
        && expected
            .iter()
            .all(|spec| observed.iter().filter(|role| *role == spec).count() == 1)
    {
        return Ok(());
    }
    let failing_role = expected
        .iter()
        .find(|spec| observed.iter().filter(|role| *role == *spec).count() != 1)
        .map_or("cardinality", |spec| spec.role);
    // At most three tuples, with bounded fields even for a rejected descriptor.
    let field = |value: &str| {
        if memcordon_core::BoundedText::<128>::new(value).is_ok() {
            value.to_owned()
        } else {
            format!("<overlong field: {} bytes>", value.len())
        }
    };
    let observed: Vec<_> = observed
        .iter()
        .map(|role| {
            serde_json::json!({
                "role":field(role.role), "package":field(role.package), "test":field(role.test),
                "features":role.features.map(field),
            })
        })
        .collect();
    Err(CiError::Message(format!(
        "original native executable roles differ: failing_role={failing_role}; expected={}; observed_count={count}; observed_first={}",
        serde_json::to_string(&expected)?,
        serde_json::to_string(&observed)?,
    )))
}
