//! Semantic parity of independently built Windows package channels.
//!
//! Exact installed images and raw qualification receipts remain authenticated by
//! each channel. Only these comparison projections discard build/run identities.

use memcordon_core::{WindowsLoaderQualificationOutcomeV2, WindowsQualificationReceiptV1};
use memcordon_windows_launch_core::ProductionLoaderPlanV1;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{CiError, Result};

pub fn package_contract(mut package: Value) -> Result<Value> {
    let object = package.as_object_mut().ok_or_else(|| {
        CiError::Message("Windows package inspection is not an object".to_owned())
    })?;
    // Never strip security/configuration or loader-contract hashes here.
    for field in [
        "executable_sha256",
        "target_desktop_bootstrap_sha256",
        "session_broker_sha256",
    ] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|digest| {
                digest.len() == Sha256::output_size() * 2
                    && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(CiError::Message(format!(
                "Windows package inspection has an invalid {field}"
            )));
        }
        object.remove(field);
    }
    Ok(package)
}

pub fn qualification_contract_sha256(
    qualification: &WindowsQualificationReceiptV1,
    plan: &ProductionLoaderPlanV1,
) -> Result<String> {
    if !qualification.qualified || !qualification.is_consistent() {
        return Err(CiError::Message(
            "channel fingerprint requires a consistent successful qualification".to_owned(),
        ));
    }
    let mut normalized = qualification.clone();
    let WindowsLoaderQualificationOutcomeV2::Ready(ready) = &mut normalized.loader_qualification
    else {
        return Err(CiError::Message(
            "channel fingerprint requires a successful loader qualification".to_owned(),
        ));
    };
    let inline = ready.launch_plan_json.as_deref().ok_or_else(|| {
        CiError::Message("channel qualification is missing its inline loader plan".to_owned())
    })?;
    let inline_plan: ProductionLoaderPlanV1 = serde_json::from_str(inline)?;
    if inline_plan != *plan || inline_plan.launch_plan_sha256() != ready.launch_plan_sha256 {
        return Err(CiError::Message(
            "channel qualification and loader plan bindings differ".to_owned(),
        ));
    }
    // This clone is a hash projection, never an emitted qualification receipt.
    ready.launch_plan_json = None;
    ready.launch_plan_sha256 = "0".repeat(Sha256::output_size() * 2);
    ready.elapsed_millis = 0;
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        normalized,
        plan.template_sha256(),
    ))?)))
}
