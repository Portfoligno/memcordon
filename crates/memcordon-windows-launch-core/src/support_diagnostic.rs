//! An explicitly separate experiment, never a production qualification plan.
use crate::ProductionLoaderPlanV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Wire")]
pub struct SupportDetachedConsolePlanV1 {
    input_plan: ProductionLoaderPlanV1,
    baseline_failure_plan_sha256: String,
    challenge: String,
    actual_creation_flags: u32,
    diagnostic_plan_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    input_plan: ProductionLoaderPlanV1,
    baseline_failure_plan_sha256: String,
    challenge: String,
    actual_creation_flags: u32,
    diagnostic_plan_sha256: String,
}

impl SupportDetachedConsolePlanV1 {
    pub const CREATION_FLAGS: u32 = ProductionLoaderPlanV1::CREATION_FLAGS | 0x8;

    pub fn new(
        input_plan: ProductionLoaderPlanV1,
        baseline_failure_plan_sha256: String,
        challenge: String,
    ) -> Result<Self, String> {
        for value in [&baseline_failure_plan_sha256, &challenge] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || value.bytes().all(|byte| byte == b'0')
            {
                return Err("support console comparison binding is invalid".into());
            }
        }
        let actual_creation_flags = Self::CREATION_FLAGS;
        let diagnostic_plan_sha256 = hex::encode(Sha256::digest(
            serde_json::to_vec(&(
                "memcordon.support-detached-console.v1",
                &input_plan,
                &baseline_failure_plan_sha256,
                &challenge,
                actual_creation_flags,
            ))
            .map_err(|error| error.to_string())?,
        ));
        Ok(Self {
            input_plan,
            baseline_failure_plan_sha256,
            challenge,
            actual_creation_flags,
            diagnostic_plan_sha256,
        })
    }

    pub fn input_plan(&self) -> &ProductionLoaderPlanV1 {
        &self.input_plan
    }
    pub fn actual_creation_flags(&self) -> u32 {
        self.actual_creation_flags
    }
    pub fn diagnostic_plan_sha256(&self) -> &str {
        &self.diagnostic_plan_sha256
    }
    pub fn validate_baseline(
        &self,
        baseline: &ProductionLoaderPlanV1,
        challenge: &str,
    ) -> Result<(), String> {
        if self.baseline_failure_plan_sha256 != baseline.launch_plan_sha256()
            || self.challenge != challenge
        {
            return Err("support comparison crosses original baseline or challenge".into());
        }
        let mut expected = serde_json::to_value(baseline).map_err(|error| error.to_string())?;
        let mut actual =
            serde_json::to_value(&self.input_plan).map_err(|error| error.to_string())?;
        for value in [&mut expected, &mut actual] {
            let object = value.as_object_mut().ok_or("support plan object absent")?;
            object.remove("command_line_sha256");
            object.remove("launch_plan_sha256");
        }
        if expected != actual {
            return Err("support comparison immutable launch inputs differ".into());
        }
        Ok(())
    }
}

impl TryFrom<Wire> for SupportDetachedConsolePlanV1 {
    type Error = String;
    fn try_from(wire: Wire) -> Result<Self, Self::Error> {
        let expected = Self::new(
            wire.input_plan,
            wire.baseline_failure_plan_sha256,
            wire.challenge,
        )?;
        if wire.actual_creation_flags != expected.actual_creation_flags
            || wire.diagnostic_plan_sha256 != expected.diagnostic_plan_sha256
        {
            return Err("support console diagnostic plan binding differs".into());
        }
        Ok(expected)
    }
}
