//! Bootstrap failure observation; only authenticated receivers retain it.
use serde::{Deserialize, Serialize};

const DETAIL_MAX_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryStage {
    SelfToken,
    ProcessIdentity,
    TokenEnvelope,
    TokenSnapshot,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryRole {
    LoaderControl,
    Probe,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntryFailureV1 {
    pub schema_version: u32,
    pub nonce: String,
    pub role: EntryRole,
    pub stage: EntryStage,
    pub detail: String,
    pub native_code: Option<i32>,
    pub detail_truncated: bool,
}

fn bounded(value: &str) -> String {
    let mut end = value.len().min(DETAIL_MAX_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

impl EntryFailureV1 {
    pub fn new(nonce: &str, role: EntryRole, stage: EntryStage, detail: &str) -> Self {
        Self {
            schema_version: memcordon_windows_launch_core::PRODUCTION_LOADER_READY_SCHEMA_VERSION,
            nonce: nonce.to_owned(),
            role,
            stage,
            detail: bounded(detail),
            // These sources return String, not a captured native error code.
            native_code: None,
            detail_truncated: detail.len() > DETAIL_MAX_BYTES,
        }
    }

    pub fn validate_for(
        &self,
        expected_nonce: &str,
        expected_role: EntryRole,
    ) -> Result<(), String> {
        if self.schema_version
            != memcordon_windows_launch_core::PRODUCTION_LOADER_READY_SCHEMA_VERSION
            || self.nonce != expected_nonce
            || self.role != expected_role
            || self.nonce.len() != 64
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.detail.len() > DETAIL_MAX_BYTES
            || self.native_code.is_some()
        {
            return Err("bootstrap entry failure binding/schema differs".into());
        }
        Ok(())
    }

    pub fn diagnostic_detail(&self) -> String {
        bounded(&format!(
            "bootstrap entry failure role={:?} stage={:?}; native_code=unavailable; detail_truncated={}; detail={:?}",
            self.role, self.stage, self.detail_truncated, self.detail
        ))
    }
}

pub fn preserve_primary(primary: String, report: Result<(), String>) -> String {
    match report {
        Ok(()) => primary,
        Err(secondary) => format!(
            "{primary}; secondary bootstrap entry report failed: {}",
            bounded(&format!("{secondary:?}"))
        ),
    }
}
