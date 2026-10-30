//! Current standard execution-probe evidence, independent of sealed capability.
use crate::{CiError, Result};

pub fn validate(probe: &serde_json::Value) -> Result<()> {
    if probe["format"] != "memcordon.capabilities-probe"
        || probe["revision"] != 2
        || probe["execution"]["helper_ready"] != true
        || probe["execution"]["target_exec_confirmed"] != true
        || probe["execution"]["target_exit"] != 0
        || probe["execution"]["cleanup_complete"] != true
    {
        return Err(CiError::Message(
            "installed macOS execution probe envelope or native lifecycle evidence differs".into(),
        ));
    }
    Ok(())
}
