//! Actual native host selection for the retained macOS execution phases.
use crate::{CiError, Result};
use std::path::Path;

pub fn require_native_host(root: &Path, stable: &str) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Err(CiError::Message(
            "macOS phase requires a native macOS host".into(),
        ));
    }
    let target = crate::release::distribution::native_target()?;
    let output = crate::command::CommandSpec::toolchain_program(
        "rustup",
        root,
        stable,
        "rustc",
        std::time::Duration::from_secs(60),
    )
    .arg("-vV")
    .output_quiet()?;
    if !output.status.success()
        || !std::str::from_utf8(&output.stdout)
            .ok()
            .is_some_and(|text| {
                text.lines()
                    .any(|line| line.strip_prefix("host: ") == Some(target))
            })
    {
        return Err(CiError::Message(
            "macOS selected compiler host differs from actual native target".into(),
        ));
    }
    Ok(())
}
