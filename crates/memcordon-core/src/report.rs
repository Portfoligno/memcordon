use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{Error, ErrorCategory};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemcordonReport {
    pub schema_version: u32,
    pub tool: ToolReport,
    pub command: CommandReport,
    pub policy: PolicyReport,
    pub backend: BackendReport,
    pub result: ResultReport,
    pub cleanup: crate::CleanupSummary,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolReport {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandReport {
    pub program: String,
    pub args: Vec<String>,
    pub pid: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyReport {
    pub requested_enforcement: String,
    pub effective_enforcement: String,
    pub memory_limit_bytes: u64,
    pub swap_limit_bytes: Option<u64>,
    pub swap_policy: String,
    pub lifetime: String,
    pub poll_interval_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendReport {
    pub name: String,
    pub class: String,
    pub metric: String,
    pub hard_limit: bool,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultReport {
    pub outcome: String,
    pub wrapper_exit_code: i32,
    pub child: Option<crate::ChildTermination>,
    pub limit_evidence: Option<crate::LimitEvidence>,
    pub peak_bytes: Option<u64>,
    pub duration_ms: u64,
}

pub fn write_report_atomic(path: &Path, report: &MemcordonReport) -> Result<(), Error> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("memcordon-report.json");
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let result = (|| -> Result<(), std::io::Error> {
        let mut file = File::create(&temporary)?;
        serde_json::to_writer_pretty(&mut file, report)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(Error::new(
            ErrorCategory::Report,
            "MCREPORT-WRITE",
            format!("could not write report {}: {error}", path.display()),
        )
        .with_os_error(&error));
    }
    Ok(())
}
