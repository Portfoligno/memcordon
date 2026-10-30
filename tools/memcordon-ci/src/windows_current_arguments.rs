//! Typed arguments for the three installed current-control frontend producers.
use std::{ffi::OsString, path::Path};

pub struct Paths<'a> {
    pub request: &'a Path,
    pub report: &'a Path,
    pub fixture: &'a Path,
}
fn prefix(
    paths: &Paths<'_>,
    observations: Option<&Path>,
    terminal: Option<&Path>,
) -> Vec<OsString> {
    let mut args = vec![
        "--sealed".into(),
        "--workload-request".into(),
        paths.request.into(),
    ];
    if let Some(path) = observations {
        args.extend(["--workload-observation-directory".into(), path.into()]);
    }
    args.extend([
        "--report-format".into(),
        "result-v3".into(),
        "--report".into(),
        paths.report.into(),
    ]);
    if let Some(path) = terminal {
        args.extend(["--windows-terminal-observation".into(), path.into()]);
    }
    args.extend(["--".into(), paths.fixture.into()]);
    args
}
pub fn preallocation(paths: &Paths<'_>, observations: &Path) -> Vec<OsString> {
    let mut args = prefix(paths, Some(observations), None);
    args.extend(["exit", "--code", "0"].map(OsString::from));
    args
}
pub fn held(
    paths: &Paths<'_>,
    observations: &Path,
    terminal: &Path,
    pid_file: Option<&Path>,
) -> Vec<OsString> {
    let mut args = prefix(paths, Some(observations), Some(terminal));
    if let Some(path) = pid_file {
        args.extend([
            "hold".into(),
            "--duration".into(),
            "240s".into(),
            "--pid-file".into(),
            path.into(),
        ]);
    } else {
        args.extend(["exit", "--code", "0"].map(OsString::from));
    }
    args
}
pub fn service_restart(paths: &Paths<'_>, terminal: &Path) -> Vec<OsString> {
    let mut args = prefix(paths, None, Some(terminal));
    args.extend(["exit", "--code", "0"].map(OsString::from));
    args
}
