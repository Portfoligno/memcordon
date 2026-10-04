use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

pub(crate) fn package_phases(package: &str, target: &Path) -> [(Vec<OsString>, Duration); 2] {
    let arguments = vec![
        OsString::from("test"),
        OsString::from("--target-dir"),
        target.as_os_str().to_owned(),
        OsString::from("--package"),
        OsString::from(package),
        OsString::from("--all-targets"),
        OsString::from("--all-features"),
        OsString::from("--locked"),
        OsString::from("--release"),
    ];
    let mut compilation = arguments.clone();
    compilation.push(OsString::from("--no-run"));
    [
        (compilation, Duration::from_secs(35 * 60)),
        (arguments, Duration::from_secs(900)),
    ]
}
