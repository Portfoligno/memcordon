use std::path::PathBuf;

use memcordon::MemcordonExecutable;
#[cfg(target_os = "linux")]
use memcordon::{ByteSize, CommandSpec, Limiter, Policy};

#[test]
fn memcordon_executable_requires_an_absolute_path() {
    let error = MemcordonExecutable::new(PathBuf::from("bin/memcordon"))
        .expect_err("relative executable path must be rejected");
    assert!(error.to_string().contains("bin/memcordon"));
    assert!(error.to_string().contains("absolute"));
}

#[cfg(unix)]
#[test]
fn memcordon_executable_accepts_an_absolute_native_path() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let path = PathBuf::from(OsString::from_vec(vec![b'/', b'm', b'e', b'm', 0xff]));
    let executable = MemcordonExecutable::new(path.clone())
        .expect("absolute non-Unicode path should be accepted losslessly");
    assert_eq!(executable.as_path(), path);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_limiter_requires_an_explicit_memcordon_executable() {
    let error = Limiter::new(Policy::new(ByteSize::gib(1)))
        .command(CommandSpec::new("target-must-not-launch"))
        .run()
        .expect_err("missing MemCordon executable must fail before platform launch");
    assert_eq!(error.code, "MCUSAGE-MEMCORDON-EXECUTABLE");
}
