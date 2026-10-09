#![cfg(all(target_os = "linux", feature = "sealed-runtime"))]

use std::process::Command;

fn unprivileged_agent() -> Command {
    let executable = env!("CARGO_BIN_EXE_memcordon-sealed-agent");
    // SAFETY: geteuid takes no pointers and cannot invalidate Rust references.
    if unsafe { libc::geteuid() } == 0 {
        let mut command = Command::new("/usr/bin/setpriv");
        command.args(["--reuid=65534", "--regid=65534", "--clear-groups", "--"]);
        command.arg(executable);
        command
    } else {
        Command::new(executable)
    }
}

#[test]
fn retired_recovery_routes_are_rejected_before_native_authorization() {
    for arguments in [
        vec!["package", "policy", "recover", "--json"],
        vec!["package", "recover", "--json"],
    ] {
        let obsolete = unprivileged_agent()
            .args(arguments)
            .output()
            .expect("launch the actual native agent with a retired recovery route");
        assert!(!obsolete.status.success());
        let refusal = String::from_utf8(obsolete.stderr).unwrap();
        assert!(
            refusal.contains("retired release command is unavailable"),
            "{refusal}"
        );
        assert!(!refusal.contains("native recovery requires authenticated root administration"));
    }
}
