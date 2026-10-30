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
    for (arguments, expected_refusal) in [
        (
            vec!["package", "policy", "recover", "--json"],
            "invalid arguments",
        ),
        (
            vec!["package", "recover", "--json"],
            "unknown package operation",
        ),
    ] {
        let obsolete = unprivileged_agent()
            .args(arguments)
            .output()
            .expect("launch the actual native agent with a retired recovery route");
        assert_eq!(obsolete.status.code(), Some(125));
        assert!(obsolete.stdout.is_empty());
        let refusal = String::from_utf8(obsolete.stderr).unwrap();
        assert_eq!(refusal.lines().next(), Some(expected_refusal), "{refusal}");
        assert!(!refusal.contains("native recovery requires authenticated root administration"));
    }
}
