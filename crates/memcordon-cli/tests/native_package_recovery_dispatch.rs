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
fn recovery_dispatch_reaches_native_authorization_before_any_mutation() {
    let native = unprivileged_agent()
        .args(["package", "policy", "recover", "--json"])
        .output()
        .expect("launch the actual native agent under unprivileged credentials");
    assert!(!native.status.success());
    let refusal = String::from_utf8(native.stderr).unwrap();
    assert!(
        refusal.contains("native recovery requires authenticated root administration"),
        "{refusal}"
    );

    let obsolete = unprivileged_agent()
        .args(["package", "recover", "--json"])
        .output()
        .expect("launch the actual native agent with the obsolete operand sequence");
    assert!(!obsolete.status.success());
    let refusal = String::from_utf8(obsolete.stderr).unwrap();
    assert!(!refusal.contains("native recovery requires authenticated root administration"));
}
