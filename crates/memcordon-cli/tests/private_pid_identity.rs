#[path = "../src/bin/memcordon-sealed-agent/linux/private_pid_identity.rs"]
mod private_pid_identity;

use private_pid_identity::parse_target_pidfd_identity;

#[test]
fn exec_association_uses_pinned_kernel_namespace_mapping() {
    let identity = parse_target_pidfd_identity(
        "pos:\t0\nflags:\t02000002\nPid:\t30054\nNSpid:\t30054\t812\t2\n",
    )
    .unwrap();
    assert_eq!(identity.host_pid(), 30054);
    identity.require_exec_pid(30054, 2).unwrap();
    // Host and init-local numbers are not interchangeable. Both halves of
    // the originally pinned mapping remain part of the association check.
    for (host, local) in [(30054, 30054), (30054, 812), (30055, 2), (0, 2), (30054, 0)] {
        assert!(identity.require_exec_pid(host, local).is_err());
    }
    let unnested = parse_target_pidfd_identity("Pid:\t42\nNSpid:\t42\n").unwrap();
    unnested.require_exec_pid(42, 42).unwrap();
}

#[test]
fn pidfd_mapping_rejects_ambiguous_invisible_and_malformed_identity() {
    for text in [
        "",
        "NSpid:\t42\t2\n",
        "Pid:\t42\n",
        "Pid:\t42\nPid:\t42\nNSpid:\t42\t2\n",
        "Pid:\t42\nNSpid:\t42\t2\nNSpid:\t42\t2\n",
        "Pid:\t42 43\nNSpid:\t42\t2\n",
        "Pid:\t\nNSpid:\t42\t2\n",
        "Pid:\t42\nNSpid:\t\n",
        "Pid:\t42\nNSpid:\t43\t2\n",
        "Pid:\t0\nNSpid:\t0\n",
        "Pid:\t-1\nNSpid:\t-1\n",
        "Pid:\t+42\nNSpid:\t42\t2\n",
        "Pid:\t42\nNSpid:\t42\t0\n",
        "Pid:\t42\nNSpid:\t42\t-1\n",
        "Pid:\t42\nNSpid:\t42\t+2\n",
        "Pid:\t42\nNSpid:\t42\t2x\n",
        "Pid:\t42\nNSpid:\t42\t2147483648\n",
    ] {
        assert!(
            parse_target_pidfd_identity(text).is_err(),
            "accepted {text:?}"
        );
    }
}

#[test]
fn pidfd_mapping_enforces_finite_kernel_namespace_depth() {
    let maximum = std::iter::repeat_n("42", 33).collect::<Vec<_>>().join("\t");
    let accepted = ["Pid:\t42\nNSpid:\t", &maximum, "\n"].concat();
    parse_target_pidfd_identity(&accepted)
        .unwrap()
        .require_exec_pid(42, 42)
        .unwrap();
    let oversized = ["Pid:\t42\nNSpid:\t", &maximum, "\t42\n"].concat();
    assert!(parse_target_pidfd_identity(&oversized).is_err());
}
