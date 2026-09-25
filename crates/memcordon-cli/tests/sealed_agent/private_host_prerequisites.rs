#![cfg(target_os = "linux")]

use crate::linux::private_host_prerequisites::{
    parse_control_tokens_for_test, parse_manager_properties_for_test, parse_proc_cgroup_for_test,
};

const MANAGER: &str = "InvocationID=0123456789abcdef0123456789abcdef\nMainPID=4321\nActiveState=active\nSubState=running\nNeedDaemonReload=no\nFragmentPath=/usr/lib/systemd/system/memcordon-sealed-network-launcher.service\nDropInPaths=\nControlGroup=/system.slice/memcordon-sealed-network-launcher.service\nDelegate=yes\n";

#[test]
fn manager_generation_requires_exact_current_unit_properties() {
    assert!(parse_manager_properties_for_test(MANAGER.as_bytes()).is_ok());
    assert!(
        parse_manager_properties_for_test(
            MANAGER
                .replace("ActiveState=active", "ActiveState=inactive")
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_manager_properties_for_test(MANAGER.replace("MainPID=4321", "MainPID=0").as_bytes())
            .is_err()
    );
    assert!(
        parse_manager_properties_for_test(
            MANAGER
                .replace("NeedDaemonReload=no", "NeedDaemonReload=yes")
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_manager_properties_for_test(
            MANAGER
                .replace(
                    "DropInPaths=",
                    "DropInPaths=/etc/systemd/system/override.conf"
                )
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_manager_properties_for_test(
            MANAGER
                .replace(
                    "InvocationID=0123456789abcdef0123456789abcdef",
                    "InvocationID=00000000000000000000000000000000"
                )
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_manager_properties_for_test(
            MANAGER.replace("Delegate=yes", "Delegate=no").as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_manager_properties_for_test(
            MANAGER
                .replace(
                    "FragmentPath=/usr/lib/systemd/system/memcordon-sealed-network-launcher.service",
                    "FragmentPath=/etc/systemd/system/memcordon-sealed-network-launcher.service"
                )
                .as_bytes()
        )
        .is_err()
    );
}

#[test]
fn manager_generation_rejects_missing_duplicate_unknown_and_oversized_output() {
    assert!(
        parse_manager_properties_for_test(
            MANAGER
                .replace(
                    "ControlGroup=/system.slice/memcordon-sealed-network-launcher.service\n",
                    ""
                )
                .as_bytes()
        )
        .is_err()
    );
    let duplicate = format!("{MANAGER}MainPID=4321\n");
    assert!(parse_manager_properties_for_test(duplicate.as_bytes()).is_err());
    let unknown = format!("{MANAGER}CallerClaim=true\n");
    assert!(parse_manager_properties_for_test(unknown.as_bytes()).is_err());
    assert!(parse_manager_properties_for_test(&vec![b' '; 16 * 1024 + 1]).is_err());
}

#[test]
fn host_cgroup_readback_requires_one_v2_membership_and_unique_controls() {
    assert_eq!(
        parse_proc_cgroup_for_test(b"0::/system.slice/memcordon-sealed-network-launcher.service\n")
            .unwrap(),
        "/system.slice/memcordon-sealed-network-launcher.service"
    );
    for invalid in [
        b"1:memory:/legacy\n".as_slice(),
        b"0::/system.slice/x\n0::/system.slice/y\n",
        b"0::/system.slice//x\n",
        b"0::relative\n",
    ] {
        assert!(parse_proc_cgroup_for_test(invalid).is_err());
    }
    assert_eq!(
        parse_control_tokens_for_test(b"pids memory\n").unwrap(),
        ["memory", "pids"]
    );
    for invalid in [
        b"".as_slice(),
        b"memory memory\n",
        b"Memory\n",
        b"+memory\n",
    ] {
        assert!(parse_control_tokens_for_test(invalid).is_err());
    }
}
