fn semantic_lines(value: &str) -> Vec<&str> {
    value.lines().collect()
}

#[test]
fn compiled_package_metadata_uses_split_control_and_launcher_identities() {
    let control_service = include_str!("../../../packaging/linux/memcordon-sealed-agent.service");
    let control_socket = include_str!("../../../packaging/linux/memcordon-sealed-agent.socket");
    let launcher_service =
        include_str!("../../../packaging/linux/memcordon-sealed-launcher.service");
    let launcher_socket = include_str!("../../../packaging/linux/memcordon-sealed-launcher.socket");
    let tmpfiles = include_str!("../../../packaging/linux/memcordon.conf");

    assert!(
        semantic_lines(control_service)
            .contains(&"ExecStart=/usr/libexec/memcordon-sealed-agent serve")
    );
    assert!(semantic_lines(control_service).contains(&"NoNewPrivileges=yes"));
    assert!(
        semantic_lines(control_service)
            .contains(&"CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE")
    );
    assert!(!control_service.contains("Delegate=yes"));
    assert!(!control_service.contains("CAP_SYS_ADMIN"));
    assert!(!control_service.contains("CAP_SYS_CHROOT"));
    assert!(!control_service.contains("CAP_SETUID"));
    assert!(!control_service.contains("CAP_SETGID"));

    assert!(
        semantic_lines(launcher_service)
            .contains(&"ExecStart=/usr/libexec/memcordon-sealed-agent launch-broker")
    );
    assert!(semantic_lines(launcher_service).contains(&"User=root"));
    assert!(semantic_lines(launcher_service).contains(&"Group=root"));
    assert!(semantic_lines(launcher_service).contains(&"Delegate=yes"));
    assert!(semantic_lines(launcher_service).contains(&"NoNewPrivileges=no"));
    assert!(!launcher_service.contains("CapabilityBoundingSet="));
    assert!(!launcher_service.contains("PrivateTmp="));
    assert!(!launcher_service.contains("ProtectSystem="));
    assert!(!launcher_service.contains("RestrictSUIDSGID="));

    assert!(control_socket.contains("ListenStream=/run/memcordon/sealed-agent.sock"));
    assert!(control_socket.contains("SocketMode=0660"));
    assert!(control_socket.contains("SocketGroup=memcordon"));
    assert!(control_socket.contains("After=systemd-tmpfiles-setup.service"));
    assert!(launcher_socket.contains("ListenStream=/run/memcordon/sealed-launcher.sock"));
    assert!(launcher_socket.contains("After=systemd-tmpfiles-setup.service"));
    assert!(launcher_socket.contains("DirectoryMode=0750"));
    assert!(launcher_socket.contains("SocketMode=0600"));
    assert!(launcher_socket.contains("SocketUser=root"));
    assert!(launcher_socket.contains("SocketGroup=root"));
    assert_eq!(tmpfiles, "d /run/memcordon 0750 root memcordon -\n");

    assert_eq!(
        control_service
            .lines()
            .filter(|line| line.starts_with("AmbientCapabilities="))
            .collect::<Vec<_>>(),
        ["AmbientCapabilities="]
    );
    assert_eq!(
        launcher_service
            .lines()
            .filter(|line| line.starts_with("AmbientCapabilities="))
            .collect::<Vec<_>>(),
        ["AmbientCapabilities="]
    );
}

#[test]
fn package_metadata_semantics_are_identical_with_crlf_checkout() {
    let unit = "[Unit]\nDescription=provider\n\n[Service]\nUser=root\n";
    let crlf = unit.replace('\n', "\r\n");
    assert_eq!(semantic_lines(unit), semantic_lines(&crlf));
    let changed = crlf.replace("User=root", "User=runner");
    assert_ne!(semantic_lines(unit), semantic_lines(&changed));
}
