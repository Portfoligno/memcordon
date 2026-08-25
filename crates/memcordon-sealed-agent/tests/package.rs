fn semantic_lines(value: &str) -> Vec<&str> {
    value.lines().collect()
}

#[test]
fn linux_package_artifacts_are_pinned_to_lf_checkouts() {
    let attributes = include_str!("../../../.gitattributes");
    assert!(
        attributes
            .lines()
            .any(|line| line == "/packaging/linux/** text eol=lf")
    );
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
    assert!(semantic_lines(control_service).contains(
        &"After=local-fs.target systemd-tmpfiles-setup.service memcordon-sealed-launcher.socket"
    ));
    assert!(
        semantic_lines(control_service)
            .contains(&"ReadWritePaths=/run/memcordon /var/lib/memcordon/sealed")
    );
    assert!(!control_service.contains("ReadWritePaths=/run/memcordon-sealed-package.lock"));
    assert!(!control_service.contains("RuntimeDirectory="));
    assert!(!control_service.contains("RuntimeDirectoryMode="));
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
    assert!(!launcher_service.contains("RuntimeDirectory="));
    assert!(!launcher_service.contains("RuntimeDirectoryMode="));
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
    assert_eq!(
        tmpfiles,
        "d /run/memcordon 0750 root memcordon -\nf /run/memcordon-sealed-package.lock 0600 root root -\n"
    );

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

    for service in [
        include_str!("../../../packaging/linux/memcordon-sealed-agent.service"),
        include_str!("../../../packaging/linux/memcordon-sealed-launcher.service"),
    ] {
        let crlf = service.replace('\n', "\r\n");
        assert_eq!(semantic_lines(service), semantic_lines(&crlf));
        assert!(
            !crlf
                .lines()
                .any(|line| line == "RuntimeDirectory=memcordon")
        );
        assert!(!crlf.lines().any(|line| line == "RuntimeDirectoryMode=0750"));
    }

    let tmpfiles = include_str!("../../../packaging/linux/memcordon.conf");
    let crlf = tmpfiles.replace('\n', "\r\n");
    assert_eq!(semantic_lines(tmpfiles), semantic_lines(&crlf));
    assert_eq!(
        semantic_lines(&crlf),
        [
            "d /run/memcordon 0750 root memcordon -",
            "f /run/memcordon-sealed-package.lock 0600 root root -",
        ]
    );
}
