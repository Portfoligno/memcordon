fn semantic_lines(value: &str) -> Vec<&str> {
    value.lines().collect()
}

#[test]
fn compiled_package_metadata_uses_fixed_root_service_identity() {
    let service = include_str!("../../../packaging/linux/memcordon-sealed-agent.service");
    let socket = include_str!("../../../packaging/linux/memcordon-sealed-agent.socket");
    assert_eq!(
        semantic_lines(service),
        [
            "[Unit]",
            "Description=MemCordon sealed supervision provider",
            "Requires=memcordon-sealed-agent.socket",
            "After=local-fs.target",
            "",
            "[Service]",
            "Type=simple",
            "ExecStart=/usr/libexec/memcordon-sealed-agent serve",
            "User=root",
            "Group=memcordon",
            "Delegate=yes",
            "KillMode=process",
            "RuntimeDirectory=memcordon",
            "RuntimeDirectoryMode=0750",
            "StateDirectory=memcordon/sealed",
            "StateDirectoryMode=0700",
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectSystem=strict",
            "ReadWritePaths=/run/memcordon /var/lib/memcordon/sealed /sys/fs/cgroup",
            "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_KILL CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
            "AmbientCapabilities=",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
        ]
    );
    assert_eq!(
        semantic_lines(socket),
        [
            "[Unit]",
            "Description=MemCordon sealed supervision provider socket",
            "",
            "[Socket]",
            "ListenStream=/run/memcordon/sealed-agent.sock",
            "DirectoryMode=0755",
            "SocketMode=0660",
            "SocketUser=root",
            "SocketGroup=memcordon",
            "RemoveOnStop=yes",
            "",
            "[Install]",
            "WantedBy=sockets.target",
        ]
    );
    assert_eq!(
        service
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
