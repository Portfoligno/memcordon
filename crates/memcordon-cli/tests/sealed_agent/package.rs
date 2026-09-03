fn semantic_lines(value: &str) -> Vec<&str> {
    value.lines().collect()
}

fn source_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing source boundary {start:?}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing source boundary {end:?}"))
        .0
}

#[test]
fn installed_provider_digest_must_match_the_invoked_package() {
    let invoked = "current-package-digest";
    assert!(crate::package::verify_installed_executable_digest(invoked, invoked).is_ok());
    let mismatch =
        crate::package::verify_installed_executable_digest(invoked, "older-provider-digest")
            .expect_err("an older installed provider must not verify against a newer package");
    assert!(mismatch.contains("MCSEALED-PACKAGE-VERSION-MISMATCH"));
    assert!(mismatch.contains("package upgrade"));
}

#[test]
fn installed_verification_uses_captured_source_digest_after_source_removal() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let source = temporary.path().join("invoked-agent");
    let installed = temporary.path().join("installed-agent");
    let source_bytes = b"exact package executable payload";
    std::fs::write(&source, source_bytes).expect("source executable should be writable");
    let captured_bytes = std::fs::read(&source).expect("source executable should be captured");
    let captured_digest = crate::package::sha256_bytes(&captured_bytes);
    std::fs::write(&installed, captured_bytes).expect("captured executable should be installed");
    std::fs::remove_file(&source).expect("source pathname should be removable");

    crate::package::verify_installed_executable_against(&installed, &captured_digest)
        .expect("installed verification must not reopen the removed source pathname");
}

#[test]
fn linux_package_artifacts_are_pinned_to_lf_checkouts() {
    let attributes = include_str!("../../../../.gitattributes");
    assert!(
        attributes
            .lines()
            .any(|line| line == "/packaging/linux/** text eol=lf")
    );
}

#[test]
fn compiled_package_metadata_uses_split_control_and_launcher_identities() {
    let control_service =
        include_str!("../../../../packaging/linux/memcordon-sealed-agent.service");
    let control_socket = include_str!("../../../../packaging/linux/memcordon-sealed-agent.socket");
    let launcher_service =
        include_str!("../../../../packaging/linux/memcordon-sealed-launcher.service");
    let launcher_socket =
        include_str!("../../../../packaging/linux/memcordon-sealed-launcher.socket");
    let tmpfiles = include_str!("../../../../packaging/linux/memcordon.conf");

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
        include_str!("../../../../packaging/linux/memcordon-sealed-agent.service"),
        include_str!("../../../../packaging/linux/memcordon-sealed-launcher.service"),
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

    let tmpfiles = include_str!("../../../../packaging/linux/memcordon.conf");
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

#[test]
fn windows_final_root_removal_does_not_require_list_authority() {
    let source = include_str!("../../src/bin/memcordon-sealed-agent/windows/package.rs");
    let provider_removal = source_between(
        source,
        "fn remove_provider_state(",
        "fn remove_file_if_present(",
    );
    assert!(
        provider_removal.contains("remove_state_root_with_kernel_empty_proof(&state, context)?")
    );
    assert!(
        !provider_removal
            .contains("remove_directory_if_present(&state, StateDirectory::StateRoot, context)?")
    );

    let exact_removal = source_between(
        source,
        "enum ExactPathDirectoryRemovalFailure {",
        "fn bounded_residual_inventory(",
    );
    assert!(exact_removal.contains("std::fs::symlink_metadata(path)"));
    assert!(exact_removal.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
    assert!(exact_removal.contains("std::fs::remove_dir(path)"));
    assert!(exact_removal.contains("ERROR_DIR_NOT_EMPTY"));
    assert!(exact_removal.contains("ERROR_ACCESS_DENIED"));
    assert!(exact_removal.contains("residual-present-but-not-enumerable"));
    assert!(exact_removal.contains("access-denied"));
    assert!(exact_removal.contains("inspection=kernel-empty-proof-no-list-authority"));
    assert!(!exact_removal.contains("read_dir"));
    assert!(!exact_removal.contains("bounded_residual_inventory"));
    assert!(!source.contains("remove_dir_all"));
}

#[test]
fn windows_fresh_rollback_and_uninstall_share_the_exact_root_removal() {
    let source = include_str!("../../src/bin/memcordon-sealed-agent/windows/package.rs");
    let fresh_rollback = source_between(source, "fn rollback_fresh_install(", "#[derive(Default)]");
    let uninstall = source_between(source, "fn uninstall(", "fn scm_ownership_marker_present(");
    let provider_files = source_between(
        source,
        "fn remove_provider_files(",
        "pub(crate) fn remove_installed_binary_with_convergence(",
    );

    assert!(fresh_rollback.contains("remove_provider_files(ProviderRemovalContext"));
    assert!(uninstall.contains("remove_provider_files(ProviderRemovalContext"));
    assert!(provider_files.contains("remove_provider_state(context)?"));
}

#[test]
fn windows_package_cleanup_terminates_jobs_before_empty_state_deletion() {
    let control = include_str!("../../src/bin/memcordon-sealed-agent/windows/control_service.rs");
    let launcher = include_str!("../../src/bin/memcordon-sealed-agent/windows/launcher_service.rs");
    let package = include_str!("../../src/bin/memcordon-sealed-agent/windows/package.rs");
    let record = include_str!("../../src/bin/memcordon-sealed-agent/windows/record.rs");

    let cleanup = source_between(
        control,
        "WindowsProviderRequestV1::PackageCleanup {",
        "WindowsProviderRequestV1::QualificationBegin {",
    );
    assert!(cleanup.contains("converge_launcher_package_cleanup(deadline_millis)"));
    assert!(cleanup.contains("and_then(|()| super::record::remove_empty_attempt_state())"));

    let convergence = source_between(
        launcher,
        "fn converge_package_cleanup(",
        "fn control_authentication_subphase(",
    );
    assert!(convergence.contains("active.job.terminate()"));
    assert!(convergence.contains("super::record::converge_package_cleanup(deadline)?"));

    let barrier = source_between(
        package,
        "fn service_owned_cleanup_barrier(",
        "#[derive(Default)]",
    );
    assert!(barrier.contains("prepare_package_cleanup(deadline_millis)"));
    assert!(record.contains("fn recover_until(deadline: Instant)"));
}
