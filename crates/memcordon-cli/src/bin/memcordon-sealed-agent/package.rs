use std::ffi::OsStr;
use std::io::Read;

use sha2::{Digest, Sha256};

#[cfg(not(target_os = "windows"))]
use crate::inspection_schema::ProviderPackageMetadataV2;
use crate::inspection_schema::{AgentPackageInspectionV2, InstalledProviderInspectionV2};

const SERVICE: &str = "[Unit]\nDescription=MemCordon sealed supervision control provider\nRequires=memcordon-sealed-agent.socket memcordon-sealed-launcher.socket\nAfter=local-fs.target systemd-tmpfiles-setup.service memcordon-sealed-launcher.socket\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent serve\nUser=root\nGroup=memcordon\nKillMode=process\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=/run/memcordon /var/lib/memcordon/sealed\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const SOCKET: &str = "[Unit]\nDescription=MemCordon sealed supervision control socket\nAfter=systemd-tmpfiles-setup.service\n\n[Socket]\nListenStream=/run/memcordon/sealed-agent.sock\nDirectoryMode=0755\nSocketMode=0660\nSocketUser=root\nSocketGroup=memcordon\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
const LAUNCHER_SERVICE: &str = "[Unit]\nDescription=MemCordon sealed supervision launch broker\nRequires=memcordon-sealed-launcher.socket\nAfter=local-fs.target\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent launch-broker\nUser=root\nGroup=root\nDelegate=yes\nKillMode=process\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=no\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const LAUNCHER_SOCKET: &str = "[Unit]\nDescription=MemCordon sealed supervision launch broker socket\nAfter=systemd-tmpfiles-setup.service\n\n[Socket]\nListenStream=/run/memcordon/sealed-launcher.sock\nDirectoryMode=0750\nSocketMode=0600\nSocketUser=root\nSocketGroup=root\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
const TMPFILES: &str = "d /run/memcordon 0750 root memcordon -\nf /run/memcordon-sealed-package.lock 0600 root root -\n";
#[cfg(target_os = "linux")]
const BINARY: &str = "/usr/libexec/memcordon-sealed-agent";
#[cfg(target_os = "linux")]
const UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.service";
#[cfg(target_os = "linux")]
const SOCKET_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.socket";
#[cfg(target_os = "linux")]
const LAUNCHER_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-launcher.service";
#[cfg(target_os = "linux")]
const LAUNCHER_SOCKET_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-launcher.socket";
#[cfg(target_os = "linux")]
const TMPFILES_FILE: &str = "/usr/lib/tmpfiles.d/memcordon.conf";
#[cfg(target_os = "linux")]
const LEGACY_PACKAGE_LEASE: &str = "/run/memcordon/sealed-package.lock";
#[cfg(target_os = "linux")]
const RUNTIME_DIRECTORY: &str = "/run/memcordon";

pub fn run(operation: &OsStr, json: bool, ephemeral_ci: bool) -> Result<(), String> {
    if operation == "inspect" {
        if ephemeral_ci {
            return Err("--ephemeral-ci is valid only for package mutations".to_owned());
        }
        return render_inspection(&inspect()?, json);
    }
    if operation == "verify" {
        if ephemeral_ci {
            return Err("--ephemeral-ci is valid only for package mutations".to_owned());
        }
        verify()?;
        return render_installed_inspection(&installed_inspection()?, json);
    }
    if json {
        return Err("--json is valid only for package inspect and package verify".to_owned());
    }
    #[cfg(target_os = "linux")]
    {
        linux_mutation(operation, ephemeral_ci)
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows::package::mutate(operation, ephemeral_ci)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = ephemeral_ci;
        Err("provider package mutation is unavailable on this platform".to_owned())
    }
}

pub(crate) fn verify() -> Result<(), String> {
    verify_compiled_metadata()?;
    #[cfg(target_os = "linux")]
    verify_installed_package()?;
    #[cfg(target_os = "windows")]
    crate::windows::package::verify_installed()?;
    Ok(())
}

fn render_inspection(inspection: &AgentPackageInspectionV2, json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(inspection).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "memcordon-sealed-agent {} ({})",
            inspection.version, inspection.source_commit
        );
        println!("executable sha256: {}", inspection.executable_sha256);
        println!("compiled package metadata: valid");
    }
    Ok(())
}

fn render_installed_inspection(
    inspection: &InstalledProviderInspectionV2,
    json: bool,
) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(inspection).map_err(|error| error.to_string())?
        );
    } else {
        println!("installed provider artifacts: valid");
        println!(
            "provider reachable: {}",
            if inspection.provider_reachable {
                "yes"
            } else {
                "no"
            }
        );
        println!(
            "qualification complete: {}",
            if inspection.qualification_complete {
                "yes"
            } else {
                "no"
            }
        );
    }
    Ok(())
}

pub(crate) fn inspect() -> Result<AgentPackageInspectionV2, String> {
    verify_compiled_metadata()?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("MCSEALED-PACKAGE-INSPECT: current executable: {error}"))?;
    let executable_sha256 = sha256_regular_no_follow(&executable)?;
    #[cfg(not(target_os = "windows"))]
    let (mechanism, platform) = (
        "linux-pid-namespace-cgroup-v2".to_owned(),
        ProviderPackageMetadataV2::LinuxSystemd {
            control_service_sha256: sha256_bytes(SERVICE.as_bytes()),
            control_socket_sha256: sha256_bytes(SOCKET.as_bytes()),
            launcher_service_sha256: sha256_bytes(LAUNCHER_SERVICE.as_bytes()),
            launcher_socket_sha256: sha256_bytes(LAUNCHER_SOCKET.as_bytes()),
            tmpfiles_sha256: sha256_bytes(TMPFILES.as_bytes()),
        },
    );
    #[cfg(target_os = "windows")]
    let (mechanism, platform) = (
        "windows-job-object-v2".to_owned(),
        crate::windows::package::compiled_metadata()?,
    );
    Ok(AgentPackageInspectionV2 {
        schema_version: 2,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        source_commit: crate::SOURCE_COMMIT.to_owned(),
        executable_sha256,
        provider_protocol: if cfg!(target_os = "windows") {
            memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
        } else {
            u32::from(crate::protocol::PROTOCOL_VERSION)
        },
        mechanism,
        execution_report_schema: memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
        plan_report_schema: memcordon_core::PLAN_REPORT_SCHEMA_VERSION,
        doctor_report_schema: memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
        platform,
        compiled_metadata_valid: true,
    })
}

fn installed_inspection() -> Result<InstalledProviderInspectionV2, String> {
    let agent = inspect()?;
    #[cfg(target_os = "linux")]
    {
        let installed_executable_sha256 = sha256_regular_no_follow(std::path::Path::new(BINARY))?;
        verify_installed_executable_digest(&agent.executable_sha256, &installed_executable_sha256)?;
        let qualification = probe_provider().ok();
        let provider_reachable = qualification.is_some();
        let qualification_complete = qualification.as_ref().is_some_and(|value| value.complete());
        let provider_identity = qualification.map(|value| value.provider_identity);
        Ok(InstalledProviderInspectionV2 {
            schema_version: 2,
            agent,
            installed_executable_sha256,
            installed_artifacts_valid: true,
            provider_identity,
            provider_reachable,
            qualification_complete,
        })
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows::package::installed_inspection(agent)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(InstalledProviderInspectionV2 {
            schema_version: 2,
            agent,
            installed_executable_sha256: String::new(),
            installed_artifacts_valid: false,
            provider_identity: None,
            provider_reachable: false,
            qualification_complete: false,
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn verify_installed_executable_digest(
    packaged_executable_sha256: &str,
    installed_executable_sha256: &str,
) -> Result<(), String> {
    if installed_executable_sha256 != packaged_executable_sha256 {
        return Err(
            "MCSEALED-PACKAGE-VERSION-MISMATCH: installed provider executable differs from the invoked memcordon package; rerun package upgrade with the matching memcordon-sealed-agent"
                .to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn sha256_regular_no_follow(path: &std::path::Path) -> Result<String, String> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    #[cfg(windows)]
    options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = options
        .open(path)
        .map_err(|error| format!("MCSEALED-PACKAGE-INSPECT: {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("MCSEALED-PACKAGE-INSPECT: {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "MCSEALED-PACKAGE-INSPECT: {} is not a no-follow regular file",
            path.display()
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("MCSEALED-PACKAGE-INSPECT: {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex_digest(digest.finalize()))
}

fn verify_compiled_metadata() -> Result<(), String> {
    const CONTROL_CAPABILITY_BOUNDING_SET: &str =
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE";
    const CONTROL_READ_WRITE_PATHS: &str =
        "ReadWritePaths=/run/memcordon /var/lib/memcordon/sealed";
    let control_capabilities = SERVICE
        .lines()
        .filter(|line| line.starts_with("CapabilityBoundingSet="))
        .collect::<Vec<_>>();
    let control_ambient = SERVICE
        .lines()
        .filter(|line| line.starts_with("AmbientCapabilities="))
        .collect::<Vec<_>>();
    let control_read_write_paths = SERVICE
        .lines()
        .filter(|line| line.starts_with("ReadWritePaths="))
        .collect::<Vec<_>>();
    let launcher_capabilities = LAUNCHER_SERVICE
        .lines()
        .filter(|line| line.starts_with("CapabilityBoundingSet="))
        .collect::<Vec<_>>();
    let launcher_ambient = LAUNCHER_SERVICE
        .lines()
        .filter(|line| line.starts_with("AmbientCapabilities="))
        .collect::<Vec<_>>();
    let launcher_forbidden = [
        "PrivateTmp=",
        "ProtectSystem=",
        "ReadWritePaths=",
        "ReadOnlyPaths=",
        "InaccessiblePaths=",
        "RestrictSUIDSGID=",
    ];
    let launcher_changes_target_mounts = LAUNCHER_SERVICE.lines().any(|line| {
        launcher_forbidden
            .iter()
            .any(|prefix| line.starts_with(prefix))
    });
    if SERVICE.contains("Description=MemCordon sealed supervision control provider")
        && SERVICE.contains("ExecStart=/usr/libexec/memcordon-sealed-agent serve")
        && SERVICE.contains("User=root")
        && SERVICE.contains("Group=memcordon")
        && SERVICE.contains("NoNewPrivileges=yes")
        && SERVICE.contains("PrivateTmp=yes")
        && SERVICE.contains("ProtectSystem=strict")
        && SERVICE.contains(
            "After=local-fs.target systemd-tmpfiles-setup.service memcordon-sealed-launcher.socket",
        )
        && !SERVICE.contains("RuntimeDirectory=")
        && !SERVICE.contains("RuntimeDirectoryMode=")
        && control_capabilities == [CONTROL_CAPABILITY_BOUNDING_SET]
        && control_ambient == ["AmbientCapabilities="]
        && control_read_write_paths == [CONTROL_READ_WRITE_PATHS]
        && SOCKET.contains("ListenStream=/run/memcordon/sealed-agent.sock")
        && SOCKET.contains("After=systemd-tmpfiles-setup.service")
        && SOCKET.contains("SocketMode=0660")
        && SOCKET.contains("SocketGroup=memcordon")
        && LAUNCHER_SERVICE.contains("Description=MemCordon sealed supervision launch broker")
        && LAUNCHER_SERVICE.contains("ExecStart=/usr/libexec/memcordon-sealed-agent launch-broker")
        && LAUNCHER_SERVICE.contains("User=root")
        && LAUNCHER_SERVICE.contains("Group=root")
        && LAUNCHER_SERVICE.contains("NoNewPrivileges=no")
        && !LAUNCHER_SERVICE.contains("RuntimeDirectory=")
        && !LAUNCHER_SERVICE.contains("RuntimeDirectoryMode=")
        && launcher_capabilities.is_empty()
        && launcher_ambient == ["AmbientCapabilities="]
        && !launcher_changes_target_mounts
        && LAUNCHER_SOCKET.contains("ListenStream=/run/memcordon/sealed-launcher.sock")
        && LAUNCHER_SOCKET.contains("After=systemd-tmpfiles-setup.service")
        && LAUNCHER_SOCKET.contains("DirectoryMode=0750")
        && LAUNCHER_SOCKET.contains("SocketMode=0600")
        && LAUNCHER_SOCKET.contains("SocketUser=root")
        && LAUNCHER_SOCKET.contains("SocketGroup=root")
        && TMPFILES
            == "d /run/memcordon 0750 root memcordon -\nf /run/memcordon-sealed-package.lock 0600 root root -\n"
    {
        Ok(())
    } else {
        Err("compiled split-service metadata is inconsistent".to_owned())
    }
}

#[cfg(target_os = "linux")]
fn prepare_runtime_directory() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::symlink_metadata("/run/memcordon") {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err("provider runtime path is not a real directory".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir("/run/memcordon").map_err(|error| error.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    std::fs::set_permissions("/run/memcordon", std::fs::Permissions::from_mode(0o750))
        .map_err(|error| error.to_string())?;
    let metadata = std::fs::symlink_metadata("/run/memcordon")
        .map_err(|error| format!("provider runtime directory unavailable: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o7777 != 0o750 {
        return Err("provider runtime directory identity or mode is unsafe".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_runtime_directory_owner(service_gid: libc::gid_t) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata("/run/memcordon")
        .map_err(|error| format!("provider runtime directory unavailable: {error}"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.gid() != service_gid
        || metadata.mode() & 0o7777 != 0o750
    {
        return Err("provider runtime directory identity or permissions are unsafe".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum ArtifactAccess {
    MetadataOnly,
    Readable,
}

#[cfg(target_os = "linux")]
fn open_artifact_descriptor(
    path: &std::path::Path,
    access: ArtifactAccess,
) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;

    let access_flag = match access {
        ArtifactAccess::MetadataOnly => libc::O_PATH,
        ArtifactAccess::Readable => 0,
    };
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(access_flag | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err("MCSEALED-PACKAGE-VERIFY: installed package is incomplete".to_owned())
        }
        Err(error) => Err(format!(
            "MCSEALED-PACKAGE-VERIFY: {}: {error}",
            path.display()
        )),
    }
}

#[cfg(target_os = "linux")]
fn verify_open_artifact(
    file: &mut std::fs::File,
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_bytes: Option<&[u8]>,
) -> Result<(), String> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .map_err(|error| format!("MCSEALED-PACKAGE-VERIFY: {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "MCSEALED-PACKAGE-VERIFY: {} is not a no-follow regular file",
            path.display()
        ));
    }
    if metadata.uid() != expected_uid || metadata.gid() != expected_gid {
        let expected_owner = if expected_uid == 0 && expected_gid == 0 {
            "root:root".to_owned()
        } else {
            format!("{expected_uid}:{expected_gid}")
        };
        return Err(format!(
            "MCSEALED-PACKAGE-VERIFY: {} is not owned by {expected_owner}",
            path.display(),
        ));
    }
    if metadata.mode() & 0o7777 != expected_mode {
        return Err(format!(
            "MCSEALED-PACKAGE-VERIFY: {} mode is not {expected_mode:04o}",
            path.display()
        ));
    }
    if let Some(expected_bytes) = expected_bytes {
        let mut actual = Vec::with_capacity(expected_bytes.len() + 1);
        file.by_ref()
            .take((expected_bytes.len() + 1) as u64)
            .read_to_end(&mut actual)
            .map_err(|error| format!("MCSEALED-PACKAGE-VERIFY: {}: {error}", path.display()))?;
        if actual != expected_bytes {
            return Err(format!(
                "MCSEALED-PACKAGE-VERIFY: {} content differs from the packaged artifact",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_metadata_artifact(
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), String> {
    let mut file = open_artifact_descriptor(path, ArtifactAccess::MetadataOnly)?;
    verify_open_artifact(
        &mut file,
        path,
        expected_uid,
        expected_gid,
        expected_mode,
        None,
    )
}

#[cfg(target_os = "linux")]
fn verify_readable_artifact(
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_bytes: Option<&[u8]>,
) -> Result<(), String> {
    let mut file = open_artifact_descriptor(path, ArtifactAccess::Readable)?;
    verify_open_artifact(
        &mut file,
        path,
        expected_uid,
        expected_gid,
        expected_mode,
        expected_bytes,
    )
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn verify_metadata_artifact_for_test(
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), String> {
    verify_metadata_artifact(path, expected_uid, expected_gid, expected_mode)
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn verify_readable_artifact_for_test(
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_bytes: Option<&[u8]>,
) -> Result<(), String> {
    verify_readable_artifact(
        path,
        expected_uid,
        expected_gid,
        expected_mode,
        expected_bytes,
    )
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn open_metadata_artifact_for_test(path: &std::path::Path) -> Result<std::fs::File, String> {
    open_artifact_descriptor(path, ArtifactAccess::MetadataOnly)
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn open_readable_artifact_for_test(path: &std::path::Path) -> Result<std::fs::File, String> {
    open_artifact_descriptor(path, ArtifactAccess::Readable)
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn verify_open_artifact_for_test(
    file: &mut std::fs::File,
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_bytes: Option<&[u8]>,
) -> Result<(), String> {
    verify_open_artifact(
        file,
        path,
        expected_uid,
        expected_gid,
        expected_mode,
        expected_bytes,
    )
}

#[cfg(target_os = "linux")]
fn verify_installed_package() -> Result<(), String> {
    verify_metadata_artifact(
        std::path::Path::new(crate::linux::service::PACKAGE_LEASE),
        0,
        0,
        0o600,
    )?;

    let packaged_executable = inspect()?;
    let installed_executable_sha256 = sha256_regular_no_follow(std::path::Path::new(BINARY))?;
    verify_installed_executable_digest(
        &packaged_executable.executable_sha256,
        &installed_executable_sha256,
    )?;

    let artifacts = [
        (BINARY, 0o755, None),
        (UNIT, 0o644, Some(SERVICE.as_bytes())),
        (SOCKET_UNIT, 0o644, Some(SOCKET.as_bytes())),
        (LAUNCHER_UNIT, 0o644, Some(LAUNCHER_SERVICE.as_bytes())),
        (
            LAUNCHER_SOCKET_UNIT,
            0o644,
            Some(LAUNCHER_SOCKET.as_bytes()),
        ),
        (TMPFILES_FILE, 0o644, Some(TMPFILES.as_bytes())),
    ];
    for (path, expected_mode, expected_bytes) in artifacts {
        verify_readable_artifact(
            std::path::Path::new(path),
            0,
            0,
            expected_mode,
            expected_bytes,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_mutation(operation: &OsStr, ephemeral_ci: bool) -> Result<(), String> {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::Path;

    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::geteuid() } != 0 {
        return Err("package mutation requires root".to_owned());
    }
    if operation != "install" && operation != "upgrade" && operation != "uninstall" {
        return Err("unknown package operation".to_owned());
    }
    let _package_lease = crate::linux::service::acquire_package_lease().map_err(|error| {
        format!("refusing package mutation while a sealed provider attempt is active: {error}")
    })?;
    prepare_runtime_directory()?;
    let _legacy_package_lease = crate::linux::service::acquire_legacy_package_lease().map_err(
        |error| {
            format!(
                "refusing package mutation while a legacy sealed provider attempt is active: {error}"
            )
        },
    )?;
    if operation == "uninstall" {
        ensure_recovery_idle("uninstall")?;
        stop_unit("memcordon-sealed-agent.service")?;
        stop_unit("memcordon-sealed-launcher.service")?;
        stop_unit("memcordon-sealed-agent.socket")?;
        stop_unit("memcordon-sealed-launcher.socket")?;
        ensure_unit_inactive("memcordon-sealed-agent.service")?;
        ensure_unit_inactive("memcordon-sealed-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-agent.socket")?;
        ensure_unit_inactive("memcordon-sealed-launcher.socket")?;
        ensure_recovery_idle("uninstall")?;
        for path in [
            SOCKET_UNIT,
            UNIT,
            LAUNCHER_SOCKET_UNIT,
            LAUNCHER_UNIT,
            TMPFILES_FILE,
            BINARY,
        ] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("could not remove {path}: {error}")),
            }
        }
        systemctl(["daemon-reload"])?;
        remove_uninstalled_file(LEGACY_PACKAGE_LEASE)?;
        for path in [
            crate::linux::CGROUP_ROOT,
            crate::linux::STATE_ROOT,
            RUNTIME_DIRECTORY,
        ] {
            remove_uninstalled_directory(path)?;
        }
        // This is the final uninstall mutation. The open exclusive lease remains locked until
        // return, while unlinking prevents the package lock itself becoming residual state.
        remove_uninstalled_file(crate::linux::service::PACKAGE_LEASE)?;
        return Ok(());
    }
    if operation == "upgrade" {
        ensure_recovery_idle("upgrade")?;
        stop_unit("memcordon-sealed-agent.service")?;
        stop_unit("memcordon-sealed-launcher.service")?;
        stop_unit("memcordon-sealed-agent.socket")?;
        stop_unit("memcordon-sealed-launcher.socket")?;
        ensure_unit_inactive("memcordon-sealed-agent.service")?;
        ensure_unit_inactive("memcordon-sealed-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-agent.socket")?;
        ensure_unit_inactive("memcordon-sealed-launcher.socket")?;
        ensure_recovery_idle("upgrade")?;
    }
    verify_compiled_metadata()?;
    let service_gid = ensure_service_group()?;
    // Already-loaded pre-transition units can remove their shared RuntimeDirectory while upgrade
    // quiesces both services. Re-establish the tmpfiles contract after all stop/recovery checks and
    // immediately before assigning the reviewed ownership. Successful uninstall returns above.
    prepare_runtime_directory()?;
    let runtime_directory =
        std::ffi::CString::new("/run/memcordon").expect("static runtime path has no NUL");
    // SAFETY: runtime_directory is a live NUL-terminated path and service_gid came from the
    // system group database. The public socket group needs traversal through this 0750 parent.
    if unsafe { libc::chown(runtime_directory.as_ptr(), 0, service_gid) } == -1 {
        return Err(format!(
            "could not assign /run/memcordon to root:memcordon: {}",
            std::io::Error::last_os_error()
        ));
    }
    verify_runtime_directory_owner(service_gid)?;
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
    let installations = [
        (
            Path::new(BINARY),
            fs::read(source).map_err(|error| error.to_string())?,
            0o755,
        ),
        (Path::new(UNIT), SERVICE.as_bytes().to_vec(), 0o644),
        (Path::new(SOCKET_UNIT), SOCKET.as_bytes().to_vec(), 0o644),
        (
            Path::new(LAUNCHER_UNIT),
            LAUNCHER_SERVICE.as_bytes().to_vec(),
            0o644,
        ),
        (
            Path::new(LAUNCHER_SOCKET_UNIT),
            LAUNCHER_SOCKET.as_bytes().to_vec(),
            0o644,
        ),
        (
            Path::new(TMPFILES_FILE),
            TMPFILES.as_bytes().to_vec(),
            0o644,
        ),
    ];
    for (path, bytes, mode) in installations {
        let parent = path
            .parent()
            .ok_or_else(|| "install path has no parent".to_owned())?;
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let temporary = parent.join(format!(
            ".{}.new",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        if temporary.exists() {
            fs::remove_file(&temporary).map_err(|error| error.to_string())?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
        fs::rename(temporary, path).map_err(|error| error.to_string())?;
    }
    verify_installed_package()?;
    systemctl(["daemon-reload"])?;
    if ephemeral_ci {
        systemctl(["start", "memcordon-sealed-launcher.socket"])?;
        systemctl(["start", "memcordon-sealed-agent.socket"])?;
    } else {
        systemctl(["enable", "--now", "memcordon-sealed-launcher.socket"])?;
        systemctl(["enable", "--now", "memcordon-sealed-agent.socket"])?;
    }
    systemctl(["restart", "memcordon-sealed-launcher.service"])?;
    systemctl(["restart", "memcordon-sealed-agent.service"])?;
    wait_provider_ready()?;
    verify_client_access()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_uninstalled_file(path: &str) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "provider uninstall could not remove residual file {path}: {error}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn remove_uninstalled_directory(path: &str) -> Result<(), String> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "provider uninstall found residual state in {path}: {error}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn ensure_recovery_idle(operation: &str) -> Result<(), String> {
    let ambiguous = crate::linux::recovery::recover()?;
    if !ambiguous.is_empty() {
        return Err(format!(
            "refusing to {operation} while sealed recovery is ambiguous: {}",
            ambiguous.join(",")
        ));
    }
    if live_attempt_exists()? {
        return Err(format!(
            "refusing to {operation} while an authenticated attempt record exists"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_client_access() -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let allowed_gid = service_group_gid()?;
    let directory = std::fs::symlink_metadata("/run/memcordon")
        .map_err(|error| format!("provider runtime directory unavailable: {error}"))?;
    if !directory.file_type().is_dir()
        || directory.uid() != 0
        || directory.gid() != allowed_gid
        || directory.mode() & 0o777 != 0o750
    {
        return Err("provider runtime directory identity or permissions are unsafe".to_owned());
    }
    let socket = std::fs::symlink_metadata("/run/memcordon/sealed-agent.sock")
        .map_err(|error| format!("provider endpoint unavailable: {error}"))?;
    if !socket.file_type().is_socket()
        || socket.uid() != 0
        || socket.gid() != allowed_gid
        || socket.mode() & 0o777 != 0o660
    {
        return Err("provider endpoint identity or permissions are unsafe".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn service_group_gid() -> Result<libc::gid_t, String> {
    let name = std::ffi::CString::new("memcordon").expect("static group name has no NUL");
    // SAFETY: package mutation is single-threaded; `name` is NUL-terminated and live for the
    // lookup, and the returned libc database pointer is read immediately without retention.
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        return Err("memcordon service group is unavailable".to_owned());
    }
    // SAFETY: the null case was rejected and the group database entry remains valid until the
    // next group lookup in this single-threaded process.
    Ok(unsafe { (*group).gr_gid })
}

#[cfg(target_os = "linux")]
pub fn probe_provider() -> Result<crate::linux::qualification::QualificationReceipt, String> {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use crate::protocol::{Frame, MessageKind, read_frame, write_frame};

    let mut stream = UnixStream::connect("/run/memcordon/sealed-agent.sock")
        .map_err(|error| readiness_error(&error.to_string()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|error| readiness_error(&error.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(60)))
        .map_err(|error| readiness_error(&error.to_string()))?;
    let nonce = [0x52; 16];
    write_frame(
        &mut stream,
        &Frame {
            kind: MessageKind::Probe,
            nonce,
            attempt_id: [0; 16],
            payload: Vec::new(),
        },
    )
    .map_err(|error| readiness_error(&error.to_string()))?;
    let receipt = read_frame(&mut stream).map_err(|error| readiness_error(&error.to_string()))?;
    if receipt.nonce != nonce || receipt.attempt_id != [0; 16] {
        return Err(readiness_error("response identity mismatch"));
    }
    if receipt.kind == MessageKind::Rejected {
        let reason = std::str::from_utf8(&receipt.payload)
            .map_err(|error| readiness_error(&format!("invalid rejection payload: {error}")))?;
        return Err(readiness_error(&format!(
            "provider rejected probe: {reason}"
        )));
    }
    if receipt.kind != MessageKind::ProbeReceipt {
        return Err(readiness_error("unexpected response kind"));
    }
    let qualification: crate::linux::qualification::QualificationReceipt =
        serde_json::from_slice(&receipt.payload)
            .map_err(|error| readiness_error(&error.to_string()))?;
    if qualification.schema_version != 2
        || qualification.mechanism != "linux-pid-namespace-cgroup-v2"
        || qualification.provider_identity.is_empty()
        || qualification.receipt_digest.is_empty()
        || !qualification.complete()
    {
        return Err(readiness_error("incomplete qualification"));
    }
    Ok(qualification)
}

#[cfg(target_os = "linux")]
fn wait_provider_ready() -> Result<(), String> {
    let _qualification = probe_provider()?;
    if live_attempt_exists()? {
        return Err(readiness_error("provider is not idle"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn live_attempt_exists() -> Result<bool, String> {
    let state_root = std::path::Path::new("/var/lib/memcordon/sealed");
    Ok(state_root.exists()
        && std::fs::read_dir(state_root)
            .map_err(|error| error.to_string())?
            .next()
            .is_some())
}

#[cfg(target_os = "linux")]
fn ensure_service_group() -> Result<libc::gid_t, String> {
    let name = std::ffi::CString::new("memcordon").expect("static group name has no NUL");
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if !group.is_null() {
        // SAFETY: getgrnam returned a live libc-managed group record.
        return Ok(unsafe { (*group).gr_gid });
    }
    let status = std::process::Command::new("/usr/sbin/groupadd")
        .args(["--system", "memcordon"])
        .status()
        .map_err(|error| format!("could not create service group: {error}"))?;
    if !status.success() {
        return Err(format!("service group creation failed with {status}"));
    }
    // SAFETY: groupadd succeeded and name remains a live NUL-terminated lookup key.
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        return Err("service group was not visible after successful creation".to_owned());
    }
    // SAFETY: getgrnam returned a live libc-managed group record.
    Ok(unsafe { (*group).gr_gid })
}

#[cfg(target_os = "linux")]
fn systemctl<const N: usize>(arguments: [&str; N]) -> Result<(), String> {
    let status = std::process::Command::new("/usr/bin/systemctl")
        .args(arguments)
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl failed with {status}"))
    }
}

#[cfg(target_os = "linux")]
fn ensure_unit_inactive(unit: &str) -> Result<(), String> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", "--property=ActiveState", "--value", unit])
        .output()
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))?;
    if !output.status.success() {
        if unit_load_state(unit)? == "not-found" {
            return Ok(());
        }
        return Err(format!(
            "MCSEALED-PACKAGE-STOP-PROOF: systemctl show failed with {}",
            output.status
        ));
    }
    let state = std::str::from_utf8(&output.stdout)
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))?
        .trim();
    if matches!(state, "inactive" | "failed") {
        Ok(())
    } else {
        Err(format!(
            "MCSEALED-PACKAGE-STOP-PROOF: {unit} remained {state}"
        ))
    }
}

#[cfg(target_os = "linux")]
fn stop_unit(unit: &str) -> Result<(), String> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["stop", unit])
        .output()
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP: unit={unit}; invocation-error={error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let diagnostic = systemctl_output_diagnostic(&output);
    match unit_load_state(unit) {
        Ok(state) if state == "not-found" => Ok(()),
        Ok(state) => Err(format!(
            "MCSEALED-PACKAGE-STOP: unit={unit}; load-state={state}; systemctl-output={diagnostic}"
        )),
        Err(error) => Err(format!(
            "MCSEALED-PACKAGE-STOP: unit={unit}; load-state-error={error}; systemctl-output={diagnostic}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn systemctl_output_diagnostic(output: &std::process::Output) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "program": "/usr/bin/systemctl",
        "status": output.status.to_string(),
        "status_code": output.status.code(),
        "stdout": bounded_systemctl_stream(&output.stdout),
        "stderr": bounded_systemctl_stream(&output.stderr),
    })
}

#[cfg(target_os = "linux")]
fn bounded_systemctl_stream(bytes: &[u8]) -> serde_json::Value {
    use std::fmt::Write as _;

    const MAXIMUM_BYTES: usize = 4 * 1024;
    let retained = &bytes[..bytes.len().min(MAXIMUM_BYTES)];
    let truncated = retained.len() != bytes.len();
    match std::str::from_utf8(retained) {
        Ok(data) => serde_json::json!({
            "encoding": "utf-8",
            "data": data,
            "original_bytes": bytes.len(),
            "truncated": truncated,
        }),
        Err(_) => {
            let mut data = String::new();
            for byte in retained {
                write!(&mut data, "{byte:02x}").expect("writing hexadecimal to a string succeeds");
            }
            serde_json::json!({
                "encoding": "hex",
                "data": data,
                "original_bytes": bytes.len(),
                "truncated": truncated,
            })
        }
    }
}

#[cfg(target_os = "linux")]
fn unit_load_state(unit: &str) -> Result<String, String> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", "--property=LoadState", "--value", unit])
        .output()
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))?;
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))
}

#[cfg(target_os = "linux")]
fn readiness_error(cause: &str) -> String {
    const MAX_SYSTEMD_BYTES: usize = 16 * 1024;
    const MAX_JOURNAL_BYTES: usize = 32 * 1024;
    let systemd = bounded_command_diagnostic(
        "/usr/bin/systemctl",
        &[
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=ExecMainStatus",
            "memcordon-sealed-agent.service",
        ],
        MAX_SYSTEMD_BYTES,
        false,
    );
    let journal = bounded_command_diagnostic(
        "/usr/bin/journalctl",
        &[
            "--unit",
            "memcordon-sealed-agent.service",
            "--boot",
            "--no-pager",
            "--output=json",
            "--lines=50",
        ],
        MAX_JOURNAL_BYTES,
        true,
    );
    let startup = match crate::linux::startup::read() {
        Ok(Some(record)) => serde_json::to_value(record)
            .unwrap_or_else(|error| serde_json::json!({"query_error": error.to_string()})),
        Ok(None) => serde_json::Value::Null,
        Err(error) => serde_json::json!({"query_error": error}),
    };
    let diagnostics = serde_json::json!({
        "systemd": systemd,
        "startup_failure": startup,
        "journal": journal,
    });
    format!("MCSEALED-PROVIDER-READINESS: {cause}; diagnostics={diagnostics}")
}

#[cfg(target_os = "linux")]
fn bounded_command_diagnostic(
    program: &str,
    arguments: &[&str],
    maximum_bytes: usize,
    parse_json_lines: bool,
) -> serde_json::Value {
    let output = std::process::Command::new(program).args(arguments).output();
    match output {
        Ok(output) if output.stdout.len().saturating_add(output.stderr.len()) <= maximum_bytes => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let content = if parse_json_lines {
                let mut entries = Vec::new();
                for line in stdout.lines() {
                    match serde_json::from_str::<serde_json::Value>(line) {
                        Ok(entry) => entries.push(entry),
                        Err(error) => {
                            return serde_json::json!({
                                "status": output.status.code(),
                                "parse_error": error.to_string(),
                                "stderr": stderr,
                            });
                        }
                    }
                }
                serde_json::json!({"entries": entries})
            } else {
                serde_json::json!({"lines": stdout.lines().collect::<Vec<_>>()})
            };
            serde_json::json!({
                "status": output.status.code(),
                "content": content,
                "stderr": stderr,
                "truncated": false,
            })
        }
        Ok(output) => serde_json::json!({
            "status": output.status.code(),
            "error": "diagnostic exceeded bounded payload",
            "truncated": true,
        }),
        Err(error) => serde_json::json!({
            "error": error.to_string(),
            "truncated": false,
        }),
    }
}
