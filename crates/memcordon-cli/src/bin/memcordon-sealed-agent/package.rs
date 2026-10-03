use std::ffi::OsStr;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::Path;

use sha2::{Digest, Sha256};

#[cfg(not(target_os = "windows"))]
use crate::inspection_schema::ProviderPackageMetadataV4;
use crate::inspection_schema::{
    AgentInspectionFormat, AgentPackageInspection, InspectionRevision, InstalledInspectionFormat,
    InstalledProviderInspection,
};
#[cfg(target_os = "linux")]
use memcordon_core::{BoundedText, DiagnosticSha256};

const SERVICE: &str = "[Unit]\nDescription=MemCordon sealed supervision control provider\nRequires=memcordon-sealed-agent.socket memcordon-sealed-launcher.socket\nAfter=local-fs.target systemd-tmpfiles-setup.service memcordon-sealed-launcher.socket\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent serve\nUser=root\nGroup=memcordon\nKillMode=process\nStateDirectory=memcordon/sealed memcordon/policy\nStateDirectoryMode=0700\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=/run/memcordon /var/lib/memcordon/sealed /var/lib/memcordon/policy\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const SOCKET: &str = "[Unit]\nDescription=MemCordon sealed supervision control socket\nAfter=systemd-tmpfiles-setup.service\n\n[Socket]\nListenStream=/run/memcordon/sealed-agent.sock\nDirectoryMode=0755\nSocketMode=0660\nSocketUser=root\nSocketGroup=memcordon\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
const LAUNCHER_SERVICE: &str = "[Unit]\nDescription=MemCordon sealed supervision launch broker\nRequires=memcordon-sealed-launcher.socket\nAfter=local-fs.target\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent launch-broker\nUser=root\nGroup=root\nDelegate=yes\nKillMode=process\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=no\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const LAUNCHER_SOCKET: &str = "[Unit]\nDescription=MemCordon sealed supervision launch broker socket\nAfter=systemd-tmpfiles-setup.service\n\n[Socket]\nListenStream=/run/memcordon/sealed-launcher.sock\nDirectoryMode=0750\nSocketMode=0600\nSocketUser=root\nSocketGroup=root\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
// The optional private broker requires its socket and refuses manual starts.
const NETWORK_LAUNCHER_SERVICE: &str = "[Unit]\nDescription=MemCordon sealed private IPv4 launch broker\nRequires=memcordon-sealed-network-launcher.socket\nAfter=local-fs.target\nRefuseManualStart=yes\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent network-launch-broker\nUser=root\nGroup=root\nDelegate=yes\nKillMode=process\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=no\nAmbientCapabilities=\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL CAP_NET_ADMIN\nRestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const NETWORK_LAUNCHER_SOCKET: &str = "[Unit]\nDescription=MemCordon sealed private IPv4 launch broker socket\nAfter=systemd-tmpfiles-setup.service\n\n[Socket]\nListenStream=/run/memcordon/sealed-network-launcher.sock\nDirectoryMode=0750\nSocketMode=0600\nSocketUser=root\nSocketGroup=root\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
const TMPFILES: &str = "d /run/memcordon 0750 root memcordon -\nf /run/memcordon-sealed-package.lock 0600 root root -\n";

/// Export the compiled operational templates into a fresh producer-owned directory.
#[cfg(target_os = "linux")]
pub fn export_unit_files(directory: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;

    let mut held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(if directory.is_absolute() { "/" } else { "." })
        .map_err(|error| error.to_string())?;
    for component in directory.components() {
        let leaf = match component {
            Component::Normal(leaf) => leaf,
            Component::RootDir | Component::CurDir => continue,
            _ => return Err("unit export path must not contain parent components".into()),
        };
        let leaf = CString::new(leaf.as_bytes()).map_err(|error| error.to_string())?;
        let fd = unsafe {
            libc::openat(
                held.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        held = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    let metadata = held.metadata().map_err(|error| error.to_string())?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err("unit export directory must be private and owned by the producer".into());
    }
    // Enumerate the held inode, rather than reopening a potentially replaced path.
    let duplicate = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut empty = true;
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::closedir(stream) };
            if error.raw_os_error() != Some(0) {
                return Err(error.to_string());
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            empty = false;
        }
    }
    if !empty {
        return Err("unit export directory must be empty".into());
    }

    let mut units = vec![
        ("memcordon-sealed-agent.service", SERVICE),
        ("memcordon-sealed-agent.socket", SOCKET),
        ("memcordon-sealed-launcher.service", LAUNCHER_SERVICE),
        ("memcordon-sealed-launcher.socket", LAUNCHER_SOCKET),
        ("memcordon.conf", TMPFILES),
    ];
    if cfg!(feature = "private-tcp") {
        units.extend([
            (
                "memcordon-sealed-network-launcher.service",
                NETWORK_LAUNCHER_SERVICE,
            ),
            (
                "memcordon-sealed-network-launcher.socket",
                NETWORK_LAUNCHER_SOCKET,
            ),
        ]);
    }
    for (name, contents) in units {
        let destination = CString::new(name).map_err(|error| error.to_string())?;
        let temporary =
            CString::new(format!(".{name}.pending")).map_err(|error| error.to_string())?;
        let fd = unsafe {
            libc::openat(
                held.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut output = unsafe { std::fs::File::from_raw_fd(fd) };
        let result = (|| {
            output.write_all(contents.as_bytes())?;
            // Restore the exact package mode independently of the producer's umask.
            if unsafe { libc::fchmod(output.as_raw_fd(), 0o644) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            output.sync_all()?;
            if unsafe {
                libc::renameat2(
                    held.as_raw_fd(),
                    temporary.as_ptr(),
                    held.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })();
        if let Err(error) = result {
            unsafe { libc::unlinkat(held.as_raw_fd(), temporary.as_ptr(), 0) };
            return Err(error.to_string());
        }
    }
    held.sync_all().map_err(|error| error.to_string())
}
#[cfg(target_os = "linux")]
const BINARY: &str = "/usr/libexec/memcordon-sealed-agent";
#[cfg(target_os = "linux")]
const PUBLIC_CLI: &str = "/usr/libexec/memcordon";
#[cfg(target_os = "linux")]
const UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.service";
#[cfg(target_os = "linux")]
const SOCKET_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.socket";
#[cfg(target_os = "linux")]
const LAUNCHER_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-launcher.service";
#[cfg(target_os = "linux")]
const LAUNCHER_SOCKET_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-launcher.socket";
#[cfg(target_os = "linux")]
const NETWORK_LAUNCHER_UNIT: &str =
    "/usr/lib/systemd/system/memcordon-sealed-network-launcher.service";
#[cfg(target_os = "linux")]
const NETWORK_LAUNCHER_SOCKET_UNIT: &str =
    "/usr/lib/systemd/system/memcordon-sealed-network-launcher.socket";
#[cfg(target_os = "linux")]
const TMPFILES_FILE: &str = "/usr/lib/tmpfiles.d/memcordon.conf";
#[cfg(target_os = "linux")]
const LEGACY_PACKAGE_LEASE: &str = "/run/memcordon/sealed-package.lock";
#[cfg(target_os = "linux")]
const RUNTIME_DIRECTORY: &str = "/run/memcordon";
#[cfg(target_os = "linux")]
const PACKAGE_TRANSACTION_JOURNAL: &str = "/usr/libexec/.memcordon-package-transaction.json";
#[cfg(target_os = "linux")]
const PACKAGE_INSTALLATION_EPOCH: &str = "/usr/libexec/.memcordon-installation-epoch.json";

#[cfg(target_os = "linux")]
#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageInstallationEpochV1 {
    pub(crate) schema_version: u8,
    pub(crate) counter: u64,
    pub(crate) nonce_digest: DiagnosticSha256,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxSourceSnapshot {
    pub(crate) agent_bytes: Vec<u8>,
    pub(crate) public_cli_bytes: Vec<u8>,
    pub(crate) arm32_helper_bytes: Option<Vec<u8>>,
    pub(crate) manifest_bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
fn read_source_regular(path: &Path, maximum: u64, mode: u32) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("package source open {}: {error}", path.display()))?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.mode() & 0o7777 != mode
        || before.len() > maximum
    {
        return Err("package source is not an exact regular artifact".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err("package source changed during pinned readback".into());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_source_snapshot(source: &Path) -> Result<LinuxSourceSnapshot, String> {
    use memcordon_core::runtime_manifest::{RuntimeComponentRole, RuntimeManifest};
    let parent = source.parent().ok_or("package source has no parent")?;
    let agent_bytes = read_source_regular(source, 128 * 1024 * 1024, 0o755)?;
    let manifest_bytes = crate::linux::runtime_manifest::source(source, &agent_bytes)?;
    let manifest = RuntimeManifest::parse(&manifest_bytes)?;
    let public_cli = manifest
        .components
        .iter()
        .find(|component| component.role == RuntimeComponentRole::PublicCli)
        .ok_or("package source has no public CLI component")?;
    let public_cli_path = if source == Path::new(BINARY) {
        Path::new(PUBLIC_CLI).to_path_buf()
    } else {
        parent.join(&public_cli.path)
    };
    let public_cli_bytes = read_source_regular(&public_cli_path, 128 * 1024 * 1024, 0o755)?;
    if public_cli_bytes.len() as u64 != public_cli.size
        || sha256_bytes(&public_cli_bytes) != public_cli.sha256
    {
        return Err("package source public CLI bytes differ from inventory".into());
    }
    let helper = manifest
        .components
        .iter()
        .find(|component| component.role == RuntimeComponentRole::Arm32AbiHelper);
    let arm32_helper_bytes = helper
        .map(|component| -> Result<Vec<u8>, String> {
            let path = if source == Path::new(BINARY) {
                Path::new(crate::linux::runtime_manifest::INSTALLED_ARM32_HELPER).to_path_buf()
            } else {
                parent.join(&component.path)
            };
            let bytes = read_source_regular(&path, 1024 * 1024, 0o755)?;
            if bytes.len() as u64 != component.size || sha256_bytes(&bytes) != component.sha256 {
                return Err("package source helper bytes differ from inventory".into());
            }
            Ok(bytes)
        })
        .transpose()?;
    Ok(LinuxSourceSnapshot {
        agent_bytes,
        public_cli_bytes,
        arm32_helper_bytes,
        manifest_bytes,
    })
}

pub fn run(operation: &OsStr, json: bool) -> Result<(), String> {
    if operation == "inspect" {
        return render_inspection(&inspect()?, json);
    }
    if operation == "verify" {
        verify()?;
        return render_installed_inspection(&installed_inspection()?, json);
    }
    if json {
        return Err("--json is valid only for package inspect and package verify".to_owned());
    }
    #[cfg(target_os = "linux")]
    {
        linux_mutation(operation)
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows::package::mutate(operation)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err("provider package mutation is unavailable on this platform".to_owned())
    }
}

pub(crate) fn verify() -> Result<(), String> {
    verify_compiled_metadata()?;
    #[cfg(target_os = "linux")]
    match std::fs::symlink_metadata(PACKAGE_TRANSACTION_JOURNAL) {
        Ok(_) => return Err("package generation has an unrecovered transaction journal".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    #[cfg(target_os = "linux")]
    verify_installed_package()?;
    #[cfg(target_os = "windows")]
    crate::windows::package::verify_installed()?;
    Ok(())
}

fn render_inspection(inspection: &AgentPackageInspection, json: bool) -> Result<(), String> {
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
    inspection: &InstalledProviderInspection,
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
    }
    Ok(())
}

pub(crate) fn inspect() -> Result<AgentPackageInspection, String> {
    verify_compiled_metadata()?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("MCSEALED-PACKAGE-INSPECT: current executable: {error}"))?;
    let executable_sha256 = sha256_regular_no_follow(&executable)?;
    #[cfg(not(target_os = "windows"))]
    let (mechanism, platform) = (
        "linux-pid-namespace-cgroup-v2".to_owned(),
        ProviderPackageMetadataV4::LinuxSystemd {
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
    Ok(AgentPackageInspection {
        format: AgentInspectionFormat::Ordinary,
        revision: InspectionRevision,
        native_protocols: if cfg!(target_os = "windows") {
            memcordon_core::runtime_manifest::NativeProviderProtocols::Windows {
                provider_contract: 3,
                public_wire: 3,
                private_wire: 3,
            }
        } else {
            memcordon_core::runtime_manifest::NativeProviderProtocols::Linux {
                provider_contract: 3,
                launch_wire: 3,
            }
        },
        runtime_manifest_schema: 1,
        workload_contract_schema: 1,
        profile_catalog_sha256: memcordon_core::runtime_manifest::baseline_catalog_digest(cfg!(
            target_os = "windows"
        )),
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

fn installed_inspection() -> Result<InstalledProviderInspection, String> {
    let agent = inspect()?;
    #[cfg(target_os = "linux")]
    {
        let installed_executable_sha256 = sha256_regular_no_follow(std::path::Path::new(BINARY))?;
        verify_installed_executable_digest(&agent.executable_sha256, &installed_executable_sha256)?;
        let qualification = probe_provider().ok();
        let provider_reachable = qualification.is_some();
        let provider_identity = qualification.map(|value| value.provider_identity);
        let policy = match crate::policy_registry::native::Lease::acquire()
            .and_then(|lease| lease.read())
        {
            Ok(Some(activation)) => activation.inspection()?,
            Ok(None) => {
                memcordon_core::runtime_manifest::InstalledPolicyObservationV1::Unconfigured
            }
            Err(_) => memcordon_core::runtime_manifest::InstalledPolicyObservationV1::Unavailable,
        };
        Ok(InstalledProviderInspection {
            format: InstalledInspectionFormat::Ordinary,
            revision: InspectionRevision,
            agent,
            installed_executable_sha256,
            installed_artifacts_valid: true,
            provider_identity,
            provider_reachable,
            policy,
        })
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows::package::installed_inspection(agent)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(InstalledProviderInspection {
            format: InstalledInspectionFormat::Ordinary,
            revision: InspectionRevision,
            agent,
            installed_executable_sha256: String::new(),
            installed_artifacts_valid: false,
            provider_identity: None,
            provider_reachable: false,
            policy: memcordon_core::runtime_manifest::InstalledPolicyObservationV1::Unavailable,
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
        "ReadWritePaths=/run/memcordon /var/lib/memcordon/sealed /var/lib/memcordon/policy";
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
    let network_launcher_capabilities = NETWORK_LAUNCHER_SERVICE
        .lines()
        .filter(|line| line.starts_with("CapabilityBoundingSet="))
        .collect::<Vec<_>>();
    let network_launcher_ambient = NETWORK_LAUNCHER_SERVICE
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
        && NETWORK_LAUNCHER_SERVICE
            .contains("Description=MemCordon sealed private IPv4 launch broker")
        && NETWORK_LAUNCHER_SERVICE
            .contains("ExecStart=/usr/libexec/memcordon-sealed-agent network-launch-broker")
        && NETWORK_LAUNCHER_SERVICE.contains("Requires=memcordon-sealed-network-launcher.socket")
        && NETWORK_LAUNCHER_SERVICE.contains("RefuseManualStart=yes")
        && NETWORK_LAUNCHER_SERVICE.contains("User=root")
        && NETWORK_LAUNCHER_SERVICE.contains("Group=root")
        && NETWORK_LAUNCHER_SERVICE.contains("Delegate=yes")
        && NETWORK_LAUNCHER_SERVICE.contains("NoNewPrivileges=no")
        && NETWORK_LAUNCHER_SERVICE.contains("RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK")
        && !NETWORK_LAUNCHER_SERVICE.contains("CAP_NET_RAW")
        && !NETWORK_LAUNCHER_SERVICE.contains("RuntimeDirectory=")
        && !NETWORK_LAUNCHER_SERVICE.contains("RuntimeDirectoryMode=")
        && network_launcher_capabilities
            == [
                "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL CAP_NET_ADMIN",
            ]
        && network_launcher_ambient == ["AmbientCapabilities="]
        && NETWORK_LAUNCHER_SOCKET
            .contains("ListenStream=/run/memcordon/sealed-network-launcher.sock")
        && NETWORK_LAUNCHER_SOCKET.contains("After=systemd-tmpfiles-setup.service")
        && NETWORK_LAUNCHER_SOCKET.contains("DirectoryMode=0750")
        && NETWORK_LAUNCHER_SOCKET.contains("SocketMode=0600")
        && NETWORK_LAUNCHER_SOCKET.contains("SocketUser=root")
        && NETWORK_LAUNCHER_SOCKET.contains("SocketGroup=root")
        && TMPFILES
            == "d /run/memcordon 0750 root memcordon -\nf /run/memcordon-sealed-package.lock 0600 root root -\n"
    {
        Ok(())
    } else {
        Err("compiled split-service metadata is inconsistent".to_owned())
    }
}

#[cfg(test)]
pub(crate) fn network_launcher_templates_for_test() -> (&'static str, &'static str) {
    (NETWORK_LAUNCHER_SERVICE, NETWORK_LAUNCHER_SOCKET)
}

#[cfg(test)]
pub(crate) fn verify_compiled_metadata_for_test() -> Result<(), String> {
    verify_compiled_metadata()
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
    let packaged_executable = inspect()?;
    verify_installed_package_against(&packaged_executable.executable_sha256)
}

#[cfg(target_os = "linux")]
fn verify_installed_package_against(packaged_executable_sha256: &str) -> Result<(), String> {
    verify_metadata_artifact(
        std::path::Path::new(crate::linux::service::PACKAGE_LEASE),
        0,
        0,
        0o600,
    )?;

    let installed_executable_sha256 = sha256_regular_no_follow(std::path::Path::new(BINARY))?;
    verify_installed_executable_digest(packaged_executable_sha256, &installed_executable_sha256)?;

    let artifacts = [
        (BINARY, 0o755, None),
        (PUBLIC_CLI, 0o755, None),
        (UNIT, 0o644, Some(SERVICE.as_bytes())),
        (SOCKET_UNIT, 0o644, Some(SOCKET.as_bytes())),
        (LAUNCHER_UNIT, 0o644, Some(LAUNCHER_SERVICE.as_bytes())),
        (
            LAUNCHER_SOCKET_UNIT,
            0o644,
            Some(LAUNCHER_SOCKET.as_bytes()),
        ),
        (
            NETWORK_LAUNCHER_UNIT,
            0o644,
            Some(NETWORK_LAUNCHER_SERVICE.as_bytes()),
        ),
        (
            NETWORK_LAUNCHER_SOCKET_UNIT,
            0o644,
            Some(NETWORK_LAUNCHER_SOCKET.as_bytes()),
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
struct PackageFileChange {
    path: std::path::PathBuf,
    bytes: Option<Vec<u8>>,
    mode: u32,
}

#[cfg(target_os = "linux")]
struct AppliedPackageFileChange {
    path: std::path::PathBuf,
    backup: Option<tempfile::TempPath>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageJournalEntry {
    pub(crate) path: std::path::PathBuf,
    pub(crate) backup: Option<std::path::PathBuf>,
    pub(crate) old_sha256: Option<DiagnosticSha256>,
    pub(crate) old_device: Option<u64>,
    pub(crate) old_inode: Option<u64>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageJournal {
    pub(crate) schema_version: u8,
    pub(crate) entries: Vec<PackageJournalEntry>,
}

#[cfg(target_os = "linux")]
struct PackageFileTransaction {
    applied: Vec<AppliedPackageFileChange>,
    directories: CreatedPackageDirectories,
    journal: PackageJournal,
    published: bool,
    postimages: Vec<PackagePostimage>,
}

#[cfg(target_os = "linux")]
struct PackagePostimage {
    path: std::path::PathBuf,
    identity: Option<(u64, u64, u32, DiagnosticSha256)>,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct CreatedPackageDirectories {
    paths: Vec<std::path::PathBuf>,
    keep: bool,
}

#[cfg(target_os = "linux")]
impl CreatedPackageDirectories {
    fn cleanup(&mut self) -> Result<(), String> {
        while let Some(path) = self.paths.pop() {
            if let Err(error) = std::fs::remove_dir(&path) {
                self.paths.push(path);
                return Err(error.to_string());
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for CreatedPackageDirectories {
    fn drop(&mut self) {
        if !self.keep {
            for path in self.paths.drain(..).rev() {
                let _ = std::fs::remove_dir(path);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn ensure_protected_package_parent(
    path: &Path,
    directories: &mut CreatedPackageDirectories,
) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let parent = path.parent().ok_or("package artifact has no parent")?;
    let mut current = std::path::PathBuf::from("/");
    for component in parent.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        current.push(name);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    return Err(format!(
                        "package artifact parent is not root-protected: {}",
                        current.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .mode(0o755)
                    .create(&current)
                    .map_err(|error| error.to_string())?;
                directories.paths.push(current.clone());
                let metadata =
                    std::fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
                if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o755 {
                    return Err("created package directory protection differs".into());
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_package_parent(path: &Path) -> Result<(), String> {
    std::fs::File::open(path.parent().ok_or("package artifact has no parent")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
const PACKAGE_ARTIFACT_PATHS: &[&str] = &[
    BINARY,
    PUBLIC_CLI,
    UNIT,
    SOCKET_UNIT,
    LAUNCHER_UNIT,
    LAUNCHER_SOCKET_UNIT,
    NETWORK_LAUNCHER_UNIT,
    NETWORK_LAUNCHER_SOCKET_UNIT,
    TMPFILES_FILE,
    crate::linux::runtime_manifest::INSTALLED,
    crate::linux::runtime_manifest::INSTALLED_ARM32_HELPER,
];

#[cfg(target_os = "linux")]
fn allowed_journal_target(path: &Path) -> bool {
    PACKAGE_ARTIFACT_PATHS
        .iter()
        .any(|expected| path == Path::new(expected))
}

#[cfg(target_os = "linux")]
fn protected_file_digest(path: &Path) -> Result<DiagnosticSha256, String> {
    DiagnosticSha256::try_from(
        BoundedText::<64>::new(&sha256_regular_no_follow(path)?).map_err(str::to_owned)?,
    )
    .map_err(str::to_owned)
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_package_journal(journal: &PackageJournal) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    if journal.schema_version != 1
        || journal.entries.is_empty()
        || journal.entries.len() > PACKAGE_ARTIFACT_PATHS.len()
    {
        return Err("package transaction journal inventory differs".into());
    }
    for entry in &journal.entries {
        if !allowed_journal_target(&entry.path)
            || !seen.insert(&entry.path)
            || entry.backup.is_some() != entry.old_sha256.is_some()
            || entry.backup.is_some() != entry.old_device.is_some()
            || entry.backup.is_some() != entry.old_inode.is_some()
        {
            return Err("package transaction journal target differs".into());
        }
        if let Some(backup) = &entry.backup {
            if backup.parent() != entry.path.parent()
                || !backup
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".memcordon-backup-"))
            {
                return Err("package transaction journal backup path differs".into());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_package_journal(journal: &PackageJournal) -> Result<(), String> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    validate_package_journal(journal)?;
    let path = Path::new(PACKAGE_TRANSACTION_JOURNAL);
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Err("unrecovered package transaction journal exists".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let bytes = serde_json::to_vec(journal).map_err(|error| error.to_string())?;
    if bytes.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
        return Err("package transaction journal exceeds byte bound".into());
    }
    let mut stage = tempfile::Builder::new()
        .prefix(".memcordon-journal-")
        .tempfile_in(path.parent().expect("fixed journal parent"))
        .map_err(|error| error.to_string())?;
    // SAFETY: the open staging file is exclusively owned by this root installer.
    if unsafe { libc::fchown(stage.as_file().as_raw_fd(), 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    stage.write_all(&bytes).map_err(|error| error.to_string())?;
    stage
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    stage
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    std::fs::rename(stage.path(), path).map_err(|error| error.to_string())?;
    sync_package_parent(path)
}

#[cfg(target_os = "linux")]
fn clear_package_journal() -> Result<(), String> {
    let path = Path::new(PACKAGE_TRANSACTION_JOURNAL);
    crate::linux::protected_read::read_protected_absolute(
        path,
        memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
        Some(0o600),
    )?;
    std::fs::remove_file(path).map_err(|error| error.to_string())?;
    sync_package_parent(path)
}

#[cfg(target_os = "linux")]
fn read_installation_epoch() -> Result<Option<(PackageInstallationEpochV1, Vec<u8>)>, String> {
    let path = Path::new(PACKAGE_INSTALLATION_EPOCH);
    let bytes = match std::fs::symlink_metadata(path) {
        Ok(_) => crate::linux::protected_read::read_protected_absolute(
            path,
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
            Some(0o600),
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let epoch: PackageInstallationEpochV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if epoch.schema_version != 1
        || epoch.counter == 0
        || epoch.nonce_digest == DiagnosticSha256::from_bytes([0; 32])
        || serde_json::to_vec(&epoch).map_err(|error| error.to_string())? != bytes
    {
        return Err("package installation epoch differs from canonical record".into());
    }
    Ok(Some((epoch, bytes)))
}

#[cfg(target_os = "linux")]
pub(crate) fn next_installation_epoch(
    previous: Option<&PackageInstallationEpochV1>,
    nonce: [u8; 32],
) -> Result<PackageInstallationEpochV1, String> {
    let counter = previous.map_or(Ok(1), |epoch| {
        epoch.counter.checked_add(1).ok_or("package epoch overflow")
    })?;
    Ok(PackageInstallationEpochV1 {
        schema_version: 1,
        counter,
        nonce_digest: memcordon_core::workload_codec::hash_bytes(&nonce),
    })
}

/// Read the protected package-generation identity. Callers must
/// retain a shared or exclusive package lease across this read and admission.
#[cfg(target_os = "linux")]
pub(crate) fn installed_generation_epoch() -> Result<DiagnosticSha256, String> {
    let (_, bytes) = read_installation_epoch()?
        .ok_or("protected package installation epoch is absent; re-install or upgrade")?;
    Ok(memcordon_core::workload_codec::hash_bytes(&bytes))
}

#[cfg(target_os = "linux")]
fn advance_installation_epoch() -> Result<DiagnosticSha256, String> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;

    let previous = read_installation_epoch()?;
    let mut nonce = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut nonce))
        .map_err(|error| format!("package epoch entropy unavailable: {error}"))?;
    let epoch = next_installation_epoch(previous.as_ref().map(|(epoch, _)| epoch), nonce)?;
    let bytes = serde_json::to_vec(&epoch).map_err(|error| error.to_string())?;
    let path = Path::new(PACKAGE_INSTALLATION_EPOCH);
    let mut directories = CreatedPackageDirectories::default();
    ensure_protected_package_parent(path, &mut directories)?;
    let mut stage = tempfile::Builder::new()
        .prefix(".memcordon-epoch-")
        .tempfile_in(path.parent().expect("fixed epoch parent"))
        .map_err(|error| error.to_string())?;
    // SAFETY: the staged epoch descriptor remains live in this root installer.
    if unsafe { libc::fchown(stage.as_file().as_raw_fd(), 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    stage.write_all(&bytes).map_err(|error| error.to_string())?;
    stage
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    stage
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    std::fs::rename(stage.path(), path).map_err(|error| error.to_string())?;
    sync_package_parent(path)?;
    directories.keep = true;
    let (_, readback) = read_installation_epoch()?.ok_or("package epoch vanished after write")?;
    if readback != bytes {
        return Err("package epoch changed during protected readback".into());
    }
    Ok(memcordon_core::workload_codec::hash_bytes(&bytes))
}

#[cfg(target_os = "linux")]
fn recover_package_journal() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let path = Path::new(PACKAGE_TRANSACTION_JOURNAL);
    let bytes = match std::fs::symlink_metadata(path) {
        Ok(_) => crate::linux::protected_read::read_protected_absolute(
            path,
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
            Some(0o600),
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let journal: PackageJournal =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    validate_package_journal(&journal)?;
    for unit in [
        "memcordon-sealed-network-launcher.service",
        "memcordon-sealed-network-launcher.socket",
        "memcordon-sealed-agent.service",
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-agent.socket",
        "memcordon-sealed-launcher.socket",
    ] {
        stop_unit(unit)?;
    }
    ensure_recovery_idle("recover package transaction")?;
    for entry in journal.entries.iter().rev() {
        if let (Some(backup), Some(old_sha256)) = (&entry.backup, &entry.old_sha256) {
            let original_matches = |path: &Path| -> Result<bool, String> {
                let metadata = match std::fs::symlink_metadata(path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                    Err(error) => return Err(error.to_string()),
                };
                Ok(metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.nlink() == 1
                    && Some(metadata.dev()) == entry.old_device
                    && Some(metadata.ino()) == entry.old_inode
                    && protected_file_digest(path)? == *old_sha256)
            };
            let backup_present = match std::fs::symlink_metadata(backup) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.to_string()),
            };
            if original_matches(backup)? {
                std::fs::rename(backup, &entry.path).map_err(|error| error.to_string())?;
            } else if original_matches(&entry.path)? {
                if backup_present {
                    std::fs::remove_file(backup).map_err(|error| error.to_string())?;
                }
            } else {
                return Err("package transaction backup and old artifact both differ".into());
            }
        } else {
            match std::fs::remove_file(&entry.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        sync_package_parent(&entry.path)?;
    }
    systemctl(["daemon-reload"])?;
    clear_package_journal()
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_install_is_new(operation: &OsStr, installed: bool) -> Result<(), String> {
    if operation == "install" && installed {
        return Err(
            "provider is already installed; use package upgrade for a quiesced replacement".into(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_install_preflight(
    operation: &OsStr,
    journal_pending: bool,
    installed: bool,
) -> Result<(), String> {
    if operation != "install" {
        return Ok(());
    }
    if journal_pending {
        return Err("package install requires recovery of a pending transaction first".into());
    }
    ensure_install_is_new(operation, installed)
}

#[cfg(target_os = "linux")]
impl PackageFileTransaction {
    fn apply(changes: Vec<PackageFileChange>) -> Result<Self, String> {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mut staged = Vec::with_capacity(changes.len());
        let mut directories = CreatedPackageDirectories::default();
        for change in changes {
            ensure_protected_package_parent(&change.path, &mut directories)?;
            let stage = if let Some(bytes) = &change.bytes {
                let parent = change.path.parent().expect("protected parent");
                let mut stage =
                    tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
                // SAFETY: the temporary file descriptor remains live, and the
                // installer is root under the exclusive package-generation lock.
                if unsafe { libc::fchown(stage.as_file().as_raw_fd(), 0, 0) } == -1 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                stage.write_all(bytes).map_err(|error| error.to_string())?;
                stage
                    .as_file()
                    .set_permissions(std::fs::Permissions::from_mode(change.mode))
                    .map_err(|error| error.to_string())?;
                stage
                    .as_file()
                    .sync_all()
                    .map_err(|error| error.to_string())?;
                Some(stage)
            } else {
                None
            };
            let identity = match &stage {
                Some(stage) => {
                    let metadata = stage
                        .as_file()
                        .metadata()
                        .map_err(|error| error.to_string())?;
                    Some((
                        metadata.dev(),
                        metadata.ino(),
                        change.mode,
                        memcordon_core::workload_codec::hash_bytes(
                            change.bytes.as_ref().expect("staged bytes are present"),
                        ),
                    ))
                }
                None => None,
            };
            staged.push((change.path, stage, identity));
        }
        let mut prepared = Vec::with_capacity(staged.len());
        let mut journal_entries = Vec::with_capacity(staged.len());
        for (path, stage, identity) in staged {
            let parent = path.parent().expect("protected parent");
            let (backup, old_sha256, old_device, old_inode) = match std::fs::symlink_metadata(&path)
            {
                Ok(metadata) => {
                    if !metadata.is_file()
                        || metadata.uid() != 0
                        || metadata.nlink() != 1
                        || metadata.mode() & 0o022 != 0
                    {
                        return Err("existing package artifact is not root-protected".into());
                    }
                    let old_sha256 = protected_file_digest(&path)?;
                    let backup = tempfile::Builder::new()
                        .prefix(".memcordon-backup-")
                        .tempfile_in(parent)
                        .map_err(|error| error.to_string())?
                        .into_temp_path();
                    (
                        Some(backup),
                        Some(old_sha256),
                        Some(metadata.dev()),
                        Some(metadata.ino()),
                    )
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    (None, None, None, None)
                }
                Err(error) => return Err(error.to_string()),
            };
            journal_entries.push(PackageJournalEntry {
                path: path.clone(),
                backup: backup.as_ref().map(|value| value.to_path_buf()),
                old_sha256,
                old_device,
                old_inode,
            });
            prepared.push((path, stage, backup, identity));
        }
        let journal = PackageJournal {
            schema_version: 1,
            entries: journal_entries,
        };
        if let Err(error) = write_package_journal(&journal) {
            // A directory fsync can fail after the journal rename. In that
            // state its recorded backup names must outlive these TempPaths so
            // the next locked mutation can inspect/recover the transaction.
            if std::fs::symlink_metadata(PACKAGE_TRANSACTION_JOURNAL).is_ok() {
                for (_, _, backup, _) in &mut prepared {
                    if let Some(backup) = backup.take() {
                        backup.keep().map_err(|keep_error| {
                            format!("journal write failed: {error}; backup retain: {keep_error}")
                        })?;
                    }
                }
                directories.keep = true;
            }
            return Err(error);
        }
        let mut transaction = Self {
            applied: Vec::with_capacity(prepared.len()),
            directories,
            journal,
            published: false,
            postimages: Vec::new(),
        };
        for (path, stage, backup, identity) in prepared {
            transaction.postimages.push(PackagePostimage {
                path: path.clone(),
                identity,
            });
            let result = (|| {
                if let Some(backup) = &backup {
                    std::fs::rename(&path, backup).map_err(|error| error.to_string())?;
                }
                transaction.applied.push(AppliedPackageFileChange {
                    path: path.clone(),
                    backup,
                });
                if let Some(stage) = stage {
                    std::fs::rename(stage.path(), &path).map_err(|error| error.to_string())?;
                }
                sync_package_parent(&path)
            })();
            if let Err(error) = result {
                return match transaction.rollback() {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(format!("{error}; package rollback failed: {rollback}")),
                };
            }
        }
        Ok(transaction)
    }

    fn rollback(mut self) -> Result<(), String> {
        if self.published {
            let compensation = (|| {
                self.verify_postimages()?;
                for entry in &self.journal.entries {
                    if let Some(backup) = &entry.backup {
                        use std::os::unix::fs::MetadataExt;
                        let metadata =
                            std::fs::symlink_metadata(backup).map_err(|error| error.to_string())?;
                        if !metadata.is_file()
                            || metadata.uid() != 0
                            || metadata.nlink() != 1
                            || metadata.mode() & 0o022 != 0
                            || Some(metadata.dev()) != entry.old_device
                            || Some(metadata.ino()) != entry.old_inode
                            || Some(protected_file_digest(backup)?) != entry.old_sha256
                        {
                            return Err("package compensation backup identity differs".into());
                        }
                    }
                }
                // Publication removed the original journal. Restore authority
                // comes only from this fresh, validated, durable transaction.
                write_package_journal(&self.journal)
            })();
            if let Err(error) = compensation {
                self.retain_backups()?;
                return Err(format!("package compensation refused: {error}"));
            }
        }
        let mut failures = Vec::new();
        for applied in self.applied.drain(..).rev() {
            match std::fs::remove_file(&applied.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => failures.push(error.to_string()),
            }
            if let Some(backup) = applied.backup {
                if let Err(error) = std::fs::rename(&backup, &applied.path) {
                    failures.push(error.to_string());
                    if let Err(keep_error) = backup.keep() {
                        failures.push(format!("could not retain rollback backup: {keep_error}"));
                    }
                }
            }
            if let Err(error) = sync_package_parent(&applied.path) {
                failures.push(error);
            }
        }
        if failures.is_empty() {
            self.directories.cleanup()?;
            clear_package_journal()
        } else {
            Err(failures.join("; "))
        }
    }

    fn retain_backups(&mut self) -> Result<(), String> {
        self.directories.keep = true;
        let mut failures = Vec::new();
        for applied in &mut self.applied {
            if let Some(backup) = applied.backup.take() {
                if let Err(mut error) = backup.keep() {
                    // PathPersistError owns the still-temporary path; dropping
                    // it must not erase evidence referenced by a crash journal.
                    error.path.disable_cleanup(true);
                    failures.push(error.to_string());
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "package backup retention failed: {}",
                failures.join("; ")
            ))
        }
    }

    fn verify_postimages(&self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        for image in &self.postimages {
            let metadata = match std::fs::symlink_metadata(&image.path) {
                Ok(metadata) => Some(metadata),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.to_string()),
            };
            match (&image.identity, metadata) {
                (None, None) => {}
                (Some((device, inode, mode, digest)), Some(metadata))
                    if metadata.is_file()
                        && metadata.uid() == 0
                        && metadata.nlink() == 1
                        && metadata.dev() == *device
                        && metadata.ino() == *inode
                        && metadata.mode() & 0o7777 == *mode
                        && protected_file_digest(&image.path)? == *digest => {}
                _ => return Err("package published postimage identity differs".into()),
            }
        }
        Ok(())
    }

    fn publish(mut self) -> Result<Self, String> {
        let publish = (|| {
            self.verify_postimages()?;
            clear_package_journal()
        })();
        if let Err(error) = publish {
            self.retain_backups()?;
            return Err(format!("package publication failed: {error}"));
        }
        self.published = true;
        self.directories.keep = true;
        Ok(self)
    }

    fn commit(mut self) -> Result<(), String> {
        if !self.published {
            self = self.publish()?;
        }
        self.directories.keep = true;
        for applied in self.applied.drain(..) {
            drop(applied.backup);
            sync_package_parent(&applied.path)?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn linux_mutation(operation: &OsStr) -> Result<(), String> {
    use std::fs;
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
    // An already installed generation must not lose its epoch merely because
    // a caller used install instead of the quiesced upgrade.
    // A pending journal is a separate fail-closed state for install; upgrade
    // and uninstall retain the locked recovery path below.
    let journal_pending = match fs::symlink_metadata(PACKAGE_TRANSACTION_JOURNAL) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.to_string()),
    };
    let installed_before_mutation = match fs::symlink_metadata(BINARY) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.to_string()),
    };
    ensure_install_preflight(operation, journal_pending, installed_before_mutation)?;
    let preflight_source = if operation == "uninstall" {
        None
    } else {
        Some(linux_source_snapshot(
            &std::env::current_exe().map_err(|error| error.to_string())?,
        )?)
    };
    recover_package_journal()?;
    // This is intentionally outside the rollback set: an interrupted or
    // byte-identical replacement may never resurrect an older detached run.
    advance_installation_epoch()?;
    let existing_installation = match fs::symlink_metadata(BINARY) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.to_string()),
    };
    ensure_install_is_new(operation, existing_installation)?;
    let source_snapshot = preflight_source;
    if operation == "uninstall" {
        ensure_recovery_idle("uninstall")?;
        stop_unit("memcordon-sealed-network-launcher.service")?;
        stop_unit("memcordon-sealed-network-launcher.socket")?;
        disable_optional_network_launcher()?;
        stop_unit("memcordon-sealed-agent.service")?;
        stop_unit("memcordon-sealed-launcher.service")?;
        stop_unit("memcordon-sealed-agent.socket")?;
        stop_unit("memcordon-sealed-launcher.socket")?;
        ensure_unit_inactive("memcordon-sealed-agent.service")?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.socket")?;
        ensure_unit_inactive("memcordon-sealed-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-agent.socket")?;
        ensure_unit_inactive("memcordon-sealed-launcher.socket")?;
        ensure_recovery_idle("uninstall")?;
        let mut removals = Vec::new();
        for path in [
            SOCKET_UNIT,
            UNIT,
            LAUNCHER_SOCKET_UNIT,
            LAUNCHER_UNIT,
            NETWORK_LAUNCHER_SOCKET_UNIT,
            NETWORK_LAUNCHER_UNIT,
            TMPFILES_FILE,
            BINARY,
            PUBLIC_CLI,
            crate::linux::runtime_manifest::INSTALLED_ARM32_HELPER,
            crate::linux::runtime_manifest::INSTALLED,
        ] {
            match fs::symlink_metadata(path) {
                Ok(_) => removals.push(PackageFileChange {
                    path: Path::new(path).to_path_buf(),
                    bytes: None,
                    mode: 0,
                }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("could not inspect {path}: {error}")),
            }
        }
        if !removals.is_empty() {
            let transaction = PackageFileTransaction::apply(removals)?;
            if let Err(error) = systemctl(["daemon-reload"]) {
                return match transaction.rollback() {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(format!(
                        "{error}; package uninstall rollback failed: {rollback}"
                    )),
                };
            }
            transaction.commit()?;
        } else {
            systemctl(["daemon-reload"])?;
        }
        remove_uninstalled_file(LEGACY_PACKAGE_LEASE)?;
        crate::linux::startup::clear()?;
        for path in [crate::linux::CGROUP_ROOT, RUNTIME_DIRECTORY] {
            remove_uninstalled_directory(path)?;
        }
        // Retain unrelated state rather than deleting nonempty directories.
        match fs::read_dir(crate::linux::STATE_ROOT) {
            Ok(mut entries) => {
                if entries.next().is_none() {
                    remove_uninstalled_directory(crate::linux::STATE_ROOT)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        // This is the final uninstall mutation. The open exclusive lease remains locked until
        // return, while unlinking prevents the package lock itself becoming residual state.
        remove_uninstalled_file(crate::linux::service::PACKAGE_LEASE)?;
        return Ok(());
    }
    if operation == "upgrade" {
        ensure_recovery_idle("upgrade")?;
        stop_unit("memcordon-sealed-network-launcher.service")?;
        stop_unit("memcordon-sealed-network-launcher.socket")?;
        disable_optional_network_launcher()?;
        stop_unit("memcordon-sealed-agent.service")?;
        stop_unit("memcordon-sealed-launcher.service")?;
        stop_unit("memcordon-sealed-agent.socket")?;
        stop_unit("memcordon-sealed-launcher.socket")?;
        ensure_unit_inactive("memcordon-sealed-agent.service")?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.socket")?;
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
    let source_snapshot = source_snapshot.expect("uninstall returned before installation");
    let source_digest = sha256_bytes(&source_snapshot.agent_bytes);
    let mut changes = Vec::new();
    let helper_path = Path::new(crate::linux::runtime_manifest::INSTALLED_ARM32_HELPER);
    if source_snapshot.arm32_helper_bytes.is_some() || fs::symlink_metadata(helper_path).is_ok() {
        changes.push(PackageFileChange {
            path: helper_path.to_path_buf(),
            bytes: source_snapshot.arm32_helper_bytes.clone(),
            mode: 0o755,
        });
    }
    for (path, bytes, mode) in [
        (BINARY, source_snapshot.agent_bytes, 0o755),
        (PUBLIC_CLI, source_snapshot.public_cli_bytes, 0o755),
        (UNIT, SERVICE.as_bytes().to_vec(), 0o644),
        (SOCKET_UNIT, SOCKET.as_bytes().to_vec(), 0o644),
        (LAUNCHER_UNIT, LAUNCHER_SERVICE.as_bytes().to_vec(), 0o644),
        (
            LAUNCHER_SOCKET_UNIT,
            LAUNCHER_SOCKET.as_bytes().to_vec(),
            0o644,
        ),
        (
            NETWORK_LAUNCHER_UNIT,
            NETWORK_LAUNCHER_SERVICE.as_bytes().to_vec(),
            0o644,
        ),
        (
            NETWORK_LAUNCHER_SOCKET_UNIT,
            NETWORK_LAUNCHER_SOCKET.as_bytes().to_vec(),
            0o644,
        ),
        (TMPFILES_FILE, TMPFILES.as_bytes().to_vec(), 0o644),
        (
            crate::linux::runtime_manifest::INSTALLED,
            source_snapshot.manifest_bytes.clone(),
            0o644,
        ),
    ] {
        changes.push(PackageFileChange {
            path: Path::new(path).to_path_buf(),
            bytes: Some(bytes),
            mode,
        });
    }
    let transaction = PackageFileTransaction::apply(changes)?;
    let prepared = (|| {
        verify_installed_package_against(&source_digest)?;
        let installed_snapshot = linux_source_snapshot(Path::new(BINARY))?;
        if installed_snapshot.manifest_bytes != source_snapshot.manifest_bytes
            || installed_snapshot.arm32_helper_bytes != source_snapshot.arm32_helper_bytes
        {
            return Err("installed runtime inventory or ARM32 helper differs from source".into());
        }
        systemctl(["daemon-reload"])?;
        disable_optional_network_launcher()?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.socket")?;
        Ok::<(), String>(())
    })();
    if let Err(error) = prepared {
        let rollback = transaction.rollback();
        let reload = systemctl(["daemon-reload"]);
        return Err(format!(
            "package install/upgrade failed: {error}; rollback: {rollback:?}; daemon reload: {reload:?}"
        ));
    }
    // Runtime verification must see a durably published generation, never an
    // in-progress journal. Retain old files for validated compensation until
    // both readiness and ordinary-client access have succeeded.
    let transaction = activate_published_package(
        || transaction.publish(),
        || {
            systemctl(["enable", "--now", "memcordon-sealed-launcher.socket"])?;
            systemctl(["enable", "--now", "memcordon-sealed-agent.socket"])?;
            systemctl(["restart", "memcordon-sealed-launcher.service"])?;
            systemctl(["restart", "memcordon-sealed-agent.service"])?;
            wait_provider_ready()?;
            // Root deliberately bypasses ordinary directory and socket ACL checks.
            verify_client_access_configuration()
        },
        |mut transaction| {
            let quiesced = {
                let mut failures = Vec::new();
                for unit in [
                    "memcordon-sealed-network-launcher.service",
                    "memcordon-sealed-network-launcher.socket",
                    "memcordon-sealed-agent.service",
                    "memcordon-sealed-launcher.service",
                    "memcordon-sealed-agent.socket",
                    "memcordon-sealed-launcher.socket",
                ] {
                    if let Err(error) = stop_unit(unit) {
                        failures.push(error);
                    }
                    if let Err(error) = ensure_unit_inactive(unit) {
                        failures.push(error);
                    }
                }
                if let Err(error) = ensure_recovery_idle("compensate package activation") {
                    failures.push(error);
                }
                if failures.is_empty() {
                    Ok(())
                } else {
                    Err(failures.join("; "))
                }
            };
            if let Err(error) = quiesced {
                transaction.retain_backups()?;
                return Err(format!("package compensation quiescence failed: {error}"));
            }
            transaction.rollback()?;
            systemctl(["daemon-reload"])
        },
    )?;
    transaction.commit().map_err(|error| {
        format!("package generation published and activated; backup cleanup failed: {error}")
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn activate_published_package<T>(
    publish: impl FnOnce() -> Result<T, String>,
    activate: impl FnOnce() -> Result<(), String>,
    compensate: impl FnOnce(T) -> Result<(), String>,
) -> Result<T, String> {
    let published = publish()?;
    if let Err(error) = activate() {
        let compensation = compensate(published);
        return Err(format!(
            "package activation failed: {error}; compensation: {compensation:?}"
        ));
    }
    Ok(published)
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
fn verify_client_access_configuration() -> Result<(), String> {
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
pub fn probe_provider() -> Result<crate::linux::qualification::ReadinessObservation, String> {
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
    crate::linux::qualification::ReadinessObservation::parse(&receipt.payload)
        .map_err(|error| readiness_error(&error))
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
    if !state_root.exists() {
        return Ok(false);
    }
    if let Some(entry) = std::fs::read_dir(state_root)
        .map_err(|error| error.to_string())?
        .next()
    {
        entry.map_err(|error| error.to_string())?;
        return Ok(true);
    }
    Ok(false)
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
fn disable_optional_network_launcher() -> Result<(), String> {
    for (unit, path) in [
        (
            "memcordon-sealed-network-launcher.socket",
            NETWORK_LAUNCHER_SOCKET_UNIT,
        ),
        (
            "memcordon-sealed-network-launcher.service",
            NETWORK_LAUNCHER_UNIT,
        ),
    ] {
        if std::path::Path::new(path)
            .try_exists()
            .map_err(|error| error.to_string())?
        {
            systemctl(["disable", "--now", unit])?;
            ensure_unit_inactive(unit)?;
        }
    }
    Ok(())
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
            "--since=-5min",
            "--no-pager",
            "--output=json",
            "--output-fields=MESSAGE,_PID,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,__REALTIME_TIMESTAMP,PRIORITY",
            "--lines=20",
        ],
        MAX_JOURNAL_BYTES,
        true,
    );
    // A reset at the control plane only identifies a failed broker exchange.
    // Preserve the launcher's rejection/startup cause before rollback stops it.
    // Invocation ids, pids and timestamps correlate recent startup attempts;
    // do not include command lines, environment or credential metadata.
    let launcher_systemd = bounded_command_diagnostic(
        "/usr/bin/systemctl",
        &[
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=ExecMainStatus",
            "memcordon-sealed-launcher.service",
        ],
        MAX_SYSTEMD_BYTES,
        false,
    );
    let launcher_journal = bounded_command_diagnostic(
        "/usr/bin/journalctl",
        &[
            "--unit",
            "memcordon-sealed-launcher.service",
            "--boot",
            "--since=-5min",
            "--no-pager",
            "--output=json",
            "--output-fields=MESSAGE,_PID,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,__REALTIME_TIMESTAMP,PRIORITY",
            "--lines=20",
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
        "launcher_systemd": launcher_systemd,
        "launcher_journal": launcher_journal,
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
