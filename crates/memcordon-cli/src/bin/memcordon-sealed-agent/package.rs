use std::ffi::OsStr;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::inspection_schema::{
    AgentInspectionFormat, AgentPackageInspectionV2, InspectionRevisionTwo,
    InstalledProviderInspectionV2,
};
#[cfg(not(target_os = "windows"))]
use crate::inspection_schema::{InstalledInspectionFormat, ProviderPackageMetadataV5};
#[cfg(target_os = "linux")]
use memcordon_core::{BoundedText, DiagnosticSha256};

const SERVICE: &str = "[Unit]\nDescription=MemCordon sealed supervision control provider\nRequires=memcordon-sealed-agent.socket memcordon-sealed-launcher.socket\nAfter=local-fs.target systemd-tmpfiles-setup.service memcordon-sealed-launcher.socket\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent serve\nUser=root\nGroup=memcordon\nKillMode=process\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=/run/memcordon /var/lib/memcordon/sealed\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const SOCKET: &str = "[Unit]\nDescription=MemCordon sealed supervision control socket\nAfter=systemd-tmpfiles-setup.service\n\n[Socket]\nListenStream=/run/memcordon/sealed-agent.sock\nDirectoryMode=0755\nSocketMode=0660\nSocketUser=root\nSocketGroup=memcordon\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
const LAUNCHER_SERVICE: &str = "[Unit]\nDescription=MemCordon sealed supervision launch broker\nRequires=memcordon-sealed-launcher.socket\nAfter=local-fs.target\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent launch-broker\nUser=root\nGroup=root\nDelegate=yes\nKillMode=process\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=no\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const LAUNCHER_SOCKET: &str = "[Unit]\nDescription=MemCordon sealed supervision launch broker socket\nAfter=systemd-tmpfiles-setup.service\n\n[Socket]\nListenStream=/run/memcordon/sealed-launcher.sock\nDirectoryMode=0750\nSocketMode=0600\nSocketUser=root\nSocketGroup=root\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
// The optional private broker requires its socket and refuses manual starts.
const NETWORK_LAUNCHER_SERVICE: &str = "[Unit]\nDescription=MemCordon sealed private IPv4 launch broker\nRequires=memcordon-sealed-network-launcher.socket\nAfter=local-fs.target\nRefuseManualStart=yes\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent network-launch-broker\nUser=root\nGroup=root\nDelegate=yes\nKillMode=process\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=no\nAmbientCapabilities=\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL CAP_NET_ADMIN CAP_MKNOD\nRestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
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
pub(crate) const PUBLIC_CLI: &str = "/usr/libexec/memcordon";
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
#[cfg(target_os = "linux")]
const RUNTIME_DIRECTORY: &str = "/run/memcordon";
#[cfg(target_os = "linux")]
const PACKAGE_TRANSACTION_JOURNAL: &str =
    "/usr/libexec/.memcordon-current-package-transaction.json";
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
    use memcordon_core::runtime_components::RuntimeComponentRole;
    use memcordon_core::runtime_manifest_v2::RuntimeManifestV2 as RuntimeManifest;
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
    if !["install", "upgrade", "inspect", "verify", "uninstall"]
        .into_iter()
        .any(|name| operation == name)
    {
        return Err("unknown package operation".into());
    }
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
        linux_mutation(operation, None)
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

#[cfg(target_os = "linux")]
pub fn uninstall_until(deadline: &OsStr) -> Result<(), String> {
    mutation_until(OsStr::new("uninstall"), deadline)
}
#[cfg(target_os = "linux")]
pub fn upgrade_until(deadline: &OsStr) -> Result<(), String> {
    mutation_until(OsStr::new("upgrade"), deadline)
}
#[cfg(target_os = "linux")]
fn mutation_until(operation: &OsStr, deadline: &OsStr) -> Result<(), String> {
    let cutoff = deadline
        .to_str()
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|cutoff| *cutoff != 0)
        .ok_or_else(|| "invalid original package cleanup monotonic cutoff".to_owned())?;
    linux_mutation(operation, Some(cutoff))
}

#[cfg(target_os = "linux")]
#[path = "package_uninstall.rs"]
mod uninstall_transaction;

pub(crate) fn verify() -> Result<(), String> {
    verify_compiled_metadata()?;
    #[cfg(target_os = "linux")]
    match std::fs::symlink_metadata(PACKAGE_TRANSACTION_JOURNAL) {
        Ok(_) => {
            let bytes = crate::linux::protected_read::read_protected_absolute(
                Path::new(PACKAGE_TRANSACTION_JOURNAL),
                memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
                Some(0o600),
            )?;
            memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
            let journal: PackageJournal =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            validate_package_journal(&journal)?;
            if journal.phase == PackageJournalPhase::Preparing {
                return Err("package generation has an unrecovered transaction journal".into());
            }
            validate_package_postimages(&journal)?;
            if journal.phase == PackageJournalPhase::Published {
                validate_package_recovery_files(&journal)?;
            } else {
                validate_package_backup_retirement_files(&journal)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
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
        ProviderPackageMetadataV5::LinuxSystemd {
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
        format: AgentInspectionFormat::Ordinary,
        revision: InspectionRevisionTwo,
        native_protocols: if cfg!(target_os = "windows") {
            memcordon_core::runtime_components::NativeProviderProtocols::Windows {
                provider_contract: 4,
                public_wire: 4,
                private_wire: 4,
            }
        } else {
            memcordon_core::runtime_components::NativeProviderProtocols::Linux {
                provider_contract: 3,
                launch_wire: if cfg!(feature = "private-tcp") { 5 } else { 3 },
            }
        },
        runtime_manifest_revision: 2,
        workload_request: memcordon_core::runtime_manifest_v2::WireVersion {
            format: "memcordon.workload-request".into(),
            revision: 1,
        },
        result: memcordon_core::runtime_manifest_v2::WireVersion {
            format: "memcordon.result".into(),
            revision: 3,
        },
        capabilities: memcordon_core::runtime_manifest_v2::WireVersion {
            format: "memcordon.capabilities".into(),
            revision: 3,
        },
        plan: memcordon_core::runtime_manifest_v2::WireVersion {
            format: "memcordon.plan".into(),
            revision: 3,
        },
        runtime_profile: if cfg!(target_os = "windows") {
            "windows-sealed-current-token-v1"
        } else if cfg!(feature = "private-tcp") {
            "linux-private-workload-v1"
        } else {
            memcordon_core::workload_request::LINUX_CREDENTIAL_PRESERVING_PROFILE
        }
        .into(),
        profile_revision: 1,
        profile_supported: (cfg!(target_os = "linux")
            && cfg!(any(target_arch = "x86_64", target_arch = "aarch64")))
            || (cfg!(target_os = "windows")
                && cfg!(feature = "windows-sealed-runtime")
                && cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        source_commit: crate::SOURCE_COMMIT.to_owned(),
        executable_sha256,
        provider_protocol: if cfg!(target_os = "windows") {
            memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION
        } else {
            u32::from(crate::protocol::PROTOCOL_VERSION)
        },
        mechanism,
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
        let provider_identity = qualification.map(|value| value.provider_identity);
        Ok(InstalledProviderInspectionV2 {
            format: InstalledInspectionFormat::Ordinary,
            revision: InspectionRevisionTwo,
            agent,
            installed_executable_sha256,
            installed_artifacts_valid: true,
            provider_identity,
            provider_reachable,
        })
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows::package::installed_inspection(agent)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(InstalledProviderInspectionV2 {
            format: InstalledInspectionFormat::Ordinary,
            revision: InspectionRevisionTwo,
            agent,
            installed_executable_sha256: String::new(),
            installed_artifacts_valid: false,
            provider_identity: None,
            provider_reachable: false,
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
                "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL CAP_NET_ADMIN CAP_MKNOD",
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
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    match std::fs::symlink_metadata("/run/memcordon") {
        Ok(metadata)
            if metadata.file_type().is_dir()
                && metadata.uid() == 0
                && metadata.mode() & 0o7777 == 0o750 =>
        {
            return Ok(());
        }
        Ok(_) => return Err("provider runtime path is not a real directory".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir("/run/memcordon").map_err(|error| error.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/memcordon")
        .map_err(|error| error.to_string())?;
    held.set_permissions(std::fs::Permissions::from_mode(0o750))
        .map_err(|error| error.to_string())?;
    let metadata = std::fs::symlink_metadata("/run/memcordon")
        .map_err(|error| format!("provider runtime directory unavailable: {error}"))?;
    let pinned = held.metadata().map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o7777 != 0o750
        || (metadata.dev(), metadata.ino()) != (pinned.dev(), pinned.ino())
    {
        return Err("provider runtime directory identity or mode is unsafe".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_current_state_directory(
    path: &Path,
    current_owned: bool,
    allowed: &[&str],
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let metadata = match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
        Ok(metadata) => metadata,
    };
    if !current_owned {
        return Err(format!(
            "unmanaged occupied current state directory: {}",
            path.display()
        ));
    }
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err("current state directory custody differs".into());
    }
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    let pinned = held.metadata().map_err(|error| error.to_string())?;
    let mut count = 0;
    for entry in std::fs::read_dir(path).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        count += 1;
        let name = entry.file_name();
        let current_attempt = path == Path::new(RUNTIME_DIRECTORY)
            && name.to_str().is_some_and(|name| {
                name.strip_prefix("private-root-")
                    .is_some_and(crate::linux::cgroup::valid_attempt_identity)
            });
        if count > allowed.len() + crate::linux::workload_attempt::MAX_RETAINED_ATTEMPTS
            || (!current_attempt && !name.to_str().is_some_and(|name| allowed.contains(&name)))
        {
            return Err("unknown occupied current state entry; retained intact".into());
        }
    }
    let after = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if (metadata.dev(), metadata.ino()) != (pinned.dev(), pinned.ino())
        || (metadata.dev(), metadata.ino()) != (after.dev(), after.ino())
    {
        return Err("current state root replaced during inventory".into());
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
#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageJournalEntry {
    pub(crate) path: std::path::PathBuf,
    pub(crate) backup: Option<std::path::PathBuf>,
    pub(crate) old_sha256: Option<DiagnosticSha256>,
    pub(crate) old_device: Option<u64>,
    pub(crate) old_inode: Option<u64>,
    pub(crate) stage: Option<PackageJournalFile>,
    pub(crate) placeholder: Option<PackageJournalFile>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageJournalFile {
    pub(crate) path: std::path::PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) mode: u32,
    pub(crate) sha256: DiagnosticSha256,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageJournal {
    pub(crate) format: String,
    pub(crate) revision: u8,
    pub(crate) phase: PackageJournalPhase,
    pub(crate) entries: Vec<PackageJournalEntry>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PackageJournalPhase {
    Preparing,
    Published,
    Retiring,
}

#[cfg(target_os = "linux")]
struct PackageFileTransaction {
    cutoff: std::time::Instant,
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
    let mut temporary_paths = std::collections::BTreeSet::new();
    if journal.format != "memcordon.current-package-transaction"
        || journal.revision != 1
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
            || entry.backup.is_some() != entry.placeholder.is_some()
            || entry.old_inode.is_some_and(|inode| inode == 0)
        {
            return Err("package transaction journal target differs".into());
        }
        for (file, prefix) in [
            (entry.stage.as_ref(), ".memcordon-stage-"),
            (entry.placeholder.as_ref(), ".memcordon-backup-"),
        ] {
            if let Some(file) = file {
                if file.path.parent() != entry.path.parent()
                    || file.inode == 0
                    || file.mode & !0o7777 != 0
                    || file.mode & 0o022 != 0
                    || !file
                        .path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with(prefix))
                {
                    return Err("current package temporary inode inventory differs".into());
                }
            }
        }
        if entry.placeholder.as_ref().is_some_and(|placeholder| {
            Some(&placeholder.path) != entry.backup.as_ref()
                || placeholder.mode != 0o600
                || placeholder.sha256 != memcordon_core::hash_bytes(&[])
        }) {
            return Err("current package backup placeholder inventory differs".into());
        }
        if let Some(backup) = &entry.backup {
            if !temporary_paths.insert(backup.clone())
                || backup.parent() != entry.path.parent()
                || !backup
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".memcordon-backup-"))
            {
                return Err("package transaction journal backup path differs".into());
            }
        }
        if entry
            .stage
            .as_ref()
            .is_some_and(|stage| !temporary_paths.insert(stage.path.clone()))
        {
            return Err("current package staging path is duplicated".into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_package_journal(journal: &PackageJournal) -> Result<(), String> {
    write_package_journal_inner(journal, false)
}
#[cfg(target_os = "linux")]
fn write_package_journal_inner(journal: &PackageJournal, replace: bool) -> Result<(), String> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    validate_package_journal(journal)?;
    let path = Path::new(PACKAGE_TRANSACTION_JOURNAL);
    match std::fs::symlink_metadata(path) {
        Ok(_) if !replace => return Err("unrecovered package transaction journal exists".into()),
        Ok(_) => {}
        Err(error) if replace && error.kind() == std::io::ErrorKind::NotFound => {
            return Err(
                "owned current package journal disappeared before phase publication".into(),
            );
        }
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
fn advance_package_journal(
    previous: &PackageJournal,
    phase: PackageJournalPhase,
) -> Result<PackageJournal, String> {
    let bytes = crate::linux::protected_read::read_protected_absolute(
        Path::new(PACKAGE_TRANSACTION_JOURNAL),
        memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
        Some(0o600),
    )?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
    let current: PackageJournal =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if current != *previous {
        return Err("current package journal changed before phase publication; retained".into());
    }
    validate_package_postimages(previous)?;
    let mut next = previous.clone();
    next.phase = phase;
    write_package_journal_inner(&next, true)?;
    Ok(next)
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
fn package_file_present(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}
#[cfg(target_os = "linux")]
fn package_file_matches(path: &Path, file: &PackageJournalFile) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    Ok(metadata.is_file()
        && metadata.uid() == 0
        && metadata.nlink() == 1
        && metadata.dev() == file.device
        && metadata.ino() == file.inode
        && metadata.mode() & 0o7777 == file.mode
        && protected_file_digest(path)? == file.sha256)
}
#[cfg(target_os = "linux")]
fn package_original_matches(path: &Path, entry: &PackageJournalEntry) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    Ok(metadata.is_file()
        && metadata.uid() == 0
        && metadata.nlink() == 1
        && metadata.mode() & 0o022 == 0
        && Some(metadata.dev()) == entry.old_device
        && Some(metadata.ino()) == entry.old_inode
        && Some(protected_file_digest(path)?) == entry.old_sha256)
}
#[cfg(target_os = "linux")]
pub(crate) fn validate_package_recovery_files(journal: &PackageJournal) -> Result<(), String> {
    for entry in &journal.entries {
        let old = package_original_matches(&entry.path, entry)?;
        let post = entry
            .stage
            .as_ref()
            .map(|stage| package_file_matches(&entry.path, stage))
            .transpose()?
            .unwrap_or(false);
        if package_file_present(&entry.path)? && !old && !post {
            return Err("occupied package artifact is neither exact original nor owned current postimage; retained".into());
        }
        if let Some(stage) = &entry.stage {
            if package_file_present(&stage.path)? && !package_file_matches(&stage.path, stage)? {
                return Err("current package staging inode was replaced; retained".into());
            }
        }
        if let Some(backup) = &entry.backup {
            let saved = package_original_matches(backup, entry)?;
            let placeholder = entry
                .placeholder
                .as_ref()
                .map(|file| package_file_matches(backup, file))
                .transpose()?
                .unwrap_or(false);
            if package_file_present(backup)? && !saved && !placeholder {
                return Err("current package backup inode was replaced; retained".into());
            }
            if !saved && !old {
                return Err(
                    "current package original artifact is absent or changed; retained".into(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_package_postimages(journal: &PackageJournal) -> Result<(), String> {
    for entry in &journal.entries {
        match &entry.stage {
            Some(stage) if package_file_matches(&entry.path, stage)? => {}
            None if !package_file_present(&entry.path)? => {}
            _ => return Err("published current package postimage differs; retained".into()),
        }
        if let Some(stage) = &entry.stage {
            if package_file_present(&stage.path)? {
                return Err("published current package staging name remains allocated".into());
            }
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn validate_package_backup_retirement_files(journal: &PackageJournal) -> Result<(), String> {
    validate_package_postimages(journal)?;
    for entry in &journal.entries {
        if let Some(backup) = &entry.backup {
            if package_file_present(backup)? && !package_original_matches(backup, entry)? {
                return Err("current package retirement backup was replaced; retained".into());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn retire_package_backups(
    journal: &PackageJournal,
    cutoff: std::time::Instant,
) -> Result<(), String> {
    validate_package_backup_retirement_files(journal)?;
    for entry in &journal.entries {
        check_package_cutoff(cutoff)?;
        if let Some(backup) = &entry.backup {
            if package_file_present(backup)? {
                if !package_original_matches(backup, entry)? {
                    return Err("current package backup changed during retirement; retained".into());
                }
                std::fs::remove_file(backup).map_err(|error| error.to_string())?;
                sync_package_parent(backup)?;
            }
        }
    }
    check_package_cutoff(cutoff)?;
    clear_package_journal()
}

#[cfg(target_os = "linux")]
fn recover_package_journal(cutoff: std::time::Instant) -> Result<(), String> {
    check_package_cutoff(cutoff)?;
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
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
    let journal: PackageJournal =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    validate_package_journal(&journal)?;
    if journal.phase == PackageJournalPhase::Retiring {
        validate_package_postimages(&journal)?;
    } else {
        validate_package_recovery_files(&journal)?;
    }
    for unit in [
        "memcordon-sealed-network-launcher.service",
        "memcordon-sealed-network-launcher.socket",
        "memcordon-sealed-agent.service",
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-agent.socket",
        "memcordon-sealed-launcher.socket",
    ] {
        stop_unit(unit, cutoff)?;
    }
    ensure_recovery_idle_until("recover package transaction", cutoff)?;
    if journal.phase == PackageJournalPhase::Retiring {
        retire_package_backups(&journal, cutoff)?;
        return systemctl(cutoff, ["daemon-reload"]);
    }
    for entry in journal.entries.iter().rev() {
        check_package_cutoff(cutoff)?;
        if let Some(backup) = &entry.backup {
            if package_original_matches(backup, entry)? {
                std::fs::rename(backup, &entry.path).map_err(|error| error.to_string())?;
            } else if package_original_matches(&entry.path, entry)? {
                if package_file_present(backup)? {
                    if !package_file_matches(
                        backup,
                        entry
                            .placeholder
                            .as_ref()
                            .ok_or("current backup placeholder identity absent")?,
                    )? {
                        return Err(
                            "current package backup placeholder changed during recovery; retained"
                                .into(),
                        );
                    }
                    std::fs::remove_file(backup).map_err(|error| error.to_string())?;
                }
            } else {
                return Err("package transaction backup and old artifact both differ".into());
            }
        } else {
            if package_file_present(&entry.path)? {
                if !entry
                    .stage
                    .as_ref()
                    .map(|stage| package_file_matches(&entry.path, stage))
                    .transpose()?
                    .unwrap_or(false)
                {
                    return Err("current fresh postimage changed during recovery; retained".into());
                }
                std::fs::remove_file(&entry.path).map_err(|error| error.to_string())?;
            }
        }
        if let Some(stage) = &entry.stage {
            if package_file_present(&stage.path)? {
                if !package_file_matches(&stage.path, stage)? {
                    return Err("current staged inode changed during recovery; retained".into());
                }
                std::fs::remove_file(&stage.path).map_err(|error| error.to_string())?;
            }
        }
        sync_package_parent(&entry.path)?;
    }
    systemctl(cutoff, ["daemon-reload"])?;
    check_package_cutoff(cutoff)?;
    clear_package_journal()
}

#[cfg(target_os = "linux")]
fn ensure_no_unowned_package_temporaries() -> Result<(), String> {
    for parent in [
        "/usr/libexec",
        "/usr/lib/systemd/system",
        "/usr/lib/tmpfiles.d",
    ] {
        let entries = match std::fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
        };
        for (count, entry) in entries.enumerate() {
            if count >= 16384 {
                return Err("current package directory inventory exceeds bound".into());
            }
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".memcordon-stage-")
                || name.starts_with(".memcordon-backup-")
                || name.starts_with(".memcordon-journal-")
            {
                return Err(format!(
                    "unowned occupied current package temporary retained: {}",
                    entry.path().display()
                ));
            }
        }
    }
    Ok(())
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
    fn apply(changes: Vec<PackageFileChange>, cutoff: std::time::Instant) -> Result<Self, String> {
        check_package_cutoff(cutoff)?;
        use std::io::Write;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mut staged = Vec::with_capacity(changes.len());
        let mut directories = CreatedPackageDirectories::default();
        for change in changes {
            check_package_cutoff(cutoff)?;
            ensure_protected_package_parent(&change.path, &mut directories)?;
            let stage = if let Some(bytes) = &change.bytes {
                let parent = change.path.parent().expect("protected parent");
                let mut stage = tempfile::Builder::new()
                    .prefix(".memcordon-stage-")
                    .tempfile_in(parent)
                    .map_err(|error| error.to_string())?;
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
                        memcordon_core::hash_bytes(
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
                stage: match (&stage, &identity) {
                    (Some(stage), Some((device, inode, mode, sha256))) => {
                        Some(PackageJournalFile {
                            path: stage.path().to_path_buf(),
                            device: *device,
                            inode: *inode,
                            mode: *mode,
                            sha256: sha256.clone(),
                        })
                    }
                    (None, None) => None,
                    _ => return Err("current package staging identity missing".into()),
                },
                placeholder: match &backup {
                    Some(backup) => {
                        let metadata =
                            std::fs::symlink_metadata(backup).map_err(|error| error.to_string())?;
                        Some(PackageJournalFile {
                            path: backup.to_path_buf(),
                            device: metadata.dev(),
                            inode: metadata.ino(),
                            mode: metadata.mode() & 0o7777,
                            sha256: protected_file_digest(backup)?,
                        })
                    }
                    None => None,
                },
            });
            prepared.push((path, stage, backup, identity));
        }
        let journal = PackageJournal {
            format: "memcordon.current-package-transaction".into(),
            revision: 1,
            phase: PackageJournalPhase::Preparing,
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
            cutoff,
            applied: Vec::with_capacity(prepared.len()),
            directories,
            journal,
            published: false,
            postimages: Vec::new(),
        };
        for (path, stage, backup, identity) in prepared {
            if let Err(error) = check_package_cutoff(cutoff) {
                transaction.retain_backups()?;
                return Err(error);
            }
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
                Ok::<(), String>(())
            })();
            if let Err(error) = compensation {
                self.retain_backups()?;
                return Err(format!("package compensation refused: {error}"));
            }
        }
        self.retain_backups()?;
        recover_package_journal(self.cutoff)?;
        self.directories.cleanup()
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
        // The durable journal owns these names from this point onward. Rust
        // unwinding or a failed phase publication must never unlink backups.
        self.retain_backups()?;
        check_package_cutoff(self.cutoff)?;
        let publish = (|| {
            self.verify_postimages()?;
            self.journal = advance_package_journal(&self.journal, PackageJournalPhase::Published)?;
            Ok::<(), String>(())
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
        self.retain_backups()?;
        check_package_cutoff(self.cutoff)?;
        self.journal = advance_package_journal(&self.journal, PackageJournalPhase::Retiring)?;
        retire_package_backups(&self.journal, self.cutoff)
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct PackageDrainGuard<'a> {
    current: &'a std::fs::File,
}

/// Exercise the real commit error path without mutating an installed package.
/// The exhausted cutoff must preserve this already journal-owned backup even
/// before any protected journal access can occur.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn expired_package_commit_with_backup_for_test(
    backup: tempfile::TempPath,
) -> Result<(), String> {
    PackageFileTransaction {
        cutoff: std::time::Instant::now(),
        applied: vec![AppliedPackageFileChange {
            path: std::path::PathBuf::from(BINARY),
            backup: Some(backup),
        }],
        directories: CreatedPackageDirectories::default(),
        journal: PackageJournal {
            format: "memcordon.current-package-transaction".into(),
            revision: 1,
            phase: PackageJournalPhase::Published,
            entries: Vec::new(),
        },
        published: true,
        postimages: Vec::new(),
    }
    .commit()
}
#[cfg(target_os = "linux")]
impl PackageDrainGuard<'_> {
    pub(crate) fn validate(&self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        for file in [self.current] {
            let metadata = file.metadata().map_err(|e| e.to_string())?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
            {
                return Err("original exclusive package lease custody changed".into());
            }
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn linux_mutation(operation: &OsStr, lease_deadline: Option<u64>) -> Result<(), String> {
    use std::fs;
    use std::path::Path;
    let account_started = std::time::Instant::now();
    let account_allowance = match lease_deadline {
        Some(deadline) => std::time::Duration::from_nanos(
            deadline.saturating_sub(crate::linux::clock::monotonic_nanos()?),
        ),
        None => std::time::Duration::from_secs(30),
    };
    let account_cutoff = account_started
        .checked_add(account_allowance)
        .ok_or("package account operation cutoff exceeds native range")?;
    let cutoff = account_cutoff;

    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::geteuid() } != 0 {
        return Err("package mutation requires root".to_owned());
    }
    if operation != "install" && operation != "upgrade" && operation != "uninstall" {
        return Err("unknown package operation".to_owned());
    }
    let acquire = || {
        if let Some(deadline) = lease_deadline {
            return crate::linux::service::acquire_package_lease_until(deadline);
        }
        crate::linux::service::acquire_package_lease()
    };
    let _package_lease = acquire().map_err(|error| {
        format!("refusing package mutation while a sealed provider attempt is active: {error}")
    })?;
    let drain_guard = PackageDrainGuard {
        current: &_package_lease,
    };
    drain_guard.validate()?;
    // Unknown occupied package state is never adopted by a fresh installer.
    // Only the current transaction journal authorizes interrupted recovery.
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
    if !installed_before_mutation && !journal_pending {
        for path in PACKAGE_ARTIFACT_PATHS {
            match fs::symlink_metadata(path) {
                Ok(_) => return Err(format!("unmanaged occupied package path: {path}")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
    }
    if installed_before_mutation && !journal_pending {
        crate::linux::runtime_manifest::installed_binding()
            .map_err(|error| format!("incompatible occupied provider installation: {error}"))?;
    }
    if journal_pending {
        let bytes = crate::linux::protected_read::read_protected_absolute(
            Path::new(PACKAGE_TRANSACTION_JOURNAL),
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
            Some(0o600),
        )?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
        let journal: PackageJournal =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        validate_package_journal(&journal)?;
    }
    let current_account = if cfg!(feature = "private-tcp") {
        crate::linux::workload_account::has_current_installation_state()?
    } else {
        false
    };
    let current_state_owned = installed_before_mutation || journal_pending || current_account;
    validate_current_state_directory(
        Path::new("/run/memcordon"),
        current_state_owned,
        &[
            "sealed-agent.sock",
            "sealed-launcher.sock",
            "sealed-network-launcher.sock",
            "sealed-startup-failure.json",
        ],
    )?;
    validate_current_state_directory(
        Path::new("/var/lib/memcordon"),
        current_state_owned,
        &[
            "sealed",
            "workload-account.json",
            "workload-account.pending",
            "workload-attempts",
            "workload-inputs",
            "workload-resources",
        ],
    )?;
    prepare_runtime_directory()?;
    let preflight_source = if operation == "uninstall" {
        None
    } else {
        Some(linux_source_snapshot(
            &std::env::current_exe().map_err(|error| error.to_string())?,
        )?)
    };
    recover_package_journal(cutoff)?;
    ensure_no_unowned_package_temporaries()?;
    if operation == "upgrade" || operation == "uninstall" {
        crate::linux::workload_recovery::drain_for_package_until(&drain_guard, account_cutoff)?;
    }
    let existing_installation = match fs::symlink_metadata(BINARY) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.to_string()),
    };
    ensure_install_is_new(operation, existing_installation)?;
    let source_snapshot = preflight_source;
    if operation == "uninstall" {
        ensure_recovery_idle_until("uninstall", cutoff)?;
        stop_unit("memcordon-sealed-network-launcher.service", cutoff)?;
        stop_unit("memcordon-sealed-network-launcher.socket", cutoff)?;
        disable_optional_network_launcher(cutoff)?;
        stop_unit("memcordon-sealed-agent.service", cutoff)?;
        stop_unit("memcordon-sealed-launcher.service", cutoff)?;
        stop_unit("memcordon-sealed-agent.socket", cutoff)?;
        stop_unit("memcordon-sealed-launcher.socket", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-agent.service", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.service", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.socket", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-launcher.service", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-agent.socket", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-launcher.socket", cutoff)?;
        ensure_recovery_idle_until("uninstall", cutoff)?;
        // Unknown runtime outputs must refuse uninstall while the complete
        // installed provider is still available for their original recovery.
        crate::linux::startup::clear()?;
        for path in [crate::linux::CGROUP_ROOT, RUNTIME_DIRECTORY] {
            remove_uninstalled_directory(path)?;
        }
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
        let transaction = if !removals.is_empty() {
            Some(PackageFileTransaction::apply(removals, cutoff)?)
        } else {
            None
        };
        uninstall_transaction::finish(
            transaction,
            || {
                systemctl(cutoff, ["daemon-reload"])?;
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
                Ok(())
            },
            |transaction| {
                transaction
                    .map(PackageFileTransaction::commit)
                    .transpose()
                    .map(|_| ())
            },
            |transaction| {
                transaction
                    .map(PackageFileTransaction::rollback)
                    .transpose()
                    .map(|_| ())
            },
            || systemctl(cutoff, ["daemon-reload"]),
        )?;
        if cfg!(feature = "private-tcp") {
            crate::linux::workload_account::uninstall(account_cutoff)?;
        }
        // Keep one stable coordination inode across package generations. Unlinking
        // a locked file would let a concurrent mutator acquire a different lock.
        return Ok(());
    }
    if operation == "upgrade" {
        ensure_recovery_idle_until("upgrade", cutoff)?;
        stop_unit("memcordon-sealed-network-launcher.service", cutoff)?;
        stop_unit("memcordon-sealed-network-launcher.socket", cutoff)?;
        disable_optional_network_launcher(cutoff)?;
        stop_unit("memcordon-sealed-agent.service", cutoff)?;
        stop_unit("memcordon-sealed-launcher.service", cutoff)?;
        stop_unit("memcordon-sealed-agent.socket", cutoff)?;
        stop_unit("memcordon-sealed-launcher.socket", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-agent.service", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.service", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.socket", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-launcher.service", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-agent.socket", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-launcher.socket", cutoff)?;
        ensure_recovery_idle_until("upgrade", cutoff)?;
    }
    verify_compiled_metadata()?;
    let service_gid = ensure_service_group(cutoff)?;
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
    let transaction = PackageFileTransaction::apply(changes, cutoff)?;
    let prepared = (|| {
        if cfg!(feature = "private-tcp") {
            crate::linux::workload_account::install(account_cutoff, current_state_owned)?;
        }
        verify_installed_package_against(&source_digest)?;
        let installed_snapshot = linux_source_snapshot(Path::new(BINARY))?;
        if installed_snapshot.manifest_bytes != source_snapshot.manifest_bytes
            || installed_snapshot.arm32_helper_bytes != source_snapshot.arm32_helper_bytes
        {
            return Err("installed runtime inventory or ARM32 helper differs from source".into());
        }
        systemctl(cutoff, ["daemon-reload"])?;
        disable_optional_network_launcher(cutoff)?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.service", cutoff)?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.socket", cutoff)?;
        Ok::<(), String>(())
    })();
    if let Err(error) = prepared {
        let rollback = transaction.rollback();
        let reload = systemctl(cutoff, ["daemon-reload"]);
        return Err(format!(
            "package install/upgrade failed: {error}; rollback: {rollback:?}; daemon reload: {reload:?}"
        ));
    }
    // Publish exact current postimages before runtime verification. Keep the
    // current journal and original inodes through verification and durable
    // retirement so a controller crash cannot orphan backup authority.
    let transaction = activate_published_package(
        || transaction.publish(),
        || {
            systemctl(
                cutoff,
                ["enable", "--now", "memcordon-sealed-launcher.socket"],
            )?;
            systemctl(cutoff, ["enable", "--now", "memcordon-sealed-agent.socket"])?;
            systemctl(cutoff, ["restart", "memcordon-sealed-launcher.service"])?;
            systemctl(cutoff, ["restart", "memcordon-sealed-agent.service"])?;
            wait_provider_ready(cutoff)?;
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
                    if let Err(error) = stop_unit(unit, cutoff) {
                        failures.push(error);
                    }
                    if let Err(error) = ensure_unit_inactive(unit, cutoff) {
                        failures.push(error);
                    }
                }
                if let Err(error) =
                    ensure_recovery_idle_until("compensate package activation", cutoff)
                {
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
            systemctl(cutoff, ["daemon-reload"])
        },
    )?;
    transaction.commit().map_err(|error| {
        format!("package generation published and activated; backup cleanup failed: {error}")
    })?;
    if operation == "upgrade" {}
    Ok(())
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
        Err(error) => {
            use std::os::unix::fs::MetadataExt;
            let mut members = Vec::new();
            let mut truncated = false;
            let observation = match std::fs::read_dir(path) {
                Ok(mut entries) => {
                    for entry in entries.by_ref().take(16) {
                        match entry {
                            Ok(entry) => {
                                let name = entry.file_name();
                                let displayed: String =
                                    name.to_string_lossy().chars().take(128).collect();
                                let name_truncated = name.to_string_lossy().chars().count() > 128;
                                match std::fs::symlink_metadata(entry.path()) {
                                    Ok(metadata) => members.push(format!(
                                        "name={displayed:?},name-truncated={name_truncated},device={},inode={},mode={},uid={},length={}",
                                        metadata.dev(), metadata.ino(), metadata.mode(), metadata.uid(), metadata.len()
                                    )),
                                    Err(cause) => members.push(format!(
                                        "name={displayed:?},name-truncated={name_truncated},metadata-error={cause}"
                                    )),
                                }
                            }
                            Err(cause) => members.push(format!("entry-error={cause}")),
                        }
                    }
                    truncated = entries.next().is_some();
                    "observed".to_owned()
                }
                Err(cause) => format!("unavailable: {cause}"),
            };
            Err(format!(
                "provider uninstall found residual state in {path}: {error}; residual-observation={observation}; members={members:?}; members-truncated={truncated}"
            ))
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_recovery_idle(operation: &str) -> Result<(), String> {
    ensure_recovery_idle_until(
        operation,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
}
#[cfg(target_os = "linux")]
fn ensure_recovery_idle_until(operation: &str, cutoff: std::time::Instant) -> Result<(), String> {
    let ambiguous = crate::linux::recovery::recover_until(cutoff)?;
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
fn check_package_cutoff(cutoff: std::time::Instant) -> Result<(), String> {
    if std::time::Instant::now() >= cutoff {
        Err("original package operation cutoff exhausted; current custody retained".into())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct PackageDeadlineStream {
    stream: std::os::unix::net::UnixStream,
    cutoff: std::time::Instant,
}

#[cfg(target_os = "linux")]
fn connect_package_probe_until(
    cutoff: std::time::Instant,
) -> Result<std::os::unix::net::UnixStream, String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: scalar socket arguments request a fresh, nonblocking owned socket.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: successful socket creation transferred this descriptor to us.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: zero is a valid empty native sockaddr storage initialization.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path = c"/run/memcordon/sealed-agent.sock".to_bytes_with_nul();
    for (target, source) in address.sun_path.iter_mut().zip(path) {
        *target = *source as libc::c_char;
    }
    let length =
        libc::socklen_t::try_from(std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len())
            .map_err(|error| error.to_string())?;
    loop {
        check_package_cutoff(cutoff)?;
        // SAFETY: address contains the exact bounded native pathname and fd is live.
        if unsafe { libc::connect(fd.as_raw_fd(), (&raw const address).cast(), length) } == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EISCONN) => break,
            Some(libc::EAGAIN | libc::EINPROGRESS | libc::EALREADY | libc::EINTR) => {
                std::thread::sleep(
                    std::time::Duration::from_millis(5)
                        .min(cutoff.saturating_duration_since(std::time::Instant::now())),
                )
            }
            _ => return Err(error.to_string()),
        }
    }
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
impl std::io::Read for PackageDeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .cutoff
            .saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original package probe cutoff exhausted",
            ));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        std::io::Read::read(&mut self.stream, bytes)
    }
}

#[cfg(target_os = "linux")]
impl std::io::Write for PackageDeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = self
            .cutoff
            .saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original package probe cutoff exhausted",
            ));
        }
        self.stream.set_write_timeout(Some(remaining))?;
        std::io::Write::write(&mut self.stream, bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.stream)
    }
}

#[cfg(target_os = "linux")]
pub fn probe_provider() -> Result<crate::linux::qualification::ReadinessObservation, String> {
    probe_provider_until(std::time::Instant::now() + std::time::Duration::from_secs(60))
}

#[cfg(target_os = "linux")]
fn probe_provider_until(
    cutoff: std::time::Instant,
) -> Result<crate::linux::qualification::ReadinessObservation, String> {
    use crate::protocol::{Frame, MessageKind, read_frame, write_frame};

    check_package_cutoff(cutoff)?;
    let stream = connect_package_probe_until(cutoff)
        .map_err(|error| readiness_error(&error.to_string(), cutoff))?;
    let mut stream = PackageDeadlineStream { stream, cutoff };
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
    .map_err(|error| readiness_error(&error.to_string(), cutoff))?;
    let receipt =
        read_frame(&mut stream).map_err(|error| readiness_error(&error.to_string(), cutoff))?;
    check_package_cutoff(cutoff)?;
    if receipt.nonce != nonce || receipt.attempt_id != [0; 16] {
        return Err(readiness_error("response identity mismatch", cutoff));
    }
    if receipt.kind == MessageKind::Rejected {
        let reason = std::str::from_utf8(&receipt.payload).map_err(|error| {
            readiness_error(&format!("invalid rejection payload: {error}"), cutoff)
        })?;
        return Err(readiness_error(
            &format!("provider rejected probe: {reason}"),
            cutoff,
        ));
    }
    if receipt.kind != MessageKind::ProbeReceipt {
        return Err(readiness_error("unexpected response kind", cutoff));
    }
    crate::linux::qualification::ReadinessObservation::parse(&receipt.payload)
        .map_err(|error| readiness_error(&error, cutoff))
}

#[cfg(target_os = "linux")]
fn wait_provider_ready(cutoff: std::time::Instant) -> Result<(), String> {
    let _qualification = probe_provider_until(cutoff)?;
    if live_attempt_exists()? {
        return Err(readiness_error("provider is not idle", cutoff));
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
fn ensure_service_group(cutoff: std::time::Instant) -> Result<libc::gid_t, String> {
    let name = std::ffi::CString::new("memcordon").expect("static group name has no NUL");
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if !group.is_null() {
        // SAFETY: getgrnam returned a live libc-managed group record.
        return Ok(unsafe { (*group).gr_gid });
    }
    let output = package_command_until("/usr/sbin/groupadd", &["--system", "memcordon"], cutoff)
        .map_err(|error| format!("could not create service group: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "service group creation failed with {}",
            output.status
        ));
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
fn systemctl<const N: usize>(
    cutoff: std::time::Instant,
    arguments: [&str; N],
) -> Result<(), String> {
    let output = package_command_until("/usr/bin/systemctl", &arguments, cutoff)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl failed: {}",
            systemctl_output_diagnostic(&output)
        ))
    }
}

/// Capture a native child without letting its pipe buffers or process wait
/// extend the original package operation. A timeout never claims restoration.
#[cfg(target_os = "linux")]
pub(crate) fn package_command_until(
    program: &str,
    arguments: &[&str],
    cutoff: std::time::Instant,
) -> Result<std::process::Output, String> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    if Instant::now() >= cutoff {
        return Err("original package command cutoff exhausted before spawn".into());
    }
    let mut child = std::process::Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut stdout = child.stdout.take().expect("requested stdout pipe");
    let mut stderr = child.stderr.take().expect("requested stderr pipe");
    let configure = |fd| {
        // SAFETY: fd is an exclusively retained child output pipe.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    };
    let result = (|| {
        configure(stdout.as_raw_fd())?;
        configure(stderr.as_raw_fd())?;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut out_closed = false;
        let mut err_closed = false;
        let mut status = None;
        loop {
            if Instant::now() >= cutoff {
                return Err("original package command cutoff expired".to_owned());
            }
            for (reader, bytes, closed) in [
                (&mut stdout as &mut dyn Read, &mut out, &mut out_closed),
                (&mut stderr as &mut dyn Read, &mut err, &mut err_closed),
            ] {
                if *closed {
                    continue;
                }
                let mut buffer = [0_u8; 4096];
                match reader.read(&mut buffer) {
                    Ok(0) => *closed = true,
                    Ok(count) => {
                        if bytes.len().saturating_add(count) > 64 * 1024 {
                            return Err(
                                "native package command output exceeds its finite bound".into()
                            );
                        }
                        bytes.extend_from_slice(&buffer[..count]);
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
            if status.is_none() {
                status = child.try_wait().map_err(|error| error.to_string())?;
            }
            if let Some(status) = status {
                if out_closed && err_closed {
                    check_package_cutoff(cutoff)?;
                    return Ok(std::process::Output {
                        status,
                        stdout: out,
                        stderr: err,
                    });
                }
            }
            std::thread::sleep(
                Duration::from_millis(5).min(cutoff.saturating_duration_since(Instant::now())),
            );
        }
    })();
    if let Err(error) = result {
        // This is a separate, once-formed child cleanup allowance. It cannot
        // renew the package operation or authorize additional package mutation.
        let cleanup_cutoff = Instant::now() + Duration::from_secs(5);
        let termination = child.kill();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(format!(
                        "{error}; child termination={termination:?}; actual wait={status}"
                    ));
                }
                Ok(None) if Instant::now() < cleanup_cutoff => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                observation => {
                    return Err(format!(
                        "{error}; child termination={termination:?}; child pid={} cleanup observation={observation:?}; no cleanup completion claimed",
                        child.id()
                    ));
                }
            }
        }
    }
    result
}

#[cfg(target_os = "linux")]
fn disable_optional_network_launcher(cutoff: std::time::Instant) -> Result<(), String> {
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
            systemctl(cutoff, ["disable", "--now", unit])?;
            ensure_unit_inactive(unit, cutoff)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_unit_inactive(unit: &str, cutoff: std::time::Instant) -> Result<(), String> {
    let output = package_command_until(
        "/usr/bin/systemctl",
        &["show", "--property=ActiveState", "--value", unit],
        cutoff,
    )
    .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))?;
    if !output.status.success() {
        if unit_load_state(unit, cutoff)? == "not-found" {
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
fn stop_unit(unit: &str, cutoff: std::time::Instant) -> Result<(), String> {
    let output = package_command_until("/usr/bin/systemctl", &["stop", unit], cutoff)
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP: unit={unit}; invocation-error={error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let diagnostic = systemctl_output_diagnostic(&output);
    match unit_load_state(unit, cutoff) {
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
fn unit_load_state(unit: &str, cutoff: std::time::Instant) -> Result<String, String> {
    let output = package_command_until(
        "/usr/bin/systemctl",
        &["show", "--property=LoadState", "--value", unit],
        cutoff,
    )
    .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))?;
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))
}

#[cfg(target_os = "linux")]
fn readiness_error(cause: &str, cutoff: std::time::Instant) -> String {
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
        cutoff,
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
        cutoff,
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
        cutoff,
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
        cutoff,
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
    cutoff: std::time::Instant,
) -> serde_json::Value {
    let output = package_command_until(program, arguments, cutoff);
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
