use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use memcordon_core::{
    WINDOWS_CONTROL_SERVICE_NAME, WINDOWS_GUARDIAN_PIPE_PREFIX, WINDOWS_GUARDIAN_SLOT_COUNT,
    WINDOWS_LAUNCHER_SERVICE_NAME, WINDOWS_SESSION_BROKER_SERVICE_NAME,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_DIR_NOT_EMPTY, ERROR_SHARING_VIOLATION,
    GetLastError,
};
use windows_sys::Win32::System::Threading::CreateMutexW;

use crate::inspection_schema::{
    AgentPackageInspectionV3, InstalledProviderInspectionV3, ProviderPackageMetadataV3,
};

use super::security::{
    SecurityDescriptor, admission_state_sddl, certification_marker_state_sddl, launcher_state_sddl,
    package_state_sddl, pre_destructive_authority_hardening_certification_marker_state_sddl,
    pre_write_restricted_certification_marker_state_sddl, replay_state_sddl, state_bootstrap_sddl,
    state_parent_sddl, state_sddl,
};
use super::service_manager::{
    self, GuardianSlotConfig, ServiceConfig, ServiceSidType, SessionBrokerConfig,
    SessionBrokerConfigurationFault,
};

pub(crate) const CONTROL_PRIVILEGES: &[&str] = &["SeImpersonatePrivilege"];
pub(crate) const LAUNCHER_PRIVILEGES: &[&str] = &[
    "SeAssignPrimaryTokenPrivilege",
    "SeBackupPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeRestorePrivilege",
    "SeTcbPrivilege",
];
pub(crate) const SESSION_BROKER_PRIVILEGES: &[&str] =
    memcordon_core::WINDOWS_SESSION_BROKER_REQUIRED_PRIVILEGES;
pub(crate) const INSTALL_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)(A;;GX;;;RC)(A;OIIO;GRGX;;;RC)(A;OICI;GRGX;;;AC)";
const IMAGE_DELETE_DEADLINE: Duration = Duration::from_secs(5);
const IMAGE_DELETE_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const PACKAGE_CLEANUP_DEADLINE: Duration = Duration::from_secs(30);
const PACKAGE_CLEANUP_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const QUALIFICATION_ROLLBACK_FAULT: &str = "qualification-rollback-fault";
const SCM_CONNECT_ACE_MARKER: &str = "scm-launcher-connect-ace-owned";
const EPHEMERAL_CI_MARKER_CONTENTS: &[u8] = b"enabled\n";

pub fn install_root() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
        .join("MemCordon")
}

pub fn state_root() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("MemCordon")
        .join("sealed")
}

pub fn installed_binary() -> PathBuf {
    install_root().join("memcordon-sealed-agent.exe")
}

pub fn installed_target_desktop_bootstrap() -> PathBuf {
    install_root().join("memcordon-target-desktop-bootstrap.exe")
}

pub fn installed_session_broker() -> PathBuf {
    install_root().join("memcordon-session-broker.exe")
}

fn packaged_target_desktop_bootstrap(agent: &Path) -> Result<PathBuf, String> {
    let directory = agent
        .parent()
        .ok_or_else(|| "packaged Windows sealed agent has no parent directory".to_owned())?;
    Ok(directory.join("memcordon-target-desktop-bootstrap.exe"))
}

fn packaged_session_broker(agent: &Path) -> Result<PathBuf, String> {
    let directory = agent
        .parent()
        .ok_or_else(|| "packaged Windows sealed agent has no parent directory".to_owned())?;
    Ok(directory.join("memcordon-session-broker.exe"))
}

fn verify_target_desktop_bootstrap_image(
    path: &Path,
) -> Result<memcordon_core::WindowsPeImports, String> {
    reject_reparse_components(path)?;
    let bytes = read_regular_no_follow(path, "target-desktop-bootstrap")?;
    verify_native_target_desktop_bootstrap_pe(&bytes)
}

fn verify_session_broker_image(path: &Path) -> Result<(), String> {
    reject_reparse_components(path)?;
    let bytes = read_regular_no_follow(path, "session-broker")?;
    verify_native_session_broker_pe(&bytes).map(|_| ())
}

fn require_native_pe_machine(
    role: &str,
    imports: memcordon_core::WindowsPeImports,
) -> Result<memcordon_core::WindowsPeImports, String> {
    let expected = native_pe_machine(role)?;
    if imports.machine != expected {
        return Err(format!(
            "MCSEALED-WINDOWS-ARTIFACT: role={role} expected_native_machine=0x{expected:04x} actual_machine=0x{:04x}",
            imports.machine,
        ));
    }
    Ok(imports)
}

#[cfg(target_arch = "x86_64")]
fn native_pe_machine(_role: &str) -> Result<u16, String> {
    Ok(memcordon_core::WINDOWS_PE_MACHINE_AMD64)
}

#[cfg(target_arch = "aarch64")]
fn native_pe_machine(_role: &str) -> Result<u16, String> {
    Ok(memcordon_core::WINDOWS_PE_MACHINE_ARM64)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn native_pe_machine(role: &str) -> Result<u16, String> {
    Err(format!(
        "MCSEALED-WINDOWS-ARTIFACT: role={role} native PE machine is unsupported on this target"
    ))
}

fn verify_native_target_desktop_bootstrap_pe(
    bytes: &[u8],
) -> Result<memcordon_core::WindowsPeImports, String> {
    require_native_pe_machine(
        "target-desktop-bootstrap",
        memcordon_core::verify_target_desktop_bootstrap_pe(bytes)?,
    )
}

fn verify_native_session_broker_pe(
    bytes: &[u8],
) -> Result<memcordon_core::WindowsPeImports, String> {
    require_native_pe_machine(
        "session-broker",
        memcordon_core::verify_session_broker_pe(bytes)?,
    )
}

#[cfg(test)]
pub(crate) fn require_native_pe_machine_for_test(machine: u16) -> Result<(), String> {
    require_native_pe_machine(
        "native-machine-test",
        memcordon_core::WindowsPeImports {
            machine,
            normal: Vec::new(),
            delayed: Vec::new(),
        },
    )
    .map(|_| ())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackageArtifactDigests {
    agent_sha256: String,
    target_desktop_bootstrap_sha256: String,
    session_broker_sha256: String,
}

struct CapturedPackageArtifacts {
    agent_bytes: Vec<u8>,
    target_desktop_bootstrap_bytes: Vec<u8>,
    session_broker_bytes: Vec<u8>,
    digests: PackageArtifactDigests,
}

fn read_regular_no_follow(path: &Path, role: &str) -> Result<Vec<u8>, String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    reject_reparse_components(path)?;
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = options.open(path).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-ARTIFACT: role={role} path={} expected=regular-file actual=unreadable error={error}",
            path.display()
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-ARTIFACT: role={role} path={} expected=regular-file actual=unreadable-metadata error={error}",
            path.display()
        )
    })?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file() {
        return Err(format!(
            "MCSEALED-WINDOWS-ARTIFACT: role={role} path={} expected=regular-file actual={}",
            path.display(),
            file_kind(&metadata),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-ARTIFACT: role={role} path={} expected=readable-regular-file actual=read-failed error={error}",
            path.display()
        )
    })?;
    Ok(bytes)
}

fn capture_package_artifacts(
    agent: &Path,
    target_desktop_bootstrap: &Path,
    session_broker: &Path,
) -> Result<CapturedPackageArtifacts, String> {
    let agent_bytes = read_regular_no_follow(agent, "agent-source")?;
    let target_desktop_bootstrap_bytes =
        read_regular_no_follow(target_desktop_bootstrap, "target-desktop-bootstrap-source")?;
    verify_native_target_desktop_bootstrap_pe(&target_desktop_bootstrap_bytes)?;
    let session_broker_bytes = read_regular_no_follow(session_broker, "session-broker-source")?;
    verify_native_session_broker_pe(&session_broker_bytes)?;
    let digests = PackageArtifactDigests {
        agent_sha256: crate::package::sha256_bytes(&agent_bytes),
        target_desktop_bootstrap_sha256: crate::package::sha256_bytes(
            &target_desktop_bootstrap_bytes,
        ),
        session_broker_sha256: crate::package::sha256_bytes(&session_broker_bytes),
    };
    Ok(CapturedPackageArtifacts {
        agent_bytes,
        target_desktop_bootstrap_bytes,
        session_broker_bytes,
        digests,
    })
}

fn validate_artifact_pair(
    agent: &Path,
    target_desktop_bootstrap: &Path,
    session_broker: &Path,
    expected: Option<&PackageArtifactDigests>,
) -> Result<PackageArtifactDigests, String> {
    let captured = capture_package_artifacts(agent, target_desktop_bootstrap, session_broker)?;
    if expected.is_some_and(|expected| expected != &captured.digests) {
        return Err(format!(
            "MCSEALED-WINDOWS-ARTIFACT: expected={expected:?} actual={:?}",
            captured.digests,
        ));
    }
    Ok(captured.digests)
}

#[derive(Clone, Debug)]
pub(crate) struct InstalledTargetDesktopBootstrapContract {
    pub sha256: String,
    pub import_contract_sha256: String,
    pub imports: memcordon_core::WindowsPeImports,
}

pub(crate) fn installed_target_desktop_bootstrap_contract()
-> Result<InstalledTargetDesktopBootstrapContract, String> {
    let path = installed_target_desktop_bootstrap();
    let bytes = read_regular_no_follow(&path, "installed-target-desktop-bootstrap")?;
    let imports = verify_native_target_desktop_bootstrap_pe(&bytes)?;
    let mut canonical = format!("machine={:04x}\n", imports.machine).into_bytes();
    for name in &imports.normal {
        canonical.extend_from_slice(b"normal=");
        canonical.extend_from_slice(name.as_bytes());
        canonical.push(b'\n');
    }
    for name in &imports.delayed {
        canonical.extend_from_slice(b"delayed=");
        canonical.extend_from_slice(name.as_bytes());
        canonical.push(b'\n');
    }
    Ok(InstalledTargetDesktopBootstrapContract {
        sha256: crate::package::sha256_bytes(&bytes),
        import_contract_sha256: super::record::digest(&canonical),
        imports,
    })
}

pub(crate) fn validate_installed_target_desktop_bootstrap() -> Result<String, String> {
    installed_target_desktop_bootstrap_contract().map(|contract| contract.sha256)
}

pub(crate) fn validate_installed_target_desktop_bootstrap_loader_control() -> Result<String, String>
{
    validate_installed_target_desktop_bootstrap()
}

pub(crate) fn validate_installed_session_broker() -> Result<String, String> {
    let path = installed_session_broker();
    let bytes = read_regular_no_follow(&path, "installed-session-broker")?;
    verify_native_session_broker_pe(&bytes)?;
    Ok(crate::package::sha256_bytes(&bytes))
}

pub fn compiled_metadata() -> Result<ProviderPackageMetadataV3, String> {
    let executable = installed_binary().to_string_lossy().into_owned();
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
    let source_bootstrap = packaged_target_desktop_bootstrap(&source)?;
    let source_broker = packaged_session_broker(&source)?;
    let target_desktop_bootstrap_imports =
        verify_target_desktop_bootstrap_image(&source_bootstrap)?;
    verify_session_broker_image(&source_broker)?;
    let control_command = String::from_utf16_lossy(&super::process::encode_command_line(&[
        executable.encode_utf16().collect(),
        "windows-control".encode_utf16().collect(),
    ]));
    let launcher_command = String::from_utf16_lossy(&super::process::encode_command_line(&[
        executable.encode_utf16().collect(),
        "windows-launcher".encode_utf16().collect(),
    ]));
    let control_config = service_config_record(
        WINDOWS_CONTROL_SERVICE_NAME,
        "MemCordon sealed local control provider",
        &control_command,
        r"NT AUTHORITY\LocalService",
        &[WINDOWS_LAUNCHER_SERVICE_NAME],
        CONTROL_PRIVILEGES,
        ServiceSidType::Restricted,
    );
    let launcher_config = service_config_record(
        WINDOWS_LAUNCHER_SERVICE_NAME,
        "MemCordon sealed privileged launcher",
        &launcher_command,
        "LocalSystem",
        &[],
        LAUNCHER_PRIVILEGES,
        ServiceSidType::Restricted,
    );
    let session_broker_executable = installed_session_broker().to_string_lossy().into_owned();
    let session_broker_command = String::from_utf16_lossy(&super::process::encode_command_line(&[
        session_broker_executable.encode_utf16().collect(),
    ]));
    let session_broker_config = session_broker_config_record(&session_broker_command)?;
    let session_broker_service_sddl = super::security::session_broker_service_sddl()?;
    let guardian_slot_config = (0..WINDOWS_GUARDIAN_SLOT_COUNT)
        .map(|index| {
            let name = super::security::guardian_slot_name(index)?;
            let command = guardian_slot_command(&executable, &name);
            guardian_slot_config_record(&name, &command)
        })
        .collect::<Result<Vec<_>, String>>()?
        .join("\u{1e}");
    Ok(ProviderPackageMetadataV3::WindowsService {
        control_service_name: WINDOWS_CONTROL_SERVICE_NAME.to_owned(),
        launcher_service_name: WINDOWS_LAUNCHER_SERVICE_NAME.to_owned(),
        session_broker_service_name: WINDOWS_SESSION_BROKER_SERVICE_NAME.to_owned(),
        guardian_slot_count: WINDOWS_GUARDIAN_SLOT_COUNT,
        control_service_config_sha256: crate::package::sha256_bytes(control_config.as_bytes()),
        launcher_service_config_sha256: crate::package::sha256_bytes(launcher_config.as_bytes()),
        session_broker_service_config_sha256: crate::package::sha256_bytes(
            session_broker_config.as_bytes(),
        ),
        guardian_slot_config_sha256: crate::package::sha256_bytes(guardian_slot_config.as_bytes()),
        control_pipe: memcordon_core::WINDOWS_CONTROL_PIPE.to_owned(),
        launcher_pipe: memcordon_core::WINDOWS_LAUNCHER_PIPE.to_owned(),
        session_broker_pipe: memcordon_core::WINDOWS_SESSION_BROKER_PIPE.to_owned(),
        guardian_pipe_prefix: WINDOWS_GUARDIAN_PIPE_PREFIX.to_owned(),
        binary_install_path: installed_binary().to_string_lossy().into_owned(),
        target_desktop_bootstrap_install_path: installed_target_desktop_bootstrap()
            .to_string_lossy()
            .into_owned(),
        target_desktop_bootstrap_sha256: crate::package::sha256_regular_no_follow(
            &source_bootstrap,
        )?,
        target_desktop_bootstrap_crt_static: cfg!(target_feature = "crt-static"),
        target_desktop_bootstrap_loader_contract_sha256: crate::package::sha256_bytes(
            format!(
                "memcordon-target-desktop-loader-contract-v1\0crt-static=true\0normal={}\0delayed={}",
                target_desktop_bootstrap_imports.normal.join(","),
                target_desktop_bootstrap_imports.delayed.join(","),
            )
            .as_bytes(),
        ),
        target_desktop_bootstrap_normal_imports: target_desktop_bootstrap_imports.normal,
        target_desktop_bootstrap_delayed_imports: target_desktop_bootstrap_imports.delayed,
        session_broker_install_path: installed_session_broker().to_string_lossy().into_owned(),
        session_broker_sha256: crate::package::sha256_regular_no_follow(&source_broker)?,
        state_root: state_root().to_string_lossy().into_owned(),
        control_service_sid_type: "restricted".to_owned(),
        launcher_service_sid_type: "restricted".to_owned(),
        session_broker_service_sid_type: "unrestricted".to_owned(),
        guardian_slot_service_sid_type: "restricted".to_owned(),
        control_required_privileges: CONTROL_PRIVILEGES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        launcher_required_privileges: LAUNCHER_PRIVILEGES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        session_broker_required_privileges: SESSION_BROKER_PRIVILEGES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        guardian_slot_required_privileges: Vec::new(),
        control_pipe_security_sha256: crate::package::sha256_bytes(
            super::security::public_pipe_sddl()?.as_bytes(),
        ),
        launcher_pipe_security_sha256: crate::package::sha256_bytes(
            super::security::private_pipe_sddl()?.as_bytes(),
        ),
        session_broker_service_security_sha256: crate::package::sha256_bytes(
            session_broker_service_sddl.as_bytes(),
        ),
        session_broker_pipe_security_sha256: crate::package::sha256_bytes(
            super::security::session_broker_pipe_sddl()?.as_bytes(),
        ),
        guardian_pipe_security_contract_sha256: crate::package::sha256_bytes(
            (0..WINDOWS_GUARDIAN_SLOT_COUNT)
                .map(super::security::guardian_slot_pipe_sddl)
                .collect::<Result<Vec<_>, _>>()?
                .join("\u{1e}")
                .as_bytes(),
        ),
        install_directory_security_sha256: crate::package::sha256_bytes(INSTALL_SDDL.as_bytes()),
        state_directory_security_sha256: crate::package::sha256_bytes(state_sddl()?.as_bytes()),
    })
}

fn guardian_slot_command(executable: &str, name: &str) -> String {
    String::from_utf16_lossy(&super::process::encode_command_line(&[
        executable.encode_utf16().collect(),
        "windows-guardian-service".encode_utf16().collect(),
        name.encode_utf16().collect(),
    ]))
}

fn guardian_slot_config_record(name: &str, binary_command: &str) -> Result<String, String> {
    Ok([
        name.to_owned(),
        "MemCordon sealed guardian slot".to_owned(),
        binary_command.to_owned(),
        "LocalSystem".to_owned(),
        "service-type=win32-own-process".to_owned(),
        "start-type=demand".to_owned(),
        "error-control=normal".to_owned(),
        "service-sid-type=restricted".to_owned(),
        format!(
            "service-dacl={}",
            super::security::guardian_slot_service_sddl(name)?
        ),
        "failure-actions=none".to_owned(),
        "dependencies=".to_owned(),
        "required-privileges=".to_owned(),
    ]
    .join("\0"))
}

fn session_broker_config_record(binary_command: &str) -> Result<String, String> {
    let mut fields = vec![
        WINDOWS_SESSION_BROKER_SERVICE_NAME.to_owned(),
        "MemCordon sealed target-session broker".to_owned(),
        binary_command.to_owned(),
        "LocalSystem".to_owned(),
        "service-type=win32-own-process".to_owned(),
        "start-type=demand".to_owned(),
        "error-control=normal".to_owned(),
        "service-sid-type=unrestricted".to_owned(),
        format!(
            "service-security={}",
            super::security::session_broker_service_sddl()?
        ),
        "failure-actions=none".to_owned(),
        "dependencies=".to_owned(),
    ];
    fields.extend(
        SESSION_BROKER_PRIVILEGES
            .iter()
            .map(|value| (*value).to_owned()),
    );
    Ok(fields.join("\0"))
}

fn service_config_record(
    name: &str,
    display_name: &str,
    binary_command: &str,
    account: &str,
    dependencies: &[&str],
    privileges: &[&str],
    sid_type: ServiceSidType,
) -> String {
    let mut fields = vec![
        name.to_owned(),
        display_name.to_owned(),
        binary_command.to_owned(),
        account.to_owned(),
        "service-type=win32-own-process".to_owned(),
        "start-type=automatic".to_owned(),
        "error-control=normal".to_owned(),
        format!("service-sid-type={}", sid_type.name()),
        format!("service-dacl={}", super::security::SERVICE_CONTROL_SDDL),
        "failure-reset-seconds=86400".to_owned(),
        "failure-actions=restart:1000,restart:5000".to_owned(),
        format!("dependencies={}", dependencies.join(",")),
    ];
    fields.extend(privileges.iter().map(|value| (*value).to_owned()));
    fields.join("\0")
}

pub fn mutate(
    operation: &OsStr,
    ephemeral_ci: bool,
    qualification_artifact_directory: Option<&Path>,
) -> Result<(), String> {
    if qualification_artifact_directory.is_some() && (!ephemeral_ci || operation != "install") {
        return Err("external qualification artifacts require an ephemeral CI install".to_owned());
    }
    if let Some(destination) = qualification_artifact_directory {
        validate_qualification_artifact_directory(destination)?;
    }
    if operation == "install-rollback-certification" {
        if !ephemeral_ci {
            return Err(
                "Windows rollback certification requires ephemeral CI installation".to_owned(),
            );
        }
        let lease = PackageLease::acquire()?;
        let transition = install(true)?;
        let marker = state_root()
            .join("package")
            .join(QUALIFICATION_ROLLBACK_FAULT);
        if let Err(error) = std::fs::write(&marker, b"inject qualification failure\n") {
            let install_error = format!(
                "MCSEALED-WINDOWS-INSTALL-STATE: cannot write rollback certification fault {}: {error}",
                marker.display()
            );
            let _lease = lease;
            return match rollback_fresh_install(FreshRollback::Transition(transition)) {
                Ok(()) => Err(install_error),
                Err(rollback_error) => Err(format!(
                    "MCSEALED-WINDOWS-INSTALL-ROLLBACK-FAILED: install={install_error}; rollback={rollback_error}"
                )),
            };
        }
        qualify_outside_package_lease(lease, QualificationRollback::Fresh(transition), None)
    } else if let Some(fault) = session_broker_certification_fault(operation) {
        let intent = InstallIntent::ephemeral_certification(ephemeral_ci, fault)?;
        let _lease = PackageLease::acquire()?;
        match install_with_intent(intent) {
            Ok(_) => Err(
                "MCSEALED-WINDOWS-CERTIFICATION-FAULT-SURVIVED: session-broker install fault did not interrupt installation"
                    .to_owned(),
            ),
            Err(error) => Err(error),
        }
    } else if operation == "seed-retired-certification-workspace" {
        if !ephemeral_ci || !certification_faults_enabled() {
            return Err(
                "Windows retired-workspace certification requires an ephemeral CI installation"
                    .to_owned(),
            );
        }
        let _lease = PackageLease::acquire()?;
        seed_retired_certification_workspace()
    } else if operation == "install" {
        let lease = PackageLease::acquire()?;
        let transition = install(ephemeral_ci)?;
        qualify_outside_package_lease(
            lease,
            QualificationRollback::Fresh(transition),
            qualification_artifact_directory,
        )
    } else if operation == "upgrade" {
        let lease = PackageLease::acquire()?;
        reconcile_services_from_installed()?;
        let installation = upgrade(ephemeral_ci)?;
        qualify_outside_package_lease(lease, QualificationRollback::Upgrade(installation), None)
    } else if operation == "uninstall" {
        let _lease = PackageLease::acquire()?;
        reconcile_services_from_installed()?;
        uninstall(ephemeral_ci)
    } else {
        Err("unknown package operation".to_owned())
    }
}

fn session_broker_certification_fault(operation: &OsStr) -> Option<InstallSessionBrokerFault> {
    Some(match operation.to_str()? {
        "install-broker-registration-rollback-certification" => {
            InstallSessionBrokerFault::AfterRegistration
        }
        "install-broker-privileges-rollback-certification" => {
            InstallSessionBrokerFault::Configuration(
                SessionBrokerConfigurationFault::AfterRequiredPrivileges,
            )
        }
        "install-broker-sid-rollback-certification" => {
            InstallSessionBrokerFault::Configuration(SessionBrokerConfigurationFault::AfterSidType)
        }
        "install-broker-failure-actions-rollback-certification" => {
            InstallSessionBrokerFault::Configuration(
                SessionBrokerConfigurationFault::AfterFailureActions,
            )
        }
        "install-broker-security-rollback-certification" => {
            InstallSessionBrokerFault::Configuration(
                SessionBrokerConfigurationFault::AfterSecurityApply,
            )
        }
        _ => return None,
    })
}

pub(super) struct PackageLease {
    _handle: super::pipe::OwnedHandle,
}

impl PackageLease {
    pub(super) fn acquire() -> Result<Self, String> {
        let name = super::pipe::wide_null(r"Global\MemCordonSealedPackageV1");
        let security = SecurityDescriptor::from_sddl(&super::security::package_mutex_sddl()?)?;
        let attributes = security.attributes(false);
        // SAFETY: name is a live NUL-terminated UTF-16 string; the returned
        // mutex handle is transferred to OwnedHandle.
        let handle = unsafe { CreateMutexW(&raw const attributes, 1, name.as_ptr()) };
        let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let handle = super::pipe::OwnedHandle::new(handle)?;
        security.verify_kernel_object(handle.raw(), super::security::SecurityObjectKind::Mutex)?;
        if already_exists {
            return Err(
                "MCSEALED-WINDOWS-PACKAGE-BUSY: another package mutation is active".to_owned(),
            );
        }
        Ok(Self { _handle: handle })
    }
}

fn install(ephemeral_ci: bool) -> Result<InstallTransition, String> {
    install_with_intent(InstallIntent::from_ephemeral_ci(ephemeral_ci))
}

fn install_with_intent(intent: InstallIntent) -> Result<InstallTransition, String> {
    require_fresh_filesystem_absence()?;
    if !package_attempts_empty()? {
        return Err(
            "MCSEALED-WINDOWS-INSTALL-ACTIVE: provider has active or unreconciled attempts"
                .to_owned(),
        );
    }
    let manager = service_manager::manager()?;
    require_fresh_service_absence(&manager)?;
    drop(manager);
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
    let source_bootstrap = packaged_target_desktop_bootstrap(&source)?;
    let source_broker = packaged_session_broker(&source)?;
    let mut transition = InstallTransition::new(intent);
    let result = install_transaction(&source, &source_bootstrap, &source_broker, &mut transition);
    if let Err(install_error) = result {
        return match rollback_fresh_install(FreshRollback::Transition(transition)) {
            Ok(()) => Err(install_error),
            Err(rollback_error) => Err(format!(
                "MCSEALED-WINDOWS-INSTALL-ROLLBACK-FAILED: install={install_error}; rollback={rollback_error}"
            )),
        };
    }
    let ownership = transition.service_ownership();
    if !ownership.complete() {
        panic!("successful fresh installation does not own every configured service");
    }
    if transition.phase != InstallPhase::ReadyForQualification {
        panic!("successful fresh installation did not reach qualification-ready phase");
    }
    Ok(transition)
}

enum FreshRollback {
    Transition(InstallTransition),
}

fn rollback_fresh_install(rollback: FreshRollback) -> Result<(), String> {
    let FreshRollback::Transition(transition) = rollback;
    let service_ownership = transition.service_ownership();
    let bootstrap_error = if transition.phase.service_cleanup_required() {
        if let Err(cleanup_error) =
            reconcile_services_from_installed().and_then(|()| service_owned_cleanup_barrier())
        {
            let retained = match reconcile_services_from_installed() {
                Ok(()) => "services=reconciled scm=retained".to_owned(),
                Err(reconcile_error) => format!(
                    "services=retained-but-reconciliation-failed scm=retained reconcile={reconcile_error}"
                ),
            };
            return Err(format!(
                "MCSEALED-WINDOWS-INSTALL-ROLLBACK-AUTHORITY-RETAINED: service-owned cleanup did not converge; {retained}; cleanup={cleanup_error}"
            ));
        }
        None
    } else {
        transition.restore_bootstrap().err()
    };
    drop(transition);
    if let Err(remove_error) = uninstall_transaction_services(&service_ownership) {
        if service_ownership.complete() {
            let reconcile = reconcile_services_from_installed();
            return match reconcile {
                Ok(()) => Err(format!(
                    "service removal failed; the coherent transaction-owned pair was restored: {remove_error}"
                )),
                Err(reconcile_error) => Err(format!(
                    "service removal failed and the transaction-owned pair could not be reconciled: remove={remove_error}; reconcile={reconcile_error}"
                )),
            };
        }
        return Err(remove_error);
    }
    let scm_ace = if service_ownership.scm_connect_ace_created {
        ScmAceDisposition::Revoked
    } else {
        ScmAceDisposition::NotOwned
    };
    match (
        remove_provider_files(ProviderRemovalContext { scm_ace }),
        bootstrap_error,
    ) {
        (Ok(()), None) => Ok(()),
        (Ok(()), Some(bootstrap_error)) => Err(format!(
            "partial installation was removed after bootstrap restoration failed: restore={bootstrap_error}"
        )),
        (Err(remove_error), Some(bootstrap_error)) => Err(format!(
            "partial-install bootstrap restoration and removal failed: restore={bootstrap_error}; remove={remove_error}"
        )),
        (Err(remove_error), None) => Err(remove_error),
    }
}

fn service_owned_cleanup_barrier() -> Result<(), String> {
    let deadline = Instant::now() + PACKAGE_CLEANUP_DEADLINE;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(
                "MCSEALED-WINDOWS-PACKAGE-CLEANUP-TIMEOUT: recovery_empty=false; last=cleanup deadline expired before convergence"
                    .to_owned(),
            );
        }
        let deadline_millis = u64::try_from((deadline - now).as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        match super::qualification::prepare_package_cleanup(deadline_millis) {
            Ok(()) => return Ok(()),
            Err(super::record::PackageCleanupError::Active(detail)) => {
                let recovery_empty = super::qualification::recovery_status()?;
                let now = Instant::now();
                if now >= deadline {
                    return Err(format!(
                        "MCSEALED-WINDOWS-PACKAGE-CLEANUP-TIMEOUT: recovery_empty={recovery_empty}; last={detail}"
                    ));
                }
                std::thread::sleep(PACKAGE_CLEANUP_RETRY_INTERVAL.min(deadline - now));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

struct InstallTransition {
    directories: Vec<TransitionDirectory>,
    guardian_slots_created: Vec<String>,
    session_broker_created: bool,
    intent: InstallIntent,
    launcher_created: bool,
    control_created: bool,
    scm_connect_ace_created: bool,
    phase: InstallPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstallSessionBrokerFault {
    AfterRegistration,
    Configuration(SessionBrokerConfigurationFault),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstallIntent {
    Normal,
    Ephemeral,
    EphemeralCertification(InstallSessionBrokerFault),
}

impl InstallIntent {
    pub(crate) fn from_ephemeral_ci(ephemeral_ci: bool) -> Self {
        if ephemeral_ci {
            Self::Ephemeral
        } else {
            Self::Normal
        }
    }

    pub(crate) fn ephemeral_certification(
        ephemeral_ci: bool,
        fault: InstallSessionBrokerFault,
    ) -> Result<Self, String> {
        if !ephemeral_ci {
            return Err(
                "MCSEALED-WINDOWS-CERTIFICATION-ADMISSION: session-broker rollback certification requires --ephemeral-ci"
                    .to_owned(),
            );
        }
        Ok(Self::EphemeralCertification(fault))
    }

    pub(crate) fn is_ephemeral(self) -> bool {
        !matches!(self, Self::Normal)
    }

    pub(crate) fn authorized_session_broker_fault(
        self,
        marker_verified: bool,
    ) -> Result<Option<InstallSessionBrokerFault>, String> {
        match self {
            Self::EphemeralCertification(fault) if marker_verified => Ok(Some(fault)),
            Self::EphemeralCertification(_) => Err(
                "MCSEALED-WINDOWS-CERTIFICATION-AUTHORIZATION: protected ephemeral marker verification failed before session-broker fault injection"
                    .to_owned(),
            ),
            Self::Normal | Self::Ephemeral => Ok(None),
        }
    }
}

pub(crate) fn establish_ephemeral_marker<Create, Verify>(
    intent: InstallIntent,
    create_marker: Create,
    verify_marker: Verify,
) -> Result<(), String>
where
    Create: FnOnce() -> Result<(), String>,
    Verify: FnOnce() -> bool,
{
    if !intent.is_ephemeral() {
        return Ok(());
    }
    create_marker()?;
    if verify_marker() {
        return Ok(());
    }
    let detail = if matches!(intent, InstallIntent::EphemeralCertification(_)) {
        "MCSEALED-WINDOWS-CERTIFICATION-AUTHORIZATION: protected ephemeral marker verification failed before service configuration"
    } else {
        "MCSEALED-WINDOWS-INSTALL-STATE: protected ephemeral marker verification failed after creation"
    };
    Err(detail.to_owned())
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum InstallPhase {
    #[default]
    Building,
    RuntimeSealed,
    ServiceCleanupAvailable,
    ReadyForQualification,
}

impl InstallPhase {
    fn service_cleanup_required(self) -> bool {
        matches!(
            self,
            Self::ServiceCleanupAvailable | Self::ReadyForQualification
        )
    }
}

#[derive(Clone, Default)]
struct ServiceOwnership {
    guardian_slots_created: Vec<String>,
    session_broker_created: bool,
    launcher_created: bool,
    control_created: bool,
    scm_connect_ace_created: bool,
}

impl ServiceOwnership {
    fn complete(&self) -> bool {
        self.guardian_slots_created.len() == WINDOWS_GUARDIAN_SLOT_COUNT
            && self.session_broker_created
            && self.launcher_created
            && self.control_created
    }
}

struct TransitionDirectory {
    path: PathBuf,
    handle: super::pipe::OwnedHandle,
    bootstrap_sddl: String,
    security_transition: DirectorySecurityTransition,
    mandatory_label_applied: std::cell::Cell<bool>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DirectorySecurityTransition {
    Dacl,
    DaclAndMandatoryLabel,
}

impl InstallTransition {
    fn new(intent: InstallIntent) -> Self {
        Self {
            directories: Vec::new(),
            guardian_slots_created: Vec::new(),
            session_broker_created: false,
            intent,
            launcher_created: false,
            control_created: false,
            scm_connect_ace_created: false,
            phase: InstallPhase::Building,
        }
    }

    fn service_ownership(&self) -> ServiceOwnership {
        ServiceOwnership {
            guardian_slots_created: self.guardian_slots_created.clone(),
            session_broker_created: self.session_broker_created,
            launcher_created: self.launcher_created,
            control_created: self.control_created,
            scm_connect_ace_created: self.scm_connect_ace_created,
        }
    }

    fn retain(&mut self, path: &Path, bootstrap_sddl: &str) -> Result<(), String> {
        self.retain_with_security_transition(
            path,
            bootstrap_sddl,
            DirectorySecurityTransition::Dacl,
        )
    }

    fn retain_with_security_transition(
        &mut self,
        path: &Path,
        bootstrap_sddl: &str,
        security_transition: DirectorySecurityTransition,
    ) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };

        const DELETE_ACCESS: u32 = 0x0001_0000;
        const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
        const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
        const WRITE_OWNER_ACCESS: u32 = 0x0008_0000;
        const DACL_TRANSITION_ACCESS: u32 = DELETE_ACCESS | READ_CONTROL_ACCESS | WRITE_DAC_ACCESS;
        let transition_access = DACL_TRANSITION_ACCESS
            | if security_transition == DirectorySecurityTransition::DaclAndMandatoryLabel {
                WRITE_OWNER_ACCESS
            } else {
                0
            };
        let path_wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: the path is NUL-terminated, the final component is opened
        // without following a reparse point, and ownership transfers once.
        let raw = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                transition_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        let handle = super::pipe::OwnedHandle::new(raw).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-DIRECTORY: retain bootstrap transition authority at {}: {error}",
                path.display()
            )
        })?;
        self.directories.push(TransitionDirectory {
            path: path.to_path_buf(),
            handle,
            bootstrap_sddl: bootstrap_sddl.to_owned(),
            security_transition,
            mandatory_label_applied: std::cell::Cell::new(false),
        });
        Ok(())
    }

    fn handle(&self, path: &Path) -> Result<windows_sys::Win32::Foundation::HANDLE, String> {
        self.directories
            .iter()
            .find(|directory| directory.path == path)
            .map(|directory| directory.handle.raw())
            .ok_or_else(|| {
                format!(
                    "MCSEALED-WINDOWS-DIRECTORY: transition handle is absent for {}",
                    path.display()
                )
            })
    }

    fn mark_mandatory_label_applied(&self, path: &Path) -> Result<(), String> {
        let directory = self
            .directories
            .iter()
            .find(|directory| directory.path == path)
            .ok_or_else(|| {
                format!(
                    "MCSEALED-WINDOWS-DIRECTORY: transition handle is absent for {}",
                    path.display()
                )
            })?;
        if directory.security_transition != DirectorySecurityTransition::DaclAndMandatoryLabel {
            panic!("mandatory label applied through a DACL-only directory transition");
        }
        directory.mandatory_label_applied.set(true);
        Ok(())
    }

    fn restore_bootstrap(&self) -> Result<(), String> {
        let mut failures = Vec::new();
        for directory in self.directories.iter().rev() {
            let result: Result<(), String> = (|| {
                let dacl = directory
                    .bootstrap_sddl
                    .strip_prefix("O:BA")
                    .ok_or_else(|| "bootstrap policy is missing its fixed owner".to_owned())?;
                SecurityDescriptor::from_sddl(dacl)?
                    .apply_to_file_object(directory.handle.raw())?;
                SecurityDescriptor::from_sddl(&directory.bootstrap_sddl)?
                    .verify_file_object(directory.handle.raw())?;
                if directory.mandatory_label_applied.get() {
                    // The low label remains exact until rollback releases all
                    // transition handles and removes the new provider tree.
                    let labeled_bootstrap =
                        format!("{}S:(ML;OICI;NW;;;LW)", directory.bootstrap_sddl);
                    SecurityDescriptor::from_sddl(&labeled_bootstrap)?
                        .verify_file_object(directory.handle.raw())?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                failures.push(format!("{}: {error}", directory.path.display()));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

struct UpgradeRollback {
    binary: PathBuf,
    target_desktop_bootstrap: PathBuf,
    session_broker: PathBuf,
    artifact_digests: PackageArtifactDigests,
    qualification: Option<PathBuf>,
    ephemeral_ci: bool,
    scm_connect_ace_owned: bool,
}

struct UpgradeInstallation {
    rollback: UpgradeRollback,
    transition: InstallTransition,
}

#[derive(Clone, Copy)]
enum ScmAceDisposition {
    Revoked,
    NotOwned,
    TransferredForUpgrade { owned: bool },
}

#[derive(Clone, Copy)]
struct ProviderRemovalContext {
    scm_ace: ScmAceDisposition,
}

impl ProviderRemovalContext {
    fn authority_attestation(self) -> &'static str {
        match self.scm_ace {
            ScmAceDisposition::Revoked => "scm=revoked",
            ScmAceDisposition::NotOwned => "scm=not-owned",
            ScmAceDisposition::TransferredForUpgrade { owned: true } => "scm=transferred-owned",
            ScmAceDisposition::TransferredForUpgrade { owned: false } => {
                "scm=transferred-preexisting"
            }
        }
    }
}

fn upgrade(ephemeral_ci: bool) -> Result<UpgradeInstallation, String> {
    let scm_connect_ace_owned = scm_ownership_marker_present()?;
    let installed = installed_binary();
    let captured = validate_existing_installed_artifacts()?;
    let backup = installed.with_extension("exe.rollback");
    copy_atomically_bytes(&captured.agent_bytes, &backup).map_err(|error| {
        format!("cannot preserve the working Windows provider for rollback: {error}")
    })?;
    let installed_bootstrap = installed_target_desktop_bootstrap();
    let bootstrap_backup = installed_bootstrap.with_extension("exe.rollback");
    copy_atomically_bytes(&captured.target_desktop_bootstrap_bytes, &bootstrap_backup).map_err(
        |error| {
            format!("cannot preserve the working target desktop bootstrap for rollback: {error}")
        },
    )?;
    let installed_broker = installed_session_broker();
    let broker_backup = installed_broker.with_extension("exe.rollback");
    copy_atomically_bytes(&captured.session_broker_bytes, &broker_backup).map_err(|error| {
        format!("cannot preserve the working session broker for rollback: {error}")
    })?;
    validate_artifact_pair(
        &backup,
        &bootstrap_backup,
        &broker_backup,
        Some(&captured.digests),
    )?;
    let qualification = state_root().join("package").join("qualification.json");
    let qualification_backup = install_root().join("qualification.json.rollback");
    let qualification_backup = if qualification.is_file() {
        std::fs::copy(&qualification, &qualification_backup).map_err(|error| {
            format!("cannot preserve the working Windows qualification for rollback: {error}")
        })?;
        Some(qualification_backup)
    } else {
        None
    };
    let rollback = UpgradeRollback {
        binary: backup,
        target_desktop_bootstrap: bootstrap_backup,
        session_broker: broker_backup,
        artifact_digests: captured.digests,
        qualification: qualification_backup,
        ephemeral_ci,
        scm_connect_ace_owned,
    };
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
    let source_broker = packaged_session_broker(&source)?;
    if let Err(cleanup_error) = service_owned_cleanup_barrier() {
        cleanup_upgrade_rollback(&rollback);
        return Err(format!(
            "MCSEALED-WINDOWS-UPGRADE-ROLLED-BACK: service-owned state cleanup failed before replacement: {cleanup_error}"
        ));
    }
    if let Err(remove_error) = uninstall_services() {
        let reconcile = reconcile_services_from_installed();
        cleanup_upgrade_rollback(&rollback);
        return match reconcile {
            Ok(()) => Err(format!(
                "MCSEALED-WINDOWS-UPGRADE-ROLLED-BACK: service removal failed before replacement and the installed pair was restored: {remove_error}"
            )),
            Err(reconcile_error) => Err(format!(
                "MCSEALED-WINDOWS-UPGRADE-ROLLBACK-FAILED: remove={remove_error}; reconcile={reconcile_error}"
            )),
        };
    }
    if let Err(remove_error) = remove_provider_state(ProviderRemovalContext {
        scm_ace: ScmAceDisposition::TransferredForUpgrade {
            owned: rollback.scm_connect_ace_owned,
        },
    }) {
        let rollback_result = restore_upgrade(&rollback, ephemeral_ci, None);
        return match rollback_result {
            Ok(()) => {
                cleanup_upgrade_rollback(&rollback);
                Err(format!(
                    "MCSEALED-WINDOWS-UPGRADE-ROLLED-BACK: filesystem cleanup failed and the installed pair was restored: {remove_error}"
                ))
            }
            Err(rollback_error) => Err(format!(
                "MCSEALED-WINDOWS-UPGRADE-ROLLBACK-FAILED: remove={remove_error}; rollback={rollback_error}; rollback artifacts were preserved"
            )),
        };
    }
    let mut transition = InstallTransition::new(InstallIntent::from_ephemeral_ci(ephemeral_ci));
    let source_bootstrap = packaged_target_desktop_bootstrap(&source)?;
    match install_transaction(&source, &source_bootstrap, &source_broker, &mut transition) {
        Ok(()) => {
            if rollback.scm_connect_ace_owned {
                std::fs::write(
                    state_root().join("package").join(SCM_CONNECT_ACE_MARKER),
                    b"owned\n",
                )
                .map_err(|error| error.to_string())?;
            }
            Ok(UpgradeInstallation {
                rollback,
                transition,
            })
        }
        Err(upgrade_error) => {
            let rollback_result = restore_upgrade(&rollback, ephemeral_ci, Some(transition));
            match rollback_result {
                Ok(()) => {
                    cleanup_upgrade_rollback(&rollback);
                    Err(format!(
                        "MCSEALED-WINDOWS-UPGRADE-ROLLED-BACK: {upgrade_error}"
                    ))
                }
                Err(rollback_error) => Err(format!(
                    "MCSEALED-WINDOWS-UPGRADE-ROLLBACK-FAILED: upgrade={upgrade_error}; rollback={rollback_error}; rollback artifacts were preserved"
                )),
            }
        }
    }
}

enum QualificationRollback {
    Fresh(InstallTransition),
    Upgrade(UpgradeInstallation),
}

fn qualify_outside_package_lease(
    lease: PackageLease,
    rollback: QualificationRollback,
    qualification_artifact_directory: Option<&Path>,
) -> Result<(), String> {
    let qualification_fault = state_root()
        .join("package")
        .join(QUALIFICATION_ROLLBACK_FAULT);
    let (qualification, _lease) = if qualification_fault.is_file() {
        (
            Err(super::qualification::QualificationFailure::from(
                "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected fresh qualification rollback"
                    .to_owned(),
            )),
            lease,
        )
    } else {
        super::qualification::qualify_and_store_for_scope("package", lease)?
    };
    let artifact_export = match qualification_artifact_directory {
        Some(destination) => export_production_qualification_artifacts(destination, &qualification),
        None => Ok(()),
    };
    match (qualification, artifact_export, rollback) {
        (Ok(_), Ok(()), QualificationRollback::Upgrade(installation)) => {
            drop(installation.transition);
            cleanup_upgrade_rollback(&installation.rollback);
            Ok(())
        }
        (Ok(_), Ok(()), QualificationRollback::Fresh(transition)) => {
            drop(transition);
            Ok(())
        }
        (Ok(_), Err(export_error), QualificationRollback::Upgrade(installation)) => {
            drop(installation.transition);
            cleanup_upgrade_rollback(&installation.rollback);
            Err(format!(
                "Windows qualification succeeded but external artifact export failed: {export_error}"
            ))
        }
        (Ok(_), Err(export_error), QualificationRollback::Fresh(transition)) => {
            drop(transition);
            Err(format!(
                "Windows qualification succeeded but external artifact export failed: {export_error}"
            ))
        }
        (Err(failure), artifact_export, QualificationRollback::Upgrade(installation)) => {
            let error = qualification_error_with_artifact_export(failure.detail, artifact_export);
            let rollback = installation.rollback;
            let rollback_result = restore_upgrade(
                &rollback,
                rollback.ephemeral_ci,
                Some(installation.transition),
            );
            match rollback_result {
                Ok(()) => {
                    cleanup_upgrade_rollback(&rollback);
                    Err(format!("MCSEALED-WINDOWS-UPGRADE-ROLLED-BACK: {error}"))
                }
                Err(rollback_error) => Err(format!(
                    "MCSEALED-WINDOWS-UPGRADE-ROLLBACK-FAILED: upgrade={error}; rollback={rollback_error}; rollback artifacts were preserved"
                )),
            }
        }
        (Err(failure), artifact_export, QualificationRollback::Fresh(transition)) => {
            let error = qualification_error_with_artifact_export(failure.detail, artifact_export);
            match rollback_fresh_install(FreshRollback::Transition(transition)) {
                Ok(()) => Err(format!(
                    "MCSEALED-WINDOWS-PACKAGE: operation=install stage=qualification rollback=complete detail={error}"
                )),
                Err(rollback_error) => Err(format!(
                    "MCSEALED-WINDOWS-INSTALL-ROLLBACK-FAILED: qualification={error}; rollback={rollback_error}"
                )),
            }
        }
    }
}

fn qualification_error_with_artifact_export(
    error: String,
    artifact_export: Result<(), String>,
) -> String {
    match artifact_export {
        Ok(()) => error,
        Err(export_error) => {
            let export_error = bounded_external_export_diagnostic(&export_error);
            format!(
                "{error}; secondary external qualification artifact export failure: {export_error}"
            )
        }
    }
}

fn bounded_external_export_diagnostic(value: &str) -> String {
    let limit = memcordon_windows_launch_core::MAX_FAILURE_DETAIL_BYTES;
    if value.len() <= limit {
        return value.to_owned();
    }
    let end = value
        .char_indices()
        .map(|(offset, character)| offset + character.len_utf8())
        .take_while(|end| *end <= limit)
        .last()
        .unwrap_or_default();
    value[..end].to_owned()
}

#[cfg(test)]
pub(crate) fn qualification_error_with_artifact_export_for_test(
    primary: String,
    export_error: String,
) -> String {
    qualification_error_with_artifact_export(primary, Err(export_error))
}

fn validate_qualification_artifact_directory(destination: &Path) -> Result<(), String> {
    reject_reparse_components(destination)?;
    let metadata = std::fs::symlink_metadata(destination).map_err(|error| {
        format!(
            "external qualification artifact directory is unavailable at {}: {error}",
            destination.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "external qualification artifact destination is not a directory: {}",
            destination.display()
        ));
    }
    Ok(())
}

fn export_production_qualification_artifacts(
    destination: &Path,
    qualification: &Result<
        memcordon_core::WindowsQualificationReceiptV1,
        super::qualification::QualificationFailure,
    >,
) -> Result<(), String> {
    let (outcome, receipt) = match qualification {
        Ok(receipt) => (&receipt.loader_qualification, Some(receipt)),
        Err(failure) => (
            failure.loader_qualification.as_ref().ok_or_else(|| {
                "typed production loader qualification outcome is absent".to_owned()
            })?,
            None,
        ),
    };
    export_typed_production_qualification_artifacts(destination, outcome, receipt)
}

fn export_typed_production_qualification_artifacts(
    destination: &Path,
    outcome: &memcordon_core::WindowsLoaderQualificationOutcomeV2,
    receipt: Option<&memcordon_core::WindowsQualificationReceiptV1>,
) -> Result<(), String> {
    validate_qualification_artifact_directory(destination)?;
    if !outcome.is_consistent() {
        return Err("typed production loader qualification outcome is inconsistent".to_owned());
    }
    let expected_plan_digest = match outcome {
        memcordon_core::WindowsLoaderQualificationOutcomeV2::Ready(ready) => {
            Some(ready.launch_plan_sha256.as_str())
        }
        memcordon_core::WindowsLoaderQualificationOutcomeV2::Failed(failure) => {
            failure.launch_plan_sha256.as_deref()
        }
    };
    let plan = match (expected_plan_digest, outcome.launch_plan_json()) {
        (Some(expected), Some(json)) => {
            let plan: memcordon_windows_launch_core::ProductionLoaderPlanV1 =
                serde_json::from_str(json)
                    .map_err(|error| format!("typed production loader plan is invalid: {error}"))?;
            if plan.launch_plan_sha256() != expected {
                return Err(
                    "typed production loader plan digest differs from its outcome".to_owned(),
                );
            }
            Some(plan)
        }
        (Some(_), None) => {
            return Err(
                "typed production loader plan is absent for a post-plan outcome".to_owned(),
            );
        }
        (None, Some(_)) => {
            return Err(
                "typed production loader plan is present for a pre-plan outcome".to_owned(),
            );
        }
        (None, None) => None,
    };
    if let Some(receipt) = receipt {
        if !receipt.qualified
            || !receipt.is_consistent()
            || receipt.loader_qualification != *outcome
        {
            return Err("typed Windows qualification receipt is inconsistent".to_owned());
        }
    }
    let mut exported_outcome = outcome.clone();
    exported_outcome.clear_launch_plan_json();

    // Publish dependencies before the outcome commit point so a reader can
    // never observe an outcome whose required plan or receipt is absent.
    if let Some(plan) = &plan {
        write_external_qualification_json(destination, "production-loader-plan-v1.json", plan)?;
    }
    if let Some(receipt) = receipt {
        write_external_qualification_json(destination, "qualification.json", receipt)?;
    }
    write_external_qualification_json(
        destination,
        "production-loader-result-v2.json",
        &exported_outcome,
    )
}

#[cfg(test)]
pub(crate) fn export_typed_production_qualification_artifacts_for_test(
    destination: &Path,
    outcome: &memcordon_core::WindowsLoaderQualificationOutcomeV2,
    receipt: Option<&memcordon_core::WindowsQualificationReceiptV1>,
) -> Result<(), String> {
    export_typed_production_qualification_artifacts(destination, outcome, receipt)
}

fn write_external_qualification_json<T: serde::Serialize>(
    destination: &Path,
    name: &str,
    value: &T,
) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    copy_atomically_bytes(&bytes, &destination.join(name))
}

fn restore_upgrade(
    rollback: &UpgradeRollback,
    ephemeral_ci: bool,
    transition: Option<InstallTransition>,
) -> Result<(), String> {
    validate_artifact_pair(
        &rollback.binary,
        &rollback.target_desktop_bootstrap,
        &rollback.session_broker,
        Some(&rollback.artifact_digests),
    )?;
    let mut bootstrap_error = None;
    let removal = if let Some(transition) = transition {
        let ownership = transition.service_ownership();
        if transition.phase.service_cleanup_required() {
            reconcile_services_from_installed().and_then(|()| service_owned_cleanup_barrier())?;
        } else {
            bootstrap_error = transition.restore_bootstrap().err();
        }
        drop(transition);
        uninstall_transaction_services(&ownership)
    } else {
        if !path_absent_no_follow(&installed_binary(), "upgrade-rollback-installed-agent")?
            && !path_absent_no_follow(
                &installed_target_desktop_bootstrap(),
                "upgrade-rollback-installed-bootstrap",
            )?
            && !path_absent_no_follow(
                &installed_session_broker(),
                "upgrade-rollback-installed-session-broker",
            )?
            && !path_absent_no_follow(&state_root(), "upgrade-rollback-state-root")?
        {
            reconcile_services_from_installed().and_then(|()| service_owned_cleanup_barrier())?;
        }
        uninstall_services()
    };
    if let Err(remove_error) = removal {
        return match reconcile_services_from_installed() {
            Ok(()) => Err(format!(
                "rollback service removal failed; the currently installed pair was reconciled: {remove_error}"
            )),
            Err(reconcile_error) => Err(format!(
                "rollback service removal failed and the installed pair could not be reconciled: remove={remove_error}; reconcile={reconcile_error}"
            )),
        };
    }
    remove_provider_state(ProviderRemovalContext {
        scm_ace: ScmAceDisposition::TransferredForUpgrade {
            owned: rollback.scm_connect_ace_owned,
        },
    })?;
    let mut restored_transition =
        InstallTransition::new(InstallIntent::from_ephemeral_ci(ephemeral_ci));
    install_transaction(
        &rollback.binary,
        &rollback.target_desktop_bootstrap,
        &rollback.session_broker,
        &mut restored_transition,
    )?;
    if rollback.scm_connect_ace_owned {
        std::fs::write(
            state_root().join("package").join(SCM_CONNECT_ACE_MARKER),
            b"owned\n",
        )
        .map_err(|error| error.to_string())?;
    }
    if let Some(qualification_backup) = &rollback.qualification {
        let destination = state_root().join("package").join("qualification.json");
        let staged = destination.with_extension("json.new");
        std::fs::copy(qualification_backup, &staged).map_err(|error| error.to_string())?;
        super::record::replace_atomically(&staged, &destination)?;
    }
    drop(restored_transition);
    match bootstrap_error {
        Some(error) => Err(format!(
            "upgrade replacement was removed and the prior provider restored, but bootstrap restoration failed: {error}"
        )),
        None => Ok(()),
    }
}

fn cleanup_upgrade_rollback(rollback: &UpgradeRollback) {
    for path in std::iter::once(&rollback.binary)
        .chain(std::iter::once(&rollback.target_desktop_bootstrap))
        .chain(std::iter::once(&rollback.session_broker))
        .chain(rollback.qualification.iter())
    {
        if path_absent_no_follow(path, "cleanup-upgrade-rollback") == Ok(false) {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn install_transaction(
    source: &Path,
    source_bootstrap: &Path,
    source_broker: &Path,
    transition: &mut InstallTransition,
) -> Result<(), String> {
    let source_artifacts = capture_package_artifacts(source, source_bootstrap, source_broker)?;
    let install_root = install_root();
    let state_root = state_root();
    reject_reparse_components(&install_root)?;
    reject_reparse_components(&state_root)?;
    let install_security = SecurityDescriptor::from_sddl(INSTALL_SDDL)?;
    create_secure_directory(
        &install_root,
        &install_security,
        "create package install root",
    )?;
    reject_reparse_components(&install_root)?;
    let destination = installed_binary();
    copy_atomically_bytes(&source_artifacts.agent_bytes, &destination)?;
    copy_atomically_bytes(
        &source_artifacts.target_desktop_bootstrap_bytes,
        &installed_target_desktop_bootstrap(),
    )?;
    copy_atomically_bytes(
        &source_artifacts.session_broker_bytes,
        &installed_session_broker(),
    )?;
    let bootstrap_security = SecurityDescriptor::from_sddl(&state_bootstrap_sddl()?)?;
    let state_parent = state_root
        .parent()
        .ok_or_else(|| "Windows sealed state root has no parent".to_owned())?;
    create_secure_directory(
        state_parent,
        &SecurityDescriptor::from_sddl(&state_parent_sddl()?)?,
        "create package state parent",
    )?;
    transition.retain(state_parent, &state_parent_sddl()?)?;
    create_secure_directory(
        &state_root,
        &bootstrap_security,
        "create bootstrap state root",
    )?;
    transition.retain(&state_root, &state_bootstrap_sddl()?)?;
    reject_reparse_components(&state_root)?;
    for directory in [
        "attempts",
        "quarantine",
        "guardian-receipts",
        "guardian-slots",
    ] {
        let path = state_root.join(directory);
        create_secure_directory(&path, &bootstrap_security, "create bootstrap runtime state")?;
        transition.retain(&path, &state_bootstrap_sddl()?)?;
    }
    let replay = state_root.join("replay");
    create_secure_directory(
        &replay,
        &bootstrap_security,
        "create bootstrap replay state",
    )?;
    transition.retain(&replay, &state_bootstrap_sddl()?)?;
    let admissions = state_root.join("admissions");
    create_secure_directory(
        &admissions,
        &bootstrap_security,
        "create bootstrap admission state",
    )?;
    transition.retain(&admissions, &state_bootstrap_sddl()?)?;
    let package_path = state_root.join("package");
    create_secure_directory(
        &package_path,
        &bootstrap_security,
        "create bootstrap package state",
    )?;
    transition.retain(&package_path, &state_bootstrap_sddl()?)?;
    let certification_markers = package_path.join("certification-markers");
    create_secure_directory(
        &certification_markers,
        &bootstrap_security,
        "create bootstrap certification markers",
    )?;
    transition.retain_with_security_transition(
        &certification_markers,
        &state_bootstrap_sddl()?,
        DirectorySecurityTransition::DaclAndMandatoryLabel,
    )?;

    let marker = package_path.join("ephemeral-ci");
    establish_ephemeral_marker(
        transition.intent,
        || {
            std::fs::write(&marker, EPHEMERAL_CI_MARKER_CONTENTS).map_err(|error| {
                format!(
                    "MCSEALED-WINDOWS-INSTALL-STATE: cannot write ephemeral package marker: {error}"
                )
            })
        },
        ephemeral_ci_enabled,
    )?;

    validate_installed_artifacts(&source_artifacts.digests)?;
    let services = configure_services(&destination, ServiceConfiguration::Fresh(transition))?;
    harden_runtime_state_security(transition)?;
    transition.phase = InstallPhase::RuntimeSealed;
    start_services(&services)?;
    transition.phase = InstallPhase::ServiceCleanupAvailable;
    verify_live_installed_state()?;
    transition.phase = InstallPhase::ReadyForQualification;
    Ok(())
}

struct ConfiguredServices {
    _session_broker: service_manager::ScHandle,
    launcher: service_manager::ScHandle,
    control: service_manager::ScHandle,
    _guardian_slots: Vec<service_manager::ScHandle>,
}

enum ServiceConfiguration<'a> {
    Fresh(&'a mut InstallTransition),
    Reconcile,
}

fn configure_services(
    binary: &Path,
    mut configuration: ServiceConfiguration<'_>,
) -> Result<ConfiguredServices, String> {
    let manager = service_manager::manager()?;
    if matches!(&configuration, ServiceConfiguration::Fresh(_)) {
        require_fresh_service_absence(&manager)?;
    }
    let scm_ace_created = match super::security::scm_launcher_connect_state(manager.raw())? {
        super::security::ScmLauncherAceState::Exact => false,
        super::security::ScmLauncherAceState::Absent => {
            super::security::set_scm_launcher_connect(manager.raw(), true)?;
            if let ServiceConfiguration::Fresh(transition) = &mut configuration {
                transition.scm_connect_ace_created = true;
            }
            true
        }
    };
    if scm_ace_created {
        if let Err(marker_error) = std::fs::write(
            state_root().join("package").join(SCM_CONNECT_ACE_MARKER),
            b"owned\n",
        ) {
            if matches!(&configuration, ServiceConfiguration::Reconcile) {
                return match super::security::set_scm_launcher_connect(manager.raw(), false) {
                    Ok(()) => Err(format!(
                        "cannot persist SCM launcher connect ownership marker: {marker_error}"
                    )),
                    Err(rollback_error) => Err(format!(
                        "cannot persist SCM launcher connect ownership marker and cannot revoke the newly added ACE: marker={marker_error}; rollback={rollback_error}"
                    )),
                };
            }
            return Err(format!(
                "cannot persist SCM launcher connect ownership marker: {marker_error}"
            ));
        }
    }
    let executable = binary.to_string_lossy().into_owned();
    let session_broker_executable = installed_session_broker().to_string_lossy().into_owned();
    let session_broker_command = String::from_utf16_lossy(&super::process::encode_command_line(&[
        session_broker_executable.encode_utf16().collect(),
    ]));
    let launcher_command = super::process::encode_command_line(&[
        executable.encode_utf16().collect(),
        "windows-launcher".encode_utf16().collect(),
    ]);
    let control_command = super::process::encode_command_line(&[
        executable.encode_utf16().collect(),
        "windows-control".encode_utf16().collect(),
    ]);
    let launcher_command = String::from_utf16_lossy(&launcher_command);
    let control_command = String::from_utf16_lossy(&control_command);
    let session_broker_config = SessionBrokerConfig {
        name: WINDOWS_SESSION_BROKER_SERVICE_NAME,
        display_name: "MemCordon sealed target-session broker",
        binary_command: &session_broker_command,
        required_privileges: SESSION_BROKER_PRIVILEGES,
    };
    let launcher_config = ServiceConfig {
        name: WINDOWS_LAUNCHER_SERVICE_NAME,
        display_name: "MemCordon sealed privileged launcher",
        binary_command: &launcher_command,
        account: Some("LocalSystem"),
        dependencies: &[],
        required_privileges: LAUNCHER_PRIVILEGES,
        sid_type: ServiceSidType::Restricted,
    };
    let control_config = ServiceConfig {
        name: WINDOWS_CONTROL_SERVICE_NAME,
        display_name: "MemCordon sealed local control provider",
        binary_command: &control_command,
        account: Some(r"NT AUTHORITY\LocalService"),
        dependencies: &[WINDOWS_LAUNCHER_SERVICE_NAME],
        required_privileges: CONTROL_PRIVILEGES,
        sid_type: ServiceSidType::Restricted,
    };
    let mut guardian_slots = Vec::with_capacity(WINDOWS_GUARDIAN_SLOT_COUNT);
    for index in 0..WINDOWS_GUARDIAN_SLOT_COUNT {
        let name = super::security::guardian_slot_name(index)?;
        let command = guardian_slot_command(&executable, &name);
        let config = GuardianSlotConfig {
            name: &name,
            display_name: "MemCordon sealed guardian slot",
            binary_command: &command,
        };
        let slot = match &mut configuration {
            ServiceConfiguration::Reconcile => {
                service_manager::reconcile_guardian_slot(&manager, &config)?
            }
            ServiceConfiguration::Fresh(transition) => {
                let slot = service_manager::create_guardian_slot_registration(&manager, &config)?;
                transition.guardian_slots_created.push(name.clone());
                service_manager::configure_created_guardian_slot(&slot, &config)?;
                slot
            }
        };
        guardian_slots.push(slot);
    }
    let session_broker = match &mut configuration {
        ServiceConfiguration::Reconcile => {
            service_manager::reconcile_session_broker(&manager, &session_broker_config)?
        }
        ServiceConfiguration::Fresh(transition) => {
            let fault = transition
                .intent
                .authorized_session_broker_fault(certification_faults_enabled())?;
            let broker = service_manager::create_session_broker_registration(
                &manager,
                &session_broker_config,
            )?;
            transition.session_broker_created = true;
            match fault {
                Some(InstallSessionBrokerFault::AfterRegistration) => {
                    return Err(
                        "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected session-broker configuration fault after registration"
                            .to_owned(),
                    );
                }
                Some(InstallSessionBrokerFault::Configuration(fault)) => {
                    service_manager::configure_created_session_broker_with_fault(
                        &broker,
                        &session_broker_config,
                        fault,
                    )?;
                }
                None => service_manager::configure_created_session_broker(
                    &broker,
                    &session_broker_config,
                )?,
            }
            broker
        }
    };
    let launcher = match &mut configuration {
        ServiceConfiguration::Reconcile => service_manager::reconcile(&manager, &launcher_config)?,
        ServiceConfiguration::Fresh(transition) => {
            let launcher = service_manager::create_registration(&manager, &launcher_config)?;
            transition.launcher_created = true;
            service_manager::configure_created(&launcher, &launcher_config)?;
            launcher
        }
    };
    let control = match &mut configuration {
        ServiceConfiguration::Reconcile => service_manager::reconcile(&manager, &control_config)?,
        ServiceConfiguration::Fresh(transition) => {
            let control = service_manager::create_registration(&manager, &control_config)?;
            transition.control_created = true;
            service_manager::configure_created(&control, &control_config)?;
            control
        }
    };
    Ok(ConfiguredServices {
        _session_broker: session_broker,
        launcher,
        control,
        _guardian_slots: guardian_slots,
    })
}

fn require_fresh_service_absence(manager: &service_manager::ScHandle) -> Result<(), String> {
    let mut residuals = Vec::<String>::new();
    for name in [
        WINDOWS_CONTROL_SERVICE_NAME,
        WINDOWS_LAUNCHER_SERVICE_NAME,
        WINDOWS_SESSION_BROKER_SERVICE_NAME,
        // Every canonical slot is included below.
    ] {
        let exists = service_manager::exists(manager, name).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-SERVICE-PREFLIGHT: cannot inspect fresh service identity {name}: {error}"
            )
        })?;
        if exists {
            residuals.push(name.to_owned());
        }
    }
    for index in 0..WINDOWS_GUARDIAN_SLOT_COUNT {
        let name = super::security::guardian_slot_name(index)?;
        if service_manager::exists(manager, &name)? {
            residuals.push(name);
        }
    }
    if residuals.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "MCSEALED-WINDOWS-SERVICE-PREFLIGHT-RESIDUAL: fresh install found pre-existing service identities: {}",
            residuals.join(", ")
        ))
    }
}

fn start_services(services: &ConfiguredServices) -> Result<(), String> {
    service_manager::start(&services.launcher, WINDOWS_LAUNCHER_SERVICE_NAME)?;
    service_manager::start(&services.control, WINDOWS_CONTROL_SERVICE_NAME)
}

fn harden_runtime_state_security(transition: &InstallTransition) -> Result<(), String> {
    let root = state_root();
    let package = root.join("package");
    apply_final_directory_security(
        transition,
        &package.join("certification-markers"),
        &certification_marker_state_sddl()?,
        "seal certification markers",
    )?;
    let package_sddl = package_state_sddl()?;
    apply_final_directory_security(transition, &package, &package_sddl, "seal package state")?;

    let launcher_sddl = launcher_state_sddl()?;
    for directory in [
        "attempts",
        "quarantine",
        "guardian-receipts",
        "guardian-slots",
    ] {
        apply_final_directory_security(
            transition,
            &root.join(directory),
            &launcher_sddl,
            "seal runtime attempt state",
        )?;
    }
    apply_final_directory_security(
        transition,
        &root.join("replay"),
        &replay_state_sddl()?,
        "seal replay state",
    )?;
    apply_final_directory_security(
        transition,
        &root.join("admissions"),
        &admission_state_sddl()?,
        "seal admission state",
    )?;
    apply_final_directory_security(transition, &root, &state_sddl()?, "seal state root")
}

fn apply_final_directory_security(
    transition: &InstallTransition,
    path: &Path,
    sddl: &str,
    phase: &str,
) -> Result<(), String> {
    let handle = transition.handle(path)?;
    let dacl = sddl.strip_prefix("O:BA").ok_or_else(|| {
        format!("MCSEALED-WINDOWS-DIRECTORY: {phase} policy is missing its fixed owner")
    })?;
    let applied = SecurityDescriptor::from_sddl(dacl)?;
    let mandatory_label_applied = applied.applies_mandatory_label();
    applied.apply_to_file_object(handle).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-DIRECTORY: {phase} at {}: {error}",
            path.display()
        )
    })?;
    if mandatory_label_applied {
        transition.mark_mandatory_label_applied(path)?;
    }
    SecurityDescriptor::from_sddl(sddl)?
        .verify_file_object(handle)
        .map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-DIRECTORY: {phase} security readback at {}: {error}",
                path.display()
            )
        })
}

pub fn certification_faults_enabled() -> bool {
    ephemeral_ci_enabled()
}

pub fn ephemeral_ci_enabled() -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let marker = state_root().join("package").join("ephemeral-ci");
    let Ok(metadata) = std::fs::symlink_metadata(&marker) else {
        return false;
    };
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return false;
    }
    if u64::try_from(EPHEMERAL_CI_MARKER_CONTENTS.len()).ok() != Some(metadata.len()) {
        return false;
    }
    std::fs::read(marker).is_ok_and(|contents| contents == EPHEMERAL_CI_MARKER_CONTENTS)
}

fn copy_atomically_bytes(bytes: &[u8], destination: &Path) -> Result<(), String> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    reject_reparse_components(destination)?;
    let staged = destination.with_extension("exe.new");
    reject_reparse_components(&staged)?;
    if !path_absent_no_follow(&staged, "prepare-staged-artifact")? {
        let metadata = std::fs::symlink_metadata(&staged).map_err(|error| error.to_string())?;
        if file_kind(&metadata) != "file" {
            return Err(format!(
                "MCSEALED-WINDOWS-ARTIFACT: phase=prepare-staged-artifact path={} expected=absent-or-regular-file actual={}",
                staged.display(),
                file_kind(&metadata),
            ));
        }
        std::fs::remove_file(&staged).map_err(|error| error.to_string())?;
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = options.open(&staged).map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    reject_reparse_components(&staged)?;
    super::record::replace_atomically(&staged, destination)?;
    reject_reparse_components(destination)
}

fn create_secure_directory(
    path: &Path,
    security: &SecurityDescriptor,
    phase: &str,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let attributes = security.attributes(false);
    // SAFETY: path is NUL-terminated and the descriptor/attributes remain live
    // for the synchronous creation call.
    if unsafe { CreateDirectoryW(path_wide.as_ptr(), &raw const attributes) } == 0 {
        let error = std::io::Error::last_os_error();
        if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            != Some(ERROR_ALREADY_EXISTS)
        {
            return Err(format!(
                "MCSEALED-WINDOWS-DIRECTORY: {phase} at {}: {error}",
                path.display()
            ));
        }
    }
    reject_reparse_components(path).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-DIRECTORY: {phase} reparse check at {}: {error}",
            path.display()
        )
    })?;
    security.verify_path(path).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-DIRECTORY: {phase} security readback at {}: {error}",
            path.display()
        )
    })
}

pub(crate) fn reject_reparse_components(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let mut components = path.ancestors().collect::<Vec<_>>();
    components.reverse();
    for component in components {
        match std::fs::symlink_metadata(component) {
            Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                return Err(format!(
                    "MCSEALED-WINDOWS-REPARSE: provider path contains a reparse link: {}",
                    component.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn uninstall_services() -> Result<(), String> {
    let manager = service_manager::manager()?;
    let control = service_manager::remove(&manager, WINDOWS_CONTROL_SERVICE_NAME);
    let launcher = service_manager::remove(&manager, WINDOWS_LAUNCHER_SERVICE_NAME);
    let broker = service_manager::remove(&manager, WINDOWS_SESSION_BROKER_SERVICE_NAME);
    let mut results = vec![
        ("control", control),
        ("launcher", launcher),
        ("session broker", broker),
    ];
    for index in (0..WINDOWS_GUARDIAN_SLOT_COUNT).rev() {
        let name = super::security::guardian_slot_name(index)?;
        results.push(("guardian slot", service_manager::remove(&manager, &name)));
    }
    let failures = results
        .into_iter()
        .filter_map(|(role, result)| result.err().map(|error| format!("{role}: {error}")))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("service removal failed: {}", failures.join("; ")))
    }
}

fn uninstall_transaction_services(ownership: &ServiceOwnership) -> Result<(), String> {
    if ownership.guardian_slots_created.is_empty()
        && !ownership.session_broker_created
        && !ownership.launcher_created
        && !ownership.control_created
        && !ownership.scm_connect_ace_created
    {
        return Ok(());
    }
    let manager = service_manager::manager()?;
    let mut residuals = Vec::new();
    for (created, name) in [
        (ownership.control_created, WINDOWS_CONTROL_SERVICE_NAME),
        (ownership.launcher_created, WINDOWS_LAUNCHER_SERVICE_NAME),
        (
            ownership.session_broker_created,
            WINDOWS_SESSION_BROKER_SERVICE_NAME,
        ),
    ] {
        if created {
            if let Err(error) = service_manager::remove(&manager, name) {
                residuals.push(format!("{name}: {error}"));
            }
        }
    }
    for name in ownership.guardian_slots_created.iter().rev() {
        if let Err(error) = service_manager::remove(&manager, name) {
            residuals.push(format!("{name}: {error}"));
        }
    }
    if residuals.is_empty() {
        if ownership.scm_connect_ace_created {
            super::security::set_scm_launcher_connect(manager.raw(), false)?;
        }
        Ok(())
    } else {
        Err(format!(
            "MCSEALED-WINDOWS-SERVICE-ROLLBACK-RESIDUAL: transaction-owned service cleanup failed: {}",
            residuals.join("; ")
        ))
    }
}

fn reconcile_services_from_installed() -> Result<(), String> {
    let _installed_artifacts = validate_existing_installed_artifacts()?;
    let services = configure_services(&installed_binary(), ServiceConfiguration::Reconcile)?;
    reconcile_runtime_state_security()?;
    start_services(&services)
}

fn reconcile_runtime_state_security() -> Result<(), String> {
    let root = state_root();
    reject_reparse_components(&root)?;
    if path_absent_no_follow(&root, "reconcile-runtime-state")? {
        return Ok(());
    }
    SecurityDescriptor::from_sddl(&state_parent_sddl()?)?.verify_path(
        root.parent()
            .ok_or_else(|| "Windows sealed state root has no parent".to_owned())?,
    )?;
    SecurityDescriptor::from_sddl(&state_sddl()?)?.verify_path(&root)?;
    let launcher_state = SecurityDescriptor::from_sddl(&launcher_state_sddl()?)?;
    for directory in [
        "attempts",
        "quarantine",
        "guardian-receipts",
        "guardian-slots",
    ] {
        let path = root.join(directory);
        launcher_state.verify_path(&path)?;
    }
    let replay = root.join("replay");
    SecurityDescriptor::from_sddl(&replay_state_sddl()?)?.verify_path(&replay)?;
    let admissions = root.join("admissions");
    SecurityDescriptor::from_sddl(&admission_state_sddl()?)?.verify_path(&admissions)?;
    SecurityDescriptor::from_sddl(&package_state_sddl()?)?.verify_path(&root.join("package"))?;
    reconcile_certification_marker_security(&root.join("package").join("certification-markers"))
}

pub(crate) fn reconcile_certification_marker_security(path: &Path) -> Result<(), String> {
    let expected = SecurityDescriptor::from_sddl(&certification_marker_state_sddl()?)?;
    let expected_error = match expected.verify_path(path) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };

    // Accept only exact historical descriptors for a one-way transition. The
    // immediate predecessor granted BA delete-child and reopenable producer
    // DELETE; the earlier predecessor predated Write Restricted Code.
    let pre_destructive_authority = SecurityDescriptor::from_sddl(
        &pre_destructive_authority_hardening_certification_marker_state_sddl()?,
    )?;
    let pre_destructive_authority_error = pre_destructive_authority.verify_path(path).err();
    let pre_write_restricted =
        SecurityDescriptor::from_sddl(&pre_write_restricted_certification_marker_state_sddl()?)?;
    if let Some(pre_destructive_authority_error) = pre_destructive_authority_error {
        if let Err(pre_write_restricted_error) = pre_write_restricted.verify_path(path) {
            let package_legacy = SecurityDescriptor::from_sddl(&package_state_sddl()?)?;
            package_legacy.verify_path(path).map_err(|package_legacy_error| {
                format!(
                    "certification marker security matched neither current nor recognized legacy policy: current={expected_error}; pre-destructive-authority={pre_destructive_authority_error}; pre-write-restricted={pre_write_restricted_error}; package={package_legacy_error}"
                )
            })?;
        }
    }
    // SetFileSecurityW does not rewrite inherited ACEs on existing children.
    // Attempt directories are nonce-bound and never reused; package removal
    // retires only its exact protocol-owned descendant inventory after the
    // service-owned cleanup barrier, rejecting unexpected or reparse entries.
    expected.apply_to_path(path)?;
    expected.verify_path(path)
}

fn uninstall(ephemeral_ci: bool) -> Result<(), String> {
    service_owned_cleanup_barrier()?;
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
    let qualification_path = state_root().join("package").join("qualification.json");
    let qualification = if qualification_path.is_file() {
        Some(std::fs::read(&qualification_path).map_err(|error| error.to_string())?)
    } else {
        None
    };
    if let Err(remove_error) = uninstall_services() {
        let reconcile = reconcile_services_from_installed();
        return match reconcile {
            Ok(()) => Err(format!(
                "MCSEALED-WINDOWS-UNINSTALL-ROLLED-BACK: service removal failed and the installed pair was restored: {remove_error}"
            )),
            Err(reconcile_error) => Err(format!(
                "MCSEALED-WINDOWS-UNINSTALL-ROLLBACK-FAILED: remove={remove_error}; reconcile={reconcile_error}"
            )),
        };
    }
    let scm_ace = if scm_ownership_marker_present()? {
        let manager = service_manager::manager()?;
        super::security::set_scm_launcher_connect(manager.raw(), false)?;
        ScmAceDisposition::Revoked
    } else {
        ScmAceDisposition::NotOwned
    };
    if let Err(remove_error) = remove_provider_files(ProviderRemovalContext { scm_ace }) {
        let mut transition = InstallTransition::new(InstallIntent::from_ephemeral_ci(ephemeral_ci));
        let source_bootstrap = packaged_target_desktop_bootstrap(&source)?;
        let source_broker = packaged_session_broker(&source)?;
        let rollback =
            install_transaction(&source, &source_bootstrap, &source_broker, &mut transition)
                .and_then(|()| {
                    if let Some(qualification) = qualification {
                        let destination = state_root().join("package").join("qualification.json");
                        let staged = destination.with_extension("json.new");
                        std::fs::write(&staged, qualification)
                            .map_err(|error| error.to_string())?;
                        super::record::replace_atomically(&staged, &destination)?;
                    }
                    Ok(())
                });
        return match rollback {
            Ok(()) => Err(format!(
                "MCSEALED-WINDOWS-UNINSTALL-ROLLED-BACK: filesystem removal failed and the installed pair was restored: {remove_error}"
            )),
            Err(rollback_error) => Err(format!(
                "MCSEALED-WINDOWS-UNINSTALL-ROLLBACK-FAILED: remove={remove_error}; rollback={rollback_error}"
            )),
        };
    }
    Ok(())
}

fn scm_ownership_marker_present() -> Result<bool, String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let marker = state_root().join("package").join(SCM_CONNECT_ACE_MARKER);
    match std::fs::symlink_metadata(&marker) {
        Ok(metadata)
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && metadata.is_file() =>
        {
            Ok(true)
        }
        Ok(metadata) => Err(format!(
            "MCSEALED-WINDOWS-INVENTORY: phase=inspect-scm-ownership-marker path={} expected=file actual={}",
            marker.display(),
            file_kind(&metadata)
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "MCSEALED-WINDOWS-INVENTORY: phase=inspect-scm-ownership-marker path={} expected=file actual=unreadable error={error}",
            marker.display()
        )),
    }
}

fn remove_provider_files(context: ProviderRemovalContext) -> Result<(), String> {
    require_removed_service_identities()?;
    let binary = installed_binary();
    let bootstrap = installed_target_desktop_bootstrap();
    let broker = installed_session_broker();
    remove_provider_state(context)?;
    remove_installed_binary_with_convergence(
        &binary,
        IMAGE_DELETE_DEADLINE,
        IMAGE_DELETE_RETRY_INTERVAL,
    )?;
    remove_installed_binary_with_convergence(
        &bootstrap,
        IMAGE_DELETE_DEADLINE,
        IMAGE_DELETE_RETRY_INTERVAL,
    )?;
    remove_installed_binary_with_convergence(
        &broker,
        IMAGE_DELETE_DEADLINE,
        IMAGE_DELETE_RETRY_INTERVAL,
    )?;
    let install = install_root();
    reject_reparse_components(&install)?;
    if !path_absent_no_follow(&install, "remove-install-root")? {
        std::fs::remove_dir(&install).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-REMOVE: cannot remove install root {}: {error}",
                install.display()
            )
        })?;
    }
    Ok(())
}

fn require_removed_service_identities() -> Result<(), String> {
    let manager = service_manager::manager().map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-REMOVE: phase=prove-services-absent path={}: {error}",
            installed_binary().display()
        )
    })?;
    let mut names = vec![
        WINDOWS_CONTROL_SERVICE_NAME.to_owned(),
        WINDOWS_LAUNCHER_SERVICE_NAME.to_owned(),
        WINDOWS_SESSION_BROKER_SERVICE_NAME.to_owned(),
    ];
    for index in 0..WINDOWS_GUARDIAN_SLOT_COUNT {
        names.push(super::security::guardian_slot_name(index)?);
    }
    for name in names {
        let exists = service_manager::exists(&manager, &name).map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-REMOVE: phase=prove-service-absent service={name} path={}: {error}",
                installed_binary().display()
            )
        })?;
        if exists {
            return Err(format!(
                "MCSEALED-WINDOWS-REMOVE: phase=prove-service-absent service={name} path={} result=still-registered",
                installed_binary().display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn remove_installed_binary_with_convergence(
    path: &Path,
    timeout: Duration,
    retry_interval: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    let mut attempts = 0_u32;
    loop {
        attempts = attempts.saturating_add(1);
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                let native_code = error
                    .raw_os_error()
                    .and_then(|value| u32::try_from(value).ok());
                let retryable = matches!(
                    native_code,
                    Some(ERROR_ACCESS_DENIED) | Some(ERROR_SHARING_VIOLATION)
                );
                if !retryable || started.elapsed() >= timeout {
                    return Err(format!(
                        "MCSEALED-WINDOWS-REMOVE: phase=delete-image path={} attempts={attempts} elapsed_ms={} native_code={native_code:?}: {error}",
                        path.display(),
                        started.elapsed().as_millis()
                    ));
                }
            }
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        std::thread::sleep(retry_interval.min(remaining));
    }
}

#[derive(Clone, Copy, Debug)]
enum PackageArtifact {
    QualificationReceipt,
    EphemeralCi,
    QualificationRollbackFault,
    ScmLauncherConnectOwnership,
    PreauthorizationFaultMatrix,
    RetirementFaultMatrix,
    TokenMatrix,
    AuthorityLoss,
    RuntimeMutants,
}

impl PackageArtifact {
    fn name(self) -> &'static str {
        match self {
            Self::QualificationReceipt => "qualification.json",
            Self::EphemeralCi => "ephemeral-ci",
            Self::QualificationRollbackFault => QUALIFICATION_ROLLBACK_FAULT,
            Self::ScmLauncherConnectOwnership => SCM_CONNECT_ACE_MARKER,
            Self::PreauthorizationFaultMatrix => "preauthorization-fault-matrix.json",
            Self::RetirementFaultMatrix => "retirement-fault-matrix.json",
            Self::TokenMatrix => "token-matrix.json",
            Self::AuthorityLoss => "authority-loss.json",
            Self::RuntimeMutants => "runtime-mutants.json",
        }
    }

    fn phase(self) -> &'static str {
        match self {
            Self::QualificationReceipt => "remove qualification receipt",
            Self::EphemeralCi => "remove ephemeral package marker",
            Self::QualificationRollbackFault => "remove qualification rollback fault",
            Self::ScmLauncherConnectOwnership => "remove SCM launcher connect ownership marker",
            Self::PreauthorizationFaultMatrix => "remove preauthorization fault matrix",
            Self::RetirementFaultMatrix => "remove retirement fault matrix",
            Self::TokenMatrix => "remove token matrix",
            Self::AuthorityLoss | Self::RuntimeMutants => "remove certification evidence",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum StateDirectory {
    CertificationMarkers,
    Package,
    Attempts,
    Quarantine,
    Admissions,
    Replay,
    GuardianReceipts,
    GuardianSlots,
    StateRoot,
    StateParent,
}

impl StateDirectory {
    fn phase(self) -> &'static str {
        match self {
            Self::CertificationMarkers => "remove certification markers",
            Self::Package => "remove package state",
            Self::Attempts => "remove attempt state",
            Self::Quarantine => "remove quarantine state",
            Self::Admissions => "remove admission state",
            Self::Replay => "remove replay state",
            Self::GuardianReceipts => "remove guardian receipt state",
            Self::GuardianSlots => "remove guardian slot lease state",
            Self::StateRoot => "remove state root",
            Self::StateParent => "remove package state parent",
        }
    }
}

fn remove_provider_state(context: ProviderRemovalContext) -> Result<(), String> {
    let state = state_root();
    reject_reparse_components(&state)?;
    let state_present = match std::fs::symlink_metadata(&state) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(removal_error(
                StateDirectory::StateRoot.phase(),
                &state,
                context,
                format!("expected=directory actual=unreadable root=StateRoot error={error}"),
            ));
        }
    };
    if state_present {
        let package = state.join("package");
        for artifact in [
            PackageArtifact::QualificationReceipt,
            PackageArtifact::EphemeralCi,
            PackageArtifact::QualificationRollbackFault,
            PackageArtifact::ScmLauncherConnectOwnership,
            PackageArtifact::PreauthorizationFaultMatrix,
            PackageArtifact::RetirementFaultMatrix,
            PackageArtifact::TokenMatrix,
            PackageArtifact::AuthorityLoss,
            PackageArtifact::RuntimeMutants,
        ] {
            remove_file_if_present(&package.join(artifact.name()), artifact, context)?;
        }
        remove_retired_certification_workspaces(&package.join("certification-markers"), context)?;
        remove_directory_if_present(
            &package.join("certification-markers"),
            StateDirectory::CertificationMarkers,
            context,
        )?;
        remove_directory_if_present(&package, StateDirectory::Package, context)?;
        for (name, directory) in [
            ("attempts", StateDirectory::Attempts),
            ("quarantine", StateDirectory::Quarantine),
            ("admissions", StateDirectory::Admissions),
            ("replay", StateDirectory::Replay),
            ("guardian-receipts", StateDirectory::GuardianReceipts),
            ("guardian-slots", StateDirectory::GuardianSlots),
        ] {
            remove_directory_if_present(&state.join(name), directory, context)?;
        }
        remove_state_root_with_kernel_empty_proof(&state, context)?;
    }
    let parent = state
        .parent()
        .ok_or_else(|| "Windows sealed state root has no parent".to_owned())?;
    remove_directory_if_present(parent, StateDirectory::StateParent, context)?;
    Ok(())
}

fn remove_retired_certification_workspaces(
    marker_root: &Path,
    context: ProviderRemovalContext,
) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let entries = match std::fs::read_dir(marker_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(removal_error(
                StateDirectory::CertificationMarkers.phase(),
                marker_root,
                context,
                format!("expected=readable-directory actual=unreadable error={error}"),
            ));
        }
    };
    let digest_length = super::record::digest(&[]).len();
    for entry in entries {
        let entry = entry.map_err(|error| {
            removal_error(
                StateDirectory::CertificationMarkers.phase(),
                marker_root,
                context,
                format!("expected=readable-entry actual=unreadable error={error}"),
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(digest) = name.strip_prefix("attempt-") else {
            continue;
        };
        if digest.len() != digest_length
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            continue;
        }
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            removal_error(
                StateDirectory::CertificationMarkers.phase(),
                &path,
                context,
                format!("expected=directory actual=unreadable error={error}"),
            )
        })?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
            continue;
        }

        // All services, admissions, Jobs, and recovery leases were proven
        // absent before provider-state removal. Only these protocol-owned
        // names are retired; unexpected contents remain visible and fail the
        // subsequent exact-directory removal.
        for child in retired_certification_workspace_paths(&path) {
            match std::fs::symlink_metadata(&child) {
                Ok(metadata)
                    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
                        && metadata.is_file() =>
                {
                    std::fs::remove_file(&child).map_err(|error| {
                        removal_error(
                            StateDirectory::CertificationMarkers.phase(),
                            &child,
                            context,
                            format!("expected=file actual=file error={error}"),
                        )
                    })?;
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(removal_error(
                        StateDirectory::CertificationMarkers.phase(),
                        &child,
                        context,
                        format!("expected=file actual=unreadable error={error}"),
                    ));
                }
            }
        }
        std::fs::remove_dir(&path).map_err(|error| {
            removal_error(
                StateDirectory::CertificationMarkers.phase(),
                &path,
                context,
                format!("expected=empty-directory actual=residual error={error}"),
            )
        })?;
    }
    Ok(())
}

fn retired_certification_workspace_paths(workspace: &Path) -> Vec<std::path::PathBuf> {
    let mut paths = [
        "nested-child.json",
        "nested-child.json.new",
        "target.result",
        "target.result.new",
        "cleanup.ready",
    ]
    .into_iter()
    .map(|leaf| workspace.join(leaf))
    .collect::<Vec<_>>();
    paths.extend(super::qualification::cleanup_process_creation_owned_paths(
        &workspace.join("cleanup.marker"),
    ));
    paths
}

pub(crate) fn remove_retired_certification_workspaces_for_test(
    marker_root: &Path,
) -> Result<(), String> {
    remove_retired_certification_workspaces(
        marker_root,
        ProviderRemovalContext {
            scm_ace: ScmAceDisposition::NotOwned,
        },
    )
}

pub(crate) fn retired_certification_workspace_paths_for_test(
    workspace: &Path,
) -> Vec<std::path::PathBuf> {
    retired_certification_workspace_paths(workspace)
}

fn seed_retired_certification_workspace() -> Result<(), String> {
    let _low_integrity = super::token::impersonate_low_integrity_current_thread()?;
    let workspace = state_root()
        .join("package")
        .join("certification-markers")
        .join(format!(
            "attempt-{}",
            "0".repeat(super::record::digest(&[]).len())
        ));
    std::fs::create_dir(&workspace).map_err(|error| {
        format!(
            "MCSEALED-WINDOWS-CERTIFICATION-WORKSPACE: create stale workspace {}: {error}",
            workspace.display()
        )
    })?;
    for path in retired_certification_workspace_paths(&workspace) {
        std::fs::write(&path, b"retired certification evidence\n").map_err(|error| {
            format!(
                "MCSEALED-WINDOWS-CERTIFICATION-WORKSPACE: seed stale leaf {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn remove_file_if_present(
    path: &Path,
    artifact: PackageArtifact,
    context: ProviderRemovalContext,
) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(removal_error(
                artifact.phase(),
                path,
                context,
                format!("expected=file actual=unreadable artifact={artifact:?} error={error}"),
            ));
        }
    };
    let actual = file_kind(&metadata);
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file() {
        return Err(removal_error(
            artifact.phase(),
            path,
            context,
            format!("expected=file actual={actual} artifact={artifact:?}"),
        ));
    }
    std::fs::remove_file(path).map_err(|error| {
        removal_error(
            artifact.phase(),
            path,
            context,
            format!("expected=file actual={actual} artifact={artifact:?} error={error}"),
        )
    })
}

fn remove_directory_if_present(
    path: &Path,
    directory: StateDirectory,
    context: ProviderRemovalContext,
) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(removal_error(
                directory.phase(),
                path,
                context,
                format!("expected=directory actual=unreadable root={directory:?} error={error}"),
            ));
        }
    };
    let actual = file_kind(&metadata);
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
        return Err(removal_error(
            directory.phase(),
            path,
            context,
            format!("expected=directory actual={actual} root={directory:?}"),
        ));
    }
    let (residuals, truncated) = bounded_residual_inventory(path, directory, context)?;
    if !residuals.is_empty() {
        return Err(removal_error(
            directory.phase(),
            path,
            context,
            format!(
                "expected=empty-directory actual=directory root={directory:?} residual_count_at_least={} truncated={truncated} residuals=[{}]",
                residuals.len(),
                residuals.join("; ")
            ),
        ));
    }
    std::fs::remove_dir(path).map_err(|error| {
        removal_error(
            directory.phase(),
            path,
            context,
            format!(
                "expected=empty-directory actual=directory root={directory:?} native_code={:?} error={error}",
                error.raw_os_error()
            ),
        )
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactPathDirectoryRemovalFailure {
    ResidualPresentButNotEnumerable,
    AccessDenied,
    NativeFailure,
}

impl ExactPathDirectoryRemovalFailure {
    fn from_error(error: &std::io::Error) -> Self {
        match error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
        {
            Some(ERROR_DIR_NOT_EMPTY) => Self::ResidualPresentButNotEnumerable,
            Some(ERROR_ACCESS_DENIED) => Self::AccessDenied,
            _ => Self::NativeFailure,
        }
    }

    fn diagnostic(self) -> (&'static str, &'static str) {
        match self {
            Self::ResidualPresentButNotEnumerable => {
                ("non-empty-directory", "residual-present-but-not-enumerable")
            }
            Self::AccessDenied => ("exact-path-delete-denied", "access-denied"),
            Self::NativeFailure => ("exact-path-delete-failed", "native-failure"),
        }
    }
}

fn remove_state_root_with_kernel_empty_proof(
    path: &Path,
    context: ProviderRemovalContext,
) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let directory = StateDirectory::StateRoot;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(removal_error(
                directory.phase(),
                path,
                context,
                format!("expected=directory actual=unreadable root={directory:?} error={error}"),
            ));
        }
    };
    let actual = file_kind(&metadata);
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_dir() {
        return Err(removal_error(
            directory.phase(),
            path,
            context,
            format!("expected=directory actual={actual} root={directory:?}"),
        ));
    }
    std::fs::remove_dir(path).map_err(|error| {
        let failure = ExactPathDirectoryRemovalFailure::from_error(&error);
        let (actual, failure) = failure.diagnostic();
        removal_error(
            directory.phase(),
            path,
            context,
            format!(
                "expected=empty-directory actual={actual} root={directory:?} inspection=kernel-empty-proof-no-list-authority failure={failure} residual_inventory=not-collected native_code={:?} error={error}",
                error.raw_os_error()
            ),
        )
    })
}

fn bounded_residual_inventory(
    path: &Path,
    directory: StateDirectory,
    context: ProviderRemovalContext,
) -> Result<(Vec<String>, bool), String> {
    const RESIDUAL_LIMIT: usize = 16;

    let entries = std::fs::read_dir(path).map_err(|error| {
        removal_error(
            directory.phase(),
            path,
            context,
            format!(
                "expected=readable-directory actual=unreadable root={directory:?} error={error}"
            ),
        )
    })?;
    let mut residuals = Vec::new();
    let mut truncated = false;
    for entry in entries {
        let entry = entry.map_err(|error| {
            removal_error(
                directory.phase(),
                path,
                context,
                format!(
                    "expected=readable-entry actual=unreadable root={directory:?} error={error}"
                ),
            )
        })?;
        if residuals.len() == RESIDUAL_LIMIT {
            truncated = true;
            break;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let actual = std::fs::symlink_metadata(entry.path())
            .map(|metadata| file_kind(&metadata))
            .unwrap_or("unreadable");
        let (artifact, expected) = classify_residual(directory, &name);
        residuals.push(format!(
            "entry={name:?},actual={actual},expected={expected},artifact={artifact}"
        ));
    }
    residuals.sort();
    Ok((residuals, truncated))
}

fn classify_residual(directory: StateDirectory, name: &str) -> (&'static str, &'static str) {
    match directory {
        StateDirectory::Package => match name {
            "qualification.json" => ("QualificationReceipt", "file"),
            "qualification.json.new" => ("QualificationReceiptStaged", "absent"),
            "ephemeral-ci" => ("EphemeralCi", "file"),
            QUALIFICATION_ROLLBACK_FAULT => ("QualificationRollbackFault", "file"),
            SCM_CONNECT_ACE_MARKER => ("ScmLauncherConnectOwnership", "file"),
            "preauthorization-fault-matrix.json" => ("PreauthorizationFaultMatrix", "file"),
            "retirement-fault-matrix.json" => ("RetirementFaultMatrix", "file"),
            "token-matrix.json" => ("TokenMatrix", "file"),
            "token-matrix.json.new" => ("TokenMatrixStaged", "absent"),
            "authority-loss.json" => ("AuthorityLoss", "file"),
            "authority-loss.json.new" => ("AuthorityLossStaged", "absent"),
            "runtime-mutants.json" => ("RuntimeMutants", "file"),
            "runtime-mutants.json.new" => ("RuntimeMutantsStaged", "absent"),
            "certification-markers" => ("CertificationMarkers", "empty-directory"),
            _ => ("Unknown", "absent"),
        },
        StateDirectory::GuardianSlots => guardian_slot_residual(name),
        StateDirectory::CertificationMarkers => ("CertificationMarker", "absent"),
        _ => ("Unknown", "absent"),
    }
}

fn guardian_slot_residual(name: &str) -> (&'static str, &'static str) {
    let (index, suffix, artifact) = if let Some(index) = name.strip_suffix(".json.new") {
        (index, ".json.new", "GuardianSlotLeaseStaged")
    } else if let Some(index) = name.strip_suffix(".json") {
        (index, ".json", "GuardianSlotLease")
    } else {
        return ("Unknown", "absent");
    };
    match index.parse::<usize>() {
        Ok(value)
            if value < WINDOWS_GUARDIAN_SLOT_COUNT && name == format!("{value:03}{suffix}") =>
        {
            (artifact, "absent")
        }
        _ => ("Unknown", "absent"),
    }
}

fn file_kind(metadata: &std::fs::Metadata) -> &'static str {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        "reparse"
    } else if metadata.is_file() {
        "file"
    } else if metadata.is_dir() {
        "directory"
    } else {
        "other"
    }
}

fn removal_error(
    phase: &str,
    path: &Path,
    context: ProviderRemovalContext,
    detail: String,
) -> String {
    format!(
        "MCSEALED-WINDOWS-REMOVE: phase={phase:?} path={} {detail} authority={} services=proven-absent package_lease=held",
        path.display(),
        context.authority_attestation()
    )
}

fn package_attempts_empty() -> Result<bool, String> {
    let root = state_root();
    reject_reparse_components(&root)?;
    if path_absent_no_follow(&root, "package-attempts-state-root")? {
        return Ok(true);
    }
    if !super::qualification::recovery_status()? {
        return Ok(false);
    }
    let leases = root.join("guardian-slots");
    reject_reparse_components(&leases)?;
    if !path_absent_no_follow(&leases, "package-attempts-guardian-slots")?
        && std::fs::read_dir(&leases)
            .map_err(|error| error.to_string())?
            .next()
            .is_some()
    {
        return Ok(false);
    }
    let manager = service_manager::manager()?;
    if service_manager::exists(&manager, WINDOWS_SESSION_BROKER_SERVICE_NAME)?
        && service_manager::is_running(&manager, WINDOWS_SESSION_BROKER_SERVICE_NAME)?
    {
        return Ok(false);
    }
    for index in 0..WINDOWS_GUARDIAN_SLOT_COUNT {
        let name = super::security::guardian_slot_name(index)?;
        if service_manager::exists(&manager, &name)?
            && service_manager::is_running(&manager, &name)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn provider_state_absent() -> Result<bool, String> {
    use memcordon_core::{
        WINDOWS_CONTROL_PIPE, WINDOWS_LAUNCHER_PIPE, WINDOWS_SESSION_BROKER_PIPE,
    };

    let manager = service_manager::manager()?;
    let mut services_absent = !service_manager::exists(&manager, WINDOWS_CONTROL_SERVICE_NAME)?
        && !service_manager::exists(&manager, WINDOWS_LAUNCHER_SERVICE_NAME)?
        && !service_manager::exists(&manager, WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    for index in 0..WINDOWS_GUARDIAN_SLOT_COUNT {
        services_absent &=
            !service_manager::exists(&manager, &super::security::guardian_slot_name(index)?)?;
    }
    let pipes_absent = !super::pipe::endpoint_exists(WINDOWS_CONTROL_PIPE)?
        && !super::pipe::endpoint_exists(WINDOWS_LAUNCHER_PIPE)?
        && !super::pipe::endpoint_exists(WINDOWS_SESSION_BROKER_PIPE)?;
    let state = state_root();
    let state_parent = state
        .parent()
        .ok_or_else(|| "Windows sealed state root has no parent".to_owned())?;
    let exact_inventory_absent = [
        state.join("package").join(SCM_CONNECT_ACE_MARKER),
        state.join("guardian-slots"),
    ]
    .iter()
    .map(|path| path_absent_no_follow(path, "attest provider inventory absence"))
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .all(|absent| absent);
    Ok(services_absent
        && pipes_absent
        && path_absent_no_follow(&install_root(), "attest install root absence")?
        && exact_inventory_absent
        && path_absent_no_follow(&state, "attest state root absence")?
        && path_absent_no_follow(state_parent, "attest state parent absence")?)
}

fn path_absent_no_follow(path: &Path, phase: &str) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!(
            "MCSEALED-WINDOWS-INVENTORY: phase={phase:?} path={} actual=unreadable error={error}",
            path.display()
        )),
    }
}

fn require_fresh_filesystem_absence() -> Result<(), String> {
    let inventory = [
        ("installed-agent", installed_binary()),
        (
            "installed-target-desktop-bootstrap",
            installed_target_desktop_bootstrap(),
        ),
        ("installed-session-broker", installed_session_broker()),
        ("installed-state-root", state_root()),
    ];
    for (role, path) in inventory {
        reject_reparse_components(&path)?;
        if !path_absent_no_follow(&path, "fresh-install-filesystem-preflight")? {
            let actual = std::fs::symlink_metadata(&path)
                .map(|metadata| file_kind(&metadata))
                .unwrap_or("unreadable");
            return Err(format!(
                "MCSEALED-WINDOWS-ALREADY-INSTALLED: phase=fresh-install-filesystem-preflight role={role} path={} expected=absent actual={actual}; use package upgrade for an existing provider",
                path.display(),
            ));
        }
    }
    Ok(())
}

pub fn verify_installed() -> Result<(), String> {
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
    let source_bootstrap = packaged_target_desktop_bootstrap(&source)?;
    let source_broker = packaged_session_broker(&source)?;
    verify_installed_against(&source, &source_bootstrap, &source_broker)
}

fn verify_installed_against(
    source: &Path,
    source_bootstrap: &Path,
    source_broker: &Path,
) -> Result<(), String> {
    let expected = capture_package_artifacts(source, source_bootstrap, source_broker)?;
    validate_installed_artifacts(&expected.digests)?;
    verify_live_installed_state()
}

fn validate_installed_artifacts(expected: &PackageArtifactDigests) -> Result<(), String> {
    reject_reparse_components(&install_root())?;
    reject_reparse_components(&state_root())?;
    reject_reparse_components(&installed_binary())?;
    reject_reparse_components(&installed_target_desktop_bootstrap())?;
    reject_reparse_components(&installed_session_broker())?;
    validate_artifact_pair(
        &installed_binary(),
        &installed_target_desktop_bootstrap(),
        &installed_session_broker(),
        Some(expected),
    )?;
    Ok(())
}

fn validate_existing_installed_artifacts() -> Result<CapturedPackageArtifacts, String> {
    reject_reparse_components(&install_root())?;
    capture_package_artifacts(
        &installed_binary(),
        &installed_target_desktop_bootstrap(),
        &installed_session_broker(),
    )
}

fn verify_live_installed_state() -> Result<(), String> {
    let manager = service_manager::manager()?;
    if super::security::scm_launcher_connect_state(manager.raw())?
        != super::security::ScmLauncherAceState::Exact
    {
        return Err("Windows SCM launcher connect policy is absent".to_owned());
    }
    if !service_manager::is_running(&manager, WINDOWS_LAUNCHER_SERVICE_NAME)? {
        return Err("Windows sealed launcher service is not running".to_owned());
    }
    if !service_manager::is_running(&manager, WINDOWS_CONTROL_SERVICE_NAME)? {
        return Err("Windows sealed control service is not running".to_owned());
    }
    let executable = installed_binary().to_string_lossy().into_owned();
    let broker_executable = installed_session_broker().to_string_lossy().into_owned();
    let broker_command =
        String::from_utf16_lossy(&super::process::encode_command_line(&[broker_executable
            .encode_utf16()
            .collect()]));
    let launcher_command = String::from_utf16_lossy(&super::process::encode_command_line(&[
        executable.encode_utf16().collect(),
        "windows-launcher".encode_utf16().collect(),
    ]));
    let control_command = String::from_utf16_lossy(&super::process::encode_command_line(&[
        executable.encode_utf16().collect(),
        "windows-control".encode_utf16().collect(),
    ]));
    for index in 0..WINDOWS_GUARDIAN_SLOT_COUNT {
        let name = super::security::guardian_slot_name(index)?;
        let command = guardian_slot_command(&executable, &name);
        service_manager::verify_guardian_slot(
            &manager,
            &GuardianSlotConfig {
                name: &name,
                display_name: "MemCordon sealed guardian slot",
                binary_command: &command,
            },
        )?;
        if service_manager::is_running(&manager, &name)? {
            return Err(format!("guardian slot is unexpectedly active: {name}"));
        }
    }
    service_manager::verify_session_broker(
        &manager,
        &SessionBrokerConfig {
            name: WINDOWS_SESSION_BROKER_SERVICE_NAME,
            display_name: "MemCordon sealed target-session broker",
            binary_command: &broker_command,
            required_privileges: SESSION_BROKER_PRIVILEGES,
        },
    )?;
    if service_manager::is_running(&manager, WINDOWS_SESSION_BROKER_SERVICE_NAME)? {
        return Err("session broker is unexpectedly active outside a one-shot request".to_owned());
    }
    service_manager::verify(
        &manager,
        &ServiceConfig {
            name: WINDOWS_LAUNCHER_SERVICE_NAME,
            display_name: "MemCordon sealed privileged launcher",
            binary_command: &launcher_command,
            account: Some("LocalSystem"),
            dependencies: &[],
            required_privileges: LAUNCHER_PRIVILEGES,
            sid_type: ServiceSidType::Restricted,
        },
    )?;
    service_manager::verify(
        &manager,
        &ServiceConfig {
            name: WINDOWS_CONTROL_SERVICE_NAME,
            display_name: "MemCordon sealed local control provider",
            binary_command: &control_command,
            account: Some(r"NT AUTHORITY\LocalService"),
            dependencies: &[WINDOWS_LAUNCHER_SERVICE_NAME],
            required_privileges: CONTROL_PRIVILEGES,
            sid_type: ServiceSidType::Restricted,
        },
    )?;
    SecurityDescriptor::from_sddl(INSTALL_SDDL)?.verify_path(&install_root())?;
    SecurityDescriptor::from_sddl(&state_parent_sddl()?)?.verify_path(
        state_root()
            .parent()
            .ok_or_else(|| "Windows sealed state root has no parent".to_owned())?,
    )?;
    SecurityDescriptor::from_sddl(&state_sddl()?)?.verify_path(&state_root())?;
    let launcher_state = SecurityDescriptor::from_sddl(&launcher_state_sddl()?)?;
    for directory in [
        "attempts",
        "quarantine",
        "guardian-receipts",
        "guardian-slots",
    ] {
        launcher_state.verify_path(&state_root().join(directory))?;
    }
    SecurityDescriptor::from_sddl(&replay_state_sddl()?)?
        .verify_path(&state_root().join("replay"))?;
    SecurityDescriptor::from_sddl(&admission_state_sddl()?)?
        .verify_path(&state_root().join("admissions"))?;
    SecurityDescriptor::from_sddl(&package_state_sddl()?)?
        .verify_path(&state_root().join("package"))?;
    SecurityDescriptor::from_sddl(&certification_marker_state_sddl()?)?
        .verify_path(&state_root().join("package").join("certification-markers"))?;
    verify_service_process_protection(&manager)
}

fn verify_service_process_protection(manager: &service_manager::ScHandle) -> Result<(), String> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE};

    let process_ids = [
        service_manager::running_process_id(manager, WINDOWS_CONTROL_SERVICE_NAME)?,
        service_manager::running_process_id(manager, WINDOWS_LAUNCHER_SERVICE_NAME)?,
    ];
    let _restricted = super::token::impersonate_restricted_current_thread()?;
    for process_id in process_ids {
        // SAFETY: the PID comes from the live SCM status and the probe requests
        // no inherited handle.
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, process_id) };
        if !handle.is_null() {
            drop(super::pipe::OwnedHandle::new(handle)?);
            return Err(format!(
                "restricted package verifier retained service termination access: {process_id}"
            ));
        }
    }
    Ok(())
}

pub fn installed_inspection(
    agent: AgentPackageInspectionV3,
) -> Result<InstalledProviderInspectionV3, String> {
    verify_installed()?;
    let installed_executable_sha256 =
        crate::package::sha256_regular_no_follow(&installed_binary())?;
    let qualification = super::qualification::probe().ok();
    let qualification_complete = qualification
        .as_ref()
        .is_some_and(|receipt| receipt.qualified && receipt.is_consistent());
    Ok(InstalledProviderInspectionV3 {
        schema_version: 3,
        agent,
        installed_executable_sha256,
        installed_artifacts_valid: true,
        provider_identity: qualification.map(|receipt| receipt.provider_identity),
        provider_reachable: qualification_complete,
        qualification_complete,
    })
}
