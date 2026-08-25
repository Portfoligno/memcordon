use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use memcordon_core::{WINDOWS_CONTROL_SERVICE_NAME, WINDOWS_LAUNCHER_SERVICE_NAME};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
use windows_sys::Win32::System::Threading::CreateMutexW;

use crate::inspection_schema::{
    AgentPackageInspectionV2, InstalledProviderInspectionV2, ProviderPackageMetadataV2,
};

use super::security::{
    SecurityDescriptor, admission_state_sddl, launcher_state_sddl, package_state_sddl,
    replay_state_sddl, state_sddl,
};
use super::service_manager::{self, ServiceConfig};

const CONTROL_PRIVILEGES: &[&str] = &["SeImpersonatePrivilege"];
const LAUNCHER_PRIVILEGES: &[&str] = &["SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"];
const INSTALL_SDDL: &str =
    "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)(A;OICI;GRGX;;;AC)";

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

pub fn compiled_metadata() -> Result<ProviderPackageMetadataV2, String> {
    let executable = installed_binary().to_string_lossy().into_owned();
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
    );
    let launcher_config = service_config_record(
        WINDOWS_LAUNCHER_SERVICE_NAME,
        "MemCordon sealed privileged launcher",
        &launcher_command,
        "LocalSystem",
        &[],
        LAUNCHER_PRIVILEGES,
    );
    Ok(ProviderPackageMetadataV2::WindowsService {
        control_service_name: WINDOWS_CONTROL_SERVICE_NAME.to_owned(),
        launcher_service_name: WINDOWS_LAUNCHER_SERVICE_NAME.to_owned(),
        control_service_config_sha256: crate::package::sha256_bytes(control_config.as_bytes()),
        launcher_service_config_sha256: crate::package::sha256_bytes(launcher_config.as_bytes()),
        control_pipe: memcordon_core::WINDOWS_CONTROL_PIPE.to_owned(),
        launcher_pipe: memcordon_core::WINDOWS_LAUNCHER_PIPE.to_owned(),
        binary_install_path: installed_binary().to_string_lossy().into_owned(),
        state_root: state_root().to_string_lossy().into_owned(),
        control_service_sid_type: "restricted".to_owned(),
        launcher_service_sid_type: "restricted".to_owned(),
        control_required_privileges: CONTROL_PRIVILEGES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        launcher_required_privileges: LAUNCHER_PRIVILEGES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        control_pipe_security_sha256: crate::package::sha256_bytes(
            super::security::public_pipe_sddl()?.as_bytes(),
        ),
        launcher_pipe_security_sha256: crate::package::sha256_bytes(
            super::security::private_pipe_sddl()?.as_bytes(),
        ),
        install_directory_security_sha256: crate::package::sha256_bytes(INSTALL_SDDL.as_bytes()),
        state_directory_security_sha256: crate::package::sha256_bytes(state_sddl()?.as_bytes()),
    })
}

fn service_config_record(
    name: &str,
    display_name: &str,
    binary_command: &str,
    account: &str,
    dependencies: &[&str],
    privileges: &[&str],
) -> String {
    let mut fields = vec![
        name.to_owned(),
        display_name.to_owned(),
        binary_command.to_owned(),
        account.to_owned(),
        "service-type=win32-own-process".to_owned(),
        "start-type=automatic".to_owned(),
        "error-control=normal".to_owned(),
        "service-sid-type=restricted".to_owned(),
        format!("service-dacl={}", super::security::SERVICE_CONTROL_SDDL),
        "failure-reset-seconds=86400".to_owned(),
        "failure-actions=restart:1000,restart:5000".to_owned(),
        format!("dependencies={}", dependencies.join(",")),
    ];
    fields.extend(privileges.iter().map(|value| (*value).to_owned()));
    fields.join("\0")
}

pub fn mutate(operation: &OsStr, ephemeral_ci: bool) -> Result<(), String> {
    if operation == "install" {
        let lease = PackageLease::acquire()?;
        if state_root().exists() {
            reconcile_runtime_state_security()?;
        }
        install(ephemeral_ci)?;
        qualify_outside_package_lease(lease, None)
    } else if operation == "upgrade" {
        let lease = PackageLease::acquire()?;
        reconcile_runtime_state_security()?;
        if !package_attempts_empty()? {
            return Err(
                "MCSEALED-WINDOWS-UPGRADE-ACTIVE: provider has active or unreconciled attempts"
                    .to_owned(),
            );
        }
        let backup = upgrade(ephemeral_ci)?;
        qualify_outside_package_lease(lease, Some(backup))
    } else if operation == "uninstall" {
        let _lease = PackageLease::acquire()?;
        reconcile_runtime_state_security()?;
        uninstall(ephemeral_ci)
    } else {
        Err("unknown package operation".to_owned())
    }
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
        security.verify_kernel_object(handle.raw())?;
        if already_exists {
            return Err(
                "MCSEALED-WINDOWS-PACKAGE-BUSY: another package mutation is active".to_owned(),
            );
        }
        Ok(Self { _handle: handle })
    }
}

fn install(ephemeral_ci: bool) -> Result<(), String> {
    if installed_binary().exists() || state_root().exists() {
        return Err(
            "MCSEALED-WINDOWS-ALREADY-INSTALLED: use package upgrade for an existing provider"
                .to_owned(),
        );
    }
    if !package_attempts_empty()? {
        return Err(
            "MCSEALED-WINDOWS-INSTALL-ACTIVE: provider has active or unreconciled attempts"
                .to_owned(),
        );
    }
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
    let result = install_transaction(&source, ephemeral_ci);
    if let Err(install_error) = result {
        return match rollback_fresh_install() {
            Ok(()) => Err(install_error),
            Err(rollback_error) => Err(format!(
                "MCSEALED-WINDOWS-INSTALL-ROLLBACK-FAILED: install={install_error}; rollback={rollback_error}"
            )),
        };
    }
    Ok(())
}

fn rollback_fresh_install() -> Result<(), String> {
    if installed_binary().exists() && state_root().exists() {
        reconcile_services_from_installed().map_err(|error| {
            format!("cannot establish the service-owned rollback authority: {error}")
        })?;
        super::qualification::prepare_package_cleanup().map_err(|error| {
            format!("service-owned rollback cleanup did not retire exact provider state: {error}")
        })?;
    }
    if let Err(remove_error) = uninstall_services() {
        let reconcile = reconcile_services_from_installed();
        return match reconcile {
            Ok(()) => Err(format!(
                "service removal failed; the coherent installed pair was restored: {remove_error}"
            )),
            Err(reconcile_error) => Err(format!(
                "service removal failed and the pair could not be reconciled: remove={remove_error}; reconcile={reconcile_error}"
            )),
        };
    }
    remove_provider_files()
}

struct UpgradeRollback {
    binary: PathBuf,
    qualification: Option<PathBuf>,
    ephemeral_ci: bool,
}

fn upgrade(ephemeral_ci: bool) -> Result<UpgradeRollback, String> {
    let installed = installed_binary();
    let backup = installed.with_extension("exe.rollback");
    std::fs::copy(&installed, &backup).map_err(|error| {
        format!("cannot preserve the working Windows provider for rollback: {error}")
    })?;
    let qualification = state_root().join("package").join("qualification.json");
    let qualification_backup = qualification.with_extension("json.rollback");
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
        qualification: qualification_backup,
        ephemeral_ci,
    };
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
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
    match install_transaction(&source, ephemeral_ci) {
        Ok(()) => Ok(rollback),
        Err(upgrade_error) => {
            let rollback_result = restore_upgrade(&rollback, ephemeral_ci);
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

fn qualify_outside_package_lease(
    lease: PackageLease,
    rollback: Option<UpgradeRollback>,
) -> Result<(), String> {
    let (qualification, _lease) =
        super::qualification::qualify_and_store_for_scope("package", lease)?;
    match (qualification, rollback) {
        (Ok(_), Some(rollback)) => {
            cleanup_upgrade_rollback(&rollback);
            Ok(())
        }
        (Ok(_), None) => Ok(()),
        (Err(error), Some(rollback)) => {
            let rollback_result = restore_upgrade(&rollback, rollback.ephemeral_ci);
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
        (Err(error), None) => match rollback_fresh_install() {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(format!(
                "MCSEALED-WINDOWS-INSTALL-ROLLBACK-FAILED: qualification={error}; rollback={rollback_error}"
            )),
        },
    }
}

fn restore_upgrade(rollback: &UpgradeRollback, ephemeral_ci: bool) -> Result<(), String> {
    if let Err(remove_error) = uninstall_services() {
        return match reconcile_services_from_installed() {
            Ok(()) => Err(format!(
                "rollback service removal failed; the currently installed pair was reconciled: {remove_error}"
            )),
            Err(reconcile_error) => Err(format!(
                "rollback service removal failed and the installed pair could not be reconciled: remove={remove_error}; reconcile={reconcile_error}"
            )),
        };
    }
    install_transaction(&rollback.binary, ephemeral_ci)?;
    if let Some(qualification_backup) = &rollback.qualification {
        let destination = state_root().join("package").join("qualification.json");
        let staged = destination.with_extension("json.new");
        std::fs::copy(qualification_backup, &staged).map_err(|error| error.to_string())?;
        super::record::replace_atomically(&staged, &destination)?;
    }
    Ok(())
}

fn cleanup_upgrade_rollback(rollback: &UpgradeRollback) {
    for path in std::iter::once(&rollback.binary).chain(rollback.qualification.iter()) {
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn install_transaction(source: &Path, ephemeral_ci: bool) -> Result<(), String> {
    let install_root = install_root();
    let state_root = state_root();
    reject_reparse_components(source)?;
    reject_reparse_components(&install_root)?;
    reject_reparse_components(&state_root)?;
    let install_security = SecurityDescriptor::from_sddl(INSTALL_SDDL)?;
    create_secure_directory(&install_root, &install_security)?;
    reject_reparse_components(&install_root)?;
    let destination = installed_binary();
    copy_atomically(source, &destination)?;
    let state_security = SecurityDescriptor::from_sddl(&state_sddl()?)?;
    let state_parent = state_root
        .parent()
        .ok_or_else(|| "Windows sealed state root has no parent".to_owned())?;
    create_secure_directory(state_parent, &state_security)?;
    create_secure_directory(&state_root, &state_security)?;
    reject_reparse_components(&state_root)?;
    let launcher_state = SecurityDescriptor::from_sddl(&launcher_state_sddl()?)?;
    for directory in ["attempts", "quarantine", "guardian-receipts"] {
        let path = state_root.join(directory);
        create_secure_directory(&path, &launcher_state)?;
    }
    create_secure_directory(
        &state_root.join("replay"),
        &SecurityDescriptor::from_sddl(&replay_state_sddl()?)?,
    )?;
    let admissions = state_root.join("admissions");
    create_secure_directory(
        &admissions,
        &SecurityDescriptor::from_sddl(&admission_state_sddl()?)?,
    )?;
    let package_state = SecurityDescriptor::from_sddl(&package_state_sddl()?)?;
    let package_path = state_root.join("package");
    create_secure_directory(&package_path, &package_state)?;
    create_secure_directory(&package_path.join("certification-markers"), &package_state)?;

    configure_services(&destination, false)?;
    if ephemeral_ci {
        std::fs::write(
            state_root.join("package").join("ephemeral-ci"),
            b"enabled\n",
        )
        .map_err(|error| error.to_string())?;
    }
    verify_installed_against(source)?;
    Ok(())
}

fn configure_services(binary: &Path, reconcile: bool) -> Result<(), String> {
    let manager = service_manager::manager()?;
    let executable = binary.to_string_lossy().into_owned();
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
    let launcher_config = ServiceConfig {
        name: WINDOWS_LAUNCHER_SERVICE_NAME,
        display_name: "MemCordon sealed privileged launcher",
        binary_command: &launcher_command,
        account: Some("LocalSystem"),
        dependencies: &[],
        required_privileges: LAUNCHER_PRIVILEGES,
    };
    let control_config = ServiceConfig {
        name: WINDOWS_CONTROL_SERVICE_NAME,
        display_name: "MemCordon sealed local control provider",
        binary_command: &control_command,
        account: Some(r"NT AUTHORITY\LocalService"),
        dependencies: &[WINDOWS_LAUNCHER_SERVICE_NAME],
        required_privileges: CONTROL_PRIVILEGES,
    };
    let launcher = if reconcile {
        service_manager::reconcile(&manager, &launcher_config)?
    } else {
        service_manager::create(&manager, &launcher_config)?
    };
    let control = if reconcile {
        service_manager::reconcile(&manager, &control_config)?
    } else {
        service_manager::create(&manager, &control_config)?
    };
    service_manager::start(&launcher)?;
    service_manager::start(&control)?;
    Ok(())
}

pub fn certification_faults_enabled() -> bool {
    state_root().join("package").join("ephemeral-ci").is_file()
}

fn copy_atomically(source: &Path, destination: &Path) -> Result<(), String> {
    reject_reparse_components(source)?;
    reject_reparse_components(destination)?;
    let staged = destination.with_extension("exe.new");
    if staged.exists() {
        std::fs::remove_file(&staged).map_err(|error| error.to_string())?;
    }
    std::fs::copy(source, &staged).map_err(|error| error.to_string())?;
    reject_reparse_components(&staged)?;
    super::record::replace_atomically(&staged, destination)?;
    reject_reparse_components(destination)
}

fn create_secure_directory(path: &Path, security: &SecurityDescriptor) -> Result<(), String> {
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
            return Err(error.to_string());
        }
    }
    reject_reparse_components(path)?;
    security.verify_path(path)
}

fn reject_reparse_components(path: &Path) -> Result<(), String> {
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
    match (control, launcher) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(control), Err(launcher)) => Err(format!(
            "control service removal failed: {control}; launcher service removal failed: {launcher}"
        )),
    }
}

fn reconcile_services_from_installed() -> Result<(), String> {
    reconcile_runtime_state_security()?;
    configure_services(&installed_binary(), true)
}

fn reconcile_runtime_state_security() -> Result<(), String> {
    let root = state_root();
    if !root.exists() {
        return Ok(());
    }
    let state_security = SecurityDescriptor::from_sddl(&state_sddl()?)?;
    create_secure_directory(&root, &state_security)?;
    super::record::recover_detached_replay()?;
    let launcher_state = SecurityDescriptor::from_sddl(&launcher_state_sddl()?)?;
    for directory in ["attempts", "quarantine", "guardian-receipts"] {
        let path = root.join(directory);
        create_secure_directory(&path, &launcher_state)?;
    }
    let replay = root.join("replay");
    create_secure_directory(
        &replay,
        &SecurityDescriptor::from_sddl(&replay_state_sddl()?)?,
    )?;
    let admissions = root.join("admissions");
    create_secure_directory(
        &admissions,
        &SecurityDescriptor::from_sddl(&admission_state_sddl()?)?,
    )?;
    Ok(())
}

fn uninstall(ephemeral_ci: bool) -> Result<(), String> {
    if !package_attempts_empty()? {
        return Err(
            "MCSEALED-WINDOWS-UNINSTALL-ACTIVE: provider has active or unreconciled attempts"
                .to_owned(),
        );
    }
    super::qualification::prepare_package_cleanup()?;
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
    if let Err(remove_error) = remove_provider_files() {
        let rollback = install_transaction(&source, ephemeral_ci).and_then(|()| {
            if let Some(qualification) = qualification {
                let destination = state_root().join("package").join("qualification.json");
                let staged = destination.with_extension("json.new");
                std::fs::write(&staged, qualification).map_err(|error| error.to_string())?;
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

fn remove_provider_files() -> Result<(), String> {
    let binary = installed_binary();
    let state = state_root();
    if state.exists() {
        let qualification = state.join("package").join("qualification.json");
        if qualification.exists() {
            std::fs::remove_file(qualification).map_err(|error| error.to_string())?;
        }
        let ephemeral = state.join("package").join("ephemeral-ci");
        if ephemeral.exists() {
            std::fs::remove_file(ephemeral).map_err(|error| error.to_string())?;
        }
        let fault_matrix = state
            .join("package")
            .join("preauthorization-fault-matrix.json");
        if fault_matrix.exists() {
            std::fs::remove_file(fault_matrix).map_err(|error| error.to_string())?;
        }
        let retirement_fault_matrix = state.join("package").join("retirement-fault-matrix.json");
        if retirement_fault_matrix.exists() {
            std::fs::remove_file(retirement_fault_matrix).map_err(|error| error.to_string())?;
        }
        let token_matrix = state.join("package").join("token-matrix.json");
        if token_matrix.exists() {
            std::fs::remove_file(token_matrix).map_err(|error| error.to_string())?;
        }
        for evidence_name in ["authority-loss.json", "runtime-mutants.json"] {
            let evidence = state.join("package").join(evidence_name);
            if evidence.exists() {
                std::fs::remove_file(evidence).map_err(|error| error.to_string())?;
            }
        }
        let markers = state.join("package").join("certification-markers");
        if markers.exists() {
            std::fs::remove_dir(markers).map_err(|error| error.to_string())?;
        }
        let package = state.join("package");
        if package.exists() {
            std::fs::remove_dir(package).map_err(|error| error.to_string())?;
        }
        let attempts = state.join("attempts");
        if attempts.exists() {
            std::fs::remove_dir(attempts).map_err(|error| error.to_string())?;
        }
        let quarantine = state.join("quarantine");
        if quarantine.exists() {
            std::fs::remove_dir(quarantine).map_err(|error| error.to_string())?;
        }
        let admissions = state.join("admissions");
        if admissions.exists() {
            std::fs::remove_dir(admissions).map_err(|error| error.to_string())?;
        }
        let replay = state.join("replay");
        if replay.exists() {
            std::fs::remove_dir(replay).map_err(|error| error.to_string())?;
        }
        let guardian_receipts = state.join("guardian-receipts");
        if guardian_receipts.exists() {
            std::fs::remove_dir(guardian_receipts).map_err(|error| error.to_string())?;
        }
        std::fs::remove_dir(state).map_err(|error| error.to_string())?;
    }
    if binary.exists() {
        std::fs::remove_file(binary).map_err(|error| error.to_string())?;
    }
    let install = install_root();
    if install.exists() {
        std::fs::remove_dir(install).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn package_attempts_empty() -> Result<bool, String> {
    if !state_root().exists() {
        Ok(true)
    } else {
        super::qualification::recovery_status()
    }
}

pub fn provider_state_absent() -> Result<bool, String> {
    use memcordon_core::{WINDOWS_CONTROL_PIPE, WINDOWS_LAUNCHER_PIPE};

    let manager = service_manager::manager()?;
    let services_absent = !service_manager::exists(&manager, WINDOWS_CONTROL_SERVICE_NAME)?
        && !service_manager::exists(&manager, WINDOWS_LAUNCHER_SERVICE_NAME)?;
    let pipes_absent = !super::pipe::endpoint_exists(WINDOWS_CONTROL_PIPE)?
        && !super::pipe::endpoint_exists(WINDOWS_LAUNCHER_PIPE)?;
    Ok(services_absent && pipes_absent && !install_root().exists() && !state_root().exists())
}

pub fn verify_installed() -> Result<(), String> {
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
    verify_installed_against(&source)
}

fn verify_installed_against(source: &Path) -> Result<(), String> {
    reject_reparse_components(source)?;
    reject_reparse_components(&install_root())?;
    reject_reparse_components(&state_root())?;
    reject_reparse_components(&installed_binary())?;
    let manager = service_manager::manager()?;
    if !service_manager::is_running(&manager, WINDOWS_LAUNCHER_SERVICE_NAME)? {
        return Err("Windows sealed launcher service is not running".to_owned());
    }
    if !service_manager::is_running(&manager, WINDOWS_CONTROL_SERVICE_NAME)? {
        return Err("Windows sealed control service is not running".to_owned());
    }
    let executable = installed_binary().to_string_lossy().into_owned();
    let launcher_command = String::from_utf16_lossy(&super::process::encode_command_line(&[
        executable.encode_utf16().collect(),
        "windows-launcher".encode_utf16().collect(),
    ]));
    let control_command = String::from_utf16_lossy(&super::process::encode_command_line(&[
        executable.encode_utf16().collect(),
        "windows-control".encode_utf16().collect(),
    ]));
    service_manager::verify(
        &manager,
        &ServiceConfig {
            name: WINDOWS_LAUNCHER_SERVICE_NAME,
            display_name: "MemCordon sealed privileged launcher",
            binary_command: &launcher_command,
            account: Some("LocalSystem"),
            dependencies: &[],
            required_privileges: LAUNCHER_PRIVILEGES,
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
        },
    )?;
    SecurityDescriptor::from_sddl(INSTALL_SDDL)?.verify_path(&install_root())?;
    SecurityDescriptor::from_sddl(&state_sddl()?)?.verify_path(&state_root())?;
    let launcher_state = SecurityDescriptor::from_sddl(&launcher_state_sddl()?)?;
    for directory in ["attempts", "quarantine", "guardian-receipts"] {
        launcher_state.verify_path(&state_root().join(directory))?;
    }
    SecurityDescriptor::from_sddl(&replay_state_sddl()?)?
        .verify_path(&state_root().join("replay"))?;
    SecurityDescriptor::from_sddl(&admission_state_sddl()?)?
        .verify_path(&state_root().join("admissions"))?;
    SecurityDescriptor::from_sddl(&package_state_sddl()?)?
        .verify_path(&state_root().join("package"))?;
    verify_service_process_protection(&manager)?;
    let packaged = crate::package::sha256_regular_no_follow(source)?;
    let installed = crate::package::sha256_regular_no_follow(&installed_binary())?;
    crate::package::verify_installed_executable_digest(&packaged, &installed)
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
    agent: AgentPackageInspectionV2,
) -> Result<InstalledProviderInspectionV2, String> {
    verify_installed()?;
    let installed_executable_sha256 =
        crate::package::sha256_regular_no_follow(&installed_binary())?;
    let qualification = super::qualification::probe().ok();
    let qualification_complete = qualification
        .as_ref()
        .is_some_and(|receipt| receipt.qualified && receipt.is_consistent());
    Ok(InstalledProviderInspectionV2 {
        schema_version: 2,
        agent,
        installed_executable_sha256,
        installed_artifacts_valid: true,
        provider_identity: qualification.map(|receipt| receipt.provider_identity),
        provider_reachable: qualification_complete,
        qualification_complete,
    })
}
