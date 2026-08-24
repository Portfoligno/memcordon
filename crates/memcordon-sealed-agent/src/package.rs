use std::ffi::OsStr;

const SERVICE: &str = "[Unit]\nDescription=MemCordon sealed supervision provider\nRequires=memcordon-sealed-agent.socket\nAfter=local-fs.target\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent serve\nUser=root\nGroup=memcordon\nDelegate=yes\nKillMode=process\nRuntimeDirectory=memcordon\nRuntimeDirectoryMode=0750\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=/run/memcordon /var/lib/memcordon/sealed /sys/fs/cgroup\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_KILL CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nAmbientCapabilities=\n\n[Install]\nWantedBy=multi-user.target\n";
const SOCKET: &str = "[Unit]\nDescription=MemCordon sealed supervision provider socket\n\n[Socket]\nListenStream=/run/memcordon/sealed-agent.sock\nDirectoryMode=0755\nSocketMode=0660\nSocketUser=root\nSocketGroup=memcordon\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
#[cfg(target_os = "linux")]
const BINARY: &str = "/usr/libexec/memcordon-sealed-agent";
#[cfg(target_os = "linux")]
const UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.service";
#[cfg(target_os = "linux")]
const SOCKET_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.socket";

pub fn run(operation: &OsStr, ephemeral_ci: bool) -> Result<(), String> {
    if operation == "verify" {
        return verify();
    }
    #[cfg(target_os = "linux")]
    {
        linux_mutation(operation, ephemeral_ci)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ephemeral_ci;
        Err("provider package mutation is implemented only on Linux".to_owned())
    }
}

fn verify() -> Result<(), String> {
    verify_compiled_metadata()?;
    #[cfg(target_os = "linux")]
    verify_installed_package()?;
    Ok(())
}

fn verify_compiled_metadata() -> Result<(), String> {
    const CAPABILITY_BOUNDING_SET: &str = "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_KILL CAP_DAC_OVERRIDE CAP_SYS_PTRACE";
    let capability_lines = SERVICE
        .lines()
        .filter(|line| line.starts_with("CapabilityBoundingSet="))
        .collect::<Vec<_>>();
    let ambient_lines = SERVICE
        .lines()
        .filter(|line| line.starts_with("AmbientCapabilities="))
        .collect::<Vec<_>>();
    if SERVICE.contains("ExecStart=/usr/libexec/memcordon-sealed-agent serve")
        && SERVICE.contains("User=root")
        && SERVICE.contains("Group=memcordon")
        && SERVICE.contains("RuntimeDirectoryMode=0750")
        && SERVICE.contains("NoNewPrivileges=yes")
        && capability_lines == [CAPABILITY_BOUNDING_SET]
        && ambient_lines == ["AmbientCapabilities="]
        && SOCKET.contains("ListenStream=/run/memcordon/sealed-agent.sock")
        && SOCKET.contains("DirectoryMode=0755")
        && SOCKET.contains("SocketMode=0660")
        && SOCKET.contains("SocketUser=root")
        && SOCKET.contains("SocketGroup=memcordon")
    {
        Ok(())
    } else {
        Err("compiled service metadata is inconsistent".to_owned())
    }
}

#[cfg(target_os = "linux")]
fn verify_installed_package() -> Result<(), String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let artifacts = [
        (BINARY, 0o755, None),
        (UNIT, 0o644, Some(SERVICE.as_bytes())),
        (SOCKET_UNIT, 0o644, Some(SOCKET.as_bytes())),
    ];
    for (path, expected_mode, expected_bytes) in artifacts {
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err("MCSEALED-PACKAGE-VERIFY: installed package is incomplete".to_owned());
            }
            Err(error) => {
                return Err(format!("MCSEALED-PACKAGE-VERIFY: {path}: {error}"));
            }
        };
        let metadata = file
            .metadata()
            .map_err(|error| format!("MCSEALED-PACKAGE-VERIFY: {path}: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "MCSEALED-PACKAGE-VERIFY: {path} is not a no-follow regular file"
            ));
        }
        if metadata.uid() != 0 || metadata.gid() != 0 {
            return Err(format!(
                "MCSEALED-PACKAGE-VERIFY: {path} is not owned by root:root"
            ));
        }
        if metadata.mode() & 0o7777 != expected_mode {
            return Err(format!(
                "MCSEALED-PACKAGE-VERIFY: {path} mode is not {expected_mode:04o}"
            ));
        }
        if let Some(expected_bytes) = expected_bytes {
            let mut actual = Vec::with_capacity(expected_bytes.len() + 1);
            file.by_ref()
                .take((expected_bytes.len() + 1) as u64)
                .read_to_end(&mut actual)
                .map_err(|error| format!("MCSEALED-PACKAGE-VERIFY: {path}: {error}"))?;
            if actual != expected_bytes {
                return Err(format!(
                    "MCSEALED-PACKAGE-VERIFY: {path} content differs from the packaged artifact"
                ));
            }
        }
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
    fs::create_dir_all("/run/memcordon").map_err(|error| error.to_string())?;
    fs::set_permissions("/run/memcordon", fs::Permissions::from_mode(0o750))
        .map_err(|error| error.to_string())?;
    let _package_lease = crate::linux::service::acquire_package_lease().map_err(|error| {
        format!("refusing package mutation while a sealed provider attempt is active: {error}")
    })?;
    if operation == "uninstall" {
        stop_unit("memcordon-sealed-agent.service")?;
        stop_unit("memcordon-sealed-agent.socket")?;
        ensure_unit_inactive("memcordon-sealed-agent.service")?;
        ensure_unit_inactive("memcordon-sealed-agent.socket")?;
        let ambiguous = crate::linux::recovery::recover()?;
        if !ambiguous.is_empty() {
            return Err(format!(
                "refusing to uninstall while sealed recovery is ambiguous: {}",
                ambiguous.join(",")
            ));
        }
        if live_attempt_exists()? {
            return Err(
                "refusing to uninstall while an authenticated attempt record exists".to_owned(),
            );
        }
        for path in [SOCKET_UNIT, UNIT, BINARY] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("could not remove {path}: {error}")),
            }
        }
        systemctl(["daemon-reload"])?;
        return Ok(());
    }
    if operation == "upgrade" {
        stop_unit("memcordon-sealed-agent.service")?;
        stop_unit("memcordon-sealed-agent.socket")?;
        ensure_unit_inactive("memcordon-sealed-agent.service")?;
        ensure_unit_inactive("memcordon-sealed-agent.socket")?;
        let ambiguous = crate::linux::recovery::recover()?;
        if !ambiguous.is_empty() {
            return Err(format!(
                "refusing to upgrade while sealed recovery is ambiguous: {}",
                ambiguous.join(",")
            ));
        }
        if live_attempt_exists()? {
            return Err(
                "refusing to upgrade while an authenticated attempt record exists".to_owned(),
            );
        }
    }
    verify_compiled_metadata()?;
    ensure_service_group()?;
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
    let installations = [
        (
            Path::new(BINARY),
            fs::read(source).map_err(|error| error.to_string())?,
            0o755,
        ),
        (Path::new(UNIT), SERVICE.as_bytes().to_vec(), 0o644),
        (Path::new(SOCKET_UNIT), SOCKET.as_bytes().to_vec(), 0o644),
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
        systemctl(["start", "memcordon-sealed-agent.socket"])?;
    } else {
        systemctl(["enable", "--now", "memcordon-sealed-agent.socket"])?;
    }
    systemctl(["restart", "memcordon-sealed-agent.service"])?;
    wait_provider_ready()?;
    verify_client_access()?;
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
    if qualification.mechanism != "linux-pid-namespace-cgroup-v1"
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
fn ensure_service_group() -> Result<(), String> {
    let name = std::ffi::CString::new("memcordon").expect("static group name has no NUL");
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if !unsafe { libc::getgrnam(name.as_ptr()) }.is_null() {
        return Ok(());
    }
    let status = std::process::Command::new("/usr/sbin/groupadd")
        .args(["--system", "memcordon"])
        .status()
        .map_err(|error| format!("could not create service group: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("service group creation failed with {status}"))
    }
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
