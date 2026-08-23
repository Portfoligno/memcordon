use std::ffi::OsStr;

const SERVICE: &str = "[Unit]\nDescription=MemCordon sealed supervision provider\nRequires=memcordon-sealed-agent.socket\nAfter=local-fs.target\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent serve\nUser=root\nGroup=root\nDelegate=yes\nKillMode=process\nRuntimeDirectory=memcordon\nRuntimeDirectoryMode=0750\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=/run/memcordon /var/lib/memcordon/sealed /sys/fs/cgroup\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_KILL CAP_DAC_OVERRIDE\n\n[Install]\nWantedBy=multi-user.target\n";
const SOCKET: &str = "[Unit]\nDescription=MemCordon sealed supervision provider socket\n\n[Socket]\nListenStream=/run/memcordon/sealed-agent.sock\nDirectoryMode=0750\nSocketMode=0660\nSocketUser=root\nSocketGroup=memcordon\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";

pub fn run(operation: &OsStr, ephemeral_ci: bool) -> Result<(), String> {
    if operation == "verify" {
        return verify();
    }
    #[cfg(target_os = "linux")]
    {
        return linux_mutation(operation, ephemeral_ci);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ephemeral_ci;
        Err("provider package mutation is implemented only on Linux".to_owned())
    }
}

fn verify() -> Result<(), String> {
    if SERVICE.contains("ExecStart=/usr/libexec/memcordon-sealed-agent serve")
        && SERVICE.contains("User=root")
        && SOCKET.contains("ListenStream=/run/memcordon/sealed-agent.sock")
    {
        Ok(())
    } else {
        Err("compiled service metadata is inconsistent".to_owned())
    }
}

#[cfg(target_os = "linux")]
fn linux_mutation(operation: &OsStr, _ephemeral_ci: bool) -> Result<(), String> {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::Path;

    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::geteuid() } != 0 {
        return Err("package mutation requires root".to_owned());
    }
    const BINARY: &str = "/usr/libexec/memcordon-sealed-agent";
    const UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.service";
    const SOCKET_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.socket";
    if operation == "uninstall" {
        let state_root = Path::new("/var/lib/memcordon/sealed");
        if state_root.exists()
            && fs::read_dir(state_root)
                .map_err(|error| error.to_string())?
                .next()
                .is_some()
        {
            return Err(
                "refusing to uninstall while an authenticated attempt record exists".to_owned(),
            );
        }
        systemctl(["stop", "memcordon-sealed-agent.socket"])?;
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
    if operation != "install" && operation != "upgrade" {
        return Err("unknown package operation".to_owned());
    }
    if operation == "upgrade" && live_attempt_exists()? {
        return Err("refusing to upgrade while an authenticated attempt record exists".to_owned());
    }
    verify()?;
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
    systemctl(["daemon-reload"])?;
    systemctl(["enable", "--now", "memcordon-sealed-agent.socket"])?;
    if operation == "upgrade" {
        systemctl(["restart", "memcordon-sealed-agent.socket"])?;
    }
    systemctl(["restart", "memcordon-sealed-agent.service"])?;
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
