//! Fixed-argv Linux qualification probe build. The workflow invokes this one
//! executable directly; no shell script or candidate-supplied compiler args
//! participate in probe construction.

use std::path::Path;

use memcordon_ci::{CiError, Result};

#[cfg(target_os = "linux")]
pub(super) fn run(workspace: &Path) -> Result<()> {
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::process::Command;

    fn execute(program: &str, args: &[&str], workspace: &Path) -> Result<()> {
        let status = Command::new(program)
            .args(args)
            .current_dir(workspace)
            .status()
            .map_err(|error| CiError::Message(format!("probe tool {program}: {error}")))?;
        if !status.success() {
            return Err(CiError::Message(format!(
                "probe tool {program} failed: {status}"
            )));
        }
        Ok(())
    }

    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|error| CiError::Message(error.to_string()))?;
    if !uid.status.success() || uid.stdout != b"0\n" {
        return Err(CiError::Message("private probe build requires root".into()));
    }
    let target_arch = match std::env::consts::ARCH {
        "x86_64" => "-D__TARGET_ARCH_x86",
        "aarch64" => "-D__TARGET_ARCH_arm64",
        _ => {
            return Err(CiError::Message(
                "unsupported private probe architecture".into(),
            ));
        }
    };
    let btf = Path::new("/sys/kernel/btf/vmlinux");
    if !btf.is_file() {
        return Err(CiError::Message(
            "private probe kernel BTF is absent".into(),
        ));
    }
    let output = Path::new("/run/memcordon-private-observer");
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(output)
        .map_err(|error| CiError::Message(format!("private probe output: {error}")))?;
    let metadata = fs::metadata(output)?;
    if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err(CiError::Message(
            "private probe directory protection differs".into(),
        ));
    }

    let header = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .current_dir(workspace)
        .output()
        .map_err(|error| CiError::Message(format!("bpftool: {error}")))?;
    if !header.status.success()
        || header.stdout.is_empty()
        || header.stdout.len() > 32 * 1024 * 1024
    {
        return Err(CiError::Message(
            "private probe BTF header generation failed".into(),
        ));
    }
    let header_path = output.join("vmlinux.h");
    let mut header_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&header_path)?;
    header_file.write_all(&header.stdout)?;
    header_file.sync_all()?;
    fs::set_permissions(&header_path, fs::Permissions::from_mode(0o600))?;

    let source = workspace.join("tools/memcordon-ci/probes/private_kernel_v1.bpf.c");
    let loader_source = workspace.join("tools/memcordon-ci/probes/private_kernel_v1_loader.c");
    let object = output.join("private_kernel_v1.bpf.o");
    let loader = output.join("private_kernel_v1_loader");
    let source = source
        .to_str()
        .ok_or_else(|| CiError::Message("probe source path is not UTF-8".into()))?;
    let loader_source = loader_source
        .to_str()
        .ok_or_else(|| CiError::Message("probe loader source path is not UTF-8".into()))?;
    let include = output
        .to_str()
        .expect("fixed private probe output path is UTF-8");
    let object_path = object
        .to_str()
        .expect("fixed private probe object path is UTF-8");
    let loader_path = loader
        .to_str()
        .expect("fixed private probe loader path is UTF-8");
    execute(
        "clang",
        &[
            "-O2",
            "-g",
            "-target",
            "bpf",
            target_arch,
            "-I",
            include,
            "-c",
            source,
            "-o",
            object_path,
        ],
        workspace,
    )?;
    execute(
        "cc",
        &[
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            loader_source,
            "-lbpf",
            "-lelf",
            "-lz",
            "-o",
            loader_path,
        ],
        workspace,
    )?;
    for (path, mode) in [(&object, 0o600), (&loader, 0o700)] {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.len() == 0 {
            return Err(CiError::Message(
                "private probe output identity differs".into(),
            ));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn run(_workspace: &Path) -> Result<()> {
    Err(CiError::Message(
        "private probe build requires Linux".into(),
    ))
}
