//! Native source socket and unsupported host-tree packing refusals.
use super::{linux_request_fixture::CallerSession, linux_test_execution::CallerImages};
use crate::{CiError, Result};
use std::{os::fd::AsFd, path::Path, time::Instant};
pub fn run_socket_import_refusals(
    caller: &CallerSession,
    images: &CallerImages,
    controller_directory: &Path,
    working_directory: &Path,
    work: Instant,
) -> Result<()> {
    use std::{
        io::Write,
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixListener,
            process::ExitStatusExt,
        },
    };
    for scenario in [
        "input-socket",
        "imported-socket",
        "host-tree-mount-import-rejected",
    ] {
        let controller = controller_directory.join(format!("isolation-{scenario}"));
        std::fs::create_dir(&controller)?;
        std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))?;
        let directory = working_directory.join(format!("isolation-{scenario}"));
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        rustix::fs::chown(
            &directory,
            Some(rustix::process::Uid::from_raw(caller.uid)),
            Some(rustix::process::Gid::from_raw(caller.gid)),
        )
        .map_err(std::io::Error::from)?;
        let input_root = directory.join("source");
        std::fs::create_dir(&input_root)?;
        std::fs::set_permissions(&input_root, std::fs::Permissions::from_mode(0o755))?;
        let host_tree = directory.join("host-tree");
        let mut tree_marker = [0u8; 32];
        if scenario == "host-tree-mount-import-rejected" {
            std::fs::create_dir(&host_tree)?;
            std::fs::set_permissions(&host_tree, std::fs::Permissions::from_mode(0o755))?;
            getrandom::fill(&mut tree_marker)
                .map_err(|error| CiError::Message(error.to_string()))?;
            let mut marker = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(host_tree.join("marker.bin"))?;
            marker.write_all(&tree_marker)?;
            marker.sync_all()?;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .open(input_root.join("socket"))?
                .sync_all()?;
        }
        let actual = if scenario == "input-socket" {
            input_root.join("socket")
        } else if scenario == "host-tree-mount-import-rejected" {
            host_tree.join("outside.sock")
        } else {
            directory.join("outside.sock")
        };
        let socket = UnixListener::bind(&actual)?;
        std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o666))?;
        rustix::fs::chown(
            &actual,
            Some(rustix::process::Uid::from_raw(caller.uid)),
            Some(rustix::process::Gid::from_raw(caller.gid)),
        )
        .map_err(std::io::Error::from)?;
        if scenario == "imported-socket" {
            std::os::unix::fs::symlink(&actual, input_root.join("socket"))?;
        }
        let member = std::fs::symlink_metadata(input_root.join("socket"))?;
        let held = std::fs::symlink_metadata(&actual)?;
        let descriptor = rustix::fs::fstat(socket.as_fd()).map_err(std::io::Error::from)?;
        let mut manifest = images.input.clone();
        manifest.entries = Default::default();
        manifest
            .entries
            .try_push(memcordon_core::workload_files::ImageEntryV1::Regular {
                path: memcordon_core::workload_files::RootRelativePath::new("socket".into())
                    .map_err(CiError::Message)?,
                sha256: memcordon_core::hash_bytes(b""),
                size: 0,
                executable: false,
            })
            .map_err(|_| {
                CiError::Message("single socket source manifest exceeds current bound".into())
            })?;
        manifest.entrypoints = Default::default();
        manifest.library_directories = Default::default();
        manifest.validate().map_err(CiError::Message)?;
        let manifest_bytes = manifest.canonical_bytes().map_err(CiError::Message)?;
        let manifest_path = directory.join("input.json");
        let spec_path = directory.join("pack.json");
        let output = directory.join("forbidden.mci");
        let mut spec = serde_json::json!({"runtime":{"manifest":images.runtime_manifest,"root":images.runtime_source},"input":{"manifest":manifest_path,"root":input_root}});
        if scenario == "host-tree-mount-import-rejected" {
            spec["host_tree"] =
                serde_json::json!({"source":host_tree,"mount_target":"/imported-host"});
        }
        for (path, bytes) in [
            (&manifest_path, manifest_bytes.clone()),
            (&spec_path, serde_json::to_vec(&spec)?),
        ] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o644)
                .open(path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        let watcher = super::linux_current_phase_gate::NativeNamespaceWatch::new(&[
            ("journal", Path::new("/var/lib/memcordon/workload-attempts")),
            (
                "input-staging",
                Path::new("/var/lib/memcordon/workload-inputs"),
            ),
            (
                "footprint",
                Path::new("/var/lib/memcordon/workload-resources"),
            ),
            ("root-staging", Path::new("/run/memcordon")),
            ("cgroup", Path::new("/sys/fs/cgroup/memcordon-sealed")),
        ])?;
        let before = watcher.snapshot()?;
        let mut child = None;
        let arguments: Vec<std::ffi::OsString> = vec![
            "workload".into(),
            "pack".into(),
            "--spec".into(),
            spec_path.as_os_str().to_owned(),
            "--output".into(),
            output.as_os_str().to_owned(),
        ];
        let process = caller
            .command(&directory, work)?
            .args(&arguments)
            .output_quiet_with_exec_observation(|native| {
                let birth = crate::linux_consumer_readiness::process_birth(native.id())
                    .map_err(CiError::Message)?;
                child = Some(
                    crate::linux_consumer_readiness::HeldLinuxProcess::acquire(native.id(), birth)
                        .map_err(CiError::Message)?,
                );
                Ok(())
            })?;
        let child = child
            .ok_or_else(|| CiError::Message("original packing child observation absent".into()))?;
        let retired = child.exited().map_err(CiError::Message)?;
        let after = watcher.snapshot()?;
        let events = watcher.drain()?;
        let named = std::fs::symlink_metadata(&actual)?;
        if named.dev() != held.dev() || named.ino() != held.ino() || named.nlink() != 1 {
            return Err(CiError::Message(
                "original source socket identity changed during packing".into(),
            ));
        }
        let status = process.status.into_raw();
        let detail = std::str::from_utf8(&process.stderr)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let expected_error = if scenario == "host-tree-mount-import-rejected" {
            detail.contains("unknown field") && detail.contains("host_tree")
        } else {
            detail.contains("os error 6")
        };
        if !retired
            || status & 0x7f != 0
            || (status >> 8) & 0xff == 0
            || output.try_exists()?
            || !process.stdout.is_empty()
            || !expected_error
            || before != after
            || events != serde_json::json!([])
            || held.mode() != 0o140666
            || held.uid() != caller.uid
            || held.nlink() != 1
            || descriptor.st_ino == 0
        {
            return Err(CiError::Message(
                "socket/host-tree packing did not fail at its actual preallocation boundary".into(),
            ));
        }
        if scenario == "input-socket"
            && (member.dev(), member.ino(), member.mode()) != (held.dev(), held.ino(), held.mode())
        {
            return Err(CiError::Message(
                "packing did not exercise the original live input socket".into(),
            ));
        }
        if scenario == "imported-socket"
            && (!member.file_type().is_symlink()
                || std::fs::read_link(input_root.join("socket"))? != actual)
        {
            return Err(CiError::Message(
                "packing did not exercise the actual imported socket symlink".into(),
            ));
        }
        if scenario == "host-tree-mount-import-rejected"
            && std::fs::read(host_tree.join("marker.bin"))? != tree_marker
        {
            return Err(CiError::Message(
                "rejected host-tree import changed host bytes".into(),
            ));
        }
    }
    Ok(())
}
