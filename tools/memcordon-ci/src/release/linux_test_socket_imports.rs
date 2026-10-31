//! Native source socket and unsupported host-tree packing refusals.
use super::{linux_request_fixture::CallerSession, linux_test_execution::CallerImages};
use crate::{CiError, Result};
use std::{os::fd::AsFd, path::Path, time::Instant};
fn io_at(error: std::io::Error, operation: &str, path: &Path) -> CiError {
    CiError::from(error).context(format!("socket refusal {operation} {}", path.display()))
}
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
        let result = (|| -> Result<()> {
            let controller = controller_directory.join(format!("isolation-{scenario}"));
            std::fs::create_dir(&controller)
                .map_err(|error| io_at(error, "create controller", &controller))?;
            std::fs::set_permissions(&controller, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| io_at(error, "chmod controller", &controller))?;
            let directory = working_directory.join(format!("isolation-{scenario}"));
            std::fs::create_dir(&directory)
                .map_err(|error| io_at(error, "create caller directory", &directory))?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| io_at(error, "chmod caller directory", &directory))?;
            rustix::fs::chown(
                &directory,
                Some(rustix::process::Uid::from_raw(caller.uid)),
                Some(rustix::process::Gid::from_raw(caller.gid)),
            )
            .map_err(std::io::Error::from)
            .map_err(|error| io_at(error, "chown caller directory", &directory))?;
            let input_root = directory.join("source");
            std::fs::create_dir(&input_root)
                .map_err(|error| io_at(error, "create source root", &input_root))?;
            std::fs::set_permissions(&input_root, std::fs::Permissions::from_mode(0o755))
                .map_err(|error| io_at(error, "chmod source root", &input_root))?;
            let host_tree = directory.join("host-tree");
            let mut tree_marker = [0u8; 32];
            if scenario == "host-tree-mount-import-rejected" {
                std::fs::create_dir(&host_tree)
                    .map_err(|error| io_at(error, "create host tree", &host_tree))?;
                std::fs::set_permissions(&host_tree, std::fs::Permissions::from_mode(0o755))
                    .map_err(|error| io_at(error, "chmod host tree", &host_tree))?;
                getrandom::fill(&mut tree_marker)
                    .map_err(|error| CiError::Message(error.to_string()))?;
                let mut marker = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o444)
                    .open(host_tree.join("marker.bin"))
                    .map_err(|error| {
                        io_at(error, "create host marker", &host_tree.join("marker.bin"))
                    })?;
                marker.write_all(&tree_marker).map_err(|error| {
                    io_at(error, "write host marker", &host_tree.join("marker.bin"))
                })?;
                marker.sync_all().map_err(|error| {
                    io_at(error, "sync host marker", &host_tree.join("marker.bin"))
                })?;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o444)
                    .open(input_root.join("socket"))
                    .map_err(|error| {
                        io_at(
                            error,
                            "create regular source member",
                            &input_root.join("socket"),
                        )
                    })?
                    .sync_all()
                    .map_err(|error| {
                        io_at(
                            error,
                            "sync regular source member",
                            &input_root.join("socket"),
                        )
                    })?;
            }
            let actual = if scenario == "input-socket" {
                input_root.join("socket")
            } else if scenario == "host-tree-mount-import-rejected" {
                host_tree.join("outside.sock")
            } else {
                directory.join("outside.sock")
            };
            let socket = UnixListener::bind(&actual)
                .map_err(|error| io_at(error, "bind original listener", &actual))?;
            std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o666))
                .map_err(|error| io_at(error, "chmod original socket", &actual))?;
            rustix::fs::chown(
                &actual,
                Some(rustix::process::Uid::from_raw(caller.uid)),
                Some(rustix::process::Gid::from_raw(caller.gid)),
            )
            .map_err(std::io::Error::from)
            .map_err(|error| io_at(error, "chown original socket", &actual))?;
            if scenario == "imported-socket" {
                std::os::unix::fs::symlink(&actual, input_root.join("socket")).map_err(
                    |error| {
                        io_at(
                            error,
                            "create imported socket symlink",
                            &input_root.join("socket"),
                        )
                    },
                )?;
            }
            let member = std::fs::symlink_metadata(input_root.join("socket")).map_err(|error| {
                io_at(error, "source member metadata", &input_root.join("socket"))
            })?;
            let held = std::fs::symlink_metadata(&actual)
                .map_err(|error| io_at(error, "original socket metadata", &actual))?;
            let descriptor = rustix::fs::fstat(socket.as_fd())
                .map_err(std::io::Error::from)
                .map_err(|error| io_at(error, "held listener fstat", &actual))?;
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
                    .open(path)
                    .map_err(|error| io_at(error, "create manifest/spec", path))?;
                file.write_all(&bytes)
                    .map_err(|error| io_at(error, "write manifest/spec", path))?;
                file.sync_all()
                    .map_err(|error| io_at(error, "sync manifest/spec", path))?;
            }
            let watcher = super::linux_current_phase_gate::NativeNamespaceWatch::new(
                &[
                    ("journal", Path::new("/var/lib/memcordon/workload-attempts")),
                    ("input-staging", Path::new("/var/lib/memcordon/workload-inputs")),
                    ("footprint", Path::new("/var/lib/memcordon/workload-resources")),
                    ("root-staging", Path::new("/run/memcordon")),
                    ("cgroup", Path::new("/sys/fs/cgroup/memcordon-sealed")),
                ],
                work,
            ).map_err(|error| {
                error.context("construct socket refusal namespace watch for journal/input-staging/footprint/root-staging/cgroup")
            })?;
            let before = watcher
                .snapshot()
                .map_err(|error| error.context("socket refusal namespace snapshot before pack"))?;
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
                .command(&directory, work)
                .map_err(|error| {
                    error.context(format!(
                        "prepare socket refusal pack command {}",
                        directory.display()
                    ))
                })?
                .args(&arguments)
                .output_quiet_with_exec_observation(|native| {
                    let birth = crate::linux_consumer_readiness::process_birth(native.id())
                        .map_err(CiError::Message)?;
                    child = Some(
                        crate::linux_consumer_readiness::HeldLinuxProcess::acquire(
                            native.id(),
                            birth,
                        )
                        .map_err(CiError::Message)?,
                    );
                    Ok(())
                })
                .map_err(|error| {
                    error.context(format!(
                        "execute socket refusal pack spec={} output={}",
                        spec_path.display(),
                        output.display()
                    ))
                })?;
            let child = child.ok_or_else(|| {
                CiError::Message("original packing child observation absent".into())
            })?;
            let retired = child.exited().map_err(CiError::Message)?;
            let after = watcher
                .snapshot()
                .map_err(|error| error.context("socket refusal namespace snapshot after pack"))?;
            let events = watcher
                .drain()
                .map_err(|error| error.context("socket refusal namespace event drain"))?;
            let named = std::fs::symlink_metadata(&actual)
                .map_err(|error| io_at(error, "original socket metadata readback", &actual))?;
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
                || output
                    .try_exists()
                    .map_err(|error| io_at(error, "output existence check", &output))?
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
                    "socket/host-tree packing did not fail at its actual preallocation boundary"
                        .into(),
                ));
            }
            if scenario == "input-socket"
                && (member.dev(), member.ino(), member.mode())
                    != (held.dev(), held.ino(), held.mode())
            {
                return Err(CiError::Message(
                    "packing did not exercise the original live input socket".into(),
                ));
            }
            if scenario == "imported-socket"
                && (!member.file_type().is_symlink()
                    || std::fs::read_link(input_root.join("socket")).map_err(|error| {
                        io_at(
                            error,
                            "imported socket readlink",
                            &input_root.join("socket"),
                        )
                    })? != actual)
            {
                return Err(CiError::Message(
                    "packing did not exercise the actual imported socket symlink".into(),
                ));
            }
            if scenario == "host-tree-mount-import-rejected"
                && std::fs::read(host_tree.join("marker.bin")).map_err(|error| {
                    io_at(error, "host marker readback", &host_tree.join("marker.bin"))
                })? != tree_marker
            {
                return Err(CiError::Message(
                    "rejected host-tree import changed host bytes".into(),
                ));
            }
            Ok(())
        })();
        result.map_err(|error| {
            error.context(format!(
                "socket import refusal scenario={scenario} root={}",
                working_directory.display()
            ))
        })?;
    }
    Ok(())
}
