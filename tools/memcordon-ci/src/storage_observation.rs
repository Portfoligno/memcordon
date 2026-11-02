//! Passive, non-atomic storage observations; never admission or cleanup authority.
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};

const ENTRY_LIMIT: usize = 16_384;
const DEPTH_LIMIT: usize = 32;

fn error(error: &std::io::Error) -> Value {
    json!({"kind":format!("{:?}",error.kind()),"native_code":error.raw_os_error()})
}

fn capacity(path: &Path, deadline: Instant) -> Value {
    if Instant::now() >= deadline {
        return json!({"status":"cutoff"});
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let existing = path.ancestors().find(|candidate| candidate.exists());
        let Some(existing) = existing else {
            return json!({"status":"absent"});
        };
        if Instant::now() >= deadline {
            return json!({"status":"cutoff"});
        }
        let metadata = match std::fs::metadata(existing) {
            Ok(value) => value,
            Err(cause) => return json!({"status":"metadata-error","error":error(&cause)}),
        };
        if Instant::now() >= deadline {
            return json!({"status":"cutoff"});
        }
        match rustix::fs::statvfs(existing) {
            Ok(value) => {
                json!({"status":"observed","filesystem_device":metadata.dev(),"available_bytes":value.f_bavail.checked_mul(value.f_frsize),"available_inodes":value.f_favail,"queried_ancestor":existing != path,"late_sample":Instant::now() >= deadline,"atomic":false})
            }
            Err(cause) => json!({"status":"query-error","native_code":cause.raw_os_error()}),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        json!({"status":"unsupported"})
    }
}

fn inventory(path: &Path, remaining: &mut usize, deadline: Instant) -> Value {
    let (mut entries, mut files, mut directories, mut symlinks, mut other, mut errors) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut logical = 0u64;
    #[cfg(unix)]
    let mut allocated = 0u64;
    let mut depth_truncated = false;
    let mut time_truncated = false;
    let mut entry_truncated = false;
    let mut samples = Vec::new();
    let mut walk = walkdir::WalkDir::new(path)
        .follow_links(false)
        .follow_root_links(false)
        .max_depth(DEPTH_LIMIT)
        .into_iter();
    loop {
        if Instant::now() >= deadline {
            time_truncated = true;
            break;
        }
        if *remaining == 0 {
            entry_truncated = true;
            break;
        }
        let Some(item) = walk.next() else {
            break;
        };
        *remaining -= 1;
        entries += 1;
        let entry = match item {
            Ok(value) => value,
            Err(cause) => {
                errors += 1;
                if samples.len() < 8 {
                    samples.push(
                        cause
                            .io_error()
                            .map_or_else(|| json!({"kind":"walk-error"}), error),
                    );
                }
                continue;
            }
        };
        let metadata = match std::fs::symlink_metadata(entry.path()) {
            Ok(value) => value,
            Err(cause) => {
                errors += 1;
                if samples.len() < 8 {
                    samples.push(error(&cause));
                }
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            symlinks += 1;
        } else if metadata.is_dir() {
            directories += 1;
            if entry.depth() == DEPTH_LIMIT {
                depth_truncated = true;
            }
        } else if metadata.is_file() {
            files += 1;
            logical = logical.saturating_add(metadata.len());
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                allocated = allocated.saturating_add(metadata.blocks().saturating_mul(512));
            }
        } else {
            other += 1;
        }
    }
    #[cfg(unix)]
    let allocated = Some(allocated);
    #[cfg(not(unix))]
    let allocated: Option<u64> = None;
    json!({"entries":entries,"files":files,"directories":directories,"symlinks":symlinks,"other":other,"logical_bytes_by_path":logical,"allocated_bytes_by_path":allocated,"hardlinks_counted_per_path":true,"unique_physical_usage":false,"errors":errors,"error_samples":samples,"entry_truncated":entry_truncated,"depth_truncated":depth_truncated,"time_truncated":time_truncated,"complete":errors==0&&!entry_truncated&&!depth_truncated&&!time_truncated,"atomic":false,"symlinks_followed":false,"directory_races_possible":true})
}

pub fn snapshot(
    root: &Path,
    target: Option<&Path>,
    include_inventory: bool,
    deadline: Instant,
) -> Value {
    let inventory_deadline = deadline.min(Instant::now() + Duration::from_millis(100));
    let target = target.map_or_else(
        || root.join("target/ci/native"),
        |path| {
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                root.join(path)
            }
        },
    );
    let roles = [
        ("native-target", target),
        ("driver-runtime", root.join("target/ci-runtime")),
        ("cold-driver", root.join("target/ci-driver-cold")),
        ("transfers", root.join("target/ci-transfer")),
        ("bootstrap-in", root.join("target/ci-bootstrap-in")),
    ];
    let per_role_entries = ENTRY_LIMIT / roles.len();
    let per_role_time = Duration::from_millis(100 / roles.len() as u64);
    let observations = roles
        .into_iter()
        .map(|(role, path)| {
            let capacity = capacity(&path, deadline);
            let inventory = if include_inventory {
                let mut remaining = per_role_entries;
                inventory(
                    &path,
                    &mut remaining,
                    inventory_deadline.min(Instant::now() + per_role_time),
                )
            } else {
                Value::Null
            };
            json!({"role":role,"capacity":capacity,"inventory":inventory})
        })
        .collect::<Vec<_>>();
    let runner_temp =
        std::env::var_os("RUNNER_TEMP").map(|path| capacity(Path::new(&path), deadline));
    json!({"format":"memcordon.storage-observation","version":1,"workspace":capacity(root,deadline),"roles":observations,"runner_temp":runner_temp,"runner_diagnostic_filesystem":"unknown","runner_temp_is_diagnostic_filesystem":null,"acceptance_authority":false,"mutation_performed":false,"inventory_entry_limit_total":ENTRY_LIMIT,"inventory_depth_limit":DEPTH_LIMIT,"inventory_work_limit_ms":100,"inventory_requested":include_inventory,"in_flight_queries_not_preempted":true,"point_in_time_nonatomic":true})
}
