//! Fresh per-attempt input custody. Only bytes cross the public boundary.
pub use super::workload_resources::FootprintReservation;
use super::workload_resources::ReceiverSlot;
use super::workload_snapshot::HeldSnapshot;
use memcordon_core::workload_bundle::{ImageEntryV1, SnapshotManifestV1};
use memcordon_core::workload_request::{RuntimeRequestV1, WorkloadRequestV1};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub struct HeldWorkloadInputs {
    pub runtime: HeldSnapshot,
    pub input: HeldSnapshot,
    pub staging: File,
    pub footprint: FootprintReservation,
}
pub struct InputFailure {
    pub cause: String,
    pub staging: Option<File>,
    pub footprint: Option<FootprintReservation>,
}

pub(crate) fn footprint(
    runtime: &SnapshotManifestV1,
    input: &SnapshotManifestV1,
    request: &WorkloadRequestV1,
) -> Result<u64, String> {
    let mut immutable = 0_u64;
    let page = super::workload_resources::native_page_size()?;
    let mut metadata = 0_u64;
    for entry in runtime
        .entries
        .as_slice()
        .iter()
        .chain(input.entries.as_slice())
    {
        let parents = u64::try_from(entry.path().as_str().split('/').count())
            .map_err(|_| "metadata path count overflow")?;
        metadata = metadata
            .checked_add(
                parents
                    .checked_mul(page)
                    .and_then(|bytes| bytes.checked_mul(2))
                    .ok_or("metadata footprint overflow")?,
            )
            .ok_or("metadata footprint overflow")?;
        if let ImageEntryV1::Regular { size, .. } = entry {
            let rounded = size
                .checked_add(page - 1)
                .map(|bytes| bytes / page * page)
                .ok_or("immutable page rounding overflow")?;
            immutable = immutable
                .checked_add(rounded)
                .ok_or("immutable footprint overflow")?;
        }
    }
    let RuntimeRequestV1::LinuxPrivate { layout, .. } = &request.runtime else {
        return Err("Linux input requires private workload request".into());
    };
    let mut writable = 0_u64;
    for root in layout.writable_roots.as_slice() {
        writable = writable
            .checked_add(super::workload_resources::rounded_bytes(
                root.byte_limit.get(),
                page,
            )?)
            .ok_or("writable footprint overflow")?;
        let inodes = super::workload_resources::writable_inode_limit(root.byte_limit.get(), page)?;
        let parents = u64::try_from(root.path.as_str().split('/').count())
            .map_err(|_| "writable parent count overflow")?;
        metadata = metadata
            .checked_add(
                inodes
                    .checked_add(parents)
                    .and_then(|count| count.checked_mul(page))
                    .and_then(|bytes| bytes.checked_mul(2))
                    .ok_or("writable metadata footprint overflow")?,
            )
            .ok_or("writable metadata footprint overflow")?;
    }
    for output in layout.output_files.as_slice() {
        let parents = u64::try_from(output.as_str().split('/').count())
            .map_err(|_| "output parent count overflow")?;
        metadata = metadata
            .checked_add(
                parents
                    .checked_mul(page)
                    .and_then(|bytes| bytes.checked_mul(2))
                    .ok_or("output metadata footprint overflow")?,
            )
            .ok_or("output metadata footprint overflow")?;
    }
    let shm = super::workload_resources::SHARED_MEMORY_BYTES;
    let shm_metadata = super::workload_resources::writable_inode_limit(shm, page)?
        .checked_mul(page)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or("shared-memory inode footprint overflow")?;
    // Staging + immutable root + writable roots + bounded export copy + manifests,
    // page-rounded object metadata and the separately mounted 64MiB /dev/shm.
    immutable
        .checked_mul(2)
        .and_then(|v| writable.checked_mul(2).and_then(|w| v.checked_add(w)))
        .and_then(|v| {
            v.checked_add(
                u64::try_from(memcordon_core::workload_bundle::MANIFEST_BYTES)
                    .expect("manifest bound fits u64")
                    .checked_mul(2)?,
            )
        })
        .and_then(|value| {
            metadata
                .checked_mul(2)
                .and_then(|metadata| value.checked_add(metadata))
        })
        .and_then(|value| value.checked_add(shm))
        .and_then(|value| value.checked_add(shm_metadata))
        .ok_or_else(|| "combined workload footprint overflow".into())
}

fn receive_inner(
    reader: &mut impl Read,
    staging: File,
    request: &WorkloadRequestV1,
    available_footprint: u64,
    attempt: &str,
    deadline: std::time::Instant,
) -> Result<HeldWorkloadInputs, InputFailure> {
    let mut failure = InputFailure {
        cause: String::new(),
        staging: Some(staging),
        footprint: None,
    };
    let result = (|| -> Result<_, String> {
        request.validate().map_err(|e| e.to_string())?;
        let (runtime, input) = memcordon_core::workload_bundle::read_bundle_headers(reader)?;
        let RuntimeRequestV1::LinuxPrivate { inputs, layout, .. } = &request.runtime else {
            return Err("unsupported Linux request profile".into());
        };
        if runtime.digest()? != inputs.runtime_digest || input.digest()? != inputs.input_digest {
            return Err("snapshot content selection differs".into());
        }
        memcordon_core::workload_bundle::validate_layout(&runtime, &input, layout)?;
        let _descriptor_capacity = super::image_fd_budget::ensure(
            runtime.entries.as_slice().len(),
            input.entries.as_slice().len(),
        )?;
        if !runtime
            .entrypoints
            .as_slice()
            .iter()
            .any(|entry| entry.id == inputs.entrypoint)
        {
            return Err("selected entrypoint is absent from runtime snapshot".into());
        }
        let charge = footprint(&runtime, &input, request)?;
        failure.footprint = Some(FootprintReservation::acquire(
            attempt,
            charge,
            available_footprint,
        )?);
        failure
            .footprint
            .as_mut()
            .expect("new charge owner installed before publication")
            .publish_charge(charge)?;
        let staging = failure
            .staging
            .as_ref()
            .expect("staging held before fallible intake");
        let metadata = staging.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
            return Err("input staging custody differs".into());
        }
        let runtime_root = fresh_directory(staging, "runtime")?;
        let input_root = fresh_directory(staging, "input")?;
        receive_snapshot(reader, &runtime_root, &runtime, deadline)?;
        receive_snapshot(reader, &input_root, &input, deadline)?;
        let runtime = HeldSnapshot::from_received_snapshot(runtime, runtime_root, deadline)?;
        let input = HeldSnapshot::from_received_snapshot(input, input_root, deadline)?;
        super::image_elf_closure::validate(&runtime, &input, layout, deadline)?;
        Ok((runtime, input))
    })();
    match result {
        Ok((runtime, input)) => Ok(HeldWorkloadInputs {
            runtime,
            input,
            staging: failure.staging.take().expect("owned staging"),
            footprint: failure.footprint.take().expect("admitted footprint"),
        }),
        Err(cause) => {
            failure.cause = cause;
            Err(failure)
        }
    }
}

/// Actual version-five intake over the original authenticated connection.
pub fn receive_framed(
    stream: &mut std::os::unix::net::UnixStream,
    association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
    deadline: std::time::Instant,
    staging: File,
    request: &WorkloadRequestV1,
    available: u64,
    _slot: ReceiverSlot,
) -> Result<HeldWorkloadInputs, InputFailure> {
    let mut reader = match FramedBundleReader::new(stream, association, deadline) {
        Ok(reader) => reader,
        Err(cause) => {
            return Err(InputFailure {
                cause,
                staging: Some(staging),
                footprint: None,
            });
        }
    };
    let attempt: String = association
        .attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let inputs = receive_inner(&mut reader, staging, request, available, &attempt, deadline)?;
    if let Err(cause) = reader.finish() {
        return Err(InputFailure {
            cause,
            staging: Some(inputs.staging),
            footprint: Some(inputs.footprint),
        });
    }
    Ok(inputs)
}

struct FramedBundleReader<'a> {
    stream: &'a mut std::os::unix::net::UnixStream,
    association: &'a memcordon_core::workload_request::WorkloadAttemptAssociationV1,
    deadline: std::time::Instant,
    headers: std::io::Cursor<Vec<u8>>,
    members: Vec<(memcordon_core::workload_chunks::SnapshotRoleV1, u32, u64)>,
    member: usize,
    received: u64,
    pending: std::io::Cursor<Vec<u8>>,
}
fn next_frame(
    stream: &mut std::os::unix::net::UnixStream,
    association: &memcordon_core::workload_request::WorkloadAttemptAssociationV1,
    deadline: std::time::Instant,
) -> Result<crate::protocol::Frame, String> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err("original workload input deadline expired".into());
    }
    let frame = read_frame_until(stream, deadline)?;
    if frame.nonce != association.challenge || frame.attempt_id != association.attempt {
        return Err("input frame crosses original native session".into());
    }
    if frame.kind == crate::protocol::MessageKind::WorkloadCancel {
        return Err("controlled workload cancellation during intake".into());
    }
    Ok(frame)
}
pub(super) fn read_frame_until(
    stream: &mut std::os::unix::net::UnixStream,
    deadline: std::time::Instant,
) -> Result<crate::protocol::Frame, String> {
    let mut reader = DeadlineStreamReader { stream, deadline };
    crate::protocol::read_frame_version(&mut reader, crate::protocol::WORKLOAD_PROTOCOL_VERSION)
        .map_err(|e| e.to_string())
}
struct DeadlineStreamReader<'a> {
    stream: &'a mut std::os::unix::net::UnixStream,
    deadline: std::time::Instant,
}
impl Read for DeadlineStreamReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original workload input cutoff expired",
            ));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(bytes)
    }
}
impl<'a> FramedBundleReader<'a> {
    fn new(
        stream: &'a mut std::os::unix::net::UnixStream,
        association: &'a memcordon_core::workload_request::WorkloadAttemptAssociationV1,
        deadline: std::time::Instant,
    ) -> Result<Self, String> {
        use memcordon_core::workload_chunks::{SnapshotRoleV1, WorkloadChunkV1};
        association.validate().map_err(|e| e.to_string())?;
        let mut manifests = Vec::new();
        for role in [SnapshotRoleV1::Runtime, SnapshotRoleV1::Input] {
            let mut bytes = Vec::new();
            let mut next = 0_u64;
            let mut declared = None;
            loop {
                let frame = next_frame(stream, association, deadline)?;
                if frame.kind != crate::protocol::MessageKind::WorkloadManifestChunk {
                    return Err("expected ordered snapshot manifest".into());
                }
                let chunk = WorkloadChunkV1::decode(&frame.payload)?;
                if chunk.role != role
                    || chunk.member_index != 0
                    || chunk.offset != next
                    || chunk.total
                        > u64::try_from(memcordon_core::workload_bundle::MANIFEST_BYTES)
                            .expect("manifest bound fits u64")
                    || declared.is_some_and(|total| total != chunk.total)
                {
                    return Err("manifest role/index/offset/length differs".into());
                }
                if declared.is_none() {
                    bytes
                        .try_reserve_exact(
                            usize::try_from(chunk.total).map_err(|_| "manifest length overflow")?,
                        )
                        .map_err(|e| e.to_string())?;
                    declared = Some(chunk.total);
                }
                bytes.extend_from_slice(chunk.bytes);
                next = next
                    .checked_add(u64::try_from(chunk.bytes.len()).expect("bounded chunk length"))
                    .ok_or("manifest offset overflow")?;
                if Some(next) == declared {
                    break;
                }
            }
            manifests.push(SnapshotManifestV1::parse(&bytes)?);
        }
        let input = manifests.pop().expect("two manifests");
        let runtime = manifests.pop().expect("two manifests");
        memcordon_core::workload_bundle::validate_combined(&runtime, &input)?;
        let mut headers = Vec::new();
        memcordon_core::workload_bundle::write_bundle_headers(&mut headers, &runtime, &input)?;
        let mut members = Vec::new();
        for (role, manifest) in [
            (SnapshotRoleV1::Runtime, &runtime),
            (SnapshotRoleV1::Input, &input),
        ] {
            for (index, member) in manifest.regular_members().into_iter().enumerate() {
                if let ImageEntryV1::Regular { size, .. } = member {
                    members.push((
                        role,
                        u32::try_from(index).map_err(|_| "member index overflow")?,
                        *size,
                    ));
                }
            }
        }
        Ok(Self {
            stream,
            association,
            deadline,
            headers: std::io::Cursor::new(headers),
            members,
            member: 0,
            received: 0,
            pending: std::io::Cursor::new(Vec::new()),
        })
    }
    fn finish(mut self) -> Result<(), String> {
        let mut extra = [0; 1];
        if self.read(&mut extra).map_err(|e| e.to_string())? != 0 {
            return Err("undeclared trailing member bytes".into());
        }
        let frame = next_frame(self.stream, self.association, self.deadline)?;
        if frame.kind != crate::protocol::MessageKind::WorkloadInputComplete
            || !frame.payload.is_empty()
        {
            return Err("missing exact input-complete frame".into());
        }
        Ok(())
    }
}
impl Read for FramedBundleReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let count = self.headers.read(output)?;
        if count != 0 {
            return Ok(count);
        }
        loop {
            let count = self.pending.read(output)?;
            if count != 0 {
                return Ok(count);
            }
            let Some(&(role, index, total)) = self.members.get(self.member) else {
                return Ok(0);
            };
            if self.received == total {
                self.member += 1;
                self.received = 0;
                continue;
            }
            let frame = next_frame(self.stream, self.association, self.deadline)
                .map_err(std::io::Error::other)?;
            if frame.kind != crate::protocol::MessageKind::WorkloadMemberChunk {
                return Err(std::io::Error::other("expected ordered member frame"));
            }
            let chunk = memcordon_core::workload_chunks::WorkloadChunkV1::decode(&frame.payload)
                .map_err(std::io::Error::other)?;
            if chunk.role != role
                || chunk.member_index != index
                || chunk.total != total
                || chunk.offset != self.received
            {
                return Err(std::io::Error::other(
                    "member role/index/offset/length differs",
                ));
            }
            self.received = self
                .received
                .checked_add(u64::try_from(chunk.bytes.len()).expect("bounded chunk length"))
                .ok_or_else(|| std::io::Error::other("member offset overflow"))?;
            self.pending = std::io::Cursor::new(chunk.bytes.to_vec());
        }
    }
}

fn fresh_directory(parent: &File, name: &str) -> Result<File, String> {
    let name = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}
fn receive_snapshot(
    reader: &mut impl Read,
    root: &File,
    manifest: &SnapshotManifestV1,
    deadline: std::time::Instant,
) -> Result<(), String> {
    for member in manifest.regular_members() {
        super::workload_snapshot::check_validation_cutoff(deadline)?;
        let ImageEntryV1::Regular { executable, .. } = member else {
            unreachable!("regular member inventory")
        };
        let mut file = super::workload_snapshot::open_relative(root.as_fd(), member.path(), true)?;
        memcordon_core::workload_bundle::stream_member(reader, &mut file, member)?;
        file.set_permissions(std::fs::Permissions::from_mode(if *executable {
            0o500
        } else {
            0o400
        }))
        .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        super::workload_snapshot::verify_regular_until(&file, member, true, deadline)?;
    }
    for member in manifest.entries.as_slice() {
        super::workload_snapshot::check_validation_cutoff(deadline)?;
        if let ImageEntryV1::Symlink { path, target } = member {
            let (parent, name) = super::workload_snapshot::parent_at(root.as_fd(), path, true)?;
            let mut relative = std::path::PathBuf::new();
            for _ in std::path::Path::new(path.as_str())
                .parent()
                .expect("relative member parent")
                .components()
            {
                relative.push("..");
            }
            relative.push(target.as_str());
            let target = std::ffi::CString::new(relative.as_os_str().as_bytes())
                .map_err(|e| e.to_string())?;
            if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
    }
    root.sync_all().map_err(|e| e.to_string())
}
