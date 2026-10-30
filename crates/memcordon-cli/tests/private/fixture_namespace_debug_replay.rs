//! Explicit owned-child replay; never replaces the original uninstrumented result.
use super::protocol;
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    time::Instant,
};
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(target_arch = "x86_64")]
#[path = "fixture_namespace_call_marker.rs"]
mod call_marker;
#[cfg(target_arch = "x86_64")]
#[path = "fixture_namespace_candidate.rs"]
mod candidate_observation;
#[cfg(target_arch = "x86_64")]
#[path = "fixture_namespace_debug_context.rs"]
mod context_observation;
#[cfg(target_arch = "x86_64")]
#[path = "fixture_namespace_context_storage.rs"]
mod context_storage;
#[cfg(target_arch = "x86_64")]
#[path = "fixture_namespace_directory_native.rs"]
mod directory_native;
#[cfg(target_arch = "x86_64")]
#[path = "fixture_namespace_directory_policy.rs"]
mod directory_policy;
#[cfg(target_arch = "x86_64")]
#[path = "fixture_namespace_helper_evidence.rs"]
mod helper_evidence;
#[cfg(target_arch = "x86_64")]
#[path = "fixture_namespace_hit_receipt.rs"]
mod hit_receipt;
#[cfg(target_arch = "x86_64")]
#[path = "fixture_namespace_mapped_path.rs"]
mod mapped_path;
#[cfg(target_arch = "x86_64")]
#[path = "fixture_namespace_debug_profile.rs"]
mod profile;

fn directory(request: &protocol::Request) -> io::Result<PathBuf> {
    // Request validation also closes the nonce grammar before using a path component.
    protocol::encode_request(request)?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("repository root"))?
        .join("target/ci/reports/namespace-win32")
        .join(&request.nonce);
    std::fs::create_dir_all(&root)?;
    Ok(root)
}
fn persist(path: &Path, value: &Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes
        .len()
        .checked_add(1)
        .is_none_or(|length| length > 65536)
    {
        return Err(io::Error::other("replay JSON bound"));
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()
}
pub fn capture(
    token: HANDLE,
    request: &protocol::Request,
    original: &protocol::Response,
    deadline: Instant,
) {
    let retained = (|| -> io::Result<()> {
        let root = directory(request)?;
        persist(
            &root.join("original-before-debug-replay.json"),
            &json!({"diagnostic_only":true,"acceptance_authority":false,"original_failure":original,"request":request}),
        )?;
        #[cfg(target_arch = "x86_64")]
        let mut result = x64::run(token, request, original, deadline, &root);
        #[cfg(not(target_arch = "x86_64"))]
        let mut result = {
            let _ = (token, deadline);
            json!({"reason":"unsupported-architecture","architecture":std::env::consts::ARCH})
        };
        result["original_failure"] = json!({"full_record":"original-before-debug-replay.json","phase":original.phase,"success":original.success,"raw_error":original.raw_error,"event_handle":original.event_handle,"modify_denied":original.modify_denied});
        result["diagnostic_only"] = json!(true);
        result["acceptance_authority"] = json!(false);
        result["replay"] = json!(true);
        result["runtime_original_call_branch"] = json!("unobserved");
        result["original_nonce"] = json!(request.nonce);
        #[cfg(target_arch = "x86_64")]
        let result =
            helper_evidence::fit_report(result).map_err(helper_evidence::CaptureError::io_error)?;
        persist(&root.join("debug-replay.json"), &result)
    })();
    if let Err(error) = retained {
        eprintln!(
            "owned debug replay unavailable: kind={:?}; raw={:?}",
            error.kind(),
            error.raw_os_error()
        );
    }
}

#[cfg(target_arch = "x86_64")]
mod x64 {
    use super::super::replay_wire;
    use super::super::{Child, launch_mode};
    use super::call_marker;
    use super::candidate_observation::{
        Candidate, Candidates, HandleState, MappedEvidence, PathEvidence, Provider, Stage,
    };
    use super::context_observation::{Call, Purpose, Stage as ContextStage, Trace};
    use super::context_storage::ContextStorage;
    use super::hit_receipt::{Metadata, Receipt, ReceiptStage, Receipts};
    use super::mapped_path;
    use super::profile;
    use super::*;
    use profile::{DebugRegisters, Planner, Site, State, Stop};
    use sha2::{Digest, Sha256};
    use std::{
        fs::File,
        io::{Read, Seek, SeekFrom},
        mem::{MaybeUninit, size_of},
        os::windows::ffi::{OsStrExt, OsStringExt},
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Globalization::{CSTR_EQUAL, CompareStringOrdinal},
        Storage::FileSystem::*,
        System::{
            Diagnostics::Debug::*, IO::CancelSynchronousIo, Memory::*, Performance::*,
            ProcessStatus::K32GetMappedFileNameW, SystemInformation::GetSystemDirectoryW,
            Threading::*,
        },
    };

    fn error() -> io::Error {
        io::Error::last_os_error()
    }
    fn counter() -> io::Result<u64> {
        let mut now = 0;
        if unsafe { QueryPerformanceCounter(&mut now) } == 0 {
            return Err(error());
        }
        u64::try_from(now).map_err(io::Error::other)
    }
    fn raw(child: &Child) -> HANDLE {
        child.process.as_raw_handle()
    }
    fn thread_raw(child: &Child) -> HANDLE {
        child
            .thread
            .as_ref()
            .expect("creation thread retained")
            .as_raw_handle()
    }
    fn registers(context: &CONTEXT) -> DebugRegisters {
        DebugRegisters {
            dr: [context.Dr0, context.Dr1, context.Dr2, context.Dr3],
            dr6: context.Dr6,
            dr7: context.Dr7,
            eflags: context.EFlags,
        }
    }
    fn register_record(value: DebugRegisters) -> Value {
        json!({"dr0_dr3":value.dr,"dr6":value.dr6,"dr7":value.dr7,"eflags":value.eflags})
    }
    const _: () = {
        assert!(std::mem::align_of::<ContextStorage<CONTEXT>>() >= 16);
        assert!(std::mem::offset_of!(ContextStorage<CONTEXT>, 0) == 0);
        assert!(size_of::<ContextStorage<CONTEXT>>() == size_of::<CONTEXT>());
    };
    fn context(
        child: &Child,
        cutoff: u64,
        wall: Instant,
        trace: &mut Trace,
        purpose: Purpose,
        stage: ContextStage,
    ) -> io::Result<CONTEXT> {
        live(cutoff, wall)?;
        let mut storage = ContextStorage(CONTEXT {
            ContextFlags: CONTEXT_CONTROL_AMD64
                | CONTEXT_INTEGER_AMD64
                | CONTEXT_DEBUG_REGISTERS_AMD64,
            ..Default::default()
        });
        let flags = storage.0.ContextFlags;
        let address_mod_16 = std::ptr::addr_of!(storage.0) as usize % 16;
        assert_eq!(address_mod_16, 0, "aligned context field");
        let success = unsafe { GetThreadContext(thread_raw(child), &mut storage.0) } != 0;
        let error = error();
        trace.record(Call {
            purpose,
            stage,
            flags,
            size: size_of::<CONTEXT>(),
            alignment: std::mem::align_of::<ContextStorage<CONTEXT>>(),
            address_mod_16,
            success,
            raw_error: (!success).then(|| error.raw_os_error()).flatten(),
        });
        if !success {
            return Err(error);
        }
        live(cutoff, wall)?;
        Ok(storage.0)
    }
    fn set(
        child: &Child,
        planned: DebugRegisters,
        cutoff: u64,
        wall: Instant,
        trace: &mut Trace,
        purpose: Purpose,
    ) -> io::Result<DebugRegisters> {
        live(cutoff, wall)?;
        let storage = ContextStorage(CONTEXT {
            ContextFlags: CONTEXT_DEBUG_REGISTERS_AMD64,
            Dr0: planned.dr[0],
            Dr1: planned.dr[1],
            Dr2: planned.dr[2],
            Dr3: planned.dr[3],
            Dr6: planned.dr6,
            Dr7: planned.dr7,
            ..Default::default()
        });
        let address_mod_16 = std::ptr::addr_of!(storage.0) as usize % 16;
        assert_eq!(address_mod_16, 0, "aligned context field");
        let success = unsafe { SetThreadContext(thread_raw(child), &storage.0) } != 0;
        let error = error();
        trace.record(Call {
            purpose,
            stage: ContextStage::SetRegisters,
            flags: storage.0.ContextFlags,
            size: size_of::<CONTEXT>(),
            alignment: std::mem::align_of::<ContextStorage<CONTEXT>>(),
            address_mod_16,
            success,
            raw_error: (!success).then(|| error.raw_os_error()).flatten(),
        });
        if !success {
            return Err(error);
        }
        live(cutoff, wall)?;
        Ok(registers(&context(
            child,
            cutoff,
            wall,
            trace,
            purpose,
            ContextStage::GetReadback,
        )?))
    }
    fn read(
        process: HANDLE,
        address: u64,
        length: usize,
        cutoff: u64,
        wall: Instant,
    ) -> io::Result<Vec<u8>> {
        live(cutoff, wall)?;
        address
            .checked_add(u64::try_from(length).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("remote extent overflow"))?;
        let mut bytes = vec![0u8; length];
        let mut count = 0;
        if unsafe {
            ReadProcessMemory(
                process,
                address as usize as *const _,
                bytes.as_mut_ptr().cast(),
                length,
                &mut count,
            )
        } == 0
        {
            return Err(error());
        }
        if count != length {
            return Err(io::Error::other("partial public argument/code read"));
        }
        live(cutoff, wall)?;
        Ok(bytes)
    }
    fn path(
        mut query: impl FnMut(*mut u16, u32) -> u32,
        cutoff: u64,
        wall: Instant,
    ) -> io::Result<Vec<u16>> {
        let mut capacity = 256usize;
        loop {
            live(cutoff, wall)?;
            let mut bytes = vec![0u16; capacity];
            let length = query(bytes.as_mut_ptr(), capacity as u32) as usize;
            let query_error = error();
            live(cutoff, wall)?;
            if length == 0 {
                return Err(query_error);
            }
            if length < capacity {
                bytes.truncate(length);
                return Ok(bytes);
            }
            capacity = capacity
                .checked_mul(2)
                .filter(|size| *size <= 32768)
                .ok_or_else(|| io::Error::other("debug image path bound"))?;
        }
    }
    fn live(cutoff: u64, wall: Instant) -> io::Result<()> {
        if counter()? >= cutoff || Instant::now() >= wall {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original replay phase cutoff",
            ));
        }
        Ok(())
    }
    fn file_information<T>(
        file: &File,
        class: FILE_INFO_BY_HANDLE_CLASS,
        cutoff: u64,
        wall: Instant,
    ) -> io::Result<T> {
        live(cutoff, wall)?;
        let mut value = MaybeUninit::<T>::uninit();
        // SAFETY: callers select the SDK structure corresponding to this public class.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                class,
                value.as_mut_ptr().cast(),
                size_of::<T>() as u32,
            )
        };
        let error = error();
        live(cutoff, wall)?;
        if ok == 0 {
            return Err(error);
        }
        Ok(unsafe { value.assume_init() })
    }
    fn file_identity(file: &File, cutoff: u64, wall: Instant) -> io::Result<Value> {
        let id: FILE_ID_INFO = file_information(file, FileIdInfo, cutoff, wall)?;
        let basic: FILE_BASIC_INFO = file_information(file, FileBasicInfo, cutoff, wall)?;
        let standard: FILE_STANDARD_INFO = file_information(file, FileStandardInfo, cutoff, wall)?;
        if standard.Directory
            || standard.DeletePending
            || standard.EndOfFile < 0
            || basic.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        {
            return Err(io::Error::other("debug host file custody"));
        }
        Ok(
            json!({"volume":id.VolumeSerialNumber,"id":id.FileId.Identifier,"length":standard.EndOfFile,"creation":basic.CreationTime,"write":basic.LastWriteTime,"change":basic.ChangeTime,"attributes":basic.FileAttributes}),
        )
    }
    fn candidate(
        file: &mut File,
        base: u64,
        child: &Child,
        cutoff: u64,
        wall: Instant,
        proof: &mut Value,
        observation: &mut Candidate,
    ) -> io::Result<Option<Vec<u16>>> {
        live(cutoff, wall)?;
        let before = file.metadata()?;
        live(cutoff, wall)?;
        if !observation.length_matches(before.len(), profile::FILE_LEN as u64) {
            return Ok(None);
        }
        let name = path(
            |buffer, size| unsafe {
                GetFinalPathNameByHandleW(
                    file.as_raw_handle(),
                    buffer,
                    size,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            },
            cutoff,
            wall,
        )?;
        observation.final_path(&name);
        let system = path(
            |buffer, size| unsafe { GetSystemDirectoryW(buffer, size) },
            cutoff,
            wall,
        )?;
        observation.system_directory(&system);
        observation.extended_dos_prefix_stripped = name.starts_with(&[92, 92, 63, 92]);
        let name = name.strip_prefix(&[92, 92, 63, 92]).unwrap_or(&name);
        let Some(split) = name.iter().rposition(|unit| *unit == 92) else {
            observation.predicates(false, false, false);
            return Ok(None);
        };
        let same = |left: &[u16], right: &[u16]| {
            let result = unsafe {
                CompareStringOrdinal(
                    left.as_ptr(),
                    left.len() as i32,
                    right.as_ptr(),
                    right.len() as i32,
                    1,
                )
            };
            (
                result == CSTR_EQUAL,
                if result == 0 {
                    error().raw_os_error()
                } else {
                    None
                },
            )
        };
        let (parent_matches, parent_error) = same(&name[..split], &system);
        let (basename_matches, basename_error) = same(
            &name[split + 1..],
            &"kernelbase.dll".encode_utf16().collect::<Vec<_>>(),
        );
        observation.parent_raw_error = parent_error;
        observation.basename_raw_error = basename_error;
        if !observation.predicates(true, parent_matches, basename_matches) {
            return Ok(None);
        }
        if !before.is_file() {
            return Err(io::Error::other("host is not regular file"));
        }
        let identity_before = file_identity(file, cutoff, wall)?;
        observation.stage = Stage::Read;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(profile::FILE_LEN);
        let mut block = [0u8; 65536];
        loop {
            live(cutoff, wall)?;
            let count = file.read(&mut block)?;
            if count == 0 {
                break;
            }
            if bytes
                .len()
                .checked_add(count)
                .is_none_or(|size| size > profile::FILE_LEN)
            {
                return Err(io::Error::other("host file bound"));
            }
            bytes.extend_from_slice(&block[..count]);
        }
        observation.stage = Stage::FileMetadataAfter;
        let after = file.metadata()?;
        use std::os::windows::fs::MetadataExt;
        if (
            before.file_size(),
            before.last_write_time(),
            before.creation_time(),
            before.file_attributes(),
        ) != (
            after.file_size(),
            after.last_write_time(),
            after.creation_time(),
            after.file_attributes(),
        ) {
            return Err(io::Error::other("host file changed"));
        }
        observation.stage = Stage::FileProfile;
        profile::validate_file(&bytes)?;
        observation.stage = Stage::FileIdentityAfter;
        let identity_after = file_identity(file, cutoff, wall)?;
        if identity_before != identity_after {
            return Err(io::Error::other("debug host file identity changed"));
        }
        live(cutoff, wall)?;
        observation.stage = Stage::RuntimeHeader;
        profile::validate_runtime_header(&read(raw(child), base, 4096, cutoff, wall)?)?;
        let sites = validate_sites(child, base, cutoff, wall, observation)?;
        *proof = json!({"hash":profile::IMAGE_SHA256,"file_length":bytes.len(),"identity_before":identity_before,"identity_after":identity_after,"sites":sites,"mapped_image_scope":"only header and listed instruction extents"});
        observation.stage = Stage::Accepted;
        Ok(Some(name.to_vec()))
    }
    fn validate_sites(
        child: &Child,
        base: u64,
        cutoff: u64,
        wall: Instant,
        observation: &mut Candidate,
    ) -> io::Result<Vec<Value>> {
        let mut sites = Vec::new();
        let extents = Site::ALL
            .into_iter()
            .map(|site| (site.rva(), site.bytes()))
            .chain(
                profile::helper_profile::byte_extents()
                    .iter()
                    .map(|extent| (extent.rva, extent.bytes.as_slice())),
            );
        for (rva, expected) in extents {
            if u64::from(rva)
                .checked_add(expected.len() as u64)
                .is_none_or(|end| end > u64::from(profile::SIZE_OF_IMAGE))
            {
                return Err(io::Error::other("profile extent outside admitted image"));
            }
            observation.stage = Stage::Mapping;
            observation.site_rva = Some(u64::from(rva));
            live(cutoff, wall)?;
            let address = base
                .checked_add(u64::from(rva))
                .ok_or_else(|| io::Error::other("helper extent address overflow"))?;
            let mut region = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
            if unsafe {
                VirtualQueryEx(
                    raw(child),
                    address as usize as *const _,
                    region.as_mut_ptr(),
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            } != size_of::<MEMORY_BASIC_INFORMATION>()
            {
                return Err(error());
            }
            live(cutoff, wall)?;
            let region = unsafe { region.assume_init() };
            let end = (region.BaseAddress as usize as u64)
                .checked_add(region.RegionSize as u64)
                .ok_or_else(|| io::Error::other("mapping overflow"))?;
            if region.State != MEM_COMMIT
                || region.Type != MEM_IMAGE
                || region.AllocationBase as usize as u64 != base
                || region.Protect & (PAGE_GUARD | PAGE_NOACCESS) != 0
                || !matches!(
                    region.Protect & 0xff,
                    PAGE_EXECUTE
                        | PAGE_EXECUTE_READ
                        | PAGE_EXECUTE_READWRITE
                        | PAGE_EXECUTE_WRITECOPY
                )
                || address
                    .checked_add(expected.len() as u64)
                    .is_none_or(|last| last > end)
            {
                return Err(io::Error::other("unverified executable image mapping"));
            }
            observation.stage = Stage::RuntimeBytes;
            let actual = read(raw(child), address, expected.len(), cutoff, wall)?;
            if actual != expected {
                return Err(io::Error::other("helper/outer mapped extent byte mismatch"));
            }
            sites.push(json!({"rva":rva,"length":expected.len(),"verified_sha256":Sha256::digest(&actual).iter().map(|byte|format!("{byte:02x}")).collect::<String>()}));
        }
        Ok(sites)
    }

    fn ordinal(left: &[u16], right: &[u16], cutoff: u64, wall: Instant) -> io::Result<i32> {
        live(cutoff, wall)?;
        let result = unsafe {
            CompareStringOrdinal(
                left.as_ptr(),
                i32::try_from(left.len()).map_err(io::Error::other)?,
                right.as_ptr(),
                i32::try_from(right.len()).map_err(io::Error::other)?,
                1,
            )
        };
        let error = error();
        live(cutoff, wall)?;
        if result == 0 {
            return Err(error);
        }
        Ok(result)
    }
    fn mapped_name(child: &Child, base: u64, cutoff: u64, wall: Instant) -> io::Result<Vec<u16>> {
        let mut capacity = 256;
        loop {
            live(cutoff, wall)?;
            let mut buffer = vec![u16::MAX; capacity];
            let count = unsafe {
                K32GetMappedFileNameW(
                    raw(child),
                    base as usize as *const _,
                    buffer.as_mut_ptr(),
                    capacity as u32,
                )
            } as usize;
            let error = error();
            live(cutoff, wall)?;
            if count == 0 {
                return Err(error);
            }
            match mapped_path::query(&buffer, count)? {
                mapped_path::Query::Complete(name) => {
                    mapped_path::nt_parts(&name)?;
                    return Ok(name);
                }
                mapped_path::Query::Grow(next) => capacity = next,
            }
        }
    }
    fn base_mapping(child: &Child, base: u64, cutoff: u64, wall: Instant) -> io::Result<()> {
        live(cutoff, wall)?;
        if base == 0 {
            return Err(io::Error::other("zero event mapping base"));
        }
        let mut region = MEMORY_BASIC_INFORMATION::default();
        let size = unsafe {
            VirtualQueryEx(
                raw(child),
                base as usize as *const _,
                &mut region,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        let error = error();
        live(cutoff, wall)?;
        if size != size_of::<MEMORY_BASIC_INFORMATION>() {
            return Err(error);
        }
        let first = region.BaseAddress as usize as u64;
        let end = first
            .checked_add(region.RegionSize as u64)
            .ok_or_else(|| io::Error::other("mapped header extent"))?;
        if region.State != MEM_COMMIT
            || region.Type != MEM_IMAGE
            || region.AllocationBase as usize as u64 != base
            || region.Protect & (PAGE_GUARD | PAGE_NOACCESS) != 0
            || first > base
            || base.checked_add(4096).is_none_or(|last| last > end)
        {
            return Err(io::Error::other("unverified event image allocation"));
        }
        Ok(())
    }
    fn final_nt(file: &File, cutoff: u64, wall: Instant) -> io::Result<Vec<u16>> {
        let name = path(
            |buffer, size| unsafe {
                GetFinalPathNameByHandleW(
                    file.as_raw_handle(),
                    buffer,
                    size,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_NT,
                )
            },
            cutoff,
            wall,
        )?;
        mapped_path::nt_parts(&name)?;
        Ok(name)
    }
    fn open_provider(path: &Path, directory: bool, cutoff: u64, wall: Instant) -> io::Result<File> {
        let name: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        if name.len() > 32768 || name[..name.len() - 1].contains(&0) {
            return Err(io::Error::other("provider open path bound"));
        }
        live(cutoff, wall)?;
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                if directory {
                    FILE_READ_ATTRIBUTES
                } else {
                    GENERIC_READ
                },
                if directory {
                    FILE_SHARE_READ | FILE_SHARE_WRITE
                } else {
                    FILE_SHARE_READ
                },
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        FILE_ATTRIBUTE_NORMAL
                    },
                std::ptr::null_mut(),
            )
        };
        let error = error();
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            live(cutoff, wall)?;
            return Err(error);
        }
        // Acquire ownership before the post-call cutoff check, including late success.
        let file = File::from(unsafe { OwnedHandle::from_raw_handle(handle) });
        live(cutoff, wall)?;
        Ok(file)
    }
    fn directory_identity(file: &File, cutoff: u64, wall: Instant) -> io::Result<Value> {
        let id: FILE_ID_INFO = file_information(file, FileIdInfo, cutoff, wall)?;
        let basic: FILE_BASIC_INFO = file_information(file, FileBasicInfo, cutoff, wall)?;
        let standard: FILE_STANDARD_INFO = file_information(file, FileStandardInfo, cutoff, wall)?;
        if !standard.Directory
            || standard.DeletePending
            || basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(io::Error::other("provider root directory custody"));
        }
        Ok(
            json!({"volume":id.VolumeSerialNumber,"id":id.FileId.Identifier,"creation":basic.CreationTime,"attributes":basic.FileAttributes}),
        )
    }
    struct EventGuard {
        file: File,
        base: u64,
        identity: Value,
        path: Vec<u16>,
    }
    impl EventGuard {
        fn recheck(&mut self, child: &Child, cutoff: u64, wall: Instant) -> io::Result<Value> {
            if file_identity(&self.file, cutoff, wall)? != self.identity {
                return Err(io::Error::other(
                    "event provider admission identity changed",
                ));
            }
            let mut proof = Value::Null;
            let mut observation = Candidate::new(
                (0, child.pid, child.tid, self.base),
                HandleState::Present,
                true,
            );
            let path = candidate(
                &mut self.file,
                self.base,
                child,
                cutoff,
                wall,
                &mut proof,
                &mut observation,
            )?
            .ok_or_else(|| io::Error::other("event provider PRE profile nonmatch"))?;
            if proof["identity_before"] != self.identity
                || proof["identity_after"] != self.identity
                || !mapped_path::ordinal_result(ordinal(&self.path, &path, cutoff, wall)?)?
            {
                return Err(io::Error::other("event provider admission binding changed"));
            }
            proof["source_binding"] = json!({"kind":"debug-event-file","section_file_identity":"not-observed","original_runtime_iat":"not-observed"});
            Ok(proof)
        }
    }
    struct MappedGuard {
        file: File,
        directory: File,
        mapped: Vec<u16>,
        root_nt: Vec<u16>,
        system: Vec<u16>,
        root_identity: Value,
        file_identity: Value,
        base: u64,
    }
    impl MappedGuard {
        fn prepare(
            child: &Child,
            base: u64,
            cutoff: u64,
            wall: Instant,
            observation: &mut Candidate,
            existing_guard: Option<&Self>,
        ) -> io::Result<Option<Self>> {
            observation.provider = Some(Provider::for_handle(observation.handle));
            if observation.provider != Some(Provider::MappedImageFile) {
                return Err(io::Error::other(
                    "mapped provider requires absent event file",
                ));
            }
            observation.mapped = Some(MappedEvidence::default());
            observation.stage = Stage::MappedBase;
            base_mapping(child, base, cutoff, wall)?;
            observation.stage = Stage::MappedName;
            let mapped = mapped_name(child, base, cutoff, wall)?;
            observation.mapped.as_mut().unwrap().before = Some(PathEvidence::new(&mapped));
            let (parent, leaf) = mapped_path::nt_parts(&mapped)?;
            let profile_leaf: Vec<u16> = mapped_path::PROFILE_LEAF.encode_utf16().collect();
            let leaf_result = ordinal(leaf, &profile_leaf, cutoff, wall)?;
            if !mapped_path::ordinal_result(leaf_result)? {
                observation.stage = Stage::MappedBasenameMismatch;
                return Ok(None);
            }
            if let Some(guard) = existing_guard {
                let parent_result = ordinal(parent, &guard.root_nt, cutoff, wall)?;
                let bound = mapped_path::bind(&mapped, &guard.root_nt, parent_result, leaf_result)?;
                let evidence = observation.mapped.as_mut().unwrap();
                evidence.root_nt = Some(PathEvidence::new(&guard.root_nt));
                evidence.root_matches = Some(bound);
                evidence.selected = bound;
                if bound {
                    return Err(io::Error::other("competing mapped host candidate"));
                }
                observation.stage = Stage::MappedRootMismatch;
                return Ok(None);
            }
            observation.stage = Stage::MappedSystemDirectory;
            let system = path(
                |buffer, size| unsafe { GetSystemDirectoryW(buffer, size) },
                cutoff,
                wall,
            )?;
            if system.contains(&0)
                || String::from_utf16(&system).is_err()
                || !system.first().is_some_and(|unit| {
                    u8::try_from(*unit).is_ok_and(|byte| byte.is_ascii_alphabetic())
                })
                || system.get(1) != Some(&u16::from(b':'))
                || system.get(2) != Some(&u16::from(b'\\'))
            {
                return Err(io::Error::other("provider system directory UTF16"));
            }
            let system_path = PathBuf::from(std::ffi::OsString::from_wide(&system));
            observation.system_directory(&system);
            observation.stage = Stage::MappedRootOpen;
            let directory = open_provider(&system_path, true, cutoff, wall)?;
            observation.stage = Stage::MappedRootIdentity;
            let root_identity = directory_identity(&directory, cutoff, wall)?;
            observation.stage = Stage::MappedRootPath;
            let root_nt = final_nt(&directory, cutoff, wall)?;
            observation.mapped.as_mut().unwrap().root_nt = Some(PathEvidence::new(&root_nt));
            let root_dos = path(
                |buffer, size| unsafe {
                    GetFinalPathNameByHandleW(
                        directory.as_raw_handle(),
                        buffer,
                        size,
                        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                    )
                },
                cutoff,
                wall,
            )?;
            let root_dos = root_dos
                .strip_prefix(&[92, 92, 63, 92])
                .unwrap_or(&root_dos);
            observation.mapped.as_mut().unwrap().root_dos = Some(PathEvidence::new(root_dos));
            let canonical = mapped_path::ordinal_result(ordinal(root_dos, &system, cutoff, wall)?)?;
            observation
                .mapped
                .as_mut()
                .unwrap()
                .canonical_system_matches = Some(canonical);
            if !canonical {
                return Err(io::Error::other("provider root DOS binding"));
            }
            let root_result = ordinal(parent, &root_nt, cutoff, wall)?;
            let bound = mapped_path::bind(&mapped, &root_nt, root_result, leaf_result)?;
            observation.mapped.as_mut().unwrap().root_matches = Some(bound);
            if !bound {
                observation.stage = Stage::MappedRootMismatch;
                return Ok(None);
            }
            observation.mapped.as_mut().unwrap().selected = true;
            observation.stage = Stage::MappedFileOpen;
            let selected = system_path.join(std::ffi::OsString::from_wide(leaf));
            let file = open_provider(&selected, false, cutoff, wall)?;
            observation.stage = Stage::MappedFilePath;
            let opened_nt = final_nt(&file, cutoff, wall)?;
            let equal = mapped_path::same_path(
                &mapped,
                &opened_nt,
                ordinal(&mapped, &opened_nt, cutoff, wall)?,
            )?;
            observation.mapped.as_mut().unwrap().opened_nt = Some(PathEvidence::new(&opened_nt));
            observation.mapped.as_mut().unwrap().opened_matches = Some(equal);
            if !equal {
                observation.stage = Stage::MappedFileMismatch;
                return Err(io::Error::other(
                    "provider opened NT path differs from mapped name",
                ));
            }
            let file_identity = file_identity(&file, cutoff, wall)?;
            Ok(Some(Self {
                file,
                directory,
                mapped,
                root_nt,
                system,
                root_identity,
                file_identity,
                base,
            }))
        }
        fn recheck(
            &self,
            child: &Child,
            cutoff: u64,
            wall: Instant,
        ) -> io::Result<(Vec<u16>, Value)> {
            base_mapping(child, self.base, cutoff, wall)?;
            let mapped = mapped_name(child, self.base, cutoff, wall)?;
            if !mapped_path::same_path(
                &self.mapped,
                &mapped,
                ordinal(&self.mapped, &mapped, cutoff, wall)?,
            )? {
                return Err(io::Error::other("provider mapped name changed"));
            }
            let root = final_nt(&self.directory, cutoff, wall)?;
            let opened = final_nt(&self.file, cutoff, wall)?;
            let root_dos = path(
                |buffer, size| unsafe {
                    GetFinalPathNameByHandleW(
                        self.directory.as_raw_handle(),
                        buffer,
                        size,
                        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                    )
                },
                cutoff,
                wall,
            )?;
            let root_dos = root_dos
                .strip_prefix(&[92, 92, 63, 92])
                .unwrap_or(&root_dos);
            if !mapped_path::ordinal_result(ordinal(root_dos, &self.system, cutoff, wall)?)? {
                return Err(io::Error::other("provider root DOS binding changed"));
            }
            if !mapped_path::same_path(
                &self.root_nt,
                &root,
                ordinal(&self.root_nt, &root, cutoff, wall)?,
            )? || !mapped_path::same_path(
                &self.mapped,
                &opened,
                ordinal(&self.mapped, &opened, cutoff, wall)?,
            )? || directory_identity(&self.directory, cutoff, wall)? != self.root_identity
                || file_identity(&self.file, cutoff, wall)? != self.file_identity
            {
                return Err(io::Error::other("provider held binding changed"));
            }
            profile::validate_runtime_header(&read(raw(child), self.base, 4096, cutoff, wall)?)?;
            let mut observation = Candidate::new(
                (0, child.pid, child.tid, self.base),
                HandleState::Null,
                true,
            );
            let sites = validate_sites(child, self.base, cutoff, wall, &mut observation)?;
            let proof = json!({"mapped_name":PathEvidence::new(&mapped),"root_identity":self.root_identity,"file_identity":self.file_identity,"sites":sites,"listed_preimages_rechecked":true});
            Ok((mapped, proof))
        }
    }

    struct Reader {
        owner: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
        cancel: Arc<AtomicBool>,
        failed: Arc<AtomicBool>,
        cancellation_requests: std::cell::Cell<u32>,
        cancellation_error: std::cell::Cell<Option<i32>>,
    }
    impl Reader {
        fn start(mut file: File, cancel: Arc<AtomicBool>) -> io::Result<Self> {
            let failed = Arc::new(AtomicBool::new(false));
            let observed_failure = failed.clone();
            let flag = cancel.clone();
            let owner = thread::Builder::new()
                .name("namespace-replay-output".into())
                .spawn(move || {
                    let outcome = (|| {
                        let mut bytes = Vec::new();
                        let mut block = [0u8; 4096];
                        loop {
                            if flag.load(Ordering::Acquire) {
                                return Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "reader cancelled",
                                ));
                            }
                            let count = file.read(&mut block)?;
                            if flag.load(Ordering::Acquire) {
                                return Err(io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "reader cancelled after read",
                                ));
                            }
                            if count == 0 {
                                return Ok(bytes);
                            }
                            if bytes
                                .len()
                                .checked_add(count)
                                .is_none_or(|size| size >= profile::OUTPUT_LIMIT)
                            {
                                return Err(io::Error::other("replay stdout overflow"));
                            }
                            bytes.extend_from_slice(&block[..count]);
                        }
                    })();
                    observed_failure.store(outcome.is_err(), Ordering::Release);
                    outcome
                })?;
            Ok(Self {
                owner: Some(owner),
                cancel,
                failed,
                cancellation_requests: std::cell::Cell::new(0),
                cancellation_error: std::cell::Cell::new(None),
            })
        }
        fn finished(&self) -> bool {
            self.owner
                .as_ref()
                .is_some_and(thread::JoinHandle::is_finished)
        }
        fn cancel(&self) {
            self.cancel.store(true, Ordering::Release);
            if !self.finished() {
                if let Some(owner) = &self.owner {
                    self.cancellation_requests
                        .set(self.cancellation_requests.get().saturating_add(1));
                    let ok = unsafe { CancelSynchronousIo(owner.as_raw_handle()) };
                    self.cancellation_error.set(if ok == 0 {
                        error().raw_os_error()
                    } else {
                        None
                    });
                }
            }
        }
        fn failed(&self) -> bool {
            self.failed.load(Ordering::Acquire)
        }
        fn join(&mut self) -> io::Result<Vec<u8>> {
            if !self.finished() {
                return Err(io::Error::other("reader not completed"));
            }
            self.owner
                .take()
                .expect("one join owner")
                .join()
                .map_err(|_| io::Error::other("reader panicked"))?
        }
    }

    pub(super) fn run(
        token: HANDLE,
        request: &protocol::Request,
        original: &protocol::Response,
        deadline: Instant,
        root: &Path,
    ) -> Value {
        let preparation = (|| -> io::Result<_> {
            let sampled = Instant::now();
            let now = counter()?;
            let remaining_ns = u128::from(
                request
                    .deadline_qpc
                    .checked_sub(now)
                    .ok_or_else(|| io::Error::other("original QPC cutoff expired"))?,
            )
            .checked_mul(1_000_000_000)
            .ok_or_else(|| io::Error::other("deadline overflow"))?
                / u128::from(request.qpc_frequency);
            let deadline = deadline.min(
                sampled
                    .checked_add(Duration::from_nanos(
                        u64::try_from(remaining_ns).map_err(io::Error::other)?,
                    ))
                    .ok_or_else(|| io::Error::other("deadline overflow"))?,
            );
            let diagnostic_deadline = sampled
                .checked_add(deadline.saturating_duration_since(sampled) / 2)
                .ok_or_else(|| io::Error::other("stop overflow"))?;
            let stop = profile::stop_qpc(now, request.deadline_qpc)?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "replay preparation cutoff",
                ));
            }
            let nonce = Sha256::digest(
                serde_json::to_vec(&(
                    request.nonce.as_str(),
                    "diagnostic-replay",
                    std::process::id(),
                ))
                .map_err(io::Error::other)?,
            );
            let replay_nonce = nonce[..16]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let envelope = replay_wire::ReplayEnvelope {
                format: "memcordon.namespace-debug-replay".into(),
                revision: 2,
                diagnostic_stop_qpc: stop,
                original_nonce: request.nonce.clone(),
                replay_nonce,
                request: request.clone(),
                request_sha256: replay_wire::replay_digest(request)?,
                source_commit: option_env!("GITHUB_SHA").map(str::to_owned),
                run: std::env::var("GITHUB_RUN_ID").ok(),
                attempt: std::env::var("GITHUB_RUN_ATTEMPT").ok(),
            };
            let encoded = replay_wire::encode_replay(&envelope)?;
            if replay_wire::decode_replay(&encoded)? != envelope {
                return Err(io::Error::other("replay argv roundtrip"));
            }
            Ok((stop, envelope, encoded, deadline, diagnostic_deadline, now))
        })();
        let (stop, envelope, encoded, deadline, diagnostic_deadline, started_qpc) =
            match preparation {
                Ok(value) => value,
                Err(error) => {
                    return json!({"reason":error.to_string(),"instrumented_replay_branch":"unobserved"});
                }
            };
        let complete = Arc::new((Mutex::new(false), Condvar::new()));
        let settled = Arc::new(AtomicBool::new(false));
        let cancel = Arc::new(AtomicBool::new(false));
        let signal = complete.clone();
        let done = settled.clone();
        let process_slot = Arc::new(Mutex::new(None::<Arc<OwnedHandle>>));
        let process = process_slot.clone();
        let flag = cancel.clone();
        let watchdog = thread::Builder::new()
            .name("namespace-replay-cutoff".into())
            .spawn(move || {
                let (lock, wake) = &*signal;
                let Ok(guard) = lock.lock() else {
                    std::process::abort()
                };
                let Ok((guard, _)) = wake.wait_timeout_while(
                    guard,
                    deadline.saturating_duration_since(Instant::now()),
                    |value| !*value,
                ) else {
                    std::process::abort()
                };
                if !*guard {
                    if let Ok(process) = process.try_lock() {
                        if let Some(process) = process.as_ref() {
                            unsafe {
                                TerminateProcess(process.as_raw_handle(), 125);
                            }
                        }
                    }
                    flag.store(true, Ordering::Release);
                    if !done.load(Ordering::Acquire) {
                        std::process::abort();
                    }
                }
            });
        let watchdog = match watchdog {
            Ok(owner) => owner,
            Err(error) => {
                return json!({"reason":"watchdog-resource-unavailable-before-creation","raw_error":error.raw_os_error()});
            }
        };
        let created = live(stop, diagnostic_deadline)
            .and_then(|()| launch_mode(token, deadline, Some(&encoded)));
        let (mut child, input, output) = match created {
            Ok(value) => value,
            Err(error) => {
                if let Ok(mut value) = complete.0.lock() {
                    *value = true;
                    complete.1.notify_all();
                }
                let joined = watchdog.join().is_ok();
                return json!({"reason":"debug-create-unavailable","raw_error":error.raw_os_error(),"detail":error.to_string(),"watchdog_joined":joined});
            }
        };
        if let Ok(mut process) = process_slot.lock() {
            *process = Some(child.process.clone());
        } else {
            std::process::abort();
        }
        drop(input);
        let mut reason = None::<String>;
        let mut reader = match Reader::start(output, cancel) {
            Ok(value) => Some(value),
            Err(error) => {
                reason = Some(error.to_string());
                None
            }
        };
        let mut terminating = reason.is_some();
        let mut terminated = false;
        let mut termination_result = Value::Null;
        let mut startup = false;
        let mut exited = false;
        let mut exit_code = None;
        let mut initial_live = true;
        let mut host = None;
        let mut host_proof = Value::Null;
        let mut mapped_guard: Option<MappedGuard> = None;
        let mut event_guard: Option<EventGuard> = None;
        let mut candidates = Candidates::default();
        let mut planner = None::<Planner>;
        let mut restored = false;
        let mut context_trace = Trace::default();
        let mut call_window =
            call_marker::Window::new(child.pid, child.tid, &envelope.replay_nonce)
                .expect("validated replay nonce");
        let mut pre_call = Value::Null;
        let mut post_call = Value::Null;
        let mut post_observed = false;
        let mut post_intact = false;
        let mut late_markers = Vec::new();
        let mut marker_receipts = Vec::new();
        let mut events = Vec::new();
        let mut received_events = 0usize;
        let mut hits = Vec::<Value>::new();
        let mut hit_receipts = Receipts::default();
        let mut helper_trace = helper_evidence::Trace::default();
        let mut directory_observation = directory_native::Observation::default();
        directory_observation.record["binding"] = json!({"pid":child.pid,"tid":child.tid,"original_nonce":request.nonce,"replay_nonce":envelope.replay_nonce,"events":"existing helper trace event ordinals and QPC timestamps"});
        let mut directory_selected = None;
        let mut directory_outer_verified = false;
        let mut directory_aggregate_verified = false;
        let mut entry_arguments = Value::Null;
        let mut limits = profile::Limit::default();
        let mut branch = "unobserved";
        if live(stop, diagnostic_deadline).is_err() {
            terminating = true;
            reason.get_or_insert_with(|| "stop before replay resume".into());
        }
        if !terminating && unsafe { ResumeThread(thread_raw(&child)) } != 1 {
            reason.get_or_insert_with(|| {
                "replay resume did not consume exactly one suspension".into()
            });
            terminating = true;
        }
        let final_wait = loop {
            let now = counter().unwrap_or(request.deadline_qpc);
            if now >= stop || Instant::now() >= diagnostic_deadline {
                terminating = true;
                reason.get_or_insert_with(|| "diagnostic stop reached".into());
            }
            if reader.as_ref().is_some_and(Reader::failed) {
                terminating = true;
                reason.get_or_insert_with(|| "reader failed".into());
            }
            if terminating {
                if let Some(reader) = &reader {
                    reader.cancel();
                }
                if !terminated {
                    let ok = unsafe { TerminateProcess(raw(&child), 125) };
                    let raw_error = if ok == 0 {
                        error().raw_os_error()
                    } else {
                        None
                    };
                    termination_result =
                        json!({"requested":true,"success":ok!=0,"raw_error":raw_error});
                    terminated = true;
                }
            }
            let wait = unsafe { WaitForSingleObject(raw(&child), 0) };
            if exited && wait == WAIT_OBJECT_0 && reader.as_ref().is_none_or(Reader::finished) {
                child.settled = true;
                break wait;
            }
            if now >= request.deadline_qpc || Instant::now() >= deadline {
                std::process::abort();
            }
            if exited {
                thread::yield_now();
                continue;
            }
            let cutoff = if terminating {
                request.deadline_qpc
            } else {
                stop
            };
            let millis = profile::wait_millis(now, cutoff, request.qpc_frequency)
                .unwrap_or(0)
                .min(
                    u32::try_from(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis(),
                    )
                    .unwrap_or(u32::MAX),
                );
            let mut event = DEBUG_EVENT::default();
            if unsafe { WaitForDebugEventEx(&mut event, millis) } == 0 {
                let error = error();
                if error.raw_os_error() != Some(ERROR_SEM_TIMEOUT as i32) {
                    reason.get_or_insert_with(|| format!("debug wait failed: {error}"));
                    terminating = true;
                }
                continue;
            }
            received_events += 1;
            let received_qpc = counter().ok();
            if received_qpc.is_none_or(|now| now >= stop) || Instant::now() >= diagnostic_deadline {
                terminating = true;
                reason.get_or_insert_with(|| "diagnostic stop reached".into());
            }
            let mut status = if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                DBG_EXCEPTION_NOT_HANDLED
            } else {
                DBG_CONTINUE
            };
            let mut exit_event = event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT
                && event.dwProcessId == child.pid;
            if exit_event {
                exit_code = Some(unsafe { event.u.ExitProcess.dwExitCode });
            }
            // Manual image-file ownership exists even if the event limit or
            // correlation check fails. OS-owned process/thread handles are not adopted.
            let image_file = match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => unsafe { event.u.CreateProcessInfo.hFile },
                LOAD_DLL_DEBUG_EVENT => unsafe { event.u.LoadDll.hFile },
                _ => std::ptr::null_mut(),
            };
            let mut image_file = if image_file.is_null() || image_file == INVALID_HANDLE_VALUE {
                None
            } else {
                Some(File::from(unsafe {
                    OwnedHandle::from_raw_handle(image_file)
                }))
            };
            let mut candidate_event = if event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT {
                let info = unsafe { event.u.LoadDll };
                let handle = if info.hFile.is_null() {
                    HandleState::Null
                } else if info.hFile == INVALID_HANDLE_VALUE {
                    HandleState::Invalid
                } else {
                    HandleState::Present
                };
                let mut value = Candidate::new(
                    (
                        received_events,
                        event.dwProcessId,
                        event.dwThreadId,
                        info.lpBaseOfDll as usize as u64,
                    ),
                    handle,
                    false,
                );
                value.stage = Stage::NotProcessed;
                Some(value)
            } else {
                None
            };
            let limit_result = limits.event(terminating);
            let teardown_exhausted = terminating && limit_result.is_err();
            let mut handled = (|| -> io::Result<()> {
                limit_result?;
                events.push(json!({"code":event.dwDebugEventCode,"pid":event.dwProcessId,"tid":event.dwThreadId}));
                if event.dwProcessId != child.pid {
                    return Err(io::Error::other("debug event from unowned process"));
                }
                if !terminating {
                    live(stop, diagnostic_deadline)?;
                }
                if terminating
                    && initial_live
                    && event.dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT
                    && !(event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT
                        && event.dwThreadId == child.tid)
                {
                    if let Some(plan) = &planner {
                        if let Ok(ctx) = context(
                            &child,
                            request.deadline_qpc,
                            deadline,
                            &mut context_trace,
                            Purpose::Restore,
                            ContextStage::GetContext,
                        ) {
                            if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                                let exception = unsafe { event.u.Exception };
                                if plan
                                    .clone()
                                    .on_hit(Stop {
                                        pid: event.dwProcessId,
                                        tid: event.dwThreadId,
                                        exception: exception.ExceptionRecord.ExceptionCode as u32,
                                        first_chance: exception.dwFirstChance != 0,
                                        exception_address: exception
                                            .ExceptionRecord
                                            .ExceptionAddress
                                            as usize
                                            as u64,
                                        rip: ctx.Rip,
                                        registers: registers(&ctx),
                                        rax: ctx.Rax,
                                        r14: ctx.R14,
                                        rbx: ctx.Rbx,
                                        rcx: ctx.Rcx,
                                        rdx: ctx.Rdx,
                                        r8: ctx.R8,
                                        r9: ctx.R9,
                                        rsp: ctx.Rsp,
                                    })
                                    .is_ok()
                                {
                                    status = DBG_CONTINUE;
                                }
                            }
                            if let Ok(regs) = plan.restore(registers(&ctx)) {
                                if let Ok(actual) = set(
                                    &child,
                                    regs,
                                    request.deadline_qpc,
                                    deadline,
                                    &mut context_trace,
                                    Purpose::Restore,
                                ) {
                                    restored = actual.dr == regs.dr
                                        && profile::dr7_equivalent(actual.dr7, regs.dr7)
                                        && (actual.dr6 & 7) == (regs.dr6 & 7);
                                    if restored {
                                        context_trace.verified();
                                    }
                                }
                            }
                        }
                    }
                }
                match event.dwDebugEventCode {
                    CREATE_PROCESS_DEBUG_EVENT => {
                        let info = unsafe { event.u.CreateProcessInfo };
                        drop(image_file.take());
                        if info.hProcess == raw(&child) || info.hThread == thread_raw(&child) {
                            return Err(io::Error::other(
                                "ambiguous creation/debug handle ownership",
                            ));
                        }
                    }
                    LOAD_DLL_DEBUG_EVENT => {
                        let info = unsafe { event.u.LoadDll };
                        let active = !terminating
                            && call_window.state != call_marker::State::Complete
                            && planner
                                .as_ref()
                                .is_none_or(|plan| plan.state() != State::Observed);
                        let observation = candidate_event
                            .as_mut()
                            .expect("LOAD_DLL candidate allocated");
                        observation.stage = if !active {
                            Stage::Inactive
                        } else if observation.handle != HandleState::Present {
                            Stage::MissingHandle
                        } else {
                            Stage::FileMetadata
                        };
                        let outcome = if let Some(mut file) = image_file.take().filter(|_| active) {
                            (|| -> io::Result<bool> {
                                observation.provider =
                                    Some(Provider::for_handle(observation.handle));
                                let mut proof = Value::Null;
                                let path = candidate(
                                    &mut file,
                                    info.lpBaseOfDll as usize as u64,
                                    &child,
                                    stop,
                                    diagnostic_deadline,
                                    &mut proof,
                                    observation,
                                )?;
                                if let Some(path) = path {
                                    if host.is_some() {
                                        return Err(io::Error::other(
                                            "competing verified event host",
                                        ));
                                    }
                                    event_guard = Some(EventGuard {
                                        file,
                                        base: info.lpBaseOfDll as usize as u64,
                                        identity: proof["identity_after"].clone(),
                                        path,
                                    });
                                    host_proof = proof;
                                    Ok(true)
                                } else {
                                    Ok(false)
                                }
                            })()
                        } else if active && observation.handle != HandleState::Present {
                            (|| -> io::Result<bool> {
                                let prepared = MappedGuard::prepare(
                                    &child,
                                    info.lpBaseOfDll as usize as u64,
                                    stop,
                                    diagnostic_deadline,
                                    observation,
                                    mapped_guard.as_ref(),
                                );
                                match prepared {
                                    Ok(Some(mut guard)) => {
                                        observation.stage = Stage::FileMetadata;
                                        let accepted = candidate(
                                            &mut guard.file,
                                            guard.base,
                                            &child,
                                            stop,
                                            diagnostic_deadline,
                                            &mut host_proof,
                                            observation,
                                        )?
                                        .is_some();
                                        let accepted = observation.selected_result(accepted)?;
                                        if accepted {
                                            if host.is_some() {
                                                return Err(io::Error::other(
                                                    "competing verified mapped host",
                                                ));
                                            }
                                            observation.stage = Stage::MappedRecheck;
                                            let (after, binding) =
                                                guard.recheck(&child, stop, diagnostic_deadline)?;
                                            let evidence = observation
                                                .mapped
                                                .as_mut()
                                                .expect("mapped provider evidence");
                                            evidence.after = Some(PathEvidence::new(&after));
                                            evidence.requery_matches = Some(true);
                                            host_proof["source_binding"] = json!({"kind":"mapped-name-system-file","provenance_strength":"mapped-name+held-disk+listed-mapped-extents","section_file_identity":"not-observed","original_runtime_iat":"not-observed","binding":binding});
                                            mapped_guard = Some(guard);
                                            observation.stage = Stage::Accepted;
                                        }
                                        Ok(accepted)
                                    }
                                    Ok(None) => Ok(false),
                                    Err(error) => {
                                        observation.failed(&error);
                                        if error.kind() == io::ErrorKind::TimedOut
                                            || observation
                                                .mapped
                                                .as_ref()
                                                .is_some_and(|evidence| evidence.selected)
                                        {
                                            Err(error)
                                        } else {
                                            Ok(false)
                                        }
                                    }
                                }
                            })()
                        } else if active {
                            Err(io::Error::other("present event file owner missing"))
                        } else {
                            Ok(false)
                        };
                        if let Err(error) = &outcome {
                            observation.failed(error);
                        }
                        if outcome.as_ref().is_ok_and(|accepted| *accepted)
                            && observation.provider == Some(Provider::EventFile)
                        {
                            host_proof["source_binding"] = json!({"kind":"debug-event-file","mapped_image_scope":"only header and listed instruction extents"});
                        }
                        let accepted = outcome?;
                        if accepted && host.replace(info.lpBaseOfDll as usize as u64).is_some() {
                            return Err(io::Error::other("competing verified host"));
                        }
                    }
                    UNLOAD_DLL_DEBUG_EVENT => {
                        if Some(unsafe { event.u.UnloadDll }.lpBaseOfDll as usize as u64) == host
                            && call_window.state != call_marker::State::Complete
                        {
                            return Err(io::Error::other("verified host unloaded"));
                        }
                    }
                    EXIT_THREAD_DEBUG_EVENT => {
                        if event.dwThreadId == child.tid {
                            initial_live = false;
                            if call_window.state != call_marker::State::Complete {
                                reason.get_or_insert_with(|| {
                                    "initial thread exited without observation".into()
                                });
                                terminating = true;
                            }
                        }
                    }
                    EXIT_PROCESS_DEBUG_EVENT => {
                        initial_live = false;
                        exit_event = true;
                    }
                    EXCEPTION_DEBUG_EVENT => {
                        let exception = unsafe { event.u.Exception };
                        let code = exception.ExceptionRecord.ExceptionCode as u32;
                        if terminating {
                            if code == call_marker::CODE && late_markers.len() < 2 {
                                late_markers.push(json!({"pid":event.dwProcessId,"tid":event.dwThreadId,"received_qpc":received_qpc,"count":exception.ExceptionRecord.NumberParameters,"flags":exception.ExceptionRecord.ExceptionFlags,"first_chance":exception.dwFirstChance,"parameters":exception.ExceptionRecord.ExceptionInformation.iter().take((exception.ExceptionRecord.NumberParameters as usize).min(call_marker::PARAMETERS)).copied().collect::<Vec<_>>(),"accepted":false,"reason":"diagnostic-stop-or-retirement"}));
                            }
                            return Ok(());
                        }
                        if code == call_marker::CODE {
                            let count = exception.ExceptionRecord.NumberParameters as usize;
                            let parameters = exception.ExceptionRecord.ExceptionInformation
                                [..count.min(call_marker::PARAMETERS)]
                                .iter()
                                .map(|word| *word as u64)
                                .collect::<Vec<_>>();
                            // Only PRE and POST can be valid. The first rejection
                            // retires immediately, so three slots retain it after both.
                            if marker_receipts.len() >= 3 {
                                return Err(io::Error::other("replay marker receipt bound"));
                            }
                            marker_receipts.push(json!({"kind":"raw-debug-exception","event_ordinal":received_events,"pid":event.dwProcessId,"tid":event.dwThreadId,"received_qpc":received_qpc,"code":code,"flags":exception.ExceptionRecord.ExceptionFlags,"first_chance":exception.dwFirstChance,"parameter_count":count,"words":parameters,"raw_words_omitted":count.saturating_sub(call_marker::PARAMETERS),"state_before":call_window.state,"expected_owner":{"pid":child.pid,"tid":child.tid},"expected_nonce":envelope.replay_nonce,"expected_version":call_marker::packet::VERSION,"admitted":false}));
                            let admission = if count != call_marker::PARAMETERS {
                                Err(call_marker::Rejection::ParameterCount)
                            } else {
                                call_window.accept(
                                    code,
                                    exception.ExceptionRecord.ExceptionFlags,
                                    exception.dwFirstChance != 0,
                                    event.dwProcessId,
                                    event.dwThreadId,
                                    &parameters,
                                )
                            };
                            let receipt =
                                marker_receipts.last_mut().expect("bounded marker receipt");
                            receipt["admitted"] = json!(admission.is_ok());
                            receipt["rejection"] = json!(admission.as_ref().err());
                            receipt["state_after"] = json!(call_window.state);
                            let phase = admission.map_err(|rejection| {
                                if rejection == call_marker::Rejection::ParameterCount {
                                    io::Error::other("replay marker parameter count")
                                } else {
                                    io::Error::new(io::ErrorKind::InvalidData, rejection)
                                }
                            })?;
                            status = DBG_CONTINUE;
                            match phase {
                                call_marker::Phase::Pre => {
                                    if !startup || !initial_live || planner.is_some() {
                                        return Err(io::Error::other(
                                            "replay PRE outside initial call window",
                                        ));
                                    }
                                    let base = host.ok_or_else(|| {
                                        io::Error::other("replay PRE without verified host")
                                    })?;
                                    let binding =
                                        match (mapped_guard.as_ref(), event_guard.as_mut()) {
                                            (Some(guard), None) => {
                                                guard.recheck(&child, stop, diagnostic_deadline)?.1
                                            }
                                            (None, Some(guard)) => {
                                                guard.recheck(&child, stop, diagnostic_deadline)?
                                            }
                                            _ => {
                                                return Err(io::Error::other(
                                                    "replay PRE provider custody",
                                                ));
                                            }
                                        };
                                    host_proof["precall_source_binding"] = binding;
                                    let saved = registers(&context(
                                        &child,
                                        stop,
                                        diagnostic_deadline,
                                        &mut context_trace,
                                        Purpose::PreCallArm,
                                        ContextStage::GetContext,
                                    )?);
                                    pre_call = json!({"pid":event.dwProcessId,"tid":event.dwThreadId,"received_qpc":received_qpc,"api":call_window.api,"before":register_record(saved),"expected_entry":profile::site_address(base, Site::Entry)?,"verified":false});
                                    let plan = Planner::arm(saved, base, child.pid, child.tid)?;
                                    pre_call["planned"] = register_record(plan.registers());
                                    let actual = set(
                                        &child,
                                        plan.registers(),
                                        stop,
                                        diagnostic_deadline,
                                        &mut context_trace,
                                        Purpose::PreCallArm,
                                    )?;
                                    pre_call["readback"] = register_record(actual);
                                    plan.verify_readback(actual)?;
                                    context_trace.verified();
                                    pre_call["verified"] = json!(true);
                                    planner = Some(plan);
                                }
                                call_marker::Phase::Post => {
                                    let actual = registers(&context(
                                        &child,
                                        stop,
                                        diagnostic_deadline,
                                        &mut context_trace,
                                        Purpose::PostCallCoverage,
                                        ContextStage::GetContext,
                                    )?);
                                    post_observed = true;
                                    post_call = json!({"pid":event.dwProcessId,"tid":event.dwThreadId,"received_qpc":received_qpc,"api":call_window.api,"result":call_window.result,"before_restore":register_record(actual),"restored":false});
                                    let plan = planner.as_ref().ok_or_else(|| {
                                        io::Error::other("replay POST without owned plan")
                                    })?;
                                    post_call["expected"] = register_record(plan.registers());
                                    post_call["planner_state"] =
                                        json!(format!("{:?}", plan.state()));
                                    post_intact = plan.verify_readback(actual).is_ok();
                                    post_call["intact"] = json!(post_intact);
                                    let restore = plan.restore(actual)?;
                                    let readback = set(
                                        &child,
                                        restore,
                                        stop,
                                        diagnostic_deadline,
                                        &mut context_trace,
                                        Purpose::Restore,
                                    )?;
                                    restored = readback.dr == restore.dr
                                        && profile::dr7_equivalent(readback.dr7, restore.dr7)
                                        && (readback.dr6 & 7) == (restore.dr6 & 7);
                                    post_call["restore_readback"] = register_record(readback);
                                    post_call["restored"] = json!(restored);
                                    if !restored {
                                        return Err(io::Error::other(
                                            "replay POST restoration readback",
                                        ));
                                    }
                                    context_trace.verified();
                                    planner = None;
                                }
                            }
                        } else if !terminating
                            && code == 0x8000_0003
                            && exception.dwFirstChance != 0
                            && !startup
                            && event.dwThreadId == child.tid
                        {
                            startup = true;
                            status = DBG_CONTINUE;
                        } else if !terminating
                            && initial_live
                            && event.dwThreadId == child.tid
                            && code == profile::SINGLE_STEP
                        {
                            let ctx = context(
                                &child,
                                stop,
                                diagnostic_deadline,
                                &mut context_trace,
                                Purpose::Hit,
                                ContextStage::GetContext,
                            )?;
                            let raw_stop = Stop {
                                pid: event.dwProcessId,
                                tid: event.dwThreadId,
                                exception: code,
                                first_chance: exception.dwFirstChance != 0,
                                exception_address: exception.ExceptionRecord.ExceptionAddress
                                    as usize
                                    as u64,
                                rip: ctx.Rip,
                                registers: registers(&ctx),
                                rax: ctx.Rax,
                                r14: ctx.R14,
                                rbx: ctx.Rbx,
                                rcx: ctx.Rcx,
                                rdx: ctx.Rdx,
                                r8: ctx.R8,
                                r9: ctx.R9,
                                rsp: ctx.Rsp,
                            };
                            let mut receipt = Receipt::capture(
                                Metadata {
                                    event_ordinal: received_events,
                                    flags: exception.ExceptionRecord.ExceptionFlags,
                                    first_chance: exception.dwFirstChance,
                                    received_qpc,
                                },
                                raw_stop,
                                planner.as_ref(),
                            );
                            let hit_result = (|| -> io::Result<()> {
                                let plan = planner.as_ref().ok_or_else(|| {
                                    receipt.rejection = Some(profile::HitRejection::MissingPlanner);
                                    profile::HitRejection::MissingPlanner.io_error()
                                })?;
                                let mut next = plan.clone();
                                receipt.stage = ReceiptStage::Validation;
                                let observed = next.on_hit(raw_stop).map_err(|rejection| {
                                    receipt.rejection = Some(rejection);
                                    rejection.io_error()
                                })?;
                                receipt.observation = Some(observed);
                                let provenance = next.snapshot(raw_stop.registers);
                                if provenance.helper_selected.is_some() {
                                    directory_selected = provenance.helper_selected;
                                }
                                receipt.initializer_planned = Some(hit_receipt::InitializerFacts {
                                    source: provenance.initializer_source,
                                    status: provenance.initializer_status,
                                    thread_token_cleared: provenance.thread_token_cleared,
                                });
                                receipt.admitted = true;
                                let helper_rva = match observed.site {
                                    Site::Helper { rva, .. } => Some(rva),
                                    _ => None,
                                };
                                let helper_index = if let Some(rva) = helper_rva {
                                    receipt.stage = ReceiptStage::HelperOperands;
                                    let operands = helper_trace
                                        .operands(rva, raw_stop, &mut |address, size| {
                                            read(
                                                raw(&child),
                                                address,
                                                size,
                                                stop,
                                                diagnostic_deadline,
                                            )
                                        })
                                        .map_err(helper_evidence::CaptureError::io_error)?;
                                    if let Some(operands) = &operands {
                                        directory_observation.observe(
                                            operands,
                                            received_events,
                                            directory_native::Target {
                                                process: raw(&child),
                                                thread: thread_raw(&child),
                                            },
                                            request,
                                            diagnostic_deadline,
                                            &|| live(stop, diagnostic_deadline),
                                        );
                                    }
                                    Some(
                                        helper_trace
                                            .record(
                                                rva,
                                                observed.slot,
                                                &receipt,
                                                next.registers(),
                                                operands,
                                            )
                                            .map_err(helper_evidence::CaptureError::io_error)?,
                                    )
                                } else {
                                    None
                                };
                                status = DBG_CONTINUE;
                                if observed.site == Site::Entry {
                                    receipt.stage = ReceiptStage::EntryArguments;
                                    let expected = replay_wire::event_name(request)?;
                                    if expected.len() > 4096 || ctx.R8 == 0 {
                                        return Err(io::Error::other("replay name bound"));
                                    }
                                    let bytes = read(
                                        raw(&child),
                                        ctx.R8,
                                        expected
                                            .len()
                                            .checked_mul(2)
                                            .ok_or_else(|| io::Error::other("name extent"))?,
                                        stop,
                                        diagnostic_deadline,
                                    )?;
                                    entry_arguments = json!({"access_low32":ctx.Rcx as u32,"inherit_low32":ctx.Rdx as u32,"name_utf16":bytes.chunks_exact(2).map(|pair|u16::from_le_bytes([pair[0],pair[1]])).collect::<Vec<_>>(),"correlated":false});
                                    profile::validate_entry(
                                        ctx.Rcx,
                                        ctx.Rdx,
                                        ctx.R8,
                                        0x0010_0000,
                                        &expected,
                                        &bytes,
                                    )?;
                                    entry_arguments["correlated"] = json!(true);
                                }
                                let status_source = match observed.site {
                                    Site::Entry | Site::InitEnter => None,
                                    Site::Initialization => Some("signed-low32-r14"),
                                    _ => Some("signed-low32-rax"),
                                };
                                let outer_hit_index = if helper_rva.is_none() {
                                    hits.push(json!({"site":format!("{:?}",observed.site),"profile_site":observed.site.name(),"slot":observed.slot,"rva":observed.site.rva(),"status":observed.status,"status_source":status_source,"status_hex":observed.status.map(|value|format!("0x{:08x}",value as u32)),"raw_rax":raw_stop.rax,"raw_r14":raw_stop.r14,"initializer_planned":receipt.initializer_planned,"helper_selected":provenance.helper_selected,"host_hash":profile::IMAGE_SHA256,"register_transition_verified":false}));
                                    Some(hits.len() - 1)
                                } else {
                                    None
                                };
                                if observed.site == Site::Native {
                                    branch = if observed.status.is_some_and(|status| status < 0) {
                                        "native-error"
                                    } else {
                                        "native-success"
                                    };
                                } else if observed.site == Site::Initialization
                                    && observed.status.is_some_and(|status| status < 0)
                                {
                                    branch = "initialization-error";
                                }
                                receipt.stage = ReceiptStage::SetRegisters;
                                receipt.transition_attempted = true;
                                let actual = set(
                                    &child,
                                    next.registers(),
                                    stop,
                                    diagnostic_deadline,
                                    &mut context_trace,
                                    Purpose::Hit,
                                )?;
                                receipt.stage = ReceiptStage::Readback;
                                receipt.readback = Some(actual);
                                if let Some(index) = helper_index {
                                    helper_trace.readback(index, next.registers(), actual, false);
                                }
                                next.verify_readback_typed(actual).map_err(|rejection| {
                                    receipt.rejection = Some(rejection);
                                    rejection.io_error()
                                })?;
                                context_trace.verified();
                                receipt.transition_verified = true;
                                if observed.site == Site::DirectoryInitializationReturn {
                                    directory_outer_verified = true;
                                }
                                if observed.site == Site::Initialization {
                                    directory_aggregate_verified = true;
                                }
                                if let Some(index) = helper_index {
                                    helper_trace.readback(index, next.registers(), actual, true);
                                }
                                restored = next.state() == State::Observed;
                                if let Some(hit) =
                                    outer_hit_index.and_then(|index| hits.get_mut(index))
                                {
                                    hit["register_transition_verified"] = json!(true);
                                }
                                planner = Some(next);
                                receipt.stage = ReceiptStage::Complete;
                                Ok(())
                            })();
                            receipt.state_after = planner.as_ref().map(Planner::state);
                            receipt.registers_after = planner.as_ref().map(Planner::registers);
                            receipt.failed = hit_result.is_err();
                            let helper_retained = receipt.transition_verified
                                && receipt.observation.is_some_and(|observed| {
                                    matches!(observed.site, Site::Helper { .. })
                                });
                            if helper_retained {
                                hit_receipts.record_helper(receipt, true);
                            } else {
                                hit_receipts.record(receipt);
                            }
                            hit_result?;
                        } else {
                            return Err(io::Error::other("unrelated debug exception"));
                        }
                    }
                    _ => {}
                }
                Ok(())
            })();
            if let Some(mut observation) = candidate_event {
                if observation.stage == Stage::NotProcessed {
                    if let Err(error) = &handled {
                        observation.failed(error);
                    }
                }
                handled = candidates.retain(observation, handled);
            }
            if let Err(error) = handled {
                reason.get_or_insert_with(|| error.to_string());
                terminating = true;
                if event.dwProcessId == child.pid
                    && initial_live
                    && event.dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT
                    && !(event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT
                        && event.dwThreadId == child.tid)
                {
                    if let Some(plan) = &planner {
                        if let Ok(ctx) = context(
                            &child,
                            request.deadline_qpc,
                            deadline,
                            &mut context_trace,
                            Purpose::Restore,
                            ContextStage::GetContext,
                        ) {
                            if let Ok(regs) = plan.restore(registers(&ctx)) {
                                if let Ok(actual) = set(
                                    &child,
                                    regs,
                                    request.deadline_qpc,
                                    deadline,
                                    &mut context_trace,
                                    Purpose::Restore,
                                ) {
                                    restored = actual.dr == regs.dr
                                        && profile::dr7_equivalent(actual.dr7, regs.dr7)
                                        && (actual.dr6 & 7) == (regs.dr6 & 7);
                                    if restored {
                                        context_trace.verified();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            drop(image_file);
            // No early return may bypass the single pending event's continuation.
            if unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) } == 0 {
                reason.get_or_insert_with(|| format!("debug continuation failed: {}", error()));
                terminating = true;
                if let Some(reader) = &reader {
                    reader.cancel();
                }
                if !terminated {
                    let ok = unsafe { TerminateProcess(raw(&child), 125) };
                    termination_result = json!({"requested":true,"success":ok!=0,"raw_error":if ok==0{error().raw_os_error()}else{None}});
                    terminated = true;
                }
                // A failed continuation leaves the SAME pending obligation.
                // Never fetch another event until this one is discharged.
                loop {
                    if live(request.deadline_qpc, deadline).is_err() {
                        std::process::abort();
                    }
                    if let Some(reader) = &reader {
                        reader.cancel();
                    }
                    if unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) }
                        != 0
                    {
                        if exit_event {
                            exited = true;
                        }
                        break;
                    }
                    thread::yield_now();
                }
            } else if exit_event {
                exited = true;
            }
            if teardown_exhausted
                && !(exited
                    && unsafe { WaitForSingleObject(raw(&child), 0) } == WAIT_OBJECT_0
                    && reader.as_ref().is_none_or(Reader::finished))
            {
                std::process::abort();
            }
        };
        let output = match reader.as_mut() {
            Some(reader) => reader.join(),
            None => Err(io::Error::other("reader absent")),
        };
        let reader_joined = reader.as_ref().is_some_and(|reader| reader.owner.is_none());
        // The selected disk file and directory remain held through observation,
        // then release while the original hard-cutoff watchdog still owns cleanup.
        drop(mapped_guard.take());
        drop(event_guard.take());
        let provider_guards_released = mapped_guard.is_none() && event_guard.is_none();
        settled.store(child.settled && reader_joined, Ordering::Release);
        let (lock, wake) = &*complete;
        if let Ok(mut value) = lock.lock() {
            *value = true;
            wake.notify_all();
        }
        let watchdog_joined = watchdog.join().is_ok();
        let replay_result = match output {
            Ok(bytes) => {
                if let Err(error) = limits.output(bytes.len()) {
                    reason.get_or_insert_with(|| error.to_string());
                }
                let _ = std::fs::write(root.join("debug-replay-stdout.bin"), &bytes);
                replay_wire::decode_replay_result(&bytes, &envelope)
                    .map(|value| {
                        if value.original_nonce != request.nonce
                            || value.replay_nonce != envelope.replay_nonce
                            || value.format != "memcordon.namespace-debug-replay-result"
                            || value.revision != 2
                            || !value.diagnostic_only
                            || value.acceptance_authority
                        {
                            return Err(io::Error::other("replay result binding"));
                        }
                        if let Some(marker) = call_window.result {
                            match &value.outcome {
                                replay_wire::ReplayOutcome::EventReturned {
                                    event_open,
                                    raw_error,
                                    ..
                                } if *event_open == marker.opened
                                    && raw_error.map_or(0, |error| error as u32)
                                        == marker.raw_error => {}
                                _ => {
                                    return Err(io::Error::other(
                                        "replay frame disagrees with saved POST result",
                                    ));
                                }
                            }
                        }
                        Ok(value)
                    })
                    .and_then(|value| value)
            }
            Err(error) => Err(error),
        };
        let frame_returned = replay_result
            .as_ref()
            .ok()
            .and_then(|value| match &value.outcome {
                replay_wire::ReplayOutcome::EventReturned { event_open, .. } => Some(*event_open),
                _ => None,
            });
        let divergence = frame_returned
            .or(call_window.result.map(|result| result.opened))
            .map(|opened| opened && !original.success);
        let call_attempt = match replay_result.as_ref().ok().map(|value| &value.outcome) {
            Some(replay_wire::ReplayOutcome::EventReturned { .. }) => "returned-frame",
            Some(replay_wire::ReplayOutcome::CallNotAttempted { .. }) => "not-attempted-frame",
            Some(replay_wire::ReplayOutcome::NamespaceFailed { .. }) => {
                "not-attempted-namespace-failure"
            }
            None if call_window.result.is_some() => "returned-post-marker",
            None => "unknown",
        };
        let directory_policy_required = directory_selected.is_some_and(|value| {
            matches!(
                value.source,
                profile::helper_profile::Source::Call {
                    call: 0x86b2d,
                    returned: 0x86b34
                }
            )
        });
        directory_observation.finish(
            directory_selected,
            directory_outer_verified,
            directory_aggregate_verified,
        );
        let cleanup = profile::CleanupFacts {
            exit_continued: exited,
            process_signaled: child.settled,
            reader_joined,
            watchdog_joined,
            pending_event: false,
            registers_live: initial_live,
            restore_verified: restored,
        }
        .complete();
        let mut record = json!({"format":"memcordon.namespace-owned-debug-replay","revision":1,"envelope":envelope,"pid":child.pid,"tid":child.tid,"host_hash":profile::IMAGE_SHA256,"host_base":host,"machine":profile::MACHINE,"size_of_image":profile::SIZE_OF_IMAGE,"events":events,"hits":hits,"instrumented_replay_branch":branch,"replay_divergence":divergence,"entry_arguments":entry_arguments,"reason":reason,"replay_result":replay_result.map_err(|error|error.to_string()),"restore_verified":restored,"registers_no_longer_live":!initial_live,"exit_continued":exited,"process_wait_observed":child.settled,"reader_joined":reader_joined,"watchdog_joined":watchdog_joined,"cleanup_complete":cleanup,"original_raw_error":original.raw_error});
        record["host_profile"] = host_proof;
        record["context_calls"] = json!(context_trace);
        record["call_attempt"] = json!(call_attempt);
        record["late_markers"] = json!(late_markers);
        record["marker_receipts"] = json!(marker_receipts);
        record["hit_receipts"] = json!(hit_receipts);
        record["helper_trace"] = json!(helper_trace);
        record["session_directory_policy"] = directory_observation.record;
        record["diagnostic_classification"] = json!(if directory_policy_required
            && directory_outer_verified
            && directory_aggregate_verified
            && directory_selected.is_some_and(|value| value.status < 0)
        {
            "replay-session-directory-bootstrap-denied"
        } else {
            "unobserved-or-other-route"
        });
        record["helper_trace_complete"] = json!(
            helper_trace.failure.is_none()
                && (helper_trace.records.is_empty()
                    || helper_trace
                        .records
                        .last()
                        .is_some_and(|record| record.0 == 0x866ba && record.6))
        );
        record["capture_evidence_complete"] = json!(
            record["reason"].is_null()
                && hit_receipts.rejected == 0
                && record["helper_trace_complete"] == true
                && (!directory_policy_required
                    || record["session_directory_policy"]["complete"] == true)
        );
        record["initializer_evidence_scope"] = json!(
            "helper inputs are paired pre-call ABI observations; returned volatile registers are not original arguments; static import identities do not prove runtime targets; opaque root handles do not identify kernel objects; selected EBX correlates outer EAX and final R14; original runtime path remains unobserved"
        );
        record["dr7_comparison"] = json!({"fixed_one_equivalence_mask":profile::DR7_FIXED_ONE_MASK,"scope":"control comparison and restoration readback ignore only the architectural fixed-one bit; raw register records are unchanged; owned_dr7_mask describes write ownership"});
        record["deadline_scope"] = json!(
            "QPC prechecks do not atomically bound subsequent API calls; late markers are not accepted as in-window evidence"
        );
        record["call_window"] = json!({"state":call_window.state,"api":call_window.api,"result":call_window.result,"pre_marker_received":call_window.state != call_marker::State::AwaitPre,"post_marker_received":call_window.state == call_marker::State::Complete,"post_registers_observed":post_observed,"pre":pre_call,"post":post_call,"coverage":call_marker::classify(post_observed,post_intact,!hits.is_empty()),"scope":"boundary snapshots do not prove uninterrupted state or every callee hop; original runtime IAT remains unobserved"});
        record["provider_guards_released"] = json!(provider_guards_released);
        record["candidate_admission"] = candidates.summary();
        record["candidate_admission"]["expected_file_length"] = json!(profile::FILE_LEN);
        record["candidate_admission"]["record"] = match persist(
            &root.join("debug-replay-candidates.json"),
            &json!(candidates),
        ) {
            Ok(()) => json!({"file":"debug-replay-candidates.json"}),
            Err(error) => json!({"unavailable":error.to_string(),"raw_error":error.raw_os_error()}),
        };
        record["exit_code"] = json!(exit_code);
        record["wait_result"] = json!(final_wait);
        record["original_cutoff_qpc"] = json!(request.deadline_qpc);
        record["diagnostic_stop_qpc"] = json!(stop);
        record["capture_started_qpc"] = json!(started_qpc);
        record["capture_finished_qpc"] = json!(counter().ok());
        record["qpc_frequency"] = json!(request.qpc_frequency);
        record["expected_profile_hash"] = json!(profile::IMAGE_SHA256);
        record["host_hash"] = json!(host.map(|_| profile::IMAGE_SHA256));
        record["machine"] = json!(host.map(|_| profile::MACHINE));
        record["size_of_image"] = json!(host.map(|_| profile::SIZE_OF_IMAGE));
        record["profile_status"] = json!(if host.is_some() {
            "verified-file-and-listed-mapped-extents"
        } else {
            "unavailable-profile"
        });
        record["termination"] = termination_result;
        record["reader_cancellation"]=reader.as_ref().map(|reader|json!({"requests":reader.cancellation_requests.get(),"last_raw_error":reader.cancellation_error.get()})).unwrap_or(Value::Null);
        record
    }
}
