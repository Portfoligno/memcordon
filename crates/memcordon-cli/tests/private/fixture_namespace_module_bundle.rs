//! Passive disk evidence only. A loaded path is not a snapshot of mapped pages.
use super::protocol::{ModuleLocation, ModuleProvenance, ModuleRole};
use std::{io, time::Instant};

pub const IMAGE_LIMIT: u64 = 64 * 1024 * 1024;
pub const TOTAL_LIMIT: u64 = 256 * 1024 * 1024;

pub fn source_reads_permitted(provenance: &ModuleProvenance, cutoff_qpc: u64) -> io::Result<bool> {
    provenance.validate()?;
    let ModuleProvenance::Present {
        started_qpc,
        finished_qpc,
        api_set_resolution,
        ..
    } = provenance
    else {
        return Ok(false);
    };
    let expired = *finished_qpc >= cutoff_qpc;
    if *started_qpc >= cutoff_qpc
        || (expired
            && !matches!(
                api_set_resolution.observation,
                super::protocol::ApiSetObservation::Unavailable { deadline: true, .. }
            ))
    {
        return Err(io::Error::other(
            "module provenance outside original cutoff",
        ));
    }
    Ok(!expired)
}

pub fn completed_bytes(
    before: &serde_json::Value,
    after: &serde_json::Value,
    size: u64,
    copied: u64,
    deadline: Instant,
    relative: &str,
    sha256: &str,
) -> io::Result<serde_json::Value> {
    check_budget(copied, 0, deadline)?;
    if before != after || copied != size {
        return Err(io::Error::other("module changed during copy"));
    }
    Ok(serde_json::json!({"relative_path":relative,"length":copied,"sha256":sha256}))
}

pub fn unavailable_entry(roles: &[ModuleRole], path: &[u16]) -> serde_json::Value {
    serde_json::json!({"roles":roles,"observed_utf16_path":path,"final_utf16_path":null,"file_identity_before":null,"file_identity_after":null,"bytes":null,"indexing":"unavailable","fixed_file_version":null,"symbol_identity":null,"errors":[]})
}

pub fn groups(provenance: &ModuleProvenance) -> io::Result<Vec<(Vec<u16>, Vec<ModuleRole>)>> {
    provenance.validate()?;
    let mut result: Vec<(Vec<u16>, Vec<ModuleRole>)> = Vec::new();
    if let ModuleProvenance::Present { modules, .. } = provenance {
        for ModuleLocation {
            path_utf16, role, ..
        } in modules
        {
            if let Some((_, roles)) = result.iter_mut().find(|(path, _)| path == path_utf16) {
                roles.push(*role);
            } else {
                result.push((path_utf16.clone(), vec![*role]));
            }
        }
    }
    if result.len() > 4 {
        return Err(io::Error::other("distinct module file bound"));
    }
    Ok(result)
}

pub fn check_budget(size: u64, total: u64, deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original capture cutoff expired",
        ));
    }
    if size > IMAGE_LIMIT
        || total
            .checked_add(size)
            .is_none_or(|value| value > TOTAL_LIMIT)
    {
        return Err(io::Error::other("module image byte bound"));
    }
    Ok(())
}

#[cfg(windows)]
pub use windows::capture;

#[cfg(windows)]
mod windows {
    use super::super::protocol::{Request, Response};
    use super::*;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        mem::{MaybeUninit, size_of},
        os::windows::{
            ffi::{OsStrExt, OsStringExt},
            fs::OpenOptionsExt,
            io::AsRawHandle,
        },
        path::{Path, PathBuf},
        ptr,
        sync::Mutex,
    };
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, HANDLE},
        Storage::FileSystem::*,
        System::{
            LibraryLoader::*, Performance::QueryPerformanceCounter,
            SystemInformation::GetSystemDirectoryW,
        },
    };

    static DBGHELP: Mutex<()> = Mutex::new(());
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
    fn error() -> io::Error {
        io::Error::last_os_error()
    }
    fn bounded(error: &io::Error) -> String {
        error.to_string().chars().take(512).collect()
    }
    fn qpc() -> Option<i64> {
        let mut value = 0;
        (unsafe { QueryPerformanceCounter(&mut value) } != 0).then_some(value)
    }
    fn remaining(deadline: Instant) -> io::Result<()> {
        check_budget(0, 0, deadline)
    }
    fn dynamic_path(
        deadline: Instant,
        mut query: impl FnMut(*mut u16, u32) -> u32,
    ) -> io::Result<Vec<u16>> {
        let mut size = 256;
        loop {
            remaining(deadline)?;
            let mut buffer = vec![0; size];
            let length = query(buffer.as_mut_ptr(), size as u32) as usize;
            remaining(deadline)?;
            if length == 0 {
                return Err(error());
            }
            if length < size {
                buffer.truncate(length);
                return Ok(buffer);
            }
            size = size
                .checked_mul(2)
                .filter(|value| *value <= 32768)
                .ok_or_else(|| io::Error::other("module path bound"))?;
        }
    }
    fn final_path(file: &File, deadline: Instant) -> io::Result<Vec<u16>> {
        dynamic_path(deadline, |buffer, size| unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle() as HANDLE,
                buffer,
                size,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        })
    }
    fn ordinal(left: &[u16], right: &[u16]) -> bool {
        use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
        unsafe {
            CompareStringOrdinal(
                left.as_ptr(),
                left.len() as i32,
                right.as_ptr(),
                right.len() as i32,
                1,
            ) == CSTR_EQUAL
        }
    }
    fn components(path: &[u16]) -> io::Result<Vec<Vec<u16>>> {
        let path = path.strip_prefix(&[92, 92, 63, 92]).unwrap_or(path);
        if path.starts_with(&[92, 92]) || path.len() < 3 || path[1] != 58 || path[2] != 92 {
            return Err(io::Error::other("non-local module path"));
        }
        let parts: Vec<_> = path
            .split(|value| *value == 92)
            .map(<[u16]>::to_vec)
            .collect();
        if parts
            .iter()
            .any(|part| part.is_empty() || part == &[46] || part == &[46, 46])
        {
            return Err(io::Error::other("noncanonical module path"));
        }
        Ok(parts)
    }
    fn allowed(path: &[u16], system: &[u16], worker: &[u16]) -> io::Result<()> {
        let parts = components(path)?;
        let worker = components(worker)?;
        let system = components(system)?;
        let same = |a: &[Vec<u16>], b: &[Vec<u16>]| {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| ordinal(a, b))
        };
        if same(&parts, &worker)
            || (parts.len() == system.len() + 1 && same(&parts[..system.len()], &system))
        {
            Ok(())
        } else {
            Err(io::Error::other(
                "module outside selected worker/native System32",
            ))
        }
    }
    unsafe fn information<T>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS) -> io::Result<T> {
        let mut value = MaybeUninit::<T>::uninit();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                class,
                value.as_mut_ptr().cast(),
                size_of::<T>() as u32,
            )
        } == 0
        {
            return Err(error());
        }
        Ok(unsafe { value.assume_init() })
    }
    fn identity(file: &File, deadline: Instant) -> io::Result<Value> {
        remaining(deadline)?;
        let id: FILE_ID_INFO = unsafe { information(file, FileIdInfo)? };
        remaining(deadline)?;
        let basic: FILE_BASIC_INFO = unsafe { information(file, FileBasicInfo)? };
        remaining(deadline)?;
        let standard: FILE_STANDARD_INFO = unsafe { information(file, FileStandardInfo)? };
        remaining(deadline)?;
        if standard.Directory
            || standard.DeletePending
            || standard.EndOfFile < 0
            || basic.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        {
            return Err(io::Error::other("not an ordinary module image"));
        }
        Ok(
            json!({"volume":id.VolumeSerialNumber,"file_id":id.FileId.Identifier,"size":standard.EndOfFile,"creation":basic.CreationTime,"write":basic.LastWriteTime,"change":basic.ChangeTime,"attributes":basic.FileAttributes}),
        )
    }
    fn version(path: &Path, deadline: Instant) -> io::Result<Value> {
        remaining(deadline)?;
        let path = wide(path);
        let mut ignored = 0;
        let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), &mut ignored) };
        if size == 0 {
            return Err(error());
        }
        if size > 1024 * 1024 {
            return Err(io::Error::other("version metadata bound"));
        }
        remaining(deadline)?;
        let mut bytes = vec![0u8; size as usize];
        if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, bytes.as_mut_ptr().cast()) } == 0 {
            return Err(error());
        }
        remaining(deadline)?;
        let mut pointer = ptr::null_mut();
        let mut length = 0;
        if unsafe {
            VerQueryValueW(
                bytes.as_ptr().cast(),
                [92u16, 0].as_ptr(),
                &mut pointer,
                &mut length,
            )
        } == 0
        {
            return Err(error());
        }
        remaining(deadline)?;
        let start = bytes.as_ptr() as usize;
        let address = pointer as usize;
        if length < size_of::<VS_FIXEDFILEINFO>() as u32
            || address < start
            || address
                .checked_add(size_of::<VS_FIXEDFILEINFO>())
                .is_none_or(|end| end > start + bytes.len())
        {
            return Err(io::Error::other("version value extent"));
        }
        let value = unsafe { ptr::read_unaligned(pointer.cast::<VS_FIXEDFILEINFO>()) };
        if value.dwSignature != 0xfeef04bd {
            return Err(io::Error::other("version signature"));
        }
        Ok(
            json!({"file_ms":value.dwFileVersionMS,"file_ls":value.dwFileVersionLS,"product_ms":value.dwProductVersionMS,"product_ls":value.dwProductVersionLS}),
        )
    }
    fn symbols(path: &Path, system: &[u16], deadline: Instant) -> io::Result<Value> {
        use windows_sys::Win32::System::Diagnostics::Debug::SYMSRV_INDEX_INFOW;
        let _lock = DBGHELP
            .try_lock()
            .map_err(|_| io::Error::other("DbgHelp indexing active or lock poisoned"))?;
        remaining(deadline)?;
        let library_path = PathBuf::from(std::ffi::OsString::from_wide(system)).join("dbghelp.dll");
        let library = unsafe {
            LoadLibraryExW(
                wide(&library_path).as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if library.is_null() {
            return Err(error());
        }
        struct Library(windows_sys::Win32::Foundation::HMODULE);
        impl Drop for Library {
            fn drop(&mut self) {
                unsafe {
                    windows_sys::Win32::Foundation::FreeLibrary(self.0);
                }
            }
        }
        let _library = Library(library);
        let actual_tool = dynamic_path(deadline, |buffer, size| unsafe {
            GetModuleFileNameW(library, buffer, size)
        })?;
        let tool_parts = components(&actual_tool)?;
        let system_parts = components(system)?;
        if tool_parts.len() != system_parts.len() + 1
            || !tool_parts
                .iter()
                .zip(&system_parts)
                .all(|(a, b)| ordinal(a, b))
        {
            return Err(io::Error::other("loaded DbgHelp outside native System32"));
        }
        let actual_tool_path = PathBuf::from(std::ffi::OsString::from_wide(&actual_tool));
        remaining(deadline)?;
        let address =
            unsafe { GetProcAddress(library, c"SymSrvGetFileIndexInfoW".as_ptr().cast()) }
                .ok_or_else(error)?;
        remaining(deadline)?;
        let call: unsafe extern "system" fn(*const u16, *mut SYMSRV_INDEX_INFOW, u32) -> i32 =
            unsafe { std::mem::transmute(address) };
        let mut index = SYMSRV_INDEX_INFOW {
            sizeofstruct: size_of::<SYMSRV_INDEX_INFOW>() as u32,
            ..Default::default()
        };
        if unsafe { call(wide(path).as_ptr(), &mut index, 0) } == 0 {
            return Err(error());
        }
        remaining(deadline)?;
        let text = |value: &[u16]| {
            value[..value.iter().position(|v| *v == 0).unwrap_or(value.len())].to_vec()
        };
        Ok(
            json!({"timestamp":index.timestamp,"image_size":index.size,"pdb_utf16":text(&index.pdbfile),"dbg_utf16":text(&index.dbgfile),"guid":{"data1":index.guid.data1,"data2":index.guid.data2,"data3":index.guid.data3,"data4":index.guid.data4},"signature":index.sig,"age":index.age,"tool":{"path_utf16":actual_tool,"fixed_file_version":version(&actual_tool_path,deadline).map_err(|e|bounded(&e))}}),
        )
    }
    fn system_path(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().collect()
    }
    struct CopyContext<'a> {
        output: &'a Path,
        system: &'a [u16],
        worker: &'a [u16],
        deadline: Instant,
    }
    fn copy_image(
        path: &[u16],
        index: usize,
        context: &CopyContext<'_>,
        total: &mut u64,
        entry: &mut Value,
    ) -> io::Result<()> {
        let CopyContext {
            output,
            system,
            worker,
            deadline,
        } = *context;
        remaining(deadline)?;
        allowed(path, system, worker)?;
        let input_path = PathBuf::from(std::ffi::OsString::from_wide(path));
        let mut input = OpenOptions::new()
            .read(true)
            .access_mode(GENERIC_READ)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(input_path)?;
        remaining(deadline)?;
        let final_name = final_path(&input, deadline)?;
        allowed(&final_name, system, worker)?;
        entry["final_utf16_path"] = json!(final_name);
        let before = identity(&input, deadline)?;
        entry["file_identity_before"] = before.clone();
        let size = before["size"]
            .as_u64()
            .ok_or_else(|| io::Error::other("image size"))?;
        check_budget(size, *total, deadline)?;
        let stem = format!("module-{index}.bin");
        let partial = output.join(format!("{stem}.partial"));
        let completed = output.join(&stem);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)?;
        let mut digest = Sha256::new();
        let mut copied = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            remaining(deadline)?;
            let length = input.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            copied = copied
                .checked_add(length as u64)
                .ok_or_else(|| io::Error::other("copy overflow"))?;
            check_budget(copied, *total, deadline)?;
            if copied > size {
                return Err(io::Error::other("module grew during copy"));
            }
            file.write_all(&buffer[..length])?;
            digest.update(&buffer[..length]);
        }
        let after = identity(&input, deadline)?;
        entry["file_identity_after"] = after.clone();
        let bytes = completed_bytes(
            &before,
            &after,
            size,
            copied,
            deadline,
            &stem,
            &digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )?;
        file.sync_all()?;
        drop(file);
        remaining(deadline)?;
        std::fs::rename(&partial, &completed)?;
        *total += copied;
        entry["bytes"] = bytes;
        entry["fixed_file_version"] = json!(version(&completed, deadline).map_err(|e| bounded(&e)));
        entry["symbol_identity"] =
            json!(symbols(&completed, system, deadline).map_err(|e| bounded(&e)));
        entry["indexing"] = json!("attempted-on-owned-copy-only");
        Ok(())
    }
    pub fn capture(
        provenance: &ModuleProvenance,
        request: &Request,
        response: &Response,
        worker: &Path,
        deadline: Instant,
    ) -> io::Result<PathBuf> {
        provenance.validate()?;
        let (grouped, bundle_errors) = match groups(provenance) {
            Ok(grouped) => (grouped, Vec::<String>::new()),
            Err(error) => (Vec::new(), vec![bounded(&error)]),
        };
        let may_read_sources = source_reads_permitted(provenance, request.deadline_qpc)?;
        if request.nonce.is_empty()
            || request.nonce.len() > 128
            || !request
                .nonce
                .bytes()
                .all(|v| v.is_ascii_hexdigit() || v == b'-')
        {
            return Err(io::Error::other("noncanonical request nonce"));
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| io::Error::other("repository root"))?
            .join("target/ci/reports/namespace-win32");
        std::fs::create_dir_all(&root)?;
        let output = root.join(&request.nonce);
        std::fs::create_dir(&output)?;
        let started = qpc();
        let mut total = 0;
        let mut entries = Vec::new();
        let system = if may_read_sources && Instant::now() < deadline {
            dynamic_path(deadline, |buffer, size| unsafe {
                GetSystemDirectoryW(buffer, size)
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original capture cutoff expired",
            ))
        };
        let worker = system_path(worker);
        for (index, (path, roles)) in grouped.into_iter().enumerate() {
            let mut entry = unavailable_entry(&roles, &path);
            let result = match &system {
                Ok(system) => copy_image(
                    &path,
                    index,
                    &CopyContext {
                        output: &output,
                        system,
                        worker: &worker,
                        deadline,
                    },
                    &mut total,
                    &mut entry,
                ),
                Err(e) => Err(io::Error::new(e.kind(), bounded(e))),
            };
            if let Err(error) = result {
                entry["errors"] = json!([bounded(&error)]);
            }
            entries.push(entry);
        }
        let native = response.native_open.as_ref();
        let manifest = json!({
            "format":"memcordon.fixture-win32-module-evidence", "revision":1,
            "source_commit":option_env!("GITHUB_SHA"), "request_nonce":request.nonce,
            "cell":request.cell,
            "original_call":{"name_utf16":native.map(|v|&v.name_utf16),"desired_access":native.map(|v|v.desired_access),"inherit":native.map(|v|v.inherit),"raw_error":response.raw_error},
            "module_provenance":provenance, "modules":entries, "bundle_errors":bundle_errors,
            "original_static_dependency":{"contract":"api-ms-win-core-synch-l1-1-0.dll","symbol":"OpenEventW"},
            "runtime_original_iat_target":"not-observed", "original_cutoff_qpc":request.deadline_qpc,
            "capture_started_qpc":started, "capture_finished_qpc":qpc(),
            "diagnostic_only":true, "acceptance_authority":false,
            "binding":"loaded-module-path-to-held-disk-file", "mapped_instruction_pages":"not-observed",
            "native_boundary":{"state":"not-observed"}
        });
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(output.join("manifest.json"))?;
        serde_json::to_writer_pretty(&mut file, &manifest)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(output)
    }
}
