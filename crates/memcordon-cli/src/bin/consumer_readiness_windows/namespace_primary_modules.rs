//! Passive public loader metadata after the original error has been saved.
use super::{clock, protocol, remaining};
use protocol::{
    ApiSetObservation, ApiSetResolution, ApiSetStage, ModuleLocation, ModuleProvenance, ModuleRole,
    Request,
};
use std::io;
use windows_sys::Win32::{
    Foundation::{FreeLibrary, HMODULE},
    System::{
        LibraryLoader::{
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GetModuleFileNameW, GetModuleHandleExW,
            GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
        },
        Performance::QueryPerformanceCounter,
        Threading::OpenEventW,
    },
};

struct Module(HMODULE);
impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: each guard owns one reference from GetModuleHandleExW, never PIN/unchanged.
        unsafe {
            FreeLibrary(self.0);
        }
    }
}
fn named(name: &[u16], request: &Request) -> io::Result<Module> {
    remaining(request)?;
    let mut module = std::ptr::null_mut();
    // SAFETY: fixed terminated DLL name; no LoadLibrary or executable call.
    let result = unsafe { GetModuleHandleExW(0, name.as_ptr(), &mut module) };
    let error = io::Error::last_os_error();
    let owned = (result != 0).then(|| Module(module));
    remaining(request)?;
    owned.ok_or(error)
}
fn location(address: usize, role: ModuleRole, request: &Request) -> io::Result<ModuleLocation> {
    remaining(request)?;
    let mut module = std::ptr::null_mut();
    // SAFETY: FROM_ADDRESS interprets this parameter only as the observed code address.
    let result = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            address as *const u16,
            &mut module,
        )
    };
    let error = io::Error::last_os_error();
    let owned = (result != 0).then(|| Module(module));
    remaining(request)?;
    let owned = owned.ok_or(error)?;
    module_location(&owned, address, role, request)
}
fn module_location(
    module: &Module,
    address: usize,
    role: ModuleRole,
    request: &Request,
) -> io::Result<ModuleLocation> {
    let base = module.0 as usize as u64;
    let rva = (address as u64)
        .checked_sub(base)
        .and_then(|rva| u32::try_from(rva).ok())
        .ok_or_else(|| io::Error::other("module address/RVA range"))?;
    let mut capacity = 256_usize;
    let path = loop {
        remaining(request)?;
        let mut path = vec![0_u16; capacity];
        // SAFETY: owned live loader reference and exact writable UTF16 capacity.
        let length = unsafe {
            GetModuleFileNameW(
                module.0,
                path.as_mut_ptr(),
                u32::try_from(path.len()).map_err(io::Error::other)?,
            )
        };
        let error = io::Error::last_os_error();
        remaining(request)?;
        let length = usize::try_from(length).map_err(io::Error::other)?;
        if length == 0 {
            return Err(error);
        }
        if length < capacity {
            path.truncate(length);
            break path;
        }
        if capacity == 32768 {
            return Err(io::Error::other("module path bound"));
        }
        capacity = capacity
            .checked_mul(2)
            .filter(|capacity| *capacity <= 32768)
            .ok_or_else(|| io::Error::other("module path growth"))?;
    };
    Ok(ModuleLocation {
        role,
        base,
        address: address as u64,
        rva,
        path_utf16: path,
    })
}
fn export(module: &Module, name: &[u8], request: &Request) -> io::Result<usize> {
    remaining(request)?;
    // SAFETY: fixed NUL-terminated public export name, owned live module; pointer is never invoked.
    let pointer = unsafe { GetProcAddress(module.0, name.as_ptr()) };
    let error = io::Error::last_os_error();
    remaining(request)?;
    pointer.map(|pointer| pointer as usize).ok_or(error)
}
fn api_set(request: &Request, original: usize) -> (ApiSetResolution, Option<ModuleLocation>) {
    let mut stage = ApiSetStage::LoadContract;
    let result = (|| -> io::Result<ModuleLocation> {
        remaining(request)?;
        let contract: Vec<u16> = protocol::API_SET_CONTRACT
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // SAFETY: exact public API-set contract found in retained PE imports;
        // system-only search. This postfailure metadata resolution MAY load code.
        // No resolved event function is invoked, and the original result is saved.
        let loaded = unsafe {
            LoadLibraryExW(
                contract.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        let error = io::Error::last_os_error();
        let owned = (!loaded.is_null()).then(|| Module(loaded));
        remaining(request)?;
        let owned = owned.ok_or(error)?;
        stage = ApiSetStage::ResolveExport;
        let address = export(&owned, b"OpenEventW\0", request)?;
        stage = ApiSetStage::ObserveOwner;
        location(address, ModuleRole::ApiSetOpenEvent, request)
    })();
    let (observation, module) = match result {
        Ok(module) => (
            ApiSetObservation::Resolved {
                same_as_original_thunk: module.address == original as u64,
            },
            Some(module),
        ),
        Err(error) => (
            ApiSetObservation::Unavailable {
                stage,
                raw_error: error.raw_os_error(),
                deadline: error.kind() == io::ErrorKind::TimedOut,
            },
            None,
        ),
    };
    (
        ApiSetResolution {
            contract: protocol::API_SET_CONTRACT.into(),
            symbol: protocol::API_SET_SYMBOL.into(),
            resolution_method: protocol::API_SET_METHOD.into(),
            observation,
        },
        module,
    )
}
pub(super) fn observe(request: &Request) -> ModuleProvenance {
    let result = (|| -> io::Result<ModuleProvenance> {
        let started_qpc = clock(request)?.0;
        let import = OpenEventW as *const () as usize;
        let imported = location(import, ModuleRole::ImportAddress, request)?;
        let kernel32 = named(
            &"kernel32.dll"
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>(),
            request,
        )?;
        let table = module_location(
            &kernel32,
            kernel32.0 as usize,
            ModuleRole::Kernel32ExportTable,
            request,
        )?;
        let resolved_address = export(&kernel32, b"OpenEventW\0", request)?;
        let resolved = location(resolved_address, ModuleRole::ResolvedExport, request)?;
        let ntdll = named(
            &"ntdll.dll"
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>(),
            request,
        )?;
        let native_address = export(&ntdll, b"NtOpenEvent\0", request)?;
        let native = location(native_address, ModuleRole::NtOpenEvent, request)?;
        let (mut api_set_resolution, mut host) = api_set(request, import);
        let finished_qpc = match clock(request) {
            Ok((now, _)) => now,
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                // Preserve already collected facts if optional resolution used
                // the remaining budget. Only the counter is sampled here; no
                // further module lookup or image read is authorized.
                let (stage, raw_error) = match api_set_resolution.observation {
                    ApiSetObservation::Unavailable {
                        stage, raw_error, ..
                    } => (stage, raw_error),
                    ApiSetObservation::Resolved { .. } => (ApiSetStage::ObserveOwner, None),
                };
                api_set_resolution.observation = ApiSetObservation::Unavailable {
                    stage,
                    raw_error,
                    deadline: true,
                };
                host = None;
                let mut now = 0;
                // SAFETY: one writable native counter, never a renewed cutoff.
                if unsafe { QueryPerformanceCounter(&mut now) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                u64::try_from(now).map_err(io::Error::other)?
            }
            Err(error) => return Err(error),
        };
        let mut modules = vec![imported, table, resolved, native];
        if let Some(host) = host {
            modules.push(host);
        }
        let value = ModuleProvenance::Present {
            started_qpc,
            finished_qpc,
            diagnostic_only: true,
            acceptance_authority: false,
            import_matches_resolved: import == resolved_address,
            api_set_resolution,
            modules,
        };
        value.validate()?;
        Ok(value)
    })();
    result.unwrap_or_else(|error| ModuleProvenance::Unavailable {
        reason: memcordon_core::BoundedText::new("public-loader-metadata-unavailable")
            .expect("bounded literal"),
        raw_error: error.raw_os_error(),
        deadline: error.kind() == io::ErrorKind::TimedOut,
    })
}
