//! Native main-image join for authenticated, controller-held private inputs.
//!
//! The caller must authenticate the original descriptor and execute within the
//! trusted controller's continuously retained prelaunch file/ancestry guards.
//! This does not exclude arbitrary hostile host-ancestor metadata changes or
//! attest image pages against copy-on-write modification.
use crate::{
    test_support::{WindowsHeldFileMetadata, windows_held_file_metadata},
    windows_private_fixture_binding::{PrivateFixtureAncestor, PrivateFixtureBinding},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Component, Path, PathBuf},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT},
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, GetFinalPathNameByHandleW, VOLUME_NAME_NT,
    },
    System::{
        LibraryLoader::GetModuleHandleW,
        Memory::{MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, VirtualQuery},
        ProcessStatus::K32GetMappedFileNameW,
        Threading::GetCurrentProcess,
    },
};

/// No file, directory, mapping or sharing restriction survives in this value.
/// Only the native verifier below can construct it.
pub struct VerifiedPrivateFixture {
    fixture: PathBuf,
    local_directory: PathBuf,
    observation: serde_json::Value,
    output: VerifiedOutput,
}
impl VerifiedPrivateFixture {
    pub fn fixture(&self) -> &Path {
        &self.fixture
    }
    pub fn local_directory(&self) -> &Path {
        &self.local_directory
    }
    pub fn observation(&self) -> &serde_json::Value {
        &self.observation
    }
    pub fn output(&self) -> &VerifiedOutput {
        &self.output
    }
}

/// Permission to publish only diagnostics at the checked output location,
/// within the authenticated descriptor and trusted controller custody scope.
pub struct VerifiedOutput {
    path: PathBuf,
    ancestors: usize,
}
impl VerifiedOutput {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug)]
struct Refusal {
    phase: &'static str,
    primary: io::Error,
}
#[derive(Debug)]
struct DeadlineFailure {
    primary: io::Error,
    secondary: io::Error,
}
impl std::fmt::Display for DeadlineFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            output,
            "{}; original deadline settlement: {}",
            self.primary, self.secondary
        )
    }
}
impl std::error::Error for DeadlineFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
fn native_code(error: &io::Error) -> Option<i32> {
    error.raw_os_error().or_else(|| {
        let source = error.get_ref()?;
        if let Some(failure) = source.downcast_ref::<DeadlineFailure>() {
            native_code(&failure.primary)
        } else if let Some(refusal) = source.downcast_ref::<Refusal>() {
            native_code(&refusal.primary)
        } else {
            None
        }
    })
}
fn with_deadline<T>(cutoff: Instant, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    live(cutoff)?;
    let timer = crate::WindowsSynchronousIoDeadline::start(cutoff).map_err(io::Error::other)?;
    let primary = operation();
    // Join the cancellation watcher before returning any capability, so it
    // cannot cancel later mutation probes or original Winsock activity.
    let secondary = timer.finish().map_err(io::Error::other);
    match (primary, secondary) {
        (Err(primary), Err(secondary)) => Err(io::Error::new(
            primary.kind(),
            DeadlineFailure { primary, secondary },
        )),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(secondary)) => Err(secondary),
        (Ok(value), Ok(())) => {
            live(cutoff)?;
            Ok(value)
        }
    }
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            output,
            "private fixture binding phase={}; native-code={:?}; {}",
            self.phase,
            native_code(&self.primary),
            self.primary
        )
    }
}
impl std::error::Error for Refusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
pub fn failure_record(error: &io::Error) -> serde_json::Value {
    if let Some(refusal) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<Refusal>())
    {
        serde_json::json!({"phase":refusal.phase,"native_code":native_code(&refusal.primary),
            "error":refusal.primary.to_string(),"mutation_authority":false})
    } else {
        serde_json::json!({"phase":"unavailable","native_code":error.raw_os_error(),
            "error":error.to_string(),"mutation_authority":false})
    }
}
fn live(cutoff: Instant) -> io::Result<()> {
    if Instant::now() >= cutoff {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "private fixture original cutoff expired",
        ))
    } else {
        Ok(())
    }
}
fn noninheritable(file: &File, cutoff: Instant) -> io::Result<()> {
    live(cutoff)?;
    let mut flags = 0;
    // SAFETY: File owns the queried handle and flags is an initialized output.
    if unsafe { GetHandleInformation(file.as_raw_handle().cast(), &mut flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & HANDLE_FLAG_INHERIT != 0 {
        return Err(io::Error::other(
            "private fixture query handle is inheritable",
        ));
    }
    live(cutoff)
}
fn open(path: &Path, directory: bool, cutoff: Instant) -> io::Result<File> {
    live(cutoff)?;
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | if directory { 0 } else { FILE_READ_DATA })
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    noninheritable(&file, cutoff)?;
    let metadata = windows_held_file_metadata(&file)?;
    live(cutoff)?;
    if metadata.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (metadata.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(io::Error::other(
            "private fixture query type or reparse state differs",
        ));
    }
    Ok(file)
}
fn directory_matches(
    file: &File,
    expected: &PrivateFixtureAncestor,
    cutoff: Instant,
) -> io::Result<()> {
    live(cutoff)?;
    let metadata = windows_held_file_metadata(file)?;
    if metadata.volume_serial != expected.volume_serial
        || metadata.file_index != expected.file_index
        || metadata.attributes != expected.attributes
    {
        return Err(io::Error::other(
            "private fixture directory identity or attributes differ",
        ));
    }
    live(cutoff)
}
fn file_matches(
    metadata: &WindowsHeldFileMetadata,
    expected: &PrivateFixtureBinding,
) -> io::Result<()> {
    if metadata.volume_serial != expected.volume_serial
        || metadata.file_index != expected.file_index
        || metadata.attributes != expected.attributes
        || metadata.links != 1
        || metadata.links != expected.links
        || metadata.length != expected.bytes
    {
        Err(io::Error::other(
            "private fixture identity, attributes, links or length differ",
        ))
    } else {
        Ok(())
    }
}

/// Query only the native name of this borrowed live handle. This is data, not
/// a loaded-image or custody capability by itself.
pub fn query_native_name(file: &File, cutoff: Instant) -> io::Result<Vec<u16>> {
    with_deadline(cutoff, || query_native_name_inner(file, cutoff))
}
fn query_native_name_inner(file: &File, cutoff: Instant) -> io::Result<Vec<u16>> {
    live(cutoff)?;
    let mut name = [0u16; 2048];
    // SAFETY: borrowed live handle and complete fixed output allocation.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle().cast(),
            name.as_mut_ptr(),
            name.len() as u32,
            VOLUME_NAME_NT,
        )
    } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    live(cutoff)?;
    if length >= name.len() || name[length] != 0 || name[..length].contains(&0) {
        return Err(io::Error::other(
            "private fixture native name is truncated or malformed",
        ));
    }
    Ok(name[..length].to_vec())
}

fn main_image(cutoff: Instant) -> io::Result<(usize, Vec<u16>)> {
    live(cutoff)?;
    // SAFETY: null requests this process's existing main module, without loading
    // or pinning any image. This is not a File HANDLE and is never closed.
    let module = unsafe { GetModuleHandleW(std::ptr::null()) };
    if module.is_null() {
        return Err(io::Error::last_os_error());
    }
    live(cutoff)?;
    let mut information = MEMORY_BASIC_INFORMATION::default();
    // SAFETY: existing main-image address and exactly sized writable output.
    let returned = unsafe {
        VirtualQuery(
            module.cast(),
            &mut information,
            std::mem::size_of_val(&information),
        )
    };
    if returned == 0 {
        return Err(io::Error::last_os_error());
    }
    live(cutoff)?;
    if returned != std::mem::size_of_val(&information)
        || information.State != MEM_COMMIT
        || information.Type != MEM_IMAGE
        || information.AllocationBase != module.cast()
        || information.RegionSize == 0
    {
        return Err(io::Error::other(
            "actual main module is not a complete committed MEM_IMAGE allocation",
        ));
    }
    let mut name = [0u16; 2048];
    // SAFETY: pseudo current-process handle, existing main mapping, fixed buffer.
    let length = unsafe {
        K32GetMappedFileNameW(
            GetCurrentProcess(),
            module.cast(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    live(cutoff)?;
    if length >= name.len() || name[length] != 0 || name[..length].contains(&0) {
        return Err(io::Error::other(
            "actual main mapped name is truncated or malformed",
        ));
    }
    Ok((module as usize, name[..length].to_vec()))
}

/// Check actual output ancestry without issuing fixture/mutation authority.
/// This also permits safe diagnostic publication after fixture verification fails.
pub fn verify_output(
    binding: &PrivateFixtureBinding,
    output: &Path,
    cutoff: Instant,
) -> io::Result<VerifiedOutput> {
    with_deadline(cutoff, || verify_output_inner(binding, output, cutoff))
}
fn verify_output_inner(
    binding: &PrivateFixtureBinding,
    output: &Path,
    cutoff: Instant,
) -> io::Result<VerifiedOutput> {
    live(cutoff)?;
    if !output.is_absolute()
        || output
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(io::Error::other("private fixture output path form differs"));
    }
    let paths = output
        .ancestors()
        .filter(|path| !path.as_os_str().is_empty())
        .collect::<Vec<_>>();
    if paths.len() > 64 {
        return Err(io::Error::other("private output ancestry exceeds bound"));
    }
    let parent = binding
        .ancestors
        .last()
        .ok_or_else(|| io::Error::other("private fixture parent absent"))?;
    let mut handles = Vec::new();
    for path in paths.into_iter().rev() {
        let handle = open(path, true, cutoff)?;
        live(cutoff)?;
        let metadata = windows_held_file_metadata(&handle)?;
        live(cutoff)?;
        for input in [parent, &binding.local_directory] {
            if metadata.volume_serial == input.volume_serial
                && metadata.file_index == input.file_index
            {
                return Err(io::Error::other(
                    "private output ancestry aliases the input namespace",
                ));
            }
        }
        handles.push(handle);
    }
    let ancestors = handles.len();
    drop(handles);
    live(cutoff)?;
    Ok(VerifiedOutput {
        path: output.to_owned(),
        ancestors,
    })
}

/// Bind the actual main mapping to authenticated descriptor data while the
/// controller's original custody scope is active. All new handles share read,
/// write and delete, are noninheritable, and close before the capability returns.
pub fn verify(
    binding: &PrivateFixtureBinding,
    paths: &[PathBuf],
    output: &Path,
    cutoff: Instant,
) -> io::Result<VerifiedPrivateFixture> {
    let mut phase = "declaration";
    let attempted = with_deadline(cutoff, || {
        live(cutoff)?;
        binding.validate(paths).map_err(io::Error::other)?;
        phase = "actual-main-image";
        let (base, mapped_name) = main_image(cutoff)?;
        phase = "held-ancestry-join";
        let mut directories = Vec::new();
        for ancestor in &binding.ancestors {
            let file = open(&ancestor.path, true, cutoff)?;
            directory_matches(&file, ancestor, cutoff)?;
            directories.push(file);
        }
        let local = open(&binding.local_directory.path, true, cutoff)?;
        directory_matches(&local, &binding.local_directory, cutoff)?;
        directories.push(local);
        phase = "held-fixture-identity";
        let mut file = open(&binding.fixture, false, cutoff)?;
        file_matches(&windows_held_file_metadata(&file)?, binding)?;
        phase = "held-fixture-bytes";
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            live(cutoff)?;
            let read = file.read(&mut buffer)?;
            live(cutoff)?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or_else(|| io::Error::other("private fixture byte count overflow"))?;
            if total > binding.bytes {
                return Err(io::Error::other("private fixture byte extent differs"));
            }
            hasher.update(&buffer[..read]);
        }
        let hash = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if total != binding.bytes || hash != binding.sha256 {
            return Err(io::Error::other(
                "private fixture immutable byte hash or length differs",
            ));
        }
        live(cutoff)?;
        file_matches(&windows_held_file_metadata(&file)?, binding)?;
        phase = "mapping-to-held-native-name";
        if query_native_name_inner(&file, cutoff)? != binding.native_path_utf16
            || mapped_name != binding.native_path_utf16
        {
            return Err(io::Error::other(
                "actual main mapping does not join the held fixture native backing name",
            ));
        }
        phase = "output-ancestry-separation";
        let output = verify_output_inner(binding, output, cutoff)?;
        let output_count = output.ancestors;
        drop(file);
        drop(directories);
        live(cutoff)?;
        Ok(VerifiedPrivateFixture {
            fixture: binding.fixture.clone(),
            local_directory: binding.local_directory.path.clone(),
            output,
            observation: serde_json::json!({"main_allocation_base":base,"main_mapping_mem_image":true,
                "native_backing_name_join":true,"volume_serial":binding.volume_serial,"file_index":binding.file_index,
                "bytes":total,"sha256":hash,"ancestor_count":binding.ancestors.len(),"output_ancestor_count":output_count,
                "temporary_query_handles_closed":true,"temporary_query_handles_share_all":true,"temporary_query_handles_noninheritable":true,
                "synchronous_io_deadline_settled_before_capability":true,
                "scope":"authenticated-descriptor-and-live-trusted-controller-private-sealed-custody",
                "hostile_host_ancestor_mutation_excluded":false,"in_memory_image_byte_integrity_proved":false,
                "completed_before_original_cutoff":true}),
        })
    });
    attempted
        .map_err(|primary: io::Error| io::Error::new(primary.kind(), Refusal { phase, primary }))
}
