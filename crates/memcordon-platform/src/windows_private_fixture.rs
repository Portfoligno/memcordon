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

/// Actual receiver-owned objects admitted by the authenticated START session.
/// Borrowing grants no raw-handle adoption or relative-open operation.
#[derive(Clone, Copy)]
pub struct BorrowedPrivateDirectories<'a> {
    pub input: &'a [File],
    pub local: &'a File,
    pub output: &'a [File],
}

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
    progress: Progress,
    primary: io::Error,
}

#[derive(Clone, Copy, Debug, Default)]
struct Progress {
    role: Option<&'static str>,
    index: usize,
    count: usize,
    substage: &'static str,
    requested_win32_mask: u32,
    observed_granted_access: Option<u32>,
    cutoff_before: Option<bool>,
    cutoff_after: Option<bool>,
}
impl Progress {
    fn object(&mut self, role: &'static str, index: usize, count: usize) {
        *self = Self {
            role: Some(role),
            index,
            count,
            ..Self::default()
        };
    }
    fn step(&mut self, substage: &'static str) {
        self.substage = substage;
        self.cutoff_before = None;
        self.cutoff_after = None;
    }
    fn before(&mut self, cutoff: Instant) -> io::Result<()> {
        let result = live(cutoff);
        self.cutoff_before = Some(result.is_ok());
        result
    }
    fn after(&mut self, cutoff: Instant) -> io::Result<()> {
        let result = live(cutoff);
        self.cutoff_after = Some(result.is_ok());
        result
    }
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
            "private fixture binding phase={}; progress={:?}; native-code={:?}; {}",
            self.phase,
            self.progress,
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
            "progress":{"role":refusal.progress.role,"index":refusal.progress.index,"count":refusal.progress.count,
                "substage":refusal.progress.substage,"requested_win32_mask":refusal.progress.requested_win32_mask,
                "observed_granted_access":refusal.progress.observed_granted_access,
                "cutoff_before":refusal.progress.cutoff_before,"cutoff_after":refusal.progress.cutoff_after,
                "cutoff_scope":"existing checks around current query/compare; null means not reached"},
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
fn noninheritable(file: &File, cutoff: Instant, progress: &mut Progress) -> io::Result<()> {
    progress.step("noninheritability-query");
    progress.before(cutoff)?;
    let mut flags = 0;
    // SAFETY: File owns the queried handle and flags is an initialized output.
    if unsafe { GetHandleInformation(file.as_raw_handle().cast(), &mut flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & HANDLE_FLAG_INHERIT != 0 {
        progress.substage = "noninheritability-compare";
        return Err(io::Error::other(
            "private fixture query handle is inheritable",
        ));
    }
    progress.after(cutoff)
}
fn open(
    path: &Path,
    directory: bool,
    cutoff: Instant,
    progress: &mut Progress,
) -> io::Result<File> {
    progress.step("open");
    progress.requested_win32_mask =
        FILE_READ_ATTRIBUTES | if directory { 0 } else { FILE_READ_DATA };
    progress.before(cutoff)?;
    let file = OpenOptions::new()
        .access_mode(progress.requested_win32_mask)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    noninheritable(&file, cutoff, progress)?;
    progress.step("metadata-query");
    let metadata = windows_held_file_metadata(&file)?;
    progress.after(cutoff)?;
    if metadata.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (metadata.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        progress.substage = "type-reparse-compare";
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
    progress: &mut Progress,
) -> io::Result<WindowsHeldFileMetadata> {
    use windows_sys::{
        Wdk::Foundation::{NtQueryObject, ObjectBasicInformation},
        Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION,
    };
    progress.requested_win32_mask = FILE_READ_ATTRIBUTES;
    noninheritable(file, cutoff, progress)?;
    progress.step("granted-access-query");
    progress.before(cutoff)?;
    let mut basic = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let provided = std::mem::size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32;
    let mut returned = 0;
    // SAFETY: borrowed original receiver-owned reference and exact documented
    // ObjectBasicInformation buffer. No path or object access is acquired here.
    let status = unsafe {
        NtQueryObject(
            file.as_raw_handle().cast(),
            ObjectBasicInformation,
            (&raw mut basic).cast(),
            provided,
            &raw mut returned,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "private metadata granted-access query failed: NTSTATUS={status} ({status:#010x}); provided={provided}; returned={returned}"
        )));
    }
    progress.after(cutoff)?;
    if returned != provided {
        return Err(io::Error::other(
            "private metadata granted-access response extent differs",
        ));
    }
    progress.observed_granted_access = Some(basic.GrantedAccess);
    progress.substage = "granted-access-compare";
    if basic.GrantedAccess != FILE_READ_ATTRIBUTES {
        return Err(io::Error::other(
            "private metadata reference lacks exact FILE_READ_ATTRIBUTES-only rights",
        ));
    }
    progress.step("identity-metadata-query");
    progress.before(cutoff)?;
    let metadata = windows_held_file_metadata(file)?;
    progress.substage = "identity-compare";
    if metadata.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || metadata.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.volume_serial != expected.volume_serial
        || metadata.file_index != expected.file_index
        || metadata.attributes != expected.attributes
    {
        return Err(io::Error::other(
            "private fixture directory identity or attributes differ",
        ));
    }
    progress.after(cutoff)?;
    Ok(metadata)
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
    directories: BorrowedPrivateDirectories<'_>,
    cutoff: Instant,
) -> io::Result<VerifiedOutput> {
    let mut progress = Progress::default();
    with_deadline(cutoff, || {
        verify_output_inner(binding, output, directories, cutoff, &mut progress)
    })
    .map_err(|primary| {
        io::Error::new(
            primary.kind(),
            Refusal {
                phase: "output-ancestry-separation",
                progress,
                primary,
            },
        )
    })
}
fn verify_output_inner(
    binding: &PrivateFixtureBinding,
    output: &Path,
    directories: BorrowedPrivateDirectories<'_>,
    cutoff: Instant,
    progress: &mut Progress,
) -> io::Result<VerifiedOutput> {
    progress.object("output-ancestor", 0, 0);
    progress.step("output-path-validation");
    progress.before(cutoff)?;
    binding.validate_output(output).map_err(io::Error::other)?;
    if directories.output.len() != binding.output_ancestors.len() {
        return Err(io::Error::other(
            "admitted output metadata role count differs",
        ));
    }
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
    let count = paths.len();
    for (index, path) in paths.into_iter().rev().enumerate() {
        progress.object("output-ancestor", index, count);
        let expected = &binding.output_ancestors[index];
        if path != expected.path.as_path() {
            return Err(io::Error::other("admitted output path order differs"));
        }
        let metadata = directory_matches(&directories.output[index], expected, cutoff, progress)?;
        progress.substage = "output-alias-compare";
        for input in [parent, &binding.local_directory] {
            if metadata.volume_serial == input.volume_serial
                && metadata.file_index == input.file_index
            {
                return Err(io::Error::other(
                    "private output ancestry aliases the input namespace",
                ));
            }
        }
    }
    let ancestors = count;
    live(cutoff)?;
    Ok(VerifiedOutput {
        path: output.to_owned(),
        ancestors,
    })
}

/// Bind the actual main mapping to authenticated descriptor data while the
/// controller's original custody scope is active. Borrowed metadata references
/// preserve their original controller file objects/sharing and may remain live
/// for root forwarding. Only the new named fixture read handle shares all and
/// closes before capability return; the receiver owns metadata lifetimes.
pub fn verify(
    binding: &PrivateFixtureBinding,
    paths: &[PathBuf],
    output: &Path,
    directories: BorrowedPrivateDirectories<'_>,
    cutoff: Instant,
) -> io::Result<VerifiedPrivateFixture> {
    let mut phase = "declaration";
    let mut progress = Progress::default();
    let attempted = with_deadline(cutoff, || {
        live(cutoff)?;
        binding.validate(paths).map_err(io::Error::other)?;
        binding.validate_output(output).map_err(io::Error::other)?;
        if directories.input.len() != binding.ancestors.len()
            || directories.output.len() != binding.output_ancestors.len()
        {
            return Err(io::Error::other(
                "admitted private metadata role counts differ",
            ));
        }
        phase = "actual-main-image";
        let (base, mapped_name) = main_image(cutoff)?;
        phase = "held-ancestry-join";
        for (index, ancestor) in binding.ancestors.iter().enumerate() {
            progress.object("input-ancestor", index, binding.ancestors.len());
            directory_matches(&directories.input[index], ancestor, cutoff, &mut progress)?;
        }
        progress.object("local-directory", 0, 1);
        directory_matches(
            directories.local,
            &binding.local_directory,
            cutoff,
            &mut progress,
        )?;
        phase = "held-fixture-identity";
        progress.object("fixture", 0, 1);
        let mut file = open(&binding.fixture, false, cutoff, &mut progress)?;
        progress.step("fixture-identity-metadata-query");
        file_matches(&windows_held_file_metadata(&file)?, binding)?;
        phase = "held-fixture-bytes";
        progress.step("fixture-byte-hash");
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
        progress.step("mapping-native-name-join");
        if query_native_name_inner(&file, cutoff)? != binding.native_path_utf16
            || mapped_name != binding.native_path_utf16
        {
            return Err(io::Error::other(
                "actual main mapping does not join the held fixture native backing name",
            ));
        }
        phase = "output-ancestry-separation";
        let output = verify_output_inner(binding, output, directories, cutoff, &mut progress)?;
        let output_count = output.ancestors;
        drop(file);
        live(cutoff)?;
        Ok(VerifiedPrivateFixture {
            fixture: binding.fixture.clone(),
            local_directory: binding.local_directory.path.clone(),
            output,
            observation: serde_json::json!({"main_allocation_base":base,"main_mapping_mem_image":true,
                "native_backing_name_join":true,"volume_serial":binding.volume_serial,"file_index":binding.file_index,
                "bytes":total,"sha256":hash,"ancestor_count":binding.ancestors.len(),"output_ancestor_count":output_count,
                "named_fixture_query_handle_closed":true,"named_fixture_query_handle_share_all":true,
                "metadata_references_borrowed_from_authenticated_session":true,"metadata_references_noninheritable":true,
                "metadata_granted_access":FILE_READ_ATTRIBUTES,"metadata_forwarding_references_may_remain_live":true,
                "metadata_references_share_original_controller_file_objects":true,
                "synchronous_io_deadline_settled_before_capability":true,
                "scope":"authenticated-descriptor-and-live-trusted-controller-private-sealed-custody",
                "hostile_host_ancestor_mutation_excluded":false,"in_memory_image_byte_integrity_proved":false,
                "completed_before_original_cutoff":true}),
        })
    });
    attempted.map_err(|primary: io::Error| {
        io::Error::new(
            primary.kind(),
            Refusal {
                phase,
                progress,
                primary,
            },
        )
    })
}
